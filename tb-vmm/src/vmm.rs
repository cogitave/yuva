//! The VM lifecycle and the `KVM_RUN` exit loop.
//!
//! [`Vmm::new`] wires KVM -> guest RAM -> kernel image -> vCPU -> devices ->
//! arch boot setup; [`Vmm::run`] drives `KVM_RUN`, dispatching serial PIO,
//! MMIO, and terminal exits (HLT/shutdown), with a wall-clock guard and an
//! exit budget so a hung guest cannot run forever.
//!
//! KVM exit-reason handling follows kvm-ioctls `VcpuExit` (docs.rs/kvm-ioctls):
//! `IoOut(port,&[u8])`, `IoIn(port,&mut[u8])`, `MmioRead`, `MmioWrite`, `Hlt`,
//! `Shutdown`, `SystemEvent`, `FailEntry(reason,cpu)`, `InternalError`.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kvm_bindings::KVM_API_VERSION;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};

use crate::arch::{self, BootParams};
use crate::cli::Config;
use crate::device::Bus;
use crate::error::VmmError;
use crate::infer_host::InferHost;
use crate::loader;
use crate::memory::GuestRam;
use crate::report::{self, BootReady, ReadyCell, SpawnPhases};
use crate::serial::Serial;
use crate::virtio_mmio::{VirtioMmio, XPORT_MMIO_BASE, XPORT_MMIO_LEN};

/// COM1 base port + register span (16550 has 8 registers).
const COM1_BASE: u64 = 0x3f8;
const COM1_LEN: u64 = 8;

/// Upper bound on VM exits before we declare the guest hung. The FULL
/// cumulative M0..M31 chain boots under this lane: its exits are dominated by
/// serial PIO (one `IoOut` per guest byte; the whole chain prints tens of
/// kilobytes, so well under one million), and the M30 stage-C virtio-console
/// sessions add only a handful of MMIO exits each (~40 register accesses + 2-3
/// notifies per session, three sessions per boot — the guest's used-ring polls
/// are RAM reads, not exits). 20M is deliberately defensive headroom over that
/// profile while still bounding a pathological exit storm.
const MAX_EXITS: u64 = 20_000_000;

/// Why the run loop stopped *cleanly*. There is exactly one clean stop: the
/// kernel executing `HLT` after printing the final milestone marker. Every other
/// terminal exit (`KVM_EXIT_SHUTDOWN`, `KVM_EXIT_SYSTEM_EVENT`, fail-entry,
/// internal error, guard timeout) is a [`VmmError`], not a `StopReason` — so a
/// boot that crashes can never be mistaken for success.
#[derive(Debug, Clone, Copy)]
pub enum StopReason {
    /// Guest executed `HLT` (the kernel halts after M4 — the only clean stop).
    Halted,
}

/// A configured, ready-to-run virtual machine.
///
/// Field order is the drop order: the vCPU drops first, then the VM, then guest
/// RAM (whose mmap must stay valid while the VM fd is open), then the Kvm handle.
pub struct Vmm {
    config: Config,
    pio_bus: Bus,
    mmio_bus: Bus,
    vcpu: VcpuFd,
    vm: VmFd,
    // Held only to keep the guest mmap alive for the VM's lifetime and to drop
    // it in the correct order (after the VM fd). Never read after construction —
    // the KVM memslots point straight at its mmap — so the field is a deliberate
    // RAII drop-guard, not dead state.
    #[allow(dead_code)]
    ram: GuestRam,
    _kvm: Kvm,
    // Spawn-path benchmark state (`--report-spawn`): the sub-phase Instants of
    // `Vmm::new`, the shared cell the BootReady (0x510) device fills on the
    // guest's boot-ready `out`, and a one-shot guard so the report prints once.
    spawn_phases: SpawnPhases,
    ready_cell: ReadyCell,
    reported: bool,
}

impl Vmm {
    /// Build the VM: open KVM, allocate + register guest RAM, load the kernel,
    /// create the vCPU, attach devices, and run the arch boot configuration.
    pub fn new(config: Config) -> Result<Self, VmmError> {
        // Spawn `t0`: the VERY FIRST line of `Vmm::new`. The host-observed
        // spawn->ready wall-clock (axis A; docs/BENCHMARKS.md §2) is measured
        // from here to the guest's boot-ready PIO write. Always captured (cheap);
        // only PRINTED under `--report-spawn`.
        let spawn_t0 = Instant::now();

        let kvm = Kvm::new().map_err(VmmError::KvmInit)?;
        let api = kvm.get_api_version();
        if api != KVM_API_VERSION as i32 {
            return Err(VmmError::ApiVersion(api));
        }

        let vm = kvm.create_vm()?;

        // M8: create the in-kernel interrupt controller (KVM_CREATE_IRQCHIP =
        // PIC + IOAPIC + a per-vCPU in-kernel LAPIC) BEFORE the vCPU, so the
        // vCPU is born owning an in-kernel LAPIC and the guest's LAPIC + LAPIC
        // timer -- M8's ONLY interrupt source on this microvm-class guest -- are
        // emulated in-kernel and timer IRQs are injected automatically. Without
        // it the GPA 0xFEE0_0000 is unmapped MMIO the Bus silently drops, the
        // timer never fires, `timer_demo()` returns false, and "M8: timer OK"
        // never prints. NOTE: with an in-kernel LAPIC the guest's terminal
        // `cli; hlt` no longer surfaces as KVM_EXIT_HLT (KVM parks the vCPU
        // in-kernel), so the run reaches the wall-clock guard; the serial device
        // flushes every byte (serial.rs `transmit`), so the marker is already in
        // the captured output by then -- exactly how scripts/run-vmm-x86_64.sh
        // (grep over OUTPUT under `timeout --foreground`) decides PASS. The
        // guest enters in long mode and never uses the real-mode TSS/identity
        // map, so the existing late `set_tss_address` in arch::setup remains
        // sufficient.
        vm.create_irq_chip()?;
        // Spawn phase 1: KVM open + VM create + irqchip done.
        let after_kvm = Instant::now();

        // Guest RAM + KVM memslots.
        let ram = GuestRam::new(config.mem_bytes)?;
        ram.register_with_kvm(&vm)?;
        // Spawn phase 2: guest RAM allocated + memslots registered.
        let after_ram = Instant::now();

        // Load the kernel ELF into guest RAM and resolve the 64-bit entry.
        let image = std::fs::read(&config.kernel_path)
            .map_err(|e| VmmError::KernelRead(config.kernel_path.clone(), e))?;
        let loaded = loader::load_kernel(&image, ram.inner())?;
        if config.print_exit {
            eprintln!(
                "tb-vmm: loaded kernel entry={:#x} ({} note), image_end={:#x}",
                loaded.entry,
                tb_boot::TB_NOTE_NAME,
                loaded.image_end
            );
        }
        // Spawn phase 3: kernel ELF read + PT_LOAD segments copied into RAM.
        let after_load = Instant::now();

        let vcpu = vm.create_vcpu(0)?;

        // Devices: a 16550A UART on COM1 carrying guest output to stdout, plus
        // the BootReady (0x510) device that timestamps the guest's boot-ready
        // PIO write into a shared cell (the `--report-spawn` axis-A clock).
        let mut pio_bus = Bus::new();
        let mut mmio_bus = Bus::new();
        let serial = Arc::new(Mutex::new(Serial::new(Box::new(io::stdout()))));
        pio_bus.register(COM1_BASE, COM1_LEN, serial)?;
        let ready_cell = report::ready_cell();
        let boot_ready = Arc::new(Mutex::new(BootReady::new(ready_cell.clone())));
        pio_bus.register(report::BOOT_READY_PORT, report::BOOT_READY_LEN, boot_ready)?;

        // M30 stage C: tb-vmm's FIRST mmio_bus device — the modern virtio-mmio
        // virtio-console transport fronting the in-process M30/M31 host peer
        // (`transport=TB-VMM-HOST`). Registered at slot 0 of the kernel's
        // hard-coded scan window (0xFEB0_0000, stride 0x200 — above the
        // 256 MiB guest RAM, so accesses arrive as KVM_EXIT_MMIO for free).
        // The device holds a clone of the guest memory (vm-memory regions are
        // internally shared — a cheap handle) to walk the virtqueues. The peer
        // custodies a per-run OS-RNG key+nonce (proposal §4: K is born HERE,
        // never in the guest image or on any command line) and writes its
        // leg-2 witness to `--xport-out` (a stream the guest cannot reach).
        let host = InferHost::from_config(
            config.xport_out.as_deref(),
            config.xport_key_out.as_deref(),
        )?;
        let xport = Arc::new(Mutex::new(VirtioMmio::new(ram.inner().clone(), host)));
        mmio_bus.register(XPORT_MMIO_BASE, XPORT_MMIO_LEN, xport)?;

        // Arch boot configuration (boot structures + sregs/regs).
        let params = BootParams {
            entry_point: loaded.entry,
            mem_regions: ram.regions(),
            cmdline: &config.cmdline,
        };
        arch::setup(&kvm, &vm, &vcpu, ram.inner(), &params)?;
        // Spawn phase 4: arch boot config done — the vCPU is ready to run.
        let after_setup = Instant::now();

        let spawn_phases = SpawnPhases {
            t0: spawn_t0,
            after_kvm,
            after_ram,
            after_load,
            after_setup,
        };

        Ok(Self {
            config,
            pio_bus,
            mmio_bus,
            vcpu,
            vm,
            ram,
            _kvm: kvm,
            spawn_phases,
            ready_cell,
            reported: false,
        })
    }

    /// Drive `KVM_RUN` until the guest halts/shuts down, or a guard fires.
    pub fn run(&mut self) -> Result<StopReason, VmmError> {
        let _ = &self.vm; // VM fd kept alive for the duration of the run
        let deadline = Instant::now() + Duration::from_secs(self.config.timeout_secs);
        let mut exits: u64 = 0;

        // The loop breaks with either a clean StopReason or an error sentinel.
        enum Outcome {
            Stop(StopReason),
            Shutdown,
            SystemEvent(u32),
            Timeout,
            ExitBudget,
            Fail { reason: u64, cpu: u32 },
            Internal,
            RunErr(kvm_ioctls::Error),
        }

        let outcome = loop {
            if Instant::now() >= deadline {
                break Outcome::Timeout;
            }
            exits += 1;
            if exits > MAX_EXITS {
                break Outcome::ExitBudget;
            }

            match self.vcpu.run() {
                Ok(exit) => match exit {
                    VcpuExit::IoIn(port, data) => self.pio_bus.read(port as u64, data),
                    VcpuExit::IoOut(port, data) => self.pio_bus.write(port as u64, data),
                    VcpuExit::MmioRead(addr, data) => self.mmio_bus.read(addr, data),
                    VcpuExit::MmioWrite(addr, data) => self.mmio_bus.write(addr, data),
                    VcpuExit::Hlt => break Outcome::Stop(StopReason::Halted),
                    // A Yuva kernel reaches the end of its boot self-test and
                    // halts (HLT). KVM_EXIT_SHUTDOWN means a triple fault / reset
                    // instead — i.e. the guest crashed — so it is a failure.
                    VcpuExit::Shutdown => break Outcome::Shutdown,
                    VcpuExit::SystemEvent(ev, _) => break Outcome::SystemEvent(ev),
                    VcpuExit::FailEntry(reason, cpu) => break Outcome::Fail { reason, cpu },
                    VcpuExit::InternalError => break Outcome::Internal,
                    other => {
                        if self.config.print_exit {
                            eprintln!("tb-vmm: ignoring unhandled VM exit: {other:?}");
                        }
                    }
                },
                Err(e) => {
                    // EINTR is benign (a delivered signal); retry. Anything else
                    // is fatal for our single-shot boot.
                    if e.errno() == libc_eintr() {
                        continue;
                    }
                    break Outcome::RunErr(e);
                }
            }

            // If the guest just wrote the boot-ready port (`out 0x510, al`), the
            // BootReady device timestamped it into `ready_cell`; print the
            // machine-parseable spawn report ONCE (under `--report-spawn`) and
            // keep running (the in-kernel LAPIC parks `hlt`; the timeout guard
            // bounds the run, exactly as without the flag).
            self.maybe_report_spawn();
        };

        // Post-loop: the vCPU borrow from the run() exit has ended, so we may
        // now read regs/sregs for diagnostics.
        match outcome {
            Outcome::Stop(reason) => Ok(reason),
            Outcome::Shutdown => {
                self.dump_diagnostics("KVM_EXIT_SHUTDOWN (triple fault / reset)");
                Err(VmmError::GuestShutdown)
            }
            Outcome::SystemEvent(ev) => {
                self.dump_diagnostics("KVM_EXIT_SYSTEM_EVENT");
                Err(VmmError::SystemEvent(ev))
            }
            Outcome::Timeout => {
                self.dump_diagnostics("run guard (timeout)");
                Err(VmmError::Timeout { secs: self.config.timeout_secs })
            }
            Outcome::ExitBudget => {
                self.dump_diagnostics("exit budget exhausted");
                Err(VmmError::ExitBudget(MAX_EXITS))
            }
            Outcome::Fail { reason, cpu } => {
                self.dump_diagnostics("KVM_EXIT_FAIL_ENTRY");
                Err(VmmError::GuestFault { reason, cpu })
            }
            Outcome::Internal => {
                self.dump_diagnostics("KVM_EXIT_INTERNAL_ERROR");
                Err(VmmError::InternalError)
            }
            Outcome::RunErr(e) => {
                self.dump_diagnostics("KVM_RUN error");
                Err(VmmError::Kvm(e))
            }
        }
    }

    /// Print the machine-parseable spawn report ONCE, the first run-loop
    /// iteration after the guest has written the boot-ready PIO port (0x510).
    /// A no-op unless `--report-spawn` is set and the BootReady device has
    /// captured the guest's ready `Instant`. The report goes to STDOUT (so the
    /// CI bench lane greps it alongside the in-guest serial markers); it never
    /// stops the run — the timeout guard still bounds it, exactly as without the
    /// flag, so the existing vmm-boot behaviour is unchanged when the flag is off.
    fn maybe_report_spawn(&mut self) {
        if !self.config.report_spawn || self.reported {
            return;
        }
        let ready = match *self.ready_cell.lock().expect("BootReady cell poisoned") {
            Some(instant) => instant,
            None => return,
        };
        println!("{}", report::format_report(&self.spawn_phases, ready));
        self.reported = true;
    }

    /// Best-effort dump of vCPU state to stderr for boot-failure triage.
    fn dump_diagnostics(&self, context: &str) {
        eprintln!("tb-vmm: vCPU diagnostics ({context}):");
        match self.vcpu.get_regs() {
            Ok(r) => eprintln!(
                "  rip={:#018x} rflags={:#x} rsp={:#018x} rdi={:#018x} rsi={:#018x}",
                r.rip, r.rflags, r.rsp, r.rdi, r.rsi
            ),
            Err(e) => eprintln!("  <get_regs failed: {e}>"),
        }
        match self.vcpu.get_sregs() {
            Ok(s) => eprintln!(
                "  cr0={:#x} cr3={:#018x} cr4={:#x} efer={:#x} cs.base={:#x} cs.l={} cs.sel={:#x}",
                s.cr0, s.cr3, s.cr4, s.efer, s.cs.base, s.cs.l, s.cs.selector
            ),
            Err(e) => eprintln!("  <get_sregs failed: {e}>"),
        }
    }
}

/// `EINTR` without pulling in the `libc` crate (kvm-ioctls already depends on
/// it transitively, but we keep our direct deps minimal).
fn libc_eintr() -> i32 {
    4
}
