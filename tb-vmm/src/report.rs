//! Spawn-path benchmark instrumentation (the `--report-spawn` flag).
//!
//! This is tb-vmm's half of the FAIR, self-certifying boot measurement
//! (docs/BENCHMARKS.md §2, axis A = VMM-spawn). `Vmm::new` captures `spawn_t0`
//! as its FIRST line plus a sub-phase `Instant` after each boot stage (KVM open,
//! guest RAM + memslots, kernel ELF load, arch setup) — a Firecracker-style
//! decomposition. A [`BootReady`] PIO device registered at port `0x510`
//! timestamps the guest's single boot-ready `out` (emitted by the kernel right
//! after the in-guest `boot-ready-cycles=` print). The difference
//! `ready - spawn_t0` is the host-observed spawn→ready wall-clock (the
//! Firecracker `--boot-timer` analog), printed on the first such write as a
//! single machine-parseable line for the CI bench lane to grep.
//!
//! The clock here is the HOST `std::time::Instant` (monotonic wall-clock), NOT
//! an in-guest cycle counter — so this axis measures the VMM/host spawn floor,
//! which is exactly the point of axis A. It is deliberately separate from the
//! guest-only `boot-ready-cycles` figure (axis B), which the guest prints itself.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::device::BusDevice;

/// The I/O port the guest kernel writes ONCE to signal "boot-ready" — matched to
/// `tb_hal::boot_ready_signal()` (`out 0x510, al`). Chosen clear of COM1
/// (`0x3f8..=0x3ff`) and QEMU's isa-debug-exit (`0x501`) so nothing else claims
/// it; a single-byte register.
pub const BOOT_READY_PORT: u64 = 0x510;
/// The BootReady device occupies exactly one byte.
pub const BOOT_READY_LEN: u64 = 1;

/// Sub-phase wall-clock marks captured along `Vmm::new`, all relative to
/// `spawn_t0` (the first instruction of `Vmm::new`). A Firecracker-style
/// decomposition so a regression can be attributed to a specific stage.
#[derive(Clone, Copy, Debug)]
pub struct SpawnPhases {
    /// `Instant` captured as the very FIRST line of `Vmm::new` — the spawn `t0`.
    pub t0: Instant,
    /// After `Kvm::new()` + `create_vm` + the irqchip (KVM open + VM create).
    pub after_kvm: Instant,
    /// After guest RAM allocation + `KVM_SET_USER_MEMORY_REGION` memslots.
    pub after_ram: Instant,
    /// After reading + loading the kernel ELF `PT_LOAD` segments into guest RAM.
    pub after_load: Instant,
    /// After `arch::setup` (boot structures + sregs/regs) — the vCPU is now
    /// ready to run; this is the last mark before `Vmm::run` enters `KVM_RUN`.
    pub after_setup: Instant,
}

impl SpawnPhases {
    /// Per-phase durations in nanoseconds, each measured from the PREVIOUS mark
    /// (so they sum to `after_setup - t0`): (kvm, ram, load, setup).
    pub fn phase_ns(&self) -> (u128, u128, u128, u128) {
        (
            self.after_kvm.duration_since(self.t0).as_nanos(),
            self.after_ram.duration_since(self.after_kvm).as_nanos(),
            self.after_load.duration_since(self.after_ram).as_nanos(),
            self.after_setup.duration_since(self.after_load).as_nanos(),
        )
    }
}

/// Shared cell the [`BootReady`] device fills with the `Instant` of the FIRST
/// guest write to the boot-ready port. `None` until the guest signals ready.
pub type ReadyCell = Arc<Mutex<Option<Instant>>>;

/// A new, empty ready cell.
pub fn ready_cell() -> ReadyCell {
    Arc::new(Mutex::new(None))
}

/// A one-byte PIO device at [`BOOT_READY_PORT`] that captures the host
/// `Instant` of the guest's boot-ready `out` into a shared [`ReadyCell`]. Only
/// the FIRST write is recorded (the kernel writes exactly once; a defensive
/// guard ignores any later writes so the measured instant is stable). Reads
/// return 0 — the port is write-only signalling.
pub struct BootReady {
    cell: ReadyCell,
}

impl BootReady {
    /// A BootReady device that records into `cell`.
    pub fn new(cell: ReadyCell) -> Self {
        BootReady { cell }
    }
}

impl BusDevice for BootReady {
    fn read(&mut self, _offset: u64, data: &mut [u8]) {
        // Write-only signalling port; return zeros for any read.
        data.fill(0);
    }

    fn write(&mut self, _offset: u64, _data: &[u8]) {
        // Capture the instant of the FIRST boot-ready write only; ignore the
        // value (the kernel writes al=0) and any subsequent writes.
        let now = Instant::now();
        let mut slot = self.cell.lock().expect("BootReady cell poisoned");
        if slot.is_none() {
            *slot = Some(now);
        }
    }
}

/// Format the machine-parseable spawn-report line the CI bench lane greps:
/// `spawn-ready-ns=<t> phase-kvm-ns=<a> phase-ram-ns=<b> phase-load-ns=<c> phase-setup-ns=<d>`.
/// `ready` is the host `Instant` of the guest's boot-ready write; the four phase
/// figures are the [`SpawnPhases`] decomposition. Pure string building so it is
/// unit-testable without a VM.
pub fn format_report(phases: &SpawnPhases, ready: Instant) -> String {
    let spawn_ready_ns = ready.duration_since(phases.t0).as_nanos();
    let (kvm, ram, load, setup) = phases.phase_ns();
    format!(
        "spawn-ready-ns={spawn_ready_ns} phase-kvm-ns={kvm} \
         phase-ram-ns={ram} phase-load-ns={load} phase-setup-ns={setup}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn boot_ready_captures_first_write_only() {
        let cell = ready_cell();
        let mut dev = BootReady::new(cell.clone());
        assert!(cell.lock().unwrap().is_none());

        dev.write(0, &[0]);
        let first = cell.lock().unwrap().expect("first write recorded");

        // A later write must NOT overwrite the captured instant.
        std::thread::sleep(Duration::from_millis(1));
        dev.write(0, &[0]);
        let again = cell.lock().unwrap().expect("still recorded");
        assert_eq!(first, again, "only the first boot-ready write is timed");
    }

    #[test]
    fn boot_ready_read_is_zero() {
        let mut dev = BootReady::new(ready_cell());
        let mut buf = [0xAAu8; 1];
        dev.read(0, &mut buf);
        assert_eq!(buf, [0]);
    }

    #[test]
    fn report_line_is_machine_parseable() {
        let t0 = Instant::now();
        let phases = SpawnPhases {
            t0,
            after_kvm: t0 + Duration::from_nanos(100),
            after_ram: t0 + Duration::from_nanos(300),
            after_load: t0 + Duration::from_nanos(600),
            after_setup: t0 + Duration::from_nanos(1000),
        };
        let ready = t0 + Duration::from_nanos(1500);
        let line = format_report(&phases, ready);
        assert_eq!(
            line,
            "spawn-ready-ns=1500 phase-kvm-ns=100 phase-ram-ns=200 \
             phase-load-ns=300 phase-setup-ns=400"
        );
    }
}
