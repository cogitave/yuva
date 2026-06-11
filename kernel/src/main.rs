//! TABOS kernel entry shim (M4: user/ring boundary).
//!
//! Framekernel rule: the kernel crate is otherwise safe Rust. THIS file is the
//! single permitted exception. It contains no `unsafe {}` blocks; the only
//! reason crate-level `forbid(unsafe_code)` is not applied here is that
//! `#[unsafe(no_mangle)]` is itself an *unsafe attribute* (it tells the linker
//! to expose `rust_main` un-mangled for tb-hal's `_start` to `call`/`b` into),
//! and the `unsafe_code` lint flags it. All real unsafe + assembly is confined
//! to tb-hal (KERNEL-FOUNDATION-SPEC.md §1).
//!
//! M2 (kept verbatim) proves the cooperative context switch: two kernel tasks
//! (A and B) on kernel-owned static stacks voluntarily `yield_to` each other
//! for `ROUND_TRIPS` strict A,B,A,B round-trips. tb-hal switches only the ABI
//! callee-saved registers + SP, so each task carries locals ACROSS every yield
//! as a REGISTER-INTEGRITY CANARY; divergence prints \"M2: FAIL <why>\". On
//! success it prints \"M2: context-switch OK\". The M0 serial hello and the M1
//! breakpoint round-trip are kept verbatim ahead of it.
//!
//! M3 (kept) appends the MMU proof: `mmu_init()`, a serial line proving the
//! UART mapping survived the enable, then `mmu_selftest()` (map -> write ->
//! verify -> remap -> re-verify). DoD marker: \"M3: mmu OK\".
//!
//! M4 (this milestone) appends the user/ring boundary proof. After M3, the
//! kernel calls `tb_hal::user_demo()`: tb-hal sets up USER-accessible code +
//! stack pages (M3 mmu layer + USER permission bits), drops the CPU to
//! unprivileged mode (x86_64 ring 3 / aarch64 EL0) at a tiny user stub, the
//! stub issues ONE syscall (`int 0x80` / `svc #0`) that traps back into the
//! kernel, the safe handler records it (+ its magic arg) and returns the CPU
//! to the kernel. `user_demo()` returns true iff the syscall was observed from
//! user mode with arg == 0xCAFE. DoD marker: \"M4: user/ring OK\". ALL the new
//! unsafe/asm lives in tb-hal; this crate calls one safe fn and branches on a
//! bool.
//!
//! MV (the L1 sovereignty rung) adds a SECOND boot path WITHOUT touching this
//! self-test: the project's own `tb-vmm` boots this SAME kernel ELF directly in
//! 64-bit long mode via tb-boot v0 (tb-hal's `_tb_start` + the TABOS ELF note),
//! with `boot_info` = the guest-physical `tb_boot::TbBootInfo` pointer instead
//! of a PVH `hvm_start_info`. `rust_main` prints "tb-boot: contract v0 OK"
//! first IFF the magic validates (a PVH pointer is silently ignored), then runs
//! M0-M4 identically. The PVH/QEMU regression path is unchanged.

#![no_std]
#![no_main]

// M5: `alloc` comes online kernel-wide. On nightly this needs NO feature gate
// (`extern crate alloc` is stable for no_std binaries, and the default
// alloc-error handler routes OOM to our `#[panic_handler]`), so the only new
// crate-level line is the `extern crate alloc;` below. The heap itself — the
// `#[global_allocator]` impl, the `.bss` arena and all raw pointer math — lives
// in tb-hal; this crate just names the allocator and uses `alloc` types.
extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::hint::black_box;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use tb_hal::{Task, TaskStack, TrapAction, TrapInfo, TrapKind};

/// The kernel-wide global allocator: a zero-sized handle whose `GlobalAlloc`
/// impl (and the `.bss` arena behind it) lives entirely in tb-hal. Declaring
/// this `static` and using `alloc` types is NOT `unsafe`; `heap_init()` lays the
/// arena down before first use (see `rust_main`).
#[global_allocator]
static HEAP: tb_hal::Heap = tb_hal::Heap::new();

/// Ping-pong round-trips (A→B→A counts as one). DoD asks for >= 1000.
const ROUND_TRIPS: usize = 1000;

/// `TURN` value meaning \"task A must run this half-round\".
const TURN_A: usize = 0;
/// `TURN` value meaning \"task B must run this half-round\".
const TURN_B: usize = 1;

/// Initial value of task A's rotating-pattern canary (arbitrary, asymmetric).
const PAT_A_INIT: usize = 0xA5A5_5A5A_DEAD_BEEF;
/// Initial value of task B's rotating-pattern canary (different from A's).
const PAT_B_INIT: usize = 0x0F0F_F0F0_CAFE_F00D;

// --- M2 scheduler bookkeeping (all in THIS forbid-class crate, all safe) ----

/// Task A's stack: 4096 usize words (32 KiB), 16-byte aligned.
static STACK_A: TaskStack<4096> = TaskStack::new();
/// Task B's stack: 4096 usize words (32 KiB), 16-byte aligned.
static STACK_B: TaskStack<4096> = TaskStack::new();

/// Task A's handle as `Task::raw()`, stashed so task B can yield back to A.
static TASK_A_RAW: AtomicUsize = AtomicUsize::new(usize::MAX);
/// Task B's handle as `Task::raw()`, stashed so task A can yield to B.
static TASK_B_RAW: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Bootstrap context's handle as `Task::raw()` (slot 0), stashed BEFORE the
/// ping-pong starts so task A can hand the CPU back to `rust_main` after the
/// M2 verdict — M3/M4 then run in the bootstrap context.
static BOOT_TASK_RAW: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Set by task A immediately after the M2 success marker and right before it
/// yields back to the bootstrap context. `rust_main` refuses to start M3
/// without it (fail-closed against any stray resume of slot 0).
static M2_PASSED: AtomicBool = AtomicBool::new(false);

/// Whose half-round it is: the strict-alternation flag (TURN_A / TURN_B).
static TURN: AtomicUsize = AtomicUsize::new(TURN_A);

/// Shared increment counter: A sees it == 2*i at round i, B sees == 2*j + 1.
static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Set by task B after it audited its own canaries on its final round.
static B_VERIFIED: AtomicBool = AtomicBool::new(false);

// --- M9 preemptive-scheduler bookkeeping (all in THIS crate, all safe) ------

/// Spin task C's stack: 4096 usize words (32 KiB), 16-byte aligned.
static STACK_C: TaskStack<4096> = TaskStack::new();
/// Spin task D's stack: 4096 usize words (32 KiB), 16-byte aligned.
static STACK_D: TaskStack<4096> = TaskStack::new();

/// Spin task C's advance counter: bumped in its infinite loop, read by the boot
/// task to prove C actually ran -- which can ONLY happen via involuntary timer
/// preemption, since the boot task never `yield_to`s it.
static SPIN_C_COUNT: AtomicU64 = AtomicU64::new(0);
/// Spin task D's advance counter (as C).
static SPIN_D_COUNT: AtomicU64 = AtomicU64::new(0);

// --- M10 per-entity-address-space bookkeeping (all in THIS crate, all safe) --

/// Task G's stack (runs in address space E): 4096 usize words, 16-aligned.
static STACK_G: TaskStack<4096> = TaskStack::new();
/// Task H's stack (runs in address space F): 4096 usize words, 16-aligned.
static STACK_H: TaskStack<4096> = TaskStack::new();

/// Task G's handle as `Task::raw()`, stashed so the boot task enters it through
/// its handle (symmetric with H/boot) and task H can target it in turn.
static TASK_G_RAW: AtomicUsize = AtomicUsize::new(usize::MAX);
/// Task H's handle as `Task::raw()`.
static TASK_H_RAW: AtomicUsize = AtomicUsize::new(usize::MAX);
/// The boot context's handle, stashed so task H hands the CPU back to it.
static BOOT10_RAW: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Set by task G iff it read back its OWN magic at the shared test VA under
/// address space E (proving the yield_to fold-in put it in its own root).
static G_SEES_OWN: AtomicBool = AtomicBool::new(false);
/// Set by task H iff it read back its OWN magic under address space F.
static H_SEES_OWN: AtomicBool = AtomicBool::new(false);

/// Armed by the boot task immediately before it provokes the cross-space fault;
/// the trap hook treats a page fault as the expected cross-space access ONLY
/// while this is set (every other fault stays fatal).
static M10_FAULT_ARMED: AtomicBool = AtomicBool::new(false);
/// The VA whose cross-space fault the trap hook expects (the M10 test VA).
static M10_FAULT_VA: AtomicU64 = AtomicU64::new(0);
/// Set by the trap hook when it observes the armed cross-space page fault.
static M10_FAULT_SEEN: AtomicBool = AtomicBool::new(false);
/// The home-space root PA the trap hook flips to (guarded resume), so the
/// faulting access re-executes where the VA is mapped instead of livelocking.
static M10_FAULT_HOME_ROOT: AtomicU64 = AtomicU64::new(0);

/// x86_64 M10 test VA: `PML4[4]` (= 4 * 2^39), a top-level slot the kernel root
/// never uses (identity `PML4[0]`, M4 user `[1]`, M7 heap `[2]`, M8 LAPIC `[3]`).
#[cfg(target_arch = "x86_64")]
const M10_TEST_VA: u64 = 0x0000_0200_0000_0000;
/// aarch64 M10 test VA: `L1[6]` (= 6 GiB), a top-level slot the kernel root
/// never uses (identity `L1[0..1]`, M3 self-test `[2]`, M4 user `[3]`, M7 heap `[4]`).
#[cfg(target_arch = "aarch64")]
const M10_TEST_VA: u64 = 0x0000_0001_8000_0000;

/// Task G's private magic, written THROUGH the shared test VA under space E.
const MAGIC_E: u64 = 0x1010_1010_1010_100E;
/// Task H's private magic, written THROUGH the shared test VA under space F.
const MAGIC_F: u64 = 0x2020_2020_2020_200F;

// --- M12 agent-runtime bookkeeping (all in THIS forbid-class crate, all safe) -

/// Agent A's KERNEL stack: 4096 usize words (32 KiB), 16-aligned -- the
/// ring0/EL1 stack a timer IRQ taken at ring3/EL0 lands on (TSS.rsp0 / SP_EL1).
static STACK_AGENT_A: TaskStack<4096> = TaskStack::new();
/// Agent B's KERNEL stack.
static STACK_AGENT_B: TaskStack<4096> = TaskStack::new();
/// M13 agent C's KERNEL stack (born-with-home substrate witness).
static STACK_AGENT_C: TaskStack<4096> = TaskStack::new();
/// M13 agent D's KERNEL stack (per-agent isolation witness).
static STACK_AGENT_D: TaskStack<4096> = TaskStack::new();

// --- M14.2 blocking-recv bookkeeping (all in THIS forbid-class crate, all safe) -

/// M14.2: the SENDER kernel task's stack (slot 11, the ONLY free MAX_TASKS slot).
/// It delivers the sentinel that wakes the boot receiver parked off the run queue.
static STACK_BLK_SENDER: TaskStack<4096> = TaskStack::new();

/// M14.2: the agent slot the sender sends FROM (agent_c), stashed for `blk_sender`.
static SEND_AGENT_SLOT: AtomicUsize = AtomicUsize::new(usize::MAX);
/// M14.2: the raw endpoint handle the sender sends ON (agent_c's `ep_a`).
static SEND_EP_RAW: AtomicU64 = AtomicU64::new(0);
/// M14.2: the boot task's slot, so the sender can poll `task_is_blocked(boot)`.
static BLK_BOOT_SLOT: AtomicUsize = AtomicUsize::new(usize::MAX);
/// M14.2: set by the sender ONLY after it observed the receiver parked OFF the
/// run queue (`task_is_blocked(boot)==true`) -- the direct "off the run queue"
/// witness, established BEFORE the wake-causing send.
static RECV_BLOCKED_OBSERVED: AtomicBool = AtomicBool::new(false);
/// M14.2: set by the sender right after its wake-causing send completes.
static BLK_SENT_DONE: AtomicBool = AtomicBool::new(false);

/// M14.2: the distinctive sentinel the sender delivers and the woken receiver
/// must observe. A directional C->D value, so an echo/wrong-ring bug surfaces as
/// a wrong payload or a hang -- a loud failure, never a silent pass.
const M14B_SENTINEL: u64 = 0xB10C_CED5;

/// Agent A's manifest grants: a read/write/recall memory home + a readable
/// budget. NO `EMIT_EXTERNAL` / `INVOKE_MODEL`, so its emit-external syscall is
/// `Denied` (least privilege is the manifest's OMISSION, not a runtime check).
static MANIFEST_A_CAPS: [tb_hal::CapGrant; 2] = [
    tb_hal::CapGrant {
        kind: tb_hal::caps::ObjKind::MemoryHome,
        rights: tb_hal::caps::Rights::READ
            .union(tb_hal::caps::Rights::WRITE)
            .union(tb_hal::caps::Rights::RECALL),
    },
    tb_hal::CapGrant {
        kind: tb_hal::caps::ObjKind::Budget,
        rights: tb_hal::caps::Rights::READ,
    },
];
/// Agent A's static manifest -- the ONLY input to its spawn (capability confinement).
static MANIFEST_A: tb_hal::AgentManifest = tb_hal::AgentManifest {
    name: "agent-a",
    caps: &MANIFEST_A_CAPS,
    wants_memory_home: true,
};

/// Agent B's manifest grants: a read/recall memory home + a readable budget.
/// Also omits `EMIT_EXTERNAL` / `INVOKE_MODEL`.
static MANIFEST_B_CAPS: [tb_hal::CapGrant; 2] = [
    tb_hal::CapGrant {
        kind: tb_hal::caps::ObjKind::MemoryHome,
        rights: tb_hal::caps::Rights::READ.union(tb_hal::caps::Rights::RECALL),
    },
    tb_hal::CapGrant {
        kind: tb_hal::caps::ObjKind::Budget,
        rights: tb_hal::caps::Rights::READ,
    },
];
/// Agent B's static manifest.
static MANIFEST_B: tb_hal::AgentManifest = tb_hal::AgentManifest {
    name: "agent-b",
    caps: &MANIFEST_B_CAPS,
    wants_memory_home: true,
};

/// Set by the trap hook when the child agent's root faults on the parent-only
/// VA (cross-space isolation proof, reusing the M10 armed-fault mechanism).
static M12_CHILD_FAULTED: AtomicBool = AtomicBool::new(false);

/// x86_64 parent-only VA: `PML4[5]`, vacant in the kernel half AND in every
/// agent root (an agent only ever adds a private `PML4[4]` leaf), so an agent
/// read of it faults.
#[cfg(target_arch = "x86_64")]
const M12_PARENT_VA: u64 = 0x0000_0280_0000_0000;
/// aarch64 parent-only VA: `L1[7]` (= 7 GiB), likewise vacant in every agent root.
#[cfg(target_arch = "aarch64")]
const M12_PARENT_VA: u64 = 0x0000_0001_C000_0000;

/// The parent's private magic at `M12_PARENT_VA`, read back after the guarded
/// resume to prove the child saw the parent's frame only via the hook's flip.
const MAGIC_PARENT: u64 = 0x9090_9090_9090_9012;

/// Involuntary switches required before the M12 verdict -- proves both ring3/EL0
/// agents genuinely lost the CPU to the timer (the first user-mode preemption).
const M12_REQUIRED_SWITCHES: u64 = 60;

/// Boot entry. Reached by EITHER of tb-hal's two x86_64 entries (or the
/// aarch64 `_start`); each sets up a stack and places the boot-info pointer in
/// SysV arg0 before calling here:
///   * PVH (`_start`, QEMU/Firecracker): `rdi` = `hvm_start_info` phys addr.
///   * tb-boot v0 (`_tb_start`, the project's `tb-vmm`): `rdi` = guest-physical
///     `tb_boot::TbBootInfo` addr (identity-mapped; magic-validated below).
///   * aarch64 (`_start`): `x0` = FDT blob (MV is an x86_64-first follow-up).
#[unsafe(no_mangle)]
pub extern "C" fn rust_main(boot_info: usize) -> ! {
    // --- M8 in-guest timing: sample the cycle counter at the EARLIEST point --
    // A pure register read (x86_64 `rdtsc` / aarch64 `CNTPCT_EL0`, needs no
    // init); paired with a second read just after the M8 marker to print a
    // guest-only `boot-cycles` delta spanning the whole M0..M8 self-test — the
    // honest, VMM-independent figure (see docs/BENCHMARKS.md). Still unsafe-free.
    let boot_c0 = tb_hal::read_cycle_counter();

    // --- M0 proof (kept verbatim): serial first-light ----------------------
    tb_hal::serial_init();

    // --- MV / tb-boot v0: announce the contract IFF tb-vmm booted us -------
    // On the tb-boot path `boot_info` is the guest-physical address of an
    // identity-mapped `tb_boot::TbBootInfo` whose magic validates; on the PVH
    // path it is an `hvm_start_info` pointer whose magic does NOT match, so we
    // silently skip (fail-closed; never misread). tb-hal performs the single
    // guarded raw read of the pointer — this `#![forbid(unsafe_code)]`-class
    // crate only compares the returned magic against `tb_boot::TB_BOOT_MAGIC`.
    // Printing this is OPTIONAL and does NOT gate M0-M4: the PVH regression path
    // skips it and emits the same markers below.
    if tb_hal::read_boot_magic(boot_info) == Some(tb_boot::TB_BOOT_MAGIC) {
        tb_hal::serial_write_str("tb-boot: contract v0 OK\n");
    }

    tb_hal::serial_write_str("hello from rust_main\n");
    // DIAG: surface the boot-entry EL + monitor flag as the second serial
    // line, so any runner where the EL2 track silently skips is immediately
    // diagnosable from the log (entry-el=0x2 el2=0x1 is the real-EL2 path).
    #[cfg(target_arch = "aarch64")]
    {
        tb_hal::serial_write_str("boot: entry-el=");
        write_hex_u64(tb_hal::boot_entry_el() as u64);
        tb_hal::serial_write_str(" el2=");
        write_hex_u64(tb_hal::booted_at_el2() as u64);
        tb_hal::serial_write_byte(b"
"[0]);
        // DIAG (#65, probe P2): paint the boot-stack + EL2-stack red-zones
        // before ANY deeper call chain or timer tick; `dispatch_irq` and the
        // milestone checkpoints below re-check them (one-time loud line on
        // the first breach, silence on a healthy run).
        tb_hal::stack_redzone_init();
    }

    // Clean guest-only BOOT-TO-READY figure: `rust_main` entry -> serial up
    // (M0 done), BEFORE any M1.. self-test runs. This is the unikernel-class
    // "first guest instruction -> ready" number for honest cross-system
    // comparison (Unikraft ~1 ms / OSv ~4-5 ms, guest-only). It is VMM-
    // independent and is NOT the `boot-cycles` line below, which deliberately
    // spans the entire M0..M8 self-test and is therefore NOT a boot figure.
    let boot_ready = tb_hal::read_cycle_counter();
    tb_hal::serial_write_str("boot-ready-cycles=");
    write_hex_u64(boot_ready.wrapping_sub(boot_c0));
    tb_hal::serial_write_byte(b'\n');

    // x86_64 boot-benchmark instrumentation (the FAIR, self-certifying axes of
    // docs/BENCHMARKS.md §2). Two emissions, BOTH at the M0-ready point, BEFORE
    // any M1.. self-test, and BOTH confined to x86_64 (aarch64 has no PIO and
    // already prints its `CNTFRQ_EL0` base elsewhere):
    //   1. `tsc-base-hz=0x..` — the MEASURED invariant-TSC base (CPUID leaf
    //      0x15). `rdtsc` ticks at this rate, NOT the core GHz, so the harness
    //      divides `boot-ready-cycles` by THIS, never an inferred GHz. `0x0`
    //      means the leaf reported zeros (older CPU / hypervisor) — the harness
    //      then treats the wall-time as unknown rather than fabricating one.
    //   2. `out 0x510, al` — the host-observable boot-ready signal (Firecracker
    //      `--boot-timer` analog). A watching `tb-vmm --report-spawn` timestamps
    //      spawn→ready at this exact instant; QEMU drops the unclaimed PIO write
    //      benignly. tb-hal owns both the `cpuid` and the `out` asm; the kernel
    //      stays `#![forbid(unsafe_code)]` and only branches on the returned u64.
    #[cfg(target_arch = "x86_64")]
    {
        tb_hal::serial_write_str("tsc-base-hz=");
        write_hex_u64(tb_hal::tsc_base_hz());
        tb_hal::serial_write_byte(b'\n');
        tb_hal::boot_ready_signal();
    }

    // --- M1 proof (kept): install traps, take a breakpoint, resume ---------
    tb_hal::install_traps();
    tb_hal::set_trap_hook(trap_hook);
    tb_hal::serial_write_str("trap-test: triggering breakpoint\n");
    tb_hal::breakpoint(); // int3 (x86_64) / brk #0 (aarch64); hook -> Resume
    tb_hal::serial_write_str("trap-test: resumed past breakpoint\n");
    tb_hal::serial_write_str("M1: traps OK\n");

    // --- M2 proof (kept): cooperative context-switch ping-pong -------------
    tb_hal::serial_write_str("ctx-test: starting ping-pong\n");
    BOOT_TASK_RAW.store(tb_hal::current_task().raw(), Ordering::Release);
    let task_a = tb_hal::task_create(STACK_A.take(), task_a_main);
    let task_b = tb_hal::task_create(STACK_B.take(), task_b_main);
    TASK_A_RAW.store(task_a.raw(), Ordering::Release);
    TASK_B_RAW.store(task_b.raw(), Ordering::Release);
    tb_hal::yield_to(task_a);

    // Fail-closed gate: the ONLY legal way back here is task A's post-verdict
    // hand-off. Anything else (a stray yield to slot 0) is an M2 failure.
    if !M2_PASSED.load(Ordering::Acquire) {
        fail("bootstrap context resumed before the M2 verdict");
    }

    // --- M3: MMU bring-up + map/remap self-test ----------------------------
    tb_hal::serial_write_str("mmu-test: init\n");
    tb_hal::mmu_init();
    tb_hal::serial_write_str("mmu-test: enabled, serial alive\n");
    if tb_hal::mmu_selftest() {
        tb_hal::serial_write_str("M3: mmu OK\n"); // <-- the M3 DoD marker
    } else {
        tb_hal::serial_write_str("M3: FAIL\n");
        tb_hal::fail_exit();
    }

    // --- M4: user/ring boundary -- drop to ring3/EL0, syscall, trap back ----
    // tb-hal maps USER-accessible code + stack pages (M3 mmu layer + USER
    // permission bits), drops the CPU to unprivileged mode at a tiny user
    // stub, the stub issues ONE syscall (int 0x80 / svc #0) that traps back
    // into the kernel, the safe handler records it (+ its magic arg) and the
    // CPU returns here. user_demo() is true iff the syscall was seen from user
    // mode with arg == 0xCAFE. All the new unsafe/asm lives in tb-hal; this
    // forbid(unsafe_code)-class crate only branches on the bool.
    tb_hal::serial_write_str("user-test: entering unprivileged mode\n");
    if tb_hal::user_demo() {
        tb_hal::serial_write_str("M4: user/ring OK\n"); // <-- the M4 DoD marker
    } else {
        tb_hal::serial_write_str("M4: FAIL\n");
        // #65 fix: fail-closed AND fail-fast -- exit the harness nonzero now
        // (a missing M4 marker used to ride to the wall-clock ceiling).
        tb_hal::fail_exit();
    }

    // --- M5: bring `alloc` online via a #[global_allocator] over a .bss arena --
    // tb-hal owns the from-scratch free-list allocator + the fixed static arena
    // and exposes a SAFE facade; this forbid(unsafe_code)-class crate only lays
    // the heap down with heap_init(), then exercises the GLOBAL allocator through
    // real `alloc` types (Box / Vec / BTreeMap / String), proves freed memory is
    // REUSED, and asserts nothing leaked (used-bytes returns to the post-init
    // baseline). All raw pointer math + the unsafe GlobalAlloc impl live in
    // tb-hal. DoD marker: "M5: alloc OK".
    tb_hal::serial_write_str("alloc-test: bringing heap online\n");
    tb_hal::heap_init();

    // Local fail helper: emit the M5 failure verdict over serial and park the
    // core (diverges). Matches the M2 `fail` style; uses only safe serial calls.
    let m5_fail = |why: &str| -> ! {
        tb_hal::serial_write_str("M5: FAIL ");
        tb_hal::serial_write_str(why);
        tb_hal::serial_write_byte(b'\n');
        tb_hal::fail_exit()
    };

    // A freshly-initialised heap has handed out zero bytes.
    let base_used = tb_hal::heap_used_bytes();
    if base_used != 0 {
        m5_fail("post-init heap not empty");
    }

    // Box: a single heap allocation + deref + drop.
    {
        let boxed = Box::new(0xABCD_1234_5678_9ABCu64);
        if *boxed != 0xABCD_1234_5678_9ABC {
            m5_fail("Box value corrupted");
        }
        if tb_hal::heap_used_bytes() == base_used {
            m5_fail("Box did not allocate");
        }
    } // boxed dropped -> its block returns to the free list

    // Vec grown WELL past its first realloc: capacity starts at 0, so 1024 pushes
    // force several grow-reallocs through GlobalAlloc's (default) realloc path.
    {
        let mut v: Vec<u32> = Vec::new();
        let n: u32 = 1024;
        let mut k: u32 = 0;
        while k < n {
            v.push(k.wrapping_mul(2_654_435_761)); // Knuth multiplicative hash
            k += 1;
        }
        if v.len() != n as usize {
            m5_fail("Vec length wrong");
        }
        if (v.capacity() as u32) < n {
            m5_fail("Vec never grew past its first allocation");
        }
        let mut k2: u32 = 0;
        while k2 < n {
            if v[k2 as usize] != k2.wrapping_mul(2_654_435_761) {
                m5_fail("Vec element corrupted across reallocs");
            }
            k2 += 1;
        }
    } // v dropped

    // BTreeMap: many internal node allocations + ordered lookups.
    {
        let mut map: BTreeMap<u32, u64> = BTreeMap::new();
        let mut k: u32 = 0;
        while k < 512 {
            map.insert(k, ((k as u64).wrapping_mul(1_099_511_628_211)) ^ 0x5A5A);
            k += 1;
        }
        if map.len() != 512 {
            m5_fail("BTreeMap length wrong");
        }
        let mut k2: u32 = 0;
        while k2 < 512 {
            match map.get(&k2) {
                Some(val) if *val == ((k2 as u64).wrapping_mul(1_099_511_628_211)) ^ 0x5A5A => {}
                _ => m5_fail("BTreeMap lookup wrong"),
            }
            k2 += 1;
        }
    } // map dropped

    // String: repeated push_str forces reallocating growth of a byte buffer.
    {
        let mut s = String::new();
        let mut k = 0;
        while k < 128 {
            s.push_str("tabos-");
            k += 1;
        }
        if s.len() != 128 * 6 {
            m5_fail("String length wrong");
        }
        if !s.starts_with("tabos-") || !s.ends_with("tabos-") {
            m5_fail("String content wrong");
        }
    } // s dropped

    // No-leak: every allocation above was dropped, so used-bytes must be back at
    // the post-init baseline, while the high-water mark stayed strictly positive.
    if tb_hal::heap_used_bytes() != base_used {
        m5_fail("leak: used-bytes above baseline after drops");
    }
    if tb_hal::heap_high_water() <= base_used {
        m5_fail("high-water mark never advanced");
    }

    // Reuse proof: a freed allocation's address is handed back out for the next
    // request of the same shape (first-fit over the re-coalesced arena). No
    // `unsafe`: a shared ref cast to a raw pointer to usize is all safe Rust.
    let reuse_addr_1 = {
        let probe = Box::new(0u64);
        (&*probe) as *const u64 as usize
    }; // probe dropped -> block freed + coalesced back
    let reuse_addr_2 = {
        let probe = Box::new(0u64);
        (&*probe) as *const u64 as usize
    };
    if reuse_addr_1 != reuse_addr_2 {
        m5_fail("freed block was not reused");
    }
    if tb_hal::heap_used_bytes() != base_used {
        m5_fail("leak after reuse probe");
    }

    // tb-hal's own low-level self-test (size-0/ZST, over-arena alloc -> null,
    // aligned alloc/dealloc/realloc reuse, neighbour coalescing) — the raw-pointer
    // checks this crate cannot do without `unsafe`, all landing back at baseline.
    if !tb_hal::heap_selftest() {
        m5_fail("tb_hal::heap_selftest failed");
    }
    if tb_hal::heap_used_bytes() != base_used {
        m5_fail("heap_selftest left bytes allocated");
    }

    tb_hal::serial_write_str("M5: alloc OK\n"); // <-- the M5 DoD marker

    // --- M6: physical frame allocator from the active boot memory map -------
    // tb-hal parses the LIVE boot path's memory map (x86_64 PVH
    // `hvm_start_info.memmap` or tb-boot `TbBootInfo` regions; aarch64 the QEMU
    // `virt` map) into an INTRUSIVE FREE-FRAME STACK that hands out / reclaims
    // 4 KiB PHYSICAL frames from usable RAM only — never the kernel image (incl.
    // M5's 2 MiB .bss heap arena), the boot structures, sub-1 MiB, or device
    // MMIO. ALL the raw memmap reads, the linker-symbol image span, and the
    // next-free-PA links written THROUGH each free frame's identity address live
    // in tb-hal; this forbid(unsafe_code)-class crate only calls the safe facade
    // (frame_alloc -> Option<u64 PA>, frame_free, the pmm stats, pmm_selftest)
    // and COMPARES the returned physical addresses — it can never deref a frame.
    // DoD marker: "M6: frame alloc OK".
    tb_hal::serial_write_str("frame-test: parsing boot memory map\n");
    tb_hal::pmm_init(boot_info);

    // Local fail helper: emit the M6 failure verdict and park the core. Matches
    // the M5 `m5_fail` style; uses only safe serial calls.
    let m6_fail = |why: &str| -> ! {
        tb_hal::serial_write_str("M6: FAIL ");
        tb_hal::serial_write_str(why);
        tb_hal::serial_write_byte(b'\n');
        tb_hal::fail_exit()
    };

    // The boot map must yield usable RAM, and a freshly seeded allocator has
    // every usable frame on the free stack: free_count == total_frames ==
    // sum(usable ranges) - reservations (the tb-hal stat).
    let total = tb_hal::pmm_total_frames();
    if total == 0 {
        m6_fail("no usable frames parsed from the boot map");
    }
    if tb_hal::pmm_free_frames() != total {
        m6_fail("post-init free count != total usable frames");
    }

    // (1) Allocate K frames; each PA must be 4 KiB-aligned, inside a usable RAM
    //     range, outside EVERY reservation, and pairwise-disjoint.
    const K: usize = 64;
    let mut frames: Vec<u64> = Vec::with_capacity(K);
    {
        let mut i = 0;
        while i < K {
            match tb_hal::frame_alloc() {
                Some(pa) => {
                    if pa % 4096 != 0 {
                        m6_fail("allocated frame is not 4 KiB-aligned");
                    }
                    if !tb_hal::pmm_addr_in_usable_ram(pa) {
                        m6_fail("allocated frame is outside usable RAM");
                    }
                    if tb_hal::pmm_addr_reserved(pa) {
                        m6_fail("allocated frame overlaps a reservation");
                    }
                    frames.push(pa);
                }
                None => m6_fail("ran out of frames before K allocations"),
            }
            i += 1;
        }
        // Pairwise-disjoint: distinct 4 KiB-aligned PAs cannot overlap.
        let mut a = 0;
        while a < K {
            let mut b = a + 1;
            while b < K {
                if frames[a] == frames[b] {
                    m6_fail("two allocations returned the same frame");
                }
                b += 1;
            }
            a += 1;
        }
    }
    if tb_hal::pmm_free_frames() != total - K {
        m6_fail("free count wrong after K allocations");
    }

    // (2) LIFO reuse: free the most-recently-allocated frame; the next alloc
    //     must hand the SAME physical frame straight back (free-stack pop).
    let last = frames[K - 1];
    if !tb_hal::frame_free(last) {
        m6_fail("free of a valid frame was rejected");
    }
    match tb_hal::frame_alloc() {
        Some(pa) if pa == last => {} // LIFO reuse proven
        Some(_) => m6_fail("free stack did not reuse the just-freed frame (LIFO)"),
        None => m6_fail("alloc after a free returned None"),
    }

    // (3) Fail-closed: reject a double-free, a misaligned free, and a null free.
    if !tb_hal::frame_free(last) {
        m6_fail("free of the re-allocated frame was rejected");
    }
    if tb_hal::frame_free(last) {
        m6_fail("double-free was accepted");
    }
    if tb_hal::frame_free(last + 1) {
        m6_fail("misaligned free was accepted");
    }
    if tb_hal::frame_free(0) {
        m6_fail("null free was accepted");
    }

    // Return the remaining K-1 held frames; the free count must climb back to
    // `total`, proving full reclaim (the seed-count invariant round-trips).
    {
        let mut i = 0;
        while i < K - 1 {
            if !tb_hal::frame_free(frames[i]) {
                m6_fail("reclaim of a held frame was rejected");
            }
            i += 1;
        }
    }
    if tb_hal::pmm_free_frames() != total {
        m6_fail("free count did not return to total after reclaim");
    }

    // (4) tb-hal's own through-the-frame self-test (alloc -> write a magic via
    //     the frame's identity address -> read it back -> free): the raw-memory
    //     check this forbid(unsafe_code)-class crate cannot perform itself.
    if !tb_hal::pmm_selftest() {
        m6_fail("tb_hal::pmm_selftest failed");
    }
    if tb_hal::pmm_free_frames() != total {
        m6_fail("pmm_selftest leaked a frame");
    }

    // (5) Drive the allocator to exhaustion: exactly `total` frames come out,
    //     then frame_alloc fail-closes to None. M7 now FOLLOWS M6 and grows the
    //     kernel heap from real frames, so the drained pool is RECLAIMED here
    //     (collected into a `with_capacity` Vec so the drain itself never
    //     reallocs) and the free count is asserted back to `total` afterwards.
    //     This drain Vec is served from the still-fixed 2 MiB .bss arena (the
    //     window is not enabled until the M7 block below), so it costs
    //     `total * 8` bytes; the M3 identity clamp keeps usable RAM <= ~1 GiB
    //     and the run scripts pin -m 256M / -m 128M, so it sits well inside the
    //     arena (~0.5 MiB / ~0.25 MiB respectively).
    drop(frames);
    let free_before = tb_hal::pmm_free_frames();
    let mut drained: Vec<u64> = Vec::with_capacity(free_before);
    loop {
        match tb_hal::frame_alloc() {
            Some(pa) => {
                if pa % 4096 != 0 {
                    m6_fail("frame from the exhaustion drain is misaligned");
                }
                drained.push(pa);
            }
            None => break,
        }
    }
    if drained.len() != free_before {
        m6_fail("exhaustion drained a different count than the free total");
    }
    if tb_hal::frame_alloc().is_some() {
        m6_fail("frame_alloc handed out a frame past exhaustion");
    }
    if tb_hal::pmm_free_frames() != 0 {
        m6_fail("free count nonzero at full exhaustion");
    }
    // Reclaim the whole pool so M7's growable heap has frames to map.
    {
        let mut i = 0;
        while i < drained.len() {
            if !tb_hal::frame_free(drained[i]) {
                m6_fail("reclaim after the exhaustion drain was rejected");
            }
            i += 1;
        }
    }
    if tb_hal::pmm_free_frames() != total {
        m6_fail("free count did not return to total after the exhaustion reclaim");
    }
    drop(drained);

    tb_hal::serial_write_str("M6: frame alloc OK\n"); // <-- the M6 DoD marker

    // --- M7: frame-backed GROWABLE kernel heap -----------------------------
    // Re-back the M5 free-list with a kernel-only VA window (RW + NX, OUTSIDE
    // the identity map) that GROWS ON DEMAND by pulling 4 KiB frames from the M6
    // allocator and mapping them through the M3 typed page-table layer — lifting
    // the heap off M5's fixed 2 MiB .bss arena. The allocator ALGEBRA (free-list
    // + coalescing + alignment) is byte-for-byte the M5 code; only the backing
    // store + the grow hook changed. ALL the page-table splicing, the frame
    // pulls and the writes THROUGH the mapped window VAs live in tb-hal; this
    // forbid(unsafe_code)-class crate only calls the safe facade, uses `alloc`
    // types, and compares numbers. DoD marker: "M7: heap OK".
    tb_hal::serial_write_str("heap-test: enabling frame-backed growable window\n");

    // Local fail helper (matches the m5_fail / m6_fail style; safe serial only).
    let m7_fail = |why: &str| -> ! {
        tb_hal::serial_write_str("M7: FAIL ");
        tb_hal::serial_write_str(why);
        tb_hal::serial_write_byte(b'\n');
        tb_hal::fail_exit()
    };

    // Baselines: the heap is empty (M5/M6 left used-bytes at 0) and the PMM pool
    // is full again (the M6 exhaustion drain was reclaimed just above).
    let heap_baseline = tb_hal::heap_used_bytes();
    let pmm_baseline = tb_hal::pmm_free_frames();
    if pmm_baseline == 0 {
        m7_fail("no free frames to grow the heap from");
    }

    tb_hal::heap_window_init();

    // A single CONTIGUOUS buffer well past the old 2 MiB arena: 4 MiB of u64
    // (524288 elements) via `with_capacity` forces ONE 4 MiB allocation that the
    // 2 MiB arena physically cannot satisfy — it can only come from the
    // contiguous-VA, frame-backed window (scattered RAM, contiguous VA).
    const BIG: usize = 512 * 1024; // 524288 u64 = 4 MiB, > the old 2 MiB arena
    const STRIDE: u64 = 0x9E37_79B9_7F4A_7C15; // odd => bijective over u64
    {
        let mut v: Vec<u64> = Vec::with_capacity(BIG);
        if v.capacity() < BIG {
            m7_fail("contiguous 4 MiB reservation failed");
        }
        // Write a pattern THROUGH every mapped page, then read it back: any
        // mis-mapped page would #PF / data-abort here (the trap hook halts and
        // the marker never prints) — so a clean readback proves the mapping.
        let mut k: u64 = 0;
        while (k as usize) < BIG {
            v.push(k.wrapping_mul(STRIDE));
            k += 1;
        }
        let mut k2: u64 = 0;
        while (k2 as usize) < BIG {
            if v[k2 as usize] != k2.wrapping_mul(STRIDE) {
                m7_fail("frame-backed buffer corrupted (mis-mapping)");
            }
            k2 += 1;
        }
        if v.len() != BIG {
            m7_fail("contiguous buffer length wrong");
        }
        // The heap grew PAST the old 2 MiB arena...
        if tb_hal::heap_high_water() <= 2 * 1024 * 1024 {
            m7_fail("heap never grew past the 2 MiB arena");
        }
        // ...the growth mapped real frames into the window...
        if tb_hal::heap_window_mapped_bytes() == 0 {
            m7_fail("window mapped no frames for the growth");
        }
        // ...and consumed REAL physical frames from M6 (free count dropped).
        if tb_hal::pmm_free_frames() >= pmm_baseline {
            m7_fail("growth consumed no physical frames");
        }
    } // v dropped -> its 4 MiB returns to the free list (still frame-backed)

    // No HEAP leak: every byte handed out above is back on the free list.
    if tb_hal::heap_used_bytes() != heap_baseline {
        m7_fail("heap leak: used-bytes above baseline after drop");
    }

    // REUSE without consuming fresh frames: the window keeps its frames mapped,
    // so a second 4 MiB allocation must be served from the already-mapped,
    // now-free window region — `pmm_free_frames` must NOT drop any further. This
    // is the strict no-FRAME-leak evidence: the retained frames are REUSABLE,
    // not lost (retention == reuse).
    let pmm_after_first = tb_hal::pmm_free_frames();
    {
        let mut v2: Vec<u64> = Vec::with_capacity(BIG);
        let mut k: u64 = 0;
        while (k as usize) < BIG {
            v2.push(!k.wrapping_mul(STRIDE));
            k += 1;
        }
        let mut k2: u64 = 0;
        while (k2 as usize) < BIG {
            if v2[k2 as usize] != !k2.wrapping_mul(STRIDE) {
                m7_fail("reused frame-backed buffer corrupted");
            }
            k2 += 1;
        }
    } // v2 dropped
    if tb_hal::pmm_free_frames() != pmm_after_first {
        m7_fail("second growth consumed fresh frames instead of reusing the window");
    }
    if tb_hal::heap_used_bytes() != heap_baseline {
        m7_fail("heap leak after the reuse pass");
    }

    // Also exercise the REALLOC path (a Vec doubling its capacity) past the
    // arena, proving the grow hook services the UNCHANGED M5 first-fit/coalesce
    // algebra through repeated alloc/free churn — not just one big up-front map.
    {
        let mut v3: Vec<u64> = Vec::new();
        let mut k: u64 = 0;
        while (k as usize) < BIG {
            v3.push(k ^ STRIDE);
            k += 1;
        }
        if v3.len() != BIG {
            m7_fail("realloc-grown vector length wrong");
        }
        if (v3.capacity() as u64) < BIG as u64 {
            m7_fail("realloc-grown vector never grew past one page");
        }
        let mut k2: u64 = 0;
        while (k2 as usize) < BIG {
            if v3[k2 as usize] != (k2 ^ STRIDE) {
                m7_fail("realloc-grown vector corrupted across reallocs");
            }
            k2 += 1;
        }
    } // v3 dropped
    if tb_hal::heap_used_bytes() != heap_baseline {
        m7_fail("heap leak after the realloc pass");
    }

    // FRAME accounting (growable design that RETAINS its window frames): grow()
    // pulled real frames from M6 — `pmm_free_frames` dropped below the M6
    // baseline — and the heap KEEPS them mapped for reuse, so the count does NOT
    // climb back to `pmm_baseline`. That is NOT a leak: every pulled frame is
    // either a live page-table frame or a data frame owned by the window's free
    // list, and the reuse pass above proved those frames are handed back out.
    // M5's own no-leak metric (heap used-bytes == baseline, asserted above) is
    // what proves nothing was lost at the allocator level; the M5 algebra has
    // no give-back hook by design (the spec-sanctioned "keeps its frames" case).
    if tb_hal::pmm_free_frames() >= pmm_baseline {
        m7_fail("window unexpectedly returned all frames (frame accounting)");
    }

    tb_hal::serial_write_str("M7: heap OK\n"); // <-- the M7 DoD marker

    // --- M8: async interrupt + monotonic timer tick (NO scheduler) ---------
    // Bring up the interrupt controller (x86_64 LAPIC / aarch64 GICv2) + a
    // periodic timer and take the kernel's FIRST asynchronous interrupt (M0..M7
    // ran fully masked behind cli / DAIF.I), resuming the EXACT interrupted
    // instruction with every register intact — proven by a register-integrity
    // canary that runs across many ticks while an AtomicU64 tick counter
    // advances; the timer is then masked again. NO scheduler is touched (that is
    // M9). ALL the controller pokes, the first `sti` / `daifclr`, the IRQ entry
    // asm and the cycle counter live in tb-hal; this forbid(unsafe_code)-class
    // crate only calls the safe facade and branches on the bool. DoD: "M8: timer OK".
    tb_hal::serial_write_str("timer-test: taking the first async interrupt\n");

    // Local fail helper (matches the m5_fail / m6_fail / m7_fail style; safe only).
    let m8_fail = |why: &str| -> ! {
        tb_hal::serial_write_str("M8: FAIL ");
        tb_hal::serial_write_str(why);
        tb_hal::serial_write_byte(b'\n');
        tb_hal::fail_exit()
    };

    if !tb_hal::timer_demo() {
        m8_fail("no ticks observed or register/state corruption across an IRQ");
    }
    // The monotonic tick counter advanced under the async timer.
    if tb_hal::tick_count() == 0 {
        m8_fail("tick counter did not advance");
    }

    tb_hal::serial_write_str("M8: timer OK\n"); // <-- the M8 DoD marker

    // In-guest timing: ENTRY -> here is a pure guest-only span (rdtsc / CNTPCT),
    // the defensible benchmark figure (docs/BENCHMARKS.md §5). Printed AFTER the
    // marker so the marker stays the exact cumulative DoD string.
    let boot_c1 = tb_hal::read_cycle_counter();
    tb_hal::serial_write_str("boot-cycles=");
    write_hex_u64(boot_c1.wrapping_sub(boot_c0));
    tb_hal::serial_write_byte(b'\n');

    // --- M9: preemptive scheduler (involuntary full-context switch) ---------
    // On a timer tick the kernel INVOLUNTARILY switches kernel tasks: a task
    // that never voluntarily `yield_to`s still loses the CPU. The M8 tick path
    // now calls a SAFE round-robin `schedule()` and tb-hal performs the switch
    // FROM INTERRUPT CONTEXT by REUSING M2's `ctx_switch` UNCHANGED -- the IRQ
    // entry (`__alltraps` / `__vec_irq`) already saved the FULL interrupted
    // frame on each task's own kernel stack, so the cooperative switch only has
    // to swap the callee-saved continuation that returns INTO the IRQ epilogue,
    // whose `iretq`/`eret` restores the full frame at the interrupted
    // instruction. M2's cooperative ping-pong re-ran UNCHANGED above and printed
    // "M2: context-switch OK", proving no regression. ALL the unsafe/asm lives
    // in tb-hal; this crate only drives the safe scheduler facade + reads
    // counters. DoD marker: "M9: preempt OK".
    tb_hal::serial_write_str("preempt-test: arming round-robin preemption\n");

    // Local fail helper (matches the m5_fail..m8_fail style; safe serial only).
    let m9_fail = |why: &str| -> ! {
        tb_hal::serial_write_str("M9: FAIL ");
        tb_hal::serial_write_str(why);
        tb_hal::serial_write_byte(b'\n');
        tb_hal::fail_exit()
    };

    // Register the boot task (the current context) as the first runnable entry,
    // point the M8 tick hook at schedule() BEFORE arming the timer (decision 5),
    // and spawn two no-yield spin tasks. Round-robin order becomes
    // boot -> C -> D -> boot, so the boot task periodically REGAINS the CPU to
    // observe the switch count and render the verdict (decision 3); the spin
    // tasks never disable interrupts, so the timer keeps firing and the rotation
    // never deadlocks.
    tb_hal::scheduler_init();
    tb_hal::set_irq_hook(tb_hal::schedule);
    // DIAG (#65, probe P6): snapshot the just-registered IRQ-hook word; the
    // checkpoint after the wait loop re-compares it (drift = the IRQ_HOOK
    // static, transmute-called on EVERY tick, was stomped).
    let m9_hook_expected = tb_hal::irq_hook_raw();
    let _ = tb_hal::scheduler_spawn(STACK_C.take(), spin_c);
    let _ = tb_hal::scheduler_spawn(STACK_D.take(), spin_d);

    // The number of INVOLUNTARY switches that proves preemption. At the M8 ~1 ms
    // tick this lands in ~100 ms -- far inside the 15 s QEMU / 30 s tb-vmm cap.
    const REQUIRED_SWITCHES: u64 = 100;
    // Fail-closed bound on a DEAD timer. Rather than a raw spin cap (which under
    // TCG can out-run the 15 s runner cap before it trips), the wait below
    // watches the M8 tick counter for STAGNATION: a live timer keeps
    // `tick_count()` climbing, so the stall counter resets every slice; only a
    // timer that never fires lets it reach STALL_LIMIT, yielding a clean
    // "M9: FAIL" well inside the runner window. STALL_LIMIT sits far above the
    // spins one ~1 ms tick slice can do, so it never trips on a healthy boot.
    const STALL_LIMIT: u64 = 100_000_000;

    // GO: re-arm the periodic timer (M8 left it masked after its canary) and
    // unmask interrupts. From here a tick drives schedule() from IRQ context.
    tb_hal::timer_rearm();

    // The boot task spins until enough INVOLUNTARY switches have happened. Each
    // tick preempts whoever runs; the boot task loses the CPU to C/D and later
    // resumes HERE through the IRQ epilogue, so this loop is its own re-entry
    // point and observes the count climb across its time slices. Fail-closed on
    // tick STAGNATION: `last_ticks`/`stalled` reset whenever `tick_count()`
    // advances, so only a dead timer lets `stalled` reach STALL_LIMIT and break
    // early into the "M9: FAIL" path below.
    let mut last_ticks = tb_hal::tick_count();
    let mut stalled: u64 = 0;
    // DIAG (#65, probe P4): count the boot task's OWN loop iterations across
    // the armed window. On a healthy run the boot task gets real slices, so
    // iterations per observed switch are large; a tick-storm/livelock run
    // shows the switch count climbing while this counter crawls (the
    // zero-progress-slice signature). Rendered as one deterministic line
    // after the disarm below.
    let mut m9_iters: u64 = 0;
    while tb_hal::involuntary_switch_count() < REQUIRED_SWITCHES {
        core::hint::spin_loop();
        m9_iters = m9_iters.wrapping_add(1);
        let now = tb_hal::tick_count();
        if now != last_ticks {
            last_ticks = now;
            stalled = 0;
        } else {
            stalled = stalled.wrapping_add(1);
            if stalled >= STALL_LIMIT {
                break;
            }
        }
    }

    // STOP: mask interrupts + disarm the timer so the verdict + marker render in
    // the boot context with no further preemption (decision 7: timer masked
    // BEFORE the marker).
    tb_hal::timer_disarm();

    // DIAG (#65): the M9-window checkpoint -- one deterministic line per run
    // (boot-loop iterations, total ticks, IRQ-hook integrity), plus a stack
    // red-zone sweep. The line prints on healthy runs too (like boot-cycles=)
    // so CI logs always carry the slice-progress + hook-integrity reading.
    tb_hal::serial_write_str("m9: diag iters=");
    write_hex_u64(m9_iters);
    tb_hal::serial_write_str(" ticks=");
    write_hex_u64(tb_hal::tick_count());
    tb_hal::serial_write_str(" ihook=");
    tb_hal::serial_write_str(if tb_hal::irq_hook_raw() == m9_hook_expected {
        "ok"
    } else {
        "BAD"
    });
    #[cfg(target_arch = "aarch64")]
    {
        // Measured stack headroom (bytes between each stack's bottom and its
        // deepest dirty word): the near-overflow question becomes a NUMBER,
        // comparable incremental-vs-noinc and local-vs-CI.
        tb_hal::serial_write_str(" bsfree=");
        write_hex_u64(tb_hal::boot_stack_headroom());
        tb_hal::serial_write_str(" e2free=");
        write_hex_u64(tb_hal::el2_stack_headroom());
    }
    tb_hal::serial_write_byte(b'\n');
    #[cfg(target_arch = "aarch64")]
    tb_hal::stack_redzone_check();

    let switches = tb_hal::involuntary_switch_count();
    let c_ran = SPIN_C_COUNT.load(Ordering::Relaxed);
    let d_ran = SPIN_D_COUNT.load(Ordering::Relaxed);

    // Optional diagnostic (does NOT gate the grep): how many involuntary
    // switches landed. Printed BEFORE the marker, like M8's boot-cycles line.
    tb_hal::serial_write_str("preempt: involuntary switches=");
    write_hex_u64(switches);
    tb_hal::serial_write_byte(b'\n');

    if switches < REQUIRED_SWITCHES {
        m9_fail("too few involuntary switches (timer never preempted)");
    }
    if c_ran == 0 {
        m9_fail("spin task C never advanced");
    }
    if d_ran == 0 {
        m9_fail("spin task D never advanced");
    }

    tb_hal::serial_write_str("M9: preempt OK\n"); // <-- the M9 DoD marker

    // --- M10: per-entity address spaces (memory isolation) -----------------
    // Each schedulable entity runs in its OWN top-level page table, so one
    // entity cannot read/write another's private memory, while the KERNEL half
    // (code, these stacks, the heap, serial) stays mapped across every switch:
    // tb-hal's `address_space_new` COPIES the whole live kernel root into each
    // space, so the kernel half is shared by reference and survives any flip.
    // The address-space switch FOLDS INTO `yield_to` via each task's assigned
    // space (TASK_AS). tb-hal owns ALL the unsafe -- the table copy/walk, the
    // CR3/TTBR0 writes, the raw VA derefs, the cross-space fault recovery; this
    // forbid(unsafe_code)-class crate only drives the safe facade + branches.
    // The design is SYMMETRIC across arches (no TTBR1/TTBR0 split) and does NOT
    // touch `mmu_init`, so "M3: mmu OK" above is unchanged. DoD: "M10: addrspace OK".
    //
    // PRECONDITION (load-bearing): the timer is DISARMED here -- M9's
    // `timer_disarm()` ran before the "M9: preempt OK" marker above -- so this
    // whole block runs single-threaded with interrupts masked. The manual
    // `address_space_switch` calls below, and the boot task's deliberately
    // unmaintained `TASK_AS[0]` (it stays the sentinel 0 while it switches roots
    // by hand), are only safe single-threaded: a stray tick-driven `schedule()`
    // would flip the root under the boot task mid-probe. Do NOT re-arm the timer
    // before this block.
    tb_hal::serial_write_str("addrspace-test: building two private address spaces\n");

    let m10_fail = |why: &str| -> ! {
        tb_hal::serial_write_str("M10: FAIL ");
        tb_hal::serial_write_str(why);
        tb_hal::serial_write_byte(b'\n');
        tb_hal::fail_exit()
    };

    // (1) Two fresh address spaces, each a COPY of the live kernel root.
    let space_e = match tb_hal::address_space_new() {
        Some(s) => s,
        None => m10_fail("address_space_new (E) out of frames"),
    };
    let space_f = match tb_hal::address_space_new() {
        Some(s) => s,
        None => m10_fail("address_space_new (F) out of frames"),
    };
    if space_e.root_pa() == space_f.root_pa() {
        m10_fail("the two spaces share a root table");
    }

    // (2) Two DISTINCT private frames, mapped at the SAME test VA in each space.
    //     The VA lives in a top-level slot the kernel root never uses, so the
    //     private leaf lands ONLY in that space (the copied kernel half and the
    //     other space are untouched).
    let frame_e = match tb_hal::frame_alloc() {
        Some(p) => p,
        None => m10_fail("no frame for space E's private page"),
    };
    let frame_f = match tb_hal::frame_alloc() {
        Some(p) => p,
        None => m10_fail("no frame for space F's private page"),
    };
    if frame_e == frame_f {
        m10_fail("private frames are not distinct");
    }
    if !tb_hal::map_in_space(space_e, M10_TEST_VA, frame_e, true) {
        m10_fail("map_in_space (E) failed");
    }
    if !tb_hal::map_in_space(space_f, M10_TEST_VA, frame_f, true) {
        m10_fail("map_in_space (F) failed");
    }

    // (3) Two tasks, one per space, exercise the yield_to address-space fold-in:
    //     boot -> G(space E) -> H(space F) -> boot. Each task runs under ITS OWN
    //     root (the fold-in flips it before ctx_switch), writes its private
    //     magic THROUGH the shared test VA and reads back ONLY its own. Serial
    //     working in each task proves the kernel half survived the flip.
    //     Slot budget: boot=0, M2 A=1/B=2, M9 C=3/D=4, M10 G=5/H=6 -> only slot 7
    //     is free under tb-hal's MAX_TASKS=8. Fine for M10 (the terminal
    //     milestone before halt); raise MAX_TASKS before any later milestone
    //     spawns more cumulative kernel tasks, else `task_create` fatals.
    BOOT10_RAW.store(tb_hal::current_task().raw(), Ordering::Release);
    let task_g = tb_hal::task_create(STACK_G.take(), task_g_main);
    let task_h = tb_hal::task_create(STACK_H.take(), task_h_main);
    TASK_G_RAW.store(task_g.raw(), Ordering::Release);
    TASK_H_RAW.store(task_h.raw(), Ordering::Release);
    tb_hal::task_set_address_space(task_g, space_e);
    tb_hal::task_set_address_space(task_h, space_f);
    // Enter G through its stashed handle (symmetric with the H/boot hand-off);
    // the fold-in flips the root boot -> E before ctx_switch, and the
    // G -> H -> boot chain returns control here.
    tb_hal::yield_to(Task::from_raw(TASK_G_RAW.load(Ordering::Acquire)));

    if !G_SEES_OWN.load(Ordering::Acquire) {
        m10_fail("task G did not read its own magic under space E");
    }
    if !H_SEES_OWN.load(Ordering::Acquire) {
        m10_fail("task H did not read its own magic under space F");
    }
    tb_hal::serial_write_str("addrspace: both tasks saw only their own magic\n");

    // (4) Isolation cross-check from the boot task: the SAME VA reads a
    //     DIFFERENT private magic under each root, so neither write leaked into
    //     the other frame. Serial keeps working across each manual switch.
    tb_hal::address_space_switch(space_e);
    if tb_hal::addr_load(M10_TEST_VA) != MAGIC_E {
        m10_fail("space E lost its private magic across switches");
    }
    tb_hal::address_space_switch(space_f);
    if tb_hal::addr_load(M10_TEST_VA) != MAGIC_F {
        m10_fail("space F sees the wrong magic (isolation breach)");
    }
    tb_hal::address_space_switch_default();
    tb_hal::serial_write_str("addrspace: same VA -> different private frame per root\n");

    // (5) Re-assert M3: the M3 self-test VA still reads its post-remap magic
    //     under the default root AND under an entity root, proving the M3
    //     mapping (part of the shared kernel half) survives every switch.
    if !tb_hal::m3_test_va_intact() {
        m10_fail("M3 mapping lost under the default root");
    }
    tb_hal::address_space_switch(space_e);
    let m3_ok_under_e = tb_hal::m3_test_va_intact();
    tb_hal::address_space_switch_default();
    if !m3_ok_under_e {
        m10_fail("M3 mapping not shared into an entity root");
    }

    // (6) Cross-space fault: under the DEFAULT root the test VA is VACANT (its
    //     top-level slot is only ever filled in the entity roots), so reading it
    //     MUST page-fault. The trap hook records the fault and, as a GUARDED
    //     resume, flips the live root to space E (where the VA IS mapped) so the
    //     re-executed read completes and returns space E's magic -- no
    //     livelock, no halt. (Interrupts are masked here: M9 disarmed the timer,
    //     so this whole block is single-threaded.)
    M10_FAULT_HOME_ROOT.store(space_e.root_pa(), Ordering::Release);
    M10_FAULT_VA.store(M10_TEST_VA, Ordering::Release);
    M10_FAULT_SEEN.store(false, Ordering::Release);
    M10_FAULT_ARMED.store(true, Ordering::Release);
    let recovered = tb_hal::addr_load(M10_TEST_VA); // faults -> hook -> resume
    M10_FAULT_ARMED.store(false, Ordering::Release);
    tb_hal::address_space_switch_default(); // undo the hook's recovery switch
    if !M10_FAULT_SEEN.load(Ordering::Acquire) {
        m10_fail("cross-space access did not fault");
    }
    if recovered != MAGIC_E {
        m10_fail("guarded resume read the wrong frame");
    }
    tb_hal::serial_write_str("addrspace: cross-space access faulted and recovered\n");

    tb_hal::serial_write_str("M10: addrspace OK\n"); // <-- the M10 DoD marker

    // --- M11: capability handle table + object registry + agent-native ABI --
    // Every kernel object is reached ONLY through an unforgeable, generation-
    // checked, rights-masked Handle in a per-principal table; unprivileged code
    // reaches the kernel through ONE numbered, capability-checked dispatcher
    // returning a CLOSED SysStatus -- zero ambient authority (no fd/errno/
    // ioctl/path). ALL cap machinery is SAFE Rust (tb_hal::caps, which is
    // forbid(unsafe_code)); the only new unsafe is the per-arch register-lift
    // shim. The timer was disarmed before M9's marker, so the table is touched
    // single-threaded with interrupts masked. DoD marker: "M11: caps OK".
    {
        use tb_hal::caps::{self, Handle, ObjKind, Rights, SyscallArgs, SysStatus};

        // Fail-closed: report which invariant broke and park the core (no M11
        // marker is printed, so the runner's grep fails loudly).
        fn m11_fail(why: &str) -> ! {
            tb_hal::serial_write_str("M11: FAIL ");
            tb_hal::serial_write_str(why);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit()
        }

        // (1) A heap-backed per-principal table; mint the ROOT object as the
        //     FIRST capability so its handle is the deterministic (generation 1,
        //     slot 0) = 0x0000_0001_0000_0000 the ring3/EL0 stub names by const.
        let mut root = caps::HandleTable::with_capacity(8);
        let broad = Rights::READ
            .union(Rights::WRITE)
            .union(Rights::DUP)
            .union(Rights::TRANSFER)
            .union(Rights::REVOKE)
            .union(Rights::SPAWN_AGENT);
        let h_root = match root.mint(ObjKind::Agent, broad) {
            Some(h) => h,
            None => m11_fail("could not mint the root capability"),
        };

        // (2) ABI proof: drive ONE numbered, capability-checked syscall FROM
        //     ring3/EL0 through the new register-lift shim, then feed the lifted
        //     call to the SAFE dispatcher and require Ok -- no fd/errno crossed
        //     the boundary, only a (method, handle) the kernel re-validates.
        //     `caps_user_probe` also fails closed unless the stub presented the
        //     deterministic root handle, a second check beside the assert below.
        let lifted = match tb_hal::caps_user_probe(h_root.raw()) {
            Some(a) => a,
            None => m11_fail("ring3 numbered syscall did not reach the dispatcher"),
        };
        if lifted.method != caps::M_OBJECT_INSPECT || lifted.handle != h_root {
            m11_fail("register-lift shim mis-marshalled the numbered syscall");
        }
        if caps::dispatch(&mut root, &lifted).status != SysStatus::Ok {
            m11_fail("dispatcher rejected a valid ring3 capability invocation");
        }
        tb_hal::serial_write_str("caps: ring3 numbered dispatcher returned Ok\n");

        // (3) The capability algebra matrix -- kernel-side safe Rust (the proof).
        //     (a) unknown method -> BadMethod (closed method set).
        if caps::dispatch(&mut root, &SyscallArgs::call(0xDEAD, h_root)).status
            != SysStatus::BadMethod
        {
            m11_fail("unknown method was not BadMethod");
        }
        //     (b) a handle that names no slot -> BadCap (out of range).
        if caps::dispatch(
            &mut root,
            &SyscallArgs::call(caps::M_OBJECT_INSPECT, Handle::from_raw(0x0000_0001_0000_0007)),
        )
        .status
            != SysStatus::BadCap
        {
            m11_fail("dangling handle was not BadCap");
        }
        //     (c) confused-deputy stop: a method whose right the cap lacks ->
        //         Denied (rights live in the slot, not the handle).
        let h_ro = match root.mint(ObjKind::MemoryHome, Rights::READ) {
            Some(h) => h,
            None => m11_fail("could not mint the read-only capability"),
        };
        if caps::dispatch(&mut root, &SyscallArgs::call(caps::M_MEM_WRITE_PROC, h_ro)).status
            != SysStatus::Denied
        {
            m11_fail("missing right was not Denied");
        }
        //     (d) monotonic attenuation: narrow-only, result ALWAYS a subset.
        let narrowed = match root.narrow(h_root, Rights::READ) {
            Some(h) => h,
            None => m11_fail("could not attenuate the root capability"),
        };
        let r_narrow = match root.rights_of(narrowed) {
            Some(r) => r,
            None => m11_fail("attenuated handle did not resolve"),
        };
        let r_root = match root.rights_of(h_root) {
            Some(r) => r,
            None => m11_fail("root handle did not resolve"),
        };
        if !r_narrow.is_subset_of(r_root) {
            m11_fail("attenuation widened rights");
        }
        //     (e) revoke = generation bump -> the SAME handle is now Stale
        //         (O(1) use-after-revoke).
        let h_victim = match root.mint(ObjKind::Generic, Rights::READ) {
            Some(h) => h,
            None => m11_fail("could not mint the revoke-victim capability"),
        };
        if root.revoke(h_victim) != SysStatus::Ok {
            m11_fail("revoke of a held capability failed");
        }
        if caps::dispatch(&mut root, &SyscallArgs::call(caps::M_OBJECT_INSPECT, h_victim)).status
            != SysStatus::Stale
        {
            m11_fail("revoked handle was not Stale");
        }
        //     (f) transfer = MOVE across principals: source goes Stale, the
        //         destination gets a fresh handle to the same object.
        let mut child = caps::HandleTable::with_capacity(4);
        let moved = match root.transfer_to(narrowed, &mut child) {
            Some(h) => h,
            None => m11_fail("transfer to the child principal failed"),
        };
        if caps::dispatch(&mut root, &SyscallArgs::call(caps::M_OBJECT_INSPECT, narrowed)).status
            != SysStatus::Stale
        {
            m11_fail("transferred-from handle was still valid");
        }
        if caps::dispatch(&mut child, &SyscallArgs::call(caps::M_OBJECT_INSPECT, moved)).status
            != SysStatus::Ok
        {
            m11_fail("transferred handle was not usable in the destination");
        }
        //     (g) object-table exhaustion is a closed status, never a panic.
        let mut tiny = caps::HandleTable::with_capacity(1);
        if tiny.mint(ObjKind::Generic, Rights::READ).is_none() {
            m11_fail("first mint into a capacity-1 table failed");
        }
        if tiny.mint(ObjKind::Generic, Rights::READ).is_some() {
            m11_fail("over-capacity mint was not refused");
        }
        tb_hal::serial_write_str("caps: attenuate/transfer/revoke/ObjFull algebra holds\n");
    }

    tb_hal::serial_write_str("M11: caps OK\n"); // <-- the M11 DoD marker

    // --- M12: the agent runtime -- AgentProcess as a first-class OS entity ----
    // Root spawns TWO agents, each in its OWN address space (M10) holding ONLY
    // its manifest-declared handles (M11), scheduled PREEMPTIVELY in ring3/EL0
    // (M9 + the user-mode preemption plumbing) and born with a memory-home handle
    // (M13 substrate later). The self-test proves, end to end: born-with memory
    // (witness #1 kernel-side + witness #2 user-side), involuntary USER-mode
    // preemption (the timer round-robins both ring3/EL0 agents), a permitted
    // capability-checked syscall (Ok) and a non-manifest one (Denied), and a
    // child fault on a parent-only VA recovered in the trap hook. The kernel
    // stays unsafe-free: every privileged step is a safe tb-hal facade call.
    // DoD marker: "M12: agent OK".
    {
        fn m12_fail(why: &str) -> ! {
            tb_hal::serial_write_str("M12: FAIL ");
            tb_hal::serial_write_str(why);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit()
        }

        // PHASE 0 -- spawn (timer still disarmed). Reset the run queue to {boot};
        // each `agent_spawn` mints its address space + handle table (born-with
        // memory_home/bootstrap/budget + the manifest grants), fabricates the
        // user-launch frame, maps its user code/stack and ENQUEUES it.
        tb_hal::scheduler_init();
        tb_hal::set_irq_hook(tb_hal::schedule);
        // DIAG (#65, probe P6): snapshot the registered hook word for the
        // heartbeat + post-window integrity re-compare (see M9).
        let m12_hook_expected = tb_hal::irq_hook_raw();
        tb_hal::agent_traps_init();
        let agent_a = tb_hal::agent_spawn(&MANIFEST_A, STACK_AGENT_A.take());
        let agent_b = tb_hal::agent_spawn(&MANIFEST_B, STACK_AGENT_B.take());

        // Witness #1 (kernel-side, BEFORE either agent has run a single
        // instruction): each agent's table already resolves its memory-home and
        // bootstrap handles -> born-with memory with ZERO setup syscalls.
        if !tb_hal::agent_born_ok(agent_a) || !tb_hal::agent_born_ok(agent_b) {
            m12_fail("an agent was not born holding its memory-home/bootstrap handles");
        }
        tb_hal::serial_write_str("agent: both agents born with memory-home + bootstrap (zero setup)\n");

        // PHASE 1 -- preemptive round-robin in ring3/EL0 (the user-preemption
        // proof). Re-arm the timer: for the FIRST time, USER tasks are
        // involuntarily preempted. Each agent's stub makes a PERMITTED
        // capability-checked syscall (inspect its memory home -> Ok) and a
        // NON-MANIFEST one (emit-external -> Denied), then spins so ONLY the
        // timer can take the CPU.
        let switches_before = tb_hal::involuntary_switch_count();
        tb_hal::timer_rearm();
        let mut stall: u64 = 0;
        const STALL_LIMIT: u64 = 800_000_000;
        loop {
            let sw = tb_hal::involuntary_switch_count().wrapping_sub(switches_before);
            let done = sw >= M12_REQUIRED_SWITCHES
                && tb_hal::agent_permitted_ok(agent_a)
                && tb_hal::agent_permitted_ok(agent_b)
                && tb_hal::agent_denied_ok(agent_a)
                && tb_hal::agent_denied_ok(agent_b);
            if done {
                break;
            }
            stall += 1;
            if stall == 100_000_000 || stall == 400_000_000 {
                // Progress heartbeat: a wall-clock-ceiling death inside this
                // wait now leaves a diagnosable line (switch count + pending
                // agent flags) instead of a silent stall. DIAG (#65, P5/P6):
                // extended with the IRQ-hook integrity bit and (aarch64) the
                // BOOTED_AT_EL2 flag, so a manifestation-1-class stall also
                // reports whether the scheduler hook / EL2 flag were stomped.
                tb_hal::serial_write_str("m12: waiting sw=");
                write_hex_u64(sw);
                tb_hal::serial_write_str(" flags=");
                tb_hal::serial_write_byte(if tb_hal::agent_permitted_ok(agent_a) { b"1"[0] } else { b"0"[0] });
                tb_hal::serial_write_byte(if tb_hal::agent_permitted_ok(agent_b) { b"1"[0] } else { b"0"[0] });
                tb_hal::serial_write_byte(if tb_hal::agent_denied_ok(agent_a) { b"1"[0] } else { b"0"[0] });
                tb_hal::serial_write_byte(if tb_hal::agent_denied_ok(agent_b) { b"1"[0] } else { b"0"[0] });
                tb_hal::serial_write_str(" ihook=");
                tb_hal::serial_write_str(if tb_hal::irq_hook_raw() == m12_hook_expected {
                    "ok"
                } else {
                    "BAD"
                });
                #[cfg(target_arch = "aarch64")]
                {
                    tb_hal::serial_write_str(" el2=");
                    write_hex_u64(tb_hal::booted_at_el2() as u64);
                }
                tb_hal::serial_write_byte(b"
"[0]);
            }
            if stall > STALL_LIMIT {
                tb_hal::timer_disarm();
                m12_fail("agents did not reach the preemption + cap-check goal in time");
            }
            core::hint::spin_loop();
        }
        tb_hal::timer_disarm(); // STOP before the verdict (like M9)
        // DIAG (#65): the M12-window checkpoint (mirrors the M9 one).
        tb_hal::serial_write_str("m12: diag ihook=");
        tb_hal::serial_write_str(if tb_hal::irq_hook_raw() == m12_hook_expected {
            "ok"
        } else {
            "BAD"
        });
        tb_hal::serial_write_byte(b'\n');
        #[cfg(target_arch = "aarch64")]
        tb_hal::stack_redzone_check();
        let switches = tb_hal::involuntary_switch_count().wrapping_sub(switches_before);

        if !tb_hal::agent_permitted_ok(agent_a) || !tb_hal::agent_permitted_ok(agent_b) {
            m12_fail("an agent's permitted capability syscall was not observed Ok");
        }
        if !tb_hal::agent_denied_ok(agent_a) || !tb_hal::agent_denied_ok(agent_b) {
            m12_fail("a non-manifest capability syscall was not Denied (TB_ENOTCAPABLE)");
        }
        if switches < M12_REQUIRED_SWITCHES {
            m12_fail("too few involuntary switches (user-mode preemption did not occur)");
        }
        tb_hal::serial_write_str("agent: permitted syscall Ok + non-manifest syscall Denied (both agents)\n");
        tb_hal::serial_write_str("agent: involuntary user-mode switches=");
        write_hex_u64(switches);
        tb_hal::serial_write_byte(b'\n');

        // PHASE 2 -- parent-only-VA fault (timer disarmed, single-threaded; reuse
        // the M10 armed-fault + guarded-resume mechanism). Map M12_PARENT_VA only
        // in a parent space and seed its magic; an agent's root leaves that
        // top-level slot vacant, so a read of it under the child's root faults ->
        // the trap hook records it and flips to the parent space (the access
        // re-executes where the VA IS mapped).
        let parent_space = match tb_hal::address_space_new() {
            Some(s) => s,
            None => m12_fail("no frame for the parent-only address space"),
        };
        let pframe = match tb_hal::frame_alloc() {
            Some(p) => p,
            None => m12_fail("no frame for the parent-only page"),
        };
        if !tb_hal::map_in_space(parent_space, M12_PARENT_VA, pframe, true) {
            m12_fail("could not map the parent-only page");
        }
        tb_hal::address_space_switch(parent_space);
        let seeded = tb_hal::addr_store_load(M12_PARENT_VA, MAGIC_PARENT);
        tb_hal::address_space_switch_default();
        if seeded != MAGIC_PARENT {
            m12_fail("seeding the parent-only page failed");
        }

        let child_root = tb_hal::agent_root_pa(agent_a);
        if child_root == 0 {
            m12_fail("agent A has no address-space root");
        }
        M10_FAULT_HOME_ROOT.store(parent_space.root_pa(), Ordering::Release);
        M10_FAULT_VA.store(M12_PARENT_VA, Ordering::Release);
        M10_FAULT_SEEN.store(false, Ordering::Release);
        M10_FAULT_ARMED.store(true, Ordering::Release);
        tb_hal::address_space_switch_root(child_root); // run under the agent's own root
        let recovered = tb_hal::addr_load(M12_PARENT_VA); // faults -> hook -> resume
        M10_FAULT_ARMED.store(false, Ordering::Release);
        tb_hal::address_space_switch_default(); // undo the hook's recovery switch
        if !M10_FAULT_SEEN.load(Ordering::Acquire) {
            m12_fail("child access to a parent-only VA did not fault (isolation breach)");
        }
        if recovered != MAGIC_PARENT {
            m12_fail("guarded resume read the wrong frame");
        }
        M12_CHILD_FAULTED.store(true, Ordering::Release);
        tb_hal::serial_write_str("agent: child fault on a parent-only VA, recovered in the hook\n");

        // VERDICT -- every M12 invariant must hold together.
        if !(tb_hal::agent_born_ok(agent_a)
            && tb_hal::agent_born_ok(agent_b)
            && tb_hal::agent_permitted_ok(agent_a)
            && tb_hal::agent_permitted_ok(agent_b)
            && tb_hal::agent_denied_ok(agent_a)
            && tb_hal::agent_denied_ok(agent_b)
            && switches >= M12_REQUIRED_SWITCHES
            && M12_CHILD_FAULTED.load(Ordering::Acquire))
        {
            m12_fail("a final M12 invariant did not hold");
        }
    }

    tb_hal::serial_write_str("M12: agent OK\n"); // <-- the M12 DoD marker

    // --- M13: the default tiered, persistent, recallable memory substrate -----
    // Every agent's born-with ObjKind::MemoryHome now carries a REAL per-agent
    // tiered substrate (T0 registers + T1 working graph + T2 episodic journal +
    // T3 lexical semantic store), reached ONLY through the M11 dispatch
    // chokepoint, rights-gated, namespaced memory:private/<agent>. The timer is
    // already disarmed (single-threaded, interrupts masked -- exactly the
    // discipline the substrate's RefCell relies on). Two witnesses: (A) kernel-
    // side, driving caps::dispatch directly with the full [u64;4] encoding, and
    // (B) through the ACTUAL born-with home of freshly spawned agents (proving it
    // is a real per-agent guarantee, not a local toy). DoD marker: "M13: memory OK".
    //
    // M14 NOTE: agent_c / agent_d are spawned HERE, at function scope BEFORE the
    // M13 block, so the M14 IPC self-test (after the M13 marker) can reuse them
    // as the two channel peers WITHOUT consuming extra MAX_TASKS slots. Their
    // slot assignment is unchanged from the green build (WITNESS A spawns nothing).
    let agent_c = tb_hal::agent_spawn(&MANIFEST_A, STACK_AGENT_C.take());
    let agent_d = tb_hal::agent_spawn(&MANIFEST_B, STACK_AGENT_D.take());
    {
        use tb_hal::caps::{self, Handle, ObjKind, Rights, SysStatus};

        fn m13_fail(why: &str) -> ! {
            tb_hal::serial_write_str("M13: FAIL ");
            tb_hal::serial_write_str(why);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit()
        }

        // A capability-checked dispatch against `h` in `tbl` with the full
        // pointer-free [u64;4] inline-arg encoding.
        fn disp(
            tbl: &mut tb_hal::caps::HandleTable,
            h: tb_hal::caps::Handle,
            method: u32,
            a: [u64; 4],
        ) -> tb_hal::caps::SysReturn {
            tb_hal::caps::dispatch(
                tbl,
                &tb_hal::caps::SyscallArgs {
                    method,
                    handle: h,
                    args: a,
                },
            )
        }

        const TOK_K: u64 = 0x1001; // a synthetic query/lexical token id (no embeddings)
        const TOK_J: u64 = 0x1002; // a different token (must NOT match a TOK_K recall)
        const V0: u64 = 0x0000_BEEF; // value scalar; read-back proves instant RYW
        let ok = SysStatus::Ok as u32;

        // ============ WITNESS A -- kernel-side over caps::dispatch ============
        let mut tbl = caps::HandleTable::with_capacity(16);
        let all = Rights::READ
            .union(Rights::WRITE)
            .union(Rights::RECALL)
            .union(Rights::CONSOLIDATE);
        let home = match tbl.mint_memory_home(all) {
            Some(h) => h,
            None => m13_fail("could not mint a memory home with all rights"),
        };

        // 1. WRITE three records (op=ADD). The high-importance + most-recent
        //    TOK_K record (id_win) must win recall; id_old (TOK_K, low imp) is the
        //    runner-up; id_other (TOK_J) must never match a TOK_K query.
        let r_old = disp(&mut tbl, home, caps::M_MEM_WRITE, [0, TOK_K, 0x1111, 3]);
        if r_old.status != SysStatus::Ok {
            m13_fail("write of id_old was not Ok");
        }
        let id_old = r_old.value;
        let r_other = disp(&mut tbl, home, caps::M_MEM_WRITE, [0, TOK_J, 0x2222, 7]);
        if r_other.status != SysStatus::Ok {
            m13_fail("write of id_other was not Ok");
        }
        let r_win = disp(&mut tbl, home, caps::M_MEM_WRITE, [0, TOK_K, V0, 9]);
        if r_win.status != SysStatus::Ok {
            m13_fail("write of id_win was not Ok");
        }
        let id_win = r_win.value;

        // 2. READ-YOUR-WRITES (instant, append-only T2): read id_win -> V0.
        let ryw = disp(&mut tbl, home, caps::M_MEM_READ, [id_win, 0, 0, 0]);
        if ryw.status != SysStatus::Ok || ryw.value != V0 {
            m13_fail("read-your-writes did not return the written value");
        }
        tb_hal::serial_write_str("mem: read-your-writes OK (instant, append-only T2)\n");

        // 3. RECALL (activation-ranked) -> copy-on-retrieve MemoryRecord.
        let rec = disp(&mut tbl, home, caps::M_MEM_RECALL, [TOK_K, 0, 1, 0]);
        if rec.status != SysStatus::Ok {
            m13_fail("activation recall did not return Ok");
        }
        let h_rec = Handle::from_raw(rec.value);
        let insp = disp(&mut tbl, h_rec, caps::M_OBJECT_INSPECT, [0, 0, 0, 0]);
        if insp.status != SysStatus::Ok || insp.value != ObjKind::MemoryRecord as u64 {
            m13_fail("recall handle did not resolve to a MemoryRecord (copy-on-retrieve)");
        }
        let rid = disp(&mut tbl, h_rec, caps::M_MEM_READ, [0, 0, 0, 0]);
        if rid.status != SysStatus::Ok || rid.value != id_win {
            m13_fail("recall did not rank the high-importance recent record first");
        }
        // retrieve_next: the Finsts ring excludes id_win -> advances to id_old.
        let rec2 = disp(&mut tbl, home, caps::M_MEM_RECALL, [TOK_K, 1, 1, 0]);
        if rec2.status != SysStatus::Ok {
            m13_fail("retrieve_next recall did not return Ok");
        }
        let rid2 = disp(&mut tbl, Handle::from_raw(rec2.value), caps::M_MEM_READ, [0, 0, 0, 0]);
        if rid2.status != SysStatus::Ok || rid2.value != id_old || rid2.value == id_win {
            m13_fail("Finsts did not advance to the next candidate (loop not broken)");
        }
        tb_hal::serial_write_str("mem: activation recall ranked + Finsts advanced (id_win -> id_old)\n");

        // 4. CONSOLIDATE (gated SUCCESS -- this home HOLDS CONSOLIDATE).
        let cons = disp(&mut tbl, home, caps::M_MEM_CONSOLIDATE, [0, id_old, 0, 0]);
        if cons.status != SysStatus::Ok || cons.value < 1 {
            m13_fail("gated consolidate (tombstone) did not run");
        }
        tb_hal::serial_write_str("mem: gated consolidate tombstoned a record (CONSOLIDATE right)\n");

        // 5. RIGHTS-DENIED paths (fall straight out of the required_right gate).
        let home_ro = match tbl.mint_memory_home(Rights::READ.union(Rights::RECALL)) {
            Some(h) => h,
            None => m13_fail("could not mint the read-only memory home"),
        };
        if disp(&mut tbl, home_ro, caps::M_MEM_WRITE, [0, TOK_K, 1, 1]).status != SysStatus::Denied {
            m13_fail("WRITE on a home lacking WRITE was not Denied");
        }
        if disp(&mut tbl, home_ro, caps::M_MEM_CONSOLIDATE, [0, 0, 0, 0]).status != SysStatus::Denied {
            m13_fail("CONSOLIDATE on a home lacking CONSOLIDATE was not Denied");
        }
        if disp(&mut tbl, home_ro, 99, [0, 0, 0, 0]).status != SysStatus::BadMethod {
            m13_fail("an unknown method was not BadMethod (closed method set changed)");
        }
        tb_hal::serial_write_str("mem: rights-denied paths Denied + closed method set intact\n");

        // ============ WITNESS B -- through the ACTUAL born-with home ============
        // Spawn two fresh agents; each is BORN with a real substrate behind its
        // memory_home (agent_spawn -> mint_memory_home). The timer stays disarmed,
        // so they never run a user instruction -- we drive their substrate from the
        // kernel through agent_mem_dispatch (the M11 chokepoint). (agent_c /
        // agent_d were spawned at function scope just above this block so the M14
        // IPC self-test can reuse them.)

        let (s, id_c) = match tb_hal::agent_mem_dispatch(agent_c, caps::M_MEM_WRITE, 0, TOK_K, V0, 5)
        {
            Some(x) => x,
            None => m13_fail("agent C is not a live agent"),
        };
        if s != ok {
            m13_fail("agent C WRITE to its born-with home was not Ok");
        }
        let (s, v) = tb_hal::agent_mem_dispatch(agent_c, caps::M_MEM_READ, id_c, 0, 0, 0)
            .unwrap_or((SysStatus::BadCap as u32, 0));
        if s != ok || v != V0 {
            m13_fail("agent C read-your-writes failed on its born-with home");
        }
        let (s, _h) = tb_hal::agent_mem_dispatch(agent_c, caps::M_MEM_RECALL, TOK_K, 0, 1, 0)
            .unwrap_or((SysStatus::BadCap as u32, 0));
        if s != ok {
            m13_fail("agent C recall failed on its born-with home");
        }
        let (s, _) = tb_hal::agent_mem_dispatch(agent_c, caps::M_MEM_CONSOLIDATE, 0, id_c, 0, 0)
            .unwrap_or((ok, 0));
        if s != SysStatus::Denied as u32 {
            m13_fail("agent C consolidate was not Denied (born-with home lacks CONSOLIDATE)");
        }
        // per-agent isolation: agent D's substrate cannot see agent C's record.
        let (s, v) = tb_hal::agent_mem_dispatch(agent_d, caps::M_MEM_READ, id_c, 0, 0, 0)
            .unwrap_or((SysStatus::BadCap as u32, 0));
        if s == ok && v == V0 {
            m13_fail("agent D read agent C's private memory (per-agent isolation breach)");
        }
        tb_hal::serial_write_str(
            "agent: born-with home is a real per-agent substrate (write/recall Ok, consolidate Denied, isolated)\n",
        );
    }

    tb_hal::serial_write_str("M13: memory OK\n"); // <-- the M13 DoD marker

    // --- M14: inter-agent IPC -- capability-passing channels + ordered streams --
    // Two agents communicate over an ORDERED, BOUNDED, BIDIRECTIONAL message
    // stream; a message can CARRY a capability MOVED from the sender's HandleTable
    // into the receiver's (the M11 transfer_to move split across the ring --
    // rights ride intact, attenuated cross-agent first via M_HANDLE_NARROW), all
    // through the single M11 dispatch chokepoint. The timer is disarmed (single-
    // core, interrupts masked -- exactly the discipline the channel's RefCell
    // rings rely on). We reuse the already-born agent_c (side 0, sender) +
    // agent_d (side 1, receiver) as the two peers (no extra task slots).
    //
    // The disarmed-timer self-test observes the CLOSED-STATUS form
    // (WouldBlock / PeerClosed) DIRECTLY; the recv-blocks-off-the-runqueue /
    // send-wakes-peer scheduler round-trip is the additive Step-2 layer the same
    // milestone wires but a disarmed-timer self-test cannot exercise. The real
    // variable-length BYTE payload (copy_to_user) is the ONLY M14 unsafe and is
    // deliberately DEFERRED -- this marker rides the inline-scalar payload with
    // the cap moved by handle, at ZERO new unsafe. DoD marker: "M14: ipc OK".
    {
        use tb_hal::caps::{self, Handle, ObjKind, Rights, SysStatus};

        fn m14_fail(why: &str) -> ! {
            tb_hal::serial_write_str("M14: FAIL ");
            tb_hal::serial_write_str(why);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit()
        }

        let ok = SysStatus::Ok as u32;
        let wb = SysStatus::WouldBlock as u32;
        let den = SysStatus::Denied as u32;
        let badcap = SysStatus::BadCap as u32;
        let badmethod = SysStatus::BadMethod as u32;
        let stale = SysStatus::Stale as u32;
        let peerclosed = SysStatus::PeerClosed as u32;
        let rd = Rights::READ.bits();
        let wr = Rights::WRITE.bits();

        // 1. CONNECT one bounded (cap=2) channel: ep_a (side 0) in C, ep_b
        //    (side 1) in D, sharing ONE Rc<Channel>.
        let (ep_a, ep_b) = match tb_hal::agent_channel_connect(agent_c, agent_d, 2) {
            Some(x) => x,
            None => m14_fail("channel connect failed"),
        };

        // 2. MINT a carried cap in C with READ|WRITE|TRANSFER, then NARROW it
        //    (mask READ|TRANSFER) -> drops WRITE: the derived-narrowed capability.
        let cap0 = match tb_hal::agent_mint_generic(
            agent_c,
            Rights::READ.union(Rights::WRITE).union(Rights::TRANSFER),
        ) {
            Some(h) => h,
            None => m14_fail("mint carried cap failed"),
        };
        let narrow_mask = Rights::READ.union(Rights::TRANSFER).bits() as u64;
        let (s, cap_h_raw) =
            tb_hal::agent_cap_dispatch(agent_c, caps::M_HANDLE_NARROW, cap0, narrow_mask, 0)
                .unwrap_or((badcap, 0));
        if s != ok || cap_h_raw == 0 {
            m14_fail("narrow of the carried cap was not Ok");
        }
        let cap_h = Handle::from_raw(cap_h_raw);

        // 3. SEND #1 (cap-carrying, payload 0xCAFE) C -> D.
        let (s, _) =
            tb_hal::agent_chan_send(agent_c, ep_a, 0xCAFE, cap_h_raw).unwrap_or((badcap, 0));
        if s != ok {
            m14_fail("cap-carrying send #1 was not Ok");
        }
        // The carried cap is now STALE in C ("A no longer can"): consumed on write.
        let (s, _) = tb_hal::agent_cap_dispatch(agent_c, caps::M_OBJECT_INSPECT, cap_h, 0, 0)
            .unwrap_or((ok, 0));
        if s != stale {
            m14_fail("carried cap was not STALE in the sender after send (move did not consume)");
        }

        // 4. SEND #2 (bytes-only, payload 0xF00D) -- fills the bound-2 outbox.
        let (s, _) = tb_hal::agent_chan_send(agent_c, ep_a, 0xF00D, 0).unwrap_or((badcap, 0));
        if s != ok {
            m14_fail("bytes-only send #2 was not Ok");
        }

        // 5. RECV #1 in D: FIFO head 0xCAFE, carrying the moved cap.
        let (s, payload, moved_raw) =
            tb_hal::agent_chan_recv_full(agent_d, ep_b).unwrap_or((badcap, 0, 0));
        if s != ok || payload != 0xCAFE || moved_raw == 0 {
            m14_fail("recv #1 did not deliver payload 0xCAFE with a moved cap");
        }
        let moved = Handle::from_raw(moved_raw);
        // D USES the moved cap: a READ-gated inspect -> Ok, right ObjKind.
        let (s, kind) = tb_hal::agent_cap_dispatch(agent_d, caps::M_OBJECT_INSPECT, moved, 0, 0)
            .unwrap_or((badcap, 0));
        if s != ok || kind != ObjKind::Generic as u64 {
            m14_fail("receiver could not USE the moved cap (inspect failed / wrong kind)");
        }
        // ATTENUATION held CROSS-AGENT: the pre-send narrow dropped WRITE.
        let mr = tb_hal::agent_rights_of(agent_d, moved).unwrap_or(0);
        if (mr & rd) == 0 || (mr & wr) != 0 {
            m14_fail("moved cap rights not attenuated cross-agent (want READ kept, WRITE dropped)");
        }

        // 6. FIFO: RECV #2 -> 0xF00D, no cap (proves 0xCAFE was delivered FIRST).
        let (s, payload, moved2) =
            tb_hal::agent_chan_recv_full(agent_d, ep_b).unwrap_or((badcap, 0, 0));
        if s != ok || payload != 0xF00D || moved2 != 0 {
            m14_fail("recv #2 broke per-direction FIFO (expected 0xF00D, no cap)");
        }
        tb_hal::serial_write_str("ipc: FIFO + capability moved + attenuated cross-agent\n");

        // 7. EMPTY inbox, peer still open -> WouldBlock.
        let (s, _, _) = tb_hal::agent_chan_recv_full(agent_d, ep_b).unwrap_or((badcap, 0, 0));
        if s != wb {
            m14_fail("recv on an empty-but-open inbox was not WouldBlock");
        }

        // 8. DENIED / non-channel paths (outbox has space; NONE of these enqueue).
        //    (a) M_CHAN_SEND on a NON-channel object (Generic w/ WRITE): passes
        //        the WRITE gate, the body sees chan==None -> BadCap.
        let gen_w = match tb_hal::agent_mint_generic(agent_c, Rights::READ.union(Rights::WRITE)) {
            Some(h) => h,
            None => m14_fail("mint non-channel WRITE cap failed"),
        };
        let (s, _) = tb_hal::agent_chan_send(agent_c, gen_w, 0, 0).unwrap_or((ok, 0));
        if s != badcap {
            m14_fail("M_CHAN_SEND on a non-channel object was not BadCap");
        }
        //    (b) endpoint NARROWed to drop WRITE -> Denied at the required_right gate.
        let (s, epa_no_w_raw) =
            tb_hal::agent_cap_dispatch(agent_c, caps::M_HANDLE_NARROW, ep_a, rd as u64, 0)
                .unwrap_or((badcap, 0));
        if s != ok || epa_no_w_raw == 0 {
            m14_fail("narrow of ep_a (drop WRITE) failed");
        }
        let (s, _) = tb_hal::agent_chan_send(agent_c, Handle::from_raw(epa_no_w_raw), 0xAA, 0)
            .unwrap_or((ok, 0));
        if s != den {
            m14_fail("send on a WRITE-less endpoint was not Denied");
        }
        //    (c) carried cap lacking TRANSFER -> Denied (checked before any detach).
        let cap_no_t = match tb_hal::agent_mint_generic(agent_c, Rights::READ) {
            Some(h) => h,
            None => m14_fail("mint no-TRANSFER cap failed"),
        };
        let (s, _) =
            tb_hal::agent_chan_send(agent_c, ep_a, 0xBB, cap_no_t.raw()).unwrap_or((ok, 0));
        if s != den {
            m14_fail("sending a cap lacking TRANSFER was not Denied");
        }
        //    (d) sending an endpoint into its OWN channel -> Denied (Zircon NOT_SUPPORTED).
        let (s, _) = tb_hal::agent_chan_send(agent_c, ep_a, 0xCC, ep_a.raw()).unwrap_or((ok, 0));
        if s != den {
            m14_fail("sending an endpoint into its own channel was not Denied");
        }
        //    (e) unknown method 33 -> BadMethod (the closed method set is intact;
        //        28..=31 are now the M15 block methods, so probe a still-free number).
        let (s, _) = tb_hal::agent_cap_dispatch(agent_c, 33, ep_a, 0, 0).unwrap_or((ok, 0));
        if s != badmethod {
            m14_fail("an unknown channel method was not BadMethod");
        }

        // 9. BACKPRESSURE + ATOMICITY: fill C's outbox to the bound (2), then a
        //    cap-carrying send -> WouldBlock with the carried cap NOT stranded.
        let (s, _) = tb_hal::agent_chan_send(agent_c, ep_a, 0x1, 0).unwrap_or((badcap, 0));
        if s != ok {
            m14_fail("backpressure fill #1 was not Ok");
        }
        let (s, _) = tb_hal::agent_chan_send(agent_c, ep_a, 0x2, 0).unwrap_or((badcap, 0));
        if s != ok {
            m14_fail("backpressure fill #2 was not Ok");
        }
        let cap2 = match tb_hal::agent_mint_generic(agent_c, Rights::READ.union(Rights::TRANSFER)) {
            Some(h) => h,
            None => m14_fail("mint atomicity cap failed"),
        };
        let (s, _) = tb_hal::agent_chan_send(agent_c, ep_a, 0x3, cap2.raw()).unwrap_or((ok, 0));
        if s != wb {
            m14_fail("cap-carrying send into a full outbox was not WouldBlock");
        }
        // ATOMICITY: the carried cap is STILL live in C (never detached).
        let (s, _) = tb_hal::agent_cap_dispatch(agent_c, caps::M_OBJECT_INSPECT, cap2, 0, 0)
            .unwrap_or((stale, 0));
        if s != ok {
            m14_fail("WouldBlock send STRANDED the carried cap (atomicity broken)");
        }
        tb_hal::serial_write_str(
            "ipc: full channel WouldBlock + non-channel BadCap + denied paths\n",
        );

        // 10. PEER-CLOSED (fire-and-forget): D closes its endpoint; a send from C
        //     now sees the peer gone -> PeerClosed.
        let (s, _) = tb_hal::agent_cap_dispatch(agent_d, caps::M_CHAN_CLOSE, ep_b, 0, 0)
            .unwrap_or((badcap, 0));
        if s != ok {
            m14_fail("closing the receiver endpoint was not Ok");
        }
        let (s, _) = tb_hal::agent_chan_send(agent_c, ep_a, 0x9, 0).unwrap_or((ok, 0));
        if s != peerclosed {
            m14_fail("send to a closed peer was not PeerClosed");
        }
        tb_hal::serial_write_str("ipc: peer-closed surfaces PeerClosed (fire-and-forget close)\n");
    }

    tb_hal::serial_write_str("M14: ipc OK\n"); // <-- the M14 DoD marker

    // --- M14.1: byte-payload IPC -- copy_to_user/copy_from_user round-trip ----
    // A message can now ALSO carry a variable-length BYTE payload, copied across
    // two agents' ISOLATED address spaces: the sender's bytes are pulled into a
    // kernel-heap bounce buffer by copy_from_user at send, and pushed into the
    // receiver's OWN address space by copy_to_user at recv. The two raw copy
    // primitives' unsafe lives ONLY in crates/tb-hal/src/arch/*/uaccess.rs; the
    // kernel orchestrates through the SAFE agent_chan_send_bytes /
    // agent_chan_recv_bytes facades (each resolves its agent's address-space
    // root). The timer is disarmed (single-core, interrupts masked). We reuse
    // agent_c (sender) + agent_d (receiver); a FRESH channel is opened because
    // the M14 block above left its channel peer-closed. The positive proof is a
    // 1024-byte known pattern minted in agent_c's user buffer that round-trips
    // byte-for-byte into agent_d's user buffer through a DISTINCT physical frame;
    // the fail-closed proofs are an oversize send (Denied), a copy_to_user to an
    // unmapped dst (Fault, message re-deliverable), a too-small recv buffer
    // (Fault, no-discard), and a WRITE-less endpoint (Denied). DoD sub-marker:
    // "M14.1: payload OK".
    {
        use tb_hal::caps::{self, Handle, Rights, SysStatus};

        fn m14_1_fail(why: &str) -> ! {
            tb_hal::serial_write_str("M14.1: FAIL ");
            tb_hal::serial_write_str(why);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit()
        }

        let ok = SysStatus::Ok as u32;
        let den = SysStatus::Denied as u32;
        let fault = SysStatus::Fault as u32;

        // A deterministic, per-word non-trivial pattern (Fibonacci-hashing
        // constant -> 128 distinct words across the 1024-byte payload).
        let pat = |i: u64| -> u64 { 0x9E37_79B9_7F4A_7C15u64.wrapping_mul(i.wrapping_add(1)) };
        const LEN: usize = 1024;
        const NWORDS: u64 = (LEN as u64) / 8;

        // 1. A FRESH bounded (cap=4) channel: ep0 (side 0) in agent_c, ep1
        //    (side 1) in agent_d, sharing one Rc<Channel>.
        let (ep0, ep1) = match tb_hal::agent_channel_connect(agent_c, agent_d, 4) {
            Some(x) => x,
            None => m14_1_fail("byte-payload channel connect failed"),
        };

        // 2. Map a writable USER buffer into BOTH agents' OWN address spaces.
        let (buf_c, pa_c) = match tb_hal::agent_map_user_buffer(agent_c) {
            Some(x) => x,
            None => m14_1_fail("map user buffer into the sender failed"),
        };
        let (buf_d, pa_d) = match tb_hal::agent_map_user_buffer(agent_d) {
            Some(x) => x,
            None => m14_1_fail("map user buffer into the receiver failed"),
        };
        // The two buffers MUST live in DISTINCT physical frames (a genuine cross-
        // address-space transfer, never an alias of one frame).
        if pa_c == pa_d {
            m14_1_fail("sender and receiver buffers share a PA (no real cross-space copy)");
        }

        // 3. SEED the sender's frame with the pattern through ITS frame's kernel
        //    identity alias (PA == VA in the boot identity / RAM-gigabyte window),
        //    and ZERO the receiver's frame so a stale-byte false match is
        //    impossible.
        let mut i = 0u64;
        while i < NWORDS {
            let _ = tb_hal::addr_store_load(pa_c + i * 8, pat(i));
            let _ = tb_hal::addr_store_load(pa_d + i * 8, 0);
            i += 1;
        }

        // 4. SEND the 1024-byte payload agent_c -> agent_d (copy_from_user pulls
        //    it into the kernel bounce buffer).
        let (s, _) =
            tb_hal::agent_chan_send_bytes(agent_c, ep0, 0x5A5A, 0, buf_c, LEN).unwrap_or((den, 0));
        if s != ok {
            m14_1_fail("byte-payload send was not Ok");
        }
        // 5. RECV into agent_d's OWN buffer (copy_to_user pushes it across the
        //    space); expect Ok, the inline payload, no moved cap, 1024 bytes.
        let (s, payload, moved, blen) =
            tb_hal::agent_chan_recv_bytes(agent_d, ep1, buf_d, LEN).unwrap_or((den, 0, 0, 0));
        if s != ok || payload != 0x5A5A || moved != 0 || blen != LEN {
            m14_1_fail("byte-payload recv did not deliver (Ok, 0x5A5A, no cap, 1024 bytes)");
        }
        // 6. VERIFY byte-for-byte: read agent_d's frame back through ITS identity
        //    alias and assert equality with the sent pattern.
        let mut i = 0u64;
        while i < NWORDS {
            if tb_hal::addr_load(pa_d + i * 8) != pat(i) {
                m14_1_fail("received bytes did not match the sent pattern");
            }
            i += 1;
        }
        tb_hal::serial_write_str(
            "ipc: byte payload copy_to/from_user round-trips across two agent address spaces (distinct PAs)\n",
        );

        // 7. FAIL-CLOSED #1: an oversize send (> MAX_PAYLOAD) is Denied; nothing
        //    is enqueued (the recv chain below stays exact).
        let (s, _) =
            tb_hal::agent_chan_send_bytes(agent_c, ep0, 0, 0, buf_c, 4097).unwrap_or((ok, 0));
        if s != den {
            m14_1_fail("oversize (> MAX_PAYLOAD) byte send was not Denied");
        }

        // 8. FAIL-CLOSED #2: a copy_to_user to an UNMAPPED dst VA faults, and the
        //    message is NOT consumed -- a retry with the GOOD buffer delivers it.
        let (s, _) =
            tb_hal::agent_chan_send_bytes(agent_c, ep0, 0x1234, 0, buf_c, LEN).unwrap_or((den, 0));
        if s != ok {
            m14_1_fail("byte send for the unmapped-dst test was not Ok");
        }
        let bad_dst = buf_d + 0x1000; // the next page in the slot is unmapped
        let (s, _, _, _) =
            tb_hal::agent_chan_recv_bytes(agent_d, ep1, bad_dst, LEN).unwrap_or((ok, 0, 0, 0));
        if s != fault {
            m14_1_fail("recv into an unmapped dst VA was not Fault");
        }
        let (s, _, _, blen) =
            tb_hal::agent_chan_recv_bytes(agent_d, ep1, buf_d, LEN).unwrap_or((den, 0, 0, 0));
        if s != ok || blen != LEN {
            m14_1_fail("the copy-faulted message was not re-deliverable (it was lost)");
        }

        // 9. FAIL-CLOSED #3: a recv whose dst_cap is SMALLER than the queued byte
        //    length faults WITHOUT discarding (Zircon BUFFER_TOO_SMALL); a retry
        //    with a big-enough buffer still delivers it.
        let (s, _) =
            tb_hal::agent_chan_send_bytes(agent_c, ep0, 0x9999, 0, buf_c, LEN).unwrap_or((den, 0));
        if s != ok {
            m14_1_fail("byte send for the too-small-buffer test was not Ok");
        }
        let (s, _, _, _) =
            tb_hal::agent_chan_recv_bytes(agent_d, ep1, buf_d, 512).unwrap_or((ok, 0, 0, 0));
        if s != fault {
            m14_1_fail("recv with dst_cap < queued byte_len was not Fault");
        }
        let (s, _, _, blen) =
            tb_hal::agent_chan_recv_bytes(agent_d, ep1, buf_d, LEN).unwrap_or((den, 0, 0, 0));
        if s != ok || blen != LEN {
            m14_1_fail("the too-small-buffer message was discarded (no-discard violated)");
        }

        // 10. RIGHTS: a byte send on a WRITE-less endpoint is Denied (the payload
        //     send requires WRITE, exactly like the scalar M_CHAN_SEND).
        let (s, ep0_no_w) = tb_hal::agent_cap_dispatch(
            agent_c,
            caps::M_HANDLE_NARROW,
            ep0,
            Rights::READ.bits() as u64,
            0,
        )
        .unwrap_or((den, 0));
        if s != ok || ep0_no_w == 0 {
            m14_1_fail("narrow of the endpoint (drop WRITE) failed");
        }
        let (s, _) =
            tb_hal::agent_chan_send_bytes(agent_c, Handle::from_raw(ep0_no_w), 0, 0, buf_c, 8)
                .unwrap_or((ok, 0));
        if s != den {
            m14_1_fail("byte send on a WRITE-less endpoint was not Denied");
        }
        tb_hal::serial_write_str(
            "ipc: byte payload fail-closed (oversize Denied, copy-fault + too-small no-discard, WRITE-gated)\n",
        );
    }

    tb_hal::serial_write_str("M14.1: payload OK\n"); // <-- the M14.1 DoD sub-marker

    // --- M14.2: blocking-recv wired to the M9 preemptive scheduler -----------
    // The deferred M14 Step-2: a receiver on an EMPTY channel BLOCKS (deschedules
    // OFF the M9 run queue) and is made RUNNABLE again by a sender's delivery
    // (runnable-on-send), LOST-WAKEUP-FREE. Demonstrated with the timer ARMED (the
    // real M9 preemptive path, NOT a synchronous disarmed self-test): the BOOT
    // task is the RECEIVER (it parks off the run queue), and ONE new kernel task
    // in the free slot 11 is the SENDER, over a FRESH agent_c<->agent_d channel.
    // Reuses M12's scheduler_init -> spawn -> timer_rearm -> round-trip ->
    // timer_disarm template. The whole {empty-recheck -> register waiter -> mark
    // BLOCKED -> yield} sequence runs under masked interrupts in tb-hal, so on a
    // single core no send can interleave between the empty-check and the block ->
    // no lost wakeup; a lost wakeup would instead hang -> QEMU/CI timeout (the
    // fail-closed catch). ZERO new unsafe in this crate. DoD sub-marker:
    // "M14.2: blocking-recv OK".
    {
        use tb_hal::caps::SysStatus;

        // PHASE 0 -- reset the run queue to {boot} (so arming the timer does NOT
        // resurrect M2/M9/M10/M12/M13's suspended tasks -- the M12 precedent) and
        // open a FRESH bounded channel between the already-born agent_c (side 0,
        // the SENDER's table) and agent_d (side 1, the RECEIVER's table).
        tb_hal::scheduler_init();
        tb_hal::set_irq_hook(tb_hal::schedule);
        let (ep_a, ep_b) = match tb_hal::agent_channel_connect(agent_c, agent_d, 1) {
            Some(x) => x,
            None => m14b_fail("could not open the blocking-recv channel"),
        };
        // Stash what the sender task needs + the boot slot it polls; reset the
        // observation flags (this region re-runs every boot).
        SEND_AGENT_SLOT.store(agent_c.raw(), Ordering::Release);
        SEND_EP_RAW.store(ep_a.raw(), Ordering::Release);
        BLK_BOOT_SLOT.store(tb_hal::current_task().raw(), Ordering::Release);
        RECV_BLOCKED_OBSERVED.store(false, Ordering::Release);
        BLK_SENT_DONE.store(false, Ordering::Release);

        // PHASE 1 -- spawn the SENDER into the free slot 11, then go preemptible.
        let _sender = tb_hal::scheduler_spawn(STACK_BLK_SENDER.take(), blk_sender);
        let switches_before = tb_hal::involuntary_switch_count();
        tb_hal::timer_rearm();

        // BLOCK: the boot RECEIVER recvs on an EMPTY channel -> it parks OFF the
        // run queue HERE. The sender (slot 11) observes it blocked, delivers
        // M14B_SENTINEL, and the runnable-on-send wake + the armed M9 timer's next
        // schedule() switch this task back in to receive it. A lost wakeup -> this
        // never returns -> QEMU/CI timeout (the intended fail-closed outcome).
        let (st, payload, _moved) = tb_hal::agent_chan_recv_blocking(agent_d, ep_b)
            .unwrap_or((SysStatus::BadCap as u32, 0, 0));

        // STOP before the verdict (the M9/M12 discipline) so no further
        // involuntary switch races the marker output.
        tb_hal::timer_disarm();
        let switches = tb_hal::involuntary_switch_count().wrapping_sub(switches_before);

        if st != SysStatus::Ok as u32 {
            m14b_fail("blocking recv did not return Ok after the wake");
        }
        if payload != M14B_SENTINEL {
            m14b_fail("woken receiver observed the wrong payload (not the sentinel)");
        }
        if !RECV_BLOCKED_OBSERVED.load(Ordering::Acquire) {
            m14b_fail("sender never observed the receiver parked off the run queue");
        }
        if !BLK_SENT_DONE.load(Ordering::Acquire) {
            m14b_fail("sender's delivery did not complete");
        }
        if switches < 1 {
            m14b_fail("no involuntary switch during the block (scheduler did not run other work)");
        }
        tb_hal::serial_write_str("ipc: receiver parked off the run queue, woken by send\n");
    }

    tb_hal::serial_write_str("M14.2: blocking-recv OK\n"); // <-- the M14.2 DoD sub-marker

    // --- M15: shared memory blocks + session blackboard ----------------------
    // A shared-memory BLOCK = one or more pinned M6 frames owned by an
    // ObjKind::Block capability, MAPPED into MULTIPLE agents' address spaces at
    // once (M10 map_in_space) so every member sees the SAME physical bytes (vs
    // M14, which COPIES). Permission is rights-derived at the M11 chokepoint:
    // writable = want && handle_rights.contains(WRITE). The session blackboard is
    // the well-known shared block all members attach; its RECORD plane is a
    // kernel-mediated CAS/versioned store (update-once-visible-everywhere). We
    // reuse the already-born agent_c + agent_d as the two session members (no new
    // task slots). The timer is disarmed (single-core, interrupts masked -- the
    // discipline the safe Block bookkeeping relies on). map_in_space leaves are
    // KERNEL-only, so the marker rides kernel-side I/O under each root (the
    // M10/M13/M14 pattern). ZERO new unsafe. DoD marker: "M15: blocks OK".
    {
        use tb_hal::caps::{self, Handle, Rights, SysStatus};

        fn m15_fail(why: &str) -> ! {
            tb_hal::serial_write_str("M15: FAIL ");
            tb_hal::serial_write_str(why);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit()
        }

        let ok = SysStatus::Ok as u32;
        let den = SysStatus::Denied as u32;
        let badcap = SysStatus::BadCap as u32;
        let badmethod = SysStatus::BadMethod as u32;
        let rd = Rights::READ.bits();
        let block_va = tb_hal::BLOCK_WINDOW_VA;

        // 1. CREATE one 1-page block; Rc-clone a Block handle into BOTH members
        //    (hb_c full RW member, hb_d plain RW member over the SAME core).
        let (hb_c, hb_d) = match tb_hal::agent_block_create(agent_c, agent_d, 1) {
            Some(x) => x,
            None => m15_fail("block create failed"),
        };

        // 2. MAP into BOTH roots at the same VA -- both now translate block_va to
        //    the SAME frame PA in two different address spaces.
        let (s, _) =
            tb_hal::agent_block_map(agent_c, hb_c, true, block_va).unwrap_or((badcap, 0));
        if s != ok {
            m15_fail("map into C not Ok");
        }
        let (s, _) =
            tb_hal::agent_block_map(agent_d, hb_d, true, block_va).unwrap_or((badcap, 0));
        if s != ok {
            m15_fail("map into D not Ok");
        }

        // 3. TRUE SHARING (the north-star): A writes the shared frame under its
        //    OWN root; B reads the SAME bytes under its OWN root. Rides kernel-
        //    side I/O because map_in_space leaves are kernel-only.
        tb_hal::address_space_switch_root(tb_hal::agent_root_pa(agent_c));
        let _ = tb_hal::addr_store_load(block_va, 0xB10C);
        tb_hal::address_space_switch_root(tb_hal::agent_root_pa(agent_d));
        let seen = tb_hal::addr_load(block_va);
        tb_hal::address_space_switch_default();
        if seen != 0xB10C {
            m15_fail("B did not read the bytes A wrote (no true sharing)");
        }
        tb_hal::serial_write_str("blocks: A wrote, B read the SAME bytes (true sharing)\n");

        // 4. RO REJECTION (cap-layer, portable -- CR0.WP=0 makes the hardware RO
        //    write-fault unobservable kernel-side on x86_64): narrow hb_d to drop
        //    WRITE; the RO handle's M_BLOCK_WRITE is Denied at the gate, and its
        //    write-requesting map is downgraded to RO (writable=min(req,rights)).
        let (s, hb_d_ro_raw) =
            tb_hal::agent_block_dispatch(agent_d, caps::M_HANDLE_NARROW, hb_d, rd as u64, 0, 0)
                .unwrap_or((badcap, 0));
        if s != ok || hb_d_ro_raw == 0 {
            m15_fail("narrow hb_d (drop WRITE) failed");
        }
        let hb_d_ro = Handle::from_raw(hb_d_ro_raw);
        let (s, _) =
            tb_hal::agent_block_dispatch(agent_d, caps::M_BLOCK_WRITE, hb_d_ro, 0, 0xDEAD, 0)
                .unwrap_or((ok, 0));
        if s != den {
            m15_fail("RO handle M_BLOCK_WRITE was not Denied");
        }
        let (s, _) = tb_hal::agent_block_map(agent_d, hb_d_ro, true, block_va + 0x1000)
            .unwrap_or((badcap, 0));
        if s != ok {
            m15_fail("RO (downgraded) map not Ok");
        }
        if tb_hal::agent_block_member_writable(agent_d, hb_d_ro, block_va + 0x1000) != Some(false) {
            m15_fail("RO map was not downgraded to RO (writable flag not false)");
        }
        tb_hal::serial_write_str("blocks: RO handle write Denied + map downgraded to RO\n");

        // 5. RECORD-plane blackboard (the well-known shared block both members
        //    attached): C publishes a versioned record; D reads the SAME record
        //    back through the SAME shared Rc<Block> -- update-once-visible-
        //    everywhere via the kernel-mediated CAS store.
        let (s, _) =
            tb_hal::agent_block_dispatch(agent_c, caps::M_BLOCK_WRITE, hb_c, 0, 0x1234, 0)
                .unwrap_or((badcap, 0));
        if s != ok {
            m15_fail("C record write not Ok");
        }
        let (s, v) = tb_hal::agent_block_dispatch(agent_d, caps::M_BLOCK_READ, hb_d, 0, 0, 0)
            .unwrap_or((badcap, 0));
        if s != ok || v != 0x1234 {
            m15_fail("D did not read C's record (blackboard not shared)");
        }
        tb_hal::serial_write_str(
            "blocks: C wrote record, D read it (update-once-visible-everywhere)\n",
        );

        // 6. DENIED / NON-BLOCK / BAD-METHOD paths (the closed status surface).
        let gen = match tb_hal::agent_mint_generic(agent_c, Rights::READ.union(Rights::WRITE)) {
            Some(h) => h,
            None => m15_fail("mint generic non-block cap failed"),
        };
        let (s, _) = tb_hal::agent_block_dispatch(agent_c, caps::M_BLOCK_READ, gen, 0, 0, 0)
            .unwrap_or((ok, 0));
        if s != badcap {
            m15_fail("M_BLOCK_READ on a non-block was not BadCap");
        }
        let (s, _) = tb_hal::agent_block_map(agent_c, gen, false, block_va).unwrap_or((ok, 0));
        if s != badcap {
            m15_fail("M_BLOCK_MAP on a non-block was not BadCap");
        }
        let (s, no_read_raw) =
            tb_hal::agent_block_dispatch(agent_c, caps::M_HANDLE_NARROW, hb_c, 0, 0, 0)
                .unwrap_or((badcap, 0));
        if s != ok {
            m15_fail("narrow hb_c to empty rights failed");
        }
        let no_read = Handle::from_raw(no_read_raw);
        let (s, _) =
            tb_hal::agent_block_map(agent_c, no_read, false, block_va).unwrap_or((ok, 0));
        if s != den {
            m15_fail("map with a READ-less block handle was not Denied");
        }
        let (s, _) = tb_hal::agent_block_dispatch(agent_c, 32, hb_c, 0, 0, 0).unwrap_or((ok, 0));
        if s != badmethod {
            m15_fail("unknown block method 32 was not BadMethod");
        }
        tb_hal::serial_write_str(
            "blocks: non-block BadCap + READ-less Denied + bad-method BadMethod\n",
        );
    }

    tb_hal::serial_write_str("M15: blocks OK\n"); // <-- the M15 DoD marker

    // --- M15.1: UNMAP a shared block + RECLAIM its frames (no stale-PTE UAF) ----
    // The inverse of M15's block-map: a block's frames are no longer pinned for
    // the kernel-session lifetime. The OWNER (the cap granted REVOKE at create)
    // unmaps -- tear down EVERY member's leaf PTE + a LOCAL TLB invalidate, POISON
    // the shared core so every outstanding handle goes Stale (the cross-table
    // revoke), then return the frames to the M6 allocator. We PROVE both halves,
    // fail-closed: (a) RECLAMATION -- the free-frame count rises by exactly n_pages
    // AND the next frame_alloc hands back the very PA the block owned; (b) NO STALE
    // ACCESS -- the owner's revoked handle AND the OTHER member's poisoned handle
    // are now Stale through every door (RECORD dispatch + map), and a SAFE page-
    // walk probe shows the old VA maps NOWHERE in either root (so no stale PTE
    // survives). A FRESH 1-page block (clean frame accounting) over the already-
    // born agent_c (owner) + agent_d (member). ZERO new kernel unsafe. DoD marker:
    // "M15.1: unmap OK".
    {
        use tb_hal::caps::{self, Rights, SysStatus};

        fn m151_fail(why: &str) -> ! {
            tb_hal::serial_write_str("M15.1: FAIL ");
            tb_hal::serial_write_str(why);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit()
        }

        let ok = SysStatus::Ok as u32;
        let den = SysStatus::Denied as u32;
        let badcap = SysStatus::BadCap as u32;
        let stale = SysStatus::Stale as u32;
        // A FRESH page in the block window, clear of the session block's maps
        // above (which used BLOCK_WINDOW_VA + 0 and + 0x1000).
        let u_va = tb_hal::BLOCK_WINDOW_VA + 0x8000;

        // 1. CREATE a fresh 1-page block: owner handle (carries REVOKE) into
        //    agent_c, plain member handle (no REVOKE) into agent_d; map into BOTH
        //    roots at u_va so both translate it to the SAME backing frame.
        let (ho, hm) = match tb_hal::agent_block_create(agent_c, agent_d, 1) {
            Some(x) => x,
            None => m151_fail("fresh block create failed"),
        };
        let (s, _) = tb_hal::agent_block_map(agent_c, ho, true, u_va).unwrap_or((badcap, 0));
        if s != ok {
            m151_fail("map owner not Ok");
        }
        let (s, _) = tb_hal::agent_block_map(agent_d, hm, true, u_va).unwrap_or((badcap, 0));
        if s != ok {
            m151_fail("map member not Ok");
        }

        // 2. Name the backing frame, and confirm BOTH roots translate u_va to it
        //    via a PURE page-walk probe (no deref -> no fault).
        let pa = match tb_hal::agent_block_frame_pa(agent_c, ho, 0) {
            Some(p) => p,
            None => m151_fail("could not read block frame PA"),
        };
        if tb_hal::agent_block_va_maps(agent_c, u_va) != Some(pa)
            || tb_hal::agent_block_va_maps(agent_d, u_va) != Some(pa)
        {
            m151_fail("u_va did not map to the block frame in both roots");
        }

        // 3. FAIL-CLOSED authorization, BEFORE any teardown:
        //    (a) a plain member (no REVOKE) cannot unmap -> Denied, and the block
        //        stays fully mapped (the Denied path tore nothing down).
        let (s, _) = tb_hal::agent_block_unmap(agent_d, hm).unwrap_or((ok, 0));
        if s != den {
            m151_fail("member unmap (no REVOKE) was not Denied");
        }
        if tb_hal::agent_block_va_maps(agent_d, u_va) != Some(pa) {
            m151_fail("Denied member unmap still tore the mapping down");
        }
        //    (b) a non-block cap presented to unmap -> BadCap (even WITH REVOKE).
        let gen = match tb_hal::agent_mint_generic(agent_c, Rights::REVOKE) {
            Some(h) => h,
            None => m151_fail("mint generic cap failed"),
        };
        let (s, _) = tb_hal::agent_block_unmap(agent_c, gen).unwrap_or((ok, 0));
        if s != badcap {
            m151_fail("unmap on a non-block cap was not BadCap");
        }
        tb_hal::serial_write_str("unmap: member Denied + non-block BadCap (fail-closed)\n");

        // 4. THE OWNER UNMAP. Snapshot the free-frame count first; the owner
        //    (REVOKE) tears down BOTH roots, poisons the core, reclaims the frame.
        let free_before = tb_hal::pmm_free_frames();
        let (s, n) = tb_hal::agent_block_unmap(agent_c, ho).unwrap_or((badcap, 0));
        if s != ok || n != 1 {
            m151_fail("owner unmap was not Ok(1)");
        }

        // 5a. RECLAMATION: the free count rose by exactly the 1 reclaimed frame,
        //     AND the next frame_alloc hands back that very PA (the free stack is
        //     LIFO and the unmap freed it last). Return it so the pool is left
        //     exactly as the unmap left it (no leak).
        if tb_hal::pmm_free_frames() != free_before + 1 {
            m151_fail("free-frame count did not rise by the reclaimed page");
        }
        match tb_hal::frame_alloc() {
            Some(got) if got == pa => {
                let _ = tb_hal::frame_free(got);
            }
            Some(_) => m151_fail("next frame_alloc did not return the reclaimed block PA"),
            None => m151_fail("frame_alloc returned None after reclamation"),
        }
        tb_hal::serial_write_str(
            "unmap: frame reclaimed -- allocator handed the block PA back out\n",
        );

        // 5b. NO STALE ACCESS: the owner's revoked handle AND the member's poisoned
        //     handle are now Stale through every door (RECORD dispatch + map), and a
        //     SAFE page-walk probe shows u_va maps NOWHERE in either root -- so
        //     neither a stale handle nor a stale PTE can reach the freed frame.
        let (s, _) = tb_hal::agent_block_dispatch(agent_c, caps::M_BLOCK_READ, ho, 0, 0, 0)
            .unwrap_or((ok, 0));
        if s != stale {
            m151_fail("owner's revoked handle READ was not Stale");
        }
        let (s, _) = tb_hal::agent_block_map(agent_c, ho, true, u_va).unwrap_or((ok, 0));
        if s != stale {
            m151_fail("owner's revoked handle re-map was not Stale");
        }
        let (s, _) = tb_hal::agent_block_dispatch(agent_d, caps::M_BLOCK_READ, hm, 0, 0, 0)
            .unwrap_or((ok, 0));
        if s != stale {
            m151_fail("member's poisoned handle READ was not Stale");
        }
        let (s, _) = tb_hal::agent_block_map(agent_d, hm, true, u_va).unwrap_or((ok, 0));
        if s != stale {
            m151_fail("member's poisoned handle re-map was not Stale");
        }
        if tb_hal::agent_block_va_maps(agent_c, u_va).is_some()
            || tb_hal::agent_block_va_maps(agent_d, u_va).is_some()
        {
            m151_fail("old VA still maps after unmap (stale PTE)");
        }
        tb_hal::serial_write_str(
            "unmap: stale owner+member handles Stale + old VA maps nowhere\n",
        );
    }

    tb_hal::serial_write_str("M15.1: unmap OK\n"); // <-- the M15.1 DoD sub-marker

    // --- M16: LLM-agnostic inference bridge -- the model: scheme + ModelSession -
    // An agent invokes a model through a capability (INVOKE_MODEL, M_MODEL_INVOKE)
    // naming the target via a `model:` scheme; a safe in-kernel ROUTER binds a
    // REGISTERED backend behind ONE uniform contract, the backend identity hidden
    // from the agent. We reuse the already-born agent_c (MANIFEST_A omits
    // INVOKE_MODEL, so the success path's right comes from the FACADE grant; the
    // Denied path narrows it away, proving the gate still bites). Two `model:`
    // names bind ONE mock contract = the backend-agnostic proof. Timer is
    // disarmed (single-core, interrupts masked). ZERO new unsafe. Marker:
    // "M16: infer OK".
    {
        use tb_hal::caps::{self, Handle};

        fn m16_fail(why: &str) -> ! {
            tb_hal::serial_write_str("M16: FAIL ");
            tb_hal::serial_write_str(why);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit()
        }

        let ok = caps::SysStatus::Ok as u32;
        let den = caps::SysStatus::Denied as u32;
        let badcap = caps::SysStatus::BadCap as u32;
        let badmethod = caps::SysStatus::BadMethod as u32;
        const PROMPT: u64 = 0x1234_5678;
        let expect = PROMPT ^ 0xA110_C0DE;

        // (1) PARSE: a model: URI parses; a non-model: scheme cleanly rejects.
        if tb_hal::infer::parse_scheme("model:local/llama3").is_none() {
            m16_fail("parse model:local/llama3 None");
        }
        if tb_hal::infer::parse_scheme("memory:x").is_some() {
            m16_fail("parse memory:x was Some");
        }

        // (2) OPEN + INVOKE: model:mock/echo -> session WITH INVOKE_MODEL; the
        // response is the mock's deterministic transform of the inline prompt.
        let (s, sraw) = tb_hal::agent_model_open(agent_c, "model:mock/echo").unwrap_or((badcap, 0));
        if s != ok {
            m16_fail("open model:mock/echo not Ok");
        }
        let sess = Handle::from_raw(sraw);
        let (s, resp) =
            tb_hal::agent_model_dispatch(agent_c, caps::M_MODEL_INVOKE, sess, PROMPT)
                .unwrap_or((badcap, 0));
        if s != ok || resp != expect {
            m16_fail("invoke not deterministic Ok");
        }

        // (3) BACKEND-AGNOSTIC: a 2nd model: name, SAME contract, SAME response --
        // identical agent code, the registered backend swapped behind the prefix.
        let (s, s2raw) =
            tb_hal::agent_model_open(agent_c, "model:local/llama3").unwrap_or((badcap, 0));
        if s != ok {
            m16_fail("open model:local/llama3 not Ok");
        }
        let sess2 = Handle::from_raw(s2raw);
        let (s, resp2) =
            tb_hal::agent_model_dispatch(agent_c, caps::M_MODEL_INVOKE, sess2, PROMPT)
                .unwrap_or((badcap, 0));
        if s != ok || resp2 != expect {
            m16_fail("backend swap changed the contract");
        }

        // (4) DENIED: NARROW the session to drop INVOKE_MODEL (mask 0), then invoke
        // (the M14 epa_no_w / M13 home_ro precedent) -> the gate still bites.
        let (s, nraw) =
            tb_hal::agent_model_dispatch(agent_c, caps::M_HANDLE_NARROW, sess, 0)
                .unwrap_or((badcap, 0));
        if s != ok {
            m16_fail("narrow session to empty rights failed");
        }
        let no_inv = Handle::from_raw(nraw);
        let (s, _) = tb_hal::agent_model_dispatch(agent_c, caps::M_MODEL_INVOKE, no_inv, PROMPT)
            .unwrap_or((ok, 0));
        if s != den {
            m16_fail("invoke without INVOKE_MODEL not Denied");
        }

        // (5) UNKNOWN scheme: a clean closed error, never a panic.
        let (s, _) = tb_hal::agent_model_open(agent_c, "model:vendor/ghost").unwrap_or((ok, 0));
        if s != badcap {
            m16_fail("unknown model: scheme not BadCap");
        }

        // (6) NON-SESSION: M_MODEL_INVOKE on a Generic cap minted WITH INVOKE_MODEL
        // -> BadCap (the payload-None branch).
        let gen = tb_hal::agent_mint_generic(agent_c, caps::Rights::INVOKE_MODEL)
            .unwrap_or_else(|| m16_fail("mint generic INVOKE_MODEL cap failed"));
        let (s, _) = tb_hal::agent_model_dispatch(agent_c, caps::M_MODEL_INVOKE, gen, PROMPT)
            .unwrap_or((ok, 0));
        if s != badcap {
            m16_fail("M_MODEL_INVOKE on a non-session not BadCap");
        }

        // (7) closed-set probe: an unknown method stays BadMethod (M_BLOCK_READ=31
        // is the highest).
        let (s, _) =
            tb_hal::agent_model_dispatch(agent_c, 33, sess, 0).unwrap_or((ok, 0));
        if s != badmethod {
            m16_fail("unknown method 33 not BadMethod");
        }

        tb_hal::serial_write_str(
            "model: parse+route + INVOKE_MODEL gate + backend-agnostic + lifecycle\n",
        );
    }

    tb_hal::serial_write_str("M16: infer OK\n"); // <-- the M16 DoD marker

    // --- M17: sleep-time consolidation / reflection / forgetting daemons ------
    // Three sleep-time memory daemons (CONSOLIDATE / REFLECT / FORGET) realized as
    // ONE bounded maintenance cycle driven through the already-wired
    // M_MEM_CONSOLIDATE=20 method (Rights::CONSOLIDATE), off the critical path.
    // The timer is DISARMED through every self-test (RefCell discipline), so the
    // marker drives the cycle SYNCHRONOUSLY over a WITNESS-A home (the M13 idiom);
    // ZERO new unsafe (all the M17 work is safe mutation of the M13 substrate).
    // DoD marker: "M17: consolidate OK".
    {
        use tb_hal::caps::{self, Handle};

        fn m17_fail(why: &str) -> ! {
            tb_hal::serial_write_str("M17: FAIL ");
            tb_hal::serial_write_str(why);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit()
        }

        // A capability-checked dispatch against `h` in `tbl` (the M13/M16 idiom).
        fn disp(
            tbl: &mut tb_hal::caps::HandleTable,
            h: tb_hal::caps::Handle,
            method: u32,
            a: [u64; 4],
        ) -> tb_hal::caps::SysReturn {
            tb_hal::caps::dispatch(
                tbl,
                &tb_hal::caps::SyscallArgs {
                    method,
                    handle: h,
                    args: a,
                },
            )
        }

        let ok = caps::SysStatus::Ok as u32;
        let den = caps::SysStatus::Denied as u32;
        let badcap = caps::SysStatus::BadCap as u32;
        const TOK_DUP: u64 = 0x2001; // two near-duplicate records share this token
        const TOK_STALE: u64 = 0x2002; // one low-importance/low-utility/stale record
        const TOK_NOISE: u64 = 0x2003; // accumulator + aging fodder (importance 9)
        const V_STALE: u64 = 0x0000_CAFE;
        const V_DUP_A: u64 = 0x0000_00D1;
        const V_DUP_B: u64 = 0x0000_00D2;

        // ============ WITNESS A -- kernel-side over caps::dispatch ============
        let mut tbl = caps::HandleTable::with_capacity(16);
        let all = caps::Rights::READ
            .union(caps::Rights::WRITE)
            .union(caps::Rights::RECALL)
            .union(caps::Rights::CONSOLIDATE);
        let home = match tbl.mint_memory_home(all) {
            Some(h) => h,
            None => m17_fail("could not mint a CONSOLIDATE-righted memory home"),
        };

        // 1. SEED STALE first -> records index 0 (inside the first SWEEP_BATCH
        //    window), importance 1 (low), never recalled (low BLA, low utility).
        let r_stale = disp(&mut tbl, home, caps::M_MEM_WRITE, [0, TOK_STALE, V_STALE, 1]);
        if r_stale.status != caps::SysStatus::Ok {
            m17_fail("seed stale write was not Ok");
        }
        let id_stale = r_stale.value;

        // 2. SEED the near-duplicate pair on TOK_DUP (importance 9). The later
        //    write (id_b, larger t_created) is the deterministic distill survivor.
        let r_a = disp(&mut tbl, home, caps::M_MEM_WRITE, [0, TOK_DUP, V_DUP_A, 9]);
        let r_b = disp(&mut tbl, home, caps::M_MEM_WRITE, [0, TOK_DUP, V_DUP_B, 9]);
        if r_a.status != caps::SysStatus::Ok || r_b.status != caps::SysStatus::Ok {
            m17_fail("seed dup pair write was not Ok");
        }
        let id_a = r_a.value;

        // 3. DRIVE the importance accumulator past 150 AND advance the clock so the
        //    stale record ages beyond MIN_AGE (bla_raw(0, ~43) ~= -1160 < -1000).
        for i in 0..40u64 {
            if disp(&mut tbl, home, caps::M_MEM_WRITE, [0, TOK_NOISE, i, 9]).status != caps::SysStatus::Ok {
                m17_fail("noise write was not Ok");
            }
        }

        // 3b. WITNESS the >=150 trigger BEFORE the cycle (op=7 reads imp_accum).
        let acc = disp(&mut tbl, home, caps::M_MEM_CONSOLIDATE, [7, 0, 0, 0]);
        if acc.status != caps::SysStatus::Ok || acc.value < 150 {
            m17_fail("importance accumulator did not cross the 150 trigger");
        }

        // 4. DRIVE ONE bounded consolidation cycle SYNCHRONOUSLY (op=3).
        let cyc = disp(&mut tbl, home, caps::M_MEM_CONSOLIDATE, [3, 0, 0, 0]);
        if cyc.status != caps::SysStatus::Ok || cyc.value < 1 {
            m17_fail("synchronous consolidation cycle (op=3) returned no effect");
        }

        // 5. ASSERT DISTILL: TOK_DUP now recalls ONLY the survivor (the loser is
        //    t_invalid -> filtered in STAGE 1); the survivor carries cites/supersedes.
        let rec = disp(&mut tbl, home, caps::M_MEM_RECALL, [TOK_DUP, 0, 1, 0]);
        if rec.status != caps::SysStatus::Ok {
            m17_fail("post-distill recall of TOK_DUP did not return Ok");
        }
        let h_rec = Handle::from_raw(rec.value);
        let insp = disp(&mut tbl, h_rec, caps::M_OBJECT_INSPECT, [0, 0, 0, 0]);
        if insp.status != caps::SysStatus::Ok || insp.value != caps::ObjKind::MemoryRecord as u64 {
            m17_fail("recalled survivor did not resolve to a MemoryRecord");
        }
        let surv = disp(&mut tbl, h_rec, caps::M_MEM_READ, [0, 0, 0, 0]);
        if surv.status != caps::SysStatus::Ok || surv.value == id_a {
            m17_fail("distill survivor was the merged-away loser (wrong tie-break)");
        }
        let survivor_id = surv.value;
        let lc = disp(&mut tbl, home, caps::M_MEM_CONSOLIDATE, [8, survivor_id, 0, 0]);
        if lc.status != caps::SysStatus::Ok || lc.value < 1 {
            m17_fail("distill survivor carries no supersedes/cites links");
        }

        // 6. ASSERT REFLECT (deterministic): op=4 writes a NEW insight (cites-back).
        let refl = disp(&mut tbl, home, caps::M_MEM_CONSOLIDATE, [4, 0, 0, 0]);
        if refl.status != caps::SysStatus::Ok || refl.value < 1 {
            m17_fail("reflect (op=4) did not produce an insight record");
        }
        let insight_id = refl.value;
        let lc2 = disp(&mut tbl, home, caps::M_MEM_CONSOLIDATE, [8, insight_id, 0, 0]);
        if lc2.status != caps::SysStatus::Ok || lc2.value < 1 {
            m17_fail("reflection insight carries no cites-back links");
        }
        let dval = disp(&mut tbl, home, caps::M_MEM_READ, [insight_id, 0, 0, 0]);
        if dval.status != caps::SysStatus::Ok || dval.value == 0 {
            m17_fail("reflection insight value (digest) was zero");
        }

        // 6b. MODEL-BRIDGED REFLECT (wired NOW via the deterministic M16 mock):
        //     op=6 reads the digest, the daemon-task model XOR-transforms it
        //     (digest ^ 0xA110_C0DE), op=4 writes that token back as the insight.
        let dig = disp(&mut tbl, home, caps::M_MEM_CONSOLIDATE, [6, 0, 0, 0]);
        if dig.status != caps::SysStatus::Ok {
            m17_fail("reflect_digest (op=6) did not return Ok");
        }
        let digest = dig.value;
        let (s, sraw) = tb_hal::agent_model_open(agent_c, "model:mock/echo").unwrap_or((badcap, 0));
        if s != ok {
            m17_fail("model:mock/echo open for the reflect bridge was not Ok");
        }
        let sess = Handle::from_raw(sraw);
        let (s, tok) = tb_hal::agent_model_dispatch(agent_c, caps::M_MODEL_INVOKE, sess, digest)
            .unwrap_or((badcap, 0));
        if s != ok || tok != (digest ^ 0xA110_C0DE) {
            m17_fail("model bridge did not return the deterministic transform");
        }
        let ins2 = disp(&mut tbl, home, caps::M_MEM_CONSOLIDATE, [4, tok, 0, 0]);
        if ins2.status != caps::SysStatus::Ok || ins2.value < 1 {
            m17_fail("model-bridged reflect (op=4 token=a) did not write an insight");
        }
        let rv2 = disp(&mut tbl, home, caps::M_MEM_READ, [ins2.value, 0, 0, 0]);
        if rv2.status != caps::SysStatus::Ok || rv2.value != tok {
            m17_fail("model-bridged insight value != digest ^ 0xA110_C0DE");
        }

        // 7. ASSERT FORGET: the stale record is GONE from recall (demoted tier 5),
        //    YET still addressable over the T2 floor (the swap-out, not free()).
        if disp(&mut tbl, home, caps::M_MEM_RECALL, [TOK_STALE, 0, 1, 0]).status
            == caps::SysStatus::Ok
        {
            m17_fail("demoted stale record still appeared in the hot recall set");
        }
        let sread = disp(&mut tbl, home, caps::M_MEM_READ, [id_stale, 0, 0, 0]);
        if sread.status != caps::SysStatus::Ok || sread.value != V_STALE {
            m17_fail("demoted record is no longer M_MEM_READ-addressable (T2 floor lost)");
        }

        // 8. T2 FLOOR INTEGRITY: the merged-away dup loser's EPISODE is intact --
        //    distill tombstoned only the DERIVED T3 record, never the T2 source.
        let aread = disp(&mut tbl, home, caps::M_MEM_READ, [id_a, 0, 0, 0]);
        if aread.status != caps::SysStatus::Ok || aread.value != V_DUP_A {
            m17_fail("distilled-away loser's T2 episode was destroyed (lossless floor)");
        }

        tb_hal::serial_write_str(
            "mem: distilled + reflected + demoted, T2 floor intact\n",
        );

        // 9. CONSOLIDATE-RIGHT-GATED DENIAL (two ways): a home lacking CONSOLIDATE
        //    is Denied at the required_right gate; an ordinary agent's born-with
        //    home (READ|WRITE|RECALL) is likewise Denied via the daemon facade.
        let home_ro = match tbl.mint_memory_home(caps::Rights::READ.union(caps::Rights::RECALL)) {
            Some(h) => h,
            None => m17_fail("could not mint the read-only memory home"),
        };
        if disp(&mut tbl, home_ro, caps::M_MEM_CONSOLIDATE, [3, 0, 0, 0]).status
            != caps::SysStatus::Denied
        {
            m17_fail("CONSOLIDATE on a home lacking CONSOLIDATE was not Denied");
        }
        let (s, _) = tb_hal::agent_consolidate_cycle(agent_c).unwrap_or((ok, 0));
        if s != den {
            m17_fail("agent_consolidate_cycle on a born-with home was not Denied");
        }
        tb_hal::serial_write_str(
            "mem: consolidation cycle is CONSOLIDATE-gated (rights-denied both ways)\n",
        );
    }

    tb_hal::serial_write_str("M17: consolidate OK\n"); // <-- the M17 DoD marker

    // --- M18: frozen-kernel self-improvement harness + held-out evaluator -----
    // An agent extends its OWN T4 skill library under a FROZEN-KERNEL /
    // EVOLVING-USERSPACE split: a held-out evaluator + test set live in a
    // kernel-owned eval_tbl/eval_home NEVER minted into any agent table, so the
    // improving agent provably cannot READ the held-out set nor WRITE the
    // evaluator. The whole guarantee REDUCES TO the M11 rights-mask invariant
    // (a handle resolves only against the table it is presented to). Skill writes
    // ride the EXISTING M_MEM_WRITE_PROC=18 arm (WRITE_PROCEDURAL-gated, an
    // op-selector inside -- NO new ABI method); the harness is a kernel facade,
    // NOT method-numbered, so an agent literally cannot invoke it. The timer is
    // disarmed (single-core, interrupts masked -- the RefCell discipline holds);
    // ZERO new unsafe. DoD marker: "M18: evolve OK".
    {
        use tb_hal::caps::{self, Handle};

        fn m18_fail(why: &str) -> ! {
            tb_hal::serial_write_str("M18: FAIL ");
            tb_hal::serial_write_str(why);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit()
        }

        // The M13/M16/M17 capability-checked dispatch helper (full [u64;4] args).
        fn disp(
            tbl: &mut tb_hal::caps::HandleTable,
            h: tb_hal::caps::Handle,
            method: u32,
            a: [u64; 4],
        ) -> tb_hal::caps::SysReturn {
            tb_hal::caps::dispatch(
                tbl,
                &tb_hal::caps::SyscallArgs {
                    method,
                    handle: h,
                    args: a,
                },
            )
        }

        let ok = caps::SysStatus::Ok as u32;
        let den = caps::SysStatus::Denied as u32;

        // write_proc op-selector (rides M_MEM_WRITE_PROC -- NO new ABI method).
        const OP_ADD: u64 = 0; // ADD_SKILL
        const OP_READ: u64 = 2; // READ_SKILL -> own body_tok
        const OP_READ_TIER: u64 = 4; // READ_TIER -> own PROPOSED/ADMITTED tier
        const PROPOSED: u64 = 0;
        const ADMITTED: u64 = 1;
        // Witness-A local secret target (the agent does not know it; the test,
        // being kernel-side, hands the matching GOOD body to prove admission).
        const TARGET: u64 = 0x0000_ABCD_0000_1234;
        const BODY_GOOD: u64 = TARGET; // generalizes -> perfect held-out score
        const BODY_OVERFIT: u64 = 0x0000_DEAD_0000_9999; // games visible, misses held-out
        const DESC: u64 = 0x0000_0DE5; // NL-description token (inert at M18)
        const IFACE: u64 = 0x0000_1FAC; // WIT-interface token (inert at M18)
        const EVAL_BASE_A: u64 = 0x0000_2000;
        const EVAL_N_A: u64 = 6;

        // ===== the FROZEN evaluator domain: kernel-owned, never agent-named =====
        let mut eval_tbl = caps::HandleTable::with_capacity(8);
        let eval_all = caps::Rights::READ
            .union(caps::Rights::WRITE)
            .union(caps::Rights::RECALL);
        let eval_home = match eval_tbl.mint_memory_home(eval_all) {
            Some(h) => h,
            None => m18_fail("could not mint the kernel-owned evaluator home"),
        };
        if !eval_tbl.eval_seed_heldout(eval_home, TARGET, EVAL_BASE_A, EVAL_N_A) {
            m18_fail("could not seed the held-out test set");
        }

        // ===== the improving agent's tables (WRITE_PROCEDURAL home + plain home) =
        let mut tbl = caps::HandleTable::with_capacity(16);
        let wp = caps::Rights::READ
            .union(caps::Rights::WRITE)
            .union(caps::Rights::RECALL)
            .union(caps::Rights::WRITE_PROCEDURAL);
        let home_wp = match tbl.mint_memory_home(wp) {
            Some(h) => h,
            None => m18_fail("could not mint the WRITE_PROCEDURAL skill home"),
        };
        let ro = caps::Rights::READ
            .union(caps::Rights::WRITE)
            .union(caps::Rights::RECALL);
        let home_ro = match tbl.mint_memory_home(ro) {
            Some(h) => h,
            None => m18_fail("could not mint the ordinary born-with home"),
        };

        // (1) GOOD SKILL ADMITTED. Propose via WRITE_PROCEDURAL (the right bites
        //     POSITIVELY on a granted home): it lands PROPOSED/inert (util 0).
        let p = disp(&mut tbl, home_wp, caps::M_MEM_WRITE_PROC, [OP_ADD, BODY_GOOD, DESC, IFACE]);
        if p.status != caps::SysStatus::Ok {
            m18_fail("propose GOOD via WRITE_PROCEDURAL was not Ok");
        }
        let id_good = p.value;
        let t0 = disp(&mut tbl, home_wp, caps::M_MEM_WRITE_PROC, [OP_READ_TIER, id_good, 0, 0]);
        if t0.status != caps::SysStatus::Ok || t0.value != PROPOSED {
            m18_fail("a freshly-proposed skill was not PROPOSED/inert");
        }
        let ln0 = tbl.skill_lineage_len(home_wp, id_good).unwrap_or(0);
        // The FROZEN harness scores BODY_GOOD on the held-out set -> strictly
        // improves -> admits (PROPOSED->ADMITTED). The agent never sees the inputs.
        let (adm, _score) = tbl.harness_admit(home_wp, id_good, &eval_tbl, eval_home);
        if !adm {
            m18_fail("the GOOD skill (perfect held-out score) was not admitted");
        }
        let t1 = disp(&mut tbl, home_wp, caps::M_MEM_WRITE_PROC, [OP_READ_TIER, id_good, 0, 0]);
        if t1.status != caps::SysStatus::Ok || t1.value != ADMITTED {
            m18_fail("the admitted skill did not flip PROPOSED->ADMITTED");
        }
        if tbl.skill_lineage_len(home_wp, id_good).unwrap_or(0) <= ln0 {
            m18_fail("admission did not grow the immutable lineage log");
        }
        // OP_READ hands back the agent's OWN body_tok (id-addressed, own skill).
        let rb = disp(&mut tbl, home_wp, caps::M_MEM_WRITE_PROC, [OP_READ, id_good, 0, 0]);
        if rb.status != caps::SysStatus::Ok || rb.value != BODY_GOOD {
            m18_fail("READ_SKILL did not return the agent's own body_tok");
        }

        // (2) BAD / GOODHARTING SKILL REJECTED. BODY_OVERFIT games a visible slice
        //     but does NOT improve the held-out score -> harness leaves it PROPOSED
        //     (inert), appends a reject verdict to lineage, admitted-count unchanged.
        let pbad = disp(&mut tbl, home_wp, caps::M_MEM_WRITE_PROC, [OP_ADD, BODY_OVERFIT, DESC, IFACE]);
        if pbad.status != caps::SysStatus::Ok {
            m18_fail("propose OVERFIT via WRITE_PROCEDURAL was not Ok");
        }
        let id_bad = pbad.value;
        let lnb0 = tbl.skill_lineage_len(home_wp, id_bad).unwrap_or(0);
        let admitted_before = tbl.skill_admitted_count(home_wp).unwrap_or(0);
        let (adm_bad, _s) = tbl.harness_admit(home_wp, id_bad, &eval_tbl, eval_home);
        if adm_bad {
            m18_fail("the overfitting skill was admitted (Goodhart leaked through)");
        }
        let tb_bad = disp(&mut tbl, home_wp, caps::M_MEM_WRITE_PROC, [OP_READ_TIER, id_bad, 0, 0]);
        if tb_bad.status != caps::SysStatus::Ok || tb_bad.value != PROPOSED {
            m18_fail("the rejected skill did not stay PROPOSED/inert");
        }
        if tbl.skill_admitted_count(home_wp).unwrap_or(0) != admitted_before {
            m18_fail("a rejected skill changed the admitted count");
        }
        if tbl.skill_lineage_len(home_wp, id_bad).unwrap_or(0) <= lnb0 {
            m18_fail("the rejection was not appended to the lineage log");
        }

        // (3) PROVABLY CANNOT READ THE HELD-OUT SET: it lives ONLY in eval_tbl,
        //     never minted into tbl, so no handle the agent holds resolves it; a
        //     fabricated raw handle against tbl -> BadCap / Stale (authority lives
        //     in the slot, not the handle). No agent_* facade takes eval_tbl.
        let forged = disp(&mut tbl, Handle::from_raw(0x0000_0001_0000_00FF), caps::M_MEM_READ, [0, 0, 0, 0]);
        if forged.status != caps::SysStatus::BadCap && forged.status != caps::SysStatus::Stale {
            m18_fail("a fabricated handle resolved (the held-out set was nameable)");
        }

        // (4) PROVABLY CANNOT WRITE THE EVALUATOR (Goodhart-stop): a home WITHOUT
        //     WRITE_PROCEDURAL is Denied at the rights gate (the live M11 idiom);
        //     and eval_home is unnameable from tbl (proven above). Both reduce to
        //     the rights-mask invariant.
        let d = disp(&mut tbl, home_ro, caps::M_MEM_WRITE_PROC, [OP_ADD, BODY_OVERFIT, DESC, IFACE]);
        if d.status != caps::SysStatus::Denied {
            m18_fail("a skill write on a home lacking WRITE_PROCEDURAL was not Denied");
        }

        // (5) CLOSED-SET INTACT: an unknown method is still BadMethod (the M11/M16
        //     `method 33 == BadMethod` proof is untouched -- NO new ABI number).
        let bm = disp(&mut tbl, home_wp, 0xDEAD, [0, 0, 0, 0]);
        if bm.status != caps::SysStatus::BadMethod {
            m18_fail("unknown method 0xDEAD was not BadMethod (closed set drifted)");
        }

        tb_hal::serial_write_str(
            "mem: skill proposed via WRITE_PROCEDURAL, frozen evaluator admitted-good + rejected-bad, held-out set unreadable + evaluator unwritable (Denied/BadCap)\n",
        );

        // ===== WITNESS B -- end-to-end through a spawned agent's M11 chokepoint ==
        // Reuse the already-born agent_c (MANIFEST_A: born-with home is
        // READ|WRITE|RECALL, NO WRITE_PROCEDURAL). The harness facade grants a
        // SEPARATE WRITE_PROCEDURAL skill-home (the agent_model_open precedent).
        let (s, gid) = tb_hal::agent_skill_propose(agent_c, OP_ADD, tb_hal::HARNESS_GOOD_BODY, DESC, IFACE)
            .unwrap_or((caps::SysStatus::BadMethod as u32, 0));
        if s != ok {
            m18_fail("agent_skill_propose on the granted WRITE_PROCEDURAL home was not Ok");
        }
        let (s, adm_b) =
            tb_hal::agent_evolve_request(agent_c, gid).unwrap_or((caps::SysStatus::BadMethod as u32, false));
        if s != ok || !adm_b {
            m18_fail("agent_evolve_request did not admit the GOOD skill through the chokepoint");
        }
        // An ordinary agent proposing through its BORN-WITH home (no
        // WRITE_PROCEDURAL) is Denied at the rights gate -- the CoALA asymmetry.
        let (s, _) = tb_hal::agent_mem_dispatch(agent_c, caps::M_MEM_WRITE_PROC, OP_ADD, tb_hal::HARNESS_BAD_BODY, DESC, IFACE)
            .unwrap_or((ok, 0));
        if s != den {
            m18_fail("a born-with-home skill write (no WRITE_PROCEDURAL) was not Denied");
        }

        tb_hal::serial_write_str(
            "mem: frozen boundary == the M11 rights-mask invariant (WRITE_PROCEDURAL gates propose; evaluator domain unnameable)\n",
        );
    }

    tb_hal::serial_write_str("M18: evolve OK\n"); // <-- the M18 DoD marker

    // --- M18.1: MANDATORY human-approval gate for the HIGH-IMPACT / -----------
    //     EMIT_EXTERNAL self-improvement class (SELF-IMPROVEMENT-SPEC §8). The
    //     merge step -- "merge (human-approval hook: mandatory in the high-impact
    //     class)" -- is STRUCTURALLY BLOCKED for an EMIT_EXTERNAL-tagged skill
    //     (§5: "EMIT_EXTERNAL-tagged side-effecting steps are conservative")
    //     unless an explicit human-approval CAPABILITY -- a handle carrying the
    //     new Rights::APPROVE_HIGH_IMPACT -- is presented. FAIL-CLOSED: a missing
    //     OR insufficient approval capability -> Denied, and the skill stays
    //     PROPOSED (the EXCEL-rung admit is never reached). The whole gate reduces
    //     to the SAME M11 rights-mask invariant: the agent's own tables never
    //     carry the approval right, and a handle resolves only against the table
    //     it is presented to, so the gate is unforgeable. An ORDINARY skill merges
    //     exactly as M18 already proves -- the gate is purely ADDITIVE. ZERO new
    //     unsafe; NO new ABI method (the high-impact propose rides the existing
    //     M_MEM_WRITE_PROC op-selector; the merge gate is a kernel-side facade,
    //     not method-numbered). DoD marker: "M18.1: approval-gate OK".
    {
        use tb_hal::caps::{self, Handle};

        fn m181_fail(why: &str) -> ! {
            tb_hal::serial_write_str("M18.1: FAIL ");
            tb_hal::serial_write_str(why);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit()
        }

        fn disp(
            tbl: &mut caps::HandleTable,
            h: Handle,
            method: u32,
            a: [u64; 4],
        ) -> caps::SysReturn {
            caps::dispatch(
                tbl,
                &caps::SyscallArgs {
                    method,
                    handle: h,
                    args: a,
                },
            )
        }

        // write_proc op-selectors (ride M_MEM_WRITE_PROC -- NO new ABI method).
        const OP_ADD: u64 = 0; // ADD_SKILL (ordinary)
        const OP_ADD_EXT: u64 = 5; // ADD_SKILL_EMIT_EXTERNAL (HIGH-IMPACT class)
        const PROPOSED: u8 = 0;
        const ADMITTED: u8 = 1;
        // The held-out evaluator's secret target; BODY_GOOD == TARGET generalizes
        // to a perfect held-out score (the EXCEL rung admits strictly above 0).
        const TARGET: u64 = 0x0000_5A1E_0000_2222;
        const BODY_GOOD: u64 = TARGET;
        const DESC: u64 = 0x0000_0DE5; // NL-description token (inert at M18.1)
        const IFACE: u64 = 0x0000_1FAC; // WIT-interface token (inert at M18.1)
        const EVAL_BASE_G: u64 = 0x0000_3000;
        const EVAL_N_G: u64 = 6;

        // ===== the FROZEN held-out evaluator domain (kernel-owned, unnameable) ==
        let mut eval_tbl = caps::HandleTable::with_capacity(8);
        let eval_all = caps::Rights::READ
            .union(caps::Rights::WRITE)
            .union(caps::Rights::RECALL);
        let eval_home = match eval_tbl.mint_memory_home(eval_all) {
            Some(h) => h,
            None => m181_fail("could not mint the frozen evaluator home"),
        };
        if !eval_tbl.eval_seed_heldout(eval_home, TARGET, EVAL_BASE_G, EVAL_N_G) {
            m181_fail("could not seed the held-out test set");
        }

        // ===== the improving agent: TWO WRITE_PROCEDURAL homes (independent T4
        //       stores, so each starts at best_score 0 and can admit a perfect
        //       skill on its own merit) -- one for the high-impact witness, one
        //       for the ordinary-still-works witness.
        let mut tbl = caps::HandleTable::with_capacity(16);
        let wp = caps::Rights::READ
            .union(caps::Rights::WRITE)
            .union(caps::Rights::RECALL)
            .union(caps::Rights::WRITE_PROCEDURAL);
        let home_hi = match tbl.mint_memory_home(wp) {
            Some(h) => h,
            None => m181_fail("could not mint the high-impact skill home"),
        };
        let home_ord = match tbl.mint_memory_home(wp) {
            Some(h) => h,
            None => m181_fail("could not mint the ordinary skill home"),
        };

        // ===== the HUMAN-APPROVAL authority: a SEPARATE table (approval is NOT
        //       ambient to the agent). `approval` carries APPROVE_HIGH_IMPACT;
        //       `not_approval` is a live cap that LACKS it (the insufficient case).
        let mut human_tbl = caps::HandleTable::with_capacity(4);
        let approval = match human_tbl.mint(caps::ObjKind::Generic, caps::Rights::APPROVE_HIGH_IMPACT) {
            Some(h) => h,
            None => m181_fail("could not mint the human-approval capability"),
        };
        let not_approval = match human_tbl.mint(caps::ObjKind::Generic, caps::Rights::READ) {
            Some(h) => h,
            None => m181_fail("could not mint the no-approval capability"),
        };

        // (A) HIGH-IMPACT skill proposed -- lands PROPOSED/inert like any skill.
        let p = disp(&mut tbl, home_hi, caps::M_MEM_WRITE_PROC, [OP_ADD_EXT, BODY_GOOD, DESC, IFACE]);
        if p.status != caps::SysStatus::Ok {
            m181_fail("propose HIGH-IMPACT skill via WRITE_PROCEDURAL was not Ok");
        }
        let id_hi = p.value;
        if tbl.skill_tier_of(home_hi, id_hi) != Some(PROPOSED) {
            m181_fail("a freshly-proposed high-impact skill was not PROPOSED/inert");
        }

        // (A1) MERGE WITH NO APPROVAL CAPABILITY (Handle::NULL) -> DENIED, the
        //      skill stays PROPOSED, admitted-count unchanged (the fail-closed core).
        let (st, adm) = tbl.harness_merge(home_hi, id_hi, &eval_tbl, eval_home, &human_tbl, Handle::NULL);
        if st != caps::SysStatus::Denied || adm {
            m181_fail("high-impact merge WITHOUT an approval capability was not Denied");
        }
        if tbl.skill_tier_of(home_hi, id_hi) != Some(PROPOSED) {
            m181_fail("a gate-denied high-impact skill did not stay PROPOSED/inert");
        }
        if tbl.skill_admitted_count(home_hi).unwrap_or(1) != 0 {
            m181_fail("a gate-denied high-impact skill changed the admitted count");
        }

        // (A2) MERGE WITH AN INSUFFICIENT CAPABILITY (live, but lacks
        //      APPROVE_HIGH_IMPACT) -> still DENIED, still PROPOSED. Proves the
        //      gate checks the RIGHT, not mere presence of any handle.
        let (st, adm) = tbl.harness_merge(home_hi, id_hi, &eval_tbl, eval_home, &human_tbl, not_approval);
        if st != caps::SysStatus::Denied || adm {
            m181_fail("high-impact merge with a cap lacking APPROVE_HIGH_IMPACT was not Denied");
        }
        if tbl.skill_tier_of(home_hi, id_hi) != Some(PROPOSED) {
            m181_fail("an insufficiently-authorised high-impact skill did not stay PROPOSED");
        }

        // (A3) MERGE WITH THE REAL HUMAN-APPROVAL CAPABILITY -> the gate opens, the
        //      EXCEL rung scores the perfect body, and it flips PROPOSED->ADMITTED.
        let (st, adm) = tbl.harness_merge(home_hi, id_hi, &eval_tbl, eval_home, &human_tbl, approval);
        if st != caps::SysStatus::Ok || !adm {
            m181_fail("high-impact merge WITH a valid approval capability was not admitted");
        }
        if tbl.skill_tier_of(home_hi, id_hi) != Some(ADMITTED) {
            m181_fail("an approved high-impact skill did not flip PROPOSED->ADMITTED");
        }
        if tbl.skill_admitted_count(home_hi).unwrap_or(0) != 1 {
            m181_fail("an approved high-impact skill did not raise the admitted count");
        }

        // (B) ORDINARY skill -- the gate is ADDITIVE: it merges with NO approval
        //     capability exactly as M18 proves (no regression of the M18 path).
        let p = disp(&mut tbl, home_ord, caps::M_MEM_WRITE_PROC, [OP_ADD, BODY_GOOD, DESC, IFACE]);
        if p.status != caps::SysStatus::Ok {
            m181_fail("propose ORDINARY skill via WRITE_PROCEDURAL was not Ok");
        }
        let id_ord = p.value;
        let (st, adm) = tbl.harness_merge(home_ord, id_ord, &eval_tbl, eval_home, &human_tbl, Handle::NULL);
        if st != caps::SysStatus::Ok || !adm {
            m181_fail("an ORDINARY skill did not merge without approval (gate not additive)");
        }
        if tbl.skill_tier_of(home_ord, id_ord) != Some(ADMITTED) {
            m181_fail("an ORDINARY merged skill did not flip PROPOSED->ADMITTED");
        }

        tb_hal::serial_write_str(
            "mem: high-impact/EMIT_EXTERNAL merge fail-closed without APPROVE_HIGH_IMPACT (Denied), admitted only with the human-approval capability; ordinary skill still merges\n",
        );
    }

    tb_hal::serial_write_str("M18.1: approval-gate OK\n"); // <-- the M18.1 DoD marker

    // --- M18.2: ROTATING HELD-OUT EVALUATOR PARTITION (anti-Goodhart) ----------
    //     SELF-IMPROVEMENT-SPEC ("Measurer-measured separation"): a SINGLE visible
    //     metric WILL be Goodharted, so MULTIPLE held-out evaluators are the
    //     default. This GENERALIZES the M18 single frozen evaluator into a SET of N
    //     kernel-owned held-out partitions, each capability-protected EXACTLY like
    //     the M18 evaluator -- it lives ONLY in a kernel-owned `eval_tbl`, never
    //     minted into any agent table, so it is unnameable/unreadable/unwritable
    //     from any agent table (the guarantee REDUCES TO the M11 rights-mask
    //     invariant: a handle resolves only against the table it is presented to).
    //     A kernel-side ROTATION counter the agent can neither read nor influence
    //     (`idx = rotation % N`) selects WHICH partition scores a given merge; the
    //     VISIBLE metric the agent can measure to self-optimize is a DIFFERENT
    //     partition, so a candidate tuned to the visible metric does NOT thereby
    //     control its real (rotated, hidden) score -- the structural anti-Goodhart
    //     DECOUPLING. ADDITIVE on top of M18 + M18.1; ZERO new ABI method (the
    //     harness is a kernel facade, not method-numbered, so an agent cannot
    //     invoke it), ZERO new unsafe, ZERO new Rights bit. The self-test PROVES,
    //     fail-closed: (a) >1 held-out partitions, none nameable/readable/writable
    //     from an agent table; (b) the rotation selects a scoring partition the
    //     agent cannot observe; (c) the visible metric is decoupled from the
    //     scoring partition. DoD marker: "M18.2: held-out OK".
    //
    //     STACK NOTE: M0..L2.0 already run in ONE huge `rust_main` frame that sits
    //     near the aarch64 16 KiB boot stack (x86_64's is 64 KiB); at -O0 every
    //     lexical block's locals coexist in that single frame, so this self-test
    //     lives in its OWN `#[inline(never)]` function to keep rust_main's frame
    //     from growing past the aarch64 boot stack.
    #[inline(never)]
    fn m182_held_out_selftest() {
        use tb_hal::caps::{self, Handle};

        fn m182_fail(why: &str) -> ! {
            tb_hal::serial_write_str("M18.2: FAIL ");
            tb_hal::serial_write_str(why);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit()
        }

        fn disp(
            tbl: &mut caps::HandleTable,
            h: Handle,
            method: u32,
            a: [u64; 4],
        ) -> caps::SysReturn {
            caps::dispatch(
                tbl,
                &caps::SyscallArgs {
                    method,
                    handle: h,
                    args: a,
                },
            )
        }

        // write_proc op-selector (rides M_MEM_WRITE_PROC -- NO new ABI method).
        const OP_ADD: u64 = 0; // ADD_SKILL (ordinary)
        const PROPOSED: u8 = 0;
        const ADMITTED: u8 = 1;
        const DESC: u64 = 0x0000_0DE5; // NL-description token (inert at M18.2)
        const IFACE: u64 = 0x0000_1FAC; // WIT-interface token (inert at M18.2)

        // Each partition has a DISTINCT secret target -> a distinct held-out
        // transform, so the body that is perfect on one partition is sub-perfect on
        // every other (the cross-partition Goodhart-resistance the M18
        // `skill_transform` already provides). `TARGET_VIS` seeds the VISIBLE
        // metric; `TARGET_H{0,1,2}` seed the N=3 held-out SCORING partitions.
        const TARGET_VIS: u64 = 0x0000_71B1_0000_5151;
        const TARGET_H0: u64 = 0x0000_A101_0000_0001;
        const TARGET_H1: u64 = 0x0000_B202_0000_0002;
        const TARGET_H2: u64 = 0x0000_C303_0000_0003;
        const VIS_BASE: u64 = 0x0000_4000;
        const H0_BASE: u64 = 0x0000_5000;
        const H1_BASE: u64 = 0x0000_6000;
        const H2_BASE: u64 = 0x0000_7000;
        const N_CASES: u64 = 8;

        // ===== the kernel-owned EVALUATOR DOMAIN: N=3 held-out SCORING partitions
        //       + 1 VISIBLE partition, NONE ever minted into an agent table =======
        let mut eval_tbl = caps::HandleTable::with_capacity(8);
        let eval_all = caps::Rights::READ
            .union(caps::Rights::WRITE)
            .union(caps::Rights::RECALL);

        let vis_home = match eval_tbl.mint_memory_home(eval_all) {
            Some(h) => h,
            None => m182_fail("could not mint the visible partition"),
        };
        if !eval_tbl.eval_seed_heldout(vis_home, TARGET_VIS, VIS_BASE, N_CASES) {
            m182_fail("could not seed the visible partition");
        }
        let h0 = match eval_tbl.mint_memory_home(eval_all) {
            Some(h) => h,
            None => m182_fail("could not mint held-out partition 0"),
        };
        if !eval_tbl.eval_seed_heldout(h0, TARGET_H0, H0_BASE, N_CASES) {
            m182_fail("could not seed held-out partition 0");
        }
        let h1 = match eval_tbl.mint_memory_home(eval_all) {
            Some(h) => h,
            None => m182_fail("could not mint held-out partition 1"),
        };
        if !eval_tbl.eval_seed_heldout(h1, TARGET_H1, H1_BASE, N_CASES) {
            m182_fail("could not seed held-out partition 1");
        }
        let h2 = match eval_tbl.mint_memory_home(eval_all) {
            Some(h) => h,
            None => m182_fail("could not mint held-out partition 2"),
        };
        if !eval_tbl.eval_seed_heldout(h2, TARGET_H2, H2_BASE, N_CASES) {
            m182_fail("could not seed held-out partition 2");
        }
        let eval_homes = [h0, h1, h2];
        let n = eval_homes.len();

        // (a) THERE ARE >1 HELD-OUT PARTITIONS, each resolves ONLY in the kernel-
        //     owned table, and NONE is the visible partition.
        if n < 2 {
            m182_fail("the held-out partition set is not larger than one");
        }
        for p in 0..n {
            if eval_tbl.eval_score(eval_homes[p], 0).is_none() {
                m182_fail("a held-out partition did not resolve in the kernel-owned table");
            }
            if eval_homes[p] == vis_home {
                m182_fail("a scoring partition aliased the visible partition");
            }
        }

        // ===== the improving agent's tables: WRITE_PROCEDURAL skill homes + a
        //       born-with home that LACKS WRITE_PROCEDURAL (the unwritable witness).
        let mut tbl = caps::HandleTable::with_capacity(16);
        let wp = caps::Rights::READ
            .union(caps::Rights::WRITE)
            .union(caps::Rights::RECALL)
            .union(caps::Rights::WRITE_PROCEDURAL);
        let ro = caps::Rights::READ
            .union(caps::Rights::WRITE)
            .union(caps::Rights::RECALL);
        let home_g = match tbl.mint_memory_home(wp) {
            Some(h) => h,
            None => m182_fail("could not mint the genuine-merit skill home"),
        };
        let home_r = match tbl.mint_memory_home(wp) {
            Some(h) => h,
            None => m182_fail("could not mint the rotation-advance skill home"),
        };
        let home_ro = match tbl.mint_memory_home(ro) {
            Some(h) => h,
            None => m182_fail("could not mint the born-with home"),
        };

        // (a, cont.) UNWRITABLE: a skill write on a home lacking WRITE_PROCEDURAL is
        //     Denied at the rights gate (the live M11 idiom); the eval partitions
        //     are ADDITIONALLY unnameable from `tbl` (proven in (b)). Both reduce to
        //     the rights-mask invariant.
        let d = disp(&mut tbl, home_ro, caps::M_MEM_WRITE_PROC, [OP_ADD, TARGET_H0, DESC, IFACE]);
        if d.status != caps::SysStatus::Denied {
            m182_fail("a skill write on a home lacking WRITE_PROCEDURAL was not Denied");
        }

        // (b) THE ROTATION SELECTS A SCORING PARTITION THE AGENT CANNOT OBSERVE.
        //     b1 -- GENUINE ROTATION: two consecutive kernel-side rotation values
        //     score two candidates against DIFFERENT partitions. id_a is proposed
        //     and scored at rotation 0 (partition 0); id_b at rotation 1 (partition
        //     1). idx0 != idx1 proves the rotation advances; the agent supplies no
        //     input to the selector.
        let pa = disp(&mut tbl, home_r, caps::M_MEM_WRITE_PROC, [OP_ADD, TARGET_H0, DESC, IFACE]);
        if pa.status != caps::SysStatus::Ok {
            m182_fail("propose rotation-witness candidate A was not Ok");
        }
        let id_a = pa.value;
        let pb = disp(&mut tbl, home_r, caps::M_MEM_WRITE_PROC, [OP_ADD, TARGET_H1, DESC, IFACE]);
        if pb.status != caps::SysStatus::Ok {
            m182_fail("propose rotation-witness candidate B was not Ok");
        }
        let id_b = pb.value;
        let (_, idx0, _) = tbl.harness_admit_rotating(home_r, id_a, &eval_tbl, &eval_homes, 0);
        let (_, idx1, _) = tbl.harness_admit_rotating(home_r, id_b, &eval_tbl, &eval_homes, 1);
        if idx0 == idx1 {
            m182_fail("the rotation did not advance to a different scoring partition");
        }
        //     b2 -- UNOBSERVABLE: the agent holds NO handle to `eval_tbl`, so it can
        //     never name the selected partition. A fabricated raw handle against the
        //     AGENT table is BadCap/Stale (authority lives in the slot, not the
        //     handle -- the live M18 idiom), so the agent cannot read which
        //     partition scored it.
        let forged = disp(&mut tbl, Handle::from_raw(0x0000_0001_0000_00FF), caps::M_MEM_READ, [0, 0, 0, 0]);
        if forged.status != caps::SysStatus::BadCap && forged.status != caps::SysStatus::Stale {
            m182_fail("a fabricated handle resolved (a scoring partition was nameable from an agent table)");
        }

        // (c) THE VISIBLE METRIC IS DECOUPLED FROM THE SCORING PARTITION. The hidden
        //     scoring partition for this witness is p_star (= rotation 0 -> 0). V is
        //     the body tuned to the VISIBLE metric (== TARGET_VIS, perfect on
        //     vis_home); G is the body matching the hidden scoring partition (==
        //     TARGET_H0). The two metrics rank V and G OPPOSITELY, so optimizing the
        //     visible metric does not optimize the real score.
        let p_star: usize = 0;
        let v_body = TARGET_VIS;
        let g_body = TARGET_H0;
        let vis_v = match eval_tbl.eval_score(vis_home, v_body) {
            Some(s) => s,
            None => m182_fail("visible-metric score did not resolve"),
        };
        let vis_g = match eval_tbl.eval_score(vis_home, g_body) {
            Some(s) => s,
            None => m182_fail("visible-metric score of G did not resolve"),
        };
        let sc_v = match eval_tbl.eval_score(eval_homes[p_star], v_body) {
            Some(s) => s,
            None => m182_fail("hidden-scorer score of V did not resolve"),
        };
        let sc_g = match eval_tbl.eval_score(eval_homes[p_star], g_body) {
            Some(s) => s,
            None => m182_fail("hidden-scorer score of G did not resolve"),
        };
        // The VISIBLE metric prefers the visible-tuned body; the HIDDEN scorer
        // prefers the matched body. Tuning the visible score does NOT raise (in fact
        // anti-correlates with) the real score -> decoupled.
        if vis_v <= vis_g {
            m182_fail("the visible-tuned body was not best on the visible metric");
        }
        if sc_g <= sc_v {
            m182_fail("the hidden scorer did not rank the matched body above the visible-tuned body");
        }
        // CROSS-PARTITION: a body matched to the scoring partition does NOT
        // generalize to the next partition the rotation would pick -- overfitting
        // ANY single partition gives no Goodhart cover once the rotation moves.
        let other = (p_star + 1) % n;
        let sc_g_other = match eval_tbl.eval_score(eval_homes[other], g_body) {
            Some(s) => s,
            None => m182_fail("cross-partition score of G did not resolve"),
        };
        if sc_g <= sc_g_other {
            m182_fail("a body matched to one partition generalized to another (rotation gave no cover)");
        }

        // (c, admit path) The GENUINE-MERIT candidate G -- matching the hidden
        //     scoring partition p_star -- is ADMITTED through the rotating scorer, so
        //     the rotation does not break the M18 admit path.
        let pg = disp(&mut tbl, home_g, caps::M_MEM_WRITE_PROC, [OP_ADD, g_body, DESC, IFACE]);
        if pg.status != caps::SysStatus::Ok {
            m182_fail("propose the genuine-merit candidate G was not Ok");
        }
        let id_g = pg.value;
        let (adm_g, idx_g, _sg) = tbl.harness_admit_rotating(home_g, id_g, &eval_tbl, &eval_homes, p_star as u64);
        if !adm_g || idx_g != p_star {
            m182_fail("the matched candidate was not admitted by the rotated scoring partition");
        }
        if tbl.skill_tier_of(home_g, id_g) != Some(ADMITTED) {
            m182_fail("the admitted matched candidate did not flip PROPOSED->ADMITTED");
        }
        if tbl.skill_admitted_count(home_g).unwrap_or(0) != 1 {
            m182_fail("the admitted matched candidate did not raise the admitted count");
        }

        // (c, reject path) With the bar now set by a genuinely-scored skill, a
        //     candidate TUNED TO THE VISIBLE METRIC (V, perfect on vis_home) scored
        //     against the SAME hidden partition is REJECTED and stays PROPOSED --
        //     tuning the visible metric did NOT control the real score. FAIL-CLOSED.
        let pv = disp(&mut tbl, home_g, caps::M_MEM_WRITE_PROC, [OP_ADD, v_body, DESC, IFACE]);
        if pv.status != caps::SysStatus::Ok {
            m182_fail("propose the visible-tuned candidate V was not Ok");
        }
        let id_v = pv.value;
        let before = tbl.skill_admitted_count(home_g).unwrap_or(0);
        let (adm_v, _iv, _sv) = tbl.harness_admit_rotating(home_g, id_v, &eval_tbl, &eval_homes, p_star as u64);
        if adm_v {
            m182_fail("a visible-tuned candidate was admitted (the visible metric controlled the real score)");
        }
        if tbl.skill_tier_of(home_g, id_v) != Some(PROPOSED) {
            m182_fail("a rejected visible-tuned candidate did not stay PROPOSED");
        }
        if tbl.skill_admitted_count(home_g).unwrap_or(before + 1) != before {
            m182_fail("a rejected visible-tuned candidate changed the admitted count");
        }

        tb_hal::serial_write_str(
            "mem: N>1 held-out partitions kernel-owned + unnameable, rotation (kernel counter) picks the hidden scorer != the visible partition, visible-tuned candidate rejected by the rotated scorer (anti-Goodhart decoupling == the M11 rights-mask invariant)\n",
        );
    }
    m182_held_out_selftest();

    tb_hal::serial_write_str("M18.2: held-out OK\n"); // <-- the M18.2 DoD marker

    // --- L2.0: VMX-root + 1-instruction nested guest + caught VM-exit --------
    // The FIRST rung of the L2 sovereignty track (tb-core, a from-scratch Type-1
    // microhypervisor): the smallest proof that TABOS *is* the hypervisor. The
    // already-booted kernel (now playing L1) drives the full Intel VMX-root
    // bring-up -- VMXON + a minimal VMCS + an EPT identity map + a 1-`CPUID`
    // long-mode nested L2 guest + the host<->guest world switch + catching the
    // guest's VM-exit (VMREAD exit-reason == 10 CPUID) + VMXOFF. ALL the new
    // silicon-unsafe/asm is confined to tb-hal's new `arch/x86_64/vmx/` subtree,
    // so the framekernel invariant SURVIVES: this crate stays unsafe-free and
    // caps/mem/ipc/blocks/infer stay `#![forbid(unsafe_code)]`; the kernel only
    // branches on the returned `VmxProof`. GRACEFUL SKIP (the vmm-boot `KVM_OK`
    // allow-skip discipline): if CPUID does not advertise VMX or the BIOS locked
    // VT-x off (the TCG `qemu64` case), NO VMX instruction runs and the SAME
    // `L2.0: vmxroot OK` marker substring still prints, tagged as a skip -- the
    // real world-switch proof fires wherever VMX is exposed (a KVM + nested-VMX
    // lane). aarch64 has no VMX, so it reports the n/a path. DoD: "L2.0: vmxroot OK".
    match tb_hal::vmx_selftest() {
        tb_hal::VmxProof::Proven { exit_reason } => {
            tb_hal::serial_write_str("vmx: nested guest VM-exited, reason=");
            write_hex_u64(exit_reason as u64);
            tb_hal::serial_write_byte(b'\n');
            // 10 = CPUID (expected), 18 = VMCALL: either proves the world switch.
            if exit_reason == 10 || exit_reason == 18 {
                tb_hal::serial_write_str("L2.0: vmxroot OK\n"); // <-- the L2.0 DoD marker
            } else {
                tb_hal::serial_write_str("L2.0: FAIL unexpected VM-exit reason\n");
            }
        }
        tb_hal::VmxProof::Unavailable => {
            // TCG `qemu64`: VMX not exposed. Same marker substring, graceful skip.
            tb_hal::serial_write_str("L2.0: vmxroot OK (vmx unavailable, skipped)\n");
        }
        tb_hal::VmxProof::NotApplicable => {
            // aarch64: no VMX -- the EL2 world-switch is a later L2 sub-milestone.
            tb_hal::serial_write_str("L2.0: vmxroot OK (x86-only, n/a on aarch64)\n");
        }
        tb_hal::VmxProof::VmxonFailed => {
            // VMX advertised but VMXON unusable (e.g. partial `-cpu max` TCG). Not
            // a proof and not the genuine skip case -- surfaced honestly, no marker.
            tb_hal::serial_write_str("L2.0: VMXON failed (vmx present but unusable here)\n");
        }
        tb_hal::VmxProof::EntryFailed { vm_error } => {
            // VMXON succeeded but VM-entry failed -- on real silicon this is a VMCS
            // bug to fix on the nested-VMX lane; under emulation it is incompleteness.
            tb_hal::serial_write_str("L2.0: VM-entry failed, vm-instruction-error=");
            write_hex_u64(vm_error);
            tb_hal::serial_write_byte(b'\n');
        }
    }

    // --- L2.0: EL2 (nVHE) world-switch -- the aarch64 realization of the same
    // "we ARE the hypervisor" rung the vmxroot block above proves on x86. Booted
    // at EL2 (QEMU virt,virtualization=on), this kernel installed a resident nVHE
    // EL2 monitor and dropped to EL1 to run M0..M18; now (playing the live EL1
    // kernel) it issues a bootstrap HVC #0 that ERETs into a tiny EL1 guest stub,
    // whose HVC #1 traps back to EL2 and is caught + verified. ALL the new
    // asm/unsafe is confined to tb-hal's arch/aarch64/{boot,el2,el2_vectors}.rs,
    // so this crate stays unsafe-free; the kernel only branches on El2Proof.
    // Unlike vmxroot (a TCG skip), this proof EXECUTES under pure TCG. On x86_64
    // there is no EL2, so it reports the n/a path. DoD: "L2.0: el2 OK".
    //
    // DIAG (#65, probe P7/manifestation-2 discriminator): BOOT_ENTRY_EL is a
    // .data record written by `_start` BEFORE any branching; BOOTED_AT_EL2 is
    // a .bss flag written AFTER .bss-zero and sitting EXACTLY at the heap
    // arena's end. If the boot really entered at EL2 but the flag now reads 0,
    // the flag was lost/stomped after boot (the silent-skip manifestation) --
    // make that loud BEFORE the gracefully-skipping selftests run, plus a
    // stack red-zone sweep at the same checkpoint.
    #[cfg(target_arch = "aarch64")]
    {
        if tb_hal::boot_entry_el() == 0x2 && tb_hal::booted_at_el2() != 1 {
            tb_hal::serial_write_str(
                "el2: DIAG BOOTED_AT_EL2 lost (entry-el=0x2 but flag=0) -- stomp suspected\n",
            );
        }
        tb_hal::stack_redzone_check();
    }
    match tb_hal::el2_selftest() {
        tb_hal::El2Proof::Proven { .. } => {
            tb_hal::serial_write_str("L2.0: el2 OK\n"); // <-- the L2.0 aarch64 DoD marker
        }
        tb_hal::El2Proof::Unavailable => {
            // Not booted at EL2 (plain `virt`): graceful green skip, no HVC issued.
            tb_hal::serial_write_str("L2.0: el2 OK (no EL2, skipped)\n");
        }
        tb_hal::El2Proof::NotApplicable => {
            // x86_64: no EL2 -- the vmxroot block above is this arch's rung.
            tb_hal::serial_write_str("L2.0: el2 OK (aarch64-only, n/a on x86_64)\n");
        }
        tb_hal::El2Proof::RoundTripFailed { code } => {
            // Booted at EL2 but the round-trip faulted -- surfaced honestly, with
            // NO 'el2 OK' substring, so the run-script grep fails (red).
            tb_hal::serial_write_str("L2.0: el2 FAIL code=");
            write_hex_u64(code);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit(); // #65: red NOW, not at the wall-clock ceiling
        }
    }

    // --- L2.1: stage-2 demand-translation -- the aarch64 analog of x86 EPT-
    // violation handling, the SECOND L2 rung built ON TOP of L2.0's resident EL2
    // monitor. Inside a short self-test window the monitor arms stage-2
    // (HCR_EL2.VM=1) over a table that identity-maps everything the guest needs
    // to RUN but leaves ONE IPA gigabyte a deliberate HOLE; the EL1 guest stub
    // touches it, faults to EL2 as a stage-2 translation fault, the monitor reads
    // HPFAR_EL2, splices a stage-2 leaf, and ERETs WITHOUT advancing ELR so the
    // guest re-executes the load and closes the round-trip -- the citable ARM
    // equivalent of the x86 'touch unmapped GPA -> reason-48 -> map -> INVEPT ->
    // resume' loop. Stage-2 is torn down (HCR.VM=0) BEFORE the monitor unwinds,
    // so the kernel resumes here cleanly (zero regression). ALL the new asm/unsafe
    // is confined to tb-hal's arch/aarch64/{stage2,el2,el2_vectors}.rs, so this
    // crate stays unsafe-free; the kernel only branches on Stage2Proof. On x86_64
    // there is no EL2/stage-2, so it reports the n/a path. DoD: "L2.1: stage2 OK".
    match tb_hal::stage2_selftest() {
        tb_hal::Stage2Proof::Proven { .. } => {
            tb_hal::serial_write_str("L2.1: stage2 OK\n"); // <-- the L2.1 aarch64 DoD marker
        }
        tb_hal::Stage2Proof::Unavailable => {
            // Not booted at EL2 (plain `virt`): graceful green skip, no stage-2 armed.
            tb_hal::serial_write_str("L2.1: stage2 OK (no EL2, skipped)\n");
        }
        tb_hal::Stage2Proof::NotApplicable => {
            // x86_64: no EL2/stage-2 -- the vmxroot block above is this arch's rung.
            tb_hal::serial_write_str("L2.1: stage2 OK (aarch64-only, n/a on x86_64)\n");
        }
        tb_hal::Stage2Proof::Faulted { code } => {
            // Booted at EL2 but the demand round-trip faulted -- surfaced honestly,
            // with NO 'stage2 OK' substring, so the run-script grep fails (red).
            tb_hal::serial_write_str("L2.1: stage2 FAIL code=");
            write_hex_u64(code);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit(); // #65: red NOW, not at the wall-clock ceiling
        }
    }

    // --- L2.2: EL2 exit-dispatch table -- the aarch64 analog of the x86
    // arm_exit_handlers[] table, the THIRD L2 rung built ON TOP of L2.0's
    // resident EL2 monitor. Inside a short self-test window the monitor routes
    // EVERY guest exit through the PURE, Kani-proven classify_exit() table, then
    // fires TWO distinct arms: a trapped WFx (HCR_EL2.TWI|TWE) it RESUMES one
    // instruction past, and an FP/SIMD access (CPTR_EL2.TFP, EC 0x07, NOT in the
    // MUST set) that hits the fail-closed inject-UNDEF DEFAULT -- software-
    // synthesized exactly as KVM's enter_exception64 and caught by the guest's
    // OWN EL1 vector, which echoes a magic. The window is torn down (HCR/CPTR
    // back to baseline) BEFORE the monitor unwinds, so the kernel resumes here
    // cleanly (zero regression). ALL the new asm/unsafe is confined to tb-hal's
    // arch/aarch64/{exits,exits_vectors,el2,el2_vectors}.rs, so this crate stays
    // unsafe-free; the kernel only branches on ExitsProof. On x86_64 there is no
    // EL2, so it reports the n/a path. DoD: "L2.2: el2-exits OK".
    match tb_hal::el2_exits_selftest() {
        tb_hal::ExitsProof::Proven { .. } => {
            tb_hal::serial_write_str("L2.2: el2-exits OK\n"); // <-- the L2.2 aarch64 DoD marker
        }
        tb_hal::ExitsProof::Unavailable => {
            // Not booted at EL2 (plain `virt`): graceful green skip, no window armed.
            tb_hal::serial_write_str("L2.2: el2-exits OK (no EL2, skipped)\n");
        }
        tb_hal::ExitsProof::NotApplicable => {
            // x86_64: no EL2 -- the vmxroot block above is this arch's rung.
            tb_hal::serial_write_str("L2.2: el2-exits OK (aarch64-only, n/a on x86_64)\n");
        }
        tb_hal::ExitsProof::Faulted { code } => {
            // Booted at EL2 but the exit round-trip faulted -- surfaced honestly,
            // with NO 'el2-exits OK' substring, so the run-script grep fails (red).
            tb_hal::serial_write_str("L2.2: el2-exits FAIL code=");
            write_hex_u64(code);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit(); // #65: red NOW, not at the wall-clock ceiling
        }
    }

    // --- L2.3: EL2 trap-and-emulate -- the aarch64 trap-and-EMULATE rung (the
    // SYSREG + MMIO-abort emulate primitive), the FOURTH L2 rung built ON TOP of
    // L2.0's resident EL2 monitor. Inside a short self-test window the monitor
    // traps a guest sysreg WRITE (HCR_EL2.TVM, the `msr contextidr_el1` trigger)
    // and a guest MMIO LDR/STR to an unmapped device IPA (HCR_EL2.VM), DECODES
    // each via the pure Kani-proven el2_trap ISS decoders, EMULATES it (records
    // the sysreg value; routes the MMIO access through the device_mmio callback
    // SEAM -- the split-VMM upcall point), and ADVANCES ELR_EL2 past the trapped
    // instruction (the OPPOSITE of L2.1's demand-retry, exactly KVM's
    // kvm_incr_pc). The window is torn down (HCR back to RW baseline) BEFORE the
    // monitor unwinds, so the kernel resumes here cleanly (zero regression). ALL
    // the new asm/unsafe is confined to tb-hal's arch/aarch64/{el2mmio,el2,
    // stage2}.rs, so this crate stays unsafe-free; the kernel only branches on
    // TrapProof. On x86_64 there is no EL2, so it reports the n/a path. DoD:
    // "L2.3: el2-trap OK".
    match tb_hal::el2_trap_selftest() {
        tb_hal::TrapProof::Proven { .. } => {
            tb_hal::serial_write_str("L2.3: el2-trap OK\n"); // <-- the L2.3 aarch64 DoD marker
        }
        tb_hal::TrapProof::Unavailable => {
            // Not booted at EL2 (plain `virt`): graceful green skip, no window armed.
            tb_hal::serial_write_str("L2.3: el2-trap OK (no EL2, skipped)\n");
        }
        tb_hal::TrapProof::NotApplicable => {
            // x86_64: no EL2 -- the vmxroot block above is this arch's rung.
            tb_hal::serial_write_str("L2.3: el2-trap OK (aarch64-only, n/a on x86_64)\n");
        }
        tb_hal::TrapProof::Faulted { code } => {
            // Booted at EL2 but the trap round-trip faulted -- surfaced honestly,
            // with NO 'el2-trap OK' substring, so the run-script grep fails (red).
            tb_hal::serial_write_str("L2.3: el2-trap FAIL code=");
            write_hex_u64(code);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit(); // #65: red NOW, not at the wall-clock ceiling
        }
    }

    // --- aL2.4: EL2 nested guest (GENUINE two-stage) -- a REAL minimal TABOS
    // guest that runs at EL1 UNDER our EL2 stage-2 with its OWN stage-1 MMU live,
    // the FIFTH L2 rung built ON TOP of L2.0's resident EL2 monitor. The monitor
    // arms the GiB0+GiB1 identity stage-2 (HCR_EL2.VM=1) and erets into a guest
    // that BUILDS its own 3-level stage-1 (reusing the REAL kernel M3 paging
    // encoders + the mmu.rs MAIR/TCR geometry), ENABLES it (SCTLR_EL1.M=1 -- the
    // Kani-proven "S1 after S2" step), and stores+reads back a sentinel through a
    // VA that has NO flat meaning -- a GENUINE VA->(guest S1)->IPA->(our S2)->PA
    // two-stage walk, the guest's own stage-1 walk itself re-translated by our
    // stage-2 (S1PTW). It then installs its OWN VBAR_EL1 and takes its OWN EL1
    // `brk` exception (an EL1->EL1 trap, NOT an EL2 exit), and HVCs done. The
    // verdict requires BOTH the guest's two-stage readback AND its EL1 trap to
    // have fired, corroborated by an INDEPENDENT EL2-side identity-alias readback
    // the guest cannot fake. Stage-2 is torn down (HCR.VM=0) BEFORE unwinding AND
    // the facade restores the kernel's TTBR0/TCR/MAIR/SCTLR/VBAR_EL1 (the EL1-side
    // teardown -- the new surface the guest mutated), so the kernel resumes on its
    // OWN stage-1 (zero regression -- M19 still prints after). ALL the new
    // asm/unsafe is confined to tb-hal's arch/aarch64/{el2,el2_nested_vectors,
    // stage2}.rs, so this crate stays unsafe-free; the kernel only branches on
    // NestedGuestProof. On x86_64 there is no EL2, so it reports the n/a path.
    // DoD: "L2.4: el2-guest OK".
    match tb_hal::el2_nested_guest_selftest() {
        tb_hal::NestedGuestProof::Proven { .. } => {
            tb_hal::serial_write_str("L2.4: el2-guest OK\n"); // <-- the aL2.4 aarch64 DoD marker
        }
        tb_hal::NestedGuestProof::Unavailable => {
            // Not booted at EL2 (plain `virt`): graceful green skip, no stage-2 armed.
            tb_hal::serial_write_str("L2.4: el2-guest OK (no EL2, skipped)\n");
        }
        tb_hal::NestedGuestProof::NotApplicable => {
            // x86_64: no EL2/two-stage -- the vmxroot block above is this arch's rung.
            tb_hal::serial_write_str("L2.4: el2-guest OK (aarch64-only, n/a on x86_64)\n");
        }
        tb_hal::NestedGuestProof::Faulted { code } => {
            // Booted at EL2 but the two-stage round-trip faulted -- surfaced
            // honestly, with NO 'el2-guest OK' substring, so the run grep fails (red).
            tb_hal::serial_write_str("L2.4: el2-guest FAIL code=");
            write_hex_u64(code);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit(); // #65: red NOW, not at the wall-clock ceiling
        }
    }

    // --- aL2.5: EL2 vGIC virtual-interrupt injection + WFI scheduler-hook -- the
    // SIXTH L2 rung, built ON TOP of L2.0's resident EL2 monitor. The monitor
    // arms the vGIC window (HCR_EL2 = RW|IMO|TWI + GICH_HCR.En) and erets into a
    // guest that enables its OWN GICV virtual CPU interface and PARKS on WFI (the
    // canonical scheduler yield point). The WFI traps to EL2 (HCR_EL2.TWI) where
    // the monitor SOFTWARE-INJECTS a pending vIRQ into GICH_LR0 (via the
    // Kani-proven tb_encode::el2_trap::gich_lr_encode) and resumes the guest past
    // the WFI; with HCR_EL2.IMO routing the VIRQ to EL1 + the guest's GICV_CTLR.En
    // + PSTATE.I clear, the guest immediately takes the vIRQ at its OWN EL1 IRQ
    // vector, reads GICV_IAR == the injected vINTID, sets a sentinel, and writes
    // GICV_EOIR. The verdict requires the CONJUNCTION of the guest-side magic AND
    // the monitor-side independent confirmation (the WFI park was observed AND
    // GICH_ELRSR0 shows LR0 retired -- a fact the guest cannot fake). The window
    // is torn down (HCR_EL2 baseline, GICH_HCR.En=0, GICH_LR0 zeroed) BEFORE
    // unwinding AND the facade restores the kernel's VBAR_EL1 (the EL1-side
    // teardown -- the guest installed its OWN vGIC vectors), so the kernel resumes
    // on its OWN exception table (zero regression -- M19 still prints after). ALL
    // the new asm/unsafe is confined to tb-hal's arch/aarch64/{el2,el2vgic,
    // el2_vgic_vectors}.rs (the GICH_LR encoder in tb-encode is forbid(unsafe) +
    // Kani-proven); the kernel only branches on VgicProof. On x86_64 there is no
    // EL2/GIC virtualization, so it reports the n/a path. DoD: "L2.5: vgic OK".
    match tb_hal::el2_vgic_selftest() {
        tb_hal::VgicProof::Proven { .. } => {
            tb_hal::serial_write_str("L2.5: vgic OK\n"); // <-- the aL2.5 aarch64 DoD marker
        }
        tb_hal::VgicProof::Unavailable => {
            // Not booted at EL2 (plain `virt`): graceful green skip, no vGIC armed.
            tb_hal::serial_write_str("L2.5: vgic OK (no EL2, skipped)\n");
        }
        tb_hal::VgicProof::NotApplicable => {
            // x86_64: no EL2/GIC virtualization -- the (deferred) APIC-virt path
            // would be this arch's rung.
            tb_hal::serial_write_str("L2.5: vgic OK (aarch64-only, n/a on x86_64)\n");
        }
        tb_hal::VgicProof::Faulted { code } => {
            // Booted at EL2 but the vGIC round-trip faulted -- surfaced honestly,
            // with NO 'vgic OK' substring, so the run grep fails (red).
            tb_hal::serial_write_str("L2.5: vgic FAIL code=");
            write_hex_u64(code);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit(); // #65: red NOW, not at the wall-clock ceiling
        }
    }

    // --- aL2.6: SMMUv3 stage-2 DMA-isolation table-programming -- the SEVENTH L2
    // rung, the IOMMU twin of L2.1's CPU stage-2 demand-translation. UNLIKE
    // L2.0..L2.5 (which world-switch through the resident EL2 monitor), this rung
    // runs ENTIRELY at EL1: the SMMUv3 is a memory-mapped platform device (QEMU
    // `virt` MMIO base 0x0905_0000, already inside the GiB0 Device identity
    // gigabyte mmu_init covers), programmed directly. The kernel probes
    // SMMU_IDR0.S2P==1 (stage-2 supported), builds a 1-entry LINEAR stream table +
    // ONE stage-2-only STE (Config==0b110) whose S2TTB == the SAME stage-2 L1 root
    // build_identity_stage2() produced, S2VMID == the CPU's VMID, and STE.VTCR ==
    // the projection of the CPU's compute_vtcr() (via the Kani-proven
    // tb_encode::smmuv3::ste_vtcr_from_vtcr_el2 LEMMA -- the SMMU stage-2 tables
    // ARE the CPU stage-2 tables), programs STRTAB_BASE/_CFG + CMDQ_BASE +
    // EVENTQ_BASE + CR0 (SMMUEN|CMDQEN|EVTQEN, CR0ACK-confirmed), pushes
    // CMD_CFGI_STE + CMD_TLBI_S12_VMALL + CMD_SYNC, and observes the SYNC drain
    // (CMDQ_CONS catches CMDQ_PROD) with GERROR clean (no CMDQ_ERR, no C_BAD_STE
    // event) -- i.e. the SMMU ACCEPTED the STE. This EXECUTES for real under TCG
    // (QEMU walks + accepts the STE) on a QEMU that advertises IDR0.S2P -- the
    // IOMMU twin of "stage2 OK", NOT a skip. NOTE: stage-2 SMMUv3 support landed in
    // QEMU 9.0 (2024), NOT 8.1; both local qemu-6.2 and the CI image qemu-8.2.2
    // advertise S1P=1 but S2P=0, so they take the green skip below until the CI
    // QEMU is >= 9.0, at which point the Proven path runs unchanged. THE HONEST
    // CLAIM: the marker
    // asserts ONLY "tables programmed + SMMU accepted them"; the ACTUAL
    // DMA-isolation GUARANTEE (a rogue device BLOCKED from memory outside its
    // grant) needs REAL SILICON (declared in assumptions.md, the L2.8/VT-d twin).
    // ALL the SMMU MMIO/asm unsafe is confined to tb-hal's arch/aarch64/smmu.rs
    // (the STE/command encoders in tb-encode are forbid(unsafe) + Kani-proven);
    // the kernel only branches on SmmuProof. The SMMU is left DISABLED
    // (teardown-clean) before M19, so M19's virtio-mmio path (NOT behind the SMMU)
    // is untouched -- the M19-prints-after-L2.6 marker is the teardown tripwire. On
    // x86_64 the VT-d/L2.8 path is x86's IOMMU rung, so it reports n/a. Skips
    // GREEN ("no SMMU, skipped") when booted WITHOUT iommu=smmuv3 or under a QEMU
    // older than 8.1 (so non-SMMU boot lanes stay green). DoD: "L2.6: smmu OK".
    match tb_hal::smmu_selftest() {
        tb_hal::SmmuProof::Proven { stream_id } => {
            tb_hal::serial_write_str("smmu: stage-2 STE accepted sid=");
            write_hex_u64(stream_id as u64);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::serial_write_str("L2.6: smmu OK\n"); // <-- the aL2.6 aarch64 DoD marker
        }
        tb_hal::SmmuProof::Unavailable => {
            // No stage-2 SMMU: either open-bus IDR0 (booted without iommu=smmuv3)
            // or IDR0.S2P==0 (an S1-only SMMU -- QEMU < 9.0, where stage-2 SMMUv3
            // support had not yet landed; QEMU 8.2.2 advertises S1P=1 but S2P=0).
            // A graceful green skip -- no stage-2 STE write attempted.
            tb_hal::serial_write_str("L2.6: smmu OK (no stage-2 SMMU, skipped)\n");
        }
        tb_hal::SmmuProof::NotApplicable => {
            // x86_64: no Arm SMMUv3 -- the (deferred) Intel VT-d / L2.8 path would
            // be this arch's IOMMU rung.
            tb_hal::serial_write_str("L2.6: smmu OK (aarch64-only, n/a on x86_64)\n");
        }
        tb_hal::SmmuProof::Faulted { code } => {
            // Probed S2P==1 but the table-programming round-trip faulted (alloc
            // OOM, CR0ACK timeout, SYNC timeout, GERROR, or a C_BAD_STE event) --
            // surfaced honestly, with NO 'smmu OK' substring, so the run grep is red.
            tb_hal::serial_write_str("L2.6: smmu FAIL code=");
            write_hex_u64(code);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit(); // #65: red NOW, not at the wall-clock ceiling
        }
    }

    // --- M27 (M27b): the CNTHP TIMER-PREEMPTED two-VMID sovereign time-partition
    // scheduler -- the sovereignty pillar's "TABOS owns time for two guests" rung,
    // built ON TOP of L2.1's stage-2 + L2.3's trap-and-emulate seam + M22's fold.
    // The EL2 monitor arms TWO distinct stage-2 roots (VMID 0 + 1) + the CNTHP
    // (EL2 physical timer) window -- the FIRST asynchronous IRQ ever taken at EL2
    // (the 0x480 vector slot, HCR_EL2.IMO=1 inside the armed window only) -- and
    // erets into the first of TWO trivial EL1 guest stubs; each, when scheduled,
    // SPINS storing to its DISTINCT (unmapped) device IPA -- every store
    // stage-2-faults to a per-VMID MMIO counter (the forward-progress witness a
    // guest cannot fake) -- and NEVER yields. When the slot's CNTHP deadline
    // expires, the 0x480 handler consults the Kani-proven
    // tb_encode::tpsched::next_slot, switches VTTBR_EL2 to the next VMID's root
    // (+ tlbi vmalls12e1is), folds a tb_encode::tpsched::SchedDecision into a
    // running sched_head (the M22 tb_encode::prov fold REUSED VERBATIM -- no new
    // fold math), RE-ARMS the next deadline BEFORE the GIC EOI (the storm-killer
    // order, with an ISTATUS read-back + a hard eoi cap), and resumes the next
    // guest. After K bounded major frames the handler tears the window down
    // (timer masked, HCR=RW, drop VTTBR, PPI disabled) BEFORE unwinding and
    // verifies the CONJUNCTION: both VMIDs advanced their cell (both-progressed,
    // neither starved), the observed VMID order is the tpsched round-robin
    // (order-honored), recompute(sched_head) matches the committed fold
    // (fold-verified) AND a single-byte tamper flips it (tamper-caught), and the
    // major frame is conserved (frame_total == Σ slot budgets). The preemption is
    // REAL but runs under QEMU TCG, which is NOT cycle-accurate: the marker emits
    // timing=TCG-NON-CYCLE-ACCURATE + realtime=NOT-CLAIMED -- an interleave/
    // liveness witness, never a latency or schedulability claim. ALL the
    // asm/unsafe is confined to tb-hal's arch/aarch64/{el2,el2_vectors,
    // tpsched_hal,stage2,el2mmio,timer}.rs (the tpsched leaf + the prov fold in
    // tb-encode are forbid(unsafe) + Kani-proven); the kernel only branches on
    // SchedProof. On x86_64 there is no EL2, so it reports the n/a path.
    // DoD: "M27: sched OK".
    match tb_hal::sched_selftest() {
        tb_hal::SchedProof::Proven { head, frames } => {
            // The honest witness line, fail-closed, positively required by the
            // run-script: render head=<hex16> + the bounded frame count + the six
            // =1 flags + the TCG-NON-CYCLE-ACCURATE / NOT-CLAIMED honesty tokens
            // (the run-script REJECTS the retired M27a COOPERATIVE-HVC-YIELD
            // token, so M27b can never be impersonated by the cooperative path).
            tb_hal::serial_write_str("sched: head=");
            write_hex_u64(head);
            tb_hal::serial_write_str(" frames=");
            write_hex_u64(frames);
            tb_hal::serial_write_str(" vmids=0x2 both-progressed=1 order-honored=1 fold-verified=1 tamper-caught=1 frame-conserved=1 timing=TCG-NON-CYCLE-ACCURATE realtime=NOT-CLAIMED\n");
            tb_hal::serial_write_str("M27: sched OK\n"); // <-- the M27 aarch64 DoD marker
        }
        tb_hal::SchedProof::Unavailable => {
            // Not booted at EL2 (plain `virt`): graceful green skip, no scheduler armed.
            tb_hal::serial_write_str("M27: sched OK (no EL2, skipped)\n");
        }
        tb_hal::SchedProof::NotApplicable => {
            // x86_64: no EL2 -- the (deferred) VMX-preemption-timer path would be
            // this arch's realization of the sovereign-scheduler rung.
            tb_hal::serial_write_str("M27: sched OK (aarch64-only, n/a on x86_64)\n");
        }
        tb_hal::SchedProof::Faulted { code } => {
            // Booted at EL2 but the timer-preempted round-trip (or its CNTHP
            // smoke prelude) faulted -- surfaced honestly, with NO 'sched OK'
            // substring, so the run grep fails (red).
            tb_hal::serial_write_str("M27: sched FAIL code=");
            write_hex_u64(code);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit(); // #65: red NOW, not at the wall-clock ceiling
        }
    }

    // --- M19: poll-based virtio-mmio virtio-rng -- the kernel's FIRST real
    // device I/O, the new cumulative boot tail. A MODERN (Version=2) virtio-rng
    // (DeviceID 4) driven over ONE virtqueue: a hard-coded slot scan, the
    // reset->ACK->DRIVER->features->FEATURES_OK->queue->DRIVER_OK handshake, one
    // WRITE-ONLY descriptor into an identity-mapped DMA frame, a POLL-ONLY (avail
    // VIRTQ_AVAIL_F_NO_INTERRUPT) used-ring completion under a fail-closed cap,
    // and a non-trivially-filled entropy buffer. ALL the MMIO/DMA/asm unsafe is
    // confined to tb-hal's arch/{x86_64,aarch64}/virtio.rs (the UC device-window
    // map + the aarch64 dmb/dsb barriers live there too); this kernel stays
    // unsafe-free and only branches on the returned `VirtioProof`. GRACEFUL GREEN
    // skip (Absent) when no virtio-rng is present -- e.g. tb-vmm with no -device,
    // where the scan reads open-bus 0xFFFF_FFFF != magic -- so vmm-boot stays
    // green with NO tb-vmm virtio backend. DoD: "M19: virtio OK".
    match tb_hal::virtio_selftest() {
        tb_hal::VirtioProof::Proven {
            slot,
            device_id,
            len,
        } => {
            tb_hal::serial_write_str("virtio: rng round-trip slot=");
            write_hex_u64(slot as u64);
            tb_hal::serial_write_str(" dev=");
            write_hex_u64(device_id as u64);
            tb_hal::serial_write_str(" len=");
            write_hex_u64(len as u64);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::serial_write_str("M19: virtio OK\n"); // <-- the M19 DoD marker
        }
        tb_hal::VirtioProof::Absent => {
            // No DeviceID==4 in any slot (e.g. tb-vmm with no -device: open-bus
            // read): a graceful GREEN skip -- the same marker substring, tagged.
            tb_hal::serial_write_str("M19: virtio OK (no device, skipped)\n");
        }
        tb_hal::VirtioProof::LegacyUnsupported => {
            // Found but legacy (Version != 2): this driver speaks only modern --
            // an honest GREEN skip.
            tb_hal::serial_write_str("M19: virtio OK (legacy v1, skipped)\n");
        }
        tb_hal::VirtioProof::Failed { stage } => {
            // Found + driven but the round-trip failed fail-closed -- surfaced
            // with NO 'virtio OK' substring, so the run-script grep fails (red).
            tb_hal::serial_write_str("M19: virtio FAIL stage=");
            write_hex_u64(stage as u64);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit(); // #65: red NOW, not at the wall-clock ceiling
        }
    }

    // ---- M20: durable persistence (the kernel's FIRST byte to outlive a boot) -
    // A poll-only modern virtio-mmio virtio-blk (DeviceID 2) backing a log-
    // structured store behind the M13 BackingStore seam. The selftest probes the
    // device, mount/formats the store on the freshly-attached disk, writes N
    // sentinel records through a real Region via the substrate's normal write
    // path (so push_record's backing.append exercises the real staged append),
    // runs the TWO-PHASE flush (records -> FLUSH barrier -> superblock gen+1 ->
    // FLUSH), DROPS the substrate (all RAM state destroyed), RE-MOUNTS the SAME
    // disk image, replays the Region log, and asserts the replayed records ==
    // the read-after-flush values AND gen bumped by exactly 1 -- a true
    // durability round-trip (the bytes left RAM, hit the device, came back on a
    // fresh mount). ALL the MMIO/DMA/asm unsafe is confined to tb-hal's
    // arch/{x86_64,aarch64}/virtio.rs; the on-disk codecs are the Kani-proven
    // tb_encode::blkfmt; the orchestration is 100% safe mem::VirtioBlkStore; this
    // kernel stays unsafe-free and only branches on the returned `PersistProof`.
    // GRACEFUL GREEN skip (no disk, skipped) when no virtio-blk is attached
    // (e.g. tb-vmm / any lane with no -drive: open-bus read != magic), so those
    // lanes stay green with NO script change. DoD: "M20: persist OK".
    match tb_hal::persist_selftest() {
        tb_hal::PersistProof::Proven {
            gen,
            replayed,
            prior,
        } => {
            tb_hal::serial_write_str("persist: gen=");
            write_hex_u64(gen);
            tb_hal::serial_write_str(" records=");
            write_hex_u64(replayed);
            tb_hal::serial_write_str(" replayed=");
            write_hex_u64(replayed);
            tb_hal::serial_write_str(" prior=");
            write_hex_u64(prior);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::serial_write_str("M20: persist OK\n"); // <-- the M20 DoD marker
        }
        tb_hal::PersistProof::Absent => {
            // No DeviceID==2 in any slot (e.g. a lane with no -drive: open-bus
            // read): a graceful GREEN skip -- the same marker substring, tagged.
            tb_hal::serial_write_str("M20: persist OK (no disk, skipped)\n");
        }
        tb_hal::PersistProof::LegacyUnsupported => {
            // Found but legacy (Version != 2): this driver speaks only modern --
            // an honest GREEN skip.
            tb_hal::serial_write_str("M20: persist OK (legacy v1, skipped)\n");
        }
        tb_hal::PersistProof::Failed { stage } => {
            // Found + driven but the round-trip failed fail-closed -- surfaced
            // with NO 'persist OK' substring, so the run-script grep fails (red).
            tb_hal::serial_write_str("M20: persist FAIL stage=");
            write_hex_u64(stage as u64);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit(); // #65: red NOW, not at the wall-clock ceiling
        }
    }

    // ---- M21: verified fixed-point ADDITIVE-policy leaf (forget/demote) --------
    // A Kani-proven, total/bounded/monotone-by-construction piecewise-LINEAR
    // integer GAM (NOT a neural net -- the knots are frozen offline + shipped as a
    // `const` i16 table) for the M17 forget/demote decision, that may only RANK
    // strictly INSIDE the existing heuristic safety envelope. It SHIPS DORMANT
    // (proposal §7): the heuristic floor in `mem::forget_sweep` owns every demote
    // decision (`KAN_ACTIVE == false`), so the proven M0..M20 boot chain is
    // BEHAVIORALLY UNCHANGED; the spline is WIRED + validated at load but never on
    // the decision path until an offline trace bake-off (which does not exist yet)
    // measures it to beat a tuned linear baseline. The fail-closed boot self-test
    // re-runs the solver-free MonoKAN + headroom structural validators on the
    // shipped frozen table AND a REAL round-trip (recompute `kan_score` over a baked
    // probe vector, require `delta <= B`), withholding the marker if any check
    // fails -- so a bad/poisoned/over-error table can never reach the comparator.
    // ALL value computation is the host-verifiable `tb_encode::kancell` (no_std,
    // forbid(unsafe), NO float); this kernel stays zero-unsafe and only branches on
    // the returned `KanProof` bools. DoD: "M21: kan-policy OK".
    {
        let kp = tb_hal::kan_selftest();
        // FAIL-CLOSED: both structural validators must pass AND the round-trip
        // deviation must be within the shipped bound. Any failure withholds the
        // marker (renders a FAIL line with NO 'kan-policy OK' substring) and exits
        // red NOW, exactly like the M20 Failed arm.
        if !kp.monotone || !kp.ovf_safe || kp.q_err > kp.bound {
            tb_hal::serial_write_str("M21: kan-policy FAIL monotone=");
            write_hex_u64(kp.monotone as u64);
            tb_hal::serial_write_str(" ovf-safe=");
            write_hex_u64(kp.ovf_safe as u64);
            tb_hal::serial_write_str(" q-err=");
            write_hex_u64(kp.q_err as u64);
            tb_hal::serial_write_str(" bound=");
            write_hex_u64(kp.bound as u64);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit(); // #65: red NOW, not at the wall-clock ceiling
        }
        // The REAL round-trip line (the anti-hollow-pass witness the run-scripts
        // positively require): the validators + round-trip provably ran at boot.
        tb_hal::serial_write_str("kan: monotone=");
        write_hex_u64(kp.monotone as u64);
        tb_hal::serial_write_str(" ovf-safe=");
        write_hex_u64(kp.ovf_safe as u64);
        tb_hal::serial_write_str(" q-err=");
        write_hex_u64(kp.q_err as u64);
        tb_hal::serial_write_str(" bound=");
        write_hex_u64(kp.bound as u64);
        tb_hal::serial_write_str(" active=");
        write_hex_u64(kp.active as u64);
        tb_hal::serial_write_byte(b'\n');
        // The marker. The spline ships DORMANT (the offline ship-gate margin is not
        // met -- no trace workload exists yet), so the heuristic floor decides and
        // the marker carries the honest `(heuristic floor, gate-not-met)` suffix.
        // It CONTAINS the `M21: kan-policy OK` substring the run-scripts grep; the
        // scripts also positively require the `kan:` round-trip line above (so a
        // hollow pass without the loader/validators FAILS) and reject a future
        // `(no table, skipped)` variant.
        tb_hal::serial_write_str("M21: kan-policy OK (heuristic floor, gate-not-met)\n");
    }

    // ---- M22: verified memory PROVENANCE LEDGER (mnemonic sovereignty) ---------
    // A per-agent, append-only, content-addressed HASH-CHAIN provenance ledger over
    // the M13 substrate: every memory mutation (write / forget-tombstone / skill-
    // admit) appends a typed entry whose 256-bit STRUCTURAL digest folds into a
    // running per-agent `chain_head`. The boot self-test writes N>=3 REAL Region
    // records, DEMOTES one through the ACTUAL M17 forget_sweep (a provable TOMBSTONE
    // -- M17's silent demote becomes a verifiable redaction), builds a GENUINE
    // inclusion proof + asserts verify==true on the clean ledger, then FLIPS ONE
    // BYTE of a COMMITTED entry's canonical bytes and asserts BOTH head-mismatch AND
    // inclusion-failure -- exercising the real verifier path, not a constant compare.
    // ALL value computation is the host-verifiable, Kani-proven `tb_encode::prov`
    // (no_std, forbid(unsafe), NO float); the digest is two+ domain-separated
    // `blkfmt::fnv1a64` lanes -- STRUCTURAL tamper-evidence, NOT cryptographic
    // (proposal §2 -- a crypto hash + signed root is a tracked successor). This
    // kernel stays zero-unsafe and only branches on the returned `ProvProof` bools.
    // The head is kept IN-RAM this milestone (it does NOT ride the M20 superblock),
    // so the M20 two-phase commit + persist_selftest gen-continuity stay byte-
    // identical (zero M20/M21 regression). DoD: "M22: provenance OK".
    {
        let pp = tb_hal::prov_selftest();
        // FAIL-CLOSED: the clean ledger must verify (recompute==head + faithful
        // reconstruction) AND a genuine inclusion proof must verify AND the injected
        // single-byte tamper must be caught on BOTH legs (head-mismatch AND
        // inclusion-fail). Any failure withholds the marker (renders a FAIL line
        // with NO 'provenance OK' substring) and exits red NOW, like the M20/M21
        // Failed arms (the #65 fail-closed idiom).
        if !pp.clean_ok || !pp.inclusion_ok || !pp.tamper_caught {
            tb_hal::serial_write_str("M22: provenance FAIL clean=");
            write_hex_u64(pp.clean_ok as u64);
            tb_hal::serial_write_str(" inclusion=");
            write_hex_u64(pp.inclusion_ok as u64);
            tb_hal::serial_write_str(" tamper-caught=");
            write_hex_u64(pp.tamper_caught as u64);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit(); // #65: red NOW, not at the wall-clock ceiling
        }
        // The REAL round-trip WITNESS line (the anti-hollow-pass non-vacuity the
        // run-scripts positively require): the verifiers provably RAN at boot over
        // real written + demoted records. `head` is a u64 fold of the 32-byte head.
        tb_hal::serial_write_str("prov: head=");
        write_hex_u64(pp.head);
        tb_hal::serial_write_str(" entries=");
        write_hex_u64(pp.entries);
        tb_hal::serial_write_str(" tamper-caught=");
        write_hex_u64(pp.tamper_caught as u64);
        tb_hal::serial_write_str(" inclusion=");
        write_hex_u64(pp.inclusion_ok as u64);
        tb_hal::serial_write_byte(b'\n');
        // The marker -- emitted ONLY when the clean head matches, the inclusion
        // proof verifies, AND the injected tamper was caught on both legs. There is
        // no device to be absent, so there is NO '(no ledger, skipped)' variant: a
        // skip is never legitimate here (the run-scripts reject one).
        tb_hal::serial_write_str("M22: provenance OK\n");
    }

    // ---- M23: verified EXPERIENCE CODEC + counterfactual shadow-recording -------
    // The verified Monitor/log layer of the learning loop. At each M17 forget/recall
    // decision the OS records an injective ExperienceRecord (the features it ALREADY
    // computes + the heuristic action + the COUNTERFACTUAL `kan_score` the DORMANT
    // cell would produce + RESERVED-but-unset propensity/outcome fields) into a
    // fixed-capacity drop-oldest ring folded into a SEPARATE per-agent `xp_head`
    // (REUSING the M22 fold -- the M22 `chain_head` is UNTOUCHED, so M22's
    // persist/prov witnesses stay byte-identical). The learned cell stays DORMANT
    // (`KAN_ACTIVE == false`): the shadow is logged ONLY, never changing a demote, so
    // the live forget/demote decision is BYTE-IDENTICAL to M22's. The boot self-test
    // SEEDS a memory-pressure scenario that forces >=3 forget-decisions + >=1
    // recall-touch, then proves (a) the clean `xp_head` matches the committed head +
    // a genuine inclusion proof, (b) a recorded feats row REPLAYED through the dormant
    // `kan_score` reproduces `kan_score_shadow` BIT-IDENTICALLY, (c) heuristic-
    // decision faithfulness, (d) a single-byte tamper of a committed record is caught.
    // ALL value computation is the host-verifiable, Kani-proven `tb_encode::exp`
    // (no_std, forbid(unsafe), NO float); this kernel stays zero-unsafe and only
    // branches on the returned `ExpProof` bools. M23 claims ONLY replay-determinism +
    // structural tamper-evidence -- NOT policy validity (the deterministic logging
    // policy gives degenerate propensity; validity is M24's burden, the exogenous
    // human-operator oracle is M25's). The honesty token
    // `oracle=DECLARED-PROXY-DEFERRED-M24` is machine-emitted so the marker
    // MECHANICALLY cannot overclaim. DoD: "M23: experience OK".
    {
        let xp = tb_hal::exp_selftest();
        // FAIL-CLOSED: the clean log must verify (recompute==head) AND a genuine
        // inclusion proof must verify AND a recorded feats row must replay BIT-EXACTLY
        // AND the heuristic action must be faithfully recorded AND the injected tamper
        // must be caught AND the learned cell must be DORMANT (kan_active==false -- the
        // shadow changed zero demotes). Any false withholds the marker (renders a FAIL
        // line with NO 'experience OK' substring) and exits red NOW (the #65 idiom).
        if !xp.clean_ok
            || !xp.inclusion_ok
            || !xp.replay_bitexact
            || !xp.heuristic_faithful
            || !xp.tamper_caught
            || xp.kan_active
        {
            tb_hal::serial_write_str("M23: experience FAIL clean=");
            write_hex_u64(xp.clean_ok as u64);
            tb_hal::serial_write_str(" inclusion=");
            write_hex_u64(xp.inclusion_ok as u64);
            tb_hal::serial_write_str(" replay-bitexact=");
            write_hex_u64(xp.replay_bitexact as u64);
            tb_hal::serial_write_str(" heuristic-faithful=");
            write_hex_u64(xp.heuristic_faithful as u64);
            tb_hal::serial_write_str(" tamper-caught=");
            write_hex_u64(xp.tamper_caught as u64);
            tb_hal::serial_write_str(" kan-active=");
            write_hex_u64(xp.kan_active as u64);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit(); // #65: red NOW, not at the wall-clock ceiling
        }
        // The REAL round-trip WITNESS line (the anti-hollow-pass non-vacuity the
        // run-scripts positively require): the codec/fold/replay/tamper verifiers
        // provably RAN at boot over real forget-decisions + a recall-touch. The
        // `oracle=` token is a LITERAL honesty string -- the marker mechanically
        // cannot claim validity the deterministic stream cannot support.
        tb_hal::serial_write_str("exp: head=");
        write_hex_u64(xp.head);
        tb_hal::serial_write_str(" records=");
        write_hex_u64(xp.records);
        tb_hal::serial_write_str(" replay-bitexact=");
        write_hex_u64(xp.replay_bitexact as u64);
        tb_hal::serial_write_str(" tamper-caught=");
        write_hex_u64(xp.tamper_caught as u64);
        tb_hal::serial_write_str(" kan_active=");
        write_hex_u64(xp.kan_active as u64);
        tb_hal::serial_write_str(" oracle=DECLARED-PROXY-DEFERRED-M24\n");
        // The marker -- emitted ONLY when the clean head matches, the inclusion proof
        // verifies, a recorded row replays bit-exactly, the heuristic action was
        // faithfully recorded, AND the injected tamper was caught. The log is IN-RAM
        // (durable spill is M24), so there is NO '(no log, skipped)' variant -- a skip
        // is never legitimate (the run-scripts reject one). The marker uses ONLY
        // recorded / replay-deterministic / tamper-evident terminology (no
        // validated/evaluated -- the deterministic-logging honesty discipline).
        tb_hal::serial_write_str("M23: experience OK\n");
    }

    // ---- M24: the HONEST ACTIVATION GATE (the honest #72 resolution) ------------
    // M24 closes the learning loop HONESTLY: (1) shielded epsilon-greedy exploration
    // restores statistical OVERLAP the M23 deterministic logging policy lacks (inside
    // the frozen M17 envelope, populating the M23-reserved propensity field); (2) a
    // deterministic 3-way RIGHT-CENSORED survival label measured on the UNFILTERED
    // read()-touch path (the recall-tier collider named, not silently handled); (3) a
    // partial-identification (Manski + Lipschitz-smoothness + empirical-Bernstein)
    // LOWER-BOUND estimator; (4) a conjunctive ONE-SHOT HCPI activation gate. The cell
    // flips ACTIVE only if `V_lower(kancell) - V_upper(heuristic) >= MARGIN` over a
    // distribution-shifted held-out split AND the re-asserted envelope-no-widening
    // proof. Because the traces are necessarily SYNTHETIC this milestone, the gate
    // does NOT clear -> 'M24: bakeoff OK (gate-not-met)' (the cell stays DORMANT) is
    // the DESIGNED, CORRECT outcome (the M21 idiom -- an honest gate that REFUSES is a
    // success). ALL value computation is the host-verifiable, Kani-proven
    // `tb_encode::explore` + `tb_encode::bakeoff` (no_std, forbid(unsafe), NO float);
    // this kernel stays zero-unsafe and only branches on the returned `BakeoffProof`
    // enum. The experience is kept IN-RAM (durable spill deferred -- the gate runs on
    // the in-RAM accumulated experience), so M20's two-phase commit + persist_selftest
    // stay byte-identical. DoD: "M24: bakeoff OK".
    {
        let bo = tb_hal::bakeoff_selftest();
        // Render the witness fields + the marker. FAIL-CLOSED: only the Failed arm
        // withholds the marker + exits red (the machinery did not execute a required
        // stage). The NotMet / NotEvaluable arms are FIRST-CLASS successes this
        // milestone (an honest gate that refuses), so they print the marker (with the
        // honest suffix). The Cleared arm is the (counterfactual) activation -- not
        // reached on synthetic traces, but rendered honestly if it ever is.
        match bo {
            tb_hal::BakeoffProof::Failed { stage } => {
                tb_hal::serial_write_str("M24: bakeoff FAIL stage=");
                write_hex_u64(stage as u64);
                tb_hal::serial_write_byte(b'\n');
                tb_hal::fail_exit(); // #65: red NOW, not at the wall-clock ceiling
            }
            tb_hal::BakeoffProof::Cleared {
                vlo_kan,
                vhi_heur,
                margin,
            } => {
                // The (counterfactual this milestone) activation: the gate cleared.
                // KAN_ACTIVE is still a const false (a real activation awaits M25's
                // human oracle), so this is reported honestly, not acted on. The
                // run-scripts ACCEPT only the dormant gate-not-met this milestone, so a
                // cleared verdict here would be flagged by the lane asserting dormancy.
                bakeoff_witness(vlo_kan, vhi_heur, margin, 1, 0, 0, 0, 0);
                tb_hal::serial_write_str("M24: bakeoff OK (gate-cleared)\n");
            }
            tb_hal::BakeoffProof::NotMet {
                vlo_kan,
                vhi_heur,
                margin,
                resolved,
                censored,
                overlap_mass,
                no_overlap,
            } => {
                // THE DESIGNED, CORRECT OUTCOME: the machinery executed (label +
                // estimator + gate + in-RAM replay), the gate was EVALUABLE, but the
                // margin was not met on the synthetic traces -> the cell stays DORMANT.
                bakeoff_witness(
                    vlo_kan,
                    vhi_heur,
                    margin,
                    0,
                    resolved,
                    censored,
                    overlap_mass,
                    no_overlap,
                );
                tb_hal::serial_write_str("M24: bakeoff OK (gate-not-met)\n");
            }
            tb_hal::BakeoffProof::NotEvaluable {
                resolved,
                overlap_mass,
            } => {
                // Too few resolved pairs / near-zero overlap: the gate is not EVALUABLE
                // (distinct from a genuine refusal). Still a first-class honest outcome.
                bakeoff_witness(0, 0, 0, 0, resolved, 0, overlap_mass, 0);
                tb_hal::serial_write_str(
                    "M24: bakeoff OK (gate-not-evaluable: insufficient resolved support)\n",
                );
            }
        }
    }

    // ---- M25: verified OPERATOR TRANSCRIPT (the exogenous-oracle channel) --------
    // The COMMUNICATION pillar's outbound half. M24's honest gate REFUSES to activate
    // the learned cell because a self-graded loop has no EXOGENOUS oracle; M25 builds
    // the channel that SURFACES the decisions to a human (the only valid exogenous
    // oracle -- Christiano RLHF arXiv:1706.03741; Thomas Seldonian Science 2019). The
    // OS emits a typed, tamper-evident transcript over serial -- INTRO (binds the
    // genesis to the LIVE M22 provenance head: "which instance am I", RATS RFC 9334),
    // MARKER, EXPERIENCE_DIGEST (the most-BORDERLINE M23 record, ranked by margin --
    // Settles active-learning), and a closing GATE_VERDICT (commits the final seq so a
    // truncated tail is caught -- Ma-Tsudik FssAgg) -- folding each into a running
    // `op_head` via the REUSED M22 fold, with a STRICTLY-MONOTONE seq folded INTO the
    // canonical bytes so a reader detects mutation/reorder/drop/truncation. The boot
    // self-test EMITS the transcript and plays the SIMULATED operator-verifier on it
    // (recompute the head + a genuine inclusion proof, assert strict-monotone seq, the
    // INTRO binding, the tail-truncation commit, and a single-byte tamper rejection).
    // ALL value computation is the host-verifiable, Kani-proven `tb_encode::opframe`
    // (no_std, forbid(unsafe), NO float; it REUSES the M22 prov fold verbatim); this
    // kernel stays zero-unsafe and only branches on the returned `OpframeProof` bools.
    // HONEST: the fold is KEYLESS (structural tamper-EVIDENCE, NOT cryptographic
    // authenticity -- `keyed=0`) and the verifier is the OS's own plumbing, NOT a human
    // (`oracle=HUMAN-DEFERRED-M26` -- the inbound RX + an enrolled operator credential
    // by which a human could COMMAND the M24 gate is M26). The transcript is TX-only +
    // IN-RAM this milestone, so M20's two-phase commit + the M22/M23 heads stay byte-
    // identical (the M22 `chain_head` is READ for the binding, never mutated). The
    // honesty tokens are machine-emitted so the marker mechanically cannot overclaim.
    // DoD: "M25: operator OK".
    {
        let op = tb_hal::opframe_selftest();
        // FAIL-CLOSED: the clean transcript must verify (recompute==head) AND a genuine
        // inclusion proof must verify AND the seq must be strictly monotone AND the
        // INTRO must bind the live M22 head AND the closing GATE_VERDICT must catch a
        // truncated tail AND the injected single-byte tamper must be caught. Any false
        // withholds the marker (renders a FAIL line with NO 'operator OK' substring) and
        // exits red NOW (the #65 fail-closed idiom).
        if !op.clean_ok
            || !op.inclusion_ok
            || !op.seq_monotone
            || !op.intro_bound
            || !op.truncation_caught
            || !op.tamper_caught
        {
            tb_hal::serial_write_str("M25: operator FAIL clean=");
            write_hex_u64(op.clean_ok as u64);
            tb_hal::serial_write_str(" inclusion=");
            write_hex_u64(op.inclusion_ok as u64);
            tb_hal::serial_write_str(" seq-monotone=");
            write_hex_u64(op.seq_monotone as u64);
            tb_hal::serial_write_str(" intro-bound=");
            write_hex_u64(op.intro_bound as u64);
            tb_hal::serial_write_str(" truncation-caught=");
            write_hex_u64(op.truncation_caught as u64);
            tb_hal::serial_write_str(" tamper-caught=");
            write_hex_u64(op.tamper_caught as u64);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit(); // #65: red NOW, not at the wall-clock ceiling
        }
        // The REAL round-trip WITNESS line (the anti-hollow-pass non-vacuity the run-
        // scripts positively require): the emit + recompute + seq + intro-binding +
        // truncation + tamper verifiers provably RAN at boot over a real emitted
        // transcript anchored to the live M22 head. `keyed=0` + `oracle=HUMAN-DEFERRED-
        // M26` are LITERAL honesty tokens -- the marker mechanically cannot claim crypto
        // authenticity or that a human replied.
        tb_hal::serial_write_str("opframe: tx_head=");
        write_hex_u64(op.head);
        tb_hal::serial_write_str(" frames=");
        write_hex_u64(op.frames);
        tb_hal::serial_write_str(" seq_monotone=");
        write_hex_u64(op.seq_monotone as u64);
        tb_hal::serial_write_str(" intro_bound=");
        write_hex_u64(op.intro_bound as u64);
        tb_hal::serial_write_str(" fold-verified=");
        write_hex_u64((op.clean_ok && op.inclusion_ok) as u64);
        tb_hal::serial_write_str(" tamper-caught=");
        write_hex_u64((op.tamper_caught && op.truncation_caught) as u64);
        tb_hal::serial_write_str(" keyed=0 oracle=HUMAN-DEFERRED-M26\n");
        // The marker -- emitted ONLY when the clean fold + inclusion verify, the seq is
        // strictly monotone, the INTRO binds the live head, the tail-truncation commit
        // holds, AND the injected tamper was caught. The transcript is IN-RAM + TX-only
        // (RX/auth is M26), so there is NO '(no channel, skipped)' variant -- a skip is
        // never legitimate (the run-scripts reject one). The marker uses ONLY surfaced /
        // tamper-evident / instance-binding terminology (no validated/evaluated -- the
        // honest discipline: the channel works, NOT that a policy was validated).
        tb_hal::serial_write_str("M25: operator OK\n");
    }

    // ---- M26: verified EL2 EXIT-TELEMETRY producer (the OS records its workload) -
    // The learning pillar's SECOND experience producer. The aarch64 EL2 (nVHE) monitor
    // ALREADY demuxes every guest exit by ESR_EL2.EC (the Kani-proven L2.2
    // el2_trap::classify_exit); M26 turns that demux into a BOUNDED, fixed-point,
    // injective TELEMETRY record -- each exit becomes {exit-class, a saturating log2
    // cost-proxy bucket, the cell count, logical time, vmid} folded into a per-instance
    // `tel_head` via the M22 prov fold REUSED verbatim. So the OS *records* its own
    // virtualization workload, a richer experience source next to the M17 forget/recall
    // decisions. The boot self-test feeds a FIXED synthetic ESR vector (one of each
    // class) through the demux and proves class-totality (six distinct classes, in-range
    // tags), bucket-exactness (each recorded bucket == an independent bucket_index), the
    // clean fold + a genuine inclusion proof, and a single-byte tamper rejection. ALL
    // value computation is the host-verifiable, Kani-proven `tb_encode::exittel` (no_std,
    // forbid(unsafe), NO float; it REUSES the el2_trap classifier + the M22 prov fold
    // verbatim); this kernel stays zero-unsafe and only branches on the returned
    // `ExitTelemetryProof` bools. HONEST: PRODUCER-ONLY -- the telemetry is recorded +
    // folded, NEVER fed to a policy whose decisions change the future exit distribution
    // (the confounding loop the M24 adversary named is structurally avoided); the
    // `tel_head` is SEPARATE from the M23 `xp_head`, so M22/M23 + M20's two-phase commit
    // stay byte-identical. The token `signal=OBSERVATIONAL-NONCAUSAL` is machine-emitted
    // so the marker mechanically cannot claim a causal state-signal. DoD: "M26:
    // exit-telemetry OK".
    {
        let et = tb_hal::exittel_selftest();
        // FAIL-CLOSED: every synthetic ESR must classify to an in-range, distinct class
        // AND the recorded buckets/counts must be exact AND the clean fold + inclusion
        // proof must verify AND the injected tamper must be caught. Any false withholds
        // the marker (renders a FAIL line with NO 'exit-telemetry OK' substring) and
        // exits red NOW (the #65 fail-closed idiom).
        if !et.class_total
            || !et.buckets_exact
            || !et.clean_ok
            || !et.inclusion_ok
            || !et.tamper_caught
        {
            tb_hal::serial_write_str("M26: exit-telemetry FAIL class-total=");
            write_hex_u64(et.class_total as u64);
            tb_hal::serial_write_str(" buckets-exact=");
            write_hex_u64(et.buckets_exact as u64);
            tb_hal::serial_write_str(" clean=");
            write_hex_u64(et.clean_ok as u64);
            tb_hal::serial_write_str(" inclusion=");
            write_hex_u64(et.inclusion_ok as u64);
            tb_hal::serial_write_str(" tamper-caught=");
            write_hex_u64(et.tamper_caught as u64);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit(); // #65: red NOW, not at the wall-clock ceiling
        }
        // The REAL round-trip WITNESS line (the anti-hollow-pass non-vacuity the run-
        // scripts positively require): the classifier-reuse + histogram + fold + tamper
        // verifiers provably RAN at boot over a synthetic exit vector. `signal=
        // OBSERVATIONAL-NONCAUSAL` is a LITERAL honesty token -- the marker mechanically
        // cannot claim the telemetry is a validated causal state-signal (it is recorded,
        // not learned-from; the confounding loop is not closed this milestone).
        tb_hal::serial_write_str("exittel: head=");
        write_hex_u64(et.head);
        tb_hal::serial_write_str(" records=");
        write_hex_u64(et.records);
        tb_hal::serial_write_str(" classes=");
        write_hex_u64(et.classes);
        tb_hal::serial_write_str(" class-total=");
        write_hex_u64(et.class_total as u64);
        tb_hal::serial_write_str(" buckets-exact=");
        write_hex_u64(et.buckets_exact as u64);
        tb_hal::serial_write_str(" fold-verified=");
        write_hex_u64((et.clean_ok && et.inclusion_ok) as u64);
        tb_hal::serial_write_str(" tamper-caught=");
        write_hex_u64(et.tamper_caught as u64);
        tb_hal::serial_write_str(" signal=OBSERVATIONAL-NONCAUSAL\n");
        // The marker -- emitted ONLY when class-totality holds, the buckets are exact,
        // the clean fold + inclusion verify, AND the injected tamper was caught. The
        // telemetry is IN-RAM + synthetic (a real EL2 exit producer drains here in M27+),
        // so there is NO '(no exits, skipped)' variant -- a skip is never legitimate. The
        // marker uses ONLY recorded / observational terminology (no validated/causal/
        // learned -- the PRODUCER-only honesty discipline).
        tb_hal::serial_write_str("M26: exit-telemetry OK\n");
    }

    // ---- M28: verified OPERATOR-INBOUND command (the exogenous-oracle CLOSURE) ----
    // ---- + M29: the KEYED-CRYPTO MAC (the M28 §5 named successor LANDED) --------
    // The CAPSTONE that closes the M23->M24->M25->M26->M27 learning loop. M24's honest
    // gate REFUSES to activate the learned cell because a self-graded loop has no
    // EXOGENOUS oracle; M25 SURFACES the decisions to a human (TX-only); M28 delivers
    // the human's authenticated COMMAND. The RX dual of M25: a SIMULATED enrolled
    // verifier (a compiled-in test key, two creds) answers the OS's freshness CHALLENGE
    // (a fresh per-boot nonce -- RATS RFC 9334 §10) and submits a well-formed, fresh,
    // head-bound, DUAL-AUTHORIZED ACTIVATE_CMD bound to the LIVE M22 head (the Terrapin
    // head-binding -- arXiv:2312.12422). The boot self-test plays the verifier: the RX
    // path ACCEPTS the valid command AND REJECTS a stale-nonce replay, a wrong-head
    // command, a single-credential command (the two-person rule), and a flipped-MAC
    // command. ALL value computation is the host-verifiable, Kani-proven
    // `tb_encode::opframe_rx` (no_std, forbid(unsafe), NO float); since M29 its keyed
    // MAC is the verified `tb_encode::khash` BLAKE2s-256 leaf (RFC 7693, native keyed
    // mode) in a derive-then-MAC composition, and its key evolution is a domain-
    // separated keyed-PRF call; this kernel stays zero-unsafe and only branches on the
    // returned `OpcmdProof` bools. HONEST (M29 tier): `mac=KEYED-CRYPTO` -- the
    // IMPLEMENTATION is verified (Kani totality/determinism/official-KAT/tamper on
    // concrete inputs) while primitive security is `sec=ASSUMED-FROM-LITERATURE`
    // (collision/preimage/PRF/forgery resistance of BLAKE2s is assumed from the
    // cryptanalysis literature, NEVER proven -- the Appel/HACL*/mlkem-native claim
    // boundary); `kat=RFC7693-PASS` is EARNED per boot (the self-test RECOMPUTES the
    // official vectors through the real compression, fail-closed, in `kat_ok`);
    // `sidechannel=NOT-CLAIMED` (constant-time-SHAPED code, no timing model);
    // `oldkey-zeroized=1` (erasure TESTED in the seam -- the Bellare-Yee forward-
    // security condition); and the oracle stays `oracle=SIMULATED-ENROLLED-KEY` (a
    // test key, NOT a human + NOT a real enrolment ceremony) -- a real hash makes the
    // key neither a human nor an activation. CRITICALLY the accepted command is
    // NECESSARY-NOT-SUFFICIENT: `kan_active=0` is REQUIRED (the command un-blocks the
    // M24 gate's oracle input, but M24's statistical bar is unmet on synthetic data, so
    // the cell stays DORMANT even WITH the command -- the designed, correct outcome).
    // The honesty tokens are machine-emitted so the marker mechanically cannot
    // overclaim; the M29 marker deliberately avoids the substring 'crypto' (all crypto
    // claims live ONLY in structured stripped tokens, so the run-scripts' bare-'crypto'
    // prose reject stays maximally strict). DoD: "M28: operator-cmd OK" then
    // "M29: khash-mac OK".
    {
        let oc = tb_hal::opcmd_selftest();
        // FAIL-CLOSED: the valid command must be ACCEPTED AND each of the four attacks
        // (stale-nonce / wrong-head / single-credential / flipped-MAC) must be REJECTED
        // AND the M29 in-boot KAT must have passed AND the old-key erasure must have
        // been demonstrated AND the cell must stay DORMANT (kan_active == false). Any
        // miss withholds BOTH markers (renders a FAIL line with NO 'operator-cmd OK' /
        // 'khash-mac OK' substring) and exits red NOW (the #65 fail-closed idiom).
        if !oc.accepted
            || !oc.stale_rejected
            || !oc.wronghead_rejected
            || !oc.single_cred_rejected
            || !oc.badmac_rejected
            || !oc.kat_ok
            || !oc.oldkey_zeroized
            || oc.kan_active
        {
            tb_hal::serial_write_str("M28: operator-cmd FAIL accepted=");
            write_hex_u64(oc.accepted as u64);
            tb_hal::serial_write_str(" stale-rejected=");
            write_hex_u64(oc.stale_rejected as u64);
            tb_hal::serial_write_str(" wronghead-rejected=");
            write_hex_u64(oc.wronghead_rejected as u64);
            tb_hal::serial_write_str(" single-cred-rejected=");
            write_hex_u64(oc.single_cred_rejected as u64);
            tb_hal::serial_write_str(" badmac-rejected=");
            write_hex_u64(oc.badmac_rejected as u64);
            tb_hal::serial_write_str(" kat=");
            write_hex_u64(oc.kat_ok as u64);
            tb_hal::serial_write_str(" oldkey-zeroized=");
            write_hex_u64(oc.oldkey_zeroized as u64);
            tb_hal::serial_write_str(" kan_active=");
            write_hex_u64(oc.kan_active as u64);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::fail_exit(); // #65: red NOW, not at the wall-clock ceiling
        }
        // The M29 khash WITNESS line (proposal §7): the primitive + the machine-emitted
        // prove/assume boundary. `kat=RFC7693-PASS` is EARNED -- the fail-closed gate
        // above already required `oc.kat_ok` (the self-test recomputed the official
        // RFC 7693 Appendix B + BLAKE2 reference-KAT vectors through the REAL
        // compression), so this literal token is only ever reachable when the KAT
        // genuinely passed this boot. `sec=ASSUMED-FROM-LITERATURE` concedes primitive
        // security; `sidechannel=NOT-CLAIMED` concedes any timing/cache/power model;
        // `tag=128` is the on-wire MAC truncation (RFC 2104 §5 / SP 800-107r1 §5.3.4).
        tb_hal::serial_write_str(
            "khash: prim=BLAKE2S-256 keylen=32 tag=128 kat=RFC7693-PASS sec=ASSUMED-FROM-LITERATURE sidechannel=NOT-CLAIMED\n",
        );
        // The REAL round-trip WITNESS line (the anti-hollow-pass non-vacuity the run-
        // scripts positively require): the decode/verify accept + the four precise
        // rejects provably RAN at boot over a real sealed command anchored to the live
        // M22 head + a fresh per-boot challenge. `mac=KEYED-CRYPTO` +
        // `kdf=DERIVE-THEN-MAC-DOMSEP` + `keyevolve=PRF-DOMSEP` +
        // `oracle=SIMULATED-ENROLLED-KEY` are LITERAL honesty tokens, `oldkey-zeroized`
        // is the TESTED erasure flag, and `kan_active=0` is the NECESSARY-NOT-
        // SUFFICIENT marker -- the line mechanically cannot claim a proven-secure MAC,
        // a human oracle, or an activation the M24 bar does not support.
        tb_hal::serial_write_str("opcmd: challenge=");
        write_hex_u64(oc.challenge);
        tb_hal::serial_write_str(" accepted=");
        write_hex_u64(oc.accepted as u64);
        tb_hal::serial_write_str(" stale-rejected=");
        write_hex_u64(oc.stale_rejected as u64);
        tb_hal::serial_write_str(" wronghead-rejected=");
        write_hex_u64(oc.wronghead_rejected as u64);
        tb_hal::serial_write_str(" single-cred-rejected=");
        write_hex_u64(oc.single_cred_rejected as u64);
        tb_hal::serial_write_str(" badmac-rejected=");
        write_hex_u64(oc.badmac_rejected as u64);
        tb_hal::serial_write_str(" oldkey-zeroized=");
        write_hex_u64(oc.oldkey_zeroized as u64);
        tb_hal::serial_write_str(" kan_active=");
        write_hex_u64(oc.kan_active as u64);
        tb_hal::serial_write_str(
            " mac=KEYED-CRYPTO kdf=DERIVE-THEN-MAC-DOMSEP keyevolve=PRF-DOMSEP oracle=SIMULATED-ENROLLED-KEY\n",
        );
        // The M28 marker -- emitted ONLY when the valid command was accepted, all four
        // attacks were rejected, AND the cell stayed dormant. The command is IN-RAM +
        // SIMULATED (a real enrolment ceremony + a trustworthy freshness clock are
        // named successors), so there is NO '(no key, skipped)' variant -- a skip is
        // never legitimate (the run-scripts reject one). The marker uses ONLY
        // auth-plumbing terminology (no validated/crypto/authenticated-human -- the
        // honest discipline: the channel + auth STRUCTURE works, NOT that a human
        // cryptographically authenticated a command).
        tb_hal::serial_write_str("M28: operator-cmd OK\n");
        // The M29 marker -- the NEW cumulative tail: the M28 MAC genuinely ran on the
        // verified khash leaf this boot (the KAT + the five gate legs above all held,
        // fail-closed). Deliberately NO 'crypto' substring in the marker text.
        tb_hal::serial_write_str("M29: khash-mac OK\n");
    }

    // DIAG (#65): final end-of-chain stack red-zone sweep before parking.
    #[cfg(target_arch = "aarch64")]
    tb_hal::stack_redzone_check();

    // #65 hardening (F4): the SINGLE legitimate clean-exit site. Every fail
    // path above terminated via `tb_hal::fail_exit()` (exit 1), so reaching
    // here means the full cumulative chain printed its markers; arm the gate
    // and ask QEMU to exit 0 NOW instead of idling to the harness's wall-clock
    // ceiling. Any OTHER entry into `qemu_exit_success` (the gate un-armed --
    // a wild ret / corrupted function pointer) prints a loud line and parks,
    // so corruption can never again fake a clean exit. Falls through to
    // `halt()` when semihosting is unavailable (non-harness boots).
    #[cfg(target_arch = "aarch64")]
    {
        tb_hal::qemu_exit_arm();
        tb_hal::qemu_exit_success();
    }
    tb_hal::halt()
}

/// Task A (\"ping\"): drives `ROUND_TRIPS` strict A,B,A,B round-trips against
/// task B, renders the M2 verdict, then hands the CPU back to the bootstrap
/// context so `rust_main` can run the M3/M4 sequence.
fn task_a_main() {
    let task_b = Task::from_raw(TASK_B_RAW.load(Ordering::Acquire));

    let mut a_loops: usize = 0; // canary 1: monotonic loop count
    let mut a_sum: usize = 0; // canary 2: accumulator over the index
    let mut a_pat: usize = PAT_A_INIT; // canary 3: rotating bit pattern

    let mut i: usize = 0;
    while i < ROUND_TRIPS {
        if TURN.load(Ordering::Acquire) != TURN_A {
            fail("A: turn flag not A at round start");
        }
        let c = COUNTER.load(Ordering::Acquire);
        if c != 2 * i {
            fail("A: shared counter out of sequence");
        }
        if black_box(a_loops) != i {
            fail("A: local loop canary corrupted");
        }
        COUNTER.store(c + 1, Ordering::Release);
        a_loops = black_box(a_loops) + 1;
        a_sum = black_box(a_sum).wrapping_add(i);
        a_pat = black_box(a_pat).rotate_left(1);
        TURN.store(TURN_B, Ordering::Release);

        tb_hal::yield_to(task_b); // <-- the cooperative switch under test

        if TURN.load(Ordering::Acquire) != TURN_A {
            fail("A: alternation broken after resume");
        }
        i += 1;
    }

    let mut want_sum: usize = 0;
    let mut want_pat: usize = PAT_A_INIT;
    let mut k: usize = 0;
    while k < ROUND_TRIPS {
        want_sum = black_box(want_sum).wrapping_add(k);
        want_pat = black_box(want_pat).rotate_left(1);
        k += 1;
    }
    if black_box(a_loops) != ROUND_TRIPS {
        fail("A: final loop count wrong");
    }
    if black_box(a_sum) != want_sum {
        fail("A: final sum canary wrong");
    }
    if black_box(a_pat) != want_pat {
        fail("A: final pattern canary wrong");
    }
    if COUNTER.load(Ordering::Acquire) != 2 * ROUND_TRIPS {
        fail("A: final shared counter wrong");
    }
    if !B_VERIFIED.load(Ordering::Acquire) {
        fail("A: task B never reported success");
    }

    tb_hal::serial_write_str("M2: context-switch OK\n"); // <-- the M2 DoD marker

    M2_PASSED.store(true, Ordering::Release);
    tb_hal::yield_to(Task::from_raw(BOOT_TASK_RAW.load(Ordering::Acquire)));

    fail("A: resumed after handing control back to bootstrap")
}

/// Task B (\"pong\"): mirror half of the ping-pong, with its own canary locals
/// live across every yield. Audits its canaries on the FINAL round before the
/// last yield and publishes the verdict via `B_VERIFIED`.
fn task_b_main() {
    let task_a = Task::from_raw(TASK_A_RAW.load(Ordering::Acquire));

    let mut b_loops: usize = 0; // canary 1: monotonic loop count
    let mut b_sum: usize = 0; // canary 2: accumulator over the index
    let mut b_pat: usize = PAT_B_INIT; // canary 3: rotating bit pattern

    let mut j: usize = 0;
    while j < ROUND_TRIPS {
        if TURN.load(Ordering::Acquire) != TURN_B {
            fail("B: turn flag not B at round start");
        }
        let c = COUNTER.load(Ordering::Acquire);
        if c != 2 * j + 1 {
            fail("B: shared counter out of sequence");
        }
        if black_box(b_loops) != j {
            fail("B: local loop canary corrupted");
        }
        COUNTER.store(c + 1, Ordering::Release);
        b_loops = black_box(b_loops) + 1;
        b_sum = black_box(b_sum).wrapping_add(j);
        b_pat = black_box(b_pat).rotate_left(1);
        j += 1;

        if j == ROUND_TRIPS {
            let mut want_sum: usize = 0;
            let mut want_pat: usize = PAT_B_INIT;
            let mut k: usize = 0;
            while k < ROUND_TRIPS {
                want_sum = black_box(want_sum).wrapping_add(k);
                want_pat = black_box(want_pat).rotate_left(1);
                k += 1;
            }
            if black_box(b_loops) != ROUND_TRIPS {
                fail("B: final loop count wrong");
            }
            if black_box(b_sum) != want_sum {
                fail("B: final sum canary wrong");
            }
            if black_box(b_pat) != want_pat {
                fail("B: final pattern canary wrong");
            }
            B_VERIFIED.store(true, Ordering::Release);
        }

        TURN.store(TURN_A, Ordering::Release);
        tb_hal::yield_to(task_a); // <-- the cooperative switch under test
    }

    fail("B: resumed after completing all rounds")
}

/// Emit the M2 failure verdict (\"M2: FAIL <why>\") over serial and park the
/// core. Never returns; the run scripts then miss the later markers.
fn fail(why: &str) -> ! {
    tb_hal::serial_write_str("M2: FAIL ");
    tb_hal::serial_write_str(why);
    tb_hal::serial_write_byte(b'\n');
    tb_hal::fail_exit()
}

/// M9 spin task C: the involuntary-preemption proof. It NEVER `yield_to`s. It
/// unmasks interrupts ONCE at the top -- a task first-activated through
/// `ctx_switch` is entered with interrupts still masked from the IRQ that
/// switched into it (it never passed through an `iretq`/`eret` that would
/// restore them), so it must go preemptible itself -- then loops forever bumping
/// its own counter. The loop has no `yield_to` / `wfi` / `hlt` / `cli`; only the
/// periodic timer can take the CPU from it, which is exactly the property M9
/// proves. It must never return (M2's `task_exit_guard` would catch it loudly).
fn spin_c() {
    tb_hal::irq_unmask(); // become preemptible exactly once, then never yield
    loop {
        SPIN_C_COUNT.fetch_add(1, Ordering::Relaxed);
        core::hint::spin_loop();
    }
}

/// M9 spin task D: identical to `spin_c` but bumps its own counter, so the
/// self-test can prove BOTH no-yield tasks advanced under round-robin preemption.
fn spin_d() {
    tb_hal::irq_unmask(); // become preemptible exactly once, then never yield
    loop {
        SPIN_D_COUNT.fetch_add(1, Ordering::Relaxed);
        core::hint::spin_loop();
    }
}

/// M14.2: the SENDER kernel task (slot 11). It (1) becomes preemptible, (2)
/// waits until the boot RECEIVER is demonstrably parked OFF the run queue, then
/// (3) delivers `M14B_SENTINEL` over agent_c's endpoint -- whose runnable-on-send
/// wake makes the receiver RUNNABLE, after which the armed M9 timer's next
/// `schedule()` switches back to it. The send (and its AGENTS borrow) runs UNDER
/// MASKED INTERRUPTS so a timer tick cannot switch to the just-woken receiver
/// while the borrow is live (the registry's single-`&mut`-at-a-time discipline).
/// Then it parks forever (the boot task never yields back -- the M9/M12 spin-task
/// precedent). Never returns.
fn blk_sender() {
    // Become preemptible: a freshly-activated task is entered through ctx_switch's
    // plain return with interrupts masked, so it unmasks itself once so the armed
    // timer can later drive schedule() back to the woken receiver.
    tb_hal::irq_unmask();

    let boot = Task::from_raw(BLK_BOOT_SLOT.load(Ordering::Acquire));
    // Wait until the receiver has parked OFF the run queue. Bounded so a
    // never-blocking receiver (a bug) is a loud failure, not an infinite spin;
    // blk_sender stays preemptible here, so the receiver can run AND block.
    let mut stall: u64 = 0;
    const STALL_LIMIT: u64 = 2_000_000_000;
    while !tb_hal::task_is_blocked(boot) {
        stall += 1;
        if stall > STALL_LIMIT {
            m14b_fail("sender never observed the receiver block off the run queue");
        }
        core::hint::spin_loop();
    }
    // The receiver is demonstrably descheduled BEFORE we deliver -> the direct
    // "off the run queue" witness.
    RECV_BLOCKED_OBSERVED.store(true, Ordering::Release);

    // Deliver the sentinel UNDER MASKED INTERRUPTS: the send's runnable-on-send
    // wake makes the receiver RUNNABLE; masking guarantees no timer tick switches
    // to it while this send still holds the AGENTS `&mut`. After we unmask, the
    // next tick's schedule() performs the actual switch to the woken receiver.
    let agent_c = Task::from_raw(SEND_AGENT_SLOT.load(Ordering::Acquire));
    let ep_a = tb_hal::caps::Handle::from_raw(SEND_EP_RAW.load(Ordering::Acquire));
    let guard = tb_hal::local_irq_save();
    let (st, _) =
        tb_hal::agent_chan_send(agent_c, ep_a, M14B_SENTINEL, 0).unwrap_or((u32::MAX, 0));
    BLK_SENT_DONE.store(true, Ordering::Release);
    tb_hal::local_irq_restore(guard);
    if st != tb_hal::caps::SysStatus::Ok as u32 {
        m14b_fail("sender's wake-causing send did not return Ok");
    }

    // Park forever: once woken, the boot receiver runs to the marker and disarms
    // the timer; it never yields back here, so this task is simply abandoned.
    loop {
        core::hint::spin_loop();
    }
}

/// M14.2: fail-closed verdict for the blocking-recv self-test (report + halt).
fn m14b_fail(why: &str) -> ! {
    tb_hal::serial_write_str("M14.2: FAIL ");
    tb_hal::serial_write_str(why);
    tb_hal::serial_write_byte(b'\n');
    tb_hal::fail_exit()
}

/// M10 task G: runs in address space E (the `yield_to` fold-in flips the live
/// root to E before this task is entered). Writes its private magic THROUGH the
/// shared test VA and reads back ONLY its own, publishes the verdict, then hands
/// the CPU to task H (which yields on to the boot task). Never returns.
fn task_g_main() {
    let seen = tb_hal::addr_store_load(M10_TEST_VA, MAGIC_E);
    if seen == MAGIC_E {
        G_SEES_OWN.store(true, Ordering::Release);
    }
    tb_hal::serial_write_str("addrspace: task G wrote+read its magic under space E\n");
    tb_hal::yield_to(Task::from_raw(TASK_H_RAW.load(Ordering::Acquire)));
    // Normal flow never resumes G; if it somehow does, fail loudly.
    tb_hal::serial_write_str("M10: FAIL task G resumed after hand-off\n");
    tb_hal::fail_exit()
}

/// M10 task H: as task G but in address space F; after writing+verifying its own
/// magic it yields back to the boot task, which renders the isolation checks and
/// the M10 verdict. Never returns.
fn task_h_main() {
    let seen = tb_hal::addr_store_load(M10_TEST_VA, MAGIC_F);
    if seen == MAGIC_F {
        H_SEES_OWN.store(true, Ordering::Release);
    }
    tb_hal::serial_write_str("addrspace: task H wrote+read its magic under space F\n");
    tb_hal::yield_to(Task::from_raw(BOOT10_RAW.load(Ordering::Acquire)));
    // Normal flow never resumes H; if it somehow does, fail loudly.
    tb_hal::serial_write_str("M10: FAIL task H resumed after hand-off\n");
    tb_hal::fail_exit()
}

/// Safe trap-dispatch policy hook (kept from M1: policy lives in this
/// `forbid(unsafe_code)`-class crate, not in tb-hal's raw entry asm).
fn trap_hook(info: &TrapInfo) -> TrapAction {
    match info.kind {
        TrapKind::Breakpoint => {
            tb_hal::serial_write_str("trap: breakpoint, resuming\n");
            TrapAction::Resume
        }
        // M10: the armed cross-space page fault. Under the default root the test
        // VA is vacant; reading it faults here. Record it and, as a GUARDED
        // resume, flip the live root to the home space (where the VA IS mapped)
        // so the re-executed access completes instead of livelocking. Disarm
        // first so any later stray fault still takes the fatal path below. Every
        // root shares the kernel half, so this handler's stack/code/serial
        // survive the flip. The compare is page-aligned (low 12 bits masked) so
        // any sub-page-offset probe access still matches the armed page.
        TrapKind::PageFault
            if M10_FAULT_ARMED.load(Ordering::Acquire)
                && (info.fault_addr & !0xFFF)
                    == (M10_FAULT_VA.load(Ordering::Acquire) & !0xFFF) =>
        {
            M10_FAULT_ARMED.store(false, Ordering::Release);
            M10_FAULT_SEEN.store(true, Ordering::Release);
            tb_hal::address_space_switch_root(M10_FAULT_HOME_ROOT.load(Ordering::Acquire));
            TrapAction::Resume
        }
        _ => {
            tb_hal::serial_write_str("trap: fatal fault, halting\n");
            tb_hal::serial_write_str("  cause=");
            write_hex_u64(info.cause);
            tb_hal::serial_write_str(" fault_addr=");
            write_hex_u64(info.fault_addr);
            tb_hal::serial_write_str(" pc=");
            write_hex_u64(info.pc);
            tb_hal::serial_write_byte(b'\n');
            TrapAction::Halt
        }
    }
}

/// Write a `u64` as a fixed-width 16-digit `0x…` hex string over serial.
/// Pure safe Rust (no `core::fmt`, no allocation).
fn write_hex_u64(value: u64) {
    tb_hal::serial_write_str("0x");
    let mut shift: i32 = 60;
    while shift >= 0 {
        let nibble = ((value >> shift) & 0xf) as u8;
        let c = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
        tb_hal::serial_write_byte(c);
        shift -= 4;
    }
}

/// M24: render the bake-off witness line (proposal §6, printed BEFORE the marker,
/// fail-closed, positively required by the run-scripts). The `confound=`/`estimator=`
/// tokens are LITERAL honesty strings -- the marker mechanically cannot overclaim. The
/// `no-float=1` + `envelope-no-widening=1` tokens are required by the run-scripts. The
/// signed `vlo_kan`/`vhi_heur`/`margin` are rendered as two's-complement hex (the
/// witness is a deterministic non-vacuity proof, not a decoded value). `cleared=0` is
/// the synthetic-trace outcome (the cell stays DORMANT). Pure safe Rust.
#[allow(clippy::too_many_arguments)]
fn bakeoff_witness(
    vlo_kan: i64,
    vhi_heur: i64,
    margin: i64,
    cleared: u64,
    resolved: u64,
    censored: u64,
    overlap_mass: u64,
    no_overlap: u64,
) {
    tb_hal::serial_write_str("bakeoff: vlo_kan=");
    write_hex_u64(vlo_kan as u64);
    tb_hal::serial_write_str(" vhi_heur=");
    write_hex_u64(vhi_heur as u64);
    tb_hal::serial_write_str(" margin=");
    write_hex_u64(margin as u64);
    tb_hal::serial_write_str(" overlap-restored-eps=");
    write_hex_u64(overlap_mass);
    tb_hal::serial_write_str(" resolved=");
    write_hex_u64(resolved);
    tb_hal::serial_write_str(" censored=");
    write_hex_u64(censored);
    tb_hal::serial_write_str(" no-overlap-mass=");
    write_hex_u64(no_overlap);
    tb_hal::serial_write_str(" cleared=");
    write_hex_u64(cleared);
    tb_hal::serial_write_str(
        " confound=RECALL-CENSORS-COLD-NAMED estimator=MANSKI+SMOOTHNESS-LP no-float=1 envelope-no-widening=1\n",
    );
}

/// Minimal `core::fmt::Write` sink over the serial console, used ONLY by the
/// panic handler so it can render the panic message + location (the rest of
/// the kernel keeps its no-`core::fmt` discipline). Pure safe Rust.
struct PanicSerialWriter;

impl core::fmt::Write for PanicSerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        tb_hal::serial_write_str(s);
        Ok(())
    }
}

/// Panic handler: report the panic MESSAGE + LOCATION over serial, then exit
/// QEMU with a NONZERO code (or halt when semihosting is unavailable).
///
/// DIAG (#65): the old handler printed a bare "panic" and exited 0 via
/// `qemu_exit_success` -- so a corruption-induced panic produced a CLEAN
/// rc=0 exit that read as "control flow reached qemu_exit_success from its
/// top" (manifestation 3). Now: (a) the file:line + message pinpoint the
/// failing source line, (b) the exit code is 1 (`qemu_exit_failure`), so a
/// panicking boot can never again masquerade as a clean exit.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use core::fmt::Write;
    tb_hal::serial_write_str("panic: ");
    let mut w = PanicSerialWriter;
    let _ = write!(w, "{}", info.message());
    if let Some(loc) = info.location() {
        let _ = write!(w, " @ {}:{}:{}", loc.file(), loc.line(), loc.column());
    }
    tb_hal::serial_write_byte(b'\n');
    // Exit QEMU NOW (semihosting SYS_EXIT, code 1) instead of parking to the
    // wall-clock ceiling. Falls through to halt() when semihosting is
    // unavailable (non-harness boots).
    #[cfg(target_arch = "aarch64")]
    tb_hal::qemu_exit_failure();
    tb_hal::halt()
}
