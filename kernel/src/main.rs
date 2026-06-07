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

use core::hint::black_box;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tb_hal::{Task, TaskStack, TrapAction, TrapInfo, TrapKind};

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

/// Boot entry. Reached by EITHER of tb-hal's two x86_64 entries (or the
/// aarch64 `_start`); each sets up a stack and places the boot-info pointer in
/// SysV arg0 before calling here:
///   * PVH (`_start`, QEMU/Firecracker): `rdi` = `hvm_start_info` phys addr.
///   * tb-boot v0 (`_tb_start`, the project's `tb-vmm`): `rdi` = guest-physical
///     `tb_boot::TbBootInfo` addr (identity-mapped; magic-validated below).
///   * aarch64 (`_start`): `x0` = FDT blob (MV is an x86_64-first follow-up).
#[unsafe(no_mangle)]
pub extern "C" fn rust_main(boot_info: usize) -> ! {
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
        tb_hal::halt();
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
    tb_hal::halt()
}

/// Safe trap-dispatch policy hook (kept from M1: policy lives in this
/// `forbid(unsafe_code)`-class crate, not in tb-hal's raw entry asm).
fn trap_hook(info: &TrapInfo) -> TrapAction {
    match info.kind {
        TrapKind::Breakpoint => {
            tb_hal::serial_write_str("trap: breakpoint, resuming\n");
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

/// Panic handler: best-effort marker over serial, then halt forever.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    tb_hal::serial_write_str("panic\n");
    tb_hal::halt()
}
