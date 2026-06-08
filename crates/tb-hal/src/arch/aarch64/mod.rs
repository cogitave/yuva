//! aarch64 backend for the `tb-hal` foundation crate.
//!
//! One of the two `#[cfg(target_arch)]` arms re-exported by `arch/mod.rs`. It
//! exposes the aarch64 primitives the safe `tb-hal` public API (`lib.rs`)
//! delegates to: [`serial_init`], [`serial_write_byte`], [`halt`] (M0), the
//! M1 trap surface [`install_traps`] and [`breakpoint`], the M2
//! cooperative-scheduling primitives [`ctx_switch`] and [`task_stack_init`]
//! (backing `lib.rs`'s safe `Task` / `task_create` / `yield_to`), the M3
//! MMU surface [`mmu_init`] / [`mmu_selftest`] (cold stage-1 bring-up +
//! 4 KiB map / Break-Before-Make remap self-test), and the M4 user/ring
//! surface [`user_demo`] (drop to EL0, `svc`, trap back into EL1).
//! (`serial_write_str` is composed in `lib.rs` from `serial_write_byte`, so it
//! is arch-independent.)
//!
//! Boot contract for the M0/M1 QEMU `virt` path (verified facts,
//! KERNEL-FOUNDATION-SPEC SS2): the vCPU enters `_start` at **EL1h, MMU OFF,
//! DAIF masked**, with **x0 = FDT/DTB pointer** (AAPCS64 arg0 already).
//! `boot.rs` owns that entry; `serial.rs` owns the PL011 UART; `vectors.rs`
//! owns the `VBAR_EL1` table; `trap.rs` owns the Rust trap dispatch;
//! `sched.rs` owns the M2 context switch (callee-saved x19..x30 + SP) and the
//! new-task initial-frame fabrication (x30 = entry); `mmu.rs` owns the M3
//! cold MMU bring-up (the MMU stays OFF until `rust_main` calls
//! [`mmu_init`] -- identity 1 GiB blocks: Device @ 0 covering the PL011,
//! Normal WB @ 0x4000_0000 covering RAM); `user.rs` owns the M4 EL0 excursion
//! (the EL0 entry/exit asm + the user-page mapping + the round-trip
//! [`user_demo`]). `vectors.rs`'s "Lower EL using AArch64, Synchronous" slot is
//! now a REAL handler (`__vec_el0_sync` -> `aarch64_el0_sync_handler` in
//! `user.rs`); the rest of the Lower-EL quadrant remains a fatal stub.

mod boot; // _start; arms VBAR_EL1; pure side-effect (`global_asm!`) module.
mod mmu; // M3: cold MMU bring-up + 4 KiB map / BBM remap self-test.
mod pmm; // M6: QEMU `virt` boot memory-map source (hard-coded map + DTB reserve).
mod sched; // M2: ctx_switch (x19..x30 + SP) + initial-frame fabrication.
mod serial; // PL011 @ 0x0900_0000 (QEMU `virt` UART0).
mod timer; // M8: GICv2 + EL1 physical timer (PPI 30); IRQ ack/EOI/tick + CNTPCT.
mod trap; // Rust trap dispatch + breakpoint(); the only raw-frame deref.
mod user; // M4: EL0 entry/exit + user-page mapping + user_demo round-trip.
mod vectors; // VBAR_EL1 table + entry/exit stubs; pure `global_asm!` module.

pub use mmu::{heap_window, map_heap_frames, mmu_init, mmu_selftest};
pub use pmm::pmm_collect_regions;
pub use sched::{ctx_switch, task_stack_init};
pub use serial::{serial_init, serial_write_byte};
pub use timer::{read_cycle_counter, sched_irq_unmask, timer_demo, timer_disarm, timer_rearm};
pub use trap::breakpoint;
pub use user::user_demo;

// -- install_traps() --------------------------------------------------------
// (a) PRE : called once from rust_main, after serial_init, at EL1h. POST:
//           VBAR_EL1 == &__exception_vectors (the 2 KiB-aligned table in
//           vectors.rs) and an `isb` has made the new vector base
//           architecturally visible. Idempotent: `_start` already pre-armed the
//           very same table, so a second call just re-writes the same value.
// (b) ABI : clobbers one scratch x-register; touches no memory/stack; takes no
//           args. Arm ARM D19.2 requires a context-synchronisation event after
//           writing VBAR_EL1 before relying on it -- the `isb` provides it.
// (c) TEST: scripts/run-aarch64.sh -- after install, breakpoint() is caught,
//           the hook resumes, and the kernel prints "M1: traps OK".
/// Install the EL1 exception vectors (`VBAR_EL1`). Idempotent; call once.
pub fn install_traps() {
    // SAFETY: writing VBAR_EL1 is legal at EL1 and merely (re)selects our own
    // 2 KiB-aligned vector table (`vectors.rs`); `adrp/add :lo12:` form its
    // address with no memory access, and `isb` synchronises the change.
    unsafe {
        core::arch::asm!(
            "adrp {t}, __exception_vectors",
            "add  {t}, {t}, :lo12:__exception_vectors",
            "msr  vbar_el1, {t}",
            "isb",
            t = out(reg) _,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// -- halt() -----------------------------------------------------------------
// (a) PRE : any state; called on the M0/M1 happy path after the marker is
//           flushed, from the kernel #[panic_handler], and from the trap
//           handler's fatal (Halt) path. POST: never returns -- the vCPU is
//           parked in a low-power wait, re-parking on any wake event.
// (b) ABI : `wfi` clobbers nothing, touches no memory/stack, preserves NZCV.
// (c) TEST: scripts/run-aarch64.sh -- the kernel reaches here after printing
//           "M1: traps OK"; the runner times out and asserts the marker.
/// Halt the current vCPU forever (low-power wait loop).
pub fn halt() -> ! {
    loop {
        // SAFETY: `wfi` is an unprivileged hint with no memory or stack
        // effects; it is always legal at EL1 and merely suspends the core
        // until a wake event, after which we loop and re-park.
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack, preserves_flags));
        }
    }
}
