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

mod boot; // _start; EL-aware bring-up + nVHE EL2-monitor install; arms VBAR_EL1.
mod el2; // L2.0: resident nVHE EL2 monitor (HVC handler) + el2_selftest() facade.
mod el2_vectors; // L2.0: VBAR_EL2 table + EL2 save path; pure `global_asm!` module.
mod el2mmio; // L2.3: trap-and-emulate arming (HCR.VM|TVM) + the MMIO device seam + served cell.
mod exits; // L2.2: EL2 exit-dispatch arming (HCR.TWI|TWE + CPTR.TFP) + served-mask cell.
mod exits_vectors; // L2.2: __l2_guest_vectors EL1 table (inject-UNDEF target); pure asm.
mod mmu; // M3: cold MMU bring-up + 4 KiB map / BBM remap self-test.
mod pmm; // M6: QEMU `virt` boot memory-map source (hard-coded map + DTB reserve).
mod sched; // M2: ctx_switch (x19..x30 + SP) + initial-frame fabrication.
mod serial; // PL011 @ 0x0900_0000 (QEMU `virt` UART0).
mod stage2; // L2.1: stage-2 demand-translation builder/arm/abort glue (+ HOLE_IPA).
mod timer; // M8: GICv2 + EL1 physical timer (PPI 30); IRQ ack/EOI/tick + CNTPCT.
mod trap; // Rust trap dispatch + breakpoint(); the only raw-frame deref.
mod uaccess; // M14.1: cross-address-space user-buffer copy (the only new aarch64 unsafe).
mod user; // M4: EL0 entry/exit + user-page mapping + user_demo round-trip.
mod vectors; // VBAR_EL1 table + entry/exit stubs; pure `global_asm!` module.
mod virtio; // M19: poll-based modern virtio-mmio virtio-rng (the kernel's FIRST device I/O).

pub use el2::el2_selftest; // L2.0: the safe EL2 world-switch self-test facade.
pub use el2::el2_exits_selftest; // L2.2: the safe EL2 exit-dispatch self-test facade.
pub use el2::el2_trap_selftest; // L2.3: the safe trap-and-emulate self-test facade.
pub use el2::stage2_selftest; // L2.1: the safe stage-2 demand-translation self-test facade.
pub use virtio::virtio_selftest; // M19: the safe virtio-rng self-test facade.
pub use mmu::{
    address_space_new, current_root, heap_window, m3_test_va_intact, map_heap_frames, map_in_root,
    map_user_in_root, mmu_init, mmu_selftest, switch_root, unmap_in_root, va_to_pa_in_root,
};
pub use pmm::pmm_collect_regions;
pub use sched::{ctx_switch, task_stack_init, task_stack_init_user};
pub use serial::{serial_init, serial_write_byte};
pub use timer::{
    local_irq_restore, local_irq_save, read_cycle_counter, sched_irq_unmask, timer_demo,
    timer_disarm, timer_rearm,
};
pub use trap::breakpoint;
// M14.1: the safe cross-address-space user-buffer copy surface (the walk + the
// byte copy via the EL1 identity alias), re-exported through `arch/mod.rs` so
// the kernel facade drives the bounce-buffer fill/drain. Same names + signatures
// as the x86_64 arm, one uniform contract.
pub use uaccess::{copy_from_user, copy_to_user};
pub use user::{agent_map_space, agent_traps_init, caps_user_probe, user_demo};

/// M12: program the running agent's kernel stack for the privilege-change frame.
/// A NO-OP on aarch64: there is no `TSS.rsp0` analogue -- `SP_EL1` already tracks
/// the current task's kernel stack (the M2 `ctx_switch` swaps SP at EL1h, and the
/// launch/resume `eret` leaves SP_EL1 at the agent's stack top), so an EL0 IRQ
/// pushes onto the agent's own kernel stack with no per-switch poke. Mirrors the
/// x86_64 `set_kernel_stack` so `lib.rs`'s `yield_to` fold-in is cross-arch.
pub fn set_kernel_stack(_top: u64) {}

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
