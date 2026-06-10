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
mod diag; // #65: stack red-zones + raw-word probe (boot-path corruption triage).
mod el2; // L2.0: resident nVHE EL2 monitor (HVC handler) + el2_selftest() facade.
mod el2_nested_vectors; // aL2.4: __l2_nested_guest_vectors EL1 table (guest's OWN brk target); pure asm.
mod el2_vectors; // L2.0: VBAR_EL2 table + EL2 save path; pure `global_asm!` module.
mod el2_vgic_vectors; // aL2.5: __l2_vgic_guest_vectors EL1 table (the injected vIRQ's GICV ack/EOI handler); pure asm.
mod el2vgic; // aL2.5: vGIC virtual-interrupt injection arming (HCR.IMO|TWI + GICH_HCR.En + GICH_LR0) + armed/park cell.
mod el2mmio; // L2.3: trap-and-emulate arming (HCR.VM|TVM) + the MMIO device seam + served cell.
mod exits; // L2.2: EL2 exit-dispatch arming (HCR.TWI|TWE + CPTR.TFP) + served-mask cell.
mod exits_vectors; // L2.2: __l2_guest_vectors EL1 table (inject-UNDEF target); pure asm.
mod mmu; // M3: cold MMU bring-up + 4 KiB map / BBM remap self-test.
mod pmm; // M6: QEMU `virt` boot memory-map source (hard-coded map + DTB reserve).
mod sched; // M2: ctx_switch (x19..x30 + SP) + initial-frame fabrication.
mod serial; // PL011 @ 0x0900_0000 (QEMU `virt` UART0).
mod smmu; // aL2.6: SMMUv3 stage-2 DMA-isolation table-programming (EL1-only; IOMMU twin of L2.1).
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
pub use el2::el2_nested_guest_selftest; // aL2.4: the safe nested-guest (two-stage) self-test facade.
pub use el2::el2_vgic_selftest; // aL2.5: the safe vGIC virtual-interrupt-injection self-test facade.
pub use smmu::smmu_selftest; // aL2.6: the safe SMMUv3 stage-2 table-programming self-test facade.
pub use virtio::virtio_selftest; // M19: the safe virtio-rng self-test facade.
pub use mmu::{
    address_space_new, current_root, heap_window, m3_test_va_intact, map_heap_frames, map_in_root,
    map_user_in_root, mmu_init, mmu_selftest, switch_root, unmap_in_root, va_to_pa_in_root,
};
pub use pmm::pmm_collect_regions;
pub use diag::{
    boot_stack_headroom, el2_stack_headroom, read_word, redzone_check_report, redzone_init,
    REDZONE_PATTERN, REDZONE_WORDS,
}; // #65 probes.
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

/// DIAG (#65, probe P4): the periodic tick period in CNTPCT counts (~1 ms),
/// for `dispatch_irq`'s tick-gap storm witness. Pure `CNTFRQ_EL0` re-read.
pub fn tick_period() -> u64 {
    timer::tick_period()
}

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
/// Exit QEMU with code 0 via AArch64 semihosting (HLT #0xF000, SYS_EXIT).
/// The boot harnesses pass -semihosting, so after the final cumulative
/// marker the kernel exits QEMU instead of parking to the wall-clock
/// ceiling: a CI timeout now always means a genuinely stuck boot, never
/// "healthy but slower than the ceiling" (the aL2.4/aL2.5 revert class).
/// Returns only if semihosting is unavailable (caller falls to halt()).
pub fn qemu_exit_success() {
    // #65 hardening (F4): the LEGITIMATE caller is the lib.rs facade, whose
    // EXIT_ARMED gate is armed only at the single end-of-chain call site in
    // `rust_main`; an un-armed (stray-control-flow) entry is reported + parked
    // THERE, so this body stays silent on the healthy path (the probe-P1
    // "success-body reached" canary print lived here during the #65 triage).
    // SYS_EXIT: x1 -> two-word block { reason, subcode }; QEMU exits with
    // subcode when reason == ADP_Stopped_ApplicationExit (0x20026).
    let block: [u64; 2] = [0x0002_0026, 0];
    // SAFETY: one HLT #0xF000 with x0/x1 per the Arm semihosting spec;
    // QEMU intercepts it at translation time when -semihosting is on.
    unsafe {
        core::arch::asm!(
            "hlt #0xF000",
            in("x0") 0x18u64,
            in("x1") block.as_ptr(),
            options(nostack),
        );
    }
}

/// Exit QEMU with code **1** via AArch64 semihosting (HLT #0xF000, SYS_EXIT).
/// The PANIC/fatal twin of [`qemu_exit_success`] (#65 hardening): a panicking
/// boot used to exit 0 and could masquerade as a clean run to anything keyed on
/// the process exit code; now the panic path is rc=1 + its own serial report.
/// Returns only if semihosting is unavailable (caller falls to halt()).
pub fn qemu_exit_failure() {
    let block: [u64; 2] = [0x0002_0026, 1];
    // SAFETY: as `qemu_exit_success` -- one HLT #0xF000 with x0/x1 per the Arm
    // semihosting spec; QEMU intercepts it when -semihosting is on.
    unsafe {
        core::arch::asm!(
            "hlt #0xF000",
            in("x0") 0x18u64,
            in("x1") block.as_ptr(),
            options(nostack),
        );
    }
}

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

/// Diagnostic: the EL `_start` entered at (CurrentEL[3:2]; 0xFF = entry did
/// not pass through `_start`, e.g. the tb-vmm `_tb_start` path).
pub fn boot_entry_el() -> u8 {
    boot::BOOT_ENTRY_EL.load(core::sync::atomic::Ordering::Acquire)
}

/// Diagnostic: 1 iff the boot path entered at EL2 and installed the monitor.
pub fn booted_at_el2() -> u8 {
    el2::BOOTED_AT_EL2.load(core::sync::atomic::Ordering::Acquire)
}
