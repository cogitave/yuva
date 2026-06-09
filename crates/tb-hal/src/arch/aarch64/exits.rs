//! aarch64 **L2.2 "el2-exits"**: the EL2 exit-dispatch ARMING glue + the
//! single-accessor served-mask context cell.
//!
//! Where L2.1 ([`super::stage2`]) proves the stage-2 leaf is the isolation
//! primitive, L2.2 proves the EL2 *exit-dispatch table* itself: inside a short
//! self-test window the monitor traps two distinct guest exits -- a `WFx`
//! (HCR_EL2.TWI|TWE) and an FP/SIMD access (CPTR_EL2.TFP, EC `0x07`, NOT in the
//! MUST set) -- routes them through the pure
//! [`tb_encode::el2_trap::classify_exit`] table, RESUMES the `WFx` and INJECTS
//! an UNDEF for the fail-closed default. This module owns the silicon-unsafe
//! arming (`msr HCR_EL2`/`CPTR_EL2`) + the EL2-only served-mask cell; the
//! handler/inject/facade live in [`super::el2`] and the guest EL1 vector table
//! in [`super::exits_vectors`], so `tb-hal`'s `#![forbid(unsafe_code)]` callers
//! (the kernel) only ever branch on the returned `ExitsProof`.
//!
//! ## Arming (HCR_EL2 / CPTR_EL2 -- absolute writes, mirroring `stage2::arm`)
//!
//! The boot baseline is `HCR_EL2 = 1<<31` (RW only; TWI/TWE clear) and
//! `CPTR_EL2 = 0x33FF` (nVHE RES1; no FP/copro traps) for the WHOLE M0..M19 +
//! L2.0/L2.1 run, so the kernel's own `wfi` (in `halt()`) and any FP use are
//! NEVER trapped. [`arm_exits_el2`] sets `HCR_EL2 |= TWI|TWE` and
//! `CPTR_EL2 |= TFP` for the window; [`disarm_exits_el2`] restores BOTH to the
//! boot baseline byte-for-byte (teardown-first, the L2.1 discipline) BEFORE the
//! monitor unwinds to the kernel -- zero regression.
//!
//! ## The served-mask cell (EL2-only; the outcome leaves via the x0 register)
//!
//! [`set_exit_served`] records which named arm fired (WFx / inject-UNDEF
//! default). It is written and read ONLY at EL2 (the `WFx` arm, the inject path,
//! and the done-HVC verdict), never by EL1, so -- like `stage2::S2_CTX` -- it is
//! a single-accessor `align(64)` cell that shares no cache line with any
//! EL1-written `.bss`. The VERDICT derived from it is delivered to EL1 in the x0
//! register (`el2_return_to_kernel`), never read by EL1 from this cacheable
//! static, so the EL2(`SCTLR_EL2.M=0`, non-cacheable) vs EL1 (Normal-WB)
//! coherency hazard the L2.0/L2.1 worlds carry does not reach the result path.

use core::arch::asm;
use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};

// ===========================================================================
// HCR_EL2 / CPTR_EL2 arming bits (Linux `kvm_arm.h`; Arm ARM DDI 0487 D13).
// ===========================================================================

/// `HCR_EL2.RW` (bit31): the next lower EL (EL1) is AArch64 -- the boot baseline.
const HCR_RW: u64 = 1 << 31;
/// `HCR_EL2.TWI` (bit13): trap EL1 `WFI` to EL2 (`kvm_arm.h HCR_TWI`).
const HCR_TWI: u64 = 1 << 13;
/// `HCR_EL2.TWE` (bit14): trap EL1 `WFE` to EL2 (`kvm_arm.h HCR_TWE`).
const HCR_TWE: u64 = 1 << 14;
/// `CPTR_EL2` nVHE RES1 baseline (no FP/copro traps) -- exactly `boot.rs`'s value.
const CPTR_EL2_BASELINE: u64 = 0x33FF;
/// `CPTR_EL2.TFP` (bit10): trap EL1&0 FP/SIMD access to EL2 (`CPTR_EL2_TFP_SHIFT`
/// = 10). Set ONLY inside the window so the default-arm trigger (EC `0x07`) hits.
const CPTR_EL2_TFP: u64 = 1 << 10;

/// Served-mask bit: the `WFx` arm fired (trapped + resumed one insn past).
pub(super) const EXIT_WFX_BIT: u64 = 1 << 0;
/// Served-mask bit: the inject-UNDEF DEFAULT arm fired (FP/SIMD trap -> `Undef`
/// -> `el2_inject_undef`).
pub(super) const EXIT_UNDEF_BIT: u64 = 1 << 1;

// Tier-1 compile-time locks (a drift from the boot baseline is a build error).
const _: () = assert!(HCR_RW == 1 << 31);
const _: () = assert!(CPTR_EL2_BASELINE == 0x33FF);
const _: () = assert!(CPTR_EL2_TFP == 0x400);

// ===========================================================================
// The EL2 served-mask context cell (single-accessor; EL1 NEVER references it).
//
// `[0]` = armed flag (0/1), `[1]` = served mask (WFX|UNDEF bits OR-accumulated).
// `align(64)` keeps the two cells alone in one cache line so no EL1-written
// `.bss` variable can false-share + write back over an EL2 store -- the exact
// `stage2::El2Ctx` pattern. Accessed via plain `read_volatile`/`write_volatile`
// (NOT atomics): at EL2 with `SCTLR_EL2.M=0` the memory is Normal non-cacheable,
// where LDXR/STXR exclusives are not guaranteed -- volatile is the coherent
// primitive.
// ===========================================================================

#[repr(C, align(64))]
struct ExitsCtx(UnsafeCell<[u64; 2]>);

// SAFETY: single vCPU; the cells are touched ONLY from EL2 (the arm / WFx /
// inject / done handlers), never concurrently and never by EL1 -- like
// `__el2_stack`. No Rust reference to the interior is ever minted; access is
// volatile raw-pointer only.
unsafe impl Sync for ExitsCtx {}

static EXITS_CTX: ExitsCtx = ExitsCtx(UnsafeCell::new([0; 2]));

fn ctx_ptr() -> *mut u64 {
    EXITS_CTX.0.get() as *mut u64
}

/// EL2: arm/disarm the exit-dispatch window flag (the `WFx`/`Undef` arms gate on
/// it so a stray exit OUTSIDE the window fails closed, never resumes/injects).
pub(super) fn set_armed(armed: bool) {
    // SAFETY: EL2, single accessor; `ctx_ptr()` is our static cell (64-B aligned,
    // EL1 never touches it). One aligned volatile store of cell 0.
    unsafe { write_volatile(ctx_ptr().add(0), u64::from(armed)) }
}

/// EL2: is the exit-dispatch window currently armed?
pub(super) fn armed() -> bool {
    // SAFETY: as `set_armed`; an aligned volatile load of cell 0.
    unsafe { read_volatile(ctx_ptr().add(0)) != 0 }
}

/// EL2: clear the served mask (called by the arm handler before `eret`-ing into
/// the guest, so each window starts from a clean slate).
pub(super) fn reset_served() {
    // SAFETY: as `set_armed`; an aligned volatile store of cell 1.
    unsafe { write_volatile(ctx_ptr().add(1), 0) }
}

/// EL2: OR `bit` into the served mask (the `WFx` arm + the inject-UNDEF default
/// each record that they fired).
pub(super) fn set_exit_served(bit: u64) {
    // SAFETY: as `set_armed`; a single-accessor read-modify-write of cell 1.
    unsafe {
        let p = ctx_ptr().add(1);
        write_volatile(p, read_volatile(p) | bit);
    }
}

/// EL2: the accumulated served mask (read by the done handler to form the verdict).
pub(super) fn served() -> u64 {
    // SAFETY: as `set_armed`; an aligned volatile load of cell 1.
    unsafe { read_volatile(ctx_ptr().add(1)) }
}

// ===========================================================================
// EL2-only: arm / disarm the exit-dispatch traps (the msr HCR_EL2/CPTR_EL2 glue).
// ===========================================================================

/// EL2: arm the window -- `HCR_EL2 |= TWI|TWE` (trap guest `WFI`/`WFE`) and
/// `CPTR_EL2 |= TFP` (trap guest FP/SIMD), then `isb`-synchronize so the next
/// EL1 access sees the new trap config. Absolute writes off the known boot
/// baseline (mirroring `stage2::arm_stage2_el2`), so the result is deterministic.
pub(super) fn arm_exits_el2() {
    // SAFETY: EL2. Program HCR_EL2 (RW|TWI|TWE) and CPTR_EL2 (baseline|TFP), then
    // `isb` so the traps are in place before control returns to the guest. No
    // stack/flags effect; not `nomem` (it reconfigures trapping behaviour).
    unsafe {
        asm!(
            "msr hcr_el2,  {hcr}",
            "msr cptr_el2, {cptr}",
            "isb",
            hcr  = in(reg) HCR_RW | HCR_TWI | HCR_TWE,
            cptr = in(reg) CPTR_EL2_BASELINE | CPTR_EL2_TFP,
            options(nostack, preserves_flags),
        );
    }
}

/// EL2: tear the window DOWN -- restore `HCR_EL2 = 1<<31` and `CPTR_EL2 = 0x33FF`
/// (the boot baseline) and `isb`. The MANDATORY zero-regression step: leaving
/// TWI|TWE or TFP armed would trap the kernel's own later `wfi` (in `halt()`) or
/// any FP use to EL2 outside any window -> hang / mis-dispatch. Teardown is the
/// FIRST action of the done-HVC handler (the L2.1 discipline).
pub(super) fn disarm_exits_el2() {
    // SAFETY: EL2. Restore the boot baseline (HCR_EL2 = RW only, CPTR_EL2 = nVHE
    // RES1), then `isb` so the next EL1 access (incl. the kernel's halt `wfi`) is
    // untrapped again. No stack/flags effect; not `nomem`.
    unsafe {
        asm!(
            "msr hcr_el2,  {hcr}",
            "msr cptr_el2, {cptr}",
            "isb",
            hcr  = in(reg) HCR_RW,
            cptr = in(reg) CPTR_EL2_BASELINE,
            options(nostack, preserves_flags),
        );
    }
}
