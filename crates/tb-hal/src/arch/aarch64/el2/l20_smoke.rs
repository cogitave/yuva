//! L2.0 "el2" rung (the EL2 world-switch smoke proof), extracted from
//! `el2/mod.rs` for readability. The dispatch-referenced `guest_stub` (named
//! by the `HVC_BOOTSTRAP` arm) STAYS in `mod.rs` next to the central
//! `aarch64_el2_sync_handler` match; this child carries the rung's safe
//! facade. As a CHILD of `el2`, it sees every `super`-private monitor item
//! via `use super::*`, so this is a 100% BEHAVIOUR-PRESERVING code move: the
//! kernel still calls `el2::el2_selftest()` through the `pub use` re-export
//! in `mod.rs`.
#![allow(unused_imports)]
use super::*;

// ===========================================================================
// The safe facade: el2_selftest() -> El2Proof (the only public surface).
// ===========================================================================
// (a) PRE : called once from the kernel at the L2.0 slot (end of boot), at EL1h
//           with the resident monitor armed (when BOOTED_AT_EL2 == 1). POST:
//           issued ONE bootstrap `HVC #0`, drove the ERET->guest->HVC->EL2
//           round-trip, and returns the outcome enum. Graceful skip (no HVC, no
//           fault) when not booted at EL2.
// (b) ABI : plain safe `fn`; all asm/unsafe confined above + in el2_vectors.rs /
//           boot.rs, so the `#![forbid(unsafe_code)]` kernel only branches on
//           the returned `El2Proof`.
// (c) TEST: scripts/run-aarch64.sh -- "L2.0: el2 OK" iff this returns `Proven`.
/// Drive the EL1->EL2->EL1-guest->EL2->EL1 world-switch and report the outcome.
/// `Unavailable` if we did not boot at EL2 (a green skip); `Proven` on a closed
/// round-trip; `RoundTripFailed{code}` if the monitor reported a fault.
pub fn el2_selftest() -> crate::El2Proof {
    use crate::El2Proof;

    // Graceful skip: no resident monitor -> issuing HVC would fault, so don't.
    // BOOTED_AT_EL2 was written caches-off at boot and is read here via a cold
    // fill (coherent), the same discipline M0..M2 `.bss` already relies on.
    if BOOTED_AT_EL2.load(Ordering::Acquire) != 1 {
        return El2Proof::Unavailable;
    }

    // Mask EL1 IRQs across the round-trip (belt-and-suspenders; mirrors
    // `vmx_selftest`'s `cli`). The guest also runs with DAIF masked (SPSR=0x3C5).
    let daif = super::timer::local_irq_save();

    let code: u64;
    // SAFETY: the resident EL2 monitor (armed in `_start`) catches `hvc #0`,
    // erets into the EL1 guest stub, catches the guest's `hvc #1`, and erets back
    // here with the outcome in x0 and every kernel register restored from B0
    // (x2..x30 transparent; x0/x1 are caller-saved, covered by clobber_abi("C")).
    // Nothing here touches the EL2 stack memory -- the result arrives in x0.
    unsafe {
        asm!("hvc #0", out("x0") code, clobber_abi("C"));
    }

    super::timer::local_irq_restore(daif);

    if code == 0 {
        El2Proof::Proven { hvc_imm: HVC_GUEST_DONE }
    } else {
        El2Proof::RoundTripFailed { code }
    }
}
