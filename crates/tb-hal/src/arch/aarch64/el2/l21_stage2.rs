//! L2.1 "stage2" rung (the stage-2 demand-translation proof), extracted from
//! `el2/mod.rs` for readability. The dispatch-called demand-fault handler
//! (`aarch64_el2_stage2_abort`) and the shared `el2_abort_retry` STAY in
//! `mod.rs` next to the central `aarch64_el2_sync_handler` match; this child
//! carries the rung's naked guest stub + the safe facade. As a CHILD of
//! `el2`, it sees every `super`-private monitor item via `use super::*`, so
//! this is a 100% BEHAVIOUR-PRESERVING code move: the kernel still calls
//! `el2::stage2_selftest()` through the `pub use` re-export in `mod.rs`.
#![allow(unused_imports)]
use super::*;

// ===========================================================================
// L2.1: the EL1 guest stub that DELIBERATELY touches the stage-2 hole.
// ===========================================================================
// (a) PRE : reached only by the `HVC #2` handler's `eret`, executing at EL1h
//           (SPSR_EL2 = 0x3C5) under the kernel's live stage-1 MMU AND the armed
//           stage-2 (HCR_EL2.VM=1). Its VA == PA: identity-mapped, EL1-executable
//           kernel `.text` in the RAM gigabyte (GiB1, which stage-2 identity-maps,
//           so the fetch + stack never S1PTW-fault). POST: the `ldr` from the hole
//           VA faults to EL2 (stage-2 translation fault); the monitor demand-maps
//           and ERET-retries WITHOUT advancing ELR, so the SAME `ldr` re-executes
//           and succeeds; the stub then `hvc #3`s and the monitor unwinds (never
//           returns here).
// (b) ABI : `#[unsafe(naked)]` -- PC-relative / immediate only (valid at its
//           identity VA), no stack. The hole VA `0x1_4000_0000` (== stage2.rs
//           `HOLE_IPA`) is materialised with MOVZ+MOVK; `mov x0,#0xACE` is one MOVZ.
// (c) TEST: scripts/run-aarch64.sh -- the demand round-trip prints "L2.1: stage2 OK".
/// The L2.1 guest: load from the stage-2 hole VA (faults -> EL2 demand-maps ->
/// retry succeeds), present the magic `0xACE` in x0, and `hvc #3` to close.
#[unsafe(naked)]
extern "C" fn stage2_guest_stub() -> ! {
    naked_asm!(
        "movz x2, #0x4000, lsl #16", // x2 = 0x0000_0000_4000_0000
        "movk x2, #0x0001, lsl #32", // x2 = 0x0000_0001_4000_0000 == HOLE_IPA (the hole VA)
        "ldr  x1, [x2]",             // stage-2 demand fault -> EL2 maps -> retry OK
        "mov  x0, #0xACE",           // the L2.1 guest magic (proves the guest ran)
        "hvc  #3",                   // trap back to EL2 (done): teardown + unwind
        "1: b 1b",                   // unreachable: the monitor unwinds, never here
    )
}

// ===========================================================================
// L2.1: the safe facade: stage2_selftest() -> Stage2Proof.
// ===========================================================================
// (a) PRE : called once from the kernel at the L2.1 slot (right after L2.0), at
//           EL1h, with the resident monitor armed (BOOTED_AT_EL2 == 1). POST:
//           built the stage-2 tables + pre-allocated the demand frame AT EL1,
//           spliced the stage-1 hole block, issued ONE `HVC #2`, drove the
//           arm -> guest -> stage-2 abort -> demand-map -> retry -> guest `hvc #3`
//           -> TEARDOWN -> unwind round-trip, and returns the outcome enum. The
//           kernel resumes here at EL1 with stage-2 fully torn down (HCR.VM=0).
//           Graceful skip (no HVC, no fault) when not booted at EL2.
// (b) ABI : plain safe `fn`; all asm/unsafe confined here + in `stage2.rs` /
//           `el2_vectors.rs`, so the `#![forbid(unsafe_code)]` kernel only
//           branches on the returned `Stage2Proof`.
// (c) TEST: scripts/run-aarch64.sh -- "L2.1: stage2 OK" iff this returns `Proven`.
/// Drive the EL1->EL2(arm)->EL1-guest->EL2(demand)->EL1-guest->EL2(done+teardown)
/// ->EL1 stage-2 demand-translation round-trip and report the outcome.
/// `Unavailable` if we did not boot at EL2 (a green skip); `Proven{fault_ipa}` on
/// the closed demand round-trip; `Faulted{code}` on any monitor-reported fault.
pub fn stage2_selftest() -> crate::Stage2Proof {
    use crate::Stage2Proof;

    // Graceful skip: no resident monitor -> no stage-2 to arm, no HVC issued.
    if BOOTED_AT_EL2.load(Ordering::Acquire) != 1 {
        return Stage2Proof::Unavailable;
    }

    // Build the stage-2 regime + pre-allocate the demand frame AT EL1 (the EL2
    // abort handler does NO allocation -- risk #4). On physical-frame OOM, surface
    // a Faulted code honestly (a red marker, never a faked OK).
    let root = match super::stage2::build_identity_stage2() {
        Some(r) => r,
        None => return Stage2Proof::Faulted { code: FAIL_S2_BUILD },
    };
    let demand = match super::stage2::prep_demand_frame() {
        Some(d) => d,
        None => return Stage2Proof::Faulted { code: FAIL_S2_BUILD },
    };
    // Splice the stage-1 identity block at L1[5] so the guest VA HOLE_IPA produces
    // IPA HOLE_IPA (which stage-2 then faults). Its stage-1 walk touches only the
    // L1 root (in GiB1, stage-2-covered), so it never S1PTW-faults.
    super::stage2::install_stage1_hole_block();

    let vtcr_v = super::stage2::compute_vtcr();
    let vttbr_v = super::stage2::compute_vttbr(root);
    let stub = stage2_guest_stub as *const () as u64;
    let expect = super::stage2::HOLE_IPA;

    // Mask EL1 IRQs across the round-trip (the guest also runs DAIF-masked).
    let daif = super::timer::local_irq_save();

    let outcome: u64;
    let fault_ipa: u64;
    // SAFETY: the resident EL2 monitor catches `hvc #2`, programs VTCR/VTTBR and
    // sets HCR.VM=1, then erets into the EL1 guest stub (now under stage-2). The
    // stub's load faults the hole; the monitor demand-maps + eret-retries (ELR
    // unchanged); the stub's `hvc #3` TEARS stage-2 DOWN (HCR.VM=0) FIRST and
    // unwinds here with x0 = outcome, x1 = fault_ipa, every other kernel register
    // restored from B2.0. The result arrives in registers -- nothing here touches
    // the EL2 stack. x2..x5 carry the in-args; clobber_abi("C") covers the rest.
    unsafe {
        asm!(
            "hvc #2",
            inout("x0") root => outcome,
            inout("x1") vtcr_v => fault_ipa,
            in("x2") vttbr_v,
            in("x3") stub,
            in("x4") demand,
            in("x5") expect,
            clobber_abi("C"),
        );
    }

    super::timer::local_irq_restore(daif);

    if outcome == 0 {
        Stage2Proof::Proven { fault_ipa }
    } else {
        Stage2Proof::Faulted { code: outcome }
    }
}
