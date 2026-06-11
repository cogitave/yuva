//! L2.2 "el2-exits" rung (the exit-dispatch proof), extracted from
//! `el2/mod.rs` for readability. The dispatch-referenced pieces (the
//! `exits_guest_stub` named by the `HVC_EXITS_ARM` arm, `el2_inject_undef`,
//! and the shared `read_vbar_el1`/`write_vbar_el1` helpers) STAY in `mod.rs`
//! next to the central `aarch64_el2_sync_handler` match; this child carries
//! the rung's CPACR window const + its EL1 helpers + the safe facade. As a
//! CHILD of `el2`, it sees every `super`-private monitor item via
//! `use super::*`, so this is a 100% BEHAVIOUR-PRESERVING code move: the
//! kernel still calls `el2::el2_exits_selftest()` through the `pub use`
//! re-export in `mod.rs`.
#![allow(unused_imports)]
use super::*;


/// `CPACR_EL1.FPEN = 0b11` (bits[21:20]) -- do NOT trap EL1&0 FP/SIMD to EL1, so
/// the L2.2 FP trigger reaches the `CPTR_EL2.TFP` EL2 trap (the fail-closed
/// default arm). The facade sets this for the window and restores the saved value.
const CPACR_FPEN_NOTRAP: u64 = 0b11 << 20;
const _: () = assert!(CPACR_FPEN_NOTRAP == 0x30_0000);

/// EL1: read `CPACR_EL1` (the FP/SIMD + copro access-control register).
fn read_cpacr_el1() -> u64 {
    let v: u64;
    // SAFETY: CPACR_EL1 is EL1-readable; side-effect-free.
    unsafe {
        asm!("mrs {v}, cpacr_el1", v = out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// EL1: write `CPACR_EL1` + `isb` so the new FP-trap policy is in effect.
fn write_cpacr_el1(v: u64) {
    // SAFETY: writing CPACR_EL1 is legal at EL1; `isb` synchronizes the FP-trap
    // policy change before the guest's FP trigger executes.
    unsafe {
        asm!("msr cpacr_el1, {v}", "isb", v = in(reg) v, options(nomem, nostack, preserves_flags));
    }
}

/// EL1: compute `&__l2_guest_vectors` (the L2.2 guest EL1 vector table in
/// `exits_vectors.rs`) PC-relative -- no memory access.
fn l2_guest_vectors_addr() -> u64 {
    let v: u64;
    // SAFETY: `adrp`/`add :lo12:` form the address of the linker-kept symbol with
    // no memory access; NZCV preserved.
    unsafe {
        asm!(
            "adrp {v}, __l2_guest_vectors",
            "add  {v}, {v}, :lo12:__l2_guest_vectors",
            v = out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    v
}

// ===========================================================================
// L2.2: the safe facade: el2_exits_selftest() -> ExitsProof.
// ===========================================================================
// (a) PRE : called once from the kernel at the L2.2 slot (right after L2.1,
//           before M19), at EL1h, with the resident monitor armed
//           (BOOTED_AT_EL2 == 1). POST: installed the L2.2 guest vectors +
//           opened CPACR_EL1.FPEN, masked IRQs, issued ONE `HVC #4`, drove the
//           arm -> WFx-trap+resume -> FP-trap -> inject-UNDEF -> guest-vector
//           -> `hvc #5` -> TEARDOWN -> unwind round-trip, restored CPACR_EL1 +
//           VBAR_EL1, and returns the outcome enum. The kernel resumes here at
//           EL1 with the exit window fully torn down (HCR/CPTR back to baseline).
//           Graceful skip (no HVC, no fault) when not booted at EL2.
// (b) ABI : plain safe `fn`; all asm/unsafe confined here + in `exits.rs` /
//           `exits_vectors.rs`, so the `#![forbid(unsafe_code)]` kernel only
//           branches on the returned `ExitsProof`.
// (c) TEST: scripts/run-aarch64.sh -- "L2.2: el2-exits OK" iff this is `Proven`.
/// Drive the EL1->EL2(arm)->EL1-guest->EL2(WFx resume)->EL1-guest->EL2(inject
/// UNDEF)->EL1-guest-vector->EL2(done+teardown)->EL1 exit-dispatch round-trip and
/// report the outcome. `Unavailable` if we did not boot at EL2 (a green skip);
/// `Proven{served}` on a closed round-trip that fired BOTH the WFx and inject-UNDEF
/// arms; `Faulted{code}` on any monitor-reported fault.
pub fn el2_exits_selftest() -> crate::ExitsProof {
    use crate::ExitsProof;

    // Graceful skip: no resident monitor -> issuing HVC would fault, so don't.
    if BOOTED_AT_EL2.load(Ordering::Acquire) != 1 {
        return ExitsProof::Unavailable;
    }

    // Save the kernel's VBAR_EL1 + CPACR_EL1, then install the L2.2 guest vector
    // table (so the injected UNDEF vectors into the guest's UNDEF handler) and
    // open CPACR_EL1.FPEN=0b11 (so the FP trigger is NOT trapped to EL1 by CPACR
    // -- the CPTR_EL2.TFP EL2 trap must win priority for the default arm).
    let saved_vbar = read_vbar_el1();
    let saved_cpacr = read_cpacr_el1();
    write_vbar_el1(l2_guest_vectors_addr());
    write_cpacr_el1(saved_cpacr | CPACR_FPEN_NOTRAP);

    // Mask EL1 IRQs across the whole window (the VBAR_EL1-hijack risk: while
    // VBAR_EL1 points at the guest table, a stray EL1 IRQ/abort would vector into
    // it -- masking + the guest fail-trampoline keep that fail-closed, never a
    // hang). The guest also runs DAIF-masked (SPSR=0x3C5).
    let daif = super::timer::local_irq_save();

    let code: u64;
    let served: u64;
    // SAFETY: the resident EL2 monitor catches `hvc #4`, arms the exit window
    // (HCR.TWI|TWE + CPTR.TFP) and erets into the EL1 exits stub. The stub's `wfi`
    // traps -> Wfx arm -> resume; its FP `.inst` traps -> Undef default -> inject
    // UNDEF -> the guest's EL1 vector echoes the magic via `hvc #5`; the done
    // handler tears the window DOWN, verifies the served bits + magic, and unwinds
    // here with x0 = outcome, x1 = served, every other kernel register restored
    // from B0. The result arrives in registers -- nothing here touches the EL2
    // stack. x0/x1 are caller-saved, covered by clobber_abi("C").
    unsafe {
        asm!(
            "hvc #4",
            out("x0") code,
            out("x1") served,
            clobber_abi("C"),
        );
    }

    super::timer::local_irq_restore(daif);

    // Restore the kernel's CPACR_EL1 + VBAR_EL1 (the EL1-side window teardown).
    write_cpacr_el1(saved_cpacr);
    write_vbar_el1(saved_vbar);

    if code == 0 {
        ExitsProof::Proven { served }
    } else {
        ExitsProof::Faulted { code }
    }
}
