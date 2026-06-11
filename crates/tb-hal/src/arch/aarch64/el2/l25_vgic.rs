//! aL2.5 "vgic" rung (the virtual-interrupt-injection proof), extracted from
//! `el2/mod.rs` for readability. As a CHILD of `el2`, this module sees every
//! `super`-private monitor item (the shared consts, the `Frame`/`BOOTED_AT_EL2`
//! core, the EL1 vbar helpers) via `use super::*`, so this is a 100%
//! BEHAVIOUR-PRESERVING code move: the kernel still calls
//! `el2::el2_vgic_selftest()` through the `pub use` re-export in `mod.rs`.
#![allow(unused_imports)]
use super::*;

// ===========================================================================
// aL2.5: the EL1 vGIC guest -- a small position-independent EL1 payload that
// enables its OWN GICV virtual CPU interface, PARKS on WFI (which traps to EL2,
// where the monitor injects a pending vIRQ via GICH_LR0 and resumes it), takes
// the injected VIRTUAL interrupt at its OWN EL1 IRQ vector (GICV_IAR ack ->
// x28 = VGIC_IRQ_TAKEN -> GICV_EOIR), and presents the vGIC magic iff the vIRQ
// was taken+acked. Modeled on `guest_stub` / `el2_nested_guest_stub`. NO new
// stack frame (SP_EL1 is the guest's own, untouched); only x9..x12 scratch +
// the callee-saved x27/x28 handshake the IRQ vector agreed on.
// ===========================================================================
// (a) PRE : reached only by the `imm == 10` handler's `eret`, executing at EL1h
//           (SPSR = SPSR_EL1H_VGIC, PSTATE.I UNMASKED) under the kernel's live
//           stage-1 (HCR_EL2.VM=0). Its VA == PA: identity-mapped EL1-executable
//           kernel `.text` in GiB1; the GICV frame (0x0804_0000) is in the GiB0
//           Device identity block the kernel maps. POST: `hvc #11` (the monitor
//           tears the window down + verifies; never returns here).
// (b) ABI : `#[unsafe(naked)]` -- a register-only sequence (enable GICV, install
//           VBAR, WFI, check sentinel, hvc). Uses NO new stack frame. The
//           GICV_BASE / sentinels / vINTID are materialised as immediates; the
//           magic + sentinel are locked against the consts (and the vector
//           table) by const-asserts.
// (c) TEST: scripts/run-aarch64.sh -- the vGIC round-trip prints "L2.5: vgic OK".
/// The aL2.5 vGIC guest: enable GICV_CTLR.En + GICV_PMR=0xFF, install its OWN
/// VBAR_EL1 (whose 0x280 SPx-IRQ slot acks/EOIs the vIRQ), park on WFI, then
/// present `VGIC_GUEST_MAGIC` (0x761) iff x28 == VGIC_IRQ_TAKEN, and `hvc #11`.
#[unsafe(naked)]
extern "C" fn el2_vgic_guest_stub() -> ! {
    naked_asm!(
        // -- (1) ENABLE the guest's OWN GICV virtual CPU interface -------------
        // x9 = GICV_BASE (0x0804_0000): the frame the guest touches as its GICC.
        "movz x9, #0x0804, lsl #16",
        // GICV_PMR = 0xFF (allow all priorities -- the injected pri-0 vIRQ passes).
        "movz x10, #0xFF",
        "str  w10, [x9, #0x04]",       // GICV_PMR @ 0x004
        // GICV_CTLR.En = 1 (enable the virtual CPU interface).
        "movz x10, #1",
        "str  w10, [x9, #0x00]",       // GICV_CTLR @ 0x000
        "dsb  ish",
        "isb",
        // -- (2) INSTALL the guest's OWN VBAR_EL1 (the vIRQ vector) ------------
        "adrp x12, __l2_vgic_guest_vectors",
        "add  x12, x12, :lo12:__l2_vgic_guest_vectors",
        "msr  vbar_el1, x12",
        "isb",
        // -- (3) PARK on WFI (PSTATE.I left UNMASKED; do NOT msr DAIFSet) -------
        // The WFI traps to EL2 (HCR_EL2.TWI=1); the monitor injects a pending
        // vIRQ into GICH_LR0 and resumes past the WFI. On resume the now-pending
        // VIRQ (IMO routes it, I clear) fires immediately at VBAR_EL1+0x280,
        // whose handler reads GICV_IAR, sets x28 = VGIC_IRQ_TAKEN (iff the IAR
        // matched the injected vINTID), writes GICV_EOIR, and erets back here.
        "movz x28, #0",                // clear the vIRQ-taken sentinel
        "wfi",                         // park -> trap -> inject -> resume -> vIRQ
        // -- (4) VERDICT: magic 0x761 iff the vIRQ was taken + acked -----------
        "mov  x0, #0xBAD",             // assume FAIL until the sentinel matches
        "movz x9, #0x5A5",             // VGIC_IRQ_TAKEN expected in x28
        "cmp  x28, x9",
        "b.ne 1f",                     // vIRQ not taken/acked -> leave x0 = 0xBAD
        "movz x0, #0x761",             // VGIC_GUEST_MAGIC -- the vIRQ round-trip closed
        "1:",
        "hvc  #11",                    // done: teardown + verify + unwind
        "2:",
        "b 2b",                        // unreachable: the monitor unwinds, never here
    )
}

// ===========================================================================
// aL2.5: the safe facade: el2_vgic_selftest() -> VgicProof.
// ===========================================================================
// (a) PRE : called once from the kernel at the L2.5 slot (right after aL2.4,
//           before M19), at EL1h, with the resident monitor armed
//           (BOOTED_AT_EL2 == 1). POST: SAVED the kernel's VBAR_EL1 (the guest
//           installs its OWN), masked IRQs, issued ONE `HVC #10`, drove the
//           arm -> guest-enables-GICV -> WFI-park -> WFI-trap-to-EL2 -> monitor
//           injects vIRQ via GICH_LR0 -> resume -> guest takes the vIRQ at EL1
//           -> ack(GICV_IAR)/EOI(GICV_EOIR) -> `hvc #11` -> TEARDOWN (HCR_EL2
//           back to baseline, GICH_HCR.En=0, GICH_LR0 zeroed) -> unwind
//           round-trip, RESTORED VBAR_EL1, and returns the outcome enum. The
//           kernel resumes here at EL1 with the vGIC window fully torn down.
//           Graceful skip when not booted at EL2.
// (b) ABI : plain safe `fn`; all asm/unsafe confined here + in `el2vgic.rs` /
//           `el2_vgic_vectors.rs`, so the `#![forbid(unsafe_code)]` kernel only
//           branches on the returned `VgicProof`.
// (c) TEST: scripts/run-aarch64.sh -- "L2.5: vgic OK" iff this is `Proven`.
/// Drive the EL1->EL2(arm)->EL1-guest(enable GICV + park on WFI)->EL2(WFI-trap:
/// inject vIRQ + resume)->EL1-guest(take + ack the vIRQ)->EL2(done+teardown)->EL1
/// vGIC injection round-trip and report the outcome. `Unavailable` if we did not
/// boot at EL2 (a green skip); `Proven{vintid}` on a closed round-trip that fired
/// the WFI park, delivered the vIRQ, AND retired the injected LR; `Faulted{code}`
/// on any monitor-reported fault.
pub fn el2_vgic_selftest() -> crate::VgicProof {
    use crate::VgicProof;

    // Graceful skip: no resident monitor -> issuing HVC would fault, so don't.
    if BOOTED_AT_EL2.load(Ordering::Acquire) != 1 {
        return VgicProof::Unavailable;
    }

    let stub = el2_vgic_guest_stub as *const () as u64;
    let _ = l2_vgic_guest_vectors_addr(); // keep the vector symbol referenced

    // SAVE the kernel's VBAR_EL1 BEFORE the round-trip: the guest installs its
    // OWN vGIC vectors, so the facade must restore the kernel's after (the
    // EL1-side teardown -- mirrors the aL2.4 VBAR save/restore).
    let saved_vbar = read_vbar_el1();

    // Mask EL1 IRQs across the whole window (the guest runs with PSTATE.I clear
    // so it CAN take the injected vIRQ, but the KERNEL side stays masked so no
    // stray physical IRQ disturbs the round-trip).
    let daif = super::timer::local_irq_save();

    let outcome: u64;
    // SAFETY: the resident EL2 monitor catches `hvc #10`, arms the vGIC window
    // (HCR_EL2 = RW|IMO|TWI + GICH_HCR.En), and erets into the EL1 vGIC guest
    // with PSTATE.I unmasked. The guest enables its GICV interface, parks on WFI
    // (which traps to EL2 -- the monitor injects a pending vIRQ via GICH_LR0 and
    // resumes past the WFI), takes the vIRQ at its EL1 vector, acks + EOIs it,
    // and `hvc #11`s -- the monitor TEARS the window DOWN (HCR_EL2 baseline,
    // GICH_HCR.En=0, GICH_LR0 zeroed) FIRST, reads the LR-retired proof, and
    // unwinds here with x0 = outcome, x1 = guest magic (unused by the verdict,
    // which reports the injected vINTID), every other kernel register restored
    // from B0. The result arrives in registers -- nothing here touches the EL2
    // stack. x3 carries the stub entry; clobber_abi("C") covers the rest.
    unsafe {
        asm!(
            "hvc #10",
            inout("x0") 0u64 => outcome,
            out("x1") _, // x1 = guest magic (consumed at EL2 in the done verdict)
            in("x3") stub,
            clobber_abi("C"),
        );
    }

    // EL1-side teardown: restore the kernel's VBAR_EL1 (the guest pointed it at
    // its OWN vGIC vectors) + isb so the next kernel exception uses the kernel
    // table. The marker discipline catches a miss: M19 must still print after.
    write_vbar_el1(saved_vbar);

    super::timer::local_irq_restore(daif);

    if outcome == 0 {
        VgicProof::Proven {
            vintid: VGIC_VINTID,
        }
    } else {
        VgicProof::Faulted { code: outcome }
    }
}

/// EL1: compute `&__l2_vgic_guest_vectors` (the aL2.5 guest EL1 vector table in
/// `el2_vgic_vectors.rs`) PC-relative -- no memory access.
fn l2_vgic_guest_vectors_addr() -> u64 {
    let v: u64;
    // SAFETY: `adrp`/`add :lo12:` form the address of the linker-kept symbol with
    // no memory access; NZCV preserved.
    unsafe {
        asm!(
            "adrp {v}, __l2_vgic_guest_vectors",
            "add  {v}, {v}, :lo12:__l2_vgic_guest_vectors",
            v = out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    v
}
