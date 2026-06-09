//! Pure aarch64 **EL2 trap-syndrome** decoders -- `ESR_EL2` / `HPFAR_EL2` /
//! `FAR_EL2` bit extraction for the L2.1 stage-2 demand-fault handler.
//!
//! When a guest EL1&0 access faults stage-2 translation (`HCR_EL2.VM == 1`), the
//! abort is taken to EL2 and the resident monitor must decide WHAT happened from
//! three raw system registers: `ESR_EL2` (the exception class + data-fault status
//! code), `HPFAR_EL2` (the faulting Intermediate Physical Address -- the
//! EPT-`PHYSICAL_ADDRESS`-of-the-violation analog), and `FAR_EL2` (the faulting
//! virtual address, for the in-page offset). Those decisions are pure bit
//! transforms, so they live here (Kani-proven total over all 64-bit inputs,
//! Miri-gated), exactly as the stage-2 descriptor algebra lives in
//! [`crate::stage2`]: `tb-hal`'s `arch/aarch64/el2.rs` reads the raw registers
//! with `mrs` and CALLS these to classify the fault. Nothing here is `unsafe` or
//! touches hardware.
//!
//! Verified bit facts (Arm ARM DDI 0487, ESR_ELx / HPFAR_EL2 / FAR_ELx;
//! cross-checked against Linux v6.6 `arch/arm64/include/asm/esr.h` +
//! `kvm_emulate.h`):
//!   * `ESR_ELx.EC` -- exception class, bits `[31:26]` (`esr.h ESR_ELx_EC_SHIFT
//!     26`, `ESR_ELx_EC_MASK GENMASK(31,26)`). Lower-EL HVC64 = `0x16`, an
//!     instruction abort from a lower EL = `0x20`, a data abort from a lower EL
//!     = `0x24`.
//!   * `ESR_ELx.ISS.DFSC` -- data/instruction fault status code, bits `[5:0]`
//!     (`esr.h ESR_ELx_FSC GENMASK(5,0)`). A **translation fault** is `0b0001LL`
//!     = `0x04..=0x07` where `LL` is the walk level (`ESR_ELx_FSC_FAULT 0x04`).
//!   * `ESR_ELx.ISS.WnR` -- write-not-read, bit `[6]` (`ESR_ELx_WNR (1<<6)`).
//!   * `ESR_ELx.ISS.S1PTW` -- stage-1-page-table-walk, bit `[7]`
//!     (`ESR_ELx_S1PTW (1<<7)`): set iff the fault occurred on the stage-1 walk
//!     itself (the access that faulted was the hardware reading a stage-1
//!     descriptor through stage-2). For the L2.1 smoke this MUST be 0 -- the
//!     identity stage-2 covers the guest's live stage-1 table frames, so an
//!     S1PTW=1 means the wrong thing faulted and the handler fails closed.
//!   * `HPFAR_EL2.FIPA` -- faulting IPA bits, stored in `HPFAR_EL2[43:4]` =
//!     IPA`[51:12]` (`kvm_emulate.h`: `(hpfar & HPFAR_MASK) << 8`, `HPFAR_MASK
//!     GENMASK(39,4)` on ARMv8.0). So the page-aligned faulting IPA is
//!     `(hpfar & !0xF) << 8`.
//!   * `FAR_ELx` -- faulting VA; the in-page offset is `FAR & 0xFFF`.

#![allow(dead_code)]

// ===========================================================================
// ESR_EL2.EC exception-class constants (the EL2 sync-handler dispatch keys).
// ===========================================================================

/// `EC` for `HVC` executed in AArch64 state (the bootstrap / done hypercalls).
pub const EC_HVC64: u64 = 0x16;
/// `EC` for an Instruction Abort taken from a LOWER EL (a stage-2 fetch fault).
pub const EC_IABT_LOW: u64 = 0x20;
/// `EC` for a Data Abort taken from a LOWER EL (the expected stage-2 demand fault).
pub const EC_DABT_LOW: u64 = 0x24;

/// `ESR_ELx.ISS.DFSC` value for a translation fault at walk level 0 (`0b000100`).
pub const DFSC_TRANSLATION_L0: u64 = 0x04;
/// `ESR_ELx.ISS.DFSC` value for a translation fault at walk level 3 (`0b000111`).
pub const DFSC_TRANSLATION_L3: u64 = 0x07;

// ===========================================================================
// ESR_EL2 field decoders (total over all 64-bit inputs -- never panic).
// ===========================================================================

/// `ESR_ELx.EC` -- the exception class, bits `[31:26]`. Always `< 64`.
#[inline]
pub const fn esr_ec(esr: u64) -> u64 {
    (esr >> 26) & 0x3F
}

/// `ESR_ELx.ISS.DFSC` -- the (data/instruction) fault status code, bits `[5:0]`.
/// Always `< 64`. The FULL 6-bit field: masking with `0x1F` instead would
/// mis-classify some faults (the negative control in `kani_esr_decode_total`).
#[inline]
pub const fn esr_dfsc(esr: u64) -> u64 {
    esr & 0x3F
}

/// Whether the syndrome's DFSC encodes a **translation fault** (`0x04..=0x07`,
/// i.e. `0b0001xx`, any walk level) -- the stage-2 demand-fault classifier. An
/// access-flag fault (`0b0010xx`), permission fault (`0b0011xx`), or any fault
/// with DFSC bit[5] set is deliberately NOT a translation fault.
#[inline]
pub const fn esr_is_translation_fault(esr: u64) -> bool {
    let dfsc = esr_dfsc(esr);
    dfsc >= DFSC_TRANSLATION_L0 && dfsc <= DFSC_TRANSLATION_L3
}

/// `ESR_ELx.ISS.WnR` -- write-not-read, bit `[6]` (`1` = the faulting access was
/// a write). Always `0` or `1`.
#[inline]
pub const fn esr_wnr(esr: u64) -> u64 {
    (esr >> 6) & 1
}

/// `ESR_ELx.ISS.S1PTW` -- stage-1-page-table-walk, bit `[7]` (`1` = the fault was
/// on the stage-1 walk, NOT the final access). Always `0` or `1`. For L2.1 a `1`
/// means the identity stage-2 failed to cover a live stage-1 table frame, so the
/// handler treats it as a fail (the wrong thing faulted).
#[inline]
pub const fn esr_s1ptw(esr: u64) -> u64 {
    (esr >> 7) & 1
}

// ===========================================================================
// HPFAR_EL2 / FAR_EL2 decoders.
// ===========================================================================

/// The page-aligned faulting Intermediate Physical Address from `HPFAR_EL2`:
/// `(hpfar & !0xF) << 8` (FIPA in `HPFAR[43:4]` = IPA`[51:12]`). The result is
/// ALWAYS page-aligned (low 12 bits 0) for every input -- proven in
/// `kani_hpfar_fault_ipa`. The `<< 8` (not `<< 4`) is load-bearing: a `<< 4`
/// would leave bits in `[11:8]` and mislocate the IPA (the negative control).
#[inline]
pub const fn hpfar_fault_ipa(hpfar: u64) -> u64 {
    (hpfar & !0xF) << 8
}

/// The in-page offset of the faulting VA from `FAR_ELx`: `far & 0xFFF`. Combined
/// with [`hpfar_fault_ipa`] it gives the exact faulting IPA, but the L2.1
/// demand-map operates at page granularity so only the page-aligned IPA is used.
#[inline]
pub const fn far_page_offset(far: u64) -> u64 {
    far & 0xFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_esr(ec: u64, dfsc: u64, wnr: u64, s1ptw: u64) -> u64 {
        (ec << 26) | (s1ptw << 7) | (wnr << 6) | (dfsc & 0x3F)
    }

    #[test]
    fn ec_decodes_the_three_dispatch_classes() {
        assert_eq!(esr_ec(make_esr(EC_HVC64, 0, 0, 0)), EC_HVC64);
        assert_eq!(esr_ec(make_esr(EC_DABT_LOW, 0, 0, 0)), EC_DABT_LOW);
        assert_eq!(esr_ec(make_esr(EC_IABT_LOW, 0, 0, 0)), EC_IABT_LOW);
    }

    #[test]
    fn translation_fault_classification_is_exact() {
        // The four translation-fault levels are classified true.
        for dfsc in DFSC_TRANSLATION_L0..=DFSC_TRANSLATION_L3 {
            assert!(esr_is_translation_fault(make_esr(EC_DABT_LOW, dfsc, 0, 0)));
        }
        // An access-flag fault (0b001000) and permission fault (0b001100) are NOT.
        assert!(!esr_is_translation_fault(make_esr(EC_DABT_LOW, 0x08, 0, 0)));
        assert!(!esr_is_translation_fault(make_esr(EC_DABT_LOW, 0x0C, 0, 0)));
        // A DFSC with bit[5] set but low bits 0b0111 (= 0x27) must NOT be a
        // translation fault (the 0x1F-vs-0x3F masking negative control).
        assert!(!esr_is_translation_fault(make_esr(EC_DABT_LOW, 0x27, 0, 0)));
    }

    #[test]
    fn wnr_and_s1ptw_are_single_bits() {
        let esr = make_esr(EC_DABT_LOW, 0x07, 1, 1);
        assert_eq!(esr_wnr(esr), 1);
        assert_eq!(esr_s1ptw(esr), 1);
        let esr0 = make_esr(EC_DABT_LOW, 0x07, 0, 0);
        assert_eq!(esr_wnr(esr0), 0);
        assert_eq!(esr_s1ptw(esr0), 0);
    }

    #[test]
    fn hpfar_fault_ipa_is_page_aligned_and_correct() {
        // HPFAR for IPA 0x1_4000_0000: FIPA = IPA[51:12] in HPFAR[43:4], i.e.
        // hpfar = (ipa >> 12) << 4 = (0x1_4000_0000 >> 8).
        let ipa = 0x1_4000_0000u64;
        let hpfar = (ipa >> 12) << 4;
        assert_eq!(hpfar_fault_ipa(hpfar), ipa);
        assert_eq!(hpfar_fault_ipa(hpfar) & 0xFFF, 0); // page aligned
    }

    #[test]
    fn far_page_offset_is_low_12_bits() {
        assert_eq!(far_page_offset(0x1_4000_0ABC), 0xABC);
    }
}
