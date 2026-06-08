//! Pure VMX value algebra (the part `tb-hal`'s `arch/x86_64/vmx` asm consumes).
//!
//! Nothing here touches a register or an MSR; these are the bit transforms whose
//! RESULT `tb-hal` then `vmwrite`s. Keeping them here makes the single most
//! safety-critical VMX computation -- the control-MSR ADJUST gate -- provable
//! over all inputs, instead of only test-covered through QEMU.

/// The control-MSR ADJUST gate: `final = (desired | allowed0) & allowed1`.
///
/// Every VMX control field (pin-based, primary/secondary processor-based, exit,
/// entry) has a capability MSR whose low 32 bits are "allowed-0" (bits that MUST
/// be 1) and whose high 32 bits are "allowed-1" (bits that MAY be 1). The only
/// legal control word forces every allowed-0 bit on and clears every bit not
/// permitted by allowed-1. SKIPPING this is the #1 cause of silent VM-entry
/// failure (Intel SDM Vol 3C Appendix A.3/A.4).
///
/// The result ALWAYS satisfies `(r & !allowed1) == 0` (no disallowed bit is
/// ever set) -- proven unconditionally in `proofs.rs`. It additionally satisfies
/// `(r & allowed0) == allowed0` (every must-be-1 bit is set) on every REAL
/// capability MSR, where `allowed0 ⊆ allowed1` (Intel SDM Vol.3D App.A: a bit
/// that MUST be 1 is always permitted to be 1); `proofs.rs` proves this under
/// that well-formedness precondition. (A malformed MSR with `allowed0 ⊄ allowed1`
/// is self-contradictory silicon that cannot exist.)
#[inline]
pub const fn adjust(desired: u32, cap_msr: u64) -> u32 {
    let allowed0 = cap_msr as u32;
    let allowed1 = (cap_msr >> 32) as u32;
    (desired | allowed0) & allowed1
}

/// The CR0/CR4 fixed-bit clamp: `final = (fixed0 | desired) & fixed1`.
///
/// In VMX operation a guest's CR0/CR4 must have every bit set in
/// `IA32_VMX_CRx_FIXED0` forced to 1 and every bit clear in
/// `IA32_VMX_CRx_FIXED1` forced to 0 (Intel SDM Vol 3C §23.8 / Appendix A.7-A.8).
/// `desired` carries the additional bits the host wants on (e.g. PE|NE|PG for
/// CR0, PAE for CR4); they survive iff `fixed1` permits them.
///
/// Proven in `proofs.rs`: the result never sets a bit outside `fixed1`, and
/// every bit in `fixed0 & fixed1` is forced on.
#[inline]
pub const fn clamp_fixed(desired: u64, fixed0: u64, fixed1: u64) -> u64 {
    (fixed0 | desired) & fixed1
}

/// Reassemble a 64-bit TSS descriptor base from the two 8-byte halves of the
/// 16-byte system descriptor.
///
/// A 64-bit (system) segment descriptor scatters the base across the low qword
/// (`base[15:0]` at byte +2, `base[23:16]` at byte +4, `base[31:24]` at byte +7)
/// with `base[63:32]` in the high qword (Intel SDM Vol 3A §3.5 / Vol 3C §24.4.1).
/// `lo`/`hi` are those two qwords read from the GDT; this stitches the base back
/// together. Pure shifts/masks -- the `read_volatile` of the descriptor stays in
/// `tb-hal`.
#[inline]
pub const fn decode_tss_base(lo: u64, hi: u64) -> u64 {
    ((lo >> 16) & 0x00FF_FFFF) | (((lo >> 56) & 0xFF) << 24) | ((hi & 0xFFFF_FFFF) << 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adjust_forces_allowed0_and_clears_disallowed() {
        // allowed0 = 0x0000_0005 (bits 0,2 MUST be 1), allowed1 = 0x0000_000F
        // (bits 0..4 MAY be 1). desired requests bit 5 (not permitted).
        let cap = (0x0000_000Fu64 << 32) | 0x0000_0005u64;
        let r = adjust(1 << 5, cap);
        assert_eq!(r & 0x5, 0x5, "allowed-0 bits forced on");
        assert_eq!(r & !0xF, 0, "no bit outside allowed-1");
        assert_eq!(r, 0x5);
    }

    #[test]
    fn adjust_matches_legacy_inline_form() {
        // Byte-identical to the former tb-hal inline `(desired|allowed0)&allowed1`.
        for &(d, c) in &[
            (0u32, 0u64),
            (0xFFFF_FFFF, 0xFFFF_FFFF_0000_0000),
            (0x8000_0000, 0x0000_0001_8000_0001),
        ] {
            let allowed0 = c as u32;
            let allowed1 = (c >> 32) as u32;
            assert_eq!(adjust(d, c), (d | allowed0) & allowed1);
        }
    }

    #[test]
    fn clamp_fixed_matches_legacy_inline_form() {
        let f0 = 0x0000_0000_8000_0021u64;
        let f1 = 0xFFFF_FFFF_FFFF_FFFFu64;
        let pe_ne_pg = (1u64 << 0) | (1 << 5) | (1 << 31);
        assert_eq!(clamp_fixed(pe_ne_pg, f0, f1), (f0 | pe_ne_pg) & f1);
    }

    #[test]
    fn decode_tss_base_reassembles_scattered_base() {
        // Place a known base 0x1234_5678_9ABC_DEF0 into the descriptor halves.
        let base = 0x1234_5678_9ABC_DEF0u64;
        let lo = ((base & 0xFFFF) << 16)
            | (((base >> 16) & 0xFF) << 32)
            | (((base >> 24) & 0xFF) << 56);
        let hi = (base >> 32) & 0xFFFF_FFFF;
        assert_eq!(decode_tss_base(lo, hi), base);
    }
}
