//! Pure **Arm SMMUv3** (IHI 0070) Stream Table Entry / command-queue / base-
//! register algebra -- the aL2.6 IOMMU sibling of [`crate::stage2`]'s CPU
//! second-stage encoders.
//!
//! The THESIS this module pins: the SMMU stage-2 tables ARE the CPU stage-2
//! tables, programmed by the SAME encoder. A stage-2-only Stream Table Entry
//! (`STE.Config == 0b110`) carries a `VTCR` field `[50:32]` whose low 19 bits are
//! BIT-FOR-BIT the same `S2T0SZ[5:0]/S2SL0[7:6]/S2IR0[9:8]/S2OR0[11:10]/
//! S2SH0[13:12]/S2TG[15:14]/S2PS[18:16]` layout as `VTCR_EL2[18:0]` that
//! [`crate::stage2::vtcr`] already packs, an `S2VMID` that is the SAME VMID the
//! CPU's `VTTBR_EL2` uses, and an `S2TTB` that is the SAME stage-2 L1 root the
//! CPU's `VTTBR_EL2.BADDR` points at. So [`ste_vtcr_from_vtcr_el2`] is a pure
//! projection of the CPU's `VTCR_EL2` into the STE slot -- the const-checkable
//! lemma that "the SMMU stage-2 geometry IS the CPU stage-2 geometry".
//!
//! Like the rest of `tb-encode`, NOTHING here is `unsafe` or touches hardware:
//! pure data layout + integer math. The silicon-`unsafe` `write_volatile` to the
//! SMMU MMIO + the stream-table/command-queue frame splices live in `tb-hal`'s
//! `arch/aarch64/smmu.rs`, which CALLS these and keeps the store next to the
//! just-computed value -- the `stage2.rs` discipline.
//!
//! Verified bit facts (Arm IHI 0070 §3.3 Stream table / §3.4 STE / §5.2 stage-2
//! VTCR-VTTB in STE / §4 command queue / §6.3 register map; cross-checked against
//! Linux `drivers/iommu/arm/arm-smmu-v3/arm-smmu-v3.h`):
//!   * `STE.0`: `V` = bit0 (Valid); `Config` = bits`[3:1]`, value `0b110` =
//!     stage-2 translate (`0b000`=abort, `0b100`=bypass, `0b101`=S1-only).
//!   * `STE.2`: `S2VMID` = `[15:0]`; `VTCR` = `[50:32]` (the `VTCR_EL2[18:0]`
//!     slice); `S2AA64` = bit51 (AArch64 stage-2 = 1); `S2ENDI` = bit52 (LE = 0);
//!     `S2PTW` = bit54 (fault on Device in S2 walk = 0); `S2R` = bit58 (record
//!     faults = 1).
//!   * `STE.3`: `S2TTB` = `[51:4]`, the stage-2 translation-table base.
//!   * Command queue (16 bytes): `CFGI_STE` op `0x03`, `TLBI_S12_VMALL` op
//!     `0x28`, `CMD_SYNC` op `0x46`; the opcode lives in word0`[7:0]`.
//!   * `STRTAB_BASE.ADDR` = `[51:6]`, `RA` = bit62; `STRTAB_BASE_CFG.LOG2SIZE` =
//!     `[5:0]`, `FMT` = `[17:16]` (0 = linear). `CMDQ_BASE`/`EVENTQ_BASE.ADDR` =
//!     `[51:5]` + `LOG2SIZE` = `[4:0]`.

// Each in-kernel consumer (tb-hal/arch/aarch64/smmu.rs) uses a subset of the
// constants + encoders; the remainder must not turn the kernel build
// warning-noisy (the `stage2.rs` `#![allow(dead_code)]` discipline).
#![allow(dead_code)]

use crate::stage2::vtcr;

// ===========================================================================
// STE Stream Table Entry field layout (Arm IHI 0070 §3.4; arm-smmu-v3.h).
// ===========================================================================

/// `STE.0` `V` (Valid) -- bit0. A cleared `V` makes the SMMU treat the STE as
/// "no stream" (its reset/teardown state); set to publish the entry.
pub const STE_0_V: u64 = 1 << 0;

/// `STE.0` `Config` field shift -- bits`[3:1]`.
pub const STE_0_CFG_SHIFT: u64 = 1;
/// `STE.0` `Config` field mask (3 bits) at its `[3:1]` home (already shifted).
pub const STE_0_CFG_MASK: u64 = 0b111 << STE_0_CFG_SHIFT;
/// `Config == 0b110` -- stage-2 translate (the aL2.6 DMA-isolation config: no
/// stage-1, no Context Descriptor). `0b000`=abort/`0b100`=bypass/`0b101`=S1-only.
pub const STE_CFG_S2_TRANS: u64 = 0b110;

/// `STE.2` `S2VMID` field mask -- bits`[15:0]` (within dword2). The SAME VMID the
/// CPU's `VTTBR_EL2[63:48]` uses, just packed at a different home.
pub const STE_2_S2VMID_MASK: u64 = 0xFFFF;
/// `STE.2` `VTCR` field shift -- bits`[50:32]` (within dword2): the 19-bit
/// `VTCR_EL2[18:0]` projection ([`ste_vtcr_from_vtcr_el2`]).
pub const STE_2_VTCR_SHIFT: u64 = 32;
/// `STE.2` `VTCR` field width: 19 bits (`S2T0SZ`..`S2PS`).
pub const STE_2_VTCR_MASK: u64 = 0x7_FFFF;
/// `STE.2` `S2AA64` -- bit51 (AArch64 stage-2 translation format = 1).
pub const STE_2_S2AA64: u64 = 1 << 51;
/// `STE.2` `S2ENDI` -- bit52 (stage-2 little-endian = 0; defined for completeness).
pub const STE_2_S2ENDI: u64 = 1 << 52;
/// `STE.2` `S2PTW` -- bit54 (fault if a stage-2 walk hits a Device region = 0).
pub const STE_2_S2PTW: u64 = 1 << 54;
/// `STE.2` `S2R` -- bit58 (record stage-2 faults = 1; the no-silent-pass guard).
pub const STE_2_S2R: u64 = 1 << 58;

/// `STE.3` `S2TTB` address-field mask -- bits`[51:4]` (the stage-2 L1 root base,
/// 64-byte-aligned for a single non-concatenated 4 KiB-granule root). WIDER than
/// [`crate::paging::ENTRY_ADDR_MASK`] (`[47:12]`); a 4 KiB-aligned root in the
/// 40-bit PA space sits well within both, but the STE field is the authoritative
/// `[51:4]` shape so the round-trip harness recovers exactly these bits.
pub const STE_3_S2TTB_MASK: u64 = 0x000F_FFFF_FFFF_FFF0;

// ===========================================================================
// STE pack + field accessors (stage-2-only; CFG=0b110, no CD pointer).
// ===========================================================================

/// Pack a **stage-2-only** Stream Table Entry (`[u64; 8]`, 64 bytes). `s2ttb` is
/// the stage-2 L1 root PA (masked to `[51:4]`); `vmid` the 16-bit VMID; `ste_vtcr`
/// the 19-bit `VTCR_EL2` projection ([`ste_vtcr_from_vtcr_el2`]).
///   * dword0 = `V | (CFG_S2_TRANS << 1)`.
///   * dword2 = `(vmid & 0xFFFF) | (ste_vtcr << 32) | S2AA64 | S2R`.
///   * dword3 = `s2ttb` masked to `[51:4]`.
///   * dwords 1,4..7 = 0 (stage-2-only: no `S1ContextPtr`, no stage-1 config).
///
/// `S2ENDI`/`S2PTW` are left clear (little-endian, no fault-on-Device-walk), the
/// stage-2-only DMA-isolation default.
#[inline]
pub const fn ste_s2(s2ttb: u64, vmid: u64, ste_vtcr: u64) -> [u64; 8] {
    let dword0 = STE_0_V | (STE_CFG_S2_TRANS << STE_0_CFG_SHIFT);
    let dword2 = (vmid & STE_2_S2VMID_MASK)
        | ((ste_vtcr & STE_2_VTCR_MASK) << STE_2_VTCR_SHIFT)
        | STE_2_S2AA64
        | STE_2_S2R;
    let dword3 = s2ttb & STE_3_S2TTB_MASK;
    [dword0, 0, dword2, dword3, 0, 0, 0, 0]
}

/// Recover `STE.V` (the Valid bit) from a packed STE.
#[inline]
pub const fn ste_v(ste: &[u64; 8]) -> u64 {
    ste[0] & STE_0_V
}

/// Recover `STE.Config` (`[3:1]`, normalized to `0b000..0b111`) from a packed STE.
#[inline]
pub const fn ste_cfg(ste: &[u64; 8]) -> u64 {
    (ste[0] >> STE_0_CFG_SHIFT) & 0b111
}

/// Recover `STE.S2VMID` (`[15:0]` of dword2) from a packed STE.
#[inline]
pub const fn ste_s2vmid(ste: &[u64; 8]) -> u64 {
    ste[2] & STE_2_S2VMID_MASK
}

/// Recover `STE.VTCR` (`[50:32]` of dword2, the 19-bit projection) from a packed STE.
#[inline]
pub const fn ste_vtcr(ste: &[u64; 8]) -> u64 {
    (ste[2] >> STE_2_VTCR_SHIFT) & STE_2_VTCR_MASK
}

/// Recover `STE.S2TTB` (`[51:4]` of dword3) from a packed STE.
#[inline]
pub const fn ste_s2ttb(ste: &[u64; 8]) -> u64 {
    ste[3] & STE_3_S2TTB_MASK
}

/// **THE LEMMA.** Project the CPU's `VTCR_EL2` word into the STE `VTCR` slot:
/// `vtcr_el2 & 0x7_FFFF` (take `[18:0]`, dropping the EL2-only `RES1` bit31 and
/// any higher bits). The returned 19-bit value is exactly what
/// [`ste_s2`]'s `ste_vtcr` argument expects -- so the SMMU stage-2 `S2T0SZ/S2SL0/
/// S2TG/S2PS/...` geometry is BIT-IDENTICAL to the CPU stage-2 geometry. Proven
/// in `proofs.rs::kani_ste_vtcr_matches_cpu_stage2`.
#[inline]
pub const fn ste_vtcr_from_vtcr_el2(vtcr_el2: u64) -> u64 {
    vtcr_el2 & STE_2_VTCR_MASK
}

/// Build the STE `VTCR` projection directly from the stage-2 geometry fields,
/// routing through the SHARED [`crate::stage2::vtcr`] so the SMMU never re-packs
/// the VTCR algebra (the encoder-reuse discipline). Convenience equal to
/// `ste_vtcr_from_vtcr_el2(stage2::vtcr(..))`.
#[inline]
pub const fn ste_vtcr_from_fields(
    t0sz: u64,
    sl0: u64,
    tg0: u64,
    ps: u64,
    sh0: u64,
    orgn0: u64,
    irgn0: u64,
) -> u64 {
    ste_vtcr_from_vtcr_el2(vtcr(t0sz, sl0, tg0, ps, sh0, orgn0, irgn0))
}

// ===========================================================================
// Command-queue entry encoders (16 bytes = `[u64; 2]`; Arm IHI 0070 §4).
// The opcode occupies word0[7:0]; operands occupy their documented fields.
// ===========================================================================

/// `CMDQ_OP_CFGI_STE` opcode (`0x03`): invalidate the STE config cache for one
/// StreamID, forcing a re-fetch of the just-written STE.
pub const CMD_OP_CFGI_STE: u64 = 0x03;
/// `CMDQ_OP_TLBI_S12_VMALL` opcode (`0x28`): flush stage-1&2 for one VMID (the
/// SMMU twin of the CPU's `TLBI VMALLS12E1IS`).
pub const CMD_OP_TLBI_S12_VMALL: u64 = 0x28;
/// `CMDQ_OP_CMD_SYNC` opcode (`0x46`): drain -- completion observable via
/// `CMDQ_CONS` advancing to `CMDQ_PROD` with no GERROR.
pub const CMD_OP_CMD_SYNC: u64 = 0x46;

/// `CFGI_STE.SID` field shift -- the 32-bit StreamID in word0`[63:32]`.
pub const CMD_CFGI_STE_SID_SHIFT: u64 = 32;
/// `CFGI_STE.Leaf` -- bit0 of word1 (invalidate only the leaf STE, not the
/// whole L2 stream-table range). Set for the single-leaf invalidate.
pub const CMD_CFGI_STE_LEAF: u64 = 1 << 0;
/// `TLBI_S12_VMALL.VMID` field shift -- the 16-bit VMID in word0`[47:32]`.
pub const CMD_TLBI_VMID_SHIFT: u64 = 32;

/// Encode `CMD_CFGI_STE(sid)`: opcode `0x03` in word0`[7:0]`, the 32-bit StreamID
/// in word0`[63:32]`, and `Leaf=1` in word1`[0]` (invalidate just our leaf STE).
#[inline]
pub const fn cmd_cfgi_ste(sid: u32) -> [u64; 2] {
    let word0 = CMD_OP_CFGI_STE | ((sid as u64) << CMD_CFGI_STE_SID_SHIFT);
    [word0, CMD_CFGI_STE_LEAF]
}

/// Encode `CMD_TLBI_S12_VMALL(vmid)`: opcode `0x28` in word0`[7:0]` + the 16-bit
/// VMID in word0`[47:32]`. The SMMU parity of the CPU's `TLBI VMALLS12E1IS`.
#[inline]
pub const fn cmd_tlbi_s12_vmall(vmid: u16) -> [u64; 2] {
    let word0 = CMD_OP_TLBI_S12_VMALL | ((vmid as u64) << CMD_TLBI_VMID_SHIFT);
    [word0, 0]
}

/// Encode `CMD_SYNC`: opcode `0x46` in word0`[7:0]`. The drain marker -- when the
/// SMMU consumes it (CONS catches PROD) with GERROR clean, every prior command
/// (the `CFGI_STE`) has completed. A SIG_NONE/no-interrupt SYNC (both words'
/// completion-signalling fields left 0 = poll for CONS, the bounded-poll path).
#[inline]
pub const fn cmd_sync() -> [u64; 2] {
    [CMD_OP_CMD_SYNC, 0]
}

// ===========================================================================
// Base / config register packers (Arm IHI 0070 §6.3).
// ===========================================================================

/// `STRTAB_BASE.ADDR` field mask -- bits`[51:6]` (64-byte-aligned stream-table PA).
pub const STRTAB_BASE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_FFC0;
/// `STRTAB_BASE.RA` -- bit62 (Read-Allocate hint for table fetches = 1).
pub const STRTAB_BASE_RA: u64 = 1 << 62;
/// `STRTAB_BASE_CFG.FMT` field shift -- bits`[17:16]` (0 = linear stream table).
pub const STRTAB_BASE_CFG_FMT_SHIFT: u64 = 16;
/// `STRTAB_BASE_CFG.FMT == 0` -- a LINEAR (single-level) stream table.
pub const STRTAB_BASE_CFG_FMT_LINEAR: u64 = 0;
/// `STRTAB_BASE_CFG.LOG2SIZE` field mask -- bits`[5:0]` (log2 of the number of
/// stream-table entries; 0 for a 1-entry table).
pub const STRTAB_BASE_CFG_LOG2SIZE_MASK: u64 = 0x3F;

/// `CMDQ_BASE`/`EVENTQ_BASE.ADDR` field mask -- bits`[51:5]` (queue-PA, the queue
/// base is 32-byte aligned at minimum; a 4 KiB frame is amply aligned).
pub const QUEUE_BASE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_FFE0;
/// `CMDQ_BASE`/`EVENTQ_BASE.RA`/`WA` -- bit62 (Read/Write-Allocate hint = 1).
pub const QUEUE_BASE_RA: u64 = 1 << 62;
/// `CMDQ_BASE`/`EVENTQ_BASE.LOG2SIZE` field mask -- bits`[4:0]` (log2 of the
/// number of queue entries).
pub const QUEUE_BASE_LOG2SIZE_MASK: u64 = 0x1F;

/// Encode `STRTAB_BASE` = the stream-table PA in `[51:6]` | `RA` (bit62).
#[inline]
pub const fn strtab_base(pa: u64) -> u64 {
    (pa & STRTAB_BASE_ADDR_MASK) | STRTAB_BASE_RA
}

/// Encode `STRTAB_BASE_CFG` = `FMT` (`[17:16]`) | `LOG2SIZE` (`[5:0]`). `fmt` is
/// [`STRTAB_BASE_CFG_FMT_LINEAR`] for the 1-entry linear table; `log2size` = 0
/// for a single STE.
#[inline]
pub const fn strtab_base_cfg(log2size: u64, fmt: u64) -> u64 {
    ((fmt & 0x3) << STRTAB_BASE_CFG_FMT_SHIFT) | (log2size & STRTAB_BASE_CFG_LOG2SIZE_MASK)
}

/// Encode `CMDQ_BASE` = the command-queue PA in `[51:5]` | `RA` | `LOG2SIZE`
/// (`[4:0]`). `log2size` is the log2 of the queue depth (e.g. 4 => 16 entries).
#[inline]
pub const fn cmdq_base(pa: u64, log2size: u64) -> u64 {
    (pa & QUEUE_BASE_ADDR_MASK) | QUEUE_BASE_RA | (log2size & QUEUE_BASE_LOG2SIZE_MASK)
}

/// Encode `EVENTQ_BASE` = the event-queue PA in `[51:5]` | `WA` | `LOG2SIZE`
/// (`[4:0]`). Same shape as [`cmdq_base`] (the WA/RA hint bit is the same bit62).
#[inline]
pub const fn eventq_base(pa: u64, log2size: u64) -> u64 {
    (pa & QUEUE_BASE_ADDR_MASK) | QUEUE_BASE_RA | (log2size & QUEUE_BASE_LOG2SIZE_MASK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stage2::vtcr;

    #[test]
    fn ste_s2_packs_cfg_v_and_recovers_every_field() {
        // The aL2.6 geometry: VMID=1, the L2.1 VTCR projection, a 4 KiB-aligned
        // stage-2 root in the 40-bit PA space.
        let s2ttb = 0x4080_0000u64;
        let vmid = 1u64;
        let cpu_vtcr = vtcr(25, 1, 0b00, 0b010, 0b11, 0b01, 0b01);
        let ste_vtcr_field = ste_vtcr_from_vtcr_el2(cpu_vtcr);

        let ste = ste_s2(s2ttb, vmid, ste_vtcr_field);
        assert_eq!(ste_v(&ste), STE_0_V); // Valid
        assert_eq!(ste_cfg(&ste), STE_CFG_S2_TRANS); // CFG == 0b110
        assert_eq!(ste_s2vmid(&ste), vmid); // VMID
        assert_eq!(ste_vtcr(&ste), ste_vtcr_field); // VTCR projection
        assert_eq!(ste_s2ttb(&ste), s2ttb); // S2TTB preserved
        // S2AA64 + S2R set; S2ENDI + S2PTW clear (stage-2-only LE default).
        assert!(ste[2] & STE_2_S2AA64 != 0);
        assert!(ste[2] & STE_2_S2R != 0);
        assert_eq!(ste[2] & STE_2_S2ENDI, 0);
        assert_eq!(ste[2] & STE_2_S2PTW, 0);
        // Stage-2-only: dwords 1,4..7 are zero (no S1ContextPtr, no S1 config).
        assert_eq!(ste[1], 0);
        assert_eq!(ste[4], 0);
        assert_eq!(ste[5], 0);
        assert_eq!(ste[6], 0);
        assert_eq!(ste[7], 0);
    }

    #[test]
    fn ste_vtcr_projection_is_low_19_bits_of_vtcr_el2() {
        // The CPU VTCR_EL2 carries RES1 bit31; the STE projection drops it but
        // keeps S2T0SZ/S2SL0/S2TG/S2PS bit-identically.
        let cpu_vtcr = vtcr(25, 1, 0b00, 0b010, 0b11, 0b01, 0b01);
        assert!(cpu_vtcr & (1 << 31) != 0); // RES1 set in the CPU word
        let proj = ste_vtcr_from_vtcr_el2(cpu_vtcr);
        assert_eq!(proj & (1 << 31), 0); // RES1 dropped
        assert_eq!(proj & 0x3F, 25); // S2T0SZ
        assert_eq!((proj >> 6) & 0x3, 1); // S2SL0
        assert_eq!((proj >> 14) & 0x3, 0b00); // S2TG
        assert_eq!((proj >> 16) & 0x7, 0b010); // S2PS
        // ...and the projection == VTCR_EL2[18:0] exactly.
        assert_eq!(proj, cpu_vtcr & 0x7_FFFF);
    }

    #[test]
    fn cmd_encoders_place_opcode_and_operands() {
        let c = cmd_cfgi_ste(0);
        assert_eq!(c[0] & 0xFF, CMD_OP_CFGI_STE); // opcode in [7:0]
        assert_eq!(c[0] >> 32, 0); // SID == 0
        assert_eq!(c[1] & 1, 1); // Leaf
        let c2 = cmd_cfgi_ste(0x1234_5678);
        assert_eq!(c2[0] & 0xFF, CMD_OP_CFGI_STE);
        assert_eq!(c2[0] >> 32, 0x1234_5678); // SID in [63:32]

        let t = cmd_tlbi_s12_vmall(1);
        assert_eq!(t[0] & 0xFF, CMD_OP_TLBI_S12_VMALL);
        assert_eq!((t[0] >> 32) & 0xFFFF, 1); // VMID

        let s = cmd_sync();
        assert_eq!(s[0] & 0xFF, CMD_OP_CMD_SYNC);
    }

    #[test]
    fn base_register_packers_place_addr_and_fields() {
        let st = strtab_base(0x4100_0000);
        assert_eq!(st & STRTAB_BASE_ADDR_MASK, 0x4100_0000); // ADDR preserved
        assert!(st & STRTAB_BASE_RA != 0); // RA set

        let cfg = strtab_base_cfg(0, STRTAB_BASE_CFG_FMT_LINEAR);
        assert_eq!(cfg & 0x3F, 0); // LOG2SIZE == 0 (one entry)
        assert_eq!((cfg >> 16) & 0x3, 0); // FMT == linear

        let cq = cmdq_base(0x4101_0000, 4);
        assert_eq!(cq & QUEUE_BASE_ADDR_MASK, 0x4101_0000);
        assert_eq!(cq & 0x1F, 4); // LOG2SIZE == 4 (16 entries)

        let eq = eventq_base(0x4102_0000, 4);
        assert_eq!(eq & QUEUE_BASE_ADDR_MASK, 0x4102_0000);
        assert_eq!(eq & 0x1F, 4);
    }
}
