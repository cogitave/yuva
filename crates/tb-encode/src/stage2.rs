//! Pure aarch64 **stage-2** (VMSAv8-64 second-stage) descriptor + control-register
//! algebra -- the L2.1 sibling of [`crate::paging`]'s EPT encoders.
//!
//! When `HCR_EL2.VM == 1`, every EL1&0 access (INCLUDING the hardware stage-1
//! page-table walk) is re-translated by a SECOND set of tables whose root is
//! `VTTBR_EL2` and whose geometry is `VTCR_EL2` -- the ARM analog of Intel EPT.
//! This module is the pure bit math for those second-stage descriptors and the
//! two control registers, exactly mirroring how `paging::ept_*` front the x86
//! EPT pokes: `tb-hal`'s `arch/aarch64/stage2.rs` CALLS these and keeps its
//! `unsafe` confined to the `msr VTTBR_EL2/VTCR_EL2/HCR_EL2` writes + the
//! `write_volatile` descriptor splices. Nothing here is `unsafe` or touches
//! hardware: pure data layout + integer math, Kani-proven over the documented
//! reachable envelope and Miri-gated for UB.
//!
//! Verified bit facts (Arm ARM DDI 0487, VMSAv8-64 stage-2 descriptor + VTCR_EL2
//! + VTTBR_EL2; cross-checked against Linux v6.6 `arch/arm64/include/asm/
//! kvm_pgtable.h` / `pgtable-prot.h`):
//!   * Stage-2 leaf descriptor low bits -- block (L1/L2) = `0b01`, page (L3) =
//!     `0b11`, table (L0..L2) = `0b11`, identical to stage-1.
//!   * `S2AP[7:6]` -- stage-2 data Access Permissions; `0b11` = read/write (the
//!     stage-2 equivalent of EPT's `R|W`). (Stage-2 has NO U/S split; EL0 vs EL1
//!     is governed by stage-1.)
//!   * `MemAttr[5:2]` -- stage-2 memory attributes; `0xF` = Normal Inner+Outer
//!     Write-Back (the EPT-`WB` analog), `0x0` = Device-nGnRnE.
//!   * `SH[9:8]` -- shareability; `0b11` = inner shareable (matches the kernel's
//!     stage-1 Normal mappings).
//!   * `AF` -- Access Flag, **bit[10], MANDATORY on every leaf**: Yuva installs
//!     no Access-Flag-fault handler, so a cleared AF = a synchronous abort on
//!     first access (the same rule `arch/aarch64/mmu.rs` documents for stage-1).
//!   * `XN[54:53]` -- stage-2 execute-never (optional; `0b10` = XN at all ELs on
//!     ARMv8.0). Defined for completeness; the L2.1 identity map leaves it clear
//!     so the guest can fetch its own code out of the RAM gigabyte.
//!   * Output address -- bits `[47:12]`, packed via the SHARED
//!     [`crate::paging::make_entry`] / [`crate::paging::ENTRY_ADDR_MASK`] (NOT a
//!     duplicate masker), so the address algebra is the one already proven in
//!     `paging.rs`.
//!   * `VTCR_EL2` -- T0SZ`[5:0]`, SL0`[7:6]`, IRGN0`[9:8]`, ORGN0`[11:10]`,
//!     SH0`[13:12]`, TG0`[15:14]`, PS`[18:16]`, **RES1 bit[31]**.
//!   * `VTTBR_EL2` -- BADDR in `[47:1]` (here the 4 KiB-granule `[47:12]` subset,
//!     a single non-concatenated L1 root) + VMID in `[63:48]` (8-bit on ARMv8.0,
//!     16-bit with FEAT_VMID16; either fits `[63:48]` and never collides BADDR).

// Each consumer uses a subset of the constants (the device memattr is only used
// by the GiB0 identity block; XN is unused by the L2.1 smoke), so the unused
// remainder must not turn the kernel build warning-noisy.
#![allow(dead_code)]

use crate::paging::{make_entry, ENTRY_ADDR_MASK};

// ===========================================================================
// Stage-2 leaf / table descriptor attribute fields (Arm ARM, VMSAv8-64).
// ===========================================================================

/// Block (leaf) descriptor low bits at L1/L2: `bits[1:0] = 0b01`.
pub const S2_DESC_BLOCK: u64 = 0b01;
/// Page (leaf) descriptor low bits at L3: `bits[1:0] = 0b11`.
pub const S2_DESC_PAGE: u64 = 0b11;
/// Table (next-level) descriptor low bits at L0..L2: `bits[1:0] = 0b11`.
pub const S2_DESC_TABLE: u64 = 0b11;

/// `S2AP[7:6] = 0b11` -- stage-2 read/write (the EPT `R|W` analog).
pub const S2AP_RW: u64 = 0b11 << 6;
/// `MemAttr[5:2] = 0xF` -- stage-2 Normal Inner+Outer Write-Back (the EPT-WB analog).
pub const S2_MEMATTR_NORMAL_WB: u64 = 0xF << 2;
/// `MemAttr[5:2] = 0x0` -- stage-2 Device-nGnRnE (for the MMIO gigabyte).
pub const S2_MEMATTR_DEVICE: u64 = 0x0 << 2;
/// `SH[9:8] = 0b11` -- inner shareable.
pub const S2_SH_INNER: u64 = 0b11 << 8;
/// `AF` -- Access Flag, bit[10]; MANDATORY on every leaf (no AF-fault handler).
pub const S2_AF: u64 = 1 << 10;
/// `XN[54:53] = 0b10` -- stage-2 execute-never at all ELs (optional; unused by
/// the L2.1 identity map so the guest can fetch its own code).
pub const S2_XN: u64 = 0b10 << 53;

// ===========================================================================
// Stage-2 leaf / table encoders. The address is forced into `[47:12]` by the
// SHARED `make_entry`; the attribute bits occupy only `[10:0]` (+ optional XN),
// so the address survives intact.
// ===========================================================================

/// Encode a stage-2 **2 MiB block** leaf (L2): `pa | block | AF | SH | S2AP_RW |
/// memattr`. `pa` must be 2 MiB-aligned (the caller passes `i << 21` or a 2 MiB
/// base); `memattr` is one of [`S2_MEMATTR_NORMAL_WB`] / [`S2_MEMATTR_DEVICE`]
/// (already shifted into `[5:2]`).
#[inline]
pub const fn s2_leaf_2mib(pa: u64, memattr: u64) -> u64 {
    make_entry(pa, S2_DESC_BLOCK | S2_AF | S2_SH_INNER | S2AP_RW | memattr)
}

/// Encode a stage-2 **4 KiB page** leaf (L3): `pa | page | AF | SH | S2AP_RW |
/// memattr`. `pa` must be 4 KiB-aligned. This is the descriptor the EL2
/// demand-fault handler splices to service a stage-2 translation fault.
#[inline]
pub const fn s2_leaf_4k(pa: u64, memattr: u64) -> u64 {
    make_entry(pa, S2_DESC_PAGE | S2_AF | S2_SH_INNER | S2AP_RW | memattr)
}

/// Encode a stage-2 **table** (next-level-pointing) descriptor: `child | 0b11`.
/// `child` is a 4 KiB-aligned table-frame address, so the `0b11` lands in the
/// low two bits the aligned address leaves clear.
#[inline]
pub const fn s2_table(child: u64) -> u64 {
    make_entry(child, S2_DESC_TABLE)
}

// ===========================================================================
// VTCR_EL2 -- the stage-2 translation-control packer (Arm ARM D19.2).
// ===========================================================================

/// `VTCR_EL2` RES1 bit[31] -- must be 1 (the stage-2 twin of EPTP's encoded
/// constants; an unset RES1 is UNPREDICTABLE on real cores).
pub const VTCR_RES1: u64 = 1 << 31;

/// Pack `VTCR_EL2` from its documented fields. `t0sz` -> `[5:0]`, `sl0` ->
/// `[7:6]` (start-level), `irgn0` -> `[9:8]`, `orgn0` -> `[11:10]`, `sh0` ->
/// `[13:12]`, `tg0` -> `[15:14]` (granule), `ps` -> `[18:16]` (PhysAddrSize),
/// plus RES1 bit[31]. Each field is masked to its width so a stray high bit can
/// never bleed into a neighbouring field (the SL0/T0SZ off-by-one bug class --
/// the ARM twin of the EPTP walk-length-minus-1 bug -- is fenced here and proven
/// in `proofs.rs::kani_vtcr_wellformed`).
#[inline]
pub const fn vtcr(t0sz: u64, sl0: u64, tg0: u64, ps: u64, sh0: u64, orgn0: u64, irgn0: u64) -> u64 {
    VTCR_RES1
        | (t0sz & 0x3F)
        | ((sl0 & 0x3) << 6)
        | ((irgn0 & 0x3) << 8)
        | ((orgn0 & 0x3) << 10)
        | ((sh0 & 0x3) << 12)
        | ((tg0 & 0x3) << 14)
        | ((ps & 0x7) << 16)
}

// ===========================================================================
// VTTBR_EL2 -- the stage-2 root + VMID packer (Arm ARM D19.2).
// ===========================================================================

/// VMID field shift in `VTTBR_EL2`: bits `[63:48]` (8-bit VMID on ARMv8.0 lands
/// in `[55:48]`; FEAT_VMID16 widens it to `[63:48]`). Disjoint from the
/// `[47:12]` BADDR field, so a VMID can never corrupt the root address.
pub const VTTBR_VMID_SHIFT: u64 = 48;

/// Pack `VTTBR_EL2`: the 4 KiB-aligned stage-2 L1 root address in BADDR
/// (`[47:12]`, via the shared [`make_entry`]) OR'd with `vmid` in `[63:48]`.
/// `root_pa` is a single, NON-concatenated L1 root (T0SZ=25 -> 4 KiB BADDR
/// alignment), so a plain frame address suffices. The VMID is masked to 16 bits
/// and shifted clear of BADDR (proven disjoint in `kani_s2_table_and_vttbr`).
#[inline]
pub const fn vttbr(root_pa: u64, vmid: u64) -> u64 {
    make_entry(root_pa, (vmid & 0xFFFF) << VTTBR_VMID_SHIFT)
}

/// The BADDR (root-address) field of `VTTBR_EL2` (the inverse of the address
/// half of [`vttbr`]) -- the same `[47:12]` subset the rest of the crate uses.
#[inline]
pub const fn vttbr_baddr(vttbr_val: u64) -> u64 {
    vttbr_val & ENTRY_ADDR_MASK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s2_leaf_2mib_sets_rw_af_wb_block_and_keeps_addr() {
        let pa = 0x4020_0000u64; // 2 MiB-aligned
        let e = s2_leaf_2mib(pa, S2_MEMATTR_NORMAL_WB);
        assert_eq!(e & 0b11, S2_DESC_BLOCK); // block leaf
        assert_eq!(e & S2AP_RW, S2AP_RW); // read/write
        assert_eq!((e >> 2) & 0xF, 0xF); // MemAttr = Normal-WB
        assert!(e & S2_AF != 0); // AF mandatory
        assert_eq!(e & ENTRY_ADDR_MASK, pa); // address preserved
    }

    #[test]
    fn s2_leaf_4k_is_a_page_not_a_block() {
        let pa = 0x4711_2000u64;
        let e = s2_leaf_4k(pa, S2_MEMATTR_NORMAL_WB);
        assert_eq!(e & 0b11, S2_DESC_PAGE); // page leaf (0b11)
        assert!(e & S2_AF != 0);
        assert_eq!(e & ENTRY_ADDR_MASK, pa);
    }

    #[test]
    fn s2_table_is_child_or_3() {
        let child = 0x4123_4000u64;
        assert_eq!(s2_table(child), child | 0b11);
    }

    #[test]
    fn vtcr_lands_each_field_and_sets_res1() {
        // The L2.1 geometry: T0SZ=25, SL0=1, TG0=0(4K), PS=0b010(40-bit),
        // SH0=0b11, ORGN0=0b01, IRGN0=0b01.
        let v = vtcr(25, 1, 0b00, 0b010, 0b11, 0b01, 0b01);
        assert_eq!(v & 0x3F, 25); // T0SZ
        assert_eq!((v >> 6) & 0x3, 1); // SL0
        assert_eq!((v >> 8) & 0x3, 0b01); // IRGN0
        assert_eq!((v >> 10) & 0x3, 0b01); // ORGN0
        assert_eq!((v >> 12) & 0x3, 0b11); // SH0
        assert_eq!((v >> 14) & 0x3, 0b00); // TG0 = 4 KiB
        assert_eq!((v >> 16) & 0x7, 0b010); // PS = 40-bit
        assert!(v & VTCR_RES1 != 0); // RES1 bit31
    }

    #[test]
    fn vttbr_packs_vmid_clear_of_baddr() {
        let root = 0x4080_0000u64; // 4 KiB-aligned
        let vt = vttbr(root, 1);
        assert_eq!(vttbr_baddr(vt), root); // BADDR preserved
        assert_eq!((vt >> VTTBR_VMID_SHIFT) & 0xFFFF, 1); // VMID in [63:48]
        assert_eq!(vt & ENTRY_ADDR_MASK & (0xFFFF << VTTBR_VMID_SHIFT), 0); // disjoint
    }
}
