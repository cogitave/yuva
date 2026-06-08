//! Pure radix-512 page-table + EPT entry algebra.
//!
//! Both TABOS architectures use the SAME translation-table shape: a 4 KiB table
//! of 512 x 8-byte entries, each level consuming a 9-bit slice of the virtual
//! address (Intel SDM Vol 3A §4.5 "4-Level Paging", Table 4-15 entry formats;
//! Arm ARM DDI 0487 VMSAv8-64 with the 4 KiB granule). This module is that
//! common bit-slicing/entry-composition math -- the part `tb-hal`'s per-arch MMU
//! backends and the x86_64 VMX/EPT bring-up consume, while keeping their
//! `unsafe` confined to the actual register pokes and mapped-VA derefs.
//!
//! Nothing here touches hardware and nothing here is `unsafe`: pure data layout +
//! integer math. The owning typed tables (`PageTable512`/`Frame4K`, whose
//! `base_addr` rests on the kernel's identity-map assumption) stay in
//! `tb-hal::mmu`, which re-exports the items below so every existing caller
//! (`crate::mmu::make_entry`, ...) is untouched.

// Each consumer uses a SUBSET of this layer (aarch64's 3-level walk never uses
// SHIFT_512G; the VMX EPT path never reads entries back), so the unused
// remainder must not turn another build target warning-noisy.
#![allow(dead_code)]

// ===========================================================================
// Shared table geometry (x86_64 + aarch64, 4 KiB granule).
// ===========================================================================

/// Bytes per page, per frame and per translation table (4 KiB granule).
pub const PAGE_SIZE: usize = 4096;

/// Entries per translation table: `4096 / 8 = 512` on both architectures.
pub const ENTRIES: usize = 512;

/// VA shift of the level whose entries each cover 512 GiB -- x86_64 PML4.
pub const SHIFT_512G: u32 = 39;

/// VA shift of the level whose entries each cover 1 GiB -- x86_64 PDPT;
/// aarch64 L1 (the `TTBR0_EL1` root table under `T0SZ=25`).
pub const SHIFT_1G: u32 = 30;

/// VA shift of the level whose entries each cover 2 MiB -- x86_64 PD
/// (`PS`-bit 2 MiB pages live here); aarch64 L2.
pub const SHIFT_2M: u32 = 21;

/// VA shift of the 4 KiB leaf level -- x86_64 PT; aarch64 L3.
pub const SHIFT_4K: u32 = 12;

/// Output-address bits common to both architectures' 4 KiB-granule entries:
/// bits `[47:12]`. `[51:48]` are deliberately NOT included (x86 address bits up
/// to MAXPHYADDR vs. VMSAv8 upper attributes); every TABOS table/frame sits far
/// below `2^47`, so no address bit is ever masked away.
pub const ENTRY_ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

/// The 9-bit table index a translation level consumes from `va`:
/// `index = (va >> shift) & 0x1FF`. Pass one of [`SHIFT_512G`], [`SHIFT_1G`],
/// [`SHIFT_2M`], [`SHIFT_4K`]. The result is ALWAYS `< 512` (proven in
/// `proofs.rs`), so it can never hand `PageTable512::get/set` an OOB index.
#[inline]
pub const fn level_index(va: u64, shift: u32) -> usize {
    ((va >> shift) & (ENTRIES as u64 - 1)) as usize
}

/// Compose a table entry / descriptor: 4 KiB-aligned output address plus the
/// caller's attribute bits. `attrs` carries ALL attribute bits (x86_64
/// `P`/`RW`/`PS`/`NX`...; aarch64 valid/type, `AF`, `SH`, `AP`, `AttrIndx`...);
/// the address is forced into the `[47:12]` field and nowhere else.
#[inline]
pub const fn make_entry(pa: u64, attrs: u64) -> u64 {
    (pa & ENTRY_ADDR_MASK) | attrs
}

/// The output address packed in an entry (the inverse of [`make_entry`]).
#[inline]
pub const fn entry_addr(entry: u64) -> u64 {
    entry & ENTRY_ADDR_MASK
}

/// Whether an entry is live: bit 0 is x86 `P`resent and VMSAv8 `Valid` on both
/// architectures, so an all-zero table maps nothing.
#[inline]
pub const fn entry_is_valid(entry: u64) -> bool {
    entry & 1 != 0
}

// ===========================================================================
// EPT (Intel SDM Vol 3C §28.2.2, Table 28-1/28-3) entry encoders.
//
//   bit0 R, bit1 W, bit2 X, bits[5:3] = EPT memory type, bit7 = "maps a page"
//   (large leaf). Non-leaf entries carry only R|W|X + the child address.
// ===========================================================================

/// EPT read|write|execute permission bits (`bit0 R | bit1 W | bit2 X`).
pub const EPT_RWX: u64 = 0b111;

/// EPT "maps a page" bit (bit 7): set on a leaf (large-page) entry.
pub const EPT_MAPS_PAGE: u64 = 1 << 7;

/// EPT memory type Write-Back (`6`), encoded in entry bits `[5:3]` and in the
/// EPTP's low bits.
pub const EPT_MEMTYPE_WB: u64 = 6;

/// Page-walk-length-minus-1 for a 4-level EPT (`3`), encoded in EPTP bits `[5:3]`.
pub const EPT_WALK_LEN_MINUS_1: u64 = 3;

/// Encode an EPT 2 MiB leaf entry: `pa | R|W|X | (memtype<<3) | maps-page`.
/// `memtype` is masked to its 3-bit field. `pa` must be 2 MiB-aligned (the
/// caller passes `i << 21`); the attribute bits then occupy only `[7:0]`, so the
/// address survives intact.
#[inline]
pub const fn ept_leaf_2mib(pa: u64, memtype: u64) -> u64 {
    pa | EPT_RWX | ((memtype & 0x7) << 3) | EPT_MAPS_PAGE
}

/// Encode an EPT non-leaf (table-pointing) entry: `child | R|W|X`. `child` is a
/// 4 KiB-aligned table frame address, so the `R|W|X` bits land in the low 3 bits
/// the aligned address leaves clear.
#[inline]
pub const fn ept_nonleaf(child: u64) -> u64 {
    child | EPT_RWX
}

/// Encode the EPT pointer (VMCS `EPT_POINTER`): `pml4 | WB | ((walk-len-1)<<3)`,
/// i.e. memory-type Write-Back in `[2:0]` and page-walk-length-minus-1 = 3 in
/// `[5:3]` over the PML4 base.
#[inline]
pub const fn eptp(pml4: u64) -> u64 {
    pml4 | EPT_MEMTYPE_WB | (EPT_WALK_LEN_MINUS_1 << 3)
}

// ===========================================================================
// Standard (guest CR3) paging entry encoders -- Intel SDM Vol 3A Table 4-15.
//
//   bit0 P(resent), bit1 R/W, bit7 PS (2 MiB page at the PD level).
// ===========================================================================

/// Standard paging Present|R/W bits (`bit0 P | bit1 RW`).
pub const PTE_P_RW: u64 = 0b11;

/// Standard paging large-page bit (bit 7, `PS`): a 2 MiB leaf at the PD level.
pub const PTE_PS: u64 = 1 << 7;

/// Encode a standard-paging non-leaf (table-pointing) entry: `child | P|RW`.
#[inline]
pub const fn std_table(child: u64) -> u64 {
    child | PTE_P_RW
}

/// Encode a standard-paging 2 MiB leaf entry: `pa | P|RW|PS`. `pa` must be
/// 2 MiB-aligned (the caller passes `i << 21`).
#[inline]
pub const fn std_leaf_2mib(pa: u64) -> u64 {
    pa | PTE_P_RW | PTE_PS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_index_is_9_bit_slice() {
        assert!(level_index(u64::MAX, SHIFT_4K) < 512);
        assert!(level_index(u64::MAX, SHIFT_512G) < 512);
        assert_eq!(level_index(0x1FF << 21, SHIFT_2M), 0x1FF);
        assert_eq!(level_index(0, SHIFT_1G), 0);
    }

    #[test]
    fn make_entry_roundtrips_address_and_preserves_attrs() {
        let pa = 0x0000_1234_5678_9000u64;
        let attrs = 0x8000_0000_0000_0083u64; // NX + PS + RW + P
        let e = make_entry(pa, attrs);
        assert_eq!(entry_addr(e), pa & ENTRY_ADDR_MASK);
        assert_eq!(e & !ENTRY_ADDR_MASK, attrs & !ENTRY_ADDR_MASK);
        assert!(entry_is_valid(e));
    }

    #[test]
    fn ept_encoders_match_legacy_constants() {
        // Legacy tb-hal literals: EPT_LEAF_2MB = 0b111 | (6<<3) | (1<<7).
        let legacy_leaf = 0b111u64 | (6 << 3) | (1 << 7);
        assert_eq!(ept_leaf_2mib(0x200_0000, EPT_MEMTYPE_WB), 0x200_0000 | legacy_leaf);
        assert_eq!(ept_nonleaf(0x100_0000), 0x100_0000 | 0b111);
        assert_eq!(eptp(0x1000), 0x1000 | 6 | (3 << 3));
    }

    #[test]
    fn std_paging_encoders_match_legacy_constants() {
        let legacy_leaf = 0b11u64 | (1 << 7); // PDE_LEAF_2MB
        assert_eq!(std_leaf_2mib(0x200_0000), 0x200_0000 | legacy_leaf);
        assert_eq!(std_table(0x100_0000), 0x100_0000 | 0b11);
    }
}
