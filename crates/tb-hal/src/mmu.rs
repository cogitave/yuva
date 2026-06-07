//! Shared typed page-table layer for M3 (`mmu_init` / `mmu_selftest`).
//!
//! Both TABOS architectures use the SAME radix-512 translation-table shape: a
//! table is 4 KiB = 512 × 8-byte entries and each level consumes a 9-bit
//! slice of the virtual address (Intel SDM Vol 3A §4.5 "4-Level Paging",
//! Table 4-15 entry formats; Arm ARM DDI 0487, VMSAv8-64 with the 4 KiB
//! granule). This module is that common shape, typed: a 4096-aligned
//! 512-entry table, a 4096-aligned data frame, and the pure entry/index
//! arithmetic — so the per-arch MMU backends (`arch/x86_64`, `arch/aarch64`)
//! share ONE audited implementation of the bit-slicing and keep their
//! `unsafe` confined to the actual register pokes, table installs and
//! mapped-VA derefs.
//!
//! NOTHING here touches hardware and nothing here is `unsafe`: pure data
//! layout + integer math. The single environmental assumption lives in
//! [`PageTable512::base_addr`] / [`Frame4K::base_addr`]: the kernel image is
//! identity-mapped (x86_64: the A0 boot tables identity-map [0, 1 GiB) with
//! 2 MiB pages; aarch64: tables are written while the MMU is OFF and the M3
//! tables identity-map the RAM gigabyte), so a static's virtual address IS
//! its physical address and may be planted into a parent entry / CR3 /
//! `TTBR0_EL1`.
//!
//! Verified bit facts the helpers rely on (sources re-checked for M3):
//!   * 512-entry tables, 9-bit index slices at shifts 39/30/21/12 — Intel SDM
//!     Vol 3A §4.5.4 (PML4/PDPT/PD/PT); Arm ARM VMSAv8-64 4 KiB granule
//!     (L1/L2/L3 under `T0SZ=25` = 39-bit VA, 3 levels).
//!   * Bit 0 is x86 `P`resent (SDM Table 4-15; Linux v6.6
//!     `arch/x86/include/asm/pgtable_types.h`: `_PAGE_BIT_PRESENT 0`) and
//!     VMSAv8 `Valid` (Linux v6.6 `arch/arm64/include/asm/pgtable-hwdef.h`:
//!     `PTE_VALID (1 << 0)`) on EVERY entry kind — so an all-zero table maps
//!     nothing on both architectures.
//!   * Output-address field: bits [47:12] are address bits on both arches for
//!     4 KiB-aligned tables/frames. x86_64 defines the field up to bit 51
//!     (MAXPHYADDR, SDM Table 4-15) but VMSAv8-64 puts upper ATTRIBUTES in
//!     [51:48] (e.g. DBM at bit 51), so [`ENTRY_ADDR_MASK`] keeps the
//!     portable [47:12] subset; every M3 table/frame sits far below 2^47
//!     (QEMU RAM < 4 GiB), so no address bit is ever masked away.

// Each arch backend consumes a SUBSET of this layer (e.g. aarch64's 3-level
// walk never uses SHIFT_512G; x86_64 never reads entries back); the unused
// remainder must not turn the other arch's build warning-noisy.
#![allow(dead_code)]

/// Bytes per page, per frame and per translation table (4 KiB granule, both
/// architectures).
pub const PAGE_SIZE: usize = 4096;

/// Entries per translation table: `4096 / 8 = 512` on both architectures.
pub const ENTRIES: usize = 512;

/// VA shift of the level whose entries each cover 512 GiB — x86_64 PML4.
/// (Unused by aarch64's 39-bit/3-level layout, which starts at 1 GiB.)
pub const SHIFT_512G: u32 = 39;

/// VA shift of the level whose entries each cover 1 GiB — x86_64 PDPT;
/// aarch64 L1 (the `TTBR0_EL1` root table under `T0SZ=25`).
pub const SHIFT_1G: u32 = 30;

/// VA shift of the level whose entries each cover 2 MiB — x86_64 PD
/// (`PS`-bit 2 MiB pages live here); aarch64 L2.
pub const SHIFT_2M: u32 = 21;

/// VA shift of the 4 KiB leaf level — x86_64 PT; aarch64 L3.
pub const SHIFT_4K: u32 = 12;

/// Output-address bits common to both architectures' 4 KiB-granule entries:
/// bits [47:12]. See the module docs for why [51:48] are deliberately NOT
/// included (x86 address bits up to MAXPHYADDR vs. VMSAv8 upper attributes).
pub const ENTRY_ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

/// The 9-bit table index a translation level consumes from `va`.
///
/// Both architectures slice the VA identically over 512-entry tables:
/// `index = (va >> shift) & 0x1FF` (Intel SDM Vol 3A §4.5.4; Arm ARM
/// VMSAv8-64 translation-walk, 4 KiB granule). Pass one of [`SHIFT_512G`],
/// [`SHIFT_1G`], [`SHIFT_2M`], [`SHIFT_4K`].
pub const fn level_index(va: u64, shift: u32) -> usize {
    ((va >> shift) & (ENTRIES as u64 - 1)) as usize
}

/// Compose a table entry / descriptor: 4 KiB-aligned output address plus the
/// caller's attribute bits.
///
/// `attrs` carries ALL low/high attribute bits — x86_64: `P`/`RW`/`PS`/`NX`…
/// (SDM Table 4-15); aarch64: valid/type, `AF`, `SH[1:0]`, `AP[2:1]`,
/// `AttrIndx[2:0]`… (Arm ARM VMSAv8-64 descriptor formats). This helper only
/// guarantees the address lands in the address field and nowhere else.
pub const fn make_entry(pa: u64, attrs: u64) -> u64 {
    (pa & ENTRY_ADDR_MASK) | attrs
}

/// The output address packed in an entry (the inverse of [`make_entry`]).
pub const fn entry_addr(entry: u64) -> u64 {
    entry & ENTRY_ADDR_MASK
}

/// Whether an entry is live: bit 0 is x86 `P`resent and VMSAv8 `Valid` on
/// both architectures (see the verified facts in the module docs).
pub const fn entry_is_valid(entry: u64) -> bool {
    entry & 1 != 0
}

/// One 4 KiB translation table: 512 × `u64` entries, 4096-aligned, so its
/// base address is directly plantable into a parent table entry, `CR3`, or
/// `TTBR0_EL1` (both architectures require table-granule alignment).
///
/// `const`-constructible all-zeroes, so per-arch `static` instances land in
/// `.bss` — and an all-zero table maps NOTHING on both architectures
/// (bit 0 = Present/Valid, see module docs), which is exactly the safe
/// starting state.
#[repr(C, align(4096))]
pub struct PageTable512(pub [u64; 512]);

impl PageTable512 {
    /// A new empty table (every entry not-present/invalid). `const` so it can
    /// initialise a `static` (placed in `.bss`, costing no image bytes).
    pub const fn new() -> Self {
        PageTable512([0; 512])
    }

    /// Read entry `idx`. Out-of-range panics — fail-closed through the kernel
    /// panic handler rather than a wild table poke.
    pub fn get(&self, idx: usize) -> u64 {
        self.0[idx]
    }

    /// Write entry `idx`. Out-of-range panics (fail-closed, as [`Self::get`]).
    ///
    /// NOTE: this is a plain store. Making it architecturally visible to the
    /// table walker — `dsb ishst` before enable/TLBI on aarch64 (Arm ARM
    /// VMSAv8-64 break-before-make), `invlpg` after changing a LIVE x86
    /// translation (SDM Vol 3A §4.10.4) — is the per-arch caller's job.
    pub fn set(&mut self, idx: usize, entry: u64) {
        self.0[idx] = entry;
    }

    /// This table's base address, for planting into a parent entry or a
    /// translation-base register. It is a PHYSICAL address only under the
    /// identity-mapping assumption spelled out in the module docs (true for
    /// the whole of M3 on both architectures).
    pub fn base_addr(&self) -> u64 {
        self as *const PageTable512 as usize as u64
    }
}

/// One 4 KiB data frame, 4096-aligned, viewed as 512 × `u64` words — the
/// mapping TARGET of the M3 self-test (frame A / frame B).
///
/// Zeroed at boot (`.bss`). The self-test writes magic words through the
/// freshly mapped test VA (a raw deref, confined to the per-arch backend) and
/// audits them through THIS identity-mapped view, which is plain safe field
/// access (`frame.0[i]`).
#[repr(C, align(4096))]
pub struct Frame4K(pub [u64; 512]);

impl Frame4K {
    /// A new zeroed frame. `const` so it can initialise a `static` (`.bss`).
    pub const fn new() -> Self {
        Frame4K([0; 512])
    }

    /// The frame's base address (physical under the identity-map assumption —
    /// module docs), for composing the 4 KiB leaf entry that maps it.
    pub fn base_addr(&self) -> u64 {
        self as *const Frame4K as usize as u64
    }
}
