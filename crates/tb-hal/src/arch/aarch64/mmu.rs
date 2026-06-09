//! aarch64 MMU: cold bring-up (MAIR/TCR/TTBR0 -> SCTLR_EL1.M|C|I) plus the M3
//! 4 KiB map / Break-Before-Make remap self-test (units A6/A7/A9).
//!
//! Entered with the MMU OFF (QEMU `virt`, EL1h -- see `boot.rs`). [`mmu_init`]
//! brings translation up FROM COLD as a 39-bit-VA, 4 KiB-granule, 3-level
//! identity space:
//!
//!   * L1[0] = 1 GiB BLOCK @ PA 0x0000_0000, Device-nGnRnE (MAIR attr0) --
//!     covers the PL011 UART at 0x0900_0000 (`serial.rs`), so serial output
//!     surviving the enable proves this descriptor is right.
//!   * L1[1] = 1 GiB BLOCK @ PA 0x4000_0000, Normal WB RA/WA (MAIR attr1) --
//!     covers all of RAM (0x4000_0000..0x4800_0000, 128 MiB; image at
//!     0x4008_0000): our code, stack, and these very tables.
//!   * L1[2] (VA 0x8000_0000, 2 GiB) stays INVALID -- [`mmu_selftest`] hangs
//!     its L2 -> L3 -> 4 KiB test mapping there, outside the RAM gigabyte.
//!
//! VERIFIED facts this module is built on (sources re-fetched 2026-06-07; do
//! NOT change the constants without re-reading them):
//!
//!   * VMSAv8-64 descriptor low bits -- table = 0b11 (L0..L2), block = 0b01
//!     (L1/L2 leaf), page = 0b11 (L3 leaf); AttrIndx = bits[4:2]; AP[2:1] =
//!     bits[7:6] (0b00 = EL1 RW, no EL0); SH = bits[9:8] (0b11 = inner
//!     shareable); **AF = bit[10], MANDATORY on every leaf** (we install no
//!     Access-Flag-fault handler, so a cleared AF = synchronous abort on first
//!     access): Arm ARM DDI 0487, VMSAv8-64 translation table format
//!     descriptors (D8.3); cross-checked against Linux v6.6
//!     `arch/arm64/include/asm/pgtable-hwdef.h` -- `PMD_TYPE_SECT (1 << 0)`,
//!     `PUD_TYPE_TABLE (3 << 0)`, `PTE_TYPE_PAGE (3 << 0)`, `PTE_AF (1 << 10)`
//!     "Access Flag", `PTE_SHARED (3 << 8)` "SH[1:0], inner shareable",
//!     `PTE_ATTRINDX(t) ((t) << 2)`, `PTE_USER (1 << 6)` /* AP[1] */,
//!     `PTE_RDONLY (1 << 7)` /* AP[2] */ -- and the descriptor diagram in
//!     lowenware.com "AArch64 MMU Programming" (AF bit 10, SH 9:8, AP 7:6,
//!     INDX 4:2, TB bit 1, VB bit 0). (osdev.org "AArch64 Paging" documents
//!     the same layout; its CDN refused our fetch, hence the Linux + lowenware
//!     cross-check.)
//!   * TCR_EL1 fields -- T0SZ bits[5:0]; IRGN0 bits[9:8] / ORGN0 bits[11:10]
//!     (0b01 = WB RA/WA cacheable walks); SH0 bits[13:12] (0b11 = inner
//!     shareable); TG0 bits[15:14] (0b00 = 4 KiB); T1SZ bits[21:16]; EPD1
//!     bit[23] (1 = TTBR1_EL1 walks disabled); IPS bits[34:32] (0b010 =
//!     40-bit PA, the ID_AA64MMFR0_EL1.PARange encoding): Linux v6.6
//!     `pgtable-hwdef.h` -- `TCR_T0SZ_OFFSET 0`, `TCR_IRGN0_WBWA (1 << 8)`,
//!     `TCR_ORGN0_WBWA (1 << 10)`, `TCR_SH0_INNER (3 << 12)`,
//!     `TCR_TG0_4K (0 << 14)`, `TCR_T1SZ_OFFSET 16`, `TCR_EPD1_SHIFT 23`,
//!     `TCR_IPS_SHIFT 32`; Arm ARM TCR_EL1 (D19.2).
//!   * SCTLR_EL1 -- M = bit 0 (stage-1 MMU enable), C = bit 2 (data/unified
//!     caches), I = bit 12 (instruction caches): Linux v6.6 `sysreg.h` --
//!     `SCTLR_ELx_M (BIT(0))`, `SCTLR_ELx_C (BIT(2))`, `SCTLR_ELx_I
//!     (BIT(12))`; Arm ARM SCTLR_EL1 (D19.2).
//!   * MAIR_EL1 encodings -- Device-nGnRnE = 0x00, Normal WB RA/WA
//!     inner+outer = 0xFF, attribute n occupies bits [8n+7:8n]: Linux v6.6
//!     `sysreg.h` -- `MAIR_ATTR_DEVICE_nGnRnE UL(0x00)`, `MAIR_ATTR_NORMAL
//!     UL(0xff)`, `MAIR_ATTRIDX(attr, idx) ((attr) << ((idx) * 8))`; Arm ARM
//!     MAIR_EL1 (D19.2).
//!   * TLBI VA-operand -- operand bits[43:0] = VA[55:12], i.e. `VA >> 12`
//!     (ASID in bits[63:48]; zero here, and VAAE1IS matches All ASIDs anyway),
//!     and the canonical sequence `DSB ISHST -> TLBI -> DSB ISH -> ISB`:
//!     Linux v6.6 `tlbflush.h` -- `__TLBI_VADDR(addr, asid)` = `(addr) >> 12`
//!     masked to GENMASK(43,0), and `__flush_tlb_kernel_pgtable()` issues
//!     exactly `dsb(ishst); __tlbi(vaae1is, addr); dsb(ish); isb()`; VAAE1IS
//!     also drops walk-cache entries, which the remap relies on; Arm ARM TLB
//!     maintenance instructions (D8.14).
//!   * Break-Before-Make -- changing the output address of a live leaf
//!     requires: invalid descriptor -> barrier -> TLBI -> barrier -> new
//!     descriptor: Arm ARM DDI 0487, "Using break-before-make when updating
//!     translation table entries" (D8.16).
//!
//! All `unsafe` + `asm!` stays in tb-hal (framekernel rule); `lib.rs` exposes
//! the safe [`mmu_init`] / [`mmu_selftest`] surface to the
//! `#![forbid(unsafe_code)]` kernel crate. The typed 512-entry table layout
//! (`PageTable512`) is shared with the x86_64 backend via `crate::mmu`.

use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};

use crate::mmu::{
    entry_addr, entry_is_valid, level_index, make_entry, PageTable512, ENTRIES, PAGE_SIZE,
    SHIFT_1G, SHIFT_2M, SHIFT_4K,
};

// ===========================================================================
// Virtual layout
// ===========================================================================

/// The M3 test virtual address: 2 GiB. With T0SZ = 25 (39-bit VA, 3 levels)
/// the indices are L1 = VA[38:30] = 2, L2 = VA[29:21] = 0, L3 = VA[20:12] = 0.
/// L1[2] is the first gigabyte slot past the identity-mapped RAM gigabyte
/// (L1[1]), so this VA has NO translation until `mmu_selftest` installs one.
const TEST_VA: u64 = 0x8000_0000;

/// Identity gigabyte 0: MMIO, including the PL011 UART at 0x0900_0000.
const GIB0_DEVICE_PA: u64 = 0x0000_0000;
/// Identity gigabyte 1: RAM (QEMU `virt`, `-m 128M` => 0x4000_0000..0x4800_0000).
const GIB1_RAM_PA: u64 = 0x4000_0000;

// ===========================================================================
// VMSAv8-64 descriptor bits (verified -- module doc)
// ===========================================================================

/// Table descriptor (valid at L0..L2): bits[1:0] = 0b11; next-level table PA
/// lives in bits [47:12].
const DESC_TABLE: u64 = 0b11;
/// Block (leaf) descriptor at L1/L2: bits[1:0] = 0b01.
const DESC_BLOCK: u64 = 0b01;
/// Page (leaf) descriptor at L3: bits[1:0] = 0b11.
const DESC_PAGE: u64 = 0b11;
/// Access Flag, bit[10]. MUST be 1 on every leaf we write: tb-hal installs no
/// Access-Flag-fault handling, so a cleared AF means a fault/hang on the very
/// first access through the mapping.
const DESC_AF: u64 = 1 << 10;
/// SH[9:8] = 0b11, inner shareable. For Device memory the field is ignored
/// (Device is always treated as outer shareable), so the uniform value is
/// architecturally harmless on the Device block.
const DESC_SH_INNER: u64 = 0b11 << 8;
/// AttrIndx[4:2] = 0 -> MAIR_EL1 attr0 (Device-nGnRnE).
const DESC_ATTRIDX_DEVICE: u64 = 0 << 2;
/// AttrIndx[4:2] = 1 -> MAIR_EL1 attr1 (Normal WB RA/WA).
const DESC_ATTRIDX_NORMAL: u64 = 1 << 2;
// AP[7:6] = 0b00 (EL1 RW, no EL0 access) is the ABSENCE of bits 6 and 7.

/// 1 GiB Device leaf at L1: block | AF | SH | attr0 (= 0x701 over the PA).
const BLOCK_DEVICE: u64 = DESC_BLOCK | DESC_AF | DESC_SH_INNER | DESC_ATTRIDX_DEVICE;
/// 1 GiB Normal leaf at L1: block | AF | SH | attr1 (= 0x705 over the PA).
const BLOCK_NORMAL: u64 = DESC_BLOCK | DESC_AF | DESC_SH_INNER | DESC_ATTRIDX_NORMAL;
/// 4 KiB Normal leaf at L3: page | AF | SH | attr1 (= 0x707 over the PA).
const PAGE_NORMAL: u64 = DESC_PAGE | DESC_AF | DESC_SH_INNER | DESC_ATTRIDX_NORMAL;

/// Privileged execute-never, bit[53]: EL1 cannot execute this page (Linux
/// `PTE_PXN (1 << 53)`). Set on the M7 heap leaves — the heap holds data.
const DESC_PXN: u64 = 1 << 53;
/// User (EL0) execute-never, bit[54] (Linux `PTE_UXN (1 << 54)`). Also set on
/// the M7 heap leaves, completing no-execute at BOTH ELs.
const DESC_UXN: u64 = 1 << 54;
/// Table / TTBR0 output-address mask: bits[47:12] (the 4 KiB-granule next-level
/// table PA; the M3 typed [`crate::mmu::entry_addr`] uses the same subset).
const TTBR_BADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
/// M7 kernel-heap 4 KiB leaf: page | AF | inner-SH | Normal-WB, EL1 RW
/// (AP[2:1] = 0b00, no EL0), no-execute at either EL (PXN | UXN). Data only.
const PAGE_KERNEL_RW_NX: u64 =
    DESC_PAGE | DESC_AF | DESC_SH_INNER | DESC_ATTRIDX_NORMAL | DESC_PXN | DESC_UXN;

/// M12 AP[1] = PTE_USER, bit[6]: set => EL0 may access (Linux `PTE_USER`). With
/// AP[2] clear this gives EL1 RW + EL0 RW; the M4/M11 user windows use the same.
const AP_EL0_RW: u64 = 1 << 6;
/// M12 AP[2], bit[7]: set => read-only at the granted EL(s) (Linux `PTE_RDONLY`).
const AP_RDONLY: u64 = 1 << 7;

// ===========================================================================
// MAIR_EL1 / TCR_EL1 / SCTLR_EL1 values (verified -- module doc)
// ===========================================================================

/// attr0 = 0x00 (Device-nGnRnE), attr1 = 0xFF (Normal WB RA/WA inner+outer).
const MAIR_VALUE: u64 = 0x00 | (0xFF << 8);

/// 39-bit VA (T0SZ = 25), 4 KiB granule, WB RA/WA cacheable inner-shareable
/// walks, 40-bit IPS, TTBR1 walks disabled. T1SZ is parked at 25 as well so
/// the (disabled) TTBR1 half still carries an architecturally valid size.
/// Computes to 0x2_0099_3519.
const TCR_VALUE: u64 = 25 // T0SZ, bits[5:0]: 64 - 25 = 39-bit VA, 3 levels @ 4 KiB
    | (0b01 << 8) // IRGN0 = WB RA/WA cacheable walks
    | (0b01 << 10) // ORGN0 = WB RA/WA cacheable walks
    | (0b11 << 12) // SH0   = inner shareable
    | (0b00 << 14) // TG0   = 4 KiB granule
    | (25 << 16) // T1SZ  (walks disabled by EPD1; keep the size field valid)
    | (1 << 23) // EPD1  = disable TTBR1_EL1 walks
    | (0b010 << 32); // IPS = 40-bit PA (ID_AA64MMFR0.PARange encoding 0b010)

/// SCTLR_EL1.M, bit 0: stage-1 MMU enable for EL1&0.
const SCTLR_M: u64 = 1 << 0;
/// SCTLR_EL1.C, bit 2: data / unified cache enable.
const SCTLR_C: u64 = 1 << 2;
/// SCTLR_EL1.I, bit 12: instruction cache enable.
const SCTLR_I: u64 = 1 << 12;

// ===========================================================================
// Static frames + tables (.bss -- zeroed by `_start`, boot.rs step (2), so
// every table starts all-invalid and both frames start all-zero)
// ===========================================================================

/// Interior-mutable, 4096-aligned page-table cell. `repr(transparent)` over
/// `UnsafeCell<PageTable512>` inherits the shared typed layer's
/// `#[repr(C, align(4096))]`, satisfying the walker's alignment rules
/// (TTBR0 BADDR and table pointers must be table-size aligned).
#[repr(transparent)]
struct TableCell(UnsafeCell<PageTable512>);

// SAFETY: single-vCPU target, cooperative kernel: there is no concurrent
// mutator. All interior access goes through this module's volatile helpers on
// raw pointers; no Rust reference to the interior is ever created or handed
// out, so the `Sync` impl cannot be used to alias `&mut`.
unsafe impl Sync for TableCell {}

impl TableCell {
    /// A new all-invalid (zeroed) table; `const`, so it can sit in `.bss`.
    const fn new() -> Self {
        TableCell(UnsafeCell::new(PageTable512([0; 512])))
    }

    /// Physical address of this table. Identity space: PA == VA both before
    /// the MMU is on (translation off) and after (RAM gigabyte is
    /// identity-mapped), so the pointer value IS the physical address.
    fn pa(&self) -> u64 {
        self.0.get() as u64
    }
}

/// A bare 4096-aligned, page-sized data frame for the self-test targets.
#[repr(C, align(4096))]
struct Frame4K(UnsafeCell<[u64; 512]>);

// SAFETY: as `TableCell` -- single vCPU, volatile raw-pointer access only,
// no interior references ever minted.
unsafe impl Sync for Frame4K {}

impl Frame4K {
    /// A new zeroed frame; `const`, so it can sit in `.bss`.
    const fn new() -> Self {
        Frame4K(UnsafeCell::new([0; 512]))
    }

    /// Physical address of this frame (identity space -- see `TableCell::pa`).
    fn pa(&self) -> u64 {
        self.0.get() as u64
    }
}

/// TTBR0_EL1 root: the L1 table (each entry covers 1 GiB under 39-bit VA).
static ID_L1: TableCell = TableCell::new();
/// Self-test L2 table hung under L1[2] (each entry covers 2 MiB).
static TEST_L2: TableCell = TableCell::new();
/// Self-test L3 table hung under TEST_L2[0] (each entry covers 4 KiB).
static TEST_L3: TableCell = TableCell::new();
/// Self-test frame A: first mapping target of TEST_VA.
static FRAME_A: Frame4K = Frame4K::new();
/// Self-test frame B: Break-Before-Make remap target of TEST_VA.
static FRAME_B: Frame4K = Frame4K::new();

/// Write one descriptor slot, volatile: the table walker reads these behind
/// the compiler's back, so ordinary stores could be reordered or elided.
fn table_set(table: &TableCell, idx: usize, desc: u64) {
    debug_assert!(idx < 512);
    // SAFETY: `table` is one of this module's static 4096-aligned tables;
    // `PageTable512` is `#[repr(C, align(4096))]` over `[u64; 512]` and
    // `TableCell` is `repr(transparent)`, so casting the cell pointer to
    // `*mut u64` and offsetting by `idx < 512` stays in bounds and aligned.
    // Single vCPU: no concurrent CPU-side access (the walker is hardware and
    // is sequenced by the explicit `dsb`s at the call sites).
    unsafe { write_volatile((table.0.get() as *mut u64).add(idx), desc) }
}

/// Volatile-write `value` into word 0 of `frame` THROUGH ITS IDENTITY ADDRESS
/// (the L1[1] Normal block) -- never through TEST_VA.
fn frame_write_ident(frame: &Frame4K, value: u64) {
    // SAFETY: word 0 of a static frame owned exclusively by this module,
    // accessed via its identity-mapped address: valid, aligned, single vCPU.
    unsafe { write_volatile(frame.0.get() as *mut u64, value) }
}

/// Volatile-read word 0 of `frame` through its identity address.
fn frame_read_ident(frame: &Frame4K) -> u64 {
    // SAFETY: as `frame_write_ident`; an aligned, side-effect-free load.
    unsafe { read_volatile(frame.0.get() as *const u64) }
}

// ===========================================================================
// Privileged system-register / barrier / TLBI wrappers (A6)
// ===========================================================================

// -- write_mair_el1() --------------------------------------------------------
// (a) PRE : EL1, any MMU state (called here with the MMU OFF). POST:
//           MAIR_EL1 = v; guaranteed visible to translation only after a
//           later `isb` (the caller's step (4)).
// (b) ABI : one `msr` from one input register; no memory, no stack, NZCV
//           preserved.
// (c) TEST: scripts/run-aarch64.sh -- serial alive after enable (attr0 right),
//           "M3: mmu OK" (attr1 right).
fn write_mair_el1(v: u64) {
    // SAFETY: writing MAIR_EL1 is legal at EL1 and only stages new
    // memory-attribute encodings; nothing observes them until the caller's
    // context-synchronizing `isb`.
    unsafe {
        core::arch::asm!(
            "msr mair_el1, {v}",
            v = in(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// -- write_tcr_el1() ---------------------------------------------------------
// (a) PRE : EL1, MMU OFF (changing TCR under a live MMU needs much more
//           ceremony than M3 performs). POST: TCR_EL1 = v; visible after the
//           caller's `isb`.
// (b) ABI : one `msr` from one input register; no memory, no stack, NZCV
//           preserved.
// (c) TEST: scripts/run-aarch64.sh -- any T0SZ/TG0/IPS mistake faults the
//           first translated fetch; the marker would never print.
fn write_tcr_el1(v: u64) {
    // SAFETY: writing TCR_EL1 is legal at EL1; with the MMU still off it
    // changes nothing until SCTLR_EL1.M is set after the caller's `isb`.
    unsafe {
        core::arch::asm!(
            "msr tcr_el1, {v}",
            v = in(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// -- write_ttbr0_el1() -------------------------------------------------------
// (a) PRE : EL1, MMU OFF; `v` = physical address of a 4096-aligned L1 table
//           whose entries are already published (`dsb ishst`). POST:
//           TTBR0_EL1 = v; the walker uses it after the caller's `isb` once
//           SCTLR_EL1.M is set.
// (b) ABI : one `msr` from one input register; no memory, no stack, NZCV
//           preserved.
// (c) TEST: scripts/run-aarch64.sh -- a wrong root would fault the first
//           translated access; marker absent.
fn write_ttbr0_el1(v: u64) {
    // SAFETY: writing TTBR0_EL1 is legal at EL1; `v` is the PA of our static,
    // correctly aligned `ID_L1` (BADDR alignment: 512 entries * 8 = 4096).
    unsafe {
        core::arch::asm!(
            "msr ttbr0_el1, {v}",
            v = in(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// -- sctlr_el1_set_bits() ----------------------------------------------------
// (a) PRE : tables + MAIR/TCR/TTBR0 programmed and `isb`-synchronized; MMU
//           OFF. POST: SCTLR_EL1 |= bits via read-modify-write (every other
//           bit preserved), pipeline flushed by the trailing `isb` -- with
//           bits = M|C|I the very next instruction executes under the new
//           identity translation with caches on.
// (b) ABI : mrs/orr/msr/isb; one scratch + one input register; no stack; NZCV
//           preserved (mrs/orr-register/msr set no flags). NOT `nomem`: this
//           is a whole-memory-context switch, so the compiler must not cache
//           memory state across it. (orr with #0x1005 is not a valid logical
//           immediate, hence the register-operand form.)
// (c) TEST: scripts/run-aarch64.sh -- "mmu-test: enabled, serial alive" prints
//           right after this returns.
fn sctlr_el1_set_bits(bits: u64) {
    // SAFETY: RMW of SCTLR_EL1 at EL1 with an immediate `isb`. The caller
    // (mmu_init) guarantees the identity tables cover the executing code,
    // stack, and UART before M|C|I flip on, so execution continues seamlessly
    // at the same (now-translated) addresses.
    unsafe {
        core::arch::asm!(
            "mrs {t}, sctlr_el1",
            "orr {t}, {t}, {b}",
            "msr sctlr_el1, {t}",
            "isb",
            t = out(reg) _,
            b = in(reg) bits,
            options(nostack, preserves_flags),
        );
    }
}

// -- dsb_ishst() -------------------------------------------------------------
// (a) PRE : any. POST: all PRIOR STORES are observable by every agent in the
//           inner shareable domain -- including the table walker -- before any
//           later memory op / TLBI executes.
// (b) ABI : one barrier instruction; no registers, no stack, NZCV preserved.
//           NOT `nomem`: it orders memory, so it must also be a compiler
//           barrier.
// (c) TEST: publishing descriptors before TTBR0 / before the L1 plug / before
//           TLBI in the BBM dance below; scripts/run-aarch64.sh marker.
fn dsb_ishst() {
    // SAFETY: barriers are side-effect-free synchronization, always legal.
    unsafe { core::arch::asm!("dsb ishst", options(nostack, preserves_flags)) }
}

// -- dsb_ish() -----------------------------------------------------------------
// (a) PRE : a TLBI (or stores) issued. POST: that TLBI and all prior memory
//           accesses in the inner shareable domain are COMPLETE -- the stale
//           translation is gone everywhere before anything later runs.
// (b) ABI : one barrier instruction; no registers, no stack, NZCV preserved.
//           NOT `nomem` (compiler barrier too).
// (c) TEST: the BBM remap below; scripts/run-aarch64.sh marker.
fn dsb_ish() {
    // SAFETY: as `dsb_ishst`.
    unsafe { core::arch::asm!("dsb ish", options(nostack, preserves_flags)) }
}

// -- isb() ---------------------------------------------------------------------
// (a) PRE : system-register writes / TLB maintenance pending architectural
//           visibility. POST: pipeline flushed; every later instruction
//           fetches and translates under the new context.
// (b) ABI : one barrier instruction; no registers, no stack, NZCV preserved.
//           NOT `nomem` (keeps ordering w.r.t. the surrounding sequence).
// (c) TEST: required after msr mair/tcr/ttbr0 and inside the BBM sequence;
//           scripts/run-aarch64.sh marker.
fn isb() {
    // SAFETY: as `dsb_ishst`.
    unsafe { core::arch::asm!("isb", options(nostack, preserves_flags)) }
}

// -- tlbi_vaae1is() ------------------------------------------------------------
// (a) PRE : the leaf for `va` was just invalidated and the store published
//           (`dsb ishst`). POST: once a following `dsb ish` completes, no TLB
//           or walk-cache entry for VA -- any ASID, EL1&0, inner shareable
//           domain -- survives.
// (b) ABI : `tlbi vaae1is, Xt` with Xt = VA >> 12 (operand bits [43:0] carry
//           VA[55:12]; ASID bits [63:48] zero -- VAAE1IS matches All ASIDs by
//           definition). Single vCPU: the -is (inner shareable) variant is
//           fine per spec; the local variant would be acceptable too.
// (c) TEST: after the BBM break, the read through TEST_VA observes frame B,
//           not a stale frame-A translation; scripts/run-aarch64.sh marker.
fn tlbi_vaae1is(va: u64) {
    let operand = va >> 12;
    // SAFETY: TLBI VAAE1IS is legal at EL1 and only discards cached
    // translations -- never memory contents. Operand format verified against
    // Linux `__TLBI_VADDR` (module doc).
    unsafe {
        core::arch::asm!(
            "tlbi vaae1is, {op}",
            op = in(reg) operand,
            options(nostack, preserves_flags),
        );
    }
}

// ===========================================================================
// M3 public surface (re-exported through arch/aarch64/mod.rs -> arch -> lib)
// ===========================================================================

// -- mmu_init() ----------------------------------------------------------------
// (a) PRE : EL1h, MMU OFF (cold, as `boot.rs` left it), `.bss` zeroed (so
//           ID_L1 starts all-invalid), install_traps() already called (a
//           bring-up mistake should vector into the M1 handler, not wedge
//           silently). POST: SCTLR_EL1.{M,C,I} = 1; identity translation live
//           (gigabyte 0 Device-nGnRnE, gigabyte 1 Normal WB); TTBR1 walks
//           disabled; L1[2] still invalid, reserved for mmu_selftest.
// (b) ABI : plain safe function; all asm confined to the leaf wrappers above.
// (c) TEST: kernel prints "mmu-test: enabled, serial alive" after this
//           returns -- the UART write through the Device block is the proof;
//           scripts/run-aarch64.sh.
/// Cold MMU bring-up: identity-map [0, 2 GiB) with two 1 GiB L1 blocks
/// (Device @ 0, Normal @ 0x4000_0000), program MAIR/TCR/TTBR0, `isb`, then
/// set SCTLR_EL1.M|C|I (read-modify-write) and `isb` again.
///
/// Call exactly once from `rust_main`, after `install_traps`. (A second call
/// would merely rewrite identical state, but it is not a supported pattern.)
pub fn mmu_init() {
    // (1) Build the identity L1 while the MMU is OFF (stores go straight to
    //     memory; cacheability cannot hide them from the walker yet).
    table_set(&ID_L1, 0, GIB0_DEVICE_PA | BLOCK_DEVICE);
    table_set(&ID_L1, 1, GIB1_RAM_PA | BLOCK_NORMAL);
    // (2) Publish the descriptors before the walker can be pointed at them.
    dsb_ishst();
    // (3) Program the translation regime: attributes, geometry, root.
    write_mair_el1(MAIR_VALUE);
    write_tcr_el1(TCR_VALUE);
    write_ttbr0_el1(ID_L1.pa());
    // (4) Context-synchronize the system-register writes...
    isb();
    // (4b) Cold-entry hygiene (Linux head.S parity): TLB + I-cache contents
    //      are architecturally UNKNOWN out of reset; invalidate before the
    //      first translated/cached fetch. QEMU TCG never holds stale state
    //      here, but real cores can — three instructions buy correctness.
    //      (a) PRE: MMU off, regime programmed. POST: EL1 TLB + I-cache clean.
    //      (b) ABI: no operands; nostack/preserves_flags.
    //      (c) Tested by: scripts/run-aarch64.sh (whole bring-up path).
    unsafe {
        core::arch::asm!(
            "tlbi vmalle1",
            "dsb nsh",
            "ic iallu",
            "dsb nsh",
            "isb",
            options(nostack, preserves_flags)
        );
    }
    // (5) ...then flip on MMU + D-cache + I-cache, preserving every other
    //     SCTLR_EL1 bit; the wrapper's trailing `isb` makes the next
    //     instruction run translated. Serial keeps working iff L1[0] is right.
    sctlr_el1_set_bits(SCTLR_M | SCTLR_C | SCTLR_I);
}

// -- mmu_selftest() --------------------------------------------------------------
// (a) PRE : mmu_init() returned (identity live, L1[2] invalid). Call ONCE:
//           the test leaves TEST_VA mapped to frame B and tears nothing down.
//           POST: true iff BOTH probes hit the right frame: (map TEST_VA ->
//           frame A, write via TEST_VA, verify via frame A's identity alias)
//           and (BBM remap to frame B, read via TEST_VA, verify frame B's
//           pre-seeded magic with frame A's value intact).
// (b) ABI : plain safe function; asm confined to the leaf wrappers.
// (c) TEST: kernel prints "M3: mmu OK" iff this returns true;
//           scripts/run-aarch64.sh greps exactly that marker, fail-closed.
/// M3 self-test: 4 KiB map at [`TEST_VA`] (1 GiB-hole VA 0x8000_0000), write
/// through the new mapping, verify through the identity alias, then remap to
/// a second frame with a full Break-Before-Make + `tlbi vaae1is` and verify
/// the VA now reads the second frame. `true` = pass.
pub fn mmu_selftest() -> bool {
    const MAGIC_A: u64 = 0xA11A_A11A_DEAD_BEEF;
    const MAGIC_B: u64 = 0xB22B_B22B_CAFE_F00D;

    // (0) Seed both frames through their IDENTITY addresses: frame B carries
    //     its magic BEFORE the test VA ever points at it; frame A starts 0.
    frame_write_ident(&FRAME_A, 0);
    frame_write_ident(&FRAME_B, MAGIC_B);

    // (1) First mapping: TEST_VA -> frame A. Build the chain bottom-up and
    //     plug it into the LIVE root last; the `dsb ishst` between the
    //     interior fill and the L1 plug keeps the walker from ever seeing a
    //     half-built chain. No TLBI needed for a first map: entries that
    //     fault (L1[2] was invalid) are architecturally never cached in a TLB.
    table_set(&TEST_L3, 0, FRAME_A.pa() | PAGE_NORMAL);
    table_set(&TEST_L2, 0, TEST_L3.pa() | DESC_TABLE);
    dsb_ishst();
    table_set(&ID_L1, 2, TEST_L2.pa() | DESC_TABLE);
    dsb_ishst();
    isb();

    // (2) Write the magic THROUGH the brand-new virtual mapping...
    // SAFETY: TEST_VA was just mapped read/write Normal onto FRAME_A, a
    // static frame this module owns exclusively; the access is an aligned
    // u64. Both aliases (TEST_VA and the identity address) carry identical
    // Normal WB inner-shareable attributes, so they are coherent views of
    // the same physical location.
    unsafe { write_volatile(TEST_VA as *mut u64, MAGIC_A) };
    // ...and verify it landed in frame A via the identity alias.
    if frame_read_ident(&FRAME_A) != MAGIC_A {
        return false;
    }

    // (3) Remap TEST_VA -> frame B: full Break-Before-Make (Arm ARM D8.16).
    //     BREAK: invalidate the leaf, publish, kill the cached translation,
    //     wait for the kill to complete, resync the pipeline...
    table_set(&TEST_L3, 0, 0);
    dsb_ishst();
    tlbi_vaae1is(TEST_VA);
    dsb_ish();
    isb();
    //     ...MAKE: install the new leaf and publish it.
    table_set(&TEST_L3, 0, FRAME_B.pa() | PAGE_NORMAL);
    dsb_ishst();
    isb();

    // (4) The same VA must now read frame B's pre-seeded magic...
    // SAFETY: TEST_VA is mapped onto FRAME_B (the BBM above completed); same
    // argument as step (2).
    let through_va = unsafe { read_volatile(TEST_VA as *const u64) };
    if through_va != MAGIC_B {
        return false;
    }
    // ...while frame A still holds its own value -- proving the remap moved
    // the translation rather than aliasing a single frame.
    frame_read_ident(&FRAME_A) == MAGIC_A
}

// ===========================================================================
// M7: frame-backed growable kernel-heap window (this milestone).
//
// `map_heap_frames` grows the heap by pulling 4 KiB frames from M6 and splicing
// them into the LIVE TTBR0_EL1 hierarchy through the M3 typed layer — the same
// publish-then-`dsb`/`isb` dance `mmu_selftest` / `user::user_demo` perform for
// their first map, but kernel-only, RW + NX, mapping MANY frames and REUSING
// intermediate L2/L3 tables across grows. All the unsafe + barriers live here;
// `heap.rs` (no asm) only calls this safe-ish primitive.
// ===========================================================================

/// Base VA of the kernel-heap window: `4 * 2^30` = `L1[4]` — a vacant root slot
/// (identity uses L1[0..1], M3 `mmu_selftest` uses L1[2], M4 `user` uses L1[3]),
/// OUTSIDE the identity map `[0, 2 GiB)`. Within the 39-bit (T0SZ=25) VA space.
const HEAP_WINDOW_BASE: u64 = 0x1_0000_0000;

/// Window VA span cap: 1 GiB — a single `L2[0..512]` subtree under `L1[4]`
/// (512 L3 tables, 2 MiB each), far more than any milestone heap needs.
const HEAP_WINDOW_SIZE: u64 = 0x4000_0000;

/// The per-arch kernel-heap window VA range `(base, size)` for `heap.rs`.
pub fn heap_window() -> (u64, u64) {
    (HEAP_WINDOW_BASE, HEAP_WINDOW_SIZE)
}

/// Read the live `TTBR0_EL1` (the L1 translation-table base + CnP/ASID bits).
fn read_ttbr0_el1() -> u64 {
    let v: u64;
    // SAFETY: TTBR0_EL1 is an EL1-readable system register; a side-effect-free
    // load with no memory or stack effect, NZCV preserved. We run at EL1.
    unsafe {
        core::arch::asm!("mrs {0}, ttbr0_el1", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// Zero all 512 entries of a freshly-allocated table frame, through its identity
/// address (M6 frames sit in the identity-mapped RAM gigabyte, so PA == VA). A
/// new table MUST start all-invalid; M6 only wrote a stale link word into it.
///
/// # Safety
/// `table` is a 4 KiB-aligned, identity-mapped frame this code exclusively owns
/// (just popped from M6 and not yet linked into any live hierarchy).
unsafe fn zero_table(table: *mut u64) {
    let mut i = 0;
    while i < ENTRIES {
        write_volatile(table.add(i), 0);
        i += 1;
    }
}

/// Return the child table referenced by `parent[idx]`, creating it from a fresh,
/// zeroed M6 frame (spliced as a TABLE descriptor, then REUSED by later grows)
/// when the slot is invalid. `None` only on physical-frame OOM.
///
/// # Safety
/// `parent` is a live, identity-mapped 512-entry table; `idx < 512`. Writes are
/// volatile; the caller publishes them with `dsb ishst` before the walker runs.
unsafe fn ensure_table(parent: *mut u64, idx: usize) -> Option<*mut u64> {
    let slot = parent.add(idx);
    let entry = read_volatile(slot);
    if entry_is_valid(entry) {
        return Some(entry_addr(entry) as *mut u64);
    }
    let frame = crate::frame_alloc()?;
    zero_table(frame as *mut u64);
    write_volatile(slot, make_entry(frame, DESC_TABLE));
    Some(frame as *mut u64)
}

/// Map ONE page `va` -> a fresh M6 frame under the live `l1`, building any
/// missing `L1[4] -> L2 -> L3` table along the way. `false` on physical-frame
/// OOM. On OOM mid-walk an interior table already spliced in by `ensure_table`
/// is RETAINED (reused by a later grow via the `entry_is_valid` fast path) and
/// the data frame is never pulled — the page is left fully unmapped, never half.
///
/// # Safety
/// EL1, MMU live; `l1` is the live root just read from TTBR0_EL1; `va` is a
/// canonical, currently-INVALID window VA in `L1[4]`; every M6 frame is
/// identity-mapped RAM, so each table pointer dereferences directly.
unsafe fn map_one_heap_page(l1: *mut u64, va: u64) -> bool {
    let l2 = match ensure_table(l1, level_index(va, SHIFT_1G)) {
        Some(t) => t,
        None => return false,
    };
    let l3 = match ensure_table(l2, level_index(va, SHIFT_2M)) {
        Some(t) => t,
        None => return false,
    };
    let data = match crate::frame_alloc() {
        Some(p) => p,
        None => return false,
    };
    // Leaf: Normal-WB, EL1 RW, no-execute (PXN|UXN), kernel-only. A data page.
    write_volatile(
        l3.add(level_index(va, SHIFT_4K)),
        make_entry(data, PAGE_KERNEL_RW_NX),
    );
    true
}

/// Map `n` contiguous pages from `start_va` to `n` freshly-allocated M6 frames
/// (intermediate L2/L3 tables ALSO from M6), each leaf Normal-WB RW + no-exec,
/// kernel-only, and report how many pages were actually mapped (`< n` ONLY on
/// physical-frame OOM, with no half-mapped page). One `dsb ishst; isb`
/// publishes the whole batch to the table walker.
///
/// The live L1 base is read from TTBR0_EL1 ONCE here and threaded into every
/// per-page walk (the root never changes mid-grow), so a multi-page grow issues
/// a single system-register read rather than one per page.
///
/// First-map only — each window VA goes INVALID -> valid exactly once, so NO
/// TLBI is needed: entries that fault are never cached (Arm ARM D8.14; the same
/// rule `mmu_selftest`'s first map relies on).
pub fn map_heap_frames(start_va: u64, n: usize) -> usize {
    let l1 = (read_ttbr0_el1() & TTBR_BADDR_MASK) as *mut u64;
    let mut mapped = 0usize;
    while mapped < n {
        let va = start_va + (mapped as u64) * (PAGE_SIZE as u64);
        // SAFETY: EL1, single vCPU, interrupts masked; `va` is a canonical,
        // not-yet-mapped window VA; `l1` is the live root (TTBR0_EL1) and all
        // M6 frames are identity-mapped RAM, so every table pointer derefs.
        if !unsafe { map_one_heap_page(l1, va) } {
            break; // physical-frame OOM
        }
        mapped += 1;
    }
    if mapped > 0 {
        // Publish every descriptor write to the table walker, then resync the
        // pipeline so the heap's first access through these VAs translates.
        dsb_ishst();
        isb();
    }
    mapped
}

// ===========================================================================
// M10: per-entity address spaces (memory isolation).
//
// Symmetric with the x86_64 backend (NO TTBR1/TTBR0 split): `address_space_new`
// frame-allocs a fresh L1 table and COPIES all 512 entries of the live
// TTBR0_EL1 L1 into it, so the kernel half (Device/RAM identity blocks + the
// M3/M4/M7 subtrees) is shared BY REFERENCE. `map_in_root` splices a private L3
// leaf into an EXPLICIT (not-live) root through the same `ensure_table` walk the
// heap mapper uses; the test VA lives in a vacant root slot (`L1[6]`).
// `switch_root` installs TTBR0_EL1 then `isb; tlbi vmalle1is; dsb ish; isb` --
// with no ASID a global EL1&0 flush is required so a prior space's translation
// of the same VA is not reused. All the unsafe + barriers live here.
// ===========================================================================

/// M10: create a fresh address space. Frame-allocate a new L1 table (one M6
/// frame) and COPY all 512 entries of the LIVE L1 (from TTBR0_EL1) into it, so
/// the whole kernel half is shared by reference. Returns the new L1 PA, or
/// `None` on physical-frame OOM.
pub fn address_space_new() -> Option<u64> {
    let root = crate::frame_alloc()?;
    // SAFETY: `root` is a 4 KiB-aligned M6 frame in the identity-mapped RAM
    // gigabyte (PA == VA), exclusively owned here; TTBR0_EL1 holds the live L1
    // base (also identity-mapped). Copy all 512 entries of the live L1 into the
    // new table -- the kernel half is then shared by reference. Volatile writes.
    unsafe {
        let src = (read_ttbr0_el1() & TTBR_BADDR_MASK) as *const u64;
        let dst = root as *mut u64;
        let mut i = 0;
        while i < ENTRIES {
            write_volatile(dst.add(i), read_volatile(src.add(i)));
            i += 1;
        }
    }
    // Publish the copied table to the walker before it can be installed.
    dsb_ishst();
    Some(root)
}

/// M10: map one private 4 KiB page `va` -> `pa` into the EXPLICIT root at
/// `root_pa` (NOT the live TTBR0_EL1), building any missing L2/L3 from M6
/// frames. `va` must sit in a vacant root slot (`L1[6]`), so the new entry lands
/// only in THIS root. Leaf = Normal-WB, EL1 RW (read-only if `!writable`),
/// no-execute. `false` on physical-frame OOM.
pub fn map_in_root(root_pa: u64, va: u64, pa: u64, writable: bool) -> bool {
    // SAFETY: `root_pa` is a 4 KiB-aligned L1 frame from `address_space_new` in
    // the identity-mapped RAM gigabyte (PA == VA); every intermediate table
    // `ensure_table` pulls is likewise an identity-mapped M6 frame. The root is
    // NOT live, so no live translation is disturbed.
    let ok = unsafe { map_one_in_root(root_pa, va, pa, writable) };
    if ok {
        // Publish the new descriptors to the table walker.
        dsb_ishst();
        isb();
    }
    ok
}

/// Splice a single private leaf into the explicit root `root_pa`. Returns
/// `false` on physical-frame OOM (intermediate tables retained, never a
/// half-mapped page).
///
/// # Safety
/// `root_pa` is a 4 KiB-aligned L1 frame in identity-mapped RAM owned by the
/// caller (not the live root); `va`/`pa` are 4 KiB-aligned. Writes are volatile;
/// the caller publishes them with `dsb ishst; isb`.
unsafe fn map_one_in_root(root_pa: u64, va: u64, pa: u64, writable: bool) -> bool {
    let l1 = root_pa as *mut u64;
    let l2 = match ensure_table(l1, level_index(va, SHIFT_1G)) {
        Some(t) => t,
        None => return false,
    };
    let l3 = match ensure_table(l2, level_index(va, SHIFT_2M)) {
        Some(t) => t,
        None => return false,
    };
    let mut leaf = PAGE_KERNEL_RW_NX;
    if !writable {
        leaf |= 1 << 7; // AP[2] = 1 -> EL1 read-only
    }
    write_volatile(l3.add(level_index(va, SHIFT_4K)), make_entry(pa, leaf));
    true
}

/// M12: map one private 4 KiB USER page `va` -> `pa` into the EXPLICIT root at
/// `root_pa` (NOT the live TTBR0_EL1), reachable from EL0. Leaf = Normal-WB,
/// `AP[1]` set (EL0+EL1 access), `PXN` set (EL1 never executes the agent's
/// code), plus `AP[2]` (read-only) when `!writable` and `UXN` when `!exec`.
/// Intermediate L2/L3 are plain table descriptors (no APTable restriction), so
/// the leaf governs EL0 access. `va` must sit in a vacant root slot (`L1[6]`).
/// `false` on physical-frame OOM.
///
/// M14.1: `pub` (was `pub(super)`) so the kernel facade `agent_map_user_buffer`
/// can map a writable EL0 scratch page whose L3 leaf carries `AP[1]` (EL0
/// access) + `AF` -- exactly what `copy_to_user`/`copy_from_user`'s walk requires.
pub fn map_user_in_root(
    root_pa: u64,
    va: u64,
    pa: u64,
    writable: bool,
    exec: bool,
) -> bool {
    // SAFETY: `root_pa` is a 4 KiB-aligned L1 frame from `address_space_new` in
    // identity-mapped RAM (PA == VA); the root is not live, so no live
    // translation is disturbed. Mirrors `map_in_root`'s ensure_table walk.
    let ok = unsafe { map_one_user_in_root(root_pa, va, pa, writable, exec) };
    if ok {
        dsb_ishst();
        isb();
    }
    ok
}

/// Splice a single private EL0-accessible leaf into the explicit root `root_pa`.
/// `false` on physical-frame OOM (intermediate tables retained, never a
/// half-mapped page).
///
/// # Safety
/// As [`map_one_in_root`]: `root_pa` is a 4 KiB-aligned, owned, not-live L1
/// frame; `va`/`pa` are 4 KiB-aligned. Writes are volatile; the caller publishes
/// them with `dsb ishst; isb`.
unsafe fn map_one_user_in_root(
    root_pa: u64,
    va: u64,
    pa: u64,
    writable: bool,
    exec: bool,
) -> bool {
    let l1 = root_pa as *mut u64;
    let l2 = match ensure_table(l1, level_index(va, SHIFT_1G)) {
        Some(t) => t,
        None => return false,
    };
    let l3 = match ensure_table(l2, level_index(va, SHIFT_2M)) {
        Some(t) => t,
        None => return false,
    };
    let mut leaf = DESC_PAGE | DESC_AF | DESC_SH_INNER | DESC_ATTRIDX_NORMAL | AP_EL0_RW | DESC_PXN;
    if !exec {
        leaf |= DESC_UXN; // EL0 no-execute (data page)
    }
    if !writable {
        leaf |= AP_RDONLY; // AP[2] = 1 -> read-only
    }
    write_volatile(l3.add(level_index(va, SHIFT_4K)), make_entry(pa, leaf));
    true
}

/// M10: make the address space whose L1 PA is `root_pa` live: install it in
/// TTBR0_EL1, then `isb; tlbi vmalle1is; dsb ish; isb`. With no ASID a global
/// EL1&0 TLB flush is required so a previous space's translation of the same VA
/// is dropped; every entity root shares an identical kernel half, so this code,
/// the stack and serial stay valid across the switch.
pub fn switch_root(root_pa: u64) {
    // SAFETY: `root_pa` is a 4 KiB-aligned L1 table from `address_space_new` (a
    // copy of the live kernel root + optional private leaves), valid as a
    // TTBR0_EL1 BADDR. The `isb` after the `msr` makes the new root active, the
    // `tlbi vmalle1is` drops every stale stage-1 EL1&0 entry (inner shareable),
    // and the trailing `dsb ish; isb` complete + synchronize it.
    unsafe {
        core::arch::asm!(
            "msr ttbr0_el1, {root}",
            "isb",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            root = in(reg) (root_pa & TTBR_BADDR_MASK),
            options(nostack, preserves_flags),
        );
    }
}

/// M10: the PA of the LIVE top-level page table (TTBR0_EL1's L1 base, ASID/CnP
/// bits masked off). Used to capture the default boot root at first space
/// creation.
pub fn current_root() -> u64 {
    read_ttbr0_el1() & TTBR_BADDR_MASK
}

/// M10: re-assert M3. `true` iff the M3 self-test VA (`TEST_VA` = 0x8000_0000)
/// still reads its post-remap magic under the LIVE root. The M3 mapping hangs
/// off `L1[2]`, copied by reference into every space, so this reads true under
/// the boot root AND any entity root -- proving the M3 kernel-half mapping
/// survives every address-space switch.
pub fn m3_test_va_intact() -> bool {
    // The M3 self-test left TEST_VA mapped to FRAME_B carrying this magic
    // (mirrors the MAGIC_B local in `mmu_selftest`).
    const M3_MAGIC_B: u64 = 0xB22B_B22B_CAFE_F00D;
    // SAFETY: TEST_VA is mapped Normal-WB in the shared kernel half present in
    // every root; an aligned volatile u64 load.
    unsafe { read_volatile(TEST_VA as *const u64) == M3_MAGIC_B }
}

// ===========================================================================
// M15.1: UNMAP + frame reclamation.
//
// `unmap_in_root` is the inverse of `map_in_root`: it walks the EXPLICIT root,
// clears the single L3 leaf for `va` via Break-Before-Make (Arm ARM D8.16 --
// write the invalid descriptor, `dsb ishst`, `tlbi vaae1is`, `dsb ish`, `isb`),
// and returns the DATA frame the safe kernel facade returns to the M6 allocator.
// It does NOT free intermediate L2/L3 tables -- they belong to the address space
// and may host sibling pages. `tlbi vaae1is` is an inner-shareable flush for `va`
// across ALL ASIDs, so it drops any stale translation regardless of which root
// is live (single core: a shootdown is a local invalidate, no IPI). `va_to_pa_in_root`
// is the read-only twin: a pure software walk the `#![forbid(unsafe_code)]` kernel
// uses to PROBE that an unmapped VA no longer resolves WITHOUT dereferencing it.
// ===========================================================================

/// Read interior descriptor `parent[idx]`; return the child table pointer when
/// it is valid, else `None`. The read-only, no-allocation twin of [`ensure_table`].
///
/// # Safety
/// `parent` is a live/owned identity-mapped 512-entry table; `idx < 512`. The
/// read is volatile (the table walker reads it behind the compiler).
unsafe fn walk_next(parent: *mut u64, idx: usize) -> Option<*mut u64> {
    let entry = read_volatile(parent.add(idx));
    if entry_is_valid(entry) {
        Some(entry_addr(entry) as *mut u64)
    } else {
        None
    }
}

/// M15.1: tear down the single 4 KiB leaf for `va` in the EXPLICIT root at
/// `root_pa`, returning the physical frame it mapped -- or `None` if `va` was
/// not mapped (idempotent: a double-unmap of the same page is a clean no-op, so
/// the owner-unmap facade can never double-free). Full Break-Before-Make so no
/// stale TLB entry for `va` can outlive the leaf.
pub fn unmap_in_root(root_pa: u64, va: u64) -> Option<u64> {
    // SAFETY: `root_pa` is a 4 KiB-aligned L1 frame in identity-mapped RAM
    // (PA == VA) from `address_space_new`; every interior table `walk_next`
    // follows is likewise an identity-mapped M6 frame, so each pointer
    // dereferences directly. We only READ interior descriptors and clear ONE L3
    // leaf to 0; the BBM ceremony below (`dsb ishst; tlbi vaae1is; dsb ish; isb`)
    // publishes the invalidation and drops every TLB/walk-cache entry for `va`
    // (all ASIDs, inner shareable) before the frame can be reused.
    let pa = unsafe {
        let l1 = root_pa as *mut u64;
        let l2 = walk_next(l1, level_index(va, SHIFT_1G))?;
        let l3 = walk_next(l2, level_index(va, SHIFT_2M))?;
        let slot = l3.add(level_index(va, SHIFT_4K));
        let entry = read_volatile(slot);
        if !entry_is_valid(entry) {
            return None;
        }
        let pa = entry_addr(entry);
        write_volatile(slot, 0);
        pa
    };
    // Break-Before-Make completion (Arm ARM D8.16): publish the invalid
    // descriptor, flush the VA from every TLB (all ASIDs, inner shareable),
    // then synchronize so the next access re-walks the now-empty leaf.
    dsb_ishst();
    tlbi_vaae1is(va);
    dsb_ish();
    isb();
    Some(pa)
}

/// M15.1: the physical frame `va` maps to in the EXPLICIT root at `root_pa`, or
/// `None` if any level of the walk is invalid. READ-ONLY (writes nothing, never
/// dereferences `va`), so the kernel can confirm an unmapped VA no longer
/// resolves without taking a translation fault.
pub fn va_to_pa_in_root(root_pa: u64, va: u64) -> Option<u64> {
    // SAFETY: as `unmap_in_root`, but it only READS interior + leaf descriptors;
    // no store, and `va` itself is never dereferenced.
    unsafe {
        let l1 = root_pa as *mut u64;
        let l2 = walk_next(l1, level_index(va, SHIFT_1G))?;
        let l3 = walk_next(l2, level_index(va, SHIFT_2M))?;
        let entry = read_volatile(l3.add(level_index(va, SHIFT_4K)));
        if !entry_is_valid(entry) {
            return None;
        }
        Some(entry_addr(entry))
    }
}
