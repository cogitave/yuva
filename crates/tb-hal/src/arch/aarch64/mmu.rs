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

use crate::mmu::PageTable512;

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
