//! aarch64 **L2.1 "stage2 OK"**: the stage-2 (second-stage translation)
//! demand-translation primitive -- the ARM analog of x86 EPT-violation handling.
//! The silicon-unsafe builder + arming + abort glue behind the SAFE
//! [`super::el2::stage2_selftest`] facade; ALL `msr VTTBR_EL2/VTCR_EL2/HCR_EL2`,
//! `write_volatile` descriptor splices, and stage-2 TLBI live here, so the
//! kernel crate stays `#![forbid(unsafe_code)]` and only branches on a
//! `Stage2Proof` enum.
//!
//! ## What this builds (all at EL1, the self-test window only)
//!
//! A stage-2 translation regime that identity-maps everything the guest needs to
//! RUN -- the full **device gigabyte (GiB0)** + **RAM gigabyte (GiB1)** as 2 MiB
//! stage-2 blocks, so the stub code, stack, AND the kernel's live stage-1 table
//! frames (every IPA the kernel's stage-1 can produce sits in GiB0/GiB1) are
//! reachable -- but leaves ONE high IPA gigabyte ([`HOLE_IPA`] = `0x1_4000_0000`,
//! stage-2 `L1[5]`) as a deliberate HOLE. The L2.1 guest stub touches an IPA
//! inside that hole, faults to EL2 as a stage-2 translation fault
//! (`ESR_EL2.EC=0x24` Data Abort, `DFSC` = translation fault), the resident
//! monitor reads the faulting IPA from `HPFAR_EL2`, splices a stage-2 leaf, and
//! `eret`s WITHOUT advancing `ELR_EL2` so the guest re-executes the load -- the
//! citable ARM equivalent of the x86 `touch-unmapped-GPA -> reason-48 -> map ->
//! INVEPT -> resume` loop.
//!
//! ## Geometry (a byte-for-byte mirror of the kernel's stage-1 TCR_EL1)
//!
//! T0SZ=25 (39-bit IPA), single 4 KiB L1 root (NO concatenation -> a plain
//! `frame_alloc` page), SL0=1 (start level 1, per the 4K formula `SL0 = 2 -
//! (4 - 3) = 1`), TG0=0b00 (4 KiB), PS=0b010 (40-bit PA), SH0=0b11/ORGN0=0b01/
//! IRGN0=0b01 (inner WBWA), RES1 bit31 -- so the stage-2 walk uses the SAME
//! proven-runnable shape as the kernel's stage-1.
//!
//! ## The S1PTW correctness fact (the load-bearing one)
//!
//! When `HCR_EL2.VM=1`, EVERY EL1&0 access -- INCLUDING the hardware stage-1
//! page-table walk -- is subject to stage-2. A stage-2 that mapped only the stub
//! code page would fault the guest's OWN stage-1 walk (S1PTW, `ESR_EL2.ISS`
//! bit7) before it ever reached the deliberate hole. The full GiB0+GiB1 identity
//! stage-2 covers the live stage-1 table frames, so the only stage-2 fault is
//! the deliberate one. The handler treats `S1PTW=1` or an unexpected fault IPA
//! as `Faulted{code}` (the wrong thing faulted).
//!
//! ## The no-EL2-allocation rule (risk: frame_alloc reentrancy from EL2)
//!
//! The EL2 abort handler MUST NOT call the EL1 frame allocator (kernel state).
//! So the ENTIRE table path down to the hole leaf is PRE-BUILT at EL1
//! ([`build_identity_stage2`]): `L1[5] -> L2 -> L3` exist, only the final L3 leaf
//! is left INVALID (the genuine hole). [`demand_map_ipa`] at EL2 then walks the
//! already-resident tables and writes ONE leaf -- zero allocation. The demand
//! frame + stage-2 root are `frame_alloc`'d at EL1 and their PAs handed across
//! the `HVC #2` register frame.
//!
//! ## Cache-coherency note (EL2 `SCTLR_EL2.M=0`)
//!
//! The EL2 handler runs with the MMU off (Device/non-cacheable accesses, flat-
//! mapped), while EL1 maps the same RAM Normal-WB cacheable. The stage-2 tables
//! the EL1 builder writes are published with `dsb ishst; isb` (mirroring
//! `mmu.rs`); under QEMU TCG (no cache model) the EL2 walker + handler see them
//! immediately. On real silicon the builder would additionally have to clean the
//! table frames to PoC -- a RESIDUAL ASSUMPTION declared in `assumptions.md`, the
//! same one L2.0 carries for its shared state. The EL2 self-context cells
//! ([`S2_CTX`]) are a single-accessor region the EL1 kernel NEVER references and
//! are 64-byte aligned so no EL1-written variable shares their cache line.

use core::arch::asm;
use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};

use crate::mmu::{entry_addr, entry_is_valid, level_index, make_entry, SHIFT_1G, SHIFT_2M, SHIFT_4K};
use tb_encode::stage2::{
    s2_leaf_2mib, s2_leaf_4k, s2_table, vtcr, vttbr, S2_MEMATTR_DEVICE, S2_MEMATTR_NORMAL_WB,
};

// ===========================================================================
// Load-bearing geometry + layout constants.
// ===========================================================================

/// The deliberate stage-2 HOLE: a vacant high IPA gigabyte. `0x1_4000_0000` is
/// stage-2 `L1[5]` (IPA `5 * 1 GiB`) -- and is ALSO the kernel's stage-1 `L1[5]`,
/// which is free (stage-1 uses L1[0..1]=identity, L1[2]=M3, L1[3]=M4, L1[4]=heap,
/// L1[6]=M10). The self-test installs a stage-1 identity block here so the guest
/// VA `0x1_4000_0000` produces IPA `0x1_4000_0000`, which then faults stage-2.
pub(super) const HOLE_IPA: u64 = 0x1_4000_0000;

/// The stage-2 VMID (8-bit on ARMv8.0; lands in `VTTBR_EL2[55:48]`). One VMID is
/// enough for the single-guest smoke; the TLBI family flushes by this VMID.
const VMID: u64 = 1;

/// 1 GiB (one stage-2 L1 entry; one kernel stage-1 L1 entry under T0SZ=25).
const GIB: u64 = 0x4000_0000;
/// 2 MiB (one stage-2 L2 block).
const BLOCK_2M: u64 = 0x20_0000;
/// The device gigabyte base (GiB0): MMIO incl. the PL011 UART at `0x0900_0000`.
const GIB0_DEVICE_BASE: u64 = 0x0000_0000;
/// The RAM gigabyte base (GiB1): `0x4000_0000..0x8000_0000` (QEMU `virt`, 128M).
const GIB1_RAM_BASE: u64 = 0x4000_0000;

// -- stage-2 geometry (VTCR_EL2 fields -- mirror the kernel's stage-1 TCR_EL1) --
/// T0SZ = 25 -> 39-bit IPA, 3-level walk @ 4 KiB (a single L1 root).
const S2_T0SZ: u64 = 25;
/// SL0 = 1 -> start the walk at level 1 (`2 - (4 - 3)` for the 4 KiB granule).
const S2_SL0: u64 = 1;
/// TG0 = 0b00 -> 4 KiB stage-2 granule.
const S2_TG0: u64 = 0b00;
/// PS = 0b010 -> 40-bit output PA (ID_AA64MMFR0_EL1.PARange encoding).
const S2_PS: u64 = 0b010;
/// SH0 = 0b11 -> inner shareable stage-2 walks.
const S2_SH0: u64 = 0b11;
/// ORGN0 = 0b01 -> outer WB RA/WA cacheable stage-2 walks.
const S2_ORGN0: u64 = 0b01;
/// IRGN0 = 0b01 -> inner WB RA/WA cacheable stage-2 walks.
const S2_IRGN0: u64 = 0b01;

// Lock the stage-2 geometry against the kernel's stage-1 (mmu.rs `TCR_VALUE`):
// the IPA size + granule + walk shape are identical, so the regime is already
// proven runnable. A drift here is a build error, not a boot hang.
const _: () = assert!(S2_T0SZ == 25); // 39-bit, same as stage-1 T0SZ
const _: () = assert!(S2_TG0 == 0b00); // 4 KiB, same as stage-1 TG0
const _: () = assert!(HOLE_IPA >> SHIFT_1G == 5); // L1[5] -- the free high gigabyte
const _: () = assert!(HOLE_IPA & (GIB - 1) == 0); // 1 GiB-aligned (stage-1 block base)

// -- HCR_EL2 stage-2 arming bits ------------------------------------------------
/// `HCR_EL2.RW` (bit31): the next lower EL (EL1) is AArch64. The boot value of
/// `HCR_EL2` is EXACTLY this (`boot.rs` sets `HCR_EL2 = 1<<31`), so disarm
/// restores it byte-for-byte.
const HCR_RW: u64 = 1 << 31;
/// `HCR_EL2.VM` (bit0): enable stage-2 translation for EL1&0. Set ONLY inside the
/// L2.1 window; cleared (the highest-blast-radius teardown step) before unwinding.
const HCR_VM: u64 = 1 << 0;

// -- stage-1 hole-block attributes (mirror mmu.rs `BLOCK_NORMAL` = 0x705) --------
/// 1 GiB stage-1 Normal-WB block leaf: `block(0b01) | AF(bit10) | SH inner(0b11
/// <<8) | AttrIndx1(Normal, 1<<2)`. Spliced at stage-1 `L1[5]` so the guest VA
/// `HOLE_IPA` produces IPA `HOLE_IPA` (which stage-2 then faults).
const STAGE1_BLOCK_NORMAL: u64 = 0b01 | (1 << 10) | (0b11 << 8) | (1 << 2);

/// The seed word the demand frame carries (read by the guest AFTER the demand
/// map closes; its value is not checked -- the LOAD completing is the proof).
const DEMAND_SEED: u64 = 0x5347_5F32_5345_5256; // "SG_2SERV" mnemonic

// ===========================================================================
// EL2 self-context cells (single-accessor; EL1 NEVER references them).
//
// Written by the `HVC #2` arm handler at EL2, read by the EL2 abort + done
// handlers. `align(64)` keeps the four cells alone in one cache line so no
// EL1-written `.bss` variable can false-share + write back over an EL2 store.
// Accessed via plain `read_volatile`/`write_volatile` (NOT atomics): at EL2 with
// `SCTLR_EL2.M=0` the memory is Normal non-cacheable, where LDXR/STXR exclusives
// are not guaranteed -- volatile stores/loads to RAM are the coherent primitive.
// ===========================================================================

/// `[0]` = stage-2 root PA, `[1]` = demand-frame PA, `[2]` = expected hole IPA,
/// `[3]` = served IPA (0 sentinel until the abort handler maps the demand leaf).
#[repr(C, align(64))]
struct El2Ctx(UnsafeCell<[u64; 4]>);

// SAFETY: single vCPU; the cells are touched ONLY from EL2 (the arm/abort/done
// handlers), never concurrently and never by EL1 -- like `__el2_stack`. No Rust
// reference to the interior is ever minted; access is volatile raw-pointer only.
unsafe impl Sync for El2Ctx {}

static S2_CTX: El2Ctx = El2Ctx(UnsafeCell::new([0; 4]));

fn ctx_ptr() -> *mut u64 {
    S2_CTX.0.get() as *mut u64
}

/// EL2: record the demand context handed across the `HVC #2` frame and reset the
/// served sentinel. Called by the arm handler before `eret`-ing into the guest.
pub(super) fn set_s2_context(root: u64, demand: u64, expect_ipa: u64) {
    // SAFETY: EL2, single accessor; `ctx_ptr()` is our static cell block (64-B
    // aligned, EL1 never touches it). Four aligned volatile u64 stores.
    unsafe {
        let p = ctx_ptr();
        write_volatile(p.add(0), root);
        write_volatile(p.add(1), demand);
        write_volatile(p.add(2), expect_ipa);
        write_volatile(p.add(3), 0); // served sentinel
    }
}

/// EL2: the stage-2 root PA recorded at arm time.
pub(super) fn s2_root() -> u64 {
    // SAFETY: as `set_s2_context`; an aligned volatile load of cell 0.
    unsafe { read_volatile(ctx_ptr().add(0)) }
}
/// EL2: the pre-allocated demand-frame PA recorded at arm time.
pub(super) fn s2_demand() -> u64 {
    // SAFETY: as `set_s2_context`; cell 1.
    unsafe { read_volatile(ctx_ptr().add(1)) }
}
/// EL2: the expected hole IPA recorded at arm time.
pub(super) fn s2_expect_ipa() -> u64 {
    // SAFETY: as `set_s2_context`; cell 2.
    unsafe { read_volatile(ctx_ptr().add(2)) }
}
/// EL2: the IPA the abort handler actually served (0 if no demand fault yet).
pub(super) fn s2_served() -> u64 {
    // SAFETY: as `set_s2_context`; cell 3.
    unsafe { read_volatile(ctx_ptr().add(3)) }
}
/// EL2: record that the demand fault for `ipa` was served (the abort handler).
pub(super) fn set_s2_served(ipa: u64) {
    // SAFETY: as `set_s2_context`; an aligned volatile store of cell 3.
    unsafe { write_volatile(ctx_ptr().add(3), ipa) }
}

// ===========================================================================
// Barriers (EL1 + EL2). Trivial wrappers -- the stage-2 publish dance, mirroring
// `mmu.rs`'s. Local copies because `mmu.rs`'s are private to that module.
// ===========================================================================

fn dsb_ishst() {
    // SAFETY: a side-effect-free store barrier; always legal, no memory/stack
    // operands. NOT `nomem` -- it orders memory, so it is also a compiler barrier.
    unsafe { asm!("dsb ishst", options(nostack, preserves_flags)) }
}
fn dsb_ish() {
    // SAFETY: as `dsb_ishst`; a full inner-shareable completion barrier.
    unsafe { asm!("dsb ish", options(nostack, preserves_flags)) }
}
fn isb() {
    // SAFETY: a context-synchronization barrier; always legal, no operands.
    unsafe { asm!("isb", options(nostack, preserves_flags)) }
}

// ===========================================================================
// Stage-2 TLBI (EL2-only). First-fault demand maps never need a TLBI (invalid
// entries are not cached -- the same rule mmu.rs's first map relies on); these
// are issued for silicon parity (TCG passes without them; real cores want them).
// ===========================================================================

/// `TLBI IPAS2E1IS, Xt` with `Xt = IPA >> 12`: invalidate stage-2 entries for one
/// IPA (current VMID, inner shareable). EL2-only.
pub(super) fn tlbi_ipas2e1is(ipa: u64) {
    let operand = ipa >> 12;
    // SAFETY: EL2; TLBI only discards cached translations (never memory). The
    // operand is the IPA page number per the Arm ARM stage-2 TLBI operand format.
    unsafe {
        asm!("tlbi ipas2e1is, {op}", op = in(reg) operand, options(nostack, preserves_flags));
    }
}

/// `TLBI VMALLS12E1IS`: invalidate ALL stage-1&2 entries for the current VMID
/// (inner shareable). EL2-only; used on arm (flush stale) + disarm (teardown).
pub(super) fn tlbi_vmalls12e1is() {
    // SAFETY: EL2; flushes only cached translations for the active VMID.
    unsafe {
        asm!("tlbi vmalls12e1is", options(nostack, preserves_flags));
    }
}

// ===========================================================================
// EL2 system-register reads (the abort handler's syndrome source).
// ===========================================================================

/// Read `HPFAR_EL2` (the faulting IPA's high bits). EL2-readable, side-effect-free.
pub(super) fn read_hpfar_el2() -> u64 {
    let v: u64;
    // SAFETY: HPFAR_EL2 is an EL2-readable system register; `mrs` has no memory
    // or stack effect and leaves NZCV unchanged. The handler runs at EL2.
    unsafe {
        asm!("mrs {v}, hpfar_el2", v = out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// Read `FAR_EL2` (the faulting VA; its low 12 bits give the in-page offset).
pub(super) fn read_far_el2() -> u64 {
    let v: u64;
    // SAFETY: FAR_EL2 is an EL2-readable system register; a side-effect-free load.
    unsafe {
        asm!("mrs {v}, far_el2", v = out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

// ===========================================================================
// EL1: build the stage-2 tables (frame_alloc + fill + pre-build the hole path).
// ===========================================================================

/// `frame_alloc` one 4 KiB frame and zero all 512 entries through its identity
/// address (M6 frames sit in the identity-mapped RAM gigabyte, so PA == VA). A
/// fresh table MUST start all-invalid; the allocator only wrote a stale link word.
fn frame_alloc_zeroed() -> Option<u64> {
    let f = crate::frame_alloc()?;
    // SAFETY: `f` is a 4 KiB-aligned M6 frame in identity-mapped RAM we now own
    // exclusively; 512 aligned volatile u64 stores stay in the frame.
    unsafe {
        let p = f as *mut u64;
        let mut i = 0usize;
        while i < 512 {
            write_volatile(p.add(i), 0);
            i += 1;
        }
    }
    Some(f)
}

/// Write one descriptor slot of a table (by its identity PA), volatile.
fn s2_set(table_pa: u64, idx: usize, desc: u64) {
    debug_assert!(idx < 512);
    // SAFETY: `table_pa` is one of our just-allocated, identity-mapped 4 KiB
    // table frames; `idx < 512` keeps the offset in the frame. Single vCPU; the
    // stage-2 walker is sequenced by the explicit `dsb`s at the call sites.
    unsafe { write_volatile((table_pa as *mut u64).add(idx), desc) }
}

/// EL1: build the L2.1 stage-2 regime and return the L1 root PA (or `None` on
/// physical-frame OOM). Identity-maps GiB0 (Device) + GiB1 (Normal-WB) as 2 MiB
/// blocks, and PRE-BUILDS the table path `L1[5] -> L2 -> L3` down to (but NOT
/// including) the hole leaf, so the EL2 abort handler needs ZERO allocation.
pub(super) fn build_identity_stage2() -> Option<u64> {
    let root = frame_alloc_zeroed()?;
    let l2_gib0 = frame_alloc_zeroed()?;
    let l2_gib1 = frame_alloc_zeroed()?;
    let l2_hole = frame_alloc_zeroed()?;
    let l3_hole = frame_alloc_zeroed()?;

    // GiB0: 512 x 2 MiB Device blocks (the MMIO gigabyte, incl. the UART).
    let mut i = 0usize;
    while i < 512 {
        let pa = GIB0_DEVICE_BASE + (i as u64) * BLOCK_2M;
        s2_set(l2_gib0, i, s2_leaf_2mib(pa, S2_MEMATTR_DEVICE));
        i += 1;
    }
    // GiB1: 512 x 2 MiB Normal-WB blocks (RAM: stub code, stack, the LIVE
    // stage-1 table frames -- so the guest's own stage-1 walk never S1PTW-faults).
    i = 0;
    while i < 512 {
        let pa = GIB1_RAM_BASE + (i as u64) * BLOCK_2M;
        s2_set(l2_gib1, i, s2_leaf_2mib(pa, S2_MEMATTR_NORMAL_WB));
        i += 1;
    }

    // L1 root: [0] -> GiB0 table, [1] -> GiB1 table, [5] -> the pre-built hole
    // path. (Every other L1 slot stays INVALID -- any stray guest IPA faults.)
    s2_set(root, level_index(GIB0_DEVICE_BASE, SHIFT_1G), s2_table(l2_gib0));
    s2_set(root, level_index(GIB1_RAM_BASE, SHIFT_1G), s2_table(l2_gib1));
    s2_set(root, level_index(HOLE_IPA, SHIFT_1G), s2_table(l2_hole));
    // Hole L2 -> hole L3 (the 2 MiB region containing HOLE_IPA). The final L3
    // leaf is left INVALID == the genuine hole the guest will fault on; the EL2
    // handler splices it WITHOUT allocating (the tables already exist).
    s2_set(l2_hole, level_index(HOLE_IPA, SHIFT_2M), s2_table(l3_hole));

    // Publish the whole hierarchy to the (EL1 + EL2) stage-2 walker.
    dsb_ishst();
    isb();
    Some(root)
}

/// EL1: `frame_alloc` the demand frame, seed word 0 (read by the guest after the
/// demand map), and publish. Returns its PA, or `None` on OOM.
pub(super) fn prep_demand_frame() -> Option<u64> {
    let f = crate::frame_alloc()?;
    // SAFETY: `f` is a 4 KiB-aligned, identity-mapped M6 frame we own; one
    // aligned volatile store seeds word 0 through its identity (PA == VA) alias.
    unsafe { write_volatile(f as *mut u64, DEMAND_SEED) }
    dsb_ishst();
    Some(f)
}

/// EL1: splice a stage-1 1 GiB identity block at `L1[5]` of the LIVE `TTBR0_EL1`
/// so the guest VA [`HOLE_IPA`] produces IPA `HOLE_IPA` (which stage-2 then
/// faults). The stage-1 walk for this VA touches only the L1 root (in GiB1, which
/// stage-2 covers), so it never S1PTW-faults. No TLBI: `L1[5]` was INVALID (a
/// first map), so no stale stage-1 translation can be cached.
///
/// Left installed after the round-trip -- harmless: it maps VA `0x1_4000_0000`
/// (just past the heap window `L1[4]`) to a PA with no backing RAM, and the
/// kernel never touches that VA again (stage-2 is torn down, so it is plain
/// stage-1 thereafter).
pub(super) fn install_stage1_hole_block() {
    let l1 = super::mmu::current_root() as *mut u64;
    let idx = level_index(HOLE_IPA, SHIFT_1G); // 5
    // SAFETY: `current_root()` returns the live `TTBR0_EL1` L1 base PA (BADDR
    // masked), an identity-mapped 512-entry table; `idx == 5 < 512`. We write a
    // single previously-INVALID slot with a valid 1 GiB Normal block whose output
    // (`HOLE_IPA`) is 1 GiB-aligned, then publish before any access through it.
    unsafe { write_volatile(l1.add(idx), make_entry(HOLE_IPA, STAGE1_BLOCK_NORMAL)) }
    dsb_ishst();
    isb();
}

// ===========================================================================
// EL1: derive the VTCR_EL2 / VTTBR_EL2 register values (pure tb-encode math).
// ===========================================================================

/// `VTCR_EL2` for the L2.1 geometry (mirrors the kernel's stage-1 TCR_EL1).
pub(super) fn compute_vtcr() -> u64 {
    vtcr(S2_T0SZ, S2_SL0, S2_TG0, S2_PS, S2_SH0, S2_ORGN0, S2_IRGN0)
}

/// `VTTBR_EL2` = stage-2 root `root` in BADDR | [`VMID`] in `[63:48]`.
pub(super) fn compute_vttbr(root: u64) -> u64 {
    vttbr(root, VMID)
}

// ===========================================================================
// EL2-only: arm / disarm stage-2 (the msr VTCR/VTTBR/HCR.VM writes).
// ===========================================================================

/// EL2: program `VTCR_EL2`/`VTTBR_EL2`, then set `HCR_EL2.VM=1` (stage-2 ON), and
/// flush stale stage-1&2 for this VMID. After this returns, EVERY EL1&0 access
/// (incl. the stage-1 walk) is stage-2-translated. Called by the `HVC #2` arm
/// handler just before `eret`-ing into the guest stub.
pub(super) fn arm_stage2_el2(vtcr_val: u64, vttbr_val: u64) {
    // SAFETY: EL2. Program the stage-2 geometry + root, `isb`-synchronize, THEN
    // enable stage-2 (HCR.VM=1) and `isb` again so the regime is fully in place
    // before the next EL1 access. The tables were published (`dsb ishst`) at
    // build time. No stack/flags effect; not `nomem` (it reconfigures translation).
    unsafe {
        asm!(
            "msr vtcr_el2,  {vtcr}",
            "msr vttbr_el2, {vttbr}",
            "isb",
            "msr hcr_el2,   {hcr}",
            "isb",
            vtcr  = in(reg) vtcr_val,
            vttbr = in(reg) vttbr_val,
            hcr   = in(reg) HCR_RW | HCR_VM,
            options(nostack, preserves_flags),
        );
    }
    // Flush any stale stage-1&2 for this VMID (parity; nothing is cached yet).
    tlbi_vmalls12e1is();
    dsb_ish();
    isb();
}

/// EL2: tear stage-2 DOWN -- the single highest-blast-radius step. Clears
/// `HCR_EL2.VM=0` (back to the boot value `1<<31`), zeroes `VTTBR_EL2`,
/// `isb`-synchronizes, and flushes all stage-1&2 for this VMID. MUST run before
/// any unwind to the EL1 kernel: returning to EL1 with `VM=1` still set leaves
/// the kernel's RAM un-stage-2-mapped and instantly aborts it.
pub(super) fn disarm_stage2_el2() {
    // SAFETY: EL2. Disable stage-2 FIRST (HCR.VM=0), then drop the root, then
    // `isb` so the next EL1 access is stage-1-only (kernel RAM mapped). No
    // stack/flags effect; not `nomem` (it reconfigures translation).
    unsafe {
        asm!(
            "msr hcr_el2,   {hcr}",   // VM=0 (RW=1 only) -- stage-2 OFF
            "msr vttbr_el2, xzr",     // drop the stage-2 root
            "isb",
            hcr = in(reg) HCR_RW,
            options(nostack, preserves_flags),
        );
    }
    tlbi_vmalls12e1is();
    dsb_ish();
    isb();
}

// ===========================================================================
// EL2-only: demand-map the faulting IPA (NO allocation -- walk pre-built tables).
// ===========================================================================

/// EL2: service a stage-2 translation fault for `ipa` by splicing a 4 KiB
/// Normal-WB stage-2 leaf -> `pa` into the PRE-BUILT `L1[5] -> L2 -> L3` path,
/// then publish + flush. Returns `false` (fail-closed) if any interior table is
/// unexpectedly missing -- which would mean the EL1 builder did not pre-build the
/// path (a build bug), never an allocation attempt at EL2.
pub(super) fn demand_map_ipa(root: u64, ipa: u64, pa: u64) -> bool {
    // SAFETY: EL2, MMU off (flat/non-cacheable). `root` is the stage-2 L1 root PA
    // recorded at arm time; every interior table was pre-built at EL1 and lives
    // in identity-mapped RAM, so each `entry_addr` pointer dereferences directly.
    // We READ two interior descriptors and write ONE L3 leaf -- no allocation.
    let ok = unsafe {
        let l1 = root as *mut u64;
        let e1 = read_volatile(l1.add(level_index(ipa, SHIFT_1G)));
        if !entry_is_valid(e1) {
            return false;
        }
        let l2 = entry_addr(e1) as *mut u64;
        let e2 = read_volatile(l2.add(level_index(ipa, SHIFT_2M)));
        if !entry_is_valid(e2) {
            return false;
        }
        let l3 = entry_addr(e2) as *mut u64;
        write_volatile(
            l3.add(level_index(ipa, SHIFT_4K)),
            s2_leaf_4k(pa, S2_MEMATTR_NORMAL_WB),
        );
        true
    };
    if ok {
        // Publish the leaf to the stage-2 walker, then flush stale (parity).
        dsb_ishst();
        isb();
        tlbi_ipas2e1is(ipa);
        dsb_ish();
        isb();
    }
    ok
}
