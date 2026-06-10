//! aarch64 **M27a "sched"**: the COOPERATIVE (HVC-yield) two-VMID sovereign
//! time-partition scheduler -- the EL2-only armed/decision context cell + the
//! TWO-stage-2-root arm/disarm window (the teardown-first discipline), mirroring
//! [`super::el2vgic`]'s `VgicCtx` + `arm_vgic_el2`/`disarm_vgic_el2` MINUS the
//! async-IRQ (CNTHP/GIC/IMO) parts that belong to M27b.
//!
//! Where aL2.5 ([`super::el2vgic`]) injects a virtual interrupt into ONE guest,
//! M27a TIME-PARTITIONS TWO guest VMIDs under TWO distinct stage-2 roots: each
//! trivial EL1 stub, when running, bumps a DISTINCT MMIO cell (the L2.3
//! trap-and-emulate seam, per-VMID) then voluntarily YIELDS with `HVC #14`. The
//! EL2 sync handler, on each yield, consults the Kani-proven
//! [`tb_encode::tpsched::next_slot`], switches `VTTBR_EL2` to the next VMID's
//! root (+ `tlbi vmalls12e1is`), folds a [`tb_encode::tpsched::SchedDecision`]
//! into a running `sched_head` (via the M22 [`tb_encode::prov`] fold reused
//! VERBATIM -- NO new fold math), and `eret`s into the next guest. After K
//! bounded major-frame iterations the orchestrator ends with `HVC #13`,
//! teardown-FIRST, and the monitor verifies: both VMIDs' MMIO cells advanced
//! (both-progressed, neither starved), the observed VMID order is the tpsched
//! round-robin (order-honored), `recompute(sched_head)` matches + a single-byte
//! tamper flips it (fold-verified + tamper-caught), and the frame is conserved.
//!
//! ## Honest scope (the marker claims ONLY COOPERATIVE timing)
//!
//! M27a exercises EVERYTHING EXCEPT the timer IRQ -- two VMIDs, two stage-2
//! roots, two forward-progress cells, round-robin order, the fold, the tamper
//! check, both-progressed -- and **cannot IRQ-storm** (there is no async IRQ at
//! all). The marker emits `timing=COOPERATIVE-HVC-YIELD` so it can NEVER
//! impersonate the M27b real-CNTHP-preemption claim (`timing=TCG-NON-CYCLE-
//! ACCURATE`). `realtime=NOT-CLAIMED` always.
//!
//! ## Arming (HCR_EL2 -- absolute writes, mirroring `stage2.rs::arm_stage2_el2`)
//!
//! The boot baseline is `HCR_EL2 = 1<<31` (RW only). [`arm_sched_el2`] programs
//! `VTCR_EL2`/`VTTBR_EL2` (the FIRST slot's root) + `HCR_EL2 = RW|VM` (stage-2
//! ON, so each guest's distinct MMIO IPA stage-2-faults to the device seam);
//! [`switch_vttbr_el2`] flips `VTTBR_EL2` to the next slot's root + flushes on
//! each yield; [`disarm_sched_el2`] restores `HCR_EL2 = RW` + drops `VTTBR_EL2`
//! + `tlbi vmalls12e1is` (teardown-first, the L2.1 discipline) BEFORE the
//! monitor unwinds. NO `HCR_EL2.IMO`, NO CNTHP arming, NO vector-table edit --
//! those are M27b.
//!
//! ## The armed/decision cell (EL2-only; the outcome leaves via the x0 register)
//!
//! Written + read ONLY at EL2 (the arm handler, the yield handler, the done
//! verdict), never by EL1, so -- like `el2vgic::VgicCtx` -- it is a single-
//! accessor `align(64)` cell that shares no cache line with any EL1-written
//! `.bss`. Accessed via plain `read_volatile`/`write_volatile` (NOT atomics): at
//! EL2 with `SCTLR_EL2.M=0` the memory is Normal non-cacheable, where exclusives
//! are not guaranteed -- volatile is the coherent primitive. The VERDICT derived
//! from it is delivered to EL1 in the x0 register.

use core::arch::asm;
use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};

use tb_encode::tpsched::{
    next_slot, sched_chain_mix, sched_hash, slot_deadline_delta, FramePlan, SchedDecision,
    N_SLOTS, PROV_HASH_LEN, SCHED_CANON_LEN,
};

// ===========================================================================
// HCR_EL2 arming bits (Linux `kvm_arm.h`; Arm ARM DDI 0487 D13). M27a uses ONLY
// RW + VM -- NO IMO (that routes physical IRQ to EL2, the M27b async path).
// ===========================================================================

/// `HCR_EL2.RW` (bit31): the next lower EL (EL1) is AArch64 -- the boot baseline.
const HCR_RW: u64 = 1 << 31;
/// `HCR_EL2.VM` (bit0): enable stage-2 translation for EL1&0 (so each guest's
/// distinct device IPA stage-2-faults -> the per-VMID MMIO emulate path). Same
/// bit `stage2.rs`/`el2mmio.rs` use.
const HCR_VM: u64 = 1 << 0;

// Tier-1 compile-time locks (a drift from the boot baseline is a build error).
const _: () = assert!(HCR_RW == 1 << 31);
const _: () = assert!(HCR_VM == 1);

/// The compile-time MAJOR-FRAME cap (proposal §3, the bounded-iteration rule): K
/// major frames, each switching both slots, then `HVC #13`. 8 is comfortably
/// inside the EL2 stack budget + can never spin. A 2-slot frame means 2*K total
/// yields; the observed-order trace is capped at this many.
pub(super) const K_MAX_FRAMES: u64 = 8;
/// The maximum number of voluntary yields the cell traces (`2 * K_MAX_FRAMES`):
/// one per slot per frame. The trace records the VMID that RAN before each yield.
pub(super) const MAX_YIELDS: usize = (2 * K_MAX_FRAMES) as usize;

const _: () = assert!(N_SLOTS == 2); // M27a is the minimal two-slot frame
const _: () = assert!(PROV_HASH_LEN == 32);
const _: () = assert!(SCHED_CANON_LEN == 21);

// ===========================================================================
// The EL2 armed/decision context cell (single-accessor; EL1 NEVER references it).
//
// Layout (all u64 cells, `align(64)` so they share no line with EL1 `.bss`):
//   [0]       armed flag (0/1)
//   [1]       current_slot (0..N_SLOTS) -- the slot whose guest is RUNNING
//   [2]       frames_done -- completed major frames (a frame == N_SLOTS yields)
//   [3]       yields_done -- total voluntary yields observed (== switch count)
//   [4..6]    vmid[0], vmid[1]            -- the per-slot guest VMIDs
//   [6..8]    vttbr[0], vttbr[1]          -- the per-slot VTTBR_EL2 values
//   [8..10]   entry_pc[0], entry_pc[1]    -- the per-slot guest stub entry PCs
//   [10..12]  slot_ticks[0], slot_ticks[1] -- the FramePlan budgets (witness)
//   [12]      frame_seq                   -- the monotone SchedDecision frame_seq
//   [13]      t_logical                   -- the SchedDecision logical clock
//   [14..18]  sched_head[0..4]            -- the running 32-byte fold head (4xu64)
//   [18..18+MAX_YIELDS] order_trace       -- the VMID that ran before each yield
// ===========================================================================

const C_ARMED: usize = 0;
const C_CUR_SLOT: usize = 1;
const C_FRAMES_DONE: usize = 2;
const C_YIELDS_DONE: usize = 3;
const C_VMID: usize = 4; // [4], [5]
const C_VTTBR: usize = 6; // [6], [7]
const C_ENTRY_PC: usize = 8; // [8], [9]
const C_SLOT_TICKS: usize = 10; // [10], [11]
const C_FRAME_SEQ: usize = 12;
const C_TLOGICAL: usize = 13;
const C_HEAD: usize = 14; // [14..18] -- 4 u64 lanes of the 32-byte head
const C_ORDER: usize = 18; // [18..18+MAX_YIELDS]

/// Total u64 cells: the fixed prefix + the order trace.
const CELL_WORDS: usize = C_ORDER + MAX_YIELDS;

#[repr(C, align(64))]
struct SchedCtx(UnsafeCell<[u64; CELL_WORDS]>);

// SAFETY: single vCPU; the cells are touched ONLY from EL2 (the arm / yield /
// done handlers), never concurrently and never by EL1 -- like `el2vgic::VgicCtx`.
// No Rust reference to the interior is ever minted; access is volatile raw-pointer
// only.
unsafe impl Sync for SchedCtx {}

static SCHED_CTX: SchedCtx = SchedCtx(UnsafeCell::new([0; CELL_WORDS]));

fn ctx_ptr() -> *mut u64 {
    SCHED_CTX.0.get() as *mut u64
}

/// EL2: store cell `i` (single-accessor volatile).
fn put(i: usize, v: u64) {
    debug_assert!(i < CELL_WORDS);
    // SAFETY: EL2, single accessor; `ctx_ptr()` is our static cell block (64-B
    // aligned, EL1 never touches it). `i < CELL_WORDS` keeps the store in-bounds.
    unsafe { write_volatile(ctx_ptr().add(i), v) }
}
/// EL2: load cell `i`.
fn get(i: usize) -> u64 {
    debug_assert!(i < CELL_WORDS);
    // SAFETY: as `put`; an aligned in-bounds volatile load.
    unsafe { read_volatile(ctx_ptr().add(i)) }
}

/// EL2: is the M27a window currently armed? (The per-VMID MMIO route gates on
/// this -- mutually exclusive with `el2mmio::armed()` -- so a store to an M27
/// device IPA OUTSIDE the window leaves the L2.3 path byte-identical.)
pub(super) fn armed() -> bool {
    get(C_ARMED) != 0
}

/// EL2: arm the M27a DECISION state -- record the two VMIDs / VTTBRs / entry PCs
/// / slot budgets, reset the running fold head to genesis (all-zero), reset the
/// frame/yield counters + logical clock, and clear the order trace. Called by the
/// `HVC #12` arm handler BEFORE programming HCR_EL2/VTTBR + `eret`-ing into slot 0.
#[allow(clippy::too_many_arguments)]
pub(super) fn set_sched_context(
    plan: &FramePlan,
    vttbr0: u64,
    vttbr1: u64,
    entry0: u64,
    entry1: u64,
) {
    put(C_ARMED, 1);
    put(C_CUR_SLOT, 0); // slot 0 runs first
    put(C_FRAMES_DONE, 0);
    put(C_YIELDS_DONE, 0);
    put(C_VMID + 0, u64::from(plan.vmid[0]));
    put(C_VMID + 1, u64::from(plan.vmid[1]));
    put(C_VTTBR + 0, vttbr0);
    put(C_VTTBR + 1, vttbr1);
    put(C_ENTRY_PC + 0, entry0);
    put(C_ENTRY_PC + 1, entry1);
    put(C_SLOT_TICKS + 0, slot_deadline_delta(plan, 0));
    put(C_SLOT_TICKS + 1, slot_deadline_delta(plan, 1));
    put(C_FRAME_SEQ, 0);
    put(C_TLOGICAL, 0);
    // Genesis head (all-zero, the `prov::recompute` start state).
    put(C_HEAD + 0, 0);
    put(C_HEAD + 1, 0);
    put(C_HEAD + 2, 0);
    put(C_HEAD + 3, 0);
    let mut i = 0usize;
    while i < MAX_YIELDS {
        put(C_ORDER + i, 0);
        i += 1;
    }
}

/// EL2: the slot whose guest is currently RUNNING (0..N_SLOTS).
pub(super) fn current_slot() -> usize {
    (get(C_CUR_SLOT) as usize) % N_SLOTS
}

/// EL2: the VTTBR_EL2 value for `slot`.
pub(super) fn vttbr_for(slot: usize) -> u64 {
    get(C_VTTBR + (slot % N_SLOTS))
}

/// EL2: the guest stub entry PC for `slot`.
pub(super) fn entry_pc_for(slot: usize) -> u64 {
    get(C_ENTRY_PC + (slot % N_SLOTS))
}

/// EL2: the VMID scheduled in `slot`.
pub(super) fn vmid_for(slot: usize) -> u64 {
    get(C_VMID + (slot % N_SLOTS))
}

// -- the 32-byte running fold head (4 LE u64 lanes) -------------------------

/// EL2: read the running fold head out of the four lane cells.
pub(super) fn head_bytes() -> [u8; PROV_HASH_LEN] {
    let mut out = [0u8; PROV_HASH_LEN];
    let mut l = 0usize;
    while l < 4 {
        let w = get(C_HEAD + l).to_le_bytes();
        let base = l * 8;
        let mut b = 0usize;
        while b < 8 {
            out[base + b] = w[b];
            b += 1;
        }
        l += 1;
    }
    out
}

/// EL2: write the running fold head back into the four lane cells.
fn store_head(head: &[u8; PROV_HASH_LEN]) {
    let mut l = 0usize;
    while l < 4 {
        let base = l * 8;
        let w = [
            head[base],
            head[base + 1],
            head[base + 2],
            head[base + 3],
            head[base + 4],
            head[base + 5],
            head[base + 6],
            head[base + 7],
        ];
        put(C_HEAD + l, u64::from_le_bytes(w));
        l += 1;
    }
}

/// EL2: the count of voluntary yields observed (== world-switch count).
pub(super) fn yields_done() -> u64 {
    get(C_YIELDS_DONE)
}

/// EL2: the count of COMPLETED major frames (a frame == N_SLOTS yields).
pub(super) fn frames_done() -> u64 {
    get(C_FRAMES_DONE)
}

/// EL2: the per-slot budget recorded at arm time (the conservation witness).
pub(super) fn slot_ticks(slot: usize) -> u64 {
    get(C_SLOT_TICKS + (slot % N_SLOTS))
}

/// EL2: the VMID that RAN before yield `i` (the observed round-robin order).
pub(super) fn order_at(i: usize) -> u64 {
    if i >= MAX_YIELDS {
        return u64::MAX; // out of range -> a sentinel the verdict rejects
    }
    get(C_ORDER + i)
}

/// EL2: the M27a YIELD step -- the heart of the cooperative scheduler. Called by
/// the `HVC #14` handler on each voluntary yield. It:
///   1. records the OUTGOING VMID into the order trace (forward-progress order),
///   2. computes the next slot via the Kani-proven [`next_slot`],
///   3. canon-encodes a [`SchedDecision`] for this preemption + FOLDS it into the
///      running head via the M22 fold REUSED VERBATIM (`sched_hash` ->
///      `sched_chain_mix`, NO new fold math),
///   4. bumps the frame/yield counters + the logical clock,
///   5. advances `current_slot` to the next slot.
/// Returns the next slot's `(vttbr, entry_pc)` so the caller flips `VTTBR_EL2`
/// and `eret`s into the next guest. PURE cell arithmetic + the proven leaf -- no
/// alloc, no deep calls (the EL2 stack red-zone discipline).
pub(super) fn note_yield() -> (usize, u64, u64) {
    let cur = current_slot();
    let nxt = next_slot(cur);
    let vmid_from = vmid_for(cur);
    let vmid_to = vmid_for(nxt);
    let frame_seq = get(C_FRAME_SEQ);
    let t_logical = get(C_TLOGICAL);

    // (1) Trace the OUTGOING VMID (the guest that just made forward progress).
    let yi = get(C_YIELDS_DONE) as usize;
    if yi < MAX_YIELDS {
        put(C_ORDER + yi, vmid_from);
    }

    // (3) Fold a SchedDecision for this preemption -- the M22 prov fold VERBATIM.
    let decision = SchedDecision {
        frame_seq,
        slot: nxt as u8,
        vmid_from: vmid_from as u16,
        vmid_to: vmid_to as u16,
        t_logical,
    };
    let mut scratch = [0u8; SCHED_CANON_LEN];
    let n = tb_encode::tpsched::canon(&decision, &mut scratch);
    if n == SCHED_CANON_LEN {
        let entry_id = sched_hash(&scratch[..n]);
        let new_head = sched_chain_mix(head_bytes(), entry_id);
        store_head(&new_head);
    }
    // (If `canon` ever returned 0 the head would not advance -- fail-closed; the
    // done verdict's recompute/tamper check would then catch the divergence.)

    // (4) Bump counters + the logical clock. A completed FRAME is every N_SLOTS
    // yields (the round-robin returned to slot 0).
    let yields = yi as u64 + 1;
    put(C_YIELDS_DONE, yields);
    put(C_TLOGICAL, t_logical.wrapping_add(slot_ticks(cur)));
    if nxt == 0 {
        // Returning to slot 0 closes one major frame.
        put(C_FRAMES_DONE, get(C_FRAMES_DONE) + 1);
        put(C_FRAME_SEQ, frame_seq + 1);
    }

    // (5) Advance the running slot.
    put(C_CUR_SLOT, nxt as u64);

    (nxt, vttbr_for(nxt), entry_pc_for(nxt))
}

// ===========================================================================
// EL2-only: arm / switch / disarm the M27a stage-2 window (the msr HCR/VTTBR
// glue -- mirrors `stage2.rs::arm_stage2_el2`/`disarm_stage2_el2` MINUS any
// async-IRQ/IMO part).
// ===========================================================================

/// EL2: arm the M27a window -- program `VTCR_EL2`/`VTTBR_EL2` (the FIRST slot's
/// root), set `HCR_EL2 = RW|VM` (stage-2 ON so each guest's distinct device IPA
/// stage-2-faults), and flush stale stage-1&2 for the VMID. After this returns,
/// EVERY EL1&0 access is stage-2-translated under the slot-0 root. Called by the
/// `HVC #12` arm handler just before `eret`-ing into slot 0's stub.
pub(super) fn arm_sched_el2(vtcr_val: u64, vttbr0_val: u64) {
    // SAFETY: EL2. Program the stage-2 geometry + slot-0 root, `isb`-synchronize,
    // THEN enable stage-2 (HCR.VM=1) and `isb` again so the regime is fully in
    // place before the next EL1 access. The tables were published (`dsb ishst`)
    // at build time. No stack/flags effect; not `nomem` (it reconfigures
    // translation). NO IMO, NO timer -- M27a is cooperative.
    unsafe {
        asm!(
            "msr vtcr_el2,  {vtcr}",
            "msr vttbr_el2, {vttbr}",
            "isb",
            "msr hcr_el2,   {hcr}",
            "isb",
            vtcr  = in(reg) vtcr_val,
            vttbr = in(reg) vttbr0_val,
            hcr   = in(reg) HCR_RW | HCR_VM,
            options(nostack, preserves_flags),
        );
    }
    super::stage2::tlbi_vmalls12e1is();
    super::stage2::dsb_ish_pub();
    super::stage2::isb_pub();
}

/// EL2: switch `VTTBR_EL2` to the next slot's stage-2 root (the world-switch on
/// each voluntary yield) + `isb` + flush ALL stage-1&2 for the (changing) VMID so
/// the next guest runs under its OWN stage-2 view. HCR_EL2 stays `RW|VM` (the
/// window remains armed). Called by the `HVC #14` yield handler after [`note_yield`]
/// before resuming the next guest.
pub(super) fn switch_vttbr_el2(vttbr_val: u64) {
    // SAFETY: EL2. Reprogram only the stage-2 ROOT (VTTBR_EL2, which also carries
    // the new VMID in [63:48]) and `isb`; HCR_EL2.VM stays set. Then flush all
    // stage-1&2 translations (the VMID changed, so any cached entry is stale). No
    // stack/flags effect; not `nomem` (it reconfigures translation).
    unsafe {
        asm!(
            "msr vttbr_el2, {vttbr}",
            "isb",
            vttbr = in(reg) vttbr_val,
            options(nostack, preserves_flags),
        );
    }
    super::stage2::tlbi_vmalls12e1is();
    super::stage2::dsb_ish_pub();
    super::stage2::isb_pub();
}

/// EL2: tear the M27a window DOWN -- the MANDATORY zero-regression step (the L2.1
/// teardown-first discipline). Clears `HCR_EL2.VM=0` (back to the boot value
/// `1<<31`), drops `VTTBR_EL2`, clears the armed flag, `isb`-synchronizes, and
/// flushes all stage-1&2 for the VMID. MUST run BEFORE any unwind to the EL1
/// kernel: returning with `VM=1` leaves the kernel's RAM un-stage-2-mapped and
/// instantly aborts it. Teardown is the FIRST action of the `HVC #13` done handler.
pub(super) fn disarm_sched_el2() {
    put(C_ARMED, 0);
    // SAFETY: EL2. Disable stage-2 FIRST (HCR.VM=0, RW=1 only), drop the root,
    // then `isb` so the next EL1 access is stage-1-only (kernel RAM mapped). No
    // stack/flags effect; not `nomem` (it reconfigures translation).
    unsafe {
        asm!(
            "msr hcr_el2,   {hcr}", // VM=0 (RW=1 only) -- stage-2 OFF
            "msr vttbr_el2, xzr",   // drop the stage-2 root
            "isb",
            hcr = in(reg) HCR_RW,
            options(nostack, preserves_flags),
        );
    }
    super::stage2::tlbi_vmalls12e1is();
    super::stage2::dsb_ish_pub();
    super::stage2::isb_pub();
}
