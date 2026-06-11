//! The M27 verified TWO-VMID TIME-PARTITION SCHEDULER math -- the pure, verified
//! value-computation leaf behind the minimal sovereign scheduler: a fixed two-slot
//! major frame that time-partitions two guest VMIDs under the EL2 physical timer, with
//! each scheduling DECISION folded into the experience stream. Lifted into `tb-encode`
//! exactly as the M26 exit-telemetry codec ([`crate::exittel`]) was. The silicon (arm
//! `CNTHP_TVAL_EL2`, switch `VTTBR_EL2`/VMID on the timer PPI) stays in `tb-hal`; this
//! leaf is the decidable timing GEOMETRY -- the slot function, the frame conservation,
//! the VMID alternation -- plus the injective decision record folded via the M22 fold.
//!
//! ## Honest scope (proposal §5 -- the marker claims ONLY what is proved)
//!
//! * **NOT real-time, NOT schedulability-proven (`realtime=NOT-CLAIMED`).** A fixed
//!   two-slot round-robin is deterministic ALTERNATION, not an ARINC-653 *guarantee* or
//!   an seL4-MCS *temporal-integrity proof* -- there are no WCET bounds. We claim only:
//!   deterministic time-partitioned alternation of two VMIDs, the partition function
//!   verified total / no-panic / frame-conserving, each decision recorded tamper-
//!   evidently.
//! * **OBSERVATIONAL, not LEARNED.** The [`SchedDecision`] records which VMID ran when;
//!   the schedule is a FIXED round-robin, never adapted from telemetry (the M26
//!   confounding firewall holds -- a learned scheduler driven by exit/sched telemetry
//!   would close the confounded loop M24 refuses).
//! * **CLAIMS injective bounded encoding + tamper-evidence (cryptographic since
//!   M29-C)** (the M23/M26 claim set): a single-byte mutation of a committed
//!   decision invalidates the recomputed `sched_head` -- the M22 fold reused
//!   verbatim (khash/BLAKE2s-256 since M29 stage C;
//!   `sec=ASSUMED-FROM-LITERATURE`).
//!
//! ## Numeric format (no float, ever -- mirrors `exittel`/`exp`/`prov`)
//!
//! Pure integer/byte arithmetic, zero alloc, zero deps. [`canon`] is a FIXED-WIDTH LE
//! byte layout (total + fail-closed). The fold REUSES the proven [`crate::prov`] leaf --
//! NO new fold math.

// The fold is the M22 provenance leaf, REUSED verbatim (no new fold math), as M23/M26.
pub use crate::prov::{
    append as sched_append, chain_mix as sched_chain_mix, head_witness as sched_head_witness,
    prov_hash as sched_hash, recompute as sched_recompute, verify_inclusion as sched_verify_inclusion,
    PROV_HASH_LEN,
};

/// The number of slots in the major frame: two (the minimal sovereign two-VMID
/// partition -- ARINC-653's minimal two-window frame).
pub const N_SLOTS: usize = 2;

/// The minimum per-slot tick budget: a slot must grant its VMID a NON-ZERO budget (a
/// zero-budget slot would starve its VMID -- the frame-conservation invariant forbids
/// it). [`slot_deadline_delta`] clamps UP to this floor.
pub const MIN_SLOT_TICKS: u64 = 1;

/// A fixed two-slot major-frame plan: each slot grants its `vmid` a `slot_ticks` budget;
/// the frame is the (saturating) sum. A static partition -- the schedule is FROZEN, not
/// learned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FramePlan {
    /// The per-slot tick budgets (the `CNTHP_TVAL_EL2` countdown each slot arms).
    pub slot_ticks: [u64; N_SLOTS],
    /// The guest VMID scheduled in each slot.
    pub vmid: [u16; N_SLOTS],
}

/// The round-robin SUCCESSOR of `current` slot: `(current + 1) % N_SLOTS`, TOTAL over
/// `0..N_SLOTS` (and fail-closed to `0` for an out-of-range input). Strictly cycles
/// `0 -> 1 -> 0`, so NEITHER slot is a fixed point -> neither VMID starves (the
/// `kani_tpsched_next_slot_roundrobin` liveness property). No panic.
#[inline]
#[must_use]
pub fn next_slot(current: usize) -> usize {
    if current >= N_SLOTS {
        return 0; // fail-closed: an out-of-range slot restarts the frame
    }
    (current + 1) % N_SLOTS
}

/// The `CNTHP_TVAL_EL2` countdown delta to arm for `slot`: the slot's `slot_ticks`,
/// clamped UP to [`MIN_SLOT_TICKS`] (so no slot arms a zero/instant deadline -> no
/// starvation) and returned saturating. Fail-closed to `MIN_SLOT_TICKS` for an out-of-
/// range slot. TOTAL, no panic, no float.
#[inline]
#[must_use]
pub fn slot_deadline_delta(plan: &FramePlan, slot: usize) -> u64 {
    if slot >= N_SLOTS {
        return MIN_SLOT_TICKS;
    }
    let t = plan.slot_ticks[slot];
    if t < MIN_SLOT_TICKS {
        MIN_SLOT_TICKS
    } else {
        t
    }
}

/// The conserved major-frame length: the SATURATING sum of every slot's clamped
/// deadline delta. Conservation (the `kani_tpsched_frame_conserved` invariant):
/// `frame_total == Σ slot_deadline_delta`, every slot contributes `>= MIN_SLOT_TICKS`,
/// so `frame_total >= N_SLOTS * MIN_SLOT_TICKS` (no slot starves) and no single slot can
/// exceed the frame (no monopoly). TOTAL, no overflow (saturating), no float.
#[inline]
#[must_use]
pub fn frame_total(plan: &FramePlan) -> u64 {
    let mut acc = 0u64;
    let mut s = 0usize;
    while s < N_SLOTS {
        acc = acc.saturating_add(slot_deadline_delta(plan, s));
        s += 1;
    }
    acc
}

/// A fixed, canonical scheduling-decision record (proposal §2.1): the sovereignty ->
/// learning experience row. EVERY field is FIXED-WIDTH, so [`canon`] is injective. It
/// captures ONE preemption: the frame sequence, the slot entered, the VMID switched
/// FROM and TO, and the logical clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedDecision {
    /// The monotone major-frame sequence number (which frame this preemption is in).
    pub frame_seq: u64,
    /// The slot entered (`0..N_SLOTS`).
    pub slot: u8,
    /// The VMID running BEFORE this preemption (the outgoing guest).
    pub vmid_from: u16,
    /// The VMID scheduled by this preemption (the incoming guest).
    pub vmid_to: u16,
    /// The logical (boot-relative) clock at the preemption.
    pub t_logical: u64,
}

/// The fixed canonical byte length of EVERY [`SchedDecision`]. Layout (LE):
///
/// ```text
///   [0..8]   frame_seq   u64 LE
///   [8]      slot        u8
///   [9..11]  vmid_from   u16 LE
///   [11..13] vmid_to     u16 LE
///   [13..21] t_logical   u64 LE
/// ```
pub const SCHED_CANON_LEN: usize = 8 + 1 + 2 + 2 + 8;

const OFF_FRAME_SEQ: usize = 0;
const OFF_SLOT: usize = 8;
const OFF_VMID_FROM: usize = 9;
const OFF_VMID_TO: usize = 11;
const OFF_TLOGICAL: usize = 13;

/// The exact canonical byte length of `rec` -- a tautological [`SCHED_CANON_LEN`] (fixed-
/// width), mirroring [`crate::exittel::canon_len`].
#[inline]
#[must_use]
pub fn canon_len(_rec: &SchedDecision) -> usize {
    SCHED_CANON_LEN
}

/// Canonical, UNAMBIGUOUS, total fixed-width LE encoding of `rec` into `out`. Returns
/// the bytes written ([`SCHED_CANON_LEN`]), or `0` if `out` is too small (TOTAL + fail-
/// closed, never panics, never partial-writes). INJECTIVE: every field at a fixed offset.
#[must_use]
pub fn canon(rec: &SchedDecision, out: &mut [u8]) -> usize {
    if out.len() < SCHED_CANON_LEN {
        return 0;
    }
    let fs = rec.frame_seq.to_le_bytes();
    let vf = rec.vmid_from.to_le_bytes();
    let vt = rec.vmid_to.to_le_bytes();
    let tl = rec.t_logical.to_le_bytes();
    let mut i = 0usize;
    while i < 8 {
        out[OFF_FRAME_SEQ + i] = fs[i];
        out[OFF_TLOGICAL + i] = tl[i];
        i += 1;
    }
    out[OFF_SLOT] = rec.slot;
    out[OFF_VMID_FROM] = vf[0];
    out[OFF_VMID_FROM + 1] = vf[1];
    out[OFF_VMID_TO] = vt[0];
    out[OFF_VMID_TO + 1] = vt[1];
    SCHED_CANON_LEN
}

/// The exact inverse of [`canon`]: decode `buf` into a [`SchedDecision`], or `None` if
/// `buf` is too small (TOTAL + fail-closed). A successful decode round-trips back to
/// identical canonical bytes (the `kani_tpsched_canon_roundtrip` harness).
#[must_use]
pub fn decode(buf: &[u8]) -> Option<SchedDecision> {
    if buf.len() < SCHED_CANON_LEN {
        return None;
    }
    let frame_seq = u64::from_le_bytes([
        buf[OFF_FRAME_SEQ],
        buf[OFF_FRAME_SEQ + 1],
        buf[OFF_FRAME_SEQ + 2],
        buf[OFF_FRAME_SEQ + 3],
        buf[OFF_FRAME_SEQ + 4],
        buf[OFF_FRAME_SEQ + 5],
        buf[OFF_FRAME_SEQ + 6],
        buf[OFF_FRAME_SEQ + 7],
    ]);
    let t_logical = u64::from_le_bytes([
        buf[OFF_TLOGICAL],
        buf[OFF_TLOGICAL + 1],
        buf[OFF_TLOGICAL + 2],
        buf[OFF_TLOGICAL + 3],
        buf[OFF_TLOGICAL + 4],
        buf[OFF_TLOGICAL + 5],
        buf[OFF_TLOGICAL + 6],
        buf[OFF_TLOGICAL + 7],
    ]);
    Some(SchedDecision {
        frame_seq,
        slot: buf[OFF_SLOT],
        vmid_from: u16::from_le_bytes([buf[OFF_VMID_FROM], buf[OFF_VMID_FROM + 1]]),
        vmid_to: u16::from_le_bytes([buf[OFF_VMID_TO], buf[OFF_VMID_TO + 1]]),
        t_logical,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> FramePlan {
        FramePlan {
            slot_ticks: [1000, 2000],
            vmid: [1, 2],
        }
    }

    fn sample() -> SchedDecision {
        SchedDecision {
            frame_seq: 7,
            slot: 1,
            vmid_from: 1,
            vmid_to: 2,
            t_logical: 0xCAFE,
        }
    }

    #[test]
    fn next_slot_round_robin() {
        assert_eq!(next_slot(0), 1);
        assert_eq!(next_slot(1), 0);
        assert_eq!(next_slot(99), 0); // fail-closed
                                      // Neither slot is a fixed point (liveness).
        assert_ne!(next_slot(0), 0);
        assert_ne!(next_slot(1), 1);
    }

    #[test]
    fn slot_deadline_clamps_and_frame_conserves() {
        let p = plan();
        assert_eq!(slot_deadline_delta(&p, 0), 1000);
        assert_eq!(slot_deadline_delta(&p, 1), 2000);
        assert_eq!(slot_deadline_delta(&p, 99), MIN_SLOT_TICKS); // fail-closed
        assert_eq!(frame_total(&p), 3000);
        // A zero-budget slot is clamped UP so it never starves.
        let z = FramePlan {
            slot_ticks: [0, 5],
            vmid: [1, 2],
        };
        assert_eq!(slot_deadline_delta(&z, 0), MIN_SLOT_TICKS);
        assert_eq!(frame_total(&z), MIN_SLOT_TICKS + 5);
        // Saturating: a pathological budget cannot overflow the frame.
        let big = FramePlan {
            slot_ticks: [u64::MAX, u64::MAX],
            vmid: [1, 2],
        };
        assert_eq!(frame_total(&big), u64::MAX);
    }

    #[test]
    fn canon_roundtrip_and_fixed_width() {
        assert_eq!(SCHED_CANON_LEN, 21);
        let e = sample();
        let mut buf = [0u8; 32];
        assert_eq!(canon(&e, &mut buf), SCHED_CANON_LEN);
        assert_eq!(decode(&buf), Some(e));
        let mut small = [0u8; SCHED_CANON_LEN - 1];
        assert_eq!(canon(&e, &mut small), 0); // fail-closed
        assert!(small.iter().all(|&b| b == 0));
    }

    fn enc(e: &SchedDecision) -> [u8; SCHED_CANON_LEN] {
        let mut b = [0u8; SCHED_CANON_LEN];
        assert_eq!(canon(e, &mut b), SCHED_CANON_LEN);
        b
    }

    #[test]
    fn canon_injective_each_field() {
        let base = sample();
        let b = enc(&base);
        let mut f = base;
        f.frame_seq ^= 1;
        assert_ne!(enc(&f), b);
        let mut s = base;
        s.slot ^= 1;
        assert_ne!(enc(&s), b);
        let mut vf = base;
        vf.vmid_from ^= 1;
        assert_ne!(enc(&vf), b);
        let mut vt = base;
        vt.vmid_to ^= 1;
        assert_ne!(enc(&vt), b);
        let mut t = base;
        t.t_logical ^= 1;
        assert_ne!(enc(&t), b);
    }

    #[test]
    fn fold_is_tamper_sensitive_via_prov() {
        let e0 = sample();
        let mut e1 = sample();
        e1.frame_seq = 8;
        let mut scratch = [0u8; SCHED_CANON_LEN + 8];
        let n0 = canon(&e0, &mut scratch);
        let id0 = sched_hash(&scratch[..n0]);
        let n1 = canon(&e1, &mut scratch);
        let id1 = sched_hash(&scratch[..n1]);
        let head = sched_recompute(id0, &[id1]);
        assert!(sched_verify_inclusion(id0, &[id1], head));
        let mut tampered = [0u8; SCHED_CANON_LEN];
        assert_eq!(canon(&e0, &mut tampered), SCHED_CANON_LEN);
        tampered[OFF_SLOT] ^= 0x01;
        let bad = sched_hash(&tampered);
        assert!(!sched_verify_inclusion(bad, &[id1], head));
    }
}
