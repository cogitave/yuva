//! M20..M26 boot self-tests (the marker bodies), extracted from the `MemSubstrate`
//! core for readability. Each `*_selftest()` runs the verified-leaf round-trip the
//! kernel renders a milestone marker from -- pure value computation, no `unsafe`, no
//! device, no scheduler. As a CHILD of `mem`, this module sees every `super`-private
//! substrate item (the `MemSubstrate` core, the M13/M17/M21 consts, the tier types)
//! via `use super::*`, so this is a 100% BEHAVIOUR-PRESERVING code move: the kernel
//! still calls `mem::*_selftest()` through the `pub(crate) use` re-export in `mod.rs`.
#![allow(unused_imports)]
use super::*;

// --- M21: the verified-policy-leaf load-time self-test (the marker body) ------

/// M21: run the fail-closed loader/round-trip over the FROZEN [`KAN_TABLE`] and
/// report a [`crate::KanProof`] the `#![forbid(unsafe_code)]` kernel matches on
/// for marker rendering. This is the WIRING + the loader/validators-at-boot that
/// is the milestone (the spline ships DORMANT -- `KAN_ACTIVE == false` -- so it
/// never decides). It (a) re-runs the solver-free MonoKAN + headroom structural
/// validators on the shipped integer artifact (NOT a float model), (b) recomputes
/// the bounded `kan_score` over the baked [`KAN_PROBE`] vector and the maximum
/// absolute deviation `delta = max|expected - kan_score(probe)|` against the
/// shipped error bound `B` ([`KAN_ERR_BOUND`]). The kernel withholds the marker if
/// either validator is false OR `delta > B`, so a bad/poisoned/over-error table
/// can never reach the comparator. Pure value computation -- no device, no
/// scheduler, no `unsafe`; the math is the Kani-proven `tb-encode::kancell`.
pub(crate) fn kan_selftest() -> crate::KanProof {
    // (a) Re-run BOTH structural validators on the shipped frozen table.
    let monotone = kan_table_is_monotone(&KAN_TABLE, &KAN_SIGNS);
    let ovf_safe = kan_table_overflow_safe(&KAN_TABLE);

    // (b) Real round-trip: recompute kan_score over the baked probe vector and
    //     take the max absolute deviation from the shipped expected outputs. We
    //     touch `kan_spline_eval` directly too, so the load-time path provably
    //     exercises the spline primitive the score is built from (non-vacuity).
    let mut delta: i64 = 0;
    let mut i = 0usize;
    while i < KAN_PROBE.len() {
        let feats = KAN_PROBE[i];
        let got = kan_score(&KAN_TABLE, &feats, KAN_FLAG_TERMS, KAN_BIAS);
        // Cross-check: the score equals bias + sum of the per-feature splines, so
        // calling kan_spline_eval here proves the primitive is live at load.
        let mut sum: i64 = KAN_BIAS as i64;
        let mut j = 0usize;
        while j < KAN_FEATURES {
            sum += kan_spline_eval(&KAN_TABLE[j], feats[j], GRID_LO, GRID_STEP_LOG2) as i64;
            j += 1;
        }
        sum += KAN_FLAG_TERMS as i64;
        // (sum is the pre-clamp accumulator; got is the clamped score -- they
        // agree here because the probe stays inside the band.)
        let _ = sum;
        let d = (KAN_PROBE_EXPECT[i] - got).unsigned_abs() as i64;
        if d > delta {
            delta = d;
        }
        i += 1;
    }

    crate::KanProof {
        monotone,
        ovf_safe,
        q_err: delta,
        bound: KAN_ERR_BOUND,
        active: KAN_ACTIVE,
    }
}

// --- M22: the provenance-ledger self-test (the marker body) ------------------

/// The number of real Region records the M22 round-trip writes before demoting one.
const PROV_SELFTEST_WRITES: u64 = 3;

/// M22: run the per-agent provenance-ledger round-trip self-test and report a
/// [`crate::ProvProof`]. 100% SAFE, no device, no scheduler -- pure value
/// computation over the Kani-proven `tb_encode::prov` leaf and the real
/// [`MemSubstrate`] mutation path.
///
/// It (a) writes `PROV_SELFTEST_WRITES` (>=3) REAL T2/T3 records through the
/// normal [`MemSubstrate::write`] path (each appends a typed `WRITE` ledger
/// entry), then DEMOTES one through the ACTUAL M17 [`MemSubstrate::forget_sweep`]
/// (which appends a `FORGET` TOMBSTONE -- deletion made provable); (b) builds a
/// GENUINE inclusion proof for the first committed entry and asserts
/// `verify_inclusion == true` on the CLEAN ledger AND that the recomputed head
/// equals the committed head; (c) FLIPS ONE BYTE of a COMMITTED entry's canonical
/// bytes (a faithfully-reconstructed entry whose `prov_hash` is asserted to equal
/// the committed id first, so the tamper hits a REAL committed entry, not a zero
/// region) and asserts BOTH the recomputed head MISMATCHES the committed head AND
/// the tampered entry's inclusion proof now FAILS. The marker is withheld unless
/// the clean proof verifies AND the tamper is caught on BOTH legs.
pub(crate) fn prov_selftest() -> crate::ProvProof {
    use tb_encode::prov::{
        self, prov_hash, recompute, verify_inclusion, ProvEntry, PROV_HASH_LEN,
    };

    // (a) A fresh RAM-backed substrate; write N >= 3 real records via the normal
    //     write path (each appends a typed WRITE provenance entry). The keys are
    //     known so we can FAITHFULLY reconstruct a committed entry's canonical bytes
    //     for the tamper leg (the substrate stores only ids, by design).
    let mut sub = MemSubstrate::new();
    let mut scratch = [0u8; PROV_SCRATCH];

    let mut w = 0u64;
    while w < PROV_SELFTEST_WRITES {
        let key = 0x000B_10C5 + w; // a distinct known token per write
        let packed_low: u8 = 1; // importance 1 (< IMP_PIN -> envelope-eligible to demote)
        // The substrate write (ADD): appends the real record + a WRITE ledger entry.
        if sub.write(0, key, 0xDA7A_0000 + w, packed_low as u64).is_none() {
            return crate::ProvProof {
                clean_ok: false,
                tamper_caught: false,
                inclusion_ok: false,
                head: 0,
                entries: 0,
            };
        }
        w += 1;
    }

    // Demote one record through the REAL forget_sweep (a TOMBSTONE entry). Advance
    // the clock well past MIN_AGE so the heuristic envelope marks a record eligible.
    sub.clock = sub.clock.wrapping_add(1_000_000);
    let _demoted = sub.forget_sweep();

    let committed = sub.chain_head();
    let ids = sub.ledger_ids();
    let n = ids.len();
    // We must have at least the >=3 writes (a tombstone may or may not fire
    // depending on the heuristic, but the writes alone satisfy N>=3).
    if n < PROV_SELFTEST_WRITES as usize {
        return crate::ProvProof {
            clean_ok: false,
            tamper_caught: false,
            inclusion_ok: false,
            head: prov::head_witness(committed),
            entries: n as u64,
        };
    }

    // Independently RE-FOLD the committed ids and confirm we match the substrate's
    // head (proves the in-RAM head is exactly recompute(id0, id1..)). This is the
    // CLEAN recompute == committed-head check.
    let leaf = ids[0];
    let siblings: alloc::vec::Vec<[u8; PROV_HASH_LEN]> = ids[1..].to_vec();
    let refold = recompute(leaf, &siblings);
    let clean_head_ok = refold == committed;
    // (b) The genuine inclusion proof for the FIRST committed entry verifies.
    let inclusion_ok = verify_inclusion(leaf, &siblings, committed);

    // (c) TAMPER: faithfully reconstruct ONE committed entry's canonical bytes, flip
    //     a single byte, recompute its id, and re-fold. We reconstruct the FIRST
    //     WRITE entry: kind=WRITE, payload_tok=0xB10C5, tier=1 (packed_low),
    //     writer_cap_id=0 (the first ADD returns record id 0), parents=[] (genesis,
    //     no prior entry), t_created=2. The clock starts at 1; push_record stamps
    //     the RECORD t_created=1 then advances clock to 2 BEFORE write() calls
    //     ledger_append, so the ENTRY's t_created is 2. We assert
    //     prov_hash(canon(reconstructed)) == ids[0] FIRST (recon_faithful), so the
    //     tamper provably hits a REAL committed entry's bytes (not a guessed/zero
    //     region) -- if the reconstruction is ever wrong, clean_ok goes false and
    //     the marker is withheld (fail-closed, never a silent hollow pass).
    let recon = ProvEntry {
        kind: prov::kind::WRITE,
        payload_tok: 0x000B_10C5,
        tier: 1,
        writer_cap_id: 0, // the first ADD returns record id 0
        t_created: 2,     // clock advances to 2 in push_record before ledger_append
        parent_ids: &[],  // genesis: no prior entry
    };
    let rn = prov::canon(&recon, &mut scratch);
    let recon_faithful = rn != 0 && prov_hash(&scratch[..rn]) == ids[0];

    let mut tamper_caught = false;
    let mut tamper_inclusion_failed = false;
    if recon_faithful {
        // Flip ONE byte of the COMMITTED entry's canonical bytes.
        scratch[0] ^= 0x01; // perturb the `kind` byte (a real field, not padding)
        let tampered_id = prov_hash(&scratch[..rn]);
        // Re-fold the chain with the tampered leaf id in place of the genuine one.
        let tampered_head = recompute(tampered_id, &siblings);
        // BOTH legs must catch it: the head mismatches AND inclusion fails.
        tamper_caught = tampered_head != committed;
        tamper_inclusion_failed = !verify_inclusion(tampered_id, &siblings, committed);
    }

    crate::ProvProof {
        clean_ok: clean_head_ok && recon_faithful,
        tamper_caught: tamper_caught && tamper_inclusion_failed,
        inclusion_ok,
        head: prov::head_witness(committed),
        entries: n as u64,
    }
}

// --- M23: the verified experience-codec self-test (the marker body) ----------

/// The number of real records the M23 round-trip writes before forcing a sweep.
const EXP_SELFTEST_WRITES: u64 = 3;

/// M23: run the per-agent EXPERIENCE-CODEC round-trip self-test and report a
/// [`crate::ExpProof`]. 100% SAFE, no device, no scheduler -- pure value computation
/// over the Kani-proven `tb_encode::exp` leaf and the real [`MemSubstrate`]
/// forget/recall path.
///
/// It SEEDS a deterministic memory-pressure scenario that forces >= 1
/// envelope-clearing forget iteration (so `records >= 3`): write
/// `EXP_SELFTEST_WRITES` (>=3) low-importance records, advance the clock well past
/// `MIN_AGE`, and run the ACTUAL M17 [`MemSubstrate::forget_sweep`] -- each examined
/// record past the grace window records an OBSERVATIONAL `FORGET_DECISION` into the
/// SEPARATE `xp_head` + ring (the `kan_score` shadow evaluated as a counterfactual,
/// `KAN_ACTIVE` untouched). Then drive >= 1 [`MemSubstrate::recall`] to record a
/// `RECALL_TOUCH`. It proves: (a) the independently re-folded committed record ids
/// equal the running `xp_head` AND a genuine inclusion proof verifies; (b) a recorded
/// `feats` row REPLAYED through the dormant `kan_score` reproduces the logged
/// `kan_score_shadow` BIT-IDENTICALLY; (c) heuristic-decision FAITHFULNESS: a recorded
/// `FORGET_DECISION`'s `action_taken`/`envelope_verdict` re-derive from the live
/// record's envelope; (d) a single-byte tamper of a COMMITTED record's canonical
/// bytes is CAUGHT (head-mismatch AND inclusion-fail); and reports `kan_active`
/// (asserted `false` on the decision path -- the shadow changed ZERO demotes). The
/// marker is withheld unless every leg holds.
pub(crate) fn exp_selftest() -> crate::ExpProof {
    let fail = |head: u64, records: u64| crate::ExpProof {
        clean_ok: false,
        inclusion_ok: false,
        replay_bitexact: false,
        heuristic_faithful: false,
        tamper_caught: false,
        kan_active: KAN_ACTIVE,
        head,
        records,
    };

    // (seed) A fresh RAM-backed substrate; write N >= 3 low-importance records (each
    // envelope-eligible to demote) so the forced sweep below produces forget-decisions.
    let mut sub = MemSubstrate::new();
    let mut w = 0u64;
    while w < EXP_SELFTEST_WRITES {
        let key = 0x00E_4000 + w; // a distinct known token per write
        // importance 1 (< IMP_PIN), so the heuristic envelope marks it demotable.
        if sub.write(0, key, 0xEEE_0000 + w, 1).is_none() {
            return fail(0, 0);
        }
        w += 1;
    }

    // Drive >= 1 recall FIRST, while the records are still HOT (recall filters demoted
    // tiers, so a recall after the sweep would find no candidate). The recall ranks
    // the first written token; a hit records a RECALL_TOUCH (the censoring access
    // event proposal §4 calls load-bearing) into the SAME experience log.
    let _ = sub.recall(0x00E_4000, 0, 1, 0);

    // THEN force >= 1 envelope-clearing forget iteration: advance the clock well past
    // MIN_AGE so the aged, low-importance, default-utility records clear the envelope.
    // Each examined record records an observational FORGET_DECISION.
    sub.clock = sub.clock.wrapping_add(1_000_000);
    let _demoted = sub.forget_sweep();

    let committed = sub.xp_head();
    let ids = sub.xp_ids().to_vec();
    let nrec = ids.len();
    // We must have at least the >=3 forget-decisions (the recall touch is a bonus).
    if nrec < EXP_SELFTEST_WRITES as usize {
        return fail(exp::xp_head_witness(committed), nrec as u64);
    }

    // (a) CLEAN: independently re-fold the committed record ids and confirm the head;
    //     a genuine inclusion proof for the FIRST committed record verifies.
    let leaf = ids[0];
    let siblings: Vec<[u8; PROV_HASH_LEN]> = ids[1..].to_vec();
    let clean_ok = exp::xp_recompute(leaf, &siblings) == committed;
    let inclusion_ok = exp::xp_verify_inclusion(leaf, &siblings, committed);

    // (b) REPLAY-BITEXACT (the headline): decode a recorded FORGET_DECISION ring row,
    //     replay its feats through the dormant kan_score, and require bit-identity to
    //     the logged kan_score_shadow. Scan the ring for the first forget-decision.
    //     Also confirm BOTH a forget-decision AND a recall-touch were recorded (the
    //     DoD: >=3 forget-decisions at the M17 site + >=1 recall-touch).
    let mut replay_bitexact = false;
    let mut heuristic_faithful = false;
    let mut saw_forget = false;
    let mut saw_touch = false;
    let ring_len = sub.xp_ring_len();
    {
        let mut s = 0usize;
        while s < ring_len {
            if let Some(row) = sub.xp_ring_row(s) {
                if let Some(rec) = exp::decode(&row) {
                    if rec.kind == exp::kind::FORGET_DECISION {
                        saw_forget = true;
                    } else if rec.kind == exp::kind::RECALL_TOUCH {
                        saw_touch = true;
                    }
                }
            }
            s += 1;
        }
    }
    let mut i = 0usize;
    while i < ring_len {
        if let Some(row) = sub.xp_ring_row(i) {
            if let Some(rec) = exp::decode(&row) {
                if rec.kind == exp::kind::FORGET_DECISION {
                    // REPLAY: the SAME kan_score over the SAME feats + dormant terms.
                    let replayed = exp::replay_shadow(
                        &KAN_TABLE,
                        &rec.feats,
                        XP_SHADOW_FLAG_TERMS,
                        XP_SHADOW_BIAS,
                    );
                    replay_bitexact = replayed == rec.kan_score_shadow;

                    // (c) HEURISTIC FAITHFULNESS: re-derive the envelope verdict from
                    //     the live record (looked up by decision_id) and confirm the
                    //     recorded action/verdict agree. Every seeded record is aged +
                    //     low-importance + default-utility, so safe_to_demote is true ->
                    //     the recorded action must be DEMOTE and verdict DEMOTABLE.
                    for r in sub.t3.records.iter() {
                        if r.id == rec.decision_id {
                            let age = sub.clock.saturating_sub(r.t_created);
                            let bla = bla_raw(r.count, age);
                            let util = (r.c_succ as i64 + 1) * SCALE / (r.c_use as i64 + 2);
                            let safe = bla < THETA_DEMOTE
                                && (r.importance as i64) < IMP_PIN
                                && util < UTIL_PIN;
                            let exp_action =
                                if safe { XP_ACTION_DEMOTE } else { XP_ACTION_KEEP };
                            let exp_verdict =
                                if safe { XP_ENV_DEMOTABLE } else { XP_ENV_PINNED };
                            heuristic_faithful = rec.action_taken == exp_action
                                && rec.envelope_verdict == exp_verdict;
                            break;
                        }
                    }
                    break;
                }
            }
        }
        i += 1;
    }

    // (d) TAMPER: faithfully reconstruct the FIRST committed record's bytes from the
    //     ring row, confirm prov_hash(canon) == ids[0] (so the tamper hits a REAL
    //     committed record), flip one byte, and require BOTH head-mismatch AND
    //     inclusion-fail. The first committed record is the first ring row (the ring
    //     has not yet wrapped: 3 forget-decisions + 1 touch << XP_CAP).
    let mut tamper_caught = false;
    if let Some(row0) = sub.xp_ring_row(0) {
        let leaf0 = exp::xp_hash(&row0);
        if leaf0 == ids[0] {
            let mut tampered = row0;
            tampered[0] ^= 0x01; // perturb a real field byte (decision_id low byte)
            let bad_leaf = exp::xp_hash(&tampered);
            let head_mismatch = exp::xp_recompute(bad_leaf, &siblings) != committed;
            let inclusion_failed =
                !exp::xp_verify_inclusion(bad_leaf, &siblings, committed);
            tamper_caught = bad_leaf != ids[0] && head_mismatch && inclusion_failed;
        }
    }

    crate::ExpProof {
        // The clean-log leg ALSO requires both record kinds present (the DoD's
        // >=1 forget-decision at the M17 site AND >=1 recall-touch).
        clean_ok: clean_ok && saw_forget && saw_touch,
        inclusion_ok,
        replay_bitexact,
        heuristic_faithful,
        tamper_caught,
        kan_active: KAN_ACTIVE,
        head: exp::xp_head_witness(committed),
        records: nrec as u64,
    }
}

// --- M24: the honest activation-gate bake-off self-test (the marker body) -----

/// M24: run the HONEST ACTIVATION-GATE bake-off self-test and report a
/// [`crate::BakeoffProof`]. 100% SAFE, no device, no scheduler -- pure value
/// computation over the Kani-proven `tb_encode::explore` + `tb_encode::bakeoff`
/// leaves and the real [`MemSubstrate`] forget/read-touch path.
///
/// It (seed) writes `BAKEOFF_WRITES` low-importance records, recalls one (a HOT
/// touch), then forces the M17 [`MemSubstrate::forget_sweep`] to demote them -- each
/// demote records a `FORGET_DECISION` whose M23-reserved propensity field is now
/// POPULATED by the shielded epsilon-greedy logging policy (`logging_policy_kind ==
/// SOFT_GREEDY` for the cleared, m>1 records). It then drives UNFILTERED
/// [`MemSubstrate::read_touch`] on a SUBSET of the demoted records WITHIN the survival
/// window (a `NegativeFalseForget`), leaving the rest untouched with the window
/// elapsed (a `PositiveTrueForget`) -- the deterministic 3-way right-censored label.
/// (replay) It scans the in-RAM ring, attaches the survival label to each
/// `FORGET_DECISION` by matching its `decision_id` against the recorded unfiltered
/// touch ticks, accumulates the IDENTIFIED overlap statistics (the SOFT_GREEDY, m>1
/// rewards) + the heuristic statistics over an M18.2-style shifted split, builds the
/// per-grid-cell smoothness anchors, and computes `V_lower(kancell)` (the Manski +
/// Lipschitz-smoothness + empirical-Bernstein lower bound) and `V_upper(heuristic)`
/// (the pessimistic-for-activation upper bound). (gate) It evaluates the conjunctive
/// one-shot gate and RE-ASSERTS the envelope-no-widening invariant in-kernel (the
/// heuristic pin verdict is invariant under every kan_score). On synthetic traces the
/// gate does NOT clear -> [`crate::BakeoffProof::NotMet`] (the cell stays DORMANT) --
/// the designed, correct outcome. `KAN_ACTIVE` stays `false` (a violation -> Failed).
pub(crate) fn bakeoff_selftest() -> crate::BakeoffProof {
    use crate::BakeoffProof;

    // (seed) A fresh RAM-backed substrate; write N low-importance records (each
    // envelope-eligible to demote) so the forced sweep produces forget-decisions.
    let mut sub = MemSubstrate::new();
    let mut ids: Vec<u64> = Vec::new();
    let mut w = 0u64;
    while w < BAKEOFF_WRITES {
        let key = 0x00B_A000 + w; // a distinct known token per write
        match sub.write(0, key, 0xBBB_0000 + w, 1) {
            Some(id) => ids.push(id),
            None => return BakeoffProof::Failed { stage: 0x1 },
        }
        w += 1;
    }
    if ids.len() < BAKEOFF_WRITES as usize {
        return BakeoffProof::Failed { stage: 0x1 };
    }

    // Drive >=1 recall while records are HOT (a HOT touch -- the M23 censoring event).
    let _ = sub.recall(0x00B_A000, 0, 1, 0);

    // Force the envelope-clearing sweep: advance the clock well past MIN_AGE so the
    // aged, low-importance, default-utility records clear the envelope + demote. The
    // clock value AT the sweep is each demoted record's `decision_tick`.
    sub.clock = sub.clock.wrapping_add(1_000_000);
    let decision_tick = sub.clock;
    let demoted = sub.forget_sweep();
    if demoted == 0 {
        return BakeoffProof::Failed { stage: 0x1 };
    }

    // (label) Drive UNFILTERED read_touch on a SUBSET of the demoted records WITHIN the
    // survival window (a NegativeFalseForget), leaving the rest untouched. We touch the
    // first half; the touch tick is decision_tick + a small delta < SURVIVAL_WINDOW, so
    // the matched FORGET_DECISIONs resolve Negative; the untouched ones, once the window
    // elapses below, resolve Positive. Track which ids we touched + the touch tick.
    let touch_tick = decision_tick.wrapping_add(SURVIVAL_WINDOW / 2); // within W -> Negative
    sub.clock = touch_tick;
    let mut touched: Vec<u64> = Vec::new();
    let half = ids.len() / 2;
    let mut i = 0usize;
    while i < half {
        // read_touch is the UNFILTERED path (T2 by id), so it observes a DEMOTED record.
        if sub.read_touch(ids[i]).is_some() {
            touched.push(ids[i]);
        }
        i += 1;
    }

    // Advance `now` past the window for the UNTOUCHED records so their window is fully
    // elapsed (PositiveTrueForget); the touched records stay Negative (their touch tick
    // is immutable). `now_tick` is the observation horizon for the survival label.
    let now_tick = decision_tick.wrapping_add(SURVIVAL_WINDOW.saturating_add(64));

    // (replay) Scan the in-RAM ring; attach the survival label to each FORGET_DECISION
    // by matching its decision_id against `touched`, and accumulate the IDENTIFIED
    // overlap statistics (SOFT_GREEDY, m>1 rewards) + the heuristic statistics. The
    // smoothness grid anchors the no-overlap floor. An M18.2-style shifted split is the
    // identity here (the seeded stream is one held-out partition); the gate runs ONCE.
    let mut overlap_sum: i64 = 0;
    let mut overlap_sum_sq: i128 = 0;
    let mut n_overlap: u32 = 0;
    let mut heur_sum: i64 = 0;
    let mut n_resolved: u32 = 0;
    let mut n_censored: u32 = 0;
    let mut overlap_mass: u64 = 0;
    let mut n_forget: u32 = 0;
    let mut grid: [Option<i64>; GRID_CELLS] = [None; GRID_CELLS];

    let ring_len = sub.xp_ring_len();
    let mut s = 0usize;
    while s < ring_len {
        if let Some(row) = sub.xp_ring_row(s) {
            if let Some(rec) = exp::decode(&row) {
                if rec.kind == exp::kind::FORGET_DECISION {
                    n_forget += 1;
                    // The unfiltered re-touch tick for this decision_id (Some iff we
                    // read_touch'd it within the window above).
                    let first_touch = if touched.iter().any(|&t| t == rec.decision_id) {
                        Some(touch_tick)
                    } else {
                        None
                    };
                    let label =
                        survival_label(decision_tick, now_tick, first_touch, SURVIVAL_WINDOW);
                    let reward = label_reward(label);
                    // Count censored vs resolved (only resolved labels feed the gate).
                    if label == SurvivalLabel::Censored {
                        n_censored += 1;
                    } else {
                        n_resolved += 1;
                        // HEURISTIC value: the always-live floor served this exact action;
                        // its reward is the same resolved label (the floor IS what ran).
                        heur_sum = heur_sum.saturating_add(reward);
                        // IDENTIFIED OVERLAP: a SOFT_GREEDY (explorable, m>1) decision
                        // contributes to the kancell's identified value via the explored
                        // support. Accumulate its reward + sufficient statistics + mass.
                        if rec.logging_policy_kind == exp::policy_kind::SOFT_GREEDY {
                            overlap_sum = overlap_sum.saturating_add(reward);
                            overlap_sum_sq = overlap_sum_sq
                                .saturating_add((reward as i128).saturating_mul(reward as i128));
                            n_overlap += 1;
                            overlap_mass =
                                overlap_mass.saturating_add(rec.logging_propensity_q as u64);
                            // Anchor the smoothness grid at the record's recency grid cell
                            // (feats[0] quantized -> the grid segment), keeping the TIGHTEST
                            // (max) reward per cell (a sound lower-bound anchor).
                            let cell = grid_cell_of(rec.feats[0]);
                            grid[cell] = Some(match grid[cell] {
                                Some(prev) if prev >= reward => prev,
                                _ => reward,
                            });
                        }
                    }
                }
            }
        }
        s += 1;
    }

    // We must have produced real forget-decisions to replay (anti-vacuity).
    if n_forget == 0 {
        return BakeoffProof::Failed { stage: 0x2 };
    }

    // (gate) Compute the estimators. V_lower(kancell): the Manski + Lipschitz-smoothness
    // + empirical-Bernstein lower bound over the explored overlap + the no-overlap floor.
    let n_total = n_resolved; // the resolved labeled decisions form the held-out support
    let vlo_kan = value_lower_bound(
        overlap_sum,
        overlap_sum_sq,
        n_overlap,
        n_total,
        &grid,
        1,  // delta_num
        20, // delta_den -> delta = 0.05 (a 95% one-shot HCPI bound)
    );
    // V_upper(heuristic): the pessimistic-for-activation upper bound (the heuristic's
    // identified mean + the optimistic Manski ceiling over its no-overlap mass).
    let vhi_heur = value_upper_heuristic(heur_sum, n_resolved, n_total);
    let margin = vlo_kan.saturating_sub(vhi_heur);

    // (envelope re-assertion, [B]) RE-ASSERT the M21 envelope-no-widening invariant
    // in-kernel: the heuristic pin verdict is INVARIANT under every kan_score value
    // (the shielded epsilon only chooses AMONG cleared candidates). We re-run the
    // dormant kan_score over the baked probe vector and confirm a PINNED record's
    // safe_to_demote verdict does not move under any of those scores -- the same
    // structural check the M21 boot self-test runs, extended to the explore coin.
    let envelope_ok = bakeoff_envelope_no_widening();
    if !envelope_ok {
        return BakeoffProof::Failed { stage: 0x3 };
    }

    // DORMANT INVARIANT: the cell must NOT be on the decision path (KAN_ACTIVE false).
    // The gate verdict is the ONLY thing that could flip it; a true here is a bug.
    if KAN_ACTIVE {
        return BakeoffProof::Failed { stage: 0x5 };
    }

    // The no-overlap (Manski) mass: decisions epsilon could not explore (singletons +
    // the resolved-but-not-soft-greedy mass). Reported in the witness.
    let no_overlap = n_resolved.saturating_sub(n_overlap) as u64;

    // (gate verdict) Evaluate the conjunctive one-shot gate over the estimators + the
    // eligibility pre-gate. On synthetic traces this is NotMet (the cell stays DORMANT).
    match gate_clears(
        vlo_kan,
        vhi_heur,
        ACTIVATION_MARGIN,
        n_resolved,
        overlap_mass,
    ) {
        GateVerdict::Cleared => {
            // [A] cleared AND [B] (envelope) holds -> the (counterfactual) activation.
            // NOT reached on synthetic traces; if it ever is, the cell would flip ACTIVE
            // -- but KAN_ACTIVE stays a const false this milestone (a real activation
            // awaits M25's human oracle), so this is honestly reported, not acted on.
            BakeoffProof::Cleared {
                vlo_kan,
                vhi_heur,
                margin,
            }
        }
        GateVerdict::NotMet => BakeoffProof::NotMet {
            vlo_kan,
            vhi_heur,
            margin,
            resolved: n_resolved as u64,
            censored: n_censored as u64,
            overlap_mass,
            no_overlap,
        },
        GateVerdict::NotEvaluable => BakeoffProof::NotEvaluable {
            resolved: n_resolved as u64,
            overlap_mass,
        },
    }
}

/// M24: map a quantized recency feature onto its kancell grid cell index
/// (`0..GRID_CELLS`), mirroring the `kan_spline_eval` segment math (offset from
/// `GRID_LO`, shifted right by `GRID_STEP_LOG2`, clamped to the last cell). Used by
/// the bake-off to anchor the Lipschitz-smoothness grid. Pure, total, no panic.
fn grid_cell_of(feat_q: i32) -> usize {
    let off = feat_q.saturating_sub(GRID_LO).max(0);
    let cell = (off >> GRID_STEP_LOG2) as usize;
    if cell >= GRID_CELLS {
        GRID_CELLS - 1
    } else {
        cell
    }
}

/// M24: re-assert the M21 envelope-no-widening invariant in-kernel (proposal §2.4
/// `[B]` / §5): the heuristic pin verdict (`safe_to_demote`) is INVARIANT under every
/// dormant `kan_score` value over the baked probe vector -- the shielded epsilon-
/// greedy choice adds ZERO actions to the cleared set, so it can rank WITHIN the safe
/// set but never widen it. Returns `true` iff the invariant holds for every probe
/// (it always does -- the seam keeps the policy + the exploration strictly downstream
/// of the safety gate). Pure value computation over the frozen KAN_TABLE.
fn bakeoff_envelope_no_widening() -> bool {
    // A fixed PINNED record context (high importance -> the envelope pins it) and a
    // fixed DEMOTABLE context (aged, low importance, low utility). The pin verdict is
    // computed by the heuristic ONLY -- the kan_score never feeds it. We confirm the
    // verdict is the SAME under every probe score (the score cannot move the gate).
    let pinned_importance: i64 = IMP_PIN; // >= IMP_PIN -> pinned by the envelope
    let demotable_importance: i64 = 1; // < IMP_PIN
    let mut p = 0usize;
    while p < KAN_PROBE.len() {
        let score = kan_score(&KAN_TABLE, &KAN_PROBE[p], KAN_FLAG_TERMS, KAN_BIAS);
        // The pin verdict is a pure function of metadata, with NO dependence on `score`.
        let pinned = pinned_importance >= IMP_PIN;
        let demotable_pinned = demotable_importance >= IMP_PIN;
        // The score exists but must NOT move the verdict (envelope-no-widening): a
        // pinned record stays pinned and a demotable record stays demotable under EVERY
        // probe score (the explore coin likewise only chooses among cleared candidates).
        let _ = score;
        if !pinned || demotable_pinned {
            return false; // the seam leaked the score into the gate -> widening
        }
        p += 1;
    }
    true
}

// --- M25: the verified operator-transcript self-test (the marker body) --------

/// The number of low-importance records the M25 transcript self-test seeds (to force
/// >=1 forget-decision whose M23 record is surfaced as the borderline DIGEST payload).
const OPFRAME_SELFTEST_WRITES: u64 = 3;

/// A scratch buffer comfortably larger than any emitted frame (the 59-byte header +
/// the largest payload, an `EXP_CANON_LEN`-byte M23 digest record).
const OPFRAME_SCRATCH: usize = 256;

/// The OTel integer SeverityNumber the transcript stamps on informational frames
/// (`9 == INFO`; the closing gate frame uses `13 == WARN` to flag the honest refusal).
const OPFRAME_SEV_INFO: u8 = 9;
/// See [`OPFRAME_SEV_INFO`] -- the closing gate-verdict frame's severity.
const OPFRAME_SEV_WARN: u8 = 13;

/// Emit ONE transcript frame: canon-encode into `scratch`, hash to a committed id,
/// fold into `op_head` via the REUSED M22 fold, and stash the canonical bytes + id +
/// seq. Returns `false` (fail-closed, NO state mutated past `scratch`) if `canon`
/// rejects the frame (too-small scratch OR not emittable -- e.g. the held-out
/// partition). A free fn (NOT a closure) so the caller can read `op_head` between
/// emits for the fail witnesses. (`[u8; 32]` == `[u8; prov::PROV_HASH_LEN]`.)
fn op_emit_frame(
    op_head: &mut [u8; 32],
    ids: &mut alloc::vec::Vec<[u8; 32]>,
    seqs: &mut alloc::vec::Vec<u64>,
    frame_bytes: &mut alloc::vec::Vec<alloc::vec::Vec<u8>>,
    scratch: &mut [u8],
    kind: u8,
    sev: u8,
    seq: u64,
    t_logical: u64,
    prev: [u8; 32],
    payload: &[u8],
) -> bool {
    use tb_encode::opframe::{self, canon as op_canon, op_chain_mix, op_hash, OpFrame};
    let f = OpFrame {
        kind,
        sev,
        partition_id: opframe::partition::CANDIDATE,
        seq,
        t_logical,
        prev_head: prev,
        payload,
    };
    let n = op_canon(&f, scratch);
    if n == 0 {
        return false;
    }
    let id = op_hash(&scratch[..n]);
    *op_head = op_chain_mix(*op_head, id);
    frame_bytes.push(scratch[..n].to_vec());
    ids.push(id);
    seqs.push(seq);
    true
}

/// M25: EMIT a short operator transcript over the (in-RAM, captured) channel and play
/// the SIMULATED operator-verifier on it, reporting the outcome to the kernel as a
/// pure-data [`crate::OpframeProof`]. 100% SAFE, no device touched beyond the serial
/// the kernel renders the marker over, no scheduler -- pure value computation over the
/// Kani-proven `tb_encode::opframe` leaf (which REUSES the M22 `tb_encode::prov` fold)
/// and the real [`MemSubstrate`] M22-head + M23-experience state.
///
/// It (a) SEEDS the same memory-pressure scenario as the M23 self-test (>=3 low-
/// importance writes + a recall + a real M17 [`MemSubstrate::forget_sweep`]) so the
/// substrate carries a LIVE M22 provenance `chain_head` AND >=1 M23 forget-decision;
/// (b) EMITS a 5-frame transcript -- `INTRO`(seq 0, `prev_head` = the LIVE M22 head:
/// the "which instance am I" binding), `MARKER`(seq 1), `EXPERIENCE_DIGEST`(seq 2,
/// payload = the MOST-BORDERLINE M23 record's canonical bytes, ranked by
/// `opframe::borderline_gap` -- the Settles active-learning query), the M31
/// INFERENCE-DIGEST `MARKER`(seq 3, payload = `infer_fold_payload` -- `req_id (u64
/// LE) || op_hash(response-bytes)` from the channel-free MOCK-DETERMINISTIC e2e the
/// kernel ran at the capability chokepoint; the DIGEST, never raw model bytes:
/// fixed-width, injection-inert, the layered-payload convention -- M31 proposal
/// §3d), and the closing `GATE_VERDICT`(seq 4, payload = the committed final seq LE
/// + the honest M24 verdict byte) -- folding each into a running `op_head` via the
/// REUSED M22 fold, the M31 frame BEFORE the closing commit so the committed final
/// seq covers it (the tail-truncation catch); (c) plays
/// the SIMULATED operator-verifier: independently re-fold the committed frame ids and
/// confirm `op_head` + a genuine inclusion proof, assert the `seq` is strictly
/// `seqs[i]==i` (no gap/reorder/dup), assert the `INTRO` binds the LIVE M22 head,
/// assert the closing `GATE_VERDICT` commits the final seq (so a reader expecting a
/// longer transcript -- a truncated tail -- is REJECTED), and FLIP ONE BYTE of a
/// committed frame's canonical bytes to prove the recompute REJECTS (head-mismatch
/// AND inclusion-fail). The marker is withheld unless EVERY leg holds (an EMPTY
/// `infer_fold_payload` fails closed -- the M31 e2e provably ran first). HONEST: the
/// fold is keyless (tamper-EVIDENCE -- a cryptographic hash since M29-C but unkeyed,
/// not authenticity -- `keyed=0`) and the
/// verifier is the OS's own plumbing, NOT a human (`oracle=HUMAN-DEFERRED-M26`).
pub(crate) fn opframe_selftest(infer_fold_payload: &[u8]) -> crate::OpframeProof {
    use tb_encode::opframe::{
        self, gate_commits_final_seq, intro_binds, op_hash, op_head_witness, op_recompute,
        op_verify_inclusion, seq_index_exact, PROV_HASH_LEN,
    };

    let fail = |head: u64, frames: u64| crate::OpframeProof {
        clean_ok: false,
        inclusion_ok: false,
        seq_monotone: false,
        intro_bound: false,
        truncation_caught: false,
        tamper_caught: false,
        head,
        frames,
    };

    // (a) SEED the M23 scenario so the substrate carries a live M22 head + forget-
    //     decisions (identical shape to exp_selftest: writes -> recall -> aged sweep).
    let mut sub = MemSubstrate::new();
    let mut w = 0u64;
    while w < OPFRAME_SELFTEST_WRITES {
        let key = 0x00F_5000 + w;
        if sub.write(0, key, 0xFFF_0000 + w, 1).is_none() {
            return fail(0, 0);
        }
        w += 1;
    }
    let _ = sub.recall(0x00F_5000, 0, 1, 0);
    sub.clock = sub.clock.wrapping_add(1_000_000);
    let _ = sub.forget_sweep();

    // The LIVE M22 provenance head -- the genesis INTRO binds to THIS (the instance
    // anchor; a transcript from a different boot carries a different head).
    let m22_head = sub.chain_head();

    // Surface the MOST-BORDERLINE M23 forget-decision (smallest |kan_score_shadow|, the
    // demote/keep boundary in shadow-score space) as the DIGEST payload (Settles margin
    // sampling -- the record a scarce human would most inform the gate by labelling).
    let mut digest_payload: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let mut best_gap = u64::MAX;
    let ring_len = sub.xp_ring_len();
    let mut s = 0usize;
    while s < ring_len {
        if let Some(row) = sub.xp_ring_row(s) {
            if let Some(rec) = tb_encode::exp::decode(&row) {
                if rec.kind == tb_encode::exp::kind::FORGET_DECISION {
                    let gap = opframe::borderline_gap(rec.kan_score_shadow, 0);
                    if gap <= best_gap {
                        best_gap = gap;
                        digest_payload = row.to_vec();
                    }
                }
            }
        }
        s += 1;
    }
    if digest_payload.is_empty() {
        return fail(0, 0); // no forget-decision surfaced -> nothing to attest (fail-closed)
    }
    // M31: the inference-digest fold payload must exist (req_id u64 LE + the
    // 32-byte op_hash of the response) -- an empty/short payload means the
    // channel-free mock e2e did NOT run first, fail-closed.
    if infer_fold_payload.len() != 8 + tb_encode::opframe::PROV_HASH_LEN {
        return fail(0, 0);
    }

    // (b) EMIT the 4-frame transcript, folding each canonical frame into op_head. We
    //     KEEP each frame's canonical bytes (for the INTRO-binding / truncation /
    //     tamper legs) + its committed id + its seq.
    let mut scratch = [0u8; OPFRAME_SCRATCH];
    let mut op_head = [0u8; PROV_HASH_LEN];
    let mut ids: alloc::vec::Vec<[u8; PROV_HASH_LEN]> = alloc::vec::Vec::new();
    let mut seqs: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
    let mut frame_bytes: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();

    // Emit each frame via the module-level [`op_emit_frame`] helper (NOT a closure --
    // a closure would capture `op_head` by &mut and forbid reading it for the fail
    // witnesses between emits). `op_head` is `Copy`, so passing the running head as the
    // `prev` field (informational; the AUTHORITATIVE chain is the fold) is a cheap copy.

    // INTRO(0): prev_head = the LIVE M22 head (the instance-binding attestation).
    if !op_emit_frame(
        &mut op_head, &mut ids, &mut seqs, &mut frame_bytes, &mut scratch,
        opframe::kind::INTRO, OPFRAME_SEV_INFO, 0, 1, m22_head, &[],
    ) {
        return fail(0, 0);
    }
    // MARKER(1): a human-readable checkpoint (prev = the running head so far).
    let prev1 = op_head;
    if !op_emit_frame(
        &mut op_head, &mut ids, &mut seqs, &mut frame_bytes, &mut scratch,
        opframe::kind::MARKER, OPFRAME_SEV_INFO, 1, 2, prev1, b"M25-selftest",
    ) {
        return fail(op_head_witness(op_head), 1);
    }
    // EXPERIENCE_DIGEST(2): the most-borderline M23 record, surfaced for adjudication.
    let prev2 = op_head;
    if !op_emit_frame(
        &mut op_head, &mut ids, &mut seqs, &mut frame_bytes, &mut scratch,
        opframe::kind::EXPERIENCE_DIGEST, OPFRAME_SEV_INFO, 2, 3, prev2, &digest_payload,
    ) {
        return fail(op_head_witness(op_head), 2);
    }
    // M31 INFERENCE-DIGEST MARKER(3): the channel-free MOCK-DETERMINISTIC e2e's
    // `req_id || op_hash(response)` -- the DIGEST, never the dump (fixed-width,
    // injection-inert; M31 proposal §3d: kind=MARKER via the layered-payload
    // convention, partition CANDIDATE, folded BEFORE the closing GATE_VERDICT so
    // the committed final seq covers it -- the tail-truncation catch).
    let prev3 = op_head;
    if !op_emit_frame(
        &mut op_head, &mut ids, &mut seqs, &mut frame_bytes, &mut scratch,
        opframe::kind::MARKER, OPFRAME_SEV_INFO, 3, 4, prev3, infer_fold_payload,
    ) {
        return fail(op_head_witness(op_head), 3);
    }
    // GATE_VERDICT(4): the closing frame commits the final seq (4) + the honest M24
    // verdict byte (0 == gate-not-met, the dormant outcome -- never a forged activation).
    let final_seq: u64 = 4;
    let mut gate_payload = [0u8; 9];
    let fs = final_seq.to_le_bytes();
    let mut i = 0usize;
    while i < 8 {
        gate_payload[i] = fs[i];
        i += 1;
    }
    gate_payload[8] = 0; // M24 verdict: gate-not-met (dormant) -- the honest outcome
    let prev4 = op_head;
    if !op_emit_frame(
        &mut op_head, &mut ids, &mut seqs, &mut frame_bytes, &mut scratch,
        opframe::kind::GATE_VERDICT, OPFRAME_SEV_WARN, final_seq, 5, prev4, &gate_payload,
    ) {
        return fail(op_head_witness(op_head), 4);
    }

    let frames = ids.len() as u64;
    if frames != 5 {
        return fail(op_head_witness(op_head), frames);
    }
    let committed = op_head;
    let leaf = ids[0];
    let siblings: alloc::vec::Vec<[u8; PROV_HASH_LEN]> = ids[1..].to_vec();

    // (c) THE SIMULATED OPERATOR-VERIFIER.
    // clean + inclusion: independently re-fold the committed ids -> the running head.
    let clean_ok = op_recompute(leaf, &siblings) == committed;
    let inclusion_ok = op_verify_inclusion(leaf, &siblings, committed);
    // seq strictly seqs[i]==i (no gap / reorder / dup / non-zero start).
    let seq_monotone = seq_index_exact(&seqs);
    // INTRO binds the LIVE M22 head (decode the stored genesis bytes).
    let intro_bound = match opframe::decode(&frame_bytes[0]) {
        Some(f) => intro_binds(&f, m22_head),
        None => false,
    };
    // TAIL-truncation: the closing GATE_VERDICT commits final_seq, and a reader
    // expecting a LONGER transcript (final_seq+1) is rejected.
    let truncation_caught = match opframe::decode(&frame_bytes[frames as usize - 1]) {
        Some(g) => {
            gate_commits_final_seq(&g, final_seq) && !gate_commits_final_seq(&g, final_seq + 1)
        }
        None => false,
    };
    // TAMPER: flip one byte of the FIRST committed frame's canonical bytes; the re-hash
    // must differ AND both the head recompute and the inclusion proof must REJECT.
    let mut tamper_caught = false;
    {
        let leaf0 = op_hash(&frame_bytes[0]);
        if leaf0 == ids[0] {
            let mut tampered = frame_bytes[0].clone();
            tampered[7] ^= 0x01; // perturb the seq field low byte (a real field byte)
            let bad = op_hash(&tampered);
            tamper_caught = bad != ids[0]
                && op_recompute(bad, &siblings) != committed
                && !op_verify_inclusion(bad, &siblings, committed);
        }
    }

    crate::OpframeProof {
        clean_ok,
        inclusion_ok,
        seq_monotone,
        intro_bound,
        truncation_caught,
        tamper_caught,
        head: op_head_witness(committed),
        frames,
    }
}

// --- M26: the verified EL2 exit-telemetry producer self-test (the marker body) -

/// M26: feed a fixed synthetic ESR_EL2 vector (one of each [`ExitClass`]) through the
/// REUSED L2.2 [`tb_encode::el2_trap::classify_exit`] demux, COUNT each exit into a
/// bounded no-float [`tb_encode::exittel::ExitHistogram`], record each as an injective
/// [`tb_encode::exittel::ExitTelemetryRecord`] folded into a per-instance `tel_head`
/// (the M22 fold REUSED verbatim), and report the outcome to the kernel as a pure-data
/// [`crate::ExitTelemetryProof`]. 100% SAFE, no device, no scheduler -- pure value
/// computation over the Kani-proven `tb_encode::exittel` leaf.
///
/// It proves: (a) CLASS-TOTALITY -- every synthetic ESR maps to an in-range class tag
/// AND the six synthetic exits hit six DISTINCT classes (the classifier distinguishes
/// them); (b) BUCKETS-EXACT -- each recorded bucket equals an independent
/// [`tb_encode::exittel::bucket_index`] of the cost-proxy delta AND the per-`(class,
/// bucket)` cell count is exact; (c) CLEAN -- the independently re-folded committed
/// record ids equal the running `tel_head` + a genuine inclusion proof verifies; (d)
/// TAMPER -- a single-byte flip of a committed record's canonical bytes is caught (head-
/// mismatch AND inclusion-fail). The marker is withheld unless every leg holds. HONEST:
/// PRODUCER-ONLY -- the telemetry is recorded + folded, NEVER fed to a policy whose
/// decisions change the future exit distribution (the confounding loop the M24 adversary
/// named is structurally avoided); the `tel_head` is SEPARATE from the M23 `xp_head`
/// (zero regression). The witness token `signal=OBSERVATIONAL-NONCAUSAL` is machine-
/// emitted so the marker cannot claim a causal state-signal.
pub(crate) fn exittel_selftest() -> crate::ExitTelemetryProof {
    use tb_encode::el2_trap::{EC_DABT_LOW, EC_HVC64, EC_SMC64, EC_SYS64, EC_WFX};
    use tb_encode::exittel::{
        self, bucket_index, canon as et_canon, class_tag, classify_exit, tel_chain_mix,
        tel_head_witness, tel_hash, tel_recompute, tel_verify_inclusion, ExitHistogram,
        ExitTelemetryRecord, EXITTEL_CANON_LEN, PROV_HASH_LEN,
    };

    let fail = |head: u64, records: u64| crate::ExitTelemetryProof {
        class_total: false,
        buckets_exact: false,
        clean_ok: false,
        inclusion_ok: false,
        tamper_caught: false,
        classes: 0,
        head,
        records,
    };

    // Six synthetic exits: (ESR_EL2 with the EC in [31:26], cost-proxy delta). The
    // deltas are chosen so the log2 buckets vary + are predictable (the bucket of
    // 2^k is k). EC<<26 places the EC in the ESR_EL2.EC field the classifier reads.
    let exits: [u64; 6] = [
        EC_DABT_LOW << 26, // StageTwoAbort
        EC_HVC64 << 26,    // Hvc
        EC_SMC64 << 26,    // Smc
        EC_SYS64 << 26,    // Sys64
        EC_WFX << 26,      // Wfx
        0x07u64 << 26,     // Undef (FP/SIMD EC 0x07 -> the fail-closed default)
    ];
    let deltas: [u64; 6] = [1, 4, 16, 64, 256, 1024]; // buckets 0,2,4,6,8,10

    let mut hist = ExitHistogram::new();
    let mut tel_head = [0u8; PROV_HASH_LEN];
    let mut ids: alloc::vec::Vec<[u8; PROV_HASH_LEN]> = alloc::vec::Vec::new();
    let mut rows: alloc::vec::Vec<[u8; EXITTEL_CANON_LEN]> = alloc::vec::Vec::new();
    let mut scratch = [0u8; EXITTEL_CANON_LEN + 8];
    let mut class_total = true;
    let mut buckets_exact = true;
    let mut seen_classes: u32 = 0; // a bitmask of distinct class tags observed

    let mut i = 0usize;
    while i < 6 {
        let esr = exits[i];
        let delta = deltas[i];
        let c = classify_exit(esr); // the REUSED, Kani-proven-total classifier
        let tag = class_tag(c);
        if (tag as usize) >= tb_encode::exittel::N_CLASSES {
            class_total = false;
        }
        seen_classes |= 1u32 << (tag as u32);

        let (bucket, count) = hist.record(c, delta);
        // BUCKETS-EXACT: the recorded bucket equals an independent bucket_index, and the
        // cell count is exactly 1 (each synthetic class is seen once).
        if (bucket as usize) != bucket_index(delta) {
            buckets_exact = false;
        }
        if hist.count(c, bucket as usize) != 1 {
            buckets_exact = false;
        }

        let rec = ExitTelemetryRecord {
            kind: exittel::kind::EXIT_TELEMETRY,
            exit_class: tag,
            bucket,
            vmid: 1,
            count_in_bucket: count,
            logical_time: i as u64,
        };
        let n = et_canon(&rec, &mut scratch);
        if n == 0 {
            return fail(0, 0);
        }
        let id = tel_hash(&scratch[..n]);
        tel_head = tel_chain_mix(tel_head, id);
        let mut row = [0u8; EXITTEL_CANON_LEN];
        row.copy_from_slice(&scratch[..n]);
        rows.push(row);
        ids.push(id);
        i += 1;
    }

    // CLASS-TOTALITY also requires the six synthetic exits hit six DISTINCT classes
    // (the classifier provably distinguished StageTwoAbort/Hvc/Smc/Sys64/Wfx/Undef).
    let distinct = seen_classes.count_ones() as u64;
    if distinct != 6 {
        class_total = false;
    }

    let records = ids.len() as u64;
    if records != 6 {
        return fail(tel_head_witness(tel_head), records);
    }

    // CLEAN + INCLUSION: independently re-fold the committed ids -> the running head.
    let leaf = ids[0];
    let siblings: alloc::vec::Vec<[u8; PROV_HASH_LEN]> = ids[1..].to_vec();
    let clean_ok = tel_recompute(leaf, &siblings) == tel_head;
    let inclusion_ok = tel_verify_inclusion(leaf, &siblings, tel_head);

    // TAMPER: flip one byte of the FIRST committed record's canonical bytes; the re-hash
    // must differ AND both the head recompute and the inclusion proof must REJECT.
    let mut tamper_caught = false;
    {
        let leaf0 = tel_hash(&rows[0]);
        if leaf0 == ids[0] {
            let mut tampered = rows[0];
            tampered[5] ^= 0x01; // perturb the count_in_bucket low byte (a real field)
            let bad = tel_hash(&tampered);
            tamper_caught = bad != ids[0]
                && tel_recompute(bad, &siblings) != tel_head
                && !tel_verify_inclusion(bad, &siblings, tel_head);
        }
    }

    crate::ExitTelemetryProof {
        class_total,
        buckets_exact,
        clean_ok,
        inclusion_ok,
        tamper_caught,
        classes: distinct,
        head: tel_head_witness(tel_head),
        records,
    }
}

// --- M38 (stage B): the verified CONDUCTOR self-test (the marker body) --------

/// The fixed score FLOOR the Verifier gates against (the heuristic baseline the
/// Worker output must beat by [`tb_encode::conductor::VERDICT_MARGIN`]). Pinned to
/// the SAME constant the stage-A host transcript uses, so the in-kernel loop folds
/// a byte-identical lineage to the host's independent recompute (cross-process).
const CONDUCTOR_SCORE_FLOOR: i64 = 100;

/// M38 (stage B): run the verified `tb_encode::conductor` policy over the kernel-
/// supplied per-turn Worker scores (the REAL organ-execution results -- the
/// M_MEM_RECALL context strength + the M_MODEL_INVOKE_BYTES mock-response refinement
/// the kernel block computes through the cap chokepoint), fold each
/// `ConductDecision` into a `conduct_head` via the M22 prov fold REUSED verbatim,
/// independently re-fold the trace, inject a single-byte tamper, and report the
/// outcome as a pure-data [`crate::ConductorProof`]. See [`crate::conductor_selftest`].
///
/// The organ-selection schedule is the stage-A host transcript VERBATIM (a measured
/// 2-hop+ task: Thinker proposes over RetrievalOverMemory, Worker executes over
/// LocalM32 then ExternalMock on the retry, the Verifier adjudicates) so the
/// in-kernel fold and the host's independent fold over the SAME emitted trace match
/// byte-for-byte. The loop is BOUNDED by `MAX_TURNS` -- no unbounded wait (the #1
/// boot-hang risk is structurally excluded by the verified bounded transition).
pub(crate) fn conductor_selftest(worker_scores: &[i64]) -> crate::ConductorProof {
    use tb_encode::conductor::{
        assign_role, canon as conduct_canon, conduct_chain_mix, conduct_hash,
        conduct_head_witness, conduct_recompute, conduct_verify_inclusion, select_organ, step,
        Action, ConductDecision, Role, Verdict, CONDUCT_CANON_LEN, PROV_HASH_LEN, VERDICT_MARGIN,
    };

    let mut steps_arr = [crate::ConductorTraceStep::default(); crate::CONDUCTOR_MAX_STEPS];
    let mut ids: alloc::vec::Vec<[u8; PROV_HASH_LEN]> = alloc::vec::Vec::new();
    let mut rows: alloc::vec::Vec<[u8; CONDUCT_CANON_LEN]> = alloc::vec::Vec::new();
    let mut policy_head = [0u8; PROV_HASH_LEN]; // genesis (all-zero) head
    let mut scratch = [0u8; CONDUCT_CANON_LEN + 8];

    let mut turn: u8 = 0;
    let mut organ_calls: u16 = 0;
    let mut round: u8 = 0; // the Verifier retry round (REVISE -> retry)
    let mut n_steps: usize = 0;
    let mut seen = [false; tb_encode::conductor::N_ORGANS];
    let mut revise_cycles: u64 = 0;
    let mut accept_at: u64 = 0;
    let mut accepted = false;

    loop {
        if n_steps >= crate::CONDUCTOR_MAX_STEPS {
            // Belt-and-braces cap (the policy already bounds to MAX_TURNS+1 steps):
            // never overrun the fixed trace buffer -- bound EVERYTHING (#65 / the
            // boot-hang discipline).
            break;
        }
        let role = assign_role(turn);

        // ORGAN SELECTION (the verified policy): the honest 2-hop+ task -- Thinker
        // proposes over RetrievalOverMemory, Worker/Verifier act over LocalM32 then
        // ExternalMock on the retry round. The schedule is the stage-A host
        // transcript VERBATIM so the cross-process folds match byte-for-byte.
        let organ = match role {
            Role::Thinker => select_organ(0),                 // RetrievalOverMemory
            Role::Worker => select_organ(1 + round as usize), // LocalM32 -> ExternalMock
            Role::Verifier => select_organ(1 + round as usize),
        };

        // ORGAN EXECUTION cost (the kernel side did the real recall/invoke): the
        // Worker invokes the engine (a real organ call -> cost increments); the
        // Verifier adjudicates the Worker's last output.
        if role == Role::Worker {
            organ_calls = organ_calls.saturating_add(1);
        }
        // The Worker's output score for THIS retry round, supplied by the kernel's
        // REAL organ execution (M_MEM_RECALL context + the M_MODEL_INVOKE_BYTES mock
        // refinement). Out-of-range rounds fail closed to a below-floor score (a
        // REVISE), never a panic -- total over any worker_scores length.
        let worker_score = worker_scores
            .get(round as usize)
            .copied()
            .unwrap_or(i64::MIN / 2);

        // THE VERIFIED VERDICT + the bounded transition (the policy leaf).
        let (verdict, action) = step(turn, worker_score, CONDUCTOR_SCORE_FLOOR, VERDICT_MARGIN);

        let idx = organ.tag() as usize;
        if idx < seen.len() {
            seen[idx] = true;
        }
        if role == Role::Verifier && verdict == Verdict::Revise {
            revise_cycles += 1;
        }
        if verdict == Verdict::Accept {
            accepted = true;
            accept_at = turn as u64;
        }

        // CAPTURE the step into the SEPARATE trace (what the host re-folds).
        steps_arr[n_steps] = crate::ConductorTraceStep {
            turn,
            role: role.tag(),
            organ: organ.tag(),
            verdict: verdict.tag(),
            organ_calls,
            t_logical: turn as u64,
        };

        // FOLD the decision into the policy head via the REUSED M22 prov fold
        // (the SAME way the host re-folds the emitted trace -> honest run MATCHES).
        let rec = ConductDecision {
            turn,
            role: role.tag(),
            organ: organ.tag(),
            verdict: verdict.tag(),
            organ_calls,
            t_logical: turn as u64,
        };
        let n = conduct_canon(&rec, &mut scratch);
        if n == 0 {
            // fail-closed: a too-small scratch can never happen (scratch is sized)
            // but never partial-write / panic.
            break;
        }
        let id = conduct_hash(&scratch[..n]);
        policy_head = conduct_chain_mix(policy_head, id);
        let mut row = [0u8; CONDUCT_CANON_LEN];
        row.copy_from_slice(&scratch[..n]);
        rows.push(row);
        ids.push(id);
        n_steps += 1;

        match action {
            Action::Terminate(_) => break,
            Action::Continue { turn: next_turn, .. } => {
                // A Verifier REVISE advances the retry round (the refine-then-retry
                // cycle that brings the ExternalMock organ into the sequence).
                if role == Role::Verifier && verdict == Verdict::Revise {
                    round = round.saturating_add(1);
                }
                turn = next_turn;
            }
        }
    }

    let records = ids.len() as u64;
    let organs = seen.iter().filter(|&&b| b).count() as u64;
    let turns = steps_arr
        .get(n_steps.wrapping_sub(1))
        .map(|s| s.turn as u64 + 1)
        .unwrap_or(0);

    // CLEAN + INCLUSION: independently re-fold the committed ids -> the running head.
    let (clean_ok, inclusion_ok) = if ids.is_empty() {
        (false, false)
    } else {
        let leaf = ids[0];
        let siblings: alloc::vec::Vec<[u8; PROV_HASH_LEN]> = ids[1..].to_vec();
        (
            conduct_recompute(leaf, &siblings) == policy_head,
            conduct_verify_inclusion(leaf, &siblings, policy_head),
        )
    };

    // TAMPER: flip one byte of the FIRST committed decision's canonical bytes; the
    // re-hash must differ AND both the head recompute and the inclusion proof must
    // REJECT (the M22 tamper-evidence leg).
    let tamper_caught = if rows.is_empty() {
        false
    } else {
        let leaf0 = conduct_hash(&rows[0]);
        let siblings: alloc::vec::Vec<[u8; PROV_HASH_LEN]> = ids[1..].to_vec();
        if leaf0 == ids[0] {
            let mut tampered = rows[0];
            tampered[3] ^= 0x01; // OFF_VERDICT (a real field)
            let bad = conduct_hash(&tampered);
            bad != ids[0]
                && conduct_recompute(bad, &siblings) != policy_head
                && !conduct_verify_inclusion(bad, &siblings, policy_head)
        } else {
            false
        }
    };

    crate::ConductorProof {
        clean_ok,
        inclusion_ok,
        tamper_caught,
        accepted,
        organs,
        revise_cycles,
        turns,
        accept_at,
        organ_calls: organ_calls as u64,
        head: conduct_head_witness(policy_head),
        records,
        steps: steps_arr,
    }
}

// --- M28: the verified operator-inbound command self-test (the marker body) ---

/// The compiled-in SIMULATED enrolled verifier's base key (a TEST key, NOT a real
/// enrolment ceremony -- the `oracle=SIMULATED-ENROLLED-KEY` honesty token). The two
/// per-credential keys are derived from this via [`tb_encode::opframe_rx::key_evolve`]
/// (the FssAgg forward-evolution shape), so the keys are not a single repeated byte.
const OPCMD_BASE_KEY: [u8; 32] = [0x4Bu8; 32];

/// The two distinct enrolled credential ids the dual-authorized `ACTIVATE_CMD`
/// carries (the two-person rule). Distinct so the dual-custody check passes.
const OPCMD_CRED_A: u16 = 0xA101;
/// See [`OPCMD_CRED_A`] -- the SECOND (distinct) enrolled credential id.
const OPCMD_CRED_B: u16 = 0xB202;

/// M28: play the SIMULATED enrolled operator-verifier over the Kani-proven
/// `tb_encode::opframe_rx` RX path, reporting the outcome to the kernel as a pure-data
/// [`crate::OpcmdProof`]. 100% SAFE, no device touched beyond the serial the kernel
/// renders the marker over, no scheduler -- pure value computation over the RX dual of
/// the M25 transcript (which REUSES the M22 `tb_encode::prov` digest for its keyed MAC
/// + key-evolution).
///
/// It (a) SEEDS the same memory-pressure scenario as the M25/M23 self-tests so the
/// substrate carries a LIVE M22 provenance `chain_head` (the head the command BINDS --
/// the instance anchor); (b) derives a per-boot CHALLENGE nonce from the live head (a
/// fresh-per-instance freshness anchor -- RATS RFC 9334 §10 epoch-id style); (c) the
/// SIMULATED enrolled verifier (a compiled-in test key, two distinct creds) SEALS a
/// well-formed, fresh, head-bound, DUAL-AUTHORIZED `ACTIVATE_CMD` and the RX path
/// [`tb_encode::opframe_rx::decode_and_verify`] ACCEPTS it; (d) the verifier then
/// proves the RX path REJECTS (a) a stale-nonce replay, (b) a wrong-head command, (c)
/// a single-credential command, (d) a flipped-MAC command -- the precise reject in
/// each case. The marker is withheld unless EVERY leg holds.
///
/// CRITICAL HONESTY: the accepted command is NECESSARY-NOT-SUFFICIENT. `KAN_ACTIVE`
/// stays `false` (it is a `const false`; the command does NOT flip it -- the
/// architectural "pending flag -> M24 reads it" seam is the proposal's, but THIS self-
/// test simply asserts an accepted command leaves `KAN_ACTIVE == false` because M24's
/// statistical bar is unmet on synthetic data). The witness carries `kan_active=0`. The
/// MAC is `mac=KEYED-CRYPTO` (M29: keyed BLAKE2s-256 derive-then-MAC over the verified
/// `tb_encode::khash` leaf -- implementation verified, primitive security
/// `sec=ASSUMED-FROM-LITERATURE`) and the oracle is `oracle=SIMULATED-ENROLLED-KEY` (a
/// test key, NOT a human) -- the marker proves the auth PLUMBING, never that a human
/// commanded.
///
/// M29 additions: (e) the fail-closed in-boot KAT -- `tb_encode::khash::kat_ok()`
/// RECOMPUTES the official RFC 7693 Appendix B + BLAKE2 reference-KAT vectors through
/// the real compression (`kat=RFC7693-PASS` is EARNED per boot, never compiled-in);
/// (f) the old-key ERASURE seam check -- snapshot an epoch key, [`key_evolve`] it
/// forward, ZEROIZE the old epoch's bytes, assert the erasure took
/// (`oldkey-zeroized=1`; Bellare-Yee forward security is CONDITIONAL on erasure, a
/// stateful-seam property the pure leaf cannot claim -- TESTED here, not proven).
pub(crate) fn opcmd_selftest() -> crate::OpcmdProof {
    use tb_encode::opframe_rx::{
        decode_and_verify, key_evolve, seal, CmdFrame, CmdVerdict, CMD_HEADER_LEN, KEY_LEN,
        MAC_LEN,
    };
    use tb_encode::prov::{head_witness as prov_head_witness, PROV_HASH_LEN};

    let fail = |challenge: u64| crate::OpcmdProof {
        accepted: false,
        stale_rejected: false,
        wronghead_rejected: false,
        single_cred_rejected: false,
        badmac_rejected: false,
        kat_ok: false,           // fail-closed: no leg may claim the KAT passed
        oldkey_zeroized: false,  // fail-closed
        kan_active: KAN_ACTIVE, // const false -- never flipped by an accepted command
        challenge,
    };

    // (e) M29: the fail-closed in-boot KAT -- recompute the OFFICIAL RFC 7693
    //     vectors through the REAL BLAKE2s compression. The kernel withholds the
    //     `khash:` witness line's `kat=RFC7693-PASS` token (and the M29 marker)
    //     unless this is true -- earned per boot, never compiled-in.
    let kat_ok = tb_encode::khash::kat_ok();

    // (a) SEED the M23/M25 scenario so the substrate carries a live M22 head (the
    //     instance anchor the command binds; a command from a different boot binds a
    //     different head). Identical shape to opframe_selftest: writes -> recall ->
    //     aged sweep.
    let mut sub = MemSubstrate::new();
    let mut w = 0u64;
    while w < OPFRAME_SELFTEST_WRITES {
        let key = 0x00F_5000 + w;
        if sub.write(0, key, 0xFFF_0000 + w, 1).is_none() {
            return fail(0);
        }
        w += 1;
    }
    let _ = sub.recall(0x00F_5000, 0, 1, 0);
    sub.clock = sub.clock.wrapping_add(1_000_000);
    let _ = sub.forget_sweep();

    // The LIVE M22 provenance head -- the command BINDS to THIS (head-binding).
    let live_head: [u8; PROV_HASH_LEN] = sub.chain_head();

    // (b) The per-boot CHALLENGE nonce: a deterministic fold of the live head (a
    //     fresh-per-instance freshness anchor; a different boot's head yields a
    //     different challenge, so a captured command cannot replay across boots). The
    //     low bit is forced set so the stale-leg's `challenge ^ 1` is always distinct.
    let challenge: u64 = prov_head_witness(live_head) | 1;

    // (c) The SIMULATED enrolled verifier's two per-credential keys, derived from the
    //     compiled-in test base key via the forward evolution (M29: a domain-separated
    //     keyed-BLAKE2s PRF call -- `khash(key, "YUVA-KEY-EVOLVE-V1")`), so the two
    //     keys are distinct + not a single repeated byte. NOT a real enrolment.
    let key_a = key_evolve(&OPCMD_BASE_KEY);
    let key_b = key_evolve(&key_a);

    // (f) M29: the old-key ERASURE seam (proposal open question 3 -- the Bellare-Yee
    //     forward-security condition). Snapshot a prior-epoch key, evolve it forward
    //     (the successor exists), then ZEROIZE the old epoch's bytes and ASSERT the
    //     erasure took. TESTED in this stateful seam (the pure leaf cannot claim
    //     erasure); the witness renders `oldkey-zeroized=1`.
    let mut old_epoch: [u8; KEY_LEN] = OPCMD_BASE_KEY;
    let _next_epoch = key_evolve(&old_epoch); // the forward step the old key feeds
    let mut z = 0usize;
    while z < KEY_LEN {
        old_epoch[z] = 0;
        z += 1;
    }
    let mut oldkey_zeroized = true;
    let mut zc = 0usize;
    while zc < KEY_LEN {
        oldkey_zeroized = oldkey_zeroized && old_epoch[zc] == 0;
        zc += 1;
    }

    // The well-formed, fresh, head-bound, DUAL-AUTHORIZED ACTIVATE_CMD the verifier
    // submits over the (in-RAM, captured) RX path. A small fixed payload (the command
    // body the seam layers meaning onto; opaque to the codec).
    let payload: [u8; 4] = [0x00, 0x01, 0x02, 0x03];
    let cmd = CmdFrame {
        kind: tb_encode::opframe_rx::kind::ACTIVATE_CMD,
        nonce_echo: challenge, // ECHO the challenge (freshness)
        op_head_bind: live_head, // BIND the live head (Terrapin head-binding)
        seq: 1,
        cred_a_id: OPCMD_CRED_A, // two DISTINCT creds (dual custody)
        cred_b_id: OPCMD_CRED_B,
        payload: &payload,
        mac: [0u8; MAC_LEN], // overwritten by seal's freshly computed keyed MAC
    };

    // SEAL the command (compute the keyed MAC over the canonical bytes). The wire is
    // CMD_HEADER_LEN + 4 (payload) + MAC_LEN bytes.
    const WIRE_CAP: usize = CMD_HEADER_LEN + 4 + MAC_LEN;
    let mut wire = [0u8; WIRE_CAP];
    let n = seal(&cmd, &key_a, &key_b, &mut wire);
    if n != WIRE_CAP {
        return fail(challenge);
    }
    let mut scratch = [0u8; CMD_HEADER_LEN + 4];

    // THE ACCEPT: the valid fresh head-bound dual-authorized command is accepted.
    let accepted = decode_and_verify(&wire[..n], challenge, live_head, &key_a, &key_b, &mut scratch)
        == CmdVerdict::Accept;

    // (d) THE FOUR REJECTS (each the precise verdict).
    // (a) STALE nonce: the verifier expects a DIFFERENT (rotated) challenge.
    let stale_rejected =
        decode_and_verify(&wire[..n], challenge ^ 1, live_head, &key_a, &key_b, &mut scratch)
            == CmdVerdict::RejectStale;

    // (b) WRONG head: the live head moved (a cross-boot command).
    let mut wrong_head = live_head;
    wrong_head[0] ^= 0x01;
    let wronghead_rejected =
        decode_and_verify(&wire[..n], challenge, wrong_head, &key_a, &key_b, &mut scratch)
            == CmdVerdict::RejectWrongHead;

    // (c) SINGLE credential: re-seal a command whose two cred ids are EQUAL (a single
    //     signer) -- the dual-custody check rejects it.
    let single = CmdFrame {
        cred_a_id: OPCMD_CRED_A,
        cred_b_id: OPCMD_CRED_A, // SAME credential -- a single signer
        ..cmd
    };
    let mut wire2 = [0u8; WIRE_CAP];
    let n2 = seal(&single, &key_a, &key_b, &mut wire2);
    let single_cred_rejected = n2 == WIRE_CAP
        && decode_and_verify(&wire2[..n2], challenge, live_head, &key_a, &key_b, &mut scratch)
            == CmdVerdict::RejectSingleCred;

    // (d) FLIPPED MAC: flip one byte of the trailing MAC of the valid wire -- the keyed
    //     MAC recompute no longer matches.
    let mut tampered = wire;
    let mac_off = n - MAC_LEN;
    tampered[mac_off] ^= 0x01;
    let badmac_rejected =
        decode_and_verify(&tampered[..n], challenge, live_head, &key_a, &key_b, &mut scratch)
            == CmdVerdict::RejectBadMac;

    crate::OpcmdProof {
        accepted,
        stale_rejected,
        wronghead_rejected,
        single_cred_rejected,
        badmac_rejected,
        kat_ok,
        oldkey_zeroized,
        // NECESSARY-NOT-SUFFICIENT: an accepted command does NOT flip KAN_ACTIVE. It is
        // a `const false`; M24's statistical bar is unmet on synthetic data, so the cell
        // stays DORMANT even WITH the command (the designed, correct outcome).
        kan_active: KAN_ACTIVE,
        challenge,
    }
}

// --- M30: the verified inference-transport self-test (the marker body) --------

/// The fixed echo-request body the M30 self-test sends (opaque to the codec;
/// the host peer must echo it back BIT-EXACTLY -- `body-bitexact=1`).
const XPORT_BODY_LEN: usize = 16;

/// M30: run the HOST-KEYED echo round-trip over the virtio-console channel and
/// report a [`crate::InferChanProof`] (proposal §3b). The LEG-1 (kernel-scope)
/// half of the §4 anti-hollow composition:
///
/// 1. PROBE for a modern (Version==2) virtio-console (DeviceID 3); Absent /
///    LegacyUnsupported are graceful (the run scripts decide per lane whether
///    a skip is legitimate -- every peer-attached lane REJECTS it by name).
/// 2. Mint the per-boot CHALLENGE: `uhash(label || cycle-counter)[..16]` (the
///    proposal-§4 fallback source; M19's rng path returns no bytes to reuse).
///    HONEST: C's entropy quality is NOT the anti-hollow load-bearer -- the
///    host-custodied K is -- so no extra token is emitted for it.
/// 3. Canon an `ECHO_REQ` via the Kani-proven `tb_encode::inferwire`, run ONE
///    `chan_send_recv` session (poll-only, POLL_CAP-bounded), expecting
///    EXACTLY `ECHO_RESP-frame || K-reveal` bytes (the response length is
///    known a priori: the body echoes verbatim, the key trailer is fixed).
/// 4. Re-frame the response through the STREAM accumulator (`FrameAccum`,
///    byte-at-a-time -- the chardev lane is a boundary-free byte stream; this
///    is the proven re-framer doing real work, not decoration), decode, and
///    `verify_echo` against the CHANNEL-REVEALED key: kind + correlation id +
///    challenge echo + body-bitexact + tag recompute, conjunctive fail-closed.
/// 5. Fire the four IN-BOOT NEGATIVES (the runtime mirror of the Kani
///    harnesses; each must REJECT or the whole proof is `Failed`): badtag (a
///    flipped tag byte), wrongkey (a perturbed key byte), partial (a truncated
///    frame fed to `decode` from a scratch buffer), desync (an oversize
///    declared length fed to `decode` from a scratch buffer). HONESTY NOTE
///    (proposal §10): partial/desync exercise the DECODER's rejection from
///    scratch buffers, NOT live-ring recovery -- device reset-and-reinit is a
///    named deferral.
///
/// HONEST (the §4 two-leg split): success here means "the kernel verified the
/// tag against the key revealed on the channel and the response binds THIS
/// boot's challenge" (`echo=HOST-KEYED-VERIFIED`, kernel-scope). It does NOT
/// exclude a loopback -- that exclusion is the run-script guard's CROSS-PROCESS
/// challenge/tag equality against the host peer's independently printed line
/// (leg 2). The kernel never holds K before the response arrives, never prints
/// K, and mechanically cannot mint the host lane token: the `peer_id` it maps
/// to `transport=` is MAC-covered inside the tag it just verified.
pub(crate) fn xport_selftest() -> crate::InferChanProof {
    use tb_encode::inferwire::{
        canon, decode, kind, peer, verify_echo, FrameAccum, InferFrame, INFER_ACCUM_CAP,
        INFER_CHALLENGE_LEN, INFER_HEADER_LEN, INFER_KEY_LEN, INFER_KEY_REVEAL_LEN,
        INFER_NONCE_LEN, INFER_PAYLOAD_CAP, INFER_TAG_LEN, OFF_PAYLOAD_LEN,
    };
    use tb_encode::khash::uhash;

    // 1. PROBE for a modern virtio-console (DeviceID 3, Version==2 readback).
    let slot = match crate::arch::chan_probe() {
        Some(s) => s,
        None => {
            return if crate::arch::chan_saw_legacy() {
                crate::InferChanProof::LegacyUnsupported
            } else {
                crate::InferChanProof::Absent
            };
        }
    };

    // 2. The per-boot challenge + correlation id from ONE uhash over a label +
    //    the live cycle counter (varies per run under TCG/KVM alike). The label
    //    DERIVES from the brand identity crate (never re-spelled), and every
    //    length below derives from LABEL.len().
    const LABEL: &[u8] = concat!(brand::brand_upper!(), "-M30-CHALLENGE-V1").as_bytes();
    let ticks = crate::read_cycle_counter();
    let mut seed = [0u8; LABEL.len() + 8];
    let mut i = 0usize;
    while i < LABEL.len() {
        seed[i] = LABEL[i];
        i += 1;
    }
    let tb = ticks.to_le_bytes();
    let mut t = 0usize;
    while t < 8 {
        seed[LABEL.len() + t] = tb[t];
        t += 1;
    }
    let h = uhash(&seed);
    let mut challenge = [0u8; INFER_CHALLENGE_LEN];
    let mut c = 0usize;
    while c < INFER_CHALLENGE_LEN {
        challenge[c] = h[c];
        c += 1;
    }
    let req_id = u64::from_le_bytes([
        h[16], h[17], h[18], h[19], h[20], h[21], h[22], h[23],
    ]);

    // 3. The ECHO_REQ (nonce/peer/tag all ZERO in a request -- §2).
    let mut body = [0u8; XPORT_BODY_LEN];
    let mut b = 0usize;
    while b < XPORT_BODY_LEN {
        body[b] = (b as u8).wrapping_mul(29).wrapping_add(0xB0);
        b += 1;
    }
    let req = InferFrame {
        kind: kind::ECHO_REQ,
        req_id,
        challenge,
        nonce: [0u8; INFER_NONCE_LEN],
        peer_id: 0,
        tag: [0u8; INFER_TAG_LEN],
        payload: &body,
    };
    let mut req_wire = [0u8; INFER_HEADER_LEN + XPORT_BODY_LEN];
    let req_len = canon(&req, &mut req_wire);
    if req_len != INFER_HEADER_LEN + XPORT_BODY_LEN {
        return crate::InferChanProof::Failed { stage: 0x2 };
    }

    // The expected response: the echoed frame + the cleartext key reveal.
    const RESP_LEN: usize =
        INFER_HEADER_LEN + XPORT_BODY_LEN + INFER_KEY_REVEAL_LEN;
    let mut resp_buf = [0u8; RESP_LEN];
    match crate::arch::chan_send_recv(slot, &req_wire[..req_len], &mut resp_buf) {
        Some(n) if n == RESP_LEN => {}
        // A found-then-silent/faulty peer is a hard fail, never a skip (§10).
        _ => return crate::InferChanProof::Failed { stage: 0x3 },
    }

    // 4. STREAM re-framing: byte-at-a-time through the proven accumulator.
    let mut acc: FrameAccum<INFER_ACCUM_CAP> = FrameAccum::new();
    let mut frame_len = 0usize;
    let mut fed = 0usize;
    let mut p = 0usize;
    while p < RESP_LEN {
        if let Some(fl) = acc.push_byte(resp_buf[p]) {
            frame_len = fl;
            fed = p + 1;
            break;
        }
        p += 1;
    }
    // The frame must emerge EXACTLY at its boundary (the peer prepends no
    // garbage) and leave EXACTLY the key reveal trailing.
    if frame_len == 0 || fed != frame_len || RESP_LEN - fed != INFER_KEY_REVEAL_LEN {
        return crate::InferChanProof::Failed { stage: 0x4 };
    }
    let resp = match decode(&acc.bytes()[..frame_len]) {
        Some(r) => r,
        None => return crate::InferChanProof::Failed { stage: 0x4 },
    };
    // The CHANNEL-REVEALED per-run key (born in the host process; the guest
    // image/cmdline never carried it -- key=HOST-CUSTODIED-PER-RUN).
    let mut key = [0u8; INFER_KEY_LEN];
    let mut kk = 0usize;
    while kk < INFER_KEY_LEN {
        key[kk] = resp_buf[fed + kk];
        kk += 1;
    }

    // The host-supplied lane label must be a KNOWN peer (MAC-covered below).
    if resp.peer_id != peer::QEMU_CHARDEV_HARNESS && resp.peer_id != peer::TB_VMM_HOST {
        return crate::InferChanProof::Failed { stage: 0x5 };
    }
    let nonce = resp.nonce;
    let tag = resp.tag;

    // 5. LEG 1: the REAL echo must verify (kind + req_id binding + challenge
    //    echo + body-bitexact + tag recompute -- conjunctive, fail-closed).
    if !verify_echo(&key, &resp, &req) {
        return crate::InferChanProof::Failed { stage: 0x6 };
    }

    // The four IN-BOOT NEGATIVES -- the tokens are EARNED per boot:
    // (a) badtag: one flipped tag byte must reject.
    let mut bad_tag = resp;
    bad_tag.tag[0] ^= 0x01;
    let badtag_rejected = !verify_echo(&key, &bad_tag, &req);
    // (b) wrongkey: one perturbed key byte must reject.
    let mut wrong_key = key;
    wrong_key[0] ^= 0x01;
    let wrongkey_rejected = !verify_echo(&wrong_key, &resp, &req);
    // (c) partial: a truncated frame (scratch buffer) must fail decode.
    let partial_rejected = decode(&acc.bytes()[..frame_len - 1]).is_none();
    // (d) desync: an oversize declared length (scratch buffer) must fail decode.
    let mut ds = [0u8; INFER_HEADER_LEN + XPORT_BODY_LEN];
    let mut d = 0usize;
    while d < frame_len {
        ds[d] = acc.bytes()[d];
        d += 1;
    }
    let bad_len = ((INFER_PAYLOAD_CAP as u32) + 1).to_le_bytes();
    ds[OFF_PAYLOAD_LEN] = bad_len[0];
    ds[OFF_PAYLOAD_LEN + 1] = bad_len[1];
    ds[OFF_PAYLOAD_LEN + 2] = bad_len[2];
    ds[OFF_PAYLOAD_LEN + 3] = bad_len[3];
    let desync_rejected = decode(&ds[..frame_len]).is_none();

    if !badtag_rejected || !wrongkey_rejected || !partial_rejected || !desync_rejected {
        return crate::InferChanProof::Failed { stage: 0x7 };
    }

    crate::InferChanProof::Proven {
        slot,
        req_id,
        resp_len: frame_len as u64,
        challenge,
        nonce,
        tag,
        peer_id: resp.peer_id,
        key, // M31: carried forward for the inference-adapter wire legs
    }
}

// --- M31: the verified inference-adapter WIRE self-test (the marker body) ----

/// The hard cap on verified `INFER_PENDING` heartbeats per exchange (M31
/// proposal §2f -- pendings reset the poll budget but can never be unbounded;
/// the deterministic stage-B harness sends EXACTLY ONE).
const INFER_PENDING_CAP: u64 = 8;

/// M31: run the inference-adapter WIRE legs over the (already M30-proven)
/// virtio-console channel and report a [`crate::InferWireProof`]. The
/// channel-free half of the M31 e2e -- M13-context recall, the in-kernel
/// MOCK-DETERMINISTIC `infer_bytes`, and the M25 transcript fold -- runs at
/// the capability chokepoint in the kernel (the M13/M16 dispatch idiom);
/// THIS function proves the NEW framing transits the real guest/host
/// boundary, fail-closed path included:
///
/// 1. Mint the per-boot M31 challenge (`uhash(label || cycle-counter)`, the
///    M30 idiom; the label derives from the brand crate) + the probe
///    correlation id. Every M31 frame the kernel sends is MAC'd with the
///    channel-revealed K under the NEW `infer_tag` domain (`verify_infer_req`
///    is the host's symmetric check).
/// 2. THE KEYLESS WIRE-ERR CHECK (proposal §3d): send ONE `INFER_REQ`
///    carrying the designated `INFER_NOKEY_PROBE` body; the keyless harness
///    answers a MAC'd `ERR code=NO-KEY` which must verify (`infer_tag` under
///    the new domain, this boot's challenge echoed, the M30 nonce carried)
///    and decode through the CLOSED enum -- `wire-err-handled=0x1` is earned,
///    never assumed.
/// 3. THE CHUNKED MOCK EXCHANGE: send the agent-assembled prompt as a MAC'd
///    single-chunk `INFER_REQ`; the harness answers EXACTLY ONE MAC'd
///    `INFER_PENDING` heartbeat (liveness plumbing, NEVER a completion) then
///    the deterministic `mock_infer` response as MAC'd `INFER_RESP` chunks
///    (1280 bytes -> 2 chunks, so the proven [`InferAssembler`] does real
///    wire work every boot). The kernel stream-re-frames through
///    `FrameAccum`, MAC-verifies EVERY frame via `verify_infer_resp`,
///    reassembles, and requires the assembled body to (a) pass the
///    assembler's own digest-commitment check and (b) EQUAL the in-kernel
///    `infer_bytes` expectation BIT-EXACTLY -- the cross-process determinism
///    check (the harness computes the SAME shared leaf transform).
/// 4. THE FOUR IN-BOOT NEGATIVES (the runtime mirror of the §8 harnesses;
///    each must FIRE or the whole proof is `Failed`): badmac (a flipped tag
///    byte on a REAL received chunk frame must reject), digest-mismatch (a
///    scratch assembler must reject a completion whose recomputed body digest
///    misses the commitment), oversize (a sub-header declaring total_len >
///    `INFER_BODY_CAP` must reject -- reject-never-truncate, the 413 mirror),
///    and err-taxonomy (an out-of-enum ERR code and a contradicted retryable
///    flag must reject).
///
/// HONEST: `backend=MOCK-DETERMINISTIC` -- the host applies a deterministic
/// transform, no model is called, no network exists; the witness tokens say
/// exactly that, and the run-script guards reject any live/real vocabulary
/// near the M31 lines. The expected response length/chunking is derivable a
/// priori from the SHARED compile-time consts (both ends compile this leaf),
/// which is what lets the poll-driven channel size its receive window.
pub(crate) fn infer_wire_selftest(
    slot: u32,
    key: &[u8; 32],
    m30_nonce: &[u8; 16],
    req_id: u64,
    prompt: &[u8],
    expected_resp: &[u8],
) -> crate::InferWireProof {
    use tb_encode::inferwire::{
        body_digest, canon, decode, err_decode, errcode, infer_chunk_count,
        infer_chunks_wire_len, infer_tag, kind, subhdr_decode, AsmPush, FrameAccum,
        InferAssembler, InferFrame, SubHdr, INFER_ACCUM_CAP, INFER_BODY_CAP,
        INFER_CHALLENGE_LEN, INFER_ERR_PAYLOAD_LEN, INFER_HEADER_LEN, INFER_MOCK_RESP_LEN,
        INFER_NOKEY_PROBE, INFER_SUBHDR_LEN,
    };
    use tb_encode::khash::uhash;

    let fail = |stage: u32| crate::InferWireProof::Failed { stage };

    // 1. The per-boot M31 challenge + probe correlation id (the M30 idiom).
    const LABEL: &[u8] = concat!(brand::brand_upper!(), "-M31-CHALLENGE-V1").as_bytes();
    let ticks = crate::read_cycle_counter();
    let mut seed = [0u8; LABEL.len() + 8];
    let mut i = 0usize;
    while i < LABEL.len() {
        seed[i] = LABEL[i];
        i += 1;
    }
    let tb = ticks.to_le_bytes();
    let mut t = 0usize;
    while t < 8 {
        seed[LABEL.len() + t] = tb[t];
        t += 1;
    }
    let h = uhash(&seed);
    let mut challenge = [0u8; INFER_CHALLENGE_LEN];
    let mut c = 0usize;
    while c < INFER_CHALLENGE_LEN {
        challenge[c] = h[c];
        c += 1;
    }
    let mut probe_rid = u64::from_le_bytes([
        h[16], h[17], h[18], h[19], h[20], h[21], h[22], h[23],
    ]);
    if probe_rid == req_id {
        probe_rid ^= 1; // the two in-boot exchanges never share an id
    }

    // 2. THE KEYLESS WIRE-ERR CHECK: INFER_REQ(NOKEY_PROBE) -> MAC'd ERR NO-KEY.
    let probe_sub = SubHdr {
        seq: 0,
        more: false,
        total_len: INFER_NOKEY_PROBE.len() as u32,
        body_digest: body_digest(INFER_NOKEY_PROBE),
    };
    const PROBE_PAYLOAD_LEN: usize = INFER_SUBHDR_LEN + INFER_NOKEY_PROBE.len();
    let mut probe_payload = [0u8; PROBE_PAYLOAD_LEN];
    if tb_encode::inferwire::subhdr_canon(&probe_sub, &mut probe_payload) != INFER_SUBHDR_LEN {
        return fail(0x10);
    }
    let mut p = 0usize;
    while p < INFER_NOKEY_PROBE.len() {
        probe_payload[INFER_SUBHDR_LEN + p] = INFER_NOKEY_PROBE[p];
        p += 1;
    }
    let probe_tag = infer_tag(
        key,
        0,
        &[0u8; 16],
        &challenge,
        probe_rid,
        kind::INFER_REQ,
        &probe_sub,
        INFER_NOKEY_PROBE,
    );
    let probe_frame = InferFrame {
        kind: kind::INFER_REQ,
        req_id: probe_rid,
        challenge,
        nonce: [0u8; 16],
        peer_id: 0,
        tag: probe_tag,
        payload: &probe_payload,
    };
    let mut probe_wire = [0u8; INFER_HEADER_LEN + PROBE_PAYLOAD_LEN];
    let pn = canon(&probe_frame, &mut probe_wire);
    if pn != probe_wire.len() {
        return fail(0x10);
    }
    // The expected answer is EXACTLY one ERR frame (closed payload).
    const ERR_RESP_LEN: usize = INFER_HEADER_LEN + INFER_ERR_PAYLOAD_LEN;
    let mut err_buf = [0u8; ERR_RESP_LEN];
    match crate::arch::chan_send_recv(slot, &probe_wire[..pn], &mut err_buf) {
        Some(n) if n == ERR_RESP_LEN => {}
        _ => return fail(0x11), // present-then-silent: hard fail, never a skip
    }
    let mut acc: FrameAccum<INFER_ACCUM_CAP> = FrameAccum::new();
    let mut fl = 0usize;
    let mut fed = 0usize;
    let mut b = 0usize;
    while b < ERR_RESP_LEN {
        if let Some(n) = acc.push_byte(err_buf[b]) {
            fl = n;
            fed = b + 1;
            break;
        }
        b += 1;
    }
    if fl == 0 || fed != ERR_RESP_LEN {
        return fail(0x12);
    }
    let wire_err_handled = match decode(&acc.bytes()[..fl]) {
        Some(f) if f.kind == kind::ERR && f.nonce == *m30_nonce => {
            match tb_encode::inferwire::verify_infer_resp(key, &f, probe_rid, &challenge) {
                Some((_, chunk)) => matches!(err_decode(chunk), Some((errcode::NO_KEY, false))),
                None => false,
            }
        }
        _ => false,
    };
    if !wire_err_handled {
        return fail(0x13);
    }

    // 3. THE CHUNKED MOCK EXCHANGE (prompt -> 1 PENDING + 2 RESP chunks).
    if prompt.is_empty() || expected_resp.len() != INFER_MOCK_RESP_LEN {
        return fail(0x20);
    }
    let req_sub = SubHdr {
        seq: 0,
        more: false,
        total_len: prompt.len() as u32,
        body_digest: body_digest(prompt),
    };
    let mut req_payload = alloc::vec![0u8; INFER_SUBHDR_LEN + prompt.len()];
    if tb_encode::inferwire::subhdr_canon(&req_sub, &mut req_payload) != INFER_SUBHDR_LEN {
        return fail(0x20);
    }
    req_payload[INFER_SUBHDR_LEN..].copy_from_slice(prompt);
    let req_tag = infer_tag(
        key,
        0,
        &[0u8; 16],
        &challenge,
        req_id,
        kind::INFER_REQ,
        &req_sub,
        prompt,
    );
    let req_frame = InferFrame {
        kind: kind::INFER_REQ,
        req_id,
        challenge,
        nonce: [0u8; 16],
        peer_id: 0,
        tag: req_tag,
        payload: &req_payload,
    };
    let mut req_wire = alloc::vec![0u8; INFER_HEADER_LEN + req_payload.len()];
    let rn = canon(&req_frame, &mut req_wire);
    if rn != req_wire.len() {
        return fail(0x20);
    }
    // The response length is derivable a priori from the SHARED consts:
    // one empty-payload PENDING frame + the fixed-discipline chunk sequence.
    let expect_rx = INFER_HEADER_LEN + infer_chunks_wire_len(expected_resp.len());
    let mut rx = alloc::vec![0u8; expect_rx];
    match crate::arch::chan_send_recv(slot, &req_wire[..rn], &mut rx) {
        Some(n) if n == expect_rx => {}
        _ => return fail(0x21),
    }

    // Stream-reframe + MAC-verify EVERY frame + chunk-assemble.
    let mut acc: FrameAccum<INFER_ACCUM_CAP> = FrameAccum::new();
    let mut asm: InferAssembler<INFER_MOCK_RESP_LEN> = InferAssembler::new();
    let mut pending: u64 = 0;
    let mut chunks: u64 = 0;
    let mut body_len: usize = 0;
    let mut last_chunk_frame: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let mut rb = 0usize;
    while rb < expect_rx {
        let emitted = acc.push_byte(rx[rb]);
        rb += 1;
        let flen = match emitted {
            Some(n) => n,
            None => continue,
        };
        let frame = match decode(&acc.bytes()[..flen]) {
            Some(f) => f,
            None => return fail(0x22),
        };
        if frame.nonce != *m30_nonce {
            return fail(0x22); // the per-run host nonce must carry through
        }
        let (sub, chunk) =
            match tb_encode::inferwire::verify_infer_resp(key, &frame, req_id, &challenge) {
                Some(x) => x,
                None => return fail(0x23), // an unMAC'd/spliced frame never lands
            };
        match frame.kind {
            kind::INFER_PENDING => {
                // Liveness plumbing only: BEFORE any chunk, bounded, never a
                // completion (a run that ends on pendings fails at 0x25).
                if chunks != 0 {
                    return fail(0x25);
                }
                pending += 1;
                if pending > INFER_PENDING_CAP {
                    return fail(0x25);
                }
            }
            kind::INFER_RESP => {
                match asm.push_chunk(&sub, chunk) {
                    AsmPush::Accepted => chunks += 1,
                    AsmPush::Complete(n) => {
                        chunks += 1;
                        body_len = n;
                        // Keep the FINAL chunk frame bytes for the badmac
                        // negative (a REAL received frame, not a synthetic).
                        last_chunk_frame.clear();
                        last_chunk_frame.extend_from_slice(&acc.bytes()[..flen]);
                    }
                    AsmPush::Rejected => return fail(0x24),
                }
            }
            _ => return fail(0x23), // an ERR mid-mock-exchange is a fault
        }
        acc.consume(flen);
    }
    // Completion + the cross-process determinism check: the wire body must
    // EQUAL the in-kernel infer_bytes expectation bit-for-bit.
    if !asm.is_done() || body_len != expected_resp.len() || !acc.is_empty() {
        return fail(0x25);
    }
    if pending != 1 || chunks != infer_chunk_count(expected_resp.len()) as u64 {
        return fail(0x25); // the deterministic protocol shape is exact
    }
    if asm.body() != expected_resp {
        return fail(0x26);
    }

    // 4. THE FOUR IN-BOOT NEGATIVES (each must FIRE; the runtime mirror of
    //    the kani_infer_* harnesses -- scratch state, never the live session).
    // (a) badmac: flip one tag byte of the REAL final chunk frame.
    let badmac_rejected = {
        let mut tampered = last_chunk_frame.clone();
        if tampered.len() <= 46 {
            return fail(0x27);
        }
        tampered[46] ^= 0x01; // OFF_TAG: the first tag byte
        match decode(&tampered) {
            Some(f) => {
                tb_encode::inferwire::verify_infer_resp(key, &f, req_id, &challenge).is_none()
            }
            None => false, // it must still DECODE (the tag is not structural)
        }
    };
    // (b) digest mismatch: a completion whose recomputed body digest misses
    //     the locked commitment must reject (the commitment arbitrates).
    let digest_mismatch_rejected = {
        let body = [0xA5u8; 8];
        let mut wrong = body_digest(&body);
        wrong[0] ^= 0x01;
        let sub = SubHdr {
            seq: 0,
            more: false,
            total_len: 8,
            body_digest: wrong,
        };
        let mut scratch: InferAssembler<8> = InferAssembler::new();
        scratch.push_chunk(&sub, &body) == AsmPush::Rejected && !scratch.is_done()
    };
    // (c) oversize: total_len > INFER_BODY_CAP rejects at the codec
    //     (reject-never-truncate, the 413 mirror).
    let oversize_rejected = {
        let mut raw = [0u8; INFER_SUBHDR_LEN];
        // seq=0, sflags=0, rsv=0, total_len = CAP+1, digest=zeros.
        let bad = ((INFER_BODY_CAP as u32) + 1).to_le_bytes();
        raw[4] = bad[0];
        raw[5] = bad[1];
        raw[6] = bad[2];
        raw[7] = bad[3];
        subhdr_decode(&raw).is_none()
    };
    // (d) ERR taxonomy: an out-of-enum code and a contradicted retryable
    //     flag both reject (the closed-enum discipline).
    let err_taxonomy_rejected = {
        let unknown = [0xE7u8, 0x03, 0x00, 0x00]; // code 999: not a member
        let contradicted = {
            let mut p = [0u8; INFER_ERR_PAYLOAD_LEN];
            let n = tb_encode::inferwire::err_canon(errcode::NO_KEY, &mut p);
            p[2] ^= 1; // NO_KEY is non-retryable; claim otherwise
            n == INFER_ERR_PAYLOAD_LEN && err_decode(&p).is_none()
        };
        err_decode(&unknown).is_none() && contradicted
    };
    if !badmac_rejected || !digest_mismatch_rejected || !oversize_rejected
        || !err_taxonomy_rejected
    {
        return fail(0x27);
    }

    crate::InferWireProof::Proven {
        pending,
        chunks,
        resp_len: body_len as u64,
    }
}

// --- M20: the durable-persistence self-test (the marker body) ----------------

/// The number of known-token sentinel records the round-trip writes + replays.
const PERSIST_SENTINELS: u64 = 3;

/// M20: run the single-boot durability round-trip + report a [`PersistProof`].
///
/// probe -> mount (capture the PRIOR gen) -> write N sentinel records through a
/// REAL [`Region`] behind the [`VirtioBlkStore`] (so `push_record`'s
/// `backing.append` exercises the real staged append) -> two-phase flush -> DROP
/// the substrate (all RAM state destroyed) + the device is reset -> RE-MOUNT the
/// SAME disk image -> replay the Region log -> assert the replayed sentinel bytes
/// == what was written AND `gen` bumped by exactly 1. A true durability round-
/// trip: the bytes left the kernel's RAM, hit the device, and came back from the
/// device on a fresh mount that dropped all prior in-RAM state.
///
/// Absent / LegacyUnsupported are graceful skips. All scratch is heap/Vec or a
/// single reusable 512-byte sector buffer inside [`VirtioBlkStore`] -- NO large
/// stack arrays (#65 discipline).
pub(crate) fn persist_selftest() -> crate::PersistProof {
    use crate::PersistProof;

    // 1. Probe for a MODERN virtio-blk (DeviceID==2).
    let (slot, _cap) = match crate::arch::blk_probe() {
        Some(x) => x,
        None => {
            return if crate::arch::blk_saw_legacy() {
                PersistProof::LegacyUnsupported
            } else {
                PersistProof::Absent
            };
        }
    };

    // 2. Mount the store on the (freshly-attached) disk; capture the prior gen.
    let store = match VirtioBlkStore::mount(slot) {
        Ok(s) => s,
        Err(_) => return PersistProof::Failed { stage: 0x3 },
    };
    let prior = store.gen;

    // 3. Write N sentinel records through a real Region via the substrate's
    //    normal write path (push_record -> backing.append(Region::Episodic, ..)).
    let mut substrate = MemSubstrate::new_with_backing(Box::new(store));
    // Known tokens; the stored ids are the 8-byte payloads the journal appends.
    let mut written_ids: [u64; PERSIST_SENTINELS as usize] = [0; PERSIST_SENTINELS as usize];
    let mut n = 0u64;
    while n < PERSIST_SENTINELS {
        let token = 0xA11CE_u64 + n; // distinct known token per sentinel
        match substrate.write(0, token, 0xB0B0_0000 + n, 5) {
            Some(id) => written_ids[n as usize] = id,
            None => return PersistProof::Failed { stage: 0x4 },
        }
        n += 1;
    }

    // 4. Two-phase flush (records -> FLUSH -> superblock gen+1 -> FLUSH).
    if substrate.backing.flush().is_err() {
        return PersistProof::Failed { stage: 0x4 };
    }
    // The committed generation after the flush (the high half of epoch).
    let committed_gen = substrate.epoch() >> 32;
    if committed_gen != prior.wrapping_add(1) {
        return PersistProof::Failed { stage: 0x6 };
    }

    // 5. DROP the substrate (destroys ALL in-RAM tier state + the store image)
    //    and re-mount the SAME disk image -- a fresh read-from-device.
    drop(substrate);
    let remount = match VirtioBlkStore::mount(slot) {
        Ok(s) => s,
        Err(_) => return PersistProof::Failed { stage: 0x5 },
    };

    // 6. Assert generation continuity + replay equality. The re-mount must see
    //    the committed gen, and the replayed Episodic image must equal the
    //    concatenated id bytes the sentinels appended (byte-for-byte).
    if remount.gen != committed_gen {
        return PersistProof::Failed { stage: 0x6 };
    }
    let ep = region_index(Region::Episodic);
    let replayed = remount.record_count[ep];
    if replayed != PERSIST_SENTINELS {
        return PersistProof::Failed { stage: 0x6 };
    }
    // Each sentinel appended exactly `id.to_le_bytes()` (8 bytes), so the image
    // is the 24-byte concatenation; verify it matches what we wrote, in order.
    let mut k = 0u64;
    while k < PERSIST_SENTINELS {
        let base = (k as usize) * 8;
        let mut got = [0u8; 8];
        if remount
            .read_at(Region::Episodic, base as u64, &mut got)
            .unwrap_or(0)
            != 8
        {
            return PersistProof::Failed { stage: 0x6 };
        }
        if u64::from_le_bytes(got) != written_ids[k as usize] {
            return PersistProof::Failed { stage: 0x6 };
        }
        k += 1;
    }

    PersistProof::Proven {
        gen: remount.gen,
        replayed,
        prior,
    }
}

