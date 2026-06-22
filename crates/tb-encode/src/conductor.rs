//! The M38 verified CONDUCTOR math -- the pure, verified value-computation leaf
//! behind the Verifier-gated organ scheduler: TRINITY's role-delegation loop
//! (Thinker proposes, Worker executes, Verifier accepts-or-revises, loop until
//! ACCEPT) instantiated as a HAND-WRITTEN discrete policy, with each
//! orchestration DECISION folded into the M22 provenance chain. Lifted into
//! `tb-encode` exactly as the M27 two-VMID scheduler ([`crate::tpsched`]) was.
//! ALL network/model/float execution stays HOST-SIDE (the `tools/conductor-host`
//! binary); this leaf is the decidable DECISION ALGEBRA -- organ selection, role
//! assignment, the bounded Verifier-gated transition, the discrete ACCEPT/REVISE
//! verdict -- plus the injective decision record folded via the REUSED M22 fold.
//!
//! ## Honest scope (proposal §1/§10 -- the marker claims ONLY what is proved)
//!
//! * **The policy is HAND-WRITTEN, NOT learned (`policy=DISCRETE-HAND-WRITTEN-
//!   NOT-LEARNED`).** TRINITY's actual mechanism is a CMA-ES float policy --
//!   intrinsically Gaussian/covariance/float, STRUCTURALLY EXCLUDED from a
//!   no-float Kani-provable leaf. The conductor ships a fixed transition table;
//!   a learned policy, if ever adopted, is trained off-substrate and distilled
//!   into a Kani-verifiable fixed-point artifact (named-deferred, proposal §9).
//! * **OBSERVATIONAL, not LEARNED (the M24/M26 confounding firewall).** The
//!   [`ConductDecision`] records which organ ran in which role with what verdict;
//!   the schedule is FIXED, never adapted from its own folded telemetry (a
//!   schedule learned from its own cost stream would re-import the confounded
//!   loop M24 refuses).
//! * **PROVABLE termination.** The loop terminates at a Verifier-ACCEPT or
//!   fail-closed [`Verdict::HaltBudget`] at [`MAX_TURNS`] (TRINITY's K) -- never
//!   a silent infinite loop, never a silent success. The ONLY `Accept`-terminal
//!   transition has `role = Verifier` (`kani_conduct_verifier_gates_termination`).
//! * **The Verifier that BITES is the discrete `gate_clears`-shaped verdict**
//!   ([`crate::bakeoff::gate_clears`] shape, `ACTIVATION_MARGIN`), hand-written +
//!   Kani-verified -- NEVER a learned classifier (`learning=DORMANT`). The M18.1
//!   `harness_merge` human-approval gate is admission-only and provably inert in
//!   the all-mock chain (no organ is high-impact -> its fail-closed branch is
//!   never reached); it bites only at the operator-gated high-impact ADMISSION.
//! * **CLAIMS injective bounded encoding + tamper-evidence (cryptographic since
//!   M29-C).** A single-byte mutation of a committed decision invalidates the
//!   recomputed `conduct_head` -- the M22 fold reused verbatim (khash/BLAKE2s-256;
//!   `sec=ASSUMED-FROM-LITERATURE`).
//! * **The cost record is the LOGICAL surrogate (`cost-metric=LOGICAL-SURROGATE-
//!   NOT-WALLCLOCK`).** `organ_calls`/`turn`/`t_logical` are deterministic
//!   logical ticks -- NOT wall-clock/dollar latency (the metric TRINITY actually
//!   hid; that is FRONTIER, proposal §5/§9). ADOPT-4: the cost is folded
//!   tamper-evidently, so TRINITY's biggest hidden weakness becomes a Yuva
//!   invariant.
//!
//! ## Numeric format (no float, ever -- mirrors `tpsched`/`prov`)
//!
//! Pure integer/byte arithmetic, zero alloc, zero deps. [`canon`] is a FIXED-WIDTH
//! LE byte layout (total + fail-closed). The fold REUSES the proven
//! [`crate::prov`] leaf -- NO new fold math.

// The fold is the M22 provenance leaf, REUSED verbatim (no new fold math), as
// M23/M26/M27. The conductor folds each ConductDecision under the NEW
// `prov::kind::CONDUCT_DECISION` tag (defined beside WRITE/FORGET/SKILL_ADMIT).
pub use crate::prov::{
    append as conduct_append, chain_mix as conduct_chain_mix,
    head_witness as conduct_head_witness, prov_hash as conduct_hash,
    recompute as conduct_recompute, verify_inclusion as conduct_verify_inclusion, PROV_HASH_LEN,
};

/// The bounded turn budget: the loop runs at most this many turns before failing
/// closed to [`Verdict::HaltBudget`]. TRINITY's K = 5 -- the
/// `kani_conduct_bounded_turns` invariant pins the counter monotone and
/// `<= MAX_TURNS`.
pub const MAX_TURNS: u8 = 5;

/// The pre-registered Verifier activation MARGIN (the [`crate::bakeoff`] shape):
/// the Worker organ's output score must beat the floor by at least this margin to
/// clear ACCEPT, else REVISE. A ship-const, pinned positive so the verdict must
/// STRICTLY beat the floor, never tie it (the `gate_clears` conjunction shape).
pub const VERDICT_MARGIN: i64 = 250;

// =============================================================================
// The closed role / organ / verdict vocabularies (the TRINITY taxonomy, verbatim)
// =============================================================================

/// The role vocabulary (TRINITY's verbatim three-role taxonomy) -- a closed `u8`
/// enum (mirroring [`crate::exittel`]'s closed class set). The Thinker proposes,
/// the Worker executes, the Verifier accepts-or-revises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    /// Proposes the next step (TRINITY's proposer).
    Thinker = 0x00,
    /// Executes the proposed step against the selected organ (the actor).
    Worker = 0x01,
    /// Accepts-or-revises the Worker's output -- the ONLY role that can terminate
    /// the loop with ACCEPT (`kani_conduct_verifier_gates_termination`).
    Verifier = 0x02,
}

impl Role {
    /// The wire tag (the closed `u8` value).
    #[inline]
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Decode a wire tag back to a [`Role`], or `None` for an out-of-range byte
    /// (TOTAL + fail-closed -- the closed-set discipline).
    #[inline]
    #[must_use]
    pub const fn from_tag(t: u8) -> Option<Role> {
        match t {
            0x00 => Some(Role::Thinker),
            0x01 => Some(Role::Worker),
            0x02 => Some(Role::Verifier),
            _ => None,
        }
    }
}

/// The organ vocabulary -- a closed `u8` enum mirroring the `inferwire::peer`
/// byte discipline. In CI all three resolve to OFFLINE-DETERMINISTIC backends
/// (no live byte, no network); the reserved space above leaves room for the live
/// external organ at the operator-gated stage (proposal §7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Organ {
    /// The lexical recall organ -- BM25+ over the M13/M20 inverted index
    /// (`retrieval=LEXICAL-NOT-SEMANTIC`; no embeddings, no float).
    RetrievalOverMemory = 0x00,
    /// The M32 local sovereign organ -- an M38-authored deterministic stand-in
    /// mock in CI (`local-organ=M38-AUTHORED-MOCK-IN-CI`); the real llama.cpp
    /// daemon replaces it at stage B (#90).
    LocalM32 = 0x01,
    /// The external organ -- the M31 MOCK-DETERMINISTIC backend in CI
    /// (`external-organ=MOCK-IN-CI`); the live Anthropic bridge is dispatch-only
    /// (proposal §7).
    ExternalMock = 0x02,
}

/// The number of registered organs the conductor selects over (the fixed slice
/// length). The selection is total + fail-closed over `0..N_ORGANS`.
pub const N_ORGANS: usize = 3;

impl Organ {
    /// The wire tag (the closed `u8` value).
    #[inline]
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Decode a wire tag back to an [`Organ`], or `None` for an out-of-range byte
    /// (TOTAL + fail-closed).
    #[inline]
    #[must_use]
    pub const fn from_tag(t: u8) -> Option<Organ> {
        match t {
            0x00 => Some(Organ::RetrievalOverMemory),
            0x01 => Some(Organ::LocalM32),
            0x02 => Some(Organ::ExternalMock),
            _ => None,
        }
    }

    /// The organ registered at index `i` of the fixed registry slice, or `None`
    /// for an out-of-range index (TOTAL + fail-closed -- the
    /// `route::longest_prefix_index` shape). The registry order IS the selection
    /// preference order (lowest index wins ties).
    #[inline]
    #[must_use]
    pub const fn at(i: usize) -> Option<Organ> {
        match i {
            0 => Some(Organ::RetrievalOverMemory),
            1 => Some(Organ::LocalM32),
            2 => Some(Organ::ExternalMock),
            _ => None,
        }
    }
}

/// The Verifier verdict -- the discrete ACCEPT/REVISE/HALT-BUDGET decision over
/// the Worker organ's output digest. CLOSED, exhaustive, mutually exclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Verdict {
    /// The Worker's output cleared the discrete gate -- the loop TERMINATES (only
    /// reachable from `role = Verifier`).
    Accept = 0x00,
    /// The Worker's output did NOT clear the gate -- loop again (re-propose).
    Revise = 0x01,
    /// The turn budget [`MAX_TURNS`] elapsed WITHOUT a Verifier-ACCEPT -- the
    /// fail-closed terminal verdict (never silent-success, never silent-loop).
    HaltBudget = 0x02,
}

impl Verdict {
    /// The wire tag (the closed `u8` value).
    #[inline]
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Decode a wire tag back to a [`Verdict`], or `None` for an out-of-range
    /// byte (TOTAL + fail-closed).
    #[inline]
    #[must_use]
    pub const fn from_tag(t: u8) -> Option<Verdict> {
        match t {
            0x00 => Some(Verdict::Accept),
            0x01 => Some(Verdict::Revise),
            0x02 => Some(Verdict::HaltBudget),
            _ => None,
        }
    }
}

/// The loop-step ACTION: the FIXED bounded transition table's output (the
/// `tpsched::next_slot` shape generalized to role transitions). Either CONTINUE
/// into the next role/turn, or TERMINATE with a final verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Advance to `role` at turn `turn` (the loop continues; `turn <= MAX_TURNS`).
    Continue {
        /// The next turn number (monotone, `<= MAX_TURNS`).
        turn: u8,
        /// The role assigned at the next turn ([`assign_role`]).
        role: Role,
    },
    /// The loop is DONE with this terminal verdict (`Accept` from the Verifier, or
    /// the fail-closed `HaltBudget` at the budget).
    Terminate(Verdict),
}

// =============================================================================
// select_organ / assign_role -- total, panic-free, deterministic
// =============================================================================

/// Select the organ to invoke at this step -- a TOTAL, panic-free, deterministic
/// pick over the fixed registered-organ slice, in the shape of
/// [`crate::route::longest_prefix_index`] (deterministic lowest-index tie-break,
/// fail-closed out-of-range). `pref` is the caller's preference index (e.g. a
/// task-stage cursor); it is reduced modulo [`N_ORGANS`] so EVERY input maps to a
/// registered organ -- no panic, no out-of-range. The mapping is a pure function
/// of `pref` (the `kani_conduct_organ_select_total` determinism property).
#[inline]
#[must_use]
pub fn select_organ(pref: usize) -> Organ {
    // Total over ALL usize: reduce into the registry range, then look up. `at`
    // is total over `0..N_ORGANS` so the unwrap is provably unreachable; the
    // fail-closed fallback keeps the function panic-free by construction.
    match Organ::at(pref % N_ORGANS) {
        Some(o) => o,
        None => Organ::RetrievalOverMemory, // unreachable (pref % N_ORGANS < N_ORGANS)
    }
}

/// Assign the role for `turn` -- a TOTAL, deterministic role assignment. The
/// fixed schedule is the TRINITY cadence: Thinker proposes, Worker executes,
/// Verifier adjudicates, repeating every 3 turns. Turn 0 is the Thinker; the
/// Verifier lands on every `turn % 3 == 2`, so an ACCEPT is reachable at turn 2
/// (the minimal 3-step loop) and the budget allows a REVISE->retry before
/// [`MAX_TURNS`]. TOTAL over all `u8`, no panic, no float.
#[inline]
#[must_use]
pub fn assign_role(turn: u8) -> Role {
    match turn % 3 {
        0 => Role::Thinker,
        1 => Role::Worker,
        _ => Role::Verifier,
    }
}

// =============================================================================
// The discrete Verifier verdict (the bakeoff::gate_clears conjunction shape)
// =============================================================================

/// The discrete Verifier verdict over the Worker organ's output: a conjunctive
/// ACCEPT/REVISE in the shape of [`crate::bakeoff::gate_clears`]
/// (`ACTIVATION_MARGIN`). The Worker's output `score` must beat the `floor` by at
/// least `margin` to clear ACCEPT, else REVISE. This is the gate that BITES in
/// the required all-mock chain -- hand-written, Kani-verified
/// (`kani_conduct_verdict_gate_clears`), NEVER a learned classifier. TOTAL,
/// saturating (no overflow), no panic, no float.
///
/// `role` is checked because only the Verifier adjudicates: a non-Verifier role
/// can NEVER return [`Verdict::Accept`] (it returns `Revise`), so a Worker-ACCEPT
/// is structurally impossible (the `kani_conduct_verifier_gates_termination`
/// property). At the turn budget the caller maps a non-ACCEPT to
/// [`Verdict::HaltBudget`] (see [`step`]).
#[inline]
#[must_use]
pub fn verifier_verdict(role: Role, score: i64, floor: i64, margin: i64) -> Verdict {
    // ONLY the Verifier can ACCEPT -- a non-Verifier role always REVISEs (it
    // cannot terminate the loop). This is the structural gate the termination
    // proof rests on.
    if role as u8 != Role::Verifier as u8 {
        return Verdict::Revise;
    }
    // [A] UTILITY (the gate_clears conjunction): the Worker's output must beat
    // the floor by at least the pre-registered margin (gating on the margin makes
    // ACCEPT a STRICT win, not a tie). i128 widen so the diff never overflows.
    let diff = (score as i128).saturating_sub(floor as i128);
    if diff >= margin as i128 {
        Verdict::Accept
    } else {
        Verdict::Revise
    }
}

// =============================================================================
// next / step -- the FIXED bounded transition table (the tpsched::next_slot shape)
// =============================================================================

/// The FIXED bounded transition: given the current `turn`, its `role`, and the
/// Verifier `verdict` at this turn, produce the next [`Action`]. TOTAL +
/// panic-free + deterministic over the small closed set (the
/// `tpsched::next_slot` discipline). The rules:
///
/// * A `Verifier`-ACCEPT TERMINATES with [`Verdict::Accept`] (the ONLY accepting
///   terminal -- `kani_conduct_verifier_gates_termination`).
/// * A non-Verifier ACCEPT cannot occur (`verifier_verdict` forbids it); defended
///   here anyway -- a non-Verifier `Accept` does NOT terminate (fail-closed: it
///   CONTINUEs, so a forged Worker-ACCEPT can never end the loop).
/// * Otherwise, if `turn + 1 < MAX_TURNS`, CONTINUE to the next turn's role.
/// * At the budget (`turn + 1 >= MAX_TURNS`) without a Verifier-ACCEPT, TERMINATE
///   with the fail-closed [`Verdict::HaltBudget`] (never silent success/loop).
#[inline]
#[must_use]
pub fn next(turn: u8, role: Role, verdict: Verdict) -> Action {
    // The ONLY accepting terminal: a Verifier that ACCEPTed.
    if role as u8 == Role::Verifier as u8 && verdict as u8 == Verdict::Accept as u8 {
        return Action::Terminate(Verdict::Accept);
    }
    // Bounded turns: advance only while strictly under the budget. `next_turn`
    // saturates so the counter is monotone and can never wrap (the
    // `kani_conduct_bounded_turns` invariant).
    let next_turn = turn.saturating_add(1);
    if next_turn < MAX_TURNS {
        return Action::Continue {
            turn: next_turn,
            role: assign_role(next_turn),
        };
    }
    // The budget elapsed without a Verifier-ACCEPT -> fail closed.
    Action::Terminate(Verdict::HaltBudget)
}

/// One full loop STEP: assign the role for `turn`, compute the Verifier verdict
/// over the Worker's `score`/`floor`, and produce the next [`Action`]. This is
/// the kernel/host driver's per-turn entry point -- TOTAL, panic-free,
/// deterministic. Returns `(verdict_at_this_turn, next_action)`: the verdict is
/// the per-step record (folded into the lineage); the action drives the loop.
#[inline]
#[must_use]
pub fn step(turn: u8, score: i64, floor: i64, margin: i64) -> (Verdict, Action) {
    let role = assign_role(turn);
    let verdict = verifier_verdict(role, score, floor, margin);
    let action = next(turn, role, verdict);
    (verdict, action)
}

// =============================================================================
// ConductDecision -- the fixed-width INJECTIVE decision record (canon/decode)
// =============================================================================

/// A fixed, canonical conductor-DECISION record (proposal §2.1): one
/// orchestration step folded into the M22 lineage. EVERY field is FIXED-WIDTH, so
/// [`canon`] is injective. It captures ONE turn: the role assigned, the organ
/// selected, the Verifier verdict, the ADOPT-4 cost (`organ_calls`), and the
/// logical clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConductDecision {
    /// The turn number (`0..MAX_TURNS`) of this step.
    pub turn: u8,
    /// The role assigned this turn ([`Role::tag`]).
    pub role: u8,
    /// The organ selected this turn ([`Organ::tag`]).
    pub organ: u8,
    /// The Verifier verdict at this turn ([`Verdict::tag`]).
    pub verdict: u8,
    /// The ADOPT-4 cost token: the accumulated organ-call count at this step (a
    /// LOGICAL surrogate, NOT wall-clock).
    pub organ_calls: u16,
    /// The logical (boot/session-relative) clock at this step.
    pub t_logical: u64,
}

/// The fixed canonical byte length of EVERY [`ConductDecision`]. Layout (LE):
///
/// ```text
///   [0]      turn         u8
///   [1]      role         u8
///   [2]      organ        u8
///   [3]      verdict      u8
///   [4..6]   organ_calls  u16 LE
///   [6..14]  t_logical    u64 LE
/// ```
pub const CONDUCT_CANON_LEN: usize = 1 + 1 + 1 + 1 + 2 + 8;

const OFF_TURN: usize = 0;
const OFF_ROLE: usize = 1;
const OFF_ORGAN: usize = 2;
const OFF_VERDICT: usize = 3;
const OFF_ORGAN_CALLS: usize = 4;
const OFF_TLOGICAL: usize = 6;

/// The exact canonical byte length of `rec` -- a tautological [`CONDUCT_CANON_LEN`]
/// (fixed-width), mirroring [`crate::tpsched::canon_len`].
#[inline]
#[must_use]
pub fn canon_len(_rec: &ConductDecision) -> usize {
    CONDUCT_CANON_LEN
}

/// Canonical, UNAMBIGUOUS, total fixed-width LE encoding of `rec` into `out`.
/// Returns the bytes written ([`CONDUCT_CANON_LEN`]), or `0` if `out` is too
/// small (TOTAL + fail-closed, never panics, never partial-writes). INJECTIVE:
/// every field at a fixed offset (the `kani_conduct_canon_injective` property).
#[must_use]
pub fn canon(rec: &ConductDecision, out: &mut [u8]) -> usize {
    if out.len() < CONDUCT_CANON_LEN {
        return 0;
    }
    let oc = rec.organ_calls.to_le_bytes();
    let tl = rec.t_logical.to_le_bytes();
    out[OFF_TURN] = rec.turn;
    out[OFF_ROLE] = rec.role;
    out[OFF_ORGAN] = rec.organ;
    out[OFF_VERDICT] = rec.verdict;
    out[OFF_ORGAN_CALLS] = oc[0];
    out[OFF_ORGAN_CALLS + 1] = oc[1];
    let mut i = 0usize;
    while i < 8 {
        out[OFF_TLOGICAL + i] = tl[i];
        i += 1;
    }
    CONDUCT_CANON_LEN
}

/// The exact inverse of [`canon`]: decode `buf` into a [`ConductDecision`], or
/// `None` if `buf` is too small (TOTAL + fail-closed). A successful decode
/// round-trips back to identical canonical bytes (the
/// `kani_conduct_canon_roundtrip` harness).
#[must_use]
pub fn decode(buf: &[u8]) -> Option<ConductDecision> {
    if buf.len() < CONDUCT_CANON_LEN {
        return None;
    }
    let organ_calls = u16::from_le_bytes([buf[OFF_ORGAN_CALLS], buf[OFF_ORGAN_CALLS + 1]]);
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
    Some(ConductDecision {
        turn: buf[OFF_TURN],
        role: buf[OFF_ROLE],
        organ: buf[OFF_ORGAN],
        verdict: buf[OFF_VERDICT],
        organ_calls,
        t_logical,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ConductDecision {
        ConductDecision {
            turn: 2,
            role: Role::Verifier.tag(),
            organ: Organ::LocalM32.tag(),
            verdict: Verdict::Accept.tag(),
            organ_calls: 3,
            t_logical: 0xCAFE,
        }
    }

    #[test]
    fn role_organ_verdict_tag_roundtrip() {
        for r in [Role::Thinker, Role::Worker, Role::Verifier] {
            assert_eq!(Role::from_tag(r.tag()), Some(r));
        }
        assert_eq!(Role::from_tag(3), None);
        for o in [Organ::RetrievalOverMemory, Organ::LocalM32, Organ::ExternalMock] {
            assert_eq!(Organ::from_tag(o.tag()), Some(o));
        }
        assert_eq!(Organ::from_tag(3), None);
        for v in [Verdict::Accept, Verdict::Revise, Verdict::HaltBudget] {
            assert_eq!(Verdict::from_tag(v.tag()), Some(v));
        }
        assert_eq!(Verdict::from_tag(3), None);
    }

    #[test]
    fn select_organ_total_and_deterministic() {
        // Total over a sweep; the registry order is the preference order.
        assert_eq!(select_organ(0), Organ::RetrievalOverMemory);
        assert_eq!(select_organ(1), Organ::LocalM32);
        assert_eq!(select_organ(2), Organ::ExternalMock);
        // Wraps deterministically; same input -> same organ.
        assert_eq!(select_organ(3), Organ::RetrievalOverMemory);
        assert_eq!(select_organ(usize::MAX), select_organ(usize::MAX));
    }

    #[test]
    fn assign_role_trinity_cadence() {
        assert_eq!(assign_role(0), Role::Thinker);
        assert_eq!(assign_role(1), Role::Worker);
        assert_eq!(assign_role(2), Role::Verifier);
        assert_eq!(assign_role(3), Role::Thinker);
        assert_eq!(assign_role(255), Role::Thinker); // 255 % 3 == 0 -> Thinker
        assert_eq!(assign_role(254), Role::Verifier); // 254 % 3 == 2 -> Verifier
    }

    #[test]
    fn verifier_only_accepts() {
        // A non-Verifier role can NEVER accept, even with a huge score.
        assert_eq!(
            verifier_verdict(Role::Worker, i64::MAX, 0, VERDICT_MARGIN),
            Verdict::Revise
        );
        assert_eq!(
            verifier_verdict(Role::Thinker, i64::MAX, 0, VERDICT_MARGIN),
            Verdict::Revise
        );
        // The Verifier accepts iff the margin is cleared.
        assert_eq!(
            verifier_verdict(Role::Verifier, 1000, 0, VERDICT_MARGIN),
            Verdict::Accept
        );
        assert_eq!(
            verifier_verdict(Role::Verifier, 100, 0, VERDICT_MARGIN),
            Verdict::Revise
        );
        // A tie (exactly the margin) clears (>= margin); one below does not.
        assert_eq!(
            verifier_verdict(Role::Verifier, VERDICT_MARGIN, 0, VERDICT_MARGIN),
            Verdict::Accept
        );
        assert_eq!(
            verifier_verdict(Role::Verifier, VERDICT_MARGIN - 1, 0, VERDICT_MARGIN),
            Verdict::Revise
        );
    }

    #[test]
    fn next_terminates_only_on_verifier_accept() {
        // Verifier-ACCEPT terminates.
        assert_eq!(
            next(2, Role::Verifier, Verdict::Accept),
            Action::Terminate(Verdict::Accept)
        );
        // A (structurally-impossible) Worker-ACCEPT does NOT terminate.
        match next(1, Role::Worker, Verdict::Accept) {
            Action::Continue { .. } => {}
            other => panic!("Worker-ACCEPT must not terminate, got {other:?}"),
        }
        // A Verifier-REVISE under the budget continues.
        match next(2, Role::Verifier, Verdict::Revise) {
            Action::Continue { turn, role } => {
                assert_eq!(turn, 3);
                assert_eq!(role, Role::Thinker);
            }
            other => panic!("expected continue, got {other:?}"),
        }
        // At the budget without ACCEPT -> HaltBudget.
        assert_eq!(
            next(MAX_TURNS - 1, Role::Verifier, Verdict::Revise),
            Action::Terminate(Verdict::HaltBudget)
        );
    }

    #[test]
    fn loop_terminates_accept_or_halt() {
        // A run where the Verifier never accepts must HALT at the budget (never
        // loop forever) -- floor above any score forces REVISE every Verifier turn.
        let mut turn = 0u8;
        let mut steps = 0u8;
        loop {
            let (_v, action) = step(turn, 0, i64::MAX, VERDICT_MARGIN);
            steps += 1;
            assert!(steps <= MAX_TURNS + 1, "loop did not terminate");
            match action {
                Action::Terminate(v) => {
                    assert_eq!(v, Verdict::HaltBudget);
                    break;
                }
                Action::Continue { turn: t, .. } => {
                    assert!(t <= MAX_TURNS);
                    turn = t;
                }
            }
        }
        // A run where the Verifier clears on its first turn (turn 2) ACCEPTs.
        let (_v0, _a0) = step(0, 1000, 0, VERDICT_MARGIN); // Thinker -> revise/continue
        let (_v1, _a1) = step(1, 1000, 0, VERDICT_MARGIN); // Worker -> revise/continue
        let (v2, a2) = step(2, 1000, 0, VERDICT_MARGIN); // Verifier -> accept
        assert_eq!(v2, Verdict::Accept);
        assert_eq!(a2, Action::Terminate(Verdict::Accept));
    }

    #[test]
    fn canon_roundtrip_and_fixed_width() {
        assert_eq!(CONDUCT_CANON_LEN, 14);
        let e = sample();
        let mut buf = [0u8; 32];
        assert_eq!(canon(&e, &mut buf), CONDUCT_CANON_LEN);
        assert_eq!(decode(&buf), Some(e));
        let mut small = [0u8; CONDUCT_CANON_LEN - 1];
        assert_eq!(canon(&e, &mut small), 0); // fail-closed
        assert!(small.iter().all(|&b| b == 0));
    }

    fn enc(e: &ConductDecision) -> [u8; CONDUCT_CANON_LEN] {
        let mut b = [0u8; CONDUCT_CANON_LEN];
        assert_eq!(canon(e, &mut b), CONDUCT_CANON_LEN);
        b
    }

    #[test]
    fn canon_injective_each_field() {
        let base = sample();
        let b = enc(&base);
        let mut t = base;
        t.turn ^= 1;
        assert_ne!(enc(&t), b);
        let mut r = base;
        r.role ^= 1;
        assert_ne!(enc(&r), b);
        let mut o = base;
        o.organ ^= 1;
        assert_ne!(enc(&o), b);
        let mut v = base;
        v.verdict ^= 1;
        assert_ne!(enc(&v), b);
        let mut oc = base;
        oc.organ_calls ^= 1;
        assert_ne!(enc(&oc), b);
        let mut tl = base;
        tl.t_logical ^= 1;
        assert_ne!(enc(&tl), b);
    }

    #[test]
    fn fold_is_tamper_sensitive_via_prov() {
        // The conductor REUSES the prov fold verbatim under the CONDUCT_DECISION
        // tag; a single-byte tamper of a committed decision invalidates the head.
        let e0 = sample();
        let mut e1 = sample();
        e1.turn = 3;
        let mut scratch = [0u8; CONDUCT_CANON_LEN + 8];
        let n0 = canon(&e0, &mut scratch);
        let id0 = conduct_hash(&scratch[..n0]);
        let n1 = canon(&e1, &mut scratch);
        let id1 = conduct_hash(&scratch[..n1]);
        let head = conduct_recompute(id0, &[id1]);
        assert!(conduct_verify_inclusion(id0, &[id1], head));
        let mut tampered = [0u8; CONDUCT_CANON_LEN];
        assert_eq!(canon(&e0, &mut tampered), CONDUCT_CANON_LEN);
        tampered[OFF_VERDICT] ^= 0x01;
        let bad = conduct_hash(&tampered);
        assert!(!conduct_verify_inclusion(bad, &[id1], head));
    }
}
