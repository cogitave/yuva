//! The M23 verified EXPERIENCE CODEC math -- the pure, verified value-computation
//! leaf behind a per-agent, fixed-capacity, tamper-evident EXPERIENCE LOG over the
//! M17 forget/recall decisions, lifted into `tb-encode` exactly as the M21 forget
//! policy ([`crate::kancell`]) and the M22 provenance ledger ([`crate::prov`]) were.
//! At each M17 forget/recall decision the OS ALREADY computes a feature vector + a
//! heuristic-envelope verdict + (would-be) a learned-cell score and then DISCARDS
//! it; M23 records that, at each decision, as a fixed-field injective
//! [`ExperienceRecord`] (features quantized to the EXACT kancell grid, the heuristic
//! action taken, the COUNTERFACTUAL `kan_score` the dormant cell WOULD have
//! produced, and reserved-but-unset propensity/outcome fields), folded into a
//! SEPARATE per-agent `xp_head` via the M22 [`crate::prov`] fold. The learned cell
//! stays DORMANT (`KAN_ACTIVE == false`): `kan_score` is logged only as a
//! counterfactual SHADOW, never changing one demote.
//!
//! ## Honest scope (proposal §1/§8 -- the marker claims ONLY what is proved)
//!
//! * **CLAIMS replay-determinism.** A recorded `feats` row replayed through the
//!   dormant `kan_score` reproduces the logged [`ExperienceRecord::kan_score_shadow`]
//!   BIT-IDENTICALLY (achievable precisely because the kancell is integer / no-float).
//! * **CLAIMS tamper-evidence (cryptographic since M29-C).** Any single-byte
//!   mutation to a committed record's canonical bytes provably invalidates the
//!   recomputed `xp_head` AND its inclusion proof -- the M22 fold, reused verbatim
//!   (khash/BLAKE2s-256 since M29 stage C; primitive security
//!   `sec=ASSUMED-FROM-LITERATURE`, never prose-claimed).
//! * **Does NOT validate any policy.** The `outcome` is `Unset`; the logging policy
//!   is `DETERMINISTIC` so the propensity is degenerate (1/0) -- naive IPS/DR is
//!   structurally non-identifiable on this stream. Validity is M24's burden; the
//!   exogenous human-operator oracle is M25's. The honesty token
//!   `oracle=DECLARED-PROXY-DEFERRED-M24` is machine-emitted so the marker
//!   mechanically cannot overclaim.
//!
//! ## The reserve-now refinement (proposal §3 -- the schema-stability lemma)
//!
//! Because the codec is a fixed-field injective encoder folded into the M22 hash
//! chain, ADDING fields in M24 would change the canonical bytes and break BOTH
//! replay-determinism and the chain head. So `logging_propensity_q`, the
//! `logging_policy_kind`, and a present-`Unset` [`OutcomeLabel`] are RESERVED in
//! the byte layout NOW (degenerate sentinels this milestone): M24 populating them
//! does NOT shift any field offset or change the canonical length (the
//! `kani_exp_schema_stability` harness discharges this).
//!
//! ## Numeric format (no float, ever -- mirrors `kancell`/`prov`/`blkfmt`)
//!
//! Pure integer/byte arithmetic, zero alloc, zero deps. [`canon`] is a FIXED-WIDTH,
//! fixed-field-order LE byte layout into a caller buffer (total + fail-closed:
//! returns `0` if the buffer is too small, never panics, mirroring [`crate::prov::
//! canon`]). [`decode`] is the exact inverse over a large-enough buffer (fail-closed
//! to `None`). Every field occupies a FIXED offset, so [`canon`] is injective by
//! construction (no variable-length tail -- the record is fully fixed-width, unlike
//! the prov entry's length-prefixed parent list). The fold over the canonical bytes
//! REUSES the proven [`crate::prov`] leaf ([`crate::prov::append`] /
//! [`crate::prov::chain_mix`] / [`crate::prov::verify_inclusion`] /
//! [`crate::prov::head_witness`]) -- NO new fold math is written here.

// Re-export the EXACT kancell grid geometry + the dormant scorer so the seam, the
// replay self-test, and the Kani harnesses all share ONE decidable geometry (the
// quantization grid, the feature count, the score band, and the demote-band clamp).
// These are NOT redefined here -- they are the M21 artifact's own constants.
pub use crate::kancell::{
    kan_score, DEMOTE_BAND, GRID_LO, GRID_STEP_LOG2, KAN_FEATURES, KnotTable,
};

// The fold is the M22 provenance leaf, REUSED verbatim (proposal §4: "fold into a
// separate per-agent `xp_head` via the M22 `chain_mix`"). We import the proven
// digest/fold/verify/witness functions; M23 writes NONE of its own fold math.
pub use crate::prov::{
    append as xp_append, chain_mix as xp_chain_mix, head_witness as xp_head_witness,
    recompute as xp_recompute, verify_inclusion as xp_verify_inclusion, prov_hash as xp_hash,
    PROV_HASH_LEN,
};

/// The fixed [`ExperienceRecord`] kind tags (proposal §3). The demote site stamps
/// [`kind::FORGET_DECISION`]; the recall/read touch sites stamp
/// [`kind::RECALL_TOUCH`] (the CENSORING events that confound the regret proxy --
/// proposal §8). A closed set the seam emits; the digest folds them in, so a forget
/// decision can never masquerade as a recall touch (the byte differs -> the head
/// differs).
pub mod kind {
    /// An M17 FORGET/demote decision record: the features the sweep computed, the
    /// heuristic envelope verdict, the action taken, + the counterfactual shadow score.
    pub const FORGET_DECISION: u8 = 1;
    /// A recall/read TOUCH observation: a censoring access event referencing the
    /// touched record's `decision_id`. Touches filter demoted tiers (the collider
    /// that confounds the naive "never re-recalled" regret proxy).
    pub const RECALL_TOUCH: u8 = 2;
}

/// The logging-policy kind tags (proposal §3). `DETERMINISTIC` this milestone (the
/// M17 safety envelope is a deterministic logging policy -> degenerate propensity
/// 1/0, so IPS is non-identifiable until M24 injects soft-greedy exploration). The
/// `SOFT_GREEDY` tag is RESERVED so M24 can DETECT support violations rather than
/// discover them too late -- the field is present in the layout NOW.
pub mod policy_kind {
    /// The M17 deterministic safety envelope (this milestone): propensity is 1 for
    /// the chosen action, 0 for the alternative (a positivity/overlap VIOLATION).
    pub const DETERMINISTIC: u8 = 0;
    /// RESERVED for M24: a soft-greedy logging policy that restores overlap by
    /// injecting controlled exploration INSIDE the safety envelope. Never emitted
    /// this milestone; present in the byte layout so populating it is bit-stable.
    pub const SOFT_GREEDY: u8 = 1;
}

/// The RESERVED degenerate propensity sentinel this milestone (proposal §3): the
/// deterministic logging policy gives propensity 1 for the chosen action, which we
/// encode as the fixed-point fraction `SCALE == 1000` so a future M24 soft-greedy
/// value (e.g. `700` for a 0.7 propensity) occupies the SAME `u16` slot without
/// shifting any offset. A SENTINEL, not a validated propensity -- M23 makes no IPS
/// claim (the field is RESERVED, populated in M24).
pub const PROPENSITY_DETERMINISTIC_Q: u16 = 1000;

/// The deferred reward `r` of the logged-bandit tuple (proposal §3), encoded as a
/// PRESENT-but-UNSET tagged variant so M24 populating it does NOT change M23's
/// canonical bytes (the schema-stability lemma). The tag occupies one byte and the
/// payload a fixed `i64` slot REGARDLESS of the variant, so an `Unset` record and a
/// future `ReRecalled`/`Evicted` record have IDENTICAL length + field offsets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutcomeLabel {
    /// This milestone: the outcome is DEFERRED (no validated label exists yet). The
    /// payload slot is present-but-zero. M24 replaces this with a populated variant
    /// WITHOUT shifting any byte offset.
    Unset,
    /// RESERVED for M24: the demoted record was later re-recalled (a candidate
    /// regret signal -- but structurally CONFOUNDED, see proposal §8). The payload
    /// carries the re-recall delay/decision id.
    ReRecalled(i64),
    /// RESERVED for M24: the record was evicted and never re-recalled within the
    /// held-out window. The payload carries the observation horizon.
    Evicted(i64),
}

impl OutcomeLabel {
    /// The fixed `u8` tag byte for this variant (proposal §3 -- present in EVERY
    /// record's layout, so the tag is load-bearing for injectivity: dropping/aliasing
    /// it would let two distinct outcomes collide, which the negative control of the
    /// `kani_exp_canon_injective` harness fires on).
    #[inline]
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            OutcomeLabel::Unset => 0,
            OutcomeLabel::ReRecalled(_) => 1,
            OutcomeLabel::Evicted(_) => 2,
        }
    }

    /// The fixed `i64` payload slot for this variant (`0` for `Unset` -- the
    /// present-but-zero sentinel). ALWAYS occupies 8 bytes in [`canon`], regardless
    /// of the variant, so M24 populating an `Unset` record cannot shift the layout.
    #[inline]
    #[must_use]
    pub fn payload(self) -> i64 {
        match self {
            OutcomeLabel::Unset => 0,
            OutcomeLabel::ReRecalled(v) | OutcomeLabel::Evicted(v) => v,
        }
    }

    /// Reconstruct an [`OutcomeLabel`] from its `(tag, payload)` byte pair (the
    /// [`decode`] inverse). An unknown tag fails closed to `None` (total decode).
    #[inline]
    #[must_use]
    pub fn from_parts(tag: u8, payload: i64) -> Option<OutcomeLabel> {
        match tag {
            0 => Some(OutcomeLabel::Unset),
            1 => Some(OutcomeLabel::ReRecalled(payload)),
            2 => Some(OutcomeLabel::Evicted(payload)),
            _ => None,
        }
    }
}

/// A fixed, canonical experience record (proposal §3). EVERY field is FIXED-WIDTH,
/// so [`canon`] is injective by construction (distinct records always encode to
/// distinct bytes -- there is no variable-length tail to disambiguate, unlike the
/// prov entry). The reserved [`logging_propensity_q`](Self::logging_propensity_q) +
/// [`logging_policy_kind`](Self::logging_policy_kind) + present-`Unset`
/// [`outcome`](Self::outcome) fields are in the layout NOW so M24 populating them
/// keeps the canonical bytes / hash-fold stable (the schema-stability lemma).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExperienceRecord {
    /// The logged-event key: orders the stream + joins a later outcome back to its
    /// decision (the OPE row identity; the rr/ReVirt replay anchor).
    pub decision_id: u64,
    /// The record kind (see [`kind`]): forget-decision vs recall-touch.
    pub kind: u8,
    /// The context `x`, quantized to the EXACT kancell grid (`GRID_LO` /
    /// `GRID_STEP_LOG2`). Exact-grid quantization is what makes the shadow score
    /// BIT-EXACTLY reconstructible (stronger than a float OPE log).
    pub feats: [i32; KAN_FEATURES],
    /// The heuristic safety-envelope verdict -- the hard-invariant gating context
    /// the cell ranks INSIDE (the HALP heuristic floor).
    pub envelope_verdict: u8,
    /// The action the heuristic policy actually served (demote/keep/tier) -- the
    /// required action `a` of the logged-bandit tuple.
    pub action_taken: u8,
    /// The COUNTERFACTUAL would-be score of the DORMANT cell over `feats` (clamped
    /// to [`DEMOTE_BAND`]). Bit-exact-replayable from `feats` -- the headline claim.
    pub kan_score_shadow: i64,
    /// RESERVED (degenerate sentinel this milestone -- [`PROPENSITY_DETERMINISTIC_Q`]):
    /// the OPE schema's required propensity `pi_l(a|x)`, populated in M24. Reserving
    /// it now keeps the canonical bytes / fold stable when M24 injects exploration.
    pub logging_propensity_q: u16,
    /// The logging-policy kind (see [`policy_kind`]): `DETERMINISTIC` this milestone
    /// vs `SOFT_GREEDY` (M24) -- lets M24 DETECT support violations early.
    pub logging_policy_kind: u8,
    /// PRESENT-but-UNSET this milestone (the deferred reward `r`): an `Unset` tagged
    /// variant so M24 populating it does NOT change M23's canonical bytes.
    pub outcome: OutcomeLabel,
    /// How close `envelope_verdict` was to the demote threshold -- cheap insurance
    /// for the IPS/DR behavior margin (optional field, present in the layout).
    pub margin_q: i16,
}

/// The fixed canonical byte length of EVERY [`ExperienceRecord`]. The record is
/// fully FIXED-WIDTH (no variable-length tail), so this is a single `const` the
/// schema-stability lemma pins: an `Unset` record and a populated one have the SAME
/// length. Layout (fixed field order, all LE):
///
/// ```text
///   [0..8]   decision_id          u64 LE
///   [8]      kind                 u8
///   [9..25]  feats[0..4]          4 x i32 LE   (16 bytes)
///   [25]     envelope_verdict     u8
///   [26]     action_taken         u8
///   [27..35] kan_score_shadow     i64 LE
///   [35..37] logging_propensity_q u16 LE       (RESERVED sentinel)
///   [37]     logging_policy_kind  u8           (RESERVED = DETERMINISTIC)
///   [38]     outcome.tag          u8           (present-Unset tag)
///   [39..47] outcome.payload      i64 LE       (present-but-zero for Unset)
///   [47..49] margin_q             i16 LE
/// ```
pub const EXP_CANON_LEN: usize = 8 + 1 + (4 * 4) + 1 + 1 + 8 + 2 + 1 + 1 + 8 + 2;

// Fixed field offsets (the layout above). Kept as named consts so the schema-
// stability lemma + the round-trip read the SAME literals the encoder writes.
const OFF_DECISION_ID: usize = 0;
const OFF_KIND: usize = 8;
const OFF_FEATS: usize = 9;
const OFF_ENVELOPE: usize = 25;
const OFF_ACTION: usize = 26;
const OFF_SHADOW: usize = 27;
const OFF_PROPENSITY: usize = 35;
const OFF_POLICY_KIND: usize = 37;
const OFF_OUTCOME_TAG: usize = 38;
const OFF_OUTCOME_PAYLOAD: usize = 39;
const OFF_MARGIN: usize = 47;

/// The exact canonical byte length of `rec` -- a tautological [`EXP_CANON_LEN`]
/// (the record is fixed-width), kept as a function to mirror [`crate::prov::
/// canon_len`]'s shape so the seam sizes its scratch buffer identically.
#[inline]
#[must_use]
pub fn canon_len(_rec: &ExperienceRecord) -> usize {
    EXP_CANON_LEN
}

/// Canonical, UNAMBIGUOUS, total fixed-width LE encoding of `rec` into `out`.
/// Returns the number of bytes written ([`EXP_CANON_LEN`]), or `0` if `out` is too
/// small (TOTAL + fail-closed: never panics, never partial-writes -- mirrors
/// [`crate::prov::canon`]).
///
/// INJECTIVITY: every field occupies a FIXED offset and a fixed width, so two
/// records that differ in ANY field encode to different bytes -- there is no
/// variable-length tail and thus no field-boundary ambiguity (the
/// `kani_exp_canon_injective` harness discharges this, INCLUDING the reserved
/// propensity field and the present-`Unset` outcome tag).
#[must_use]
pub fn canon(rec: &ExperienceRecord, out: &mut [u8]) -> usize {
    // Fail-closed: too-small buffer -> 0 bytes, no partial write (totality).
    if out.len() < EXP_CANON_LEN {
        return 0;
    }
    write_u64(out, OFF_DECISION_ID, rec.decision_id);
    out[OFF_KIND] = rec.kind;
    let mut j = 0usize;
    while j < KAN_FEATURES {
        write_i32(out, OFF_FEATS + j * 4, rec.feats[j]);
        j += 1;
    }
    out[OFF_ENVELOPE] = rec.envelope_verdict;
    out[OFF_ACTION] = rec.action_taken;
    write_i64(out, OFF_SHADOW, rec.kan_score_shadow);
    write_u16(out, OFF_PROPENSITY, rec.logging_propensity_q);
    out[OFF_POLICY_KIND] = rec.logging_policy_kind;
    out[OFF_OUTCOME_TAG] = rec.outcome.tag();
    write_i64(out, OFF_OUTCOME_PAYLOAD, rec.outcome.payload());
    write_i16(out, OFF_MARGIN, rec.margin_q);
    EXP_CANON_LEN
}

/// The exact inverse of [`canon`]: decode `buf` back into an [`ExperienceRecord`],
/// or `None` if `buf` is too small OR carries an unknown `outcome` tag (TOTAL +
/// fail-closed: never panics -- mirrors the `blkfmt` fail-closed decoders). A
/// successful decode round-trips back to identical canonical bytes (the
/// `kani_exp_canon_roundtrip` harness).
#[must_use]
pub fn decode(buf: &[u8]) -> Option<ExperienceRecord> {
    if buf.len() < EXP_CANON_LEN {
        return None;
    }
    let decision_id = read_u64(buf, OFF_DECISION_ID);
    let kind = buf[OFF_KIND];
    let mut feats = [0i32; KAN_FEATURES];
    let mut j = 0usize;
    while j < KAN_FEATURES {
        feats[j] = read_i32(buf, OFF_FEATS + j * 4);
        j += 1;
    }
    let envelope_verdict = buf[OFF_ENVELOPE];
    let action_taken = buf[OFF_ACTION];
    let kan_score_shadow = read_i64(buf, OFF_SHADOW);
    let logging_propensity_q = read_u16(buf, OFF_PROPENSITY);
    let logging_policy_kind = buf[OFF_POLICY_KIND];
    let outcome_tag = buf[OFF_OUTCOME_TAG];
    let outcome_payload = read_i64(buf, OFF_OUTCOME_PAYLOAD);
    let outcome = OutcomeLabel::from_parts(outcome_tag, outcome_payload)?; // fail-closed
    let margin_q = read_i16(buf, OFF_MARGIN);
    Some(ExperienceRecord {
        decision_id,
        kind,
        feats,
        envelope_verdict,
        action_taken,
        kan_score_shadow,
        logging_propensity_q,
        logging_policy_kind,
        outcome,
        margin_q,
    })
}

/// REPLAY (the headline claim, proposal §5.2): re-derive the dormant cell's
/// would-be score over a record's quantized `feats` BIT-IDENTICALLY -- the value the
/// record's [`ExperienceRecord::kan_score_shadow`] was logged as. This is the SAME
/// [`kan_score`] the dormant seam evaluates (the M21 artifact), so a recorded row
/// replays to its logged shadow with NO float, NO platform dependence. `table` is
/// the frozen `KAN_TABLE`; `flag_terms`/`bias` are the dormant comparator terms
/// (both `0` this milestone). Pure, total (the kancell clamp proves no panic).
#[inline]
#[must_use]
pub fn replay_shadow(
    table: &KnotTable,
    feats: &[i32; KAN_FEATURES],
    flag_terms: i32,
    bias: i32,
) -> i64 {
    kan_score(table, feats, flag_terms, bias)
}

/// Quantize a raw continuous signal onto the EXACT kancell grid the dormant cell
/// scores over (`[GRID_LO, GRID_LO + 8*step]`), so the recorded `feats` land on a
/// grid point and the shadow score is bit-exactly reconstructible (proposal §3).
/// SATURATING + clamped to the grid range -- total, no panic, no float. The seam
/// calls this with the SAME raw values the forget sweep already computes.
#[inline]
#[must_use]
pub fn quantize_feature(raw: i64) -> i32 {
    let step = 1i64 << GRID_STEP_LOG2;
    let span = step.saturating_mul((9 - 1) as i64); // KAN_KNOTS-1 == 8 intervals
    let lo = GRID_LO as i64;
    let hi = lo.saturating_add(span);
    let c = if raw < lo {
        lo
    } else if raw > hi {
        hi
    } else {
        raw
    };
    c as i32
}

// --- fixed-width LE scalar helpers (pure, total, no panic on a sized buffer) -----
// The caller guarantees the offset window fits (canon/decode check the length
// FIRST), so these index a known-large-enough slice. Kept tiny + inlined so CBMC
// constant-folds them and the harnesses stay cheap.

#[inline]
fn write_u64(out: &mut [u8], off: usize, v: u64) {
    let b = v.to_le_bytes();
    let mut i = 0usize;
    while i < 8 {
        out[off + i] = b[i];
        i += 1;
    }
}

#[inline]
fn write_i64(out: &mut [u8], off: usize, v: i64) {
    write_u64(out, off, v as u64);
}

#[inline]
fn write_i32(out: &mut [u8], off: usize, v: i32) {
    let b = (v as u32).to_le_bytes();
    let mut i = 0usize;
    while i < 4 {
        out[off + i] = b[i];
        i += 1;
    }
}

#[inline]
fn write_u16(out: &mut [u8], off: usize, v: u16) {
    let b = v.to_le_bytes();
    out[off] = b[0];
    out[off + 1] = b[1];
}

#[inline]
fn write_i16(out: &mut [u8], off: usize, v: i16) {
    write_u16(out, off, v as u16);
}

#[inline]
fn read_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

#[inline]
fn read_i64(buf: &[u8], off: usize) -> i64 {
    read_u64(buf, off) as i64
}

#[inline]
fn read_i32(buf: &[u8], off: usize) -> i32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as i32
}

#[inline]
fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

#[inline]
fn read_i16(buf: &[u8], off: usize) -> i16 {
    read_u16(buf, off) as i16
}

/// A fixed-capacity, drop-oldest (FIFO) experience ring (proposal §4) -- the
/// in-RAM, fixed-capacity replay buffer (Lin 1992 / Mnih DQN). `push` NEVER
/// allocates and NEVER panics at capacity: a full ring drops the OLDEST record to
/// admit the newest (the recency bias is NAMED in proposal §8 and accepted for
/// determinism this milestone; reservoir sampling is the M24+ alternative). The
/// fold into `xp_head` is the caller's job (via [`xp_append`]); this ring is the
/// bounded WINDOW of recorded canonical bytes the boot self-test replays over.
///
/// `CAP` is the fixed capacity, `LEN` the per-record byte width ([`EXP_CANON_LEN`]).
/// Stored as fixed `[u8; LEN]` rows so the whole ring is one POD array (no `Vec`,
/// no heap -- the no-alloc fixed-capacity guarantee the `kani_exp_ring_total`
/// harness proves).
#[derive(Clone, Copy, Debug)]
pub struct ExpRing<const CAP: usize, const LEN: usize> {
    rows: [[u8; LEN]; CAP],
    /// The index of the oldest row (the FIFO read cursor).
    head: usize,
    /// The number of live rows (`0..=CAP`).
    len: usize,
}

impl<const CAP: usize, const LEN: usize> Default for ExpRing<CAP, LEN> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAP: usize, const LEN: usize> ExpRing<CAP, LEN> {
    /// A fresh, empty ring (all-zero rows, `len == 0`). No alloc.
    #[must_use]
    pub const fn new() -> Self {
        ExpRing {
            rows: [[0u8; LEN]; CAP],
            head: 0,
            len: 0,
        }
    }

    /// The number of live rows (`0..=CAP`).
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the ring holds no rows.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether the ring is at capacity (the next [`push`](Self::push) drops oldest).
    #[inline]
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.len == CAP
    }

    /// Push one canonical record row, DROP-OLDEST on full. TOTAL: never allocates,
    /// never panics, never blocks. Returns `true` if a prior row was evicted to make
    /// room (the FIFO overwrite), `false` if the ring merely grew. A `CAP == 0` ring
    /// is a no-op (returns `false`) -- it can hold nothing, fail-soft.
    pub fn push(&mut self, row: &[u8; LEN]) -> bool {
        if CAP == 0 {
            return false; // degenerate capacity: nothing to store, never panic
        }
        if self.len < CAP {
            // Append at the logical tail (head + len) mod CAP -- no eviction.
            let slot = (self.head + self.len) % CAP;
            self.rows[slot] = *row;
            self.len += 1;
            false
        } else {
            // Full: overwrite the OLDEST (the head), then advance the head.
            self.rows[self.head] = *row;
            self.head = (self.head + 1) % CAP;
            true
        }
    }

    /// Read the `i`-th live row in FIFO order (`0` == oldest), or `None` if out of
    /// range. Total -- no panic.
    #[inline]
    #[must_use]
    pub fn get(&self, i: usize) -> Option<&[u8; LEN]> {
        if i >= self.len || CAP == 0 {
            return None;
        }
        let slot = (self.head + i) % CAP;
        Some(&self.rows[slot])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ExperienceRecord {
        ExperienceRecord {
            decision_id: 0xDEAD_BEEF_0000_1234,
            kind: kind::FORGET_DECISION,
            feats: [0, 256, 512, 1024],
            envelope_verdict: 1,
            action_taken: 1,
            kan_score_shadow: -777,
            logging_propensity_q: PROPENSITY_DETERMINISTIC_Q,
            logging_policy_kind: policy_kind::DETERMINISTIC,
            outcome: OutcomeLabel::Unset,
            margin_q: -42,
        }
    }

    // ---- canon: layout, length, fail-closed totality ------------------------

    #[test]
    fn canon_len_is_fixed_width() {
        let e = sample();
        assert_eq!(canon_len(&e), EXP_CANON_LEN);
        assert_eq!(EXP_CANON_LEN, 49);
        let mut buf = [0u8; 64];
        let n = canon(&e, &mut buf);
        assert_eq!(n, EXP_CANON_LEN);
    }

    #[test]
    fn canon_fail_closed_on_small_buffer() {
        let e = sample();
        let mut small = [0u8; EXP_CANON_LEN - 1];
        assert_eq!(canon(&e, &mut small), 0);
        assert!(small.iter().all(|&b| b == 0)); // no partial write
        let mut exact = [0u8; EXP_CANON_LEN];
        assert_eq!(canon(&e, &mut exact), EXP_CANON_LEN);
    }

    #[test]
    fn canon_field_offsets() {
        let e = sample();
        let mut buf = [0u8; EXP_CANON_LEN];
        assert_eq!(canon(&e, &mut buf), EXP_CANON_LEN);
        assert_eq!(read_u64(&buf, OFF_DECISION_ID), e.decision_id);
        assert_eq!(buf[OFF_KIND], kind::FORGET_DECISION);
        assert_eq!(read_i32(&buf, OFF_FEATS), 0);
        assert_eq!(read_i32(&buf, OFF_FEATS + 4), 256);
        assert_eq!(read_i32(&buf, OFF_FEATS + 12), 1024);
        assert_eq!(buf[OFF_ENVELOPE], 1);
        assert_eq!(buf[OFF_ACTION], 1);
        assert_eq!(read_i64(&buf, OFF_SHADOW), -777);
        assert_eq!(read_u16(&buf, OFF_PROPENSITY), PROPENSITY_DETERMINISTIC_Q);
        assert_eq!(buf[OFF_POLICY_KIND], policy_kind::DETERMINISTIC);
        assert_eq!(buf[OFF_OUTCOME_TAG], 0); // Unset
        assert_eq!(read_i64(&buf, OFF_OUTCOME_PAYLOAD), 0); // present-but-zero
        assert_eq!(read_i16(&buf, OFF_MARGIN), -42);
    }

    // ---- canon round-trip + injectivity ------------------------------------

    #[test]
    fn canon_decode_roundtrip() {
        let e = sample();
        let mut buf = [0u8; EXP_CANON_LEN];
        assert_eq!(canon(&e, &mut buf), EXP_CANON_LEN);
        assert_eq!(decode(&buf), Some(e));
        // ...and re-encoding the decoded record reproduces identical bytes.
        let r = decode(&buf).unwrap();
        let mut buf2 = [0u8; EXP_CANON_LEN];
        assert_eq!(canon(&r, &mut buf2), EXP_CANON_LEN);
        assert_eq!(buf, buf2);
    }

    #[test]
    fn canon_roundtrip_populated_outcome() {
        // A future M24-shaped record (populated outcome) round-trips too.
        let mut e = sample();
        e.outcome = OutcomeLabel::ReRecalled(987);
        let mut buf = [0u8; EXP_CANON_LEN];
        assert_eq!(canon(&e, &mut buf), EXP_CANON_LEN);
        assert_eq!(decode(&buf), Some(e));
        let mut e2 = sample();
        e2.outcome = OutcomeLabel::Evicted(-5);
        assert_eq!(canon(&e2, &mut buf), EXP_CANON_LEN);
        assert_eq!(decode(&buf), Some(e2));
    }

    #[test]
    fn decode_fail_closed_on_short_and_bad_tag() {
        let e = sample();
        let mut buf = [0u8; EXP_CANON_LEN];
        assert_eq!(canon(&e, &mut buf), EXP_CANON_LEN);
        // Short buffer -> None.
        assert_eq!(decode(&buf[..EXP_CANON_LEN - 1]), None);
        // Unknown outcome tag -> None (fail-closed, never panic).
        buf[OFF_OUTCOME_TAG] = 0xFF;
        assert_eq!(decode(&buf), None);
    }

    fn enc(e: &ExperienceRecord) -> [u8; EXP_CANON_LEN] {
        let mut b = [0u8; EXP_CANON_LEN];
        assert_eq!(canon(e, &mut b), EXP_CANON_LEN);
        b
    }

    #[test]
    fn canon_injective_each_field() {
        let base = sample();
        let b = enc(&base);

        let mut d = base;
        d.decision_id ^= 1;
        assert_ne!(enc(&d), b, "decision_id change must alter the bytes");

        let mut k = base;
        k.kind = kind::RECALL_TOUCH;
        assert_ne!(enc(&k), b, "kind change must alter the bytes");

        let mut f = base;
        f.feats[2] ^= 1;
        assert_ne!(enc(&f), b, "feats change must alter the bytes");

        let mut ev = base;
        ev.envelope_verdict ^= 1;
        assert_ne!(enc(&ev), b, "envelope_verdict change must alter the bytes");

        let mut at = base;
        at.action_taken ^= 1;
        assert_ne!(enc(&at), b, "action_taken change must alter the bytes");

        let mut sh = base;
        sh.kan_score_shadow ^= 1;
        assert_ne!(enc(&sh), b, "kan_score_shadow change must alter the bytes");

        // RESERVED fields are load-bearing for injectivity too.
        let mut pr = base;
        pr.logging_propensity_q ^= 1;
        assert_ne!(enc(&pr), b, "reserved propensity change must alter the bytes");

        let mut pk = base;
        pk.logging_policy_kind = policy_kind::SOFT_GREEDY;
        assert_ne!(enc(&pk), b, "policy_kind change must alter the bytes");

        // The present-Unset OUTCOME TAG is load-bearing (the §5.1 negative control).
        let mut oc = base;
        oc.outcome = OutcomeLabel::ReRecalled(0);
        assert_ne!(enc(&oc), b, "outcome tag change must alter the bytes");

        let mut mg = base;
        mg.margin_q ^= 1;
        assert_ne!(enc(&mg), b, "margin_q change must alter the bytes");
    }

    // ---- schema-stability: Unset vs populated have identical length/offsets --

    #[test]
    fn schema_stability_unset_vs_populated() {
        // An Unset record + a populated one differ ONLY in the outcome tag/payload
        // bytes (38 + 39..47); EVERY other field offset is byte-identical, and the
        // canonical LENGTH is identical -- so M24 populating the outcome cannot shift
        // the fold (the reserve-now correctness obligation).
        let unset = sample();
        let mut populated = sample();
        populated.outcome = OutcomeLabel::ReRecalled(0xABCD);
        let a = enc(&unset);
        let c = enc(&populated);
        assert_eq!(a.len(), c.len());
        // Bytes [0..38) (every field BEFORE the outcome tag) are identical.
        assert_eq!(&a[..OFF_OUTCOME_TAG], &c[..OFF_OUTCOME_TAG]);
        // The trailing margin field (after the fixed 8-byte payload) is identical.
        assert_eq!(&a[OFF_MARGIN..], &c[OFF_MARGIN..]);
        // Only the outcome tag + payload differ.
        assert_ne!(&a[OFF_OUTCOME_TAG..OFF_MARGIN], &c[OFF_OUTCOME_TAG..OFF_MARGIN]);
    }

    // ---- replay: a recorded feats row replays to its logged shadow ----------

    #[test]
    fn replay_reproduces_shadow_bit_identical() {
        // A frozen table (the kancell shape); the shadow is logged as kan_score over
        // feats, and replay_shadow re-derives the SAME i64 bit-for-bit.
        let table: KnotTable = [
            [4000, 3500, 3000, 2400, 1800, 1200, 600, 100, -400],
            [-400, 100, 600, 1200, 1800, 2400, 3000, 3500, 4000],
            [200, 200, 150, 150, 100, 100, 50, 50, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0],
        ];
        let feats = [128i32, 896, 256, 640];
        let logged = kan_score(&table, &feats, 0, 0);
        let mut rec = sample();
        rec.feats = feats;
        rec.kan_score_shadow = logged;
        // Replay the recorded feats -> identical shadow.
        let replayed = replay_shadow(&table, &rec.feats, 0, 0);
        assert_eq!(replayed, rec.kan_score_shadow);
    }

    #[test]
    fn quantize_lands_on_grid_range() {
        let step = 1i64 << GRID_STEP_LOG2;
        let hi = GRID_LO as i64 + step * 8;
        assert_eq!(quantize_feature(i64::MIN), GRID_LO);
        assert_eq!(quantize_feature(i64::MAX) as i64, hi);
        assert_eq!(quantize_feature(512), 512);
    }

    // ---- ring: fixed-capacity, drop-oldest, no panic ------------------------

    #[test]
    fn ring_drops_oldest_at_capacity() {
        const CAP: usize = 3;
        let mut ring: ExpRing<CAP, EXP_CANON_LEN> = ExpRing::new();
        assert!(ring.is_empty());
        // Push CAP distinct rows (no eviction).
        for i in 0..CAP as u64 {
            let mut e = sample();
            e.decision_id = i;
            let evicted = ring.push(&enc(&e));
            assert!(!evicted);
        }
        assert!(ring.is_full());
        assert_eq!(ring.len(), CAP);
        // FIFO order: row 0 is decision_id 0.
        assert_eq!(read_u64(ring.get(0).unwrap(), OFF_DECISION_ID), 0);
        assert_eq!(read_u64(ring.get(2).unwrap(), OFF_DECISION_ID), 2);
        // One more push EVICTS the oldest (decision_id 0); now front is id 1.
        let mut e = sample();
        e.decision_id = 99;
        assert!(ring.push(&enc(&e)));
        assert_eq!(ring.len(), CAP); // capacity never exceeded
        assert_eq!(read_u64(ring.get(0).unwrap(), OFF_DECISION_ID), 1);
        assert_eq!(read_u64(ring.get(2).unwrap(), OFF_DECISION_ID), 99);
        assert_eq!(ring.get(CAP), None); // out of range -> None, no panic
    }

    #[test]
    fn ring_zero_capacity_is_noop() {
        let mut ring: ExpRing<0, EXP_CANON_LEN> = ExpRing::new();
        let e = sample();
        assert!(!ring.push(&enc(&e))); // never panics, never stores
        assert_eq!(ring.len(), 0);
        assert_eq!(ring.get(0), None);
    }

    // ---- fold reuse: the M22 chain folds the canonical bytes ----------------

    #[test]
    fn fold_is_tamper_sensitive_via_prov() {
        // Encode two records, fold each into a fresh head via the REUSED prov fold,
        // and confirm a single-byte tamper of a committed record changes the head.
        let e0 = sample();
        let mut e1 = sample();
        e1.decision_id = 2;
        let mut scratch = [0u8; EXP_CANON_LEN + 8];
        let n0 = canon(&e0, &mut scratch);
        let id0 = xp_hash(&scratch[..n0]);
        let n1 = canon(&e1, &mut scratch);
        let id1 = xp_hash(&scratch[..n1]);
        let head = xp_recompute(id0, &[id1]);
        assert!(xp_verify_inclusion(id0, &[id1], head));
        // Tamper one byte of e0's canonical bytes -> a different id -> head mismatch.
        let mut tampered = [0u8; EXP_CANON_LEN];
        assert_eq!(canon(&e0, &mut tampered), EXP_CANON_LEN);
        tampered[OFF_KIND] ^= 0x01;
        let bad_id = xp_hash(&tampered);
        assert!(!xp_verify_inclusion(bad_id, &[id1], head));
    }
}
