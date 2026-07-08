//! The M39 verified EXPERIENCE-CORPUS CODEC math -- the pure, verified value-
//! computation leaf behind Yuva's Phase-1 EXPERIENCE CORPUS: a GROWING, CURATED,
//! tamper-evident dataset of curated experiences, lifted into `tb-encode` exactly
//! as the M22 provenance ledger ([`crate::prov`]) and the M23 experience log
//! ([`crate::exp`]) were. Each [`CorpusRecord`] is one CURATED experience -- an M17
//! episodic-consolidation outcome, an M25/M28 operator turn, or a labeled-outcome
//! row -- encoded as a fixed-width injective [`canon`] byte layout and folded into a
//! per-agent `corpus_head` via the M22 [`crate::prov`] fold, REUSED VERBATIM (no new
//! fold math). The frozen byte contract is `docs/spec/corpus-format-v1.md`.
//!
//! ## Honest scope (the marker claims ONLY what is proved -- corpus-format-v1 SS0)
//!
//! * **A corpus record is a PROVENANCE SKELETON, not text.** Memory content in Yuva
//!   is stored as u64 INTERNED TOKENS (`mem/mod.rs:766,787,862`), not strings; the
//!   text dictionary is agent-side. So a record carries TOKEN IDS (`content_tok` /
//!   `aux_tok`) + a lineage `source_head` + a `t_created` timestamp + a
//!   `curation_verdict`; the host exporter joins the tokens to text through the agent
//!   dictionary. `token=corpus=PROVENANCE-SKELETON-TEXT-IS-AGENT-DICT-JOIN`.
//! * **This is a LEARNING-PREREQUISITE, not a capability advance.** Building the
//!   corpus is Phase-1 data-engineering that stocks the dataset a Phase-2 (operator-
//!   gated) fine-tune would consume. It does NOT touch `KAN_ACTIVE`, does NOT flip the
//!   Learning pillar out of dormancy, and trains NOTHING.
//!   `token=phase1=LEARNING-PREREQUISITE-NOT-CAPABILITY-ADVANCE`,
//!   `token=training=NONE-PHASE2-GATED`.
//! * **The curation verdict is DECLARED, not learned.** [`CorpusRecord::curation_verdict`]
//!   records the outcome of a deterministic curation predicate (a later in-kernel
//!   increment); nothing here learns or grades. `token=curation=PREDICATE-DECLARED-NOT-LEARNED`.
//! * **CLAIMS tamper-evidence (cryptographic since M29-C), INHERITED from `prov`.**
//!   A single-byte mutation to a committed record's canonical bytes provably
//!   invalidates the recomputed `corpus_head` AND its inclusion proof -- the M22 fold,
//!   reused verbatim (BLAKE2s-256; primitive security `sec=ASSUMED-FROM-LITERATURE`,
//!   never prose-claimed).
//!
//! ## The reserve-now refinement (corpus-format-v1 SS4 -- the schema-stability lemma)
//!
//! Because the codec is a fixed-field injective encoder folded into the M22 hash
//! chain, ADDING fields later would change the canonical bytes and break BOTH replay-
//! determinism and every committed `corpus_head`. So the labeled-outcome
//! [`OutcomeLabel`] (present-`Unset`), the [`CorpusRecord::curation_score_q`] graded-
//! curation sentinel, and the [`CorpusRecord::aux_tok`] secondary handle are RESERVED
//! in the byte layout NOW: a later milestone populating them does NOT shift any field
//! offset or change the canonical length (the `kani_corpus_schema_stability` harness
//! discharges this). `schema_version` is the coarse escape hatch -- a genuinely
//! incompatible v2 changes byte `[0]`, which this v1 decoder REJECTS (fail-closed).
//!
//! ## Numeric format (no float, ever -- mirrors `exp`/`prov`/`blkfmt`)
//!
//! Pure integer/byte arithmetic, zero alloc, zero deps. [`canon`] is a FIXED-WIDTH,
//! fixed-field-order LE byte layout into a caller buffer (total + fail-closed: returns
//! `0` if the buffer is too small, never panics, mirroring [`crate::exp::canon`]).
//! [`decode`] is the exact inverse over a large-enough buffer, fail-closed to `None`
//! on a short buffer OR any out-of-vocabulary closed-set tag. Every field occupies a
//! FIXED offset, so [`canon`] is injective by construction (no variable-length tail).
//! The fold over the canonical bytes REUSES the proven [`crate::prov`] leaf
//! ([`corpus_append`] / [`corpus_chain_mix`] / [`corpus_verify_inclusion`] /
//! [`corpus_head_witness`]) -- NO new fold math is written here.

// The fold is the M22 provenance leaf, REUSED verbatim (corpus-format-v1 SS5: "fold
// into a separate per-agent `corpus_head` via the M22 `chain_mix`"). We import the
// proven digest/fold/verify/witness functions under `corpus_*` aliases; M39 writes
// NONE of its own fold math (the exact M23/M38 prov-reuse discipline). The one wrapper
// below ([`corpus_append`]) does NOT add fold math -- it canon-encodes a
// [`CorpusRecord`] and calls the proven `prov_hash` + `chain_mix`, exactly as
// `prov::append` does for a `ProvEntry`.
pub use crate::prov::{
    chain_mix as corpus_chain_mix, head_witness as corpus_head_witness,
    prov_hash as corpus_hash, recompute as corpus_recompute,
    verify_inclusion as corpus_verify_inclusion, PROV_HASH_LEN,
};

/// The frozen v1 schema version stamped at byte `[0]` of every record. A genuinely
/// incompatible v2 changes this byte; this v1 [`decode`] REJECTS any other value
/// (fail-closed), so a version bump is loud + replay-detectable, never a silent
/// reinterpretation (corpus-format-v1 SS2/SS4).
pub const CORPUS_SCHEMA_V1: u8 = 1;

/// M39 increment-3 (the DURABLE corpus): the 16-byte DOMAIN TAG stamped into the
/// REUSED [`crate::provhead`] record's `i_id` slot to mark an on-disk slab as a
/// Yuva EXPERIENCE-CORPUS region -- disjoint from the M33 signed-head slabs (which
/// live in a SEPARATE disk region and carry the real LMS identifier in that slot).
/// The durable persistence REUSES the proven `provhead` MULTI-SECTOR, TORN-WRITE-
/// SAFE codec VERBATIM (no new fold/codec math): the record `head` slot carries the
/// tamper-evident M22 `corpus_head`, and the `sig` slot carries the packed fixed-
/// width [`CorpusRecord`] canonical bytes (`count * CORPUS_CANON_LEN`). NO LMS
/// signature is added this increment -- the head's tamper-evidence is the M22 fold
/// (reused verbatim), and the `provhead` FNV checksums are TORN-WRITE detection
/// ONLY, never a security property. A read-back whose `i_id` != this tag is
/// fail-closed rejected (a defense-in-depth domain gate on top of the region split).
pub const CORPUS_PERSIST_DOMAIN: [u8; 16] = *b"YUVA-CORPUS-M39\0";

/// The maximum number of fixed-width [`CorpusRecord`]s ONE durable slab carries:
/// `provhead::SIG_CAP / CORPUS_CANON_LEN` (the packed records ride the reused
/// `provhead` signature slot, capped by `SIG_CAP`). An accumulation that would
/// exceed this is bounded to the MOST-RECENT records (the ring discipline the
/// persist seam applies); an unbounded multi-slab corpus region is a later
/// increment. `2508 / 71 == 35`.
pub const CORPUS_PERSIST_MAX_RECORDS: usize = crate::provhead::SIG_CAP / CORPUS_CANON_LEN;

/// The curated-channel kind tags (corpus-format-v1 SS3.1): which curated experience a
/// row is. A closed set the seam emits; the digest folds it in, so an operator-turn
/// can never masquerade as an episodic-consolidation outcome (the byte differs -> the
/// head differs). [`decode`] fails closed on any value outside this set.
pub mod example_kind {
    /// An M17 consolidation outcome -- a `distill()` survivor or `reflect_inner()`
    /// insight promoted to a curated example.
    pub const EPISODIC_CONSOLIDATION: u8 = 1;
    /// An M25/M28 operator-approved turn (a human-in-the-loop transcript row).
    pub const OPERATOR_TURN: u8 = 2;
    /// A row carrying a resolved outcome label from the survival stream.
    pub const LABELED_OUTCOME: u8 = 3;

    /// Whether `v` is a defined `example_kind` (the [`decode`] fail-closed gate).
    #[inline]
    #[must_use]
    pub const fn is_valid(v: u8) -> bool {
        matches!(v, EPISODIC_CONSOLIDATION | OPERATOR_TURN | LABELED_OUTCOME)
    }
}

/// The provenance-stream tags (corpus-format-v1 SS3.2): which substrate stream a row
/// was curated FROM. A closed set; [`decode`] fails closed outside it.
pub mod source_stream {
    /// An M13 `MemRecord` (`content_tok` is the record's content token).
    pub const M13_MEM: u8 = 1;
    /// An M17 reflection insight (`aux_tok` is the cited-back token).
    pub const M17_REFLECT: u8 = 2;
    /// An M25/M28 approved operator turn.
    pub const M25_OPERATOR: u8 = 3;
    /// An M31/M32 inference digest.
    pub const M31_INFER: u8 = 4;

    /// Whether `v` is a defined `source_stream` (the [`decode`] fail-closed gate).
    #[inline]
    #[must_use]
    pub const fn is_valid(v: u8) -> bool {
        matches!(v, M13_MEM | M17_REFLECT | M25_OPERATOR | M31_INFER)
    }
}

/// The DECLARED curation-predicate outcome tags (corpus-format-v1 SS3.3). A REJECTED
/// row is RECORDED, not silently dropped (deletion stays provable, the M22 tombstone
/// discipline). The predicate itself is a deterministic later increment; nothing here
/// learns or grades. `token=curation=PREDICATE-DECLARED-NOT-LEARNED`.
pub mod curation_verdict {
    /// The curation predicate declined the row (recorded, not dropped).
    pub const REJECTED: u8 = 0;
    /// The curation predicate admitted the row into the corpus.
    pub const ACCEPTED: u8 = 1;

    /// Whether `v` is a defined `curation_verdict` (the [`decode`] fail-closed gate).
    #[inline]
    #[must_use]
    pub const fn is_valid(v: u8) -> bool {
        matches!(v, REJECTED | ACCEPTED)
    }
}

/// The labeled-outcome channel (corpus-format-v1 SS3.4), a PRESENT-but-UNSET tagged
/// variant mirroring the PROVEN M23 [`crate::exp::OutcomeLabel`] idiom so populating
/// it later is bit-stable (the schema-stability lemma). The tag occupies one byte and
/// the payload a fixed `i64` slot REGARDLESS of variant, so an `Unset` record and a
/// future `Positive`/`Negative` record have IDENTICAL length + field offsets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutcomeLabel {
    /// This milestone: the outcome is DEFERRED (no validated label yet). The payload
    /// slot is present-but-zero. A later increment replaces this WITHOUT shifting any
    /// byte offset.
    Unset,
    /// RESERVED: a positive training label (e.g. an operator-approval id). Payload
    /// carries the label id/score.
    Positive(i64),
    /// RESERVED: a negative training label (e.g. a corrected/rejected id). Payload
    /// carries the label id/score.
    Negative(i64),
}

impl OutcomeLabel {
    /// The fixed `u8` tag byte for this variant (present in EVERY record's layout, so
    /// the tag is load-bearing for injectivity: dropping/aliasing it would let two
    /// distinct outcomes collide -- the negative control of `kani_corpus_canon_injective`).
    #[inline]
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            OutcomeLabel::Unset => 0,
            OutcomeLabel::Positive(_) => 1,
            OutcomeLabel::Negative(_) => 2,
        }
    }

    /// The fixed `i64` payload slot for this variant (`0` for `Unset` -- the present-
    /// but-zero sentinel). ALWAYS occupies 8 bytes in [`canon`], regardless of variant,
    /// so populating an `Unset` record cannot shift the layout.
    #[inline]
    #[must_use]
    pub fn payload(self) -> i64 {
        match self {
            OutcomeLabel::Unset => 0,
            OutcomeLabel::Positive(v) | OutcomeLabel::Negative(v) => v,
        }
    }

    /// Reconstruct an [`OutcomeLabel`] from its `(tag, payload)` byte pair (the
    /// [`decode`] inverse). An unknown tag fails closed to `None` (total decode).
    #[inline]
    #[must_use]
    pub fn from_parts(tag: u8, payload: i64) -> Option<OutcomeLabel> {
        match tag {
            0 => Some(OutcomeLabel::Unset),
            1 => Some(OutcomeLabel::Positive(payload)),
            2 => Some(OutcomeLabel::Negative(payload)),
            _ => None,
        }
    }
}

/// A fixed, canonical corpus record (corpus-format-v1 SS2) -- ONE curated experience as
/// a PROVENANCE SKELETON. EVERY field is FIXED-WIDTH, so [`canon`] is injective by
/// construction (distinct records always encode to distinct bytes -- no variable-
/// length tail to disambiguate). The RESERVED [`outcome`](Self::outcome) (present-
/// `Unset`), [`curation_score_q`](Self::curation_score_q), and [`aux_tok`](Self::aux_tok)
/// fields are in the layout NOW so a later milestone populating them keeps the
/// canonical bytes / hash-fold stable (the schema-stability lemma).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorpusRecord {
    /// The frozen schema version (`= CORPUS_SCHEMA_V1`); a bump is replay-detectable
    /// and this v1 decoder rejects any other value.
    pub schema_version: u8,
    /// The curated channel (see [`example_kind`]): episodic-consolidation / operator-
    /// turn / labeled-outcome.
    pub example_kind: u8,
    /// The provenance stream the row was curated from (see [`source_stream`]).
    pub source_stream: u8,
    /// The DECLARED curation-predicate outcome (see [`curation_verdict`]).
    pub curation_verdict: u8,
    /// The interned CONTENT token id -- the agent-dictionary text-join handle
    /// (PROVENANCE SKELETON, not text).
    pub content_tok: u64,
    /// A secondary interned token id (reflect cite-back / operator response / inference
    /// prompt handle), `0` when unused. RESERVED per `example_kind`.
    pub aux_tok: u64,
    /// The substrate logical clock at curation time.
    pub t_created: u64,
    /// The M22 fold-position: the lineage head (`chain_head`/`xp_head`) this row was
    /// curated at, linking it back to its source provenance (all-zero = genesis).
    pub source_head: [u8; PROV_HASH_LEN],
    /// The labeled-outcome channel -- PRESENT-but-`Unset` this milestone (RESERVED).
    pub outcome: OutcomeLabel,
    /// RESERVED graded-curation sentinel (present; `0` this milestone).
    pub curation_score_q: i16,
}

/// The fixed canonical byte length of EVERY [`CorpusRecord`]. The record is fully
/// FIXED-WIDTH (no variable-length tail), so this is a single `const` the schema-
/// stability lemma pins: an `Unset` record and a populated one have the SAME length.
/// Layout (corpus-format-v1 SS2, all LE):
///
/// ```text
///   [0]      schema_version    u8
///   [1]      example_kind      u8
///   [2]      source_stream     u8
///   [3]      curation_verdict  u8
///   [4..12]  content_tok       u64 LE
///   [12..20] aux_tok           u64 LE
///   [20..28] t_created         u64 LE
///   [28..60] source_head       [u8;32]
///   [60]     outcome.tag       u8
///   [61..69] outcome.payload   i64 LE   (present-but-zero for Unset)
///   [69..71] curation_score_q  i16 LE   (RESERVED sentinel)
/// ```
pub const CORPUS_CANON_LEN: usize = 1 + 1 + 1 + 1 + 8 + 8 + 8 + PROV_HASH_LEN + 1 + 8 + 2;

// Fixed field offsets (the layout above). Kept as named consts so the schema-
// stability lemma + the round-trip read the SAME literals the encoder writes.
const OFF_SCHEMA_VERSION: usize = 0;
const OFF_EXAMPLE_KIND: usize = 1;
const OFF_SOURCE_STREAM: usize = 2;
const OFF_CURATION_VERDICT: usize = 3;
const OFF_CONTENT_TOK: usize = 4;
const OFF_AUX_TOK: usize = 12;
const OFF_T_CREATED: usize = 20;
const OFF_SOURCE_HEAD: usize = 28;
const OFF_OUTCOME_TAG: usize = 60;
const OFF_OUTCOME_PAYLOAD: usize = 61;
const OFF_CURATION_SCORE: usize = 69;

// Compile-pin: the outcome window is the fixed 9 bytes `[OFF_OUTCOME_TAG..OFF_CURATION_SCORE)`
// and the record ends exactly at CORPUS_CANON_LEN (a drifted layout can never build).
const _: () = assert!(OFF_CURATION_SCORE - OFF_OUTCOME_TAG == 1 + 8);
const _: () = assert!(OFF_CURATION_SCORE + 2 == CORPUS_CANON_LEN);
const _: () = assert!(OFF_SOURCE_HEAD + PROV_HASH_LEN == OFF_OUTCOME_TAG);

/// The exact canonical byte length of `rec` -- a tautological [`CORPUS_CANON_LEN`]
/// (the record is fixed-width), kept as a function to mirror [`crate::exp::canon_len`]'s
/// shape so the seam sizes its scratch buffer identically.
#[inline]
#[must_use]
pub fn canon_len(_rec: &CorpusRecord) -> usize {
    CORPUS_CANON_LEN
}

/// Canonical, UNAMBIGUOUS, total fixed-width LE encoding of `rec` into `out`. Returns
/// the number of bytes written ([`CORPUS_CANON_LEN`]), or `0` if `out` is too small
/// (TOTAL + fail-closed: never panics, never partial-writes -- mirrors
/// [`crate::exp::canon`]).
///
/// INJECTIVITY: every field occupies a FIXED offset and a fixed width, so two records
/// that differ in ANY field encode to different bytes -- there is no variable-length
/// tail and thus no field-boundary ambiguity (the `kani_corpus_canon_injective`
/// harness discharges this, INCLUDING the RESERVED `curation_score_q` field and the
/// present-`Unset` outcome tag). Note `canon` encodes over the WHOLE `u8` domain of the
/// closed-set fields (validity is a `decode` property, not an encode one).
#[must_use]
pub fn canon(rec: &CorpusRecord, out: &mut [u8]) -> usize {
    // Fail-closed: too-small buffer -> 0 bytes, no partial write (totality).
    if out.len() < CORPUS_CANON_LEN {
        return 0;
    }
    out[OFF_SCHEMA_VERSION] = rec.schema_version;
    out[OFF_EXAMPLE_KIND] = rec.example_kind;
    out[OFF_SOURCE_STREAM] = rec.source_stream;
    out[OFF_CURATION_VERDICT] = rec.curation_verdict;
    write_u64(out, OFF_CONTENT_TOK, rec.content_tok);
    write_u64(out, OFF_AUX_TOK, rec.aux_tok);
    write_u64(out, OFF_T_CREATED, rec.t_created);
    let mut b = 0usize;
    while b < PROV_HASH_LEN {
        out[OFF_SOURCE_HEAD + b] = rec.source_head[b];
        b += 1;
    }
    out[OFF_OUTCOME_TAG] = rec.outcome.tag();
    write_i64(out, OFF_OUTCOME_PAYLOAD, rec.outcome.payload());
    write_i16(out, OFF_CURATION_SCORE, rec.curation_score_q);
    CORPUS_CANON_LEN
}

/// The exact inverse of [`canon`]: decode `buf` back into a [`CorpusRecord`], or `None`
/// if `buf` is too small OR carries an out-of-vocabulary tag (TOTAL + fail-closed:
/// never panics -- the frozen v1 fail-closed posture, corpus-format-v1 SS3/SS6). A
/// successful decode round-trips back to identical canonical bytes (the
/// `kani_corpus_canon_roundtrip` harness). Rejected byte patterns: a short buffer, a
/// `schema_version != CORPUS_SCHEMA_V1`, or an unknown `example_kind` / `source_stream`
/// / `curation_verdict` / `outcome.tag`.
#[must_use]
pub fn decode(buf: &[u8]) -> Option<CorpusRecord> {
    if buf.len() < CORPUS_CANON_LEN {
        return None;
    }
    let schema_version = buf[OFF_SCHEMA_VERSION];
    if schema_version != CORPUS_SCHEMA_V1 {
        return None; // this is the v1 decoder -- an unknown version fails closed
    }
    let example_kind = buf[OFF_EXAMPLE_KIND];
    if !example_kind::is_valid(example_kind) {
        return None;
    }
    let source_stream = buf[OFF_SOURCE_STREAM];
    if !source_stream::is_valid(source_stream) {
        return None;
    }
    let curation_verdict = buf[OFF_CURATION_VERDICT];
    if !curation_verdict::is_valid(curation_verdict) {
        return None;
    }
    let content_tok = read_u64(buf, OFF_CONTENT_TOK);
    let aux_tok = read_u64(buf, OFF_AUX_TOK);
    let t_created = read_u64(buf, OFF_T_CREATED);
    let mut source_head = [0u8; PROV_HASH_LEN];
    let mut b = 0usize;
    while b < PROV_HASH_LEN {
        source_head[b] = buf[OFF_SOURCE_HEAD + b];
        b += 1;
    }
    let outcome_tag = buf[OFF_OUTCOME_TAG];
    let outcome_payload = read_i64(buf, OFF_OUTCOME_PAYLOAD);
    let outcome = OutcomeLabel::from_parts(outcome_tag, outcome_payload)?; // fail-closed
    let curation_score_q = read_i16(buf, OFF_CURATION_SCORE);
    Some(CorpusRecord {
        schema_version,
        example_kind,
        source_stream,
        curation_verdict,
        content_tok,
        aux_tok,
        t_created,
        source_head,
        outcome,
        curation_score_q,
    })
}

/// Fold `rec` into `head` in one step -- canon-encode into a caller-supplied scratch
/// buffer, [`corpus_hash`] the canonical bytes, and [`corpus_chain_mix`] the resulting
/// record id into `head`. Returns `(new_head, record_id)`, or `None` if `scratch` is
/// too small for the record's canonical bytes (fail-closed -- the caller sizes
/// `scratch >= canon_len(rec)`). This is the exact step the in-kernel `corpus_head`
/// seam runs at each curation site, and it writes NO fold math -- it REUSES the proven
/// `prov` leaf verbatim (the mirror of [`crate::prov::append`], for a [`CorpusRecord`]).
#[must_use]
pub fn corpus_append(
    head: [u8; PROV_HASH_LEN],
    rec: &CorpusRecord,
    scratch: &mut [u8],
) -> Option<([u8; PROV_HASH_LEN], [u8; PROV_HASH_LEN])> {
    let n = canon(rec, scratch);
    if n == 0 {
        return None; // buffer too small -- fail closed, no head advance
    }
    let record_id = corpus_hash(&scratch[..n]);
    let new_head = corpus_chain_mix(head, record_id);
    Some((new_head, record_id))
}

// --- fixed-width LE scalar helpers (pure, total, no panic on a sized buffer) -----
// The caller guarantees the offset window fits (canon/decode check the length FIRST),
// so these index a known-large-enough slice. Kept tiny + inlined so CBMC constant-
// folds them and the harnesses stay cheap (the exact `exp.rs` helper shape).

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
fn write_i16(out: &mut [u8], off: usize, v: i16) {
    let b = (v as u16).to_le_bytes();
    out[off] = b[0];
    out[off + 1] = b[1];
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
fn read_i16(buf: &[u8], off: usize) -> i16 {
    u16::from_le_bytes([buf[off], buf[off + 1]]) as i16
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(seed: u8) -> [u8; PROV_HASH_LEN] {
        let mut a = [0u8; PROV_HASH_LEN];
        let mut i = 0usize;
        while i < PROV_HASH_LEN {
            a[i] = seed.wrapping_add(i as u8).wrapping_mul(31);
            i += 1;
        }
        a
    }

    fn sample() -> CorpusRecord {
        CorpusRecord {
            schema_version: CORPUS_SCHEMA_V1,
            example_kind: example_kind::EPISODIC_CONSOLIDATION,
            source_stream: source_stream::M17_REFLECT,
            curation_verdict: curation_verdict::ACCEPTED,
            content_tok: 0x00C0_FFEE_1234,
            aux_tok: 0xBEEF,
            t_created: 4242,
            source_head: head(9),
            outcome: OutcomeLabel::Unset,
            curation_score_q: 0,
        }
    }

    // ---- canon: layout, length, fail-closed totality ------------------------

    #[test]
    fn canon_len_is_fixed_width() {
        let e = sample();
        assert_eq!(canon_len(&e), CORPUS_CANON_LEN);
        assert_eq!(CORPUS_CANON_LEN, 71);
        let mut buf = [0u8; 96];
        assert_eq!(canon(&e, &mut buf), CORPUS_CANON_LEN);
    }

    #[test]
    fn canon_fail_closed_on_small_buffer() {
        let e = sample();
        let mut small = [0u8; CORPUS_CANON_LEN - 1];
        assert_eq!(canon(&e, &mut small), 0);
        assert!(small.iter().all(|&b| b == 0)); // no partial write
        let mut exact = [0u8; CORPUS_CANON_LEN];
        assert_eq!(canon(&e, &mut exact), CORPUS_CANON_LEN);
    }

    #[test]
    fn canon_field_offsets() {
        let e = sample();
        let mut buf = [0u8; CORPUS_CANON_LEN];
        assert_eq!(canon(&e, &mut buf), CORPUS_CANON_LEN);
        assert_eq!(buf[OFF_SCHEMA_VERSION], CORPUS_SCHEMA_V1);
        assert_eq!(buf[OFF_EXAMPLE_KIND], example_kind::EPISODIC_CONSOLIDATION);
        assert_eq!(buf[OFF_SOURCE_STREAM], source_stream::M17_REFLECT);
        assert_eq!(buf[OFF_CURATION_VERDICT], curation_verdict::ACCEPTED);
        assert_eq!(read_u64(&buf, OFF_CONTENT_TOK), 0x00C0_FFEE_1234);
        assert_eq!(read_u64(&buf, OFF_AUX_TOK), 0xBEEF);
        assert_eq!(read_u64(&buf, OFF_T_CREATED), 4242);
        assert_eq!(&buf[OFF_SOURCE_HEAD..OFF_SOURCE_HEAD + PROV_HASH_LEN], &head(9));
        assert_eq!(buf[OFF_OUTCOME_TAG], 0); // Unset
        assert_eq!(read_i64(&buf, OFF_OUTCOME_PAYLOAD), 0); // present-but-zero
        assert_eq!(read_i16(&buf, OFF_CURATION_SCORE), 0);
    }

    // ---- canon round-trip + injectivity ------------------------------------

    #[test]
    fn canon_decode_roundtrip() {
        let e = sample();
        let mut buf = [0u8; CORPUS_CANON_LEN];
        assert_eq!(canon(&e, &mut buf), CORPUS_CANON_LEN);
        assert_eq!(decode(&buf), Some(e));
        // Re-encoding the decoded record reproduces identical bytes.
        let r = decode(&buf).unwrap();
        let mut buf2 = [0u8; CORPUS_CANON_LEN];
        assert_eq!(canon(&r, &mut buf2), CORPUS_CANON_LEN);
        assert_eq!(buf, buf2);
    }

    #[test]
    fn canon_roundtrip_populated_outcome() {
        // A future labeled-outcome record (populated outcome) round-trips too.
        let mut e = sample();
        e.example_kind = example_kind::LABELED_OUTCOME;
        e.outcome = OutcomeLabel::Positive(987);
        e.curation_score_q = -3;
        let mut buf = [0u8; CORPUS_CANON_LEN];
        assert_eq!(canon(&e, &mut buf), CORPUS_CANON_LEN);
        assert_eq!(decode(&buf), Some(e));
        let mut e2 = sample();
        e2.outcome = OutcomeLabel::Negative(-5);
        assert_eq!(canon(&e2, &mut buf), CORPUS_CANON_LEN);
        assert_eq!(decode(&buf), Some(e2));
    }

    #[test]
    fn decode_fail_closed_on_short_and_bad_tags() {
        let e = sample();
        let mut buf = [0u8; CORPUS_CANON_LEN];
        assert_eq!(canon(&e, &mut buf), CORPUS_CANON_LEN);
        // Short buffer -> None.
        assert_eq!(decode(&buf[..CORPUS_CANON_LEN - 1]), None);
        // Unknown schema version -> None (this is the v1 decoder).
        let mut bad_ver = buf;
        bad_ver[OFF_SCHEMA_VERSION] = 2;
        assert_eq!(decode(&bad_ver), None);
        // Unknown example_kind -> None.
        let mut bad_ek = buf;
        bad_ek[OFF_EXAMPLE_KIND] = 0xFF;
        assert_eq!(decode(&bad_ek), None);
        // Unknown source_stream -> None.
        let mut bad_ss = buf;
        bad_ss[OFF_SOURCE_STREAM] = 0xFF;
        assert_eq!(decode(&bad_ss), None);
        // Unknown curation_verdict -> None.
        let mut bad_cv = buf;
        bad_cv[OFF_CURATION_VERDICT] = 0xFF;
        assert_eq!(decode(&bad_cv), None);
        // Unknown outcome tag -> None (fail-closed, never panic).
        let mut bad_oc = buf;
        bad_oc[OFF_OUTCOME_TAG] = 0xFF;
        assert_eq!(decode(&bad_oc), None);
    }

    fn enc(e: &CorpusRecord) -> [u8; CORPUS_CANON_LEN] {
        let mut b = [0u8; CORPUS_CANON_LEN];
        assert_eq!(canon(e, &mut b), CORPUS_CANON_LEN);
        b
    }

    #[test]
    fn canon_injective_each_field() {
        let base = sample();
        let b = enc(&base);

        let mut sv = base;
        sv.schema_version ^= 0x10;
        assert_ne!(enc(&sv), b, "schema_version change must alter the bytes");

        let mut ek = base;
        ek.example_kind = example_kind::OPERATOR_TURN;
        assert_ne!(enc(&ek), b, "example_kind change must alter the bytes");

        let mut ss = base;
        ss.source_stream = source_stream::M31_INFER;
        assert_ne!(enc(&ss), b, "source_stream change must alter the bytes");

        let mut cv = base;
        cv.curation_verdict = curation_verdict::REJECTED;
        assert_ne!(enc(&cv), b, "curation_verdict change must alter the bytes");

        let mut ct = base;
        ct.content_tok ^= 1;
        assert_ne!(enc(&ct), b, "content_tok change must alter the bytes");

        let mut au = base;
        au.aux_tok ^= 1;
        assert_ne!(enc(&au), b, "aux_tok change must alter the bytes");

        let mut tc = base;
        tc.t_created ^= 1;
        assert_ne!(enc(&tc), b, "t_created change must alter the bytes");

        let mut sh = base;
        sh.source_head[7] ^= 1;
        assert_ne!(enc(&sh), b, "source_head change must alter the bytes");

        // The present-`Unset` OUTCOME TAG is load-bearing (the injectivity neg control).
        let mut oc = base;
        oc.outcome = OutcomeLabel::Positive(0);
        assert_ne!(enc(&oc), b, "outcome tag change must alter the bytes");

        // The RESERVED curation_score_q is load-bearing for injectivity too.
        let mut cs = base;
        cs.curation_score_q ^= 1;
        assert_ne!(enc(&cs), b, "reserved curation_score_q change must alter the bytes");
    }

    // ---- schema-stability: Unset vs populated have identical length/offsets --

    #[test]
    fn schema_stability_unset_vs_populated() {
        // An Unset record + a populated one differ ONLY in the outcome tag/payload
        // window (60..69); EVERY other field offset is byte-identical, and the
        // canonical LENGTH is identical -- so a later increment populating the outcome
        // cannot shift the fold (the reserve-now correctness obligation).
        let unset = sample();
        let mut populated = sample();
        populated.outcome = OutcomeLabel::Positive(0xABCD);
        let a = enc(&unset);
        let c = enc(&populated);
        assert_eq!(a.len(), c.len());
        // Bytes [0..60) (every field BEFORE the outcome tag) are identical.
        assert_eq!(&a[..OFF_OUTCOME_TAG], &c[..OFF_OUTCOME_TAG]);
        // The trailing curation_score_q field (after the fixed 8-byte payload) is identical.
        assert_eq!(&a[OFF_CURATION_SCORE..], &c[OFF_CURATION_SCORE..]);
        // Only the outcome tag + payload window differs.
        assert_ne!(&a[OFF_OUTCOME_TAG..OFF_CURATION_SCORE], &c[OFF_OUTCOME_TAG..OFF_CURATION_SCORE]);
    }

    // ---- fold reuse: the M22 chain folds the canonical bytes ----------------

    #[test]
    fn fold_is_deterministic_and_tamper_sensitive_via_prov() {
        // Encode two records, fold each into a fresh head via the REUSED prov fold,
        // and confirm (a) determinism and (b) a single-byte tamper of a committed
        // record changes the head + fails the inclusion proof.
        let e0 = sample();
        let mut e1 = sample();
        e1.content_tok = 2;
        let mut scratch = [0u8; CORPUS_CANON_LEN + 8];

        // Determinism: append the same record from the same head twice -> same head.
        let genesis = [0u8; PROV_HASH_LEN];
        let (ha, id_a) = corpus_append(genesis, &e0, &mut scratch).unwrap();
        let (hb, id_b) = corpus_append(genesis, &e0, &mut scratch).unwrap();
        assert_eq!(ha, hb);
        assert_eq!(id_a, id_b);

        // Build a 2-record chain; inclusion of the first verifies.
        let n0 = canon(&e0, &mut scratch);
        let id0 = corpus_hash(&scratch[..n0]);
        let n1 = canon(&e1, &mut scratch);
        let id1 = corpus_hash(&scratch[..n1]);
        let chain_head = corpus_recompute(id0, &[id1]);
        assert!(corpus_verify_inclusion(id0, &[id1], chain_head));

        // Tamper one byte of e0's canonical bytes -> a different id -> head mismatch.
        let mut tampered = [0u8; CORPUS_CANON_LEN];
        assert_eq!(canon(&e0, &mut tampered), CORPUS_CANON_LEN);
        tampered[OFF_EXAMPLE_KIND] ^= 0x01;
        let bad_id = corpus_hash(&tampered);
        assert!(bad_id != id0);
        assert!(!corpus_verify_inclusion(bad_id, &[id1], chain_head));

        // The head witness moves when the head moves (the boot-line witness).
        assert_ne!(corpus_head_witness(ha), corpus_head_witness(chain_head));
    }

    #[test]
    fn append_fail_closed_on_small_scratch() {
        let e = sample();
        let mut tiny = [0u8; 8]; // far too small for CORPUS_CANON_LEN
        assert!(corpus_append([0u8; PROV_HASH_LEN], &e, &mut tiny).is_none());
    }
}
