//! The M40 verified LEXICAL RECALL-SCORING math -- the pure, no-float, fixed-point
//! BM25-family relevance kernel behind Yuva's memory retrieval, lifted into
//! `tb-encode` exactly as the M13 recall RANKING math ([`crate::memscore`]) and the
//! M16 route helpers were. This is the "learns to research" skill foundation stated
//! honestly: it SHARPENS which memory records a query surfaces, using classic
//! LEXICAL term-overlap scoring (Robertson/Sparck-Jones BM25) -- term frequency,
//! inverse document frequency, and document-length normalization -- over the u64
//! INTERNED TOKENS Yuva's memory stores. It is emphatically NOT semantic: there are
//! NO embeddings, NO vectors, NO learned weights, and NO float anywhere (a semantic
//! retriever needs a no-float fixed-point embedding encoder that does not exist --
//! out of scope, `token=retrieval=LEXICAL-BM25-NO-FLOAT`, `token=semantic=NONE`).
//!
//! These functions are the deterministic, FPU-free, zero-dep arithmetic that decides
//! HOW RELEVANT a candidate memory record is to a query token-set -- the relevance
//! computation one millimetre in front of the M13 tier logic, with no `unsafe`, no
//! floats, and no kernel state:
//!
//!   * [`bm25_idf`] -- the non-negative Lucene/BM25+ inverse document frequency
//!     `ln(1 + (N - df + 0.5)/(df + 0.5))` in fixed point (a rarer term scores
//!     higher). This is the EXACT expression the M13 `mem::recall` computed inline;
//!     hoisting it HERE makes the production recall path CALL a Kani-proven leaf (the
//!     `memscore`/`route` precedent), numerically identical (no ranking drift).
//!   * [`bm25_tf_norm`] -- the term-frequency SATURATION with document-length
//!     normalization `(tf*(k1+1)) / (tf + k1*(1 - b + b*dl/avgl))` in fixed point
//!     (more matches never lowers the score, but saturates; a longer document is
//!     penalized). `k1`/`b` are the frozen integer constants [`BM25_K1`]/[`BM25_B`].
//!   * [`bm25_term_score`] -- one query term's full BM25 contribution to one document
//!     (`idf * tf_norm`), and [`bm25_doc_score`] -- the additive accumulation over a
//!     query token-SET (the multi-term score, saturating).
//!   * [`hit_canon`] / [`hit_decode`] -- a FIXED-WIDTH injective, fail-closed encode
//!     of a ranked hit `(rank, id, score)`, so a ranking result is a
//!     replay-deterministic record (the M22/M39 canon discipline, no fold math here).
//!
//! Hoisting them HERE makes them host-verifiable with NO model drift: `tb-hal` CALLS
//! these exact functions, the Tier-0 Miri lane EXECUTES them over concrete
//! monotonicity/correctness vectors, and the `prove-encode` Kani lane proves
//! panic/overflow-freedom + monotonicity + bounds over UNTRUSTED query/document
//! metadata -- exactly the `memscore` / `vmx` / `paging` precedent. `#![no_std]` and
//! `#![forbid(unsafe_code)]` (inherited from the crate root): pure integer
//! arithmetic, zero alloc, zero deps. The integer logarithm is [`crate::memscore::ln_fixed`],
//! REUSED verbatim (already Kani-proven panic-free/bounded/monotone -- no new log math).
//!
//! ## Reachable-input envelope (a SOUNDNESS note, read before extending a proof)
//!
//! The fixed-point scheme multiplies intermediates by [`SCALE`] (1000), so the
//! arithmetic is panic-free only over the values the recall path can actually feed:
//! a document has a BOUNDED token count and the corpus a BOUNDED document count. The
//! Kani harnesses `assume` a documented envelope and prove panic-freedom + bounds
//! WITHIN it. At astronomically large `tf` / `doc_len` (beyond ~`2^40`) the
//! `numer * SCALE` term could overflow `i64`; neither is reachable from the interned-
//! token memory. An unconstrained full-range harness would be UNSOUND and turn the
//! lane RED -- the #49 over-quantification trap the `memscore` leaf documents.
//!
//! ## Two distinct envelopes -- and WHY the document one is `2^8` (a TRACTABILITY +
//! REACHABLE-BOUND note, deliberate, NOT a silent coverage cut)
//!
//! The DOCUMENT-size fields (`tf`, `doc_len`, `avg_len`) enter a SYMBOLIC integer
//! DIVISION (`numer * SCALE / denom`, `dl / avgl`), which CBMC bit-blasts into a
//! costly 64-bit divider circuit -- so the harnesses bound them to [`ENVELOPE_MAX`]
//! (`256`). This is the REACHABLE document-token count, not a convenience clamp:
//! Yuva's memory records are SINGLE-TOKEN by the MEMORY-SPEC design (`mem/mod.rs`
//! `content_tok`/`token`/`body_tok`), so a recall "document" has `tf == 1` and
//! `doc_len == 1` today; `256` leaves 256x headroom for any future short multi-token
//! record. The `denom > 0`, saturation, and non-negativity properties the harnesses
//! prove hold IDENTICALLY at every scale, so bounding to the reachable slice removes
//! only wasted over-provisioned range -- every mutation-table mutant (div-by-zero at
//! `avg_len==0`, the dropped `.max(0)`, `saturating_add`->`sub`, the removed `/SCALE`)
//! still fires WITHIN `2^8`, so no harness is made vacuous. The CORPUS-size fields
//! (`df`, `n_docs`) enter only [`bm25_idf`], whose logarithm reuses the CHEAP proven
//! `ln_fixed`, so those stay bounded much wider (`< 2^20`, a million-document corpus)
//! at no tractability cost. This split -- narrow the division-bearing document
//! envelope to the reachable slice, keep the cheap corpus envelope wide -- is the
//! exact CBMC-budget discipline the M31/M33-B proofs follow.

use crate::memscore::ln_fixed;

/// Fixed-point scale: `1.0` is represented as `SCALE`. Mirrors [`crate::memscore`]'s
/// `SCALE` so the two recall leaves compose without a unit mismatch.
pub const SCALE: i64 = 1000;

/// BM25 `k1` (term-frequency saturation) as a fixed-point constant: `1.2 * SCALE`.
/// Larger `k1` = slower saturation (raw term counts matter more). The literature
/// default band is `[1.2, 2.0]`; `1.2` is the Lucene default. FROZEN, not learned.
pub const BM25_K1: i64 = 1200;

/// BM25 `b` (document-length normalization strength) as a fixed-point constant:
/// `0.75 * SCALE`. `b = 0` disables length normalization; `b = SCALE` (1.0) applies
/// it fully. `0.75` is the Lucene default. FROZEN, not learned.
pub const BM25_B: i64 = 750;

/// The reachable-input envelope for the DOCUMENT-size fields (`tf` / `doc_len` /
/// `avg_len`): a recall document holds fewer than `256` interned tokens. This is the
/// REACHABLE bound, not a convenience clamp -- Yuva's memory records are single-token
/// (`tf == doc_len == 1` today), so `256` is 256x headroom. The Kani harnesses
/// `assume` these fields below this so the SYMBOLIC integer division stays tractable
/// (see the module-level two-envelope note); the fixed-point `numer * SCALE` terms
/// stay well inside `i64`. The corpus-size fields (`df` / `n_docs`) are bounded
/// separately and wider (they feed only the cheap [`bm25_idf`]).
pub const ENVELOPE_MAX: u64 = 1 << 8;

/// The exclusive upper bound on [`bm25_tf_norm`]: the term-frequency saturation term
/// `(tf*(k1+1))/(tf + k1*norm)` tends to `k1 + 1` as `tf -> inf`, so scaled by
/// [`SCALE`] it is strictly below `BM25_K1 + SCALE` (`2200`). Used as the proven
/// range ceiling.
pub const TF_NORM_CEIL: i64 = BM25_K1 + SCALE;

/// Non-negative Lucene/BM25+ inverse document frequency in fixed point:
/// `max(0, ln(1 + (N - df + 0.5)/(df + 0.5))) * SCALE`, computed as
/// `(ln_fixed(2N + 2) - ln_fixed(2df + 1)).max(0)` -- the EXACT expression the M13
/// `mem::recall` used inline, hoisted verbatim so the production path calls this
/// proven leaf with ZERO ranking drift. A rarer term (smaller `df`) scores higher; a
/// term in every document (`df == N`) scores at or near `0`. Fail-safe: `df` is
/// clamped to `[1, n_docs.max(1)]` so the argument stays `>= 1` (`ln_fixed(x) = 0`
/// for `x <= 1` in any case) -- never panics.
#[must_use]
pub fn bm25_idf(df: u64, n_docs: u64) -> i64 {
    let n = n_docs.max(1);
    let d = df.clamp(1, n);
    (ln_fixed(2 * n + 2) - ln_fixed(2 * d + 1)).max(0)
}

/// BM25 term-frequency SATURATION with document-length normalization, in fixed point:
/// `(tf * (k1 + 1)) / (tf + k1 * (1 - b + b * dl/avgl)) * SCALE`.
///
/// Returns a value in `[0, TF_NORM_CEIL)`: `0` when `tf == 0` (the term does not
/// occur), rising and SATURATING toward [`TF_NORM_CEIL`] as `tf` grows, and PENALIZED
/// when the document is longer than average (`dl > avgl`). `avg_len` is clamped to
/// `>= 1` (a corpus with any document has a positive average). The length factor
/// `norm = (1 - b) + b * dl/avgl` is `>= (1 - b) > 0`, so the denominator is always
/// positive -- never a divide-by-zero, never a panic within [`ENVELOPE_MAX`].
#[must_use]
pub fn bm25_tf_norm(tf: u64, doc_len: u64, avg_len: u64) -> i64 {
    let tf = tf as i64;
    let dl = doc_len as i64;
    let avgl = (avg_len.max(1)) as i64;
    // norm = (1 - b + b*dl/avgl) * SCALE. The length ratio is evaluated
    // MULTIPLY-BEFORE-DIVIDE -- `(BM25_B * dl) / avgl`, NOT `BM25_B * (dl / avgl)`
    // -- so the fixed-point keeps ~3 fractional digits of dl/avgl instead of
    // flooring the ratio to an integer (which collapses length normalization to a
    // step function and, for the common dl < avgl case, drops it entirely). With
    // b = 0.75*SCALE this is 250 + 750*dl/avgl >= 250 > 0. Identical for the
    // single-token records the kernel feeds today (dl == avgl == 1 => 250 + 750),
    // so the boot KAT is unchanged; it only sharpens multi-token ranking.
    let norm = (SCALE - BM25_B) + BM25_B * dl / avgl;
    // numer = tf*(k1+1) scaled: tf * (BM25_K1 + SCALE).
    let numer = tf * (BM25_K1 + SCALE);
    // denom = SCALE*(tf + k1*norm_real) = tf*SCALE + BM25_K1*norm/SCALE.
    let denom = tf * SCALE + BM25_K1 * norm / SCALE;
    // denom > 0 always (norm > 0, BM25_K1 > 0), so the division is total.
    numer * SCALE / denom
}

/// One query term's full BM25 contribution to one document: `idf * tf_norm / SCALE`.
/// Non-negative (both factors are), `0` when the term is absent (`tf == 0`) or
/// universal (`df == N`). Bounded: `idf` is bounded by `ln_fixed` over the envelope
/// and `tf_norm < TF_NORM_CEIL`, so the product stays well inside `i64`.
#[must_use]
pub fn bm25_term_score(tf: u64, df: u64, n_docs: u64, doc_len: u64, avg_len: u64) -> i64 {
    bm25_idf(df, n_docs) * bm25_tf_norm(tf, doc_len, avg_len) / SCALE
}

/// The multi-term LEXICAL score of ONE candidate document against a query token-SET:
/// the ADDITIVE accumulation of [`bm25_term_score`] over each query term's
/// `(tf, df)` in this document. `query` is `&[(tf, df)]` -- the per-term
/// (term-frequency-in-this-document, document-frequency-in-the-corpus) pairs; a term
/// absent from the document contributes `tf = 0` (score `0`). The sum uses
/// `saturating_add` so an adversarial input can never overflow (it clamps to
/// `i64::MAX`, never panics). MONOTONE: adding a matching term (or increasing any
/// term's `tf`) never LOWERS the document's score -- the load-bearing recall
/// invariant (more query-term evidence never hurts).
#[must_use]
pub fn bm25_doc_score(query: &[(u64, u64)], n_docs: u64, doc_len: u64, avg_len: u64) -> i64 {
    let mut acc: i64 = 0;
    for &(tf, df) in query {
        acc = acc.saturating_add(bm25_term_score(tf, df, n_docs, doc_len, avg_len));
    }
    acc
}

/// The fixed byte width of a [`hit_canon`] record: `rank` (u16 LE) ++ `id` (u64 LE)
/// ++ `score` (i64 two's-complement LE) = 2 + 8 + 8.
pub const HIT_CANON_LEN: usize = 18;

/// A single ranked recall hit -- the deterministic result record of a query->ranking
/// scoring pass. Injectively encoded by [`hit_canon`] so a ranking is replay-verifiable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RankedHit {
    /// The 0-based rank of this hit within the query's ranking (0 == best).
    pub rank: u16,
    /// The memory record id this hit refers to.
    pub id: u64,
    /// The BM25 lexical score this record earned (fixed point; higher = more relevant).
    pub score: i64,
}

/// Injectively encode a [`RankedHit`] into a caller buffer as a FIXED-WIDTH,
/// fixed-field-order LE byte layout (the M22/M39 canon discipline). TOTAL +
/// fail-closed: returns `0` (writing nothing) if the buffer is smaller than
/// [`HIT_CANON_LEN`], never panics. Because every field occupies a FIXED offset with
/// no variable-length tail, the encoding is injective by construction: distinct
/// `(rank, id, score)` triples produce distinct bytes.
#[must_use]
pub fn hit_canon(hit: &RankedHit, out: &mut [u8]) -> usize {
    if out.len() < HIT_CANON_LEN {
        return 0;
    }
    out[0..2].copy_from_slice(&hit.rank.to_le_bytes());
    out[2..10].copy_from_slice(&hit.id.to_le_bytes());
    out[10..18].copy_from_slice(&hit.score.to_le_bytes());
    HIT_CANON_LEN
}

/// The exact inverse of [`hit_canon`]: decode a [`RankedHit`] from a buffer whose
/// first [`HIT_CANON_LEN`] bytes are a canonical record. Fail-closed to `None` on a
/// short buffer, never panics. `score` is decoded as a two's-complement `i64`, so the
/// round-trip is exact over the full signed range.
#[must_use]
pub fn hit_decode(buf: &[u8]) -> Option<RankedHit> {
    if buf.len() < HIT_CANON_LEN {
        return None;
    }
    let mut r = [0u8; 2];
    let mut i = [0u8; 8];
    let mut s = [0u8; 8];
    r.copy_from_slice(&buf[0..2]);
    i.copy_from_slice(&buf[2..10]);
    s.copy_from_slice(&buf[10..18]);
    Some(RankedHit {
        rank: u16::from_le_bytes(r),
        id: u64::from_le_bytes(i),
        score: i64::from_le_bytes(s),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The host tests EXECUTE concrete vectors (no CBMC cost), so they smoke a much
    // wider ceiling than the Kani ENVELOPE_MAX (2^8): 2^20 exercises the function far
    // beyond any reachable document size while staying inside the fixed-point overflow
    // point -- concrete evidence the panic-freedom holds well past the proof envelope.
    const SMOKE: u64 = 1 << 20;

    // -----------------------------------------------------------------------
    // bm25_idf: the rarer-term-scores-higher invariant + known points. The Miri
    // lane EXECUTES these, proving panic-freedom + zero UB on the concrete vectors.
    // -----------------------------------------------------------------------

    #[test]
    fn idf_universal_term_scores_at_the_floor() {
        // A term in EVERY document (df == N) has the SMALLEST idf -- the non-negative
        // BM25+ floor `ln(1 + 0.5/(N+0.5)) * SCALE`, small and positive, NOT zero (the
        // additive-1 keeps it non-negative but the exact hoisted expression does not
        // collapse to 0). The load-bearing property is that it is far below a rare term.
        let floor = bm25_idf(1000, 1000);
        assert!(floor >= 0, "universal-term idf went negative: {floor}");
        assert!(
            floor < bm25_idf(1, 1000),
            "universal-term idf {floor} was not below the rare-term idf"
        );
    }

    #[test]
    fn idf_rarer_term_scores_higher() {
        // Over a fixed corpus, a smaller df (rarer term) must score >= a larger df.
        let n = 100_000u64;
        let mut prev = i64::MAX;
        for &df in &[1u64, 2, 4, 8, 64, 512, 4096, 32_768, 100_000] {
            let v = bm25_idf(df, n);
            assert!(v >= 0, "idf({df},{n})={v} went negative");
            assert!(v <= prev, "idf({df},{n})={v} rose above the rarer-term {prev}");
            prev = v;
        }
    }

    #[test]
    fn idf_matches_the_hoisted_inline_expression() {
        // The production seam relies on this leaf reproducing the EXACT value the M13
        // recall computed inline: (ln_fixed(2N+2) - ln_fixed(2df+1)).max(0).
        for &(df, n) in &[(1u64, 1u64), (1, 10), (3, 10), (7, 1000), (1, 1_000_000)] {
            let inline = (ln_fixed(2 * n + 2) - ln_fixed(2 * df + 1)).max(0);
            assert_eq!(bm25_idf(df, n), inline, "df={df} n={n}");
        }
    }

    // -----------------------------------------------------------------------
    // bm25_tf_norm: tf saturation + doc-length penalty. More matches never lowers;
    // a longer doc never scores higher; the output stays in [0, TF_NORM_CEIL).
    // -----------------------------------------------------------------------

    #[test]
    fn tf_norm_zero_when_absent() {
        assert_eq!(bm25_tf_norm(0, 10, 10), 0);
        assert_eq!(bm25_tf_norm(0, 1, 1), 0);
    }

    #[test]
    fn tf_norm_non_decreasing_in_tf() {
        for &(dl, avgl) in &[(10u64, 10u64), (1, 10), (100, 10), (5, 5)] {
            let mut prev = i64::MIN;
            for &tf in &[0u64, 1, 2, 3, 5, 10, 100, 1000, 100_000, SMOKE] {
                let v = bm25_tf_norm(tf, dl, avgl);
                assert!(v >= prev, "tf_norm({tf},{dl},{avgl})={v} fell below {prev}");
                assert!((0..TF_NORM_CEIL).contains(&v), "tf_norm({tf},{dl},{avgl})={v} escaped [0,{TF_NORM_CEIL})");
                prev = v;
            }
        }
    }

    #[test]
    fn tf_norm_penalizes_longer_documents() {
        // A longer document (larger dl at fixed tf/avgl) must not score HIGHER.
        let mut prev = i64::MAX;
        for &dl in &[1u64, 5, 10, 50, 100, 1000] {
            let v = bm25_tf_norm(5, dl, 10);
            assert!(v <= prev, "tf_norm(5,{dl},10)={v} rose above the shorter-doc {prev}");
            prev = v;
        }
    }

    #[test]
    fn tf_norm_saturates_below_ceiling() {
        // Even an enormous tf stays strictly below k1+1 (== TF_NORM_CEIL scaled).
        let v = bm25_tf_norm(SMOKE, 10, 10);
        assert!(v < TF_NORM_CEIL, "tf_norm saturated to {v} >= {TF_NORM_CEIL}");
        assert!(v > BM25_K1, "tf_norm({SMOKE}) only reached {v}, expected near-ceiling");
    }

    // -----------------------------------------------------------------------
    // bm25_term_score + bm25_doc_score: the multi-term additive score. More
    // query-term evidence never lowers the document's score.
    // -----------------------------------------------------------------------

    #[test]
    fn term_score_absent_is_zero() {
        // A term that does NOT occur in the document (tf == 0) contributes exactly 0.
        assert_eq!(bm25_term_score(0, 5, 100, 10, 10), 0);
        // A UNIVERSAL term (df == N) contributes only the tiny idf floor, far below a
        // rare term with the same tf -- the discriminating property (not exactly 0).
        let universal = bm25_term_score(3, 100, 100, 10, 10);
        let rare = bm25_term_score(3, 2, 100, 10, 10);
        assert!(universal >= 0 && universal < rare, "universal {universal} not below rare {rare}");
    }

    #[test]
    fn doc_score_monotone_in_matches() {
        let n = 10_000u64;
        // A document matching MORE of the query terms scores >= one matching fewer.
        let one = bm25_doc_score(&[(2, 50)], n, 20, 20);
        let two = bm25_doc_score(&[(2, 50), (1, 500)], n, 20, 20);
        let three = bm25_doc_score(&[(2, 50), (1, 500), (3, 5)], n, 20, 20);
        assert!(two >= one, "adding a matching term lowered the score: {two} < {one}");
        assert!(three >= two, "adding a matching term lowered the score: {three} < {two}");
        assert!(one > 0, "a real match scored 0");
    }

    #[test]
    fn doc_score_ranking_is_deterministic() {
        // The same query->document scoring is reproducible (pure integer math).
        let q = [(2u64, 50u64), (1, 500)];
        assert_eq!(
            bm25_doc_score(&q, 10_000, 20, 20),
            bm25_doc_score(&q, 10_000, 20, 20)
        );
    }

    // -----------------------------------------------------------------------
    // hit_canon / hit_decode: the injective, fail-closed ranked-hit record.
    // -----------------------------------------------------------------------

    #[test]
    fn hit_canon_roundtrips() {
        for &(rank, id, score) in &[
            (0u16, 0u64, 0i64),
            (1, 0xDEAD_BEEF, 12_345),
            (7, u64::MAX, i64::MIN),
            (65535, 42, i64::MAX),
            (3, 0x1234_5678_9ABC_DEF0, -1),
        ] {
            let hit = RankedHit { rank, id, score };
            let mut buf = [0u8; HIT_CANON_LEN];
            assert_eq!(hit_canon(&hit, &mut buf), HIT_CANON_LEN);
            assert_eq!(hit_decode(&buf), Some(hit));
        }
    }

    #[test]
    fn hit_canon_fail_closed_on_short_buffer() {
        let hit = RankedHit { rank: 1, id: 2, score: 3 };
        let mut small = [0u8; HIT_CANON_LEN - 1];
        assert_eq!(hit_canon(&hit, &mut small), 0);
        assert_eq!(hit_decode(&small), None);
    }

    #[test]
    fn hit_canon_injective() {
        // Distinct triples -> distinct bytes (fixed-offset layout).
        let a = RankedHit { rank: 1, id: 2, score: 3 };
        let b = RankedHit { rank: 1, id: 2, score: 4 };
        let mut ba = [0u8; HIT_CANON_LEN];
        let mut bb = [0u8; HIT_CANON_LEN];
        assert_eq!(hit_canon(&a, &mut ba), HIT_CANON_LEN);
        assert_eq!(hit_canon(&b, &mut bb), HIT_CANON_LEN);
        assert_ne!(ba, bb);
    }
}
