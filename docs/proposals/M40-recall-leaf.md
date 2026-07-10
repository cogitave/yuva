# M40 — the verified LEXICAL recall leaf (no-float BM25 memory scoring, the research-skill foundation)

> **STATUS: PROPOSED + LANDED-IN-THIS-PR.** Track A of `docs/proposals/forward-plan.md` §3: a verified BM25-family LEXICAL recall-scoring leaf that sharpens Cogi's memory retrieval, following the house pattern exactly (a `tb-encode` pure/no-float/Kani-proven leaf + a `tb-hal` `mem/` seam + a deterministic gated boot marker). `token=retrieval=LEXICAL-BM25-NO-FLOAT`, `token=recall=DETERMINISTIC`, `token=semantic=NONE`.

## 1. What this is (and, sharply, what it is NOT)

The M40 leaf is the pure, no-float, fixed-point **BM25-family relevance kernel** behind Yuva's memory retrieval — classic Robertson/Sparck-Jones **LEXICAL term-overlap** scoring: term frequency (saturating), inverse document frequency (a rarer term scores higher), and document-length normalization, over the u64 **interned tokens** Yuva's memory stores.

It is emphatically **NOT semantic**: no embeddings, no vectors, no learned weights, and **no float anywhere** (the M21 KAN leaf's fixed-point discipline; a semantic retriever would need a no-float fixed-point embedding encoder that does not exist — structurally out of scope, `token=semantic-retrieval=STRUCTURALLY-EXCLUDED`). It sharpens **which** memory a query surfaces; it does not understand meaning. `token=weights=NONE-FROZEN-FIXED-POINT` (`k1 = 1.2`, `b = 0.75` are frozen integer constants, not learned).

## 2. The three house-pattern pieces

1. **The leaf** — `crates/tb-encode/src/recall.rs` (`#![no_std]`, forbid-unsafe, zero-dep):
   - `bm25_idf(df, n_docs)` — the non-negative Lucene/BM25+ IDF, the **EXACT** expression the M13 `mem::recall` computed inline, hoisted verbatim (the `memscore`/`route` precedent). The reused integer logarithm is `memscore::ln_fixed` — no new log math.
   - `bm25_tf_norm(tf, doc_len, avg_len)` — tf saturation with document-length normalization, `(tf*(k1+1)) / (tf + k1*(1 - b + b*dl/avgl))` in fixed point.
   - `bm25_term_score(...)` — one query term's full BM25 contribution; `bm25_doc_score(query, ...)` — the additive multi-term accumulation (saturating).
   - `hit_canon`/`hit_decode` — a FIXED-WIDTH injective, fail-closed encode of a ranked hit `(rank, id, score)`, so a ranking is a replay-deterministic record (the M22/M39 canon discipline, no fold math).

2. **The `mem/` seam (SP#3)** — the production `MemSubstrate::recall` (`mem/mod.rs:~1339`) now computes its BM25+ IDF via `recall::bm25_idf`. The value is **numerically identical** to the former inline expression, so the recall ranking is byte-identical (no drift). The `recall_selftest()` in `mem/selftests.rs` scores a deterministic multi-term KAT **and** drives the real organ recall.

3. **The gated marker (SP#1)** — `kernel/src/main.rs` emits, in a PROFILE-GATED (agent) block between M39 and M38, an honest `recall:` witness + `M40: recall OK`. The substrate profile takes the skip form and emits **no** `recall:` witness (the census-forbidden prefix). M40 folds on **no head** — it displaces nothing (M38 stays the cumulative tail).

## 3. The proven properties (Kani, `proofs.rs`, +7 harnesses, 128→135)

Mirroring the `memscore` discipline **exactly**: Kani proves panic-freedom + bounds + codec injectivity/fail-closed + accumulation-monotonicity; **strict** `df`/`tf` monotonicity stays a concrete host test (the #49 over-quantification trap — fixed-point division can break strict monotonicity at rounding boundaries).

| Harness | Property | Negative control (the mutant that turns it RED) |
|---|---|---|
| `kani_recall_idf_panic_free_bounded` | `bm25_idf ∈ [0, 34_000)`, panic-free | drop `.max(0)` → a universal term goes negative |
| `kani_recall_tf_norm_panic_free_bounded` | `bm25_tf_norm ∈ [0, TF_NORM_CEIL)`, no div-by-zero, no overflow | replace `avg_len.max(1)` with `avg_len` → div-by-zero at `avg_len==0` |
| `kani_recall_term_score_panic_free_bounded` | `bm25_term_score ∈ [0, 100_000)`, panic-free | remove `/ SCALE` → blows the bound |
| `kani_recall_term_score_absent_is_zero` | `tf==0 ⇒ score == 0` (absent-term identity) | a `+1` numerator bias → absent term scores non-zero |
| `kani_recall_doc_score_accumulation_monotone` | adding a matching term never lowers the score | `saturating_add`→`saturating_sub` → second term lowers the score |
| `kani_recall_hit_canon_roundtrip` | `hit_decode(hit_canon(h)) == Some(h)` (injective) | narrow `score` to `i32` → round-trip fails for large scores |
| `kani_recall_hit_decode_fail_closed` | short buffer → `None`, `hit_canon` writes 0, never panics | drop the length guard → panic on a short buffer |

The negative controls are the designed mutants; each is embedded as a `NEGATIVE CONTROL` note on its harness. Execution is the CI Kani lane (`prove-encode-a`, shard A — the recall harnesses sit next to the `memscore` fixed-point family; all trivial, no hashing).

## 4. SP#4 — the M38 conduct-head re-verification

The forward-plan flags recall output as conductor input, so a recall-scoring change **could** shift the M38 conduct head `0x066855300c57557b`. Two structural facts make this landing byte-identical, not merely hoped:

1. **The seam is value-preserving.** `recall::bm25_idf` reproduces the exact former inline IDF, so the recall ranking (and the returned record id) is unchanged.
2. **The conductor does not consume the recall SCORE.** The M38 block (`main.rs:~5590`) uses `M_MEM_RECALL` only as a **gate** (`ctx_recalls == 3`) and folds a **hardcoded** `context_strength = 200`; it discards the returned record id (`_id`). So even a re-ordering that still returns 3 hits would keep the head byte-identical.

**Expectation: the M38 conduct head stays byte-identical** (`0x066855300c57557b`). This is verified from the CI boot log at landing (the `conduct: head=...` line), per the plan's MUST-VERIFY gate — not asserted blind.

## 5. Honest scope / deferrals

- LEXICAL term-overlap only; **no** semantic/embedding retrieval (structurally excluded, no-float). The witness spells the negations: `semantic=0x0`, `embedding=NONE`, `retrieval=LEXICAL-BM25-NO-FLOAT`.
- No learning: the BM25 params are frozen integer constants, nothing is graded or updated. `token=weights=NONE-FROZEN-FIXED-POINT`.
- The score primitive's security posture is inherited from the fixed-point discipline; the leaf claims only deterministic, bounded, panic-free scoring (`sec=ASSUMED-FROM-LITERATURE` for the reused `ln_fixed`).
