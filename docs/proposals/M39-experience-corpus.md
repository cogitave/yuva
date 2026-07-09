---
type: Design Decision
title: "M39 — Phase-1 Experience Corpus (dataset moat)"
description: "Freezes corpus-format-v1 (token provenance skeleton, not text) + verified codec leaf + 5 Kani proofs; no dataset, no training yet."
tags: ["m39", "corpus", "provenance", "codec", "kani", "proposal"]
timestamp: 2026-07-08T11:43:52+03:00
status: locked
diataxis: explanation
---

# M39 — the Phase-1 EXPERIENCE CORPUS (the dataset moat)

**Status:** **PROPOSAL — research-first. Stage A (this increment) LANDS the frozen
format spec + the verified codec leaf + its Kani harnesses ONLY.** The in-kernel emit
seam, the durable growing region, and the host export tool are named-but-deferred later
increments (§7). Nothing model-bearing is proposed; this is verified data-engineering.

**Honesty tokens (machine-emitted so the milestone mechanically cannot overclaim):**
`token=corpus=PROVENANCE-SKELETON-TEXT-IS-AGENT-DICT-JOIN`,
`token=curation=PREDICATE-DECLARED-NOT-LEARNED`,
`token=phase1=LEARNING-PREREQUISITE-NOT-CAPABILITY-ADVANCE`,
`token=training=NONE-PHASE2-GATED`,
`token=reuse=M22-FOLD-VERBATIM-NO-NEW-FOLD-MATH`.

---

## 1. Motivation — turn signed memory into a training-ready corpus, with NO live model

The forward plan's flagship ungated move (`docs/proposals/forward-plan.md` §2.2) is to
turn Yuva's already-signed, reboot-surviving memory into a **GROWING, CURATED, tamper-
evident EXPERIENCE CORPUS** — the dataset moat that is the real prerequisite for a
future sovereign Cogi model (Phase 2, operator-gated). The corpus is **data-engineering,
not a capability advance**: it does not activate learning, does not touch `KAN_ACTIVE`,
and trains nothing. It simply stocks, provenance-preserved, the dataset a later fine-tune
would consume, so we know EXACTLY what Cogi would have learned from.

Two structural facts from `forward-plan.md` §1 shape the whole design, and the format
honors both:

1. **Memory content is stored as u64 INTERNED TOKENS, not text**
   (`crates/tb-hal/src/mem/mod.rs:766,787,862`). So a kernel-side corpus is a
   **PROVENANCE SKELETON in tokens** — token ids + a lineage head + a timestamp + a
   curation verdict — and the text is joined host-side through the agent-supplied
   dictionary. The format never pretends to hold text.
2. **KAN is not learning.** The corpus is orthogonal to the dormant kancell; it is NOT
   the M23 `ExperienceRecord` scheduling tuples (those feed the dormant policy). The
   corpus rows are curated LANGUAGE/REASONING examples (episodic-consolidation outcomes,
   operator turns, labeled outcomes), and they REUSE the M22/M23/M33 tamper-evidence
   machinery but are a distinct record type folded into a distinct head.

## 2. What already exists to build on (reuse, don't reinvent)

- **The M22 prov fold** (`crates/tb-encode/src/prov.rs`): the BLAKE2s-256 hash-chain
  `append`/`chain_mix`/`recompute`/`verify_inclusion`/`head_witness` — proven injective,
  total, tamper-sensitive, inclusion-sound. The corpus REUSES it VERBATIM under a
  separate `corpus_head`; M39 writes NO new fold math (the exact M23 exp / M38 conductor
  reuse discipline).
- **The M23 experience codec** (`crates/tb-encode/src/exp.rs`): the fixed-width injective
  `canon`/`decode`, the present-`Unset` `OutcomeLabel` reserve-now idiom, and the
  schema-stability lemma. The corpus record is modeled on it EXACTLY.
- **The M33 durable signed head** (`crates/tb-encode/src/provhead.rs`): the multi-sector
  torn-write-safe persistence the durable growing corpus will reuse — a LATER increment.

## 3. The frozen format (stage A deliverable #1)

`docs/spec/corpus-format-v1.md` is FROZEN before any codec (the tabos-milestone
discipline: a record is folded into a hash chain, so a field added after the freeze
breaks replay-determinism and every committed head — the exact obligation `exp.rs:32-40`
pre-reserved fields for). The record is one curated experience as a provenance skeleton:

- **classification**: `schema_version` (frozen v1), `example_kind` (episodic-consolidation
  / operator-turn / labeled-outcome), `source_stream` (M13 mem / M17 reflect / M25
  operator / M31 infer), `curation_verdict` (the DECLARED predicate outcome).
- **skeleton**: `content_tok` + `aux_tok` (interned token ids — the agent-dict text-join
  handles), `t_created` (substrate clock), `source_head` (the M22 fold-position lineage
  head linking the row back to its source provenance).
- **RESERVED (reserve-now)**: the labeled-outcome `OutcomeLabel` (present-`Unset`),
  `curation_score_q` (graded-curation sentinel), `aux_tok` (secondary handle) — present
  at fixed offsets NOW so a later increment populates them without shifting the fold.

Fully fixed-width, 71 bytes, all LE. `decode` is fail-closed on a short buffer, an
unknown `schema_version`, or any out-of-vocabulary closed-set tag — a stronger posture
than the M23 exp decoder (which validated only the outcome tag). See the spec for the
byte layout, vocabularies, and the six frozen invariants.

## 4. The verified codec leaf (stage A deliverable #2)

`crates/tb-encode/src/corpus.rs` — `#![no_std]`, `forbid(unsafe)`, zero external dep
(brand allowed). It mirrors `exp.rs`:

- `CorpusRecord` + `canon`/`decode` (fixed-width, injective, TOTAL, fail-closed);
- `OutcomeLabel` (present-`Unset` tagged variant, the reserved labeled-outcome channel);
- the closed-set validators `example_kind::is_valid` / `source_stream::is_valid` /
  `curation_verdict::is_valid` that gate `decode`;
- `corpus_append` — the fold step: canon → `prov_hash` → `chain_mix` into `corpus_head`,
  a wrapper that REUSES the proven `prov` leaf (no new fold math), the mirror of
  `prov::append` for a `CorpusRecord`;
- the re-exported `corpus_*` fold aliases over `prov`.

## 5. Verification (stage A deliverable #3 — Track E folded in per the plan)

Five Kani harnesses in `crates/tb-encode/src/proofs.rs`, each with a negative control,
following the CBMC budget law (`forward-plan.md` §2.2 / the M33-B precedent): prove the
FNV-FREE geometry / fail-close / schema-stability core SYMBOLICALLY (cheap, the exp-canon
regime, no hashing), and delegate the hash-bearing fold to COMPOSITION over the already-
proven `prov` leaf, with one CONCRETE-record end-to-end fold witness.

| # | harness | proves | cost regime |
|---|---|---|---|
| 1 | `kani_corpus_canon_injective` | `canon` total + fail-closed + injective on every field (incl. reserved `curation_score_q` + present-`Unset` outcome tag) | FNV-free, symbolic, cheap |
| 2 | `kani_corpus_canon_roundtrip` | `decode(canon(rec)) == rec` over the valid vocabularies + a populated outcome + short-buffer `None` | FNV-free, symbolic, cheap |
| 3 | `kani_corpus_decode_fail_closed` | `decode` → `None` on short buffer, unknown `schema_version`, or any out-of-vocabulary `example_kind`/`source_stream`/`curation_verdict`/`outcome.tag` | FNV-free, symbolic, cheap |
| 4 | `kani_corpus_schema_stability` | `Unset` vs populated: identical length + identical offsets outside the fixed `[60..69)` outcome window | FNV-free, symbolic, cheap |
| 5 | `kani_corpus_fold_determinism` | `corpus_append` deterministic + a single-byte tamper of a committed record changes the head and fails inclusion — riding the reused `prov` fold | concrete record, one prov evaluation |

The full symbolic fold determinism / tamper-sensitivity / inclusion-soundness are ALREADY
discharged by `kani_prov_head_deterministic` / `kani_prov_chain_mix_tamper` /
`kani_prov_inclusion_sound` and are inherited (the corpus writes no new fold math). Host
tests (`corpus.rs` `#[cfg(test)]`) cover the hash-bearing legs + full-size records.

**Shard lockstep (SP#2):** `EXPECTED_HARNESSES_TOTAL` 123 → 128; the five harnesses land
in shard B (the lighter shard by measured cost, coherent with the M23 exp family); the
3-way completeness guard stays green (`A=55 + B=64 + C=9 == 128 == proofs.rs count`).

## 6. Honest scope — what stage A does NOT claim

- It builds NO dataset yet — it lands the FORMAT + CODEC. The corpus GROWS only once the
  in-kernel emit + durable region land (§7).
- It does NOT curate — `curation_verdict` is a DECLARED field; the predicate that
  computes it is a later increment. `token=curation=PREDICATE-DECLARED-NOT-LEARNED`.
- It does NOT touch the model, KAN, or training. `token=training=NONE-PHASE2-GATED`.
- The BLAKE2s-256 primitive's collision/preimage resistance is
  `sec=ASSUMED-FROM-LITERATURE`, inherited verbatim from `prov`/`khash`, never proven.

## 7. Later increments (named, deferred — NOT this PR)

Per `forward-plan.md` §2.2 DoD and the Track A′ scope:

1. **In-kernel `corpus_head` seam** — `corpus_head` + `corpus_ids` alongside (never
   inside) `chain_head`/`xp_head`, a deterministic curation predicate, emit wired into
   `consolidation_cycle` (`mem/mod.rs:1794`), a `CorpusProof` boot self-test, a new
   cumulative marker. **Requires the SP#4 M38 conduct-head re-verify** (recall output
   feeds the conductor input, so the emit must re-confirm the byte-identical head).
2. **Durable growing corpus** — reuse the M33 `provhead.rs` persistence to spill records
   + persist a SIGNED `corpus_head` to a new durable M20 region, with a two-boot cross-
   reboot witness.
3. **Host export tool** (`tools/corpus-export/`) — verify the signed head, join the
   agent token→text dictionary, emit training-ready JSONL where every example carries a
   provenance envelope; a CPU-only, zero-secret, zero-network CI lane asserting round-trip
   (kernel `corpus_head` == host-recomputed head over the exported rows).
4. **Labeled-outcome + operator-turn channels populated** — the reserved `OutcomeLabel`
   from the survival stream; M25/M28 approved turns as `example_kind=operator-turn`.

## 8. ROADMAP row (handed to Track F — A′ does NOT edit `ROADMAP-V2.md`)

> **M39 — Phase-1 Experience Corpus (dataset moat).** Stage A LANDED: frozen
> `corpus-format-v1` spec + verified `corpus.rs` codec (reuses the M22 prov fold
> verbatim under a separate `corpus_head`) + 5 Kani harnesses (128 total). Provenance
> skeleton (interned tokens, text-join agent-side); curation DECLARED-not-learned;
> Learning pillar STAYS DORMANT (prerequisite, not advance); no training (Phase-2
> gated). Later increments: in-kernel emit seam + SP#4 head re-verify, durable growing
> region, `tools/corpus-export/`, labeled-outcome/operator-turn channels.
