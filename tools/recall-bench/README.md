---
type: How-to
title: recall-bench — benchmarking the M40 verified no-float BM25 recall leaf
description: Reproduce the same-box comparison of Yuva's integer BM25 recall leaf against the float BM25 references (bm25s, rank-bm25) on BEIR NFCorpus.
tags: [recall, bm25, benchmark, m40, tb-encode]
timestamp: 2026-07-14T00:00:00Z
status: active
diataxis: how-to
---

# recall-bench

A host benchmark for the **M40 verified no-float BM25 recall leaf**
(`tb_encode::recall`). It links the *same* Kani-proven
`tb_encode::recall::bm25_doc_score` the kernel scores with — **never a second BM25
implementation** (the same-math rule as `tools/prov-signer`). The inverted index,
candidate generation and top-k are harness plumbing; the scored arithmetic is the
verified leaf, byte-for-byte.

## What it answers

An apples-to-apples, **same-box** comparison against the implementations everyone
else uses, isolating the one variable that matters — integer fixed-point vs float:

- **`bm25s` (method `lucene`)** — the 2024 accelerated-sparse SOTA; its Lucene IDF
  is Yuva's *exact* IDF twin (`ln((N+1)/(df+0.5))`), so it is the reference for
  "did the no-float quantization cost ranking quality?"
- **`rank-bm25` (Okapi)** — the ubiquitous Python baseline (different IDF).
- **Rust-float (ideal)** — the same harness with `f64` and real `avgdl`; validates
  the harness (it reproduces `bm25s` NDCG to 4 decimals) and isolates float-vs-int.

Metrics: NDCG@10 / Recall@10 / MAP (canonical `pytrec_eval`), query latency
(same box), and the axis no float engine offers — **bit-exact determinism**.

## Why lexical + deterministic (the design rationale)

BM25 stays competitive-to-superior out-of-domain and on precise-terminology
corpora (BEIR; and beats `text-embedding-3-large` on finance/code term matching).
For an *agent* reading its own memory, exact-match lexical retrieval gives
"deterministic, interpretable matches on actual terms" and "grounding … in
verifiable text" that embedding similarity does not (arXiv 2605.05242). Yuva's
leaf is the *retrieval primitive*; QA-memory systems (Mem0, Letta, A-MEM) are a
layer above it and could sit on top.

## Reproduce

Prereqs: a Python venv with the baselines, and the dataset. On Linux/WSL:

```bash
python3 -m venv ~/irbench && ~/irbench/bin/pip install \
    rank-bm25 bm25s numpy scipy pytrec_eval-terrier
export IRBENCH_DATA=~/irbench/data && mkdir -p "$IRBENCH_DATA"
# BEIR NFCorpus (public): 3,633 docs, 323 test queries
curl -sSL -o "$IRBENCH_DATA/nfcorpus.zip" \
  https://public.ukp.informatik.tu-darmstadt.de/thakur/BEIR/datasets/nfcorpus.zip
python3 -c "import zipfile;zipfile.ZipFile('$IRBENCH_DATA/nfcorpus.zip').extractall('$IRBENCH_DATA')"
```

Then, from this directory:

```bash
# 1. tokenize (shared for all systems), run the float baselines, export interchange
~/irbench/bin/python3 prep_bench.py
# 2. score the SAME tokens with the verified integer leaf (writes yuva_run.tsv)
cargo run --release -- "$IRBENCH_DATA"
# 3. evaluate every run through the one canonical evaluator
~/irbench/bin/python3 eval_all.py
```

All three systems consume identical tokens (`bm25s` standard pipeline,
`stopwords=english`, no stemmer) so only the *scoring* differs. `k1=1.2`, `b=0.75`
everywhere — the leaf's frozen constants; the harness asserts the interchange
agrees, so the comparison isolates float vs integer and nothing else.

## Result (BEIR, one WSL box; NDCG@10 / Recall@10 via pytrec_eval)

**NFCorpus** (3,633 docs, 323 test queries):

| system | NDCG@10 | Recall@10 | QPS | deterministic |
|---|---|---|---|---|
| bm25s (float, lucene) | 0.3052 | 0.1435 | ~3,250 | no (float) |
| rank-bm25 (float, okapi) | 0.3056 | 0.1446 | ~840 | no (float) |
| Rust-float (ideal, harness) | 0.3052 | 0.1435 | ~15,900 | no (float) |
| **Yuva no-float leaf (integer)** | **0.3051** | **0.1433** | **~19,400** | **bit-exact** |

**SciFact** (5,183 docs, 300 test queries):

| system | NDCG@10 | Recall@10 | QPS | deterministic |
|---|---|---|---|---|
| bm25s (float, lucene) | 0.6625 | 0.7799 | ~3,290 | no (float) |
| rank-bm25 (float, okapi) | 0.6657 | 0.7899 | ~190 | no (float) |
| Rust-float (ideal, harness) | 0.6625 | 0.7799 | ~2,160 | no (float) |
| **Yuva no-float leaf (integer)** | **0.6634** | **0.7833** | **~2,520** | **bit-exact** |

**What holds, honestly:**

1. **Ranking-quality parity with float BM25.** On both datasets the verified
   integer leaf matches the float twin's NDCG@10 (0.3051 vs 0.3052; 0.6634 vs
   0.6625) and reproduces its ranking with **int-vs-float top-10 overlap 0.997**.
   The in-harness ideal-float run equals `bm25s` to 4 decimals on both sets,
   validating the harness.
2. **Unique properties:** it is the only implementation here that is *both*
   bit-exact **deterministic** (identical across runs, and by construction across
   platforms — no float) and formally **Kani-machine-checked**.
3. **Speed — the robust claim is vs the *same-harness* float:** the integer leaf
   is consistently faster than the ideal-float twin in the identical harness
   (~22% NFCorpus, ~17% SciFact) — pure integer arithmetic, no FP division. It is
   always far faster than `rank-bm25`. It is **not** universally faster than
   `bm25s`: `bm25s`'s numpy vectorisation over candidates wins on long-document
   corpora (SciFact ~3,290 vs ~2,520), while the leaf's scalar scoring wins on
   short-document corpora (NFCorpus ~19,400 vs ~3,250). Absolute QPS is
   hardware/workload-dependent — only these same-box figures are comparable; do
   not compare them to a paper's numbers from other hardware.

> **What the length-normalization fix did.** These figures hold *after* the
> `bm25_tf_norm` multiply-before-divide fix, which this benchmark surfaced. The
> principled effect is *fidelity to real BM25*: int-vs-float top-10 overlap rose
> from **0.74 → 0.997 on both datasets**. That recovered a real **−5.4% NDCG@10**
> loss on NFCorpus (0.2887 → 0.3051); on SciFact NDCG was already at float parity
> either way (before 0.6667, after 0.6634 — the floored error there was benign
> noise, not a gain). Faithfully computing the intended BM25 is the goal, not a
> lucky-on-one-dataset approximation. See the commit preceding this harness.
