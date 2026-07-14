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

## Result (BEIR, one WSL box; NDCG@10 via pytrec_eval, same-box QPS)

Three datasets spanning short keyword queries (NFCorpus), claim queries (SciFact)
and whole-argument queries of hundreds of terms (ArguAna). "Fidelity" = int-vs-float
top-10 overlap: how faithfully the integer leaf reproduces the float ranking.

| dataset | Yuva NDCG@10 | float twin | fidelity | Yuva QPS | float QPS¹ | bm25s QPS |
|---|---|---|---|---|---|---|
| NFCorpus (3.6k docs, 323 q) | **0.3051** | 0.3052 | 0.999 | **19,155** | 15,587 | 3,101 |
| SciFact (5.2k docs, 300 q) | **0.6634** | 0.6625 | 0.997 | 2,366 | 1,970 | 3,224 |
| ArguAna (8.7k docs, 1406 q) | **0.3552** | 0.3551 | 0.996 | 87 | 84 | 1,926 |

<sub>¹ Rust-float = the identical harness with f64; it reproduces `bm25s` NDCG@10 to
four decimals on all three sets, which validates the harness. `rank-bm25` (not shown)
matches on quality but is far slower everywhere (816 / 187 / 10 QPS).</sub>

**What holds, honestly:**

1. **Ranking-quality parity with float BM25 on all three datasets.** The verified
   integer leaf matches the float twin's NDCG@10 to ≤0.001 and reproduces its
   ranking with **fidelity ≥ 0.996** — including on ArguAna's hundreds-of-terms
   queries, which is exactly where a naive integer BM25 drifts (see the fixes).
2. **Unique properties:** it is the only implementation here that is *both*
   bit-exact **deterministic** (identical across runs, and by construction across
   platforms — no float) and formally **Kani-machine-checked**.
3. **Speed — the robust claim is vs the *same-harness* float:** the integer leaf
   is consistently faster than the ideal-float twin in the identical harness
   (+23% NFCorpus, +20% SciFact, +4% ArguAna) — pure integer arithmetic, no FP
   division — and always far faster than `rank-bm25`. It is **not** universally
   faster than `bm25s`: `bm25s`'s numpy vectorisation wins as candidates-per-query
   grow — decisively on ArguAna's long queries (1,926 vs 87), and on SciFact
   (3,224 vs 2,366) — while the scalar leaf wins on short-query NFCorpus (19,155
   vs 3,101). Absolute QPS is hardware/workload-dependent; only these same-box
   figures are comparable — never compare them to a paper's numbers from other
   hardware.

> **Two precision fixes this benchmark surfaced** (both preserve determinism,
> verifiability, and the single-token boot proof; both principled = *fidelity to
> real BM25*, not a dataset-specific tweak):
>
> 1. **Length-norm floor** — `bm25_tf_norm` computed `BM25_B * (dl / avgl)`, an
>    integer-floored ratio that silently disabled length normalization for
>    sub-average documents. Multiply-before-divide fixed it: NFCorpus fidelity
>    0.74 → 0.999, recovering a real **−5.4% NDCG@10** (0.2887 → 0.3051).
> 2. **Per-term rounding accumulation** — `bm25_doc_score` divided every term by
>    `SCALE` before summing, so one rounding error accrued per query term. On
>    ArguAna's long queries this dropped fidelity to **0.75** and inflated NDCG to
>    0.3679 (a *false* win — the divergence merely landed favourably). Deferring
>    the division to a single end step restored fidelity **0.75 → 0.996** and
>    honest parity (0.3552 vs float 0.3551).
>
> Both were invisible on short queries and only appeared once the benchmark spanned
> corpus/query shapes — the reason to benchmark against the field, not in a vacuum.
