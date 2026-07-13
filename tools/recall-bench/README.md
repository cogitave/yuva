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

## Result (BEIR NFCorpus test, 323 queries, one WSL box)

| system | NDCG@10 | Recall@10 | MAP | QPS | deterministic |
|---|---|---|---|---|---|
| bm25s (float, lucene) | 0.3052 | 0.1435 | 0.1164 | ~3,250 | no (float) |
| rank-bm25 (float, okapi) | 0.3056 | 0.1446 | 0.1166 | ~840 | no (float) |
| Rust-float (ideal, harness) | 0.3052 | 0.1435 | 0.1164 | ~15,900 | no (float) |
| **Yuva no-float leaf (integer)** | **0.3051** | **0.1433** | **0.1164** | **~19,400** | **bit-exact** |

The verified integer leaf matches float BM25 ranking quality (NDCG@10 0.3051 vs
0.3052) while being ~22% faster than the same-harness ideal-float and the only
implementation that is deterministic *and* formally machine-checked. Absolute QPS
is hardware-dependent — only the same-box numbers here are comparable; do not
compare them to a paper's numbers from other hardware.

> The 0.3051 figure holds only *after* the length-normalization precision fix
> (`bm25_tf_norm` multiply-before-divide). This benchmark is what surfaced that
> bug: before it, integer NDCG@10 was 0.2887 (−5.4% vs float), because the floored
> `dl/avgl` ratio silently disabled length normalization for sub-average-length
> documents. See the commit that precedes this harness.
