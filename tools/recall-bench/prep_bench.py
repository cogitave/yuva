#!/usr/bin/env python3
"""Fairness-controlled BM25 benchmark: shared tokenization for ALL systems.

Phase A: load BEIR NFCorpus, tokenize ONCE (bm25s standard pipeline), export the
         integer-token corpus + queries + qrels for the Rust (Yuva) harness.
Phase B: run the float baselines (bm25s method='lucene' == Yuva's exact IDF twin;
         rank-bm25 = popular ecosystem baseline) with k1=1.2, b=0.75 on the SAME
         tokens, save TREC run files, and time query latency same-box.

Every system sees identical tokens; the ONLY variable for the bm25s-lucene twin is
float vs Yuva's integer fixed-point scoring. Metrics come later (eval_all.py) from
pytrec_eval so all runs are scored by the identical canonical evaluator.

Data dir: $IRBENCH_DATA (default ~/irbench/data), holding nfcorpus/.
"""
import json, time, os
import bm25s
from rank_bm25 import BM25Okapi

OUT  = os.environ.get("IRBENCH_DATA", os.path.expanduser("~/irbench/data"))
DATA = f"{OUT}/nfcorpus"
K1, B = 1.2, 0.75
TOPK = 10
LAT_REPEATS = 5  # repeat the query loop; report the fastest (warm) pass

def load_jsonl(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows

def load_qrels(path):
    qrels = {}
    with open(path, encoding="utf-8") as f:
        f.readline()  # header: query-id  corpus-id  score
        for line in f:
            p = line.split()
            if len(p) >= 3:
                qrels.setdefault(p[0], {})[p[1]] = int(p[2])
    return qrels

print("== loading NFCorpus ==")
corpus = load_jsonl(f"{DATA}/corpus.jsonl")
queries_all = load_jsonl(f"{DATA}/queries.jsonl")
qrels = load_qrels(f"{DATA}/qrels/test.tsv")
test_qids = set(qrels.keys())
queries = [q for q in queries_all if q["_id"] in test_qids]
print(f"docs={len(corpus)}  test-queries={len(queries)}  judged-pairs={sum(len(v) for v in qrels.values())}")

doc_ids   = [d["_id"] for d in corpus]
doc_texts = [((d.get("title", "") + " ") + d.get("text", "")).strip() for d in corpus]
q_ids     = [q["_id"] for q in queries]
q_texts   = [q.get("text", "") for q in queries]

print("== tokenizing (shared, stopwords=english, no stemmer) ==")
doc_tok = bm25s.tokenize(doc_texts, stopwords="english", stemmer=None, return_ids=False, show_progress=False)
q_tok   = bm25s.tokenize(q_texts,   stopwords="english", stemmer=None, return_ids=False, show_progress=False)

# shared vocab (string -> int id) over corpus + queries, for the Rust harness
vocab = {}
def to_ids(toks):
    out = []
    for tok in toks:
        row = []
        for t in tok:
            i = vocab.get(t)
            if i is None:
                i = len(vocab); vocab[t] = i
            row.append(i)
        out.append(row)
    return out
doc_tok_ids = to_ids(doc_tok)
q_tok_ids   = to_ids(q_tok)

# zero-dep plain-text interchange for the Rust (Yuva) harness -- no serde needed
def write_tok(path, rows):
    with open(path, "w") as f:
        for row in rows:
            f.write(" ".join(str(i) for i in row) + "\n")
def write_lines(path, items):
    with open(path, "w") as f:
        for it in items:
            f.write(str(it) + "\n")
write_tok(f"{OUT}/docs.tok", doc_tok_ids)
write_tok(f"{OUT}/queries.tok", q_tok_ids)
write_lines(f"{OUT}/doc_ids.txt", doc_ids)
write_lines(f"{OUT}/query_ids.txt", q_ids)
with open(f"{OUT}/meta.txt", "w") as f:
    f.write(f"{int(round(K1*1000))} {int(round(B*1000))} {TOPK} {len(doc_ids)} {len(q_ids)} {len(vocab)}\n")
with open(f"{OUT}/qrels.json", "w") as f:
    json.dump(qrels, f)
print(f"exported docs.tok/queries.tok/*_ids.txt/meta.txt (vocab={len(vocab)}) + qrels.json")

def save_run(name, run):
    with open(f"{OUT}/{name}_run.json", "w") as f:
        json.dump(run, f)

# ---- bm25s (method='lucene' == Yuva IDF twin), float ----
print("== bm25s (lucene, float) ==")
retr = bm25s.BM25(k1=K1, b=B, method="lucene")
retr.index(doc_tok, show_progress=False)
best = None
for _ in range(LAT_REPEATS):
    t0 = time.perf_counter()
    res, scores = retr.retrieve(q_tok, k=TOPK, show_progress=False, n_threads=1)
    dt = time.perf_counter() - t0
    best = dt if best is None else min(best, dt)
bm25s_run = {q_ids[qi]: {doc_ids[res[qi, r]]: float(scores[qi, r]) for r in range(res.shape[1])}
             for qi in range(len(q_ids))}
save_run("bm25s", bm25s_run)
print(f"bm25s  query-loop best={best*1000:.2f} ms total  ({len(q_ids)/best:.1f} QPS)")

# ---- rank-bm25 (popular baseline, float, own IDF w/ epsilon) ----
print("== rank-bm25 (okapi, float) ==")
bm = BM25Okapi(doc_tok, k1=K1, b=B)
best_r = None
rank_run = {}
for rep in range(LAT_REPEATS):
    t0 = time.perf_counter()
    for qi, qtok in enumerate(q_tok):
        sc = bm.get_scores(qtok)
        idx = sorted(range(len(sc)), key=lambda i: sc[i], reverse=True)[:TOPK]
        if rep == 0:
            rank_run[q_ids[qi]] = {doc_ids[i]: float(sc[i]) for i in idx}
    dt = time.perf_counter() - t0
    best_r = dt if best_r is None else min(best_r, dt)
save_run("rankbm25", rank_run)
print(f"rank-bm25 query-loop best={best_r*1000:.2f} ms total  ({len(q_ids)/best_r:.1f} QPS)")

with open(f"{OUT}/py_timing.json", "w") as f:
    json.dump({"bm25s_qps": len(q_ids)/best, "rankbm25_qps": len(q_ids)/best_r,
               "n_queries": len(q_ids), "n_docs": len(doc_ids)}, f)
print("== phase A/B done ==")
