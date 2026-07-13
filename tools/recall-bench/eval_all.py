#!/usr/bin/env python3
"""Score every run through the ONE canonical evaluator (pytrec_eval / trec_eval)
so bm25s, rank-bm25, the Yuva integer leaf and the ideal-float twin are judged
identically. Reports NDCG@10, Recall@10, MAP on BEIR NFCorpus test qrels.

Data dir: $IRBENCH_DATA (default ~/irbench/data).
"""
import json, os
import pytrec_eval

OUT = os.environ.get("IRBENCH_DATA", os.path.expanduser("~/irbench/data"))

with open(f"{OUT}/qrels.json") as f:
    qrels = json.load(f)

def load_json_run(path):
    with open(path) as f:
        r = json.load(f)
    return {q: {d: float(s) for d, s in docs.items()} for q, docs in r.items()}

def load_tsv_run(path):
    run = {}
    with open(path) as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) >= 3:
                run.setdefault(p[0], {})[p[1]] = float(p[2])
    return run

runs = {}
def maybe(name, loader, path):
    if os.path.exists(path):
        runs[name] = loader(path)

maybe("bm25s (float, lucene)",       load_json_run, f"{OUT}/bm25s_run.json")
maybe("rank-bm25 (float, okapi)",    load_json_run, f"{OUT}/rankbm25_run.json")
maybe("Rust-float (ideal, harness)", load_tsv_run,  f"{OUT}/rustfloat_run.tsv")
maybe("Yuva no-float leaf (int)",    load_tsv_run,  f"{OUT}/yuva_run.tsv")

evaluator = pytrec_eval.RelevanceEvaluator(qrels, {"ndcg_cut.10", "recall.10", "map"})

# FAIRNESS: average over ALL test qrels queries; a query a system returned nothing
# for (e.g. all terms out-of-corpus-vocabulary) scores 0 -- identical denominator
# for every system (matching trec_eval -c / the BEIR convention).
all_qids = list(qrels.keys())
N = len(all_qids)

print(f"{'system':<32} {'NDCG@10':>9} {'Recall@10':>10} {'MAP':>8}  {'#q/N':>7}")
print("-" * 72)
results = {}
for name, run in runs.items():
    res = evaluator.evaluate(run)
    ndcg = sum(res.get(q, {}).get("ndcg_cut_10", 0.0) for q in all_qids) / N
    rec  = sum(res.get(q, {}).get("recall_10", 0.0) for q in all_qids) / N
    mp   = sum(res.get(q, {}).get("map", 0.0) for q in all_qids) / N
    results[name] = {"ndcg@10": ndcg, "recall@10": rec, "map": mp, "nq_returned": len(res), "N": N}
    print(f"{name:<32} {ndcg:>9.4f} {rec:>10.4f} {mp:>8.4f}  {len(res):>3}/{N}")

with open(f"{OUT}/eval_results.json", "w") as f:
    json.dump(results, f, indent=2)
print("\nsaved eval_results.json")
