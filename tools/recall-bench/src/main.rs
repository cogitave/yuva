//! Host benchmark for the M40 verified no-float BM25 recall leaf.
//!
//! Reads the shared, pre-tokenised NFCorpus interchange written by the Python
//! prep step (identical tokens for every system, so only the *scoring* differs),
//! scores every candidate document with the exact Kani-proven
//! [`tb_encode::recall::bm25_doc_score`] the kernel uses, and emits a TREC run
//! plus same-box latency and a determinism proof.
//!
//! Usage: `recall-bench <data-dir>` (default `./data`). The data dir must hold
//! `meta.txt docs.tok queries.tok doc_ids.txt query_ids.txt` and receives
//! `yuva_run.tsv`. Query-term multiplicity is preserved (linear qtf), matching
//! the `bm25s` / `rank-bm25` baselines which sum per query-token occurrence.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::time::Instant;

use tb_encode::recall::{bm25_doc_score, BM25_B, BM25_K1};

const LAT_REPEATS: usize = 7; // report the fastest (warm) query-loop pass

fn read_tok(path: &str) -> Vec<Vec<u32>> {
    fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {path}: {e}"))
        .lines()
        .map(|l| l.split_whitespace().map(|x| x.parse().unwrap()).collect())
        .collect()
}

fn read_lines(path: &str) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {path}: {e}"))
        .lines()
        .map(|s| s.to_string())
        .collect()
}

/// Corpus statistics the leaf needs, computed once (harness plumbing).
struct Index {
    doc_tf: Vec<HashMap<u32, u32>>, // per-doc term frequencies
    doc_len: Vec<u64>,
    df: HashMap<u32, u32>,       // document frequency per token
    inv: HashMap<u32, Vec<u32>>, // token -> posting list (doc indices)
    n_docs: u64,
    avg_len: u64,   // rounded integer mean length -- the no-float design point
    avg_len_f: f64, // real mean length -- for the ideal-float reference
}

/// The IDEAL real-valued BM25 the integer leaf approximates: Lucene non-negative
/// IDF `ln((N+1)/(df+0.5))` + the classic `(k1+1)` tf saturation, k1=1.2 b=0.75.
/// Same formula and same tokens as [`bm25_doc_score`]; the ONLY differences are
/// f64 vs integer fixed-point and real-vs-rounded avgdl -- i.e. exactly the cost
/// of the no-float design. Should track `bm25s method='lucene'` to within ULPs,
/// which cross-validates the harness.
fn float_doc_score(query: &[(u64, u64)], n_docs: u64, doc_len: u64, avg_len_f: f64) -> f64 {
    let k1 = BM25_K1 as f64 / SCALE_F;
    let b = BM25_B as f64 / SCALE_F;
    let nf = n_docs as f64;
    let dl = doc_len as f64;
    let mut acc = 0.0;
    for &(tf, df) in query {
        let idf = ((nf + 1.0) / (df as f64 + 0.5)).ln().max(0.0);
        let tff = tf as f64;
        let tfn = tff * (k1 + 1.0) / (tff + k1 * (1.0 - b + b * dl / avg_len_f));
        acc += idf * tfn;
    }
    acc
}

const SCALE_F: f64 = 1000.0;

fn build_index(docs: &[Vec<u32>]) -> Index {
    let n = docs.len();
    let mut doc_tf = Vec::with_capacity(n);
    let mut doc_len = Vec::with_capacity(n);
    let mut df: HashMap<u32, u32> = HashMap::new();
    let mut inv: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut total: u64 = 0;
    for (di, toks) in docs.iter().enumerate() {
        let mut tf: HashMap<u32, u32> = HashMap::new();
        for &t in toks {
            *tf.entry(t).or_insert(0) += 1;
        }
        doc_len.push(toks.len() as u64);
        total += toks.len() as u64;
        for &t in tf.keys() {
            *df.entry(t).or_insert(0) += 1;
            inv.entry(t).or_default().push(di as u32);
        }
        doc_tf.push(tf);
    }
    let n_docs = n as u64;
    let avg_len = (total + n_docs / 2) / n_docs.max(1); // rounded integer mean
    let avg_len_f = total as f64 / n_docs.max(1) as f64;
    Index { doc_tf, doc_len, df, inv, n_docs, avg_len, avg_len_f }
}

/// Score every query against the corpus, returning per-query top-k
/// `(doc_index, score)` ranked (score desc, doc index asc for a total, platform-
/// independent order). This is the timed hot path; it calls the verified leaf.
fn run_queries(ix: &Index, queries: &[Vec<u32>], topk: usize) -> Vec<Vec<(u32, i64)>> {
    let mut runs = Vec::with_capacity(queries.len());
    for qt in queries {
        // candidate docs = union of the posting lists of the unique query terms
        let mut uniq: HashSet<u32> = HashSet::new();
        let mut cands: HashSet<u32> = HashSet::new();
        for &t in qt {
            if uniq.insert(t) {
                if let Some(pl) = ix.inv.get(&t) {
                    cands.extend(pl.iter().copied());
                }
            }
        }
        let mut scored: Vec<(u32, i64)> = Vec::with_capacity(cands.len());
        for &d in &cands {
            let tf = &ix.doc_tf[d as usize];
            // one (tf_in_doc, df) pair per query-token OCCURRENCE -> linear qtf,
            // matching bm25s / rank-bm25 which sum per query-token occurrence.
            let mut pairs: Vec<(u64, u64)> = Vec::with_capacity(qt.len());
            for &t in qt {
                if let Some(&c) = tf.get(&t) {
                    pairs.push((c as u64, ix.df[&t] as u64));
                }
            }
            let s = bm25_doc_score(&pairs, ix.n_docs, ix.doc_len[d as usize], ix.avg_len);
            scored.push((d, s));
        }
        scored.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        scored.truncate(topk);
        runs.push(scored);
    }
    runs
}

/// The ideal-float twin of [`run_queries`], identical plumbing, [`float_doc_score`]
/// instead of the leaf -- isolates float-vs-integer at same language/harness.
fn run_queries_float(ix: &Index, queries: &[Vec<u32>], topk: usize) -> Vec<Vec<(u32, f64)>> {
    let mut runs = Vec::with_capacity(queries.len());
    for qt in queries {
        let mut uniq: HashSet<u32> = HashSet::new();
        let mut cands: HashSet<u32> = HashSet::new();
        for &t in qt {
            if uniq.insert(t) {
                if let Some(pl) = ix.inv.get(&t) {
                    cands.extend(pl.iter().copied());
                }
            }
        }
        let mut scored: Vec<(u32, f64)> = Vec::with_capacity(cands.len());
        for &d in &cands {
            let tf = &ix.doc_tf[d as usize];
            let mut pairs: Vec<(u64, u64)> = Vec::with_capacity(qt.len());
            for &t in qt {
                if let Some(&c) = tf.get(&t) {
                    pairs.push((c as u64, ix.df[&t] as u64));
                }
            }
            let s = float_doc_score(&pairs, ix.n_docs, ix.doc_len[d as usize], ix.avg_len_f);
            scored.push((d, s));
        }
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap().then(a.0.cmp(&b.0)));
        scored.truncate(topk);
        runs.push(scored);
    }
    runs
}

fn main() {
    let data = std::env::args().nth(1).unwrap_or_else(|| "./data".to_string());

    let meta = fs::read_to_string(format!("{data}/meta.txt")).expect("meta.txt");
    let m: Vec<u64> = meta.split_whitespace().map(|x| x.parse().unwrap()).collect();
    let (k1x, bx, topk, n_docs_meta, n_q_meta) =
        (m[0], m[1], m[2] as usize, m[3], m[4]);
    // The leaf's params are FROZEN constants; assert the float twin used the same
    // ones so the head-to-head isolates float-vs-integer, nothing else.
    assert_eq!(k1x as i64, BM25_K1, "k1 mismatch: leaf {BM25_K1} vs input {k1x}");
    assert_eq!(bx as i64, BM25_B, "b mismatch: leaf {BM25_B} vs input {bx}");

    let docs = read_tok(&format!("{data}/docs.tok"));
    let queries = read_tok(&format!("{data}/queries.tok"));
    let doc_ids = read_lines(&format!("{data}/doc_ids.txt"));
    let query_ids = read_lines(&format!("{data}/query_ids.txt"));
    assert_eq!(docs.len() as u64, n_docs_meta);
    assert_eq!(queries.len() as u64, n_q_meta);

    let t_ix = Instant::now();
    let ix = build_index(&docs);
    let index_ms = t_ix.elapsed().as_secs_f64() * 1e3;

    // latency: repeat the query loop, report the fastest warm pass
    let mut best = f64::MAX;
    let mut runs: Option<Vec<Vec<(u32, i64)>>> = None;
    for rep in 0..LAT_REPEATS {
        let t0 = Instant::now();
        let r = run_queries(&ix, &queries, topk);
        let dt = t0.elapsed().as_secs_f64();
        best = best.min(dt);
        if rep == 0 {
            runs = Some(r);
        }
    }
    let runs = runs.unwrap();

    // determinism: a fresh independent pass must be byte-identical (pure integer)
    let again = run_queries(&ix, &queries, topk);
    let deterministic = again == runs;

    // ideal-float twin, same harness -- isolates float-vs-integer speed & ranking
    let mut best_f = f64::MAX;
    let mut runs_f: Option<Vec<Vec<(u32, f64)>>> = None;
    for rep in 0..LAT_REPEATS {
        let t0 = Instant::now();
        let r = run_queries_float(&ix, &queries, topk);
        let dt = t0.elapsed().as_secs_f64();
        best_f = best_f.min(dt);
        if rep == 0 {
            runs_f = Some(r);
        }
    }
    let runs_f = runs_f.unwrap();

    // top-10 ranking agreement of the integer leaf vs its ideal-float twin
    let mut overlap = 0usize;
    let mut top1_same = 0usize;
    for (ri, rf) in runs.iter().zip(runs_f.iter()) {
        let sf: HashSet<u32> = rf.iter().map(|(d, _)| *d).collect();
        overlap += ri.iter().filter(|(d, _)| sf.contains(d)).count();
        if !ri.is_empty() && !rf.is_empty() && ri[0].0 == rf[0].0 {
            top1_same += 1;
        }
    }
    let denom: usize = runs.iter().map(|r| r.len()).sum();

    let write_run = |name: &str, rows: &dyn Fn(&mut String)| {
        let mut out = String::new();
        rows(&mut out);
        fs::write(format!("{data}/{name}"), out).expect("write run");
    };
    write_run("yuva_run.tsv", &|out: &mut String| {
        for (qi, ranked) in runs.iter().enumerate() {
            for (d, s) in ranked {
                out.push_str(&query_ids[qi]);
                out.push('\t');
                out.push_str(&doc_ids[*d as usize]);
                out.push('\t');
                out.push_str(&s.to_string());
                out.push('\n');
            }
        }
    });
    write_run("rustfloat_run.tsv", &|out: &mut String| {
        for (qi, ranked) in runs_f.iter().enumerate() {
            for (d, s) in ranked {
                out.push_str(&query_ids[qi]);
                out.push('\t');
                out.push_str(&doc_ids[*d as usize]);
                out.push('\t');
                out.push_str(&format!("{s:.6}"));
                out.push('\n');
            }
        }
    });

    let nq = queries.len() as f64;
    let qps = nq / best;
    let qps_f = nq / best_f;
    eprintln!("== Yuva no-float BM25 leaf (tb_encode::recall::bm25_doc_score) ==");
    eprintln!("docs={}  queries={}  avg_len={} (int) / {:.2} (real)  k1={} b={} (x1000)", ix.n_docs, queries.len(), ix.avg_len, ix.avg_len_f, BM25_K1, BM25_B);
    eprintln!("index build       : {index_ms:.2} ms");
    eprintln!("INTEGER leaf loop : best={:.2} ms  ({qps:.1} QPS, {:.3} ms/query)", best * 1e3, best * 1e3 / nq);
    eprintln!("ideal-FLOAT loop  : best={:.2} ms  ({qps_f:.1} QPS, {:.3} ms/query)  [same harness]", best_f * 1e3, best_f * 1e3 / nq);
    eprintln!("determinism       : {} (independent integer re-run byte-identical)", if deterministic { "PASS" } else { "FAIL" });
    eprintln!("int-vs-float top-10 overlap: {}/{} = {:.4}   top-1 agree: {}/{}", overlap, denom, overlap as f64 / denom as f64, top1_same, queries.len());
    eprintln!("runs written: {data}/yuva_run.tsv , {data}/rustfloat_run.tsv");
    assert!(deterministic, "non-deterministic ranking -- integer leaf must be bit-exact");
}
