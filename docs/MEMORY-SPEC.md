---
type: Architecture
title: "Yuva Memory Specification (Default Memory Structure)"
description: "Draft v1.0 spec for Yuva's tiered agent memory (T0-T5+BLOCKS, schema, ABI, quotas) — mostly PROPOSAL/OPEN, not confirmed built."
tags: ["memory", "architecture", "spec", "agent-os", "kernel-abi"]
timestamp: 2026-06-07T01:48:32+03:00
status: draft
diataxis: explanation
---

# Yuva Memory Specification (Default Memory Structure)

> Status: v1.0 draft — marked **[DECISION] / [PROPOSAL] / [OPEN]**.
> Basis: [RESEARCH-REPORT §4](RESEARCH-REPORT.md) · Related: [ARCHITECTURE](ARCHITECTURE.md) · [AGENTS-SPEC](AGENTS-SPEC.md) · [SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md)

---

## 0. Principle

**In Yuva, memory is not a library but a kernel guarantee.** When each agent is born, the tier set below exists automatically; no framework code is required. The kernel guarantees *the store, the index, the quotas, the consistency and the provenance*; *the intelligence that decides what matters* (enrichment, op selection, distillation) lives in pluggable userspace services (LLM-agnosticism: exokernel separation — protection in the kernel, policy outside).

## 1. Tier Architecture **[DECISION — T0–T5 + BLOCKS structure derived from the fivefold convergence of the survey; rationale: 84 architectures, arXiv:1610.08602]**

```
T0  CONTEXT REGISTERS   ACT-R buffers: named, bounded, typed register slots
                        (goal, retrieval, percept, tool-result, …). The prompt is
                        materialized from these — NO unbounded context blob.
T1  WORKING             Soar WM: state-rooted graph; unreachable auto-GC;
                        i-support (justifying thought auto-retracted) / o-support distinction.
T2  EPISODIC JOURNAL    Automatic flight-recorder (requires no agent action — Soar EpMem);
                        lossless, append-only, bi-temporal; read-your-writes INSTANT.
T3  SEMANTIC STORE      Distilled fact/note records; embedded store (SQLite-class:
                        sub-ms over millions of nodes, <1KB/fact); activation-ranked retrieval.
T4  PROCEDURAL / SKILL  Executable skills + distilled principles; write is privileged
                        (CoALA risk asymmetry: WRITE_PROCEDURAL a separate right; verification-
                        before-commit — see SELF-IMPROVEMENT-SPEC).
T5  ARCHIVAL / PARAMETRIC  (optional modules) Vector-archival (Letta-style) ·
                        graph tier (Zep/Mem0g — opt-in for temporal queries) ·
                        parametric (fine-tune/knowledge-edit; local backend only, BULK).
+   BLOCKS              Letta memory-block tier: named, quota'd pinned segments that can be
                        MAPped into N agents' contexts; CAS/CRDT write
                        semantics (the last-write-wins library bug is resolved in the kernel).
```

Deviation rationales (the survey's own rule: *deviation needs justification*): the survey's **sensory** tier is not a separate tier in Yuva — the percept/ingest flow lands in T0 registers (ACT-R perceptual buffer model); T5 and BLOCKS are optional/add-on layers on top of the fivefold core (T0–T4).

Union-namespace ergonomics: the session-scratch tier is bound on top of the persistent tier; `tb_recall` lands in union order ([ARCHITECTURE §3](ARCHITECTURE.md)).

## 2. Record Schema **[PROPOSAL — A-MEM + Zep + GA synthesis]**

`MemRecord` (kernel-fixed fields; inode analogy):

| Field | Type | Source/pattern |
|---|---|---|
| `id`, `content` | — | raw content (text/MIME-parts — ACP lesson) |
| `t_created, t_expired` | transaction timeline | **bi-temporal mandatory** (Zep) |
| `t_valid, t_invalid` | event timeline | contradiction = invalidate, not delete |
| `importance` | int 1-10 | single LLM call at write time (GA "poignancy") |
| `embedding` | vec | provider pluggable |
| `keywords, tags, context` | derived | enrichment userspace service (A-MEM; local 1B model ~1.1 s/op) |
| `links[]` | typed | `cites` (derived→source: hallucination audit — GA reflection), `relates`, `supersedes` |
| `provenance` | enum+ref | inside-trial / cross-trial / external (survey 2404.13501) + producing agent/task |
| `access` | {count, last_k_ts[k=10]} | base-level activation O(1) state (ACT-R/Petrov) |
| `utility` | {c_succ, c_use} | s=(c_succ+1)/(c_use+2) — kernel fills from outcome telemetry (EvolveR) |
| `acl` | namespace ref | §7 |

**The write is transactional**: one insert can evolve neighboring k records (A-MEM memory evolution) → multi-record atomic update + old versions are recoverable (versioning).

## 3. Operation ABI **[PROPOSAL]**

- **Three syscall families** (the survey's three OPERATIONS classes): `tb_mem_write` / `tb_mem_read` / `tb_mem_manage`; the CoALA triad `tb_recall`/`tb_reflect`/`tb_learn` is sugar on top of these.
- **Update decision with a four-op vocabulary**: `ADD / UPDATE / DELETE(→tombstone) / NOOP` — the LLM "oracle" that makes the policy decision is pluggable (function-calling interface, Mem0); the kernel is what *executes* the op.
- **Retrieval is a three-stage pipeline, not a monolithic search** (Zep): ① candidate search — hybrid default: lexical (BM25) + dense (cosine) + graph/BFS in parallel; ② rerank — pluggable: RRF/MMR/cross-encoder/node-distance; ③ context constructor — templated, with validity date ranges.
- **Default ranking (weighted sum)**: `score = w_a·BLA(d=0.5) + w_r·relevance + w_i·importance` (components min-max normalized, default w=1) — the additive form is faithful to GA's validated score (α_rec·rec + α_imp·imp + α_rel·rel, all α=1) and to ACT-R's own activation equation (A = B + S + P + ε); BLA(d=0.5) is the best-validated 50-year-old constant on which both Soar and ACT-R converge; spreading activation (priming from buffer content, fan-effect penalized), partial match and noise are **OFF by default** (ACT-R conservatism).
- **Finsts** [DECISION]: the kernel keeps a bounded + time-limited "just returned" set per agent and offers `exclude_recent` / `retrieve_next` iteration semantics — the 40-year-old breaker of the RAG return-the-same-result loop (ACT-R 4/3 s; Yuva default scaled to session length [OPEN]).
- **Indexing scope** [PROPOSAL]: the default index covers agent *outputs too*, not just user inputs — Zep's single-session-assistant regression (−17.7%, gpt-4o) showed that derived tiers lose assistant-side detail.
- **Copy-on-retrieve** [PROPOSAL]: retrieval instantiates a *copy* into working memory (Soar LTI/STI distinction); the long-term store changes only by explicit commit — no accidental in-place mutation.
- **Access metadata is written on the read path** → relatime-style batching [OPEN].

## 4. Consolidation and Reflection **[PROPOSAL]**

- **The trigger is not a cron but an importance accumulator** (GA: threshold 150, 2-3 triggers per day): the kernel counts the sum of incoming importance per agent; on threshold overflow it schedules a `BULK`-class reflection job (dirty-page writeback analogy).
- Reflection outputs return to T3 with `cites` links; reflection-over-reflection trees are allowed.
- **Async consolidation daemon** (kswapd analogy — Mem0's async summary refresher): summaries, dedup (embedding + LLM equivalence), merge, demotion; it never blocks the agent's critical path.
- **Sleep-time compute** is the generalized form of this daemon; it lands in idle inference capacity as `BULK` (~5× measured payback — [SELF-IMPROVEMENT-SPEC §4](SELF-IMPROVEMENT-SPEC.md)).

## 5. Consistency and Quota **[DECISION — principles]**

- **Read-your-writes is INSTANT over T2 (raw episodic).** Derived tiers (T3+, graph, communities) carry a **visible epoch/freshness marker**; the agent can query it before trusting. (Zep's hours-long ingestion lag + lack of RYW is the counter-example.)
- **Write-amplification is quota'd in tokens** (disk quota analogy): unbounded LLM-derivation can inflate by more than 20× (Zep measurement: 26K→600K+); space-bank-style hierarchical budget (KeyKOS).
- p95 retrieval budget **<200 ms** (Mem0 proved it); **escape hatch**: for a high-stakes query, raw-episode replay is always addressable (at a 10-17 s cost — full-context ~5 J-point ceiling difference).

## 6. Forgetting **[PROPOSAL — where the field has not solved it, Yuva design]**

No primary system implements tested real deletion; the converged safe composition:

1. **Demotion via score-decay** (GA decay × BLA): the record moves down across tiers (T3→T5 archival), it does not disappear.
2. **Tombstone, not delete** (Zep+Mem0g consensus): `t_invalid` is set; history is preserved; temporal queries work.
3. **Hard delete only as a privileged explicit op** (privacy/compliance; tagged to a human-approval gate).
4. **Soar's two admitted gaps are closed in the kernel**: default compaction/summary tier for the unbounded journal + pluggable secondary indexes over the canonical journal (the linear-scan worst-case).

## 7. Multi-Agent Memory Namespaces **[PROPOSAL — greenfield; no standard in the literature]**

Survey §8.2 declares this area open; the Yuva design:

```
memory:private/<agent>/…    owner only; default home
memory:session/<sess>/…     the agents in the session (blackboard pattern: shared
                            cognitive state with parallel writers — the proven structure of the 84-architecture survey)
memory:world/…              installation-wide knowledge; READ to everyone, WRITE curated
blocks:<name>               pinned shared segments; CAS/versioned write + watch
```

- Access by capability (handle+rights); the `RECALL` right can be separated per tier.
- Write conflict in the session tier: record-level CAS + on conflict keep both versions bi-temporally with a `supersedes` link [OPEN: CRDT or CAS — prototype measurement].
- Timing side-channel: prefix/embedding cache sharing between agents of different trust-domains is off by default [OPEN].

## 8. Benchmark Reality **[OPEN]**

Existing benchmarks (DMR saturated at 98%; LOCOMO conversation-QA; all systems F1<4 on DialSim) do not measure OS-lifetime agent memory. Yuva must define its own evaluation harness: tool-use traces, code tasks, cross-task skill transfer, multi-agent sessions, life cycles lasting weeks. ([OPEN-QUESTIONS §Memory](OPEN-QUESTIONS.md))