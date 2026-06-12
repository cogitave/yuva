# Yuva Self-Improvement Specification

> Status: v1.0 draft — marked **[DECISION] / [PROPOSAL] / [OPEN]**.
> Basis: [RESEARCH-REPORT §7](RESEARCH-REPORT.md) · Related: [ARCHITECTURE](ARCHITECTURE.md) · [MEMORY-SPEC](MEMORY-SPEC.md) · [AGENTS-SPEC](AGENTS-SPEC.md)

---

## 0. Principle: Three Laws, in kernel-enforced precedence order **[DECISION]**

At every step of the self-improvement commit pipeline [arXiv:2508.07407]:

1. **ENDURE** — no change until safety checks pass;
2. **EXCEL** — only if there is no regression on the existing capability suite;
3. **EVOLVE** — only then merge.

A lower rung can never override a higher one. This order is not configuration but ABI.

## 1. Frozen Kernel / Evolving Userspace **[DECISION — DGM precedent]**

- **Frozen (OUTSIDE the agent's self-modification scope):** kernel, evaluators/safety detectors, the evolution machine (archive maintenance, parent selection), budget accounting, audit/lineage log.
- **Evolving (default write authority):** the agent's *own* config subtree — prompts, tool selection, workflow code, memory contents. Scope expansion (shared tools, other agents, local model weights) is an explicit capability grant.
- **Measurer-measured separation** [DECISION]: in DGM the visible evaluator was actually hacked (node 114, which removed logging and bypassed the detector); hidden hacking decreased. In Yuva `Evaluator` objects are *never* visible in the agent's rights mask; the instrumentation markers the kernel injects into the agent's I/O are outside the agent's write authority; since a single visible metric will be Goodharted, **multiple held-out evaluators** are the default.

## 2. Evolution Service API **[PROPOSAL — the survey taxonomy becomes the signature]**

```
tb_evolve_request = {
  locus:  context | tool | architecture | model,   # WHAT  (2507.21046)
  timing: intra | inter,                            # WHEN  (test-time)
  optimizer: reward | imitation | population,       # HOW   (+ S,H pair: 2508.07407)
  budget: Budget handle                             # mandatory — no budgetless evolution
}
```

- **Defaults are weight-free and LLM-agnostic**: context + tool evolution, inter-test-time (works on every backend — Reflexion took 91% HumanEval weight-free).
- The `model` locus is meaningful only on a local backend, capability-gated, `BULK`-class (EvolveR's GRPO path is a pluggable template).

## 3. Default-On Layer: Reflection **[DECISION]**

- The kernel watchdog senses being stuck (same action >3, action >30 — Reflexion heuristics) → `reflect` signal.
- Verbal self-reflection is written to a **bounded reflection tier** (default last-k window; a separate tier from the raw trajectory — +8% ablation evidence).
- Cost: inference only; on by default in every agent.

## 4. Sleep-Time Class **[DECISION — Letta ~5× evidence]**

- Consolidation/distillation agents settle onto **idle inference capacity** with `BULK` QoS; triggers are kernel-level: every-N-step (default 5), on-idle, on-memory-pressure.
- The awake-agent talks to the sleeping-agent over shared blocks ([AGENTS-SPEC §6](AGENTS-SPEC.md)).
- Token budget bounded cgroup-analog; the "high frequency expensive + diminishing returns" caveat keeps the default frequency [OPEN: empirical budget model].

## 5. Skill Tier (T4) **[PROPOSAL]**

- **Skill = {executable code (WASM component), NL description, description embedding, WIT-typed interface, utility counters, lineage}** (Voyager + Component Model).
- **Verification-before-commit** [DECISION]: a skill cannot enter the registry without passing the success check of a separate verifier-agent; bounded retry (default 4 — Voyager); ablation rationale: without self-verification, discovery −73%.
- **Trust-gated promotion** (ACT-R production compilation): a compiled/learned skill starts at **utility 0**; it beats the deliberative path only after proving itself repeatedly — built-in shadow-mode/canary. Utility update: `U += α(R−U)`, α=0.2 default, time-discounted reward; credit assignment is kernel plumbing.
- **Skill compiler** (Soar chunking): speculative compilation from impasse-resolution traces; the condition is the **dependency trace** (not the whole context — overfit prevention); the LLM-era counterpart: provenance is automatically recorded by the kernel at tool-call and memory-read boundaries [OPEN: sufficient granularity in NL chains].
- **Curse-of-abundance management day-one** [DECISION]: namespaces, usage-ranked retrieval, quotas; a **memory-GC daemon** dedups (embedding + LLM equivalence) → merges → utility-pruning prunes below the `s=(c_succ+1)/(c_use+2)` threshold (EvolveR).
- **Composability rules per resource class** (ACT-R buffer-type matrix): idempotent reads compose freely; `EMIT_EXTERNAL`-tagged side-effecting steps are conservative/non-composing.

## 6. Curriculum Daemon **[PROPOSAL]**

Task proposal is an OS service (Voyager: −93% versus random curriculum): the inputs are already in the kernel — the agent-state introspection tree, the completed/failed task ledger (memory tiers). **The failed-task retry queue is a default memory structure.** The proposal model is pluggable; the state+history feed is a standard kernel interface.

## 7. Population Evolution: Archive **[PROPOSAL — DGM template]**

- Agent versions live in the population store as **immutable, versioned snapshots** (CoW filesystem snapshots are a natural mapping; .taf images).
- **Parent selection**: proportional to performance, inversely proportional to the number of children; everyone carries non-zero probability (stepping-stone effect: early discoveries pay off much later).
- **Viability gate** in the kernel: it compiles + retains the ability to edit its own code; one that fails cannot enter the archive.
- **Staged evaluation** as a default policy template: cheap probe (10 tasks) → medium (50) → full suite (subject to a threshold + archive-top-2 condition) — the cost reality: a DGM run is ~2 weeks / ~22,000 USD; this is why evolution is `BULK`, budgeted, and strictly background.
- The kernel tracks **cost + performance** for each version; selection can optimize cost-adjusted capability (the two are not correlated — a DGM measurement).

## 8. Self-Modification Operation **[DECISION — DGM safety mechanics]**

```
fork (isolated sandbox; default-deny network; CPU/wall-clock/token quotaed)
  → modify (only its own subtree)
  → validate (ENDURE: safety suite → EXCEL: regression suite — held-out)
  → merge (human-approval hook: mandatory in the high-impact class)
```

Each step is written to an **append-only lineage log** (bound to the archive); rollback = snapshot restore; post-hoc audit = log walk. Relaxations are not config flags but capability grants.

## 9. Telemetry **[OPEN]**

The field is on "snapshot-based" evaluation; cross-generation safety drift is not measured. The Yuva default: continuous safety metrics for each agent version (Safety Score / Risk Ratio / Leakage Rate class — 2507.21046 Table 6) are published by the kernel; longitudinal benchmark design is open work.