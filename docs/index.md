---
type: Index
title: Yuva documentation index
description: >-
  Progressive-disclosure entry point for docs/: three reading paths, the
  shelves by content type, and the knowledge graph that ends in the boot
  transcript. Status fields are maintained at landing time; the BACKLOG
  banner is the live status source for plans.
tags: [index, docs]
timestamp: 2026-07-09T00:00:00Z
status: active
diataxis: reference
---

# Yuva documentation — start here

Yuva is a from-scratch, agent-native sovereign unikernel / micro-VMM where
**the boot is the proof**. Every push builds and boots both architectures and
fails closed unless the full cumulative self-test marker chain prints over
serial — with machine-emitted UPPERCASE honesty tokens stating what is and is
NOT claimed. The documentation follows the same discipline
([DOCUMENTATION-STANDARD](DOCUMENTATION-STANDARD.md)): every doc is typed,
statused, and honest about its own stage; decision records are superseded,
never deleted.

## Three reading paths

**The skeptic's 15 minutes** — the claim boundary IS the product:

1. [README](../README.md) — what this is, with a real boot transcript
2. [TRY-IT](TRY-IT.md) — watch it boot yourself (two commands, WSL2/Linux);
   the demo is a viewer, the run scripts are the verifier
3. [assumptions.md](assumptions.md) — what the proofs do NOT discharge (the
   seL4-style residual trusted base, written down)
4. [spec/yuva-abi-v1.md](spec/yuva-abi-v1.md) — the normative contract,
   enforced fail-closed at boot

**The contributor:**

1. [CONTRIBUTING](../CONTRIBUTING.md) — the engineering discipline is the
   contributor guide
2. [PROCESS](PROCESS.md) — how the project actually works (research-first →
   adversarial review → boot-verified landing)
3. [ROADMAP-V2](ROADMAP-V2.md) — the canonical milestone chain and its
   executable DoDs
4. [proposals/forward-plan.md](proposals/forward-plan.md) — where work goes
   next, and which gates are operator-owned

**The operator:**

1. [TRY-IT](TRY-IT.md) → [RUN-THE-HELLO](RUN-THE-HELLO.md) (the
   operator-gated live-model lane — never unattended, never a required check)
2. [proposals/forward-plan.md](proposals/forward-plan.md) §gates — the
   operator-owned gates
3. [BACKLOG](BACKLOG.md) — the live status banner for everything in flight

## The shelves

### Understand (explanation — the why)

| Doc | One line |
|---|---|
| [VISION](VISION.md) | Why Yuva exists: agent + computer as one kernel object; the four pillars |
| [SOVEREIGNTY](SOVEREIGNTY.md) | Clean-slate decision: silicon-mandated vs open-standard vs rejected-Linux vs Yuva-owned |
| [ARCHITECTURE](ARCHITECTURE.md) | Kernel design north-star + the honest design→reality as-built map |
| [research/cogi-cognitive-architecture.md](research/cogi-cognitive-architecture.md) | The agent-side position: what is buildable-now vs frontier-unsolved, held apart |
| [RESEARCH-REPORT](RESEARCH-REPORT.md) | The planning-phase research synthesis everything cites |

### Operate (how-to / runbook)

| Doc | One line |
|---|---|
| [TRY-IT](TRY-IT.md) | Boot it in 2 minutes; viewer vs verifier; why there is no .iso |
| [../BUILD.md](../BUILD.md) | Toolchain, manual build/run, ELF-note verification |
| [RUN-THE-HELLO](RUN-THE-HELLO.md) | The one operator-gated real-model call (M31 stage C) |

### Contracts (reference — normative, frozen)

| Doc | One line |
|---|---|
| [spec/yuva-abi-v1.md](spec/yuva-abi-v1.md) | Yuva↔agent ABI v1: two planes, RFC 2119, boot-enforced registry |
| [spec/yuva-abi-negotiation-v1.md](spec/yuva-abi-negotiation-v1.md) | Version negotiation shape (runtime gate deferred, honestly) |
| [spec/corpus-format-v1.md](spec/corpus-format-v1.md) | FROZEN CorpusRecord schema — a provenance skeleton, not text, not training |
| [assumptions.md](assumptions.md) | The residual trusted base the proofs assume, stated bluntly |
| [BENCHMARKS](BENCHMARKS.md) | Boot-time numbers with matched metrics and cited sources (pipeline-maintained) |

### Plan of record (roadmap)

| Doc | One line |
|---|---|
| [ROADMAP-V2](ROADMAP-V2.md) | The canonical agent-native chain; DoD = exact serial markers |
| [MILESTONES](MILESTONES.md) | The milestone record + development pipeline |
| [SOVEREIGNTY-ROADMAP](SOVEREIGNTY-ROADMAP.md) | The L0→L3 sovereignty ladder; full sovereignty = L2 |
| [SOVEREIGNTY-L2-ROADMAP](SOVEREIGNTY-L2-ROADMAP.md) | tb-core, the from-scratch Type-1 microhypervisor track (aarch64-first) |
| [BACKLOG](BACKLOG.md) | Leverage-ordered forward tasks + the LIVE status banner |
| [proposals/forward-plan.md](proposals/forward-plan.md) | The phased forward map; pillar states stated honestly (learning: DORMANT) |

### Decision records (ADR — superseded, never deleted)

| Where | What lives there |
|---|---|
| [proposals/](proposals/index.md) | The research-first proposal set — this project's ADR form: proposal → adversarial review → landing banner → retained forever. See the ledger for the status/stage of each |
| [plans/INDEX.md](plans/INDEX.md) | Point-in-time execution plans (2026-06-08). Consult the [BACKLOG](BACKLOG.md) banner for which have since landed vs stay operator-gated |
| [KERNEL-FOUNDATION-SPEC](KERNEL-FOUNDATION-SPEC.md) · [MEMORY-SPEC](MEMORY-SPEC.md) · [AGENTS-SPEC](AGENTS-SPEC.md) · [SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md) | The 2026-06 planning-phase DESIGN specs ([DECISION]/[PROPOSAL]/[OPEN]-marked). Distinct from `spec/` — same word, two shelves: these explain the design; `spec/` freezes contracts |
| [LANGUAGE-AND-STANDARDS](LANGUAGE-AND-STANDARDS.md) | The per-layer language allowlist decision |
| [PROCESS](PROCESS.md) · [OPEN-QUESTIONS](OPEN-QUESTIONS.md) | The audited process record; the question ledger with its resolved [DECISION] rows |
| [DOCUMENTATION-STANDARD](DOCUMENTATION-STANDARD.md) | This documentation standard (OKF + Diátaxis + docs-as-code + the honesty rules) |

### Research library (explanation — point-in-time, immutable-by-convention)

[research/](research/) — per-milestone literature reviews
(`m2X-*-literature.md`), engine evaluations, root-cause analyses, and the two
position papers. `research/raw/` is the immutable JSON research provenance the
docs cite — never edited, only added to.

## The knowledge graph

Docs here are nodes in one repeating pipeline; the edges below are the only
edge types, so you can navigate any milestone the same way:

```
research/X-literature.md
        │ grounds
        ▼
proposals/X.md   (adversarial review + landing banner recorded in-body)
        │ promoted-to
        ▼
spec/X-v1.md
        │ enforced-by
        ▼
code + CI lane
        │ witnessed-by
        ▼
the boot serial marker (+ honesty tokens)
        │ tracked-in
        ▼
ROADMAP-V2.md row
```

Standing edges: [assumptions.md](assumptions.md) is cited FROM the silicon
glue (`crates/tb-hal/src/arch/aarch64/stage2.rs`); [BACKLOG](BACKLOG.md) is
the freshness source for `plans/`; `crates/brand` is the single source of
every name-bearing wire byte. The chain deliberately terminates in an
executable witness, not prose: when a document and the boot transcript
disagree, the boot wins.
