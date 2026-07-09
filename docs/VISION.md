---
type: Explanation
title: "Yuva Vision Document"
description: "Planning-phase (v1.0) vision for Yuva: an OS where agent mind+sandbox are one kernel object; roadmap phases are non-committal drafts."
tags: ["vision", "agent-os", "planning-phase", "capabilities", "memory", "roadmap"]
timestamp: 2026-06-07T01:48:32+03:00
status: active
diataxis: explanation
---

# Yuva Vision Document

**Turkiye's Agent Based Operating System**

> Status: v1.0 (planning phase) · Basis: [RESEARCH-REPORT](RESEARCH-REPORT.md)
> Related: [ARCHITECTURE](ARCHITECTURE.md) · [MEMORY-SPEC](MEMORY-SPEC.md) · [AGENTS-SPEC](AGENTS-SPEC.md) · [SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md) · [OPEN-QUESTIONS](OPEN-QUESTIONS.md)

---

## 1. Yuva in One Sentence

**Yuva is an operating system designed from scratch, in which the AI agent and its computer are a single kernel object, and in which memory, self-improvement, and multi-agent life are offered as operating-system guarantees.**

What Linux is for the human operator, Yuva is for the agent — but without carrying over any of Linux's 35-year human-desktop legacy (ttys, the multi-user uid model, X11, non-human-readable binary ABIs, hundreds of syscalls the agent will never call).

## 2. Why Does It Exist? — Gap Analysis

The sharpest finding of the research ([RESEARCH-REPORT §5](RESEARCH-REPORT.md)): in today's ecosystem the agent's "mind" and its "hands" live in separate systems, and no system owns both at once:

| System | Part it owns | What it cannot own |
|---|---|---|
| **E2B** | The computer (microVM, FS+RAM snapshot) | The agent's mind — context, memory, LLM loop live in the host application |
| **Letta** | The mind (.af: memory blocks, message history, tool definitions) | Execution sandbox state; concurrency (last-write-wins) |
| **AIOS** | Scheduling (LLM syscalls, 2.1× throughput) | Isolation (Python daemon, hashmap ACL); persistent per-user kernel "ongoing" |

**None of them can suspend/resume/migrate/fork the whole of `{context window + memory tiers + in-flight inference state + sandbox processes + file system}` as a single atomic unit.** Yuva's reason for being is to own this join at the kernel level: *no torn state* — no half-finished checkpoint between the brain and the hands; capability flows from brain to hand without leaving the kernel; a single resource account (token + CPU + RAM + disk + dollar).

## 3. Design Philosophy — Five Principles

### Principle 1: Every subsystem lives by the question "what does it gain the agent?"
The user's founding constraint. If a subsystem does not enlarge the potential of what the agent can do, it has no place in Yuva. Its architectural counterpart is library-OS modularity (Unikraft: only the needed components are compiled, ~1 MB image [arXiv:2104.12721]). Zero human-desktop legacy: no terminal emulation, no multi-user session, no GUI infrastructure. The human touches Yuva not as *operator* but as **consent-giver and observer** (elicitation channel, audit trees).

### Principle 2: Memory is not a feature, it is a kernel guarantee
Today memory is a library every framework reinvents. In Yuva **default, persistent, tiered memory is given to every agent at birth** — just as the file system is not "optional." KeyKOS's orthogonal persistence is the template: the agent's entire state experiences a power outage like "the clock skipping"; **hibernate is the default, terminate is the exception.** Detail: [MEMORY-SPEC](MEMORY-SPEC.md).

### Principle 3: There is no ambient authority — authority is always visible and weakens as it is delegated
Agents are the very thing Shapiro's "programs, not people" critique ([EROS essay](RESEARCH-REPORT.md)) is about: actors open to prompt-injection, fed by third-party code, distrusting one another. In Yuva the POSIX uid model never exists; every tool call, every memory access, every model invocation goes through **explicit capability** (Zircon handle+rights model; attenuation-only duplicate; birth via a single bootstrap handle). The bonus of this: mutually-suspicious cooperation — my proprietary agent on your secret data, with neither side able to leak.

### Principle 4: Token, context, and inference are schedulable resources
Just as CPU-second and RAM-byte are resources, so are the ITPM/OTPM quota, the KV-cache block, the context window, and the dollar. seL4 MCS's budget+period scheduling-context capabilities have been proven in production for compute (its formal verification is still ongoing); Yuva applies the same model to token flows. In the kernel a single neutral **context scheduler**, with two driver families beneath it: local (HBM, GPU-second) and remote (dollar, quota). The asymmetric trump card: because the persistent state is the token *text* (KV is a recomputable cache [vLLM]), agent migration moves KB, not GB.

### Principle 5: Self-improvement is an OS service — but the measurer is separate from the measured
Reflection, skill accumulation, and experience distillation are offered default-on to every agent (weight-free, hence LLM-agnostic [Reflexion]). But the Darwin Gödel Machine's lesson is the rule: **frozen kernel / evolving userspace** — evaluators, safety detectors, and the evolution engine are in a layer the agent cannot read/write (a visible metric gets Goodharted; in DGM the agent effectively bypassed the detector). The priority hierarchy is coded into the kernel: **Endure > Excel > Evolve** [arXiv:2508.07407]. Detail: [SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md).

## 4. Yuva's First-Class Citizens

1. **Agent process** — `{context + memory + inference + sandbox + FS}` as a single object; atomic checkpoint/fork/migrate ([AGENTS-SPEC](AGENTS-SPEC.md))
2. **Memory record / tier** — bi-temporally stamped, with provenance, quota-bound ([MEMORY-SPEC](MEMORY-SPEC.md))
3. **Capability/handle** — authority that multiplies only by weakening, with a rights mask
4. **Task** — a unit of work with 9 states, durable, with human/credential-blocked states (A2A model)
5. **Token budget** — a budget+period, hierarchical, delegatable budget
6. **Skill** — code + description + embedding + utility score; accepted with verification-before-commit
7. **Session** — a shared living space for one or N agents with a shared blackboard and event streams

## 5. Identity: Name and Language

- **Yuva** *(Turkish: "nest, home")* — the project's name (decided 2026-06; just Yuva — no acronym, no backronym). It was developed under the code name **TABOS** (*Turkiye's Agent Based Operating System*), selected after a two-round vetting of 31 candidates (24+7; 23 fully vetted; npm/PyPI/crates empty, no active conflict in the AI/agent/OS space — [RESEARCH-REPORT §9](RESEARCH-REPORT.md)). The TABOS-era wire/ABI strings were migrated in the brand PR: every name-bearing byte now derives from `crates/brand` (script mirror: `scripts/project.env`).
- Kernel symbol prefix (placeholder tied to the code name): **`tb_`** (syscalls), **`TB_`** (constants). CLI: `yuva` / `tb`. No spec carries a semantic dependency on the name — if the name changes, a mechanical find-replace suffices.
- A reserved concept pool for subsystem naming (those that came out during vetting as "nice as a concept but taken as a brand" are free as internal names): `daemon`→agent supervisor, `synapse`→IPC channels, `engram`→the internal name of the memory record, `hexis`→the internal name of the skill object.
- Project language: documentation in Turkish (technical terms in English); code/identifiers in English (open to international contribution).

## 6. Out of Scope (deliberate)

- **Being a general-purpose human desktop/server OS** — no competition with Linux; non-agent workloads are not a target.
- **Having to train/host your own LLM** — inference is always behind a driver (remote API or local engine); Yuva is not the model but the model's *home*.
- **Writing your own hardware driver universe in v1** — Yuva boots as a guest on top of a hypervisor/VMM (KVM/Firecracker-class); bare metal is a later phase ([OPEN-QUESTIONS](OPEN-QUESTIONS.md)).
- **Marriage to a single protocol** — MCP/A2A/ACP/ANP are userspace bridges; the kernel ABI stays neutral.

## 7. Success Criteria (planning-phase exit bars)

| # | Criterion | Measure |
|---|---|---|
| 1 | Agent spawn cold start | Below the E2B bar of <200 ms; target **<50 ms** with the unikernel path |
| 2 | Atomic checkpoint | Mind+computer in a single image; zero torn state after resume |
| 3 | Memory default | Persistent recall without writing any framework code; p95 retrieval <200 ms (Mem0 bar) |
| 4 | Quota efficiency | ≥3× effective work at the same ITPM via cache-aware placement (Anthropic cache-exempt arithmetic) |
| 5 | Self-improvement payback | ≥2× test-time compute reduction in the sleep-time compute class (Letta ~5× bar) |
| 6 | Security | Zero ambient authority; every authority enumerable at spawn time; evaluators unreadable by the agent |

## 8. Roadmap View (draft)

1. **Phase 0 — this folder:** Document set + closing the open questions (spec freeze).
2. **Phase 1 — core prototype:** Handle/capability layer + agent process object + memory T0-T2 tiers; host: user-mode prototype on top of Linux (for fast iteration), preserving the target ABI.
3. **Phase 2 — real isolation:** Yuva unikernel guest in a Firecracker-class microVM; WASM nanoprocess tool runtime; context scheduler v1 (remote lease driver first).
4. **Phase 3 — multi-agent + self-improvement:** Session/blackboard, A2A bridge, sleep-time class, skill compiler.
5. **Phase 4 — ecosystem:** Agent image format + package/agent hub (Cerebrum lessons), .af import compatibility.

> The phases are not a commitment until the kernel-vs-userspace decisions in [OPEN-QUESTIONS](OPEN-QUESTIONS.md) are closed.
