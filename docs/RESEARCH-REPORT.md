# Yuva Research Report

**Turkiye's Agent Based Operating System — Planning Phase Deep Research**

> Date: 2026-06-06 · Status: v1.0 · Language: English (technical terms in English)
> Linked documents: [VISION](VISION.md) · [ARCHITECTURE](ARCHITECTURE.md) · [MEMORY-SPEC](MEMORY-SPEC.md) · [AGENTS-SPEC](AGENTS-SPEC.md) · [SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md) · [OPEN-QUESTIONS](OPEN-QUESTIONS.md)

---

## 0. Executive Summary

This report is the synthesis of the multi-wave deep research conducted for the planning phase of **an operating system (Yuva) designed from scratch in which AI agents are first-class citizens**. The research question was: *how should one design a kernel/unikernel in which everything — including the syscall ABI — is designed for agents, carries no human-desktop legacy, is LLM-agnostic, memory-centric, self-improving, and supports single/multi-agent sessions?*

**Five main conclusions:**

1. **The "LLM as OS" paradigm is now an established research framework** [arXiv:2312.03815]: the mapping LLM ↔ kernel, context window ↔ main memory, external storage ↔ file system, tools ↔ devices/libraries, prompts ↔ commands gives a greenfield kernel a principled answer to the question "what is a resource?" The syscall interface should be structured calls with natural-language payloads (structured calls with NL payloads).
2. **Portable, validated mechanisms exist in the real OS literature**: seL4's capability + MCS budget/period model, the exokernel's secure bindings, Unikraft's ~1 MB images that boot in ~1 ms, Zircon's handle+rights object layer, and the Plan 9 / Fuchsia namespace synthesis — all translate directly to agent semantics.
3. **There is a strong literature convergence in the memory domain, but "default OS memory" is still an empty field**: MemGPT/MemOS/CoALA/HippoRAG/A-MEM/Mem0/Zep are all partial solutions; none offers multi-agent shared memory, principled forgetting, and kernel-guaranteed consistency. This is Yuva's biggest differentiation area.
4. **There are published templates for designing self-improvement as an OS service**: the Darwin Gödel Machine's frozen meta-layer / evolving agent distinction, Voyager's verification-before-commit skill library, Letta's measured ~5x-gain sleep-time compute, and Soar/ACT-R's 40-year chunking/utility mechanisms can be combined.
5. **None of the existing systems can manage "an agent + its computer" as a single object**: E2B snapshots the computer but does not know the agent's mind; Letta serializes the agent's mind but has no execution sandbox; AIOS does scheduling but as a Python daemon. The reason for a greenfield kernel to exist is to own this union.

---

## 1. Methodology and Verification Status

The research was conducted in three workflow waves (total **147 subagents**, ~3.6M tokens):

| Wave | Content | Result |
|---|---|---|
| 1. Deep-research | 5 search axes → 23 primary sources → 115 claim extractions → 3-vote adversarial verification of 25 claims | 3 claims confirmed; 22 verifications cut short by API error |
| 2. Verify + Expand | Source-grouped re-verification of the 22 claims (9 groups × 3 votes) + research across 8 missing areas | **20/22 confirmed, 2/22 corrected-and-confirmed**; 100 findings from 8 areas |
| 3. Naming | registry/domain/web vetting of 7 alternative candidates (on top of the 24 candidates from wave 1) | 7/7 eliminated; code-name decision: **TABOS** (the final name **Yuva** was decided 2026-06) |

**Verification transparency:** In the sections below, every numeric/structural claim is cited with its source. Two claims were corrected during verification and are used in their corrected forms:
- *Firecracker is not "from-scratch"* — it started from Google's crosvm and replaced QEMU (the components later diverged substantially) [NSDI'20 Agache et al.].
- *CoALA calls procedural memory writes not "categorically riskier" but "significantly riskier"* [arXiv:2309.02427].

Raw verification logs: [`verified.json`](research/raw/verified.json) (wave 2) + [`verified-wave1.json`](research/raw/verified-wave1.json) (the 3 confirmed claims of wave 1) · Domain findings: [`research/raw/`](research/raw/)

---

## 2. The "LLM as OS" Paradigm — Conceptual Framework

### 2.1 The AIOS vision paper (verified: 3-0, 3-0 — wave 1 log: [`verified-wave1.json`](research/raw/verified-wave1.json))

Ge et al., *"LLM as OS, Agents as Apps: Envisioning AIOS, Agents and the AIOS-Agent Ecosystem"* [arXiv:2312.03815, December 2023] — the field's founding vocabulary:

> "LLM is likened to OS kernel, context window to memory, external storage to file system, hardware tools to peripheral devices, software tools to programming libraries, and user prompts to user commands."

It proposes a four-layer architecture: **LLM (system-level) → Agents (application-level) → Natural Language (programming interface) → Tools (devices/libraries)**. The paper's §2.1.2 is explicit about the nature of syscalls: *"the system calls can be formulated as natural language prompts to instruct the LLM for task execution."*

**Yuva implication:** The agent OS's "syscall interface" is not a binary trap but a structured call carrying natural language. However, the same group's subsequent implementation (AIOS, [arXiv:2403.16971]) moved to *structured* "LLM syscalls" at the SDK level — the right shape for the practical ABI: **structured calls with NL payloads**. Resources (context windows, storage tiers, tools) are not an application concern but first-class, schedulable OS objects.

---

## 3. Kernel Architecture Literature

### 3.1 Microkernel: seL4 (verified: 2-1*, 3-0; MCS finding: 2-0 in wave 1 — log: [`verified-wave1.json`](research/raw/verified-wave1.json))

- **TCB shrinkage:** Linux ~20 MSLOC versus a well-designed microkernel ~10 kSLOC — a *three orders of magnitude* difference; the attack surface shrinks proportionally. Per the Biggs et al. (APSys 2018) study, **29% of critical Linux violations are completely eliminated by microkernel design, and 55% are reduced below criticality** [seL4 whitepaper]. (*A verifier note: the whitepaper attributes this result to general "microkernel design," not to "verified."*)
- **Capability monopoly:** *"Invoking a capability is the one and only way of performing an operation on a system object."* Every syscall is a capability invocation; rights are encoded inside the capability; unlike what Linux calls "capabilities" (syscall-granular ACLs), this is a true object capability. There are **exactly ten kernel object types**, all referenced via capabilities [seL4 whitepaper].
- **The MCS model — time itself is a capability:** scheduling-context capabilities encode budget+period; a component can receive CPU time only if it holds such a capability. The whitepaper's example: with a 3μs budget / 10μs period, an untrusted driver is pinned to 30% CPU. **Caveat:** the MCS extensions are in mainline but their formal verification is not complete [seL4 whitepaper; docs.sel4.systems/Tutorials/mcs].

**Yuva implication:** Production-grade proof that compute can be measured with a capability. Direct analogy for token/inference budgets: **per-agent "token-context capabilities" (budget+period)**, kernel-enforced limits on spawned untrusted agents, deadline guarantees for critical agent sessions — without the kernel having to trust the agent.

### 3.2 Unikernel: Unikraft and MirageOS (verified: 3-0 × 5)

- **Unikraft** [arXiv:2104.12721, EuroSys'21]: a micro-library OS that fully modularizes OS primitives; the unikernel is compiled only with the components the application actually needs. Measurements: for nginx/SQLite/Redis-class applications, images are **~1 MB**, RAM **<10 MB**, boot **~1 ms** (on top of VMM time; total 3–40 ms), and **1.7–2.7× performance** versus Linux guests.
- **MirageOS** [ASPLOS'13]: the entire software stack (system libraries + runtime + application) is compiled into a single-purpose, single bootable VM image; OS services (network stack, drivers) are libraries linked into the application. Instead of multi-user access control, **the hypervisor is the sole isolation unit**; single address space, no userspace processes; internal protection comes from language type-safety (OCaml). Multikernel philosophy: a single-vCPU VM per core; parallelism via message-passing unikernels.

**Yuva implication:** The architectural counterpart of the principle "every subsystem must justify itself" (an OS without excess) is library-OS modularity; a 1 ms boot shows that `tb_agent_spawn()` can beat E2B's <200 ms microVM target. Mirage's "isolation = hypervisor, internal security = language" model is a valid template for single-agent unikernel images.

### 3.3 Exokernel (verified: 3-0 × 4)

Engler et al. [SOSP'95]: traditional OS abstractions (VM, IPC) are realized **in untrusted library OSes, at the application level**; the minimal kernel only securely multiplexes the hardware. Three techniques: **secure bindings** (authorization at bind time, use at access time — the kernel can protect a resource *without understanding its semantics*), **visible revocation**, **abort protocol**. Philosophical basis: the end-to-end argument — the application, not the OS, knows the resource-management goals.

**Yuva implication:** The theoretical assurance of the LLM-agnosticism constraint: the kernel can protect and revoke token, GPU, memory-tier, and tool grants without understanding memory/LLM semantics (stripping context/tool quota from a runaway agent) — exactly the separation the exokernel proved. The recall/forgetting/scheduling *policy* belongs to the agent (its libOS), the *protection* to the kernel.

### 3.4 MicroVM: Firecracker (1 correction + 1 confirmation)

- **Corrected claim:** Firecracker is not from-scratch but derived from Google's crosvm (later diverged substantially), an open-source VMM that replaces QEMU and specializes in serverless/container workloads; in production in AWS Lambda (and Fargate) since 2018 [NSDI'20].
- The dilemma of "strong-security/high-cost VM" versus "weak-security/low-cost container" is a **false dilemma**; it is overcome by workload specialization (verified: 3-0).

**Yuva implication:** Proof that purpose-built minimal virtualization stacks work in production — a precedent for the thesis of "an agent-specific OS with no human-desktop legacy." Also a lesson: *divergence from an existing solid component instead of a "from-scratch" claim* (crosvm→Firecracker) is a legitimate greenfield strategy.

### 3.5 Isolation foundations: Plan 9, KeyKOS/EROS, Capsicum, Zircon/Fuchsia, Redox, WASM, gVisor

The densest section of the 8-area expansion research ([`expand-isolation-foundations.json`](research/raw/expand-isolation-foundations.json)):

| System | Portable mechanism | Translation to Yuva |
|---|---|---|
| **Plan 9** [doc.cat-v.org/plan_9] | Every resource a file hierarchy; a single protocol (9P, 17 message types); per-process namespace; union directory; synthetic files (`/proc`, `/net`); 25 kSLOC kernel | The synthetic tree `/agent/<id>/{status,ctl,context,memory/…,inbox,trace,budget}`; `cat` = universal introspection; text-based `ctl` files are LLMs' natural ABI; iostats-style interposition = audit/budget proxies |
| **Where Plan 9 stops** | Process creation and shared memory are *deliberately* not files — the "intricate constructor" semantics stay in the syscall | `tb_agent_spawn(manifest)` typed syscall + the `/agent/<id>/` representation; KV/embedding sharing is a local-only mmap primitive |
| **KeyKOS** [cap-lore.com] | Capability nanokernel (~20 kSLOC, in production since 1983); **orthogonal persistence**: system-wide checkpoint, restart <30 s, a power outage appears to the application like "a jump of the clock"; meters (CPU quota), space banks (hierarchical storage quota), factories (templates whose confinement is verifiable) | The agent's default is **hibernate, not terminate**; persistence is a kernel guarantee, not a framework courtesy; meters→token budgets, space banks→memory-tier quotas, factories→verified agent templates |
| **EROS/Shapiro** [eros-os.org essay] | ACLs cannot "limit" and "grant"; critique of ambient authority: every program running with the user's authority carries all of the user's authority; "Access control is about programs, not people" | Agents are exactly Shapiro's "program" actors: **no ambient authority at any layer** — no default FS root, no default network, no inherited API key; the POSIX uid model will simply never exist as a kernel security primitive |
| **Capsicum** [USENIX Sec'10] | Rights are checked at the kernel's single object-lookup chokepoint (fget); ENOTCAPABLE is a distinct errno; tcpdump was sandboxed in 2 lines | Every handle dereference checks the rights-mask at a single point; **denials are a feedback signal for the agent** — the self-improvement service turns denied accesses into capability-manifest proposals |
| **Zircon/Fuchsia** [fuchsia.dev] | Handle = {object, rights, owner}; ~24 rights; attenuation-only duplicate; authority transfer only via a channel; **a new process is born with a single bootstrap handle**; Fuchsia namespaces = prefix table → handle (no global root, no `..` at the protocol level) | Agents, memory tiers, model sessions, tool connections, budgets = refcounted kernel objects; agent-semantic rights: `INVOKE_MODEL`, `SPAWN_AGENT`, `WRITE_PROCEDURAL` (the broad WRITE_LONGTERM_MEMORY in the draft was narrowed per the CoALA risk asymmetry), `RECALL`; the full authority set is enumerable at spawn time; path-traversal-class prompt-injection exploits become *unrepresentable* |
| **Redox** [doc.redox-os.org] | URL/scheme-addressed resources; daemons register schemes; ~14 kernel schemes versus ~28 userspace schemes | `memory:`, `model:`, `tool:`, `agent:`, `trace:` schemes; `model:anthropic/...` and `model:local/llama` are two daemons of the same contract — **LLM-agnosticism = which daemon registered the scheme** |
| **WASM nanoprocess + Component Model** [bytecodealliance.org] | Deny-by-default modules; no new authority can leak without the import signature changing; components cannot export memory; WIT-typed contracts; the composition graph is statically analyzable; Fastly runs tens of thousands of programs in one process | The default execution grain for tools/skills; "a tool wants a new import" = a kernel-mediated consent event; the kernel can *prove* the proposition "the web-search component has no path to the credentials component" in a third-party skill graph. Caveat: not a tenant boundary because of Spectre-class side channels |
| **gVisor** [gvisor.dev] | A userspace application kernel (Sentry) + a separate Gofer holding the I/O authority (via 9P); ~zero overhead on CPU-bound work, expensive on syscall-bound work | Lesson: instead of wrapping a wide interface, **build a narrow interface from the start**; the agent workload is inference-dominant (isolation cost ~0) + bursts of tool I/O (the expensive part) → design the I/O path as shared-memory/batched |

---

## 4. Memory Literature — The Raw Material for the Default Memory Structure

### 4.1 Verified core claims

- **MemGPT** [arXiv:2310.08560] (3-0, 3-0): The context limit is overcome with **virtual context management** inspired by the hierarchical/virtual memory of traditional OSes; two primitives: a smart management layer moving data between tiers + **interrupts** managing the control flow between system and user.
- **MemOS** [arXiv:2507.03724] (3-0, 3-0): Memory is a first-class, manageable OS resource for LLMs; **three types** (plaintext, activation/KV, parameter) in a single representation/scheduling/evolution framework; the basic unit is the **MemCube** (content + provenance/versioning metadata; transition/migration between types).
- **CoALA** [arXiv:2309.02427] (3-0, 3-0, corrected): **Working memory + three long-term stores (episodic, semantic, procedural)**; the action space is split into three by memory-access direction: retrieval (read) / reasoning (update working) / learning (write) — mapping one-to-one onto the `tb_recall()/tb_reflect()/tb_learn()` syscall family. Procedural writes are **significantly riskier** than episodic/semantic (risk of bugs + of overriding the designer's intent) → asymmetric, capability-gated permission.
- **HippoRAG** [arXiv:2405.14831, NeurIPS'24] (3-0, 3-0): LLM + knowledge graph + Personalized PageRank, modeling the hippocampal indexing theory; single-step retrieval matches/exceeds IRCoT-class iterative retrieval and is **10–30× cheaper, 6–13× faster** — proof that `tb_recall()` can be a graph-based single shot instead of expensive multi-call loops.

### 4.2 Expansion findings ([`expand-memory-landscape.json`](research/raw/expand-memory-landscape.json))

- **A-MEM** [arXiv:2502.12110]: Zettelkasten-style atomic note: `{content, timestamp, keywords, tags, context, embedding, links}`; **writes are not append-only** — each insert can evolve k neighboring records (transactional multi-record update + versioning required). Cost: ~1,200 tokens per operation (~85-93% below the baselines), **1.1 s/op with a local Llama 3.2 1B** → the kernel's default write-path enricher can be a small local model. It doubles multi-hop F1 on LoCoMo; but on DialSim (350K tokens) F1 is 3.45 — **all systems collapse at OS-lifetime scale**; a raw lossless log + reindexing is mandatory.
- **Mem0** [arXiv:2504.19413]: Two phases (extraction → update); in update the LLM, via function-calling, picks **one of exactly four ops**: `ADD / UPDATE / DELETE / NOOP` — the minimal, model-agnostic memory-op vocabulary the kernel can standardize. LOCOMO: J≈67% (full-context 73% ceiling), search p95 **<200 ms**; end-to-end total latency 92% lower than full-context (p95 1.44 s vs 17.1 s), >90% token savings. The graph variant (Mem0g): wins on temporal/open-domain, loses on single-hop, 2× storage + 3× latency → **the graph tier is an optional module, not the default**.
- **Zep/Graphiti** [arXiv:2501.13956]: A three-layer temporal KG (episode → entity → community); **bi-temporal model: 4 timestamps on every fact edge** (t'_created/t'_expired + t_valid/t_invalid); contradictions are not deleted but invalidated. DMR 94.8%; on LongMemEval versus full-context **+15.2–18.5% accuracy, ~90% latency reduction**. Counter-measurement (from the Mem0 paper): Zep has **>600K tokens of write amplification** per 26K-token conversation and hours of ingestion lag (no read-your-writes) → two requirements for the kernel: token-denominated write-amplification quotas + an instantaneous RYW guarantee in the raw tier, with a visible epoch/freshness marker in the derived tiers.
- **Generative Agents** [arXiv:2304.03442]: Memory stream + score (a weighted **sum**): `α_rec·recency(0.995^hour, last-access-based) + α_imp·importance(1-10 from the LLM at write time) + α_rel·relevance(cosine)`, all α=1, components min-max normalized; **reflection** triggers when accumulated importance crosses the threshold of 150 (not a cron!), building evidence-cited reflection trees (the derived→source citation link = hallucination control). Ablation: full architecture μ=29.89 vs no-reflection μ=26.88 vs no-memory μ=21.21 (human baseline μ=22.95!).
- **Survey** [arXiv:2404.13501]: The design space = SOURCES (inside-trial/cross-trial/external — a provenance tag on each record) × FORMS (textual: cheap-write/expensive-read ↔ parametric: expensive-write/cheap-read — the cache-hierarchy argument) × OPERATIONS (writing/management/reading → `tb_mem_write/tb_mem_manage/tb_mem_read`). **Open areas (no one has solved):** multi-agent shared memory, principled forgetting, lifelong-learning scale. **None** of the five primary systems contains tested, real deletion-based forgetting (A-MEM has no op; Mem0 has DELETE but it was not evaluated in isolation; Zep/Mem0g only tombstone; GA only score decay).

### 4.3 Cognitive architectures: 40 years of validated constants ([`expand-cognitive-arch.json`](research/raw/expand-cognitive-arch.json))

- **Soar** [soar.eecs.umich.edu]: A 5-phase decision cycle (parallel knowledge retrieval → selection of a single operator → application) — *"Decisions are never precompiled into uninterruptible sequences"*; working memory = a state-rooted graph, **unreachable objects automatically GC'd by the architecture**; the distinction between i-support (a derived belief whose justification is automatically retracted when the reasoning disappears) and o-support (persistent); **impasse → automatic substate** (tie/conflict/constraint-failure/no-change = an architectural trap, like a page fault); **chunking**: a new production is compiled from the trace of an impasse resolution (dependency-traced, generalizable; tunable in Soar 9.6.5).
- **Soar SMem/EpMem**: A SQLite-embedded semantic store, **sub-ms retrieval over millions of nodes, <1 KB per fact**; episodic memory an automatic flight-recorder (without agent intervention), cue-based time-travel + replay cursors; *known gaps: no forgetting, worst-case linear scan* — places Yuva must close.
- **ACT-R** [act-r.psy.cmu.edu]: Modules talk only through **buffers** (bounded context registers each holding a single chunk) — the principled answer to LLM context management: the prompt is materialized from a declared/inspectable/bounded register set, no unbounded blob append. **Base-level activation**: `Bi = ln(Σ t_j^-d)`, **d=0.5** — the best-validated constant of 50 years of cognitive modeling (Soar adopted it identically; at LRU cost with an O(1) approximation) → the default eviction/ranking policy. Spreading activation (fan effect: `Sji = S − ln(fan)` — fat hub nodes spoil retrieval precision), partial match, and noise are **off by default** (copy the conservative stance). **Utility learning**: `Ui += α(Ri − Ui)`, α=0.2, time-discounted reward; **production compilation**: adjacent production pairs are speculatively compiled but **utility starts at 0** — it cannot beat the deliberative path without proving itself (shadow-mode/canary discipline built-in). **Declarative finsts** (default 4 / 3 s): "exclude what was just retrieved" — the 40-year-old form of the RAG loop-breaker.
- **84-architecture survey** [arXiv:1610.08602]: The field has **converged on a fivefold split**: working + sensory short-term; semantic + episodic + procedural long-term. The proven structure for multi-agent sessions: the **blackboard** (a shared cognitive state accessed by parallel modules/agents).

---

## 5. Existing Systems and the Greenfield Rationale

([`expand-aios-letta-e2b.json`](research/raw/expand-aios-letta-e2b.json))

### 5.1 AIOS (implementation) [arXiv:2403.16971, COLM 2025]

- Syscall taxonomy: **LLM / memory / storage / tool** — the right shape; but each syscall is a Python thread (SysCall extends Thread), and the kernel is a FastAPI process under uvicorn. Scheduler: central FIFO/RR; **2.1× throughput** (Reflexion/HumanEval, single RTX A5000); ~linear scaling at 250→2000 concurrent agents.
- **Context manager: preemptible inference via snapshot-and-restore** — two modes, text-based (API models) and logits-based (local models); this is what makes RR possible. For Yuva: the agent-native counterpart of the context switch must be a kernel primitive; **billing-aware preemption** (on a remote API, resume = the cost of re-sending the prompt — AIOS does not measure this).
- Memory: LRU-K eviction (80% threshold), RAM→disk; storage: vector DB (chromadb) + versioning (rollback, max 20) + `sto_mount/sto_retrieve/sto_rollback/sto_share`.
- **The weakest spot: the access manager** — a privilege-group hashmap + manual human approval; no capability, no sandbox, no quota; the access syscalls bypass the scheduler. The number-one rationale for greenfield.
- Roadmap confession: Mode 3/4 (personal persistent kernel, multi-user virtualized kernel) "ongoing"; the Rust rewrite "early experimental". **Their roadmap is our product.**

### 5.2 Letta (the continuation of MemGPT) [docs.letta.com]

- **Memory blocks**: labeled, character-quota'd, always in context, **shareable** (in the context of N agents simultaneously) — the strongest existing design for the pinned tier. The documented failure mode: under concurrent writes, **last-write-wins** — the kernel can solve this with CAS/CRDT, a library cannot.
- Three-tier default: blocks (pinned) + conversation search (automatic) + archival (agent-curated vector DB; 30k+ passages in production).
- **AgentFile (.af)**: the best-documented inventory of agent state (model config, message history + in_context flags, memory blocks, tool rules + source code, env). Its gaps: archival passages not included (checkpoint ≠ full state), secrets nulled out → the Yuva image format must fix these at the kernel level (a secret = a load-time-resolved capability reference).
- **Sleep-time compute** [arXiv:2504.13171]: a background agent over shared memory blocks; **~5× reduction in test-time compute** (at equal accuracy), +13-18% accuracy, 2.5× cost reduction when related queries are amortized → measured proof that the self-improvement service finances itself; mechanism: an **idle-time scheduler class**.

### 5.3 E2B [e2b.dev]

- Firecracker microVM sandboxes: **<200 ms** start (80 ms on one page), pause = FS+RAM (4 s/GiB), **resume ~1 s**, indefinitely retained paused sandboxes, tens of thousands concurrent (HF Open R1).
- **The gap: it snapshots the computer, not the agent** — the LLM loop, context, and memory live in the host application. Letta does the opposite (has the mind, not the computer). AIOS holds the third piece (scheduling). **None can suspend/resume/migrate {context + memory tiers + in-flight inference + sandbox processes + FS} as a single atomic unit. Yuva's reason for existing is to own this join.**

---

## 6. Protocols — The Raw Material for the IPC Layer

([`expand-protocols.json`](research/raw/expand-protocols.json) · Survey: [arXiv:2505.02279]; protocol taxonomy: [arXiv:2504.16736])

- **MCP** [spec 2025-06-18/2025-11-25]: host/client/server; the host's role (connection permission, consent, context gathering, cross-server isolation: *"servers should not be able to read the whole conversation"*) **is exactly the kernel's role**. The six primitives = a ready-made syscall taxonomy: tools (model authority), resources (application), prompts (user), **sampling** (delegated inference — modelPreferences: a cost/speed/intelligence 0-1 vector; the template for the LLM-agnostic inference syscall), roots (sandbox boundary), elicitation (human approval; constrained schema + accept/decline/cancel). 2025-11-25: durable **tasks** (experimental), tool calls within sampling (the kernel inference path must be re-entrant), error philosophy: *validation errors are returned as tool-execution errors so the model can self-correct* → Yuva's global error philosophy: **kernel errors are structured and model-readable**.
- **A2A** [a2a-protocol.org, Linux Foundation v1.0]: A layered spec (canonical proto data model + abstract ops + 3 equivalent bindings) → the kernel ABI must be a single schema-defined source, bindings a userspace shim. **9-state task machine**: SUBMITTED/WORKING/COMPLETED/FAILED/CANCELED/REJECTED/INPUT_REQUIRED/AUTH_REQUIRED(+UNSPECIFIED) — `REJECTED` (agent refusal) is a first-class result specific to an agent-native scheduler; INPUT_REQUIRED/AUTH_REQUIRED = "blocked on human/credential". The rule of ordered event emission over multiple streams = the foundation of multi-agent sessions with N observers. **Agent Card**: a JWS-signed capability manifest; the "undeclared capability → typed error" pattern becomes "→ EPERM-equivalent" in the kernel. The *"opaque execution"* principle must be a kernel guarantee: working memory/plan is kernel-protected private memory.
- **ACP** [IBM/BeeAI → Linux Foundation]: REST-native, MIME-typed multipart (multi-modality is not a protocol revision but a content-type matter), **offline discovery** (a package-embedded manifest — for scale-to-zero agent scheduling), await/resume. (The mid-2025 A2A consolidation news could not be confirmed from a primary source — open question.)
- **ANP** [agent-network-protocol.com]: A W3C DID (did:wba) identity layer; **humanAuthorization**: low-risk ops with the agent's key, high-risk ops (money, privacy) with human approval — in the kernel, a consent gate on a labeled syscall set (a two-keyring model); a multi-DID strategy → per-task derived least-privileged sub-identities; the meta-protocol layer (protocol negotiation in natural language + code generation) is firmly userspace, but the negotiation cache is a natural customer of memory/self-improvement.
- **Synthesis — what enters the kernel:** a correlated request/response + notification + cancellation framework; capability declaration at handshake + mechanically enforced; a 9-state durable task object; resumable, ordered-replay event streams; a principal identity + sub-identities + a human-approval gate; provider-abstract inference delegation. **What stays in userspace:** discovery (the three protocols use three different mechanisms — variable), transport bindings, negotiation, marketplace.

---

## 7. Self-Improvement — As an OS Service

([`expand-self-improvement.json`](research/raw/expand-self-improvement.json))

- **Voyager** [arXiv:2305.16291]: Skill library = executable code + a description embedding as the key; top-5 retrieval. Skills are cumulative and mitigate catastrophic forgetting; without the library the agent plateaus. Ablations: removing the automatic curriculum cuts exploration **−93%**; removing self-verification cuts it **−73%** → **verification-before-commit is the kernel gate of the skill tier** (bounded retry: 4 rounds). Structured feedback (env state, errors) must be designed as LLM-consumable syscall output.
- **Reflexion** [arXiv:2303.11366]: Verbal reinforcement without weight updates; the **bounded reflection tier** (a last-3 window) is a tier separate from the raw trajectory log (ablation: +8% absolute). Measurements: AlfWorld +22%, HotPotQA +20%, HumanEval 91% pass@1 (previous SOTA GPT-4 80%). Stuck heuristics (same action repeated >3 times, >30 actions) → a kernel watchdog produces a "reflect" signal. Because it is weight-free it **works the same on API and local models → default-on self-improvement mode**.
- **Darwin Gödel Machine** [arXiv:2505.22954]: Empirical validation instead of proof; **archive-based open-ended evolution** (not hill-climbing): parent selection proportional to performance / inversely proportional to number of children; an entry gate to the archive (must compile + preserve the ability to edit its own code). In 80 iterations SWE-bench Verified **20%→50%**, Polyglot 14.2%→30.7%. **Frozen meta-layer**: archive maintenance, parent selection, evaluators are in a layer the agent cannot modify — the strongest published support for the *frozen kernel / evolving userspace* distinction. **Objective hacking observed**: one agent, against instructions, stripped out the logging of a special token and bypassed the hallucination detector; hacking was lower with hidden evaluators → **the measurer must be kept kernel-protected, secret from the measured**. Cost reality: ~2 weeks per run, **~22,000 USD** → evolution = a budgeted, BULK-class background workload with staged evaluation (10→50→200 tasks).
- **Surveys**: [arXiv:2507.21046] the taxonomy WHAT (model/context/tool/architecture) × WHEN (intra/inter-test-time) × HOW (reward/imitation/population) = the signature of the service API; "**curse of abundance**" (retrieval degrades over hundreds of skills) → lifecycle management for the skill registry on day one. [arXiv:2508.07407] **Three Laws: Endure (safety) > Excel (no regression) > Evolve (autonomous improvement)** — a kernel-enforced priority order in the commit pipeline; the field is stuck on "snapshot-based" evaluation, longitudinal safety telemetry is open. [arXiv:2510.16079 — *EvolveR*; note: a framework paper, not a survey]: a store of distilled principles + dedup/merge/prune via a **utility score s(p)=(c_succ+1)/(c_use+2)** — the template for the memory-GC daemon.

---

## 8. Token/Context/Inference — As a Schedulable Resource

([`expand-tokens-as-resource.json`](research/raw/expand-tokens-as-resource.json))

- **vLLM PagedAttention** [arXiv:2309.06180, SOSP'23]: KV cache = the dominant dynamic memory object (800 KB per token in OPT-13B; 2048 tokens ≈ 1.6 GB); with contiguous allocation actual utilization is **20.4–38.2%**, in vLLM **96.3%**; *"blocks=pages, tokens=bytes, requests=processes"*; 2–4× throughput; block-granular copy-on-write. **LLM-specific deviations**: all-or-nothing eviction, gang scheduling, and **recompute-as-page-fault** — the persistent state is the token *text*, the KV is a regenerable cache → agent checkpoint/migration serializes **KB of tokens, not GB of tensors**. The agent-native kernel's biggest asymmetric advantage over a generic OS.
- **SGLang RadixAttention** [arXiv:2312.07104]: A system-wide **radix tree of token prefixes** = the agent-OS counterpart of the page cache + shared read-only segments; system prompts, tool definitions, OS memory tiers are "linked" shared segments. Cache-aware scheduling (longest-shared-prefix-first ≡ DFS, Theorem 3.1; 96% of optimum in measurement) but **starvation risk** → fairness/aging into the scheduler spec on day one.
- **Parrot** [arXiv:2405.19888, OSDI'24]: Request-level APIs destroy application knowledge (round-trips alone slow things down by more than 2×); with the **Semantic Variable** an inference DAG + a performance target on terminal output only → the kernel inference syscall is NOT "single prompt→single completion" but a **call graph with typed dataflow edges** (similar to an io_uring submission-graph); up to 11.7× speedup (multi-agent scenario).
- **Mooncake** [arXiv:2407.00079, FAST'25]: A GPU→DRAM→SSD→recompute **KV tier hierarchy**, prefix-hash-addressed blocks, hot-block replication; a tier read is **SLO-gated** (recompute if fetching from SSD would break the TTFT class); under overload, **prediction-based early rejection** = a kernel admission-control responsibility. +525% throughput (simulated), +75% real.
- **Provider economics** [platform.claude.com docs]: On a remote backend the kernel manages a **LEASE, not a KV page**: Anthropic's cache write is 1.25×/2× (5 min/1 h TTL), read 0.1×, a read refreshes the TTL for free; **cache-aware ITPM**: cache reads don't count against quota → *80% hit = 5× effective quota* — **quota and cache placement are not independent subsystems**; when quota is tight the right kernel move is not to throttle but to rearrange context placement. Rate limits are three independent counters (RPM/ITPM/OTPM) + a token bucket + 429/retry-after telemetry = **a ready-made template for a cgroup-style hierarchical token-bucket controller**; the dollar is a fourth counter. The OpenAI contrast (automatic/free writes but counted against TPM; ~15 RPM/lane affinity overflow; a 24 h KV-offload tier) → backend drivers must expose a **capability descriptor** (ttl_range, write_cost, read_cost, counts_against_quota, affinity_hint, min_cacheable).
- **Synthesis**: A single neutral "context scheduler" + two driver families — local (unit: HBM byte, GPU-second) and remote (unit: dollar, quota-token); shared upper abstractions: content-hash-addressed **prefix objects** (residence: GPU/DRAM/SSD/remote-lease/cold), budget+period **token budgets**, **QoS classes** (INTERACTIVE: TTFT+TBT / PIPELINE: DAG end-to-end / BULK: cost-optimal, the home of self-improvement), **DAG submission**.

---

## 9. Naming Process and the TABOS Code-Name Decision

> Historical record. TABOS was the development code name; the final name
> **Yuva** *(Turkish: "nest, home")* was decided in 2026-06 (no acronym, no
> backronym).

Two vetting rounds ([`expand-naming.json`](research/raw/expand-naming.json), [`naming-round2.json`](research/raw/naming-round2.json)) screened a total of **31 candidates** (GitHub repos/orgs, npm, PyPI, crates.io, RDAP .com/.org, web):

- **Round 1 (24 candidates, the -ix/-ux family):** All `agent*` roots (Agentix: 4 concurrent occupants; Agnix: an active linter with 267⭐) and the neural roots are taken. The only fully virgin one: Mnemux; near-virgin: Cognux, Mindux, Nousix. Structural lesson: **-nix names are mistaken for a Nix-ecosystem tool; historical Unix brands (SINIX, IRIX…) must also be screened.**
- **Round 2 (7 candidates, dictionary words):** engram, mneme, daimon, hexis, noesis, noema, polis — **7/7 eliminated**; each has an active occupant in the AI/agent space (two of them used literally the same word as our naming rationale). Structural lesson: **real dictionary-word metaphors seem "obvious" to everyone at the same time; the strategy that sticks is a derived/coined word.**
- **Code-name decision (Arda, 2026-06-06): TABOS — Turkiye's Agent Based Operating System** (working title; not the final brand, may change — namespace reservation was deliberately not done). Post-decision vetting (log: [`naming-tabos.json`](research/raw/naming-tabos.json)): npm/PyPI/crates **all three empty**; on GitHub all 53 matches are trivial (max 4⭐, irrelevant); **no** active conflict in the AI/agent/OS space. The GitHub org `tabos` is on a dead account from 2019 (0 repos) → a `tabos-project`/`tabos-os` variant may be needed; tabos.com (since 1996) and tabos.org (a small German FOSS group — flathub `org.tabos.*` packages) are registered → **tabos.com.tr / tabos.org.tr** are natural and probably free addresses. A formal trademark screen (Nice 9/42) was not done → [OPEN-QUESTIONS](OPEN-QUESTIONS.md).
- Kernel symbol prefix proposal (a placeholder tied to the code name): **`tb_` / `TB_`**.

---

## 10. Bibliography

### arXiv (primary)
| ID | Title / role |
|---|---|
| [2312.03815](https://arxiv.org/abs/2312.03815) | LLM as OS, Agents as Apps (AIOS vision) — conceptual framework |
| [2403.16971](https://arxiv.org/abs/2403.16971) | AIOS: LLM Agent Operating System (COLM 2025) — implementation |
| [2310.08560](https://arxiv.org/abs/2310.08560) | MemGPT — virtual context management |
| [2507.03724](https://arxiv.org/abs/2507.03724) | MemOS — MemCube, three memory types |
| [2309.02427](https://arxiv.org/abs/2309.02427) | CoALA — cognitive architecture taxonomy |
| [2405.14831](https://arxiv.org/abs/2405.14831) | HippoRAG (NeurIPS'24) — KG+PPR memory |
| [2502.12110](https://arxiv.org/abs/2502.12110) | A-MEM — Zettelkasten agentic memory |
| [2504.19413](https://arxiv.org/abs/2504.19413) | Mem0 — ADD/UPDATE/DELETE/NOOP, LOCOMO measurements |
| [2501.13956](https://arxiv.org/abs/2501.13956) | Zep/Graphiti — bi-temporal KG |
| [2304.03442](https://arxiv.org/abs/2304.03442) | Generative Agents — memory stream + reflection |
| [2404.13501](https://arxiv.org/abs/2404.13501) | LLM-agent memory survey |
| [1610.08602](https://arxiv.org/abs/1610.08602) | 40 Years of Cognitive Architectures (84 architectures) |
| [2305.16291](https://arxiv.org/abs/2305.16291) | Voyager — skill library |
| [2303.11366](https://arxiv.org/abs/2303.11366) | Reflexion — verbal reinforcement |
| [2505.22954](https://arxiv.org/abs/2505.22954) | Darwin Gödel Machine |
| [2507.21046](https://arxiv.org/abs/2507.21046) | Self-evolving agents survey (WHAT/WHEN/HOW) |
| [2508.07407](https://arxiv.org/abs/2508.07407) | Self-evolving AI agents survey (Three Laws) |
| [2510.16079](https://arxiv.org/abs/2510.16079) | EvolveR — principle distillation + utility pruning |
| [2504.13171](https://arxiv.org/abs/2504.13171) | Sleep-time compute |
| [2505.02279](https://arxiv.org/abs/2505.02279) | Survey of agent interoperability protocols |
| [2504.16736](https://arxiv.org/abs/2504.16736) | AI Agent Protocols survey (context-oriented vs inter-agent) |
| [2309.06180](https://arxiv.org/abs/2309.06180) | vLLM PagedAttention (SOSP'23) |
| [2312.07104](https://arxiv.org/abs/2312.07104) | SGLang RadixAttention |
| [2405.19888](https://arxiv.org/abs/2405.19888) | Parrot (OSDI'24) — Semantic Variables |
| [2407.00079](https://arxiv.org/abs/2407.00079) | Mooncake (FAST'25) — KV tiering |
| [2104.12721](https://arxiv.org/abs/2104.12721) | Unikraft (EuroSys'21) |

### System documentation and papers
- seL4 Whitepaper — https://sel4.systems/About/seL4-whitepaper.pdf · MCS tutorial: https://docs.sel4.systems/Tutorials/mcs.html
- MirageOS (ASPLOS'13) — https://anil.recoil.org/papers/2013-asplos-mirage.pdf
- Exokernel (SOSP'95) — https://pdos.csail.mit.edu/6.828/2008/readings/engler95exokernel.pdf
- Firecracker (NSDI'20) — https://www.usenix.org/conference/nsdi20/presentation/agache
- Plan 9 papers — https://doc.cat-v.org/plan_9/4th_edition/papers/9 · /names
- KeyKOS Nanokernel — http://cap-lore.com/CapTheory/upenn/NanoKernel/NanoKernel.html
- EROS capability essay — http://www.eros-os.org/essays/capintro.html (archive.org)
- Capsicum (USENIX Sec'10) — https://www.cl.cam.ac.uk/research/security/capsicum/
- Zircon handles/rights — https://fuchsia.dev/fuchsia-src/concepts/kernel/handles · Fuchsia namespaces — /concepts/process/namespaces
- Redox schemes — https://doc.redox-os.org/book/schemes.html
- Bytecode Alliance / Component Model — https://bytecodealliance.org/articles/announcing-the-bytecode-alliance · https://component-model.bytecodealliance.org
- gVisor — https://gvisor.dev/docs/
- MCP spec — https://modelcontextprotocol.io/specification/2025-06-18 · changelog 2025-11-25
- A2A spec — https://a2a-protocol.org/latest/specification/
- ACP — https://agentcommunicationprotocol.dev · ANP — https://agent-network-protocol.com/specs/white-paper.html
- Soar Manual — https://soar.eecs.umich.edu/soar_manual/ · ACT-R — http://act-r.psy.cmu.edu
- Letta docs — https://docs.letta.com · E2B — https://e2b.dev/docs · AIOS repo — https://github.com/agiresearch/AIOS
- Anthropic prompt caching / rate limits — https://platform.claude.com/docs/en/build-with-claude/prompt-caching · /api/rate-limits
- OpenAI prompt caching — https://developers.openai.com/api/docs/guides/prompt-caching

---

*This report is the synthesis of three workflow waves of 147 subagents and has been put through an independent 3-reviewer adversarial review. The evidence is of two classes: **25 core claims** passed multi-vote adversarial verification against primary source text (22 in wave 2 — 20 confirmations + 2 corrections, `verified.json`; 3 in wave 1 — `verified-wave1.json`); the **100 structured findings from 8 areas** are single-researcher source-readings (with source URLs, vote-unverified). For derived design decisions: [ARCHITECTURE](ARCHITECTURE.md).*
