# TABOS Architecture Draft

> Status: v1.0 draft — decision items are marked **[DECISION]**, strong recommendations **[PROPOSAL]**, open issues **[OPEN]**.
> Basis: [RESEARCH-REPORT](RESEARCH-REPORT.md) · Related: [VISION](VISION.md) · [MEMORY-SPEC](MEMORY-SPEC.md) · [AGENTS-SPEC](AGENTS-SPEC.md) · [SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md) · [LANGUAGE-AND-STANDARDS](LANGUAGE-AND-STANDARDS.md) · [OPEN-QUESTIONS](OPEN-QUESTIONS.md)

---

## 1. Kernel Approach Comparison and Decision

### 1.1 Candidates (with verified data)

| Approach | Strength | Weakness | Source |
|---|---|---|---|
| **Capability microkernel** (seL4/Zircon class) | TCB ~10 kSLOC (1/1000th of Linux); 29% of critical vulnerabilities vanish, 55% drop below critical; everything is a capability including time/compute; auditing at a single object-lookup point | Inter-service IPC cost; you build the driver/service ecosystem yourself | seL4 whitepaper; Biggs'18; Capsicum |
| **Unikernel / library OS** (Unikraft/Mirage class) | ~1 MB image, <10 MB RAM, ~1 ms boot, 1.7–2.7× perf; only the needed component is compiled (the direct equivalent of the "no-bloat OS" principle); hypervisor = isolation | Single address space — internal protection falls to the language/compiler; no multi-tenant single image | arXiv:2104.12721; ASPLOS'13 |
| **Exokernel** | Protection ↔ management separation is proven (secure bindings, visible revocation, abort protocol); the kernel protects resources without understanding their semantics → LLM-agnosticity theorem | No production ecosystem in pure form; dependent on libOS quality | SOSP'95 |
| **MicroVM substrate** (Firecracker class) | Production-proven (AWS Lambda); tens of thousands of concurrent agent sandboxes at E2B; the VM-vs-container dilemma is a false dilemma | Not a kernel but a substrate — still needs a guest OS on top | NSDI'20; e2b.dev |

### 1.2 **[DECISION] Hybrid: "Capability core + unikernel body + exokernel spirit"**

TABOS layers the three approaches — they are not rivals but answers for different layers:

```
┌─────────────────────────────────────────────────────────────────┐
│  HOST: hypervisor (KVM / Firecracker-class VMM)                 │ ← production-proven substrate
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ TABOS NODE IMAGE (single image booting as a unikernel)     │  │ ← Unikraft-style modular build
│  │  ┌──────────────────────────────────────────────────────┐ │  │
│  │  │ TB-CORE (frozen capability core, target ≤15kSLOC)    │ │  │ ← seL4/Zircon lessons
│  │  │  handle+rights · scheme dispatch · task machine ·     │ │  │
│  │  │  token-budget controller · event streams ·            │ │  │
│  │  │  checkpoint/persistence · held-out evaluator domain   │ │  │
│  │  └──────────────────────────────────────────────────────┘ │  │
│  │  TB-SERVICES (userspace daemons, scheme providers):        │  │ ← Redox lesson: userspace where possible
│  │   memory: · model: · tool: · agent: · trace: · discovery   │  │
│  │  AGENTS: WASM nanoprocess (tool/skill) +                   │  │ ← Bytecode Alliance
│  │   per-agent/per-tenant sub-microVM/unikernel as needed     │  │ ← Mirage model
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

- **The core is a microkernel** because our security claims (no ambient authority, measurer-measured separation, mutually-suspicious agents) require a small, auditable TCB — the numbers support this (three orders of magnitude, 29%/55%).
- **The body is a unikernel** because the "no-bloat OS" principle requires compile-time modularity and our agent spawn target (<50 ms) is achievable with ~1 ms boot images.
- **The spirit is exokernel** because the kernel does *not understand* the agent's memory/model semantics; it only establishes secure bindings, revokes them visibly (including stripping the context/tool quota from a runaway agent), and leaves policy to the agent's libOS (end-to-end argument).
- **The substrate is microVM** because hardware-backed isolation at the tenant boundary is the only trustworthy answer today (WASM side-channel admission; gVisor cost profile).

**[OPEN]** Whether the Phase-1 prototype will be user-mode on top of Linux or a direct Unikraft port ([OPEN-QUESTIONS](OPEN-QUESTIONS.md) §Architecture).

### 1.3 Implementation Language **[DECISION — detail: [LANGUAGE-AND-STANDARDS](LANGUAGE-AND-STANDARDS.md)]**

From the kernel to the protocol bridges, **Rust** (frozen kernel `no_std` + framekernel pattern: all `unsafe` in a small foundation crate, `#![forbid(unsafe_code)]` above it). The rationale is production-proven: Android memory-safety vulnerabilities 76%→24% (2019-2024), Rust in production in the Linux/Windows/AWS kernels, Asterinas's 15 kLOC framekernel TCB. C only in vendored llama.cpp behind a driver daemon; Python/TS only in external SDKs + network-bound inference engines (vLLM/SGLang). The substrate (Firecracker/crosvm) is already Rust. If certification-class kernel verification is needed, the path to building the node image on top of seL4 is open ([OPEN-QUESTIONS §I](OPEN-QUESTIONS.md)).

### 1.4 Kernel Foundation and Assembly **[DECISION — detail: [KERNEL-FOUNDATION-SPEC](KERNEL-FOUNDATION-SPEC.md)]**

The kernel boots as a Firecracker/KVM guest (not bare-metal) → large amounts of boot asm are eliminated. ALL `unsafe`+asm in a single `tb-hal` foundation crate (`#[unsafe(naked)]`+`naked_asm!`/`global_asm!`, Rust ≥1.88); `#![forbid(unsafe_code)]` above it. x86_64 **LinuxBoot** (enters 64-bit, no trampoline), aarch64 **PE-Image** (MMU cold, bring-up required). Single-vCPU (Mirage) → AP/SMP asm not in v1. Assembly work items split into 13 units (A1-A13), the build into 5 milestones (M0 boot → M1 trap → M2 context-switch → M3 MMU → M4 v2-user); each unit has an executable DoD (Firecracker+QEMU CI, both arches). Kernel-verification decision: pure-Rust + tiered-assurance (Miri+Kani mandatory, Verus selective). **Sovereignty:** TABOS inherits zero Linux code/design; canonical boot = our own `tb-boot`/`tb-vmm`, Firecracker is only the bootstrap loader (detail + the 'we don't carry old bugs' ledger: [SOVEREIGNTY](SOVEREIGNTY.md)).

## 2. Kernel Object Model **[PROPOSAL]**

The Zircon template, with agent semantics:

- **Objects** (refcounted, accessible only via handle): `Agent`, `Session`, `Task`, `MemTier`, `MemRecord`, `Block`, `Skill`, `ModelSession`, `ToolConn`, `Budget`, `Stream`, `Namespace`, `Evaluator`(held-out).
- **Handle = {object, rights, owner}**; duplication only by lowering rights (`tb_handle_dup` ⊆ rights); transfer only via channel (an auditable authority-flow graph — the self-improvement service learns least-authority manifests from this graph).
- **Agent-semantic rights** (parallel to READ/WRITE/TRANSFER/DUP): `INVOKE_MODEL`, `SPAWN_AGENT`, `WRITE_PROCEDURAL` (a separate right per CoALA risk asymmetry), `RECALL`, `CONSOLIDATE`, `EMIT_EXTERNAL` (writing to the outside world), `DELEGATE_BUDGET`.
- **Birth protocol [DECISION]**: a new agent starts with a **single bootstrap channel handle** (Zircon model); its manifest's prefix table is translated by the kernel into a handle set — *what is not in the table is unreachable*; the authority set is fully enumerable at spawn time.

## 3. Namespace and Resource Addressing **[PROPOSAL]**

A Plan 9 + Fuchsia + Redox synthesis:

- **No global root** (Fuchsia): each agent's namespace is the prefix→handle table in its manifest. `..` traversal does not exist at the protocol level → the path-traversal class of prompt-injection exploits is not representable.
- **Typed schemes** (Redox): `memory:`, `model:`, `tool:`, `agent:`, `task:`, `fs:`, `trace:`, `budget:`. `model:anthropic/opus` and `model:local/llama` are two provider daemons of the same contract — **LLM-agnosticity = who registered the scheme.**
- **Synthetic introspection tree** (Plan 9): a kernel-served `/agent/<id>/{status,ctl,context,goals,memory/{working,episodic,semantic,procedural},inbox,trace,budget}` for each agent; `status` is single-line fixed-format text, `ctl` accepts text verbs (`pause`, `checkpoint`, `compact-context`, `reflect`). Text = the LLM's natural ABI; `cat` is the universal introspection verb; the supervisor's `ps` is `cat` over a union. Interposition (the iostats pattern) = audit/budget/guardrail proxies splice in without touching the agent.
- **The deliberate limit of the file metaphor** (Plan 9's own lesson): spawn and KV/embedding sharing are not files — `tb_agent_spawn(manifest)` is a typed syscall + a local-only mmap primitive; `/agent/<id>/` is only *representation and control*.
- **Union directories**: the session-scratch memory tier is bound on top of the persistent tier; reads fall through in order — the ergonomics of tiered memory come for free.
- **Storage (`fs:`) [PROPOSAL]**: the file system is natively a *semantic + versioned* VFS — vector index and rollback are at the VFS layer, not bolted on (AIOS builds this in userspace with chromadb+Redis; the `sto_mount(collection)` mount metaphor and LSFS [ICLR'25] are precedents). The T5 archival memory tier and the file store **merge into a single storage manager** (the Letta finding: one manager can serve both file and memory-passage retrieval) — [OPEN: OPEN-QUESTIONS §C].

## 4. Syscall Surface (draft) **[PROPOSAL]**

The AIOS lesson: structural call + NL payload. The MCP lesson: errors return model-readable, suited to self-correction. The Capsicum lesson: all auditing at a single lookup point; denial `TB_ENOTCAPABLE` + leaves a trace (self-improvement feeds on these traces).

```
FAMILY      CALLS (summary)
──────────  ────────────────────────────────────────────────────────────
infer       tb_infer_submit(dag, qos, prefs) → future[]   # Parrot: DAG + target only the terminal output
            tb_infer_cancel(future)                        # MCP cancellation
mem         tb_mem_write(tier, record, policy) / tb_mem_read(query, pipeline)
            tb_mem_manage(op)                              # consolidate/demote/tombstone (see MEMORY-SPEC)
            tb_recall(cue, opts) · tb_reflect() · tb_learn(artifact)   # the CoALA triad
tool        tb_tool_call(conn, wit_typed_args) → typed_result|model_readable_error
agent       tb_agent_spawn(manifest) → handle · tb_agent_fork(h, hints) → handle   # shared-prefix hint (SGLang)
            tb_agent_send(h, msg) · tb_agent_watch(h) → stream
task        tb_task_create/get/cancel/subscribe            # A2A 9-state machine
session     tb_session_create() → h · tb_session_join/leave(h, agent) · tb_session_watch(h) → stream
cap         tb_handle_dup(h, rights_subset) · tb_handle_transfer(chan, h) · tb_handle_replace
budget      tb_budget_split(h, slice) · tb_budget_query    # delegable, hierarchical
consent     tb_consent_request(schema_restricted)          # MCP elicitation: accept/decline/cancel
stream      tb_stream_read(h, from_seq)                    # ordered, with replay (Last-Event-ID pattern)
```

- **`tb_infer_submit` takes a DAG** (not one prompt→one completion): typed dataflow edges, intermediate values flow over kernel channels (Parrot: client round-trips alone lose 2×+; up to 11.7× gain).
- The inference preference vector is the MCP sampling model: `{costPriority, speedPriority, intelligencePriority}` + advisory hint; the **kernel router** binds the concrete backend, not the caller.
- Re-entrancy: the inference path can re-enter tool dispatch (the MCP SEP-1577 direction).

## 5. Scheduling **[PROPOSAL]**

- **Quantum = decision cycle** (Soar): a parallel preparation phase (retrieval, tool results, rule match) → a single serialized commit; preemption and interrupt delivery only at the cycle boundary — the "no uninterruptible sequence ever" guarantee.
- **Impasse traps**: if arbitration produces a tie/conflict/constraint-failure/no-change, the kernel automatically opens a child reasoning context (page-fault analogy); the handler policy is userspace (escalate to a bigger model / ask another agent / return to memory), while detection + substate stack + automatic teardown (GDS) are in the kernel.
- **Arbitration algebra**: the default decision mechanism among competing proposed actions is Soar preference semantics (acceptable/reject/better/worse/require/prohibit); the proposal generators (LLM, rules) are userspace, the algebra is in the kernel.
- **Retrieval pricing**: the ACT-R latency equation `RT = F·e^(−f·A)` is the kernel's cost model — the scheduler can price a memory retrieval *before* dispatching it and decide wait/re-derive/escalate (F, f are per-backend calibration constants).
- **QoS classes (fixed in the ABI)**: `INTERACTIVE` (TTFT+TBT SLO; early rejection under overload — Mooncake), `PIPELINE` (DAG end-to-end target; inner nodes derived — Parrot), `BULK` (cost-optimal; the home of self-improvement; can be deferred indefinitely).
- **Cache-topology-aware dispatch**: runnable steps are nodes in a global prefix tree; within a class prefer DFS/longest-shared-prefix (SGLang Theorem 3.1, 96% of optimum) + **aging/fairness day-one** (the starvation admission).
- **Billing-aware preemption**: preempt freely on a local engine (swap/recompute); on a metered remote API lean toward run-to-completion — the token cost of text-resume is priced (the gap AIOS does not measure).
- **Admission control**: under token pressure, prediction-based early rejection/deferral; turn it away rather than thrash (Mooncake).

## 6. Context Scheduler — Token Resource Management **[PROPOSAL]**

A single neutral layer, two driver families (analogy to the block-layer/driver separation):

| | Local driver (vLLM/SGLang/llama.cpp class) | Remote driver (Anthropic/OpenAI class) |
|---|---|---|
| Unit cost | HBM byte, GPU-second | dollar, quota-token |
| Mechanism | KV block tables (PagedAttention: 96.3% utilization), radix prefix tree, all-or-nothing eviction, gang scheduling, swap-vs-**recompute** | **Lease objects** {prefix-hash, TTL, read=0.1×, write=1.25×/2×}; lease-renewal scheduler; breakpoint placement; affinity key management (~15 RPM/lane) |
| Quota | local pool arbitration (cache-vs-batch) | cgroup-style hierarchical token bucket (RPM/ITPM/OTPM/dollar 4 counters); preventive scheduling with header telemetry instead of 429 |
| Common abstraction | **Prefix object** (content-hash; residence: GPU/DRAM/SSD/lease/cold) · **Budget** (budget+period) · QoS · DAG | same |

- **Quota×cache joint optimization**: at Anthropic, cache reads do not count against ITPM → 80% hit = 5× effective quota; when quota is tight, the kernel's first move is not to throttle but to **re-arrange context placement**.
- **Checkpoint asymmetry**: persistent state is token text; the KV can be recomputed → migration carries KB, not GB.
- Backend drivers publish a **capability descriptor**: `{ttl_range, write_cost, read_cost, counts_against_quota, affinity_hint, min_cacheable_tokens}`.

## 7. Security Model **[DECISION — principles] / [PROPOSAL — mechanisms]**

1. **Zero ambient authority** [DECISION]: no default FS root, no default network, no inherited API key; secrets are capability references resolved at load-time (the correction of the Letta .af lesson).
2. **Single audit chokepoint**: a rights-mask at every handle dereference (the Capsicum fget pattern); denial = `TB_ENOTCAPABLE` + denial trace.
3. **Signed agent manifest** [DECISION]: the A2A Agent Card JWS model — verification at load time; an undeclared capability is mechanical EPERM. Tool manifests are also signed (the survey's tool-poisoning threat); capability grants are **task-scoped and time-limited** (the privilege-persistence threat); tool arguments are kernel-side schema-validated (command injection).
4. **Isolation ladder** [PROPOSAL]: intra-agent tool/skill = WASM nanoprocess (import-signature diff = consent event; static proof of "X has no path to Y" in the component graph); a different principal/tenant = a separate microVM/unikernel (a hardware boundary per the Spectre admission).
5. **Human-approval gate**: ANP humanAuthorization + MCP elicitation — `EMIT_EXTERNAL`-class labeled ops (payment, privacy, irreversible deletion) fall to human approval via a two-keyring model; kernel-enforced, not application courtesy.
6. **Measurer-measured separation**: evaluator/detector objects never appear in the agent's rights mask ([SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md)).
7. **Opaque execution** (A2A): the agent's working memory/plan is kernel-protected private memory; sharing only by explicit grant.

## 8. Persistence **[PROPOSAL]**

The KeyKOS orthogonal-persistence template: system-wide, tunable-interval checkpoint; on restart all agents return exactly at the register/VM level; a power outage = a "clock jump". The E2B cost asymmetry (4 s/GiB to save, ~1 s to return) validates hibernate-default. The agent image = `{manifest, context (token text), memory tier references, handle table, task states, FS delta}` — the kernel-completed form of the .af inventory ([AGENTS-SPEC §3](AGENTS-SPEC.md)). The revocation × restore interaction and external (non-transactional) resource handles are [OPEN].

## 9. IPC and Protocol Layering **[DECISION]**

The kernel speaks a **single canonical, schema-defined ABI** (the a2a.proto pattern); MCP/A2A/ACP/ANP are **userspace bridge daemons** — every protocol arriving from outside terminates at a bridge, and inside a single kernel IPC dialect flows. Kernel primitives: correlated request/response, notification, cancellation, capability-passing channel, ordered-replay stream (same order to N observers — the A2A rule), durable Task. Discovery, negotiation (ANP meta-protocol), transport bindings, and the marketplace are in userspace; the ANP negotiation cache binds to the memory tiers, and generated adapter code binds to the skill registry + sandbox pipeline.

## 10. Frozen Kernel Boundary

The kernel + evaluators + evolution engine (archive maintenance, parent selection) are **outside the scope of agents' self-modification** (the DGM precedent). The agent's default write authority is only its own config subtree; extension is an explicit capability grant. Detail: [SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md).

---

### The verification chain of the decisions in this document
All numeric bases are sourced and vote-verified in [RESEARCH-REPORT](RESEARCH-REPORT.md); the **[PROPOSAL]** items in this document are design inferences derived from that data (they are not themselves additionally verified "facts") and must be tested against prototype measurements.
