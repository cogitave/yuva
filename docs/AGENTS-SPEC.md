# TABOS Agent Specification (Single/Multi-Agent, Scheduling, IPC)

> Status: v1.0 draft — marked **[DECISION] / [PROPOSAL] / [OPEN]**.
> Basis: [RESEARCH-REPORT §5-6-8](RESEARCH-REPORT.md) · Related: [ARCHITECTURE](ARCHITECTURE.md) · [MEMORY-SPEC](MEMORY-SPEC.md) · [SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md)

---

## 1. Agent Process Object **[DECISION]**

TABOS's schedulable, checkpointable, migratable unit:

```
AgentProcess = {
  manifest,            # signed; prefix→handle table; capability declarations
  context,             # T0 register set + token-text canonical state (KV = cache)
  memory,              # tier handles (MEMORY-SPEC; private home automatic)
  inference,           # open ModelSessions, in-flight DAG futures, leases
  sandbox,             # WASM nanoprocesses + (if any) sub-microVM; FS delta
  tasks,               # owned/assumed Task objects (9-state)
  budget,              # token/dollar/CPU budget handles (hierarchical)
  identity,            # principal + derived task-scoped sub-identities (ANP multi-DID)
  handles              # single table of all the above — authority = this table
}
```

**Atomic integrity guarantee**: checkpoint/fork/migrate captures the *entire* structure in a single operation — no torn state between brain/hand (closing the E2B/Letta/AIOS gap, [VISION §2](VISION.md)).

## 2. Lifecycle **[PROPOSAL]**

The A2A 9-state machine is adopted scheduler-native, with two TABOS extensions:

```
SUBMITTED → WORKING ⇄ {INPUT_REQUIRED, AUTH_REQUIRED}   # "blocked on human/credential"
WORKING → {COMPLETED, FAILED, CANCELED, REJECTED}        # REJECTED: agent refusal is first-class
+ HIBERNATED   # default waiting state: not terminate (KeyKOS/E2B; save 4s/GiB, return ~1s)
+ EVOLVING     # fork-modify-validate-merge in the self-modification sandbox (SELF-IMPROVEMENT-SPEC)
```

- Message to a terminal task → typed error (A2A rule).
- `tb_agent_send` supports blocking (until terminal-or-interrupted) and non-blocking (poll/subscribe/webhook-bridge) modes.

## 3. Agent Image Format **[PROPOSAL — ".taf", the kernel-completed version of Letta's .af inventory]**

| Taken from .af | TABOS correction |
|---|---|
| model config, message history + in_context flags, system prompt, memory blocks, tool rules + source + JSON schemas, env | in_context flags belong to the kernel context-manager, not serialized application data |
| — | **All memory tiers included** (including archival): checkpoint = full state |
| secrets nulled | **secret = load-time-resolved capability reference** |
| — | FS delta + task states + budget + handle table included (the entire AgentProcess) |
| — | Signature: manifest JWS (A2A Agent Card model); image = unit of install/fork/suspend/migrate/repro-eval (the ELF+core-dump role) |

.af **import compatibility** is targeted as a cheap ecosystem win [OPEN: converter scope].

## 4. Spawn Protocol **[DECISION]**

1. The caller says `tb_agent_spawn(manifest)`; the manifest signature is verified (kernel/trusted loader).
2. The kernel turns the manifest's **prefix table** into a handle set (Fuchsia namespace transfer); a resource not in the table simply *does not exist* for the agent.
3. The agent is born with a **single bootstrap channel** (Zircon); it requests everything else over that channel — the authority set is enumerable at birth.
4. Budget: a slice from the caller's budget handle via `tb_budget_split` — delegatable, nested, revocable [OPEN: dollar+token composition].
5. Fork variant: `tb_agent_fork` passes the shared prefix to the scheduler as a structural hint (SGLang fork-hint: shared system prompt/tool definitions give free cache hits).
6. Spawn cost target: **<50 ms** (unikernel path ~1 ms boot + image load; below the E2B <200 ms bar).

## 5. Scheduling **[PROPOSAL — detail in ARCHITECTURE §5-6]**

For context summary: quantum = decision cycle (interruption only at cycle boundary); impasse traps automatically create a child-context; QoS `INTERACTIVE/PIPELINE/BULK`; cache-topology-aware dispatch + aging; billing-aware preemption (local freely, metered remote tends to run-to-completion); admission control under token-pressure. Watchdog: repeated-action (>3) and action-count (>30) heuristics produce a `reflect` signal (Reflexion) — the signal is delivered at the cycle boundary.

## 6. IPC and Intra-Session Communication **[DECISION — layering; PROPOSAL — mechanisms]**

- **Single kernel dialect**: correlated request/response + notification + cancellation + capability-passing channel + durable Task + ordered-replay Stream ([ARCHITECTURE §9](ARCHITECTURE.md)).
- **File surface**: agent A reads `cat /agent/B/status`; writes to `/agent/B/inbox` — no new API is invented for coordination (Plan 9). One wanting typed channels opens a channel from the `agent:` scheme.
- **Blackboard**: `memory:session/<sess>` + shared `blocks:` — Letta's "update once, visible everywhere" experience, race-free via kernel CAS/watch. Producer/consumer: the awake agent and the sleep-time-agent share the same blocks.
- **Event fan-out**: N observers on a Task's stream; everyone gets the same events in the same order; one stream breaking does not affect another (A2A rule) — the common observation foundation for supervisors/auditors/peers.
- **External protocols**: MCP (tool/data plane), A2A (peer delegation), ACP (REST/multipart; the offline package-discovery idea is taken into the package), ANP (DID identity; humanAuthorization gate) — all userspace bridges; webhooks are converted to kernel stream subscriptions for NAT'd endpoints [OPEN].

## 7. Identity and Trust **[PROPOSAL]**

- Agent = kernel principal; for each task a **derived, least-privilege, time-bounded sub-identity** (ANP multi-DID strategy).
- Key custody: keyring service; ops tagged `EMIT_EXTERNAL` (payment, privacy, irreversibles) request a signature from a **human-approved second keyring** (humanAuthorization; MCP elicitation accept/decline/cancel — the constrained schema is cheaply verified in the kernel).
- Mutually-suspicious cooperation: thanks to the capability model, "your data × my agent, neither direction leaks" — confinement via verifiable agent templates (KeyKOS factory pattern) [OPEN: verification mechanism].

## 8. Multi-Agent Session **[PROPOSAL]**

The `Session` object = member agent handles + `memory:session` tier + shared blocks + task fan-out streams + a common budget pool (optional oversubscribe, Anthropic workspace pattern). Topology (who messages whom) is a **versioned, evolvable object** — one of the evolution targets of self-improvement (the topology-evolution class of survey 2508.07407). A single-agent session = the special case of |members|=1; there is no separate code path.
