---
type: Reference
title: "Yuva Open Questions"
description: "Tracker of 60 open P0-P2 design questions across kernel/security/memory/scheduling/sovereignty specs; several already resolved inline."
tags: ["open-questions", "tracker", "kernel", "sovereignty", "spec-freeze", "decisions"]
timestamp: 2026-06-07T01:48:32+03:00
status: active
diataxis: reference
---

# Yuva Open Questions

> Status: v1.0 · Priority: **P0** = must close before spec freeze · **P1** = before the Phase-1 prototype · **P2** = before the relevant phase starts
> Source: domain-based openQuestions outputs from the three research waves ([`research/raw/`](research/raw/)) + questions arising during document authoring.

---

## A. Architecture / Kernel

| P | Question | Context |
|---|---|---|
| P0 | **Where is the kernel-vs-userspace boundary in local KV management?** Does the kernel itself hold PagedAttention-style block tables, or does it schedule vLLM/SGLang as a userspace engine-server? | All source systems are userspace; nobody has measured the gain/loss of a kernel-resident KV pager |
| ✅ DECISION | **Substrate: guest on a Firecracker/KVM-class VMM, single-vCPU (Mirage), x86_64 LinuxBoot / aarch64 PE-Image.** Not bare-metal; Unikraft's C-TCB was rejected (pure-Rust node image). Detail + executable DoD: [KERNEL-FOUNDATION-SPEC](KERNEL-FOUNDATION-SPEC.md) §0,§2 | Resolved 2026-06-07 |
| P1 | Is the seL4 formal verification approach realistic for our handle layer; the completion status of MCS verification must be tracked | seL4 MCS is still outside proof-coverage |
| P1 | The chattiness of a 9P-style protocol over high-latency links (walk/open/read): a batched/pipelined extension for remote memory tiers and model endpoints, or a LISAfs-style protocol? | gVisor migrated away from 9P |
| P1 | Agent manifest schema: is Fuchsia .cml, OCI runtime spec, or WASI component imports taken as the base, or a new schema? | Plan 9's non-serializable namespace admission + Fuchsia precedent |
| P1 | AIOS's actual syscall catalog (Table 2) must be verified from the `agiresearch/AIOS` source tree — before the `tb_` naming freezes | table embedded as an image in the HTML; open question in the raw data |
| 🎯 GATE | The <50 ms spawn target is bound to the M0/M3 DoD as a **validation-gate** (Hermit pure-Rust unikernel boots on Firecracker — precedent exists); if the measurement falls short, fall back to Firecracker+minimal-guest | [KERNEL-FOUNDATION-SPEC §9](KERNEL-FOUNDATION-SPEC.md) |
| P2 | Multi-node federation: how are scheme/handle namespaces bridged across machines — Plan 9 import, A2A discovery, or capability-passing over a network channel; what replaces 9P auth/attach in inter-kernel security? | Swarm scenario |
| ✅ DECISION | **VMM sovereignty = our own `tb-vmm`** (rust-vmm based, `tb-boot v0` contract); stock Firecracker is only the bootstrap loader. virtio = OASIS open standard (replaceable driver). Detail: [SOVEREIGNTY](SOVEREIGNTY.md) | Resolved 2026-06-07 |
| P2 | When is the bare-metal target (if ever)? Do GPU side-channels require separate isolation? (natural extension after tb-vmm) | Bytecode Alliance Spectre admission; GPU side-channel literature not surveyed |

## B. Capability / Security

| P | Question | Context |
|---|---|---|
| ✅ RESOLVED | **Is the capability attenuation invariant (rights-subset / no-amplification, no-confused-deputy) machine-proven or only boot-tested?** Now MACHINE-PROVEN: Kani harnesses in `crates/tb-caps-core` verify the `Rights` algebra over the full `u32` space, every per-op derivation, an inductive single-step no-widen, and the forged-handle/revoke unforgeability — over the SAME code the kernel runs (zero model drift). CI marker `M11: caps-subset PROVEN`. The deeper *intent*-encoding confused-deputy question (first P0 row) stays open. | Resolved 2026-06-08 · task #38 · [kani.yml](../.github/workflows/kani.yml) |
| P0 | **The binding between LLM-generated text and a kernel handle**: which representation in the tool-call text binds to an unforgeable token; how is confused-deputy (prompt-injection abusing a legitimate capability) constrained — the rights mask bounds the blast-radius but does not encode *intent* | The sharpest question of the isolation research |
| P0 | Capability granularity: can a single hierarchy be designed that losslessly carries MCP feature-level + A2A skill-level + ANP service-level declarations? | Risk of lossy translation in bridges |
| P1 | KeyKOS-style universal persistence × revocation × external (non-transactional) resources: the remote-API/model-session handles in a restored agent's possession did not roll back — what is the contract? | [ARCHITECTURE §8](ARCHITECTURE.md) |
| P1 | Do WASI 0.2/0.3 resource handles now natively provide attenuated re-export (passing authority down the dependency tree while weakening it)? The current status of the 2019 admission | Component Model evolved rapidly |
| P1 | The factory pattern (agent templates with verifiable leak-tightness): by which mechanism is it verified? | The mutually-suspicious collaboration promise leans on this |
| P2 | External protocols with webhooks at NATed/edge endpoints: a kernel-managed relay daemon, or translation to a stream-subscription in the bridge? | A2A push-notification assumption |

## C. Memory

| P | Question | Context |
|---|---|---|
| P0 | **Conflict semantics of multi-agent shared memory**: record-level CAS, or CRDT merge; what consistency model does Soar i-support auto-retraction imply under concurrent writers? | No standard in the literature — greenfield |
| P0 | The place of the graph tier: Zep claims +18.5% on LongMemEval, Mem0 measures that it loses on single/multi-hop and 2-3× cost, A-MEM finds graph DBs rigid — is it in the default, or opt-in? (Current decision: opt-in; to be measured in the prototype) | Conflicting primary sources |
| P1 | Benchmark for the eviction/forgetting default: with what is the score-decayed demotion + tombstone combination measured? An OS-lifetime memory benchmark must be designed (existing ones: DMR is saturated, on DialSim everyone scores F1<4) | [MEMORY-SPEC §8](MEMORY-SPEC.md) |
| P1 | Local small model on the write-path: how much accuracy does a 1B-class enricher/op-decider lose against the frontier on extraction/dedup/importance/op-selection? (A-MEM measured 1.1 s/op, did not measure the accuracy gap) | Default enricher decision |
| P1 | Recalibration of time constants: are human-calibrated constants (d=0.5 over seconds, finst 3 s, decay 0.995/hour) defined in terms of wall-clock, decision-cycle, or token on the LLM-agent timescale? | Cognitive architecture porting |
| P1 | T0 register set: how many registers, what is the token budget per register; a hard cap (ARCADIA 3-6) or a soft activation threshold? | ACT-R 1-chunk human calibration |
| P1 | File system: a semantic+versioned VFS, or a flat object store; merging with T5 archival into a single storage manager (`fs:` scheme contract — Letta/AIOS findings) | [ARCHITECTURE §3](ARCHITECTURE.md) |
| P2 | Writing access metadata (last-k timestamps) on the read path: is relatime-style batching sufficient? | Read-path write traffic |
| P2 | Parametric tier promotion criteria: when is textual→parametric migrated; what are the catastrophic-forgetting guards? | Survey: under-researched |
| P2 | Utility vs activation: two separate ranking planes (skill trust / memory salience), or a single ledger? | ACT-R keeps two separate subsymbolic systems |

## D. Scheduling / Token Economy

| P | Question | Context |
|---|---|---|
| P0 | **Cache-locality × fairness**: SGLang left starvation as future-work; which aging/virtual-runtime mechanism is the default? | The core of the scheduler spec |
| P1 | OTPM reservation: how is the output budget allocated to concurrent agents when output length is unpredictable (Anthropic OTPM counts only what is generated, not max_tokens)? | Over/under-commit dilemma |
| P1 | Lease-renewal economics: a break-even policy function for 5min-touch vs 1hr-TTL according to the idle-time distribution (prices are known, the curve must be derived) | Remote driver policy |
| P1 | Recompute-vs-fetch crossover: prefill speed against tier bandwidth — a default curve requiring per-deployment measurement | Mooncake gives no model |
| P1 | Token budgets as a delegable capability: how do dollars + tokens combine into a single capability type; nested and revocable delegation (generalization of the workspace pattern) | `tb_budget_split` design |
| P2 | Remote DAG loss: while public APIs stay request-level, how much does speculative dispatch/stream-pipelining recover client-side? | Parrot's gain is in self-hosted |
| P2 | Prefix-cache sharing across different trust-domains: timing side-channel ("has another agent seen this prefix") — intra-host isolation policy | No source addresses it |

## E. Self-Improvement

| P | Question | Context |
|---|---|---|
| P0 | **Introspection × hidden-evaluator tension**: where exactly does the boundary run between the kernel state the agent can read and the evaluator set it cannot read? | The agent-native OS transparency promise conflicts with the Goodhart defense |
| P1 | Budget unit and payer of evolution jobs: token, dollar, or wall-clock; in a multi-agent session who gets the bill? (DGM reality: ~22k USD/run) | `tb_evolve_request.budget` |
| P1 | Regression suite of the EXCEL law: how is the per-agent capability test kept current while the agent's task distribution shifts? | The teeth of the merge gate |
| P1 | Skill-compiler provenance granularity in NL reasoning chains: are tool-call/memory-read boundaries sufficient, or is token-level attribution needed? | LLM translation of Soar backtrace |
| P1 | Storage unification: can the DGM archive + Reflexion buffer + Voyager skill lib + EvolveR policy store live on a single tiered substrate with different retention/index policies? (Current design: yes, T2-T4; to be verified) | [MEMORY-SPEC](MEMORY-SPEC.md)×[SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md) |
| P1 | Empirical budget model of sleep-time economics (Letta gives no number: "expensive, diminishing returns") | The cost side of the default-on decision |
| P2 | Longitudinal safety telemetry: which metric set becomes the kernel default for cross-generation drift (Safety Score/Risk Ratio/Leakage Rate class)? | The field is snapshot-based |
| P2 | ANP negotiation-generated adapter code: is passing through the skill sandbox+verification pipeline sufficient? | Userspace-generated code is adjacent to the kernel |

## F. Protocols / Ecosystem

| P | Question | Context |
|---|---|---|
| P1 | Will MCP tasks (SEP-1686, experimental) converge with the A2A 9-state machine? Watch before freezing the kernel task ABI | If the two standards collapse into one shape, the bridge simplifies |
| P1 | ACP's consolidation into A2A (mid-2025 rumors) must be verified from a primary source; if ACP is sunset, offline-discovery + await/resume are internalized directly | Bridge, or native feature |
| P1 | The normative final form of the A2A discovery well-known URI (agent.json → agent-card.json migration) | Discovery daemon spec |
| P2 | Post-survey protocols (AGNTCY, Agora arXiv:2410.11905, AP2/payments): does any introduce a kernel-relevant new primitive? | Periodic scan |
| P2 | AIOS Cerebrum agent-hub mechanics must be read deeply (package/distribution/discovery) — input to the Yuva package manager design | Phase 4 |
| P2 | Independent benchmark of E2B's latency claims (80 ms vs <200 ms) — the bar of success criterion #1 must be fixed by measurement | with the self-host repo |
| P2 | Scope of the .af import converter: which fields carry over losslessly; how are the archival/secret gaps filled? | [AGENTS-SPEC §3](AGENTS-SPEC.md) |

## G. Name / Brand

| P | Question | Context |
|---|---|---|
| P1 | **Formal trademark search (Nice 9/42)** — once the final name is settled, for that name: USPTO/EUIPO/TURKPATENT search; a human/attorney job since it is not bot-accessible | All vettings were at the registry-level |
| P2 | **Final name decision** + (but only after the decision) namespace reservation — **RESOLVED (2026-06): the final name is Yuva** (no acronym; TABOS was the code name). Namespace reservation is now actionable; the half-life of virgin spaces is short (agnix 0→267⭐ in ~1 year), so act fast | Arda (2026-06): "just Yuva" |
| P1 | Full web sweep on big engines (Google/Bing) for the final name — mandatory before announcement (lesson from round 2: registry/Mojeek level is not enough); record: `naming-tabos.json` web column NOT SWEPT | [naming-tabos.json](research/raw/naming-tabos.json) |
| P2 | The risk of confusion with the current owner of tabos.org (German FOSS group, flathub `org.tabos.*`) is low but must be monitored; the RDAP entity lookup of the tabos.com (1996) owner was not done | Naming report |

## I. Language and Verification

| P | Question | Context |
|---|---|---|
| ✅ DECISION | **Kernel verification = pure Rust + tiered-assurance** (Tier0 Miri+coding-guidelines mandatory, Tier1 Kani on every unsafe/parser, Tier2 Verus selective: capability invariants). The seL4-on-top path is NOT in v1; kept as a v3 option if the certification market is entered. asm test-covered (not formal) | Resolved 2026-06-07 · [KERNEL-FOUNDATION-SPEC §8](KERNEL-FOUNDATION-SPEC.md) |
| P1 | Audit of the `no_std` core dependency base — Rust std/core is not yet verified (AWS initiative ongoing, ~7.5k unsafe functions); which minimal crate set will the kernel trust? | AWS verify-std initiative |
| P1 | When does native-Rust inference (candle/mistral.rs) fully replace the C++ engine for single-node/dense models — is a fully-Rust node image possible? | stack-fit finding |
| P2 | Is Ferrocene qualification (ASIL D) really necessary — will the functional-safety/automotive market be entered, or is FLS+consortium-guidelines sufficient? | EU CRA vs ISO 26262 |
| P2 | How does the EU CRA timeline (Sep 2026 reporting, Dec 2027 CE) fit into the Yuva release plan — when is the SBOM/provenance pipeline set up? | Reg. (EU) 2024/2847 |

## H. Process / Methodology

| P | Question | Context |
|---|---|---|
| P1 | **Persona validation**: interviews with real agent developers and operators — [PROCESS §4](PROCESS.md) draft personas/JTBDs were produced at the desk, not validated in the field (Design Thinking Empathize gap) | G0 gate criterion |
| P2 | Success-measure tracking automation: tooling/file layout for gate-based R/Y/G tracking of the VISION §7 measures (SUCCESS-MEASURES.md in Phase 1) | [PROCESS §3.4](PROCESS.md) |

## J. Sovereignty (L1 -> L2 -> bare metal)

| P | Question | Context |
|---|---|---|
| GR | **Full sovereignty = L2 (own minimal Type-1 microhypervisor), not L3.** Split-VMM: a tiny <10K-LOC privileged `tb-core` + an untrusted userspace `tb-vmm`. A hardware IOMMU (VT-d/AMD-Vi/SMMU) is a hard L2 requirement. The GPU/CUDA stack is permanent and quarantined in a confined Linux driver VM (VFIO passthrough), reached via a vsock inference API. RESOLVED — detail: [SOVEREIGNTY-ROADMAP](SOVEREIGNTY-ROADMAP.md) | Resolved 2026-06-07 |
| GR | **`tb-boot v0` is build-ready**: verified `KVM_SET_SREGS` long-mode constants (EFER_LME=0x100/LMA=0x400, CR0_PE=0x1/PG=0x8000_0000, CR4_PAE=0x20) + aarch64 `KVM_ARM_VCPU_INIT`; rust-vmm crate matrix fixed; one console device for MV. RESOLVED | [SOVEREIGNTY-ROADMAP §7](SOVEREIGNTY-ROADMAP.md) |
| P1 | Which silicon ABI first for L2 — Intel VMX vs AMD SVM vs ARM EL2? Surfaces are disjoint; sequence one (ARM EL2 / pKVM-shape is the lightest study). Decided at the first L2 milestone gate | per-arch hypervisor scope |
| P1 | SMP / AP bring-up: M0-M4 are single-core; a Type-1 needs per-pCPU VMXON + per-vCPU VMCS. Not yet designed | type1-x86-vmx gap |
| P1 | VMX-reachability probe: IA32_FEATURE_CONTROL may be BIOS-locked / VMX disabled — need a "can we reach VMX root here?" check before committing to L2 on a box | type1-x86-vmx gap |
| P2 | Bare-metal platform bring-up body: UEFI (uefi-rs) + ACPI (MADT/DMAR/MCFG) + PCIe ECAM + APIC/GIC + SMMU + timer calibration — a large separate work stream | firmware-baremetal gap |
| P2 | Yuva "certified hardware" list: ACS-clean IOMMU groups required for safe device passthrough | driver-gpu gap |

---

**Count (2026-06-07):** Open: P0 ×7 · P1 ×32 · P2 ×21 — total 60. **Resolved decisions:** substrate (Firecracker/single-vCPU/LinuxBoot), kernel-verification (pure-Rust tiered), implementation language (Rust). 1 item turned into a validation-gate (<50 ms spawn). Spec freeze is not declared before the P0s are closed ([VISION §8 Phase 0](VISION.md)).
