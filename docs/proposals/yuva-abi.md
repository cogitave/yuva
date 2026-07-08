# Yuva↔agent ABI — the versioned, agent-agnostic contract across which a conformant agent speaks to Yuva (the precondition for the `cogitave/agent` extraction, NOT the extraction)

**Status:** **PROPOSAL V1 (research-first; nothing landed). The HOW-they-talk sequel to boot-profiles' WHICH-side-runs (`docs/proposals/boot-profiles.md`, branch `boot-profiles-proposal`), and the second buildable step of the 2026-07-08 operator directive that `cogitave/yuva` (the OS) and `cogitave/agent` (the agent, whose identity is "Cogi") become SEPARATE projects with Yuva AGENT-AGNOSTIC.** · **Pillars:** sovereignty (Yuva hosts ANY conformant agent — or none, per boot-profiles' substrate profile — through a single numbered capability chokepoint and a small versioned wire namespace; the agent is SPECIFIED to run sovereign on yuva-native or degraded on a generic host — the sovereign binding is real today, the degraded binding is `substrate=YUVA-SOVEREIGN-REAL|HOST-DEGRADED-SPEC-ONLY`) + verification (the ABI is FORMALIZED from the existing code, not invented — every seam cited to a landed line; enforcement is a FROZEN-LITERAL registry cross-checked against the live seam constants plus frozen conformance vectors, Kani budget ZERO-OR-ONE) + honesty (the ABI is `abi=IN-REPO-SPEC-AT-STAGE-A`; the version token is `token=DISCOVERY-ONLY-LABEL-NOT-A-GATE` at stage A; the pluggable yuva-native/generic-host RUNTIME backends are `backends=DEFERRED`; the repo split + code move is `extraction=DEFERRED-SEPARATE-MILESTONE`; this proposal is a CONTRACT, never the extraction and never a rewrite). · **Depends on:** the M11 capability dispatch chokepoint (`crates/tb-hal/src/caps.rs` — numbered methods `M_OBJECT_INSPECT=0 … M_MODEL_INVOKE_BYTES=32` `:189-264`, `required_right()` `:268-298`, the generation-checked rights-masked `Handle` algebra, the closed `SysStatus`, and the FUTURE EL0 syscall-gate seam `:240,249`), the M12 AgentProcess hosting socket (`kernel/src/main.rs:1368-1549`, marker `M12: agent OK`), the wire namespace PARTIALLY single-sourced in the brand crate (`crates/brand/src/lib.rs` — `MAGIC_OPFRAME=0x5956`/`MAGIC_OPFRAME_RX=0x5957`/`MAGIC_INFERWIRE=0x5958`, the `DOMSEP_*` labels ALREADY `YUVA-*`; but `ATTEST_MAGIC=0x5959` is NOT here — it lives in `crates/tb-encode/src/attest.rs:53`), the M30 inferwire codec (`crates/tb-encode/src/inferwire.rs` — magic `0x5958`, `INFER_VER=1`, khash echo, `FrameAccum` resync), the M18/M18.1 admission gate (`caps.rs:991 harness_merge`, `:970 carries_approval`, `Rights::APPROVE_HIGH_IMPACT`), the M13-M20 memory seam (`crates/tb-hal/src/mem/mod.rs:1339 recall()`), the M38 conductor spine (`crates/tb-encode/src/conductor.rs` — `Organ`/`Role`/`Verdict`, landed in-kernel `main.rs:5057-5307`), the in-kernel boot-report renderer that STILL names the agent (`kernel/src/bootreport.rs` — `enum View{Cogi,Substrate}`, default `Cogi`, `yuva.view=cogi` `:224`, boot-wire strings `:321,391,394,441`), and the organ-composability position of `docs/research/cogi-cognitive-architecture.md` §2. · **Tasks:** the Yuva-ABI task closes at **stage A** (the in-repo ABI SPEC + the `abi.rs` frozen-literal registry leaf + the frozen conformance-vector skeleton + the discoverable version witness + the bootreport terminology neutralization); stage B (runtime feature-negotiation + version GATING) and the extraction/backends milestones are named successors, explicitly NOT blocked on. · **Markers (the M38/boot-profiles additional-lane discipline):** the CI-required cumulative tail stays `M38: conductor OK turns=N organs=K verdict=ACCEPT` (`scripts/run-x86_64.sh:37`), **byte-untouched**; the ABI's evidence is one new `abi:` witness line (emitted only where it cannot enter the cumulative grep) plus a conformance marker `ABI: conformance OK planes=2 vectors=K` that lives ONLY on a NEW additional lane's summary — the cumulative M0..M38 chain is never displaced, renamed, or reordered.

> **One-line:** The agent and Yuva are ALREADY coupled across two distinct ABI planes that live in the code today — **Plane 1**, an in-process numbered capability-dispatch surface (M11 `caps.rs`, methods `0..32`, rights-masked, zero ambient authority) reached through the M12 agent-hosting socket; and **Plane 2**, a cross-process wire namespace (the M25/M28/M30/M33 frame family, magics `0x5956..0x5959`, of which three are single-sourced in the brand crate and one — `ATTEST_MAGIC=0x5959` — is a standalone literal in `tb-encode/attest.rs`, all four `YUVA-*`-labelled). Yuva is agent-agnostic in the LOAD-BEARING seams — the capability surface and the hosting socket say "agent", with generic `agent-a..d` principals — but it is NOT yet agent-neutral end-to-end: `kernel/src/bootreport.rs` still hardcodes the specific agent name "Cogi" as the default boot-report `View` and emits it on the boot wire (`Cogi is resident`, `Cogi inference deterministic stub`), and "Cogi" also survives in one host-side greeting fixture (`tools/xport-harness/src/live.rs`). What is MISSING is not the seams but their FORMALIZATION: (a) a single-sourced **two-axis version token** (cap-plane SEMVER + wire-plane `u8`) — there is no ABI version constant anywhere in-tree today; (b) a **frozen-literal machine-readable registry** over the method numbers, their `required_right()` mappings, the `Rights` bits, the wire magics, the domain labels, and the organ tags — a DELIBERATE independent copy that a test cross-checks against the live seam constants, so a renumber or a relaxed right FAILS the check (today append-only only BY CONVENTION, enforced by comments); and (c) a **frozen conformance-vector skeleton** that a mock/mini agent passes — the POSITIVE demonstration of agent-agnosticism, the complement of boot-profiles' NEGATIVE substrate census. This proposal ships that formalization as a spec + a `no_std` frozen-literal leaf + a conformance lane. It documents and version-stamps the EXISTING seams; it rewrites nothing and moves no code.

This proposal is the convergent synthesis of three research strands (§15 References), which independently arrived at: the coupling is ALREADY two ABI planes, name-and-version them rather than invent; the four industry precedents (Linux syscall append-only numbers, virtio feature-negotiation, WASI witx→WIT + preview1↔preview2 adapter, Firecracker independent SEMVER); the conformance-vector mini-agent as the positive agent-agnostic demonstration; and the honest `SOVEREIGN|DEGRADED` backend axis. It honors — does not re-litigate — `docs/research/cogi-cognitive-architecture.md` (the substrate = non-parametric retrieval STORE; the organs = composable agent-side capabilities; the novelty is the verified/provenance/sovereign WRAPPER, never a learning paradigm).

---

## 1. Why this milestone, and why these choices

### 1.1 The gap: the seams exist, the contract does not

boot-profiles proves the two layers separate at the **execution/admission level** — it gates the organs off behind `yuva.profile=substrate` and proves by a negative census that they did not run. It explicitly leaves `agent-abi=NOT-DEFINED` (boot-profiles §1.2): the profile gate documents the cut-line but freezes no contract. This proposal is that contract. The distinction is exact and load-bearing:

| Question | Proposal | Token |
|---|---|---|
| WHICH side runs (substrate-alone vs full-agent)? | boot-profiles | `separation=IN-REPO-PROFILE-NOT-EXTRACTION` |
| HOW the two sides talk (the versioned surface)? | **this proposal** | `abi=IN-REPO-SPEC-AT-STAGE-A` |
| WHERE the agent side physically lives (repo split + code move)? | future extraction | `extraction=DEFERRED-SEPARATE-MILESTONE` |

The seams are not hypothetical — they are eight concrete, cited couplings (§2). What is genuinely absent, verified against the working tree (2026-07-08), is any **version token** (`grep -rE 'ABI_VERSION' crates/ kernel/` = 0 hits) and any **machine-readable manifest** of the method-number / rights / wire namespaces. The method table in `caps.rs` is append-only ONLY by convention — `M_MODEL_INVOKE_BYTES=32` is "highest since M31" by a comment, not by a frozen literal a conformance check can cross-read. `token=coupling=SEAMS-EXIST-CONTRACT-DOES-NOT`.

### 1.2 Why now: the spine, not the embryo

The M38 conductor has **landed in-kernel** (`main.rs:5057-5307`; the `M38: conductor OK …` cumulative tail at `run-x86_64.sh:37`) — the organ-scheduler spine is on the boot wire, and every further milestone makes the eventual `cogitave/agent` cut heavier. The directive's discipline is *split the spine, not the embryo*: the M38 conductor is the spine, and the ABI formalizes the seams the conductor and the organs it schedules depend on — the numbered capability surface it invokes organs through, the wire the cross-process organs speak, the admission gate a future external agent docks at, and the `Organ` enum that IS the agent-organ contract. Formalizing the contract now, while the seams are few and cited, is cheaper than after the spine grows further. `token=discipline=SPLIT-THE-SPINE-NOT-THE-EMBRYO`, `spine=M38-CONDUCTOR`.

### 1.3 Why an industry-standard shape — the four precedents, mapped

Formalizing an existing coupling into a versioned contract is a solved problem, and each precedent maps cleanly onto one plane or one axis (`token=shape=INDUSTRY-PRECEDENTED-NOT-INVENTED`):

- **Linux syscall ABI — "don't break userspace", append-only syscall numbers** (kernel.org `Documentation/ABI/stable/syscalls`). Governs **Plane 1**: methods are only ADDED, never removed or renumbered; the append-only registry is the discipline `caps.rs` already follows by convention, made machine-checked by a FROZEN-LITERAL snapshot cross-verified against the live constants (§3.2) — NOT merely a ceiling comment.
- **virtio 1.x feature negotiation + `VIRTIO_F_VERSION_1` legacy detection** (OASIS virtio v1.2/1.3). Governs **Plane 2** forward/back-compat: a device offers features, the driver accepts a subset, unrecognized bits are ignored, and a version bit detects legacy — the model for runtime version-DISCOVERY (stage A) and eventual offer/accept negotiation + GATING (stage B, deferred).
- **WASI witx (preview1 ABI) → WIT worlds (preview2) + the preview1↔preview2 adapter** (Bytecode Alliance wasmtime). The two-plane spec + the dual binding: an IDL-defined interface with an adapter bridging two ABI levels is exactly the `yuva-native SOVEREIGN` vs `generic-host DEGRADED` model (§4).
- **Firecracker's SEMVER snapshot version INDEPENDENT of the binary version** (`firecracker docs/snapshotting/versioning.md`). The **two-axis** discipline: the cap-plane SEMVER and the wire-plane `u8` evolve independently, minor = backward-compatible, major = breaking.

None of these is a rewrite — each is a discipline laid over an existing surface. Yuva adopts the discipline, not new mechanism. `token=precedents=LINUX-SYSCALL/VIRTIO-NEG/WASI-ADAPTER/FIRECRACKER-SEMVER`.

### 1.4 Terminology — agent-neutral in the SEAMS, NOT yet in the boot-report

Corrected against the working tree (this retracts an earlier-draft overclaim): the LOAD-BEARING seams are agent-neutral — the capability surface (`caps.rs`) and the hosting socket (`main.rs` M12) use generic `agent-a..d` principals and say "agent", and "Cogi" does NOT appear in `caps.rs` or in the M12 hosting path. But the kernel is NOT agent-neutral end-to-end:

- **In-kernel, on the boot wire — `kernel/src/bootreport.rs`.** The boot-report renderer hardcodes the specific agent name: `enum View { Cogi, Substrate }` with `Cogi` as the DEFAULT, the cmdline selector `yuva.view=cogi` (default `cogi`, `:224`), and serial strings `"cogi view"` (`:321`), `"Cogi inference deterministic stub"` (`:391,394`), and `"Cogi is resident. Yuva ready (logical surrogate)"` (`:441`). This is a real in-kernel identity coupling, emitted on the boot wire — NOT a lint-only host artifact.
- **Host-side fixture — `tools/xport-harness/src/live.rs`.** The MERHABA greeting fixture where "Cogi" is the semantic content of the greeting (`:364,382,993,1037-1050,1378-1395` — "one short sentence greeting Cogi, the mind"). Historical witness content, not a coupling.

Stage-A terminology work is therefore GENUINE scope, not a cheap tidy: (a) neutralize `bootreport.rs` — rename `View::Cogi`→`View::Agent`, default the selector to the neutral render, and re-word the boot-wire strings to `"agent view"` / `"agent inference deterministic stub"` / `"agent resident. Yuva ready"` (real edits to serial output — see the DoD-5 reconciliation in §7.1); (b) a LANGUAGE-AND-STANDARDS lint banning `Cogi` in `kernel/src` and `crates/` (with a narrowly-scoped allowance for the `live.rs` greeting-fixture region, or the fixture neutralized to `"the resident mind"` — an operator judgment call, §12); (c) this proposal and its docs fan-out use **agent** throughout. The `cogitave/agent` project may be discussed by name; the in-repo neutral term is **agent**, never Cogi. `token=terminology=AGENT-NEUTRAL-IN-CAP+HOSTING-SEAMS/AGENT-NAME-STILL-IN-BOOTREPORT`, `cogi-residue=IN-KERNEL-BOOTREPORT + HOST-GREETING-FIXTURE`.

---

## 2. The SEAM INVENTORY — the eight concrete agent↔Yuva couplings, cited

The coupling is two planes. **Plane 1** is the in-process capability-dispatch ABI (the agent runs as an M12 `AgentProcess` and speaks numbered, rights-masked methods to the kernel). **Plane 2** is the cross-process wire ABI (the agent's organs talk to host-side peers over serial-framed, khash-authenticated frames). Each seam below is stated with its current coupling and whether it is load-bearing ABI surface.

### 2.1 Plane 1 — the in-process capability-dispatch ABI

**Seam 1 — Capability dispatch (M11).** `crates/tb-hal/src/caps.rs`: numbered methods `M_OBJECT_INSPECT=0`, `M_HANDLE_{DUP,NARROW,TRANSFER,REVOKE,CLOSE}=1..5`, `M_AGENT_SPAWN=16`, `M_MODEL_INVOKE=17`, `M_MEM_WRITE_PROC=18`, `M_MEM_RECALL=19`, `M_MEM_CONSOLIDATE=20`, `M_EMIT_EXTERNAL=21`, `M_BUDGET_DELEGATE=22`, `M_MEM_WRITE=23`, `M_MEM_READ=24`, `M_CHAN_{SEND,RECV,CLOSE}=25..27`, `M_BLOCK_{MAP,UNMAP,WRITE,READ}=28..31`, `M_MODEL_INVOKE_BYTES=32` (`:189-264`); `required_right()` maps each to a `Rights` bit (`:268-298`); the closed `SysStatus`; the generation-checked, rights-masked `Handle` algebra. **Coupling:** a CLEAN chokepoint — zero ambient authority, fail-closed. **Leak:** method numbers are ad-hoc-in-`caps.rs`, append-only ONLY by convention, with NO version constant and NO machine-readable manifest; the `required_right()` mapping (the single most safety-critical part of the surface) is likewise unpinned. **Second, structural blocker for EXTRACTION (not for spec):** the surface currently dispatches in-kernel on `&mut HandleTable`; `caps.rs:240,249` explicitly mark the EL0 syscall gate as FUTURE ("the number stays registered for the future EL0 syscall gate that DOES know the agent's space"). The agent runs IN-KERNEL — there is no privilege/trap boundary yet, so a separately-compiled/separately-privileged agent CANNOT bind at stage A. **Load-bearing:** YES — the primary agent↔kernel contract. **Tightening (cheap):** frozen-literal registry snapshot + per-method `required_right()` pin, cross-checked against the live constants (§3.2). `token=plane1=CAPABILITY-DISPATCH-M11`, `plane1-extraction-blocker=EL0-TRAP-GATE-UNBUILT`.

**Seam 2 — Hosting + agent lifecycle (M12).** `kernel/src/main.rs:1368-1549`: `AgentProcess` as a first-class OS entity, born with a memory-home + bootstrap handles, spawned via `M_AGENT_SPAWN` under a manifest of `Rights`; marker `M12: agent OK` (`:1549`). **Coupling:** agent-agnostic in this path — `agent-a..d` are generic principals; "Cogi" does not appear here (it DOES appear in the sibling `bootreport.rs` renderer, §1.4). This is the "agent socket" boot-profiles' substrate mode leaves present-but-empty (boot-profiles §3.2: "Linux has processes with none running; Yuva has an agent socket with no agent admitted"). **Load-bearing:** YES — the manifest-of-`Rights` IS the admission contract; it is the docking point a future external `cogitave/agent` artifact is spawned through. `token=hosting-socket=M12-AGENT-AGNOSTIC-IN-PATH`.

### 2.2 Plane 1 — the admission and operator control seams

**Seam 3 — Capability-admission (M18/M18.1).** `caps.rs:991 harness_merge` + `:970 carries_approval` + `Rights::APPROVE_HIGH_IMPACT`: organs-as-opt-in-capabilities; the human-approval gate that structurally blocks ADMISSION of a high-impact (`EMIT_EXTERNAL`-class) organ unless an approval capability is presented (fail-closed `Denied`, `:999-1011`). Per M38 §3, this gates **admission, not per-step invocation** — the runtime invoke path is the `INVOKE_MODEL` possession gate (`caps.rs:294`, enforced `:649`). **Coupling:** clean, fail-closed. **Load-bearing:** YES — this is the NAMED SEAM through which a future external `cogitave/agent` artifact is admitted; it is the extraction's docking gate (boot-profiles §11 "runtime organ ADMISSION of an external agent via the M18.1 gate"). `token=admission-gate=M18.1-EXTRACTION-DOCKING-POINT`.

**Seam 4 — Operator-command (M28).** `crates/tb-encode/src/opframe_rx.rs`: inbound operator commands, magic `0x5957` (`CMD_MAGIC = brand::MAGIC_OPFRAME_RX`), khash-authenticated with a key-evolution PRF chain (`KDF_DOMAIN = "YUVA-OPCMD-KDF-V1"`, `EVOLVE_DOMAIN = "YUVA-KEY-EVOLVE-V1"`). **Coupling:** a wire-plane sibling to inferwire — a THIRD frame format in the same namespace. **Load-bearing:** for the ABI, it belongs in the wire-magic registry so the namespace is collision-checked as one unit (the brand crate already compile-time-asserts `MAGIC_OPFRAME != MAGIC_OPFRAME_RX != MAGIC_INFERWIRE`, `brand/src/lib.rs:264-266` — but NOT `ATTEST_MAGIC`, see Seam 5). `token=operator-channel=M28-WIRE-SIBLING`.

### 2.3 Plane 2 — the cross-process wire ABI

**Seam 5 — Inference wire (M30).** `crates/tb-encode/src/inferwire.rs`: magic `0x5958` (`INFER_MAGIC = brand::MAGIC_INFERWIRE`), `INFER_VER=1` (`:113`), `ECHO_REQ/RESP/ERR` kinds, `req_id` correlation, challenge/nonce/peer_id/tag, khash echo (label `DOMSEP_M30_ECHO = "YUVA-M30-ECHO-V1"`), `FrameAccum` resync scan (`:646-699`). Cross-process to a host peer over virtio-console / serial-frame. **Coupling:** ALREADY versioned (a per-frame `ver` byte, checked at `:370` and in the `FrameAccum` scan `:654`) and DESIGNED to migrate transports unchanged (M30 §3d) — this is precisely the property that makes a future generic-host binding possible. **Correction to earlier drafts, TWICE over:** (i) the "TABOS-*" domain-label leak is ALREADY CLOSED — the labels are brand-derived and already `YUVA-*` (`brand/src/lib.rs:235-239` compile-time-asserts `DOMSEP_M30_ECHO == b"YUVA-M30-ECHO-V1"`); (ii) the wire-plane is only PARTIALLY single-sourced — `MAGIC_OPFRAME/RX/INFERWIRE` (`0x5956/57/58`) live in brand with a pairwise-disjointness assert, but `ATTEST_MAGIC=0x5959` is a STANDALONE literal `pub const ATTEST_MAGIC: u16 = 0x5959;` in `crates/tb-encode/src/attest.rs:53`, and its disjointness from the brand three is a COMMENT (`attest.rs:50`), not an assert. This reinforces the proposal's premise: the wire namespace is NOT fully single-sourced, and `abi.rs` is the place that unifies it. **Load-bearing:** YES — the canonical Plane-2 codec; the enabler of `HOST-DEGRADED`. `token=plane2=WIRE-INFERWIRE-M30`, `wire-labels=ALREADY-YUVA`, `wire-magics=3-IN-BRAND+ATTEST-STANDALONE-IN-TB-ENCODE`.

**Seam 6 — Inference backend (M31).** `infer.rs` ROUTES + `route::longest_prefix_index`, backend keys `mock`/`local`/`live`; the `M_MODEL_INVOKE_BYTES` byte path through the SAME `INVOKE_MODEL` possession gate (`caps.rs:294/:649`). **Coupling:** the route registry IS the pluggable-backend seam — `yuva-native` (M30 channel) and `generic-host` (deferred) both resolve here; live Anthropic is operator-gated (`real-infer.yml`, dispatch-only). **Load-bearing:** YES — this is where `substrate=YUVA-SOVEREIGN|HOST-DEGRADED` is SELECTED at runtime (§4). `token=backend-select=M31-ROUTE-REGISTRY`.

### 2.4 The memory seam and the spine

**Seam 7 — Memory (M13-M20-M22-M33).** `M_MEM_{WRITE,READ,RECALL,CONSOLIDATE,WRITE_PROC}`; `recall()` BM25+ lexical at `crates/tb-hal/src/mem/mod.rs:1339` (`retrieval=LEXICAL-NOT-SEMANTIC` — no embeddings, no float); M20 `VirtioBlkStore` durable persistence; M22 provenance fold + M33 signed head. **Coupling — the BIGGEST LEAK:** the storage ENGINE (M20) and the memory ORGAN (M13 tiers) COHABIT `crates/tb-hal/src/mem/` UNFACTORED (`mod.rs` ~2,023 + `selftests.rs` ~2,322 lines) — the boot-profiles §3.4 landing-blocker audit. **Consequence for the ABI:** the memory seam is SPEC-ABLE at stage A (the method surface `M_MEM_*` is clean and numbered) but not cleanly CUTTABLE at the code level until `mem/` is factored — a hard blocker SHARED with boot-profiles stage B. **Load-bearing:** YES as spec; DEFERRED as a code cut. `token=memory-seam=SPEC-ABLE-NOT-CUTTABLE`, `mem-engine-organ=UNFACTORED-SHARED-BLOCKER-WITH-BOOT-PROFILES-STAGE-B`.

**Seam 8 — Conductor (M38).** `crates/tb-encode/src/conductor.rs`: `Role{Thinker,Worker,Verifier}`, `Organ{RetrievalOverMemory=0x00, LocalM32=0x01, ExternalMock=0x02}` (a closed `u8` enum with `tag()`/`from_tag`, `:120-169`), `Verdict`, `ConductDecision` folded under `prov::kind::CONDUCT_DECISION`; landed in-kernel `main.rs:5057-5307`; cumulative tail `M38: conductor OK …`. **Coupling:** this is the SPINE. The `Organ` enum IS the enumerated agent-organ contract the ABI must version — organ ids are append-only exactly like syscall numbers (a new organ is a new tag, never a renumber). **Load-bearing:** YES — the contract the whole loop is built on. `token=organ-registry=M38-APPEND-ONLY-TAGS`.

### 2.5 The load-bearing subset, and the two separability blockers

Of the eight, the **capability-dispatch surface (Seam 1)**, the **wire namespace (Seams 4-5)**, the **admission gate (Seam 3)**, and the **organ registry (Seam 8)** are the load-bearing ABI surface — what a conformant agent MUST agree with Yuva on, and what a version bump must protect. The hosting socket (Seam 2) is the container; the backend select (Seam 6) is the `SOVEREIGN|DEGRADED` switch; the memory seam (Seam 7) is spec-able-not-cuttable.

Separability is honest about TWO tight-coupling blockers, not one:

- **Plane-1 privilege blocker (Seam 1):** the capability surface dispatches in-kernel; the EL0 trap gate that would let a separately-privileged agent enter is UNBUILT (`caps.rs:240,249`). So the stage-A mini-agent (§3.4) runs IN-PROCESS in the SAME binary — it proves the surface is CALL-COMPATIBLE by non-resident in-process code, NOT that a separately-compiled/separately-privileged `cogitave/agent` can bind.
- **Memory-cut blocker (Seam 7):** the `mem/` engine↔organ factorization, shared with boot-profiles stage B.

Both are named so extractability is not overclaimed. `token=load-bearing=DISPATCH+WIRE+ADMISSION+ORGAN-REGISTRY`, `separability=EXECUTION-ADMISSION-LEVEL-AT-STAGE-A`, `extraction-blockers=EL0-TRAP-GATE + MEM-FACTORIZATION`.

---

## 3. The ABI FORMALIZATION — a two-plane, two-axis versioned contract

### 3.1 The two version axes (Firecracker's independent-version discipline)

`YUVA_ABI_VERSION` carries TWO INDEPENDENT axes, because the two planes evolve for different reasons:

- **Cap-plane SEMVER** `(major: u16, minor: u16)` — governs Plane 1 (the method-number registry + the `Rights` bit registry + the `required_right()` mapping). MINOR bumps on an append-only method or rights addition (backward-compatible, the Linux-syscall rule); MAJOR bumps only on a breaking change (a renumber, a removed method, or a RELAXED right — all of which the frozen-literal cross-check catches, §3.2). Today's snapshot: `cap_plane = (1, 0)` (methods `0..32`).
- **Wire-plane `u8`** — governs Plane 2 (the frame magics + the per-frame `ver` bytes + the domain labels). Already realized per-frame (`INFER_VER=1`, `OPFRAME_VER`); the axis token is the ceiling over the frame family. Today's snapshot: `wire_plane = 1`.

They move independently: adding a memory method bumps cap-plane minor and leaves wire-plane untouched; a new frame `ver` bumps wire-plane and leaves cap-plane untouched. `token=abi-version=YUVA-ABI-V1`, `versioning=TWO-AXES-INDEPENDENT-PER-FIRECRACKER`.

### 3.2 `crates/tb-encode/src/abi.rs` — the FROZEN-LITERAL registry leaf (the enforcement, made concrete)

A NEW `tb-encode::abi` leaf (`no_std`, `forbid(unsafe_code)`, no-float, zero-alloc, zero-dep beyond `brand` + the existing sibling leaves). **This design deliberately reverses an earlier-draft mistake.** An earlier draft said `abi.rs` would be "single-source BY REFERENCE, never a copy" AND a "drift-detecting equality test" — those two are contradictory: if `abi.rs` merely re-exports `caps.rs`/`brand`/`conductor` constants, then "registry == referenced constants" is a TAUTOLOGY (`M_MODEL_INVOKE_BYTES == M_MODEL_INVOKE_BYTES` is always true) that fails on NOTHING. To actually catch a renumber/relabel/relaxed-right, `abi.rs` MUST hold a **frozen INDEPENDENT literal registry** — a second, hand-committed copy — that a test cross-checks against the LIVE seam constants. The "never a copy" rule is retracted; the copy is the mechanism.

Contents (all LITERALS, not re-exports):

- **`pub const YUVA_ABI_VERSION`** — the two-axis token of §3.1, literal.
- **`FROZEN_METHODS: &[(u32, &str, u32)]`** — a committed literal snapshot of `(method_id, name, required_right_bits)` triples, e.g. `(21, "M_EMIT_EXTERNAL", RIGHT_EMIT_EXTERNAL_BITS)`, `(0, "M_OBJECT_INSPECT", …)`, … `(32, "M_MODEL_INVOKE_BYTES", …)` — written as literal numbers, INCLUDING the `required_right()` bit value for each method (the single most safety-critical part of the surface). This is a deliberate independent copy.
- **`FROZEN_RIGHTS: &[(u32, &str)]`** — the committed bit→name snapshot, literal.
- **`FROZEN_WIRE_MAGICS: &[(u16, &str)]`** — `(0x5956,"MAGIC_OPFRAME")`, `(0x5957,"MAGIC_OPFRAME_RX")`, `(0x5958,"MAGIC_INFERWIRE")`, `(0x5959,"ATTEST_MAGIC")` + the disk/note/boot magics, literal — enumerating the FULL namespace as one unit (note `ATTEST_MAGIC` is sourced from `tb-encode/attest.rs`, NOT brand — `abi.rs` is the first place all four sit in one asserted list).
- **`FROZEN_DOMSEP: &[&str]`** — the domain-label snapshot (already `YUVA-*`), literal.
- **`FROZEN_ORGANS: &[(u8, &str)]`** — `(0x00,"RetrievalOverMemory")`, `(0x01,"LocalM32")`, `(0x02,"ExternalMock")`, literal, append-only.

**The enforcement test (`abi_snapshot.rs`, a unit test — THIS is what fails on a seam violation):**

1. For each `FROZEN_METHODS` row, `assert_eq!(caps::<NAMED_CONST>, frozen_id)` — a renumber of an existing method changes the live constant's value and FAILS. (The live-symbol↔frozen-row mapping is written once, explicitly, in the test.)
2. For each row, `assert_eq!(caps::required_right(frozen_id).bits(), frozen_right_bits)` — a RELAXED right (e.g. `required_right(M_EMIT_EXTERNAL)` weakened from `EMIT_EXTERNAL` to `NONE` at `caps.rs:294`, the single most dangerous seam break) changes the live bits and FAILS. This is the check the earlier ceiling-only assert entirely missed.
3. `assert_eq!(*FROZEN_METHODS.iter().map(id).max(), 32)` — the append-only ceiling (catches an addition-past-ceiling without a version bump).
4. Wire-magic disjointness over ALL FOUR magics (extending the brand assert, which covers only three), and label/organ equality against the live `brand`/`conductor`/`attest` constants.

So `abi.rs` is a FROZEN LITERAL manifest, and `abi_snapshot.rs` is a genuine drift detector, not a tautology. `token=abi-leaf=FROZEN-LITERAL-SNAPSHOT`, `registry=CROSSCHECKED-VS-LIVE-INCLUDING-REQUIRED-RIGHT`, `enforcement=RENUMBER+RELAX-RIGHT+CEILING-ALL-CAUGHT`.

### 3.3 Runtime DISCOVERY — the `abi:` witness + `M_OBJECT_INSPECT` (a LABEL, not a GATE)

For an agent to eventually DEGRADE (the virtio-feature-negotiation / WASI-adapter pattern), it must discover the host ABI version at runtime. Stage A ships DISCOVERY only, over two zero-risk surfaces:

- **A boot witness line** `abi: cap-plane=1.0 wire-plane=1 methods=0x21 rights=0x<hex> magics=0x5956..0x5959 organs=0x3 planes=2 negotiation=NONE-AT-STAGE-A` — emitted at a stream position that CANNOT enter the cumulative grep (the boot-profiles §2.5 / real-infer summary discipline).
- **`M_OBJECT_INSPECT=0` on the root capability** wired to REPORT `YUVA_ABI_VERSION` — the id-0 inspect verb, reporting the version an agent reads before binding.

**Honest scope of the token at stage A:** this is a discoverable version **LABEL**, not a version **GATE**. Nothing at stage A CONSUMES the token to reject a mismatched agent — there is only one version and no rejection path. A version cannot "gate" until there is an offer/accept + reject mechanism, which is stage B. The title/pillars are tensed accordingly. `token=discovery=INSPECT-ROOT+ABI-WITNESS`, `version-token=DISCOVERY-ONLY-LABEL-NOT-A-GATE`, `negotiation=SPEC-ONLY-AT-STAGE-A`.

### 3.4 The conformance-vector discipline — FROZEN vectors that FAIL on a seam violation

boot-profiles demonstrates agent-agnosticism NEGATIVELY (a census that the organs did not run in substrate). The ABI demonstrates it POSITIVELY: a conformant agent that is NOT the resident agent passes the contract's vectors. **The vectors MUST be FROZEN literals, not recomputed at test time** — a "golden vector" produced by calling the same encode/dispatch path during the test is a round-trip identity assertion that catches ZERO drift. Stage A ships the SKELETON, frozen:

- **A golden-vector file** (a committed, hex-only, deterministic corpus) in three families, each with PINNED expected outputs as literals:
  1. **Capability-dispatch vectors** — `(manifest, method, args) → SysStatus`, with the expected `SysStatus` pinned as a committed literal. INCLUDING NEGATIVE vectors: a manifest LACKING `EMIT_EXTERNAL` invoking `M_EMIT_EXTERNAL` MUST expect `Denied` as a frozen literal — so a relaxed admission that returns `Ok` FAILS the lane rather than passing silently. This family is the ONLY mechanism in the proposal that fails on a live-dispatch seam break at runtime (complementing the compile/unit-level §3.2 snapshot); it is therefore specified as frozen-literal, positive+negative pairs.
  2. **Wire-codec vectors** — `frame → canon bytes + echo tag`, reusing the landed inferwire encode/verify and the pinned-vector (#49) literal idiom (`inferwire.rs:1616,1685`).
  3. **Conductor-invariant vectors** — `transcript → head / turns / verdict`, pinned against the landed `conductor` fold.
- **A MINI/MOCK conformant agent** (~200 lines, deliberately SMALLER than the resident agent, sharing NO code with it) that binds to Yuva through Plane 1 + Plane 2 and passes the frozen vectors. **Honest ceiling:** because the EL0 trap gate is unbuilt (§2.5), this mini-agent runs IN-PROCESS in the SAME binary. A passing mini-agent DEMONSTRATES the surface is SPEAKABLE by non-resident in-process code — NOT that a separately-compiled/separately-privileged agent can bind, and NOT that the resident agent is cleanly extractable. `token=agent-agnostic=DEMONSTRATED-BY-MINI-AGENT-SKELETON`, `conformance=VECTOR-SKELETON-NOT-EXHAUSTIVE`, `conformance-ceiling=SPEAKABILITY-BY-IN-PROCESS-CODE-NOT-EXTRACTABILITY`.

---

## 4. The agent-Yuva-optional story — `substrate=YUVA-SOVEREIGN-REAL|HOST-DEGRADED-SPEC-ONLY`

The directive's Jarvis vision: the agent is Yuva-OPTIONAL — sovereign on yuva-native, degraded on a generic host. The ABI makes this a documented axis, not a promise, by leaning on M30's transport-migration-unchanged property (Seam 5). Tensed honestly — the degraded runtime is NOT built at stage A:

| Binding | Transport | Guarantees | Status |
|---|---|---|---|
| **YUVA-SOVEREIGN** (yuva-native) | M11 caps in-process + M30 serial-frame cross-process, khash-authenticated | full: capability confinement, provenance fold, signed head, verified policy | REAL TODAY (M11 + M30 landed) |
| **HOST-DEGRADED** (generic-host) | the SAME ABI schemas over a POSIX unix-socket/stdio transport | sovereign guarantees ABSENT (no capability kernel, no verified fold); the agent WOULD run, degraded | `backends=DEFERRED` — stage A specifies ONLY schema symmetry, builds NO runtime |

Stage A does NOT build the degraded runtime. It specifies the SCHEMA SYMMETRY that makes it possible: the same method registry, the same frame canon, the same organ tags, reachable over a different transport — exactly the property M30 was designed for ("migrate transports unchanged"). The WASI preview1↔preview2 adapter is the precedent: one IDL, two ABI-level bindings, an adapter between. `token=substrate=YUVA-SOVEREIGN-REAL|HOST-DEGRADED-SPEC-ONLY`, `sovereign-binding=REAL-TODAY`, `degraded-binding=SCHEMA-SYMMETRY-ONLY-BACKENDS-DEFERRED`.

Honest ceiling: the degraded path is where the sovereignty pillar is SURRENDERED by construction — a generic host offers no capability confinement and no verified fold. Stage A names this so the Jarvis story cannot be mistaken for a sovereign one. `token=degraded-sovereignty=SURRENDERED-BY-CONSTRUCTION-NAMED`.

---

## 5. HONEST SCOPE — what stage A is, and the six things it is NOT

**Stage A IS:** (1) the in-repo ABI SPEC (this document, promoted to `docs/spec/yuva-abi-v1.md` at landing) enumerating the two planes, the eight seams, the message schemas (already concrete in `caps.rs` + `inferwire.rs` + `conductor.rs`), the two version axes, the conformance discipline, and the `SOVEREIGN|DEGRADED` axis; (2) `crates/tb-encode/src/abi.rs` — the FROZEN-LITERAL registry leaf + `abi_snapshot.rs` cross-check (§3.2); (3) the discoverable `abi:` witness + `M_OBJECT_INSPECT` version LABEL (§3.3); (4) the FROZEN conformance-vector skeleton + the mini-agent + a NEW additional CI lane (§7); (5) the GENUINE terminology neutralization of `bootreport.rs` + the `Cogi` lint (§1.4, §7.1). `token=abi=IN-REPO-SPEC-AT-STAGE-A`, `seams=FORMALIZED-NOT-REWRITTEN`.

**Stage A is NOT (each named so it cannot creep in):**

- **NOT the extraction.** The `cogitave/agent` repo split + moving the agent's portable core out is `extraction=DEFERRED-SEPARATE-MILESTONE`. The ABI is its PRECONDITION, not its execution.
- **NOT a rewrite.** It documents and version-stamps the EXISTING seams; `abi.rs` is a frozen literal copy that CROSS-CHECKS the landed lines, changing no seam's behavior. `token=this-proposal=CONTRACT-NOT-REWRITE`.
- **NOT the pluggable backends.** The `yuva-native SOVEREIGN` binding is real; the `generic-host DEGRADED` RUNTIME is `backends=DEFERRED` (§4) — stage A specifies only schema symmetry.
- **NOT a clean code cut of the seams.** TWO blockers: `mem-engine-organ=UNFACTORED-SHARED-BLOCKER-WITH-BOOT-PROFILES-STAGE-B` (the memory ABI is spec-able but not cuttable until `mem/` is factored) AND `plane1-extraction-blocker=EL0-TRAP-GATE-UNBUILT` (a separately-privileged agent cannot bind until the EL0 syscall gate exists). Separability stays `separability=EXECUTION-ADMISSION-LEVEL-AT-STAGE-A`.
- **NOT runtime feature-negotiation or version GATING.** `negotiation=SPEC-ONLY-AT-STAGE-A`, `version-token=DISCOVERY-ONLY-LABEL-NOT-A-GATE` — discovery via the version token only; offer/accept + reject bitsets are deferred.
- **NOT a signed ABI attestation.** The frozen registry is keyless/tamper-evident (a committed literal snapshot + cross-check); a signed ABI-version attestation is the M33 successor, `abi-attestation=UNSIGNED-KEYLESS`, `sec=ASSUMED-FROM-LITERATURE`.

---

## 6. Honest tokens (the complete vocabulary)

- `abi=IN-REPO-SPEC-AT-STAGE-A`, `abi-version=YUVA-ABI-V1` (`cap_plane=(1,0)` SEMVER + `wire_plane=1` `u8`, independent per Firecracker).
- `plane1=CAPABILITY-DISPATCH-M11` / `plane2=WIRE-INFERWIRE-M30`; `hosting-socket=M12-AGENT-AGNOSTIC-IN-PATH`.
- `versioning=APPEND-ONLY-METHOD-REGISTRY(Linux-syscall) + WIRE-VER-BYTE+FEATURE-DISCOVERY(virtio)`.
- `abi-leaf=FROZEN-LITERAL-SNAPSHOT`, `registry=CROSSCHECKED-VS-LIVE-INCLUDING-REQUIRED-RIGHT`, `enforcement=RENUMBER+RELAX-RIGHT+CEILING-ALL-CAUGHT` (NOT a by-reference tautology; NOT a ceiling-only comment).
- `seams=FORMALIZED-NOT-REWRITTEN`, `this-proposal=CONTRACT-NOT-EXTRACTION-NOT-REWRITE`.
- `agent-agnostic=HOSTING-SOCKET-EMPTY-IN-SUBSTRATE / DEMONSTRATED-BY-MINI-AGENT-SKELETON`; `conformance=VECTOR-SKELETON-NOT-EXHAUSTIVE`; `conformance-ceiling=SPEAKABILITY-BY-IN-PROCESS-CODE-NOT-EXTRACTABILITY`.
- `substrate=YUVA-SOVEREIGN-REAL|HOST-DEGRADED-SPEC-ONLY` (degraded runtime = `backends=DEFERRED`; only schema symmetry specified; `degraded-sovereignty=SURRENDERED-BY-CONSTRUCTION-NAMED`).
- `extraction=DEFERRED-SEPARATE-MILESTONE`; `separability=EXECUTION-ADMISSION-LEVEL-AT-STAGE-A`; `extraction-blockers=EL0-TRAP-GATE + MEM-FACTORIZATION`.
- `mem-engine-organ=UNFACTORED-SHARED-BLOCKER-WITH-BOOT-PROFILES-STAGE-B`; `memory-seam=SPEC-ABLE-NOT-CUTTABLE`; `plane1-extraction-blocker=EL0-TRAP-GATE-UNBUILT`.
- `negotiation=SPEC-ONLY-AT-STAGE-A`; `discovery=INSPECT-ROOT+ABI-WITNESS`; `version-token=DISCOVERY-ONLY-LABEL-NOT-A-GATE`.
- `kani-budget=ZERO-OR-ONE-VECTOR-HARNESS` (registry cross-check = a committed-snapshot unit test).
- `marker-chain=INTACT` / `abi-marker=ADDITIONAL-LANE-SUMMARY-ONLY` (no cumulative-chain displacement, the M38/boot-profiles discipline).
- `terminology=AGENT-NEUTRAL-IN-CAP+HOSTING-SEAMS/AGENT-NAME-STILL-IN-BOOTREPORT`; `cogi-residue=IN-KERNEL-BOOTREPORT + HOST-GREETING-FIXTURE`; `bootreport-neutralization=GENUINE-STAGE-A-KERNEL-WORK-NOT-LINT-ONLY`.
- `wire-labels=ALREADY-YUVA` (the TABOS leak is CLOSED); `wire-magics=3-IN-BRAND+ATTEST-STANDALONE-IN-TB-ENCODE` (namespace NOT fully single-sourced — `abi.rs` unifies it).
- `abi-attestation=UNSIGNED-KEYLESS` (`sec=ASSUMED-FROM-LITERATURE`; signed = M33 successor).
- `discipline=SPLIT-THE-SPINE-NOT-THE-EMBRYO`; `spine=M38-CONDUCTOR`; `role=PRECONDITION-FOR-EXTRACTION-NOT-THE-EXTRACTION`.

---

## 7. ZERO CI regression — a spec + one additional conformance lane

### 7.1 The invariant: the cumulative chain is byte-untouched (and the bootreport reconciliation)

Nothing executable in the required cumulative chain moves. `abi.rs` is a new frozen-literal leaf that no required boot path depends on for a marker; the `abi:` witness and `M_OBJECT_INSPECT` version LABEL are additive and stream-positioned OUTSIDE every cumulative grep. The cumulative tail stays `M38: conductor OK turns=N organs=K verdict=ACCEPT` (`run-x86_64.sh:37`), byte-identical, on both arches. The three required verifier scripts change by ZERO lines (the boot-profiles §8.1 / aL2.4b §2.6 discipline).

**Explicit reconciliation with the `bootreport.rs` neutralization (§1.4).** Renaming `View::Cogi` and re-wording the `"Cogi is resident"` / `"Cogi inference deterministic stub"` boot-wire strings DOES edit serial output — so DoD-5 requires a NAMED verification step at landing: confirm that the required cumulative markers (the `M0..M38` chain: `M12: agent OK`, `M38: conductor OK …`, etc.) do NOT include any `bootreport.rs` view string, i.e. no required grep asserts `"Cogi …"`. On the working tree the required markers are the milestone `Mnn: … OK` lines, NOT the bootreport view render, so the neutralization is expected to be byte-safe for the cumulative chain — but this is VERIFIED at landing, not assumed, and is an operator/verification checkpoint (§12). `token=cumulative-chain=BYTE-UNTOUCHED`, `bootreport-edit=SERIAL-OUTPUT-CHANGED-BUT-OUTSIDE-REQUIRED-GREP-VERIFIED-AT-LANDING`.

### 7.2 The additional conformance lane

A NEW `abi-conformance.yml` job (QEMU/TCG or host-native, offline, deterministic — no network, no human, no hardware): builds the mini-agent, runs it against the FROZEN golden vectors (positive AND negative), asserts all pass, and emits `ABI: conformance OK planes=2 vectors=K` on the lane's SUMMARY only (structurally outside every guest-serial grep — it CANNOT enter the cumulative chain even by accident, the real-infer/M38-stage-A summary-marker precedent). A skip-form or a single-plane pass FAILS the lane by name (honest-skip-is-failure). `token=abi-marker=ADDITIONAL-LANE-SUMMARY-ONLY`, `lane=OFFLINE-DETERMINISTIC-AUTONOMOUS`.

### 7.3 Kani budget: ZERO-OR-ONE

The method/rights/`required_right`/magic/organ registry cross-check is a UNIT test (`abi_snapshot.rs`: frozen literals vs live constants + the append-only-ceiling assert) — not a Kani harness. AT MOST ONE canon-vector harness may be added, reusing the pinned-vector (#49) shape over the inferwire/conductor canon already proven — so `EXPECTED_HARNESSES_TOTAL=122` (the pin at `scripts/kani-shards.sh`) moves 0 or +1 in lockstep, re-measured at landing, never guessed (the M32 §17.6 lesson). The wire/conductor leaves keep their existing harnesses workspace-wide regardless of `abi.rs`. `token=kani-budget=ZERO-OR-ONE-VECTOR-HARNESS`, `harness-pin=+0-OR-+1-LOCKSTEP-REMEASURED`.

---

## 8. DoD — committed proof obligations

- **DoD-1 — the ABI SPEC.** `docs/spec/yuva-abi-v1.md` enumerating the two planes, the eight seams (§2), the schemas, the two version axes, the conformance discipline, the `SOVEREIGN|DEGRADED` axis, and BOTH separability blockers. `token=dod1=SPEC-DOCUMENT`.
- **DoD-2 — the frozen-literal leaf + cross-check.** `crates/tb-encode/src/abi.rs` compiles `no_std`/`forbid(unsafe)`/no-float and holds the FROZEN independent literal registry; `abi_snapshot.rs` asserts each frozen `(id, name, required_right_bits)` triple against the LIVE `caps.rs` constant AND its `required_right()` bits, plus the wire-magic/label/organ cross-checks and the append-only ceiling — so a renumber, a relaxed right, or an addition-past-ceiling FAILS the test. `token=dod2=FROZEN-SNAPSHOT-CROSSCHECK-CATCHES-RENUMBER-AND-RELAXED-RIGHT`.
- **DoD-3 — runtime discovery (LABEL).** The `abi:` witness line is emitted (outside the cumulative grep) and `M_OBJECT_INSPECT=0` on the root capability reports `YUVA_ABI_VERSION`, asserted by a boot check. Discovery-only; no rejection path at stage A. `token=dod3=VERSION-DISCOVERABLE-LABEL-NOT-GATE`.
- **DoD-4 — conformance skeleton (FROZEN).** The golden-vector file (three families, PINNED expected outputs, INCLUDING negative capability-dispatch vectors expecting `Denied`) + the mini-agent + the `abi-conformance.yml` additional lane green; the mini-agent passes; `ABI: conformance OK` on the lane summary only; a relaxed admission that returns `Ok` on a negative vector FAILS the lane. `token=dod4=MINI-AGENT-PASSES-FROZEN-POS+NEG-VECTORS`.
- **DoD-5 — zero CI regression + bootreport reconciliation.** The cumulative M0..M38 chain byte-identical on both arches; the three required verifiers change zero lines; the harness pin moves +0/+1 lockstep, re-measured; and it is VERIFIED that the `bootreport.rs` neutralization touches no required grep (§7.1). `token=dod5=CUMULATIVE-CHAIN-BYTE-UNTOUCHED-BOOTREPORT-VERIFIED-OUTSIDE-GREP`.
- **DoD-6 — terminology (GENUINE kernel work).** `bootreport.rs` neutralized (`View::Cogi`→`View::Agent`, default selector neutral, boot-wire strings re-worded) + the `Cogi` lint over `kernel/src` + `crates/` (with the `live.rs` greeting-fixture decision recorded); the docs fan-out uses **agent** throughout. Scoped as real stage-A work, NOT lint-only. `token=dod6=BOOTREPORT-NEUTRALIZED+COGI-LINT+AGENT-NEUTRAL-DOCS`.

Evidence is these committed tests + the spec, honestly NOT (beyond the one optional harness) Kani proofs. `token=evidence=FROZEN-SNAPSHOT-TESTS+CONFORMANCE-LANE-NOT-KANI`.

---

## 9. Relationship to boot-profiles + the split-the-spine discipline

boot-profiles and Yuva-ABI are siblings that compose without overlap:

- **boot-profiles decides WHICH side runs.** `yuva.profile=substrate|agent` gates the organs off (substrate) or on (agent). Its agent-agnostic proof is NEGATIVE (a census that organs did not run).
- **Yuva-ABI decides HOW the two sides talk.** The versioned two-plane contract. Its agent-agnostic demonstration is POSITIVE (a mini-agent passes the frozen vectors). The two are complements: boot-profiles proves the organs CAN be absent; the ABI demonstrates ANY conformant agent can be present (as in-process code, at stage A).
- **The future extraction MOVES the agent side.** It physically splits `cogitave/agent` out — enabled by BOTH siblings (boot-profiles' execution-level separability + the ABI's frozen contract) and BLOCKED by BOTH shared/named blockers (the `mem/` factorization AND the EL0 trap gate).

Shared seams, non-conflicting: both name the M12 hosting socket (Seam 2) and the M18.1 admission gate (Seam 3) — boot-profiles as "present-but-empty in substrate", the ABI as "the docking point a conformant agent binds through". Shared blocker: the `mem/` engine-organ factorization (boot-profiles §3.4 / stage B; this proposal's Seam 7). The split-the-spine discipline governs both: the M38 conductor is the spine (landed, on the cumulative tail); boot-profiles gates the spine's organs, the ABI versions the spine's seams — neither touches the embryo (the resident agent's portable core), which the extraction moves later. `token=siblings=PROFILES-WHICH-SIDE / ABI-HOW-THEY-TALK / EXTRACTION-MOVES-AGENT-SIDE`.

---

## 10. Honest caveats (conceded — encoded as tokens)

- **The ABI is a SPEC + a frozen-literal snapshot leaf, enforced by a cross-check test — not a semantically-complete freeze.** The `abi_snapshot.rs` cross-check catches a renumber, a relaxed `required_right()`, and an addition-past-ceiling; it does NOT catch every possible semantic break (e.g. a behavioral change to a method that keeps its number and right). A determined in-repo change could still alter behavior beneath a stable signature. `token=freeze=CROSSCHECK-CATCHES-SIGNATURE-BREAKS-NOT-ALL-SEMANTICS`.
- **The mini-agent demonstrates the contract is SPEAKABLE by a non-resident IN-PROCESS agent, NOT that a separately-privileged agent can bind, NOR that the resident agent is cleanly extractable.** Extractability is gated on BOTH the `mem/` factorization AND the unbuilt EL0 trap gate. `token=conformance=SPEAKABILITY-BY-IN-PROCESS-CODE-NOT-EXTRACTABILITY`.
- **The degraded/generic-host binding is schema-symmetry-only at stage A** — no runtime is built, and on a generic host the sovereign guarantees are surrendered by construction. `token=degraded=SCHEMA-ONLY / SOVEREIGNTY-SURRENDERED`.
- **The version token is a discoverable LABEL, not a GATE** — an agent can read the host ABI version but nothing rejects a mismatch at stage A; negotiation is deferred. `token=version-token=DISCOVERY-ONLY-LABEL-NOT-A-GATE`.
- **The registry is keyless/tamper-evident, not signed** — `sec=ASSUMED-FROM-LITERATURE`; a signed ABI-version attestation is the M33 successor.
- **"Cogi" is still in-kernel** — `bootreport.rs` hardcodes it as the default boot-report `View` and emits it on the boot wire; the greeting fixture in `live.rs` also carries it. Neutralizing the boot-report is genuine stage-A kernel work; the lint's scope over the `live.rs` fixture is an operator judgment call (§12). `token=cogi-residue=IN-KERNEL-BOOTREPORT + HOST-GREETING-FIXTURE`.
- **The wire namespace is only PARTIALLY single-sourced today** — `MAGIC_OPFRAME/RX/INFERWIRE` are in `brand` with a pairwise assert, but `ATTEST_MAGIC=0x5959` is a standalone literal in `tb-encode/attest.rs:53` with only a comment for disjointness. An earlier draft's claim that all four were "single-sourced in the brand crate" is retracted. The `abi.rs` frozen list is the first place all four sit together with an enforced disjointness check. The separate "TABOS-*" domain-label leak IS closed (labels already `YUVA-*`). `token=wire-magics=3-IN-BRAND+ATTEST-STANDALONE`, `wire-labels=ALREADY-YUVA`.
- **Named-deferred, stated not built:** the generic-host degraded runtime (backends); the `cogitave/agent` repo split + code move (extraction); the `mem/` engine-organ factorization; the EL0 trap gate; exhaustive conformance coverage; runtime feature-negotiation + version GATING; the signed ABI attestation; aarch64/tb-vmm cmdline channels for version pass-through (inherited from boot-profiles §11).

---

## 11. Frontier / named deferrals

- **The pluggable RUNTIME backends.** `yuva-native` is real (M11 + M30); the `generic-host` DEGRADED binding (the same schemas over a POSIX unix-socket/stdio transport) is `backends=DEFERRED`; stage A specifies only the schema symmetry M30's transport-portability enables.
- **The `cogitave/agent` extraction.** Repo split + moving the agent's portable core out — `extraction=DEFERRED-SEPARATE-MILESTONE`, gated on BOTH the `mem/` factorization AND the EL0 trap gate. The ABI is its precondition.
- **The EL0 trap gate.** The privilege boundary that lets a separately-compiled/separately-privileged agent enter the capability surface (`caps.rs:240,249` mark it FUTURE) — a Plane-1 extraction blocker.
- **The `mem/` engine↔organ factorization.** A hard blocker SHARED with boot-profiles stage B; until it lands the memory seam is spec-able but not cleanly cuttable — `separability=EXECUTION-ADMISSION-LEVEL-AT-STAGE-A`.
- **Exhaustive conformance coverage.** Stage A is a skeleton with a handful of frozen vectors per family; full coverage is deferred.
- **Runtime feature-negotiation + version GATING** (virtio-style offer/accept bitsets + a rejection path beyond the discoverable version LABEL).
- **A signed/keyed ABI-version attestation** — the M33 successor.
- **aarch64 `/chosen/bootargs`, tb-vmm `TbBootInfo.cmdline`, and EL1-guest channels** for version/profile pass-through (inherited from boot-profiles §11).

---

## 12. Landing plan — staged, CI-green, offline; operator veto points

- **(A) The ABI SPEC + the frozen-literal leaf + the conformance skeleton + the terminology neutralization (closes the Yuva-ABI task).** `docs/spec/yuva-abi-v1.md` + `crates/tb-encode/src/abi.rs` (frozen literals + `abi_snapshot.rs` cross-check + append-only-ceiling assert) + the `abi:` witness + `M_OBJECT_INSPECT` version LABEL + the frozen golden-vector file (pos+neg) + the mini-agent + `abi-conformance.yml` (additional lane, summary marker) + the `bootreport.rs` neutralization + the `Cogi` lint + the §13 docs fan-out, in the same landing. The three required verifiers: ZERO lines changed. Kani pin: +0/+1, re-measured. After (A) the conformance lane is green unattended — offline, no secrets, no unlanded-crate dependency.
- **(B) Runtime feature-negotiation + version GATING** (stage B, §11) — the offer/accept bitset dance + a rejection path over the discoverable version token; a separate reviewed landing.
- **(C) The channel follow-ups** (aarch64/vmm/guest version pass-through) inherited from boot-profiles.
- **(D) The extraction milestones** (repo split, moving the agent's portable core, the pluggable backends, the EL0 trap gate) — separate proposals, explicitly out of scope; gated on the shared `mem/` factorization AND the EL0 gate.

**Operator veto points (named; none reachable from an unattended run):** (1) the `bootreport.rs` neutralization wording + the `Cogi` lint's scope over the `live.rs` greeting fixture (neutralize vs narrowly-allow — a historical-witness judgment) AND the §7.1 confirmation that no required grep asserts a bootreport view string; (2) any cap-plane MAJOR bump (a breaking method change or relaxed right — never silent, the frozen cross-check forces the bump to be explicit); (3) admitting any external `cogitave/agent` artifact through the M18.1 seam (the extraction line's gate); (4) first build of the generic-host degraded runtime (surrenders sovereignty by construction — a product decision); (5) any move from the discoverable version LABEL toward implemented feature-negotiation/GATING; (6) the EL0 trap gate and the repo split themselves.

---

## 13. Ledger + docs fan-out (written WITH the landing)

- **`docs/spec/yuva-abi-v1.md` (NEW)** — this proposal, promoted to the canonical spec.
- **`crates/tb-encode/src/abi.rs` (NEW)** — the frozen-literal registry; the version token; and **`abi_snapshot.rs` (NEW)** — the cross-check test (frozen vs live, including `required_right()` + the ceiling assert).
- **`kernel/src/main.rs`** — the `abi:` witness line; `M_OBJECT_INSPECT` on the root capability reporting `YUVA_ABI_VERSION` (additive, outside the cumulative grep).
- **`kernel/src/bootreport.rs`** — the terminology neutralization: `View::Cogi`→`View::Agent`, neutral default selector, re-worded boot-wire strings (`:224,321,391,394,441`).
- **`crates/tb-hal/src/caps.rs`** — a doc-comment cross-reference to `abi.rs` as the registry's home (the "highest since M31" comment upgraded to point at the machine-checked ceiling assert; no numbering change).
- **The mini-agent + frozen golden-vector file + `scripts/run-abi-conformance.sh` (NEW)** + `.github/workflows/abi-conformance.yml` (NEW additional job); the three required verifiers — ZERO lines changed.
- **`LANGUAGE-AND-STANDARDS.md`** — the `Cogi`-ban lint rule; the two-axis versioning rule (cap-plane SEMVER + wire-plane `u8`, append-only, minor=compat/major=breaking, MAJOR forced on a renumber or relaxed right by the frozen cross-check); the "ABI is spec + frozen snapshot cross-check, not semantically-complete freeze" honesty rule.
- **`docs/{MILESTONES,ARCHITECTURE,ROADMAP-V2}.md`** — the two planes, the two axes, the `SOVEREIGN|DEGRADED` axis, the conformance discipline, the two extraction blockers.
- **`assumptions.md` NEW rows** — the ABI is in-repo-spec at stage A; the version token is discovery-only; three wire magics are in brand and `ATTEST_MAGIC` is standalone in `tb-encode`; the wire labels are already `YUVA-*`; the memory seam is spec-able-not-cuttable pending `mem/` factorization; Plane-1 extraction is gated on the unbuilt EL0 trap gate; the registry cross-check is keyless.
- **`docs/proposals/boot-profiles.md`** — a cross-reference note: `agent-abi=NOT-DEFINED` is picked up by this proposal (HOW-they-talk to its WHICH-side-runs).
- **`.claude/skills/tabos-milestone/SKILL.md`; `docs/plans/INDEX.md`; `docs/BACKLOG.md`; the tracker task.**

---

## 14. Adversarial review

This proposal was submitted to two independent adversarial reviewers. Both returned **SOUND-WITH-AMENDMENTS**. Every must_fix and every overclaim is resolved in the text above; the changes are recorded here so the amendment trail is auditable.

### 14.1 Enforcement made concrete — the four must_fixes on the mechanism

- **The by-reference/drift-detection contradiction (Reviewer 1, must_fix 1) — FIXED.** An earlier draft claimed `abi.rs` was "single-source BY REFERENCE, never a copy" AND a "drift-detecting equality test" — a tautology that fails on nothing. Resolved in §3.2: `abi.rs` now holds a FROZEN INDEPENDENT LITERAL registry (a deliberate second copy), and `abi_snapshot.rs` cross-checks it against the live seam constants. The "never a copy" rule is explicitly retracted. `token=abi-leaf=FROZEN-LITERAL-SNAPSHOT`.
- **The ceiling assert enforced almost nothing (Reviewer 1, must_fix 2) — FIXED.** The frozen snapshot now includes the per-method `required_right()` mapping (`caps.rs:268-298`), and the cross-check asserts each method's live `required_right(id).bits()` equals the frozen literal — so a RELAXED right (the single most dangerous seam break) FAILS. A renumber of an existing method also fails (frozen id vs live constant). §3.2 checks 1-2. `token=enforcement=RENUMBER+RELAX-RIGHT+CEILING-ALL-CAUGHT`.
- **Golden vectors must be frozen literals with negatives (Reviewer 1, must_fix 3) — FIXED.** §3.4 now specifies all three vector families as FROZEN pinned literals, and the capability-dispatch family carries NEGATIVE vectors with `Denied` pinned as a literal — so a relaxed admission returning `Ok` fails the lane. This is the runtime complement to the compile/unit-level snapshot cross-check.
- **The second, unstated Plane-1 separability blocker (Reviewer 1, must_fix 4) — FIXED.** §2.1/§2.5/§5/§11 now state that the EL0 syscall gate is FUTURE (`caps.rs:240,249`), the agent runs in-kernel, and the stage-A mini-agent therefore runs IN-PROCESS in the SAME binary — proving speakability by non-resident in-process code, NOT extractability by a separately-privileged agent. The `conformance` token is widened accordingly, and extraction blockers are now BOTH the `mem/` factorization AND the EL0 gate.

### 14.2 Terminology / citation must_fixes (Reviewer 2)

- **False "kernel is agent-neutral" claim — RETRACTED.** `kernel/src/bootreport.rs` hardcodes `View::Cogi` (default), `yuva.view=cogi` (`:224`), and boot-wire strings (`:321,391,394,441`). §1.4 and Seam 2 now state the kernel is agent-neutral only in the cap/hosting SEAMS, with the agent name still in the boot-report. Tokens replaced.
- **DoD-6 re-scoped as genuine kernel work — DONE.** §1.4, §7.1, and DoD-6 now treat the `bootreport.rs` neutralization as real stage-A kernel work that edits serial output, with an explicit DoD-5 reconciliation that the edited strings sit outside the required cumulative grep (verified at landing, not assumed).
- **`ATTEST_MAGIC` citation corrected — DONE.** It is a standalone literal in `tb-encode/attest.rs:53`, NOT a brand export; brand's disjointness assert covers only the three `0x5956/57/58` magics. The preamble, Depends-on, Seam 5, §3.2, and References are corrected; the "single-sourced in brand" framing is retracted. This reinforces the case for `abi.rs` unifying the namespace.

### 14.3 Overclaims neutralized (both reviewers)

- **"versioned contract with a version token that gates" → LABEL not GATE.** Title/pillars/§3.3 now state the stage-A token is `DISCOVERY-ONLY-LABEL-NOT-A-GATE`; nothing consumes it to reject a mismatch until stage B.
- **"machine-enforced append-only by a committed snapshot" → cross-check semantics named.** §1.3/§3.2/§10 state exactly what the cross-check catches (renumber, relaxed right, ceiling) and does not (all semantics under a stable signature).
- **"PROVEN by mini-agent conformance" → DEMONSTRATED / SKELETON.** §3.4 and the tokens use `DEMONSTRATED-BY-MINI-AGENT-SKELETON` and name the in-process/same-binary ceiling.
- **Present-tense "runs SOVEREIGN … or DEGRADED" → tensed spec-only.** The pillar sentence and §4 header are tensed: sovereign is real today, degraded is `SPEC-ONLY / backends=DEFERRED`.
- **Minor cite drift — corrected.** `recall()` is `mem/mod.rs:1339` (not `:1338`) throughout.

---

## 15. References

**In-tree (verified against the working tree, 2026-07-08):**
- `crates/tb-hal/src/caps.rs` — the M11 method-number registry `M_OBJECT_INSPECT=0 … M_MODEL_INVOKE_BYTES=32` `:189-264`; `required_right()` `:268-298`; the `INVOKE_MODEL` possession gate `:294,649`; the M18.1 admission gate `harness_merge` `:991`, `carries_approval` `:970`, `Rights::APPROVE_HIGH_IMPACT`; the FUTURE EL0 syscall-gate seam `:240,249`. *(Plane-1 dispatch + admission — the primary agent↔kernel contract to freeze-snapshot and cross-check, INCLUDING the `required_right()` mapping; a clean zero-ambient-authority chokepoint; no version constant exists today; the EL0 gate is a named Plane-1 extraction blocker.)*
- `kernel/src/main.rs` — M11 agent-native ABI comment `:1226`; the M12 `AgentProcess` hosting socket `:1368-1549`, marker `M12: agent OK` `:1549`; the M38 conductor spine `:5057-5307`; the cumulative M38 tail. *(The hosting socket path is agent-agnostic; the landed conductor is the spine the ABI formalizes seams around.)*
- `kernel/src/bootreport.rs` — `enum View{Cogi,Substrate}` with `Cogi` DEFAULT, `yuva.view=cogi` `:224`, boot-wire strings `"cogi view"` `:321`, `"Cogi inference deterministic stub"` `:391,394`, `"Cogi is resident. Yuva ready (logical surrogate)"` `:441`. *(The in-kernel agent-name residue — retracts the earlier "Cogi nowhere in kernel" claim; genuine stage-A neutralization target, on the boot wire.)*
- `crates/brand/src/lib.rs` — the wire-magic family `MAGIC_OPFRAME=0x5956` `:169`, `MAGIC_OPFRAME_RX=0x5957` `:174`, `MAGIC_INFERWIRE=0x5958` `:178`, `SB_MAGIC="YUVAMEM0"` `:189`; the domain labels `DOMSEP_{OPCMD_KDF,KEY_EVOLVE,M30_ECHO,M31_INFER,M33_ATTEST}` ALREADY `YUVA-*` `:83-114`; the compile-time disjointness (THREE magics only) + label asserts `:196-266`. *(The wire-plane is PARTIALLY single-sourced and ALREADY `YUVA-*` — the "TABOS leak" is closed; but `ATTEST_MAGIC` is NOT here.)*
- `crates/tb-encode/src/attest.rs:53` — `pub const ATTEST_MAGIC: u16 = 0x5959;` (standalone literal; disjointness a comment `:50`, not an assert). *(The FOURTH wire magic, NOT in brand — the concrete evidence the namespace is not fully single-sourced; `abi.rs` unifies all four with an enforced disjointness check.)*
- `crates/tb-encode/src/inferwire.rs` — magic `0x5958` (`INFER_MAGIC = brand::MAGIC_INFERWIRE`) `:109`, `INFER_VER=1` `:113`, ver-check `:370`, `FrameAccum` resync `:646-699`, `DOMSEP_M30_ECHO="YUVA-M30-ECHO-V1"`, pinned canon vectors `:1616,1685`. *(Plane-2 wire ABI — already versioned per-frame and transport-portable; the enabler of the future generic-host degraded binding; the #49 pinned-literal idiom for the frozen wire vectors.)*
- `crates/tb-encode/src/opframe.rs` + `opframe_rx.rs` — `OPFRAME_MAGIC=0x5956`, `CMD_MAGIC=0x5957`, `KDF_DOMAIN="YUVA-OPCMD-KDF-V1"` `:98`. *(The M28/M25 wire siblings that belong in the collision-checked magic namespace.)*
- `crates/tb-encode/src/conductor.rs` — `Role` `:82`, `Organ{RetrievalOverMemory=0x00,LocalM32=0x01,ExternalMock=0x02}` with `tag()`/`from_tag` `:120-169`, `Verdict` `:179`, `prov::kind::CONDUCT_DECISION` `:54`. *(The spine's `Organ` enum IS the append-only agent-organ registry the ABI versions.)*
- `crates/tb-hal/src/mem/mod.rs:1339` — `recall()` BM25+ lexical (`retrieval=LEXICAL-NOT-SEMANTIC`); the M20 engine + M13 organ cohabit `mem/` unfactored. *(The biggest coupling leak — the memory seam is spec-able but not cleanly cuttable until factorization, the shared boot-profiles blocker.)*
- `tools/xport-harness/src/live.rs:364,382,993,1037-1050,1378-1395` — the residual "Cogi" greeting fixture. *(The host-side non-neutral residue; the `Cogi` lint's operator judgment point — distinct from the in-kernel `bootreport.rs` site.)*
- `docs/proposals/boot-profiles.md` (branch `boot-profiles-proposal`) — §1.2 `separation=IN-REPO-PROFILE-NOT-EXTRACTION` / `agent-abi=NOT-DEFINED`; §3.2 the M12 agent-agnostic socket; §3.4 the `mem/` engine-organ blocker; §8.2c the negative census. *(The sibling that decides WHICH side runs; this proposal is its HOW-they-talk sequel and shares the M12/M18 seams + the `mem/` blocker.)*
- `docs/proposals/M38-conductor.md` — the policy-in-kernel / execution-host-side SPLIT; the `Organ` enum; "split the spine not the embryo"; the additional-lane / summary-marker landing discipline. *(The spine to formalize; the exact template for the ABI's stage-A conformance lane and Kani-budget posture.)*
- `docs/proposals/M30-infer-transport.md` §3d — the one-codec rule and the transport-migration-unchanged property. *(The precedent for the wire-plane's forward-compat and the future degraded binding.)*
- `docs/research/cogi-cognitive-architecture.md` §2/§3.1 — memory = non-parametric STORE (substrate-side), organs = composable capabilities (agent-side); the verified/provenance/sovereign WRAPPER razor. *(Grounds the substrate/agent cut-line the ABI formalizes; keeps the honesty razor — the novelty is the wrapper, not a learning paradigm.)*

**Industry precedents:**
- **Linux syscall ABI** — "don't break userspace", append-only syscall numbers (kernel.org `Documentation/ABI/stable/syscalls`). *(Plane-1 versioning: methods added, never removed/renumbered — the discipline `caps.rs` follows by convention, made machine-checked by the frozen cross-check.)*
- **virtio 1.x feature negotiation + `VIRTIO_F_VERSION_1` legacy detection** (OASIS virtio v1.2/1.3). *(Plane-2 forward/back-compat + the runtime version-DISCOVERY (stage A) / eventual feature-negotiation + GATING (stage B) model.)*
- **WASI witx (preview1) → WIT worlds (preview2) + the preview1↔preview2 adapter** (Bytecode Alliance wasmtime). *(The two-plane spec + the `SOVEREIGN|DEGRADED` dual binding: one IDL, two ABI levels, an adapter between — the yuva-native vs generic-host degrade model.)*
- **Firecracker OpenAPI + SEMVER snapshot version INDEPENDENT of the binary version** (`firecracker docs/snapshotting/versioning.md`, `docs/api-change-runbook.md`). *(The two-axis versioning discipline — cap-plane SEMVER vs wire-plane `u8` evolve independently; minor=compat, major=breaking.)*