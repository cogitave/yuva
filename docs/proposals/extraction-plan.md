---
type: Design Decision
title: "Extraction Plan — moving the agent's host-side core to cogitave/cogi"
description: "Plan (not executed) to move four host-side agent binaries to a new cogitave/cogi repo behind the frozen Yuva-ABI; resident agent stays."
tags: ["extraction", "repo-split", "yuva-abi", "m38", "sovereignty"]
timestamp: 2026-07-08T08:11:18+03:00
status: active
diataxis: explanation
---

# Yuva→cogitave/cogi EXTRACTION PLAN — moving the agent's portable host-side core out to a separate repo across the frozen Yuva-ABI (the operator's cross-repo action, de-risked and sequenced — NOT the execution)

**Status:** **PROPOSAL V2 (research-first; nothing executed; hardened against adversarial review — see §13). The WHERE-the-agent-lives sequel to boot-profiles' WHICH-side-runs (`docs/proposals/boot-profiles.md`) and Yuva-ABI's HOW-they-talk (`docs/proposals/yuva-abi.md` → `docs/spec/yuva-abi-v1.md`), and the FINAL step of the 2026-07-08 operator directive that `cogitave/yuva` (the OS) and `cogitave/cogi` (the agent, whose identity is "Cogi") become SEPARATE projects with Yuva AGENT-AGNOSTIC and the agent Yuva-OPTIONAL.** · **Pillars:** sovereignty (the agent's portable core is lifted to `cogitave/cogi` and binds back to a still-in-Yuva kernel over the frozen Plane-2 wire — the sovereign yuva-native binding is REAL IN-REPO TODAY and is PREDICTED to survive the split, to be PROVEN by DoD-5's boot-against-pinned-image lane, NOT asserted as already-true-across-the-boundary; the generic-host binding stays `SPEC-ONLY-SKELETON`) + verification (the move is MECHANICAL for THREE of the four tools — a rename + one-line dep rewrite over already-nested dep-clean-at-the-tool-level workspaces — with ONE named non-trivial tail: `infer-daemon` drags a vendored-native `llama-engine-sys` member + a GGUF test artifact + host-only engine/seccomp/landlock deps, so ITS move is a fresh-CI toolchain rebuild, not a dep line; every move is proven green in BOTH repos before any deletion) + honesty (`extraction=PLAN-NOT-EXECUTED`; creating `cogitave/cogi` + the physical `git filter-repo` move + the push are the operator's cross-repo actions — this document DE-RISKS and SEQUENCES them, it does not perform them; the RESIDENT in-kernel agent does NOT extract). · **Depends on — the in-repo separation, ALREADY LANDED (origin/main `089f03b`):** (1) agent-terminology neutral in code (`View::Agent`, generic `agent-a..d` principals; the last "Cogi" survives only in the `tools/xport-harness/src/live.rs` greeting fixture); (2) the Yuva-ABI stage A (`docs/spec/yuva-abi-v1.md` + `crates/tb-encode/src/abi.rs` frozen-literal registry + `caps::abi_registry_selfcheck` in-kernel boot self-check that FAIL-CLOSES the boot on drift — TWO planes: Plane-1 numbered caps `0..32` rights-masked, Plane-2 wire magics `0x5956..0x5959`); (3) boot-profiles stage A (`kernel/src/profile.rs`, `yuva.profile=substrate|agent`, a real execution GATE with a negative-census witness). **So the seams are formalized + versioned + enforced, and the two layers provably separate at the execution/admission level.** · **Tasks:** the extraction task closes at **stage A** (the four host-side binaries moved behind the versioned contract, both repos green); stage B (the thin published `yuva-abi` facade + the resident in-kernel cut) is a named successor, explicitly NOT blocked on and BLOCKED by two unbuilt prerequisites (§9). · **Markers:** the CI-required cumulative M0..M38 chain and the tail `M38: conductor OK turns=N organs=K verdict=ACCEPT` (`scripts/run-x86_64.sh:37`) are **byte-untouched by construction** — nothing marker-bearing moves; every moved tool is a host binary that was never on the guest-serial chain.

> **One-line:** The in-repo separation is complete — Yuva is agent-neutral, the ABI is frozen and enforced at boot, and the substrate profile proves the organs don't run. What remains is the physical move. This plan takes the agent's *portable host-side core* — the M38 host executor (`tools/conductor-host`), the reasoning-organ host (`tools/infer-daemon`), the wire transport client (`tools/xport-core`), and the transport peer + live bridge + identity fixture (`tools/xport-harness`) — each already an isolated nested Cargo workspace that, AT THE TOOL LEVEL, path-deps `tb-encode` alone, and lifts them to `cogitave/cogi` with history, rewriting one dependency line per tool (`path` → pinned git tag of Yuva at the frozen ABI version). It KEEPS in Yuva the ABI *server* (the kernel, the M11/M12 caps + hosting socket, the organ *host* bodies, the shared `tb-encode` contract crate the kernel itself links, and `prov-signer` — Yuva's own provenance-signing leg). The disciplining principle, stated literally: **split the spine, not the embryo.** The M38 conductor is the spine, and it has TWO halves that must never be conflated — the verified DECISION ALGEBRA (`tb-encode/src/conductor.rs`, linked by BOTH the kernel and the host executor, carrying the Kani proof surface) is the SHARED CONTRACT and STAYS; the host EXECUTOR (`tools/conductor-host`) MOVES. The embryo — the resident in-kernel agent (M12 socket + in-kernel M38 selftest + conformance mini-agent) — does NOT move: it is blocked by the two named blockers (EL0 trap gate UNBUILT, `mem/` engine↔organ UNFACTORED). This is the PLAN the operator reviews and then executes across the repo boundary; it is not executed here.

This proposal is the convergent synthesis of three research strands (§12 References) which independently arrived at: the four `tools/*` host binaries are the mechanically-cuttable surface because they are already dep-clean-at-the-tool-level nested workspaces; `tb-encode` is the shared contract crate that CANNOT move (the kernel links it) and becomes a versioned git-tag dependency — **and is itself NOT dep-free: it path-deps `crates/brand` and hard-uses `brand::MAGIC_*`/`DOMSEP_*`, a coupling that is transparent at stage A but constrains the stage-B facade (§2.4)**; the resident in-kernel agent CANNOT extract at stage A (both blockers open); incremental-behind-the-ABI beats big-bang; and — corrected against the first draft — the genuine cross-repo drift detector is NOT a committed corpus (the frozen vectors are in-code consts pulled byte-identically via the same git object, so an agent-local `cargo test` re-check of them is near-tautological), but the DoD-5 lane that BOOTS a pinned Yuva image and exercises the REAL live seam (§3.9, §5 R2). Where the strands differed on sequencing (all-four-at-once vs conductor-host-first), §3.10 records both and §8 makes it an explicit operator veto point.

---

## 1. Why this step, and why now

### 1.1 The gap: the seams are cut, the code has not moved

Three sibling milestones have landed on `origin/main` (`089f03b`), and together they closed everything EXCEPT the physical move:

| Milestone | What it proved | Token |
|---|---|---|
| boot-profiles stage A | the two layers separate at the **execution/admission** level (organs provably don't run in substrate — negative census) | `separability=EXECUTION-ADMISSION-LEVEL` |
| Yuva-ABI stage A | the contract is **frozen + versioned + enforced** (`abi.rs` registry, `caps::abi_registry_selfcheck` fail-closes the boot on drift) | `abi=IN-REPO-SPEC-AT-STAGE-A` |
| agent-terminology | Yuva is **agent-neutral in code** (`View::Agent`, generic principals; last `Cogi` in one host fixture) | `terminology=AGENT-NEUTRAL-PER-DIRECTIVE` |

What is genuinely absent is the **cross-repo action**: `cogitave/cogi` does not exist, and the agent's portable core still lives physically under `tools/` in the Yuva tree. The seams are cut; the code has not moved. This plan is that move — and, crucially, it is a MECHANICAL move (for three of four tools; `infer-daemon` carries a non-trivial native tail, §2.1) of a small, already-isolated set of host binaries gated on cross-repo contract discipline, NOT a code disentangling. The disentangling was the previous three milestones' work. `token=coupling=SEAMS-CUT-CODE-NOT-MOVED`.

### 1.2 Why now: the spine is mature, and every milestone makes the cut heavier

The M38 conductor has landed in-kernel (`kernel/src/main.rs:5280-5568`; the `M38: conductor OK …` cumulative tail at `run-x86_64.sh:37`) and its host executor (`tools/conductor-host`) is a mature, offline, deterministic 452-line binary. The directive's discipline is *split the spine, not the embryo*: the conductor is the spine — landed, verified, and now stable enough to move its host half — and every further milestone that grows the resident agent makes the eventual cut heavier. Moving the host-side spine NOW, while it is a rename + one dep-line rewrite, is cheaper than after it grows further. `token=discipline=SPLIT-THE-SPINE-NOT-THE-EMBRYO`, `spine=M38-CONDUCTOR`, `spine=TWO-HALVES-MATH-STAYS-HOST-EXECUTOR-MOVES`.

### 1.3 Why an industry-standard shape — the precedents, mapped

Splitting a subtree into a new repo across a versioned interface is a solved problem, and each precedent maps onto one mechanic (`token=shape=INDUSTRY-PRECEDENTED-NOT-INVENTED`):

- **`git filter-repo --subdirectory-filter` / subtree extraction** (GitHub Docs, "Splitting a subfolder out into a new repository"). Governs the physical move: history-preserving, and materially faster and lossless-er than `git subtree split` (which loses pre-move history). The four `tools/*` subtrees are lifted WITH their commit history.
- **Rust shared-types crate, `path` → `git` → published `version`** (The Cargo Book, "Specifying Dependencies"). Governs the dependency contract: a `path` dep cannot cross a repo boundary and cannot publish, so each moved tool's `tb-encode = { path = … }` becomes a git-tag dep (stage A), then a published `yuva-abi` facade version (stage B) — a facade that itself must carry or vendor `brand` to build off-repo (§2.4).
- **WASI witx→WIT versioned interface package** (Bytecode Alliance). Governs the contract shape: one versioned interface crate that BOTH the host (kernel via `tb-hal`) and the component (agent) pin by semver — precisely `tb-encode`-as-versioned-contract and the future thin `yuva-abi` facade.
- **Firecracker's independent SEMVER** (firecracker `docs/snapshotting/versioning.md`). Governs the pin discipline: the agent consciously bumps its pinned Yuva revision to consume a new `YUVA_ABI_VERSION`; the contract is immutable per agent revision.

None of these is a rewrite. The extraction adopts the discipline, not new mechanism. `token=precedents=FILTER-REPO/CARGO-PATH-TO-GIT-TO-PUBLISHED/WASI-WIT/FIRECRACKER-SEMVER`.

---

## 2. The MOVABLE SURFACE — moves-out vs stays-in, and the entangled seams

The extraction moves the agent's **portable host-side core**. It is portable precisely because of a structural fact already in the tree: every `tools/*` host binary is an INDEPENDENT nested Cargo workspace with its OWN `Cargo.lock`, auto-excluded from the root no_std workspace, and — AT THE TOOL LEVEL — path-deping `crates/tb-encode` alone (plus, for the reasoning tools, host-only deps). The root `Cargo.toml` confirms this: `exclude = ["tb-vmm", "tools/xport-harness", "tools/prov-signer"]` (`Cargo.toml:47`), and `conductor-host`/`infer-daemon`/`xport-core` are auto-excluded by carrying their own `[workspace]` stanza. The extraction is therefore, for the tools that path-dep `tb-encode` alone, a **rename + dep-rewrite, not a disentangle**. **HONEST QUALIFIER: "dep-clean" is a claim about the TOOL boundary, not the whole contract crate. `tb-encode` is itself NOT a leaf — it path-deps `crates/brand` (`crates/tb-encode/Cargo.toml:41`) and hard-uses `brand::MAGIC_*`/`DOMSEP_*` across `abi.rs`, `inferwire.rs`, `attest.rs`, `opframe.rs`, `opframe_rx.rs`. This is transparent at stage A (§2.4) and load-bearing at stage B (§9).** `token=positioning=TOOL-LEVEL-DEP-CLEAN-BUT-TB-ENCODE-DEPS-BRAND`.

### 2.1 MOVES OUT — the agent's portable host-side core (→ `cogitave/cogi`)

- **`tools/conductor-host/`** (whole nested workspace) — the M38 HOST executor: runs the verified `tb-encode::conductor` policy over the mock-organ transcript, executes organs, and independently recomputes the M22 decision lineage (the anti-hollow "independent recompute" leg). 452 lines, offline, deterministic; path-deps `tb-encode` ALONE. **This is the agent's portable orchestration spine (host-executor half) and the single cleanest first move — genuinely one dependency line to rewrite.** `token=conductor-host=ONE-LINE-CLEANEST-FIRST-MOVE`.
- **`tools/infer-daemon/`** (+ its `llama-engine-sys/` member, `models/stories260K.gguf` test artifact, `engine.rs`/`worker.rs`/`witness.rs`/`pins.rs`) — the M32 local REASONING ORGAN host: a key-holding safe-Rust daemon supervising the sandboxed vendored-llama.cpp GGUF worker. The swappable reasoning organ (cogi-cognitive-architecture §2.3). Deps: `xport-core` + `tb-encode` + optional host deps (engine/seccomp/landlock). Carries the `SOVEREIGNTY-OPEN-B3` debt tokens. **NON-TRIVIAL TAIL — NOT a one-line move: this tool vendors a native `llama-engine-sys` member (C/C++ llama.cpp), commits a GGUF test artifact, and pulls host-only engine/seccomp/landlock deps. Its cross-repo move is a fresh-CI native/toolchain rebuild (C toolchain, LFS audit per §5 R8), not a dep-line rewrite. This is why §3.10 batches it AFTER `conductor-host` and gives it its own green window.** `token=infer-daemon=VENDORED-NATIVE-TAIL-NOT-ONE-LINE`.
- **`tools/xport-core/`** — the dep-clean `FrameAccum` serve-glue + hex/witness helpers = the Plane-2 wire TRANSPORT CLIENT (the ABI-client library). Path-deps `tb-encode` ALONE, by construction. Becomes the agent's `abi-client` / `backend-yuva` transport layer.
- **`tools/xport-harness/`** — the M30/M31 host peer (echo + MOCK-DETERMINISTIC inference serve) AND `src/live.rs` (the operator-gated Anthropic bridge, M31 stage C, `ureq`+`serde_json`). The reasoning transport peer + live backend. **It also carries the ONE remaining `Cogi` greeting fixture** (`live.rs` — the historical-reply consts and greeting envelope tests around `:993,996,1040,1045,1054,1056` and the `:1378-1398` envelope tests; the code already annotates at `:996,1045` that "Cogi is now the identity of the separate cogitave/cogi project") — whose correct home is now the agent's identity, not Yuva. `token=cogi-residue=RIDES-OUT-WITH-XPORT-HARNESS`.
- **The agent-attributable host-side CI lanes/scripts** that drive the above: `.github/workflows/conductor-host.yml`, `conductor-m18neg.yml`, `real-infer.yml`, `m32-local-infer.yml`, `abi-conformance.yml`, and the `local-infer` (engine feature) lane; the driver scripts `scripts/conductor-adjudicate.sh`, `scripts/m32-adjudicate.sh`, `scripts/run-abi-conformance.sh`. These re-host in the agent repo's CI (re-wired to pull `tb-encode` as an external dep) — see §2.5 for the anti-hollow-proof tradeoff this relocation forces.

> **NOTE — the agent-organ CODEC LEAVES do NOT move at stage A.** The pure agent-organ leaves in `crates/tb-encode` (`conductor`, `inferwire`, `opframe_rx`, `exp`, `bakeoff`, `kancell`, `memscore`, `route`, `explore`, `exittel`, `provhead`, `attest`) stay PHYSICALLY in `tb-encode` because the KERNEL boot selftests link them too. They are agent-ATTRIBUTABLE but SHARED via the contract crate, not moved. This is the shared-codec reality (§2.3, boot-profiles §4). `token=shared-codec=AGENT-LEAVES-STAY-IN-TB-ENCODE-LINKED-BY-KERNEL`.

### 2.2 STAYS IN — the ABI server, the kernel, the organ hosts (Yuva)

- **`kernel/` ENTIRELY** — the ABI SERVER: `rust_main`, all cumulative M0..M38 selftest markers, `bootreport.rs` (`View::Agent`), `profile.rs` (the substrate|agent execution gate), the M12 `AgentProcess` hosting socket (`main.rs:1368-1549`), the in-kernel M38 conductor selftest/spine (`main.rs:5280-5568`), the in-kernel conformance mini-agent (`main.rs:1469-1522`). The resident spine cannot extract — EL0 gate unbuilt. The marker chain survives the split TRIVIALLY because nothing marker-bearing moves.
- **`crates/tb-encode/` ENTIRELY** — the SHARED CONTRACT, NOT moved: `conductor.rs` (the verified spine MATH both the kernel and the moved `conductor-host` link — its own doc-comment states "ALL network/model/float execution stays HOST-SIDE (the `tools/conductor-host` binary); this leaf is the decidable DECISION ALGEBRA", `conductor.rs:7-10`), the Plane-2 wire codecs, `abi.rs` (the frozen-literal registry + `abi_snapshot` cross-check), and `proofs.rs` (the Kani proof surface — the 122 harnesses that `scripts/kani-shards.sh:75`'s `EXPECTED_HARNESSES_TOTAL=122` counts and guards). Moving any leaf would sever the kernel's link AND relocate the proof harness. It ALSO path-deps `crates/brand` (§2.4). The contract lives WITH the server (Yuva is the source of truth for `YUVA_ABI_VERSION`); the agent CONSUMES it.
- **`crates/brand/`** — the single-source of the Plane-2 wire magics + `DOMSEP_*` labels. **STAYS in Yuva; it is a hard transitive dependency of `tb-encode` (`tb-encode/Cargo.toml:41`), consumed by `abi.rs`/`inferwire.rs`/`attest.rs`/`opframe.rs`/`opframe_rx.rs`.** At stage A this is invisible (the git-tag checkout resolves `brand = { path = "../brand" }` inside the pulled Yuva tree). At stage B it becomes load-bearing: a published thin `yuva-abi` facade whose surface calls `brand::` CANNOT build off-repo unless `brand` is ALSO published (or its consts inlined into the facade). `token=brand=STAYS-YUVA-TRANSITIVE-DEP-OF-TB-ENCODE-FACADE-STAGE-B-MUST-PUBLISH-OR-INLINE`.
- **`crates/tb-hal/` ENTIRELY** — the kernel HAL (the only unsafe/asm crate): `caps.rs` (the M11 Plane-1 dispatch = the ABI-server capability-plane implementation + `abi_registry_selfcheck` + the `set_cognitive_deny` chokepoint + the UNBUILT EL0 trap gate — the future EL0 syscall-gate seam documented in the `M_BLOCK_MAP` region around `caps.rs:240,249`, an approximate anchor not an exact line pin), `infer.rs` (the M16/M31 route registry = SOVEREIGN|DEGRADED backend select), and `mem/` (M13-M20 storage engine + memory organ, UNFACTORED — the shared cut blocker; the `RetrievalOverMemory` organ is welded here and is NOT host-buildable).
- **`crates/tb-caps-core`** — the `Rights` bitset algebra (the Plane-1 primitive the ABI freezes). **`crates/tb-boot`, `tb-vmm/`, `targets/`** — pure substrate (boot info, host VMM, custom target specs).
- **`crates/tb-encode/src/abi.rs` + `docs/spec/yuva-abi-v1.md`** — the FROZEN registry + normative contract; source of truth for `YUVA_ABI_VERSION`.
- **`tools/prov-signer/`** — the M33 LMS host SIGNER. It holds the signing key for YUVA's memory-provenance chain (Yuva's sovereignty leg), NOT an agent capability. Stays Yuva-side. Its output is still validated by the retained kernel-side verifier (`provhead.rs` in `tb-encode`, which stays) — verify this binding is intact after the move (§7 DoD-5). `token=prov-signer=STAYS-YUVA-PROVENANCE-LEG-NOT-AN-ORGAN`.
- **The required boot/verifier scripts** — `scripts/run-x86_64.sh`, `run-aarch64.sh`, `run-vmm-x86_64.sh`, `run-substrate-x86_64.sh`, `verify-caps.sh`, `check-agent-neutral.sh`, `gen-witness-census.sh` — the both-arch boot verification stays wholly Yuva-side.
- **The in-kernel `caps::abi_registry_selfcheck` (Plane-1 method/rights/required_right half)** — lives in `tb-hal`, NOT shipped to the agent; the agent can only self-check the wire/organ half (`abi_snapshot`). Honest asymmetry (§6, tokens) — and, crucially, the reason the agent-local vector check cannot detect a forked live seam (§2.5, §5 R2).

### 2.3 The ENTANGLED seams needing a cut FIRST (both DEFERRED — they gate the RESIDENT cut, not the host-binary move)

Two couplings would need a cut before the RESIDENT in-kernel agent could extract. **Neither blocks the stage-A host-binary move** — they are named so the plan does not overclaim a clean embryo cut:

- **EL0 trap gate UNBUILT (`caps.rs:240,249` region).** The M11 surface dispatches in-kernel on `&mut HandleTable`; there is no privilege/trap boundary, so a separately-compiled/separately-privileged `cogitave/cogi` binary cannot bind at Plane 1 as a sovereign in-VM guest. Post-extraction the moved artifact is a HOST-SIDE wire peer over Plane 2 (serial-frame) only. `token=plane1-extraction-blocker=EL0-TRAP-GATE-UNBUILT`.
- **`mem/` engine↔organ UNFACTORED (`tb-hal/src/mem/{mod.rs,selftests.rs}`).** The M20 storage ENGINE and the M13 memory ORGAN cohabit `mem/` (~2,023 + ~2,322 lines), no_std, not host-buildable. The moved `conductor-host` therefore runs three MOCK organs precisely because the real `RetrievalOverMemory` organ is welded to the kernel. `token=mem-engine-organ=UNFACTORED-SHARED-BLOCKER-WITH-BOOT-PROFILES-STAGE-B`, `moved-organs=MOCK-UNTIL-MEM-FACTORED`.

Because both are open, the SCOPE is exact: what extracts is the HOST-SIDE organ/orchestration/reasoning binaries; the RESIDENT in-kernel agent stays. `token=extraction-blockers=EL0-TRAP-GATE + MEM-FACTORIZATION` (unchanged by this milestone).

### 2.4 The `tb-encode → brand` transitive coupling — transparent at stage A, load-bearing at stage B

Made explicit because the first draft's "path-deps `tb-encode` ALONE / dep-clean" framing hid it:

- **Stage A (git-tag dep): TRANSPARENT.** When a moved tool declares `tb-encode = { git = "…/yuva", tag = "yuva-abi-v1.0.0" }`, cargo checks out the WHOLE Yuva tree at that tag and resolves `tb-encode`'s own `brand = { path = "../brand" }` inside that checkout. `brand` rides along invisibly; nothing to do. `token=brand-stageA=TRANSPARENT-RESOLVED-IN-TAG-CHECKOUT`.
- **Stage B (published thin `yuva-abi` facade): LOAD-BEARING.** The facade surface (`abi.rs` and the speakable leaves) itself calls `brand::MAGIC_*`/`DOMSEP_*`. A crates.io-published facade CANNOT build off-repo with an unpublished `path`-dep. The facade plan (§9) MUST therefore either (a) publish `brand` too (it is small, wire-magic/label consts only — cheap to publish), or (b) inline `brand`'s consts into the facade at publish time (a codegen/vendor step, with a drift guard back to `crates/brand`). This is a NAMED stage-B obligation, not a stage-A blocker. `token=brand-stageB=PUBLISH-OR-INLINE-INTO-FACADE`.

### 2.5 The CI-relocation tradeoff at the cut — named, not glossed (feeds §3.8, §5 R1, §8 veto-7)

`scripts/conductor-adjudicate.sh`'s anti-hollow leg REQUIRES a SEPARATE host process: it asserts the conductor policy-head recomputed in-kernel equals the head independently recomputed by the `conductor-host` binary (the forged-trace catcher — a hollow/replayed transcript is caught precisely because a SECOND process recomputes the lineage). Removing `conductor-host` from Yuva removes that second process. The two options each carry a REAL, previously-unnamed cost:

- **Option A — relocate the agent-attributable lanes (incl. `conductor-host.yml`) to `cogitave/cogi`.** COST: Yuva LOSES its M38 cross-process independent-recompute proof. Only the in-kernel marker (`main.rs:5551`, `M38: conductor OK …`) survives on the Yuva side; the forged-trace catcher leaves with the binary. Yuva's own CI can no longer independently falsify a hollow conductor transcript — it trusts its own in-kernel recompute alone. `token=relocation-costA=YUVA-LOSES-CROSS-PROCESS-ANTI-HOLLOW-PROOF`.
- **Option B — pin `cogitave/cogi` back into Yuva (git-dep/submodule) so Yuva's lane can still spawn the host conductor.** COST: a CIRCULAR cross-repo dependency — agent→yuva (via the `tb-encode` git tag) AND yuva→agent (via the submodule/git-dep). Circular pins are a known maintenance hazard (lockstep bumps, clone-order fragility, CI bootstrap loops). `token=relocation-costB=CIRCULAR-AGENT<->YUVA-DEP`.

Neither is free; the plan does not pretend the relocation is a pure copy. The operator picks one at veto-7 (§8) with BOTH costs on the table. A THIRD framing worth noting: accept Option A's loss AS the honest post-split state (the anti-hollow independent-recompute proof legitimately BELONGS to the agent repo once the executor lives there), and have Yuva assert only its in-kernel marker — which is the natural end-state after the resident cut anyway. `token=relocation-tradeoff=A-LOSES-PROOF/B-CIRCULAR/OR-ACCEPT-A-AS-HONEST-END-STATE`.

---

## 3. The MECHANICAL STEPS — the `cogitave/cogi` repo, the versioned dependency, the green-preserving sequence

### 3.1 The dependency contract — `tb-encode` as a versioned git-tag dep (stage A), published facade (stage B)

`tb-encode` IS ALREADY the single-source SAME-math crate that both the kernel (via `tb-hal`) and every host tool consume by `path`. The extraction pins it as a VERSIONED CONTRACT:

- **Stage A:** each moved tool's `tb-encode = { path = "../../crates/tb-encode" }` becomes `tb-encode = { git = "https://github.com/cogitave/yuva", tag = "yuva-abi-v1.0.0" }`. The tag is an immutable Yuva revision (Firecracker's independent-version discipline made cross-repo). Because the tag checks out the whole Yuva tree, `tb-encode`'s own `brand` path-dep resolves transparently (§2.4). The agent pins by tag; a `cap_minor` (append-only) Yuva bump does not disturb it; the agent consciously bumps the pin to consume new surface.
- **Stage B (deferred):** split a thin `yuva-abi` facade carrying ONLY the speakable surface (the agent-attributable leaves + `abi.rs`) and publish it, so the agent no longer pins the WHOLE `tb-encode` (incl. silicon math it never calls). **This facade must publish-or-inline `brand` (§2.4, §9), because its surface calls `brand::`.** This is the named de-coupling successor (§9).

`token=contract=TB-ENCODE-IS-THE-SHARED-CRATE-TODAY`, `dep=GIT-TAG-AT-STAGE-A-THEN-PUBLISHED-FACADE-WITH-BRAND`.

### 3.2 The recommended `cogitave/cogi` repo structure

A workspace mirroring the `tools/` nested-workspace convention (own `Cargo.lock`, `panic=abort`), restructured for a backend-swappable shape (restructure is optional-but-recommended, §8 veto):

```
cogitave/cogi/
├─ Cargo.toml                    # workspace root
├─ crates/
│  ├─ agent-core/               # from conductor-host: the M38 host orchestration logic
│  ├─ abi-client/               # from xport-core: the Plane-2 speaker + M_OBJECT_INSPECT/abi: version-discovery reader
│  ├─ backend-yuva/             # REAL: abi-client over the QEMU chardev/serial transport (sovereign binding)
│  ├─ backend-generic/          # SPEC-ONLY skeleton: the SAME inferwire/opframe_rx schemas over a POSIX
│  │                            #   unix-socket/stdio, behind a `Backend` trait — builds, marked spec-only
│  └─ organ-infer/             # from infer-daemon + llama-engine-sys (vendored native) + xport-harness/live.rs bridge
├─ bin/
│  └─ cogi/                     # the identity binary; the live.rs greeting fixture is now correctly the agent's own
├─ tests/vectors/              # the FROZEN conformance vectors, mirrored from Yuva (byte-identical by shared git object)
└─ .github/workflows/          # the re-hosted conductor-host / real-infer / abi-conformance lanes
```

`token=repo-shape=AGENT-CORE+ABI-CLIENT+BACKEND-YUVA(real)+BACKEND-GENERIC(spec-only)+ORGAN-INFER+BIN-COGI`.

### 3.3 The sovereign vs generic binding, post-move (honest axis)

| Binding | Transport | Status post-extraction |
|---|---|---|
| **YUVA-SOVEREIGN** (`backend-yuva`) | the moved host binaries speak Plane-2 wire (frozen `0x5956..0x5959`) to a still-in-Yuva kernel that still hosts the resident spine | **REAL IN-REPO TODAY; PREDICTED to survive the split; PROVEN cross-repo only by DoD-5** — the same binaries, the same frames, over the same serial transport, but that the split-repo binary still binds is an EXPECTED-AND-TO-BE-PROVEN state, not an already-true fact |
| **HOST-GENERIC** (`backend-generic`) | the SAME schemas over a POSIX transport, no kernel | **SPEC-ONLY SKELETON** — builds behind the `Backend` trait, marked spec-only; sovereignty surrendered by construction, NAMED |

Moving code does NOT build the generic backend, and does NOT by itself PROVE the sovereign one across the boundary (DoD-5 does). `token=sovereign-binding=REAL-IN-REPO-TODAY/CROSS-REPO-BINDING-UNPROVEN-UNTIL-DoD-5`, `generic-host-backend=SPEC-ONLY-SKELETON`, `degraded-sovereignty=SURRENDERED-BY-CONSTRUCTION-NAMED`.

### 3.4 STEP 0 — Yuva prep: bump + tag the contract (keep source-of-truth single)

In Yuva: bump `crates/tb-encode/Cargo.toml` to a real semver mirroring `YUVA_ABI_VERSION` (e.g. `1.0.0` for cap-plane `(1,0)` + wire `1`), commit, and `git tag yuva-abi-v1.0.0` on `origin/main` (currently `089f03b`). This tag is the versioned-contract anchor the agent pins. Do NOT split `tb-encode` yet (the thin `yuva-abi` facade is stage B — keep blast radius small). Run the full both-arch boot + `abi_registry_selfcheck` + `abi-conformance` lane green so the frozen registry and vectors are the certified contract snapshot. **NOTE: there is no separate "promote the vectors to a cross-repo corpus" action — the frozen vectors are in-code consts in `abi.rs` (`FROZEN_METHODS`/`_RIGHTS`/`_WIRE_MAGICS`/`_DOMSEP`/`_ORGANS`, `CONFORMANCE_CAP_VECTORS`), and the agent pulls the SAME git object via the tag, so they are byte-identical by construction. Committing a duplicate corpus file adds nothing (§5 R2).** `token=vectors=IN-CODE-CONSTS-BYTE-IDENTICAL-VIA-TAG-NO-SEPARATE-CORPUS`.

### 3.5 STEP 1 — create the agent repo, history-preserving

From a FRESH full clone of `cogitave/yuva` (NOT this Windows-.git-pointer worktree — see §5 risk): `pip install git-filter-repo`, then into a scratch clone:

```
git filter-repo \
  --path tools/conductor-host --path tools/infer-daemon \
  --path tools/xport-core --path tools/xport-harness \
  --path-rename tools/:
```

This yields a repo containing only those four trees WITH their commit history. Then `gh repo create cogitave/cogi --private` (via the bahadirarda-authenticated `gh`), add it as remote, push. (GitHub Docs recommends `filter-repo` over `git subtree split`, which loses pre-move history and is materially slower.) **Before running: audit `infer-daemon/models/stories260K.gguf` and the vendored llama.cpp under `llama-engine-sys/` for LFS pointers, so `filter-repo` does not sever them (§5 R8).**

### 3.6 STEP 2 — wire the agent build STANDALONE against the contract

In `cogitave/cogi`: add a workspace `Cargo.toml`; in EACH moved tool rewrite `tb-encode = { path = … }` → the git-tag dep (§3.1). The relative intra-agent paths SURVIVE (`infer-daemon`'s `xport-core = { path = "../xport-core" }` and `llama-engine-sys = { path = "llama-engine-sys" }` moved together). Run `cargo build` + each tool's tests. For `infer-daemon` specifically, the first agent-CI build is a native/toolchain rebuild (C toolchain for `llama-engine-sys`, engine/seccomp/landlock features), not a trivial recompile — budget for it (§2.1). Run `cargo test -p tb-encode` (pulled via git) to execute the `abi_snapshot` cross-check INSIDE the agent's own CI — **HONEST SCOPE: this only re-validates `tb-encode`'s INTERNAL well-formedness on an identical git checkout; it CANNOT detect a forked/relaxed LIVE seam, because the live-seam detector (`abi_registry_selfcheck`) lives in `tb-hal`/kernel and does not travel. Genuine cross-repo drift detection is DoD-5's booted-image lane (§3.9, §5 R2), not this near-tautological re-check.**

### 3.7 STEP 3 — the DUAL-HOMED green window (keep BOTH repos green BEFORE cutting)

Do NOT delete from Yuva yet. Yuva still builds all four tools from `tools/` and its `conductor-host.yml`/`real-infer` lanes stay green; the agent builds them from its own tree. This is the "move behind the ABI while Yuva still vendors a copy" phase. Verify: Yuva `scripts/run-x86_64.sh` boot is BYTE-IDENTICAL (the resident spine, M12 socket, in-kernel M38 selftest, mini-agent all untouched — nothing moved was in the kernel link graph). `token=green-discipline=DUAL-HOME-THEN-CUT`.

### 3.8 STEP 4 — THE CUT (atomic with CI relocation, tradeoff chosen at §8 veto-7)

`git rm -r tools/conductor-host tools/infer-daemon tools/xport-core tools/xport-harness` in Yuva (KEEP `tools/prov-signer`). Update Yuva's root `Cargo.toml` `exclude=[…]` list (drop the removed nested-workspace entries). **RELOCATE the CI atomically, per the operator's veto-7 choice between the two NAMED-COST options (§2.5):** move `conductor-host.yml` + `conductor-m18neg.yml` + `real-infer.yml` + `m32-local-infer.yml` + `abi-conformance.yml` + their driver scripts to `cogitave/cogi` (Option A — Yuva loses its cross-process anti-hollow proof, keeps only its in-kernel marker), OR pin the agent back into Yuva as a git dep/submodule so Yuva's M38 cross-process adjudication lane can still spawn the host conductor (Option B — accepts a circular agent↔yuva dependency). Do whichever IN the same change as the `rm`, or a Yuva lane goes red (§5, highest risk). Re-run `check-agent-neutral.sh` (the `live.rs` exception is gone from Yuva, tightening the lint) and `empty-diff-proof.sh` (the LOCAL two-repo baseline tool, in no CI workflow — honest scope) to certify the default agent-profile boot stream is byte-identical.

### 3.9 STEP 5 — prove the two-repo contract holds (DoD-5 is the REAL drift detector)

In the agent: (a) a lane that runs the in-code `abi_snapshot` vectors — a NECESSARY-BUT-WEAK internal-well-formedness check, NOT a live-seam detector; (b) **the load-bearing lane: an integration lane that boots a PINNED Yuva image (release artifact from the `yuva-abi-v1.0.0` tag) under QEMU and runs the REAL `backend-yuva` end-to-end — this is the SOVEREIGN binding AND the genuine cross-repo drift tripwire, because it exercises the actual live seam a forked/relaxed Yuva would betray;** (c) `backend-generic` builds but is marked spec-only, with the token-discipline lint pinning `SPEC-ONLY/SURRENDERED-BY-CONSTRUCTION` wording so it cannot silently flip to REAL. Yuva keeps the in-kernel `caps::abi_registry_selfcheck` (Plane-1 half) reddening every boot on drift — the agent trusts that leg (§5 R2, honest asymmetry). Re-measure and re-pin `EXPECTED_HARNESSES_TOTAL` in `scripts/kani-shards.sh` if any Kani surface moved (**it does not** — the harnesses stay in `tb-encode/proofs.rs`, which stays in Yuva; the pin lives in `scripts/kani-shards.sh:75`, also Yuva-side). `token=kani-pin=UNMOVED`, `real-drift-detector=DoD5-BOOTED-PINNED-IMAGE-NOT-AGENT-LOCAL-VECTOR-RECHECK`.

### 3.10 Recommended sequencing — INCREMENTAL, not big-bang (an operator veto point, §8)

The `filter-repo` in §3.5 lifts all four tools at once. Two strands recommend, and this plan concurs, that the *dep-rewrite + CI-relocation + cut* proceed INCREMENTALLY: **`conductor-host` FIRST** (452 lines, offline, genuinely one dep line — the provably-cleanest island), prove the cross-repo conformance lane green, THEN the `xport-core` + `xport-harness` transport-peer pair (xport-core is their shared dep, so they batch), and LAST `infer-daemon` — deliberately last because it is the non-trivial native tail (vendored llama.cpp, GGUF artifact, host-only feature deps) and deserves its own green window rather than being bundled into a clean-tool PR (§2.1). Incremental contains the blast radius to provably-clean host binaries first and isolates the native rebuild. `token=sequencing=INCREMENTAL-CONDUCTOR-FIRST-INFER-DAEMON-LAST-NOT-BIG-BANG`.

---

## 4. HONEST SCOPE — what this plan IS, and the seven things it is NOT

**This document IS:** the extraction PLAN the operator reviews and then EXECUTES across the repo boundary — the movable surface (§2), the repo structure + versioned-dependency mechanism + green-preserving sequence (§3), the risk register (§5), the DoD (§7), the veto points (§8). `token=extraction=PLAN-NOT-EXECUTED`.

**This document is NOT (each named so it cannot creep in):**

- **NOT the execution.** Creating `cogitave/cogi`, running `filter-repo`, and pushing are the operator's cross-repo actions. This plan de-risks and sequences them; it performs none of them here.
- **NOT the resident cut.** The RESIDENT in-kernel agent (M12 socket + in-kernel M38 conductor + mini-agent) STAYS in Yuva, blocked by EL0-trap-gate + `mem/`-factorization. What extracts is the HOST-SIDE binaries. `token=scope=HOST-SIDE-BINARIES-ONLY-RESIDENT-STAYS`.
- **NOT a uniformly one-line move.** Three tools are a rename + one-line dep rewrite over already-isolated nested workspaces; `infer-daemon` is a NON-TRIVIAL native tail (vendored llama.cpp, GGUF artifact, host toolchain rebuild). `token=move=THREE-ONE-LINE-ONE-NATIVE-TAIL`.
- **NOT a code untangle.** The untangle was the three landed milestones. This is a rename + dep rewrite over already-isolated nested workspaces (with the `infer-daemon` native caveat above).
- **NOT building the generic-host backend.** The `backend-yuva` (sovereign) binding is real in-repo and predicted-to-survive; `backend-generic` is a SPEC-ONLY skeleton. Moving code builds no runtime. `token=generic-host=SPEC-ONLY`.
- **NOT a runtime version gate.** The version token is `DISCOVERY-ONLY-LABEL-NOT-A-GATE` at stage A; nothing rejects a mismatched pin at runtime (§5, version-pin-drift). Negotiation/GATING is deferred.
- **NOT a `tb-encode` (or `brand`) split.** The thin published `yuva-abi` facade — and the `brand` publish-or-inline it forces — is stage B; at stage A the agent pins the WHOLE `tb-encode` by git tag and `brand` rides along transparently.

---

## 5. RISK REGISTER — what must be true, the risks, the de-risking

**What must be TRUE before the trigger (mostly DONE):** (a) the ABI is frozen — **DONE** (`abi.rs` cap-plane `(1,0)`/wire `1`, enforced by `abi_registry_selfcheck`); (b) the profiles prove separation — **DONE** (`run-substrate-x86_64.sh` negative census); (c) the terminology is neutral in code — **DONE** (last `Cogi` in the moving `live.rs` fixture); (d) the drift-detection story is understood — **CLARIFIED (not a new artifact)**: the frozen vectors are in-code consts pulled byte-identically via the tag, so genuine cross-repo drift detection is the DoD-5 booted-pinned-image lane, NOT a duplicated corpus and NOT the agent-local `abi_snapshot` re-check; (e) the `tb-encode` dependency mechanism is chosen (git-tag) — **decided (§3.1)**.

| # | Risk | Severity | De-risking |
|---|---|---|---|
| R1 | **CI-continuity + anti-hollow-proof tradeoff** — Yuva's `conductor-host.yml`/`real-infer`/`m32-local-infer` lanes BUILD the moved tools; the M38 anti-hollow leg (`conductor-adjudicate.sh`) needs a SECOND process. After the cut, EITHER Yuva loses that cross-process proof (Option A) OR a circular agent↔yuva dep appears (Option B) — §2.5 | **highest** | relocate those lanes to the agent repo (Option A, Yuva keeps only its in-kernel marker) OR pin the agent back into Yuva (Option B, circular) — ATOMICALLY with the `git rm` (§3.8); operator picks the tradeoff at veto-7 with BOTH costs named |
| R2 | **Shared-codec / shared-leaf drift — and the WEAK agent-local check** — `tb-encode` is linked by BOTH the kernel and every moved binary; the in-kernel drift detector (`abi_registry_selfcheck`) does NOT travel; a stale/forked agent pin drifts silently. The agent-local `abi_snapshot` vector re-check is NEAR-TAUTOLOGICAL (same git object, internal well-formedness only) and CANNOT see a forked live seam | high | the git-TAG pin (not floating branch/path) keeps the contract immutable per agent revision; **the genuine tripwire is DoD-5's lane that BOOTS a pinned Yuva image and runs the real `backend-yuva` against the actual live seam** — NOT a committed corpus, NOT the agent-local re-check |
| R3 | **Seam-that-reaches-into-Yuva** — the `RetrievalOverMemory` organ is the kernel's BM25 recall in `tb-hal/src/mem/`, no_std, not host-buildable; the moved conductor runs MOCK organs; a reviewer could mistake the clean dep for "the whole spine is extractable" | high | name it: only the DECISION half extracts; the RETRIEVAL organ body stays welded until `mem/` factorization (stage B) |
| R4 | **EL0-trap-gate unbuilt** — no privilege boundary, so the moved artifact is a HOST-SIDE Plane-2 wire peer, not a sovereign in-VM guest | high | conformance-ceiling=SPEAKABILITY-BY-IN-PROCESS-CODE-NOT-EXTRACTABILITY stated across the repo boundary; the resident cut is a named successor |
| R5 | **Git environment** — prior notes flag WSL/Windows `.git`-pointer breakage in worktrees; a `filter-repo` on the wrong checkout silently drops history | high | `filter-repo` MUST run from a FRESH FULL clone, not this worktree; pushes via the bahadirarda-authenticated `gh` |
| R6 | **Honesty regression** — once in a backend-swappable, environment-adaptive agent repo, standing temptation to BUILD `backend-generic` and flip `generic-host=SPEC-ONLY → REAL` without naming the sovereignty surrender | medium | the token-discipline lint (like `check-agent-neutral.sh`) travels to the agent repo and pins the `SPEC-ONLY/SURRENDERED-BY-CONSTRUCTION` wording |
| R7 | **Version-pin drift** — a `cap_major` (breaking) Yuva bump with a stale agent pin = silent incompatibility; there is NO runtime GATE at stage A (`version-token=DISCOVERY-ONLY-LABEL`) | medium | cross-repo contract-bump protocol in BOTH `CONTRIBUTING`: any registered-surface change bumps `abi.rs` AND requires the agent to bump its pin + re-run the DoD-5 booted-image lane; acceptable at stage A (one version), a real hazard once a second wire version exists → GATING is the stage-B fix |
| R8 | **Large/native/binary artifacts (infer-daemon)** — `infer-daemon/models/stories260K.gguf` is committed (small, fine), and the vendored llama.cpp under `llama-engine-sys/` makes the move a native/toolchain rebuild; a future real GGUF or LFS-tracked blobs could bloat/sever filtered history | low→medium | audit for LFS BEFORE `filter-repo` so pointers aren't broken; sequence `infer-daemon` LAST (§3.10) with its own green window for the C-toolchain rebuild |
| R9 | **prov-signer placement** — it holds the M33 private key host-side; an unconsidered move could split the signer from the in-kernel verifier (`provhead.rs`, stays) | low | prov-signer STAYS Yuva-side; verify the signer's output is still validated by the retained kernel-side verifier after the move |
| R10 | **Marker-chain survival** | LOW (verify, don't assume) | the 100+ cumulative markers + both-arch boot live entirely in `kernel/` + `scripts/` which STAY; nothing marker-bearing moves — VERIFY byte-identity at STEP 4, do not assume |

---

## 6. Honest tokens (the complete vocabulary)

- `extraction=PLAN-NOT-EXECUTED` — this is the design doc the operator reviews; creating `cogitave/cogi` + the physical git move + the push are the operator's cross-repo actions.
- `scope=HOST-SIDE-BINARIES-ONLY` (`conductor-host` + `infer-daemon` + `xport-core` + `xport-harness`); `RESIDENT-IN-KERNEL-AGENT-STAYS`.
- `moves=CONDUCTOR-SIDE-HOST-EXECUTOR` / `stays=ORGAN-HOST-SIDE-KERNEL` — split-the-spine-not-the-embryo, literal; `spine=TWO-HALVES` (`conductor-MATH=SHARED-CONTRACT-STAYS-IN-TB-ENCODE` / `conductor-HOST=MOVES`).
- `positioning=TOOL-LEVEL-DEP-CLEAN-BUT-TB-ENCODE-DEPS-BRAND` — each tool own `Cargo.lock`, path-deps `tb-encode` alone AT THE TOOL BOUNDARY; but `tb-encode` itself path-deps + code-uses `crates/brand`. Extraction is a rename + dep-rewrite for three tools, a native rebuild for `infer-daemon`.
- `move=THREE-ONE-LINE-ONE-NATIVE-TAIL` — `conductor-host`/`xport-core`/`xport-harness` are one-line dep rewrites; `infer-daemon=VENDORED-NATIVE-TAIL-NOT-ONE-LINE` (llama.cpp + GGUF + host feature deps = fresh-CI toolchain rebuild).
- `contract=TB-ENCODE-IS-THE-SHARED-CRATE-TODAY`; `dep=GIT-TAG==YUVA_ABI_VERSION` at stage A → `PUBLISHED-THIN-yuva-abi` at stage B; `brand=STAGE-A-TRANSPARENT / STAGE-B-PUBLISH-OR-INLINE`.
- `sovereign-binding=REAL-IN-REPO-TODAY / CROSS-REPO-BINDING-UNPROVEN-UNTIL-DoD-5` (moved host binaries ↔ still-in-Yuva kernel over Plane-2 wire — real today, PREDICTED to survive the split, PROVEN only by the booted-pinned-image lane) / `generic-host-backend=SPEC-ONLY-SKELETON` (same schemas, POSIX transport, no kernel, sovereignty surrendered).
- `blockers-unchanged=EL0-TRAP-GATE-UNBUILT(caps.rs:240,249 region) + MEM-FACTORIZATION(tb-hal/src/mem/)` — these gate the RESIDENT cut, NOT the host-binary extraction.
- `conformance-asymmetry=WIRE+ORGAN-HALF-INTERNALLY-CHECKABLE-IN-AGENT(abi_snapshot, WELL-FORMEDNESS-ONLY) / CAPS-HALF-TRUSTS-YUVA-BOOT(abi_registry_selfcheck in tb-hal, not shipped)`; `cross-repo-drift-tripwire=DoD5-BOOTED-PINNED-IMAGE-NOT-A-COMMITTED-CORPUS-NOT-AGENT-LOCAL-RECHECK`.
- `vectors=IN-CODE-CONSTS-IN-abi.rs-BYTE-IDENTICAL-VIA-TAG` — no standalone corpus file; duplicating one is redundant.
- `cogi-residue=RIDES-OUT-WITH-XPORT-HARNESS(live.rs greeting, ~:993/996/1040/1045/1054/1056 + :1378-1398)` — its correct home is the agent identity, not Yuva; the code already annotates the terminology fix at `:996,1045`.
- `prov-signer=STAYS-YUVA` (M33 signing key = Yuva provenance-sovereignty leg, not an agent organ).
- `green-discipline=DUAL-HOME-THEN-CUT`; `sequencing=INCREMENTAL-CONDUCTOR-FIRST-INFER-DAEMON-LAST-NOT-BIG-BANG`.
- `ci-relocation=A-YUVA-LOSES-CROSS-PROCESS-ANTI-HOLLOW-PROOF / B-CIRCULAR-DEP / OR-ACCEPT-A-AS-HONEST-END-STATE` — the cut's named tradeoff.
- `version-gate=ABSENT-AT-STAGE-A` — nothing rejects a mismatched pin; a `cap_major` bump with a stale pin is a silent-incompat risk.
- `kani-pin=UNMOVED` — the 122 harnesses live in `tb-encode/proofs.rs` (stays) and the pin `EXPECTED_HARNESSES_TOTAL=122` lives in `scripts/kani-shards.sh:75` (also stays); untouched by the host-tool move.
- `conformance-ceiling=SPEAKABILITY-BY-IN-PROCESS-CODE-NOT-EXTRACTABILITY` (the moved artifact binds Plane-2/wire only, not Plane-1/sovereign-guest).
- `precedent-map=FILTER-REPO(history)/CARGO-PATH→GIT→PUBLISHED/WASI-WIT(versioned interface)/FIRECRACKER-SEMVER`.

---

## 7. DoD — committed proof obligations (of the EXECUTED extraction, when the operator runs it)

- **DoD-1 — the contract anchor.** `tb-encode` bumped to `1.0.0` mirroring `YUVA_ABI_VERSION`; `git tag yuva-abi-v1.0.0` on `089f03b`; Yuva both-arch boot + `abi_registry_selfcheck` + `abi-conformance` green at the tag. `token=dod1=CONTRACT-TAGGED`.
- **DoD-2 — the agent repo builds standalone against the frozen contract.** `cogitave/cogi` created history-preserving (`filter-repo`, LFS-audited); each tool's `tb-encode` dep rewritten to the git-tag (`brand` resolving transparently in the tag checkout); `cargo build` + tests green INCLUDING the `infer-daemon` native/toolchain rebuild; `cargo test -p tb-encode` runs `abi_snapshot` as an INTERNAL well-formedness check (explicitly NOT a live-seam drift detector — see DoD-5). `token=dod2=AGENT-BUILDS-STANDALONE-INCL-NATIVE-TAIL`.
- **DoD-3 — the dual-homed green window.** Both repos green simultaneously BEFORE any deletion; Yuva `run-x86_64.sh` byte-identical. `token=dod3=DUAL-HOME-BOTH-GREEN`.
- **DoD-4 — the cut + atomic CI relocation (tradeoff chosen).** The four tools `git rm`-ed from Yuva (prov-signer kept); `exclude=[…]` pruned; the agent-attributable lanes relocated (Option A) OR the agent pinned back (Option B) per veto-7 — atomically, no red Yuva lane; the chosen option's named cost (§2.5) recorded in the PR. `token=dod4=CUT-WITH-CI-RELOCATED-ATOMIC-TRADEOFF-RECORDED`.
- **DoD-5 — the two-repo contract PROVEN by a booted pinned image (the real drift detector) + prov-signer binding intact.** The agent runs a QEMU integration lane that BOOTS a PINNED Yuva image (release artifact from `yuva-abi-v1.0.0`) and exercises the REAL `backend-yuva` sovereign binding end-to-end — this is what PROVES the cross-repo binding survives the split and is the genuine live-seam drift tripwire (the agent-local `abi_snapshot` re-check does NOT suffice); `backend-generic` builds spec-only with the token lint; the retained kernel-side `provhead.rs` verifier still validates `prov-signer` output. `token=dod5=SOVEREIGN-BINDING-PROVEN-BY-BOOTED-IMAGE+PROV-SIGNER-VERIFIED`.
- **DoD-6 — invariants untouched.** Yuva cumulative M0..M38 chain byte-identical on both arches; `EXPECTED_HARNESSES_TOTAL=122` in `scripts/kani-shards.sh:75` untouched (harnesses stay in `tb-encode/proofs.rs`); `check-agent-neutral.sh` tightened (the `live.rs` exception gone from Yuva). `token=dod6=MARKER-CHAIN+KANI-PIN-UNTOUCHED`.

Evidence is these committed builds + lanes across two repos, honestly NOT (beyond the unchanged existing surface) new Kani proofs.

---

## 8. Operator VETO POINTS (explicit)

1. **Create `cogitave/cogi` at all, and its visibility (`--private`) + the authenticated `gh` account (bahadirarda).** The repo does not exist; its creation is the operator's GitHub action. VETO/GO.
2. **Big-bang vs INCREMENTAL sequencing (§3.10).** This plan RECOMMENDS incremental (`conductor-host` first, then the `xport-*` pair, then `infer-daemon` LAST for its native rebuild). The operator may elect big-bang (all four in one PR) — accepting the larger blast radius and the native rebuild folded into a clean-tool PR. VETO the recommendation or confirm.
3. **What moves — specifically `prov-signer`.** This plan KEEPS `prov-signer` in Yuva (provenance-sovereignty leg). The operator may judge the SIGNING act agent-authored and move it — but must then keep the signer's output validated by the retained kernel verifier. VETO/GO on prov-signer placement.
4. **The `tb-encode` dependency mechanism.** This plan chooses a git-TAG pin (stage A). The operator may instead publish `tb-encode` (and its `brand` dep) to crates.io immediately (real semver, heavier, forces the `brand` publish-or-inline early). Confirm git-tag or elect publish.
5. **The `live.rs` `Cogi` greeting fixture's fate.** It rides out with `xport-harness` to the agent's identity. The operator may instead neutralize it. Confirm ride-out.
6. **Repo restructure (§3.2) — flat tool move vs the `agent-core/abi-client/backend-*` shape.** Optional-but-recommended; the operator may keep the flat `tools/`-style layout at stage A and restructure later. Confirm.
7. **CI relocation strategy at the cut (§2.5, §3.8) — Option A (relocate the lanes to `cogitave/cogi`; Yuva LOSES its M38 cross-process anti-hollow proof, keeps only its in-kernel marker) vs Option B (pin the agent back into Yuva as a git dep/submodule for the cross-process adjudication leg; accepts a CIRCULAR agent↔yuva dependency).** BOTH costs are now on the table; a third stance is to accept Option A's loss as the honest post-split end-state. Pick one; both keep Yuva green at the cut.

---

## 9. Named deferrals (stage B and beyond — explicitly NOT blocked on)

- **The thin published `yuva-abi` facade — and its `brand` obligation.** Split the speakable surface out of `tb-encode` and publish it, so the agent stops pinning silicon math it never calls. **This is NOT free: the facade surface (`abi.rs` + speakable leaves) calls `brand::MAGIC_*`/`DOMSEP_*`, so publishing the facade REQUIRES also publishing `crates/brand` (small, consts-only — cheap) OR inlining `brand`'s consts into the facade at publish time with a drift guard back to `crates/brand` (§2.4).** `token=facade=STAGE-B-DECOUPLING-REQUIRES-BRAND-PUBLISH-OR-INLINE`.
- **Runtime version GATING** — offer/accept/reject negotiation so a mismatched pin is REJECTED at runtime (today `version-token=DISCOVERY-ONLY-LABEL-NOT-A-GATE`). `token=gating=DEFERRED`.
- **The RESIDENT in-kernel cut** — blocked by BOTH the EL0 trap gate (a separately-privileged agent binding at Plane 1) AND the `mem/` engine↔organ factorization (the `RetrievalOverMemory` organ becomes host-buildable). Only after BOTH land can the embryo move. `token=resident-cut=BLOCKED-BY-EL0+MEM`.
- **The `backend-generic` runtime** — building the real degraded POSIX transport (sovereignty surrendered by construction). `token=backends=DEFERRED`.

---

## 10. Relationship to boot-profiles + Yuva-ABI — the three siblings, composed

boot-profiles, Yuva-ABI, and this extraction plan are the three steps of the 2026-07-08 directive, composing without overlap:

- **boot-profiles decides WHICH side runs** (`yuva.profile=substrate|agent`; negative census). Landed.
- **Yuva-ABI decides HOW the two sides talk** (the versioned two-plane contract; positive mini-agent conformance). Landed.
- **This extraction decides WHERE the agent side physically lives** (the repo split + code move). This plan.

Shared seams, non-conflicting: all three name the M12 hosting socket + the M18.1 admission gate. Shared blockers: the `mem/` factorization + the EL0 trap gate — which gate the RESIDENT cut in ALL three. The split-the-spine discipline governs every step: boot-profiles gates the spine's organs, Yuva-ABI versions the spine's seams, and the extraction moves the spine's HOST HALF while the spine's MATH (the shared contract) and the embryo (the resident agent) stay. `token=siblings=PROFILES-WHICH / ABI-HOW / EXTRACTION-WHERE`.

---

## 11. Honest caveats (conceded — encoded as tokens)

- **The extracted artifact is a HOST-SIDE wire peer, not a sovereignly-hosted in-VM agent.** The EL0 trap gate is unbuilt, so post-extraction the moved binaries bind only over Plane 2 (serial-frame) to a still-in-Yuva kernel. `token=conformance-ceiling=SPEAKABILITY-NOT-EXTRACTABILITY`.
- **The sovereign binding is REAL in-repo TODAY but its survival across the split is PREDICTED, not proven, until DoD-5.** The moved-binary↔pinned-image binding is an expected-and-to-be-proven state; DoD-5's booted-image lane is what certifies it. `token=sovereign-binding=REAL-IN-REPO-TODAY/CROSS-REPO-UNPROVEN-UNTIL-DoD-5`.
- **`infer-daemon`'s move is a native/toolchain rebuild, not a one-line rewrite.** The vendored llama.cpp `llama-engine-sys` member + GGUF artifact + host feature deps make it the non-trivial tail; only the other three tools are one-line moves. `token=move=THREE-ONE-LINE-ONE-NATIVE-TAIL`.
- **The moved conductor's `RetrievalOverMemory` organ stays a MOCK** until the `mem/` factorization lands; the real BM25 recall is welded to the kernel. `token=moved-organs=MOCK-UNTIL-MEM-FACTORED`.
- **The agent CANNOT independently detect a forked live seam.** Its `abi_snapshot` vector re-check is internal-well-formedness only (same git object); it TRUSTS Yuva's in-kernel `abi_registry_selfcheck` for the capability plane, and the ONLY genuine cross-repo drift tripwire is DoD-5's booted-pinned-image lane. A malicious/forked Yuva could relax a right and the agent-local re-check would not catch it. `token=conformance-asymmetry=CAPS-HALF-TRUSTS-YUVA-BOOT / DRIFT-CAUGHT-ONLY-BY-BOOTED-IMAGE`.
- **The CI relocation at the cut is not a free copy.** It either strips Yuva of its cross-process anti-hollow proof (Option A) or introduces a circular agent↔yuva dependency (Option B). `token=ci-relocation=A-LOSES-PROOF/B-CIRCULAR`.
- **Nothing rejects a mismatched pin at runtime at stage A** — a `cap_major` bump with a stale agent pin is a silent incompatibility until the agent manually bumps; GATING is deferred. `token=version-gate=ABSENT-AT-STAGE-A`.
- **This is the PLAN, not the execution.** The clean-embryo cut is NOT claimed; what extracts is the host-side organ/orchestration/reasoning binaries. `token=extraction=PLAN-NOT-EXECUTED`.

---

## 12. References

- **In-tree, verified against the working tree (2026-07-08, `origin/main 089f03b`):**
  - `Cargo.toml:47` — `exclude = ["tb-vmm", "tools/xport-harness", "tools/prov-signer"]`; `conductor-host`/`infer-daemon`/`xport-core` auto-excluded as nested `[workspace]` islands. Proves the four host tools are already isolated workspaces; the CUT edits this `exclude` list and they leave the root graph cleanly.
  - `crates/tb-encode/Cargo.toml:41` — `brand = { path = "../brand" }` (with the `:37` note that "zero deps" means zero EXTERNAL deps). Proves `tb-encode` is NOT a leaf; the `brand` coupling is transparent at stage A, load-bearing at the stage-B facade (§2.4, §9).
  - `crates/tb-encode/src/{abi.rs,inferwire.rs,attest.rs,opframe.rs,opframe_rx.rs}` — hard uses of `brand::MAGIC_*`/`DOMSEP_*` (`abi.rs` wire-magic asserts among them). The concrete `brand`-usage surface the facade must carry.
  - `tools/conductor-host/Cargo.toml` — the M38 host executor, self-contained nested workspace, path-deps `tb-encode` ALONE; the cleanest, genuinely one-line first move.
  - `tools/infer-daemon/Cargo.toml` (+ `llama-engine-sys/` vendored-native member, `models/stories260K.gguf`) — the M32 reasoning-organ daemon; deps `xport-core` + `tb-encode` + optional host deps (engine/seccomp/landlock); carries `SOVEREIGNTY-OPEN-B3`; the NON-TRIVIAL native tail (§2.1).
  - `tools/xport-core/Cargo.toml` — the dep-clean `FrameAccum` serve-glue carrying `tb-encode` alone; the abi-client / backend-yuva transport layer.
  - `tools/xport-harness/Cargo.toml` + `tools/xport-harness/src/live.rs` (the greeting/historical-reply consts + envelope tests around `:993,996,1040,1045,1054,1056` and `:1378-1398`; the terminology-fix annotations at `:996,1045` already state "Cogi is now the identity of the separate cogitave/cogi project") — the M30/M31 transport peer + Anthropic live bridge + the LAST `Cogi` greeting fixture.
  - `crates/tb-encode/src/conductor.rs:7-10` — "ALL network/model/float execution stays HOST-SIDE (the `tools/conductor-host` binary); this leaf is the decidable DECISION ALGEBRA" — the two-halves-of-the-spine finding and the one-line-rewrite move; the leaf reuses the M22 `prov` fold (`:55-59`).
  - `crates/tb-encode/src/abi.rs` (`YUVA_ABI_VERSION`, `FROZEN_METHODS`, `FROZEN_WIRE_MAGICS`, `CONFORMANCE_CAP_VECTORS`, `abi_snapshot` test) — the frozen contract + version token that becomes the pinned dependency anchor; the in-code consts (NOT a separate corpus) the agent pulls byte-identically via the tag; the wire/organ half the agent can self-check for INTERNAL well-formedness only.
  - `crates/tb-encode/src/proofs.rs` — the 122 Kani harnesses (the proof surface that STAYS); the pin that guards their count is `scripts/kani-shards.sh:75` `EXPECTED_HARNESSES_TOTAL=122`, NOT a constant in `proofs.rs` — both stay Yuva-side, so `kani-pin=UNMOVED`.
  - `crates/tb-hal/src/caps.rs` (`abi_registry_selfcheck` in-kernel drift detector; the M11 dispatch chokepoint + `set_cognitive_deny`; the future EL0-syscall-gate seam in the `M_BLOCK_MAP` region ~`:240,249`, an approximate anchor) — the Plane-1 ABI-server implementation that STAYS in Yuva + the EL0-trap-gate blocker + the reason the agent cannot self-detect live-seam drift.
  - `crates/tb-hal/src/mem/{mod.rs,selftests.rs}` — the M13 retrieval organ + M20 storage engine cohabiting unfactored; the `RetrievalOverMemory`-welded-to-kernel seam and the shared cut blocker.
  - `kernel/src/main.rs` (M12 socket `:1368-1549`, in-kernel mini-agent `:1469-1522`, in-kernel M38 conductor `:5280-5568`, the `M38: conductor OK …` marker `:5551`) — the resident spine + hosting socket that CANNOT extract at stage A + the in-kernel marker that survives Option-A relocation.
  - `scripts/conductor-adjudicate.sh` — the M38 anti-hollow leg that asserts in-kernel-head == host-conductor-head (needs a SECOND process); the CI-relocation tradeoff source (§2.5).
  - `tools/prov-signer/` — the M33 host signer (Yuva's provenance-sovereignty leg); stays.
- **Sibling docs:** `docs/spec/yuva-abi-v1.md` (the normative contract, §2 planes / §7 SOVEREIGN|DEGRADED / §9 the two blockers; §-note that `EXPECTED_HARNESSES_TOTAL` is unchanged by registry work); `docs/proposals/yuva-abi.md` (rationale + the eight-seam inventory + the mini-agent conformance skeleton); `docs/proposals/boot-profiles.md` (§3.4 the `mem/` factorization landing-blocker; §4 the agent-attributable `tb-encode` leaf list; the negative-census separability proof; `:357` the `EXPECTED_HARNESSES_TOTAL=122` pin location in `scripts/kani-shards.sh:75`); `docs/research/cogi-cognitive-architecture.md` §2 (memory = substrate retrieval STORE; organs = agent-side composable capabilities — the moves-out/stays-in dividing line).
- **External precedents:** GitHub Docs, "Splitting a subfolder out into a new repository" + the Close.com `filter-repo`-vs-`subtree` writeup (history-preserving physical move, faster than subtree split which loses history); The Cargo Book, "Specifying Dependencies" (path vs git vs version; path-only crates cannot publish — the concrete dep-rewrite grounding AND the `brand` publish-or-inline constraint on the facade); WebAssembly component-model `WIT.md` + Bytecode Alliance WASI 0.2 (witx→WIT versioned interface package both host and component pin by semver — the model for `tb-encode`-as-versioned-contract + the future thin `yuva-abi` facade); Firecracker `docs/snapshotting/versioning.md` (independent SEMVER — the immutable-per-revision pin discipline).

---

## 13. Adversarial review

This section records the adversarial review this plan was hardened against, and where each finding is now discharged. Two independent reviewers returned **SOUND-WITH-AMENDMENTS**; every must_fix is applied and every overclaim neutralized with an honest token.

### 13.1 Must-fix items — applied

| # | Finding | Where discharged |
|---|---|---|
| MF-1 | **Unmentioned `tb-encode → brand` transitive dep.** The tools are dep-clean at the TOOL level, but `tb-encode` path-deps `crates/brand` and hard-uses `brand::MAGIC_*`/`DOMSEP_*` across `abi.rs`/`inferwire.rs`/`attest.rs`/`opframe.rs`/`opframe_rx.rs`. Transparent at stage A (whole-tree tag checkout); load-bearing at stage B — a published facade calling `brand::` cannot build off-repo unless `brand` is also published or inlined. | §2 preamble + §2.2 (`brand` STAYS) + §2.4 (transparent-vs-load-bearing) + §3.1 + §9 (facade requires brand publish-or-inline) + tokens §6 + References §12. |
| MF-2 | **Mischaracterized cross-repo drift tripwire.** The "frozen vectors committed identically in both repos" are in-code consts pulled byte-identically via the tag — no standalone corpus, the "promote to a cross-repo artifact" step is redundant. The agent-local `abi_snapshot` re-check is near-tautological (internal well-formedness on an identical checkout) and cannot see a forked live seam, because `abi_registry_selfcheck` stays in `tb-hal`/kernel. The REAL tripwire is DoD-5's booted-pinned-image lane. | §3.4 (no separate corpus) + §3.6 (agent-local check is well-formedness only) + §3.9 (DoD-5 is the real detector) + §5 R2 (rewritten) + DoD-5 (relabeled) + tokens §6 + §11. |
| MF-3 | **Unflagged CI-relocation tradeoff at the cut.** `conductor-adjudicate.sh`'s anti-hollow leg needs a SECOND process. Option A (relocate lanes) strips Yuva of its cross-process independent-recompute proof (only the in-kernel marker survives); Option B (pin agent back) creates a circular agent↔yuva dependency. The draft named both options but neither cost. | §2.5 (new subsection, both costs named + a third honest-end-state stance) + §3.8 + §5 R1 (rewritten) + DoD-4 + §8 veto-7 (rewritten) + tokens §6 + §11. |
| MF-4 | **Wrong `EXPECTED_HARNESSES_TOTAL=122` attribution** — it is in `scripts/kani-shards.sh:75`, not `proofs.rs` (which holds the 122 harnesses the script counts). `kani-pin=UNMOVED` still holds since both stay. | §2.2 + §3.9 + DoD-6 + tokens §6 (`kani-pin`) + References §12 (corrected citation). |
| MF-5 | **Qualify `sovereign-binding=REAL`** — REAL only IN-REPO TODAY; the cross-repo binding is forward-looking, proven only by DoD-5. Soften the Pillars "stays REAL" / "same binaries, same frames." | Pillars (restamped) + §3.3 (table + prose softened) + DoD-5 + tokens §6 + §11. |
| MF-6 | **Scope the "one-line dep rewrite per tool" headline** — TRUE for `conductor-host`, but `infer-daemon` carries vendored llama.cpp + a GGUF artifact + host-only feature deps, so its move is a fresh-CI native/toolchain rebuild. R8 undersold this as "low." | Pillars (three-one-line-one-native-tail) + §2.1 (`infer-daemon` tail) + §3.6 + §3.10 (sequenced LAST) + §4 + §5 R8 (raised to low→medium) + tokens §6 + §11. |

### 13.2 Overclaims — neutralized with honest tokens

- **"path-deps `tb-encode` ALONE / dep-clean"** → re-scoped to `positioning=TOOL-LEVEL-DEP-CLEAN-BUT-TB-ENCODE-DEPS-BRAND` (§2, §6). The purity claim is now explicitly about the tool boundary, with `brand` named.
- **"the sole cross-repo drift tripwire is the frozen conformance corpus"** → replaced by `cross-repo-drift-tripwire=DoD5-BOOTED-PINNED-IMAGE-NOT-A-COMMITTED-CORPUS-NOT-AGENT-LOCAL-RECHECK` (§3.9, §5 R2, §11). The corollary — that without the traveling selfcheck the agent-local check is near-tautological — is stated.
- **"rename + one-line dep rewrite per tool, proven green in BOTH repos"** → `move=THREE-ONE-LINE-ONE-NATIVE-TAIL`; the dual-home discipline (R1=highest, DoD-3/DoD-4) is retained as real, but the `infer-daemon` native rebuild and the non-free CI relocation are named.
- **"sovereign-binding=REAL / same binaries, same frames"** → `sovereign-binding=REAL-IN-REPO-TODAY/CROSS-REPO-BINDING-UNPROVEN-UNTIL-DoD-5` (Pillars, §3.3, §11).
- **Stale line citations** — corrected: the `live.rs` `Cogi` fixture is at the `:993/996/1040/1045/1054/1056` + `:1378-1398` region (not `:364/382/1378-1395`); the `caps.rs:240,249` EL0-gate anchor is labeled APPROXIMATE (the `M_BLOCK_MAP` future-EL0-syscall-gate region), not an exact pin; `EXPECTED_HARNESSES_TOTAL=122` is `scripts/kani-shards.sh:75`.

Both reviewers' verdict — **SOUND-WITH-AMENDMENTS** — is carried into this V2 as: the plan's core (mechanical host-binary move behind a frozen, versioned contract, dual-homed then cut, resident agent explicitly staying) survives; the amendments sharpen the dependency analysis (`brand`), the drift-detection story (booted image, not corpus), the CI tradeoff (named costs), and the honesty tokens (in-repo-today vs cross-repo-proven, three-clean-one-native).