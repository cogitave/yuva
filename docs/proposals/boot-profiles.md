---
type: Design Decision
title: "Boot Profiles — substrate vs agent execution gate"
description: "yuva.profile=substrate|agent runtime gate (default agent) skips/denies cognitive organs; stage A landed; stage-B compile-out of every main.rs organ block landed (PR-1..4), the PR-5 image-split product step stays operator-gated."
tags: ["boot-profiles", "substrate", "micro-vmm", "tcb", "agent-agnostic", "sovereignty"]
timestamp: 2026-07-08T02:31:19+03:00
status: active
diataxis: explanation
---

# Boot Profiles — substrate (plain micro-VMM core) vs agent (the full resident-agent stack), as a real execution gate, not a render filter

> **STAGE A LANDED (2026-07-08).** `yuva.profile=substrate|agent` (DEFAULT agent) is implemented as a real execution+admission gate: `kernel/src/profile.rs` (the `AtomicBool` selector + `agent_organs_enabled()` + the `emit_substrate_witness` DoD-3 exerciser), the `yuva.profile=` parse folded into `bootreport::apply_cmdline` (drives the profile latch + defaults the view), the ~18 gated `main.rs` blocks with string-equal-prefix skip forms, the M11 chokepoint denial in `tb_hal::caps::dispatch` (a `set_cognitive_deny` latch — the four cognitive families fail closed), the substrate-arm-only khash KAT (`tb_hal::khash_kat_selftest`), the bootreport M12 row split + profile-aware INFO/adjective-free tail, the `profile:` witness + `PROFILE: substrate OK` tail, `scripts/run-substrate-x86_64.sh` + `scripts/gen-witness-census.sh` + `scripts/witness-census.txt` + the `substrate-boot` ci.yml job. **VERIFIED:** the agent-default empty-byte-diff PASSES on the x86_64 host stream AND the decoded aarch64 guest stream (the M38 conduct head `0x066855300c57557b` unchanged); the substrate lane's positive core + intact skip chain + census-derived negative inversion + DoD-3 (`admission=DENIED-AT-CHOKEPOINT promotion=REFUSED-AT-GATE`, earned) + default-boot tripwire all pass. **DEVIATIONS from this V2 spec (proposal wins where it can; these are forced/superseded):** (1) **M18.2 held-out is ALSO gated** — the spec's explicit gated set (§2.3) predates the landed M18.2, which drives `M_MEM_WRITE_PROC` expecting `Ok` (same class as M18/M18.1) and would fail-exit under the §2.4 chokepoint denial; gating it is the same resolution §15-R1-1 applied. (2) **The agent-neutral rename lint already landed** as `scripts/check-agent-neutral.sh` (bans `Cogi` in `kernel/src`/`crates/`, intentionally exempts the `tools/xport-harness/src/live.rs` greeting semantic content) — so §1.5's residual (b)/(a) is satisfied by the existing lint, not re-done here. (3) **The census (§8.2c) includes `prov-sig:`** — M33's witness prefix, correctly agent-gated; the V2 hand list omitted it, and the generator derives it. (4) **DoD-3 (ii) promotion refusal** is exercised as a `M_MEM_WRITE_PROC` (the M18.1 skill-admission verb) dispatch asserted `Denied` at the chokepoint — the honest realization, since the M18.1 promotion write IS `M_MEM_WRITE_PROC`. Everything else follows the V2 spec.

> **STAGE-B PROOF-OF-CONCEPT LANDED (2026-07-09) — ONE ORGAN.** The compile-out MECHANISM (§11, §1.4 rung 3) is now proven end-to-end for exactly ONE organ, WITHOUT touching the other ~18. A kernel-crate-local Cargo feature `agent-organs` (DEFAULT-ON → every existing build/CI invocation byte-identical, SP#4 safe by construction) gates the M26 exit-telemetry `main.rs` block — BOTH the agent path AND the runtime substrate-skip `else` arm — behind `#[cfg(feature = "agent-organs")]`; `tb-encode`/`tb-hal` are untouched (the `exittel` leaf becomes unreferenced + DCE-eligible; the marker literals live only in the gated kernel block, so their image absence is by construction). A NEW additive lane (`scripts/run-compileout-poc-x86_64.sh` + the `compileout-poc-boot` ci.yml job, x86_64-only, 90s ceiling) builds `--no-default-features` and boots it under `yuva.profile=substrate`, asserting M26 is **ABSENT-BY-OMISSION** from BOTH the serial stream (no marker, no skip form, no `exittel:` witness) AND the compiled ELF (strict anchored byte-search), while the profile-scoped core RAN to the `PROFILE: substrate OK` tail and the neighbors M25/M28 stayed built in the stage-A skip form — the honest side-by-side contrast of rung-2 (skip form) vs rung-3 (absent-by-omission). Witness `bprof-poc: organ=M26-EXITTEL organs=NOT-BUILT scope=ONE-ORGAN-ONLY` — NO `tcb=`/minimal/secure/reduced claim (the other organs are STILL BUILT). The three required verifiers + the substrate lane + the census are ZERO lines changed. **STILL OPEN (full stage B):** every remaining organ + a measured image-size delta remain the named successor — the `mem/` engine/organ factorization itself LANDED separately as **#80** (`crates/tb-hal/src/mem/` split into `engine.rs` [substrate-side store] / `organ.rs` [agent-side organs], zero behavior change, verified line-multiset-conserving); this PoC proves only the mechanism, and full stage B lands as one reviewed, operator-gated product decision (§12).

> **STAGE-B COMPILE-OUT — EVERY main.rs ORGAN BLOCK LANDED (2026-07-10..12, PR-1..4).** The PoC's mechanism scaled to the whole kernel crate in four reviewed, 2×-green, SP#4-byte-identical steps: **#85 (PR-1)** the M20 persist untangle — `persist_selftest` moved ONTO the engine, driving `VirtioBlkStore`/`BackingStore` directly, `persist:` witness byte-identical; **#86 (PR-2)** the 14 SELF-CONTAINED organs (M13, M16, M17, M18, M18.1, M18.2 with its co-gated helper fn, M21-M24, M26, M33, M39, M40) each got the PoC's `#[cfg(feature = "agent-organs")]` on the whole `if/else`, and the lane became the table-driven `scripts/run-compileout-x86_64.sh`; **#87 (PR-3)** the M28/M29 ASYMMETRIC split — the one site where whole-gating would be WRONG (§3.3: khash is substrate-core): the M28 organ arm gates out while the M29 khash KAT hoisted to a standalone block guarded by a dual-cfg `let`, so with the feature OFF the KAT is unconditional and can never fall through a runtime check into absence; **#88 (PR-4)** the PIPELINE cluster (M25, M30, M31 both legs, M32-local, M38) via a contiguous data-flow span audit — the cross-block bindings (`m31_fold`, `m31_chan`, the M31 leg-1 tuple, the M32 tuple) co-gated with their producers/consumers, M38 gated by its OUTER statement only (the SP#4-computing interior untouched). The lane now asserts **20 organ families ABSENT** from stream AND ELF with witness `bprof: organs-not-built=20 scope=MAIN-RS-ORGAN-BLOCKS pipeline-organs=NONE-REMAINING` — deliberately scoped: it does NOT claim "zero agent code in the image" (tb-hal/tb-encode organ code may be linker-kept). **REMAINING (PR-5, the §12 operator gate):** the image-split product decision — the full-compile-out lane promotion, llvm-nm/objdump symbol-absence + measured size-delta, the `profile.rs` wire-witness `organs=NOT-BUILT` flip, census regeneration, and the explicit design choice (recommended: kernel-only gate + linker-DCE + post-link symbol verification; the alternative tb-hal/tb-encode mirrored features is strictly more coupling for no Kani benefit).

---


**Status:** **PROPOSAL V2 (research-first; nothing landed) — amended per two independent adversarial reviews, both SOUND-WITH-AMENDMENTS (§15). The named successor of industrial-boot §10 (`token=substrate-compile-out=DEFERRED`) and the first buildable step of the 2026-07-08 operator directive that `cogitave/yuva` (the OS) and `cogitave/cogi` (the agent) become SEPARATE projects, with Yuva AGENT-AGNOSTIC.** · **Pillars:** sovereignty (Yuva carries a **Firecracker-ALTERNATIVE core, profile-scoped** — kernel + capabilities + durable storage bootable alone with the agent organs honestly SKIPPED, not hidden; NOT claimed: that a stage-A substrate boot witnesses isolation or guest-running — the substrate lane is x86_64-only where there is no EL2, so hypervisor/guest evidence at stage A exists only on aarch64 agent lanes, `token=substrate-guest-evidence=AARCH64-AGENT-LANE-ONLY-AT-STAGE-A`) + honesty (the load-bearing distinction is made structural: the industrial-boot substrate VIEW is a pure RENDER FILTER whose own wording concedes "present in this build but HIDDEN" — a substrate PROFILE must actually NOT RUN and NOT ADMIT the cognitive organs; three wordings map 1:1 onto three mechanisms and are never swapped) + verification (ZERO CI regression by the DEFAULT-equals-today invariant — default profile is AGENT, no required lane passes a cmdline, proven by a landing-time empty-byte-diff on all three surfaces plus a per-run CI tripwire, `token=dod1=LOCAL-LANDING-PROOF+CI-TRIPWIRE` — plus a NEW additional substrate lane whose anti-hollow core is NEGATIVE greps proving the organs did not run) + separability (boot-profiles is the in-repo separability proof **at the EXECUTION/ADMISSION level** — organs provably not run and not admissible behind a pinned seam; CODE-level separability is proven only by stage B's symbol-absence check after the `mem/` engine/organ factorization, `token=separability=EXECUTION-ADMISSION-LEVEL-AT-STAGE-A`; it de-risks the future `cogitave/cogi` extraction and is NOT the extraction). · **Depends on:** the landed industrial-boot presentation layer (`kernel/src/bootreport.rs` — `View::Substrate` vs `View::Agent` at `:83-116`, `yuva.view=` parsed in `apply_cmdline` `:224-255`, the honest `"Cognitive subsystems present in this build but HIDDEN in the substrate view"` line `:375`), the aL2.4b in-guest acceptance-profile precedent (`TB_BOOT_FLAG_IN_GUEST = 1<<0`, `crates/tb-boot/src/lib.rs:106`; the `(no EL2, skipped)` lane-gated marker forms; the §2.6 strip-then-assert script discipline), the M18/M18.1 capability-admission gate (M18 evolve `kernel/src/main.rs:2788-2978`, M18.1 approval-gate `:2985-3147` — organs as opt-in capabilities), the x86 PVH cmdline channel (`tb_hal::boot_cmdline_x86`, `crates/tb-hal/src/lib.rs:882`; `main.rs:304-313` → `bootreport::apply_cmdline`), the frozen `TbBootInfo.cmdline_ptr/cmdline_len` fields (`tb-boot/src/lib.rs:300-320`, offsets 32/40), and the organ-composability position of `docs/research/cogi-cognitive-architecture.md` §2. · **Tasks:** the boot-profiles task closes at **stage A** (the runtime-gated profile + the substrate lane); stage B (genuine compile-out) and the extraction/ABI milestones are named successors, explicitly NOT blocked on. · **Markers (the M27/M31/M38 displacement discipline, extended):** the CI-required cumulative markers and witness lines are **NEVER removed, renamed, or reordered on the default (agent) profile** — every required lane boots the agent profile and sees a byte-identical stream, `M38: conductor OK turns=N organs=K verdict=ACCEPT` (`scripts/run-x86_64.sh:37`) staying the cumulative tail. Skip-form prefixes are **string-equal to the landed marker literals** (`M16: infer OK`, `M30: infer-transport OK` — never paraphrased; DoD-5 lints this mechanically). The substrate profile is an ADDITIONAL opt-in lane with its own tail marker `PROFILE: substrate OK` (not "substrate-vmm" — no stage-A substrate boot exercises EL2 or tb-vmm, both named deferrals); cross-lane non-impersonation is a LANE-level property carried by the required lanes' positive witness-line and pinned-tail guards, stated precisely in §2.3 — NOT a per-guard property, and NOT delegated to existing skip-reject regexes.

> **One-line:** Yuva today has only a presentation split — `yuva.view=substrate` hides the cognitive rows while `rust_main` runs every organ unconditionally. Boot Profiles adds `yuva.profile=substrate|agent` (DEFAULT **agent**, the state of every CI lane and the re-entrant EL1 guest, so the required chain is byte-identical): in the substrate profile the ~17 cognitive selftest blocks (M13 memory, M16/M17, **M18/M18.1 — the organ-exercising selftests, gated so the chokepoint denial cannot fail the boot; the admission MECHANISM itself stays**, M21-M26, M28, M30/M31 inference, M22/M33 provenance, M38 conductor) genuinely DO NOT RUN — each marker takes the lane-legitimate aL2.4b-grammar form `(substrate profile, agent organ skipped)` carrying no witness tokens — and the cognitive syscall families are DENIED at the M11 dispatch chokepoint, so organs are not merely unexercised but structurally NOT ADMITTED. What remains is the honest profile-scoped core: kernel (M0-M11), the agent-agnostic M12 hosting ABI, M14/M15 IPC, the M18 admission mechanism (kept as the deny gate — it IS the opt-in seam), L2.0-L2.6 + M27 hypervisor/scheduler, M19 virtio, M20 durable storage, M29 khash, aL2.4b, and tb-vmm. A NEW substrate CI lane positively requires the core chain + the exact skip forms, and NEGATIVELY asserts every agent witness family is ABSENT (a mechanically-derived census, §8.2c). Genuine compile-out (the only rung that may ever say "not present") is stage B, named and deferred.

This proposal is the convergent synthesis of three research strands (§References), which independently arrived at: the render-filter/execution-gate distinction as the load-bearing design question; DEFAULT=agent as the zero-CI-regression invariant; the substrate lane as additional-with-negative-greps; and a **two-stage honesty ladder** in which the strands' one real disagreement (runtime-gate-with-skip-forms vs compile-out-with-absent-markers) dissolves — the skip form is honest exactly while the code is still in the image (stage A), and absence-by-omission is honest exactly when it is not (stage B). Neither wording may borrow the other's stage. Two adversarial reviews then forced six amendments each; §15 records every must-fix and its resolution.

---

## 1. Why this feature, and why these choices

### 1.1 The gap: a view is not a profile — the real-TCB omission, razor-sharp

Industrial-boot stage A landed a **render filter**: `kernel/src/bootreport.rs` tags each row substrate-or-agent and the substrate view suppresses the cognitive rows. Its own comments are honest about this (`:83-85`: at stage A the organs run "unconditionally (§3.2), so substrate says 'HIDDEN in the substrate view'"), and the emitted line is `"Cognitive subsystems present in this build but HIDDEN in the substrate view"` (`:375`) — the adversarially-mandated wording (industrial-boot §3.2, V2-must-fix-3: "not present" would be *a pretty-boot-that-lies*, because the organs DID execute). Meanwhile `rust_main` (`kernel/src/main.rs`, ~5,900 lines) runs every cognitive selftest in one unconditional chain, through the landed M38 conductor at `:5057-5307`.

A **substrate PROFILE** is a different thing from a substrate VIEW, and the difference is enumerable in attacker-relevant state, not presentation:

| Runtime fact on a substrate boot | View (landed) | Profile (this proposal) |
|---|---|---|
| M30 serial-framed RX parser listening for input | YES (ran) | **NO — never instantiated** |
| M28 operator-command verifier key material derived, key-evolution state in RAM | YES | **NO — never derived** |
| Memory-organ state allocated and exercised (M13 tiers, M18 skill writes via `M_MEM_WRITE_PROC`) | YES | **NO — blocks gated, syscalls denied** |
| Cognitive M11 syscall families reachable | YES (Ok paths) | **NO — `SysStatus::Denied`, fail-closed** |
| Persistent cognitive side effects (provenance/experience/transcript folds; M33 signed-head sectors) | YES (written) | **NO — never written** |
| What changed vs the agent boot | render only | **execution + admission + live attack surface + persistent state** |

The view changes ZERO rows of this table. The profile changes every row — that is the real attack-surface/TCB claim a plain-VMM user is buying; hiding rows is not. What the profile does NOT change (stated with equal sharpness, §4): the image bytes, the shared unsafe/asm perimeter, and the hosting-ABI surface. `token=view=RENDER-FILTER / profile=EXECUTION-GATE — never conflated`.

### 1.2 Why now: the operator directive + the growing spine

The 2026-07-08 directive makes Yuva agent-agnostic and the agent a separate project. The full extraction (repo split, frozen Yuva↔agent ABI, pluggable backends) is heavy and NOT this proposal's scope (§11, §13). But M38 stage-B has **landed in-kernel** (`main.rs:5057-5307`; `run-x86_64.sh:37` pins `M38: conductor OK …` as the cumulative tail — note industrial-boot.md's "`grep -c M38 main.rs` = 0" claim is now **stale** and this landing corrects it in passing) — the conductor spine is on the boot wire, and every further milestone makes the eventual cut heavier. Boot Profiles marks the joint now: *split the spine, not the embryo*. The profile gate is the in-repo proof that the substrate/agent layers separate **at the execution/admission level** — organs provably not run and not admissible behind one pinned seam. It is NOT yet a code-level separability proof: §3.4 concedes the M20 storage engine and the M13 memory organ COHABITED `crates/tb-hal/src/mem/` unfactored — **now split** by **#80** into `engine.rs` (substrate-side store) / `organ.rs` (agent-side organs), zero behavior change — so code-level separability is earned only by stage B's symbol-absence check across every organ (the factorization prerequisite is satisfied; the check itself has run for only the one M26 organ, #81). The dependency audits (§3.4) are the first concrete extraction work products. `token=separation=IN-REPO-PROFILE-NOT-EXTRACTION`, `separability=EXECUTION-ADMISSION-LEVEL-AT-STAGE-A`, `agent-abi=NOT-DEFINED` (the gate documents the cut-line; it freezes no ABI).

> **Update (Yuva-ABI stage A landed):** the `agent-abi=NOT-DEFINED` token is now
> picked up by its sibling proposal — boot-profiles decides WHICH side runs, the
> Yuva-ABI contract (`docs/spec/yuva-abi-v1.md`, `crates/tb-encode/src/abi.rs`)
> decides HOW the two sides talk. The two share the M12 hosting socket + the
> M18.1 admission gate + the `mem/` factorization blocker; boot-profiles' NEGATIVE
> census (organs did not run) and the ABI's POSITIVE mini-agent conformance are
> complements. `agent-abi` is now `abi=IN-REPO-SPEC-AT-STAGE-A` (still
> `version-token=DISCOVERY-ONLY-LABEL-NOT-A-GATE`; GATING is stage B).

### 1.3 Why an industry-standard shape

Feature-set minimization as the mechanism for a minimal-profile VMM is the entire thesis of this product class: Firecracker's design goal is explicit attack-surface/TCB reduction (~50 KLOC Rust VMM, virtio-only device model, no BIOS/PCI/legacy — Agache et al., NSDI 2020); Cloud Hypervisor ships the same via a deliberately small Rust codebase and refusal of legacy emulation; Solo5 distills the guest-host interface to a minimal hypercall set with tenders "orders of magnitude smaller than QEMU". All three validate **"omit, don't hide"** as the standard mechanism. `token=class=OMIT-NOT-HIDE-IS-THE-VMM-IDIOM`. What none of them require and Yuva does not claim: "minimal" as a superlative — the token vocabulary is descriptive (`tcb=VMM-SUBSET-NO-AGENT-ORGANS`), never `MINIMAL-VMM` (nothing proves minimality). Nor does stage A claim Firecracker-class capability: the honest phrase is **Firecracker-ALTERNATIVE core, profile-scoped**, and at stage A the substrate lane witnesses neither EL2 isolation nor guest-running (`substrate-guest-evidence=AARCH64-AGENT-LANE-ONLY-AT-STAGE-A`).

### 1.4 The two-stage honesty ladder (the strands' disagreement, resolved)

Three mechanisms, three wordings, mapped 1:1 and **never swapped** (`token=three-wordings=NEVER-SWAPPED`):

| Rung | Mechanism | What is true | The only honest wording |
|---|---|---|---|
| View (landed) | render filter | organs RAN, rows hidden | "present in this build but **HIDDEN** in the substrate view" |
| **Stage A profile (this proposal)** | runtime gate, `yuva.profile=` | code in image, organs **NOT RUN / NOT ADMITTED** | marker skip form `(substrate profile, agent organ skipped)` + INFO "present in this build, **NOT RUN and NOT ADMITTED** (substrate profile, runtime-gated)" |
| Stage B (deferred) | cargo-feature compile-out | organ code **NOT IN IMAGE** | markers **ABSENT-BY-OMISSION** (no skip form — emitting one would overclaim presence); INFO "**NOT built** into this image" |

The aL2.4b skip-form grammar (the family of `(no EL2, skipped)`) means "capability compiled-in, this lane cannot exercise it" — exactly true at stage A, false at stage B. The suffix deliberately contains the word **skipped** — the same grammar family the required lanes already treat as honest-skip, and the word the one regex-style skip-reject actually matches (§2.3). Conversely "not present" is FORBIDDEN until stage B verifies symbol absence. `token=omission=RUNTIME-GATED-NOT-COMPILED-OUT` (stage A); may flip to `omission=COMPILED-OUT` only when the lane positively verifies the image delta.

### 1.5 The neutral-term rename — verified ALREADY LANDED; residual is lint-only

Corrected against the working tree (2026-07-08): the agent-neutral rename has **already landed** — `bootreport.rs` uses `View::Agent` (`:114`, `:321`, `:441`) and parses `yuva.view=agent` (`:224`); `demo.sh` defaults `VIEW="agent"` with `--agent` and keeps `--cogi` only as a deprecated alias (`demo.sh:50`); `test-industrial-boot.sh` is Cogi-free; the raw marker wire is Cogi-free. (The draft's citation of `demo.sh:97-101` was wrong — that region is APPEND assembly; the review's correction is itself now superseded by the landed rename.) Residual stage-A work is small and precise: (a) the single stray `"Cogi"` literal in `tools/xport-harness/src/live.rs`; (b) a LANGUAGE-AND-STANDARDS lint banning reintroduction of the name in this repo; (c) this proposal and its docs fan-out using **agent** as the neutral term throughout. `token=terminology=AGENT-NEUTRAL-PER-DIRECTIVE`.

One adjacent wording obligation surfaced by review: the pretty summary tail at `bootreport.rs:319` emits `" — sovereign agent-native OS · "`, which the substrate render would inherit. "Sovereign" is a defined ledger-backed term in this repo (`docs/plans/sovereignty-plan.md` principle 1 — machine-checkable, every stage proven at boot), and it stays on the AGENT render bound to that sense. The SUBSTRATE-profile render must NOT inherit it: the substrate summary tail reads the adjective-free `" — agent-agnostic micro-VMM core (substrate profile) · "`. This proposal's own title carries no unbacked adjective for the same reason. `token=sovereign=LEDGER-BOUND-AGENT-RENDER-ONLY`.

## 2. The mechanism — `yuva.profile=substrate|agent`, DEFAULT agent

### 2.1 The selector

A boot-cmdline token `yuva.profile=substrate|agent`, **DEFAULT `agent`** (the state of an absent token):

- Parsed at the existing single cmdline site — `main.rs:304-313` → a sibling of `bootreport::apply_cmdline` (`bootreport.rs:224-255`), in a small NEW `kernel/src/profile.rs` exposing `pub fn agent_organs_enabled() -> bool` backed by an `AtomicBool`, key brand-derived via `concat!(brand::brand_lower!(), ".profile=")` like the existing tokens.
- `profile=substrate` also **defaults the render VIEW to substrate** (view stays independently overridable) — the substrate profile's honest render is the substrate view (requirement 3). When the PROFILE (not merely the view) is substrate, the INFO line upgrades to: `Cognitive subsystems present in this build, NOT RUN and NOT ADMITTED (substrate profile, runtime-gated)` — still never "not present" (§1.4) — and the summary tail takes the adjective-free substrate form (§1.5).
- **Channel reality (x86-first, honest):** the PVH `-append` path is wired today (`tb_hal::boot_cmdline_x86`, `tb-hal/src/lib.rs:882`). The aarch64 `/chosen/bootargs` reader is the already-named industrial-boot follow-up; the tb-vmm lane can later pass the profile through the frozen `TbBootInfo.cmdline_ptr/cmdline_len` fields (offsets 32/40, `tb-boot/src/lib.rs:300-320`, zero layout growth); the EL1 guest, if ever needed, would use a `TB_BOOT_FLAG_SUBSTRATE = 1<<1` beside the landed `TB_BOOT_FLAG_IN_GUEST = 1<<0` precedent (`tb-boot/src/lib.rs:106`). All three are named deferrals (§11); stage A's substrate lane is x86_64-only — which is exactly why no stage-A substrate boot witnesses EL2 isolation or guest-running (`substrate-guest-evidence=AARCH64-AGENT-LANE-ONLY-AT-STAGE-A`). `token=lane=X86-FIRST-BUILDABLE-NOW`.

### 2.2 Why runtime-first, compile-out-second (not the reverse)

- **The re-entrant guest constraint cuts the other way here.** Industrial-boot's pretty knob HAD to be runtime because a compile-time feature would corrupt the cmdline-less guest stream. The profile has the same shape at stage A (default=agent keeps the guest agent-profile, its full chain IS the aL2.4b acceptance), and stage B's compile-out is legitimate later precisely because it produces **two artifacts** rather than one binary with two behaviors — the substrate lane builds and boots its OWN image, and the guest keeps re-entering the agent image.
- **Runtime gating is the cheaper, safer first cut of the SAME seam.** The `if profile::agent_organs_enabled()` branches of stage A become the `#[cfg(feature = "agent-organs")]` boundaries of stage B — the cut-line is pinned once, then hardened. Stage B (`agent-organs` DEFAULT-ON, substrate built `--no-default-features`, linker-stripping the organ halves of tb-hal and the agent-attributable tb-encode leaves) is the only rung that earns "not present" and the code-bytes TCB delta, verified by an image-size + symbol-absence check (§11).
- **Honest framing, binding:** stage A = **attack-surface and execution** TCB reduction (`tcb=ATTACK-SURFACE-REDUCED-NOT-BYTES-REMOVED`); stage B = **code** TCB reduction. Stage A never claims "smaller image".

### 2.3 The gated blocks and their skip grammar

Each cognitive block in `kernel/src/main.rs` becomes `if profile::agent_organs_enabled() { <existing block, byte-identical> } else { <skip marker> }`, the skip taking the aL2.4b grammar:

```
M13: memory OK (substrate profile, agent organ skipped)
```

Three properties, all load-bearing and stated precisely:

1. **The cumulative substring survives in both profiles.** The prefix of every skip form is **string-equal to the landed marker literal** — `M16: infer OK` (`main.rs:2573`), `M30: infer-transport OK` (`:4810`), never a paraphrase (the draft's "infer-bridge"/"transport" renames were caught in review and are forbidden; DoD-5 lints prefix parity mechanically). The never-removed/renamed/reordered marker-chain invariant holds, and the substrate lane verifies the chain INTACT in skip form.
2. **Cross-lane non-impersonation is a LANE-level property, and only that — stated honestly.** Individual positive substring greps in the required lanes (e.g. `run-x86_64.sh:240`-style `grep -qF 'M21: kan-policy OK'`) **WOULD be satisfied by the skip form** — deliberately, that is the cumulative-substring invariant. What a substrate boot can NEVER satisfy is a required LANE: the lanes' positive witness-line requirements (`kan:`, `prov:`, `xport:`, …) and the pinned cumulative tail (`M38: conductor OK turns=6 organs=3 verdict=ACCEPT`, `run-x86_64.sh:37`) all fail, because the skip forms carry no witness tokens and the substrate M38 form lacks `turns=`/`verdict=ACCEPT`. The draft's claim that existing skip-reject guards "already reject any skip form" was FALSE and is withdrawn: the exact-string skip-rejects (e.g. `grep -qF '(no table, skipped)'`) do not cover the new form and are not claimed to; the one regex-style reject (`run-x86_64.sh:709`, `M38: conductor OK \(.*(skip|single organ|always-accept)`) DOES fire on a leaked substrate M38 form — because the suffix contains the word `skipped` — and that is a bonus tripwire, not the mechanism. No required-lane verifier is edited to achieve any of this (the zero-lines-changed invariant, §8.1). `token=cross-lane-reject=LANE-LEVEL-POSITIVES-NOT-PER-GUARD`.
3. **The suffix carries no witness tokens** — no `kan:`, `prov:`, `exp:`, `mem:`, `turns=`, `verdict=ACCEPT` — so the §8.2c negative census stays clean.

**The gated set (marker-anchored; ~17 blocks):** M13 memory (block ≈`:1560-1727`; **note** the two agent-task spawns just before it stay unconditional — they are the M14 IPC peers), M16 infer (`M16: infer OK`, block ≈`:2465-2573`), M17 consolidation (≈`:2575-2775`), **M18 evolve (`:2788-2978`) and M18.1 approval-gate (`:2985-3147`) — gated as selftests because they positively exercise `M_MEM_WRITE_PROC` skill writes expecting `Ok` (e.g. `:2868`, `:2873`), which ARE procedural-memory-organ exercise and which the §2.4 chokepoint denial would otherwise fail-exit at `m18_fail`; the admission MECHANISM (capability tiers, dispatch arms, the fail-closed deny path) stays compiled and active in substrate — it IS the deny gate**, M21 kan-policy (≈`:3966-4022`), M22 provenance (≈`:4024-4077`), M23 experience (≈`:4080-4156`), M24 bakeoff (≈`:4159-4242`), M31-part-1 (≈`:4267-4400`), M25 operator transcript (≈`:4400-4488`), M26 exit-telemetry (≈`:4491-4566`), M28 operator-cmd (≈`:4606-4690`, with the M29 KAT handled per §3.3), M30 infer-transport (`M30: infer-transport OK`, ≈`:4696-4810`, profile-checked BEFORE the host-peer probe so the skip reason is honest), M31-part-2 (≈`:4813-4950`), M33 prov-lineage (≈`:4952-5033`), M38 conductor (≈`:5057-5307`).

**One real cross-block data dependency, handled explicitly:** M31-part-1's function-scope tuple (`m31_req_id`, `m31_digest32`, …) feeds M25's fold and M31-part-2. It becomes `Option<…>` = `None` in substrate; its consumers (M25, M31-part-2) are themselves gated, so it is never unwrapped. The Kani-relevant leaves are untouched — the gate is a branch-on-bool in the zero-unsafe kernel layer, never inside `tb-encode` (§8.4).

### 2.4 Structural non-admission — the chokepoint tripwire

"Not run" must not be merely incidental-to-selftests. In the substrate profile:

- The cognitive M11 dispatch method families (`M_MEM_RECALL`, `M_MEM_WRITE_PROC`, `M_MODEL_INVOKE`, `M_MODEL_INVOKE_BYTES`) return `SysStatus::Denied` at the dispatch chokepoint — fail-closed, so even future in-image code cannot exercise an organ in substrate. This deny set is CONSISTENT with the substrate boot chain precisely because the M18/M18.1 organ-exercising selftests are gated (§2.3) — the review-caught contradiction (deny `M_MEM_WRITE_PROC` while a kept M18 selftest expects it to succeed → every substrate boot fail-exits) is resolved by gating the selftests, not by carving the write arm out of the deny set. `token=admission=DENIED-AT-CHOKEPOINT`.
- The M18/M18.1 admission mechanism refuses ADMITTED-tier promotion — the M18 idiom applied: **an organ is a capability whose gate is never met in substrate**. This refusal is not merely asserted: DoD-3 exercises BOTH the chokepoint denial AND the promotion refusal in-boot (§9). M18 the mechanism is KEPT (§3.2): it is how organs are opt-in, and the named seam through which a future external agent artifact would be admitted (deferred to the Yuva-ABI milestone). `token=promotion=REFUSED-AT-GATE-EXERCISED`.

### 2.5 The profile witness (emitted ONLY on non-default selection)

To preserve default byte-identity, the agent-default stream gains **zero new bytes**. When `yuva.profile=substrate` is selected, one witness line is emitted:

```
profile: sel=SUBSTRATE source=PVH-CMDLINE organs=SKIPPED-RUNTIME-GATED code=PRESENT-IN-IMAGE admission=DENIED-AT-CHOKEPOINT promotion=REFUSED-AT-GATE tcb=ATTACK-SURFACE-REDUCED-NOT-BYTES-REMOVED separability=EXECUTION-ADMISSION-LEVEL guest-evidence=AARCH64-AGENT-LANE-ONLY view=SUBSTRATE-DEFAULTED smp=UP-ONLY rootfs=NONE realtime=NOT-CLAIMED
```

plus, at the clean-exit site (so a crash-before-organs cannot impersonate omission — the anti-hollow tail), the lane's cumulative tail marker:

```
PROFILE: substrate OK organs=SKIPPED-RUNTIME-GATED
```

The tail deliberately does NOT say "substrate-vmm": a stage-A substrate boot exercises neither the EL2 hypervisor nor tb-vmm pass-through (both named deferrals, §11) — the marker may earn a `-vmm` qualifier only when a substrate-profile lane actually witnesses guest-running.

## 3. What stays — the profile-scoped core (unconditional in BOTH profiles)

### 3.1 The substrate core

M0-M11 core kernel (traps/ctx/MMU/rings/allocators/timer/preempt/addrspace/caps), M14 IPC + M15 shared blocks (generic kernel mechanisms; see §3.4), the M18/M18.1 admission MECHANISM (capability tiers + fail-closed gate — the selftests are gated per §2.3; M18 evolve selftest `:2788-2978`, M18.1 selftest `:2985-3147`), L2.0-L2.6 + M27 hypervisor/scheduler, M19 virtio, M20 persist (`main.rs:3925-3953`, with its lane-legitimate `(no disk, skipped)` forms), M29 khash (§3.3), aL2.4b full-kernel-EL1-guest, `bootreport::render`, and all of tb-vmm. This is the sovereignty-plan M34 line productized **as a core, profile-scoped** — kernel + caps + L2 hypervisor + virtio + durable storage + tb-vmm — with the §10 concession standing: not yet a USABLE Firecracker alternative, and at stage A the hypervisor/guest members of this list are exercised only on aarch64 agent lanes.

### 3.2 M12 — the agent-agnostic hosting socket (a decision, surfaced)

**Recommendation: M12 AgentProcess ABI (`main.rs:1378-1549`) STAYS in substrate.** Under the 2026-07-08 directive it is precisely the agent-AGNOSTIC hosting ABI — Linux has processes with none running; Yuva has an agent socket with no agent admitted. Consequence: `bootreport`'s "Agent runtime & memory" row (which today rolls M12..M18 together as an agent-view row) needs a **row split** — the hosting ABI + admission mechanism (M12/M14/M15/M18-mechanism) becomes a substrate row ("Agent hosting ABI — socket and admission gate present, no organ admitted"), while the organ exercise (M13/M16/M17 and the M18/M18.1 selftests) stays agent-view. This is an explicit operator veto point (§12): the defensible alternative (M12 gated as agent-only) trades the honest hosting-socket story for a smaller substrate wire, and reasonable reviewers may differ.

### 3.3 The khash KAT (one small refactor, byte-identity-safe by construction)

`bootreport.rs` already tags "Message-authenticated integrity — keyed BLAKE2s-256" as a SUBSTRATE row, but today the M29 KAT runs only inside `tb_hal::opcmd_selftest` (`main.rs:4605-4693`) — inside the gated M28 block. Stage A extracts a standalone `tb_hal::khash_kat_selftest()` and wires it **asymmetrically, so the agent stream cannot gain duplicate lines** (the review-caught DoD-1 hazard): on the **agent profile the emission site is UNCHANGED** — the KAT runs and emits `khash: prim=BLAKE2S-256 … kat=RFC7693-PASS` + `M29: khash-mac OK` inside the opcmd path exactly as today, byte-for-byte; on the **substrate profile only**, the gated M28 block's `else` arm calls the standalone KAT, which emits the same two lines at that stream position. One KAT implementation, two call sites, **exactly one emission per boot on either profile**; the agent-profile ordering and bytes are untouched and DoD-1's byte-identity proof covers this refactor specifically. The khash primitive is a substrate integrity feature, not an agent organ. `token=khash-hoist=SUBSTRATE-ARM-ONLY-EMISSION`.

### 3.4 The M14/M15 + M20/mem entanglement audits (first extraction work products; the M20 audit is a landing BLOCKER)

Two dependency audits ship WITH stage A, findings recorded in the landing:

- **M14/M15:** their selftests sit inside the M12-M18 region; IPC/shared-blocks are generic mechanisms (`tb-hal` `ipc.rs`/`blocks.rs`/`caps.rs` stay in the substrate TCB either way). Decide by audit whether their selftests need the M12 agent entity (then run them on generic tasks in substrate — stronger substrate verification) or gate them.
- **M20/mem:** the M20 durable-storage selftest (a substrate row) routes through the M13 `BackingStore` seam and `mem::VirtioBlkStore`'s `Region`/`push_record` path (`main.rs:3908-3941`) — the storage ENGINE and the agent memory ORGAN cohabit `crates/tb-hal/src/mem/` (mod.rs 2,023 + selftests.rs 2,322 lines). Review correctly flagged that §4's "no memory-organ exercise" claim is OVERCLAIMED until this is checked: therefore the call-path audit proving the M20 round-trip does not exercise organ logic is a **stage-A landing BLOCKER, not a promise** — until its finding is recorded in the landing, the token is `m20-organ-overlap=AUDIT-REQUIRED-AT-LANDING` and the §4 claim is stated as conditional on it. If the audit finds organ-path exercise, the claim narrows (or the call path is refactored) BEFORE landing. The full engine/organ **factorization** of `mem/` — the codebase-decomposition follow-up made load-bearing, and a hard prerequisite of stage B's compile-out (you cannot `#[cfg]`-out an organ entangled with a kept engine) — **LANDED as #80** (`engine.rs`/`organ.rs` split, zero behavior change, verified line-multiset-conserving); the M26 exit-telemetry one-organ compile-out PoC (**#81**) has since exercised the resulting seam end-to-end, but the full stage-B cutover across every organ has not. This is exactly the seam `docs/research/cogi-cognitive-architecture.md` §2/§2.1 already draws: Yuva-memory = the non-parametric retrieval STORE (substrate-side storage), the organs above it composable capabilities (agent-side). **UPDATE — M20 engine/organ untangle (stage-B PR-1):** the last residual entanglement is now resolved: `persist_selftest` moved ONTO the engine (`crates/tb-hal/src/mem/engine.rs`) and drives `VirtioBlkStore`/`BackingStore` DIRECTLY (`append`/`read_at`/`flush` + the gen/replay legs) instead of routing through the organ's `MemSubstrate::write`→`push_record` journal, so the M20 substrate row exercises ZERO organ logic while the `persist: gen=.. records=.. replayed=.. prior=..` witness + `M20: persist OK` marker stay byte-identical — clearing the way to eventually put `#[cfg(feature = "agent-organs")]` on the crate-level `mod organ` without dragging the M20 round-trip out with it.

## 4. What the substrate profile genuinely omits — the honest TCB delta

**Stage A (runtime-gated) omits at RUNTIME:**
1. **Execution** of all ~17 cognitive selftest blocks (M13/M16/M17/**M18/M18.1**/M21-M26/M28/M30/M31×2/M33/M38) — the majority of `rust_main`'s post-core body (≈3,300+ lines of organ wiring+selftests by the strands' accounting; the exact number is a stage-B `tcb-delta=MEASURED-BYTES` obligation, never an adjective).
2. **Admission** — no memory-organ exercise (M13 gated; the M18/M18.1 `M_MEM_WRITE_PROC` skill writes gated; the M20 round-trip covered by the §3.4 landing-blocker audit, `m20-organ-overlap=AUDIT-REQUIRED-AT-LANDING`), no `ModelSession`, no ADMITTED-tier skill promotion (refusal exercised, DoD-3); the cognitive M11 families return `Denied` (§2.4).
3. **Live input-parsing attack surface** — the M30 serial-framed transport RX parser never listens; the M28 operator-command verifier is never instantiated (no key material derived, no key-evolution state in RAM).
4. **Persistent side effects** — no provenance/experience/transcript folds; the M33 signed-head sectors above the 4 MiB M20 boundary are never written.
5. **Host-side** — no conductor-host, no xport echo peer, no M32 daemon deployed on a substrate lane.

**Stage A does NOT omit (never overclaimed):** the code BYTES — the image is identical, `.text` still contains every organ (`code=PRESENT-IN-IMAGE`); the M12/M14/M15 hosting surface and the M18 admission mechanism (kept by design); the khash primitive. And in both profiles the **entire unsafe/asm perimeter is SHARED** — boot trampolines, paging, traps, EL2 monitor, stage-2, virtio MMIO/DMA, serial, scheduler, capability table, tb-boot, tb-vmm. `token=unsafe-core=SHARED / tcb-delta=SAFE-ORGAN-CODE-GATED` — the reduction is in safe-Rust organ code and its execution, never the unsafe perimeter, and "reduced" is always relative to the agent build (`tcb=VMM-SUBSET-NO-AGENT-ORGANS`), never an absolute-minimality claim.

**Stage B adds the code delta:** organ symbols literally absent (~17 main.rs blocks + the organ halves of `tb-hal/src/mem/` + `infer.rs` + the agent-attributable `tb-encode` leaves no longer linked — inferwire, lmsig, opframe/opframe_rx, bakeoff, exp, conductor, provhead, prov, attest, sha256, exittel, kancell, memscore, route, explore; roughly ~20 KLOC by the strands' count, to be **measured** at landing), positively asserted by the substrate lane's image-size + symbol-absence check.

**What the AGENT profile adds back (self-declared):** the full M13→M38 organ chain — tiered memory + lexical recall, consolidation, dormant gated learning (KAN_ACTIVE=false, gate-not-met), provenance fold + signed lineage, operator TX/RX, inference transport + mock e2e (`backend=MOCK-DETERMINISTIC`), the Verifier-gated conductor — plus host-side conductor/M32. The agent profile inherits and never displaces the existing on-wire honesty tokens.

## 5. Full concrete boot examples

### 5.1 Substrate profile, x86_64 (the NEW lane; raw markers, excerpt)

```
M1: traps OK
…
M11: caps OK
M12: agent OK
M13: memory OK (substrate profile, agent organ skipped)
M14: ipc OK
M15: blocks OK
M16: infer OK (substrate profile, agent organ skipped)
M17: consolidate OK (substrate profile, agent organ skipped)
M18: evolve OK (substrate profile, agent organ skipped)
M18.1: approval-gate OK (substrate profile, agent organ skipped)
…
M19: virtio OK
persist: gen=0x1 records=0x2 replayed=0x2
M20: persist OK
M21: kan-policy OK (substrate profile, agent organ skipped)
…
khash: prim=BLAKE2S-256 keylen=32 tag=128 kat=RFC7693-PASS sec=ASSUMED-FROM-LITERATURE sidechannel=NOT-CLAIMED
M29: khash-mac OK
M30: infer-transport OK (substrate profile, agent organ skipped)
M31: infer-e2e OK (substrate profile, agent organ skipped)
M33: prov-lineage OK (substrate profile, agent organ skipped)
M38: conductor OK (substrate profile, agent organ skipped)
profile: sel=SUBSTRATE source=PVH-CMDLINE organs=SKIPPED-RUNTIME-GATED code=PRESENT-IN-IMAGE admission=DENIED-AT-CHOKEPOINT promotion=REFUSED-AT-GATE tcb=ATTACK-SURFACE-REDUCED-NOT-BYTES-REMOVED separability=EXECUTION-ADMISSION-LEVEL guest-evidence=AARCH64-AGENT-LANE-ONLY view=SUBSTRATE-DEFAULTED smp=UP-ONLY rootfs=NONE realtime=NOT-CLAIMED
PROFILE: substrate OK organs=SKIPPED-RUNTIME-GATED
```

Every skip-form prefix above is string-equal to the landed marker literal (DoD-5). Note what is NOT here: no `mem:`, `kan:`, `prov:`, `exp:`, `bakeoff:`, `opframe:`, `exittel:`, `opcmd:`, `xport:`, `infer:`, `infer-dump:`, `conduct:`, `conduct-step:`, `cost:` witness line; no `turns=`/`verdict=ACCEPT`; no `backend=MOCK-DETERMINISTIC`. The presence of ANY of these on a substrate boot is RED, and the list is mechanically derived, not hand-typed (§8.2c).

### 5.2 Default (agent) profile — every required lane

Byte-identical to today, all three surfaces (x86_64 host, vmm host with pinned skips, decoded aarch64 `GUEST_STREAM`), M38 cumulative tail intact. No `profile:` line (emitted only on non-default selection). The khash refactor provably adds/moves zero agent-profile bytes (§3.3).

### 5.3 The substrate profile's pretty render (view defaulted to substrate)

As industrial-boot §3.2, with the profile-upgraded INFO line — `[ INFO ] Cognitive subsystems present in this build, NOT RUN and NOT ADMITTED (substrate profile, runtime-gated)` — an honest upgrade from "HIDDEN", still never "not present" until stage B; and the adjective-free substrate summary tail (§1.5), never inheriting "sovereign" from the agent render.

### 5.4 Forbidden renderings/claims (lint FAILS)

```
"not present" / "removed" / "compiled-out" / "smaller image"   ← stage-B-only vocabulary, forbidden at stage A
"zero-TCB" / "minimal VMM" / "secure/isolated/sandboxed"       ← banned superlatives/adjectives (aL2.4b §5, run-script ban lists)
"sovereign" on the substrate render or profile witness          ← ledger-bound term, agent render only (§1.5)
"Firecracker-replacement" / "KVM-class"                        ← banned; the honest phrase is Firecracker-ALTERNATIVE core, profile-scoped
any cognitive witness family on a substrate boot                ← anti-hollow inversion, RED (census-derived list, §8.2c)
a skip-form prefix not string-equal to a landed marker literal  ← accidental rename, DoD-5 RED
"M16: infer-bridge OK" / "M30: transport OK"                    ← the two review-caught rename examples, memorialized as lint fixtures
```

## 6. Honest tokens (the complete vocabulary)

- `profile: sel=SUBSTRATE source=PVH-CMDLINE organs=SKIPPED-RUNTIME-GATED code=PRESENT-IN-IMAGE admission=DENIED-AT-CHOKEPOINT promotion=REFUSED-AT-GATE tcb=ATTACK-SURFACE-REDUCED-NOT-BYTES-REMOVED separability=EXECUTION-ADMISSION-LEVEL guest-evidence=AARCH64-AGENT-LANE-ONLY …` — the one-line profile witness; non-default selection only.
- `PROFILE: substrate OK organs=SKIPPED-RUNTIME-GATED` — the substrate lane's cumulative tail (anti-hollow: clean-exit-sited; no `-vmm` until a substrate lane witnesses guest-running). At stage B: `organs=NOT-BUILT`, only with the symbol-absence check green.
- `(substrate profile, agent organ skipped)` — the per-marker skip suffix; prefix string-equal to the landed marker literal (DoD-5); aL2.4b "skipped" grammar family; carries no witness tokens; honest ONLY while code is in the image (§1.4).
- `cross-lane-reject=LANE-LEVEL-POSITIVES-NOT-PER-GUARD` — non-impersonation rests on the required lanes' positive witness/tail guards; individual substring greps match skip forms by design; no per-guard rejection is claimed.
- `omission=RUNTIME-GATED-NOT-COMPILED-OUT` → may flip to `omission=COMPILED-OUT` only at stage B with the image delta verified.
- `tcb=VMM-SUBSET-NO-AGENT-ORGANS` (descriptive, never MINIMAL), `unsafe-core=SHARED`, `tcb-delta=MEASURED-BYTES` (stage B: a bench-measured number, not an adjective).
- `separability=EXECUTION-ADMISSION-LEVEL-AT-STAGE-A` (code-level separability = stage B, post-factorization), `separation=IN-REPO-PROFILE-NOT-EXTRACTION`, `agent-abi=NOT-DEFINED`, `extraction=DEFERRED`, `backends=DEFERRED`.
- `substrate-guest-evidence=AARCH64-AGENT-LANE-ONLY-AT-STAGE-A`, `guest-lane=AGENT-PROFILE-UNCHANGED`, `firecracker-class=NOT-CLAIMED` (smp=UP-ONLY, rootfs=NONE carried from aL2.4b).
- `m20-organ-overlap=AUDIT-REQUIRED-AT-LANDING` (a landing blocker, §3.4), `khash-hoist=SUBSTRATE-ARM-ONLY-EMISSION` (§3.3), `sovereign=LEDGER-BOUND-AGENT-RENDER-ONLY` (§1.5).
- `dod1=LOCAL-LANDING-PROOF+CI-TRIPWIRE` — byte-identity is proven at landing with the local two-repo empty-diff tool (the industrial-boot precedent, honestly NOT wired into CI) plus a weaker per-run CI tripwire (§8.2a); `substrate-not-run=PROVEN-BY-ABSENT-WITNESSES-CENSUS-DERIVED`.
- Agent profile: inherits `backend=MOCK-DETERMINISTIC`, `gate-not-met`, `KAN_ACTIVE=0x0`, `host=RESIDUAL-TCB`, `sec=ASSUMED-FROM-LITERATURE`, `sidechannel=NOT-CLAIMED` unchanged; no new default-stream token at stage A (byte-identity).
- The three-wordings rule (§1.4) is itself a lint-gated token discipline: HIDDEN (view) / NOT-RUN-NOT-ADMITTED (runtime profile) / NOT-BUILT (compile-out) — never swapped.

## 7. Consistency with the industrial-boot view (requirement 3)

- `profile=substrate` ⇒ view defaults to substrate (the honest render for that profile); view remains overridable, but `yuva.view=agent` on a substrate-profile boot renders the agent rows in their DERIVED skip states — never green organ rows, because the derived glyphs key off the on-wire skip forms (industrial-boot §2.2 discipline, unchanged).
- In the AGENT image/profile, `yuva.view=substrate` stays a pure render filter and KEEPS the "present in this build but HIDDEN" wording (still true there). `scripts/test-industrial-boot.sh` DoD-3 is extended to assert both wordings in their correct contexts, to reject "not present" everywhere until stage B, and to assert the substrate render's adjective-free summary tail (§1.5).

## 8. ZERO CI regression — the concrete proof (requirement 4)

### 8.1 The invariant: DEFAULT-equals-today

Default profile is AGENT; **no existing run script or CI lane passes `-append`** (verified: zero matches across `scripts/run-x86_64.sh`, `run-aarch64.sh`, `run-vmm-x86_64.sh`; lanes wired at `.github/workflows/ci.yml:64,69` + `vmm-boot.yml`), and the re-entrant aL2.4b EL1 guest has no cmdline channel — so every required lane boots the agent profile and its 100+ grep chain (the M38 tail at `run-x86_64.sh:37`, the positive-require/skip-reject blocks, the aarch64 `GUEST_STREAM` G-partition, the vmm pinned skips) sees a **byte-identical** stream. The three required verifier scripts change by **zero lines** (the aL2.4b §2.6 strip-then-assert discipline: a new profile without weakening one byte of the host profile) — which is also why cross-lane rejection is carried by their EXISTING positive guards (§2.3), never by editing them.

### 8.2 Enforcement — stated at its true strength, no stronger

- **(a) Byte-identity: a landing-time LOCAL proof + a per-run CI tripwire (the honest recharacterization).** Review verified that `scripts/empty-diff-proof.sh` is a local two-repo baseline-comparison tool wired into NONE of the 12 CI workflows — so the draft's "enforced per-run" was untrue and is withdrawn. As landed for industrial-boot, the empty-byte-diff (no `yuva.profile` token ⇒ zero-diff stream on both arches AND the decoded guest stream, against the pre-change baseline) is performed and recorded AT LANDING with the local tool. Additionally, the NEW substrate CI job gains a per-run tripwire: it boots the SAME binary once with NO cmdline and asserts the default stream contains no `profile:` line, no skip-form suffix, and every agent witness family present (i.e., the default boot is agent-complete) — a weaker-than-byte-diff but CI-required guard against profile leakage into the default. `token=dod1=LOCAL-LANDING-PROOF+CI-TRIPWIRE`.
- **(b)** The NEW `scripts/run-substrate-x86_64.sh` + a NEW ci.yml job (an ADDITIONAL lane): positively requires every substrate-real marker AND witness (M0-M11, M12, M14, M15, real `M19: virtio OK`, real `persist: gen=…` round-trip, `khash: … kat=RFC7693-PASS` + `M29: khash-mac OK`, per-arch L2/M27 forms), positively requires the EXACT `(substrate profile, agent organ skipped)` form for each gated marker (the cumulative chain verified INTACT in skip form, incl. M18/M18.1), requires the `profile:` witness line and the `PROFILE: substrate OK` tail verbatim.
- **(c)** **The anti-hollow INVERSION (the lane's core), census-derived:** any cognitive witness family on the substrate stream is RED. The ABSENT list is NOT hand-enumerated (review caught three omissions in the draft's hand list — `mem:` from M13 `main.rs:1635-1683`, `conduct-step:` `:5216`, `cost:` `:5293`): a census script greps the witness-prefix emissions inside the gated block ranges of `main.rs` and emits the list as a generated, committed file; the substrate lane asserts against the generated list and CI re-runs the census and diffs it against the committed copy — so a future organ's new witness prefix cannot silently escape the inversion. Current census: `mem:`, `kan:`, `prov:`, `exp:`, `bakeoff:`, `opframe:`, `exittel:`, `opcmd:`, `xport:`, `infer:`, `infer-dump:`, `conduct:`, `conduct-step:`, `cost:`, plus `verdict=ACCEPT`, `turns=`, `backend=MOCK-DETERMINISTIC`. This — organs proven NOT to have run — is precisely what distinguishes a profile from the render filter. `token=substrate-not-run=PROVEN-BY-ABSENT-WITNESSES-CENSUS-DERIVED`.
- **(d)** Overclaim-vocabulary rejects near the profile/skip lines: `not present`, `removed`, `zero-TCB`, `compiled-out`, `smaller image`, `minimal`, `secure`, `isolated`, `sandboxed`, `sovereign` (substrate stream), `Firecracker-replacement`.
- **(e)** Cross-lane non-impersonation per §2.3, stated at lane level: substrate skip forms lack the agent witness tokens and the pinned M38 tail, so no required LANE passes on a substrate stream; the `skipped` wording additionally trips the one regex-style reject (`run-x86_64.sh:709`) if an M38 skip form ever leaked. No claim that exact-string skip-rejects or individual positive greps reject the new forms — verified, they do not, and the design does not need them to.
- **(f)** Inherited tripwires apply to the new lane: ESC-`0x1b` FAIL, hex-only dump fields.

### 8.3 Autonomously buildable

The substrate lane is QEMU/TCG + `-append` only — no network, no human, no hardware. Cost: two extra QEMU boots per CI run at stage A (the substrate boot + the (a)-tripwire default boot; one extra build at stage B).

### 8.4 Kani budget: ZERO

The gate is a branch-on-bool in the zero-unsafe kernel layer, never inside a `tb-encode` leaf; no new pure leaf, no new harness. `EXPECTED_HARNESSES_TOTAL=122` — the enforced pin lives at `scripts/kani-shards.sh:75` (asserted against `crates/tb-encode/src/proofs.rs`; `kani.yml` carries it only as a comment, `kani.yml:88`) — is **untouched**; the tb-encode agent leaves keep their harnesses workspace-wide regardless of which kernel image links them (true at stage B too — the proof surface is workspace-scoped, not image-scoped). `token=kani-budget=ZERO-NEW-HARNESSES`.

## 9. DoD — committed proof obligations

- **DoD-1 — default byte-identity (honestly scoped):** at landing, the LOCAL empty-diff proof — no `yuva.profile` token ⇒ empty serial diff vs the pre-change baseline on the x86_64 host stream, the vmm host stream (incl. pinned skips), and the decoded aarch64 `GUEST_STREAM` (the industrial-boot DoD-1 precedent; recorded in the landing, NOT claimed as CI-per-run). Per-run in CI: the §8.2a default-boot tripwire in the substrate job. `token=dod1=LOCAL-LANDING-PROOF+CI-TRIPWIRE`.
- **DoD-2 — the substrate lane (NEW, required):** `run-substrate-x86_64.sh` green — positive substrate chain + exact skip forms + `profile:` witness + `PROFILE: substrate OK` tail + the §8.2c census-derived negative inversion + the §8.2d vocabulary rejects. `token=dod2=SUBSTRATE-LANE-POSITIVE+NEGATIVE-GREPS`.
- **DoD-3 — structural non-admission, BOTH gates exercised:** an in-boot substrate-profile negative check (i) exercises one cognitive method family at the M11 chokepoint and asserts `SysStatus::Denied`, AND (ii) exercises an ADMITTED-tier promotion attempt at the M18.1 gate and asserts refusal — witnessed as `admission=DENIED-AT-CHOKEPOINT promotion=REFUSED-AT-GATE` on the `profile:` line. The M38-style "exercise the gate, don't merely assert it" discipline, applied to both claims §2.4 makes. `token=dod3=DENIAL+REFUSAL-EXERCISED-NOT-ASSERTED`.
- **DoD-4 — view/wording parity:** `test-industrial-boot.sh` extended per §7 — profile-substrate INFO says NOT-RUN-NOT-ADMITTED; view-only substrate keeps HIDDEN; "not present" rejected everywhere; the substrate summary tail is adjective-free. `token=dod4=THREE-WORDINGS-LINTED`.
- **DoD-5 — marker-literal parity (NEW, review-mandated):** every skip-form prefix is string-equal to the landed marker literal, checked mechanically — the check greps each gated marker's literal from `main.rs` and asserts the skip form in the substrate stream is `<literal> (substrate profile, agent organ skipped)` exactly; hand-typed paraphrases (the caught `infer-bridge`/`transport` renames) are structurally impossible to land. `token=dod5=SKIP-PREFIX-STRING-EQUAL-TO-LANDED-LITERAL`.
- **DoD-6 — the M20/mem call-path audit (landing blocker):** the §3.4 audit finding (M20 round-trip exercises no organ logic — or the narrowed claim otherwise) recorded in the landing before the §4 "no memory-organ exercise" claim ships. `token=dod6=M20-AUDIT-AT-LANDING`.

Evidence is these committed tests + the §8.1 invariant, honestly NOT Kani proofs. `token=evidence=LANE-TESTS-NOT-KANI`.

## 10. Honest caveats (conceded — encoded as tokens)

- **Stage A removes zero image bytes.** `code=PRESENT-IN-IMAGE`; the claim ceiling is `tcb=ATTACK-SURFACE-REDUCED-NOT-BYTES-REMOVED`. Only stage B's verified compile-out earns "not present" / `omission=COMPILED-OUT` / a measured size delta.
- **The unsafe/asm perimeter does not shrink in either stage.** `unsafe-core=SHARED` — the reduction is safe organ code and its execution/admission.
- **"Reduced" is relative, never minimal.** `tcb=VMM-SUBSET-NO-AGENT-ORGANS`; no minimality, security, isolation, or Firecracker-parity claim (`firecracker-class=NOT-CLAIMED`, smp=UP-ONLY, rootfs=NONE, no multi-tenancy/migration/hotplug, no adversarially-proven sandbox).
- **No stage-A substrate boot witnesses isolation or guest-running.** The substrate lane is x86_64-only (no EL2 there); hypervisor/guest evidence at stage A lives only on aarch64 AGENT lanes. `substrate-guest-evidence=AARCH64-AGENT-LANE-ONLY-AT-STAGE-A`; the tail marker says `substrate`, not `substrate-vmm`, for exactly this reason.
- **The separability proof is execution/admission-level only.** The mem/ engine/organ code entanglement is unresolved at stage A (§3.4); code-level separability is a stage-B obligation, post-factorization, proven by symbol absence.
- **Cross-lane rejection is a lane-level property.** Individual positive substring greps in required lanes DO match the skip forms (by design — the cumulative-substring invariant); rejection rests on the lanes' witness-line and pinned-tail positives, plus one incidental regex tripwire. No per-guard rejection is claimed (`cross-lane-reject=LANE-LEVEL-POSITIVES-NOT-PER-GUARD`).
- **Byte-identity is a landing-time local proof, not a CI-per-run diff.** `dod1=LOCAL-LANDING-PROOF+CI-TRIPWIRE` — matching what industrial-boot actually did, plus the §8.2a per-run tripwire.
- **The "no memory-organ exercise" claim is conditional on the M20 audit until landing.** `m20-organ-overlap=AUDIT-REQUIRED-AT-LANDING` (DoD-6, a blocker).
- **The substrate profile is not yet a USABLE Firecracker alternative.** A host-facing guest-launch API surface is a separate future proposal; boot-profiles proves the separability (at its stated level), not the product.
- **Boot-profiles is NOT the extraction.** `separation=IN-REPO-PROFILE-NOT-EXTRACTION`, `agent-abi=NOT-DEFINED` — the cfg/branch seam documents the cut-line and forces the dependency audits (the M20/mem entanglement is the first concrete finding, §3.4); repo split, frozen ABI, and pluggable backends are the extraction milestones' scope.
- **default=agent is a CI-preservation choice, not a security default.** The substrate product story may eventually want default=substrate — at which point the byte-identity invariant must be explicitly renegotiated (an operator veto point, §12).
- **M12's substrate placement is a judgment call, surfaced not buried** (§3.2).
- **The stage-A skip forms claim presence — deliberately.** They are honest at stage A (code in image) and MUST be replaced by absence-by-omission at stage B; the two grammars never mix (§1.4).
- **The x86-first lane is a channel limitation, not a design one** — aarch64 `/chosen/bootargs`, tb-vmm `TbBootInfo.cmdline`, and `TB_BOOT_FLAG_SUBSTRATE` are named deferrals with landed anchors.

## 11. Frontier / named deferrals

- **Stage B — genuine compile-out.** Cargo feature `agent-organs` DEFAULT-ON (every existing build/CI invocation unchanged; substrate built `--no-default-features`), `#[cfg]`-removing the same blocks + the organ halves of `tb-hal/src/mem/` + `infer.rs` + unlinking the agent-attributable tb-encode leaves; hard prerequisite: the §3.4 mem/ engine/organ factorization (**LANDED as #80**; the M26 one-organ mechanism PoC, **#81**, has since proven the cfg-gate on the resulting seam — full stage B across every organ remains open); verified by image-size + symbol-absence (zero agent marker literals in the substrate binary, all present in the agent binary) in the substrate lane; only THIS rung says "not present" / `organs=NOT-BUILT`, and only this rung earns code-level separability. The industrial-boot §10 named successor, fulfilled. `token=substrate-compile-out=STAGE-B-NAMED`.
- **aarch64 substrate lane** behind the `/chosen/bootargs` follow-up (incl. substrate-guest re-entry expectations) — the first lane that could witness EL2 isolation under the substrate profile and thus the first that could justify a `-vmm`-qualified tail marker. `token=aarch64-substrate=FOLLOW-UP`.
- **tb-vmm profile pass-through** via the frozen `TbBootInfo.cmdline_ptr/cmdline_len` (zero layout growth). `token=vmm-profile=FOLLOW-UP`.
- **`TB_BOOT_FLAG_SUBSTRATE = 1<<1`** for the EL1 guest if ever needed; meanwhile `guest-lane=AGENT-PROFILE-UNCHANGED` (its full chain IS the aL2.4b acceptance).
- **Substrate boot-time benchmark** — the honest comparison number improves once the gated blocks don't run; measured in bench, `tcb-delta=MEASURED-BYTES` at stage B. `token=benchmark=DEFERRED-MEASURED-NEVER-CLAIMED`.
- **The extraction line (separate milestones):** the repo split (portable organ core → `cogitave/cogi`); the frozen versioned Yuva↔agent ABI (the capability/syscall surface an EXTERNAL agent artifact builds against); pluggable agent backends; runtime organ ADMISSION of an external agent via the M18.1 gate (the named seam, not built here); M32/host-daemon packaging. `token=extraction=DEFERRED`.
- **A host-facing guest-launch API** (what makes substrate a usable Firecracker alternative) — a separate proposal.
- **default=substrate** as the eventual product default — requires renegotiating the byte-identity invariant; operator-gated.

## 12. Landing plan — staged, CI-green, offline; operator veto points

- **(A) The runtime profile + the substrate lane (closes the boot-profiles task).** `kernel/src/profile.rs` (`yuva.profile=`, brand-keyed, DEFAULT agent) + the ~17 gated blocks with string-equal-prefix skip forms (§2.3, incl. M18/M18.1; M31-tuple→Option) + the M11 chokepoint denial + the M18.1 promotion refusal, both exercised (§2.4, DoD-3) + the substrate-arm-only khash KAT (§3.3) + the M12 bootreport row split (§3.2) + the profile-aware INFO wording and adjective-free substrate tail (§1.5, §7) + the rename residue (xport-harness stray + reintroduction lint, §1.5) + the `profile:` witness + `PROFILE: substrate OK` tail + NEW `run-substrate-x86_64.sh` + ci.yml job (substrate boot + default-boot tripwire) + the witness-prefix census generator (§8.2c) + DoD-1..6 + the M14/M15 audit and the BLOCKING M20/mem audit (§3.4, DoD-6) + the industrial-boot.md stale-M38 correction + the §13 docs fan-out, in the same landing. The three required verifiers: **zero lines changed**.
- **(B) Compile-out** (stage B, §11) — the mem/ factorization LANDED (**#80**) and the one-organ mechanism PoC LANDED (**#81**, M26); full stage B across every organ is a separate reviewed landing, operator-gated (veto point 3 below), with the symbol-absence guard and the wording flip.
- **(C) The channel follow-ups** (aarch64 lane, tb-vmm pass-through, guest flag) and the benchmark.
- **(D) The extraction milestones** (repo split, Yuva-ABI, backends) — separate proposals, explicitly out of scope.

**Operator veto points (named; none reachable from an unattended run):** (1) any change of the DEFAULT away from `agent` (touches CI's input — never silent); (2) the M12 substrate-placement decision (§3.2); (3) stage B's landing (image-splitting is a product decision) and any first use of "not present"; (4) admitting any external agent artifact through the M18 seam (the extraction line's gate); (5) any weakening of the three-wordings rule, the anti-hollow inversion, or the census mechanism; (6) renegotiating byte-identity for a future default=substrate.

## 13. Ledger + docs fan-out (written WITH the landing)

- **`kernel/src/profile.rs` (NEW)** — the selector, the `AtomicBool`, `agent_organs_enabled()`, the profile witness emitter.
- **`kernel/src/main.rs`** — the ~17 gated blocks + skip markers (prefixes taken verbatim from the landed literals); the chokepoint denial + promotion-refusal exercise; the substrate-arm khash call; the M31 Option tuple.
- **`kernel/src/bootreport.rs`** — the M12 row split; the profile-aware INFO line; the adjective-free substrate summary tail (`:319` made profile-aware).
- **`tools/xport-harness/src/live.rs`** — the last stray "Cogi" literal.
- **`scripts/run-substrate-x86_64.sh` (NEW)** + **`scripts/gen-witness-census.sh` (NEW, §8.2c)** + **`.github/workflows/ci.yml`** (additional job: substrate boot + default-boot tripwire); **`run-{x86_64,aarch64,vmm-x86_64}.sh` — ZERO lines changed**; `empty-diff-proof.sh` used at landing per DoD-1 (local, honestly not CI-wired); `test-industrial-boot.sh` extended per DoD-4.
- **`docs/proposals/industrial-boot.md`** — a dated correction note: M38 stage-B landed; the §10 compile-out deferral is picked up by this proposal.
- **`docs/{MILESTONES,ARCHITECTURE,ROADMAP-V2}.md`** — the two profiles, the honesty ladder, the substrate lane.
- **`LANGUAGE-AND-STANDARDS.md`** — the three-wordings rule; the skip-form-vs-absence grammar + string-equal-prefix rule; the DEFAULT-agent invariant; the lane-level (not per-guard) cross-lane-rejection statement; the agent-neutral terminology rule (never "Cogi" in this repo; "sovereign" ledger-bound, agent render only).
- **`assumptions.md` NEW rows** — default=agent preserves byte-identity on three surfaces (proven at landing, tripwired per-run); stage-A omission is runtime-gated (code present); the unsafe core is shared; the substrate lane's census-derived negatives are the not-run proof; the M20 round-trip is organ-free per the DoD-6 audit.
- **`.claude/skills/tabos-milestone/SKILL.md`; `docs/plans/INDEX.md`; `docs/BACKLOG.md`; the tracker task.**

## 14. Roadmap context

Boot Profiles is the hinge between two roadmap lines: **downward**, it productizes the sovereignty-plan M34 substrate line as a **profile-scoped Firecracker-alternative core** (kernel + caps + L2 hypervisor + M19/M20 + tb-vmm — bootable alone, honestly declared, guest evidence still aarch64-agent-lane at stage A); **upward**, it is step 1 of the yuva/agent separation directive — the in-repo proof that the organ layer (`docs/research/cogi-cognitive-architecture.md`'s composable MEMORY/LEARNING/REASONING/SKILL organs around a retrieval store) gates off cleanly at a pinned seam **at the execution/admission level**, before the M38 spine grows further. Named successors: stage-B compile-out (the first measured code-TCB delta and the code-level separability proof), the mem/ engine/organ factorization, the aarch64/vmm/guest channels, the substrate benchmark, and — in their own milestones — the `cogitave/cogi` extraction, the frozen Yuva-ABI, and pluggable agent backends.

## 15. Adversarial review

Two independent adversarial reviews of the V1 draft, both **SOUND-WITH-AMENDMENTS** (2026-07-08). Every must-fix is applied in this V2; every flagged overclaim is withdrawn or bound to an honest token. The ledger:

**Review 1 must-fixes → resolutions:**
1. **M18/M18.1 vs chokepoint-denial contradiction** (kept M18/M18.1 selftests exercise `M_MEM_WRITE_PROC` expecting Ok at `main.rs:2868,2873` → denial would fail-exit every substrate boot at `m18_fail`, and those skill writes ARE memory-organ exercise) → resolved by **gating the M18/M18.1 selftests** with skip forms while keeping the admission MECHANISM as the deny gate (§2.3, §2.4); §3.2's row wording and §5.1's stream updated consistently; the full deny set (incl. `M_MEM_WRITE_PROC`) retained.
2. **False skip-reject claim** (`run-x86_64.sh:709` matches only `skip|single organ|always-accept`) → the claim is withdrawn and §2.3(2)/§8.2e rewritten: cross-lane rejection is lane-level via positive witness/tail guards; the suffix is changed to the aL2.4b `skipped` grammar so the :709 regex additionally fires; no verifier edited (`cross-lane-reject=LANE-LEVEL-POSITIVES-NOT-PER-GUARD`).
3. **Accidental marker renames** (`M16: infer-bridge OK`, `M30: transport OK` vs the landed `M16: infer OK` `:2573`, `M30: infer-transport OK` `:4810`) → corrected everywhere; **DoD-5** added: skip-form prefixes mechanically checked string-equal to landed literals.
4. **DoD-1 mischaracterization** (`empty-diff-proof.sh` is local, in no CI workflow) → downgraded to the landing-time local proof matching the industrial-boot precedent, plus a NEW per-run CI default-boot tripwire in the substrate job (§8.2a, `dod1=LOCAL-LANDING-PROOF+CI-TRIPWIRE`).
5. **Incomplete negative-grep list** (missing `mem:` `:1635-1683`, `conduct-step:` `:5216`, `cost:` `:5293`) → added, and the ABSENT list is now **census-derived** by a committed generator script, re-run and diffed in CI (§8.2c).
6. **khash-hoist byte-identity hazard** (duplicate emission on the agent stream) → specified: agent-profile emission site UNCHANGED inside `opcmd_selftest`; the standalone KAT emits **only on the substrate arm**; exactly one emission per boot on either profile (§3.3, `khash-hoist=SUBSTRATE-ARM-ONLY-EMISSION`).

**Review 2 must-fixes → resolutions:**
1. **Marker literals** → same as R1-3, fixed + DoD-5.
2. **Skip-reject falsity + positive-substring-grep reality** (skip forms DO satisfy substring greps like `grep -qF 'M21: kan-policy OK'`) → both halves of the recommended fix taken: honest lane-level rewording AND the `skipped` suffix; the per-guard "NEVER satisfy" claim withdrawn; zero-verifier-lines-changed reconciled (§2.3).
3. **Pillar overclaim** ("stands alone as a genuine Firecracker-alternative micro-VMM … isolation + guest-running", unwitnessed on any stage-A substrate boot) → pillar rewritten to the approved phrase "Firecracker-ALTERNATIVE core, profile-scoped" + `substrate-guest-evidence=AARCH64-AGENT-LANE-ONLY-AT-STAGE-A` on the witness line; tail marker renamed `PROFILE: substrate OK` (no `-vmm`).
4. **"Separability PROOF" overstatement** → scoped everywhere to **execution/admission-level** at stage A; code-level separability explicitly a stage-B obligation post-mem/-factorization (`separability=EXECUTION-ADMISSION-LEVEL-AT-STAGE-A`); the M20 call-path audit promoted to a landing BLOCKER (DoD-6, `m20-organ-overlap=AUDIT-REQUIRED-AT-LANDING`).
5. **Unbacked "sovereign" in the title** → dropped from the title/one-liner; the term bound to its sovereignty-plan ledger sense on the AGENT render only; the substrate summary tail specified adjective-free, superseding the inherited `bootreport.rs:319` string (§1.5, `sovereign=LEDGER-BOUND-AGENT-RENDER-ONLY`).
6. **Unexercised promotion-refusal claim** → DoD-3 extended to exercise BOTH the M11 chokepoint denial and the M18.1 ADMITTED-tier promotion refusal in-boot, witnessed as `promotion=REFUSED-AT-GATE` (§2.4, §9).

**Accuracy nits applied:** M18 evolve is `:2788-2978` and M18.1 `:2985-3147` (the draft's `:2995-3147` "M18/M18.1" citation was M18.1-only); the harness pin is enforced at `scripts/kani-shards.sh:75` (kani.yml `:88` is a comment); the rename citations corrected — and superseded by the working-tree finding that the rename has already landed (`View::Agent`, `demo.sh:50` `--cogi` deprecated alias; one stray in `tools/xport-harness/src/live.rs`) (§1.5); the two caught paraphrase-renames are memorialized as §5.4 lint fixtures.

---

## References

**In-tree (verified against the working tree, 2026-07-08):**
- `kernel/src/bootreport.rs` — `View` enum (`View::Agent` `:114`) + stage-A render-filter comment `:83-116`; `apply_cmdline` + `yuva.view=` `:224-255`; the HIDDEN INFO line `:375`; the "sovereign agent-native OS" pretty tail `:319` (made profile-aware by this proposal); substrate summary/tally `:322,423-443`. *(The seed: a pure render filter; the parse point to extend; the authored substrate row partition — incl. khash as a substrate row — the execution gate must realize.)*
- `kernel/src/main.rs` — cmdline seam `:304-313`; `tb_boot_consume` in-guest precedent `:324-331`; M12 marker `:1549`; M13 block/marker `:1560-1727` (`mem:` witnesses `:1635-1683`); `M16: infer OK` `:2573`; M18 evolve `:2788-2978` (`M_MEM_WRITE_PROC` writes `:2868,2873`); M18.1 gate `:2985-3147`; M20 + skip forms `:3925-3953`; M29 KAT inside opcmd `:4605-4693`; `M30: infer-transport OK` `:4721-4810`; M33 `:5033`; M38 conductor `:5057-5307` (`conduct-step:` `:5216`, `cost:` `:5293`). *(The exact gating anchors, the landed marker LITERALS the skip forms must equal, what stays, and the landed M38 tail.)*
- `crates/tb-boot/src/lib.rs` — `TB_BOOT_FLAG_IN_GUEST = 1<<0` `:106`; frozen `cmdline_ptr/cmdline_len` offsets 32/40 `:300-320,386`. *(The boot-flag precedent and the zero-growth tb-vmm channel.)*
- `crates/tb-hal/src/lib.rs:882` (`boot_cmdline_x86` — PVH-only today) and `crates/tb-hal/src/mem/{mod.rs,selftests.rs}` (~4,345 lines; `KAN_ACTIVE=false` at mod.rs:273). *(x86-first channel reality; the M20/mem entanglement behind DoD-6.)*
- `scripts/run-x86_64.sh` — `MARKER='M38: conductor OK turns=6 organs=3 verdict=ACCEPT'` `:37`; the ONE regex-style skip-reject `:709` (`(skip|single organ|always-accept)` — the reason the suffix says "skipped"); exact-string positive/skip guards (substring-style positives WOULD match skip forms — the lane-level-rejection reality, §2.3); zero `-append` across `scripts/run-*.sh`; lanes at `.github/workflows/ci.yml:64,69`. *(Proof the required lanes ARE the agent profile; the grammar the substrate lane mirror-inverts.)*
- `scripts/kani-shards.sh:75` — `EXPECTED_HARNESSES_TOTAL=122`, the ENFORCED pin (kani.yml:88 is documentation only). `scripts/empty-diff-proof.sh` — the LOCAL two-repo baseline tool (in no CI workflow; DoD-1's honest scope). `scripts/demo.sh:50` — the `--cogi` deprecated alias, the rename's residue.
- `docs/proposals/industrial-boot.md` §3.2 (V2-must-fix-3), §5.2-5.3, §6, §10 — the render-filter honesty ruling, the DEFAULT-unchanged + landing-time empty-diff pattern this proposal's DoD-1 honestly matches, and the named compile-out deferral this proposal fulfills (its `grep -c M38 = 0` claim now stale).
- `docs/proposals/aL2.4b-full-kernel-guest.md` §2.6-2.7, §5 — the landed second-acceptance-profile precedent: lane-legitimate `skipped` forms, strip-then-assert, the banned-vocabulary list carried forward.
- `docs/research/cogi-cognitive-architecture.md` §2, §2.1, §2.4 — organs as composable capabilities around a retrieval store; the documented seam the profile follows (M20 storage substrate-side, M13 organ exercise agent-side).
- `docs/plans/sovereignty-plan.md` — the M34 substrate line; principle 1 (sovereignty as a machine-checkable ledger claim — the binding for the word "sovereign", §1.5); the kernel-never-hosts-an-engine boundary keeping M32 host-side in both profiles.
- `docs/proposals/M38-conductor.md` — the marker-displacement and exercise-the-gate disciplines reused here (the latter now applied to the promotion refusal too, DoD-3).

**External precedent:**
- Agache et al., *Firecracker: Lightweight Virtualization for Serverless Applications*, NSDI 2020; https://github.com/firecracker-microvm/firecracker — feature-set minimization = attack-surface/TCB reduction; the "omit, don't hide" idiom.
- https://github.com/cloud-hypervisor/cloud-hypervisor — small-Rust-codebase security posture; fewer compiled-in features = smaller attack surface (the stage-B argument).
- https://github.com/Solo5/solo5/blob/main/docs/architecture.md — minimal guest-host interface, modular tenders; the model for keeping M18 as the sole opt-in seam.
- Steinberg & Kauer, *NOVA: A Microhypervisor-Based Secure Virtualization Architecture*, EuroSys 2010 — quantified privileged-image decomposition precedent.
- seL4 / TrustVisor TCB-reduction literature — the security claim attaches to what is ABSENT from the trusted image, which is why absence must be machine-verifiable (the symbol-absence guard), not asserted.

**The three research strands (synthesized above):** strand 1 (runtime-gate mechanism, gating-point enumeration, chokepoint denial, khash refactor, non-default-only witness); strand 2 (the honesty ladder, the three-wordings rule, absence-by-omission at compile-out, the ~20 KLOC delta accounting, the anti-minimal token amendment); strand 3 (the neutral-term rename, the M20/mem entanglement finding, the M12 socket argument, separation-not-extraction scoping, "split the spine, not the embryo"). **Plus the two adversarial reviews (§15), whose twelve must-fixes shaped this V2.**