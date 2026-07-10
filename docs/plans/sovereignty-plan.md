---
type: Roadmap
title: "The full-sovereignty plan — reconciled roadmap (M29 → M37 + phases B/D)"
description: "Reconciled M29-M37 sovereignty roadmap: mocked-inference, vendored-llama.cpp debt named; per-milestone DoD/markers/deps graph."
tags: ["roadmap", "sovereignty", "milestones", "kernel", "provenance", "attestation"]
timestamp: 2026-06-11T14:39:26+03:00
status: active
diataxis: reference
---

# The full-sovereignty plan — reconciled roadmap (M29 → M37 + phases B/D)

**Status:** adopted (operator plan, adversarially reviewed) · **Origin:** the operator's directive document (`TABOS-EGEMENLIK-PLANI.md`, 2026-06-11) reconciled against the repo by a 3-reviewer ultracode audit (feasibility vs codebase / conflict+numbering / risk+honesty) — verdict **sound-with-amendments**; every amendment below is baked in. · **Tracker:** tasks #86–#98 carry this plan with the dependency graph. · **Discipline:** every milestone goes through the standard pipeline (research proposal → tb-encode verified leaf (Kani) → adversarial review → both-arch build+boot → docs/scripts → PR-loop, 2× green). No step is skipped.

> **What full sovereignty means (principles, as amended):**
> 1. **Zero UNACKNOWLEDGED external dependencies.** (Restated from "zero permanent" — rustc nightly, Kani, QEMU and the vendored builder toolchain are honestly permanent. The claim is machine-checkable: a sovereignty ledger — `dep + status TEMPORARY|ACCEPTED-PERMANENT|QUARANTINED` — is emitted inside the M33/M36 attestations.) Vendored llama.cpp is TEMPORARY debt with a grep-enforced closure plan (B3).
> 2. **The kernel never hosts an engine.** Float/GPU/nondeterminism stay out; even the sovereign engine lives in a separate domain (host daemon / driver-VM). Sovereignty = owning the code, never loosening isolation.
> 3. **Endure > Excel > Evolve applies recursively.** The frozen root shrinks from "the whole kernel" to a small monitor + evaluator + rollback machine; everything above it enters the challenger loop.
> 4. **Every stage is proven at boot.** Work that prints no marker is work that did not happen. Candidate-printed text is UNTRUSTED across promotion boundaries (see M34).

## Reconciled numbering

The operator plan's numbers collided with `docs/proposals/M29-crypto-mac.md` (merged to main 2026-06-11, which binds **M29 = khash**). khash is the plan's true first item (research complete); every plan number shifts +1:

| Plan item | Was | Now | Tracker | Marker |
|---|---|---|---|---|
| khash KEYED-CRYPTO MAC (inserted as A0) | — | **M29** | #86 | `M29: khash-mac OK` |
| A1 infer-transport | M29 | **M30** | #87 | `M30: infer-transport OK` |
| A2 real Anthropic adapter | M30 | **M31** | #89 | `M31: infer-e2e OK` (+ secret-gated `M31: real-infer OK`) |
| B1 local llama.cpp daemon | M31 | **M32** | #90 | `M32: local-infer OK` |
| C1 crypto lineage (re-scoped) | M32 | **M33** | #91 | `M33: prov-lineage OK` |
| C2 champion/challenger | M33 | **M34** | #92 | `M34: challenger OK` |
| C3 A/B + rollback | M34 | **M35** | #93 | `M35: ab-rollback OK` |
| C4 builder domain | M35 | **M36** | #94 | `M36: self-build OK` |
| C5 suggestion loop | M36 | **M37** | #96 | `M37: evolve-loop OK` |
| B2 GPU driver-VM / B3 pure-Rust engine / D-phase | — | unnumbered until proposal time | #98 / #95 / #97 | — |

Rule: no milestone starts until this document and the corresponding `docs/proposals/` entry agree on the number and marker.

---

## Phase A — communication ("hello" chain; no hardware gate)

### M29 — khash KEYED-CRYPTO MAC (#86) — the true first landing
Per the merged proposal: BLAKE2s-256 (RFC 7693) native keyed mode as ONE verified leaf `tb-encode::khash`; stage A+B = leaf + the M28 MAC cutover (derive-then-MAC, `mac=KEYED-NONCRYPTO → mac=KEYED-CRYPTO`); stage C = the FNV→khash `prov_hash` cutover. `EXPECTED_HARNESSES` 80→84. **#77 (Kani CI caching) lands before/alongside stage C** (declared ×1.5–3 fold-cost risk against the 45-min lane). Tokens per proposal §7; `kan_active=0` and `oracle=SIMULATED-ENROLLED-KEY` stay verbatim.

### M30 — verified inference transport (#87)
Bidirectional virtio-mmio request/response channel; frame codec as a Kani-proven leaf (starting point: the M22-proposal runner-up, `M22-memory-provenance.md` §runner-up); **tb-vmm's FIRST host-side virtio device backend** (BACKLOG row 23's deferred remainder — tb-vmm's mmio_bus is empty today, x86/KVM/Linux-only, exit loop sized for M0–M4 boots).
**Anti-hollow (mandatory):** the DoD requires a **host-applied khash-transformed echo** (host-held key/nonce, kernel-verified) so an in-kernel loopback can never pass — the exact hollow-pass exposure the M22 proposal demoted this design for. Per-lane tokens `transport=TB-VMM-HOST` vs `transport=QEMU-CHARDEV-HARNESS`; loopback variants rejected by name. The aarch64 host peer (no stock QEMU device carries this channel; tb-vmm has no aarch64 arch) is an explicit external-dependency decision to log in the proposal. Watch #71 if the channel ever moves from polling to completion IRQs.

### M31 — real Anthropic adapter (#89)
The bulk is the **byte-prompt/byte-response framing** (today's `InferRequest` is a u64 scalar toy; the variable-length path is explicitly deferred in `infer.rs`). HTTPS/TLS lives ONLY in the tb-vmm host bridge — write the TLS-outside-kernel decision into `LANGUAGE-AND-STANDARDS.md` (verified absent today) + a dependency-policy ledger entry for the rustls/reqwest-class host deps. **Dual markers:** CI-required `M31: infer-e2e OK backend=MOCK-DETERMINISTIC` (the only variant in the cumulative chain; lane rejects `real` nearby) and secret-gated optional `M31: real-infer OK backend=ANTHROPIC-LIVE` proving liveness via a per-run challenge nonce whose transform must appear in the response; request-id + response digest folded into the M25 transcript; missing secret = LOUD skip. **Injection-proofing:** untrusted model bytes are hex-encoded/regex-inert before serial (grep guards are not line-anchored — model text could forge a marker). Tokens `key=CAPREF-HOST-CUSTODIED host=RESIDUAL-TCB`; zero-ambient-authority is claimed in-GUEST only; `assumptions.md` gains the host-bridge residual. **Not fit for an unattended overnight run** (network + secrets).

---

## Phase B — the local mind

### M32 — local inference daemon (#90) — TEMPORARY debt, grep-enforced
Honestly a **host Linux process** (the sovereignty ledger says so — "separate driver daemon" must not overstate isolation) serving `model:local/llama` over the M30 channel; vendored llama.cpp + `-sys` crate firewalled from the kernel workspace's zero-unsafe/zero-dep lanes and the pinned harness count. The witness REQUIRES `engine=VENDORED-C-LLAMACPP debt=SOVEREIGNTY-OPEN-B3 memsafety=UNSAFE-C-PROCESS-CONFINED weights=UNTRUSTED-INPUT-NAMED` — the debt is machine-checked, not prose-remembered. The GGUF parser is a named untrusted-input C attack surface. B3's closure test must be defined (in the B3 research note) BEFORE this lands.

### B2 — GPU driver-VM (#98, HARDWARE-GATED)
Implementation ticket for the standing SOVEREIGNTY-ROADMAP §6 [DECISION] (cite, don't re-decide): VFIO passthrough into a confined Linux driver-VM, vsock-only `model:` API. Honesty fix: L2.6 SMMUv3 is table-programming proven under QEMU only — the DMA-isolation GUARANTEE needs real silicon (`assumptions.md` A3). Gate = the IOMMU+GPU machine (NOT #37, which gates nested-VMX x86). Effectively a second, much bigger VMM — XL.

### B3 — the pure-Rust sovereign engine (#95)
Research-first eval of candle / mistral.rs / burn for a **std-Rust host daemon** (not no_std), C-free chain including the tokenizer per model family. The research note DEFINES the llama.cpp debt-closure test (output-equivalence or a quality bar) before M32 lands. Closure DoD: the local-infer lane flips to `engine=PURE-RUST` AND both run scripts gain a REJECT for `VENDORED-C` on that lane — closure is grep-enforced.

---

## Phase C — the OS's own evolution

### Prerequisite: aL2.4b — the FULL kernel as EL1 guest (#88)
The operator plan's "M34 = direct composition of M27 + L2.4" is **false as written**: M27's guests are store-spin stubs and L2.4 v1's nested guest is a stub in the same image. M34 needs the full M0..M28 kernel booting as an EL1 guest under stage-2: the aarch64 tb-boot guest-RAM loader, PL011/GIC/CNTP/virtio-mmio device-emulate paths, and an **in-guest acceptance profile** (EL2-dependent markers legitimately print `(no EL2, skipped)` in-guest, which today's anti-hollow guards reject). Marker `L2.4b: el1-kernel-guest OK` (SOVEREIGNTY-L2-ROADMAP Track B). XL; can run in parallel with the Phase-A arc.

### M33 — provenance lineage (#91) — exactly the M29 §9 remainder
The operator plan's "FNV→crypto hash" bullet is **deleted from this scope** (it IS M29 stage C — landing it twice would double-count a sovereignty claim). Scope: (1) a Kani-proven **signature** primitive leaf (#74's signed-root half; a separate, heavier primitive than khash — likely the first vetted-crypto-dependency decision); (2) the SIGNED prov head **persisted to M20** (a genuinely new contract — heads are per-boot in-RAM today); (3) the **SLSA-style attestation codec** leaf for code/image lineage (consumed by M34/M36; doubles as the machine-readable sovereignty-ledger carrier); (4) the signing key inherits `oracle=SIMULATED-ENROLLED-KEY` (real enrolment stays #85). Marker `M33: prov-lineage OK` (the original `crypto-prov OK` violates the M29 §7 bare-`crypto` marker discipline). DoD: signature-tamper caught + head survives reboot (two-boot harness) + attestation decodes. Tokens `sig=<scheme> sec=ASSUMED-FROM-LITERATURE key=SIMULATED-ENROLLED sidechannel=NOT-CLAIMED`. Sequenced after M29 stage C (colliding `prov.rs` edits).

### M34 — champion/challenger kernel (#92)
**Trust-boundary rule:** candidate-printed serial is UNTRUSTED BYTES — a malicious candidate prints the whole M0..M28 chain for free, so marker-grep carries zero evidential weight across this boundary. The EL2 monitor trusts only: the M33 attestation (**image identity**, assumption-conditional), monitor-counted **trapped-MMIO forward-progress cells** (the M27 pattern), EL2 **identity-alias readbacks of monitor-chosen per-boot nonces** at chain checkpoints (the L2.4 pattern), and **rotated monitor-private held-out probes** absent from the candidate-visible tree (the M18.2 anti-Goodhart discipline). The chain acceptor is a Kani-proven tb-encode leaf over witnessed events — never a string parser in the TCB. Tokens `verdict=SUITE-PASS-OBSERVED candidate-trust=NONE marker-channel=UNTRUSTED-TEXT attest=IMAGE-IDENTITY-ONLY`. Promotion is high-impact → the M18.1 + M28 human gate is REQUIRED. The DoD never claims candidate correctness/safety — "passes-suite-now does not bound future behavior" is a named residual in `assumptions.md`. x86 lane: loud `(hardware-gated #37, skipped)`.

### M35 — A/B slots + rollback (#93)
**Custody rule:** slot selection + boot-counter custody live on the FROZEN side (loader/tb-vmm, or the EL2 monitor for nested candidates) — never in the kernel under test (the Android A/B analogy works because the *bootloader* owns slot metadata). The M20 superblock/gen-bump pattern is reused for slot METADATA only, candidate access stage-2/SMMU-confined; the revert deadline is monitor-armed via CNTHP (the M27b machinery). The DoD includes the adversarial cases: a candidate that ATTEMPTS to write slot metadata is denied with a witnessed stage-2 fault, AND a candidate that hangs pre-marker is reverted by the deadline. Needs a new two-boot persistent-disk CI harness (CI deletes the scratch disk each run today). Token `slotmeta=MONITOR-CUSTODY`. The boot counter is NOT a freshness clock (#85 stays separate). M35's DoD is extended to ALSO custody the durable never-decrement LMS leaf-index counter named by the M33 docs (`docs/proposals/M33-prov-lineage.md`, `assumptions.md`) — same frozen-side monitor, same future persistent-disk CI lane; it is ONE milestone, not two.

### M36 — builder domain (#94)
Honest first cut: a host-side hermetic jail (container/QEMU-Linux) with a vendored pinned toolchain and default-deny network — stated as host ops-tooling or logged as debt. The vsock contract ("source in → image + proof bundle + attestation out") becomes a Kani-proven codec leaf. **Reproducibility token ladder:** `repro=BIT-IDENTICAL-2BUILD` earned ONLY by an in-run double-build hash compare with the one-perturbed-byte negative control; honest fallback `repro=ATTESTED-SINGLE-BUILDER` (the SLSA L2-vs-L3 distinction). `M36: self-build OK` is never emitted on the fallback tier without its token; the word "reproducible" is banned near the marker unless the 2-build compare ran this boot (strip-then-reject). The toolchain hash is always in the M33-format attestation.

### M37 — the suggestion loop (#96) — composition-only capstone
No new mechanism — composition only; every upstream slip lands here. Design the telemetry EXPORT seam (M25-frame or M20-persisted) so the userspace suggestion agent reads real M26 data without violating the producer-only invariant; **re-document `signal=OBSERVATIONAL-NONCAUSAL` as a RUNTIME-IN-KERNEL-scope claim** — the system-level exit→patch→exit loop IS being closed here (the exact loop M26 §2.4 scoped out) and carries its own tokens: `loop=CROSS-GEN-HUMAN-GATED evidence=SELF-TELEMETRY-CONFOUNDED suggestion=HYPOTHESIS-ONLY`. Telemetry generates HYPOTHESES only; acceptance evidence is exogenous — the M34 witnessed regression + rotated held-out probes + the M28 human approval, with gate inputs enumerated on the witness citing ZERO telemetry-derived metrics; the curriculum daemon never sees the promotion scorer. Reject `learned|validated|causal` near the marker. DoD: ONE real end-to-end improvement lands this way.

---

## Phase D — its own model (#97, umbrella)

Mostly future-vision; ONE actionable first leg: M23 trace EXPORT plumbing (records are in-RAM per boot today) + the offline kancell retrain pipeline (traces → offline training → a new envelope-bounded const knot table → the M24 gate), honoring training-outside-kernel. The distilled-local-model leg has NO data source until real inference traffic (M31/M32) accumulates. **D2 discipline:** every gate run PRE-REGISTERED (frozen table+split hash written to the transcript BEFORE evaluation; `gate=PREREGISTERED-ONE-SHOT`; one evaluation per frozen pair — a refusing gate stays a SUCCESS). Training-set admission is provenance-filtered + tombstone-excluded (`trainingdata=PROVENANCE-FILTERED-SELF-GENERATED` — still confounded, said so; the memory-poisoning residual named in `assumptions.md`). D3 is re-scoped as the first Evolution Service API verb (capability-gated, local-only, BULK-class); the API layer itself (SELF-IMPROVEMENT-SPEC §2) is the missing prerequisite. Additionally blocked by #85's pending-flag→M24 seam.

---

## Dependencies, first moves, hardware

```
#86 M29-khash ──→ #87 M30 ──→ { #89 M31, #90 M32, #98 B2(hw) }
   └──→ #91 M33 ──→ { #92 M34 (also needs #88 aL2.4b), #94 M36 }
                        #92 ──→ #93 M35
{ #89, #90, #93, #94 } ──→ #96 M37
#90 ──→ #95 B3 (research starts immediately; cutover after M32)
{ #85, #89, #90 } ──→ #97 FAZ-D umbrella
```

**First moves (replacing the original "A1+A2 night run"):** M29-khash stages A+B (+C if the lane budget holds; **#77 Kani caching promoted to land before/alongside stage C**) + the M30 research proposal in parallel; aL2.4b design can also start in parallel (aarch64-only, no A-chain dependency). M31 is unfit for unattended runs (network + secrets + the unbuilt tb-vmm backend).

**Hardware shopping list (the only thing software doesn't wait for):**
- nested-VMX x86 machine → the x86 L2 chain + M34's x86 lane (#37)
- IOMMU (VT-d/AMD-Vi/SMMUv3) machine + GPU → B2 (#98)
- a KVM Linux host for continuous CI/runs (WSL2 is the interim)

**Invariants (every milestone):** framekernel (all unsafe/asm in `tb-hal` only); every new codec a Kani-proven `tb-encode` leaf with the pinned, fail-closed harness count; every DoD a serial marker asserted on both arches per push; zero ambient authority; the human-approval gate (M18.1/M28) never bypassed on high-impact; candidate/model text never trusted across a promotion or serial boundary.
