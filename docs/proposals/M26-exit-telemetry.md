---
type: Design Decision
title: "M26 — Verified EL2 exit-telemetry producer"
description: "Verified EL2 exit-telemetry: folds each guest exit into a no-float histogram record on the M23 experience stream; producer-only, non-causal."
tags: ["m26", "el2", "telemetry", "learning", "kani"]
timestamp: 2026-06-10T18:00:11+03:00
status: locked
diataxis: explanation
---

# M26 — Verified EL2 exit-telemetry producer (the OS records its own virtualization workload)

**Status:** proposed (build) · **Pillar:** learning (the experience stream's second PRODUCER) + a bridge to sovereignty · **Depends on:** M22 (provenance fold), M23 (experience stream + xp_head), L2.2 (`el2_trap` ESR_EL2.EC classifier) · **Marker:** `M26: exit-telemetry OK`

> **One-line:** the aarch64 EL2 (nVHE) monitor already demuxes every guest exit by `ESR_EL2.EC` (WFx / sysreg / data-abort-MMIO / HVC / iabt / stage-2 fault) through the **already-Kani-proven** `tb-encode::el2_trap` classifier. M26 turns that demux into a **bounded, fixed-point, injective, verified TELEMETRY RECORD** — each exit becomes one structured record (exit-class + a saturating no-float log-bucket histogram + logical time) folded into the **M23 experience stream via the M22 fold reused verbatim**, so the OS *records* its own virtualization workload. **PRODUCER-ONLY by construction:** the telemetry is recorded and folded; it does **not** this milestone influence any policy whose decisions change the future exit distribution (the algorithmic-confounding feedback loop the M24 adversary named — restated for an exit stream — is structurally avoided). **Honest by construction:** the marker emits `signal=OBSERVATIONAL-NONCAUSAL` so it mechanically cannot claim the telemetry is a valid causal state-signal.

This is the output of a research-first arxiv/standards survey (VMI / exit-accounting, learned-from-traces scheduling, bounded streaming aggregation, and the self-logging confounding pitfall — see [`docs/research/m26-exit-telemetry-literature.md`](../research/m26-exit-telemetry-literature.md)). Every mechanism is cited; where M26 goes beyond the literature it is flagged.

---

## 1. Why this is M26 (and why A-alone)

The learning loop has a Monitor (M23 experience codec), an honest gate (M24), and an outbound operator channel (M25). What it lacks is a **second, richer source of experience**: today the only experiences are M17 forget/recall decisions. The EL2 monitor is a privileged, isolated vantage point (Garfinkel & Rosenblum, VMI, NDSS 2003) that **already** classifies every guest exit — so the cheapest, soundest next experience producer is the virtualization workload itself.

M26 is scoped to **Strand A only** (the telemetry producer). The two sibling strands the survey identified — a **two-VMID sovereign time-partition scheduler** (M27) and the **operator INBOUND channel** (`opframe` RX + an enrolled-key activation command, M28 — the capstone that finally delivers the exogenous-oracle command the whole M23→M24→M25 loop was built to receive) — are deferred. Rationale: A is near-pure **reuse** (the exit classifier + the experience fold both exist and are Kani-proven), producer-only sidesteps the one hard problem (the confounding loop), and it lands CI-green with a synthetic-vector self-test and no new HAL runtime — the surest overnight increment. B carries new EL2 runtime + a two-guest harness; C carries a *keyed* construction whose honesty boundary deserves its own milestone. All three ultimately feed the **same** `xp_head`, so they should extend `kind::*` tags sequentially against a stable, already-proven fold rather than racing three concurrent schema changes against the M23 schema-stability lemma.

---

## 2. The design (cited, mechanism by mechanism)

### 2.1 The exit class — REUSE the already-verified classifier
A new `tb-encode::exittel` leaf (no_std, forbid-unsafe, no-float, zero-dep, Kani-proven). Its `ExitClass` u8 enum **is literally the `el2_trap::EC_*` set** — `EC_WFX (0x01)`, `EC_HVC64 (0x16)`, `EC_SYS64 (0x18)`, `EC_IABT_LOW (0x20)`, `EC_DABT_LOW (0x24)`, plus a stage-2-translation-fault class via the existing `el2_trap::esr_is_translation_fault`, and an `OTHER` catch-all. The classifier `el2_trap::esr_ec` is **already Kani-proven total** (L2.2), so the exit-class is a *verified* projection, not an invented one — M26 writes no new ESR decoding.

### 2.2 The bounded fixed-point histogram (no float, total)
Each exit carries an exit-handling **cost proxy** (a bounded cycle/logical-tick delta the monitor already has). M26 buckets it by an **integer log2 index** (`63 - delta.leading_zeros()`, clamped to `N_BUCKETS`) — the OpenTelemetry **exponential-histogram** base-2 *idea* without the float mapping, and the HdrHistogram dynamic-range *idea* without the float. Per exit-class, a **direct-mapped saturating `[u64; N_BUCKETS]`** counter array: saturating add → total, no overflow, no panic over all u64 inputs. (A direct-mapped per-class histogram is deliberately chosen over a Count-Min sketch: for the small *closed* `EC_*` set there are no hash collisions to bound, so the count is *exact* per class, not probabilistic — the safer first increment; Cormode-Muthukrishnan Count-Min remains the named successor if the class space ever opens up.)

### 2.3 The record + the fold — REUSE the M23/M22 stream
A fixed-field, fixed-width, injective `canon`/`decode` pair mirroring `exp.rs` (every field at a fixed offset; total + fail-closed on a too-small buffer; reject unknown class/version). An `ExitTelemetryRecord { exit_class, bucket, count_in_bucket, logical_time, vmid }` is folded into the **existing `xp_head`** via `exp::xp_append` / `exp::xp_chain_mix` (the M22 fold, reused verbatim — **no new fold math**), under a NEW `kind::EXIT_TELEMETRY` tag so an exit record can never masquerade as an M23 forget-decision (the tag is folded into the digest → the byte differs → the head differs). The M23 `xp_head` schema-stability lemma is honored: the new record kind extends the tag space; existing M23 record offsets are untouched.

### 2.4 PRODUCER-ONLY — the confounding firewall
The single load-bearing soundness decision (§5 of the survey): the telemetry is **recorded and folded, never fed to a policy whose decisions change the future exit distribution** this milestone. Learning from one's own logs is confounded and the OPE bias is *non-identifiable and untestable* (Chaudhry et al., arXiv:2309.04222; the algorithmic-confounding feedback-loop line, Chaney et al. 2018) — the *exact* exogeneity problem the M24 adversary named, now for an exit stream. M26 does **not** close any exit→policy→exit loop. The honesty token `signal=OBSERVATIONAL-NONCAUSAL` makes the marker say so.

---

## 3. DoD — `M26: exit-telemetry OK` (the boot self-test)
The boot self-test (QEMU/TCG, no human/network/hw) feeds a FIXED synthetic `ESR_EL2` vector (one of each `EC_*` class + a stage-2 fault + an OTHER) through the demux, records each into the `exittel` ring + folds into a SEPARATE telemetry head (or the shared `xp_head`), then verifies: (a) each ESR maps to EXACTLY one class (totality + the verified projection); (b) the per-class histogram buckets are bucket-EXACT for the synthetic deltas; (c) the folded head matches a frozen recompute + a genuine inclusion proof; (d) a single-byte tamper of a committed record is caught. It prints, fail-closed:
```
exittel: head=<hex16> records=<n> classes=<m> buckets-exact=1 fold-verified=1 tamper-caught=1 signal=OBSERVATIONAL-NONCAUSAL
M26: exit-telemetry OK
```
The run-scripts positively **require** the `exittel:` witness with `buckets-exact=1 fold-verified=1 tamper-caught=1`, **require** the honesty token `signal=OBSERVATIONAL-NONCAUSAL`, **reject** any `validated`/`causal`/`learned` near the marker, and fail-closed withhold the marker if any leg fails. `EXPECTED_HARNESSES` 64 → ~68.

---

## 4. Kani obligations (each with a negative control; measure locally first)
1. **canon injectivity + totality** — distinct records → distinct bytes; never panics, fail-closed 0/None on a short buffer; reject unknown class/version. *Neg:* a dropped field offset lets two records alias.
2. **class totality (the verified projection)** — every `ESR_EL2` maps to EXACTLY one `ExitClass` (reuse the `el2_trap::esr_ec` proof shape). *Neg:* a missing arm leaves an ESR unclassified.
3. **histogram saturation** — the bucket counter saturates (no overflow/panic) over ALL u64 deltas + counts; the log2 bucket index is in `0..N_BUCKETS`. *Neg:* a `+=` without saturation overflows.
4. **fold tamper-sensitivity** — a single-byte flip of a committed record changes the recomputed head (reuse the M22 fold tamper proof over the new record type). *Neg:* a constant fold accepts a tampered record.
5. **canon round-trip** — `decode(canon(rec)) == rec` (the fixed-width bijection). *Neg:* a layout swap transposes fields.

---

## 5. Honest caveats (conceded — encoded as the witness token)
- **OBSERVATIONAL, NON-CAUSAL (`signal=OBSERVATIONAL-NONCAUSAL`).** The exit stream is self-generated and confounded; it is NOT validated as a causal state-signal for any decision. M26 records; it does not learn. Closing an exit→policy loop is explicitly out of scope (and would need the M24 honest-gate discipline, on a *representative* distribution).
- **Per-class counts are exact; cross-class cost attribution is not.** The cost proxy (cycle/tick delta) is a coarse handling-time, not a validated cost model; the histogram bounds *distribution*, not *causal attribution*.
- **TCG timing is not cycle-accurate.** The cost-proxy buckets are a relative shape under emulation, not a hardware timing measurement — say so; do not quote latencies.
- **Producer only — the loop is NOT closed.** This milestone advances the *learning substrate* (a richer experience source), not learned behavior. The cell stays dormant (M24 unchanged).

---

## 6. Where M26 goes beyond the literature
- A **Kani-proven, no-float, in-EL2 streaming aggregation folded into a tamper-evident hash chain** is not in the prior art: `perf kvm` / eBPF exit histograms are float-tolerant, unverified, and have no provenance fold; Count-Min / OTel exponential histograms are not formally verified no-panic integer leaves. The *combination* (verified + chained + no-float + reusing one decidable M22 fold for exits, experiences, provenance, and the operator transcript) is novel. The novelty is claimed **narrowly** (a verified bounded encoder + fold), not a new aggregation algorithm.

---

## 7. Roadmap context (the deferred siblings)
- **M27 — two-VMID sovereign scheduler** (the sovereignty pillar): an EL2 monitor that time-partitions two guest VMIDs using the architectural EL2 physical timer (`CNTHP_*_EL2`; the x86 dual is the VMX-preemption timer), a minimal ARINC-653-style two-slot major frame, with each scheduling DECISION folded into the experience stream (sovereignty → learning). New EL2 runtime + a two-guest QEMU harness.
- **M28 — operator INBOUND channel (the capstone)**: `opframe` RX + an enrolled-key, freshness-bound (RATS RFC 9334 §10 nonce), head-bound (the Terrapin seq lesson), **dual-authorized** (two-person rule) `ACTIVATE_CMD` so a HUMAN can finally COMMAND the M24 gate — the exogenous-oracle CLOSURE the entire M23→M24→M25 loop was built to receive. Honestly scoped: `mac=KEYED-NONCRYPTO` (a keyed forward-secure aggregate checksum, FssAgg-shaped) unless/until a verified real MAC lands; `oracle=SIMULATED-ENROLLED-KEY` (the CI self-test proves the auth plumbing, never that a human commanded it, and must NOT actually flip `KAN_ACTIVE`).

---

### References
Full survey + citations in [`docs/research/m26-exit-telemetry-literature.md`](../research/m26-exit-telemetry-literature.md). Key: Garfinkel & Rosenblum (VMI, NDSS 2003) · Linux `perf kvm stat` / KVM tracepoints / eBPF exit histograms · Mao et al. (Decima, SIGCOMM 2019, arXiv:1810.01963) · Cormode & Muthukrishnan (Count-Min, 2005) · OpenTelemetry Exponential Histogram (OTEP-0149) · Chaudhry et al. (unobserved confounding in offline eval, arXiv:2309.04222) · Chaney et al. (algorithmic confounding, RecSys 2018).
