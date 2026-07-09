---
type: Design Decision
title: "M25 — Verified operator transcript (the exogenous-oracle channel)"
description: "Proposes a TX-only, keyless tamper-evident serial transcript leaf surfacing borderline decisions; no crypto auth, no real human oracle."
tags: ["m25", "communication", "tamper-evident", "attestation", "active-learning", "serial"]
timestamp: 2026-06-10T16:47:56+03:00
status: locked
diataxis: explanation
---

# M25 — Verified operator transcript (the exogenous-oracle channel)

**Status:** proposed (build) · **Pillar:** communication ("an OS that talks with its operator") · **Depends on:** M22 (provenance fold + head), M23 (experience records), M24 (gate verdict + held-out partition) · **Marker:** `M25: operator OK`

> **One-line:** a `tb-encode::opframe` leaf emits a typed, fixed-field, injective, **tamper-evident OUTBOUND transcript** over the serial console by which the OS **surfaces** what it recorded and decided — anchored to its M22 provenance head ("which instance am I"), with a running fold + strictly-monotone sequence so a reader detects any mutation, reorder, drop, or truncation. The transcript surfaces the **borderline** forget/recall decisions (active-learning) and the M24 gate verdict so a **human operator becomes the exogenous ground-truth oracle** the self-graded learning loop lacks (the adversary's verdict on M24). **TX-only** this milestone: inbound operator auth + the operator *commanding* the gate activation needs serial RX + an enrolled credential and is M26+ (it fails the no-human CI gate today). **Honest by construction:** the fold is keyless structural FNV, so M25 claims tamper-*evidence* under non-adversarial corruption — **not** cryptographic authenticity/non-repudiation (`keyed=0`), and **not** that a human has replied (`oracle=HUMAN-DEFERRED-M26`).

This is the output of a 4-arm arxiv research pass (RATS/attestation-identity, tamper-evident-transparency, human-oracle, OS-operator-channel; the synthesis is recovered from the four convergent arms — see [`docs/research/m25-operator-transcript-literature.md`](../research/m25-operator-transcript-literature.md)). Every mechanism is cited.

---

## 1. Why this is M25

M24's honest gate **correctly refuses** to activate the learned policy because there is **no exogenous oracle** — a self-graded policy with no external signal is theater (the conceded adversary verdict). The literature is unanimous: a **human (or external workload) is the only valid exogenous ground-truth oracle** for a self-graded loop (Christiano RLHF, arXiv:1706.03741; the Seldonian framework, Thomas et al. *Science* 2019). M25 builds the channel that surfaces decisions to that human — realizing the **communication pillar** *and* laying the exact path the M26+ RX/auth will consume to let a human clear the M24 gate.

---

## 2. The design (cited, mechanism by mechanism)

### 2.1 The frame + the running fold (REUSE the M22 fold verbatim)
A new `crates/tb-encode/src/opframe.rs` leaf (no_std, forbid-unsafe, no-float, zero-dep, Kani-proven). A fixed-field, injective, length-prefixed OUTBOUND frame:
```
{ magic:u16 | ver:u8 | kind:u8 {1=INTRO,2=MARKER,3=EXPERIENCE_DIGEST,4=GATE_VERDICT}
  | sev:u8 (OTel integer SeverityNumber 1..24; 9=INFO/13=WARN/17=ERROR, no float)
  | reserved:u8=0 | seq:u64 LE (STRICTLY monotone, +1 per frame) | t_logical:u64 LE
  | prev_head:[u8;32] | payload_len:u32 LE | payload[payload_len] }
```
folded into a running transcript head: `op_head' = prov::chain_mix(op_head, prov::prov_hash(canon(frame)))` — **REUSING the already-Kani-proven M22 `prov` fold** (`chain_mix`/`recompute`/`verify_inclusion`/`head_witness`), writing **no new fold math**, exactly as M23/M24 reused it. The kind/severity vocabulary mirrors the **OpenTelemetry LogRecord** data model (a typed EventName + an integer SeverityNumber) so the schema maps onto a recognized standard, not an ad-hoc one.

### 2.2 Identity anchor — the INTRO frame (attestation)
The first frame (`seq=0`) **binds the transcript genesis to the live M22 provenance `chain_head`** = "which instance am I". This is the RATS layered-attestation *staging* model (RFC 9334 §3.2: each measured layer becomes the attesting environment for the next) and the DICE identity-derivation *structure* (`head' = fold(head, entry_id)` is structurally DICE's `CDI = OWF(secret, measurement)` **minus** the per-device secret), yielding a **structural UEID** (an EAT-style Universal Entity ID, RFC 9711 — like a serial number, **not** a key-certified DeviceID). The self-test asserts `INTRO.prov_head == the live M22 head`, so a replayed/older transcript from a different boot cannot verify in isolation.

### 2.3 Tamper / truncation evidence — fold + strict-monotone seq
The four tamper properties a non-key-holding reader needs (Schneier-Kelsey 1999 forward-integrity; Ma-Tsudik FssAgg 2007):
- **Modification / reorder / insertion** — the running fold is order-dependent and a non-degenerate function of every byte, so a recomputed `op_head` *diverges* the moment any emitted frame is edited/swapped/inserted.
- **Truncation-of-tail** — the fold alone is blind (frames `0..k` are internally consistent for any `k`); the **strictly-monotone `seq` folded INTO the canon bytes** + the **closing GATE_VERDICT frame committing the final seq + running head** closes the gap (the FssAgg/Ma-Tsudik fix to the bare Schneier-Kelsey chain). The reader asserts **strict +1** monotonicity (not merely non-decreasing) so a dropped/duplicated middle frame is caught. (`seq` *must* be inside `canon()` before hashing — a side-label `seq` is renumberable without disturbing the head; the Terrapin lesson, arXiv:2312.12422.)

### 2.4 What to surface — borderline decisions (active learning) + the leakage guard
- **EXPERIENCE_DIGEST** frames surface **only the BORDERLINE decisions** — rank the M23 records by `|kan_score_shadow − heuristic margin|` (margin sampling) and forget-vs-counterfactual disagreement (query-by-committee proxy), each with its features, the action taken, the counterfactual `kan_score`, and the survival label `{Negative|Positive|Censored}`. Surfacing the *most-uncertain* decisions is the label-efficient query strategy (Settles, *Active Learning Literature Survey* 2009) — the few records a scarce human labels are exactly the ones that un-confound the M24 gate.
- **HELD-OUT LEAKAGE GUARD** (Seldonian + reusable-holdout, Dwork et al. *Science* 2015): the transcript MUST surface only candidate-selection-partition records and MUST NOT emit any record, label, statistic, or grid cell from the **sealed M24 safety partition** — every frame carries a `partition_id` and `canon()` **fail-closed asserts `partition != SAFETY_HELD_OUT`**. The human's eventual labels are a one-shot pre-registered gate input; adaptive resurfacing across boots cannot overfit the held-out (the precise reason M24's gate is currently vacuous — a snooped proxy).

### 2.5 Emission discipline (human factors + fail-closed)
TX-only over the existing 16550 / PL011 serial console. INTRO exactly once at boot; **EXPERIENCE_DIGEST aggregated/rate-limited** windows (NOT per-decision) so the steady rate stays near the EEMUA-191 / ISA-18.2 alarm ceiling (~1 / 10 min, never the <10-per-10-min upset rate) — per-decision emission would blow past it in milliseconds and make the human a useless oracle (alert fatigue). The TX path is backed by the existing `tb-encode::BoundedRing`: an overrun **drops-with-a-counted-overflow-marker** rather than growing or blocking the kernel (fail-closed backpressure).

---

## 3. DoD — `M25: operator OK` (the self-test plays the simulated operator-verifier)
The boot self-test (QEMU/TCG, no human/network/hw) **EMITS** a short transcript (INTRO → MARKER → EXPERIENCE_DIGEST → GATE_VERDICT) over serial, then **itself acts as the simulated operator-verifier**: recompute `op_head` via `prov::recompute`, assert `op_head == the running head`, assert `seq` strictly increasing with no gap, assert `INTRO.prov_head == the live M22 head` (instance binding), run `prov::verify_inclusion` on one EXPERIENCE_DIGEST frame, and **flip a single byte to prove the recompute REJECTS** (anti-hollow). It prints, fail-closed:
```
opframe: tx_head=<hex16> frames=<n> seq_monotone=1 intro_bound=1 fold-verified=1 tamper-caught=1 keyed=0 oracle=HUMAN-DEFERRED-M26
M25: operator OK
```
The run-scripts positively **require** the `opframe:` witness with `seq_monotone=1 intro_bound=1 fold-verified=1 tamper-caught=1`, **require** the honesty tokens `keyed=0` + `oracle=HUMAN-DEFERRED-M26`, **reject** any `validated`/`evaluated` near the marker, and fail-closed withhold the marker if any leg fails. `EXPECTED_HARNESSES` 58 → ~63.

---

## 4. Kani obligations (each with a negative control; **measure locally first**)
1. **canon injectivity + totality** — distinct frames → distinct bytes (incl. the length-prefixed payload + the partition_id); never panics, fail-closed 0/None on a short buffer; reject unknown `ver`/`kind`/reserved bits. *Neg:* an un-length-prefixed payload lets two frames alias.
2. **seq strict-monotone tamper-sensitivity** — the reader rejects `seq <= last` (a gap/dup/reorder); `seq` folded into canon → renumbering changes the head. *Neg:* a non-decreasing (`<=`) check accepts a duplicate.
3. **transcript-fold tamper + truncation sensitivity** — flipping any byte of any frame changes `op_head` (reuse the M22 `chain_mix` tamper proof over the new frame type); dropping the last frame is caught by the closing-commit seq/count. *Neg:* a constant/identity fold accepts a tampered frame.
4. **INTRO-binding soundness** — `op_head` verifies iff INTRO carries the *true* M22 head; a wrong anchor fails. *Neg:* an INTRO with a forged head still verifies (must fail the harness).
5. **partition-leak negative-control** — a `SAFETY_HELD_OUT`-tagged frame is **rejected** by `canon()`. *Neg:* a canon that ignores the partition tag emits a held-out frame.
6. **inclusion soundness** — `verify_inclusion` accepts iff the frame is in the transcript (reuse the M22 proof shape).

---

## 5. Honest caveats (conceded — encoded as witness tokens)
- **Keyless, structural only (`keyed=0`).** An unkeyed FNV fold is *publicly recomputable*; a stream-rewriting adversary can forge a self-consistent transcript+head. M25 claims tamper-**evidence** under *non-adversarial* corruption (line drops, serial glitches, accidental reorder, benign flips) + transport integrity — **not** forgery-resistance/non-repudiation. The successors are named: a **secret-keyed forward-secure aggregate MAC** (Schneier-Kelsey / FssAgg) for forgery resistance and a **signed history-tree consistency proof** (RFC 6962/9162 STH, Crosby-Wallach) for equivocation-proof append-only — both M26+, both needing the inbound credential M25 does not have.
- **No freshness/liveness.** TX-only, no RX, no trustworthy clock → no verifier nonce (RFC 9334 §10.2); `seq` + boot clock are epoch-ID-like SELF-assertions (§10.3), so a captured transcript can be replayed wholesale to a human who issued no challenge. Named, deferred to M26.
- **The simulated verifier is NOT the human.** The autonomous self-test grades the OS's own plumbing — it proves the *channel*, not that a human read or believed the transcript (`oracle=HUMAN-DEFERRED-M26`). The marker claims only tx + frame-verification, never that a policy was validated or the M24 gate cleared.
- **Split-view first-mile gap.** A no-key head cannot prove to an external observer that two readers saw the same transcript (the CT split-view problem needs gossip or a signature); the INTRO binds the transcript to *this boot's* M22 head, but a wholesale instance substitution is undetectable without an externally-rooted key (M26+).

---

## 6. Where M25 goes beyond the literature
- A **formally verified** (Kani-proven injective/total/tamper-sensitive), **no-float, in-kernel** structured operator-transcript leaf — RATS/CT/secure-logging prior art is float userspace + keyed; M25 is the *structural* (keyless, M22-fold-reused) verified-leaf form with the honesty boundary machine-encoded.
- **Fusing** the RATS/DICE *identity-staging* structure with the Schneier-Kelsey/CT *tamper-evident-transcript* construction over the **same M22 provenance fold** — one decidable geometry serving attestation, internal provenance (M22), experience (M23), and the outbound operator story (M25).
- **The held-out-leakage guard as a canon-time fail-closed invariant** — the Seldonian no-snoop requirement encoded as a Kani-proven `partition != SAFETY_HELD_OUT` assertion in the encoder, not operational discipline.
- **Honesty-by-construction tokens** (`keyed=0`, `oracle=HUMAN-DEFERRED-M26`) that mechanically prevent the marker from overclaiming authenticity or oracle-closure — beyond the literature's prose cautions.

---

## 7. Roadmap context
M25 is the COMMUNICATION pillar's outbound half + the exogenous-oracle channel. **M26** consumes it: serial **RX** + an enrolled operator credential (a keyed challenge/nonce) so a human can *command* the M24 gate activation (the inbound auth M25 deliberately lacks), plus the EL2 exit-telemetry + two-VMID sovereign scheduler (sovereignty). The keyed forward-secure MAC + signed-STH successors land here too.

---

### References
Full survey + citations in [`docs/research/m25-operator-transcript-literature.md`](../research/m25-operator-transcript-literature.md). Key: RFC 9334 (RATS) · TCG DICE / open-dice · RFC 9711 (EAT) · RFC 6962 / 9162 (Certificate Transparency, STH) · Schneier & Kelsey (secure audit logs, USENIX Sec'98 / TISSEC'99) · Ma & Tsudik (FssAgg, IACR 2007/052) · Crosby & Wallach (tamper-evident logging, USENIX Sec'09) · OpenTelemetry Logs Data Model v1.53 · CBOR deterministic encoding (draft-bormann-cbor-det) · EEMUA-191 / ISA-18.2 / IEC 62682 · Christiano et al. (RLHF, arXiv:1706.03741) · Settles (active learning, 2009) · Thomas et al. (Seldonian, *Science* 2019) · Dwork et al. (reusable holdout, *Science* 2015) · Terrapin (arXiv:2312.12422).
