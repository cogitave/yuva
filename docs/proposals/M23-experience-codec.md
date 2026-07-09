---
type: Design Decision
title: "M23 — Verified experience codec + counterfactual shadow-recording"
description: "Logs each forget/recall decision as a tamper-evident, replayable record with a dormant cell's shadow score; validates no policy."
tags: ["m23", "continuous-learning", "off-policy-evaluation", "tamper-evidence", "shadow-mode", "kani"]
timestamp: 2026-06-10T12:36:50+03:00
status: locked
diataxis: explanation
---

# M23 — Verified experience codec + counterfactual shadow-recording

**Status:** proposed (build-refined) · **Pillar:** continuous learning (the DATA layer) · **Depends on:** M13 (memory), M17 (forget/recall), M21 (kancell grid + dormant cell), M22 (provenance fold) · **Marker:** `M23: experience OK`

> **One-line:** the OS already computes, at every M17 forget/recall decision, a feature vector + a heuristic-envelope verdict + (would-be) a learned-cell score — and then **discards it**. M23 records that, at each decision, as a fixed-field **injective `ExperienceRecord`** (features quantized to the *exact* kancell grid, the heuristic action taken, the **counterfactual** `kan_score` the dormant cell *would* have produced, and **reserved-but-unset** propensity/outcome fields), into a fixed-capacity ring folded into a **tamper-evident** per-agent hash-chain (reusing the M22 fold). The learned cell stays **DORMANT** (`KAN_ACTIVE=false`) — `kan_score` is logged only as a counterfactual *shadow*, never changing one demote. M23 claims **only** replay-determinism + structural tamper-evidence; it **does not** validate any policy. This is the verified Monitor phase of the learning loop.

This is the output of a literature-first research pass (4 arxiv arms + synthesis; see [`docs/research/m23-experience-literature.md`](../research/m23-experience-literature.md)). Every mechanism is academically grounded, and the genuine novelty is named.

---

## 1. The gap M23 fills (why it's the right next layer)

The Machine's distinctive pillar is **learning from its own operation**. The substrate is built (M13 memory, M17 forget envelope, M20 durable store, M21 dormant verified policy cell, M22 tamper-evident provenance). The one thing the architecture *cannot yet do* is convert the signals it already computes-and-discards at each forget/recall decision — age, access-count, ACT-R `bla`, the EvolveR utility, the `safe_to_demote` verdict, and the would-be `kan_score` — into a durable, tamper-evident, **bit-exactly-replayable** experience record.

That gap is exactly why the M21 ship-gate (#72) is blocked: there is no replayable `(features → decision → outcome)` tuple to evaluate. M23 produces it. **Crucially, M23 does not claim to *evaluate* anything** — it builds the verified Monitor/log layer; validity is M24's burden, and the true exogenous oracle (a human operator) is M25's.

---

## 2. Academic grounding (mechanism by mechanism)

M23's design maps onto four established literatures, with one load-bearing correction.

1. **Counterfactual shadow-recording = the OPE *logging-policy* pattern.** Logging the behavior (heuristic) action *actually taken* alongside the dormant cell's would-be score, deferring target-policy evaluation offline, is the textbook off-policy-evaluation setup — Bottou et al., *Counterfactual Reasoning and Learning Systems* (JMLR 2013, arXiv:1209.2355); Li et al., *Unbiased Offline Evaluation of Contextual-bandit* (WSDM 2011, arXiv:1003.5956); Swaminathan & Joachims, *Batch Learning from Logged Bandit Feedback / CRM* (ICML 2015, arXiv:1502.02362).

   **The load-bearing correction:** the M17 safety envelope is a **deterministic** logging policy, so the logged action has **degenerate propensity** (1 for the chosen action, 0 for the alternative). This **violates positivity/overlap**, and standard IPS/DR off-policy evaluation is not merely high-variance but **structurally non-identifiable** on this stream — Saito et al., *OPE under Deterministic Logging Policies* (arXiv:2603.21485); *Logging Policy Design for OPE* (arXiv:2605.15108): "the IPW estimator fundamentally depends on knowing πₗ(a|x)"; Zhao et al., *Positivity-free Policy Learning* (PMLR v238, 2024). **Therefore M23's refusal to claim validity is not conservatism — it is the literature-mandated stance for deterministically-logged data.**

2. **Experience as a first-class, fixed-capacity, replayable artifact = experience replay** — Lin (1992); Mnih et al. (DQN, Nature 2015, the fixed-size replay buffer). *Nuance the design adopts:* what M23 logs (pre-aggregated feature rows + a counterfactual score per decision) is **OPE-logged-bandit-feedback-shaped** (Open Bandit Pipeline, Saito et al. arXiv:2008.07146), **not** RL-replay-buffer-shaped (raw `(s,a,r,s′)` for TD bootstrapping). We cite experience replay for the *principle*, the OPE dataset schema for the *schema*. M23's **bit-exact** replay is the *systems* definition (ReVirt, OSDI'02; Mozilla `rr`, arXiv:1705.05937), achievable **precisely because the kancell is integer / no-float** (float/GPU nondeterminism is what makes bit-exact RL reproducibility fragile — Nagarajan et al., arXiv:1809.05676).

3. **"Observe before you adapt" = the MAPE-K Monitor phase** — Kephart & Chess, *The Vision of Autonomic Computing* (IEEE Computer, 2003) + the IBM MAPE-K reference model. M23 implements **Monitor + Knowledge** (the hash-chained log), deferring Analyze/Plan/Execute (validation/activation). `KAN_ACTIVE=false` is the Monitor phase *and* the MLOps **shadow-mode / dark-launch** idiom ("all work done but the decision not acted on"). Systems precedent: self-driving DBMS (Pavlo et al., VLDB 2021 — forecast + *offline* behavior-modeling + separate online action-planning); learned-systems needing offline validation against strong heuristics before activation (learned indexes, Kraska SIGMOD'18; LinnOS, OSDI'20; **HALP**, NSDI'23 — the heuristic-floored shield that is M21/M23's exact pattern).

4. **Validity-deferral / name-the-confound** is grounded in the OPE overlap condition + the Goodhart / distribution-shift literature. The obvious "regret = re-recall of a demoted record" proxy is **confounded** because recall filters demoted tiers: a **positivity violation** (the logging policy assigns ~zero recall probability to demoted records) *and* a closed-loop selection / **collider** bias. Point-identification is impossible without overlap (Uehara/Shi/Kallus, *A Review of OPE*, arXiv:2212.06355; *OPE beyond overlap*, arXiv:2305.11812). Activating on a confounded proxy *is* the failure M23 avoids by keeping `KAN_ACTIVE=false` (no optimization pressure on the proxy — Skalse et al., *Goodhart's Law in RL*, ICLR 2024). The remedy — distribution-shifted held-out (M24) + an **exogenous** human-operator oracle (M25) — is the literature-prescribed cure: only a signal **not** produced by the censoring demote policy can break the confound. **The "self-licking ice cream cone" critique is academically correct and properly handled.**

---

## 3. The refined record schema (every field justified by what valid OPE requires)

`ExperienceRecord` — fixed-field, injective, fixed-width (so `canon()` is total + Kani-injective), folded into a **separate** per-agent `xp_head` via the M22 `chain_mix` (M22's own `chain_head` is **untouched** → byte-identical, zero M22 regression):

| field | type | justified by |
|---|---|---|
| `decision_id` | `u64` | the logged-event key; orders the stream + joins a later outcome back to its decision (OPE row identity; rr/ReVirt anchor) |
| `kind` | `u8` | `FORGET_DECISION \| RECALL_TOUCH` — the demote site vs the recall/read touch (touches are the *censoring* events that confound the regret proxy) |
| `feats[4]` | `[i32;4]` | the **context x**, quantized to the **exact** kancell grid (`GRID_LO`/`GRID_STEP_LOG2`). Standard OPE requires context; exact-grid quant is what makes the shadow score *bit-exactly* reconstructible (stronger than float OPE logs) |
| `envelope_verdict` | `u8` | the heuristic safety-envelope verdict — the hard-invariant gating context the cell ranks *inside* (HALP heuristic floor) |
| `action_taken` | `u8` | the **action a** the heuristic policy actually served (demote/keep/tier) — required field of the logged-bandit tuple (Swaminathan & Joachims 2015) |
| `kan_score_shadow` | `i64` | the **counterfactual** would-be score of the dormant cell (clamped to `DEMOTE_BAND`) — raw material for the direct-method arm of a doubly-robust estimator (Dudík-Langford-Li, arXiv:1103.4601); bit-exact-replayable from `feats` |
| `logging_propensity_q` | `u16` | **RESERVED NOW** (degenerate sentinel this milestone), populated in M24 — the OPE schema's *required* propensity πₗ(a\|x) (Open Bandit Pipeline). Reserving it now keeps the canonical bytes / hash-fold stable when M24 injects exploration |
| `logging_policy_kind` | `u8` | `DETERMINISTIC` (this milestone) vs `SOFT-GREEDY` (M24) — lets M24 *detect* support violations rather than discover them too late (positivity is the binding assumption) |
| `outcome` | `OutcomeLabel` | **present but UNSET** this milestone — the deferred reward `r` of the logged-bandit tuple; encoded as a tagged `Unset` variant so M24 populating it **does not change M23's canonical bytes** |
| `margin_q` *(optional)* | `i16` | how close `envelope_verdict` was to `THETA_DEMOTE` — cheap insurance for IPS/DR which needs the behavior margin |

**NOT logged (by honest scope):** no validated label, no policy-value estimate, no IPS weight. The record supports counterfactual **replay** (bit-exact re-derivation) but does **not** by itself license IPS-style off-policy value estimates — the deterministic logging policy gives propensity 1, so IPS is degenerate until M24 adds exploration.

**The reserve-now refinement is load-bearing:** because the codec is a fixed-field injective encoder folded into the M22 hash chain, *adding* fields in M24 would change the canonical bytes and **break both replay-determinism and the chain head**. Reserving `logging_propensity_q` + `logging_policy_kind` + a present-`Unset` `outcome` now costs three fixed fields and zero behavior this milestone.

---

## 4. The seam (`tb-hal/src/mem.rs`, 100% safe)

`MemSubstrate` gains a **separate** `xp_head: [u8;32]` + `xp_ring: [ExpRecordRaw; XP_CAP]` (fixed-capacity, drop-oldest) + `xp_ids` — **alongside, never inside** the M22 `chain_head`. Recording is inserted at the sites that **already** compute the signals:
- in `forget_sweep`, right after `safe_to_demote` is computed and at the demote site — capturing the **same** `feats` array the sweep already builds, and **evaluating `kan_score` unconditionally as a counterfactual shadow** (`KAN_ACTIVE` stays `false`; the live demote is byte-identical); encode via `exp::canon`, fold into `xp_head` via `prov::append` (reusing the proven fold over the new bytes), push into the ring (drop-oldest on full, never panic, never block the sweep);
- at `recall()`/`read()` touch sites — a lightweight `RECALL_TOUCH` observation referencing `decision_id`.

Recording is strictly **downstream/observational**: no feedback into the same-cycle decision, no perturbation of `clock`/finsts/the M22 head (the observer-effect risk). Exposed to the kernel via a `tb_hal::exp_selftest() -> ExpProof` facade (mirroring `prov_selftest`).

---

## 5. Kani proof obligations (each with a negative control; **measure locally before pushing** — the M22 lesson)

1. **`canon` injectivity + totality** — never panics on any field values; injective (distinct records → distinct bytes), *including the reserved propensity field and the present-`Unset` outcome tag*. Load-bearing; written before the seam. *Neg control:* a canon dropping/aliasing the outcome tag fails injectivity.
2. **`replay-determinism`** (the headline claim) — a recorded `feats` row replayed through `kan_score` reproduces `kan_score_shadow` **bit-identically**, for all in-grid `feats` and any overflow-safe `KnotTable`. Extends M21's `kani_kan_score_deterministic` into a property of the *logged stream*. **Bound `feats` to the kancell clamp range** so the spline eval stays the proven kancell regime (the #49 trap — and measure with `cargo kani --harness` in WSL first). *Neg control:* a re-quantizing replay landing on a different grid cell fails bit-equality.
3. **`ring` totality + fixed-capacity** — append never allocates and never panics at capacity; the FIFO overwrite is total. *Neg control:* an unbounded-grow append fails the fixed-capacity assertion.
4. **`chain-fold` tamper-sensitivity** (reuse/extend M22) — flipping any single byte of any committed record's canon bytes changes the recomputed `xp_head` (structural/FNV, **not** cryptographic). *Neg control:* a constant/identity mix accepts a tampered record.
5. **`canon` round-trip** — `decode(canon(record)) == record` (symbolic harness + concrete Miri twin).
6. **`schema-stability` lemma** — `canon()` of a record with `outcome=Unset` + the reserved propensity sentinel produces bytes whose **length and field offsets are identical** to a future record with those fields populated, proving **M24 population cannot shift the fold** (the reserve-now correctness obligation).

---

## 6. Definition of Done — `M23: experience OK`

`exp_selftest()` proves, over **real** records: (a) it wrote N ≥ 3 real `ExperienceRecord`s at the actual M17 forget-decision site + ≥ 1 recall-touch, each folded into `xp_head`; (b) a recorded `feats` row **replayed** through the dormant `kan_score` reproduces `kan_score_shadow` **bit-identically**; (c) the clean head matches the committed head AND a single-byte tamper of a **committed** record's canon bytes is **caught**; (d) `KAN_ACTIVE==false` is asserted on the decision path so the shadow provably changed **zero** demotes.

**Witness (printed before the marker, both grepped fail-closed):**
```
exp: head=<hex16> records=<n> replay-bitexact=1 tamper-caught=1 kan_active=0 oracle=DECLARED-PROXY-DEFERRED-M24
```
then `M23: experience OK`.

**Anti-hollow-pass:** the run-scripts positively **require** the `exp:` witness, **require** `replay-bitexact=1` + `tamper-caught=1` + `kan_active=0`, and **reject** any `(no log, skipped)` variant (in-RAM, so a skip is never legitimate). Any failure withholds the marker, prints a FAIL line with no `experience OK` substring, and `fail_exit()`s red (the M20/M21/M22 idiom).

**The honesty token** `oracle=DECLARED-PROXY-DEFERRED-M24` is machine-emitted so the marker **mechanically cannot overclaim** validity the deterministic stream cannot support. Terminology discipline: the marker/witness use only *recorded* / *replay-deterministic* / *tamper-evident*; CI **rejects** any `validated`/`evaluated` substring near the marker. (The OPE-loaded words "replay"/"counterfactual" are scoped to mean bit-exact re-derivation, not a validity claim.)

---

## 7. Where M23 goes *beyond* the literature (the justified novelty)

- A **formally verified** (Kani-proven injective + total + replay-deterministic, Miri-gated) counterfactual OPE / experience log. OPE datasets/pipelines and RL replay buffers are float, userspace, and *unverified*; none machine-check that the logging codec is injective/total or that replay reproduces the shadow score **bit-identically**. M23 turns an *assumed* property into a *proven* one.
- A **no-float, no_std, in-kernel** counterfactual logging leaf. All OPE/CRM/shadow-mode prior art lives in float userspace networked services; a fixed-point integer-only fixed-capacity counterfactual log *inside an OS forget daemon* — where bit-exactness is achievable *precisely because* there is no float/GPU nondeterminism — is a new operating point.
- **Fusing** tamper-evident hash-chained logging (Crosby & Wallach, USENIX Sec'09; Schneier & Kelsey, USENIX Sec'99) **with** OPE-typed records, via the M22 fold — learned-systems telemetry that is itself integrity-attested. These two literatures have never been combined, never as a verified no-float kernel leaf. (Integrity claim honestly down-scoped to **structural/FNV**, not cryptographic — what an integer no-float verified fold can actually prove.)
- **Domain transfer:** counterfactual shadow-recording for an OS **memory-management** (forget/demote/eviction) policy, inside a proven M21 safety envelope (HALP-style floor). The OPE/logged-bandit literature is overwhelmingly ads/recsys/search; no direct prior art for verified in-kernel cache/memory eviction.
- **Honesty-by-construction:** a kernel-enforced `KAN_ACTIVE=false` invariant + a marker-checked anti-overclaim boot token that *mechanically* prevents the marker from asserting validity — the OPE-support and Goodhart cautions encoded as a build-time, CI-gated, fail-closed invariant, beyond the literature's prose cautions.

---

## 8. Honest caveats & risks (conceded)

- M23 claims **only** replay-determinism + structural tamper-evidence. It does **not** validate the kancell or any forget policy; the outcome is `Unset`; validity is M24's burden.
- M23 does **not** unblock #72 by itself — it produces a *replayable* trace, not a *representative* eviction distribution. M24's bake-off must be **distribution-shifted** (M18.2 rotating-held-out) and the confound named, or the gate is confounded.
- The regret proxy is **structurally confounded** (recall filters `TIER_COLD`; "never re-recalled" is partly an artifact of demotion — a collider/survivorship bias). M25's exogenous oracle is **required** for validity, and must preserve a held-out **un-demoted** sampling channel so it observes outcomes for records the policy *would* have removed.
- **Deterministic-logging identifiability dead-end** if M24 forgets the constraint: propensity is 1/0, so naive IPS/DR is silently biased. Mitigation: the reserved `logging_propensity_q` + `logging_policy_kind` fields, and M24 must take a named route — **(a)** inject controlled soft-greedy exploration *inside* the safety envelope (restore overlap, never violate a hard invariant), and/or **(c)** a partial-identification / smoothness estimator returning **bounds** not point estimates (arXiv:2305.11812). (We recommend (a)+(c).)
- **FIFO drop-oldest** induces a recency bias (Vitter 1985); kept for determinism this milestone but **named** in the M24 caveats; reservoir sampling is the M24+ alternative.
- Tamper-evidence is **structural/FNV**, not cryptographic (an input-choosing adversary is out of scope) — crypto hash + signed root is the M22-successor track.

---

## 9. Roadmap context

M23 is the **DATA layer** of the learning loop. It is followed by: **M24** (honest oracle + durable spill to M20 + gated bake-off — the honest #72 resolution, with the named identifiability route); **M25** (verified operator transcript `opframe` — the human becomes the exogenous oracle); **M26** (EL2 exit-telemetry producer into the experience stream + two-VMID sovereign scheduler — sovereignty feeds the learning substrate). See [`the-machine-vision`] roadmap.

---

### References
Full survey + citations in [`docs/research/m23-experience-literature.md`](../research/m23-experience-literature.md). Key: Bottou et al. arXiv:1209.2355 · Li et al. arXiv:1003.5956 · Swaminathan & Joachims arXiv:1502.02362 · Saito et al. (deterministic logging) arXiv:2603.21485 · Logging Policy Design arXiv:2605.15108 · Open Bandit Pipeline arXiv:2008.07146 · Dudík-Langford-Li arXiv:1103.4601 · Uehara/Shi/Kallus arXiv:2212.06355 · Levine et al. arXiv:2005.01643 · Skalse et al. (Goodhart in RL) arXiv:2310.09144 · Lin 1992 / Mnih et al. DQN 2015 · Schaul et al. arXiv:1511.05952 · Kephart & Chess (MAPE-K) 2003 · Pavlo et al. (self-driving DBMS) VLDB 2021 · Kraska SIGMOD'18 / LinnOS OSDI'20 / HALP NSDI'23 · Crosby & Wallach USENIX Sec'09 · ReVirt OSDI'02 / Mozilla rr arXiv:1705.05937 / Nagarajan arXiv:1809.05676.
