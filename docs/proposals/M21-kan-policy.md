---
type: Design Decision
title: "M21 — Verified fixed-point policy seam for the M17 forget/demote decision"
description: "Build a Kani-proven fixed-point additive policy cell inside M17's forget/demote envelope, shipped dormant until it beats a linear baseline."
tags: ["m21", "eviction-policy", "kani", "fixed-point", "memory", "safety-envelope"]
timestamp: 2026-06-10T07:46:18+03:00
status: locked
diataxis: explanation
---

# M21 — Verified fixed-point policy seam for the M17 forget/demote decision

**Status:** proposed (build-reshaped) · **Depends on:** M13 (memory substrate), M17 (forget/demote daemon), `tb-encode::memscore` · **Marker:** `M21: kan-policy OK`

> **One-line verdict — `build-reshaped`.** Build a **Kani-proven, total/bounded/monotone, fixed-point *additive* policy cell** (a piecewise-linear integer GAM) that may only **rank within** the existing M17 heuristic safety envelope, fail-closed gated, and **shipped dormant** until it is measured to beat a tuned linear baseline on held-out, distribution-shifted eviction traces. **Drop the "KAN / neural network" framing**: the knots are frozen offline, nothing is *learnable* in-kernel, and a depth-1 sum of 1-D splines is operationally a per-segment lookup table + linear interpolation. What is novel and worth building is the *verified-policy-inside-a-proven-envelope* seam — not a neural net.

This proposal is the output of a literature-first research pass (4 blind arms + an adversarial skeptic + synthesis; see [`docs/research/kan-policy-literature.md`](../research/kan-policy-literature.md) for the cited evidence). The honest conclusion of that pass is that the *maximal* "ship a learnable KAN in the kernel" idea is a solution in search of a problem, but a *reshaped* verified additive-policy seam is cheap, invariant-respecting, and a genuine first (no prior work formally verifies a learned eviction-policy leaf for an OS).

---

## 1. Why reshape, not build-as-proposed

The original M21 candidate (#69) was: *"replace the M17 hand-tuned forget/demote constants with a Kani-proven fixed-point KAN-cell (9-knot i16 spline)."* Four independent research arms and an adversarial review converged on the same correction:

1. **The closest published analog wins with a *linear* scorer.** A-MAC (*Adaptive Memory Admission Control for LLM Agents*, ICLR 2026, arXiv:2603.04549) is the exact M17 shape — learned forget/keep over ~5 interpretable agent-memory features — and it deliberately chose a **linear weighted sum**, *explicitly declined* MLP/tree/nonlinear models for interpretability, and beat recency heuristics by +22.4% F1. Its dominant gain (ΔF1 −0.107 when removed) was a **categorical type-prior**, not nonlinearity in continuous features. A spline buys nothing on a flag.

2. **KANs only beat simpler models on clean symbolic regression — not tabular scoring.** *KAN or MLP: A Fairer Comparison* (arXiv:2407.16674): at matched parameters, MLPs beat KANs on tabular classification "by a substantial margin"; KANs win only symbolic-formula fitting. The M17 forget score is tabular scoring, not symbolic regression.

3. **The heuristic baseline bar is brutal.** SIEVE (NSDI'24, ~21 LoC + one bit) ties/beats ARC; TinyLFU shows a good admission filter makes inter-eviction-policy differences "marginal." Whatever M21 ships must beat *that*.

4. **Nothing is "learnable" in-kernel.** TABOS freezes the knots offline and ships a `const` integer table with no online training. A depth-1 sum of frozen 1-D splines is, by definition, a spline **GAM** == a per-segment LUT + linear interpolation. The "learnable activation function" KAN sales pitch does not apply to a frozen table; calling it a "KAN" overclaims.

5. **A depth-1 additive cell cannot model feature interactions** ("high-frequency *AND* large-size"), which is the one place a tuned heuristic is plausibly improvable.

**What survives the critique** is the part every arm endorsed: the *verifiable leaf* is trivially Kani-able, and the *safety seam* (a learned ranker strictly inside a proven heuristic envelope — the Black-Box Simplex / shielding pattern) is the mature, correct architecture. So we build **M17-plus-a-validated-fixed-point-additive-table**, not "a Kani-proven KAN cell."

The seam already exists in the codebase. `crates/tb-hal/src/mem.rs` already:
- computes an additive default score `w_a·BLA(d=0.5) + w_r·relevance + w_i·importance` (recall path, `minmax`-normalized), and
- gates demotion in `forget_sweep()` with `bla < THETA_DEMOTE(-1000) && importance < IMP_PIN(8) && util < UTIL_PIN(600)` inside a pin/grace/batch envelope (`MIN_AGE=16`, `SWEEP_BATCH=64`, persisted clock-hand), and
- already hoists `bla_raw` / `minmax` / `ln_fixed` into the Kani-proven, `#![forbid(unsafe_code)]`, no-float `tb-encode::memscore` leaf.

M21 is therefore a *drop-in*: a new `tb-encode::kancell` leaf that produces a bounded keepability score consumed by the **unchanged** `THETA_DEMOTE` comparator, behind a fail-closed loader, with the heuristic as the always-live floor.

---

## 2. The reshaped design

### 2.1 Numeric format (no float, ever)
- **Knots:** `i16` Q4.11 fixed-point y-values (1 sign, 4 int, 11 frac bits).
- **Inputs:** pre-quantized to `i32` in a fixed per-feature Q-format.
- **Accumulator:** widened `i32 → i64`, **saturating** ops throughout.
- **Output:** final **saturating clamp** into the existing M17 score band (`[-34_000, 34_000]` / `SCALE=1000`, where `bla_raw` already lives), so the output bound is a tautology.

### 2.2 Basis — piecewise-LINEAR, not cubic/B-spline
Monotonicity of a piecewise-linear interpolant reduces to a finite **sign check on consecutive knot deltas** (Schumaker / Fritsch-Carlson) — a const-evaluable condition Kani discharges with zero solver difficulty. Cubic/B-spline monotonicity needs derivative-region side conditions an automatic checker cannot auto-discharge. Eval is **compare + interpolate only** — no recursion, no division — matching the no-float, easily-Kani regime (ReLU-KAN / PL-KAN, arXiv:2503.01702, arXiv:2406.02075). It also sidesteps the Free-Knots B-spline NaN/oscillation pathologies (arXiv:2501.09283).

### 2.3 Knots & features
- **9 knots = 8 intervals** per feature on a **fixed uniform power-of-2 grid** → segment selection is a `>>`, not a divide. This is the empirically-validated LUT-KAN sweet spot (L=8; F1 drop < 0.0004; arXiv:2601.03332).
- **3–4 univariate splines** over the genuinely-continuous, possibly-saturating signals: **recency/age, access-frequency/count, size**.
- **Tier and pin/importance stay as plain linear/gating terms** — A-MAC's lesson: the categorical/tier signal is the high-value feature and belongs in the *envelope*, not the spline.

### 2.4 Form
```
score = bias + Σ_j spline_j(feature_j) + Σ_k w_k · flag_k          // a fixed-point additive GAM
```
computed in `tb-encode::kancell::kan_score`, returned into the **existing** `THETA_DEMOTE` comparator unchanged.

### 2.5 Structural monotonicity (MonoKAN-style, solver-free)
For features with a known sign — recency/age ⇒ non-increasing knot y's, frequency ⇒ non-decreasing, with non-negative summation weights — enforce monotonicity *by construction* on the integer table. Validated once on the host **and** cheaply re-asserted in-kernel at load (a sign check on the `i16` table, no solver). This gives "staler is never scored more keepable" for free (MonoKAN, arXiv:2409.11078).

### 2.6 Offline training, frozen integer artifact
Fit knots **offline in float** on the host (the sensitive part — KANtize, arXiv:2603.17230, shows coefficients are sensitive < 5-bit while *evaluated* spline outputs tolerate 3-bit). Quantize **only** the resilient evaluated y-table to `i16` and freeze it. Ship a **checked error bound** `B = max|float_score − fixedpoint_score|` over the quantized input grid alongside the table, so M21 cannot silently verify a *different* function than M17 trained (the "No Soundness in the Real World" residual obligation, arXiv:2506.01054 — verify the **integer artifact**, never the float model).

---

## 3. The safety seam (Black-Box Simplex / shield)

The kancell is a **pure ranker strictly inside** the existing M17 heuristic safety envelope. The envelope in `mem.rs` **owns the decision and is unchanged**:

- `forget_sweep()` walks `SWEEP_BATCH` records from the persisted wrapping clock-hand.
- The envelope computes the **eligible-and-safe candidate set** by applying the HARD invariants *first*: `MIN_AGE` grace (brand-new records immune), `IMP_PIN` flashbulb pin (importance ≥ 8 never demoted on age), `UTIL_PIN` EvolveR utility pin, and the ordered tier path Working → Semantic → Episodic → drop (no tier skipped).
- **Only after** a record clears every envelope guard does `tb-hal` call `tb_encode::kancell::kan_score` to produce the bounded score the **identical** `THETA_DEMOTE` comparator thresholds — `kan_score` replaces the inline `w_a·BLA + w_r·relevance + w_i·importance` default, returning into the same comparator+threshold so the eviction logic, serial marker, and CI gating are unchanged.

**Consequence:** the KAN output can only reorder/threshold *within* the already-safe set; it can **never widen** the action set. No weight table — even a signed-but-poisoned one inside `i16` range — can cause never-forget, always-forget, or a pin violation. A worst-case adversarial-but-valid table is merely *suboptimal*, never *unsafe*. (Cold-RL, arXiv:2508.12485, demonstrates crafted patterns *do* collapse *unguarded* learned policies — the envelope is load-bearing, not decorative.)

**Anti-starvation stays in the envelope** as the existing clock-hand/aging counter (bounded liveness: every eligible record considered within N sweeps) plus an eviction-cooldown (a record can't be churned faster than K ticks) — **never** inferred from the KAN. Liveness can't be delegated to a learned ranker; only the counter guarantees it (arXiv:1908.03284).

**The heuristic floor is always live.** If the kancell table is absent, rejected by the loader, or the offline ship-gate margin was not met, the path falls back to the tuned linear/default additive score with **zero behavioral change**. FRAMEKERNEL stays intact: kancell is pure value computation in `tb-encode` (no_std, forbid(unsafe), no float); `tb-hal` merely calls it next to the comparator exactly as it already calls `bla_raw`/`minmax`.

---

## 4. `tb-encode::kancell` API

```rust
pub const KAN_KNOTS: usize = 9;
pub const KAN_FEATURES: usize = 4;
pub type KnotTable = [[i16; KAN_KNOTS]; KAN_FEATURES];   // frozen i16 Q4.11, 9 knots / 8 uniform power-of-2 intervals

/// One univariate piecewise-LINEAR spline. Clamp x_q to the grid, segment
/// index via >> grid_step_log2 (no divide), two lookups, saturating linear
/// interp. TOTAL by construction: the clamp proves the index in 0..=7 for ALL
/// i32, so [..9] indexing is in-bounds and saturating mul/add can't panic.
pub fn kan_spline_eval(knots: &[i16; KAN_KNOTS], x_q: i32, grid_lo: i32, grid_step_log2: u32) -> i32;

/// The additive GAM: bias + Σ_j kan_spline_eval(..) + flag_terms, accumulated
/// in a widened saturating i64, then saturating-clamped to the M17 band so the
/// output bound is a tautology. This is what the M17 comparator consumes.
pub fn kan_score(table: &KnotTable, feats: &[i32; KAN_FEATURES], flag_terms: i32, bias: i32) -> i64;

/// Structural MonoKAN validator: signs[j] = +1 require non-decreasing knot
/// deltas, -1 non-increasing, 0 unconstrained. A finite i16 comparison
/// conjunction (no solver). Called by the fail-closed loader and re-checked
/// in-kernel at load — validate the INTEGER artifact, not the float model.
pub fn kan_table_is_monotone(table: &KnotTable, signs: &[i8; KAN_FEATURES]) -> bool;

/// Structural headroom validator: every knot within the sub-range for which
/// Σ over KAN_FEATURES + bias + flag_terms provably stays inside the i32
/// accumulator before the clamp. Const-evaluable (KAN_FEATURES * KAN_KNOT_MAX);
/// a poisoned-but-in-i16 table still cannot overflow.
pub fn kan_table_overflow_safe(table: &KnotTable) -> bool;
```

---

## 5. Kani proof obligations (6 new harnesses → `tb-encode` 34 ⇒ 40)

Each has a **negative control** (the discipline learned from the `esr_decode_total` tautology and the `#49` over-quantification slips):

1. **`kani_kan_spline_eval_total_bounded`** — ∀ `x_q: i32`, ∀ `knots`: never panics (saturating ops, post-clamp segment index proven `0..=7`), output in the linear-interp range. *Negative control:* dropping the input clamp lets a large `x_q` produce index ≥ 9 and the `[9]` index assert FAILS — proving the clamp is load-bearing.
2. **`kani_kan_score_no_overflow_bounded`** — ∀ in-envelope `table`/`feats`/`flag_terms`/`bias`: never panics, final saturating clamp puts the `i64` in **exactly** `[-34_000, 34_000]`. The closed-form `Σ = N·max|knot|` bound — **re-run whenever `KAN_FEATURES` or the knot sub-range changes** (not one-time). *Negative control:* widening the headroom assumption past `i32` reddens the lane.
3. **`kani_kan_monotone_structural`** — ∀ `table` passing `kan_table_is_monotone(.., signs)`, for `x1 ≤ x2` in a monotone-decreasing feature, `eval(x2) ≤ eval(x1)` (staler never scored more keepable). Decidable from the knot-delta sign conjunction because the basis is piecewise-linear. *Negative control:* one mis-signed knot delta flips a segment slope and the inequality FAILS for a straddling `x`.
4. **`kani_kan_table_validators_total`** — both validators are total (return `bool`, never panic) over all `i16` tables, and **sound**: `overflow_safe(table)==true` ⟹ `kan_score` cannot overflow. *Negative control:* loosening the bound past `N·max|knot|` lets a passing table overflow under harness 2.
5. **`kani_kan_score_deterministic`** — `kan_score(..) == kan_score(..)` bit-for-bit (no float on the path), pinning the EL2/ring determinism + reproducibility guarantee (same no-FPU discipline as `bla_raw`/`skill_transform`).
6. **`kani_kan_envelope_no_widening`** — structural proof that `kan_score`'s clamped output can never reorder a record the envelope marks pinned (`IMP_PIN`/`UTIL_PIN`/`MIN_AGE`) into the victim set: the safe-set membership computed by the heuristic is *independent of* `kan_score`. *Negative control:* a variant that feeds `kan_score` *into* the pin test FAILS, proving the seam keeps the KAN strictly downstream of the safety gate.

---

## 6. Definition of Done — the `M21: kan-policy OK` marker

A fail-closed boot self-test prints `M21: kan-policy OK` **only after** the in-kernel loader, on the **frozen integer table actually shipped**:

1. re-runs `kan_table_is_monotone(table, signs)` **and** `kan_table_overflow_safe(table)` and requires both true;
2. verifies the table provenance hash + signature (OpenSSF-OMS-style attestation) — an unsigned-or-tampered table fails closed to the pure heuristic and the marker is **not** printed;
3. executes a **real round-trip** proving the cell agrees with its shipped error bound — prints
   `M21: kan-cell q-err=<delta> bound=<B> (delta<=B)`
   where `delta = max|float_score − kan_score|` recomputed in-kernel over a small fixed probe-input vector baked next to the table, and the boot **aborts the kan path** (reverts to heuristic, marker withheld) if `delta > B`.

**Cumulative DoD:** the run-scripts grep `M21: kan-policy OK` fail-closed exactly like `V1: kani-encoders OK` and the per-milestone markers; `scripts/verify-encode.sh` + `kani.yml` gain the six `kani_kan_*` harnesses (34 ⇒ 40) so a missing/under-set proof reddens `V1` **before** M21 can claim its marker. The two printed lines together — `kan-policy OK` **and** the real `q-err<=bound` round-trip — are the fail-closed proof that a bad/unsigned/over-error table can never reach the comparator.

**Anti-hollow-pass (the aL2.5 / M20 substring lesson):** when the offline ship-gate margin over the tuned linear baseline is **not** met, the build ships the table dormant and the boot prints `M21: kan-policy OK (heuristic floor, gate-not-met)`. Because that variant **contains** the `M21: kan-policy OK` substring the run-scripts grep, the scripts MUST (a) reject the `(heuristic floor, gate-not-met)` and `(no table, skipped)` variants on any lane that ships an *active* table, and (b) positively require the `q-err=.. bound=.. (delta<=B)` round-trip line — the same reject-skip + require-real guard pattern that closed the M20 hollow-pass.

---

## 7. The ship-gate (why M21 ships *dormant* first)

**M21's leaf + seam are unconditionally safe to build and land; turning the spline *on* in the decision path is a separate, gated, evidence-bearing decision.** The synthesis is emphatic: no published work validates a KAN/spline GAM for OS eviction, the closest analog won with linear+categorical, and strong simple heuristics (SIEVE/TinyLFU) make the baseline near-optimal. So the additive nonlinearity must **earn** its place:

> **Pre-registered, falsifiable ship-gate:** the frozen GAM must beat a tuned **linear/GDSF** baseline, fit on the **same** replayed TABOS Working→Semantic→Episodic eviction traces, by a pre-registered margin on a **held-out, distribution-shifted** trace. If it does not clear the margin, ship the tuned linear scorer instead and the kancell leaf stays **dormant** behind the fail-closed loader.

TABOS does not yet have a real agent-memory eviction workload to replay. Therefore **M21 (this milestone) builds and proves the leaf + the fail-closed dormant seam**, lands it green with the heuristic floor deciding (`M21: kan-policy OK (heuristic floor, gate-not-met)`), and the **ship-gate is a tracked follow-up** (the offline trace-replay + baseline-bake-off harness). This is the honest division: the *verified machinery* is the milestone; the *activation* waits for evidence.

---

## 8. Risks (carried forward, with mitigations)

| Risk | Mitigation |
|---|---|
| **Justification risk (dominant)** — additive nonlinearity may beat the tuned linear baseline by an immeasurable margin → negative-ROI pipeline + proof surface. | The pre-registered held-out distribution-shifted gate; **ship dormant** if not met. The verified seam is reusable regardless. |
| **Spec/quantization soundness gap** — Kani proves the i16 cell, but float→i16 freezing can make the shipped cell disagree with the host model (arXiv:2506.01054). | Shipped checked error bound `B` + the in-kernel `q-err ≤ bound` boot round-trip; validate the **integer** artifact. |
| **Expressiveness ceiling** — a depth-1 GAM can't model feature interactions. | Measure additive-vs-heuristic offline before activating; minimal escalation is one EBM-style pairwise spline (resisted in-kernel — re-enters CBMC unrolling cost). |
| **Distribution shift / frozen-table staleness** — knots fit on yesterday's workload degrade to a near-constant at clamp endpoints. | Out-of-band re-fit/re-sign/re-validate pipeline; runtime clamp-hit metric; always-available heuristic floor + HALP-style online regression-revert. |
| **Supply-chain / poisoning** — a signed-but-malicious in-`i16` table passes the proofs yet ranks adversarially (proofs bound behavior, not intent). | The envelope's hard invariants (pin/progress/aging/cooldown) keep even a worst-case valid table merely suboptimal; tune aging/cooldown against a TABOS-specific trap benchmark, not defaults. |
| **Verification/maintenance creep** — the overflow bound is not one-time; provenance/versioning adds permanent proof surface. | Freeze `KAN_FEATURES`/`KAN_KNOTS` as compile-time consts gating the harnesses; keep the in-kernel network to **one** summed layer (stacking re-enters the PSPACE-hard QNN regime). |

---

## 9. What is genuinely novel here

Per the literature pass, **no prior work formally verifies a learned eviction-policy leaf for an operating system.** M21's contribution is not "a KAN in a kernel" (overclaim) but the *composition*: a **Kani-proven-total, monotone-by-construction, fixed-point additive-policy cell that can only rank inside a proven heuristic safety envelope, fail-closed gated, in a framekernel with zero real `unsafe` and no float.** That seam — verified policy as a *hint* inside a *proven* envelope, mechanically checked end-to-end — is the unbuilt thing worth building, and it generalizes beyond forget/demote to any future learned in-kernel policy.

---

### References
A-MAC arXiv:2603.04549 · KAN-or-MLP arXiv:2407.16674 · SIEVE NSDI'24 · TinyLFU arXiv:1512.00727 · Scalable-QNN-Verification AAAI'21/arXiv:2012.08185 · LUT-KAN arXiv:2601.03332 · KANtize arXiv:2603.17230 · No-Soundness-in-the-Real-World arXiv:2506.01054 · MonoKAN arXiv:2409.11078 · Black-Box-Simplex arXiv:2102.12981 · Shielding arXiv:1708.08611 · Cold-RL arXiv:2508.12485 · HALP NSDI'23 · Certified-Control arXiv:2104.06178 · full survey in [`docs/research/kan-policy-literature.md`](../research/kan-policy-literature.md).
