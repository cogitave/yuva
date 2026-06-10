# Literature survey — verified fixed-point policy inference for OS memory eviction (M21)

**Method:** a literature-first research pass for [M21](../proposals/M21-kan-policy.md) — 4 blind research arms (each swept a distinct angle via web/arXiv search), an adversarial skeptic given all four, and a synthesis. This document records the cited evidence and the honest conclusion. All four arms' verdict signals plus the adversary converged on **build-reshaped**: build a verified fixed-point *additive* policy seam (not a "KAN"), ship it dormant, gate activation on measured wins.

The four angles:
- **A. Verified fixed-point / quantized NN inference** — is the leaf provable?
- **B. KAN internals for integer inference** — is 9-knot i16 the right cell, and is it worth it over linear?
- **C. Learned cache/memory eviction** — does a learned scorer beat a tuned heuristic for *this* decision?
- **D. The offline-train / online-infer safety seam** — how do you ship a frozen learned policy into a determinism-critical kernel safely?

---

## A. Verified fixed-point / quantized NN inference — *the leaf is provable*

**Verdict: for-M21.** A single bounded, loop-free, fixed-shape integer spline leaf is squarely in Kani/CBMC's decidable regime; the only obligation the proof does *not* cover is the float→i16 freezing error.

- **Bit-exact QNN verification is PSPACE-hard for *whole networks*, but that hardness comes from depth/width + adversarial input search — not from one leaf.** A single bounded-domain, fixed-shape spline has a tiny, fully-unrollable state space: exactly where CBMC's bit-vector SMT backend is decisive. *Scalable Verification of Quantized Neural Networks*, Henzinger/Lechner/Zikelic, **AAAI 2021** (arXiv:2012.08185). Foundational method: *How Many Bits Does it Take to Quantize Your Neural Network?*, Giacobbe/Henzinger/Lechner, **TACAS 2020** — SMT over bit-vectors captures exact fixed-point semantics (overflow, wraparound, rounding), with the warning that robustness is **non-monotonic in bit-width** so the integer cell must be verified *as-shipped*.
- **Totality (no panic, no overflow, in-bounds index) is Kani/CBMC's built-in automatic check** — not a bespoke lemma. "Spline eval never overflows the accumulator and never indexes the 9-knot table OOB for all inputs" is one `#[kani::proof]` over an unconstrained input, matching the existing ~34 `tb-encode` harnesses.
- **Bounded-output is sound interval/affine propagation** — established mechanized tech, not research risk: *FloVer* (Becker et al., 2017, arXiv:1707.02115, Coq+HOL4) supports interval **and** affine domains for **fixed-point** arithmetic. For a sum of N splines each clamped to `[knot_min, knot_max]`, the output range is `[N·min, N·max]` by monotone interval arithmetic — Kani discharges the clamp bound as a postcondition assert.
- **Round/clip/saturate encode soundly with integer-only constraints:** *Towards Efficient Verification of Quantized NNs (EQV)*, Huang et al., 2023 (arXiv:2312.12679) — round = ±0.5, clip = stacked ReLUs/saturation. The encoding template for the kancell's clamp/saturate.
- **The single biggest honest risk is the spec gap, not the proof gap.** *No Soundness in the Real World: On the Challenges of the Verification of Deployed Neural Networks*, Szász/Bánhelyi/Jelasity, **2025** (arXiv:2506.01054): verified properties routinely fail to transfer because proofs are on *idealized float* models while deployment uses quantized integer arithmetic with different rounding/clip. **Mitigation = exactly TABOS's plan**: Kani-prove the *actual integer* leaf, and ship a checked error bound for the float→i16 freezing step.

**Design implications:** piecewise-linear (not cubic) so monotonicity is a finite knot-delta sign check; loop-free fixed-size so CBMC fully unrolls; widen to an `i32`/`i64` saturating accumulator with a final clamp so the only overflow obligation is a closed-form `N·max|knot|` bound; treat float→i16 freezing as a first-class, separately-checked obligation.

---

## B. KAN internals for integer inference — *9-knot i16 is right; build it as a piecewise-linear GAM*

**Verdict: reshape-M21.** The integer-spline-as-LUT idea is well-supported and 9 knots is empirically justified — but build it as a **piecewise-linear monotone GAM fit offline in float**, and gate it on beating the heuristic.

- **A 1-D KAN activation** is `φ(x) = w_b·silu(x) + w_s·Σ c_i·B_{i,k}(x)` with `G+k` coefficients; by Cox–de Boor local support only `k+1` basis funcs are nonzero at any `x`. Replacing the spline with a fixed integer table collapses this to *one index + one interpolation*. *KAN: Kolmogorov–Arnold Networks*, Liu et al., 2024 (arXiv:2404.19756); *Free-Knots KAN* (arXiv:2501.09283) confirms knot count `= G+K` and warns of B-spline NaN/oscillation on narrow grids.
- **Segment-wise integer LUT + linear interp is the established integer-only KAN.** *LUT-KAN* (arXiv:2601.03332) and *LUT-Compiled KAN for IoT DoS* (arXiv:2601.08044): per-segment int8 quant + linear interp, **deterministic fixed-op-count** latency, integer-only — exactly the proposed 9-knot i16 leaf (widened to i16 for headroom).
- **Very few knots suffice.** LUT-KAN: `L ∈ {4,8}` give maximum speedup with minimal memory; **L=8 is the sweet spot** (F1 drop < 0.0004, ROC-AUC 0.999 preserved, 63×–6000× speedup). **9 knots = 8 intervals sits right at the validated sweet spot** — not arbitrary.
- **The activation *table* is the most quantization-tolerant part of a KAN.** *KANtize* (arXiv:2603.17230): B-spline *outputs* resilient to **3-bit**, learnable *coefficients* sensitive below ~**5-bit**. TABOS ships a frozen **16-bit** table fit offline in float → the sensitive coefficient-fitting stays in float on the host; only the resilient evaluated table goes integer, far above the danger zone. FPGA corroboration: cutting spline-table precision 8→3 bit cut LUT 36% at maintained accuracy.
- **A depth-1 KAN *is* a spline GAM:** `y = b₀ + Σ_j f_j(x_j)`. It strictly dominates a linear/threshold scorer (each `f_j` nonlinear/non-monotone) while keeping per-feature interpretability and easy monotonicity — the right altitude for a handful of features. *InterpretML/EBM* (Nori et al., arXiv:1909.09223): glassbox additive shape functions reach near-boosted-tree accuracy with logistic-regression interpretability.
- **Piecewise-linear is a sound, cheap substitute for cubic** here: *PL-KAN↔ReLU* (arXiv:2503.01702) calls linear splines a "reasonable economical substitute"; *ReLU-KAN* (arXiv:2406.02075) shows KAN works with only add/dot/ReLU (no recursion, no division), ~20× speedup. For an 8-interval integer table the smoothness gain of cubic is marginal and not worth the recursion/division in a no-float kernel. (RBF alternative if curvature is insufficient: *FastKAN*, arXiv:2405.06721 — 8 Gaussian centers ≈ 3-order B-spline at 3.33× speed.)

**Honest caveats (arm B's own risks):** a depth-1 additive GAM **cannot model feature interactions**; linear (8-interval) splines are coarse and the LUT-KAN < 0.0004 F1 numbers come from *softmax classifiers*, not a kernel eviction ranker — validate the actual eviction decisions, not a proxy accuracy; frozen knots degrade under distribution shift.

---

## C. Learned cache/memory eviction — *a tuned heuristic is likely near-optimal; the win is unproven*

**Verdict: reshape-M21.** This is the decisive arm: the evidence says a well-tuned linear/heuristic forget-score probably matches a spline on a handful of features, so M21 is justified only as a verified, *gated* upgrade — not a default replacement.

- **The closest published analog deliberately used LINEAR, not nonlinear.** *A-MAC: Adaptive Memory Admission Control for LLM Agents*, **ICLR 2026** (arXiv:2603.04549): `score = w1·Utility + w2·Confidence + w3·Novelty + w4·Recency + w5·TypePrior`, weights fit offline by 5-fold CV + grid search. **F1 0.583 vs equal-weights 0.476 (+22.4%) vs MemGPT recency+importance 0.324.** Authors **explicitly decline MLP/tree models** (interpretability); **no nonlinear ablation**. The dominant gain (ΔF1 −0.107 when removed) is a **categorical type-prior**, not nonlinearity in continuous features.
- **At matched params, KANs do *not* beat simpler models on tabular scoring.** *KAN or MLP: A Fairer Comparison* (arXiv:2407.16674): MLP beats KAN on tabular classification "by a substantial margin"; KAN wins only symbolic regression. A 9-knot summed-spline score is GAM/symbolic-ish — the one regime where splines *might* help, but only if the true score is genuinely nonlinear-additive.
- **Dead-simple modern heuristics match/beat complex learned policies.** *SIEVE* (NSDI'24): one FIFO + one hand bit, ~21 LoC, beats/ties SOTA (up to 63% lower miss vs ARC). *TinyLFU* (arXiv:1512.00727): after its admission filter, "the difference between the various eviction policies becomes marginal" — and its metadata fits one memory page (kernel-friendly).
- **Heavyweight learned policies pay 1–2+ orders more compute for modest gains and are shift-fragile.** *LRB* (NSDI'20): GBM, 4–25% WAN savings over LRU; "*A Learned Cache Eviction Framework with Minimal Overhead*" (arXiv:2301.11886): LRB needs > 2 orders more CPU. *Testing Robustness of Learned Index Structures* (arXiv:2207.11575): up to 20% degradation under poisoned data. **Note:** M21's frozen 9-knot i16 table sidesteps the *compute* objection (it's cheap) — but **not** the *robustness/shift* objection.
- **A fixed-point certified-monotone spline is feasible and matches TABOS's constraints:** *MonoKAN* (arXiv:2409.11078) — certified partial monotonicity via simple parameter conditions; KAN TinyML (arXiv:2409.11418) — 8-bit splines via LUTs, 145 kB flash/26 kB RAM on Cortex-M4F.
- **Weak (older) pro-nonlinearity data point:** web-cache work increasing size/frequency contribution non-linearly to evict large/low-value objects (GDSF lineage) — but workload-specific and pre-dates SIEVE.

**Design implications:** reframe as a fixed-point monotone GAM (not "neural net"); make a tuned linear/GDSF scorer a **strict, falsifiable baseline**; gate acceptance on beating it by a pre-registered margin on a held-out, **distribution-shifted** trace; keep a heuristic floor live; spend the spline budget on continuous saturating features (recency/frequency/size), keep tier/pin as linear/gating terms; offline fit only, ship frozen integer tables.

---

## D. The offline-train / online-infer safety seam — *learned hint inside a proven envelope*

**Verdict: reshape-M21.** Ship the cell only as a Kani-proven-total integer *ranker* strictly inside the heuristic safety envelope; the envelope owns pin/progress/aging and the safe candidate set; fail-closed gate the frozen table.

- **"Learned policy as a hint inside a proven envelope" is the mature canonical design.** *Black-Box Simplex Architecture* (arXiv:2102.12981): control authority switches from an unverified advanced controller to a verified baseline to maintain safety. *Safe RL via Shielding* (Alshiekh et al., arXiv:1708.08611) + *Shields for Safe RL* (CACM 2025): a synthesized shield provides the list of safe actions and overrides the learner only on violation. *Certified Control* (Jha/Rushby et al., arXiv:2104.06178): a *small verifiable certificate checker* is the trusted component, not the ML. **Map:** the Kani-proven M17 heuristic = baseline + decision module; the KAN = unverified advanced controller that may only **rank within** the safe set.
- **The exact eviction analog exists and works.** *Cold-RL* (arXiv:2508.12485): a dueling-DQN scores **only the K least-recently-used candidates** (bounded scope) with a 500 µs hard-timeout fallback to native LRU; its adversarial *Trap Benchmark* (size inversions, bursts, scanning) collapses unguarded LRU (~5.6% hit) while the *constrained* learned policy holds ~42.1%. *HALP* (NSDI'23, Google): a learned reward model + "a suboptimal but simple and robust heuristic like LRU" stays robust to a temporarily-uninformative reward model. **The threat model is real, and the envelope is the defense.**
- **Monotonicity is a structural, solver-free, by-construction property.** *MonoKAN* (arXiv:2409.11078): monotone knot values + non-negative derivatives + positive output weights, enforced by a per-epoch projection — explicitly avoiding the MILP/SMT post-hoc verification of *Certified Monotonic NNs* (Liu et al., NeurIPS 2020, arXiv:2011.10219). For an i16 table this collapses to: knot deltas ≥ 0 (or ≤ 0) and a non-negative summation weight.
- **Float-trained / int-inferred is a soundness hazard** — verify the **integer** table, not the float model (arXiv:2506.01054; *Sound Mixed Fixed-Point Quantization of NNs*, ACM TECS 10.1145/3609118: fixed-point "requires ensuring overflow-freedom explicitly"; *QVIP* ASE'22; arXiv:2312.12679).
- **Trust the frozen table via a fail-closed gate:** signature + provenance + structural validation (bounds, knot count, monotone-delta, output-range). *OpenSSF Model Signing (OMS)* spec (2025) + *Coalition for Secure AI*: signing "authenticates origin, detects tampering, establishes trust boundaries between training and inference"; SLSA-style "mandatory verification gates… fail-closed where a model that cannot be cryptographically verified is prevented from executing." Unsigned/unvalidated ⇒ pure heuristic.
- **Anti-starvation must be *bounded liveness* in the envelope, not delegated to the KAN.** *Monitor-Based Runtime Assurance* (arXiv:1908.03284) + RV surveys (arXiv:2201.10436, arXiv:2311.09811): liveness can't be decided on a finite trace; only "something good within N steps" is runtime-checkable. So "pinned never dropped" is static safety (Kani-provable); "every eligible record considered within N sweeps" is an aging counter in the envelope.

**Design implications:** strict two-tier Simplex/shield seam; total saturating leaf with fixed output clamp (proof quantifies over the table, not the learned weights); structural MonoKAN monotonicity; fail-closed signed+structural loader; validate the integer artifact; aging/cooldown counters in the envelope.

---

## The adversary's case (steelmanned, and what survived)

> *"M21 is a solution in search of a problem, and three of the four arms quietly admit it."*

The skeptic's strongest points: (1) A-MAC — the exact M17 shape — won with a **linear** scorer + a **categorical** feature, where a spline buys nothing; (2) frozen knots mean **nothing is learnable in-kernel** — a depth-1 sum of frozen splines is **a fancy lookup table** that **cannot model interactions**; (3) the baseline bar (SIEVE ~21 LoC, TinyLFU "marginal" inter-policy gaps) is brutal; (4) M21 adds a permanent train→quantize→sign→validate pipeline + a larger proof surface + the float→i16 unverified error obligation — **more attack/maintenance surface for an unproven, non-interactive, frozen table.**

**What survived:** *do not ship a KAN in the decision path on faith.* Ship a tuned integer GAM **only if** it clears a pre-registered margin over a tuned linear/GDSF baseline on held-out, distribution-shifted TABOS traces. If it passes, the defensible artifact is the determinism arm's reshape — the heuristic envelope owns pin/progress/aging and the safe set; the frozen monotone i16 table is a pure ranker inside it, fail-closed gated. **That is M17-plus-a-validated-table, not "a Kani-proven KAN cell." The KAN framing is the part to cut.**

---

## Synthesis verdict: `build-reshaped`

Build the **Kani-proven-total, monotone-by-construction, fixed-point additive-policy leaf + the fail-closed dormant safety seam** now (the verified machinery is the milestone, and it's a genuine first — *no prior work formally verifies a learned eviction-policy leaf for an OS*). **Drop the "KAN/neural" framing.** Ship it **dormant** with the heuristic floor deciding (`M21: kan-policy OK (heuristic floor, gate-not-met)`), and make the **offline trace-replay + linear-baseline bake-off the tracked ship-gate** for ever turning the spline *on*. Safety is unconditional (the envelope); utility is earned (the gate).

See the concrete design, API, Kani obligations, seam, and DoD in [`docs/proposals/M21-kan-policy.md`](../proposals/M21-kan-policy.md).
