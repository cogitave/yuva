# Literature survey — verified counterfactual experience logging for an OS learning loop (M23)

**Method:** a literature-first pass for [M23](../proposals/M23-experience-codec.md) — 4 arxiv arms (off-policy/counterfactual evaluation; experience replay + deterministic record-replay; autonomic/learned-systems; confounding/validity-deferral) + a synthesis. Verdict: **build-refined**. The literature confirms M23's design, mandates one refinement (reserve the propensity/outcome fields now), and certifies the honesty discipline as the *correct* stance for deterministically-logged data — not mere caution.

This document is the academic basis: nothing in M23 is without a citation or a stated, justified novelty (per the project's standing academic-grounding directive). Where M23 goes *beyond* the literature, it is named in §5.

---

## Arm A — Off-policy / counterfactual evaluation & logged-bandit feedback

**The core confirmation:** logging the behavior (heuristic) decision plus the counterfactual would-be learned score, deferring target-policy evaluation offline, **is** the textbook logging-policy / off-policy-evaluation (OPE) setup.
- Bottou et al., *Counterfactual Reasoning and Learning Systems* (JMLR 14, 2013; **arXiv:1209.2355**) — OPE as "reasoning about the expected reward of a new policy given data collected from an older one"; log the behavior policy for later offline counterfactual estimation. M23 is the Monitor/log phase: it records, it does not evaluate.
- Li, Chu, Langford, Wang, *Unbiased Offline Evaluation of Contextual-bandit-based News Article Recommendation* (WSDM 2011; **arXiv:1003.5956**) — the replay methodology: a logged stream lets you evaluate a *target* policy offline.
- Swaminathan & Joachims, *Batch Learning from Logged Bandit Feedback / CRM (POEM)* (ICML 2015; **arXiv:1502.02362**) — the logged-bandit tuple `{context, action, reward, propensity}`.

**The load-bearing correction (all arms agree):** the M17 safety envelope is a **deterministic** logging policy ⇒ the logged action has **degenerate propensity** (1 for chosen, 0 for the alternative) ⇒ **positivity/overlap is violated** ⇒ standard IPS/DR OPE is **structurally non-identifiable** (not merely high-variance).
- Saito et al., *OPE for Ranking Policies under Deterministic Logging Policies* (**arXiv:2603.21485**) — "under deterministic logging, propensities are binary … this is not a high-variance problem, it is a structural inability to identify the target quantity"; signal recovered only by exploiting intrinsic outcome stochasticity.
- *Logging Policy Design for Off-Policy Evaluation* (**arXiv:2605.15108**) — "the IPW estimator fundamentally depends on knowing πₗ(a|x)"; deterministic greedy policies "fail because they cannot satisfy overlap."
- Zhao et al., *Positivity-free Policy Learning* (PMLR v238, 2024) — positivity/overlap is the binding assumption.

⇒ **M23's refusal to claim validity is the literature-mandated stance**, and the minimal OPE schema `{context x, action a, reward r, propensity π(a|x)}` (Open Bandit Pipeline, Saito et al., **arXiv:2008.07146**) dictates **reserving propensity + outcome fields now** so M24 can populate them without breaking the injective hash-chain fold. The logged would-be score is the raw material for the direct-method arm of a doubly-robust estimator (Dudík, Langford, Li, *Doubly Robust Policy Evaluation*, **arXiv:1103.4601**).

---

## Arm B — Experience replay + deterministic record-replay

- Lin (1992, *Machine Learning* 8:293-321) — introduced experience replay; Mnih et al. (DQN, *Nature* 2015) — the fixed-size replay buffer is load-bearing. The fixed-capacity ring matches the canonical DQN/PER circular buffer; Schaul et al., *Prioritized Experience Replay* (**arXiv:1511.05952**).
- **Nuance:** what M23 logs (feature rows + a counterfactual score per decision) is **OPE-logged-bandit-shaped** (Open Bandit Pipeline), not RL-replay-buffer-shaped (raw `(s,a,r,s′)`). Cite experience replay for the *principle*, the OPE schema for the *schema*.
- **Bit-exact** replay is the *systems* definition — ReVirt (Dunlap et al., OSDI 2002); Mozilla `rr` (O'Callahan et al., USENIX ATC 2017, **arXiv:1705.05937**) — not statistical RL resampling, and achievable **precisely because the kancell is integer / no-float** (float/GPU nondeterminism is what makes bit-exact RL reproducibility fragile — Nagarajan et al., **arXiv:1809.05676**).

---

## Arm C — Autonomic computing & learned / self-driving systems

- Kephart & Chess, *The Vision of Autonomic Computing* (IEEE Computer, 2003) + IBM **MAPE-K** — M23 implements Monitor + Knowledge, defers Analyze/Plan/Execute. `KAN_ACTIVE=false` is the Monitor phase **and** the MLOps **shadow-mode / dark-launch** idiom ("all work done but the decision not acted on").
- Self-driving DBMS — Pavlo et al., *Towards Self-Driving Operation* (VLDB 2021) — workload-forecast + **offline** behavior-modeling + online action-planning: a direct systems precedent for *record now, gate activation separately*.
- Learned systems need offline validation against strong heuristics before activation — learned indexes (Kraska et al., SIGMOD'18, arXiv:1712.01208); LinnOS (Hao et al., OSDI'20); **HALP** (Song et al., NSDI'23) — the heuristic-floored shield that is M21/M23's exact pattern.

---

## Arm D — Confounding, distribution shift, and the validity-deferral honesty

- The "regret = re-recall of a demoted record" proxy is **confounded** because recall filters demoted tiers: a positivity violation (logging policy assigns ~zero recall probability to demoted records) **and** a closed-loop selection / **collider** bias — *Feedback Loop and Bias Amplification* (**arXiv:2007.13019**); *Simpson's Paradox in Offline Eval* (**arXiv:2104.08912**); conditioning on a collider (PMC10245143).
- Point-identification is impossible without overlap — Uehara/Shi/Kallus, *A Review of OPE* (**arXiv:2212.06355**); *OPE beyond overlap: partial identification through smoothness* (**arXiv:2305.11812**); *OPE under Weak Distributional Overlap* (**arXiv:2402.08201**); offline-RL distribution shift (Levine et al., **arXiv:2005.01643**).
- Activating on a confounded proxy *is* the failure — Skalse et al., *Goodhart's Law in RL* (ICLR 2024, **arXiv:2310.09144**); Manheim & Garrabrant, *Categorizing Variants of Goodhart's Law* (**arXiv:1803.04585**). M23 avoids it by keeping `KAN_ACTIVE=false` (no optimization pressure on the proxy).

⇒ The remedy — distribution-shifted held-out (M24) + an **exogenous** human-operator oracle (M25) — is the literature-prescribed cure. **The "self-licking ice cream cone" critique is academically correct and is the reason validity is deferred, not asserted.**

---

## §5 — Where M23 goes beyond the literature (justified novelty)

1. A **formally verified** (Kani injective + total + replay-deterministic, Miri-gated) counterfactual OPE / experience log — OPE pipelines + RL replay buffers are float, userspace, unverified; none machine-check codec injectivity/totality or **bit-exact** shadow-score replay.
2. A **no-float, no_std, in-kernel** counterfactual logging leaf — all OPE/CRM/shadow-mode prior art is float userspace; bit-exactness is achievable here *because* there is no float/GPU nondeterminism.
3. **Fusing** tamper-evident hash-chained logging (Crosby & Wallach, USENIX Sec'09; Schneier & Kelsey, USENIX Sec'99) **with** OPE-typed records via the M22 fold — never combined before, never as a verified no-float kernel leaf (integrity honestly scoped to structural/FNV).
4. **Domain transfer** of the logging-policy + offline-counterfactual pattern to **verified in-kernel memory eviction** — no direct prior art (the literature is ads/recsys/search).
5. **Honesty-by-construction** — a kernel-enforced `KAN_ACTIVE=false` invariant + a CI-gated anti-overclaim boot token, encoding the OPE-support + Goodhart cautions as a fail-closed invariant rather than prose.

---

## Annotated bibliography (full)

Bottou et al. arXiv:1209.2355 · Li et al. arXiv:1003.5956 · Swaminathan & Joachims arXiv:1502.02362 · Saito et al. (deterministic logging) arXiv:2603.21485 · Logging Policy Design arXiv:2605.15108 · Open Bandit Pipeline arXiv:2008.07146 · Dudík-Langford-Li arXiv:1103.4601 · Uehara/Shi/Kallus arXiv:2212.06355 · OPE-beyond-overlap arXiv:2305.11812 · weak-overlap arXiv:2402.08201 · Levine et al. arXiv:2005.01643 · Skalse et al. arXiv:2310.09144 · Manheim & Garrabrant arXiv:1803.04585 · Lin 1992 · Mnih et al. DQN 2015 · Schaul et al. arXiv:1511.05952 · Vitter 1985 (reservoir sampling) · Kephart & Chess 2003 (MAPE-K) · Pavlo et al. VLDB 2021 · Kraska et al. arXiv:1712.01208 · LinnOS OSDI'20 · HALP NSDI'23 · Crosby & Wallach USENIX Sec'09 · Schneier & Kelsey USENIX Sec'99 · ReVirt OSDI'02 · Mozilla rr arXiv:1705.05937 · Nagarajan et al. arXiv:1809.05676 · feedback-loop arXiv:2007.13019 · Simpson's-paradox-offline-eval arXiv:2104.08912.
