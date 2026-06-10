# Literature survey — honest activation gating for a verified in-kernel learned policy (M24)

**Method:** an arxiv-first pass for [M24](../proposals/M24-honest-gate.md) — 4 arms (shielded exploration to restore overlap; partial identification under no-overlap; high-confidence safe policy improvement; the deterministic survival label + durable replay) + synthesis. Verdict: **build-reshaped**. The literature provides every mechanism; the genuine novelty (a verified, no-float, in-kernel partial-identification OPE estimator, and the *shield-as-logging-policy identity*) is named in §5.

This is the academic basis (per the project's standing academic-grounding directive); where M24 goes beyond known work it is justified.

---

## Arm A — restoring overlap via shielded / safe exploration
- **Preemptive shielding** — Alshiekh, Bloem, Ehlers, Könighofer, Niekum, Topcu, *Safe RL via Shielding* (**arXiv:1708.08611**, AAAI-18): the shield computes the safe action set `A_safe(s)` *before* selection; exploration over it preserves safety for **any** policy. ⇒ the M17 envelope *is* the shield; ε-greedy strictly inside `A_safe` keeps the pin/grace invariant **by construction**.
- **ε-greedy logs a closed-form propensity** — Open Bandit Dataset and Pipeline (Saito et al., **arXiv:2008.07146**, NeurIPS'21 D&B): `π_b(greedy)=(1−ε)+ε/|A|`, `π_b(other)=ε/|A|`; a deterministic policy gives `π_b∈{0,1}` (positivity violation, IPS weights undefined); any `π_b>0` restores identifiability. ⇒ integer-exact into the M23-reserved `logging_propensity_q`.
- **Deterministic argmax logging collapses IS; sample instead** — Lawrence et al., *Counterfactual Learning under Deterministic Logging* (**arXiv:1707.09118**, EMNLP'17). ⇒ the seeded-PRNG explore choice keyed to the immutable `decision_id` (reuse the M22 fold) restores a valid propensity *and* stays bit-exactly replayable (the reproducibility trap — Nagarajan **arXiv:1809.05676** — is avoided by keying to identity, not a step counter).
- **Safe-exploration risk posture** — García & Fernández, *A Comprehensive Survey on Safe RL* (JMLR 16, 2015): random exploration is safe only when external knowledge bounds it to a pre-computed safe set. ⇒ ε>0 strictly inside the frozen envelope is *principled* safe exploration.

## Arm B — partial identification under no overlap
- Khan, Saveski, Ugander, *OPE Beyond Overlap: Sharp Partial Identification Under Smoothness* (**arXiv:2305.11812**, ICML'24): Lipschitz-smoothness LPs with a concise closed form give **sharp `[L,U]` bounds** on the no-overlap region. ⇒ a no-float nearest-neighbour integer sweep over the kancell grid returning the **lower** bound the gate consumes.
- Manski bounds / no-point-ID without overlap — via Uehara/Shi/Kallus, *A Review of OPE* (**arXiv:2212.06355**); weak-overlap (**arXiv:2402.08201**). ⇒ the Manski floor (`L=−∞`, fill no-overlap with `Y_LO`) is the always-sound fallback. Singletons (`m==1`, forced by a hard invariant) are *routed* to bounds, never to IPS.

## Arm C — high-confidence safe policy improvement (the gate)
- Thomas, Theocharous, Ghavamzadeh, *High-Confidence Policy Improvement* (ICML'15) + Thomas et al., *Seldonian framework* (**Science 2019**): a candidate/safety-test split; deploy **only if** the `(1−δ)` lower-confidence-bound clears the baseline floor; otherwise return **No-Solution-Found**. ⇒ the literal `gate-not-met → stay dormant` rule; **one-shot** per `(table, split)` (re-testing spends confidence — multiple-comparisons inflation).
- Maurer & Pontil, *Empirical Bernstein Bounds* (**arXiv:0907.3740**, COLT'09): a variance-sensitive, data-dependent finite-sample lower bound reducible to closed-form integer `(sum, sum², n, rational δ)`. ⇒ the no-float Kani-provable concentration math for `V_lower`.
- Skalse et al., *Goodhart in RL* (**arXiv:2310.09144**, ICLR'24): optimizing a confounded proxy is the failure mode. ⇒ the held-out split must be a genuine M18.2 distribution shift, and the gate must not be tuned against it.

## Arm D — the deterministic outcome label + durable replay
- **Right-censored survival / delayed feedback** — Chapelle, *Modeling Delayed Feedback* (KDD'14) + CVR-debiasing (PMC11431287): open-window records are **right-censored**, not negatives. ⇒ the 3-way `{Negative, Positive, Censored}` label, Censored excluded.
- **Reuse distance = the cache oracle** — Liu et al., *Learning Forward Reuse Distance* (**arXiv:2007.15859**) + Bélády (1966): a bounded-window re-touch is a thresholded forward-reuse-distance event — an integer *measured* label, not an invented proxy.
- **The collider** — Mansoury et al., *Feedback Loop and Bias Amplification* (**arXiv:2007.13019**): what is shown filters what is observed. ⇒ measure re-touch on the **unfiltered `read()`** path, never `recall()` (which filters `TIER_COLD`).
- **Durable replay** — Rosenblum & Ousterhout, *LFS* (ACM TOCS, 1992); ReVirt (OSDI'02); rr (**arXiv:1705.05937**): append-only log + consistent checkpoint + revert-and-replay; bit-exact *because* the codec is integer/no-float. ⇒ reuse M20's two-phase commit verbatim, separate region + head, zero M20 regression.

---

## §5 — Beyond the literature (justified novelty)
1. A **formally verified, no-float, in-kernel partial-identification OPE estimator + empirical-Bernstein lower bound** — these all live in float userspace; none is Kani-proven total/sound nor a saturating-integer grid sweep inside an OS forget daemon.
2. **The shield-as-logging-policy identity** — the *same* frozen envelope is the safety proof, the preemptive shield, **and** the deterministic-logging policy whose positivity the ε repairs (the literature treats shielding and logging-policy design as separate; here they are one verified object).
3. **Honesty-by-construction** — the `SOFT_GREEDY`-tag + `propensity==1000` detector mechanically routes singletons to the bound; the marker mechanically cannot activate beyond what the lower bound supports.
4. **Domain transfer with an explicit censoring model** — a deterministic 3-way right-censored survival label on the unfiltered `read()` reuse-distance channel, inside a proven envelope; no prior art unifies OPE / survival / safe-RL for verified in-kernel forget/demote.

---

## Annotated bibliography
Alshiekh arXiv:1708.08611 · Open Bandit Pipeline arXiv:2008.07146 · Lawrence arXiv:1707.09118 · Saito (deterministic logging) arXiv:2603.21485 · Khan-Saveski-Ugander arXiv:2305.11812 · Uehara/Shi/Kallus arXiv:2212.06355 · weak-overlap arXiv:2402.08201 · Thomas HCPI ICML'15 · Thomas Seldonian *Science* 2019 · Maurer-Pontil arXiv:0907.3740 · Skalse arXiv:2310.09144 · Chapelle KDD'14 · Liu arXiv:2007.15859 / Bélády 1966 · Mansoury arXiv:2007.13019 · Rosenblum-Ousterhout LFS 1992 · ReVirt OSDI'02 · rr arXiv:1705.05937 · Nagarajan arXiv:1809.05676 · García & Fernández JMLR 2015 · LS arXiv:2405.14335 · TDR arXiv:2402.08201.
