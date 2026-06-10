# M24 — Honest oracle + durable spill + gated bake-off (the honest #72 resolution)

**Status:** proposed (build-reshaped) · **Pillar:** continuous learning (the GATE) · **Depends on:** M21 (kancell + envelope-no-widening proof), M23 (experience codec + reserved propensity/outcome fields), M20 (durable store), M18.2 (rotating held-out) · **Marker:** `M24: bakeoff OK`

> **One-line:** M24 closes the learning loop **honestly**. It (1) restores the statistical *overlap* M23's deterministic logging policy lacks by injecting **shielded ε-greedy exploration** strictly *inside* the frozen M17 safety envelope (so hard invariants hold by construction), logging the closed-form propensity into **the field M23 already reserved**; (2) attaches a **deterministic, no-float, right-censored survival label** measured on the *unfiltered* `read()` re-touch path; (3) spills the labeled stream **durably** via M20; and (4) gates the M21 kancell activation on a **lower-confidence-bound** test (`V_lower(kancell) − V_upper(heuristic) ≥ MARGIN`) over a distribution-shifted held-out split, **AND** a re-asserted envelope-no-widening proof. Because the traces are necessarily synthetic this milestone, **`gate-not-met` (cell stays dormant) is the expected, correct outcome** — M24 proves the *honest machinery*, not a real activation (that awaits M25's human oracle). This is the honest resolution of the long-blocked #72.

Output of an arxiv-grounded research pass (4 arms + synthesis; see [`docs/research/m24-honest-gate-literature.md`](../research/m24-honest-gate-literature.md)). Every mechanism is cited; the genuine novelty is named.

---

## 1. The problem (precisely)

M23 records a verified experience stream, but M23's research proved it **cannot validate any policy**: the M17 envelope is a **deterministic** logging policy, so the logged propensity is 1/0 — a **positivity/overlap violation** that makes standard off-policy evaluation **structurally non-identifiable** (Saito arXiv:2603.21485), and the obvious regret proxy is **confounded** (recall filters demoted tiers — a collider). M24 must resolve activation **without** these traps, no-float and Kani-provable.

---

## 2. The design (four parts, each cited)

### 2.1 Restore overlap — shielded ε-greedy (the shield *is* the logging policy)
The frozen M17/HALP **Black-Box-Simplex** envelope is a **preemptive shield** (Alshiekh arXiv:1708.08611): it emits the cleared candidate set `A_safe(x)` *before* any choice. M24 injects a rational `ε = ε_num/ε_den` (ship-const, e.g. 1/16) flipping the kancell-greedy-vs-heuristic choice **only among already-cleared candidates**. Because *"demote a pinned/grace record"* is never an element of `A_safe(x)`, exploration **physically cannot** select it — **the hard invariant holds by construction, and the M21 `kani_kan_envelope_no_widening` proof re-asserts unchanged** (the ε path adds *zero* actions to `A_safe`). This restores positivity: `π_b ∈ (0,1)` with a **closed-form integer propensity** over the M23-reserved `logging_propensity_q: u16` (SCALE=1000): `π_b(greedy) = 1000·(1 − ε_num/ε_den + ε_num/(ε_den·m))`, `π_b(other) = 1000·ε_num/(ε_den·m)` for `m = |A_safe(x)|` (Open Bandit Pipeline arXiv:2008.07146; Lawrence arXiv:1707.09118). **Deterministic replay** is preserved by keying the explore coin to a **seeded integer hash of `decision_id`** (reusing the proven M22 fold), never a mutable step counter — so the chosen action *and* its propensity are bit-exactly replayable (extending M23's headline property to the action choice). Safe-exploration framing: exploration is principled *only because* the envelope already pruned every catastrophic action (Garcia & Fernández, JMLR 2015).

### 2.2 The residual — partial identification for singletons
Any **singleton** decision (`m == 1`: a pin/grace/util-pin forces the one safe action) stays structurally deterministic (`propensity == 1000`) — it can *never* be explored. These are **routed**, by the `SOFT_GREEDY`-tag + `propensity==1000` in-kernel detector, to a **Manski + Lipschitz-smoothness partial-identification** estimator returning integer **bounds** `[L, U]` (Khan-Saveski-Ugander arXiv:2305.11812 — a closed-form nearest-neighbour smoothness LP over the quantized kancell grid; Manski floor = fill no-overlap mass with `Y_LO`). **Why both routes:** ε-greedy alone is silent on singletons (a point estimate would overclaim there); bounds alone over tiny overlap are vacuous. ε shrinks the no-overlap mass so the bound is informative; bounds make the gate *sound* exactly where ε physically cannot explore.

### 2.3 The outcome label — deterministic 3-way right-censored survival
`survival_label(decision_tick, now_tick, first_read_touch_tick, W) → {NegativeFalseForget, PositiveTrueForget, Censored}`. A `FORGET_DECISION` is matched against subsequent `RECALL_TOUCH` records drawn **only from the unfiltered `read()` path** (never `recall()`, which filters demoted `TIER_COLD` — the collider). Re-touch within an integer window `W` ⇒ **NegativeFalseForget** (a bounded forward-reuse-distance event — the Belady cache-quality oracle, Liu arXiv:2007.15859); window fully elapsed, no touch ⇒ **PositiveTrueForget**; window still open ⇒ **Censored** and **excluded** from both classes (the delayed-feedback false-negative trap — Chapelle KDD'14). Encoded into the M23-reserved `OutcomeLabel` slot with **no byte-offset shift** (the `kani_exp_schema_stability` lemma). **The confound is NAMED in the witness** (`confound=RECALL-CENSORS-COLD-NAMED`), not silently handled — `read()` removes the recall-tier collider but a hard-*evicted* record is still unobservable, so M25's exogenous oracle remains required for full validity.

### 2.4 The activation gate — conjunctive, one-shot, lower-bound (HCPI/Seldonian)
`KAN_ACTIVE` flips `false→true` **only if**, over the M18.2 rotating **distribution-shifted** held-out safety partition: **[A]** `V_lower(kancell) − V_upper(heuristic) ≥ MARGIN`, where `V_lower` is the **integer lower confidence bound** (identified self-normalized IPS mass over `m>1` explored records + Manski/smoothness bounds over singletons; a **Maurer-Pontil empirical-Bernstein** lower bound, arXiv:0907.3740, reduced to closed-form integer `(sum, sum-of-squares, n, rational δ)`; **rounding always *down*** — pessimistic); **AND** **[B]** the M21 `kani_kan_envelope_no_widening` proof **re-asserts** on the exact shipped table. Safety **[B]** is unconditional + proven for every table; utility **[A]** is *earned*. An **eligibility pre-gate** (a minimum of *resolved* non-censored pairs AND a minimum overlap-restored mass) distinguishes `gate-not-evaluable` from a genuine `gate-not-met`. The gate runs **exactly once** per frozen `(table, split)` — re-testing spends confidence (multiple-comparisons inflation) and is forbidden (Thomas HCPI ICML'15; Thomas Seldonian, *Science* 2019). **Gating on the lower bound makes activation sound:** if the cell's *worst-case* value still beats the always-live heuristic floor, activation cannot regress even under worst unobserved outcomes; a non-identifiable / near-zero-overlap stream yields a low/vacuous `L` that simply **fails closed to dormant**.

---

## 3. Durable spill (zero M20 regression)
The labeled stream (canonical `ExperienceRecord` bytes, folded through the **reused** M22 `xp_chain_mix` into the **separate** per-agent `xp_head`) is appended as M20 log-structured frames into a **dedicated experience region** behind M20's existing `gen+1` two-phase commit (dirty → FLUSH → superblock `gen+1` → FLUSH) — the Rosenblum-Ousterhout LFS + checkpoint-replay discipline M20 already proves. On mount, the experience log replays to the committed watermark, discarding any torn tail. **M20's superblock `gen` and M22's `chain_head` are byte-identical** — M24 adds a region + a separate head, never a new M20 superblock field or a change to M20's flush/replay path, so M20's persist self-test + 6 `blkfmt` harnesses stay byte-green. The bake-off verdict + integer bounds spill alongside (the gate decision survives reboot, replay-deterministic).

---

## 4. `tb-encode` leaves + Kani (52 → ~58; **measure each locally** — the M22 lesson)
New no-float leaves: `explore.rs` (the propensity helper) + `bakeoff.rs` (estimator/label/bounds), all saturating integer on the kancell grid, reusing `kan_score`/`GRID_*`/`DEMOTE_BAND`/`KAN_FEATURES` + `exp.rs` `OutcomeLabel`/`policy_kind`. Three pure functions + harnesses (each with a negative control):
1. **`explore_propensity_q(ε_num, ε_den, m, is_greedy) → u16`** — total/saturating, provably in `[1,1000]` (positivity) for every cleared action when `ε_num>0, m≥1`, with the **`m==1` singleton guard returning exactly 1000**. *Neg:* an `ε=0`/`m=0`/non-saturating path yields 0 or panics.
2. **`survival_label(...) → {Neg,Pos,Censored}`** — total on saturating tick subtraction; the partition **exhaustive + mutually exclusive**; **monotone-resolution** (Censored→resolved only, a resolved label never flips → replay-stable). *Neg:* a 2-way label (dropping Censored) mislabels an open-window record; a `recall()`-derived touch re-opens the collider.
3. **`value_lower_bound(...) → i64`** — total (no divide, no recursion in the nearest-neighbour smoothness sweep) and **sound** (`L` never exceeds the true overlap-region mean; Manski floor `L=−∞` fallback; rounds **down**). *Neg:* gating on the upper bound / midpoint, or loosening `L`, lets an unsound interval clear `MARGIN`.
4. **bit-exact replay determinism** of `(chosen action, propensity, label, V_lower)` from `(decision_id, agent_seed, A_safe, frozen table)` alone (extends `kani_exp_replay_determinism`). *Neg:* keying the coin to a mutable step counter desyncs replay.
5. **envelope-no-widening re-assertion** (reuse M21) — re-passes unchanged under the soft-greedy path (ε only chooses *among* cleared candidates). *Neg:* exploration *before* the shield, or widening `A_safe`, fails it.
6. **schema-stability** (reuse `kani_exp_schema_stability`) — populating `logging_propensity_q` + `SOFT_GREEDY` + a resolved `OutcomeLabel` shifts no byte offset → M22/M20 fold/spill byte-identical.

---

## 5. Seam (`tb-hal/src/mem.rs` + a `bakeoff_selftest()` facade)
At the `forget_sweep` demote site, **after** the frozen envelope emits `A_safe(x)`: draw the explore coin `c = xp_chain_mix(decision_id, agent_seed) mod ε_den mod m` (keyed to the immutable `decision_id`), pick the explore index among cleared candidates or the kancell-greedy one, stamp `logging_propensity_q` + `logging_policy_kind=SOFT_GREEDY`; pin/grace/util-pin stay `propensity==1000` DETERMINISTIC, never explored. At `read()` touches, stamp the unfiltered `RECALL_TOUCH`. The bake-off replay + gate is `tb_hal::bakeoff_selftest() → BakeoffProof{Cleared{vlo_kan,vhi_heur,margin} | NotMet | NotEvaluable | Failed{stage}}`, spilling via the M20 store + re-asserting the envelope proof; the kernel branches on it (the `ExpProof`/`PersistProof` pattern). `KAN_ACTIVE` stays a const `false`, flipped **only** by the gate verdict. `tb-encode` stays pure; `tb-hal` calls the leaf next to `kan_score`/`prov::append`.

---

## 6. DoD — `M24: bakeoff OK` (with the honest gate-not-met path as a first-class success)
Witness (printed before the marker, fail-closed, positively required):
```
bakeoff: vlo_kan=<i> vhi_heur=<i> margin=<m> cleared=<0|1> overlap-restored-eps=<q> resolved=<n> censored=<c> no-overlap-mass=<f> confound=RECALL-CENSORS-COLD-NAMED estimator=MANSKI+SMOOTHNESS-LP no-float=1 envelope-no-widening=1
```
- `M24: bakeoff OK` — the machinery executed (spill + replay + label + gate) and the gate evaluated.
- **`M24: bakeoff OK (gate-not-met)`** — the margin was not cleared on the (synthetic) traces; the cell stays **dormant**. **This is the designed, correct outcome** (the M21 `(heuristic floor, gate-not-met)` idiom) — an honest gate that *refuses* is a success, not a failure.
- `M24: bakeoff OK (gate-not-evaluable: insufficient resolved support)` — too few non-censored pairs / near-zero overlap (distinct from a genuine refusal).

Run-scripts: positively **require** the `bakeoff:` witness with `no-float=1` + `envelope-no-widening=1`; **reject** the `(gate-not-met)`/`(gate-not-evaluable)` variants on any lane asserting an **active** cell; **reject** any `validated`/`evaluated` near the marker; **fail-closed** withhold the marker if the self-test does not execute. `EXPECTED_HARNESSES` 52 → ~58.

---

## 7. Honest caveats (conceded)
- **The traces are necessarily SYNTHETIC** (no real agent-memory eviction workload yet — the same gap that shipped M21 dormant). So **`gate-not-met` is the expected, correct outcome**; M24 proves the honest *machinery* (estimator + label + gate + spill), not a real activation. Real activation on a distribution-shifted operator workload is future work (M25+).
- The label is **still residually confounded** even on `read()` — a hard-*evicted* (not merely demoted) record is unobservable. `read()` removes only the recall-tier collider. Full validity **requires** M25's exogenous human-operator oracle with a held-out un-demoted channel; named in the witness, not claimed closed.
- The Lipschitz constant `L` is an **untestable** smoothness assumption — pinned **conservatively** as a pre-registered const (emitted in the witness), with the Manski floor (`L=−∞`) as the always-sound fallback.
- With small ε the no-overlap mass is large → the interval is near-vacuous → the gate (correctly) almost never clears. **A vacuous bound that never activates is the right failure mode.** Persistent vacuity is the signal to raise ε within the envelope or defer to M25.
- The `(1−δ)` HCPI/Seldonian guarantee holds only for a **single pre-registered one-shot** safety test; re-running the gate or tuning `MARGIN` against the partition spends confidence and Goodhart-optimizes the held-out set — enforced one-shot by compile-time consts.
- Tighter bounds (Logarithmic-Smoothing arXiv:2405.14335; TDR arXiv:2402.08201) need float — kept strictly out-of-band, never on the Kani-proven gate path (or only as a frozen fixed-point LUT with a checked max-error bound, the M21 `q-err≤B` discipline).

---

## 8. Where M24 goes beyond the literature
- A **formally verified** (Kani-proven total/sound/bit-exact-replayable), **no-float, in-kernel partial-identification OPE estimator** + **empirical-Bernstein lower bound** — the smoothness LP / Manski bounds / HCPI test all live in float userspace; none is machine-checked total/sound nor reduced to a saturating-integer grid sweep inside an OS forget daemon.
- **The shield-as-logging-policy identity** — the *same* frozen envelope artifact is the safety proof, the preemptive shield emitting `A_safe(x)`, **and** the deterministic-logging policy whose positivity the ε repairs. The literature treats shielding (Alshiekh) and logging-policy design (Saito) as separate concerns; here they are one verified object.
- **Honesty-by-construction** — the `SOFT_GREEDY`-tag + `propensity==1000` detector *mechanically* routes singletons away from naive IPS to the partial-ID bound, and the marker mechanically cannot emit an activation the lower bound does not support nor launder the confounded recall proxy.
- **Domain transfer with an explicit censoring model** — a deterministic 3-way right-censored survival label (delayed-feedback CVR formalism) on the unfiltered `read()` reuse-distance channel, inside a proven safety envelope; no prior art unifies OPE / survival / safe-RL for verified in-kernel forget/demote.

---

### References
Full survey + citations in [`docs/research/m24-honest-gate-literature.md`](../research/m24-honest-gate-literature.md). Key: Alshiekh arXiv:1708.08611 · Open Bandit Pipeline arXiv:2008.07146 · Saito (deterministic logging) arXiv:2603.21485 · Khan-Saveski-Ugander arXiv:2305.11812 · Thomas HCPI ICML'15 + Seldonian *Science* 2019 · Maurer-Pontil arXiv:0907.3740 · Chapelle KDD'14 · Mansoury et al. arXiv:2007.13019 · Liu (forward reuse distance) arXiv:2007.15859 / Belady 1966 · Garcia & Fernández JMLR 2015 · Rosenblum-Ousterhout LFS 1992 / ReVirt OSDI'02 / rr arXiv:1705.05937 · Skalse (Goodhart) arXiv:2310.09144.
