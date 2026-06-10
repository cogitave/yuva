//! The M24 HONEST-GATE estimator math -- the pure, verified value-computation
//! leaf behind the deterministic survival LABEL, the partial-identification
//! VALUE LOWER BOUND, and the empirical-Bernstein CONFIDENCE lower bound the M24
//! activation gate conjuncts over, lifted into `tb-encode` exactly as the M21
//! forget policy ([`crate::kancell`]), the M22 ledger ([`crate::prov`]), and the
//! M23 codec ([`crate::exp`]) were.
//!
//! ## What M24 gates on (proposal §2.3/§2.4)
//!
//! The learning loop is closed HONESTLY by three composable integer estimators,
//! all no-float, all Kani-total/sound:
//!
//! 1. **[`survival_label`]** -- a deterministic, no-float, right-censored 3-way
//!    survival label `{Negative, Positive, Censored}` over a `FORGET_DECISION`
//!    matched against subsequent unfiltered-`read()` `RECALL_TOUCH` events. A
//!    re-touch WITHIN an integer window `W` is a `NegativeFalseForget` (a bounded
//!    forward-reuse-distance event -- the Belady cache-quality oracle, Liu
//!    arXiv:2007.15859); the window fully elapsed with no touch is a
//!    `PositiveTrueForget`; the window still open is `Censored` and EXCLUDED from
//!    both classes (the delayed-feedback false-negative trap -- Chapelle KDD'14).
//!    The partition is EXHAUSTIVE + MUTUALLY-EXCLUSIVE + MONOTONE-RESOLUTION
//!    (a `Censored` label can only ever resolve to `Negative`/`Positive`, never
//!    flip a resolved one -> replay-stable).
//!
//! 2. **[`value_lower_bound`]** -- the Manski floor (fill the no-overlap mass with
//!    the worst admissible reward `Y_LO`) PLUS a closed-form Lipschitz-smoothness
//!    nearest-neighbour integer sweep over the quantized kancell grid
//!    (Khan-Saveski-Ugander arXiv:2305.11812), returning an integer LOWER bound on
//!    the overlap-region mean. TOTAL (no divide, no recursion in the sweep) and
//!    SOUND (`L` never exceeds the true overlap-region mean; rounds DOWN).
//!
//! 3. **[`eb_lower_bound`]** -- a Maurer-Pontil empirical-Bernstein integer LOWER
//!    confidence bound (arXiv:0907.3740) reduced to closed-form integer
//!    `(sum, sum_sq, n, rational delta)`, rounding DOWN -- the `(1-delta)` HCPI
//!    lower bound the gate clears `>= MARGIN` against the heuristic floor (Thomas
//!    HCPI ICML'15; Thomas Seldonian, Science 2019).
//!
//! 4. **[`gate_clears`]** -- the conjunctive ONE-SHOT activation test: utility
//!    `[A]` (`V_lower(kancell) - V_upper(heuristic) >= MARGIN`) earned over the
//!    distribution-shifted held-out split, AND safety `[B]` (the re-asserted M21
//!    envelope-no-widening proof, discharged in `proofs.rs`). On synthetic traces
//!    the gate WILL NOT clear -- `gate-not-met` (the cell stays DORMANT) is the
//!    designed, correct outcome (proposal §6/§7).
//!
//! ## Numeric format (no float, ever -- mirrors `kancell`/`exp`)
//!
//! Pure integer arithmetic, zero alloc, zero deps, SATURATING throughout
//! (`#![no_std]` + `#![forbid(unsafe_code)]` inherited from the crate root). All
//! rewards live in the M17 [`DEMOTE_BAND`]-shaped reward band so the closed-form
//! overflow headroom is a tautology, and every divide is by a structurally
//! non-zero divisor (a count `>= 1` guarded before the division), so no
//! divide-by-zero is reachable. The bounds round DOWN (pessimistic / sound).

// Re-export the EXACT kancell grid geometry + the dormant scorer so the seam, the
// estimator, and the Kani harnesses all share ONE decidable geometry (the
// quantization grid, the feature count, the score band, and the demote-band clamp)
// -- NOT redefined here, they are the M21 artifact's own constants (proposal §4).
pub use crate::kancell::{
    kan_score, DEMOTE_BAND, GRID_LO, GRID_STEP_LOG2, KAN_FEATURES, KnotTable,
};
// Reuse the M23 outcome label + policy-kind vocabulary (proposal §4): the survival
// label encodes into the M23-reserved OutcomeLabel slot; the SOFT_GREEDY detector
// routes singletons (propensity == 1000) to the partial-id bound.
pub use crate::exp::{policy_kind, OutcomeLabel};

/// The worst admissible reward `Y_LO` (the Manski floor fill value, proposal §2.2):
/// the no-overlap mass -- decisions the soft-greedy policy could NOT explore (every
/// singleton + every record outside the explored support) -- is filled with this
/// pessimistic floor, so the bound is SOUND even where epsilon physically cannot
/// explore. The M17 reward band is the [`DEMOTE_BAND`]; `Y_LO` is its low edge.
pub const Y_LO: i64 = DEMOTE_BAND.0; // -34_000

/// The best admissible reward `Y_HI` (the Manski ceiling, proposal §2.2): the
/// no-overlap mass of the OPPONENT (the always-live heuristic) is filled with this
/// optimistic ceiling when forming `V_upper(heuristic)`, so the gate compares the
/// kancell's WORST case against the heuristic's BEST case (pessimistic for
/// activation -- the gate clears only if the cell beats the heuristic even then).
pub const Y_HI: i64 = DEMOTE_BAND.1; // 34_000

/// The pre-registered Lipschitz smoothness constant `L` (proposal §2.2/§7): the
/// nearest-neighbour smoothness sweep assumes the overlap-region mean reward
/// changes by at most `L` per unit of quantized grid distance, so an unexplored
/// grid cell's reward is bounded below by `(nearest explored reward) - L * dist`.
/// An UNTESTABLE assumption, pinned CONSERVATIVELY (large) as a ship-const and
/// emitted in the witness; the Manski floor (`Y_LO`) is the always-sound fallback
/// when no explored neighbour is within range. Chosen so `L * max_grid_dist` is a
/// large fraction of the reward band (a near-vacuous, almost-always-refusing
/// bound -- the right failure mode for synthetic traces, proposal §7).
pub const LIPSCHITZ_L: i64 = 64;

/// The number of quantized grid cells along ONE feature axis (9 knots / 8
/// intervals -- the kancell `KAN_KNOTS`). The smoothness sweep walks this many
/// cells, so the loop is fixed-bound (no recursion, `#[kani::unwind]`-friendly).
pub const GRID_CELLS: usize = 9;

/// The pre-registered activation MARGIN (proposal §2.4): `KAN_ACTIVE` flips
/// `false -> true` ONLY if `V_lower(kancell) - V_upper(heuristic) >= MARGIN`. A
/// ship-const (one-shot, compile-time -- re-tuning it against the held-out split
/// spends confidence + Goodhart-optimizes, forbidden by HCPI). Pinned positive so
/// the cell must STRICTLY beat the heuristic floor by a real margin, not tie it.
pub const ACTIVATION_MARGIN: i64 = 250;

/// The minimum count of RESOLVED (non-censored) labeled pairs the eligibility
/// pre-gate requires before the gate is even EVALUABLE (proposal §2.4): below this
/// the verdict is `gate-not-evaluable` (insufficient resolved support), distinct
/// from a genuine `gate-not-met`. A small floor so the boot self-test's seeded
/// stream is evaluable, but non-zero so a vacuous (all-censored) stream is honestly
/// reported as not-evaluable.
pub const MIN_RESOLVED_SUPPORT: u32 = 1;

/// The minimum overlap-restored exploration mass (summed soft-greedy propensity,
/// in `SCALE == 1000` units) the eligibility pre-gate requires (proposal §2.4): a
/// near-zero-overlap stream (no exploration actually happened) is `gate-not-
/// evaluable`, not a genuine refusal. The exploration that the boot self-test's
/// shielded epsilon-greedy injects clears this; a pure-deterministic stream does not.
pub const MIN_OVERLAP_MASS: u64 = 1;

/// The deterministic 3-way RIGHT-CENSORED survival label (proposal §2.3) of a
/// `FORGET_DECISION`, matched against the subsequent unfiltered-`read()`
/// `RECALL_TOUCH` stream. A CLOSED, EXHAUSTIVE, MUTUALLY-EXCLUSIVE set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SurvivalLabel {
    /// NegativeFalseForget: the demoted record was re-touched WITHIN the window
    /// `W` -- the forget was WRONG (a bounded forward-reuse-distance event). The
    /// reward is HIGH (forgetting a still-useful record is a mistake).
    Negative,
    /// PositiveTrueForget: the window fully elapsed with NO re-touch -- the forget
    /// was CORRECT. The reward is LOW/neutral (the record was genuinely cold).
    Positive,
    /// Censored: the window is still OPEN (not enough time has elapsed to know).
    /// EXCLUDED from both classes -- using it would introduce a delayed-feedback
    /// false-negative (Chapelle KDD'14). A `Censored` label can ONLY resolve to
    /// `Negative`/`Positive` as `now_tick` advances (monotone resolution).
    Censored,
}

impl SurvivalLabel {
    /// `true` iff this label is RESOLVED (contributes to the gate's support count).
    /// `Censored` is the only unresolved variant.
    #[inline]
    #[must_use]
    pub fn is_resolved(self) -> bool {
        !matches!(self, SurvivalLabel::Censored)
    }

    /// Encode this RESOLVED survival label into the M23-reserved [`OutcomeLabel`]
    /// slot WITHOUT shifting a byte offset (the `kani_exp_schema_stability` lemma):
    /// a `Negative` (false-forget) becomes a `ReRecalled(delay)` (the re-touch
    /// delay), a `Positive` (true-forget) becomes an `Evicted(horizon)` (the
    /// observation horizon). `Censored` has no resolved outcome and maps to
    /// `Unset` (it is excluded from the gate). Total -- no panic.
    #[inline]
    #[must_use]
    pub fn to_outcome(self, delay_or_horizon: i64) -> OutcomeLabel {
        match self {
            SurvivalLabel::Negative => OutcomeLabel::ReRecalled(delay_or_horizon),
            SurvivalLabel::Positive => OutcomeLabel::Evicted(delay_or_horizon),
            SurvivalLabel::Censored => OutcomeLabel::Unset,
        }
    }
}

/// Compute the deterministic 3-way right-censored survival label of a
/// `FORGET_DECISION` (proposal §2.3). TOTAL on saturating tick subtraction; the
/// partition is EXHAUSTIVE + MUTUALLY-EXCLUSIVE + MONOTONE-RESOLUTION.
///
/// * `decision_tick` -- the logical clock at which the record was demoted.
/// * `now_tick` -- the current logical clock (the observation horizon).
/// * `first_read_touch_tick` -- `Some(t)` if the demoted record was re-touched on
///   the UNFILTERED `read()` path at tick `t` (NEVER `recall()`, which filters
///   demoted tiers -- the collider, proposal §8), else `None`.
/// * `w` -- the integer survival window width.
///
/// Resolution (exhaustive, mutually exclusive):
/// * a re-touch with `t - decision_tick <= w` (and `t >= decision_tick`) ->
///   [`SurvivalLabel::Negative`] (re-touched IN window: the forget was wrong);
/// * otherwise, if the window has fully elapsed (`now - decision >= w`) ->
///   [`SurvivalLabel::Positive`] (no in-window touch + window closed: true forget);
/// * otherwise (window still open, no in-window touch yet) ->
///   [`SurvivalLabel::Censored`].
///
/// MONOTONE RESOLUTION: a `Censored` label resolves only as `now_tick` advances;
/// once `Negative`/`Positive` it never flips (a re-touch tick is immutable, and a
/// closed window stays closed) -- so a replayed stream relabels identically.
#[must_use]
pub fn survival_label(
    decision_tick: u64,
    now_tick: u64,
    first_read_touch_tick: Option<u64>,
    w: u64,
) -> SurvivalLabel {
    // A re-touch IN the window decides Negative immediately (the strongest signal),
    // regardless of how far `now` has advanced -- a re-touch tick is immutable, so
    // this is the monotone-stable resolution. Saturating subtraction is TOTAL.
    if let Some(t) = first_read_touch_tick {
        // Only a touch AT/AFTER the decision counts (a pre-decision touch is not a
        // re-touch of the demoted record). saturating_sub clamps a stale touch to 0.
        if t >= decision_tick {
            let reuse_dist = t.saturating_sub(decision_tick);
            if reuse_dist <= w {
                return SurvivalLabel::Negative;
            }
            // A touch AFTER the window does NOT make it a false-forget (the record
            // was genuinely cold during the window); fall through to the elapsed test.
        }
    }
    // No in-window re-touch. If the window has fully elapsed, it is a true forget;
    // otherwise the outcome is still unknown -> censored (excluded from the gate).
    let elapsed = now_tick.saturating_sub(decision_tick);
    if elapsed >= w {
        SurvivalLabel::Positive
    } else {
        SurvivalLabel::Censored
    }
}

/// Map a resolved [`SurvivalLabel`] to its integer REWARD in the M17 reward band
/// (proposal §2.3): a `Positive` true-forget earns the high reward (`Y_HI` -- the
/// forget was correct, the demote freed capacity with no regret), a `Negative`
/// false-forget earns the low reward (`Y_LO` -- forgetting a still-useful record
/// is the costly mistake the policy must avoid). `Censored` has no reward and
/// returns the Manski floor `Y_LO` (sound; it is excluded from the gate anyway).
/// TOTAL -- a pure closed-form map, no divide, no panic.
#[inline]
#[must_use]
pub fn label_reward(label: SurvivalLabel) -> i64 {
    match label {
        SurvivalLabel::Positive => Y_HI,
        SurvivalLabel::Negative => Y_LO,
        SurvivalLabel::Censored => Y_LO, // excluded; the sound floor
    }
}

/// A Maurer-Pontil empirical-Bernstein integer LOWER confidence bound
/// (arXiv:0907.3740), reduced to closed-form integer arithmetic over the sufficient
/// statistics `(sum, sum_sq, n)` of `n` bounded rewards in `[lo, hi]` and a rational
/// confidence `delta = delta_num/delta_den` (proposal §2.4). Returns an integer
/// lower bound on the TRUE mean that holds with probability `>= 1 - delta`, ROUNDED
/// DOWN (pessimistic / sound). TOTAL: `n == 0` fails closed to the floor `lo` (no
/// support -> no claim above the floor), and every divide is by a guarded non-zero.
///
/// The Maurer-Pontil bound is
/// `mean - sqrt(2 * Var * ln(2/delta) / n) - 7 * range * ln(2/delta) / (3 * (n-1))`.
/// We compute a CONSERVATIVE integer surrogate: the empirical mean MINUS an integer
/// over-approximation of both penalty terms, so the returned value is `<=` the true
/// Maurer-Pontil bound (hence still a valid `(1-delta)` lower bound -- rounding the
/// penalties UP and the mean DOWN can only make the gate harder to clear, never
/// unsound). `ln(2/delta)` is replaced by the integer ceiling `ln_ceil` derived from
/// the rational `delta` via the pure [`crate::memscore::ln_fixed`] (no float). The
/// variance term uses the integer population variance `Var = (n*sum_sq - sum^2)/n^2`.
///
/// NEGATIVE-CONTROL discipline: a bound that ADDED the penalties (an UPPER bound) or
/// rounded the mean UP would let an unsound interval clear the margin -- the
/// `kani_bakeoff_eb_*` harness fires on exactly that.
#[must_use]
pub fn eb_lower_bound(
    sum: i64,
    sum_sq: i128,
    n: u32,
    range: i64,
    delta_num: u32,
    delta_den: u32,
    lo: i64,
) -> i64 {
    // No support -> no claim above the Manski floor (fail closed, no divide).
    if n == 0 {
        return lo;
    }
    let n_i = n as i128;
    // Empirical mean, rounded DOWN (toward -inf via floored division for negatives).
    let mean = floor_div_i128(sum as i128, n_i);
    if n == 1 {
        // A single sample has no variance estimate; the Maurer-Pontil bound is
        // dominated by the range penalty. Subtract a full range as a conservative
        // (sound, near-vacuous) penalty -- one sample can barely support a claim.
        return saturating_sub_i64(mean as i64, range.saturating_abs());
    }
    // Integer population variance numerator: n*sum_sq - sum^2 >= 0 (Cauchy-Schwarz),
    // so Var = (n*sum_sq - sum^2) / n^2, rounded UP (conservative -> larger penalty).
    let var_num = n_i.saturating_mul(sum_sq).saturating_sub((sum as i128).saturating_mul(sum as i128));
    let var_num = if var_num < 0 { 0 } else { var_num }; // clamp tiny negatives from saturation
    let n_sq = n_i.saturating_mul(n_i);
    let var = ceil_div_i128(var_num, n_sq); // round variance UP (larger penalty)
    // ln(2/delta) as an integer ceiling via the pure fixed-point ln. delta = num/den,
    // so 2/delta = 2*den/num; ln_fixed returns ln(x) in SCALE==1000 fixed-point, which
    // we ceil-divide back to an integer >= 1 (a larger ln -> larger penalty -> sound).
    let ln_arg = if delta_num == 0 {
        // delta == 0 is an undefined (infinitely tight) confidence: use a large ln.
        1 << 20
    } else {
        // 2 * den / num, floored to >= 1.
        let v = (2u64.saturating_mul(delta_den as u64)) / (delta_num as u64);
        if v < 2 { 2 } else { v }
    };
    let ln_fixed_q = crate::memscore::ln_fixed(ln_arg); // ln in SCALE==1000 units
    let scale: i128 = 1000;
    let ln_ceil = ceil_div_i128(ln_fixed_q as i128, scale).max(1); // integer ln, >= 1
    // VARIANCE PENALTY (conservative integer surrogate of sqrt(2*Var*ln/n)):
    // we over-approximate sqrt(x) by an integer ceiling, and round the whole term UP.
    let var_term_inner = (2i128)
        .saturating_mul(var)
        .saturating_mul(ln_ceil)
        / n_i.max(1);
    let var_penalty = isqrt_ceil_i128(var_term_inner.max(0));
    // RANGE PENALTY: 7 * range * ln / (3 * (n-1)), rounded UP (conservative).
    let range_penalty_num = (7i128)
        .saturating_mul(range.saturating_abs() as i128)
        .saturating_mul(ln_ceil);
    let range_penalty_den = (3i128).saturating_mul((n_i - 1).max(1));
    let range_penalty = ceil_div_i128(range_penalty_num, range_penalty_den);
    // The lower bound: mean - var_penalty - range_penalty, saturating in i128, then
    // floored at the Manski floor `lo` (the bound never claims above the truth
    // without support -- a sound interval). `var_penalty` is the i64 ceiling sqrt.
    let bound = mean
        .saturating_sub(var_penalty as i128)
        .saturating_sub(range_penalty);
    let bound_i64 = clamp_i128_to_i64(bound);
    // Floor at the Manski floor `lo` (never claim below the sound floor).
    bound_i64.max(lo)
}

/// The MANSKI + Lipschitz-SMOOTHNESS partial-identification VALUE LOWER BOUND
/// (proposal §2.2), `V_lower`: a SOUND integer lower bound on the candidate
/// policy's value, combining (a) the identified empirical-Bernstein lower bound
/// over the `n_overlap` EXPLORED (overlap-region) rewards with (b) the Manski +
/// nearest-neighbour smoothness floor over the `n_total - n_overlap` UNEXPLORED
/// (singleton / no-overlap) mass. Returns the support-weighted integer mean,
/// rounded DOWN. TOTAL (no divide-by-zero -- `n_total == 0` fails closed to `Y_LO`;
/// no recursion in the sweep) and SOUND (`L` never exceeds the true mean).
///
/// * `overlap_sum`/`overlap_sum_sq`/`n_overlap` -- the sufficient statistics of the
///   explored (`m > 1`, soft-greedy) rewards.
/// * `n_total` -- the total labeled decisions (explored + singleton/no-overlap).
/// * `grid` -- the per-grid-cell explored-reward table (the nearest-neighbour
///   smoothness anchors): `grid[c] = Some(r)` if grid cell `c` has an explored
///   reward `r`, else `None`. The smoothness floor for an unexplored cell is
///   `(nearest explored reward) - LIPSCHITZ_L * dist`, floored at `Y_LO` (the
///   Manski fallback when no anchor is within the grid).
/// * `delta_num`/`delta_den` -- the rational HCPI confidence for the explored part.
///
/// SOUNDNESS: the overlap part uses the empirical-Bernstein LOWER bound (rounds
/// down); the no-overlap part uses the Manski floor RAISED only by a smoothness
/// term that is itself a lower bound under the pre-registered `L`; the two are
/// combined by support-weighting and the whole is rounded DOWN. So `V_lower` can
/// never exceed the true overlap-region-plus-floor mean.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn value_lower_bound(
    overlap_sum: i64,
    overlap_sum_sq: i128,
    n_overlap: u32,
    n_total: u32,
    grid: &[Option<i64>; GRID_CELLS],
    delta_num: u32,
    delta_den: u32,
) -> i64 {
    // No labeled support at all -> the sound Manski floor.
    if n_total == 0 {
        return Y_LO;
    }
    // (a) The IDENTIFIED part: the empirical-Bernstein lower bound over the explored
    //     overlap rewards (range == the full reward band width). Rounds DOWN.
    let range = Y_HI.saturating_sub(Y_LO);
    let overlap_lb = eb_lower_bound(
        overlap_sum,
        overlap_sum_sq,
        n_overlap,
        range,
        delta_num,
        delta_den,
        Y_LO,
    );
    // (b) The NO-OVERLAP mass: n_total - n_overlap decisions epsilon could not
    //     explore. Their value is bounded below by the Manski + nearest-neighbour
    //     smoothness floor -- the AVERAGE over the grid of each cell's smoothness
    //     floor (a fixed GRID_CELLS sweep, no recursion). This is a SOUND lower
    //     bound on the unexplored mean (every unexplored decision lands in some
    //     grid cell whose floor we take).
    let n_no_overlap = n_total.saturating_sub(n_overlap);
    let no_overlap_floor = smoothness_floor_mean(grid);
    // Support-weight the two parts into one integer lower bound, rounded DOWN.
    // weighted = (overlap_lb * n_overlap + no_overlap_floor * n_no_overlap) / n_total.
    let num = (overlap_lb as i128)
        .saturating_mul(n_overlap as i128)
        .saturating_add((no_overlap_floor as i128).saturating_mul(n_no_overlap as i128));
    let weighted = floor_div_i128(num, n_total as i128);
    let v = clamp_i128_to_i64(weighted);
    // Final clamp into the reward band (tautological output bound). Y_LO < Y_HI is
    // a compile-time const fact, so `clamp` cannot panic.
    v.clamp(Y_LO, Y_HI)
}

/// The Manski + Lipschitz-SMOOTHNESS floor averaged over the kancell grid: for
/// EVERY grid cell, the floor is its own explored reward if it has one, else
/// `(nearest explored reward) - LIPSCHITZ_L * dist`, floored at `Y_LO`. Returns the
/// integer average over [`GRID_CELLS`] cells, rounded DOWN. A CLOSED-FORM nearest-
/// neighbour sweep: two fixed `GRID_CELLS`-bounded loops (the outer cell, the inner
/// nearest-anchor search), NO recursion, NO divide-by-zero (`GRID_CELLS >= 1`).
/// SOUND: each cell's floor is a lower bound on that cell's true mean under the
/// pre-registered Lipschitz `L`, and `Y_LO` is the always-sound Manski fallback
/// when a cell has no explored anchor anywhere in the grid.
#[must_use]
pub fn smoothness_floor_mean(grid: &[Option<i64>; GRID_CELLS]) -> i64 {
    let mut total: i128 = 0;
    let mut c = 0usize;
    while c < GRID_CELLS {
        let floor_c = match grid[c] {
            // An explored cell: its own (already lower-bounded) reward IS the floor.
            Some(r) => r,
            // An unexplored cell: nearest-anchor smoothness floor, Manski fallback.
            None => {
                let mut best: Option<i64> = None;
                let mut a = 0usize;
                while a < GRID_CELLS {
                    if let Some(r) = grid[a] {
                        let dist = a.abs_diff(c) as i64;
                        // The smoothness lower bound for cell c from anchor a: the
                        // anchor reward minus L per unit grid distance (rounds DOWN).
                        let cand = r.saturating_sub(LIPSCHITZ_L.saturating_mul(dist));
                        best = Some(match best {
                            Some(b) if b >= cand => b, // keep the TIGHTEST (largest) sound floor
                            _ => cand,
                        });
                    }
                    a += 1;
                }
                // No anchor anywhere -> the Manski floor Y_LO (always sound). A
                // smoothness candidate can dip below Y_LO at large distance; floor it.
                best.unwrap_or(Y_LO).max(Y_LO)
            }
        };
        total = total.saturating_add(floor_c as i128);
        c += 1;
    }
    // The grid average, rounded DOWN. GRID_CELLS >= 1, so this never divides by zero.
    clamp_i128_to_i64(floor_div_i128(total, GRID_CELLS as i128))
}

/// The integer `V_upper(heuristic)` (proposal §2.4): the always-live heuristic
/// floor's value, formed PESSIMISTICALLY FOR ACTIVATION -- the heuristic's
/// identified mean over its resolved labels PLUS the optimistic Manski CEILING
/// `Y_HI` over its no-overlap mass, so the gate compares the cell's WORST case
/// against the heuristic's BEST case. The empirical mean rounds toward `+inf`
/// (ceil) so `V_upper` is an UPPER bound. TOTAL (`n == 0` -> `Y_HI`, the most
/// pessimistic-for-activation value; no divide-by-zero).
#[must_use]
pub fn value_upper_heuristic(heur_sum: i64, n_resolved: u32, n_total: u32) -> i64 {
    if n_total == 0 {
        return Y_HI; // no data -> the heuristic could be arbitrarily good (block activation)
    }
    // The identified heuristic mean over its resolved labels, rounded UP (ceil).
    let resolved_mean = if n_resolved == 0 {
        Y_HI
    } else {
        clamp_i128_to_i64(ceil_div_i128(heur_sum as i128, n_resolved as i128))
    };
    // The no-overlap mass is filled with the optimistic ceiling Y_HI (Manski upper).
    let n_no = n_total.saturating_sub(n_resolved);
    let num = (resolved_mean as i128)
        .saturating_mul(n_resolved as i128)
        .saturating_add((Y_HI as i128).saturating_mul(n_no as i128));
    let upper = ceil_div_i128(num, n_total as i128); // round UP -> an upper bound
    let v = clamp_i128_to_i64(upper);
    // Clamp into the reward band (Y_LO < Y_HI is a compile-time const, no panic).
    v.clamp(Y_LO, Y_HI)
}

/// The conjunctive ONE-SHOT activation gate verdict (proposal §2.4). A CLOSED set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateVerdict {
    /// `[A]` cleared: `vlo_kan - vhi_heur >= MARGIN` over a sufficiently-supported,
    /// overlap-restored held-out split. (Safety `[B]` -- the envelope-no-widening
    /// proof -- is discharged separately, in `proofs.rs`/the boot self-test.) On
    /// synthetic traces this is NOT reached (the cell stays DORMANT, proposal §6/§7).
    Cleared,
    /// The margin was NOT met on the (synthetic) traces -- the cell stays DORMANT.
    /// THE DESIGNED, CORRECT OUTCOME this milestone (the M21 `(heuristic floor,
    /// gate-not-met)` idiom -- an honest gate that REFUSES is a success).
    NotMet,
    /// Too few RESOLVED non-censored pairs / near-zero overlap mass: the gate is not
    /// EVALUABLE (distinct from a genuine refusal). The eligibility pre-gate failed.
    NotEvaluable,
}

/// Evaluate the conjunctive ONE-SHOT activation gate (proposal §2.4) over the
/// computed estimators. The ELIGIBILITY PRE-GATE runs first: too few resolved pairs
/// OR near-zero overlap mass -> [`GateVerdict::NotEvaluable`]. Otherwise the utility
/// test `[A]`: `vlo_kan - vhi_heur >= margin` -> [`GateVerdict::Cleared`], else
/// [`GateVerdict::NotMet`]. The SAFETY test `[B]` (envelope-no-widening) is
/// UNCONDITIONAL + proven separately, so a `Cleared` here is necessary-but-not-
/// sufficient: the kernel ANDs it with the re-asserted envelope proof. TOTAL,
/// saturating, no panic.
#[must_use]
pub fn gate_clears(
    vlo_kan: i64,
    vhi_heur: i64,
    margin: i64,
    n_resolved: u32,
    overlap_mass: u64,
) -> GateVerdict {
    // ELIGIBILITY PRE-GATE: distinguish not-evaluable from a genuine refusal.
    if n_resolved < MIN_RESOLVED_SUPPORT || overlap_mass < MIN_OVERLAP_MASS {
        return GateVerdict::NotEvaluable;
    }
    // [A] UTILITY: the cell's WORST-case value must beat the heuristic's BEST-case
    // value by at least the pre-registered margin (gating on the lower bound makes
    // activation SOUND -- if the cell's worst case still wins, activation cannot
    // regress even under worst unobserved outcomes).
    let diff = (vlo_kan as i128).saturating_sub(vhi_heur as i128);
    if diff >= margin as i128 {
        GateVerdict::Cleared
    } else {
        GateVerdict::NotMet
    }
}

// --- integer helpers (pure, total, no panic, no float) -----------------------

/// Floor division for `i128` (rounds toward -inf, unlike Rust's `/` which
/// truncates toward 0). `den` MUST be non-zero (every caller guards it). Total.
#[inline]
fn floor_div_i128(num: i128, den: i128) -> i128 {
    if den == 0 {
        return 0; // guarded by callers; total fallback (never reached on the live path)
    }
    let q = num / den;
    let r = num % den;
    if (r != 0) && ((r < 0) != (den < 0)) {
        q - 1
    } else {
        q
    }
}

/// Ceiling division for `i128` (rounds toward +inf). `den` MUST be non-zero. Total.
#[inline]
fn ceil_div_i128(num: i128, den: i128) -> i128 {
    if den == 0 {
        return 0;
    }
    let q = num / den;
    let r = num % den;
    if (r != 0) && ((r < 0) == (den < 0)) {
        q + 1
    } else {
        q
    }
}

/// Integer CEILING square root of a non-negative `i128`: the smallest `s >= 0`
/// with `s*s >= x`. A bounded bit-by-bit (no float, no recursion) computation;
/// returns `0` for `x <= 0`. Used to OVER-approximate the Bernstein variance
/// penalty (rounding the penalty UP keeps the lower bound sound). Total.
#[inline]
fn isqrt_ceil_i128(x: i128) -> i64 {
    if x <= 0 {
        return 0;
    }
    // Newton-free bit method: find the highest power-of-two bit, then refine.
    let mut bit: i128 = 1;
    // Highest bit <= x (bounded: i128 has 128 bits, so this loop is <= 64 iters).
    while bit.saturating_mul(bit) <= x && bit < (1i128 << 62) {
        bit <<= 1;
    }
    let mut res: i128 = 0;
    let mut b = bit;
    while b > 0 {
        let cand = res + b;
        if cand.saturating_mul(cand) <= x {
            res = cand;
        }
        b >>= 1;
    }
    // res is the FLOOR sqrt; bump to the CEILING if res*res < x.
    if res.saturating_mul(res) < x {
        res += 1;
    }
    clamp_i128_to_i64(res)
}

/// Saturating `i64` subtraction lifted through `i64::saturating_sub` (named for
/// readability at the call sites). Total.
#[inline]
fn saturating_sub_i64(a: i64, b: i64) -> i64 {
    a.saturating_sub(b)
}

/// Clamp an `i128` into `i64` range (the final narrowing before returning a band-
/// bounded reward). Total -- never panics.
#[inline]
fn clamp_i128_to_i64(x: i128) -> i64 {
    if x > i64::MAX as i128 {
        i64::MAX
    } else if x < i64::MIN as i128 {
        i64::MIN
    } else {
        x as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- survival_label: exhaustive, mutually exclusive, monotone resolution ----

    #[test]
    fn label_negative_on_in_window_retouch() {
        // demote at 100, window 50; a re-touch at 130 (dist 30 <= 50) -> Negative.
        assert_eq!(
            survival_label(100, 200, Some(130), 50),
            SurvivalLabel::Negative
        );
        // boundary: dist == w exactly is still in-window (<=).
        assert_eq!(
            survival_label(100, 200, Some(150), 50),
            SurvivalLabel::Negative
        );
    }

    #[test]
    fn label_positive_on_elapsed_window_no_touch() {
        // demote at 100, window 50, now 200 (elapsed 100 >= 50), no touch -> Positive.
        assert_eq!(survival_label(100, 200, None, 50), SurvivalLabel::Positive);
        // a touch AFTER the window (dist 60 > 50) does not make it false-forget.
        assert_eq!(
            survival_label(100, 200, Some(160), 50),
            SurvivalLabel::Positive
        );
    }

    #[test]
    fn label_censored_on_open_window() {
        // demote at 100, window 50, now 120 (elapsed 20 < 50), no touch -> Censored.
        assert_eq!(survival_label(100, 120, None, 50), SurvivalLabel::Censored);
    }

    #[test]
    fn label_monotone_resolution() {
        // A Censored label resolves only as now advances; once resolved it stays.
        // open window:
        assert_eq!(survival_label(100, 110, None, 50), SurvivalLabel::Censored);
        // window closes -> Positive (and stays Positive for all larger now):
        assert_eq!(survival_label(100, 150, None, 50), SurvivalLabel::Positive);
        assert_eq!(survival_label(100, 999, None, 50), SurvivalLabel::Positive);
        // an in-window touch makes it Negative regardless of how far now advanced:
        assert_eq!(survival_label(100, 110, Some(120), 50), SurvivalLabel::Negative);
        assert_eq!(survival_label(100, 999, Some(120), 50), SurvivalLabel::Negative);
    }

    #[test]
    fn label_total_on_extremes_and_stale_touch() {
        // saturating: a pre-decision touch (t < decision) is not a re-touch.
        assert_eq!(survival_label(100, 200, Some(50), 50), SurvivalLabel::Positive);
        // u64 extremes never panic.
        let _ = survival_label(u64::MAX, 0, Some(0), u64::MAX);
        let _ = survival_label(0, u64::MAX, Some(u64::MAX), 0);
        // w == 0: any touch at the decision tick is in-window (dist 0 <= 0).
        assert_eq!(survival_label(100, 100, Some(100), 0), SurvivalLabel::Negative);
        assert_eq!(survival_label(100, 100, None, 0), SurvivalLabel::Positive);
    }

    #[test]
    fn resolved_and_outcome_mapping() {
        assert!(SurvivalLabel::Negative.is_resolved());
        assert!(SurvivalLabel::Positive.is_resolved());
        assert!(!SurvivalLabel::Censored.is_resolved());
        assert_eq!(
            SurvivalLabel::Negative.to_outcome(7),
            OutcomeLabel::ReRecalled(7)
        );
        assert_eq!(
            SurvivalLabel::Positive.to_outcome(9),
            OutcomeLabel::Evicted(9)
        );
        assert_eq!(SurvivalLabel::Censored.to_outcome(0), OutcomeLabel::Unset);
    }

    // ---- eb_lower_bound: sound, rounds down, total ------------------------------

    #[test]
    fn eb_no_support_is_floor() {
        assert_eq!(eb_lower_bound(0, 0, 0, 1000, 1, 20, Y_LO), Y_LO);
    }

    #[test]
    fn eb_lower_bound_is_below_mean() {
        // 5 samples all == 1000: mean 1000, the bound must be <= mean (penalties >= 0).
        let n = 5u32;
        let sum = 5_000i64;
        let sum_sq = 5i128 * 1000 * 1000;
        let lb = eb_lower_bound(sum, sum_sq, n, 2000, 1, 20, Y_LO);
        assert!(lb <= 1000, "bound {lb} exceeded the mean 1000 (unsound)");
        assert!(lb >= Y_LO, "bound {lb} below the Manski floor");
    }

    #[test]
    fn eb_zero_variance_penalty_smaller_than_high_variance() {
        // Same mean, but a high-variance sample set yields a LOWER (looser) bound.
        let n = 4u32;
        // low variance: all 500.
        let lo_var = eb_lower_bound(2000, 4 * 500 * 500, n, 2000, 1, 20, Y_LO);
        // high variance: {0,0,1000,1000} -> mean 500, larger variance.
        let hi_var = eb_lower_bound(2000, (1000i128 * 1000) * 2, n, 2000, 1, 20, Y_LO);
        assert!(hi_var <= lo_var, "higher variance should not give a higher bound");
    }

    #[test]
    fn eb_total_on_extremes() {
        let _ = eb_lower_bound(i64::MAX, i128::MAX, u32::MAX, i64::MAX, 0, 0, Y_LO);
        let _ = eb_lower_bound(i64::MIN, 0, 1, i64::MAX, 1, 1, Y_LO);
    }

    // ---- smoothness_floor_mean + value_lower_bound: sound, rounds down ----------

    #[test]
    fn smoothness_floor_uses_nearest_anchor() {
        // One anchor at cell 4 with reward 1000; cell 0 is 4 away -> 1000 - 64*4 = 744.
        let mut grid: [Option<i64>; GRID_CELLS] = [None; GRID_CELLS];
        grid[4] = Some(1000);
        // cell 0 floor: 1000 - 64*4 = 744; cell 8 floor: 1000 - 64*4 = 744; cell 4: 1000.
        let mean = smoothness_floor_mean(&grid);
        // Average is below 1000 (distant cells are penalized) and above Y_LO.
        assert!(mean < 1000 && mean > Y_LO);
    }

    #[test]
    fn smoothness_floor_no_anchor_is_manski() {
        let grid: [Option<i64>; GRID_CELLS] = [None; GRID_CELLS];
        assert_eq!(smoothness_floor_mean(&grid), Y_LO);
    }

    #[test]
    fn value_lower_bound_total_and_sound() {
        // No support -> floor.
        let empty: [Option<i64>; GRID_CELLS] = [None; GRID_CELLS];
        assert_eq!(value_lower_bound(0, 0, 0, 0, &empty, 1, 20), Y_LO);
        // Some overlap support: the bound stays in-band and <= the overlap mean.
        let mut grid: [Option<i64>; GRID_CELLS] = [None; GRID_CELLS];
        grid[2] = Some(800);
        let v = value_lower_bound(8000, 8000i128 * 1000, 10, 12, &grid, 1, 20);
        assert!((Y_LO..=Y_HI).contains(&v));
    }

    #[test]
    fn value_upper_heuristic_is_pessimistic_for_activation() {
        // No data -> Y_HI (block activation).
        assert_eq!(value_upper_heuristic(0, 0, 0), Y_HI);
        // Some resolved data; the upper stays in-band and >= the resolved mean.
        let u = value_upper_heuristic(3000, 6, 10);
        assert!((Y_LO..=Y_HI).contains(&u));
    }

    // ---- gate_clears: eligibility, margin, the synthetic gate-not-met outcome ---

    #[test]
    fn gate_not_evaluable_on_thin_support() {
        assert_eq!(
            gate_clears(1000, 0, ACTIVATION_MARGIN, 0, 100),
            GateVerdict::NotEvaluable
        );
        assert_eq!(
            gate_clears(1000, 0, ACTIVATION_MARGIN, 5, 0),
            GateVerdict::NotEvaluable
        );
    }

    #[test]
    fn gate_not_met_when_margin_unmet() {
        // The cell's worst case (vlo) does not beat the heuristic's best case (vhi).
        assert_eq!(
            gate_clears(-5000, 1000, ACTIVATION_MARGIN, 5, 100),
            GateVerdict::NotMet
        );
        // Exactly margin-short:
        assert_eq!(
            gate_clears(1000, 1000, ACTIVATION_MARGIN, 5, 100),
            GateVerdict::NotMet
        );
    }

    #[test]
    fn gate_clears_only_when_margin_strictly_met() {
        // A (counterfactual) cleared case: vlo - vhi == margin exactly clears.
        assert_eq!(
            gate_clears(1250, 1000, ACTIVATION_MARGIN, 5, 100),
            GateVerdict::Cleared
        );
        assert_eq!(
            gate_clears(2000, 1000, ACTIVATION_MARGIN, 5, 100),
            GateVerdict::Cleared
        );
    }

    #[test]
    fn isqrt_ceil_is_a_ceiling() {
        assert_eq!(isqrt_ceil_i128(0), 0);
        assert_eq!(isqrt_ceil_i128(1), 1);
        assert_eq!(isqrt_ceil_i128(2), 2); // ceil(sqrt 2) = 2
        assert_eq!(isqrt_ceil_i128(4), 2);
        assert_eq!(isqrt_ceil_i128(5), 3); // ceil(sqrt 5) = 3
        assert_eq!(isqrt_ceil_i128(10000), 100);
        // ceiling property on a range.
        for x in 0..200i128 {
            let s = isqrt_ceil_i128(x) as i128;
            assert!(s * s >= x, "isqrt_ceil({x})={s} not a ceiling");
            if s > 0 {
                assert!((s - 1) * (s - 1) < x, "isqrt_ceil({x})={s} not minimal");
            }
        }
    }

    #[test]
    fn floor_and_ceil_div_signs() {
        assert_eq!(floor_div_i128(7, 2), 3);
        assert_eq!(floor_div_i128(-7, 2), -4);
        assert_eq!(ceil_div_i128(7, 2), 4);
        assert_eq!(ceil_div_i128(-7, 2), -3);
        assert_eq!(floor_div_i128(7, 0), 0); // guarded fallback
    }
}
