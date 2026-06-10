//! The M21 forget/demote POLICY-CELL math -- a verified, fixed-point ADDITIVE
//! policy leaf (a piecewise-linear integer GAM) lifted out of `tb-hal::mem`
//! exactly as the M13 recall ranking was lifted into [`crate::memscore`]. It is
//! the value computation one millimetre in front of the M17 forget/demote
//! comparator: given a record's pre-quantized continuous features it produces a
//! bounded keepability score the EXISTING `THETA_DEMOTE` comparator thresholds.
//!
//! This is NOT a "KAN"/neural net (the reshape verdict, proposal §1): nothing is
//! learnable in-kernel. The knots are frozen OFFLINE in float and shipped as a
//! `const` i16 table; a depth-1 sum of frozen 1-D splines is operationally a
//! per-segment lookup table + linear interpolation. What is built here is the
//! VERIFIED-POLICY-INSIDE-A-PROVEN-ENVELOPE seam: the cell may only RANK inside
//! the M17 heuristic safety envelope (`tb-hal` owns the pin/grace/aging decision;
//! this leaf is strictly downstream of every hard invariant), it ships DORMANT
//! (the heuristic floor decides until an offline trace bake-off activates it),
//! and -- like [`crate::memscore`] -- it is host-verifiable with NO model drift:
//! `tb-hal` CALLS these exact functions, the Kani lane PROVES totality/overflow-
//! freedom/monotonicity/determinism over the integer artifact, and the host
//! tests EXECUTE them on concrete vectors. `#![no_std]` + `#![forbid(unsafe_code)]`
//! (inherited from the crate root): pure integer arithmetic, zero alloc, zero
//! deps, NO FLOAT anywhere on the kernel path.
//!
//! ## Numeric format (no float, ever -- proposal §2.1)
//!
//! * **Knots:** `i16` Q4.11 fixed-point y-values (1 sign, 4 int, 11 frac bits),
//!   each bounded in magnitude by [`KAN_KNOT_MAX`] so the closed-form overflow
//!   bound `KAN_FEATURES * KAN_KNOT_MAX` stays deep inside `i32` BEFORE the clamp.
//! * **Grid:** 9 knots / 8 intervals on a fixed UNIFORM POWER-OF-2 grid, so the
//!   segment index is a `>>` (never a divide) -- the LUT-KAN sweet spot.
//! * **Eval:** clamp `x_q` to `[grid_lo, grid_hi]`, pick the segment by `>>`, two
//!   knot lookups, one SATURATING linear interpolation. TOTAL by construction:
//!   the clamp proves the segment index in `0..=KAN_KNOTS-2` for ALL `i32`, so the
//!   `[seg]`/`[seg+1]` indexing is in-bounds and the saturating mul/add cannot
//!   panic.
//! * **Accumulator:** widened `i32 -> i64`, SATURATING ops throughout, then a
//!   final SATURATING CLAMP into the M17 score band ([`DEMOTE_BAND`]) so the
//!   output bound is a tautology -- the same `[-34_000, 34_000]` window
//!   `bla_raw` already lives in (`crate::memscore`), where `SCALE == 1000`.
//!
//! ## Structural monotonicity (MonoKAN-style, solver-free -- proposal §2.5)
//!
//! For a feature with a known sign (recency/age non-increasing, frequency non-
//! decreasing) the monotonicity of the piecewise-LINEAR interpolant reduces to a
//! finite SIGN CHECK on consecutive knot deltas -- [`kan_table_is_monotone`], a
//! const-evaluable `i16` comparison conjunction Kani discharges with zero solver
//! difficulty (cubic/B-spline would need derivative-region side conditions an
//! auto-checker cannot discharge). This gives "staler is never scored more
//! keepable" by CONSTRUCTION, validated once on the host AND cheaply re-asserted
//! in-kernel at load -- we validate the INTEGER artifact, never a float model.

/// Knots per feature spline: 9 knots == 8 uniform intervals (the LUT-KAN L=8
/// sweet spot, proposal §2.3).
pub const KAN_KNOTS: usize = 9;

/// Univariate splines summed by the additive GAM (the genuinely-continuous,
/// possibly-saturating signals -- recency/age, frequency, size, +1 reserved).
/// Tier/importance/pins stay LINEAR/gating terms in the M17 envelope, NOT here
/// (A-MAC's lesson: the categorical signal belongs in the envelope).
pub const KAN_FEATURES: usize = 4;

/// Per-knot magnitude bound (Q4.11): every shipped knot must satisfy
/// `|knot| <= KAN_KNOT_MAX`. This is the CLOSED-FORM headroom constant
/// ([`kan_table_overflow_safe`] checks it): the worst-case accumulator before the
/// clamp is `KAN_FEATURES * KAN_KNOT_MAX` plus the bounded bias/flag terms, which
/// must stay deep inside `i32` so no in-`i16`-range table -- even a poisoned one --
/// can overflow. `4 * 8000 = 32_000` leaves > 2^31 of `i32` headroom and matches
/// the `[-34_000, 34_000]` [`DEMOTE_BAND`] window the M17 comparator thresholds.
pub const KAN_KNOT_MAX: i16 = 8_000;

/// The M17 forget/demote score band (`SCALE == 1000`, where `bla_raw` lives in
/// [`crate::memscore`]): `kan_score`'s final SATURATING CLAMP lands here, so the
/// output bound is a tautology and the cell can never reorder a record out of the
/// band the comparator thresholds. Identical to the `bla_raw` `+/-34_000` bound.
pub const DEMOTE_BAND: (i64, i64) = (-34_000, 34_000);

/// A frozen univariate piecewise-LINEAR spline table: `KAN_FEATURES` rows of
/// `KAN_KNOTS` i16 Q4.11 y-values over a uniform power-of-2 grid.
pub type KnotTable = [[i16; KAN_KNOTS]; KAN_FEATURES];

/// Evaluate ONE univariate piecewise-LINEAR spline at `x_q` (pre-quantized to the
/// feature's fixed Q-format). The grid is `KAN_KNOTS` knots spaced
/// `1 << grid_step_log2` apart starting at `grid_lo`; the segment index is the
/// quantized offset shifted right by `grid_step_log2` (NEVER a divide). `x_q` is
/// CLAMPED to `[grid_lo, grid_hi]` first, so the segment index is proven in
/// `0..=KAN_KNOTS-2` for ALL `i32`: the `[seg]`/`[seg+1]` lookups are in-bounds
/// and the SATURATING linear interpolation cannot panic.
///
/// Returns the interpolated y in the same Q4.11 units as the knots, so the result
/// magnitude is bounded by `max|knot|` (it lies BETWEEN two knots).
#[must_use]
pub fn kan_spline_eval(knots: &[i16; KAN_KNOTS], x_q: i32, grid_lo: i32, grid_step_log2: u32) -> i32 {
    let step = 1i32 << grid_step_log2; // uniform interval width (power of 2)
                                       // grid_hi == grid_lo + 8*step is the last knot's x; clamp x_q to [lo, hi].
    let span = step.saturating_mul((KAN_KNOTS - 1) as i32);
    let grid_hi = grid_lo.saturating_add(span);
    let xc = if x_q < grid_lo {
        grid_lo
    } else if x_q > grid_hi {
        grid_hi
    } else {
        x_q
    };
    // Offset into the grid, then the segment index by >> (no divide). The clamp
    // guarantees 0 <= off <= span, so 0 <= seg <= KAN_KNOTS-1; we additionally
    // pin seg to KAN_KNOTS-2 so seg+1 is always a valid knot index (the top knot
    // x maps to the last segment, interpolating to exactly knots[KAN_KNOTS-1]).
    let off = xc - grid_lo; // in [0, span], fits i32
    let mut seg = (off >> grid_step_log2) as usize;
    if seg >= KAN_KNOTS - 1 {
        seg = KAN_KNOTS - 2;
    }
    let y0 = knots[seg] as i32;
    let y1 = knots[seg + 1] as i32;
    // Fractional position WITHIN the segment, in [0, step).
    let seg_lo = grid_lo.saturating_add((seg as i32).saturating_mul(step));
    let frac = xc - seg_lo; // in [0, step]
                            // Linear interp: y0 + (y1 - y0) * frac / step. SATURATING throughout; the
                            // >> grid_step_log2 divides by the power-of-2 step (no real divide). dy and
                            // frac are bounded (|dy| <= 2*KAN_KNOT_MAX << i32, frac <= step), so the
                            // product never escapes i32 in practice, but saturate to be total anyway.
    let dy = y1.saturating_sub(y0);
    let slope_num = dy.saturating_mul(frac);
    let interp = slope_num >> grid_step_log2; // arithmetic shift: floor toward -inf
    y0.saturating_add(interp)
}

/// The additive GAM (proposal §2.4): `bias + Sum_j kan_spline_eval(feature_j)
/// + flag_terms`, accumulated in a WIDENED SATURATING `i64`, then SATURATING-
/// CLAMPED into the M17 [`DEMOTE_BAND`] so the output bound is a tautology. This
/// is the bounded keepability score the M17 comparator consumes in place of the
/// inline `w_a*BLA + w_r*relevance + w_i*importance` default.
///
/// Every feature spline shares the SAME canonical grid (`grid_lo == 0`,
/// `grid_step_log2` chosen so the 8 intervals cover the feature's quantized
/// range); callers pre-quantize each `feats[j]` into that grid. `flag_terms` and
/// `bias` are the linear/categorical contributions computed by the envelope.
#[must_use]
pub fn kan_score(table: &KnotTable, feats: &[i32; KAN_FEATURES], flag_terms: i32, bias: i32) -> i64 {
    // The canonical per-feature grid: 9 knots over [0, 8*step) with step == 2^7
    // (so a feature quantized into 0..=1024 lands across all 8 intervals). The
    // grid is a CONST of the format, not a per-call parameter, so the in-kernel
    // round-trip and the proofs share one decidable geometry.
    let mut acc: i64 = bias as i64;
    let mut j = 0usize;
    while j < KAN_FEATURES {
        let y = kan_spline_eval(&table[j], feats[j], GRID_LO, GRID_STEP_LOG2);
        acc = acc.saturating_add(y as i64);
        j += 1;
    }
    acc = acc.saturating_add(flag_terms as i64);
    // Final SATURATING CLAMP into the M17 band (the tautological output bound).
    let (lo, hi) = DEMOTE_BAND;
    if acc < lo {
        lo
    } else if acc > hi {
        hi
    } else {
        acc
    }
}

/// The canonical grid origin shared by every feature spline in [`kan_score`].
pub const GRID_LO: i32 = 0;
/// The canonical grid step exponent: intervals are `1 << GRID_STEP_LOG2` wide, so
/// the 8 intervals span `[0, 8 << GRID_STEP_LOG2)` of quantized feature units.
pub const GRID_STEP_LOG2: u32 = 7;

/// Structural MonoKAN validator (proposal §2.5): `signs[j] == +1` requires the
/// row's consecutive knot deltas be NON-NEGATIVE (non-decreasing spline),
/// `signs[j] == -1` NON-POSITIVE (non-increasing), `0` unconstrained. A finite
/// `i16` comparison conjunction -- NO solver. Called by the fail-closed loader
/// AND re-checked in-kernel at load: validate the INTEGER artifact, not a float
/// model. A `true` result proves "staler is never scored more keepable" for every
/// sign-`-1` feature by construction (the basis is piecewise-linear, so segment
/// monotonicity follows from knot-delta sign).
#[must_use]
pub fn kan_table_is_monotone(table: &KnotTable, signs: &[i8; KAN_FEATURES]) -> bool {
    let mut j = 0usize;
    while j < KAN_FEATURES {
        let s = signs[j];
        let row = &table[j];
        let mut k = 0usize;
        while k < KAN_KNOTS - 1 {
            let d = (row[k + 1] as i32) - (row[k] as i32);
            if s > 0 && d < 0 {
                return false; // non-decreasing violated
            }
            if s < 0 && d > 0 {
                return false; // non-increasing violated
            }
            k += 1;
        }
        j += 1;
    }
    true
}

/// Structural HEADROOM validator (proposal §2.4): every knot of every row is
/// within `[-KAN_KNOT_MAX, KAN_KNOT_MAX]`, so the worst-case accumulator
/// `KAN_FEATURES * KAN_KNOT_MAX` (plus the bounded bias/flag terms the comparator
/// supplies) provably stays inside the `i32`/`i64` accumulator BEFORE the clamp.
/// Const-evaluable; a poisoned-but-in-`i16` table (e.g. all knots `i16::MAX`)
/// still cannot overflow `kan_score` -- it returns `false` here and the loader
/// fails closed to the heuristic. Soundness: `overflow_safe(table) == true`
/// implies `kan_score` cannot overflow (proven by `kani_kan_table_validators_total`).
#[must_use]
pub fn kan_table_overflow_safe(table: &KnotTable) -> bool {
    let mut j = 0usize;
    while j < KAN_FEATURES {
        let row = &table[j];
        let mut k = 0usize;
        while k < KAN_KNOTS {
            let v = row[k];
            if !(-KAN_KNOT_MAX..=KAN_KNOT_MAX).contains(&v) {
                return false;
            }
            k += 1;
        }
        j += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // A canonical monotone-decreasing recency row (staler -> less keepable) and a
    // monotone-increasing frequency row, both inside KAN_KNOT_MAX -- the shape the
    // shipped frozen table uses.
    const DECREASING: [i16; KAN_KNOTS] = [4000, 3500, 3000, 2400, 1800, 1200, 600, 100, -400];
    const INCREASING: [i16; KAN_KNOTS] = [-400, 100, 600, 1200, 1800, 2400, 3000, 3500, 4000];
    const FLAT: [i16; KAN_KNOTS] = [500; KAN_KNOTS];

    fn sample_table() -> KnotTable {
        [DECREASING, INCREASING, FLAT, DECREASING]
    }

    // -----------------------------------------------------------------------
    // kan_spline_eval: KNOT round-trip (eval AT a grid point recovers that knot),
    // clamp behaviour at/past the grid ends, and the linear midpoint.
    // -----------------------------------------------------------------------

    #[test]
    fn spline_eval_recovers_knots_at_grid_points() {
        let step = 1i32 << GRID_STEP_LOG2;
        for (k, &knot) in INCREASING.iter().enumerate() {
            let x = GRID_LO + (k as i32) * step;
            let got = kan_spline_eval(&INCREASING, x, GRID_LO, GRID_STEP_LOG2);
            assert_eq!(got, knot as i32, "knot {k} not recovered at x={x}");
        }
    }

    #[test]
    fn spline_eval_clamps_below_and_above_grid() {
        let step = 1i32 << GRID_STEP_LOG2;
        let hi = GRID_LO + (KAN_KNOTS as i32 - 1) * step;
        // Far below the grid -> first knot; far above -> last knot.
        assert_eq!(
            kan_spline_eval(&INCREASING, i32::MIN, GRID_LO, GRID_STEP_LOG2),
            INCREASING[0] as i32
        );
        assert_eq!(
            kan_spline_eval(&INCREASING, i32::MAX, GRID_LO, GRID_STEP_LOG2),
            INCREASING[KAN_KNOTS - 1] as i32
        );
        // Exactly at the top grid x -> the last knot (not an out-of-bounds index).
        assert_eq!(
            kan_spline_eval(&INCREASING, hi, GRID_LO, GRID_STEP_LOG2),
            INCREASING[KAN_KNOTS - 1] as i32
        );
    }

    #[test]
    fn spline_eval_linear_midpoint() {
        // Midpoint between knot 0 and knot 1 of INCREASING: (-400 + 100)/2 = -150.
        let step = 1i32 << GRID_STEP_LOG2;
        let mid = GRID_LO + step / 2;
        let got = kan_spline_eval(&INCREASING, mid, GRID_LO, GRID_STEP_LOG2);
        assert_eq!(got, -150);
    }

    // -----------------------------------------------------------------------
    // kan_spline_eval is TOTAL: never panics for any x_q / any in-i16 row, and
    // the output stays within the row's [min knot, max knot] envelope.
    // -----------------------------------------------------------------------

    #[test]
    fn spline_eval_total_and_bounded_on_extremes() {
        let row: [i16; KAN_KNOTS] = [i16::MIN, i16::MAX, 0, -1, 1, i16::MIN, i16::MAX, 0, 7];
        let lo = *row.iter().min().unwrap() as i32;
        let hi = *row.iter().max().unwrap() as i32;
        for &x in &[i32::MIN, -1, 0, 1, 63, 64, 1024, i32::MAX] {
            let y = kan_spline_eval(&row, x, GRID_LO, GRID_STEP_LOG2);
            // The interpolant lies between adjacent knots, hence within [min, max].
            assert!(y >= lo && y <= hi, "eval({x})={y} escaped [{lo},{hi}]");
        }
    }

    // -----------------------------------------------------------------------
    // kan_score: determinism, clamp into DEMOTE_BAND, and additive structure.
    // -----------------------------------------------------------------------

    #[test]
    fn score_is_deterministic() {
        let t = sample_table();
        let feats = [0i32, 256, 512, 900];
        assert_eq!(
            kan_score(&t, &feats, 123, -50),
            kan_score(&t, &feats, 123, -50)
        );
    }

    #[test]
    fn score_clamps_into_demote_band() {
        let (lo, hi) = DEMOTE_BAND;
        let t = sample_table();
        let feats = [0i32, 1024, 1024, 0];
        // A huge positive bias/flag pair must clamp to hi, a huge negative to lo.
        assert_eq!(kan_score(&t, &feats, i32::MAX, i32::MAX), hi);
        assert_eq!(kan_score(&t, &feats, i32::MIN, i32::MIN), lo);
        // A modest score stays strictly inside the band.
        let mid = kan_score(&t, &feats, 0, 0);
        assert!(mid >= lo && mid <= hi);
    }

    #[test]
    fn score_is_additive_over_features() {
        // With an all-FLAT table (every spline == 500), the score is
        // bias + 4*500 + flag_terms, clamped. Pick small values to stay in band.
        let t: KnotTable = [FLAT; KAN_FEATURES];
        let feats = [10i32, 200, 700, 1000];
        let got = kan_score(&t, &feats, 7, -3);
        assert_eq!(got, (-3) + 4 * 500 + 7);
    }

    // -----------------------------------------------------------------------
    // kan_table_is_monotone: the MonoKAN structural validator.
    // -----------------------------------------------------------------------

    #[test]
    fn monotone_accepts_correctly_signed_rows() {
        let t = sample_table(); // [decreasing, increasing, flat, decreasing]
        let signs: [i8; KAN_FEATURES] = [-1, 1, 0, -1];
        assert!(kan_table_is_monotone(&t, &signs));
        // A flat row satisfies BOTH a +1 and a -1 sign (all deltas zero).
        let flat_t: KnotTable = [FLAT; KAN_FEATURES];
        assert!(kan_table_is_monotone(&flat_t, &[1, -1, 1, -1]));
        // Sign 0 accepts any row.
        assert!(kan_table_is_monotone(&t, &[0, 0, 0, 0]));
    }

    #[test]
    fn monotone_rejects_misordered_row() {
        // A decreasing-required row that rises somewhere fails the -1 check.
        let mut bad = DECREASING;
        bad[4] = bad[3] + 1; // inject one rising delta
        let t: KnotTable = [bad, INCREASING, FLAT, DECREASING];
        assert!(!kan_table_is_monotone(&t, &[-1, 1, 0, -1]));
        // The same row as +1-required passes (it is mostly decreasing, so a
        // +1 check rejects it too -- assert the increasing row fails as -1).
        let t2: KnotTable = [DECREASING, INCREASING, FLAT, INCREASING];
        assert!(!kan_table_is_monotone(&t2, &[-1, 1, 0, -1])); // row3 increasing, -1 -> fail
    }

    // -----------------------------------------------------------------------
    // kan_table_overflow_safe: the headroom validator.
    // -----------------------------------------------------------------------

    #[test]
    fn overflow_safe_accepts_in_bound_table() {
        assert!(kan_table_overflow_safe(&sample_table()));
        // Exactly at the +/-bound is accepted (inclusive).
        let edge: KnotTable = [[KAN_KNOT_MAX; KAN_KNOTS], [-KAN_KNOT_MAX; KAN_KNOTS], FLAT, FLAT];
        assert!(kan_table_overflow_safe(&edge));
    }

    #[test]
    fn overflow_safe_rejects_poisoned_table() {
        // One knot past the bound fails closed (even though it is a valid i16).
        let mut poisoned = sample_table();
        poisoned[2][4] = KAN_KNOT_MAX + 1;
        assert!(!kan_table_overflow_safe(&poisoned));
        // The all-i16::MAX poison table (the worst-case attacker) is rejected.
        let worst: KnotTable = [[i16::MAX; KAN_KNOTS]; KAN_FEATURES];
        assert!(!kan_table_overflow_safe(&worst));
    }

    // -----------------------------------------------------------------------
    // Cross-cutting: an overflow-safe table can NEVER drive kan_score out of the
    // i64 accumulator, and the result is always exactly in DEMOTE_BAND.
    // -----------------------------------------------------------------------

    #[test]
    fn overflow_safe_table_keeps_score_in_band() {
        let (lo, hi) = DEMOTE_BAND;
        let safe: KnotTable = [[KAN_KNOT_MAX; KAN_KNOTS]; KAN_FEATURES];
        assert!(kan_table_overflow_safe(&safe));
        for &(b, f) in &[(0i32, 0i32), (5000, -5000), (-9000, 9000)] {
            for &x in &[0i32, 512, 1024] {
                let s = kan_score(&safe, &[x; KAN_FEATURES], f, b);
                assert!(s >= lo && s <= hi, "score {s} escaped the band");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Monotone-by-construction END-TO-END: for a sign=-1 (recency) feature, a
    // larger quantized x never scores HIGHER through kan_spline_eval (staler is
    // never more keepable) -- the concrete-vector twin of the Kani proof.
    // -----------------------------------------------------------------------

    #[test]
    fn decreasing_feature_is_non_increasing_in_x() {
        let xs: [i32; 10] = [0, 50, 64, 100, 128, 300, 512, 700, 1024, 2000];
        let mut prev = i32::MAX;
        for &x in &xs {
            let y = kan_spline_eval(&DECREASING, x, GRID_LO, GRID_STEP_LOG2);
            assert!(y <= prev, "eval({x})={y} rose above {prev}");
            prev = y;
        }
    }

    #[test]
    fn panic_free_on_extreme_grid_steps() {
        // Smoke the totality on a large grid_step_log2 + extreme x (no shift/mul
        // overflow path is reachable thanks to the saturating ops + the clamp).
        let _ = kan_spline_eval(&INCREASING, i32::MAX, i32::MIN, 30);
        let _ = kan_spline_eval(&DECREASING, i32::MIN, i32::MAX, 30);
        let _ = kan_score(
            &[[i16::MAX; KAN_KNOTS]; KAN_FEATURES],
            &[i32::MAX; KAN_FEATURES],
            i32::MAX,
            i32::MAX,
        );
    }
}
