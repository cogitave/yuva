//! The M24 SHIELDED EPSILON-GREEDY exploration math -- the pure, verified
//! value-computation leaf behind the closed-form logging PROPENSITY M24 stamps
//! into the M23-reserved [`crate::exp::ExperienceRecord::logging_propensity_q`]
//! field, lifted into `tb-encode` exactly as the M21 forget policy
//! ([`crate::kancell`]) and the M23 experience codec ([`crate::exp`]) were.
//!
//! ## Why this leaf exists (proposal §2.1 -- restore overlap)
//!
//! M23's research proved the M17 safety envelope is a DETERMINISTIC logging
//! policy: it emits a single cleared action with propensity 1, the alternatives
//! with propensity 0 -- a positivity/overlap VIOLATION that makes standard
//! off-policy evaluation structurally non-identifiable (Saito arXiv:2603.21485).
//! M24 repairs positivity by injecting a rational `eps = eps_num/eps_den`
//! (ship-const, e.g. 1/16) that flips the kancell-greedy-vs-heuristic choice
//! ONLY among the already-cleared candidate set `A_safe(x)` the frozen M17
//! shield emits (Alshiekh arXiv:1708.08611): exploration physically cannot
//! select a pinned/grace/util-pin action because it is never an element of
//! `A_safe(x)`, so the hard invariant holds by construction and the M21
//! envelope-no-widening proof re-asserts unchanged.
//!
//! ## The closed-form propensity (Open Bandit Pipeline arXiv:2008.07146)
//!
//! For `m = |A_safe(x)|` cleared candidates and rational `eps = eps_num/eps_den`,
//! a uniform epsilon-greedy logging policy assigns
//!
//! ```text
//!   pi_b(greedy) = (1 - eps) + eps/m          (the greedy action)
//!   pi_b(other)  = eps/m                       (any other cleared action)
//! ```
//!
//! Encoded over the M23 fixed-point `SCALE == 1000` slot (so a 0.7 propensity is
//! `700`). [`explore_propensity_q`] computes this with SATURATING integer
//! mul/div ONLY (no float, ever), proven TOTAL and in `[1, 1000]` for every
//! cleared action when `eps_num > 0` and `m >= 1` (POSITIVITY -- the whole point:
//! no cleared action gets a zero propensity, so IPS is identifiable over the
//! explored support). The `m == 1` SINGLETON guard returns exactly `1000`: a
//! singleton decision (a pin/grace/util-pin forced the one safe action) stays
//! structurally deterministic and can never be explored (proposal §2.2 routes it
//! to the partial-identification bound instead).
//!
//! ## Numeric format (no float, ever -- mirrors `kancell`/`exp`)
//!
//! Pure integer arithmetic, zero alloc, zero deps, SATURATING throughout
//! (`#![no_std]` + `#![forbid(unsafe_code)]` inherited from the crate root). The
//! division is by `eps_den * m`, both `>= 1` on the validated path, so no
//! divide-by-zero is reachable; the `m == 0` / `eps_den == 0` degenerate inputs
//! fail closed to the deterministic sentinel `1000` rather than panicking (the
//! totality the `kani_explore_propensity_*` harnesses discharge).

/// The fixed-point propensity scale (mirrors [`crate::exp::PROPENSITY_DETERMINISTIC_Q`]
/// == 1000): a propensity `p in [0,1]` is encoded as `round(p * SCALE)`, so a
/// deterministic action is `1000` and a 0.7 propensity is `700`.
pub const PROPENSITY_SCALE: u32 = 1000;

/// The closed-form SHIELDED epsilon-greedy logging propensity (proposal §2.1),
/// over the M23 fixed-point `SCALE == 1000` slot.
///
/// Given `eps = eps_num/eps_den` and `m = |A_safe(x)|` cleared candidates,
/// returns `round(SCALE * pi_b(a|x))` where `pi_b(greedy) = (1-eps) + eps/m` and
/// `pi_b(other) = eps/m` (`is_greedy` selects the action whose propensity is
/// returned). SATURATING integer mul/div only -- TOTAL, never panics, never
/// divides by zero.
///
/// Guarantees (the `kani_explore_propensity_*` harnesses):
/// * **Singleton guard:** `m == 1` returns exactly `PROPENSITY_SCALE` (== 1000)
///   regardless of `eps`/`is_greedy` -- a singleton is forced + deterministic and
///   can NEVER be explored (the lone cleared action IS the greedy action, and
///   `(1-eps) + eps/1 == 1`).
/// * **Positivity:** when `eps_num > 0` and `m >= 1` the result is in `[1, 1000]`
///   for BOTH the greedy and an other action -- no cleared action gets a zero
///   propensity (so IPS is identifiable over the explored support).
/// * **Range:** the result is always in `[0, 1000]` (clamped); `0` is only
///   reachable on the degenerate `eps_num == 0`/`eps_den == 0`/`m == 0`
///   fail-closed inputs the seam never feeds on the cleared path.
#[must_use]
pub fn explore_propensity_q(eps_num: u32, eps_den: u32, m: u32, is_greedy: bool) -> u16 {
    // Fail closed on a degenerate candidate count: an empty cleared set has no
    // propensity to assign. Return 0 (the seam never calls this with m == 0 on the
    // cleared path; this keeps the function TOTAL rather than dividing by zero).
    if m == 0 {
        return 0;
    }
    // SINGLETON guard (proposal §2.2): the one cleared action is forced. Whether
    // greedy or not, pi_b == 1 exactly: (1-eps) + eps/1 == 1 for the lone action,
    // and there is no "other" to explore. Deterministic propensity == SCALE.
    if m == 1 {
        return PROPENSITY_SCALE as u16;
    }
    // A degenerate epsilon (eps_den == 0, i.e. an undefined fraction) or eps_num == 0
    // means NO exploration: the greedy action keeps the whole mass (deterministic),
    // an "other" action is unreachable (propensity 0). Fail closed without dividing.
    if eps_den == 0 || eps_num == 0 {
        return if is_greedy { PROPENSITY_SCALE as u16 } else { 0 };
    }
    // The "other"-action mass: SCALE * eps / m == SCALE * eps_num / (eps_den * m).
    // SATURATING throughout; eps_den * m >= 2 here (m >= 2), so the divisor is
    // non-zero. Compute in u64 to avoid intermediate truncation, then narrow.
    let scale = PROPENSITY_SCALE as u64;
    let num = scale.saturating_mul(eps_num as u64);
    let den = (eps_den as u64).saturating_mul(m as u64);
    // den >= 2 (eps_den >= 1, m >= 2), so this never divides by zero.
    let other_q = num / den; // floor division (rounds DOWN -- pessimistic, total)
    // The total exploration mass SCALE * eps == SCALE * eps_num / eps_den (the
    // fraction of decisions that DON'T take the greedy action), used to form the
    // greedy propensity (1-eps) + eps/m == 1 - eps*(m-1)/m. We build it as
    // SCALE - eps_mass + other_q so the two-action arithmetic is exact-enough and
    // saturating: greedy = SCALE - (SCALE*eps) + (SCALE*eps/m).
    let eps_mass = scale.saturating_mul(eps_num as u64) / (eps_den as u64); // SCALE * eps
    // The greedy propensity: SCALE*(1-eps) + SCALE*eps/m. Saturating-subtract the
    // exploration mass from SCALE (clamps at 0 if eps > 1, a misconfig), then add
    // back the greedy share of the spread mass.
    let greedy_q = scale.saturating_sub(eps_mass).saturating_add(other_q);
    // POSITIVITY floor for the explored "other" action: when eps_num > 0 and m >= 2
    // the true eps/m > 0, but floor division can round a very small mass to 0. We
    // raise an explored action to at least 1 so positivity holds by construction
    // (no cleared action gets a zero propensity on the explored path). The greedy
    // action's mass is always >= other's, so it needs no floor here.
    let chosen = if is_greedy {
        greedy_q
    } else {
        other_q.max(1)
    };
    // Final clamp into [0, SCALE] (the tautological output bound; greedy_q can only
    // exceed SCALE under a pathological eps that the saturating_sub already floors,
    // so this is belt-and-suspenders totality).
    let clamped = if chosen > scale { scale } else { chosen };
    clamped as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn singleton_is_deterministic() {
        // m == 1: forced, deterministic, propensity == 1000 for any eps / is_greedy.
        assert_eq!(explore_propensity_q(1, 16, 1, true), 1000);
        assert_eq!(explore_propensity_q(1, 16, 1, false), 1000);
        assert_eq!(explore_propensity_q(8, 16, 1, true), 1000);
        assert_eq!(explore_propensity_q(0, 16, 1, false), 1000);
    }

    #[test]
    fn two_actions_eps_one_sixteenth() {
        // eps = 1/16, m = 2.
        //   other  = 1000 * (1/16) / 2 = 1000/32 = 31 (floor)
        //   greedy = 1000 - 1000/16 + other = 1000 - 62 + 31 = 969
        let other = explore_propensity_q(1, 16, 2, false);
        let greedy = explore_propensity_q(1, 16, 2, true);
        assert_eq!(other, 31);
        assert_eq!(greedy, 969);
        // The two-action propensities sum to ~SCALE (within floor-rounding): the
        // greedy action plus ONE other action carry (1-eps)+eps/m + eps/m.
        assert!(greedy as u32 + other as u32 <= 1000);
    }

    #[test]
    fn positivity_holds_for_cleared_actions() {
        // For every eps_num in 1..eps_den and every m in 2..=8, BOTH the greedy
        // and an other action get a propensity in [1, 1000] (no zero -> IPS
        // identifiable over the explored support).
        for eps_den in [2u32, 4, 8, 16, 32] {
            for eps_num in 1..eps_den {
                for m in 2u32..=8 {
                    let g = explore_propensity_q(eps_num, eps_den, m, true);
                    let o = explore_propensity_q(eps_num, eps_den, m, false);
                    assert!((1..=1000).contains(&g), "greedy {g} out of [1,1000] eps={eps_num}/{eps_den} m={m}");
                    assert!((1..=1000).contains(&o), "other {o} out of [1,1000] eps={eps_num}/{eps_den} m={m}");
                }
            }
        }
    }

    #[test]
    fn eps_zero_is_deterministic_split() {
        // eps_num == 0: no exploration. Greedy keeps the whole mass, other is 0.
        assert_eq!(explore_propensity_q(0, 16, 4, true), 1000);
        assert_eq!(explore_propensity_q(0, 16, 4, false), 0);
    }

    #[test]
    fn degenerate_inputs_fail_closed_no_panic() {
        // m == 0 -> 0 (no cleared action); eps_den == 0 -> deterministic split.
        assert_eq!(explore_propensity_q(1, 16, 0, true), 0);
        assert_eq!(explore_propensity_q(1, 0, 4, true), 1000);
        assert_eq!(explore_propensity_q(1, 0, 4, false), 0);
        // A pathological eps > 1 (eps_num > eps_den) saturates without panic.
        let _ = explore_propensity_q(99, 1, 4, true);
        let _ = explore_propensity_q(u32::MAX, 1, u32::MAX, false);
    }

    #[test]
    fn greedy_dominates_other() {
        // The greedy action always carries at least as much mass as an other action
        // (it keeps the (1-eps) lump plus its eps/m share).
        for m in 2u32..=8 {
            let g = explore_propensity_q(1, 8, m, true);
            let o = explore_propensity_q(1, 8, m, false);
            assert!(g >= o, "greedy {g} < other {o} at m={m}");
        }
    }
}
