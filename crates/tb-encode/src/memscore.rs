//! The M13 memory-recall RANKING MATH -- the PURE fixed-point integer kernel of
//! the "memory-central" pillar, lifted out of `tb-hal::mem` exactly as the M16
//! `route::` helpers were lifted out of `tb-hal::infer`.
//!
//! These five functions are the deterministic, FPU-free, zero-dep arithmetic
//! that decides HOW MUCH a memory record is worth at recall time -- the value
//! computation one millimetre in front of the kernel's tier logic, with no
//! `unsafe`, no floats, and no kernel state:
//!
//!   * [`log2_fixed`] / [`ln_fixed`] -- fixed-point `log2`/`ln` scaled by
//!     `SCALE`, the integer logarithms every other term is built from.
//!   * [`bla_raw`] -- the ACT-R Base-Level Activation `BLA(d=0.5)` (Petrov
//!     optimized-learning) that DRIVES recall ranking and the M17 FORGET sweep:
//!     it grows with access frequency and decays with age.
//!   * [`minmax`] -- the min-max normalizer that folds each score component into
//!     the fixed-point window `[0, SCALE]` so no single term can run away.
//!   * [`skill_transform`] -- the M18 frozen held-out evaluator's kernel-private
//!     scoring transform (the same no-float discipline as recall).
//!
//! Hoisting them HERE makes them host-verifiable with NO model drift: `tb-hal`
//! CALLS these exact functions, while the Tier-0 Miri lane EXECUTES them over
//! concrete monotonicity/correctness vectors and the `prove-encode` Kani lane
//! proves panic/overflow-freedom + result bounds over UNTRUSTED memory metadata
//! -- exactly the `vmx` / `paging` / `ipc_frame` / `route` precedent. `#![no_std]`
//! and `#![forbid(unsafe_code)]` (inherited from the crate root): pure integer
//! arithmetic, zero alloc, zero deps.
//!
//! ## Reachable-input envelope (a SOUNDNESS note, read before extending a proof)
//!
//! The fixed-point scheme multiplies an intermediate by `SCALE` (1000), so the
//! arithmetic is panic-free only over the values the kernel can actually feed:
//! `log2_fixed`/`ln_fixed` take `x` derived from u32 access counts (`<= 2^33`)
//! or bounded logical-clock deltas, and `bla_raw` takes a u32 `count` plus a
//! bounded `age`. At astronomically large `x` (beyond ~`2^53`) the `(x - pow) *
//! SCALE` term overflows `i64`, and `bla_raw`'s `age + 1` overflows at
//! `u64::MAX` -- neither is reachable from the kernel's bounded inputs. The Kani
//! harnesses therefore `assume` that documented envelope and prove
//! panic-freedom + bounds WITHIN it (an unconstrained full-range harness would
//! be UNSOUND and turn the lane RED -- the #49 over-quantification trap).

/// Fixed-point scale: every normalized score component lives in `[0, SCALE]`.
const SCALE: i64 = 1000;
/// `ln(2)` scaled by [`SCALE`] (converts an integer `log2` into `ln`).
const LN2_FIXED: i64 = 693;
/// The held-out evaluator's kernel-private transform seed (golden-ratio const,
/// the `REFLECT_SEED` discipline) -- non-zero so an all-zero body still mixes.
const SKILL_XFORM_SEED: u64 = 0x9E37_79B9_7F4A_7C15;
/// FNV-style odd multiplier mixing the held-out input into the transform.
const SKILL_XFORM_MUL: u64 = 0x0000_0100_0000_01B3;

/// `log2(x) * SCALE` as an integer (`0` for `x <= 1`): floor part from the
/// leading-bit position, fractional part by a linear interpolation in `[0, 1)`.
#[must_use]
pub fn log2_fixed(x: u64) -> i64 {
    if x <= 1 {
        return 0;
    }
    let ip = 63 - x.leading_zeros() as i64; // floor(log2 x)
    let pow = 1u64 << (ip as u32);
    let frac = ((x - pow) as i64 * SCALE) / pow as i64; // linear in [0, SCALE)
    ip * SCALE + frac
}

/// `ln(x) * SCALE` as an integer, via `log2(x) * ln(2)`.
#[must_use]
pub fn ln_fixed(x: u64) -> i64 {
    log2_fixed(x) * LN2_FIXED / SCALE
}

/// The ACT-R base-level activation BLA(d=0.5) in fixed point (the O(1) fallback,
/// Petrov optimized-learning): grows with access frequency, decays with age.
/// Higher = more active (more recent and/or more often accessed).
#[must_use]
pub fn bla_raw(count: u32, age: u64) -> i64 {
    let freq = ln_fixed(2 * (count as u64 + 1)); // frequency term
    let recency = ln_fixed(age + 1) / 2; // 0.5 * ln(age) decay
    freq - recency
}

/// M18: the deterministic fixed-point transform modeling a candidate skill's
/// behavior on one held-out input (the held-out evaluator's KERNEL-PRIVATE
/// scoring rule -- the same no-float discipline as recall). It is SENSITIVE to
/// `body`, so only the secret target body reproduces every held-out expected
/// value: a skill that games a visible slice still misses the held-out set. The
/// candidate never runs in the evaluator's sandbox, so it can neither introspect
/// nor rewrite this function (the "validate, not just hide" sharpening).
#[must_use]
pub fn skill_transform(body: u64, input: u64) -> u64 {
    let mut h = body ^ SKILL_XFORM_SEED;
    h = h.rotate_left((input & 63) as u32);
    h ^= input.wrapping_mul(SKILL_XFORM_MUL);
    h = h.rotate_left(17) ^ (body >> 7);
    h
}

/// Min-max normalize `vals[i]` over the candidate set into `[0, SCALE]`; a
/// degenerate (all-equal) component contributes `0` so it cannot reorder.
#[must_use]
pub fn minmax(vals: &[i64], i: usize) -> i64 {
    let mut lo = vals[0];
    let mut hi = vals[0];
    for &v in vals.iter() {
        if v < lo {
            lo = v;
        }
        if v > hi {
            hi = v;
        }
    }
    if hi == lo {
        0
    } else {
        (vals[i] - lo) * SCALE / (hi - lo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The largest input the recall callers can actually produce stays well
    // inside the panic-free envelope documented at the top of this module: a
    // u32 access count yields `2*(count+1) <= 2^33`, and a logical-clock delta
    // is far smaller. `2^48` is the smoke ceiling used throughout (it is below
    // the ~`2^53` point where the fixed-point `* SCALE` term could overflow).
    const SMOKE_CEIL: u64 = 1u64 << 48;

    // -----------------------------------------------------------------------
    // log2_fixed: known points + monotonicity (the Miri lane EXECUTES these,
    // proving panic-freedom + zero UB on the concrete vectors).
    // -----------------------------------------------------------------------

    #[test]
    fn log2_fixed_known_points() {
        assert_eq!(log2_fixed(0), 0); // x <= 1 floor to 0
        assert_eq!(log2_fixed(1), 0);
        assert_eq!(log2_fixed(2), 1000); // log2(2) = 1.0 * SCALE
        assert_eq!(log2_fixed(4), 2000);
        assert_eq!(log2_fixed(8), 3000);
        assert_eq!(log2_fixed(16), 4000);
        assert_eq!(log2_fixed(3), 1500); // ip=1, frac=(3-2)*1000/2
    }

    #[test]
    fn log2_fixed_monotone_non_decreasing() {
        let xs: [u64; 16] = [
            0, 1, 2, 3, 4, 7, 8, 15, 16, 1000, 65_536, 1 << 24, 1 << 32, 1 << 40, 1 << 47, 1 << 48,
        ];
        let mut prev = i64::MIN;
        for &x in &xs {
            let v = log2_fixed(x);
            assert!(v >= prev, "log2_fixed({x})={v} dropped below {prev}");
            prev = v;
        }
    }

    // -----------------------------------------------------------------------
    // ln_fixed: known points + monotonicity.
    // -----------------------------------------------------------------------

    #[test]
    fn ln_fixed_known_points() {
        assert_eq!(ln_fixed(1), 0);
        // log2_fixed(2)=1000; 1000 * 693 / 1000 = 693 == ln(2)*SCALE.
        assert_eq!(ln_fixed(2), 693);
    }

    #[test]
    fn ln_fixed_monotone_non_decreasing() {
        let xs: [u64; 12] = [1, 2, 3, 4, 8, 16, 256, 65_536, 1 << 24, 1 << 32, 1 << 40, 1 << 48];
        let mut prev = i64::MIN;
        for &x in &xs {
            let v = ln_fixed(x);
            assert!(v >= prev, "ln_fixed({x})={v} dropped below {prev}");
            prev = v;
        }
    }

    // -----------------------------------------------------------------------
    // bla_raw: the recall-ranking driver. Monotone NON-INCREASING in age (older
    // -> not higher) and NON-DECREASING in count (more accesses -> not lower)
    // across sampled points -- the M13/M17 ranking + FORGET-decay invariants.
    // (Strict monotonicity can break at fixed-point rounding boundaries, so we
    // sample concretely instead of a symbolic monotonicity proof -- the
    // documented #49 over-quantification trap.)
    // -----------------------------------------------------------------------

    #[test]
    fn bla_raw_non_increasing_in_age() {
        let ages: [u64; 12] =
            [0, 1, 2, 3, 5, 8, 16, 32, 100, 1_000, 100_000, 1 << 40];
        for &count in &[0u32, 1, 7, 50, 1_000, u32::MAX] {
            let mut prev = i64::MAX;
            for &age in &ages {
                let b = bla_raw(count, age);
                assert!(b <= prev, "bla_raw({count},{age})={b} rose above {prev}");
                prev = b;
            }
        }
    }

    #[test]
    fn bla_raw_non_decreasing_in_count() {
        let counts: [u32; 11] =
            [0, 1, 2, 3, 5, 10, 100, 1_000, 100_000, 10_000_000, u32::MAX];
        for &age in &[0u64, 1, 10, 100, 10_000, 1 << 32] {
            let mut prev = i64::MIN;
            for &count in &counts {
                let b = bla_raw(count, age);
                assert!(b >= prev, "bla_raw({count},{age})={b} fell below {prev}");
                prev = b;
            }
        }
    }

    // -----------------------------------------------------------------------
    // minmax: the recall normalizer. It folds a component into `[0, SCALE]` --
    // it is NOT a select (its output is a fraction, not a slice element), so the
    // correctness property is: the max element maps to SCALE, the min to 0, a
    // proportional middle in between, an all-equal slice to 0, and EVERY output
    // lies in `[0, SCALE]`.
    // -----------------------------------------------------------------------

    #[test]
    fn minmax_degenerate_slice_is_zero() {
        assert_eq!(minmax(&[5, 5, 5], 0), 0);
        assert_eq!(minmax(&[5, 5, 5], 2), 0);
        assert_eq!(minmax(&[-3, -3], 1), 0);
        assert_eq!(minmax(&[0], 0), 0); // single element: hi == lo
    }

    #[test]
    fn minmax_picks_the_right_normalized_value() {
        // min element -> 0, max element -> SCALE.
        assert_eq!(minmax(&[0, 100], 0), 0);
        assert_eq!(minmax(&[0, 100], 1), 1000);
        // proportional middle.
        assert_eq!(minmax(&[0, 50, 100], 1), 500);
        assert_eq!(minmax(&[10, 20, 30, 40], 0), 0);
        assert_eq!(minmax(&[10, 20, 30, 40], 3), 1000);
        assert_eq!(minmax(&[10, 20, 30, 40], 1), 333); // (20-10)*1000/30
        // negatives normalize identically (the bla component is signed).
        assert_eq!(minmax(&[-100, 0, 100], 0), 0);
        assert_eq!(minmax(&[-100, 0, 100], 1), 500);
        assert_eq!(minmax(&[-100, 0, 100], 2), 1000);
    }

    #[test]
    fn minmax_output_always_in_scale_window() {
        let v = [-7i64, 3, 42, 1000, -1000, 0];
        for i in 0..v.len() {
            let r = minmax(&v, i);
            assert!((0..=SCALE).contains(&r), "minmax(_,{i})={r} escaped [0,SCALE]");
        }
    }

    // -----------------------------------------------------------------------
    // skill_transform: the M18 frozen-evaluator transform must be DETERMINISTIC
    // (same inputs -> same output) and BODY-SENSITIVE (distinct bodies disagree
    // on some held-out input -- the property that makes Goodharting a visible
    // slice still miss the held-out set).
    // -----------------------------------------------------------------------

    #[test]
    fn skill_transform_is_deterministic() {
        for &(b, i) in &[
            (0u64, 0u64),
            (1, 2),
            (0xDEAD_BEEF, 0xF00D),
            (u64::MAX, u64::MAX),
            (0x9E37_79B9_7F4A_7C15, 7),
        ] {
            assert_eq!(skill_transform(b, i), skill_transform(b, i));
        }
    }

    #[test]
    fn skill_transform_is_body_sensitive() {
        // Two distinct bodies must disagree on at least one of the held-out
        // probe inputs (the `seed_heldout` input schedule).
        let differ = |b1: u64, b2: u64| {
            (0u64..8).any(|k| {
                let inp = k.wrapping_mul(0x0010_0001).wrapping_add(0x51);
                skill_transform(b1, inp) != skill_transform(b2, inp)
            })
        };
        assert!(differ(0x1111_1111_1111_1111, 0x2222_2222_2222_2222));
        assert!(differ(0, 1));
        assert!(differ(u64::MAX, 0));
    }

    // -----------------------------------------------------------------------
    // Panic-freedom smoke on the EXTREME ends of the reachable envelope. NOTE:
    // `u64::MAX` is deliberately excluded for the log/bla path -- `age + 1`
    // overflows at `u64::MAX` and the `* SCALE` term overflows beyond ~2^53, and
    // BOTH are unreachable from u32 counts / bounded clock deltas (see the
    // module-level soundness note). `skill_transform` is all-wrapping, so it is
    // panic-free over the FULL u64 range.
    // -----------------------------------------------------------------------

    #[test]
    fn pure_fns_panic_free_on_safe_extremes() {
        let _ = log2_fixed(0);
        let _ = log2_fixed(1);
        let _ = log2_fixed(SMOKE_CEIL);
        let _ = ln_fixed(1);
        let _ = ln_fixed(SMOKE_CEIL);
        let _ = bla_raw(0, 0);
        let _ = bla_raw(u32::MAX, 0); // full u32 count is safe
        let _ = bla_raw(u32::MAX, 1 << 40);
        let _ = bla_raw(0, 1 << 40);
        let _ = skill_transform(0, 0);
        let _ = skill_transform(u64::MAX, u64::MAX); // wrapping: full-range safe
        // bounded-magnitude slice keeps `(vals[i]-lo)*SCALE` inside i64.
        let _ = minmax(&[-1_000_000, 0, 1_000_000], 1);
    }
}
