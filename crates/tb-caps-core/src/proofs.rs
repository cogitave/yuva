//! Kani proof harnesses for the M11 capability rights-subset / no-confused-deputy
//! invariant. Compiled ONLY under `cfg(kani)` (the module is gated in `lib.rs`),
//! so a normal `cargo build` / `cargo kbuild` never sees them.
//!
//! Three tiers:
//!   * Tier-1 -- the [`Rights`] algebra over `Rights::from_bits(kani::any::<u32>())`,
//!     i.e. ALL 2^32 bit patterns. These are COMPLETE bit-vector proofs with NO
//!     `#[kani::unwind]` bound: derive/narrow only ever shrinks rights.
//!   * Tier-2 -- one harness per capability operation on the REAL [`CapTable`]`<()>`
//!     (small cap N=4), proving each op never widens authority and that a forged
//!     handle resolves to no authority beyond its slot's.
//!   * Tier-3 -- the headline inductive single-step preservation harness over
//!     arbitrary fixed-width seeded state (an INDUCTION STEP -> the no-widen
//!     guarantee holds for op-sequences of UNBOUNDED length, bounded only in
//!     table width N=4), plus a bounded K<=4 concrete-sequence cross-check.
//!
//! NEGATIVE CONTROL (documented, not run here): replacing `Rights::intersect`'s
//! `&` with `|` makes `kani_intersect_subset_both` and
//! `kani_step_preserves_attenuation` FAIL with a concrete counterexample
//! (`-Z concrete-playback`), proving the harnesses actually constrain the
//! property and are not vacuous.

use crate::rights::Rights;
use crate::table::{CapTable, Handle, SysStatus};

/// Table-harness capacity bound. The bounded-model-checker reasons over tables of
/// this width; the residual soundness gap (width N) is closed by the optional
/// Verus model and is documented in the plan.
const N: usize = 4;

// ===========================================================================
// Tier-1: the Rights algebra over the FULL u32 space (no unwind bound).
// ===========================================================================

/// `r.intersect(m)` is a subset of BOTH operands -- the core attenuation law.
#[kani::proof]
fn kani_intersect_subset_both() {
    let r = Rights::from_bits(kani::any());
    let m = Rights::from_bits(kani::any());
    let got = r.intersect(m);
    assert!(got.is_subset_of(r));
    assert!(got.is_subset_of(m));
}

/// Attenuation is monotone: `a <= b  =>  a&m <= b&m`.
#[kani::proof]
fn kani_intersect_monotone() {
    let a = Rights::from_bits(kani::any());
    let b = Rights::from_bits(kani::any());
    let m = Rights::from_bits(kani::any());
    kani::assume(a.is_subset_of(b));
    assert!(a.intersect(m).is_subset_of(b.intersect(m)));
}

/// `is_subset_of` is a partial order: reflexive and transitive.
#[kani::proof]
fn kani_subset_reflexive_transitive() {
    let a = Rights::from_bits(kani::any());
    let b = Rights::from_bits(kani::any());
    let c = Rights::from_bits(kani::any());
    // Reflexive.
    assert!(a.is_subset_of(a));
    // Transitive: a <= b <= c  =>  a <= c.
    kani::assume(a.is_subset_of(b));
    kani::assume(b.is_subset_of(c));
    assert!(a.is_subset_of(c));
}

/// The dispatch gate `r.contains(need)` is EXACTLY `need.is_subset_of(r)`.
#[kani::proof]
fn kani_contains_subset_duality() {
    let r = Rights::from_bits(kani::any());
    let need = Rights::from_bits(kani::any());
    assert_eq!(r.contains(need), need.is_subset_of(r));
}

/// `union` only ever GROWS (build-only; never applied to a live capability).
#[kani::proof]
fn kani_union_only_grows() {
    let r = Rights::from_bits(kani::any());
    let o = Rights::from_bits(kani::any());
    assert!(r.is_subset_of(r.union(o)));
    assert!(o.is_subset_of(r.union(o)));
}

// ===========================================================================
// Tier-2: per-operation proofs on the REAL CapTable<()> (cap N=4).
// ===========================================================================

/// NARROW yields a child whose rights are a subset of the parent's.
#[kani::proof]
fn kani_narrow_shrinks() {
    let mut t: CapTable<()> = CapTable::with_capacity(N);
    let r = Rights::from_bits(kani::any());
    let root = t.alloc(r, ()).unwrap();
    let mask = Rights::from_bits(kani::any());
    if let Some(child) = t.narrow(root, mask) {
        let cr = t.rights_of(child).unwrap();
        assert!(cr.is_subset_of(r));
        assert!(cr.is_subset_of(t.rights_of(root).unwrap()));
    }
}

/// DUP yields a sibling with the SAME rights (hence trivially a subset).
#[kani::proof]
fn kani_dup_not_widen() {
    let mut t: CapTable<()> = CapTable::with_capacity(N);
    let r = Rights::from_bits(kani::any());
    let root = t.alloc(r, ()).unwrap();
    if let Some(sib) = t.dup(root) {
        let sr = t.rights_of(sib).unwrap();
        assert_eq!(sr.bits(), r.bits());
        assert!(sr.is_subset_of(r));
    }
}

/// TRANSFER preserves rights into the destination (subset of parent) AND drains
/// the source (the old handle no longer resolves `Ok`).
#[kani::proof]
fn kani_transfer_preserves_and_drains() {
    let mut src: CapTable<()> = CapTable::with_capacity(N);
    let mut dst: CapTable<()> = CapTable::with_capacity(N);
    let r = Rights::from_bits(kani::any());
    let h = src.alloc(r, ()).unwrap();
    if let Some(moved) = src.transfer_to(h, &mut dst) {
        let mr = dst.rights_of(moved).unwrap();
        assert_eq!(mr.bits(), r.bits());
        assert!(mr.is_subset_of(r));
        // The source slot is drained: no residual authority for the old handle.
        assert!(src.live(h).is_err());
    }
}

/// REVOKE makes the old handle `Stale`, and a reissued slot carries a DIFFERENT
/// generation (so the old handle can never resolve `Ok` again).
#[kani::proof]
fn kani_revoke_makes_stale() {
    let mut t: CapTable<()> = CapTable::with_capacity(N);
    let r = Rights::from_bits(kani::any());
    let h = t.alloc(r, ()).unwrap();
    let g0 = h.generation();
    assert_eq!(t.revoke(h), SysStatus::Ok);
    // The old handle is now Stale (the slot is vacant) -- never `Ok`.
    assert_eq!(t.live(h), Err(SysStatus::Stale));
    // A reissued capability on the same slot gets a fresh generation.
    let h2 = t.alloc(r, ()).unwrap();
    if h2.slot() == h.slot() {
        assert!(h2.generation() != g0);
        assert!(t.live(h).is_err());
    }
}

/// The UNFORGEABILITY half of no-confused-deputy: a forged `u64` either fails to
/// resolve, or resolves to a slot whose authority is EXACTLY that slot's rights
/// (never anything derived from the forged bits), and that authority is <= the
/// only rights ever minted.
#[kani::proof]
fn kani_forged_handle_no_amplify() {
    let mut t: CapTable<()> = CapTable::with_capacity(N);
    let r = Rights::from_bits(kani::any());
    let _root = t.alloc(r, ()).unwrap();
    // A forged handle: arbitrary 64 bits an attacker controls.
    let forged = Handle::from_raw(kani::any());
    match t.live(forged) {
        Ok(i) => {
            // Authority comes from the SLOT, not the handle integer.
            let resolved = t.rights_of(forged).unwrap();
            assert_eq!(resolved.bits(), t.rights_at(i).bits());
            assert!(resolved.is_subset_of(r));
        }
        Err(_) => { /* forged handle yields no authority -- the intended case */ }
    }
}

// ===========================================================================
// Tier-3: inductive single-step no-widen + a bounded concrete-sequence check.
// ===========================================================================

/// THE headline proof. Seed N slots in a nondeterministic state that satisfies
/// the table invariant BY CONSTRUCTION (each occupied slot's rights =
/// `root & any`, so a subset of `root`; generation any nonzero), `assume` the
/// invariant, apply ONE nondeterministically-chosen op {dup, narrow, transfer,
/// revoke} to a nondeterministically-chosen handle, then assert EVERY occupied
/// slot's rights is still a subset of `root`. A single-step preservation over
/// arbitrary fixed-width state is an INDUCTION STEP, so the no-widen guarantee
/// holds for op-sequences of unbounded length (bounded only in table width N).
#[kani::proof]
#[kani::unwind(8)]
fn kani_step_preserves_attenuation() {
    let root = Rights::from_bits(kani::any());
    // cap = 2*N so dup/narrow can allocate a fresh child slot.
    let mut t: CapTable<()> = CapTable::with_capacity(2 * N);
    let mut dst: CapTable<()> = CapTable::with_capacity(2 * N);

    // Seed N slots; each occupied slot's rights = root & any  (=> subset root).
    for _ in 0..N {
        let occupied: bool = kani::any();
        let g: u32 = kani::any();
        kani::assume(g >= 1);
        let rights = root.intersect(Rights::from_bits(kani::any()));
        t.seed_slot(g, rights, if occupied { Some(()) } else { None });
    }

    // Precondition (the table-level invariant): every occupied slot subset root.
    // True by construction above; `assume` it to make the induction explicit.
    for s in 0..t.slot_count() {
        if t.is_occupied(s) {
            kani::assume(t.peek_rights(s).is_subset_of(root));
        }
    }

    // A nondeterministic target handle (slot + generation both arbitrary).
    let h = Handle::new(kani::any(), kani::any());

    // Apply exactly ONE nondeterministically-chosen capability op.
    let op: u8 = kani::any();
    match op % 4 {
        0 => {
            let _ = t.dup(h);
        }
        1 => {
            let mask = Rights::from_bits(kani::any());
            let _ = t.narrow(h, mask);
        }
        2 => {
            let _ = t.transfer_to(h, &mut dst);
        }
        _ => {
            let _ = t.revoke(h);
        }
    }

    // Postcondition: no occupied slot of EITHER table exceeds root (no widen).
    for s in 0..t.slot_count() {
        if t.is_occupied(s) {
            assert!(t.peek_rights(s).is_subset_of(root));
        }
    }
    for s in 0..dst.slot_count() {
        if dst.is_occupied(s) {
            assert!(dst.peek_rights(s).is_subset_of(root));
        }
    }
}

/// Independent cross-check: a bounded sequence of K<=4 derive ops (dup / narrow /
/// revoke) over nondeterministic choices, building a real derivation chain, never
/// makes any occupied slot's rights exceed the root authority.
#[kani::proof]
#[kani::unwind(8)]
fn kani_bounded_sequence() {
    let root = Rights::from_bits(kani::any());
    let mut t: CapTable<()> = CapTable::with_capacity(16);
    let h0 = t.alloc(root, ()).unwrap();

    let mut handles: [Option<Handle>; 5] = [Some(h0), None, None, None, None];
    let mut n: usize = 1;

    for _ in 0..4 {
        let pick: usize = kani::any();
        kani::assume(pick < n);
        if let Some(h) = handles[pick] {
            let op: u8 = kani::any();
            let produced = match op % 3 {
                0 => t.dup(h),
                1 => {
                    let mask = Rights::from_bits(kani::any());
                    t.narrow(h, mask)
                }
                _ => {
                    let _ = t.revoke(h);
                    None
                }
            };
            if let Some(p) = produced {
                if n < handles.len() {
                    handles[n] = Some(p);
                    n += 1;
                }
            }
        }
    }

    for s in 0..t.slot_count() {
        if t.is_occupied(s) {
            assert!(t.peek_rights(s).is_subset_of(root));
        }
    }
}
