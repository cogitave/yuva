//! Kani proof harnesses for the pure silicon-adjacent encoders. Compiled ONLY
//! under `cfg(kani)` (the module is gated in `lib.rs`), so a normal `cargo
//! build` / `cargo kbuild` never sees them.
//!
//! Scope (honest):
//!   * The fixed-size, loop-free bit transforms (VMX adjust/clamp, TSS decode,
//!     page-table / EPT entry encoders, the 16-byte IPC frame) are TOTAL proofs
//!     over their full symbolic input space -- no `#[kani::unwind]` needed.
//!   * The ONE loop-bearing harness (`kani_bounded_ring_framing`) is a BOUNDED
//!     proof with a small explicit op count + `#[kani::unwind]`, so an
//!     under-set bound fails closed (unwinding assertion) rather than hanging.
//!
//! Each harness carries a NEGATIVE-CONTROL note: the concrete code break that
//! would turn it FAILED, so the suite is provably non-vacuous.

use crate::ipc_frame::{BoundedRing, FrameError, MessageFrame, FRAME_SIZE};
use crate::paging::{
    entry_addr, ept_leaf_2mib, ept_nonleaf, eptp, level_index, make_entry, ENTRIES,
    ENTRY_ADDR_MASK, EPT_MAPS_PAGE, EPT_MEMTYPE_WB, EPT_RWX, EPT_WALK_LEN_MINUS_1, SHIFT_1G,
    SHIFT_2M, SHIFT_4K, SHIFT_512G,
};
use crate::vmx::{adjust, clamp_fixed, decode_tss_base};

// ===========================================================================
// VMX: the control-MSR ADJUST legality gate (the headline proof).
// ===========================================================================

/// THE proof that prevents silent VM-entry failure: for ALL `desired:u32` and
/// `cap_msr:u64`, `adjust` forces every allowed-0 bit on and clears every bit
/// not permitted by allowed-1. A total bit-vector proof over the whole space.
///
/// NEGATIVE CONTROL: changing `adjust` to `desired & allowed1` (dropping the
/// `| allowed0` force) makes `r & allowed0 == allowed0` FAIL whenever `allowed0`
/// has a bit `desired` lacks.
#[kani::proof]
fn kani_adjust_within_allowed() {
    let desired: u32 = kani::any();
    let cap_msr: u64 = kani::any();
    let allowed0 = cap_msr as u32;
    let allowed1 = (cap_msr >> 32) as u32;
    // Well-formedness precondition: on every REAL VMX capability MSR the
    // allowed-0 (MUST-be-1) set is a subset of the allowed-1 (MAY-be-1) set --
    // Intel SDM Vol.3D App.A guarantees a bit that must be 1 is always permitted
    // to be 1. A symbolic cap_msr with allowed0 ⊄ allowed1 describes
    // self-contradictory silicon that cannot exist, so constraining it away is
    // sound (it is not a reachable hardware state).
    kani::assume(allowed0 & !allowed1 == 0);
    let r = adjust(desired, cap_msr);
    // Every allowed-0 (MUST-be-1) bit is set.
    assert_eq!(r & allowed0, allowed0);
    // No bit outside allowed-1 (MAY-be-1) is set.
    assert_eq!(r & !allowed1, 0);
}

/// `adjust` is idempotent: re-adjusting an already-legal value is a no-op, so
/// the gate is a true projection onto the legal set.
///
/// NEGATIVE CONTROL: an `adjust` built from XOR rather than OR/AND would not be
/// idempotent and this equality would FAIL.
#[kani::proof]
fn kani_adjust_idempotent() {
    let desired: u32 = kani::any();
    let cap_msr: u64 = kani::any();
    let once = adjust(desired, cap_msr);
    assert_eq!(adjust(once, cap_msr), once);
}

/// The CR0/CR4 fixed-bit clamp obeys the same forced/forbidden law: the result
/// never sets a bit outside `fixed1`, and forces on every bit of `fixed0 & fixed1`.
///
/// NEGATIVE CONTROL: replacing `fixed0 | desired` with `fixed0 & desired` drops
/// the forced bits and makes the `r & (f0 & f1) == f0 & f1` assert FAIL.
#[kani::proof]
fn kani_clamp_fixed_within_bounds() {
    let desired: u64 = kani::any();
    let fixed0: u64 = kani::any();
    let fixed1: u64 = kani::any();
    let r = clamp_fixed(desired, fixed0, fixed1);
    // Never sets a bit forbidden by fixed1.
    assert_eq!(r & !fixed1, 0);
    // Forces on every must-be-1 bit that is also permitted.
    assert_eq!(r & (fixed0 & fixed1), fixed0 & fixed1);
}

/// `decode_tss_base` equals an INDEPENDENT byte-wise re-derivation of the
/// scattered 64-bit TSS base, for all descriptor halves, and never panics.
///
/// NEGATIVE CONTROL: dropping the `(hi & 0xFFFF_FFFF) << 32` term makes the
/// high-32-bit base contribution mismatch and this equality FAIL.
#[kani::proof]
fn kani_decode_tss_base_matches() {
    let lo: u64 = kani::any();
    let hi: u64 = kani::any();
    let got = decode_tss_base(lo, hi);
    // Reassemble byte-field by byte-field, a structurally different derivation.
    let b0_15 = (lo >> 16) & 0xFFFF; // base[15:0]  @ desc+2
    let b16_23 = (lo >> 32) & 0xFF; // base[23:16] @ desc+4
    let b24_31 = (lo >> 56) & 0xFF; // base[31:24] @ desc+7
    let b32_63 = hi & 0xFFFF_FFFF; // base[63:32] in the high qword
    let expect = b0_15 | (b16_23 << 16) | (b24_31 << 24) | (b32_63 << 32);
    assert_eq!(got, expect);
}

// ===========================================================================
// Paging / EPT entry encoders.
// ===========================================================================

/// `entry_addr(make_entry(pa, attrs))` recovers `pa & MASK`, and every attribute
/// bit OUTSIDE the address field is preserved bit-for-bit.
///
/// NEGATIVE CONTROL: if `make_entry` masked `attrs` (e.g. `(pa|attrs) & MASK`),
/// the attribute-preservation assert would FAIL.
#[kani::proof]
fn kani_make_entry_roundtrip() {
    let pa: u64 = kani::any();
    let attrs: u64 = kani::any();
    // Contract precondition: `attrs` are permission/flag bits, by construction
    // DISJOINT from the [47:12] output-address field. Every caller passes a flag
    // set (P|RW|PS|memtype|NX ...), never address bits -- `make_entry` composes
    // an address with its flags, it is not a general OR. (A caller that smuggled
    // address bits into `attrs` would be the bug, not `make_entry`.)
    kani::assume(attrs & ENTRY_ADDR_MASK == 0);
    let e = make_entry(pa, attrs);
    assert_eq!(entry_addr(e), pa & ENTRY_ADDR_MASK);
    assert_eq!(e & !ENTRY_ADDR_MASK, attrs & !ENTRY_ADDR_MASK);
}

/// For any VA and any of the four real level shifts, `level_index` is `< 512`,
/// so a walk can never hand `PageTable512::get/set` an out-of-bounds index.
///
/// NEGATIVE CONTROL: masking with `0x3FF` (10 bits) instead of `0x1FF` lets the
/// index reach 1023 and this bound FAILS.
#[kani::proof]
fn kani_level_index_bounds() {
    let va: u64 = kani::any();
    let sel: u8 = kani::any();
    let shift = match sel % 4 {
        0 => SHIFT_4K,
        1 => SHIFT_2M,
        2 => SHIFT_1G,
        _ => SHIFT_512G,
    };
    assert!(level_index(va, shift) < ENTRIES);
}

/// An EPT 2 MiB leaf sets exactly the intended bits: R|W|X, the memory type in
/// bits `[5:3]`, the maps-page bit, and the (aligned) address preserved.
///
/// NEGATIVE CONTROL: forgetting `EPT_MAPS_PAGE` makes `e & EPT_MAPS_PAGE != 0`
/// FAIL (a non-leaf masquerading as a leaf -> EPT misconfiguration VM-exit).
#[kani::proof]
fn kani_ept_leaf_wellformed() {
    let pa: u64 = kani::any();
    kani::assume(pa & 0x1F_FFFF == 0); // 2 MiB aligned
    kani::assume(pa <= ENTRY_ADDR_MASK); // fits the [47:12] address field
    let memtype: u64 = kani::any();
    kani::assume(memtype < 8); // a valid 3-bit EPT memory type
    let e = ept_leaf_2mib(pa, memtype);
    assert_eq!(e & EPT_RWX, EPT_RWX);
    assert_eq!((e >> 3) & 0x7, memtype);
    assert!(e & EPT_MAPS_PAGE != 0);
    assert_eq!(e & ENTRY_ADDR_MASK, pa);
}

/// An EPT non-leaf carries R|W|X + the child address, and the EPTP encodes
/// memory-type WB (`6`) in `[2:0]` and page-walk-length-1 (`3`) in `[5:3]`.
///
/// NEGATIVE CONTROL: encoding the EPTP walk length as `4` (instead of len-1 = 3)
/// makes `(p >> 3) & 0x7 == 3` FAIL -- the classic off-by-one VM-entry failure.
#[kani::proof]
fn kani_ept_nonleaf_and_eptp() {
    let child: u64 = kani::any();
    kani::assume(child & 0xFFF == 0); // 4 KiB-aligned table frame
    let nl = ept_nonleaf(child);
    assert_eq!(nl & EPT_RWX, EPT_RWX);
    assert_eq!(nl & ENTRY_ADDR_MASK, child & ENTRY_ADDR_MASK);

    let pml4: u64 = kani::any();
    kani::assume(pml4 & 0xFFF == 0);
    let p = eptp(pml4);
    assert_eq!(p & 0x7, EPT_MEMTYPE_WB);
    assert_eq!((p >> 3) & 0x7, EPT_WALK_LEN_MINUS_1);
    assert_eq!(p & ENTRY_ADDR_MASK, pml4 & ENTRY_ADDR_MASK);
}

// ===========================================================================
// IPC frame codec + bounded ring.
// ===========================================================================

/// `decode(encode(f)) == f` for any frame -- encode/decode is identity.
///
/// NEGATIVE CONTROL: if `encode` skipped the 4 rights bytes, `decode` could not
/// recover `rights` and this equality would FAIL.
#[kani::proof]
fn kani_ipc_frame_roundtrip() {
    let payload: u64 = kani::any();
    let cap_present: bool = kani::any();
    let rights: u32 = kani::any();
    let f = MessageFrame::new(payload, cap_present, rights);
    assert_eq!(MessageFrame::decode(&f.encode()), Ok(f));
}

/// `decode` is TOTAL: ANY 16 bytes decode to `Ok` or `Err` without panicking;
/// a successful decode round-trips back to the SAME bytes (so every bit is
/// accounted for and reserved discipline held); a short buffer is always
/// `Err(ShortBuffer)`.
///
/// NEGATIVE CONTROL: if `decode` ignored a reserved flag/trailing byte, `encode`
/// (which zeroes them) would not reproduce the input and `f.encode() == bytes`
/// would FAIL -- proving the malformed-rejection check is load-bearing.
#[kani::proof]
fn kani_ipc_frame_decode_total() {
    let bytes: [u8; FRAME_SIZE] = kani::any();
    match MessageFrame::decode(&bytes) {
        Ok(f) => {
            assert_eq!(f.encode(), bytes);
            assert_eq!(bytes[12] & 0xFE, 0); // no reserved flag bit set
            assert_eq!(bytes[13], 0);
            assert_eq!(bytes[14], 0);
            assert_eq!(bytes[15], 0);
        }
        Err(_) => { /* malformed input rejected without panic -- intended */ }
    }
    let short: [u8; FRAME_SIZE - 1] = kani::any();
    assert!(matches!(
        MessageFrame::decode(&short),
        Err(FrameError::ShortBuffer { .. })
    ));
}

/// A bounded push/pop sequence over a capacity-4 ring never exceeds capacity,
/// tracks length exactly, and rejects a push into a full ring (no panic, no
/// growth); a concrete sub-check pins FIFO order.
///
/// NEGATIVE CONTROL: dropping the `if self.len == N { return false; }` guard in
/// `push` lets `len()` exceed `N`, failing the `r.len() <= CAP` assert (and the
/// `ok == (model_len < CAP)` equality).
#[kani::proof]
#[kani::unwind(7)]
fn kani_bounded_ring_framing() {
    const CAP: usize = 4;
    let mut r: BoundedRing<u32, CAP> = BoundedRing::new();
    let mut model_len = 0usize;
    for _ in 0..6 {
        let do_push: bool = kani::any();
        if do_push {
            let v: u32 = kani::any();
            let ok = r.push(v);
            assert_eq!(ok, model_len < CAP);
            if ok {
                model_len += 1;
            }
        } else {
            let got = r.pop();
            assert_eq!(got.is_some(), model_len > 0);
            if got.is_some() {
                model_len -= 1;
            }
        }
        assert!(r.len() <= CAP);
        assert_eq!(r.len(), model_len);
    }

    // Concrete FIFO ordering (cheap; no symbolic-array reasoning).
    let mut q: BoundedRing<u32, CAP> = BoundedRing::new();
    assert!(q.push(10));
    assert!(q.push(20));
    assert!(q.push(30));
    assert_eq!(q.pop(), Some(10));
    assert_eq!(q.pop(), Some(20));
    assert_eq!(q.pop(), Some(30));
    assert_eq!(q.pop(), None);
}
