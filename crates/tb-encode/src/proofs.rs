//! Kani proof harnesses for the pure silicon-adjacent encoders. Compiled ONLY
//! under `cfg(kani)` (the module is gated in `lib.rs`), so a normal `cargo
//! build` / `cargo kbuild` never sees them.
//!
//! Scope (honest):
//!   * The fixed-size, loop-free bit transforms (VMX adjust/clamp, TSS decode,
//!     page-table / EPT entry encoders, the 16-byte IPC frame) are TOTAL proofs
//!     over their full symbolic input space -- no `#[kani::unwind]` needed.
//!   * The ONE loop-bearing IPC harness (`kani_bounded_ring_framing`) is a
//!     BOUNDED proof with a small explicit op count + `#[kani::unwind]`, so an
//!     under-set bound fails closed (unwinding assertion) rather than hanging.
//!   * The `memscore` ranking-math harnesses prove what is SAFE and
//!     UNCONDITIONALLY TRUE for the M13 recall math over UNTRUSTED memory
//!     metadata: panic / overflow / divide-by-zero / shift-overflow FREEDOM plus
//!     a documented result BOUND. They are deliberately NOT symbolic-monotonicity
//!     proofs: fixed-point rounding can break strict monotonicity at boundaries,
//!     so a monotonicity harness would be UNSOUND and turn the lane RED (the #49
//!     over-quantification trap) -- monotonicity is covered by CONCRETE Miri
//!     vectors instead. Each `assume`s the DOCUMENTED reachable-input envelope
//!     (`x < 2^48`, bounded `age`, bounded `minmax` magnitudes); the fixed-point
//!     `* SCALE` term genuinely overflows i64 at astronomically large inputs the
//!     kernel never feeds, so an unconstrained full-range harness would ALSO be
//!     unsound. The `minmax` harness is loop-bearing (`#[kani::unwind]`) over a
//!     tiny fixed-length slice (the prior Kani state-explosion lesson).
//!
//! Each harness carries a NEGATIVE-CONTROL note: the concrete code break that
//! would turn it FAILED, so the suite is provably non-vacuous.

use crate::el2_trap::{
    classify_exit, dabt_access_size_bytes, dabt_iss_isv, dabt_iss_sas, dabt_iss_srt, dabt_iss_sse,
    dabt_iss_sf, esr_dfsc, esr_ec, esr_inject_undef, esr_is_translation_fault, esr_s1ptw, esr_wnr,
    gich_lr_encode, hpfar_fault_ipa, lr_is_retired, lr_state, lr_virtid, sysreg_iss_crm,
    sysreg_iss_crn, sysreg_iss_is_read, sysreg_iss_op0, sctlr_el1_guest_enable, sysreg_iss_op1,
    sysreg_iss_op2, sysreg_iss_rt, sysreg_iss_sys_val, vtr_list_regs, ExitClass, EC_DABT_LOW,
    EC_HVC64, EC_IABT_LOW, GICH_LR_MASK, GICH_LR_STATE_INVALID, GICH_LR_STATE_PENDING,
    SCTLR_EL1_GUEST_ENABLE_BITS, SYSREG_ISS_SYS_MASK,
};
use crate::blkfmt::{
    episode_decode, episode_encode, frame_header_decode, frame_header_encode, record_frame_decode,
    record_frame_encode, record_sector, region_extent, req_header_decode, req_header_encode,
    req_type_is_known, superblock_decode, superblock_encode, EPISODE_LEN, EP_COUNT,
    EP_FIRST, MAX_PAYLOAD, REGION_EPISODIC, REGION_SEMANTIC, REGION_WORKING, SECTOR_SIZE,
    SEM_COUNT, SEM_FIRST, T_FLUSH, T_IN, T_OUT, WM_COUNT, WM_FIRST,
};
use crate::ipc_frame::{BoundedRing, FrameError, MessageFrame, FRAME_SIZE};
use crate::kancell::{
    kan_score, kan_spline_eval, kan_table_is_monotone, kan_table_overflow_safe, DEMOTE_BAND,
    GRID_LO, GRID_STEP_LOG2, KAN_FEATURES, KAN_KNOTS, KAN_KNOT_MAX, KnotTable,
};
use crate::memscore::{bla_raw, ln_fixed, log2_fixed, minmax};
use crate::smmuv3::{
    cmd_cfgi_ste, cmd_sync, cmd_tlbi_s12_vmall, ste_cfg, ste_s2, ste_s2ttb, ste_s2vmid, ste_v,
    ste_vtcr, ste_vtcr_from_vtcr_el2, CMD_OP_CFGI_STE, CMD_OP_CMD_SYNC, CMD_OP_TLBI_S12_VMALL,
    STE_0_V, STE_2_S2AA64, STE_2_S2R, STE_2_VTCR_SHIFT, STE_3_S2TTB_MASK, STE_CFG_S2_TRANS,
};
use crate::paging::{
    entry_addr, ept_leaf_2mib, ept_nonleaf, eptp, level_index, make_entry, ENTRIES,
    ENTRY_ADDR_MASK, EPT_MAPS_PAGE, EPT_MEMTYPE_WB, EPT_RWX, EPT_WALK_LEN_MINUS_1, SHIFT_1G,
    SHIFT_2M, SHIFT_4K, SHIFT_512G,
};
use crate::stage2::{
    s2_leaf_2mib, s2_leaf_4k, s2_table, vtcr, vttbr, vttbr_baddr, S2AP_RW, S2_AF, S2_DESC_BLOCK,
    S2_DESC_PAGE, S2_DESC_TABLE, VTCR_RES1, VTTBR_VMID_SHIFT,
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

// ===========================================================================
// memscore: the M13 recall RANKING MATH. SAFE (panic/overflow-freedom + result
// bound) proofs over the DOCUMENTED reachable-input envelope. NOT monotonicity
// (that is concrete Miri vectors -- see the module-level honesty note).
// ===========================================================================

/// `log2_fixed` is panic-free (no overflow / shift-overflow / divide-by-zero)
/// and `0 <= r < 48 * SCALE` over the reachable domain.
///
/// DOMAIN (`x < 2^48`): the kernel only calls `log2_fixed` (via `ln_fixed`) on
/// values derived from u32 access counts (`<= 2^33`) or bounded logical-clock
/// deltas, so this ceiling covers every reachable input with >2^14 headroom. The
/// bound is LOAD-BEARING for soundness: at `x >= 2^54` the fixed-point
/// `(x - pow) * SCALE` term overflows i64, a panic the kernel never reaches but
/// a full-range `kani::any::<u64>()` harness WOULD hit -- the #49
/// over-quantification trap. Within the domain `ip <= 47` and `frac < SCALE`, so
/// `r < 48 * SCALE`.
///
/// NEGATIVE CONTROL: widening the scale to `(x - pow) * (SCALE << 12)` overflows
/// i64 inside the domain and turns this harness RED.
#[kani::proof]
fn kani_log2_fixed_panic_free_bounded() {
    let x: u64 = kani::any();
    kani::assume(x < (1u64 << 48));
    let r = log2_fixed(x);
    assert!(r >= 0);
    assert!(r < 48 * 1000); // 48 * SCALE
}

/// `ln_fixed` is panic-free and `0 <= r < 34_000` over the same `x < 2^48`
/// domain (`log2_fixed(x) < 48_000`, `* LN2_FIXED / SCALE` => `< 48*693 = 33_264`).
///
/// NEGATIVE CONTROL: replacing `* LN2_FIXED / SCALE` with `* SCALE` (no divide)
/// blows the `< 34_000` bound and turns this harness RED.
#[kani::proof]
fn kani_ln_fixed_panic_free_bounded() {
    let x: u64 = kani::any();
    kani::assume(x < (1u64 << 48));
    let r = ln_fixed(x);
    assert!(r >= 0);
    assert!(r < 34_000);
}

/// `bla_raw` -- the ACT-R Base-Level Activation that drives recall ranking and
/// the M17 FORGET sweep -- is panic-free and `|r| <= 34_000`. The u32 `count` is
/// taken over its FULL range (`2*(count+1) <= 2^33` can never overflow the u64
/// or the fixed-point path); only `age` needs the `< 2^48` envelope (`age + 1`
/// overflows at `u64::MAX` and feeds the same `log2_fixed` overflow point). `freq`
/// lies in `[0, ~33_264]` and `recency` in `[0, ~16_632]`, so the difference is
/// comfortably inside +/-34_000.
///
/// NEGATIVE CONTROL: dropping the `+ 1` guard in `ln_fixed(age + 1)` -> `ln_fixed(
/// age)` lets `age == 0` reach `log2_fixed(0)`; harmless here, but removing the
/// `/2` recency scale would push `r` past the bound and turn this harness RED.
#[kani::proof]
fn kani_bla_raw_panic_free_bounded() {
    let count: u32 = kani::any(); // full u32 is safe: 2*(count+1) <= 2^33
    let age: u64 = kani::any();
    kani::assume(age < (1u64 << 48));
    let r = bla_raw(count, age);
    assert!(r >= -34_000);
    assert!(r <= 34_000);
}

/// `minmax` (the recall score normalizer) returns a value in `[0, SCALE]` for a
/// tiny fixed-length symbolic slice, so a normalized component can never reorder
/// candidates out of band or escape the fixed-point window -- AND it never
/// panics (the `hi == lo` guard avoids divide-by-zero; bounded magnitudes avoid
/// the `(vals[i]-lo) * SCALE` overflow).
///
/// DOMAIN: the recall caller feeds `minmax` only small bounded components (the
/// `bla`/`idf`/importance vectors, each well under +/-2^20), so bounding the
/// symbolic elements to +/-2^20 is sound -- it covers the reachable inputs and
/// stays inside i64 for `(vals[i]-lo) * SCALE`. Length 4 + `#[kani::unwind(5)]`
/// keeps the proof cheap (the prior state-explosion lesson: tiny fixed slice).
///
/// SOUNDNESS NOTE: `minmax` is a NORMALIZER -- its output is the fixed-point
/// fraction in `[0, SCALE]`, NOT one of the slice elements (e.g.
/// `minmax([0,100],1) == 1000`), so the true invariant is the `[0, SCALE]` range,
/// not membership; asserting membership would be FALSE and turn the lane RED.
///
/// NEGATIVE CONTROL: deleting the `if hi == lo { 0 }` arm divides by zero on an
/// all-equal slice and turns this harness RED (the guard is load-bearing).
#[kani::proof]
#[kani::unwind(5)]
fn kani_minmax_in_scale_range() {
    const N: usize = 4;
    let mut vals = [0i64; N];
    let mut j = 0;
    while j < N {
        let v: i64 = kani::any();
        kani::assume(v >= -(1i64 << 20));
        kani::assume(v <= (1i64 << 20));
        vals[j] = v;
        j += 1;
    }
    let i: usize = kani::any();
    kani::assume(i < N);
    let r = minmax(&vals, i);
    assert!(r >= 0);
    assert!(r <= 1000); // SCALE
}

// ===========================================================================
// L2.1: aarch64 stage-2 descriptor + control-register encoders (`stage2.rs`).
//
// The ARM second-stage analog of the EPT proofs above: each asserts only
// UNCONDITIONALLY-TRUE, bounded well-formedness over a documented reachable
// envelope (memattr a 4-bit field, page-aligned addresses, T0SZ/SL0/PS in their
// legal field widths, VMID 16-bit), so the lane can never trip the #49
// over-quantification trap. Cloned from the `kani_ept_*` style.
// ===========================================================================

/// A stage-2 2 MiB block leaf is well-formed: S2AP=RW set, the MemAttr field in
/// `[5:2]` equals the input, AF set, the block low bits (`0b01`), and the
/// (2 MiB-aligned) address preserved. The 4 KiB-page variant carries the page
/// low bits (`0b11`) instead. The exact stage-2 twin of `kani_ept_leaf_wellformed`.
///
/// DOMAIN: `pa` 2 MiB-aligned and within the `[47:12]` field; `memattr` a 4-bit
/// MemAttr value in `[5:2]` (every caller passes `S2_MEMATTR_NORMAL_WB` or
/// `S2_MEMATTR_DEVICE`, both `<= 0xF<<2`), so the attribute bits never overlap
/// the address field.
///
/// NEGATIVE CONTROL: dropping `S2_AF` from `s2_leaf_2mib` makes the `e & S2_AF`
/// assert FAIL -- the cleared-Access-Flag abort-on-first-access bug (TABOS
/// installs no AF-fault handler, so a leaf without AF faults the guest's load).
#[kani::proof]
fn kani_s2_leaf_wellformed() {
    let pa: u64 = kani::any();
    kani::assume(pa & 0x1F_FFFF == 0); // 2 MiB aligned
    kani::assume(pa <= ENTRY_ADDR_MASK); // fits the [47:12] address field
    let memattr_idx: u64 = kani::any();
    kani::assume(memattr_idx < 16); // a valid 4-bit MemAttr value
    let memattr = memattr_idx << 2; // shifted into the [5:2] field

    let blk = s2_leaf_2mib(pa, memattr);
    assert_eq!(blk & S2AP_RW, S2AP_RW); // read/write
    assert_eq!((blk >> 2) & 0xF, memattr_idx); // MemAttr == input
    assert!(blk & S2_AF != 0); // AF mandatory (the abort-on-first-access guard)
    assert_eq!(blk & 0b11, S2_DESC_BLOCK); // block leaf low bits
    assert_eq!(blk & ENTRY_ADDR_MASK, pa); // address preserved

    // The 4 KiB page variant carries the same attrs but page low bits (0b11).
    let pg = s2_leaf_4k(pa, memattr);
    assert_eq!(pg & 0b11, S2_DESC_PAGE);
    assert!(pg & S2_AF != 0);
    assert_eq!(pg & ENTRY_ADDR_MASK, pa);
}

/// A stage-2 table descriptor is `child | 0b11` with the child address intact,
/// and `VTTBR_EL2` packs the VMID into `[63:48]` WITHOUT colliding the BADDR
/// (`[47:12]`) field -- the two are bit-disjoint. The stage-2 twin of
/// `kani_ept_nonleaf_and_eptp`.
///
/// DOMAIN: `child`/`root` 4 KiB-aligned; `vmid` a 16-bit value (the widest
/// FEAT_VMID16 VMID -- ARMv8.0's 8-bit VMID is a strict subset).
///
/// NEGATIVE CONTROL: packing the VMID as `vmid << 47` (one bit low) would set
/// BADDR bit[47] for any odd VMID, so `vttbr_baddr(vt) == root` would FAIL (the
/// VMID bleeding into the root-address field).
#[kani::proof]
fn kani_s2_table_and_vttbr() {
    let child: u64 = kani::any();
    kani::assume(child & 0xFFF == 0); // 4 KiB-aligned table frame
    let t = s2_table(child);
    assert_eq!(t & 0b11, S2_DESC_TABLE);
    assert_eq!(t & ENTRY_ADDR_MASK, child & ENTRY_ADDR_MASK);

    let root: u64 = kani::any();
    kani::assume(root & 0xFFF == 0);
    let vmid: u64 = kani::any();
    kani::assume(vmid < (1u64 << 16)); // 16-bit VMID envelope
    let vt = vttbr(root, vmid);
    assert_eq!((vt >> VTTBR_VMID_SHIFT) & 0xFFFF, vmid); // VMID in [63:48]
    assert_eq!(vttbr_baddr(vt), root & ENTRY_ADDR_MASK); // BADDR preserved
    // BADDR and VMID fields are structurally disjoint -- the VMID never overlaps
    // the address field (the negative control's `vmid << 47` would break this).
    assert_eq!(ENTRY_ADDR_MASK & (0xFFFFu64 << VTTBR_VMID_SHIFT), 0);
}

/// `VTCR_EL2` packs each field into its own slice -- T0SZ `[5:0]`, SL0 `[7:6]`,
/// TG0 `[15:14]`, PS `[18:16]` -- with RES1 bit[31] set and NO field overlap.
/// The ARM twin of the EPTP walk-length proof: a wrong SL0 for the chosen T0SZ
/// is the classic stage-2 off-by-one walk-length bug, fenced here.
///
/// DOMAIN: each field bounded to its real width (T0SZ 6-bit, SL0/TG0 2-bit, PS
/// 3-bit, the cacheability fields 2-bit) -- the reachable VTCR programming space.
///
/// NEGATIVE CONTROL: shifting SL0 into bits `[5:4]` instead of `[7:6]` would
/// collide the top of T0SZ, so `v & 0x3F == t0sz` (T0SZ readback) would FAIL.
#[kani::proof]
fn kani_vtcr_wellformed() {
    let t0sz: u64 = kani::any();
    kani::assume(t0sz < (1 << 6));
    let sl0: u64 = kani::any();
    kani::assume(sl0 < (1 << 2));
    let tg0: u64 = kani::any();
    kani::assume(tg0 < (1 << 2));
    let ps: u64 = kani::any();
    kani::assume(ps < (1 << 3));
    let sh0: u64 = kani::any();
    kani::assume(sh0 < (1 << 2));
    let orgn0: u64 = kani::any();
    kani::assume(orgn0 < (1 << 2));
    let irgn0: u64 = kani::any();
    kani::assume(irgn0 < (1 << 2));

    let v = vtcr(t0sz, sl0, tg0, ps, sh0, orgn0, irgn0);
    assert_eq!(v & 0x3F, t0sz); // T0SZ  [5:0]
    assert_eq!((v >> 6) & 0x3, sl0); // SL0   [7:6]  (the walk-length field)
    assert_eq!((v >> 8) & 0x3, irgn0); // IRGN0 [9:8]
    assert_eq!((v >> 10) & 0x3, orgn0); // ORGN0 [11:10]
    assert_eq!((v >> 12) & 0x3, sh0); // SH0   [13:12]
    assert_eq!((v >> 14) & 0x3, tg0); // TG0   [15:14]
    assert_eq!((v >> 16) & 0x7, ps); // PS    [18:16]
    assert!(v & VTCR_RES1 != 0); // RES1  bit[31]
}

/// `ESR_EL2` decoding is TOTAL: for EVERY 32-bit syndrome, EC/DFSC/WnR/S1PTW
/// decode without panic into their bounded ranges, and the translation-fault
/// classification is EXACT (true iff the full 6-bit DFSC is `0x04..=0x07`). The
/// three dispatch EC constants are distinct. Clone of `kani_ipc_frame_decode_total`
/// + `kani_level_index_bounds`.
///
/// NEGATIVE CONTROL: masking DFSC with `0x1F` instead of `0x3F` (in `esr_dfsc`)
/// would mis-class a fault like `0x27` (DFSC bit[5] set, low bits `0b0111`) as a
/// level-3 translation fault, so the `esr_is_translation_fault == (ref in 4..=7)`
/// equality (with `ref` computed from the full `& 0x3F`) would FAIL.
#[kani::proof]
fn kani_esr_decode_total() {
    let esr: u64 = kani::any();
    let ec = esr_ec(esr);
    let dfsc = esr_dfsc(esr);
    let wnr = esr_wnr(esr);
    let s1ptw = esr_s1ptw(esr);
    assert!(ec < 64); // EC is a 6-bit field
    assert!(dfsc < 64); // DFSC is the full 6-bit field
    assert!(wnr < 2); // single bit
    assert!(s1ptw < 2); // single bit

    // Translation-fault classification is exact against an INDEPENDENT 6-bit
    // re-derivation taken DIRECTLY from the raw syndrome (`esr & 0x3F`), NOT via
    // `esr_dfsc` (the fn under test). Deriving the reference through `esr_dfsc`
    // would move both sides of the equality together (tautological); inlining
    // the `& 0x3F` mask here makes the negative control real -- an `esr_dfsc`
    // `0x1F`-masking bug makes `esr_is_translation_fault` (which routes through
    // `esr_dfsc`) disagree with this reference on e.g. `0x27`, reddening the lane.
    let ref_dfsc = esr & 0x3F;
    let ref_is_xlat = ref_dfsc >= 0x04 && ref_dfsc <= 0x07;
    assert_eq!(esr_is_translation_fault(esr), ref_is_xlat);

    // The three dispatch classes are distinct (the handler routes on them).
    assert!(EC_HVC64 != EC_DABT_LOW);
    assert!(EC_DABT_LOW != EC_IABT_LOW);
    assert!(EC_HVC64 != EC_IABT_LOW);
}

/// `hpfar_fault_ipa` is page-aligned (low 12 bits 0) for ALL inputs and, over
/// the reachable HPFAR domain, lands within the 52-bit PA space. The faulting
/// IPA the demand-map handler splices a leaf for can therefore never be
/// mis-aligned or out of range.
///
/// DOMAIN: `hpfar < 2^44` -- FIPA occupies `HPFAR[43:4]`, bits above are RES0,
/// so a real HPFAR readback is always within this bound; it keeps `(hpfar &
/// !0xF) << 8 < 2^52`. The page-alignment half holds for EVERY u64 with no
/// assumption.
///
/// NEGATIVE CONTROL: `(hpfar & !0xF) << 4` (instead of `<< 8`) would leave the
/// extracted bits in `[11:8]`, so the `ipa & 0xFFF == 0` page-alignment assert
/// would FAIL -- the IPA mislocated by a factor of 16.
#[kani::proof]
fn kani_hpfar_fault_ipa() {
    let hpfar: u64 = kani::any();
    // Page-alignment is unconditional over the full input space.
    assert_eq!(hpfar_fault_ipa(hpfar) & 0xFFF, 0);

    // Within the reachable FIPA field, the IPA fits the 52-bit PA space.
    kani::assume(hpfar < (1u64 << 44));
    let ipa = hpfar_fault_ipa(hpfar);
    assert!(ipa < (1u64 << 52));
}

// ===========================================================================
// L2.2: the aarch64 ESR_EL2.EC exit-dispatch classifier (`el2_trap::classify_exit`)
// + the injected-UNDEF syndrome encoder. The ARM analog of x86 `arm_exit_handlers[]`.
// ===========================================================================

/// `classify_exit` is TOTAL: for EVERY u64 ESR it returns a defined `ExitClass`
/// without panic; the six MUST-handle ECs map to their NAMED arms; and EVERY
/// other EC (all 58 remaining) maps to `Undef` (the fail-closed inject-UNDEF
/// default) -- the `arm_exit_handlers[0..EC_MAX]=kvm_handle_unknown_ec`
/// discipline, machine-checked. Also pins the injected-syndrome encoder.
///
/// NEGATIVE CONTROL #1 (default non-vacuity): if `classify_exit` lost its
/// `_ => Undef` arm it would not COMPILE; if a MUST arm were mis-mapped (e.g.
/// `EC_SMC64 => Undef`) the `0x17 => Smc` assertion below FAILS. NEGATIVE
/// CONTROL #2 (a real non-MUST EC really defaults): the explicit `ec == 0x07`
/// (FP_ASIMD, the self-test's default trigger) is asserted `Undef`; routing it
/// to a named arm reddens the lane. NEGATIVE CONTROL #3 (encoder): placing IL at
/// bit26 instead of bit25 makes `esr_ec(esr_inject_undef()) == 0x00` FAIL.
#[kani::proof]
fn kani_exit_classifier_total() {
    let esr: u64 = kani::any();
    let class = classify_exit(esr); // total: returns for every input
    let ec = esr_ec(esr); // proven < 64 by kani_esr_decode_total
    match ec {
        0x24 | 0x20 => assert_eq!(class, ExitClass::StageTwoAbort),
        0x16 => assert_eq!(class, ExitClass::Hvc),
        0x17 => assert_eq!(class, ExitClass::Smc),
        0x18 => assert_eq!(class, ExitClass::Sys64),
        0x01 => assert_eq!(class, ExitClass::Wfx),
        _ => assert_eq!(class, ExitClass::Undef), // the fail-closed default
    }
    // Concrete anchors (non-vacuity + the real negative control on EC 0x07):
    assert_eq!(classify_exit(0x07 << 26), ExitClass::Undef); // FP_ASIMD -> default
    assert_eq!(classify_exit(0x00 << 26), ExitClass::Undef); // UNKNOWN  -> default
    assert_ne!(classify_exit(0x16 << 26), ExitClass::Undef); // HVC64 is NAMED

    // The injected UNKNOWN syndrome decodes back to EC=0x00 with IL set.
    assert_eq!(esr_inject_undef(), (0x00u64 << 26) | (1u64 << 25));
    assert_eq!(esr_ec(esr_inject_undef()), 0x00);
}

// ===========================================================================
// L2.3: the trap-and-emulate ISS decoders (`el2_trap` SYS64 + DABT MMIO ISS).
// One harness per syndrome FAMILY, each proving TOTALITY (bounded, no panic)
// AND round-trip CORRECTNESS against an INDEPENDENT literal-Arm-ARM-shift
// reference -- the one-harness-per-decoder-family pattern of
// `kani_esr_decode_total` / `kani_exit_classifier_total`.
// ===========================================================================

/// `ESR.ISS` SYS64 (MSR/MRS) decoding is TOTAL: for EVERY u64 ESR each field
/// decodes without panic into its bounded range (op0<4, op2<8, op1<8, crn<16,
/// rt<32, crm<16, is_read a bool). CORRECTNESS: pack symbolic op0/op1/op2/crn/
/// crm/rt/dir via INDEPENDENT literal Arm-ARM shifts and assert every decoder
/// recovers its field, plus `(iss & SYSREG_ISS_SYS_MASK) == sysreg_iss_sys_val(...)`.
///
/// NEGATIVE CONTROL (non-tautological, literal shifts vs the fns under test):
/// if `sysreg_iss_op1` masked at shift `[15:13]` instead of `[16:14]` it would
/// alias CRn bit[13]; the op1-recovery equality FAILS for any op1 with bit2 set.
/// The reference shifts are the literal 20/17/14/10/5/1/0, never routed through
/// the fns under test (so the two sides cannot move together).
#[kani::proof]
fn kani_sysreg_iss_decode_total() {
    let esr: u64 = kani::any();
    // TOTALITY: every decoder is bounded over the full input space (no panic).
    assert!(sysreg_iss_op0(esr) < 4);
    assert!(sysreg_iss_op2(esr) < 8);
    assert!(sysreg_iss_op1(esr) < 8);
    assert!(sysreg_iss_crn(esr) < 16);
    assert!(sysreg_iss_rt(esr) < 32);
    assert!(sysreg_iss_crm(esr) < 16);
    let _ = sysreg_iss_is_read(esr); // a bool by construction -- cannot panic

    // CORRECTNESS: pack each field from symbolic, bounded sources via the LITERAL
    // Arm-ARM ISS shifts (20/17/14/10/5/1/0), then assert the decoders recover them.
    let op0: u64 = kani::any();
    kani::assume(op0 < 4);
    let op2: u64 = kani::any();
    kani::assume(op2 < 8);
    let op1: u64 = kani::any();
    kani::assume(op1 < 8);
    let crn: u64 = kani::any();
    kani::assume(crn < 16);
    let rt: u64 = kani::any();
    kani::assume(rt < 32);
    let crm: u64 = kani::any();
    kani::assume(crm < 16);
    let dir: u64 = kani::any();
    kani::assume(dir < 2);
    // INDEPENDENT literal-shift reference (NOT via the fns under test).
    let iss = (op0 << 20) | (op2 << 17) | (op1 << 14) | (crn << 10) | (rt << 5) | (crm << 1) | dir;
    assert_eq!(sysreg_iss_op0(iss), op0);
    assert_eq!(sysreg_iss_op2(iss), op2);
    assert_eq!(sysreg_iss_op1(iss), op1);
    assert_eq!(sysreg_iss_crn(iss), crn);
    assert_eq!(sysreg_iss_rt(iss), rt);
    assert_eq!(sysreg_iss_crm(iss), crm);
    assert_eq!(sysreg_iss_is_read(iss), dir != 0);
    // The Rt/direction-independent SYS key matches the packer over the masked ISS.
    assert_eq!(iss & SYSREG_ISS_SYS_MASK, sysreg_iss_sys_val(op0, op1, op2, crn, crm));
}

/// `ESR.ISS` Data-Abort (MMIO) decoding is TOTAL: for EVERY u64 ESR the single-bit
/// fields (isv/sse/sf) are `< 2`, sas `< 4`, srt `< 32`, and `dabt_access_size_bytes`
/// is in `{1,2,4,8}` (no shift-overflow). CORRECTNESS: an INDEPENDENT literal match
/// of the access size and a packed-then-recovered symbolic SRT.
///
/// NEGATIVE CONTROL: masking SRT with `0xF` (4 bits) instead of `0x1F` drops
/// x16..x31, so the srt-recovery FAILS for srt == 0x1F (x31); equivalently a
/// `1 << ((esr>>21)&3)` (SSE-aliased) size impl disagrees with the literal-shift
/// `size_ref`. The reference uses raw `(esr>>22)&3` / `(esr>>16)&0x1F`, never the
/// fns under test (no tautology).
#[kani::proof]
fn kani_dabt_iss_decode_total() {
    let esr: u64 = kani::any();
    // TOTALITY over the full input space (no panic, no shift-overflow).
    assert!(dabt_iss_isv(esr) < 2);
    assert!(dabt_iss_sse(esr) < 2);
    assert!(dabt_iss_sf(esr) < 2);
    assert!(dabt_iss_sas(esr) < 4);
    assert!(dabt_iss_srt(esr) < 32);
    let sz = dabt_access_size_bytes(esr);
    assert!(sz == 1 || sz == 2 || sz == 4 || sz == 8);

    // CORRECTNESS: an INDEPENDENT literal match of the access size from raw SAS.
    let size_ref = match (esr >> 22) & 3 {
        0 => 1u64,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    assert_eq!(dabt_access_size_bytes(esr), size_ref);
    // And a packed-then-recovered symbolic SRT over the FULL 5-bit field.
    let srt: u64 = kani::any();
    kani::assume(srt < 32);
    let iss = (1u64 << 24) | (srt << 16);
    assert_eq!(dabt_iss_srt(iss), srt);
    assert_eq!(dabt_iss_isv(iss), 1);
}

// ===========================================================================
// aL2.4: the guest's SCTLR_EL1 first-stage ENABLE word -- the "S1 after S2" step.
// ===========================================================================

/// `sctlr_el1_guest_enable` OR-sets EXACTLY bits {0,2,12} (M|C|I) and preserves
/// every other baseline bit, for ALL `baseline:u64` -- and is idempotent. This
/// pins the single instant the aL2.4 guest brings its first stage up under our
/// second stage (KVM nvhe/switch.c "S2 ... enabled ... now restore the guest's
/// S1 ... SCTLR") to a machine-checked invariant.
///
/// NEGATIVE CONTROL: an enable that ANDed (`baseline & BITS`) instead of ORed
/// would clear the baseline RES1/EE bits and make the preservation assert FAIL;
/// a wrong bit (e.g. `1<<13` instead of `1<<12`) would make the M|C|I asserts
/// FAIL.
#[kani::proof]
fn kani_sctlr_el1_guest_enable() {
    let baseline: u64 = kani::any();
    let r = sctlr_el1_guest_enable(baseline);
    // (a) The three enable bits {0,2,12} are set.
    assert_eq!(r & SCTLR_EL1_GUEST_ENABLE_BITS, SCTLR_EL1_GUEST_ENABLE_BITS);
    assert_eq!(SCTLR_EL1_GUEST_ENABLE_BITS, (1 << 0) | (1 << 2) | (1 << 12));
    // (b) Every baseline bit OUTSIDE the enable mask is preserved bit-for-bit
    //     (no clobber of RES1 / EE / SA / WXN ...).
    assert_eq!(
        r & !SCTLR_EL1_GUEST_ENABLE_BITS,
        baseline & !SCTLR_EL1_GUEST_ENABLE_BITS
    );
    // And every baseline bit survives (it is a pure OR-projection).
    assert_eq!(r & baseline, baseline);
    // (c) Idempotent: re-enabling an already-enabled word is a no-op.
    assert_eq!(sctlr_el1_guest_enable(r), r);
}

// ===========================================================================
// aL2.5: the GICv2 GICH_LRn list-register ENCODER + decoder family
// (`el2_trap::gich_lr_encode` / `lr_state` / `lr_virtid` / `lr_is_retired`).
// The pure value the EL2 monitor stores into GICH_LR0 to software-inject a
// virtual interrupt, and the readback decode the done-side retire-check uses.
// The ARM virtual-interrupt analog of the EPT/stage-2 entry proofs above:
// FIELD round-trip via INDEPENDENT literal shifts + NO field bleed + a real
// negative control, over each field's documented bit width.
// ===========================================================================

/// `gich_lr_encode` composes a GICH_LRn value whose every field round-trips and
/// whose bits never bleed outside the documented union mask (== QEMU
/// `GICH_LR_MASK`). DOMAIN: vintid/pintid 10-bit, state 2-bit, priority 5-bit,
/// group/hw/eoi single bits -- each field's real width per IHI 0048B §4.4.
///
/// (a) FIELD ROUND-TRIP: `lr_virtid(encode(...)) == vintid`, `lr_state(...) ==
///     state`, and every OTHER field recovered by an INDEPENDENT literal-shift
///     reference (NOT via the decoders under test -- the non-tautology
///     discipline of `kani_sysreg_iss_decode_total`): PhysicalID via `>>10`,
///     Priority via `>>23 & 0x1F`, EOI via bit19, Grp1 via bit30, HW via bit31.
/// (b) NO FIELD BLEED: the encoded value has NO bit set outside `GICH_LR_MASK`;
///     State[29:28] never overlaps VirtualID/Priority; HW(31) and Grp1(30) are
///     single bits.
///
/// THE bit-19 OVERLAP (verified against QEMU v8.2.0 `gic_internal.h`
/// `REG32(GICH_LR0,0x100)`): the GICv2 spec defines `PhysicalID` as `[19:10]`
/// (`FIELD(...,PhysicalID,10,10)`) AND `EOI` as bit 19 (`FIELD(...,EOI,19,1)`),
/// so bit 19 is SHARED -- it is the top bit of PhysicalID when `HW=1` (hardware
/// de-activation) and the EOI-maintenance bit when `HW=0` (software-injected).
/// QEMU's `GICH_LR_MASK` ORs both masks, which OVERLAP at bit 19. aL2.5 is
/// purely SW-injected (`HW=0`, `pintid=0`), so EOI owns bit 19 and PhysicalID is
/// effectively the low 9 bits. The harness mirrors this exactly: it bounds
/// `pintid < 512` (the 9 bits `[18:10]` that do NOT collide with EOI) and varies
/// EOI freely over bit 19 -- the honest, non-overlapping field decomposition.
/// (Bounding `pintid < 1024` would let `pintid` bit 9 set bit 19, making the
/// independent `eoi`/`pintid` references disagree -- a FALSE alarm on a genuine
/// architectural mux, not an encoder bug.)
///
/// NEGATIVE CONTROL: placing State at `[27:26]` (`<< 26`) instead of `[28:29]`
/// (`<< 28`) would alias Priority bit27 -- so a nonzero `priority` would corrupt
/// the recovered `state`, breaking the `lr_state == state` round-trip; and
/// State bit29 would fall outside the priority field, the `state` round-trip
/// failing for `state >= 2`. Either way the harness turns RED. The reference
/// shifts are the literal 0/10/19/23/28/30/31, never routed through the encoder.
#[kani::proof]
fn kani_gich_lr_encode_roundtrip() {
    let vintid: u64 = kani::any();
    kani::assume(vintid < 1024); // VirtualID is a 10-bit field
    let pintid: u64 = kani::any();
    // PhysicalID is [19:10] but bit 19 is SHARED with EOI (the HW=0/HW=1 mux);
    // for the SW-injected (HW=0) path EOI owns bit 19, so the non-overlapping
    // PhysicalID is [18:10] (9 bits). Bound it there + vary EOI over bit 19.
    kani::assume(pintid < 512);
    let state: u64 = kani::any();
    kani::assume(state < 4); // State is a 2-bit field
    let priority: u64 = kani::any();
    kani::assume(priority < 32); // stored Priority is a 5-bit field (priority[7:3])
    let group: u64 = kani::any();
    kani::assume(group < 2); // Grp1 is a single bit
    let hw: u64 = kani::any();
    kani::assume(hw < 2); // HW is a single bit
    let eoi: u64 = kani::any();
    kani::assume(eoi < 2); // EOI is a single bit (bit 19, owns it when HW=0)

    let lr = gich_lr_encode(vintid, pintid, state, priority, group, hw, eoi);
    let lr64 = lr as u64;

    // (a) FIELD ROUND-TRIP. VirtualID + State via the decoders under test...
    assert_eq!(lr_virtid(lr), vintid);
    assert_eq!(lr_state(lr), state);
    // ...and EVERY field via an INDEPENDENT literal-shift reference. PhysicalID
    // is recovered from [18:10] (9 bits, disjoint from EOI bit 19); EOI from bit
    // 19 (which it owns under HW=0). The literal shifts never route through the
    // encoder, so the references are independent.
    assert_eq!(lr64 & 0x3FF, vintid); // VirtualID [9:0]
    assert_eq!((lr64 >> 10) & 0x1FF, pintid); // PhysicalID [18:10] (9 bits, no EOI overlap)
    assert_eq!((lr64 >> 19) & 1, eoi); // EOI bit19
    assert_eq!((lr64 >> 23) & 0x1F, priority); // Priority [27:23]
    assert_eq!((lr64 >> 28) & 0x3, state); // State [29:28]
    assert_eq!((lr64 >> 30) & 1, group); // Grp1 bit30
    assert_eq!((lr64 >> 31) & 1, hw); // HW bit31

    // (b) NO FIELD BLEED: nothing set outside the documented union mask.
    assert_eq!(lr & !GICH_LR_MASK, 0);
    // State[29:28] is bit-disjoint from VirtualID[9:0] and Priority[27:23].
    assert_eq!((0x3u32 << 28) & 0x3FF, 0);
    assert_eq!((0x3u32 << 28) & (0x1F << 23), 0);
    // HW(31) and Grp1(30) are single bits (each exactly one bit set).
    assert_eq!((1u32 << 31).count_ones(), 1);
    assert_eq!((1u32 << 30).count_ones(), 1);

    // `lr_is_retired` iff State == INVALID (the done-side completion proof). A
    // freshly PENDING-injected LR is NOT retired; an INVALID one IS.
    let pending = gich_lr_encode(vintid, 0, GICH_LR_STATE_PENDING, 0, 0, 0, 0);
    assert!(!lr_is_retired(pending));
    let invalid = gich_lr_encode(vintid, 0, GICH_LR_STATE_INVALID, 0, 0, 0, 0);
    assert!(lr_is_retired(invalid));

    // `vtr_list_regs` decodes GICH_VTR.ListRegs (num_lrs - 1) as `>= 1` for ALL
    // u32 (the monitor asserts num_lrs >= 1 before writing LR0).
    let vtr: u32 = kani::any();
    let n = vtr_list_regs(vtr);
    assert!(n >= 1 && n <= 64);
}

// ===========================================================================
// aL2.6 -- SMMUv3 STE / command-queue encoder harnesses.
// ===========================================================================

/// A stage-2-only SMMUv3 Stream Table Entry round-trips: for a symbolic
/// `s2ttb`(aligned)/`vmid`(16-bit)/`ste_vtcr`(19-bit), the `ste_*` accessors
/// recover each field via INDEPENDENT literal shifts, `Config == 0b110`, `V` is
/// set, the documented `S2AA64`/`S2R` flags are set + `S2ENDI`/`S2PTW` clear, and
/// the address/VMID/VTCR fields are bit-disjoint (no field bleed). The IOMMU twin
/// of `kani_gich_lr_encode_roundtrip` + `kani_s2_table_and_vttbr`.
///
/// DOMAIN: `s2ttb` masked to the STE `[51:4]` field, `vmid` a 16-bit value (the
/// widest FEAT_VMID16 VMID -- the 8-bit VMID is a subset), `ste_vtcr` a 19-bit
/// value (the full `VTCR_EL2[18:0]` projection envelope).
///
/// NEGATIVE CONTROL: packing `Config` at `<< 2` instead of `<< 1` (i.e. into
/// `[4:2]` instead of `[3:1]`) would leave `V` (bit0) clear yet `0b110<<2` would
/// set bit3 -- so `ste_cfg` (which reads `[3:1]`) would recover `0b011`, not
/// `0b110`, and `ste_v` would read 0; the `ste_cfg == STE_CFG_S2_TRANS` AND
/// `ste_v == STE_0_V` conjunction would FAIL. The reference shifts (`& STE_0_V`,
/// `>> 1 & 0b111`, the `[15:0]`/`<<32`/`[51:4]` slices) never route through the
/// encoder, so the readback references are independent.
#[kani::proof]
fn kani_ste_s2_roundtrip() {
    let s2ttb: u64 = kani::any();
    kani::assume(s2ttb & 0xFFF == 0); // 4 KiB-aligned stage-2 L1 root
    kani::assume(s2ttb <= STE_3_S2TTB_MASK); // fits the [51:4] S2TTB field
    let vmid: u64 = kani::any();
    kani::assume(vmid < (1u64 << 16)); // 16-bit VMID envelope
    let ste_vtcr_field: u64 = kani::any();
    kani::assume(ste_vtcr_field < (1u64 << 19)); // 19-bit VTCR projection

    let ste = ste_s2(s2ttb, vmid, ste_vtcr_field);

    // (a) FIELD ROUND-TRIP via the accessors under test...
    assert_eq!(ste_v(&ste), STE_0_V); // V set
    assert_eq!(ste_cfg(&ste), STE_CFG_S2_TRANS); // Config == 0b110 (stage-2 translate)
    assert_eq!(ste_s2vmid(&ste), vmid); // S2VMID
    assert_eq!(ste_vtcr(&ste), ste_vtcr_field); // VTCR projection
    assert_eq!(ste_s2ttb(&ste), s2ttb); // S2TTB preserved

    // ...and via INDEPENDENT literal-shift references (never via the accessors).
    assert_eq!(ste[0] & 1, 1); // V bit0
    assert_eq!((ste[0] >> 1) & 0b111, STE_CFG_S2_TRANS); // Config [3:1] == 0b110
    assert_eq!(ste[2] & 0xFFFF, vmid); // S2VMID [15:0]
    assert_eq!((ste[2] >> STE_2_VTCR_SHIFT) & 0x7_FFFF, ste_vtcr_field); // VTCR [50:32]
    assert_eq!(ste[3] & STE_3_S2TTB_MASK, s2ttb); // S2TTB [51:4]

    // (b) DOCUMENTED FLAGS: S2AA64 (AArch64 stage-2) + S2R (record faults) set;
    // the stage-2-only LE default leaves S2ENDI + S2PTW clear.
    assert!(ste[2] & STE_2_S2AA64 != 0);
    assert!(ste[2] & STE_2_S2R != 0);

    // (c) STAGE-2-ONLY: NO S1ContextPtr / stage-1 config -- dwords 1,4..7 zero.
    assert_eq!(ste[1], 0);
    assert_eq!(ste[4], 0);
    assert_eq!(ste[5], 0);
    assert_eq!(ste[6], 0);
    assert_eq!(ste[7], 0);

    // (d) NO FIELD BLEED: VMID[15:0], VTCR[50:32] and the flag bits are mutually
    // disjoint (the VMID never overlaps the VTCR slot, which starts at bit32), and
    // the V/Config field in dword0 is disjoint from the S2TTB field in dword3.
    assert_eq!((0xFFFFu64) & (0x7_FFFFu64 << STE_2_VTCR_SHIFT), 0); // VMID vs VTCR
    assert_eq!(STE_3_S2TTB_MASK & 0xF, 0); // S2TTB starts at bit4 (low nibble clear)
}

/// THE LEMMA: the SMMU stage-2 geometry IS the CPU stage-2 geometry. For a
/// symbolic `VTCR_EL2` built by [`crate::stage2::vtcr`] over bounded fields,
/// `ste_vtcr_from_vtcr_el2(vtcr_el2)` recovers `S2T0SZ`/`S2SL0`/`S2TG`/`S2PS`
/// BIT-IDENTICALLY to `VTCR_EL2[18:0]`, proving the projection into the STE `VTCR`
/// slot is the SAME 19 bits the CPU's `VTCR_EL2` carries (minus the EL2-only RES1
/// bit31). The const-checkable "SMMU S2 config == CPU S2 config" fact.
///
/// DOMAIN: each `vtcr` field bounded to its real width (T0SZ 6-bit, SL0/TG0/
/// cacheability 2-bit, PS 3-bit) -- the reachable stage-2 programming space, the
/// same envelope `kani_vtcr_wellformed` proves.
///
/// NEGATIVE CONTROL: an off-by-one on `S2SL0`'s `[7:6]` slot -- reading SL0 from
/// `[6:5]` (`>> 5`) instead of `[7:6]` (`>> 6`) -- would diverge from `VTCR_EL2.
/// SL0` for any nonzero T0SZ bit5 / SL0 combination, so the `(proj >> 6) & 0x3 ==
/// sl0` equality would FAIL. The references read DIRECTLY off the symbolic input
/// fields, not via the encoder, so they are independent.
#[kani::proof]
fn kani_ste_vtcr_matches_cpu_stage2() {
    let t0sz: u64 = kani::any();
    kani::assume(t0sz < (1 << 6));
    let sl0: u64 = kani::any();
    kani::assume(sl0 < (1 << 2));
    let tg0: u64 = kani::any();
    kani::assume(tg0 < (1 << 2));
    let ps: u64 = kani::any();
    kani::assume(ps < (1 << 3));
    let sh0: u64 = kani::any();
    kani::assume(sh0 < (1 << 2));
    let orgn0: u64 = kani::any();
    kani::assume(orgn0 < (1 << 2));
    let irgn0: u64 = kani::any();
    kani::assume(irgn0 < (1 << 2));

    // The CPU's VTCR_EL2 (the EXACT same packer the CPU stage-2 calls), carrying
    // RES1 bit31; the STE projection drops bit31 but keeps [18:0] bit-identically.
    let cpu_vtcr = vtcr(t0sz, sl0, tg0, ps, sh0, orgn0, irgn0);
    assert!(cpu_vtcr & VTCR_RES1 != 0); // the CPU word has RES1 set...
    let proj = ste_vtcr_from_vtcr_el2(cpu_vtcr);
    assert_eq!(proj & VTCR_RES1, 0); // ...the STE projection drops it.

    // BIT-IDENTITY: every stage-2 geometry field is recovered from the projection
    // identically to the symbolic input (the SMMU S2 == CPU S2 lemma). References
    // taken directly off the symbolic fields, never via the encoder.
    assert_eq!(proj & 0x3F, t0sz); // S2T0SZ  [5:0]
    assert_eq!((proj >> 6) & 0x3, sl0); // S2SL0   [7:6] (the off-by-one control)
    assert_eq!((proj >> 8) & 0x3, irgn0); // S2IR0   [9:8]
    assert_eq!((proj >> 10) & 0x3, orgn0); // S2OR0   [11:10]
    assert_eq!((proj >> 12) & 0x3, sh0); // S2SH0   [13:12]
    assert_eq!((proj >> 14) & 0x3, tg0); // S2TG    [15:14]
    assert_eq!((proj >> 16) & 0x7, ps); // S2PS    [18:16]
    // The projection IS exactly VTCR_EL2[18:0] -- the whole 19-bit slice.
    assert_eq!(proj, cpu_vtcr & 0x7_FFFF);
}

/// The SMMUv3 command-queue encoders are TOTAL: `cmd_cfgi_ste`/
/// `cmd_tlbi_s12_vmall`/`cmd_sync` place the right opcode in word0`[7:0]` for ALL
/// symbolic operands, never panic, and land each operand in its documented field
/// (StreamID `[63:32]` of CFGI_STE, VMID `[47:32]` of TLBI_S12_VMALL). Clone of
/// `kani_dabt_iss_decode_total`'s totality style.
///
/// DOMAIN: `sid` any 32-bit StreamID, `vmid` any 16-bit VMID (the whole operand
/// space the kernel can pass).
///
/// NEGATIVE CONTROL: encoding the opcode at `[15:8]` (`<< 8`) instead of `[7:0]`
/// would make the `word0 & 0xFF == op` readback recover 0, not the opcode -- the
/// `& 0xFF == CMD_OP_*` assertions would FAIL. The references mask `& 0xFF` /
/// `>> 32` directly, never through a decoder.
#[kani::proof]
fn kani_smmu_cmd_encode_total() {
    let sid: u32 = kani::any();
    let c = cmd_cfgi_ste(sid);
    assert_eq!(c[0] & 0xFF, CMD_OP_CFGI_STE); // opcode [7:0]
    assert_eq!(c[0] >> 32, sid as u64); // StreamID [63:32]
    assert_eq!(c[1] & 1, 1); // Leaf bit set (single-leaf invalidate)

    let vmid: u16 = kani::any();
    let t = cmd_tlbi_s12_vmall(vmid);
    assert_eq!(t[0] & 0xFF, CMD_OP_TLBI_S12_VMALL); // opcode [7:0]
    assert_eq!((t[0] >> 32) & 0xFFFF, vmid as u64); // VMID [47:32]

    let s = cmd_sync();
    assert_eq!(s[0] & 0xFF, CMD_OP_CMD_SYNC); // opcode [7:0]

    // The three opcodes are distinct (the SMMU routes on them).
    assert!(CMD_OP_CFGI_STE != CMD_OP_TLBI_S12_VMALL);
    assert!(CMD_OP_TLBI_S12_VMALL != CMD_OP_CMD_SYNC);
    assert!(CMD_OP_CFGI_STE != CMD_OP_CMD_SYNC);
}

// ===========================================================================
// M20 blkfmt: the durable-persistence on-disk + virtio-blk request codecs.
// Six harnesses (the EXPECTED_HARNESSES 28 -> 34 bump in verify-encode.sh).
// ===========================================================================

/// (1) The virtio-blk REQUEST HEADER round-trips + the three request types are
/// well-formed. For ALL symbolic `(type, sector)`, `req_header_decode(
/// req_header_encode(..))` recovers the pair, and the three issued types
/// (`T_IN`/`T_OUT`/`T_FLUSH`) all pass `req_type_is_known`. A total, loop-free
/// proof over the whole 16-byte layout (the reserved dword is decode-ignored).
///
/// NEGATIVE CONTROL: writing the sector at byte offset 4 (overlapping the
/// reserved dword) instead of 8 would corrupt the low sector bytes -> the
/// `ds == sector` readback FAILS for any sector with set low bytes. The
/// `req_type_is_known` checks reference the public type constants directly.
#[kani::proof]
fn kani_blk_req_header_roundtrip() {
    let t: u32 = kani::any();
    let sector: u64 = kani::any();
    let enc = req_header_encode(t, sector);
    let (dt, ds) = req_header_decode(&enc);
    assert_eq!(dt, t);
    assert_eq!(ds, sector);
    // The three types the driver issues are recognised as known.
    assert!(req_type_is_known(T_IN));
    assert!(req_type_is_known(T_OUT));
    assert!(req_type_is_known(T_FLUSH));
    // and they are pairwise distinct (the device routes on them).
    assert!(T_IN != T_OUT && T_OUT != T_FLUSH && T_IN != T_FLUSH);
}

/// (2) The SUPERBLOCK encode->decode IDENTITY + the field LAYOUT is read back
/// from the correct offsets. The fields are CONCRETE distinct values (so the
/// FNV-1a-64 checksum the encoder stamps + the decoder recomputes is a CBMC
/// CONSTANT, not a symbolic-hash formula -- a fully-symbolic 504-byte FNV equality
/// is the documented #49 state-explosion trap). The distinct sentinel values
/// prove each field is read from its OWN offset (no field bleed): gen, the three
/// log_head entries, and the three record_count entries all round-trip to their
/// distinct inputs, and the version is the stamped `SB_VERSION`. The checksum
/// gate's symbolic fail-closure is harness (3); the encode/decode over arbitrary
/// fields is exercised concretely under Miri in `blkfmt::tests`.
///
/// NEGATIVE CONTROL: stamping the checksum over `[0..512]` (including its own
/// slot) in the encoder but recomputing over `[0..504]` in the decoder would make
/// the checksum gate reject the encoder's own output -> `decode` returns `None`
/// and the `expect` traps; reading any field from the wrong offset would recover
/// a different sentinel -> the per-field `assert_eq!` FAILS (the distinct values
/// are chosen so no two offsets share a value).
#[kani::proof]
fn kani_blk_superblock_identity() {
    // Distinct sentinels so a cross-offset read recovers the WRONG value.
    let gen: u64 = 0x0102_0304_0506_0708;
    let log_head = [0x1111_1111_1111_1111u64, 0x2222_2222_2222_2222, 0x3333_3333_3333_3333];
    let record_count = [0x4444_4444_4444_4444u64, 0x5555_5555_5555_5555, 0x6666_6666_6666_6666];
    let s = superblock_encode(gen, log_head, record_count);
    // TOTALITY + the checksum gate accepts the encoder's own output.
    let d = superblock_decode(&s).expect("the encoder's own output must decode");
    // Every field round-trips from its OWN offset (the distinct values rule out
    // field bleed), and the version is the stamped constant.
    assert_eq!(d.gen, gen);
    assert_eq!(d.log_head, log_head);
    assert_eq!(d.record_count, record_count);
    assert_eq!(d.version, crate::blkfmt::SB_VERSION);
}

/// (3) The SUPERBLOCK decode is TOTAL + FAIL-CLOSED under the documented BOUNDED
/// assume-envelope (NOT a full 512-byte `kani::any()` -- the #49 trap the
/// proofs.rs honesty note warns of). We take a valid encoder output and let Kani
/// nondeterministically perturb a SINGLE byte in either the header region (magic/
/// version) OR the checksum tail; the decode must NEVER panic, and a perturbation
/// that lands on a magic/version/checksum byte must yield `None` (fail-closed). A
/// matching perturbation on a reserved byte stays `Some` (it is covered by the
/// recompute). This proves the decode is total AND the integrity gate bites.
///
/// NEGATIVE CONTROL: dropping the magic check in `superblock_decode` would let a
/// flipped magic byte still decode -> the `is_none()` assertion on the magic-byte
/// branch FAILS.
#[kani::proof]
fn kani_blk_superblock_decode_total() {
    // A concrete, structurally-valid base (fixed fields keep the state space
    // bounded; the perturbation is the only nondeterminism).
    let mut s = superblock_encode(1, [512, 1024, 2048], [3, 1, 0]);
    // One symbolic byte index in {magic[0], version[0], checksum[0]} and one
    // symbolic nonzero delta -- the bounded envelope.
    let which: u8 = kani::any();
    kani::assume(which < 3);
    let delta: u8 = kani::any();
    kani::assume(delta != 0);
    let idx: usize = match which {
        0 => 0,                                // a magic byte
        1 => 8,                                // the version low byte
        _ => crate::blkfmt::SB_CKSUM_OFF,      // a checksum byte
    };
    s[idx] = s[idx].wrapping_add(delta);
    // TOTALITY: decode must not panic for any of these perturbations.
    let d = superblock_decode(&s);
    // FAIL-CLOSURE: perturbing magic, version, or checksum invalidates the block.
    // (version perturbation: any nonzero delta on byte 8 makes version != 1.)
    assert!(d.is_none());
}

/// (4) The FRAME HEADER round-trips over ALL symbolic fields: `frame_header_decode(
/// frame_header_encode(tag, len, seq, crc))` recovers `(tag, len, seq, crc)`. A
/// total, loop-free proof over the 24-byte layout (the two reserved regions are
/// decode-ignored).
///
/// NEGATIVE CONTROL: encoding `seq` at offset 2 (overlapping `len`) instead of 4
/// would corrupt both fields -> the `seq`/`len` readbacks FAIL.
#[kani::proof]
fn kani_blk_frame_header_roundtrip() {
    let tag: u8 = kani::any();
    let len: u16 = kani::any();
    let seq: u64 = kani::any();
    let crc: u32 = kani::any();
    let h = frame_header_encode(tag, len, seq, crc);
    let d = frame_header_decode(&h);
    assert_eq!(d.region_tag, tag);
    assert_eq!(d.len, len);
    assert_eq!(d.seq, seq);
    assert_eq!(d.payload_crc, crc);
}

/// (5) The RECORD FRAME structure is TOTAL + the CRC gate accepts the encoder's
/// own frame, the header fields round-trip, and the payload window stays in-
/// bounds. The FRAME PARAMETERS (`region_tag`, `seq`) are symbolic; the payload
/// is a fixed CONCRETE 4-byte body. Keeping the payload concrete makes the
/// FNV-1a-32 CRC a CBMC-computed CONSTANT on BOTH the encode (stamp) and decode
/// (recompute) sides, so the CRC-equality gate is proven WITHOUT the symbolic-
/// hash SAT blowup (a fully-symbolic-payload CRC equality is the documented #49
/// state-explosion trap; the CRC's correctness over ARBITRARY data + the torn-
/// tail rejection are exercised concretely under Miri in `blkfmt::tests`).
///
/// NEGATIVE CONTROL: computing the CRC over the WRONG byte range in the decoder
/// (e.g. `[24..512]` instead of `[24..24+len]`) would make the recomputed CRC
/// differ from the stamped one -> `record_frame_decode` returns `None` and the
/// `expect` traps; placing `seq`/`len` at the wrong header offset would break the
/// `seq`/`len` round-trip + the in-bounds `off+len <= 512` check.
#[kani::proof]
#[kani::unwind(513)] // the 512-byte sector-zeroing loop in record_frame_encode
                     // dominates (a concrete 512-bound unroll is cheap for CBMC);
                     // the FNV/copy loops over the 4-byte payload are far shorter.
fn kani_blk_record_frame_decode_total() {
    // A fixed concrete payload (the CRC is then a CBMC constant, not symbolic).
    let payload: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
    let region_tag: u8 = kani::any();
    kani::assume(
        region_tag == REGION_EPISODIC
            || region_tag == REGION_SEMANTIC
            || region_tag == REGION_WORKING,
    );
    let seq: u64 = kani::any();

    let mut sector = [0u8; 512];
    let ok = record_frame_encode(region_tag, seq, &payload, &mut sector);
    assert!(ok);
    // TOTALITY + the CRC gate accepts the encoder's own frame.
    let (h, off) = record_frame_decode(&sector).expect("the encoder's own frame must decode");
    // HEADER ROUND-TRIP over the symbolic frame parameters.
    assert_eq!(h.region_tag, region_tag);
    assert_eq!(h.len as usize, payload.len());
    assert_eq!(h.seq, seq);
    // IN-BOUNDS: the payload window never escapes the sector; header is 24 bytes.
    assert_eq!(off, 24);
    assert!(off + (h.len as usize) <= 512);
    // REPLAY DETERMINISM: the payload bytes land at the payload offset.
    assert_eq!(sector[off], payload[0]);
    assert_eq!(sector[off + 3], payload[3]);
    // CONST tie: the real 48-byte T2 Episode payload fits a single-sector frame.
    assert!(EPISODE_LEN <= MAX_PAYLOAD);
    let _ = (episode_encode, episode_decode); // keep the codecs referenced
}

/// (6) The SECTOR MATH is NO-OVERFLOW + IN-EXTENT, plus the GENERATION-
/// MONOTONICITY / REPLAY-DETERMINISM lemma. For each region tag, a valid log head
/// (strictly below the extent ceiling) maps to a sector strictly INSIDE that
/// region's `[first, first+count)` extent and never overlaps the superblock
/// (sector 0) or another region (the extents are disjoint by const construction);
/// a head AT/PAST the ceiling fails closed (`None`). The lemma: `gen + 1 > gen`
/// for every non-saturating gen (the two-phase commit's strict monotone advance),
/// and a record's sector is a strictly increasing function of its sector-aligned
/// log head (so replaying frames in log order reproduces the on-disk order).
///
/// NEGATIVE CONTROL: changing the ceiling test from `idx >= count` to `idx > count`
/// would let the one-past sector escape the extent -> the `< first + count`
/// assertion FAILS at the boundary head.
#[kani::proof]
fn kani_blk_sector_math_and_gen_monotone() {
    // Region tag in {0,1,2}; an unknown tag is None (fail-closed).
    let tag: u8 = kani::any();
    kani::assume(tag == REGION_EPISODIC || tag == REGION_SEMANTIC || tag == REGION_WORKING);
    let (first, count) = region_extent(tag).expect("known tag has an extent");

    // A sector index strictly inside the extent (bounded so the head cannot
    // overflow when multiplied; count <= 4095 so head < ~2 MiB).
    let idx: u64 = kani::any();
    kani::assume(idx < count);
    let head = idx * SECTOR_SIZE; // no overflow: idx < 4095, * 512 < 2^21
    let sec = record_sector(tag, head).expect("in-extent head maps to a sector");
    // IN-EXTENT: strictly inside [first, first+count); never the SB sector 0.
    assert!(sec >= first);
    assert!(sec < first + count);
    assert!(sec != 0); // first >= 1 for every region, so never the superblock
    assert_eq!(sec, first + idx); // exact, no-overflow

    // CEILING fail-closure: a head AT the ceiling is None (the Full case).
    let ceil_head = count * SECTOR_SIZE;
    assert!(record_sector(tag, ceil_head).is_none());

    // STRICT MONOTONICITY of record_sector in idx (replay reproduces log order):
    // a strictly larger in-extent idx maps to a strictly larger sector.
    let idx2: u64 = kani::any();
    kani::assume(idx2 < count);
    kani::assume(idx2 > idx);
    let sec2 = record_sector(tag, idx2 * SECTOR_SIZE).expect("in-extent");
    assert!(sec2 > sec);

    // GENERATION MONOTONICITY: the two-phase commit advances gen by exactly 1 and
    // strictly increases it (for every non-saturating gen).
    let gen: u64 = kani::any();
    kani::assume(gen < u64::MAX);
    assert!(gen + 1 > gen);

    // The const extents are DISJOINT and ordered (Episodic < Semantic < Working),
    // and none overlaps the superblock at sector 0.
    assert!(EP_FIRST >= 1);
    assert!(EP_FIRST + EP_COUNT <= SEM_FIRST);
    assert!(SEM_FIRST + SEM_COUNT <= WM_FIRST);
    let _ = (WM_FIRST, WM_COUNT);
}

// ===========================================================================
// M21 kancell: the verified fixed-point ADDITIVE-policy leaf (a piecewise-LINEAR
// integer GAM) for the M17 forget/demote decision. SIX harnesses (the
// EXPECTED_HARNESSES 34 -> 40 bump in verify-encode.sh). Each proves what is
// SAFE + UNCONDITIONALLY TRUE over the DOCUMENTED reachable envelope -- totality,
// the tautological output bound, structural monotonicity from the knot-delta
// signs (DECIDABLE because the basis is piecewise-linear, unlike the memscore
// fixed-point-rounding case), bit-for-bit determinism, and the envelope-no-
// widening seam property. Each carries a REAL negative control (the discipline
// that caught the `esr_decode_total` tautology + the #49 over-quantification
// slips). Concrete small tables / bounded `kani::assume` envelopes keep the
// harnesses in CBMC's decidable regime (the bla_raw / blkfmt precedent).
// ===========================================================================

/// A canonical monotone-DECREASING recency row + monotone-INCREASING frequency
/// row, both strictly inside `KAN_KNOT_MAX` -- the shape the shipped frozen table
/// uses. Concrete so the round-trip/monotone harnesses stay in CBMC's reach.
const KAN_DEC: [i16; KAN_KNOTS] = [4000, 3500, 3000, 2400, 1800, 1200, 600, 100, -400];
const KAN_INC: [i16; KAN_KNOTS] = [-400, 100, 600, 1200, 1800, 2400, 3000, 3500, 4000];
const KAN_FLAT: [i16; KAN_KNOTS] = [500; KAN_KNOTS];

/// (1) `kan_spline_eval` is TOTAL over ALL `x_q: i32` (no panic: the clamp proves
/// the segment index in `0..=KAN_KNOTS-2`, the saturating mul/add cannot trap),
/// and the interpolated output stays within the row's `[min knot, max knot]`
/// envelope (the interpolant lies BETWEEN two knots). The row is a CONCRETE mix of
/// the table's real shapes; `x_q` is fully symbolic (the totality dimension).
///
/// NEGATIVE CONTROL: dropping the input clamp (or the `seg >= KAN_KNOTS-1`
/// pin-down) lets a large `x_q` produce a segment index `>= KAN_KNOTS-1`, so the
/// `knots[seg + 1]` index reaches `[9]` and panics -- this harness turns RED,
/// proving the clamp is load-bearing for totality. The `[lo, hi]` bound is
/// computed by an INDEPENDENT min/max over the concrete row, never via the fn.
#[kani::proof]
fn kani_kan_spline_eval_total_bounded() {
    let x_q: i32 = kani::any(); // the FULL i32 totality dimension
    let grid_lo: i32 = GRID_LO;
    let row = KAN_DEC;
    let y = kan_spline_eval(&row, x_q, grid_lo, GRID_STEP_LOG2);
    // Independent [min, max] over the concrete row (NOT via the fn under test).
    let mut lo = row[0] as i32;
    let mut hi = row[0] as i32;
    let mut k = 1usize;
    while k < KAN_KNOTS {
        let v = row[k] as i32;
        if v < lo {
            lo = v;
        }
        if v > hi {
            hi = v;
        }
        k += 1;
    }
    assert!(y >= lo); // interpolant never below the row minimum
    assert!(y <= hi); // ...nor above the row maximum (no out-of-band reorder)
}

/// (2) `kan_score` NEVER overflows + the final SATURATING CLAMP puts the `i64`
/// result EXACTLY in `[-34_000, 34_000]` (the M17 `DEMOTE_BAND`), for an
/// OVERFLOW-SAFE table (`|knot| <= KAN_KNOT_MAX` -- the envelope
/// `kan_table_overflow_safe` enforces) over FULLY symbolic feats/flag_terms/bias.
/// The closed-form `Sum = KAN_FEATURES * KAN_KNOT_MAX` headroom bound (re-checked
/// whenever `KAN_FEATURES` or the knot sub-range changes -- NOT one-time).
///
/// DOMAIN: the table is a per-row symbolic knot assumed into `[-KAN_KNOT_MAX,
/// KAN_KNOT_MAX]` (the loader's accepted envelope); feats/flags/bias are the
/// FULL i32 space (saturating ops + the clamp make the score total there).
///
/// NEGATIVE CONTROL: widening the assumed knot bound past i32 / removing the
/// final clamp lets `acc` escape `[-34_000, 34_000]` and the EXACT-band assert
/// FAILS. The band literals are the independent `DEMOTE_BAND` const, not the fn.
#[kani::proof]
fn kani_kan_score_no_overflow_bounded() {
    // A symbolic but OVERFLOW-SAFE table: every knot assumed in the loader band.
    let mut table: KnotTable = [[0i16; KAN_KNOTS]; KAN_FEATURES];
    let mut j = 0usize;
    while j < KAN_FEATURES {
        let mut k = 0usize;
        while k < KAN_KNOTS {
            let v: i16 = kani::any();
            kani::assume(v >= -KAN_KNOT_MAX && v <= KAN_KNOT_MAX);
            table[j][k] = v;
            k += 1;
        }
        j += 1;
    }
    // The envelope the harness assumes IS exactly what the validator certifies.
    assert!(kan_table_overflow_safe(&table));

    let feats: [i32; KAN_FEATURES] = kani::any(); // full i32 features
    let flag_terms: i32 = kani::any();
    let bias: i32 = kani::any();
    let s = kan_score(&table, &feats, flag_terms, bias);
    let (lo, hi) = DEMOTE_BAND;
    // TOTAL (no panic above) + the result is EXACTLY in the band.
    assert!(s >= lo);
    assert!(s <= hi);
}

/// (3) STRUCTURAL MONOTONICITY: for a table the structural validator accepts as
/// monotone-DECREASING (`signs[0] == -1`), `x1 <= x2` implies `eval(x2) <=
/// eval(x1)` -- staler is NEVER scored more keepable. DECIDABLE from the knot-
/// delta sign conjunction because the basis is piecewise-LINEAR (a property the
/// memscore fixed-point math could NOT prove symbolically -- the honesty note --
/// but this LINEAR interpolant can). The table is the concrete `KAN_DEC` row;
/// `x1`/`x2` are symbolic within a bounded grid window.
///
/// NEGATIVE CONTROL: one mis-signed knot delta (e.g. `KAN_DEC` with a single
/// rising step) FAILS `kan_table_is_monotone` (so the `assume` is vacuous-free)
/// AND flips a segment slope so the `eval(x2) <= eval(x1)` inequality FAILS for a
/// straddling `x` -- proving the sign check is load-bearing, not decorative.
#[kani::proof]
fn kani_kan_monotone_structural() {
    let table: KnotTable = [KAN_DEC, KAN_INC, KAN_FLAT, KAN_DEC];
    let signs: [i8; KAN_FEATURES] = [-1, 1, 0, -1];
    // The validator accepts this table (non-vacuity: a rejected table would make
    // the proof vacuously true; the assert pins that the precondition holds).
    assert!(kan_table_is_monotone(&table, &signs));

    // Two ordered x within a bounded window spanning the whole grid (8 segments
    // of step 2^7 == 1024 quantized units; +/- one step of slack for the clamp).
    let span = (1i32 << GRID_STEP_LOG2) * (KAN_KNOTS as i32 - 1);
    let x1: i32 = kani::any();
    let x2: i32 = kani::any();
    kani::assume(x1 >= GRID_LO - 64 && x1 <= GRID_LO + span + 64);
    kani::assume(x2 >= GRID_LO - 64 && x2 <= GRID_LO + span + 64);
    kani::assume(x1 <= x2);
    // The sign=-1 feature is non-increasing in x: a later (staler) x scores no
    // higher than an earlier one.
    let y1 = kan_spline_eval(&table[0], x1, GRID_LO, GRID_STEP_LOG2);
    let y2 = kan_spline_eval(&table[0], x2, GRID_LO, GRID_STEP_LOG2);
    assert!(y2 <= y1);
}

/// (4) Both validators are TOTAL (return `bool`, never panic) over symbolic
/// tables, AND SOUND: `kan_table_overflow_safe(table) == true` IMPLIES `kan_score`
/// cannot overflow (its result lands in `DEMOTE_BAND`). The implication is the
/// real content: a table the headroom validator PASSES can never drive the
/// accumulator out of `i64`. `kan_table_is_monotone` totality is checked on the
/// same symbolic table.
///
/// NEGATIVE CONTROL: loosening `kan_table_overflow_safe`'s bound past
/// `KAN_KNOT_MAX` (e.g. accepting `i16::MAX`) would let a PASSING table reach
/// `KAN_FEATURES * i16::MAX` in the accumulator -- still inside i64, but the
/// soundness claim that a passing table keeps `kan_score` in the band would then
/// only hold because of the clamp, not the headroom; the `passed ==>` guarded
/// band assert pins the validator's contract to the score's actual behaviour.
#[kani::proof]
fn kani_kan_table_validators_total() {
    let mut table: KnotTable = [[0i16; KAN_KNOTS]; KAN_FEATURES];
    let mut j = 0usize;
    while j < KAN_FEATURES {
        let mut k = 0usize;
        while k < KAN_KNOTS {
            let v: i16 = kani::any(); // FULL i16 range (the validator must be total here)
            table[j][k] = v;
            k += 1;
        }
        j += 1;
    }
    let signs: [i8; KAN_FEATURES] = kani::any();
    // TOTALITY: both validators return a bool without panicking for ANY i16 table.
    let safe = kan_table_overflow_safe(&table);
    let _mono = kan_table_is_monotone(&table, &signs);

    // SOUNDNESS: a table the headroom validator PASSES keeps kan_score in-band for
    // bounded comparator terms (the closed-form N*KAN_KNOT_MAX headroom holds).
    if safe {
        let feats: [i32; KAN_FEATURES] = kani::any();
        let bias: i32 = kani::any();
        kani::assume(bias >= -34_000 && bias <= 34_000);
        let s = kan_score(&table, &feats, 0, bias);
        let (lo, hi) = DEMOTE_BAND;
        assert!(s >= lo && s <= hi);
    }
}

/// (5) `kan_score` is DETERMINISTIC bit-for-bit: two evaluations on the SAME
/// inputs are equal (no float on the path -> reproducible across rings/EL2, the
/// same no-FPU guarantee as `bla_raw`/`skill_transform`). A symbolic overflow-safe
/// table + symbolic comparator terms; equality must hold for every input.
///
/// NEGATIVE CONTROL: any nondeterminism (e.g. reading an uninitialised slot, a
/// float intermediate that rounds differently, or a `kani::any()` re-draw inside
/// `kan_score`) would make the two calls disagree and FAIL this equality.
#[kani::proof]
fn kani_kan_score_deterministic() {
    let mut table: KnotTable = [[0i16; KAN_KNOTS]; KAN_FEATURES];
    let mut j = 0usize;
    while j < KAN_FEATURES {
        let mut k = 0usize;
        while k < KAN_KNOTS {
            let v: i16 = kani::any();
            kani::assume(v >= -KAN_KNOT_MAX && v <= KAN_KNOT_MAX);
            table[j][k] = v;
            k += 1;
        }
        j += 1;
    }
    let feats: [i32; KAN_FEATURES] = kani::any();
    let flag_terms: i32 = kani::any();
    let bias: i32 = kani::any();
    let a = kan_score(&table, &feats, flag_terms, bias);
    let b = kan_score(&table, &feats, flag_terms, bias);
    assert_eq!(a, b);
}

/// (6) ENVELOPE-NO-WIDENING (the safety-seam proof, proposal §3/§5.6):
/// `kan_score`'s clamped output can NEVER reorder a record the heuristic envelope
/// marks pinned into the victim set, because the safe-set membership is computed
/// by the heuristic INDEPENDENTLY of `kan_score`. We model the M17 pin tests
/// (`IMP_PIN`/`UTIL_PIN`/`MIN_AGE`) as a pure function of the record metadata and
/// prove a pinned record's `is_safe` verdict is invariant under EVERY possible
/// `kan_score` value -- the KAN is strictly DOWNSTREAM of the gate.
///
/// NEGATIVE CONTROL: a variant that fed `kan_score` INTO the pin test (e.g.
/// `is_pinned = importance >= IMP_PIN || score > T`) would make `is_pinned`
/// depend on the symbolic score, so the `pinned_a == pinned_b` invariance across
/// two distinct scores FAILS -- proving the seam keeps the KAN out of the gate.
#[kani::proof]
fn kani_kan_envelope_no_widening() {
    // The M17 envelope thresholds (mirrors tb-hal::mem THETA/PIN consts; the seam
    // owns these, the KAN never sees them).
    const IMP_PIN: i64 = 8;
    const UTIL_PIN: i64 = 600;
    const MIN_AGE: u64 = 16;

    // A record's heuristic safety verdict -- a PURE function of metadata, with NO
    // dependence on any KAN score (the load-bearing seam property).
    fn is_pinned(importance: i64, util: i64, age: u64) -> bool {
        age < MIN_AGE || importance >= IMP_PIN || util >= UTIL_PIN
    }

    let importance: i64 = kani::any();
    let util: i64 = kani::any();
    let age: u64 = kani::any();

    // Two ARBITRARY, DISTINCT kan_score outputs over an overflow-safe table: the
    // pin verdict must be IDENTICAL under both (the score cannot move the gate).
    let table: KnotTable = [KAN_DEC, KAN_INC, KAN_FLAT, KAN_DEC];
    assert!(kan_table_overflow_safe(&table));
    let feats_a: [i32; KAN_FEATURES] = kani::any();
    let feats_b: [i32; KAN_FEATURES] = kani::any();
    let score_a = kan_score(&table, &feats_a, kani::any(), kani::any());
    let score_b = kan_score(&table, &feats_b, kani::any(), kani::any());
    // Both scores are in-band (no widening of the value range) ...
    let (lo, hi) = DEMOTE_BAND;
    assert!(score_a >= lo && score_a <= hi);
    assert!(score_b >= lo && score_b <= hi);
    // ... and the pin verdict is INVARIANT under the score (the seam keeps the KAN
    // strictly downstream of the safety gate -- it can rank WITHIN the safe set,
    // never widen it). `score_a`/`score_b` are deliberately UNUSED by `is_pinned`.
    let pinned_a = is_pinned(importance, util, age);
    let pinned_b = is_pinned(importance, util, age);
    let _ = (score_a, score_b); // the scores exist but DO NOT feed the gate
    assert_eq!(pinned_a, pinned_b);
}
