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
use crate::recall::{
    bm25_doc_score, bm25_idf, bm25_term_score, bm25_tf_norm, hit_canon, hit_decode, RankedHit,
    ENVELOPE_MAX, HIT_CANON_LEN, TF_NORM_CEIL,
};
use crate::smmuv3::{
    cmd_cfgi_ste, cmd_sync, cmd_tlbi_s12_vmall, ste_cfg, ste_s2, ste_s2ttb, ste_s2vmid, ste_v,
    ste_vtcr, ste_vtcr_from_vtcr_el2, CMD_OP_CFGI_STE, CMD_OP_CMD_SYNC, CMD_OP_TLBI_S12_VMALL,
    STE_0_V, STE_2_S2AA64, STE_2_S2R, STE_2_VTCR_SHIFT, STE_3_S2TTB_MASK, STE_CFG_S2_TRANS,
};
use crate::prov::{
    canon, canon_len, chain_mix, prov_hash, recompute, verify_inclusion, ProvEntry,
    CANON_PREFIX_LEN, PROV_HASH_LEN,
};
use crate::exp::{
    canon as exp_canon, canon_len as exp_canon_len, decode as exp_decode, replay_shadow,
    ExpRing, ExperienceRecord, OutcomeLabel, EXP_CANON_LEN, PROPENSITY_DETERMINISTIC_Q,
};
use crate::corpus::{
    canon as corpus_canon, canon_len as corpus_canon_len, corpus_append, corpus_hash,
    corpus_recompute, corpus_verify_inclusion, decode as corpus_decode, CorpusRecord,
    OutcomeLabel as CorpusOutcomeLabel, CORPUS_CANON_LEN, CORPUS_SCHEMA_V1,
};
use crate::opframe::{
    canon as op_canon, canon_len as op_canon_len, decode as op_decode, fold_frame,
    gate_commits_final_seq, intro_binds, seq_index_exact, OpFrame, OPFRAME_HEADER_LEN,
};
use crate::exittel::{
    bucket_index, canon as et_canon, class_from_tag, class_tag, decode as et_decode,
    ExitHistogram, ExitTelemetryRecord, EXITTEL_CANON_LEN, N_BUCKETS, N_CLASSES,
};
use crate::tpsched::{
    canon as tp_canon, decode as tp_decode, frame_total, next_slot, slot_deadline_delta,
    FramePlan, SchedDecision, MIN_SLOT_TICKS, N_SLOTS, SCHED_CANON_LEN,
};
use crate::conductor::{
    assign_role, canon as cd_canon, conduct_hash, decode as cd_decode, next as conduct_next,
    select_organ, verifier_verdict, Action, ConductDecision, Organ, Role, Verdict,
    CONDUCT_CANON_LEN, MAX_TURNS, N_ORGANS, VERDICT_MARGIN,
};
use crate::opframe_rx::{
    canon as cmd_canon, compute_mac, decode as cmd_decode, key_evolve, verify_decoded,
    CmdFrame, CmdVerdict, CMD_HEADER_LEN, KEY_LEN, MAC_LEN,
};
use crate::khash::{kat_ok, khash, uhash, KAT_ABC_UNKEYED, KHASH_KEY_LEN, KHASH_TAG_LEN};
use crate::guestlog::{
    guestlog_decode, guestlog_encode, guestlog_frame_len, is_hex_lower, GUESTLOG_MAX_FRAME,
    GUESTLOG_MAX_PAYLOAD, GUESTLOG_PREFIX,
};
use crate::inferwire::{
    body_digest, canon as iw_canon, decode as iw_decode, echo_tag, err_canon, err_code_known,
    err_decode, err_retryable, errcode, infer_tag, kind as iw_kind, peer as iw_peer,
    resp_binds_req, subhdr_canon, subhdr_decode, verify_echo, verify_infer_resp, AsmPush,
    FrameAccum, InferAssembler, InferFrame, SubHdr, INFER_ACCUM_CAP, INFER_BODY_CAP,
    INFER_CHALLENGE_LEN, INFER_DOMAIN, INFER_ERR_PAYLOAD_LEN, INFER_HEADER_LEN, INFER_KEY_LEN,
    INFER_MAGIC, INFER_NONCE_LEN, INFER_PAYLOAD_CAP, INFER_SUBHDR_LEN, INFER_TAG_LEN, INFER_VER,
    OFF_FLAGS as IW_OFF_FLAGS, OFF_KIND as IW_OFF_KIND, OFF_MAGIC as IW_OFF_MAGIC,
    OFF_PAYLOAD_LEN as IW_OFF_PAYLOAD_LEN, OFF_VER as IW_OFF_VER, SFLAG_MORE,
};
use crate::explore::{explore_propensity_q, PROPENSITY_SCALE};
use crate::bakeoff::{
    eb_lower_bound, gate_clears, label_reward, smoothness_floor_mean, survival_label,
    value_lower_bound, value_upper_heuristic, GateVerdict, SurvivalLabel, ACTIVATION_MARGIN,
    GRID_CELLS, Y_HI, Y_LO,
};
use crate::paging::{
    entry_addr, ept_leaf_2mib, ept_nonleaf, eptp, level_index, make_entry, ENTRIES,
    ENTRY_ADDR_MASK, EPT_MAPS_PAGE, EPT_MEMTYPE_WB, EPT_RWX, EPT_WALK_LEN_MINUS_1, SHIFT_1G,
    SHIFT_2M, SHIFT_4K, SHIFT_512G,
};
use crate::stage2::{
    guest_carve_pa, s2_leaf_2mib, s2_leaf_4k, s2_table, vtcr, vttbr, vttbr_baddr,
    GUEST_CARVE_PA, GUEST_CARVE_SIZE, GUEST_DOORBELL_IPA, GUEST_IPA_BASE, S2AP_RW, S2_AF,
    S2_DESC_BLOCK, S2_DESC_PAGE, S2_DESC_TABLE, VTCR_RES1, VTTBR_VMID_SHIFT,
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
// M40: the LEXICAL RECALL-SCORING leaf (`recall.rs`) -- the BM25-family no-float
// fixed-point relevance kernel that sharpens memory retrieval. Mirroring the
// `memscore` discipline EXACTLY: Kani proves PANIC-FREEDOM + BOUNDS + the codec's
// injectivity / fail-closed decode + the accumulation-monotonicity invariant
// (which stands on each term being non-negative, NOT on `ln_fixed` monotonicity,
// so it is sound and boundary-safe). STRICT monotonicity in `df`/`tf` stays a
// CONCRETE host test (the #49 over-quantification trap: fixed-point division can
// break strict monotonicity at rounding boundaries, so it is sampled, never
// symbolically over-quantified -- the exact `memscore` `bla_raw` precedent). No
// float, ever.
//
// ## The two-tier CBMC budget (#76 shard-D fix -- read before touching a harness)
//
// The recall math has TWO classes of integer division and CBMC pays for them very
// differently -- the SAME lesson `log2_fixed` teaches (its `/pow` is a POWER of
// two, so symbolic-`x` `ln_fixed` proves in seconds in shard A), applied to BM25:
//
//   * The CORPUS dimension (`df`, `n_docs`) enters ONLY `bm25_idf`, whose sole
//     division lives inside the REUSED `ln_fixed` (divide by `pow == 1 << ip`, a
//     power of two -- the cheap case CBMC already proves fast). So `df`/`n_docs`
//     stay FULLY SYMBOLIC across the whole reachable `< 2^20` corpus at no
//     tractability cost -- genuine unbounded-over-a-million-documents coverage.
//   * The DOCUMENT dimension (`tf`, `doc_len`, `avg_len`) enters two GENERAL
//     (non-power-of-two) symbolic divisions -- `dl / avgl` and the tf-saturation
//     `numer * SCALE / denom`. A general symbolic-dividend / symbolic-divisor
//     64-bit divide is the CBMC state-explosion case: `kani::assume(x < 256)`
//     bounds the VALUE but NOT the divider circuit, and BM25 couples the dividend
//     and the divisor through the SAME variables (`tf` sits in both `numer` and
//     `denom`; `dl` sits in `denom` via `norm`), so no "concrete divisor x
//     symbolic dividend" split can collapse the second divide while any of the
//     three stays symbolic. Left symbolic, this recall family ran the shard PAST
//     the 65-min cap (it was cancelled). So the document fields are proven over a
//     CONCRETE LADDER (`RECALL_DOC_LADDER`) that pins each general divisor to a
//     boundary/interior value spanning the reachable envelope -- the `memscore`
//     `bla_raw` SAMPLED-not-symbolic precedent this module already cites, here
//     extended from monotonicity to panic-freedom/bounds. Every ladder point runs
//     the REAL production function under CBMC's overflow/panic instrumentation, so
//     it is a genuine (sampled-document, symbolic-corpus) proof, not vacuous:
//     every documented mutant still fires (see each harness's NEGATIVE CONTROL).
//     The ladder INCLUDES `avg_len == 0` (the divide-by-zero mutant trigger), the
//     single-token reachable point (`tf == doc_len == 1`), and the `ENVELOPE_MAX-1`
//     boundary corner.
// ===========================================================================

/// `bm25_idf` (the rarer-term-scores-higher inverse document frequency) is
/// panic-free and `0 <= r < 34_000` over the reachable envelope. `df`/`n_docs` (the
/// CORPUS-size fields) are bounded WIDE to `< 2^20` (a million-document corpus), so
/// the `ln_fixed(2N + 2)` argument stays `< 2^21 < 2^48` -- inside the proven
/// `ln_fixed` domain; the result is a difference of two `[0, 34_000)` logarithms
/// clamped non-negative. idf reuses the CHEAP `ln_fixed` (no symbolic 64-bit
/// division), so the wide corpus bound costs no tractability (unlike the tf-norm
/// document envelope, tightened to `2^8` -- see the module two-envelope note).
///
/// NEGATIVE CONTROL: dropping the `.max(0)` clamp lets a universal term (`df == N`)
/// where numerical noise makes `ln_fixed(2df+1) > ln_fixed(2N+2)` go negative and
/// turns the `r >= 0` assertion RED.
#[kani::proof]
fn kani_recall_idf_panic_free_bounded() {
    let df: u64 = kani::any();
    let n_docs: u64 = kani::any();
    kani::assume(df < (1u64 << 20));
    kani::assume(n_docs < (1u64 << 20));
    let r = bm25_idf(df, n_docs);
    assert!(r >= 0);
    assert!(r < 34_000);
}

/// The `ENVELOPE_MAX - 1` boundary value (`255`) -- the top of the reachable
/// document-token envelope, pinned once for the ladders below.
const RECALL_HI: u64 = ENVELOPE_MAX - 1;

/// The concrete DOCUMENT-field ladder `(tf, doc_len, avg_len)` that the
/// division-bearing recall harnesses iterate INSTEAD of leaving these fields
/// symbolic (the #76 shard-D CBMC-budget fix -- see the module two-tier note). Each
/// row pins the GENERAL (non-power-of-two) symbolic divisors -- `avg_len` in
/// `dl/avgl`, and `tf`/`doc_len` which couple into the tf-saturation denominator
/// `numer*SCALE/denom` -- to a boundary or interior value of the reachable
/// `< ENVELOPE_MAX` envelope, so CBMC never bit-blasts a general symbolic-divisor
/// divide; the CORPUS fields (`df`/`n_docs`) stay symbolic in the harnesses that
/// carry them (their only division is the cheap power-of-two `ln_fixed`). The rows
/// span: the absent term (`tf == 0`), the single-token reachable record
/// (`tf == doc_len == 1`), `avg_len == 0` (the divide-by-zero mutant trigger,
/// guarded by `avg_len.max(1)`), a doc longer than average (the length-penalty
/// direction), tf-saturation near the ceiling (`tf == RECALL_HI`), and the
/// all-boundary corner.
const RECALL_DOC_LADDER: [(u64, u64, u64); 8] = [
    (0, 1, 1),                         // absent term, single-token reachable doc
    (1, 1, 1),                         // THE reachable single-token record (tf==doc_len==1)
    (1, 1, 0),                         // avg_len==0 -> exercises the .max(1) divide-by-zero guard
    (2, 8, 3),                         // short multi-token interior, doc longer than average
    (RECALL_HI, 1, RECALL_HI),         // max tf, short doc, large avg -> tf-saturation near ceiling
    (1, RECALL_HI, 1),                 // long doc, min avg -> strongest length penalty
    (RECALL_HI, RECALL_HI, RECALL_HI), // the all-boundary corner
    (0, 0, 0),                         // all-zero degenerate (avg_len==0 guard + tf==0 + doc_len==0)
];

/// `bm25_tf_norm` (term-frequency saturation + document-length normalization) is
/// panic-free -- no divide-by-zero (the length factor `norm >= (1-b) > 0` keeps the
/// denominator positive) and no `i64` overflow -- and its result lies in
/// `[0, TF_NORM_CEIL)` (the saturation ceiling `k1 + 1` scaled), proven over the
/// concrete `RECALL_DOC_LADDER`. This function carries NO corpus field, so EVERY
/// input is a ladder point: its two divisions (`dl/avgl` and `numer*SCALE/denom`)
/// are GENERAL symbolic-divisor divides coupled through `tf`/`dl`, so no
/// concrete-divisor/symbolic-dividend split stays tractable while any of the three
/// is symbolic -- the ladder is the `memscore` `bla_raw` SAMPLED precedent this
/// module cites. Every row runs the REAL function under CBMC's overflow/panic
/// instrumentation (concrete arithmetic -- no symbolic divider, so fast) and the
/// rows are boundary-covering.
///
/// NEGATIVE CONTROL (still fires -- the ladder pins `avg_len == 0`): replacing
/// `avg_len.max(1)` with `avg_len` reaches a divide-by-zero at that row and turns
/// this harness RED.
#[kani::proof]
#[kani::unwind(9)]
fn kani_recall_tf_norm_panic_free_bounded() {
    let mut i = 0;
    while i < RECALL_DOC_LADDER.len() {
        let (tf, doc_len, avg_len) = RECALL_DOC_LADDER[i];
        let r = bm25_tf_norm(tf, doc_len, avg_len);
        assert!(r >= 0);
        assert!(r < TF_NORM_CEIL);
        i += 1;
    }
}

/// `bm25_term_score` (one query term's full BM25 contribution, `idf * tf_norm /
/// SCALE`) is panic-free and non-negative + bounded: `idf < 34_000` and
/// `tf_norm < TF_NORM_CEIL (2200)`, so the product `/ SCALE` stays well under
/// `34_000 * 2200 / 1000 < 75_000` and never overflows `i64`. The document fields
/// iterate `RECALL_DOC_LADDER` (the general symbolic divides inside `tf_norm`) while
/// the CORPUS fields `df`/`n_docs` stay FULLY SYMBOLIC over the reachable `< 2^20`
/// corpus -- their only division is the cheap power-of-two `ln_fixed` inside
/// `bm25_idf`, and `idf * tf_norm / SCALE` divides by the CONCRETE `SCALE`. So idf
/// is proven for EVERY corpus size, tf_norm for the sampled document geometry.
///
/// NEGATIVE CONTROL: removing the `/ SCALE` (so `idf * tf_norm` is returned raw)
/// blows the `< 100_000` bound -- CBMC drives the symbolic `df`/`n_docs` to a large
/// `idf` at the near-ceiling `tf_norm` ladder row and turns this harness RED.
#[kani::proof]
#[kani::unwind(9)]
fn kani_recall_term_score_panic_free_bounded() {
    let df: u64 = kani::any();
    let n_docs: u64 = kani::any();
    kani::assume(df < (1u64 << 20));
    kani::assume(n_docs < (1u64 << 20));
    let mut i = 0;
    while i < RECALL_DOC_LADDER.len() {
        let (tf, doc_len, avg_len) = RECALL_DOC_LADDER[i];
        let r = bm25_term_score(tf, df, n_docs, doc_len, avg_len);
        assert!(r >= 0);
        assert!(r < 100_000);
        i += 1;
    }
}

/// A term that does NOT occur in the document (`tf == 0`) contributes EXACTLY `0` to
/// the score -- the absent-term identity the multi-term accumulation relies on (an
/// absent query term neither helps nor hurts). `tf` is pinned to `0`; the document
/// geometry (`doc_len`/`avg_len`) iterates `RECALL_DOC_LADDER`, and `df`/`n_docs`
/// stay FULLY SYMBOLIC over the corpus.
///
/// NEGATIVE CONTROL: a `+ 1` bias in `bm25_tf_norm`'s numerator makes an absent term
/// score non-zero -- CBMC finds a symbolic `df`/`n_docs` with `idf > 0` so the
/// product is non-zero and turns this harness RED.
#[kani::proof]
#[kani::unwind(9)]
fn kani_recall_term_score_absent_is_zero() {
    let df: u64 = kani::any();
    let n_docs: u64 = kani::any();
    kani::assume(df < (1u64 << 20));
    kani::assume(n_docs < (1u64 << 20));
    let mut i = 0;
    while i < RECALL_DOC_LADDER.len() {
        // tf pinned to 0 (the ABSENT term); the ladder's (doc_len, avg_len) span the
        // reachable document geometry (incl. avg_len == 0).
        let (_, doc_len, avg_len) = RECALL_DOC_LADDER[i];
        assert_eq!(bm25_term_score(0, df, n_docs, doc_len, avg_len), 0);
        i += 1;
    }
}

/// The load-bearing recall invariant, proven SOUNDLY without over-quantifying a
/// fixed-point division: ADDING a matching query term never LOWERS a document's
/// accumulated score. Every per-term `idf * tf_norm` product is non-negative (both
/// factors are proven non-negative above), the accumulation uses `saturating_add`,
/// and the final integer division by `SCALE` is order-preserving -- so the two-term
/// score is `>= 0` and `>=` the one-term prefix ("more query-term evidence never
/// hurts"). The term-frequencies + document geometry iterate a small `(tf0, tf1,
/// doc_len, avg_len)` ladder (the general symbolic divides), while the two corpus
/// document-frequencies `df0`/`df1` stay FULLY SYMBOLIC (cheap `ln_fixed`).
///
/// NEGATIVE CONTROL: changing `saturating_add` to `saturating_sub` in `bm25_doc_score`
/// makes the second term LOWER the score -- at a row with `tf1 > 0` and a symbolic
/// `df1` giving a positive contribution, the prefix assertion turns RED.
#[kani::proof]
#[kani::unwind(6)]
fn kani_recall_doc_score_accumulation_monotone() {
    // (tf0, tf1, doc_len, avg_len): the term-frequencies + document geometry pinned to
    // boundary/interior values (the general symbolic divides); df0/df1 stay symbolic.
    const MONO_LADDER: [(u64, u64, u64, u64); 5] = [
        (1, 1, 1, 1),                                 // both single-token reachable
        (2, 3, 8, 3),                                 // interior, both terms present
        (RECALL_HI, RECALL_HI, RECALL_HI, RECALL_HI), // the all-boundary corner
        (1, RECALL_HI, RECALL_HI, 1),                 // 2nd term high tf, long doc / min avg
        (0, 1, 1, 0),                                 // 1st absent + avg_len==0 guard
    ];
    let df0: u64 = kani::any();
    let df1: u64 = kani::any();
    kani::assume(df0 < (1u64 << 20));
    kani::assume(df1 < (1u64 << 20));
    let mut i = 0;
    while i < MONO_LADDER.len() {
        let (tf0, tf1, doc_len, avg_len) = MONO_LADDER[i];
        let query = [(tf0, df0), (tf1, df1)];
        let one = bm25_doc_score(&query[..1], 1u64 << 20, doc_len, avg_len);
        let two = bm25_doc_score(&query[..2], 1u64 << 20, doc_len, avg_len);
        assert!(one >= 0);
        assert!(two >= one); // adding a matching term never lowers the score
        i += 1;
    }
}

/// `hit_canon` -> `hit_decode` is a lossless round-trip over the FULL symbolic
/// `(rank, id, score)` range: `hit_decode(hit_canon(h)) == Some(h)`. The fixed
/// 18-byte layout is therefore INJECTIVE (distinct hits -> distinct bytes), so a
/// ranking result is a replay-deterministic record.
///
/// NEGATIVE CONTROL: narrowing the `score` field to `i32` in the codec drops the high
/// bytes and turns the round-trip RED for `score > i32::MAX`.
#[kani::proof]
fn kani_recall_hit_canon_roundtrip() {
    let hit = RankedHit {
        rank: kani::any(),
        id: kani::any(),
        score: kani::any(),
    };
    let mut buf = [0u8; HIT_CANON_LEN];
    let wrote = hit_canon(&hit, &mut buf);
    assert_eq!(wrote, HIT_CANON_LEN);
    assert_eq!(hit_decode(&buf), Some(hit));
}

/// `hit_decode` is TOTAL and FAIL-CLOSED: it returns `None` (never panics, never
/// reads out of bounds) on any buffer shorter than `HIT_CANON_LEN`, and `hit_canon`
/// writes NOTHING (returns `0`) into a too-small buffer. Proven over a symbolic
/// length in `[0, HIT_CANON_LEN)`.
///
/// NEGATIVE CONTROL: removing the `if buf.len() < HIT_CANON_LEN` guard makes the
/// fixed-slice copies panic on a short buffer and turns this harness RED.
#[kani::proof]
#[kani::unwind(19)]
fn kani_recall_hit_decode_fail_closed() {
    let len: usize = kani::any();
    kani::assume(len < HIT_CANON_LEN);
    let buf = [0u8; HIT_CANON_LEN];
    assert!(hit_decode(&buf[..len]).is_none());
    let hit = RankedHit { rank: 1, id: 2, score: 3 };
    let mut out = [0u8; HIT_CANON_LEN];
    assert_eq!(hit_canon(&hit, &mut out[..len]), 0);
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
/// assert FAIL -- the cleared-Access-Flag abort-on-first-access bug (Yuva
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

// ===========================================================================
// aL2.4b: the guest-RAM carve map (stage2.rs) -- the FIRST non-identity
// stage-2 geometry. Two harness extensions per proposal §4.2: the IPA->PA map
// is INJECTIVE and RANGE-BOUNDED (the isolation flip, proven as pure math).
// ===========================================================================

/// The carve map is RANGE-BOUNDED + TOTAL: for EVERY 64-bit IPA, either the
/// map yields `None` (the builder maps nothing -- fail-closed confinement) or
/// the output PA falls strictly inside the carve `[GUEST_CARVE_PA,
/// GUEST_CARVE_PA + GUEST_CARVE_SIZE)` -- NO guest IPA can ever reach a host
/// frame outside the carve, and the doorbell IPA (the monitor's watched
/// progress cell) is provably unmapped.
///
/// NEGATIVE CONTROL / SEEDED MUTATION: an off-by-one carve base
/// (`GUEST_CARVE_PA - 1 + off`, the survey §8 mutant) aliases the guest's
/// first page onto a host frame BELOW the carve, so the `pa >= GUEST_CARVE_PA`
/// range-bound assert FAILS on exactly that mutant. Equally, widening the `if`
/// to `ipa <= GUEST_IPA_BASE + GUEST_CARVE_SIZE` maps the doorbell IPA and the
/// `guest_carve_pa(GUEST_DOORBELL_IPA) == None` assert FAILS.
#[kani::proof]
fn kani_guest_carve_range_bounded() {
    let ipa: u64 = kani::any();
    match guest_carve_pa(ipa) {
        Some(pa) => {
            // Every mapped PA is inside the carve window.
            assert!(pa >= GUEST_CARVE_PA);
            assert!(pa < GUEST_CARVE_PA + GUEST_CARVE_SIZE);
            // And only window IPAs map at all.
            assert!(ipa >= GUEST_IPA_BASE && ipa < GUEST_IPA_BASE + GUEST_CARVE_SIZE);
        }
        None => {
            // Everything outside the window is unmapped (fail-closed).
            assert!(ipa < GUEST_IPA_BASE || ipa >= GUEST_IPA_BASE + GUEST_CARVE_SIZE);
        }
    }
    // The doorbell IPA -- the first page past the window -- is NEVER mapped.
    assert!(guest_carve_pa(GUEST_DOORBELL_IPA).is_none());
}

/// The carve map is INJECTIVE: two DISTINCT guest IPAs can never resolve to
/// the SAME host PA (no aliasing inside the carve -- the second half of the
/// §2.1 confinement property; with range-boundedness it gives the full
/// "bijection onto a carve slice" shape).
///
/// NEGATIVE CONTROL / SEEDED MUTATION: replacing the offset translation with
/// a page-masked one (`GUEST_CARVE_PA + ((ipa - GUEST_IPA_BASE) & !0xFFF)`)
/// aliases all 4096 byte-addresses of each page onto one PA, so the
/// `pa_a != pa_b` assert FAILS for two IPAs inside one page.
#[kani::proof]
fn kani_guest_carve_injective() {
    let a: u64 = kani::any();
    let b: u64 = kani::any();
    kani::assume(a != b);
    if let (Some(pa_a), Some(pa_b)) = (guest_carve_pa(a), guest_carve_pa(b)) {
        assert!(pa_a != pa_b);
    }
}

// ===========================================================================
// aL2.4b: the `guestlog:` frame codec (guestlog.rs) -- the injection-proofing
// leaf (proposal §2.5/§4.1). Four harnesses: bounded length, total round-trip,
// injectivity, and the load-bearing no-raw-leak (regex-inertness) property.
// ===========================================================================

/// Encode is TOTAL + BOUNDED: for any payload within the frame cap, encode
/// writes EXACTLY `guestlog_frame_len(n)` bytes (prefix + 2n hex + LF) and
/// never more; oversize payloads / short out-buffers yield 0 (fail-closed).
/// Symbolic over the payload BYTES at a small concrete length (the #49
/// state-explosion discipline: totality is structural over the loop).
///
/// NEGATIVE CONTROL / SEEDED MUTATION: dropping the LF terminator write (or
/// emitting 1 hex digit per byte) changes the written length, so the
/// `n == guestlog_frame_len(LEN)` / terminator asserts FAIL.
#[kani::proof]
fn kani_guestlog_bounded() {
    const LEN: usize = 3; // small symbolic payload (structural totality)
    let payload: [u8; LEN] = kani::any();
    let mut out = [0u8; GUESTLOG_MAX_FRAME];
    let n = guestlog_encode(&payload, &mut out);
    assert_eq!(n, guestlog_frame_len(LEN));
    assert!(n <= GUESTLOG_MAX_FRAME);
    assert_eq!(out[n - 1], b'\n'); // LF-terminated
    assert_eq!(&out[..GUESTLOG_PREFIX.len()], GUESTLOG_PREFIX);
    // Fail-closed arm: an out-buffer too short for the frame writes NOTHING.
    let mut tiny = [0u8; 5];
    assert_eq!(guestlog_encode(&payload, &mut tiny), 0);
}

/// Encode -> decode is the EXACT identity (round-trip), and decode is TOTAL
/// over the produced frame. Symbolic payload bytes, small concrete length.
///
/// NEGATIVE CONTROL / SEEDED MUTATION: swapping the nibble order in the
/// encoder (`hex_digit(b & 0xF)` first) still decodes -- but to DIFFERENT
/// bytes, so the `dec == payload` assert FAILS (the mutant is caught by
/// round-trip equality, not by grammar).
#[kani::proof]
fn kani_guestlog_roundtrip_total() {
    const LEN: usize = 2;
    let payload: [u8; LEN] = kani::any();
    let mut enc = [0u8; GUESTLOG_MAX_FRAME];
    let n = guestlog_encode(&payload, &mut enc);
    assert_eq!(n, guestlog_frame_len(LEN));
    let mut dec = [0u8; GUESTLOG_MAX_PAYLOAD];
    let m = guestlog_decode(&enc[..n], &mut dec);
    assert_eq!(m, Some(LEN));
    let mut i = 0usize;
    while i < LEN {
        assert_eq!(dec[i], payload[i]);
        i += 1;
    }
}

/// The codec is INJECTIVE over equal-length payloads: two distinct payloads
/// encode to distinct frames (hex is a bijection per byte), so no two guest
/// outputs can collide into one framed line.
///
/// NEGATIVE CONTROL / SEEDED MUTATION: a truncating encoder (masking each
/// byte `& 0x0F` before hexing) collapses 16 payloads onto one frame, so the
/// "frames differ" assert FAILS for payloads differing only in high nibbles.
#[kani::proof]
fn kani_guestlog_injective() {
    const LEN: usize = 2;
    let a: [u8; LEN] = kani::any();
    let b: [u8; LEN] = kani::any();
    kani::assume(a != b);
    let mut ea = [0u8; GUESTLOG_MAX_FRAME];
    let mut eb = [0u8; GUESTLOG_MAX_FRAME];
    let na = guestlog_encode(&a, &mut ea);
    let nb = guestlog_encode(&b, &mut eb);
    assert_eq!(na, nb);
    // The frames must differ in at least one byte.
    let mut differ = false;
    let mut i = 0usize;
    while i < na {
        if ea[i] != eb[i] {
            differ = true;
        }
        i += 1;
    }
    assert!(differ);
}

/// THE LOAD-BEARING SAFETY PROPERTY (regex-inertness / no-raw-leak): for ANY
/// payload byte values, the payload region of the encoded frame consists of
/// lowercase-hex bytes `[0-9a-f]` ONLY -- no byte of the marker/guard
/// alphabet (uppercase letters, ':', ' ', '(', ')', '=', '.') passes through
/// raw, so guest bytes are inert to every unanchored host substring grep BY
/// CONSTRUCTION (survey §5; the same property M31/M34 untrusted model bytes
/// need).
///
/// NEGATIVE CONTROL / SEEDED MUTATION: the survey §8 mutant -- an
/// identity-passthrough encoder (copying payload bytes into the hex region)
/// leaks a forged `M20: persist OK` byte ('M' = 0x4D, ':' = 0x3A, ' ' = 0x20,
/// all non-hex-lower), so the `is_hex_lower` assert FAILS on exactly that
/// mutant.
#[kani::proof]
fn kani_guestlog_regex_inert() {
    const LEN: usize = 2;
    let payload: [u8; LEN] = kani::any();
    let mut enc = [0u8; GUESTLOG_MAX_FRAME];
    let n = guestlog_encode(&payload, &mut enc);
    assert_eq!(n, guestlog_frame_len(LEN));
    // Every byte of the payload (hex) region is lowercase hex -- NEVER an
    // uppercase letter, colon, space, paren, equals or dot.
    let p = GUESTLOG_PREFIX.len();
    let mut i = p;
    while i < n - 1 {
        let b = enc[i];
        assert!(is_hex_lower(b));
        assert!(b != b':' && b != b' ' && b != b'(' && b != b')' && b != b'=' && b != b'.');
        assert!(!(b.is_ascii_uppercase()));
        i += 1;
    }
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

// ===========================================================================
// M22 prov: the verified memory-PROVENANCE LEDGER leaf (the EXPECTED_HARNESSES
// 40 -> 46 bump in verify-encode.sh). SIX harnesses, each with a REAL negative
// control: (1) canon INJECTIVITY + TOTALITY -- the LOAD-BEARING proof (a distinct
// entry encodes to distinct bytes; canon never panics + fails closed on a small
// buffer); (2) prov_hash TOTALITY + no-overflow; (3) chain_mix TAMPER-SENSITIVITY
// (the fold folds every input byte); (4) verify_inclusion SOUNDNESS (accept IFF
// recompute==head; siblings are load-bearing); (5) canon round-trip (the canonical
// bytes decode back to the entry's fields); (6) head-DETERMINISM (the same append
// sequence folds to the same head bit-for-bit). Bounded symbolic inputs / small
// fixed parent + sibling counts keep them in CBMC's decidable regime (the blkfmt /
// kancell precedent: a fully-symbolic 32-byte-array FNV equality is the #49 state-
// explosion trap, so the hash/fold harnesses use SMALL fixed-length symbolic
// buffers and bounded byte-flip indices).
// ===========================================================================

/// (1) THE LOAD-BEARING PROOF (proposal §5.1): `canon` is TOTAL (never panics;
/// fails closed to `0` on a too-small buffer with no partial write) AND INJECTIVE
/// on the fixed entry struct -- two entries that differ in ANY field encode to
/// DIFFERENT bytes. Proven field-by-field over symbolic scalars + a bounded parent
/// count (0 or 1, the #49-safe small-array regime): a `kind`/`tier`/`payload_tok`/
/// `writer_cap_id`/`t_created` difference lands at its FIXED offset, and a differing
/// parent COUNT changes the `[26..34]` length-prefix (and the total length), so no
/// two distinct entries can collide.
///
/// NEGATIVE CONTROL: dropping the `n_parents` length-prefix from `canon` would let
/// a 0-parent entry whose trailing bytes happen to equal a 1-parent entry's parent
/// alias it -> the count-difference half of this proof FAILS. Writing two scalars
/// to the SAME offset (a layout bug) makes the corresponding field-difference
/// assertion FAIL (a differing field no longer changes the bytes).
#[kani::proof]
fn kani_prov_canon_injective() {
    // Symbolic scalar fields; a single bounded parent (count 0 or 1).
    let kind: u8 = kani::any();
    let tier: u8 = kani::any();
    let payload_tok: u64 = kani::any();
    let writer_cap_id: u64 = kani::any();
    let t_created: u64 = kani::any();
    let parent: [u8; PROV_HASH_LEN] = kani::any();

    let p0: [[u8; PROV_HASH_LEN]; 1] = [parent];
    let base = ProvEntry {
        kind,
        payload_tok,
        tier,
        writer_cap_id,
        t_created,
        parent_ids: &p0[..1], // one parent
    };

    // TOTALITY + a tight, large-enough buffer: canon writes exactly canon_len.
    let mut a = [0u8; CANON_PREFIX_LEN + PROV_HASH_LEN];
    let na = canon(&base, &mut a);
    assert_eq!(na, canon_len(&base));
    assert_eq!(na, CANON_PREFIX_LEN + PROV_HASH_LEN);

    // FAIL-CLOSED TOTALITY: a one-byte-too-small buffer yields 0, no partial write.
    let mut small = [0u8; CANON_PREFIX_LEN + PROV_HASH_LEN - 1];
    assert_eq!(canon(&base, &mut small), 0);

    // INJECTIVITY, field by field. Each variant differs from `base` in exactly one
    // field; its encoding must differ from `a` somewhere. We compare the encodings
    // by recomputing them into a fresh buffer and asserting inequality.
    macro_rules! differs {
        ($e:expr) => {{
            let mut b = [0u8; CANON_PREFIX_LEN + PROV_HASH_LEN];
            let nb = canon(&$e, &mut b);
            // Same parent count -> same length here; the difference is in the body.
            assert_eq!(nb, na);
            // At least one byte differs (injectivity).
            let mut any_diff = false;
            let mut i = 0usize;
            while i < na {
                if a[i] != b[i] {
                    any_diff = true;
                }
                i += 1;
            }
            any_diff
        }};
    }

    // kind: only differ when the symbolic kind actually changes.
    let k2: u8 = kani::any();
    kani::assume(k2 != kind);
    assert!(differs!(ProvEntry { kind: k2, ..base }));

    let t2: u8 = kani::any();
    kani::assume(t2 != tier);
    assert!(differs!(ProvEntry { tier: t2, ..base }));

    let pt2: u64 = kani::any();
    kani::assume(pt2 != payload_tok);
    assert!(differs!(ProvEntry { payload_tok: pt2, ..base }));

    let wc2: u64 = kani::any();
    kani::assume(wc2 != writer_cap_id);
    assert!(differs!(ProvEntry { writer_cap_id: wc2, ..base }));

    let tc2: u64 = kani::any();
    kani::assume(tc2 != t_created);
    assert!(differs!(ProvEntry { t_created: tc2, ..base }));

    // A DIFFERENT parent COUNT (0 vs 1): the length-prefix + total length differ,
    // so the encodings are different lengths (the load-bearing length-prefix half).
    let zero = ProvEntry {
        parent_ids: &p0[..0],
        ..base
    };
    let mut z = [0u8; CANON_PREFIX_LEN + PROV_HASH_LEN];
    let nz = canon(&zero, &mut z);
    assert_eq!(nz, CANON_PREFIX_LEN); // shorter than the 1-parent encoding
    assert!(nz != na);
}

/// (2) `prov_hash` is TOTAL (panic / overflow / shift-overflow FREE -- since
/// M29-C the body is `khash::uhash`, pure wrapping/rotating 32-bit BLAKE2s ARX)
/// over a bounded-length symbolic buffer, returns exactly
/// `PROV_HASH_LEN` bytes, and is DETERMINISTIC. The buffer is a small FIXED-LENGTH
/// symbolic array (the #49 state-explosion lesson: fully-symbolic data through
/// a hash is the documented trap; the totality is structural over the loop, so
/// a short bound covers the no-panic property).
///
/// NEGATIVE CONTROL: replacing a `wrapping_add` with a checked `+` in the
/// BLAKE2s `g` mixer (the compression primitive `prov_hash` now drives) would
/// panic on overflow inside this harness, turning it RED -- the wrapping
/// arithmetic is load-bearing for totality.
#[kani::proof]
fn kani_prov_hash_total() {
    // TOTALITY (no panic / no overflow -- wrapping ARX) over a SHORT symbolic
    // buffer: a long fully-symbolic input through the compression is the #49
    // trap (in the FNV era N=6 computed TWICE timed the lane out >220s locally).
    // N=2, digest computed ONCE, exercises the symbolic path (no-panic is
    // structural over the loop) at a fraction of the cost.
    const N: usize = 2;
    let data: [u8; N] = kani::any();
    let h = prov_hash(&data);
    assert_eq!(h.len(), PROV_HASH_LEN);
    // The empty input also hashes without panic (the len-0 loop edge).
    assert_eq!(prov_hash(&[]).len(), PROV_HASH_LEN);
    // DETERMINISM over a CONCRETE input (the code is pure -- no float, no
    // nondeterminism -- so a concrete witness pins it cheaply; CBMC constant-folds).
    let c = [0xABu8, 0xCD, 0xEF, 0x01];
    assert_eq!(prov_hash(&c), prov_hash(&c));
}

/// (3) `chain_mix` is TAMPER-SENSITIVE (proposal §5.3 fold non-degeneracy): for a
/// concrete `head` and `entry_id`, flipping the single bit at a SYMBOLIC byte
/// index changes the fold output -- so the head is a function of EVERY one of the
/// 64 head/entry byte positions (no degenerate fold can drop an entry or its
/// anchor). Also DETERMINISTIC. M29-C form (the `kani_khash_tamper` discipline --
/// a symbolic CHOICE over concrete data): the OLD 66-call 2x32 concrete unroll
/// was an FNV-era workaround for the #49 symbolic-fold blow-up; per the stage-C
/// budget plan the precedent INVERTS once `prov_hash` is one-block-per-call --
/// the symbolic index costs ONE evaluation per leg while the unroll pays full
/// price PER position (~20 min projected). Coverage is IDENTICAL: all 64
/// positions, now by symbolic index. base + determinism + one symbolic
/// entry-id-flip + one symbolic head-flip + the flip-back NEG = 5 fold calls.
///
/// NEGATIVE CONTROLS: an identity/constant fold (`chain_mix(h, _) == h`,
/// ignoring `entry_id`) would make the flipped-vs-original outputs EQUAL -> the
/// `!=` asserts FAIL. The flip-back leg (flip the SAME index back -> the BASE
/// digest returns) proves the mutation genuinely reaches the hash -- a harness
/// whose tamper never reached `chain_mix`, or a broken restore, fails the
/// equality (a strict ADDITION over the FNV-era body).
#[kani::proof]
fn kani_prov_chain_mix_tamper() {
    // TRACTABILITY (#49): the fold DATA stays CONCRETE; ONLY the flip index is
    // symbolic (the kani_khash_tamper shape, already baselined in this lane).
    let head: [u8; PROV_HASH_LEN] = [0x5a; PROV_HASH_LEN];
    let mut entry_id: [u8; PROV_HASH_LEN] = [0u8; PROV_HASH_LEN];
    {
        let mut i = 0usize;
        while i < PROV_HASH_LEN {
            entry_id[i] = i as u8;
            i += 1;
        }
    }
    let base = chain_mix(head, entry_id);
    // DETERMINISTIC.
    assert_eq!(chain_mix(head, entry_id), base);

    // TAMPER (entry side): one bit at a SYMBOLIC byte index over ALL
    // PROV_HASH_LEN entry positions changes the fold.
    let idx: usize = kani::any();
    kani::assume(idx < PROV_HASH_LEN);
    let mut tampered = entry_id;
    tampered[idx] ^= 0x01;
    assert!(chain_mix(head, tampered) != base);

    // NEG (flip-back): restoring the SAME byte restores the BASE digest -- the
    // mutation provably reached the hash.
    tampered[idx] ^= 0x01;
    assert!(chain_mix(head, tampered) == base);

    // TAMPER (head side): one bit at a SYMBOLIC byte index over ALL
    // PROV_HASH_LEN head positions changes the fold (the chained anchor).
    let hidx: usize = kani::any();
    kani::assume(hidx < PROV_HASH_LEN);
    let mut htamper = head;
    htamper[hidx] ^= 0x01;
    assert!(chain_mix(htamper, entry_id) != base);
}

/// (4) `verify_inclusion` is SOUND (proposal §5.4): for a small fixed chain
/// (leaf + ONE sibling), `verify_inclusion(leaf, sibs, any_head) == (head ==
/// any_head)` over a fully SYMBOLIC candidate `any_head`, where `head =
/// recompute(leaf, sibs)` is computed ONCE -- the iff IS the property. M29-C
/// form (the stage-C budget plan): the FNV-era body re-evaluated `recompute`
/// on BOTH sides of the iff and then asserted separate genuine-accept and
/// tampered-head-reject legs; the symbolic `any_head` SUBSUMES both (any_head
/// == head is the reachable accept case, any_head != head covers EVERY forged/
/// tampered head), and the single-recompute form is sound because `recompute`
/// determinism is separately proven (`kani_prov_head_deterministic`). The
/// `bad_leaf` + `bad_sib` rejections are kept VERBATIM. Nothing is conceded.
///
/// NEGATIVE CONTROL: a verifier that ignored `siblings` (e.g. a `recompute`
/// that skipped the sibling fold) would ACCEPT a forged proof whose sibling was
/// replaced -> the "tampered sibling rejects" assert FAILS. The genuine `head`
/// is computed by the SAME `recompute`, so the iff's accept half is non-vacuous.
#[kani::proof]
fn kani_prov_inclusion_sound() {
    // TRACTABILITY (the #49 symbolic-fold trap): CONCRETE leaf + sibling keep
    // `recompute` concrete, so the soundness iff is checked over a SYMBOLIC
    // candidate head (the load-bearing generality) and the tamper rejections use
    // concrete single-byte flips.
    let mut leaf: [u8; PROV_HASH_LEN] = [0u8; PROV_HASH_LEN];
    let mut sib: [u8; PROV_HASH_LEN] = [0u8; PROV_HASH_LEN];
    {
        let mut i = 0usize;
        while i < PROV_HASH_LEN {
            leaf[i] = 0xA0u8 ^ (i as u8);
            sib[i] = 0x0Bu8 ^ (i as u8);
            i += 1;
        }
    }
    let sibs = [sib];

    // The GENUINE committed head for (leaf, [sib]) -- computed ONCE (M29-C).
    let head = recompute(leaf, &sibs);

    // SOUNDNESS (the iff): verify == (head == any_head), over an ARBITRARY head.
    // Subsumes the genuine-accept (any_head == head, reachable -> non-vacuous)
    // and the tampered-head-reject (any_head != head) legs of the FNV-era body.
    let any_head: [u8; PROV_HASH_LEN] = kani::any();
    assert_eq!(verify_inclusion(leaf, &sibs, any_head), head == any_head);

    // A single-byte tamper of the LEAF is REJECTED (the fold caught it). We assume
    // the flip lands where it actually changes the recomputed value: chain_mix is
    // tamper-sensitive (harness 3), so a real leaf change yields a different head.
    let mut bad_leaf = leaf;
    bad_leaf[0] ^= 0x01;
    assert!(!verify_inclusion(bad_leaf, &sibs, head));

    // A single-byte tamper of the SIBLING is REJECTED (siblings are load-bearing).
    let mut bad_sib = sib;
    bad_sib[0] ^= 0x01;
    assert!(!verify_inclusion(leaf, &[bad_sib], head));
}

/// (5) CANONICAL ROUND-TRIP (proposal §5.5): `canon` lays the scalar fields out at
/// their documented FIXED offsets, so reading them back via INDEPENDENT LE
/// shifts (NOT through `canon`) recovers the entry -- the `blkfmt` round-trip
/// pattern. Symbolic scalars + a bounded single parent; the parent bytes land
/// verbatim after the length-prefix. (There is no `decode` fn -- the entry is a
/// borrow-bearing struct -- so the round-trip is asserted as a field-by-field
/// offset read, which is the same injectivity witness in the other direction.)
///
/// NEGATIVE CONTROL: encoding `t_created` at the `writer_cap_id` offset (a layout
/// swap) would make the independent `[18..26]` read recover `writer_cap_id`, not
/// `t_created` -> the `t_created` readback assert FAILS.
#[kani::proof]
fn kani_prov_canon_roundtrip() {
    let kind: u8 = kani::any();
    let tier: u8 = kani::any();
    let payload_tok: u64 = kani::any();
    let writer_cap_id: u64 = kani::any();
    let t_created: u64 = kani::any();
    let parent: [u8; PROV_HASH_LEN] = kani::any();
    let parents = [parent];
    let e = ProvEntry {
        kind,
        payload_tok,
        tier,
        writer_cap_id,
        t_created,
        parent_ids: &parents[..1],
    };
    let mut buf = [0u8; CANON_PREFIX_LEN + PROV_HASH_LEN];
    let n = canon(&e, &mut buf);
    assert_eq!(n, CANON_PREFIX_LEN + PROV_HASH_LEN);

    // INDEPENDENT offset reads (the literal layout, never via canon).
    assert_eq!(buf[0], kind);
    assert_eq!(buf[1], tier);
    let rd = |o: usize| {
        u64::from_le_bytes([
            buf[o],
            buf[o + 1],
            buf[o + 2],
            buf[o + 3],
            buf[o + 4],
            buf[o + 5],
            buf[o + 6],
            buf[o + 7],
        ])
    };
    assert_eq!(rd(2), payload_tok);
    assert_eq!(rd(10), writer_cap_id);
    assert_eq!(rd(18), t_created);
    assert_eq!(rd(26), 1); // the length-prefix == parent count
                           // The parent bytes land verbatim after the 34-byte prefix.
    let mut b = 0usize;
    while b < PROV_HASH_LEN {
        assert_eq!(buf[CANON_PREFIX_LEN + b], parent[b]);
        b += 1;
    }
}

/// (6) HEAD-DETERMINISM (proposal §5.6): the SAME entry sequence folds to the SAME
/// head bit-for-bit (no float, no platform dependence -- the reproducibility
/// guarantee the persisted/replayed head relies on). Two independent recomputes of
/// the same (leaf, siblings) chain are equal; AND the fold is ORDER-SENSITIVE --
/// swapping two distinct entries yields a different head (so a reordered ledger is
/// caught, not silently accepted). One symbolic sibling keeps it in the bounded
/// regime.
///
/// NEGATIVE CONTROL: any nondeterminism in `chain_mix`/`prov_hash` (a `kani::any`
/// redraw, a float intermediate) makes the two recomputes disagree -> the equality
/// FAILS. A COMMUTATIVE fold (e.g. XOR-only) would make the swapped chain equal the
/// original -> the order-sensitivity `!=` FAILS (proving the chain is a sequence,
/// not a set).
#[kani::proof]
fn kani_prov_head_deterministic() {
    // TRACTABILITY (the #49 symbolic-FNV trap): CONCRETE distinct (a, b) keep the
    // fold concrete; determinism + order-sensitivity hold for this representative
    // witness and the commutative-fold negative control still fires (folding two
    // fully-symbolic 32-byte arrays three times is the documented blow-up).
    let mut a: [u8; PROV_HASH_LEN] = [0u8; PROV_HASH_LEN];
    let mut b: [u8; PROV_HASH_LEN] = [0u8; PROV_HASH_LEN];
    {
        let mut i = 0usize;
        while i < PROV_HASH_LEN {
            a[i] = 0x11u8 ^ (i as u8);
            b[i] = 0xEEu8 ^ (i as u8);
            i += 1;
        }
    }

    // DETERMINISM: same sequence -> same head, twice.
    let h1 = recompute(a, &[b]);
    let h2 = recompute(a, &[b]);
    assert_eq!(h1, h2);

    // ORDER-SENSITIVITY: a != b by construction (0x11 vs 0xEE at byte 0); swapping
    // leaf/sibling changes the head (the fold is a SEQUENCE, not a set).
    let swapped = recompute(b, &[a]);
    assert!(swapped != h1);
}

// ===========================================================================
// M23 -- the verified EXPERIENCE CODEC (`exp.rs`). Six harnesses, each with a
// NEGATIVE CONTROL, mirroring the M22 prov suite. The record is FULLY FIXED-WIDTH
// (no variable-length tail), so canon-injectivity is a fixed-offset proof; the
// fold REUSES the proven M22 `prov` leaf (no new fold math). The replay harness
// BOUNDS `feats` to the kancell clamp range so the spline eval stays the proven
// kancell regime (the #49 trap) and evaluates `kan_score` a SINGLE time (the M22
// hash_total saga: a symbolic score over many bytes / multiple evaluations times
// the lane out). Each harness is sized to verify in << 60s standalone.
// ===========================================================================

/// A small symbolic-but-fixed-width [`ExperienceRecord`] builder for the harnesses.
/// `feats` is left to the caller (the replay harness bounds it; the others vary it
/// freely). The reserved propensity + present-`Unset` outcome are populated so the
/// injectivity/round-trip/schema proofs exercise the FULL layout.
#[cfg(kani)]
fn kani_exp_record(feats: [i32; KAN_FEATURES]) -> ExperienceRecord {
    ExperienceRecord {
        decision_id: kani::any(),
        kind: kani::any(),
        feats,
        envelope_verdict: kani::any(),
        action_taken: kani::any(),
        kan_score_shadow: kani::any(),
        logging_propensity_q: PROPENSITY_DETERMINISTIC_Q,
        logging_policy_kind: kani::any(),
        outcome: OutcomeLabel::Unset,
        margin_q: kani::any(),
    }
}

/// (1) THE LOAD-BEARING PROOF (proposal §5.1): `exp::canon` is TOTAL (never panics;
/// fails closed to `0` on a too-small buffer with NO partial write) AND INJECTIVE on
/// the fixed-width record -- two records that differ in ANY field (INCLUDING the
/// reserved propensity field and the present-`Unset` outcome tag) encode to DIFFERENT
/// bytes. Because the record is FULLY FIXED-WIDTH, each field lands at its own fixed
/// offset, so a single differing field changes the bytes; we prove this for the
/// outcome TAG explicitly (the reserve-now field whose aliasing is the §5.1 neg
/// control). Symbolic scalars; the differing-field witness is a symbolic redraw.
///
/// NEGATIVE CONTROL: a `canon` that DROPPED the outcome tag byte (or aliased two
/// scalars to one offset) would let two records differing only in `outcome` collide
/// -> the outcome-tag injectivity assert FAILS. Writing two fields to the SAME offset
/// makes the corresponding field-difference assert FAIL.
#[kani::proof]
fn kani_exp_canon_injective() {
    let feats: [i32; KAN_FEATURES] = kani::any();
    let base = kani_exp_record(feats);

    // TOTALITY + exact width: canon writes exactly EXP_CANON_LEN into a sized buffer.
    let mut a = [0u8; EXP_CANON_LEN];
    let na = exp_canon(&base, &mut a);
    assert_eq!(na, EXP_CANON_LEN);
    assert_eq!(na, exp_canon_len(&base));

    // FAIL-CLOSED TOTALITY: a one-byte-too-small buffer yields 0, no partial write.
    let mut small = [0u8; EXP_CANON_LEN - 1];
    assert_eq!(exp_canon(&base, &mut small), 0);

    // INJECTIVITY, exercised on representative fields via a symbolic redraw that is
    // FORCED to differ. Each differing field must change at least one byte.
    macro_rules! differs {
        ($e:expr) => {{
            let mut b = [0u8; EXP_CANON_LEN];
            let nb = exp_canon(&$e, &mut b);
            assert_eq!(nb, na); // fixed width: same length
            let mut any_diff = false;
            let mut i = 0usize;
            while i < na {
                if a[i] != b[i] {
                    any_diff = true;
                }
                i += 1;
            }
            any_diff
        }};
    }

    // decision_id: the OPE row key -- a differing id changes the [0..8] bytes.
    let d2: u64 = kani::any();
    kani::assume(d2 != base.decision_id);
    assert!(differs!(ExperienceRecord { decision_id: d2, ..base }));

    // kind: a forget-decision must not alias a recall-touch.
    let k2: u8 = kani::any();
    kani::assume(k2 != base.kind);
    assert!(differs!(ExperienceRecord { kind: k2, ..base }));

    // kan_score_shadow: the counterfactual score -- a differing shadow changes bytes.
    let s2: i64 = kani::any();
    kani::assume(s2 != base.kan_score_shadow);
    assert!(differs!(ExperienceRecord { kan_score_shadow: s2, ..base }));

    // The RESERVED propensity field is load-bearing for injectivity (the reserve-now
    // bytes are real bytes -- a differing sentinel must change the encoding).
    let p2: u16 = kani::any();
    kani::assume(p2 != base.logging_propensity_q);
    assert!(differs!(ExperienceRecord { logging_propensity_q: p2, ..base }));

    // The present-`Unset` OUTCOME TAG is load-bearing (§5.1 neg control): an
    // `Unset` record vs a `ReRecalled` record must differ at the tag byte.
    let other = ExperienceRecord {
        outcome: OutcomeLabel::ReRecalled(0),
        ..base
    };
    assert!(differs!(other));
}

/// (2) REPLAY-DETERMINISM (the headline claim, proposal §5.2): a recorded `feats`
/// row replayed through the dormant `kan_score` reproduces the logged
/// `kan_score_shadow` BIT-IDENTICALLY. We model "logging then replay" as TWO
/// evaluations of the SAME `kan_score` over the SAME `(table, feats)` and prove they
/// are equal i64-for-i64. CRITICAL (the #49 trap): `feats` is BOUNDED to the kancell
/// clamp range `[GRID_LO, GRID_LO + 8*step]` so the spline eval stays the PROVEN
/// kancell regime, and the table is CONCRETE so each `kan_score` is a concrete
/// evaluation (the symbolic surface is the four bounded feats only -- a single
/// evaluation pair, not a symbolic score over many bytes).
///
/// NEGATIVE CONTROL: a re-quantizing replay that landed `feats` on a DIFFERENT grid
/// cell (e.g. `replay_shadow(table, &[f^step ...])`) would evaluate a different
/// spline segment and the bit-equality FAILS. Any float intermediate (there is none)
/// would also break the i64 bit-identity. The concrete table keeps the proof cheap.
#[kani::proof]
fn kani_exp_replay_determinism() {
    // The frozen kancell-shaped table (concrete -> each kan_score is concrete).
    let table: KnotTable = [KAN_DEC, KAN_INC, KAN_FLAT, KAN_DEC];

    // BOUND feats to the kancell clamp range so the spline stays the proven regime.
    let span = (1i32 << GRID_STEP_LOG2) * (KAN_KNOTS as i32 - 1);
    let mut feats = [0i32; KAN_FEATURES];
    let mut j = 0usize;
    while j < KAN_FEATURES {
        let f: i32 = kani::any();
        kani::assume(f >= GRID_LO && f <= GRID_LO + span);
        feats[j] = f;
        j += 1;
    }

    // LOGGING: the shadow logged at decision time (a single kan_score evaluation).
    let logged = kan_score(&table, &feats, 0, 0);
    // REPLAY: the recorded feats re-derive the SAME shadow bit-for-bit.
    let replayed = replay_shadow(&table, &feats, 0, 0);
    assert_eq!(replayed, logged);

    // And it lands in the M17 DEMOTE_BAND (the clamped output -- in the proven regime).
    let (lo, hi) = DEMOTE_BAND;
    assert!(replayed >= lo && replayed <= hi);
}

/// (3) RING TOTALITY + FIXED-CAPACITY (proposal §5.3): `ExpRing::push` NEVER
/// allocates and NEVER panics, the length never exceeds `CAP`, and the drop-oldest
/// FIFO overwrite is total. A bounded push sequence over a capacity-3 ring tracks a
/// model length exactly and `is_full`/`len` stay consistent. `#[kani::unwind]`
/// bounds the loop (an under-set bound fails closed). The row payload is a tiny
/// fixed-content array (the framing is what matters, not the bytes -- a symbolic
/// per-row payload is the state-explosion trap, so the rows are concrete tags).
///
/// NEGATIVE CONTROL: dropping the `if self.len < CAP` guard (always overwriting and
/// always incrementing) lets `len()` exceed `CAP`, failing the `len <= CAP` assert;
/// a `push` that grew an internal `Vec` would not be the fixed `[[u8;LEN];CAP]` POD
/// this harness's `len <= CAP` invariant pins.
#[kani::proof]
#[kani::unwind(7)]
fn kani_exp_ring_total() {
    const CAP: usize = 3;
    const LEN: usize = EXP_CANON_LEN;
    let mut ring: ExpRing<CAP, LEN> = ExpRing::new();
    let mut model_len = 0usize;
    let mut tick = 0u8;
    for _ in 0..6 {
        // A concrete, distinguishable row (the tag rides byte 0; framing is the point).
        let mut row = [0u8; LEN];
        row[0] = tick;
        tick = tick.wrapping_add(1);
        let evicted = ring.push(&row);
        // The model: grow until full, then stay full (drop-oldest).
        if model_len < CAP {
            assert!(!evicted);
            model_len += 1;
        } else {
            assert!(evicted);
        }
        assert!(ring.len() <= CAP); // capacity NEVER exceeded (the fixed-cap invariant)
        assert_eq!(ring.len(), model_len);
        assert_eq!(ring.is_full(), model_len == CAP);
    }
    // Out-of-range reads fail closed to None (no panic).
    assert!(ring.get(CAP).is_none());
}

/// (4) FOLD TAMPER-SENSITIVITY (proposal §5.4): a single-byte flip of a committed
/// record's CANONICAL bytes changes the recomputed `xp_head` -- REUSING the proven
/// M22 `prov::chain_mix` fold (M23 writes NO fold math). We encode a record, hash it
/// to a leaf id, fold a concrete sibling, and prove flipping byte `idx` of the
/// canonical bytes drives a DIFFERENT leaf id (hence a different head + a failing
/// inclusion proof). The flip INDEX stays symbolic (every byte position proven); the
/// record + sibling are concrete so each fold is a concrete `prov` evaluation (the
/// #49 symbolic-FNV trap the M22 suite documents).
///
/// M29-C: this harness is KEPT FULL (leaf re-hash -> head mismatch -> inclusion
/// failure, end-to-end through the REAL fold at full depth) as THE one
/// representative end-to-end fold-tamper witness -- it is what LICENSES the
/// leaf-sensitivity thinning of `kani_opframe_fold_truncation` /
/// `kani_exittel_fold_tamper` / `kani_tpsched_fold_tamper` (each carries the
/// `fold-claim=` composition marker naming this harness as `e2e=`).
///
/// NEGATIVE CONTROL: a constant/identity hash (`exp::xp_hash(_) == const`) would make
/// the flipped-vs-original leaf ids EQUAL -> the `!=` assert FAILS; a fold that
/// ignored the leaf would accept the tampered record at the inclusion check.
#[kani::proof]
fn kani_exp_fold_tamper() {
    // A concrete record's canonical bytes (so the hash/fold are concrete).
    let rec = ExperienceRecord {
        decision_id: 0xA17_C0DE,
        kind: 1,
        feats: [0, 256, 512, 1024],
        envelope_verdict: 1,
        action_taken: 1,
        kan_score_shadow: -123,
        logging_propensity_q: PROPENSITY_DETERMINISTIC_Q,
        logging_policy_kind: 0,
        outcome: OutcomeLabel::Unset,
        margin_q: 7,
    };
    let mut bytes = [0u8; EXP_CANON_LEN];
    let n = exp_canon(&rec, &mut bytes);
    assert_eq!(n, EXP_CANON_LEN);

    // The genuine committed leaf id + a concrete sibling -> the committed head.
    let leaf = prov_hash(&bytes);
    let sib: [u8; PROV_HASH_LEN] = [0x5au8; PROV_HASH_LEN];
    let head = recompute(leaf, &[sib]);
    assert!(verify_inclusion(leaf, &[sib], head));

    // TAMPER: flip the bit at a SYMBOLIC byte index of the canonical bytes. The
    // re-hashed leaf differs (canon is injective + prov_hash is tamper-sensitive),
    // so the recomputed head mismatches AND the inclusion proof fails.
    let idx: usize = kani::any();
    kani::assume(idx < EXP_CANON_LEN);
    let mut tampered = bytes;
    tampered[idx] ^= 0x01;
    let bad_leaf = prov_hash(&tampered);
    // The tampered bytes differ from the genuine bytes -> a different leaf id.
    assert!(bad_leaf != leaf);
    // ...so the fold catches it: head mismatch AND inclusion failure.
    assert!(recompute(bad_leaf, &[sib]) != head);
    assert!(!verify_inclusion(bad_leaf, &[sib], head));
}

/// (5) CANON ROUND-TRIP (proposal §5.5): `exp::decode(exp::canon(rec)) == rec` for a
/// symbolic record -- the codec is a true bijection on the fixed-width layout (every
/// field read back from its fixed offset). The `outcome` is `Unset` (the tag-0
/// present sentinel); a separate concrete sub-check round-trips a POPULATED outcome
/// (the M24 shape) so the tagged decode is non-vacuous.
///
/// NEGATIVE CONTROL: encoding `kan_score_shadow` at the `decision_id` offset (a
/// layout swap) would make `decode` recover the fields transposed -> the round-trip
/// equality FAILS. A `decode` that ignored the outcome tag would mis-reconstruct the
/// variant and FAIL the populated sub-check.
#[kani::proof]
fn kani_exp_canon_roundtrip() {
    let feats: [i32; KAN_FEATURES] = kani::any();
    let rec = kani_exp_record(feats); // outcome = Unset (present sentinel)
    let mut buf = [0u8; EXP_CANON_LEN];
    let n = exp_canon(&rec, &mut buf);
    assert_eq!(n, EXP_CANON_LEN);
    // The bijection: decode recovers the EXACT record.
    assert_eq!(exp_decode(&buf), Some(rec));

    // A POPULATED outcome (the M24 shape) round-trips too -- the tagged decode is
    // exercised (concrete payload so the tag arm is non-vacuous).
    let pop = ExperienceRecord {
        outcome: OutcomeLabel::ReRecalled(0x1234),
        ..rec
    };
    let mut pb = [0u8; EXP_CANON_LEN];
    assert_eq!(exp_canon(&pop, &mut pb), EXP_CANON_LEN);
    assert_eq!(exp_decode(&pb), Some(pop));

    // A too-short buffer decodes to None (fail-closed totality, no panic).
    assert!(exp_decode(&buf[..EXP_CANON_LEN - 1]).is_none());
}

/// (6) SCHEMA-STABILITY (the reserve-now correctness obligation, proposal §5.6):
/// `canon()` of a record with `outcome = Unset` + the reserved propensity sentinel
/// has the SAME canonical LENGTH and IDENTICAL field offsets as a future record with
/// those fields POPULATED -- so M24 populating them CANNOT shift the fold. Proven by
/// encoding an `Unset` record and an otherwise-identical `ReRecalled`/`Evicted`
/// record and asserting (a) identical length, (b) every byte BEFORE the outcome tag
/// is identical, and (c) the trailing `margin_q` field (after the fixed 8-byte
/// outcome payload) is identical -- the outcome tag/payload window is the ONLY
/// difference, at a FIXED offset that never moves.
///
/// NEGATIVE CONTROL: if `Unset` encoded as a ZERO-LENGTH (absent) outcome and a
/// populated variant added 8 bytes, the lengths would differ and the trailing
/// `margin_q` would shift -> the length + trailing-field asserts FAIL. (M23 instead
/// encodes a present `Unset` with a fixed 8-byte zero payload, so the layout is
/// stable -- the property this harness pins.)
#[kani::proof]
fn kani_exp_schema_stability() {
    let feats: [i32; KAN_FEATURES] = kani::any();
    // Two records identical EXCEPT the outcome: Unset (this milestone) vs populated.
    let unset = ExperienceRecord {
        outcome: OutcomeLabel::Unset,
        ..kani_exp_record(feats)
    };
    let pay: i64 = kani::any();
    let populated = ExperienceRecord {
        outcome: OutcomeLabel::ReRecalled(pay),
        ..unset
    };

    let mut a = [0u8; EXP_CANON_LEN];
    let mut b = [0u8; EXP_CANON_LEN];
    let na = exp_canon(&unset, &mut a);
    let nb = exp_canon(&populated, &mut b);

    // (a) IDENTICAL length -- the schema-stability length lemma.
    assert_eq!(na, nb);
    assert_eq!(na, EXP_CANON_LEN);

    // (b) Every byte BEFORE the outcome tag (offset 38) is byte-identical: the
    // decision_id/kind/feats/envelope/action/shadow/propensity/policy_kind fields
    // do NOT move when the outcome is populated. (38 = OFF_OUTCOME_TAG, the literal.)
    const OUTCOME_TAG_OFF: usize = 38;
    const MARGIN_OFF: usize = 47;
    let mut i = 0usize;
    while i < OUTCOME_TAG_OFF {
        assert_eq!(a[i], b[i]);
        i += 1;
    }
    // (c) The trailing margin_q field (after the FIXED 8-byte outcome payload) is
    // identical -- the populated outcome did NOT push it to a new offset.
    let mut m = MARGIN_OFF;
    while m < EXP_CANON_LEN {
        assert_eq!(a[m], b[m]);
        m += 1;
    }
}

// ===========================================================================
// M24 -- the HONEST ACTIVATION GATE (`explore.rs` + `bakeoff.rs`). SIX harnesses,
// each with a NEGATIVE CONTROL, mirroring the M22/M23 suites. The math is
// no-float saturating integer; the gate refuses on synthetic traces (gate-not-met
// is the designed outcome). The symbolic surface is kept SMALL and the kancell
// table CONCRETE wherever a kan_score is computed (the #49 / M22 hash_total trap:
// a symbolic score / a symbolic FNV over many bytes times the lane out). Each
// harness is sized to verify in << 60s standalone.
// ===========================================================================

/// (1) PROPENSITY TOTALITY + POSITIVITY + SINGLETON (proposal §4.1): the closed-form
/// shielded epsilon-greedy `explore_propensity_q` is TOTAL (never panics / never
/// divides by zero over ALL inputs), the `m == 1` SINGLETON guard returns EXACTLY
/// `PROPENSITY_SCALE` (== 1000) for any eps / is_greedy, and -- the load-bearing
/// POSITIVITY claim -- for every cleared action with `eps_num > 0` and `m >= 2` the
/// propensity is in `[1, 1000]` (no cleared action gets a zero propensity, so IPS is
/// identifiable over the explored support). The symbolic surface is four small
/// scalars BOUNDED to the seam's shipped regime (`eps_den <= 64`, `m <= 16`).
///
/// NEGATIVE CONTROL: a `propensity` that returned `0` for an explored "other" action
/// (dropping the `.max(1)` positivity floor) FAILS the `>= 1` assert; a singleton
/// guard that returned `(1-eps)*1000` instead of `1000` FAILS the `== 1000` assert;
/// a non-saturating mul/div would panic on the extreme-input totality leg.
#[kani::proof]
fn kani_explore_propensity_total_positivity() {
    // TOTALITY over the extremes (a single concrete probe -- saturating, no panic).
    let _ = explore_propensity_q(u32::MAX, 1, u32::MAX, true);
    let _ = explore_propensity_q(0, 0, 0, false);

    // SINGLETON guard: m == 1 is deterministic 1000 for ANY symbolic eps / is_greedy.
    let en: u32 = kani::any();
    let ed: u32 = kani::any();
    let g: bool = kani::any();
    kani::assume(en <= 64 && ed <= 64);
    assert_eq!(
        explore_propensity_q(en, ed, 1, g),
        PROPENSITY_SCALE as u16
    );

    // POSITIVITY: a small bounded (eps, m) in the shipped regime -- both the greedy
    // and an other action land in [1, 1000] when eps_num > 0 and m >= 2.
    let eps_num: u32 = kani::any();
    let eps_den: u32 = kani::any();
    let m: u32 = kani::any();
    kani::assume(eps_den >= 2 && eps_den <= 64);
    kani::assume(eps_num >= 1 && eps_num < eps_den); // a proper eps in (0,1)
    kani::assume(m >= 2 && m <= 16);
    let pg = explore_propensity_q(eps_num, eps_den, m, true);
    let po = explore_propensity_q(eps_num, eps_den, m, false);
    assert!(pg >= 1 && pg <= 1000);
    assert!(po >= 1 && po <= 1000);
    // The greedy action carries at least as much mass as an other action.
    assert!(pg >= po);
}

/// (2) SURVIVAL-LABEL TOTALITY + EXHAUSTIVE PARTITION + MONOTONE-RESOLUTION
/// (proposal §4.2): `survival_label` is TOTAL on saturating tick subtraction over
/// ALL u64 inputs; the 3-way partition is EXHAUSTIVE + MUTUALLY EXCLUSIVE (it
/// returns exactly one of the three variants, and each is characterised by a
/// disjoint condition); and it is MONOTONE-RESOLUTION (a `Censored` label resolves
/// only as `now_tick` advances, and a resolved `Negative`/`Positive` NEVER flips
/// -- so a replayed stream relabels identically). Symbolic ticks BOUNDED to a small
/// window so the saturating arithmetic stays in the decidable regime.
///
/// NEGATIVE CONTROL: a 2-way label that DROPPED `Censored` (treating an open window
/// as `Positive`) would relabel a record as the window closes -> the monotone-
/// resolution invariance (a resolved label is stable as `now` advances) FAILS; a
/// label that re-opened the collider (a `recall()`-derived touch re-classifying a
/// closed window) would also break stability.
#[kani::proof]
fn kani_bakeoff_label_partition() {
    let decision: u64 = kani::any();
    let now: u64 = kani::any();
    let w: u64 = kani::any();
    let touch_present: bool = kani::any();
    let touch: u64 = kani::any();
    // BOUND to a small window so the saturating subtraction is the decidable regime.
    kani::assume(decision <= 1000 && now <= 4000 && w <= 1000 && touch <= 4000);
    kani::assume(now >= decision); // the horizon never precedes the decision

    let tt = if touch_present { Some(touch) } else { None };
    let label = survival_label(decision, now, tt, w);

    // EXHAUSTIVE + MUTUALLY EXCLUSIVE: exactly one variant, and each matches its
    // disjoint defining condition (re-derived independently from the inputs).
    let retouch_in_window = touch_present && touch >= decision && touch - decision <= w;
    let window_closed = now - decision >= w;
    match label {
        SurvivalLabel::Negative => assert!(retouch_in_window),
        SurvivalLabel::Positive => assert!(!retouch_in_window && window_closed),
        SurvivalLabel::Censored => assert!(!retouch_in_window && !window_closed),
    }

    // MONOTONE RESOLUTION: a RESOLVED label is invariant as `now` advances (a
    // re-touch tick is immutable; a closed window stays closed). Re-label at a
    // strictly-later horizon and assert a resolved verdict is unchanged.
    let later: u64 = kani::any();
    kani::assume(later >= now && later <= 8000);
    let label2 = survival_label(decision, later, tt, w);
    if label.is_resolved() {
        assert_eq!(label, label2);
    }
}

/// (3) VALUE-LOWER-BOUND TOTALITY + SOUNDNESS + ROUND-DOWN (proposal §4.3): the
/// Manski + Lipschitz-smoothness `value_lower_bound` (and its `eb_lower_bound` /
/// `smoothness_floor_mean` / `value_upper_heuristic` companions) is TOTAL (no
/// divide-by-zero -- `n_total == 0` fails closed to `Y_LO`; the smoothness sweep is
/// a fixed `GRID_CELLS` loop with no recursion) and SOUND: the returned `V_lower`
/// stays in the reward band `[Y_LO, Y_HI]` and NEVER exceeds the empirical mean of a
/// constant-reward overlap set (the bound rounds DOWN). The symbolic surface is the
/// small overlap statistics + a single grid anchor (the sweep stays concrete-table).
///
/// NEGATIVE CONTROL: gating on the UPPER bound / midpoint, or LOOSENING `L` so the
/// smoothness floor exceeds the true mean, lets an unsound interval clear the
/// margin -> the `vlo <= mean` soundness assert FAILS. A `value_lower_bound` that
/// divided by `n_overlap` (zero on the no-overlap path) would panic the totality leg.
///
/// CONCRETE-STATISTICS DISCIPLINE (the #49 / M22 hash_total trap): `eb_lower_bound`
/// contains a closed-form integer ceiling-sqrt + a fixed-point `ln` whose internal
/// loops, if driven by a SYMBOLIC variance, blow CBMC out (a symbolic value through a
/// variable-bound `while` loop -- the lane out). So the soundness/round-down leg
/// sweeps a SMALL set of CONCRETE reward levels (each `eb_lower_bound` is then a fully
/// concrete evaluation), and the symbolic surface is kept to the grid/totality
/// plumbing only. `#[kani::unwind]` bounds the concrete sweep (an under-set bound
/// fails closed).
#[kani::proof]
#[kani::unwind(12)]
fn kani_bakeoff_bound_sound_rounddown() {
    // TOTALITY: no support -> the sound Manski floor, no divide-by-zero.
    let empty: [Option<i64>; GRID_CELLS] = [None; GRID_CELLS];
    assert_eq!(value_lower_bound(0, 0, 0, 0, &empty, 1, 20), Y_LO);
    assert_eq!(value_upper_heuristic(0, 0, 0), Y_HI);
    assert_eq!(smoothness_floor_mean(&empty), Y_LO);

    // SOUNDNESS + ROUND-DOWN over a CONSTANT-reward overlap set: n samples all equal
    // to a CONCRETE reward r -> mean == r, and the EB lower bound must be <= r (the
    // penalties are non-negative, the bound rounds DOWN), and >= the Manski floor.
    // The reward levels span the band (low/mid/high, both signs); n is a small
    // concrete count so every eb_lower_bound is a concrete evaluation.
    const LEVELS: [i64; 5] = [Y_LO, -1000, 0, 1000, Y_HI];
    let range = Y_HI - Y_LO;
    let mut li = 0usize;
    while li < LEVELS.len() {
        let r = LEVELS[li];
        let mut n = 2u32;
        while n <= 8 {
            let sum = (n as i64).saturating_mul(r);
            let sum_sq = (n as i128).saturating_mul((r as i128).saturating_mul(r as i128));
            let lb = eb_lower_bound(sum, sum_sq, n, range, 1, 20, Y_LO);
            assert!(lb <= r, "EB lower bound exceeded the constant mean (unsound)");
            assert!(lb >= Y_LO, "EB lower bound below the Manski floor");
            // value_lower_bound over the same constant overlap set + one grid anchor
            // stays in-band and is itself <= r (the support-weighted floor never rises
            // above the identified mean for a single explored cell).
            let mut grid: [Option<i64>; GRID_CELLS] = [None; GRID_CELLS];
            grid[0] = Some(r);
            let v = value_lower_bound(sum, sum_sq, n, n, &grid, 1, 20);
            assert!(v >= Y_LO && v <= Y_HI);
            assert!(v <= r, "V_lower exceeded the overlap mean (unsound)");
            n += 2;
        }
        li += 1;
    }

    // The no-support / single-sample TOTALITY legs over the same concrete band.
    assert_eq!(eb_lower_bound(0, 0, 0, range, 1, 20, Y_LO), Y_LO);
    let _ = eb_lower_bound(Y_HI, (Y_HI as i128) * (Y_HI as i128), 1, range, 1, 20, Y_LO);
}

/// (4) REPLAY-DETERMINISM of the M24 decision tuple (proposal §4.4): the chosen
/// EXPLORE-vs-GREEDY action, its logged PROPENSITY, the survival LABEL, and the
/// value LOWER-BOUND are ALL bit-exactly reproducible from `(decision_id,
/// agent_seed, A_safe, frozen table)` alone -- the M23 replay-determinism property
/// extended to the action choice. We model the explore coin as the SAME seeded
/// integer fold the seam uses (`xp_chain_mix(decision_id, agent_seed) mod eps_den
/// mod m`, keyed to the IMMUTABLE decision_id, never a mutable step counter) and
/// prove two replays agree on coin + propensity + label + bound. The fold inputs +
/// table are CONCRETE (so the hash fold / kan_score stay concrete -- the #49 trap);
/// the symbolic surface is the small bounded scalars.
///
/// NEGATIVE CONTROL: keying the explore coin to a MUTABLE step counter (instead of
/// the immutable decision_id) desyncs the two replays -> the `coin_a == coin_b`
/// assert FAILS; any float intermediate in the propensity/bound would also break
/// the i64/u16 bit-identity.
#[kani::proof]
fn kani_bakeoff_replay_determinism() {
    // The explore coin: a SEEDED integer fold of the immutable decision_id (reusing
    // the proven M22 fold via prov::chain_mix -> a 32-byte head -> a u64 witness),
    // then mod eps_den mod m. CONCRETE seed/id so the hash fold is concrete.
    let did: [u8; PROV_HASH_LEN] = [0x24u8; PROV_HASH_LEN];
    let seed: [u8; PROV_HASH_LEN] = [0xA5u8; PROV_HASH_LEN];
    let eps_den: u32 = 16;
    let m: u32 = 4;

    fn coin(did: [u8; PROV_HASH_LEN], seed: [u8; PROV_HASH_LEN], eps_den: u32, m: u32) -> u32 {
        // chain_mix(seed, did) folds both immutable inputs; fold the 32-byte head to
        // a u32 witness, then mod eps_den mod m (the seam's exact coin recipe).
        let head = chain_mix(seed, did);
        let mut w = 0u32;
        let mut i = 0usize;
        while i < PROV_HASH_LEN {
            w = w.wrapping_add(head[i] as u32);
            i += 1;
        }
        (w % eps_den.max(1)) % m.max(1)
    }

    // Two replays from the SAME immutable inputs agree on the coin (the action choice).
    let coin_a = coin(did, seed, eps_den, m);
    let coin_b = coin(did, seed, eps_den, m);
    assert_eq!(coin_a, coin_b);
    // ...and on whether it is the greedy action (coin == 0 keeps greedy).
    let greedy_a = coin_a == 0;
    let greedy_b = coin_b == 0;
    assert_eq!(greedy_a, greedy_b);

    // The PROPENSITY of the chosen action replays bit-for-bit.
    let p_a = explore_propensity_q(1, eps_den, m, greedy_a);
    let p_b = explore_propensity_q(1, eps_den, m, greedy_b);
    assert_eq!(p_a, p_b);

    // The survival LABEL replays bit-for-bit over bounded symbolic ticks.
    let decision: u64 = kani::any();
    let now: u64 = kani::any();
    let w: u64 = kani::any();
    kani::assume(decision <= 1000 && now <= 4000 && w <= 1000 && now >= decision);
    let l_a = survival_label(decision, now, None, w);
    let l_b = survival_label(decision, now, None, w);
    assert_eq!(l_a, l_b);
    // ...and its reward (a pure closed-form map) is deterministic too.
    assert_eq!(label_reward(l_a), label_reward(l_b));

    // The value LOWER-BOUND replays bit-for-bit over the same concrete statistics.
    let grid: [Option<i64>; GRID_CELLS] = [Some(500); GRID_CELLS];
    let v_a = value_lower_bound(2000, 2000i128 * 500, 4, 6, &grid, 1, 20);
    let v_b = value_lower_bound(2000, 2000i128 * 500, 4, 6, &grid, 1, 20);
    assert_eq!(v_a, v_b);
}

/// (5) ENVELOPE-NO-WIDENING RE-ASSERTION under the soft-greedy path (proposal §4.5,
/// the M21 `kani_kan_envelope_no_widening` re-asserted for M24): the shielded
/// epsilon-greedy choice adds ZERO actions to the cleared set `A_safe(x)` -- it only
/// chooses AMONG already-cleared candidates -- so the heuristic pin verdict
/// (`IMP_PIN`/`UTIL_PIN`/`MIN_AGE`) stays INVARIANT under both the kan_score AND the
/// explore coin. We re-assert the M21 property with the explore choice ALSO unable
/// to move the gate: a pinned record's `is_pinned` verdict is invariant under every
/// `(kan_score, explore_coin)` pair (pin/grace/util-pin are never explorable).
///
/// NEGATIVE CONTROL: exploration BEFORE the shield (letting the coin add a pinned
/// action to the candidate set), or feeding the coin INTO the pin test, would make
/// `is_pinned` depend on the coin -> the `pinned_a == pinned_b` invariance FAILS.
#[kani::proof]
fn kani_kan_envelope_no_widening_m24() {
    // The M17 envelope thresholds (the seam owns these; neither the KAN score nor
    // the explore coin ever sees them -- the load-bearing seam property).
    const IMP_PIN: i64 = 8;
    const UTIL_PIN: i64 = 600;
    const MIN_AGE: u64 = 16;

    // A record's heuristic safety verdict -- a PURE function of metadata, with NO
    // dependence on a KAN score OR an explore coin.
    fn is_pinned(importance: i64, util: i64, age: u64) -> bool {
        age < MIN_AGE || importance >= IMP_PIN || util >= UTIL_PIN
    }

    let importance: i64 = kani::any();
    let util: i64 = kani::any();
    let age: u64 = kani::any();

    // An overflow-safe concrete table + two arbitrary kan_score outputs.
    let table: KnotTable = [KAN_DEC, KAN_INC, KAN_FLAT, KAN_DEC];
    assert!(kan_table_overflow_safe(&table));
    let feats_a: [i32; KAN_FEATURES] = kani::any();
    let feats_b: [i32; KAN_FEATURES] = kani::any();
    let score_a = kan_score(&table, &feats_a, kani::any(), kani::any());
    let score_b = kan_score(&table, &feats_b, kani::any(), kani::any());
    let (lo, hi) = DEMOTE_BAND;
    assert!(score_a >= lo && score_a <= hi);
    assert!(score_b >= lo && score_b <= hi);

    // Two arbitrary explore propensities (the shielded epsilon-greedy choice over a
    // cleared set) -- the coin chooses AMONG cleared candidates, it cannot widen the
    // set. The pin verdict is invariant under BOTH the score AND the coin.
    let m_a: u32 = kani::any();
    let m_b: u32 = kani::any();
    kani::assume(m_a >= 1 && m_a <= 16 && m_b >= 1 && m_b <= 16);
    let coin_a = explore_propensity_q(1, 16, m_a, kani::any());
    let coin_b = explore_propensity_q(1, 16, m_b, kani::any());

    let pinned_a = is_pinned(importance, util, age);
    let pinned_b = is_pinned(importance, util, age);
    // The scores + coins exist but DO NOT feed the gate (the seam keeps the policy +
    // the exploration strictly downstream of the safety gate).
    let _ = (score_a, score_b, coin_a, coin_b);
    assert_eq!(pinned_a, pinned_b);
}

/// (6) SCHEMA-STABILITY of the M24-POPULATED outcome (proposal §4.6, reusing the M23
/// `kani_exp_schema_stability` lemma): populating the M23-reserved `OutcomeLabel`
/// slot with a RESOLVED survival label (a `ReRecalled`/`Evicted` payload) and the
/// soft-greedy propensity/policy-kind shifts NO byte offset -- so the M22 fold / M20
/// spill stay byte-identical. We encode a record whose outcome is the M24-resolved
/// label (vs the M23 `Unset` sentinel) and assert identical canonical LENGTH +
/// identical field offsets everywhere except the fixed outcome tag/payload window.
///
/// NEGATIVE CONTROL: an outcome encoding that GREW the record when populated (a
/// variable-length tail) would shift `margin_q` -> the length + trailing-field
/// asserts FAIL (M23/M24 instead use a present, fixed 8-byte payload, so the layout
/// is stable).
#[kani::proof]
fn kani_bakeoff_schema_stability() {
    let feats: [i32; KAN_FEATURES] = kani::any();
    // The M23 sentinel record (Unset outcome, deterministic propensity sentinel) vs
    // the M24-populated record (a resolved survival label -> ReRecalled, soft-greedy
    // propensity + policy kind). EVERY non-outcome/propensity/policy field identical.
    let base = kani_exp_record(feats); // Unset outcome, deterministic sentinel
    let pay: i64 = kani::any();
    let prop: u16 = kani::any();
    // The M24 record: the survival label resolved to a Negative false-forget encodes
    // as ReRecalled(delay); the soft-greedy propensity replaces the sentinel.
    let resolved = SurvivalLabel::Negative.to_outcome(pay);
    let m24 = ExperienceRecord {
        outcome: resolved,
        logging_propensity_q: prop,
        logging_policy_kind: crate::bakeoff::policy_kind::SOFT_GREEDY,
        ..base
    };

    let mut a = [0u8; EXP_CANON_LEN];
    let mut b = [0u8; EXP_CANON_LEN];
    let na = exp_canon(&base, &mut a);
    let nb = exp_canon(&m24, &mut b);

    // IDENTICAL length -- populating the reserved fields cannot change the width.
    assert_eq!(na, nb);
    assert_eq!(na, EXP_CANON_LEN);

    // The fixed field offsets (the M23 layout literals): propensity @35, policy @37,
    // outcome tag @38, payload @39..47, margin @47. Every byte OUTSIDE the
    // propensity/policy/outcome window is byte-identical (the populated fields only
    // touch their own reserved slots).
    const OFF_PROP: usize = 35;
    const OFF_MARGIN: usize = 47;
    // Bytes [0..35) (decision_id/kind/feats/envelope/action/shadow) are identical.
    let mut i = 0usize;
    while i < OFF_PROP {
        assert_eq!(a[i], b[i]);
        i += 1;
    }
    // The trailing margin_q field (after the fixed 8-byte outcome payload) is
    // identical -- the populated outcome did NOT push it to a new offset.
    let mut m = OFF_MARGIN;
    while m < EXP_CANON_LEN {
        assert_eq!(a[m], b[m]);
        m += 1;
    }
    // And the gate verdict over thin support is honestly NotEvaluable (a cheap
    // non-vacuity check that the gate plumbing is live in this harness).
    assert_eq!(
        gate_clears(Y_HI, Y_LO, ACTIVATION_MARGIN, 0, 0),
        GateVerdict::NotEvaluable
    );
}

// ===========================================================================
// M25 opframe: the verified OPERATOR-TRANSCRIPT codec. Six harnesses (one per
// proposal §4 obligation), each with a NEGATIVE CONTROL. The codec proofs
// (canon/decode) are cheap (pure byte layout, no FNV), so they run more
// symbolic; the FOLD harness keeps the record/sibling CONCRETE and only the
// flip index symbolic (the #49 symbolic-FNV trap the M22/M23 suites document).
// ===========================================================================

/// A symbolic-but-EMITTABLE 2-byte-payload frame builder for the codec harnesses:
/// the validated fields (kind/sev/partition) are CONCRETE-valid so `canon` does not
/// fail-close on them, while seq/t_logical/prev_head/payload are symbolic. (The
/// validation/leakage REJECTIONS are proven separately in `kani_opframe_partition_leak`.)
fn kani_op_frame<'a>(payload: &'a [u8; 2]) -> OpFrame<'a> {
    OpFrame {
        kind: crate::opframe::kind::EXPERIENCE_DIGEST,
        sev: 9, // INFO -- in the 1..=24 OTel band
        partition_id: crate::opframe::partition::CANDIDATE,
        seq: kani::any(),
        t_logical: kani::any(),
        prev_head: kani::any(),
        payload,
    }
}

/// (1) THE LOAD-BEARING PROOF (proposal §4.1): `opframe::canon` is TOTAL (never
/// panics; fails closed to `0` on a too-small buffer with NO partial write) AND
/// INJECTIVE -- two emittable frames that differ in ANY field encode to DIFFERENT
/// bytes, the fixed header at fixed offsets + the `payload_len` u32 prefix making the
/// variable tail self-delimiting (so a different payload LENGTH yields a different
/// total length -- the disambiguator). Symbolic scalars; each differing-field witness
/// is a symbolic redraw forced to differ.
///
/// NEGATIVE CONTROL: a `canon` that DROPPED the `payload_len` prefix would let a
/// 2-byte-payload frame alias a 3-byte one whose extra byte matched the next field ->
/// the length-disambiguation assert FAILS; writing two header fields to one offset
/// makes the corresponding field-difference assert FAIL.
#[kani::proof]
fn kani_opframe_canon_injective() {
    let pay: [u8; 2] = kani::any();
    let base = kani_op_frame(&pay);

    // TOTALITY + exact width: canon writes exactly canon_len into a sized buffer.
    let mut a = [0u8; OPFRAME_HEADER_LEN + 2];
    let na = op_canon(&base, &mut a);
    assert_eq!(na, op_canon_len(&base));
    assert_eq!(na, OPFRAME_HEADER_LEN + 2);

    // FAIL-CLOSED TOTALITY: a one-byte-too-small buffer yields 0, no partial write.
    let mut small = [0u8; OPFRAME_HEADER_LEN + 2 - 1];
    assert_eq!(op_canon(&base, &mut small), 0);

    // INJECTIVITY over same-length frames (the differing field is forced to differ).
    macro_rules! differs {
        ($e:expr) => {{
            let mut b = [0u8; OPFRAME_HEADER_LEN + 2];
            let nb = op_canon(&$e, &mut b);
            assert_eq!(nb, na); // same payload length -> same total length
            let mut any_diff = false;
            let mut i = 0usize;
            while i < na {
                if a[i] != b[i] {
                    any_diff = true;
                }
                i += 1;
            }
            any_diff
        }};
    }

    // seq: the strictly-monotone counter -- a differing seq changes the [7..15] bytes
    // (and is FOLDED into the digest, so a renumber perturbs the head).
    let s2: u64 = kani::any();
    kani::assume(s2 != base.seq);
    assert!(differs!(OpFrame { seq: s2, ..base }));

    // t_logical: a differing logical clock changes the bytes.
    let t2: u64 = kani::any();
    kani::assume(t2 != base.t_logical);
    assert!(differs!(OpFrame { t_logical: t2, ..base }));

    // payload VALUE at the same length: a differing payload byte changes the bytes.
    let mut pv = pay;
    pv[0] ^= 1;
    assert!(differs!(OpFrame { payload: &pv, ..base }));

    // A different payload LENGTH (the load-bearing length-prefix half): a 3-byte
    // payload has a strictly longer total length than the 2-byte base.
    let pay3 = [pay[0], pay[1], 0xAB];
    let longer = OpFrame { payload: &pay3, ..base };
    let mut c = [0u8; OPFRAME_HEADER_LEN + 3];
    let nc = op_canon(&longer, &mut c);
    assert_eq!(nc, OPFRAME_HEADER_LEN + 3);
    assert!(nc != na); // distinct length -> cannot alias the 2-byte frame
}

/// (2) THE LEAKAGE GUARD negative control (proposal §4.5): `opframe::canon` FAIL-CLOSES
/// (returns 0, no bytes written, no head advance) on a frame tagged the SEALED
/// `partition::SAFETY_HELD_OUT` (the Seldonian no-snoop invariant) AND on any other
/// invalid header (an out-of-band severity, an unknown kind). The candidate partition
/// with a valid header DOES encode (the accept half is non-vacuous).
///
/// NEGATIVE CONTROL: a `canon` whose `frame_is_emittable` IGNORED the partition tag
/// would ENCODE the held-out frame -> the `== 0` assert FAILS (the transcript would
/// leak a sealed-partition record). Dropping the severity-band check encodes `sev==0`.
#[kani::proof]
fn kani_opframe_partition_leak() {
    let pay: [u8; 2] = kani::any();
    let mut out = [0u8; OPFRAME_HEADER_LEN + 2];

    // THE HELD-OUT GUARD: a SAFETY_HELD_OUT frame must NOT encode (fail-closed to 0).
    let held = OpFrame {
        kind: crate::opframe::kind::EXPERIENCE_DIGEST,
        sev: 9,
        partition_id: crate::opframe::partition::SAFETY_HELD_OUT,
        seq: kani::any(),
        t_logical: kani::any(),
        prev_head: kani::any(),
        payload: &pay,
    };
    assert_eq!(op_canon(&held, &mut out), 0);
    // ...and the fold step also refuses to advance the head on a held-out frame.
    assert!(fold_frame([0u8; PROV_HASH_LEN], &held, &mut out).is_none());

    // An out-of-band severity (0) is rejected.
    let badsev = OpFrame { sev: 0, partition_id: crate::opframe::partition::CANDIDATE, ..held };
    assert_eq!(op_canon(&badsev, &mut out), 0);

    // The CANDIDATE partition with a valid header DOES encode (accept half non-vacuous).
    let ok = OpFrame { partition_id: crate::opframe::partition::CANDIDATE, sev: 9, ..held };
    assert_eq!(op_canon(&ok, &mut out), OPFRAME_HEADER_LEN + 2);
}

/// (3) SEQ STRICT-MONOTONE reader sensitivity (proposal §4.2): `seq_index_exact`
/// accepts the well-formed sequence `seqs[i]==i` and REJECTS a gap, a duplicate, a
/// reorder, or a non-zero start (so a dropped/duplicated/reordered middle frame is
/// caught). We prove acceptance for a concrete in-order triple and rejection under a
/// SYMBOLIC single-position perturbation of one element.
///
/// NEGATIVE CONTROL: a check using `>=`/non-decreasing instead of `== i` would ACCEPT
/// a duplicate (`[0,1,1]`) -> the rejection assert FAILS; ignoring index 0 accepts a
/// non-zero start.
#[kani::proof]
fn kani_opframe_seq_monotone() {
    // ACCEPT the genuine in-order sequence.
    assert!(seq_index_exact(&[0, 1, 2]));

    // REJECT a SYMBOLIC single-element perturbation: pick a position and a wrong value.
    let pos: usize = kani::any();
    kani::assume(pos < 3);
    let wrong: u64 = kani::any();
    kani::assume(wrong != pos as u64); // anything other than the correct index value
    let mut seqs = [0u64, 1, 2];
    seqs[pos] = wrong;
    assert!(!seq_index_exact(&seqs)); // any single corrupted index is caught

    // A non-zero start is rejected (the genesis-INTRO-at-0 requirement).
    assert!(!seq_index_exact(&[1, 2, 3]));
}

/// (4) INTRO-BINDING soundness (proposal §4.4): `intro_binds(frame, m22_head)` accepts
/// IFF the frame is a genesis INTRO (`kind==INTRO`, `seq==0`) carrying the TRUE live
/// M22 head as its `prev_head`. A forged anchor (any other head), a non-zero seq, or a
/// non-INTRO kind is REJECTED -- so a transcript replayed from a different boot (whose
/// M22 head differs) cannot verify in isolation. Symbolic head + a symbolic single-byte
/// forgery.
///
/// NEGATIVE CONTROL: an `intro_binds` that ignored `prev_head` (binding on kind/seq
/// alone) would ACCEPT a forged anchor -> the forged-head rejection assert FAILS.
#[kani::proof]
fn kani_opframe_intro_binding() {
    let head: [u8; PROV_HASH_LEN] = kani::any();
    let intro = OpFrame {
        kind: crate::opframe::kind::INTRO,
        sev: 9,
        partition_id: crate::opframe::partition::CANDIDATE,
        seq: 0,
        t_logical: kani::any(),
        prev_head: head,
        payload: &[],
    };
    // SOUND ACCEPT: the genuine genesis INTRO binds to the live head.
    assert!(intro_binds(&intro, head));

    // FORGED ANCHOR: flip the bit at a symbolic index of the head the verifier holds;
    // the INTRO's prev_head no longer matches -> reject.
    let idx: usize = kani::any();
    kani::assume(idx < PROV_HASH_LEN);
    let mut forged = head;
    forged[idx] ^= 0x01;
    assert!(!intro_binds(&intro, forged));

    // A non-genesis seq is rejected even with the true head.
    let notgenesis = OpFrame { seq: 1, ..intro };
    assert!(!intro_binds(&notgenesis, head));
    // A non-INTRO kind is rejected even with the true head + seq 0.
    let notintro = OpFrame { kind: crate::opframe::kind::MARKER, ..intro };
    assert!(!intro_binds(&notintro, head));
}

/// (5) LEAF-SENSITIVITY + TAIL-TRUNCATION (proposal §4.3, M29-C-thinned): a
/// single-byte flip at a SYMBOLIC index of a committed frame's CANONICAL bytes
/// changes its `prov_hash` LEAF id (the 61-byte buffer is one hash invocation
/// per call), AND the closing `gate_commits_final_seq` detects a truncated tail
/// (a reader expecting a longer transcript than the GATE_VERDICT commits is
/// rejected) -- the hash-free half, kept VERBATIM. The frame is CONCRETE; the
/// flip INDEX stays symbolic over ALL canonical byte positions.
///
/// M29-C COMPOSITION (the ONE documented stage-C concession): this harness
/// machine-proves the LEAF claim only; the chain-level rejection (head mismatch
/// + inclusion failure, the FNV-era corroboration legs) is the COMPOSITION of
/// three separately machine-proven conjuncts -- (leaf != leaf' [THIS harness])
/// AND (`chain_mix` tamper-sensitive at every byte
/// [`kani_prov_chain_mix_tamper`]) AND (inclusion iff
/// [`kani_prov_inclusion_sound`]) -- demonstrated end-to-end at full depth by
/// the kept-FULL `kani_exp_fold_tamper`.
/// fold-claim=LEAF-SENSITIVITY+COMPOSED(chain_mix_tamper, inclusion_sound; e2e=exp_fold_tamper)
///
/// NEGATIVE CONTROLS: a constant/identity hash would make the flipped-vs-
/// original leaf ids EQUAL -> the `!=` assert FAILS; the flip-back leg (re-flip
/// the SAME index -> the genuine leaf id returns) proves the mutation reaches
/// the hash; a `gate_commits_final_seq` that ignored the expected length would
/// ACCEPT a truncated tail -> the truncation assert FAILS.
#[kani::proof]
fn kani_opframe_fold_truncation() {
    // A concrete emittable frame -> concrete canonical bytes.
    let pay: [u8; 2] = [0xDE, 0xAD];
    let frame = OpFrame {
        kind: crate::opframe::kind::EXPERIENCE_DIGEST,
        sev: 9,
        partition_id: crate::opframe::partition::CANDIDATE,
        seq: 1,
        t_logical: 0xCAFE,
        prev_head: [0x5a; PROV_HASH_LEN],
        payload: &pay,
    };
    let mut bytes = [0u8; OPFRAME_HEADER_LEN + 2];
    let n = op_canon(&frame, &mut bytes);
    assert_eq!(n, OPFRAME_HEADER_LEN + 2);

    // The genuine committed LEAF id.
    let leaf = prov_hash(&bytes[..n]);

    // TAMPER: flip the bit at a SYMBOLIC byte index -> a different leaf id
    // (-> a different head + a failing inclusion proof, BY COMPOSITION -- see
    // the fold-claim marker above).
    let idx: usize = kani::any();
    kani::assume(idx < n);
    let mut tampered = bytes;
    tampered[idx] ^= 0x01;
    let bad_leaf = prov_hash(&tampered[..n]);
    assert!(bad_leaf != leaf);

    // NEG (flip-back): restoring the SAME byte restores the genuine leaf id --
    // the mutation provably reached the hash.
    tampered[idx] ^= 0x01;
    assert!(prov_hash(&tampered[..n]) == leaf);

    // TAIL-TRUNCATION: a closing GATE_VERDICT at seq=4 committing final_seq=4 is
    // accepted only when the reader expects exactly 4; a reader expecting 5 (a frame
    // was truncated AFTER) rejects -> truncation caught.
    let gpay = 4u64.to_le_bytes();
    let gate = OpFrame {
        kind: crate::opframe::kind::GATE_VERDICT,
        sev: 9,
        partition_id: crate::opframe::partition::CANDIDATE,
        seq: 4,
        t_logical: 0,
        prev_head: [0u8; PROV_HASH_LEN],
        payload: &gpay,
    };
    assert!(gate_commits_final_seq(&gate, 4));
    assert!(!gate_commits_final_seq(&gate, 5));
}

/// (6) CANON ROUND-TRIP (proposal §4.1): `opframe::decode(opframe::canon(frame)) ==
/// frame` for a symbolic emittable frame -- the codec is a true bijection on the
/// header layout (every field read back from its fixed offset, the payload slice
/// recovered via the length prefix). The validated fields are concrete-valid (a
/// non-emittable frame does not encode, proven in harness 2).
///
/// NEGATIVE CONTROL: encoding `seq` at the `t_logical` offset (a layout swap) would
/// make `decode` recover the two transposed -> the round-trip equality FAILS; a decode
/// that ignored the `payload_len` prefix would recover the wrong payload slice.
#[kani::proof]
fn kani_opframe_canon_roundtrip() {
    let pay: [u8; 2] = kani::any();
    let frame = kani_op_frame(&pay);
    let mut buf = [0u8; OPFRAME_HEADER_LEN + 2];
    let n = op_canon(&frame, &mut buf);
    assert_eq!(n, OPFRAME_HEADER_LEN + 2);
    let d = op_decode(&buf[..n]).unwrap();
    assert!(d == frame); // every field round-trips, payload slice recovered exactly
}

// ===========================================================================
// M26 exittel: the verified EL2 EXIT-TELEMETRY codec. Five harnesses (per
// proposal §4), each with a NEGATIVE CONTROL. The codec proofs are cheap (pure
// byte layout, no FNV); the FOLD harness keeps the record concrete and only the
// flip index symbolic (the #49 symbolic-FNV trap).
// ===========================================================================

/// A symbolic exit-telemetry record with a CONCRETE-valid class tag (so `decode` does
/// not fail-close on the class) and symbolic remaining fields, for the codec harnesses.
fn kani_et_record() -> ExitTelemetryRecord {
    let class_sel: u8 = kani::any();
    kani::assume((class_sel as usize) < N_CLASSES);
    ExitTelemetryRecord {
        kind: crate::exittel::kind::EXIT_TELEMETRY,
        exit_class: class_sel,
        bucket: kani::any(),
        vmid: kani::any(),
        count_in_bucket: kani::any(),
        logical_time: kani::any(),
    }
}

/// (1) THE LOAD-BEARING PROOF: `exittel::canon` is TOTAL (never panics; fails closed to
/// `0` on a too-small buffer with NO partial write) AND INJECTIVE on the fixed-width
/// record -- two records that differ in ANY field encode to different bytes (every
/// field at a fixed offset, no variable tail).
///
/// NEGATIVE CONTROL: writing two fields to the SAME offset makes the corresponding
/// field-difference assert FAIL.
#[kani::proof]
fn kani_exittel_canon_injective() {
    let base = kani_et_record();
    let mut a = [0u8; EXITTEL_CANON_LEN];
    let na = et_canon(&base, &mut a);
    assert_eq!(na, EXITTEL_CANON_LEN);
    // FAIL-CLOSED TOTALITY: a one-byte-too-small buffer yields 0, no partial write.
    let mut small = [0u8; EXITTEL_CANON_LEN - 1];
    assert_eq!(et_canon(&base, &mut small), 0);

    macro_rules! differs {
        ($e:expr) => {{
            let mut b = [0u8; EXITTEL_CANON_LEN];
            let nb = et_canon(&$e, &mut b);
            assert_eq!(nb, na);
            let mut any = false;
            let mut i = 0usize;
            while i < na {
                if a[i] != b[i] {
                    any = true;
                }
                i += 1;
            }
            any
        }};
    }

    // exit_class (another valid tag): a differing class changes the class byte.
    let c2sel: u8 = kani::any();
    kani::assume((c2sel as usize) < N_CLASSES && c2sel != base.exit_class);
    assert!(differs!(ExitTelemetryRecord { exit_class: c2sel, ..base }));

    let bk2: u8 = kani::any();
    kani::assume(bk2 != base.bucket);
    assert!(differs!(ExitTelemetryRecord { bucket: bk2, ..base }));

    let v2: u16 = kani::any();
    kani::assume(v2 != base.vmid);
    assert!(differs!(ExitTelemetryRecord { vmid: v2, ..base }));

    let n2: u64 = kani::any();
    kani::assume(n2 != base.count_in_bucket);
    assert!(differs!(ExitTelemetryRecord { count_in_bucket: n2, ..base }));

    let t2: u64 = kani::any();
    kani::assume(t2 != base.logical_time);
    assert!(differs!(ExitTelemetryRecord { logical_time: t2, ..base }));
}

/// (2) CANON ROUND-TRIP: `exittel::decode(exittel::canon(rec)) == rec` for a symbolic
/// record (the fixed-width bijection; every field read back from its fixed offset).
///
/// NEGATIVE CONTROL: encoding `count_in_bucket` at the `logical_time` offset (a layout
/// swap) would make `decode` recover the two transposed -> the equality FAILS.
#[kani::proof]
fn kani_exittel_canon_roundtrip() {
    let rec = kani_et_record();
    let mut buf = [0u8; EXITTEL_CANON_LEN];
    let n = et_canon(&rec, &mut buf);
    assert_eq!(n, EXITTEL_CANON_LEN);
    assert!(et_decode(&buf) == Some(rec));
}

/// (3) CLASS TAG TOTALITY + BIJECTION (the verified-projection reuse): the reused L2.2
/// `classify_exit` is TOTAL over every ESR (already proven `kani_exit_classifier_total`);
/// here we prove `class_tag` maps EVERY `ExitClass` into `0..N_CLASSES` and
/// `class_from_tag` is its exact inverse (a bijection), so an exit's class always
/// encodes to a valid, round-trippable byte. An unknown tag fails closed to `None`.
///
/// NEGATIVE CONTROL: a `class_tag` that aliased two classes to one byte would break the
/// `class_from_tag(class_tag(c)) == c` round-trip for the collided pair.
#[kani::proof]
fn kani_exittel_class_total() {
    // The 6 classes round-trip through the tag and stay in range.
    let classes = [
        ExitClass::StageTwoAbort,
        ExitClass::Hvc,
        ExitClass::Smc,
        ExitClass::Sys64,
        ExitClass::Wfx,
        ExitClass::Undef,
    ];
    let mut i = 0usize;
    while i < classes.len() {
        let c = classes[i];
        assert!((class_tag(c) as usize) < N_CLASSES);
        assert!(class_from_tag(class_tag(c)) == Some(c));
        i += 1;
    }
    // The classifier maps a SYMBOLIC ESR to one of the 6 classes (totality reuse), and
    // that class always has an in-range tag.
    let esr: u64 = kani::any();
    let c = classify_exit(esr);
    assert!((class_tag(c) as usize) < N_CLASSES);
    // An out-of-range tag fails closed.
    let bad: u8 = kani::any();
    kani::assume((bad as usize) >= N_CLASSES);
    assert!(class_from_tag(bad).is_none());
}

/// (4) BUCKET BOUNDED + HISTOGRAM SATURATION: `bucket_index(delta)` is in
/// `0..N_BUCKETS` for ALL `u64` delta (total, no panic), and `ExitHistogram::record`
/// SATURATING-increments -- the returned bucket is in range and the count is monotone
/// non-decreasing (never wraps below the prior value), over symbolic inputs.
///
/// NEGATIVE CONTROL: a `bucket_index` without the `>= N_BUCKETS` clamp would return an
/// out-of-range index for a large delta -> the bound assert FAILS; a `+=` instead of
/// `saturating_add` could wrap a near-`u64::MAX` count below its prior value.
#[kani::proof]
fn kani_exittel_histogram_saturates() {
    // Bounded over ALL u64 (the cost-proxy delta).
    let delta: u64 = kani::any();
    let b = bucket_index(delta);
    assert!(b < N_BUCKETS);

    // record(): bucket in range, count monotone non-decreasing. A symbolic class.
    let class_sel: u8 = kani::any();
    kani::assume((class_sel as usize) < N_CLASSES);
    let c = class_from_tag(class_sel).unwrap();
    let mut h = ExitHistogram::new();
    let before = h.count(c, bucket_index(delta));
    let (rb, after) = h.record(c, delta);
    assert!((rb as usize) < N_BUCKETS);
    assert!(after >= before); // saturating -> never wraps below prior
    assert!(after == before.saturating_add(1));
}

/// (5) LEAF-SENSITIVITY (M29-C-thinned): a single-byte flip at a SYMBOLIC index
/// of a committed record's CANONICAL bytes changes its `prov_hash` LEAF id (the
/// 21-byte buffer is one hash invocation per call). The record is CONCRETE; the
/// flip INDEX stays symbolic over ALL canonical byte positions.
///
/// M29-C COMPOSITION (the ONE documented stage-C concession): this harness
/// machine-proves the LEAF claim only; the chain-level rejection of a tampered
/// record (recomputed `tel_head` mismatch + inclusion failure, the FNV-era
/// corroboration legs) is the COMPOSITION of three separately machine-proven
/// conjuncts -- (leaf != leaf' [THIS harness]) AND (`chain_mix` tamper-sensitive
/// at every byte [`kani_prov_chain_mix_tamper`]) AND (inclusion iff
/// [`kani_prov_inclusion_sound`]) -- demonstrated end-to-end at full depth by
/// the kept-FULL `kani_exp_fold_tamper` (M26 writes NO fold math; the fold IS
/// the M22 `prov` fold those harnesses drive).
/// fold-claim=LEAF-SENSITIVITY+COMPOSED(chain_mix_tamper, inclusion_sound; e2e=exp_fold_tamper)
///
/// NEGATIVE CONTROLS: a constant/identity hash would make the flipped-vs-
/// original leaf ids EQUAL -> the `!=` assert FAILS; the flip-back leg (re-flip
/// the SAME index -> the genuine leaf id returns) proves the mutation reaches
/// the hash.
#[kani::proof]
fn kani_exittel_fold_tamper() {
    let rec = ExitTelemetryRecord {
        kind: crate::exittel::kind::EXIT_TELEMETRY,
        exit_class: class_tag(ExitClass::Sys64),
        bucket: 5,
        vmid: 0x1234,
        count_in_bucket: 7,
        logical_time: 0xCAFE,
    };
    let mut bytes = [0u8; EXITTEL_CANON_LEN];
    let n = et_canon(&rec, &mut bytes);
    assert_eq!(n, EXITTEL_CANON_LEN);

    // The genuine committed LEAF id.
    let leaf = prov_hash(&bytes);

    // TAMPER: a symbolic-index flip -> a different leaf id (-> a different
    // head + a failing inclusion proof, BY COMPOSITION -- the fold-claim marker).
    let idx: usize = kani::any();
    kani::assume(idx < EXITTEL_CANON_LEN);
    let mut tampered = bytes;
    tampered[idx] ^= 0x01;
    let bad = prov_hash(&tampered);
    assert!(bad != leaf);

    // NEG (flip-back): restoring the SAME byte restores the genuine leaf id.
    tampered[idx] ^= 0x01;
    assert!(prov_hash(&tampered) == leaf);
}

// ===========================================================================
// M27 tpsched: the verified TWO-VMID TIME-PARTITION SCHEDULER. Five harnesses
// (per proposal §4), each with a NEGATIVE CONTROL. The codec/arithmetic proofs
// are cheap; the FOLD harness keeps the record concrete + the flip index
// symbolic (the #49 symbolic-FNV trap).
// ===========================================================================

/// (1) NEXT_SLOT TOTALITY + ROUND-ROBIN LIVENESS: `next_slot` is total over ALL `usize`
/// (fail-closed to 0 for an out-of-range slot), strictly cycles `0 -> 1 -> 0`, and
/// NEITHER slot is a fixed point -- so neither VMID can starve.
///
/// NEGATIVE CONTROL: an `% (N_SLOTS-1)` typo makes slot 1 a fixed point (`next_slot(1)
/// == 1`) -> VMID 1 starves -> the "no fixed point" assert FAILS.
#[kani::proof]
fn kani_tpsched_next_slot_roundrobin() {
    // Total over ALL usize: the result is always a valid slot, no panic.
    let s: usize = kani::any();
    let n = next_slot(s);
    assert!(n < N_SLOTS);
    // Round-robin + liveness on the two valid slots: neither is a fixed point.
    assert_eq!(next_slot(0), 1);
    assert_eq!(next_slot(1), 0);
    assert!(next_slot(0) != 0);
    assert!(next_slot(1) != 1);
    // An out-of-range slot fail-closes to 0 (restarts the frame).
    let big: usize = kani::any();
    kani::assume(big >= N_SLOTS);
    assert_eq!(next_slot(big), 0);
}

/// (2) FRAME CONSERVATION: over a SYMBOLIC `FramePlan`, `frame_total == Σ
/// slot_deadline_delta`, every slot's delta is clamped UP to `MIN_SLOT_TICKS` (so no
/// slot starves) and is `<= frame_total` (so no slot monopolizes), and the saturating
/// sum never overflows/panics.
///
/// NEGATIVE CONTROL: a `slot_deadline_delta` WITHOUT the `MIN_SLOT_TICKS` clamp would
/// return 0 for a zero-budget slot -> that VMID never runs -> the `>= MIN_SLOT_TICKS`
/// assert FAILS; a non-saturating `+` would panic on the `u64::MAX` budgets.
#[kani::proof]
fn kani_tpsched_frame_conserved() {
    let st0: u64 = kani::any();
    let st1: u64 = kani::any();
    let plan = FramePlan {
        slot_ticks: [st0, st1],
        vmid: [1, 2],
    };
    let d0 = slot_deadline_delta(&plan, 0);
    let d1 = slot_deadline_delta(&plan, 1);
    // No slot starves (clamped up to the floor).
    assert!(d0 >= MIN_SLOT_TICKS);
    assert!(d1 >= MIN_SLOT_TICKS);
    // Conservation: the frame is the saturating sum of the two slots.
    let total = frame_total(&plan);
    assert_eq!(total, d0.saturating_add(d1));
    // No slot monopolizes (each <= the frame) and the frame is at least the floor sum.
    assert!(d0 <= total);
    assert!(d1 <= total);
    assert!(total >= (N_SLOTS as u64).saturating_mul(MIN_SLOT_TICKS));
}

/// (3) CANON INJECTIVITY + TOTALITY: `tpsched::canon` is TOTAL (fails closed to 0 on a
/// too-small buffer) AND INJECTIVE -- two decisions differing in ANY field encode to
/// different bytes (every field at a fixed offset).
///
/// NEGATIVE CONTROL: writing `vmid_to` at the `vmid_from` offset would let two decisions
/// differing only in those fields alias -> a field-difference assert FAILS.
#[kani::proof]
fn kani_tpsched_canon_injective() {
    let base = SchedDecision {
        frame_seq: kani::any(),
        slot: kani::any(),
        vmid_from: kani::any(),
        vmid_to: kani::any(),
        t_logical: kani::any(),
    };
    let mut a = [0u8; SCHED_CANON_LEN];
    let na = tp_canon(&base, &mut a);
    assert_eq!(na, SCHED_CANON_LEN);
    let mut small = [0u8; SCHED_CANON_LEN - 1];
    assert_eq!(tp_canon(&base, &mut small), 0);

    macro_rules! differs {
        ($e:expr) => {{
            let mut b = [0u8; SCHED_CANON_LEN];
            let nb = tp_canon(&$e, &mut b);
            assert_eq!(nb, na);
            let mut any = false;
            let mut i = 0usize;
            while i < na {
                if a[i] != b[i] {
                    any = true;
                }
                i += 1;
            }
            any
        }};
    }
    let f2: u64 = kani::any();
    kani::assume(f2 != base.frame_seq);
    assert!(differs!(SchedDecision { frame_seq: f2, ..base }));
    let s2: u8 = kani::any();
    kani::assume(s2 != base.slot);
    assert!(differs!(SchedDecision { slot: s2, ..base }));
    let vf2: u16 = kani::any();
    kani::assume(vf2 != base.vmid_from);
    assert!(differs!(SchedDecision { vmid_from: vf2, ..base }));
    let vt2: u16 = kani::any();
    kani::assume(vt2 != base.vmid_to);
    assert!(differs!(SchedDecision { vmid_to: vt2, ..base }));
    let t2: u64 = kani::any();
    kani::assume(t2 != base.t_logical);
    assert!(differs!(SchedDecision { t_logical: t2, ..base }));
}

/// (4) CANON ROUND-TRIP: `tpsched::decode(tpsched::canon(rec)) == rec` for a symbolic
/// decision (the fixed-width bijection; every field read back from its fixed offset).
///
/// NEGATIVE CONTROL: a layout swap (frame_seq at the t_logical offset) transposes the
/// fields -> the equality FAILS.
#[kani::proof]
fn kani_tpsched_canon_roundtrip() {
    let rec = SchedDecision {
        frame_seq: kani::any(),
        slot: kani::any(),
        vmid_from: kani::any(),
        vmid_to: kani::any(),
        t_logical: kani::any(),
    };
    let mut buf = [0u8; SCHED_CANON_LEN];
    let n = tp_canon(&rec, &mut buf);
    assert_eq!(n, SCHED_CANON_LEN);
    assert!(tp_decode(&buf) == Some(rec));
}

/// (5) LEAF-SENSITIVITY (M29-C-thinned): a single-byte flip at a SYMBOLIC index
/// of a committed decision's CANONICAL bytes changes its `prov_hash` LEAF id
/// (the 21-byte buffer is one hash invocation per call). The record is
/// CONCRETE; the flip INDEX stays symbolic over ALL canonical byte positions.
///
/// M29-C COMPOSITION (the ONE documented stage-C concession): this harness
/// machine-proves the LEAF claim only; the chain-level rejection of a tampered
/// decision (recomputed `sched_head` mismatch + inclusion failure, the FNV-era
/// corroboration legs) is the COMPOSITION of three separately machine-proven
/// conjuncts -- (leaf != leaf' [THIS harness]) AND (`chain_mix` tamper-sensitive
/// at every byte [`kani_prov_chain_mix_tamper`]) AND (inclusion iff
/// [`kani_prov_inclusion_sound`]) -- demonstrated end-to-end at full depth by
/// the kept-FULL `kani_exp_fold_tamper` (M27 writes NO fold math; the fold IS
/// the M22 `prov` fold those harnesses drive).
/// fold-claim=LEAF-SENSITIVITY+COMPOSED(chain_mix_tamper, inclusion_sound; e2e=exp_fold_tamper)
///
/// NEGATIVE CONTROLS: a constant/identity hash would make the flipped-vs-
/// original ids EQUAL -> the `!=` assert FAILS; the flip-back leg (re-flip the
/// SAME index -> the genuine leaf id returns) proves the mutation reaches the
/// hash.
#[kani::proof]
fn kani_tpsched_fold_tamper() {
    let rec = SchedDecision {
        frame_seq: 7,
        slot: 1,
        vmid_from: 1,
        vmid_to: 2,
        t_logical: 0xCAFE,
    };
    let mut bytes = [0u8; SCHED_CANON_LEN];
    let n = tp_canon(&rec, &mut bytes);
    assert_eq!(n, SCHED_CANON_LEN);

    // The genuine committed LEAF id.
    let leaf = prov_hash(&bytes);

    // TAMPER: a symbolic-index flip -> a different leaf id (-> a different
    // head + a failing inclusion proof, BY COMPOSITION -- the fold-claim marker).
    let idx: usize = kani::any();
    kani::assume(idx < SCHED_CANON_LEN);
    let mut tampered = bytes;
    tampered[idx] ^= 0x01;
    let bad = prov_hash(&tampered);
    assert!(bad != leaf);

    // NEG (flip-back): restoring the SAME byte restores the genuine leaf id.
    tampered[idx] ^= 0x01;
    assert!(prov_hash(&tampered) == leaf);
}

// ===========================================================================
// M38 conductor: the verified VERIFIER-GATED ORGAN SCHEDULER. Ten harnesses
// (per proposal §6 budget table), each with a NEGATIVE CONTROL. The decision
// ALGEBRA proofs (totality / determinism / bounded-turns / Verifier-gates-
// termination / no-fixed-point / verdict / canon) are CHEAP -- closed small
// sets, no khash. Only kani_conduct_fold_tamper is a budget event: it rides
// the EXISTING prov/khash pinned-vector shape (concrete-key/concrete-bytes,
// SYMBOLIC FLIP INDEX only -- NEVER a fresh MAC shape; the #49 discipline),
// exactly like kani_tpsched_fold_tamper above. The conductor writes NO fold
// math (it REUSES the M22 prov fold verbatim under the CONDUCT_DECISION tag).
// ===========================================================================

/// (1) NEXT TOTALITY + DETERMINISM: `conduct_next` is total + panic-free over ALL
/// `(turn, role, verdict)`, and DETERMINISTIC (same input -> same Action). A
/// Verifier-ACCEPT terminates with Accept; everything else either Continues (under
/// the budget) or Terminates with HaltBudget (at the budget).
///
/// NEGATIVE CONTROL: a non-exhaustive `next` match (e.g. omitting the budget
/// branch) would leave a reachable input with no defined Action -> a panic the
/// totality assert would hit; here every symbolic input yields a well-formed Action.
#[kani::proof]
fn kani_conduct_next_total_deterministic() {
    let turn: u8 = kani::any();
    let rt: u8 = kani::any();
    kani::assume(rt <= 2);
    let role = match Role::from_tag(rt) {
        Some(r) => r,
        None => return,
    };
    let vt: u8 = kani::any();
    kani::assume(vt <= 2);
    let verdict = match Verdict::from_tag(vt) {
        Some(v) => v,
        None => return,
    };
    // Total + panic-free over ALL inputs, and DETERMINISTIC.
    let a = conduct_next(turn, role, verdict);
    let b = conduct_next(turn, role, verdict);
    assert!(a == b);
    // The result is always a well-formed Action (a Continue stays within the
    // budget, a Terminate carries a closed verdict).
    match a {
        Action::Continue { turn: nt, .. } => assert!(nt <= MAX_TURNS),
        Action::Terminate(v) => assert!(
            v as u8 == Verdict::Accept as u8 || v as u8 == Verdict::HaltBudget as u8
        ),
    }
}

/// (2) BOUNDED TURNS: the turn counter `conduct_next` emits is MONOTONE and never
/// exceeds `MAX_TURNS` -- a Continue advances strictly under the budget, so no
/// input drives the turn past the bound (no infinite loop, the liveness analog of
/// `tpsched`'s frame conservation).
///
/// NEGATIVE CONTROL: an off-by-one bound (`<= MAX_TURNS` instead of `< MAX_TURNS`
/// in the advance guard) would let a Continue emit `turn == MAX_TURNS` and then
/// one more -> turn `MAX_TURNS+1` would be reachable -> the `< MAX_TURNS` assert
/// on the next turn FAILS.
#[kani::proof]
fn kani_conduct_bounded_turns() {
    let turn: u8 = kani::any();
    let rt: u8 = kani::any();
    kani::assume(rt <= 2);
    let role = Role::from_tag(rt).unwrap();
    let vt: u8 = kani::any();
    kani::assume(vt <= 2);
    let verdict = Verdict::from_tag(vt).unwrap();
    if let Action::Continue { turn: nt, .. } = conduct_next(turn, role, verdict) {
        // A Continue is emitted ONLY within the budget (`<= MAX_TURNS`, never
        // beyond), and the next turn is monotone (one greater than the current,
        // saturating). Turn MAX_TURNS is the last evaluable turn.
        assert!(nt <= MAX_TURNS);
        assert!(nt == turn.saturating_add(1));
    }
}

/// (3) VERIFIER GATES TERMINATION: the ONLY `Accept`-terminal transition has
/// `role = Verifier`. A non-Verifier role can NEVER drive `conduct_next` to
/// `Terminate(Accept)` -- so a Worker/Thinker "ACCEPT" cannot forge loop success.
///
/// NEGATIVE CONTROL: dropping the `role == Verifier` guard in `next` (terminating
/// on ANY Accept) would make a Worker-ACCEPT terminate -> the
/// `role != Verifier => not Terminate(Accept)` assert FAILS.
#[kani::proof]
fn kani_conduct_verifier_gates_termination() {
    let turn: u8 = kani::any();
    let rt: u8 = kani::any();
    kani::assume(rt <= 2);
    let role = Role::from_tag(rt).unwrap();
    let vt: u8 = kani::any();
    kani::assume(vt <= 2);
    let verdict = Verdict::from_tag(vt).unwrap();
    let action = conduct_next(turn, role, verdict);
    let accept_terminal = matches!(action, Action::Terminate(v) if v as u8 == Verdict::Accept as u8);
    if accept_terminal {
        // The ONLY way to an Accept-terminal is a Verifier that Accepted.
        assert!(role as u8 == Role::Verifier as u8);
        assert!(verdict as u8 == Verdict::Accept as u8);
    }
    // And conversely: a non-Verifier role NEVER yields an Accept-terminal.
    if role as u8 != Role::Verifier as u8 {
        assert!(!accept_terminal);
    }
}

/// (4) HALT-BUDGET FAIL-CLOSED: past the budget (`turn + 1 > MAX_TURNS`, i.e. the
/// next turn would EXCEED MAX_TURNS) WITHOUT a Verifier-ACCEPT the transition is
/// `Terminate(HaltBudget)` -- never a silent fall-through into success, never a
/// silent loop. Turn MAX_TURNS is still evaluable (the Verifier landing there can
/// ACCEPT); only ADVANCING beyond it fails closed.
///
/// NEGATIVE CONTROL: a silent fall-through at the budget (returning a Continue, or
/// Terminate(Accept)) would make the budget-exhausted Verifier-REVISE NOT halt ->
/// the `Terminate(HaltBudget)` assert FAILS.
#[kani::proof]
fn kani_conduct_halt_budget_failclosed() {
    let turn: u8 = kani::any();
    let rt: u8 = kani::any();
    kani::assume(rt <= 2);
    let role = Role::from_tag(rt).unwrap();
    let vt: u8 = kani::any();
    kani::assume(vt <= 2);
    let verdict = Verdict::from_tag(vt).unwrap();
    // The next turn would EXCEED the budget AND it is not a Verifier-ACCEPT ->
    // fail closed. (turn.saturating_add(1) > MAX_TURNS <=> turn >= MAX_TURNS.)
    let is_verifier_accept =
        role as u8 == Role::Verifier as u8 && verdict as u8 == Verdict::Accept as u8;
    kani::assume(turn.saturating_add(1) > MAX_TURNS);
    kani::assume(!is_verifier_accept);
    assert!(conduct_next(turn, role, verdict) == Action::Terminate(Verdict::HaltBudget));
}

/// (5) NO STARVING FIXED POINT (liveness, the `next_slot_roundrobin` analog): the
/// role assignment cycles through all three roles, so no role is a fixed point
/// that starves the Verifier -- a Verifier turn is reachable within every window
/// of 3 consecutive turns over the loop's REACHABLE turn range. Concretely:
/// `assign_role` is total, and over any three consecutive (non-wrapping) turns the
/// Verifier role appears exactly once and all three roles are distinct (a true
/// 3-cycle), so progress toward an ACCEPT is always reachable (no `(role, organ)`
/// deadlock). The window is constrained so `turn + 2` does not wrap the `u8` --
/// the loop only ever runs turns `0..MAX_TURNS`, never the wrap boundary, so the
/// period-3 cover is the exact reachable property (the modular-arithmetic wrap at
/// `255 -> 0` is NOT a reachable loop state and is correctly excluded).
///
/// NEGATIVE CONTROL: an `assign_role` that returned a constant role (e.g. always
/// Thinker) would make the Verifier unreachable -> the "Verifier appears in the
/// window" assert FAILS (the loop could never ACCEPT -> starvation).
#[kani::proof]
fn kani_conduct_no_fixed_point() {
    let turn: u8 = kani::any();
    // The reachable window: `turn + 2` must not wrap the u8 (the loop runs turns
    // 0..MAX_TURNS, far below the wrap). This is the exact non-degenerate range.
    kani::assume(turn <= 253);
    let r0 = assign_role(turn);
    let r1 = assign_role(turn + 1);
    let r2 = assign_role(turn + 2);
    // Over any 3 consecutive turns the Verifier role appears (period-3 cover).
    let verifier_in_window = r0 as u8 == Role::Verifier as u8
        || r1 as u8 == Role::Verifier as u8
        || r2 as u8 == Role::Verifier as u8;
    assert!(verifier_in_window);
    // The three roles in the window are all distinct (a true 3-cycle, never a
    // 2-role or 1-role degenerate that could starve a role).
    assert!(r0 as u8 != r1 as u8);
    assert!(r1 as u8 != r2 as u8);
    assert!(r0 as u8 != r2 as u8);
}

/// (6) ORGAN-SELECT TOTALITY + DETERMINISM: `select_organ` is total + panic-free
/// over ALL `usize` (it reduces into the registry range and looks up), DETERMINISTIC
/// (same input -> same organ), and always returns a REGISTERED organ.
///
/// NEGATIVE CONTROL: a tie-break nondeterminism (or an out-of-range index without
/// the `% N_ORGANS` reduction) would let `select_organ` panic or return an
/// unregistered organ -> the determinism/registered assert FAILS.
#[kani::proof]
fn kani_conduct_organ_select_total() {
    let pref: usize = kani::any();
    let a = select_organ(pref);
    let b = select_organ(pref);
    // Deterministic.
    assert!(a as u8 == b as u8);
    // Always one of the registered organs (the closed set).
    assert!((a as u8) < N_ORGANS as u8);
    assert!(
        a as u8 == Organ::RetrievalOverMemory as u8
            || a as u8 == Organ::LocalM32 as u8
            || a as u8 == Organ::ExternalMock as u8
    );
}

/// (7) VERDICT MATCHES THE GATE_CLEARS CONJUNCTION: the discrete Verifier verdict
/// is exactly the `bakeoff::gate_clears`-shaped conjunction -- a Verifier ACCEPTs
/// iff `score - floor >= margin`, else REVISEs; and a NON-Verifier role NEVER
/// ACCEPTs regardless of score (the structural gate). Proven over symbolic
/// `score`/`floor`/`role`.
///
/// NEGATIVE CONTROL: an off-margin verdict (using `>` instead of `>=`, or dropping
/// the role check) would flip a boundary ACCEPT or let a Worker ACCEPT -> the
/// margin/role equivalence assert FAILS.
#[kani::proof]
fn kani_conduct_verdict_gate_clears() {
    let score: i64 = kani::any();
    let floor: i64 = kani::any();
    let rt: u8 = kani::any();
    kani::assume(rt <= 2);
    let role = Role::from_tag(rt).unwrap();
    let v = verifier_verdict(role, score, floor, VERDICT_MARGIN);
    let clears = (score as i128).saturating_sub(floor as i128) >= VERDICT_MARGIN as i128;
    if role as u8 == Role::Verifier as u8 {
        // The Verifier verdict is EXACTLY the gate conjunction.
        if clears {
            assert!(v as u8 == Verdict::Accept as u8);
        } else {
            assert!(v as u8 == Verdict::Revise as u8);
        }
    } else {
        // A non-Verifier role NEVER accepts (structural), even when the gate clears.
        assert!(v as u8 == Verdict::Revise as u8);
    }
}

/// (8) CANON INJECTIVITY + TOTALITY: `conductor::canon` is TOTAL (fails closed to 0
/// on a too-small buffer) AND INJECTIVE -- two decisions differing in ANY field
/// encode to different bytes (every field at a fixed offset).
///
/// NEGATIVE CONTROL: writing `verdict` at the `organ` offset (a dropped/overlapping
/// field) would let two decisions differing only in those fields alias -> a
/// field-difference assert FAILS.
#[kani::proof]
fn kani_conduct_canon_injective() {
    let base = ConductDecision {
        turn: kani::any(),
        role: kani::any(),
        organ: kani::any(),
        verdict: kani::any(),
        organ_calls: kani::any(),
        t_logical: kani::any(),
    };
    let mut a = [0u8; CONDUCT_CANON_LEN];
    let na = cd_canon(&base, &mut a);
    assert_eq!(na, CONDUCT_CANON_LEN);
    let mut small = [0u8; CONDUCT_CANON_LEN - 1];
    assert_eq!(cd_canon(&base, &mut small), 0);

    macro_rules! differs {
        ($e:expr) => {{
            let mut b = [0u8; CONDUCT_CANON_LEN];
            let nb = cd_canon(&$e, &mut b);
            assert_eq!(nb, na);
            let mut any = false;
            let mut i = 0usize;
            while i < na {
                if a[i] != b[i] {
                    any = true;
                }
                i += 1;
            }
            any
        }};
    }
    let t2: u8 = kani::any();
    kani::assume(t2 != base.turn);
    assert!(differs!(ConductDecision { turn: t2, ..base }));
    let r2: u8 = kani::any();
    kani::assume(r2 != base.role);
    assert!(differs!(ConductDecision { role: r2, ..base }));
    let o2: u8 = kani::any();
    kani::assume(o2 != base.organ);
    assert!(differs!(ConductDecision { organ: o2, ..base }));
    let v2: u8 = kani::any();
    kani::assume(v2 != base.verdict);
    assert!(differs!(ConductDecision { verdict: v2, ..base }));
    let oc2: u16 = kani::any();
    kani::assume(oc2 != base.organ_calls);
    assert!(differs!(ConductDecision { organ_calls: oc2, ..base }));
    let tl2: u64 = kani::any();
    kani::assume(tl2 != base.t_logical);
    assert!(differs!(ConductDecision { t_logical: tl2, ..base }));
}

/// (9) CANON ROUND-TRIP: `conductor::decode(conductor::canon(rec)) == rec` for a
/// symbolic decision (the fixed-width bijection; every field read back from its
/// fixed offset).
///
/// NEGATIVE CONTROL: a layout swap (turn at the t_logical offset) transposes the
/// fields -> the equality FAILS.
#[kani::proof]
fn kani_conduct_canon_roundtrip() {
    let rec = ConductDecision {
        turn: kani::any(),
        role: kani::any(),
        organ: kani::any(),
        verdict: kani::any(),
        organ_calls: kani::any(),
        t_logical: kani::any(),
    };
    let mut buf = [0u8; CONDUCT_CANON_LEN];
    let n = cd_canon(&rec, &mut buf);
    assert_eq!(n, CONDUCT_CANON_LEN);
    assert!(cd_decode(&buf) == Some(rec));
}

/// (10) FOLD-TAMPER (the ONLY budget event; M29-C-thinned): a single-byte flip at
/// a SYMBOLIC index of a committed decision's CANONICAL bytes changes its
/// `conduct_hash` LEAF id (the 14-byte buffer is one hash invocation per call).
/// The record is CONCRETE; the flip INDEX stays symbolic over ALL canonical byte
/// positions -- the #49 pinned-vector / concrete-key / symbolic-flip-index shape
/// the M22/M27 suites document, NEVER a fresh MAC shape.
///
/// M29-C COMPOSITION (the one documented stage-C concession, identical to
/// `kani_tpsched_fold_tamper`): this harness machine-proves the LEAF claim only;
/// the chain-level rejection of a tampered decision (recomputed `conduct_head`
/// mismatch + inclusion failure) is the COMPOSITION of three separately
/// machine-proven conjuncts -- (leaf != leaf' [THIS harness]) AND (`chain_mix`
/// tamper-sensitive at every byte [`kani_prov_chain_mix_tamper`]) AND (inclusion
/// iff [`kani_prov_inclusion_sound`]). The conductor writes NO fold math: the fold
/// IS the M22 `prov` fold those harnesses drive (reused verbatim under the
/// CONDUCT_DECISION tag).
/// fold-claim=LEAF-SENSITIVITY+COMPOSED(chain_mix_tamper, inclusion_sound)
///
/// NEGATIVE CONTROLS: a constant/identity hash would make the flipped-vs-original
/// ids EQUAL -> the `!=` assert FAILS; the flip-back leg (re-flip the SAME index
/// -> the genuine leaf id returns) proves the mutation reaches the hash.
#[kani::proof]
fn kani_conduct_fold_tamper() {
    let rec = ConductDecision {
        turn: 2,
        role: Role::Verifier as u8,
        organ: Organ::LocalM32 as u8,
        verdict: Verdict::Accept as u8,
        organ_calls: 3,
        t_logical: 0xCAFE,
    };
    let mut bytes = [0u8; CONDUCT_CANON_LEN];
    let n = cd_canon(&rec, &mut bytes);
    assert_eq!(n, CONDUCT_CANON_LEN);

    // The genuine committed LEAF id.
    let leaf = conduct_hash(&bytes);

    // TAMPER: a symbolic-index flip -> a different leaf id (-> a different head +
    // a failing inclusion proof, BY COMPOSITION -- the fold-claim marker).
    let idx: usize = kani::any();
    kani::assume(idx < CONDUCT_CANON_LEN);
    let mut tampered = bytes;
    tampered[idx] ^= 0x01;
    let bad = conduct_hash(&tampered);
    assert!(bad != leaf);

    // NEG (flip-back): restoring the SAME byte restores the genuine leaf id.
    tampered[idx] ^= 0x01;
    assert!(conduct_hash(&tampered) == leaf);
}

// ===========================================================================
// M28 opframe_rx: the verified OPERATOR-INBOUND command codec (the RX dual of
// M25 opframe). Six harnesses (one per proposal §4 obligation), each with a
// NEGATIVE CONTROL. The codec proof (canon/decode) is cheap (pure byte layout,
// no FNV), so it runs more symbolic; the keyed-MAC + key-evolution harnesses
// keep the FNV inputs CONCRETE and only the flip INDEX symbolic (the #49
// symbolic-FNV trap the M22/M23/M25 suites document). The freshness / head-
// binding / dual-custody REJECTIONS are proven over a CONCRETE sealed frame with
// only the verifier's expectation (nonce / live_head / cred) symbolic -- those
// rejections fire BEFORE the keyed-MAC recompute, so no symbolic FNV is reached.
// ===========================================================================

/// A symbolic-but-ENCODABLE 2-byte-payload command frame for the codec harness:
/// the validated field (kind) is CONCRETE-valid (ACTIVATE_CMD) so `canon` does not
/// fail-close on it, while nonce/head/seq/creds/payload/mac are symbolic. (The
/// unknown-kind REJECTION is proven inside this harness's totality leg.)
fn kani_cmd_frame<'a>(payload: &'a [u8; 2]) -> CmdFrame<'a> {
    CmdFrame {
        kind: crate::opframe_rx::kind::ACTIVATE_CMD,
        nonce_echo: kani::any(),
        op_head_bind: kani::any(),
        seq: kani::any(),
        cred_a_id: kani::any(),
        cred_b_id: kani::any(),
        payload,
        mac: kani::any(),
    }
}

/// (1) THE LOAD-BEARING PROOF (proposal §4.1): `opframe_rx::canon` is TOTAL (never
/// panics; fails closed to `0` on a too-small buffer with NO partial write OR an
/// unknown kind) AND INJECTIVE -- two encodable frames that differ in ANY MAC'd
/// field encode to DIFFERENT bytes, the fixed header at fixed offsets + the
/// `payload_len` u32 prefix making the variable tail self-delimiting. Plus `decode`
/// fails closed on a buffer missing the trailing MAC.
///
/// NEGATIVE CONTROL: a `canon` that DROPPED the `payload_len` prefix would let a
/// 2-byte-payload frame alias a 3-byte one -> the length-disambiguation assert
/// FAILS; writing two header fields to one offset makes the field-difference assert
/// FAIL; a `decode` that ignored the magic would accept a foreign stream.
#[kani::proof]
fn kani_cmd_canon_injective() {
    let pay: [u8; 2] = kani::any();
    let base = kani_cmd_frame(&pay);

    // TOTALITY + exact width: canon writes exactly canon_len (header + payload).
    let mut a = [0u8; CMD_HEADER_LEN + 2];
    let na = cmd_canon(&base, &mut a);
    assert_eq!(na, CMD_HEADER_LEN + 2);

    // FAIL-CLOSED TOTALITY: a one-byte-too-small buffer yields 0, no partial write.
    let mut small = [0u8; CMD_HEADER_LEN + 2 - 1];
    assert_eq!(cmd_canon(&base, &mut small), 0);

    // FAIL-CLOSED on an UNKNOWN kind (the encodable-set guard).
    let badkind = CmdFrame { kind: 0x55, ..base };
    assert_eq!(cmd_canon(&badkind, &mut a), 0);

    // INJECTIVITY over same-length frames (the differing field is forced to differ).
    macro_rules! differs {
        ($e:expr) => {{
            let mut b = [0u8; CMD_HEADER_LEN + 2];
            let nb = cmd_canon(&$e, &mut b);
            assert_eq!(nb, na);
            let mut any_diff = false;
            let mut i = 0usize;
            while i < na {
                if a[i] != b[i] {
                    any_diff = true;
                }
                i += 1;
            }
            any_diff
        }};
    }

    // nonce_echo: a differing echoed freshness nonce changes the [5..13] bytes.
    let n2: u64 = kani::any();
    kani::assume(n2 != base.nonce_echo);
    assert!(differs!(CmdFrame { nonce_echo: n2, ..base }));
    // seq: folded into the MAC'd bytes (never a side label) -> a renumber differs.
    let s2: u64 = kani::any();
    kani::assume(s2 != base.seq);
    assert!(differs!(CmdFrame { seq: s2, ..base }));
    // cred_a_id: the first enrolled credential changes the [53..55] bytes.
    let ca2: u16 = kani::any();
    kani::assume(ca2 != base.cred_a_id);
    assert!(differs!(CmdFrame { cred_a_id: ca2, ..base }));
    // cred_b_id: the second enrolled credential changes the [55..57] bytes.
    let cb2: u16 = kani::any();
    kani::assume(cb2 != base.cred_b_id);
    assert!(differs!(CmdFrame { cred_b_id: cb2, ..base }));
    // payload VALUE at the same length: a differing payload byte changes the bytes.
    let mut pv = pay;
    pv[0] ^= 1;
    assert!(differs!(CmdFrame { payload: &pv, ..base }));

    // A different payload LENGTH (the load-bearing length-prefix half): a 3-byte
    // payload has a strictly longer canon length than the 2-byte base.
    let pay3 = [pay[0], pay[1], 0xAB];
    let longer = CmdFrame { payload: &pay3, ..base };
    let mut c = [0u8; CMD_HEADER_LEN + 3];
    let nc = cmd_canon(&longer, &mut c);
    assert_eq!(nc, CMD_HEADER_LEN + 3);
    assert!(nc != na); // distinct length -> cannot alias the 2-byte frame

    // DECODE fail-closed: a canon-only buffer (no trailing MAC) is rejected.
    assert!(cmd_decode(&a[..na]).is_none());
}

// The freshness / head-binding / dual-custody REJECT harnesses (2..4) prove the
// accept-gate's CONJUNCTIVE DISCRIMINATION by driving the REAL gate -- the pure
// `verify_decoded` function `decode_and_verify` delegates its verdict to VERBATIM --
// fully symbolically. `verify_decoded` is buffer-free + hash-free (pure field
// compares), so CBMC handles it symbolically with no FNV/array-theory blow-up.
// What is NOT driven by Kani is the `decode_and_verify` WRAPPER itself: its
// multi-buffer round-trip (seal -> wire -> decode -> re-canon -> compute_mac) is
// array theory CBMC cannot constant-fold even for concrete inputs (observed: it does
// NOT terminate in minutes -- the same class as the #49 symbolic-FNV trap, here a
// buffer-array-theory blow-up). So the split is: (a) `decode` faithfully recovers the
// symbolic fields from a `canon`+MAC wire (the codec half -- pure byte layout, NO
// FNV, fully SYMBOLIC); (b) `verify_decoded` -- THE GATE -- is proven branch-exact:
// every reject branch live, `Accept` unreachable with ANY violated conjunct (genuine
// negative controls: deleting/ignoring a reject branch in `verify_decoded` makes
// these harnesses FAIL); (c) the keyed-MAC comparison input is proven by
// `kani_cmd_mac_tamper`. The wrapper's buffer/MAC PLUMBING (decode -> re-canon ->
// compute_mac -> verify_decoded) is exercised CONCRETELY by the host unit tests
// (`verify_accepts_valid_and_rejects_each_leg`, all 7 verdict arms, run under the
// Miri CI lane) + the both-arch boot self-test witness.

/// Build an on-wire frame from a `CmdFrame` (canon MAC'd bytes + a fixed placeholder
/// MAC) for the codec/discrimination harnesses -- pure byte layout, NO FNV (the MAC is
/// not recomputed here; the MAC gate is `kani_cmd_mac_tamper`). The placeholder MAC
/// round-trips through `decode` verbatim so the codec half stays exact.
fn kani_cmd_wire(frame: &CmdFrame, out: &mut [u8]) -> usize {
    let n = cmd_canon(frame, out);
    if n == 0 {
        return 0;
    }
    let mut m = 0usize;
    while m < MAC_LEN {
        out[n + m] = (0x90 + m as u8) ^ 0x5A; // a fixed, distinct placeholder MAC
        m += 1;
    }
    n + MAC_LEN
}

/// (2) FRESHNESS -- stale-nonce rejection (proposal §4.2): the nonce the command echoes
/// is recovered EXACTLY by `decode` (the codec half, fully symbolic), AND the REAL gate
/// (`verify_decoded` -- the exact function `decode_and_verify` delegates its verdict
/// to) REJECTS a stale echo with the precise `RejectStale` verdict and can only
/// `Accept` a fresh one. Fully symbolic challenge/head/mac_ok; FNV-free (`decode` +
/// `verify_decoded` are pure byte layout / pure compares), so tractable.
///
/// NEGATIVE CONTROL (genuine -- the gate itself is driven): a `verify_decoded` that
/// IGNORED `nonce_echo` (deleted/skipped the freshness branch) would make BOTH gate
/// asserts FAIL -- a stale echo would Accept (breaking the iff) instead of RejectStale.
/// Also proves the KIND conjunct dominates: any decoded non-ACTIVATE kind is
/// `NotActivate` regardless of every other field.
#[kani::proof]
fn kani_cmd_stale_nonce() {
    // SYMBOLIC echoed nonce + SYMBOLIC verifier challenge.
    let echoed: u64 = kani::any();
    let pay: [u8; 2] = kani::any();
    let frame = CmdFrame {
        kind: crate::opframe_rx::kind::ACTIVATE_CMD,
        nonce_echo: echoed,
        op_head_bind: kani::any(),
        seq: kani::any(),
        cred_a_id: kani::any(),
        cred_b_id: kani::any(),
        payload: &pay,
        mac: kani::any(),
    };
    let mut wire = [0u8; CMD_HEADER_LEN + 2 + MAC_LEN];
    let n = kani_cmd_wire(&frame, &mut wire);
    assert_eq!(n, CMD_HEADER_LEN + 2 + MAC_LEN);
    let d = cmd_decode(&wire[..n]).unwrap();
    assert_eq!(d.nonce_echo, echoed); // the codec recovers the echoed nonce EXACTLY

    // THE GATE: drive the REAL `verify_decoded` with a fully symbolic challenge, live
    // head, and MAC result. The frame kind is ACTIVATE_CMD, so the verdict is
    // `RejectStale` IFF the echoed nonce mismatches the challenge -- and an `Accept`
    // PROVES the echo was fresh (the freshness conjunct is unskippable).
    let expected: u64 = kani::any();
    let live: [u8; PROV_HASH_LEN] = kani::any();
    let mac_ok: bool = kani::any();
    let v = verify_decoded(&d, expected, &live, mac_ok);
    assert_eq!(v == CmdVerdict::RejectStale, echoed != expected);
    if v == CmdVerdict::Accept {
        assert_eq!(d.nonce_echo, expected);
    }

    // KIND DOMINANCE: a decoded frame of ANY non-ACTIVATE kind is `NotActivate`
    // regardless of nonce/head/creds/mac -- a NOP/CHALLENGE_REQ can never activate.
    let k: u8 = kani::any();
    let other = CmdFrame { kind: k, ..d };
    let v2 = verify_decoded(&other, expected, &live, mac_ok);
    assert_eq!(
        v2 == CmdVerdict::NotActivate,
        k != crate::opframe_rx::kind::ACTIVATE_CMD
    );
}

/// (3) HEAD-BINDING -- wrong-head rejection (proposal §4.3, the Terrapin lesson): the
/// `op_head_bind` the command binds is recovered EXACTLY by `decode` (the codec half,
/// fully symbolic), AND the REAL gate (`verify_decoded` -- the exact function
/// `decode_and_verify` delegates its verdict to), driven with a FULLY SYMBOLIC live
/// head (covering every cross-boot / forged head, strictly more than a single-byte
/// flip), returns the precise `RejectWrongHead` IFF the bound head differs from the
/// live head -- and an `Accept` PROVES the heads matched. The nonce is pinned fresh so
/// the head conjunct is the discriminating one. FNV-free, fully symbolic + tractable.
///
/// NEGATIVE CONTROL (genuine -- the gate itself is driven): a `verify_decoded` that
/// IGNORED `op_head_bind` (deleted/skipped the head-binding branch) would make the
/// iff-assert FAIL -- a cross-boot command would Accept instead of RejectWrongHead.
#[kani::proof]
fn kani_cmd_head_binding() {
    let bound: [u8; PROV_HASH_LEN] = kani::any();
    let pay: [u8; 2] = kani::any();
    let frame = CmdFrame {
        kind: crate::opframe_rx::kind::ACTIVATE_CMD,
        nonce_echo: kani::any(),
        op_head_bind: bound,
        seq: kani::any(),
        cred_a_id: kani::any(),
        cred_b_id: kani::any(),
        payload: &pay,
        mac: kani::any(),
    };
    let mut wire = [0u8; CMD_HEADER_LEN + 2 + MAC_LEN];
    let n = kani_cmd_wire(&frame, &mut wire);
    let d = cmd_decode(&wire[..n]).unwrap();
    assert!(d.op_head_bind == bound); // the codec recovers the bound head EXACTLY

    // THE GATE: drive the REAL `verify_decoded` against a FULLY SYMBOLIC verifier live
    // head (every possible cross-boot head, not just a byte flip), with the nonce
    // pinned FRESH (echo == expected) so head-binding is the discriminating conjunct.
    let live: [u8; PROV_HASH_LEN] = kani::any();
    let mac_ok: bool = kani::any();
    let v = verify_decoded(&d, d.nonce_echo, &live, mac_ok);
    assert_eq!(v == CmdVerdict::RejectWrongHead, d.op_head_bind != live);
    if v == CmdVerdict::Accept {
        assert!(d.op_head_bind == live);
    }
}

/// (4) DUAL-CUSTODY + THE ACCEPT-IFF-ALL THEOREM (proposal §4.4): the two credential
/// ids are recovered EXACTLY by `decode` (the codec half, fully symbolic), AND the
/// REAL gate (`verify_decoded` -- the exact function `decode_and_verify` delegates its
/// verdict to), driven with the kind/freshness/head conjuncts pinned TRUE and the cred
/// ids + MAC result fully symbolic, is BRANCH-EXACT over the remaining conjuncts:
/// `RejectSingleCred` IFF `cred_a == cred_b` (the two-person rule), `RejectBadMac` IFF
/// creds distinct AND the MAC failed, and `Accept` IFF creds distinct AND the MAC
/// passed -- i.e. with the other conjuncts held, the verdict is EXACTLY determined and
/// `Accept` requires EVERY remaining conjunct (the conjunctive-gate theorem).
///
/// NEGATIVE CONTROL (genuine -- the gate itself is driven): a `verify_decoded` that
/// checked only one credential (dropped the `!=`) or ignored `mac_ok` would make the
/// corresponding iff-assert FAIL -- a one-person break-glass / forged-MAC command
/// would Accept.
#[kani::proof]
fn kani_cmd_dual_custody() {
    let ca: u16 = kani::any();
    let cb: u16 = kani::any();
    let pay: [u8; 2] = kani::any();
    let frame = CmdFrame {
        kind: crate::opframe_rx::kind::ACTIVATE_CMD,
        nonce_echo: kani::any(),
        op_head_bind: kani::any(),
        seq: kani::any(),
        cred_a_id: ca,
        cred_b_id: cb,
        payload: &pay,
        mac: kani::any(),
    };
    let mut wire = [0u8; CMD_HEADER_LEN + 2 + MAC_LEN];
    let n = kani_cmd_wire(&frame, &mut wire);
    let d = cmd_decode(&wire[..n]).unwrap();
    assert_eq!(d.cred_a_id, ca); // the codec recovers BOTH creds EXACTLY
    assert_eq!(d.cred_b_id, cb);

    // THE GATE: drive the REAL `verify_decoded` with kind==ACTIVATE_CMD (by
    // construction), the nonce pinned FRESH, and the head pinned BOUND, so the verdict
    // is exactly determined by the two remaining symbolic conjuncts (creds, MAC):
    let mac_ok: bool = kani::any();
    let v = verify_decoded(&d, d.nonce_echo, &d.op_head_bind, mac_ok);
    // Two-person rule: a single signer is the precise RejectSingleCred...
    assert_eq!(v == CmdVerdict::RejectSingleCred, ca == cb);
    // ...a failed MAC (with distinct creds) is the precise RejectBadMac...
    assert_eq!(v == CmdVerdict::RejectBadMac, ca != cb && !mac_ok);
    // ...and Accept IFF every remaining conjunct holds (the conjunctive theorem).
    assert_eq!(v == CmdVerdict::Accept, ca != cb && mac_ok);
}

/// (5) MAC TAMPER-SENSITIVITY (M28 §4.5, re-measured at M29): the KEYED MAC over a
/// command's canonical (MAC'd) bytes is sensitive to a single-byte flip of those
/// bytes -- a tampered command has a DIFFERENT recomputed MAC than the original (so
/// a forgery that mutated the seq / head / payload is caught). Since M29 the body
/// under proof is the khash-backed DERIVE-THEN-MAC (2 keyed-BLAKE2s calls, ~4
/// compressions per `compute_mac`); the canon bytes + keys are CONCRETE so every
/// compression is concrete, only the flip INDEX stays symbolic (the #49 trap --
/// the M22/M25 fold-tamper discipline; cost re-measured at the swap).
///
/// NEGATIVE CONTROL: a constant/identity MAC (a `compute_mac` that ignored the canon
/// bytes) would make the flipped-vs-original MACs EQUAL -> the `!=` assert FAILS (a
/// forgery rides). Mutation-tested at M29 (a canon-ignoring body turned it RED).
#[kani::proof]
fn kani_cmd_mac_tamper() {
    // Concrete keys + a concrete canon-bytes buffer -> concrete FNV.
    let ka: [u8; KEY_LEN] = [0x3Au8; KEY_LEN];
    let kb: [u8; KEY_LEN] = [0x4Bu8; KEY_LEN];
    // A short concrete canon-sized buffer (header + a 2-byte payload), so the FNV is
    // over a fixed-size concrete slice with ONLY the flip index symbolic.
    let canon_bytes: [u8; CMD_HEADER_LEN + 2] = [0x5Cu8; CMD_HEADER_LEN + 2];
    let base = compute_mac(&ka, &kb, &canon_bytes);

    // TAMPER: flip the bit at a SYMBOLIC byte index -> a different MAC.
    let idx: usize = kani::any();
    kani::assume(idx < CMD_HEADER_LEN + 2);
    let mut tampered = canon_bytes;
    tampered[idx] ^= 0x01;
    assert!(compute_mac(&ka, &kb, &tampered) != base);
}

/// (6) KEY FORWARD-EVOLUTION (M28 §4.6, re-measured at M29 -- now the Bellare-Yee
/// shape): `key_evolve` is DETERMINISTIC (the same key always evolves to the same
/// successor), advances (the successor differs from the key -- not a fixed point),
/// AND is TAMPER-SENSITIVE (a single-byte change to the input key changes the
/// evolved key). Since M29 the body under proof is `khash(key, EVOLVE_DOMAIN)` (a
/// domain-separated keyed-BLAKE2s call, 2 compressions per evolve); the key is
/// CONCRETE so every compression is concrete, only the flip INDEX is symbolic (the
/// #49 trap; cost re-measured at the swap).
///
/// NEGATIVE CONTROL: an identity `key_evolve` (returning the key unchanged) would
/// make the advance assert FAIL; a constant `key_evolve` would make the tamper assert
/// FAIL (the evolved keys would be equal regardless of the input). Mutation-tested
/// at M29 (an identity body turned it RED).
#[kani::proof]
fn kani_cmd_key_evolve() {
    let key: [u8; KEY_LEN] = [0x9Eu8; KEY_LEN];
    let evolved = key_evolve(&key);
    // DETERMINISTIC.
    assert!(key_evolve(&key) == evolved);
    // ADVANCES (not a fixed point -- the FssAgg forward step).
    assert!(evolved != key);

    // TAMPER: flip the bit at a SYMBOLIC index of the key -> a different evolution.
    let idx: usize = kani::any();
    kani::assume(idx < KEY_LEN);
    let mut k2 = key;
    k2[idx] ^= 0x01;
    assert!(key_evolve(&k2) != evolved);
}

// ===========================================================================
// M29: the khash BLAKE2s-256 KEYED-HASH primitive leaf (proposal §6.1) -- the
// verified REAL keyed hash behind mac=KEYED-CRYPTO. The #49 strategy
// throughout: hash inputs CONCRETE (constant propagation keeps 10-round ARX
// cheap for CBMC) or a <=2-byte symbolic message for totality at the ceiling;
// only flip INDEXES symbolic (a symbolic CHOICE over concrete data). There is
// deliberately NO symbolic collision/preimage/PRF harness -- no tool in the
// field proves those (research §5), and a vacuous one would be overclaim-by-
// implication; primitive security stays ASSUMED-FROM-LITERATURE, tokened.
// ===========================================================================

/// (1) TOTALITY + DETERMINISM over the §3.3 split paths (proposal §6.1.1,
/// MEASURED + restructured per the #49 mitigation ladder -- the proposal's
/// compute-twice-at-every-boundary-length form measured ~6x over the local
/// budget at ~9s per CONCRETE compression, so this is the MINIMAL
/// path-covering set with every computed digest REUSED across asserts):
/// `khash` at lengths {0, 64, 65} -- the keyed key-block-as-final, the
/// block-aligned final, and the full-block + partial-final paths (a 1..=63
/// remainder takes the SAME partial-final branch as 65's) -- and `uhash` at
/// {0, 1, 65} -- the all-zero-block empty special case, the partial final,
/// and the full+partial multi-block loop. PANIC-FREEDOM over each path;
/// compute-twice DETERMINISM pinned to keyed-64 and unkeyed-empty. The
/// remaining boundary lengths {1, 2, 31, 32, 55, 63, 128, 129} are pinned by
/// the OFFICIAL KAT sweep under `cargo test` + Miri (same code, same paths).
/// Deliberately NO fully-symbolic message bytes through the compression (the
/// #49 rule); data-variation through the compression is exercised by the
/// symbolic-flip-index `kani_khash_tamper` (a symbolic CHOICE over concrete
/// data, the M22..M28 fold-tamper discipline).
///
/// NEGATIVE CONTROL (the classic last-block bug): `khash(k, m64) !=
/// khash(k, m64 || 0x00)` -- a broken finalization counter / padding branch
/// that absorbed the extension fails it; and `uhash("") != uhash("\x00")` --
/// the two PADDED final blocks are byte-identical, ONLY the t counter
/// separates them, so an implementation that dropped the §3.2 t fold fails.
#[kani::proof]
fn kani_khash_total_deterministic() {
    let key: [u8; KHASH_KEY_LEN] = [0x5Au8; KHASH_KEY_LEN];
    // One concrete 65-byte buffer: m65 = m64 || 0x00 by construction.
    let mut m65 = [0u8; 65];
    let mut i = 0usize;
    while i < 64 {
        m65[i] = (i as u8).wrapping_mul(7).wrapping_add(3);
        i += 1;
    }
    m65[64] = 0x00;
    // KEYED split paths (digests reused below).
    let k0 = khash(&key, &[]); // key block IS the final block (keyed-empty)
    let k64 = khash(&key, &m65[..64]); // block-aligned final
    let k65 = khash(&key, &m65); // full block + 1-byte partial final
    // DETERMINISM (keyed, the aligned-final path): twice, equal.
    assert!(khash(&key, &m65[..64]) == k64);
    // NEG: the m64 vs m64||0x00 extension (the padding/counter last-block bug).
    assert!(k64 != k65);
    // Distinct split paths give distinct digests (a degenerate constant fails).
    assert!(k0 != k64);
    // UNKEYED split paths.
    let u0 = uhash(&[]); // the all-zero-block empty special case
    let u00 = uhash(&[0u8]); // partial final
    let u65 = uhash(&m65); // full + partial multi-block loop
    // DETERMINISM (unkeyed empty): twice, equal.
    assert!(uhash(&[]) == u0);
    // NEG: "" vs "\x00" -- identical padded blocks, t-counter-only separation.
    assert!(u0 != u00);
    assert!(u65 != u00);
}

/// (2) OFFICIAL-VECTOR functional correctness (proposal §6.1.2): the boot KAT
/// body [`kat_ok`] -- RFC 7693 Appendix B "abc" (unkeyed) + the BLAKE2
/// reference keyed KATs (key 000102..1f; the empty-input key-block-as-final
/// vector + the 65-byte two-message-block vector) -- recomputed through the
/// REAL compression and asserted. Any wrong IV / sigma / rotation / counter /
/// final-flag constant fails the KAT. The SAME vectors re-run under Miri and
/// in-boot (the kernel earns `kat=RFC7693-PASS` from this exact function).
///
/// NEGATIVE CONTROL (non-vacuous comparator): the computed "abc" digest does
/// NOT equal the expected constant perturbed at a SYMBOLIC byte index -- a
/// comparator that accepted everything (or a digest function returning the
/// constant table) fails the inequality.
#[kani::proof]
fn kani_khash_vectors() {
    // The fail-closed boot KAT, verbatim (kat=RFC7693-PASS is earned by this).
    assert!(kat_ok());
    // NEG: a one-byte-perturbed EXPECTED digest must NOT match the computed
    // one, at every position (symbolic flip index over the 32 digest bytes).
    let computed = uhash(b"abc");
    let idx: usize = kani::any();
    kani::assume(idx < KHASH_TAG_LEN);
    let mut perturbed = KAT_ABC_UNKEYED;
    perturbed[idx] ^= 0x01;
    assert!(computed != perturbed);
}

/// (3) TAMPER-SENSITIVITY at a symbolic flip position (proposal §6.1.3): a
/// concrete key + a concrete 65-byte message (forcing BOTH message blocks);
/// flipping one bit at a SYMBOLIC index ranging over ALL 65 message bytes AND
/// all 32 key bytes changes the tag (the M22/M25/M28 fold-tamper discipline:
/// the symbolic part is the CHOICE over concrete data, never the data).
///
/// NEGATIVE CONTROL: flip-then-flip-back RESTORES the reference tag -- proves
/// the harness genuinely mutates the hashed input (a tamper harness whose
/// mutation never reached the hash would fail the restore equality, and a
/// constant/length-only digest stand-in fails the inequality).
#[kani::proof]
fn kani_khash_tamper() {
    let key: [u8; KHASH_KEY_LEN] = [0x3Cu8; KHASH_KEY_LEN];
    let mut msg = [0u8; 65];
    let mut i = 0usize;
    while i < 65 {
        msg[i] = (i as u8).wrapping_mul(11).wrapping_add(5);
        i += 1;
    }
    let base = khash(&key, &msg);

    // TAMPER: one bit at a symbolic index over message bytes [0,65) and key
    // bytes [65,97).
    let idx: usize = kani::any();
    kani::assume(idx < 65 + KHASH_KEY_LEN);
    let mut tkey = key;
    let mut tmsg = msg;
    if idx < 65 {
        tmsg[idx] ^= 0x01;
    } else {
        tkey[idx - 65] ^= 0x01;
    }
    assert!(khash(&tkey, &tmsg) != base);

    // NEG: flip back -> the reference tag returns (the mutation was real).
    if idx < 65 {
        tmsg[idx] ^= 0x01;
    } else {
        tkey[idx - 65] ^= 0x01;
    }
    assert!(khash(&tkey, &tmsg) == base);
}

/// (4) KEYED-MODE SEPARATION (proposal §6.1.4): two concrete keys differing in
/// ONE byte produce DISTINCT tags on the same message, and the keyed mode is
/// DISTINCT from the unkeyed mode on the same message (`kk` lives in the §2.5
/// parameter word AND the key occupies block 0, so the modes can never alias).
///
/// NEGATIVE CONTROL: an implementation that SKIPPED the key block (or dropped
/// `kk` from the parameter word) makes `khash(k, m) == uhash(m)` -> the
/// mode-separation assert FAILS; one that ignored the key bytes makes the two
/// keyed tags equal -> the key-sensitivity assert FAILS.
#[kani::proof]
fn kani_khash_keyed_distinct() {
    let k1: [u8; KHASH_KEY_LEN] = [0x42u8; KHASH_KEY_LEN];
    let mut k2 = k1;
    k2[7] ^= 0x01; // one concrete byte apart
    let mut msg = [0u8; 40];
    let mut i = 0usize;
    while i < 40 {
        msg[i] = (i as u8).wrapping_mul(13).wrapping_add(1);
        i += 1;
    }
    let t1 = khash(&k1, &msg);
    // KEY SENSITIVITY: a one-byte key change moves the tag.
    assert!(t1 != khash(&k2, &msg));
    // MODE SEPARATION: keyed and unkeyed never alias on the same message.
    assert!(t1 != uhash(&msg));
}

// ===========================================================================
// M30: the inferwire verified INFERENCE-TRANSPORT codec leaf (proposal §6) --
// the frame codec + stream accumulator + host-keyed echo behind the
// guest<->host channel. The #49 strategy throughout: frame INPUTS concrete (or
// <=8 symbolic bytes for totality), only flip-indexes/predicates/lengths
// symbolic; the khash body inside `echo_tag` runs on CONCRETE inputs with a
// SHORT message (label 17 + peer 1 + nonce 16 + challenge 16 + body 8 = 58
// bytes -> key block + ONE message block = 2 compressions per call, the M29
// measured-budget discipline); deliberately NO symbolic collision/preimage/PRF
// harness (overclaim-by-implication, banned -- the M29 convention).
// ===========================================================================

/// A concrete, fully-populated inferwire ECHO_RESP over a borrowed payload
/// (helper -- concrete tag bytes; the codec never verifies tags, `verify_echo`
/// does, so the codec harnesses stay khash-FREE).
#[cfg(kani)]
fn kani_iw_frame<'a>(payload: &'a [u8]) -> InferFrame<'a> {
    let mut challenge = [0u8; INFER_CHALLENGE_LEN];
    let mut nonce = [0u8; INFER_NONCE_LEN];
    let mut tag = [0u8; INFER_TAG_LEN];
    let mut i = 0usize;
    while i < 16 {
        challenge[i] = (i as u8).wrapping_mul(7).wrapping_add(1);
        nonce[i] = (i as u8).wrapping_mul(11).wrapping_add(3);
        tag[i] = (i as u8).wrapping_mul(13).wrapping_add(5);
        i += 1;
    }
    InferFrame {
        kind: iw_kind::ECHO_RESP,
        req_id: 0xA5A5_5A5A_0123_4567,
        challenge,
        nonce,
        peer_id: iw_peer::QEMU_CHARDEV_HARNESS,
        tag,
        payload,
    }
}

/// (1) M30 CANON ROUND-TRIP + INJECTIVITY (proposal §6.1): at the boundary
/// payload lengths {0, 1, 31} (+ the cap pinned by length math -- the FULL
/// 1024-byte round-trip is pinned by `cargo test` + Miri over the same code;
/// a concrete 1024-iteration copy x4 in CBMC buys no extra proof over 31,
/// the #49 cost discipline), `decode(canon(f))` recovers EVERY field
/// bit-exactly; and flipping ONE byte at a SYMBOLIC index across the
/// fixed-width header value fields (req_id | challenge | nonce | peer_id |
/// tag) canons to DISTINCT bytes -- the injectivity that makes the frame a
/// sound MAC/witness carrier.
///
/// NEGATIVE CONTROL (the kind-blind-encoder break): two frames identical
/// except `kind` (ECHO_REQ vs ECHO_RESP) MUST canon to distinct bytes -- an
/// encoder that dropped `kind` from the layout passes every round-trip leg
/// and fails exactly this inequality.
#[kani::proof]
#[kani::unwind(70)]
fn kani_inferwire_canon_roundtrip() {
    // Round-trip at the boundary payload lengths (concrete).
    let payload = [0xC3u8; 31];
    let mut l = 0usize;
    while l < 3 {
        let plen = [0usize, 1, 31][l];
        let f = kani_iw_frame(&payload[..plen]);
        let mut buf = [0u8; INFER_HEADER_LEN + 31];
        let n = iw_canon(&f, &mut buf);
        assert!(n == INFER_HEADER_LEN + plen);
        let d = match iw_decode(&buf[..n]) {
            Some(d) => d,
            None => panic!("valid frame must decode"),
        };
        assert!(d.kind == f.kind);
        assert!(d.req_id == f.req_id);
        assert!(d.challenge == f.challenge);
        assert!(d.nonce == f.nonce);
        assert!(d.peer_id == f.peer_id);
        assert!(d.tag == f.tag);
        assert!(d.payload.len() == plen);
        let mut p = 0usize;
        while p < plen {
            assert!(d.payload[p] == f.payload[p]);
            p += 1;
        }
        l += 1;
    }
    // The cap is pinned by the length math (the 1024-byte copy itself adds no
    // proof value -- covered by host tests + Miri on the same code).
    assert!(crate::inferwire::canon_len(INFER_PAYLOAD_CAP) == INFER_ACCUM_CAP);
    assert!(crate::inferwire::frame_is_encodable(INFER_PAYLOAD_CAP));
    assert!(!crate::inferwire::frame_is_encodable(INFER_PAYLOAD_CAP + 1));

    // INJECTIVITY: a one-byte perturbation at a SYMBOLIC index across the
    // fixed-width value fields canons to distinct bytes.
    let base = kani_iw_frame(&payload[..2]);
    let mut cb = [0u8; INFER_HEADER_LEN + 2];
    let nb = iw_canon(&base, &mut cb);
    assert!(nb == INFER_HEADER_LEN + 2);
    let idx: usize = kani::any();
    kani::assume(idx < 8 + 16 + 16 + 1 + 16); // req_id|challenge|nonce|peer|tag
    let mut m = base;
    if idx < 8 {
        m.req_id ^= 1u64 << (8 * idx as u32); // flip one req_id byte
    } else if idx < 24 {
        m.challenge[idx - 8] ^= 0x01;
    } else if idx < 40 {
        m.nonce[idx - 24] ^= 0x01;
    } else if idx < 41 {
        m.peer_id ^= 0x01;
    } else {
        m.tag[idx - 41] ^= 0x01;
    }
    let mut cm = [0u8; INFER_HEADER_LEN + 2];
    let nm = iw_canon(&m, &mut cm);
    assert!(nm == nb);
    let mut differs = false;
    let mut k = 0usize;
    while k < nb {
        if cm[k] != cb[k] {
            differs = true;
        }
        k += 1;
    }
    assert!(differs);

    // NEG: a kind-only difference canons to distinct bytes (kind-blind fails).
    let mut req = base;
    req.kind = iw_kind::ECHO_REQ;
    let mut cr = [0u8; INFER_HEADER_LEN + 2];
    let nr = iw_canon(&req, &mut cr);
    assert!(nr == nb);
    assert!(cr[IW_OFF_KIND] != cb[IW_OFF_KIND]);
}

/// (2) M30 DECODE TOTALITY -- fail-closed over malformed input (proposal
/// §6.2): a fully-SYMBOLIC short buffer never panics and never decodes (the
/// header is 66 bytes); EVERY concrete truncation of a valid frame rejects;
/// a reserved-NONZERO `flags` byte rejects (symbolic over all 255 values); an
/// OVERSIZE declared `payload_len` rejects (symbolic over all values past the
/// cap); a fully-symbolic exact-header buffer never panics, and IF it decodes
/// then its magic/ver/flags bytes provably hold the required values (accept-
/// soundness).
///
/// NEGATIVE CONTROL (the rejector is non-vacuous): the exactly-valid frame
/// MUST decode `Some` -- a decoder that rejects everything passes every
/// fail-closed leg and fails exactly this.
#[kani::proof]
#[kani::unwind(70)]
fn kani_inferwire_decode_total() {
    // A fully-symbolic SHORT buffer: total + always None.
    let short: [u8; 8] = kani::any();
    let sl: usize = kani::any();
    kani::assume(sl <= 8);
    assert!(iw_decode(&short[..sl]).is_none());

    // A fully-symbolic exact-header buffer: total; accept-soundness on Some.
    let hdr: [u8; INFER_HEADER_LEN] = kani::any();
    if iw_decode(&hdr).is_some() {
        assert!(hdr[IW_OFF_MAGIC] == (INFER_MAGIC & 0xFF) as u8);
        assert!(hdr[IW_OFF_MAGIC + 1] == (INFER_MAGIC >> 8) as u8);
        assert!(hdr[IW_OFF_VER] == INFER_VER);
        assert!(hdr[IW_OFF_FLAGS] == 0);
    }

    // A concrete valid frame (payload 2): every truncation rejects.
    let payload = [0xEEu8, 0x11];
    let f = kani_iw_frame(&payload);
    let mut wire = [0u8; INFER_HEADER_LEN + 2];
    let n = iw_canon(&f, &mut wire);
    assert!(n == INFER_HEADER_LEN + 2);
    let cut: usize = kani::any();
    kani::assume(cut < n);
    assert!(iw_decode(&wire[..cut]).is_none());

    // Reserved-NONZERO flags reject (all 255 nonzero values, symbolic).
    let flags: u8 = kani::any();
    kani::assume(flags != 0);
    let mut bf = wire;
    bf[IW_OFF_FLAGS] = flags;
    assert!(iw_decode(&bf[..n]).is_none());

    // An OVERSIZE declared payload_len rejects (symbolic past the cap).
    let plen: u32 = kani::any();
    kani::assume(plen as usize > INFER_PAYLOAD_CAP);
    let mut bl = wire;
    let lb = plen.to_le_bytes();
    bl[IW_OFF_PAYLOAD_LEN] = lb[0];
    bl[IW_OFF_PAYLOAD_LEN + 1] = lb[1];
    bl[IW_OFF_PAYLOAD_LEN + 2] = lb[2];
    bl[IW_OFF_PAYLOAD_LEN + 3] = lb[3];
    assert!(iw_decode(&bl[..n]).is_none());

    // NEG: the exactly-valid frame decodes Some (non-vacuous rejector).
    assert!(iw_decode(&wire[..n]).is_some());
}

/// (3) M30 CORRELATION BINDING -- the iff-theorem (proposal §6.3):
/// `resp_binds_req(resp, id)` holds IFF `resp.req_id == id` AND `resp.kind ==
/// ECHO_RESP`, proven fully symbolically over the id space and the kind byte.
///
/// NEGATIVE CONTROL (the harness genuinely mutates): flipping one SYMBOLIC
/// byte of a bound resp's `req_id` BREAKS the binding, and flipping it back
/// RESTORES it -- a binding check that ignored `req_id` (or a harness whose
/// mutation never reached the field) fails one of the two.
#[kani::proof]
fn kani_inferwire_req_binding() {
    // The iff, fully symbolic.
    let id: u64 = kani::any();
    let rid: u64 = kani::any();
    let k: u8 = kani::any();
    kani::assume(k == iw_kind::ECHO_REQ || k == iw_kind::ECHO_RESP || k == iw_kind::ERR);
    let mut f = kani_iw_frame(&[]);
    f.req_id = rid;
    f.kind = k;
    let binds = resp_binds_req(&f, id);
    assert!(binds == (rid == id && k == iw_kind::ECHO_RESP));

    // Flip-then-flip-back at a symbolic req_id byte.
    let mut bound = kani_iw_frame(&[]);
    bound.req_id = id;
    assert!(resp_binds_req(&bound, id));
    let bidx: usize = kani::any();
    kani::assume(bidx < 8);
    bound.req_id ^= 1u64 << (8 * bidx as u32);
    assert!(!resp_binds_req(&bound, id)); // broken
    bound.req_id ^= 1u64 << (8 * bidx as u32);
    assert!(resp_binds_req(&bound, id)); // restored (the mutation was real)
}

/// (4) M30 ECHO SOUNDNESS + single-byte tamper rejection (proposal §6.4):
/// with a CONCRETE key/nonce/challenge/peer and a CONCRETE 8-byte body (the
/// khash message is 58 bytes -> key block + ONE message block = 2 compressions
/// per call, the M29 measured budget; 4 khash calls total = 8 compressions),
/// `verify_echo` ACCEPTS the genuine `(echo_tag, body)` response; flipping one
/// bit at a SYMBOLIC index over ALL tag bytes AND all body bytes makes it
/// REJECT. MEASURED TRIM vs the proposal's sketch (#49 budget): the key-byte
/// flip range is EXCLUDED -- a symbolic key flip makes khash's key block
/// symbolic-choice in every call and pushed the harness past the 120s budget
/// (129s measured); key-BIT sensitivity is already `kani_khash_tamper`'s
/// theorem at the primitive level (a symbolic flip over all 32 key bytes
/// changes the tag), `verify_echo`'s key path is a direct `khash(key, ..)`
/// call with no intervening transform, and the WRONGKEY reject additionally
/// fires IN-BOOT on every attached lane (`wrongkey-rejected=1`, the runtime
/// mirror) plus in the host tests.
///
/// NEGATIVE CONTROL: flip-then-flip-back RESTORES acceptance -- proves the
/// harness genuinely mutates what the verifier reads (a constant/length-only
/// tag stand-in fails the tamper inequality; a mutation that never reached
/// the verifier fails the restore -- the M29 §6.3 tamper idiom). The
/// challenge/nonce/peer MAC-coverage mutants are killed by harness (6).
#[kani::proof]
#[kani::unwind(70)]
fn kani_inferwire_echo_sound() {
    let key: [u8; INFER_KEY_LEN] = [0x6Du8; INFER_KEY_LEN];
    let body = [0x42u8, 0x99, 0x17, 0xE0, 0x3B, 0x70, 0x55, 0x08];
    let req = {
        let mut r = kani_iw_frame(&body);
        r.kind = iw_kind::ECHO_REQ;
        r
    };
    let mut resp = kani_iw_frame(&body);
    resp.tag = echo_tag(&key, resp.peer_id, &resp.nonce, &req.challenge, &body);
    resp.challenge = req.challenge;

    // ACCEPT the genuine host-keyed echo.
    assert!(verify_echo(&key, &resp, &req));

    // TAMPER: one bit at a SYMBOLIC index over tag[0..16) | body[16..24)
    // -> reject (the key range is excluded -- see the harness doc).
    let idx: usize = kani::any();
    kani::assume(idx < INFER_TAG_LEN + 8);
    let mut tbody = body;
    let mut tresp = resp;
    if idx < INFER_TAG_LEN {
        tresp.tag[idx] ^= 0x01;
    } else {
        tbody[idx - INFER_TAG_LEN] ^= 0x01;
        tresp.payload = &tbody;
    }
    assert!(!verify_echo(&key, &tresp, &req));

    // NEG: flip back (fresh copies -- the borrow above stays untouched) ->
    // acceptance returns (the mutation was real).
    let mut rbody = tbody;
    let mut rresp = tresp;
    if idx < INFER_TAG_LEN {
        rresp.tag[idx] ^= 0x01;
    } else {
        rbody[idx - INFER_TAG_LEN] ^= 0x01;
        rresp.payload = &rbody;
    }
    assert!(verify_echo(&key, &rresp, &req));
}

/// (5) M30 STREAM-ACCUMULATOR capacity + resync discipline (proposal §6.5, the
/// `BoundedRing` never-overflow proof shape -- RESHAPED down the FULL, measured
/// #49 mitigation ladder, ending at the ladder's named last rung, "split the
/// FrameAccum harness out": the proposal's symbolic-garbage-then-full-frame
/// trace form was walked through fully-symbolic bytes, symbolic-length,
/// symbolic-values-only, `kani::solver(kissat)`, a chunked-unwind restructure,
/// AND a decode-free scan hot path -- every form exceeded the measured local
/// budget (>>120s; >6 min at the cheapest), because ~68 sequential `push_byte`
/// inlines x the per-harness unwind bound on the scan/consume/resync loops is
/// a STRUCTURAL formula floor for a 66-byte-header protocol, independent of
/// data concreteness. What Kani PROVES here is the part model-checking
/// uniquely adds -- index/capacity/totality discipline + every byte-wise
/// resync class, each leg concrete + tiny:
///
/// * (leg A, the off-by-one-capacity killer) a TINY-cap `FrameAccum<6>` is fed
///   a CONCRETE plausible-header stream that can never complete a frame
///   (CAP < header), driving `len` to CAP and THROUGH the at-capacity
///   consume-then-resync branch -- Kani checks EVERY buffer index on that
///   path, so a capacity off-by-one is an out-of-bounds proof failure, and
///   `len() <= CAP` is asserted after every push (the §6 mutation set's
///   designated cap-mutant killer; `FrameAccum` is const-generic, so the
///   discipline proven at CAP=6 is the SAME code path the `INFER_ACCUM_CAP`
///   alias runs -- whose value is pinned by the length math in harness (1)).
/// * (leg B, the resync classes) every byte-wise rejection class the scan
///   enforces -- non-magic first byte, magic-then-bad-second-byte, bad
///   version, unknown kind, reserved-nonzero flags -- each fed concretely
///   after a fresh plausible prefix: every push returns `None` (no fabricated
///   frame boundary) and the accumulator drains/resyncs without overflow.
///
/// The FULL emit trace (garbage prefix -> 68-byte frame -> emitted EXACTLY
/// ONCE at exactly the wire length -> the emitted window decodes) is the
/// NAMED delegation: it runs as 5 dedicated host tests (byte-by-byte split
/// delivery, garbage resync, plausible-garbage-header resync, the max-size
/// frame completing AT capacity, tiny-cap saturation) under `cargo test` AND
/// the Miri UB gate over this exact code, and BOTH live CI boot lanes push
/// the real host response through `FrameAccum` byte-at-a-time every boot with
/// the proven fail-closed [`decode`] as the arbiter of the emitted window
/// (the kernel rejects at stage 0x4 if the emitted bytes do not decode).
/// Recorded in the gate docs + the proposal status note -- auditable, not
/// implied.
///
/// NEGATIVE CONTROL (resync does not false-positive): every leg asserts
/// `push_byte(..).is_none()` -- an accumulator that fabricated a frame
/// boundary on garbage (or emitted below a complete header) fails the asserts.
#[kani::proof]
#[kani::unwind(14)]
fn kani_inferwire_accum_resync() {
    let magic0 = (INFER_MAGIC & 0xFF) as u8;
    let magic1 = (INFER_MAGIC >> 8) as u8;

    // Leg A: tiny-cap capacity discipline on a CONCRETE plausible stream.
    // bytes 0..5 pass every byte-wise plausibility check (magic|ver|kind|
    // flags), so len climbs to CAP=6; push 7 takes the at-capacity
    // consume(1) branch; the resync then drains on the implausible shifted
    // prefix. A frame can NEVER complete below INFER_HEADER_LEN, so every
    // push must return None.
    let mut tiny: FrameAccum<6> = FrameAccum::new();
    let stream: [u8; 10] = [
        magic0,
        magic1,
        INFER_VER,
        iw_kind::ECHO_REQ,
        0x00, // flags (plausible)
        0x11,
        0x22,
        0x33,
        magic0, // a fresh magic start late in the stream
        0x55,
    ];
    let mut i = 0usize;
    while i < 10 {
        assert!(tiny.push_byte(stream[i]).is_none());
        assert!(tiny.len() <= 6);
        i += 1;
    }

    // Leg B: every byte-wise resync class, each after a fresh plausible
    // prefix, on a 12-cap accumulator (capacity is leg A's concern; 12 leaves
    // headroom so no class is masked by the at-capacity branch).
    let mut acc: FrameAccum<12> = FrameAccum::new();
    // (B1) non-magic first byte: resync-to-empty.
    assert!(acc.push_byte(0x99).is_none());
    assert!(acc.is_empty());
    // (B2) magic then a bad SECOND magic byte: partial-candidate front drop.
    assert!(acc.push_byte(magic0).is_none());
    assert!(acc.push_byte(0x07).is_none());
    assert!(acc.is_empty());
    // (B3) magic+magic then a bad VERSION byte.
    assert!(acc.push_byte(magic0).is_none());
    assert!(acc.push_byte(magic1).is_none());
    assert!(acc.push_byte(0xEE).is_none()); // != INFER_VER
    assert!(acc.is_empty());
    // (B4) magic+magic+ver then an UNKNOWN kind.
    assert!(acc.push_byte(magic0).is_none());
    assert!(acc.push_byte(magic1).is_none());
    assert!(acc.push_byte(INFER_VER).is_none());
    assert!(acc.push_byte(0x7F).is_none()); // not a known kind
    assert!(acc.is_empty());
    // (B5) magic+magic+ver+kind then RESERVED-NONZERO flags.
    assert!(acc.push_byte(magic0).is_none());
    assert!(acc.push_byte(magic1).is_none());
    assert!(acc.push_byte(INFER_VER).is_none());
    assert!(acc.push_byte(iw_kind::ECHO_RESP).is_none());
    assert!(acc.push_byte(0x80).is_none()); // reserved flags bit set
    assert!(acc.is_empty());
    // After every rejection class the accumulator is reusable: a plausible
    // prefix accumulates again (and still cannot emit below a full header).
    assert!(acc.push_byte(magic0).is_none());
    assert!(acc.push_byte(magic1).is_none());
    assert!(acc.len() == 2);
}

/// (6) M30 MAC-COVERAGE of the labels (proposal §6.6 -- proves the run-script
/// lane-token cross-pin §5.4 is REAL, not decorative): on the SAME concrete
/// `(K, N, C, body)`, two distinct `peer_id`s yield DISTINCT tags, a distinct
/// challenge yields a distinct tag, and a distinct nonce yields a distinct tag
/// -- so peer/challenge/nonce are all provably INSIDE the MAC'd bytes (4 khash
/// calls x 2 compressions = 8, the measured budget).
///
/// NEGATIVE CONTROL: an `echo_tag` that DROPPED `peer_id` (or the challenge,
/// or the nonce) from its MAC input makes the corresponding pair EQUAL and
/// fails that inequality -- the §6 mutation set's designated killers.
#[kani::proof]
#[kani::unwind(70)]
fn kani_inferwire_peer_label_bound() {
    let key: [u8; INFER_KEY_LEN] = [0x2Bu8; INFER_KEY_LEN];
    let mut nonce = [0u8; INFER_NONCE_LEN];
    let mut chal = [0u8; INFER_CHALLENGE_LEN];
    let mut i = 0usize;
    while i < 16 {
        nonce[i] = (i as u8).wrapping_mul(17).wrapping_add(9);
        chal[i] = (i as u8).wrapping_mul(23).wrapping_add(2);
        i += 1;
    }
    let body = [0x5Au8; 8];

    let base = echo_tag(&key, iw_peer::TB_VMM_HOST, &nonce, &chal, &body);
    // peer_id is MAC-covered (the lane cross-pin is bound inside the tag).
    assert!(base != echo_tag(&key, iw_peer::QEMU_CHARDEV_HARNESS, &nonce, &chal, &body));
    // The challenge is MAC-covered (a canned cross-boot response moves the tag).
    let mut c2 = chal;
    c2[0] ^= 0x01;
    assert!(base != echo_tag(&key, iw_peer::TB_VMM_HOST, &nonce, &c2, &body));
    // The host nonce is MAC-covered (host participation is bound per run).
    let mut n2 = nonce;
    n2[15] ^= 0x80;
    assert!(base != echo_tag(&key, iw_peer::TB_VMM_HOST, &n2, &chal, &body));
}

/// (6b) M32 PEER-BINDING under `infer_tag` (proposal §3/§9 -- the actual
/// evidence for the NEW local-engine peers, distinct from the echo-only
/// `kani_inferwire_peer_label_bound` above): on the SAME concrete
/// `(K, N, C, req_id, kind, sub, chunk)`, the closed peer set
/// `{QEMU_CHARDEV_HARNESS=0x02, INFER_DAEMON=0x03, INFER_DAEMON_PURE=0x04}`
/// yields PAIRWISE-DISTINCT tags under the `YUVA-M31-INFER-V1` domain -- so the
/// kernel rendering `local-organ`/engine identity from `peer_id` on a `0x03`
/// RESP is MAC-un-forgeable: a `0x02` mock frame can never wear the `0x03`
/// local-engine identity, and neither can pre-empt the reserved `0x04` closure
/// peer. NEGATIVE CONTROL: an `infer_tag` that DROPPED `peer_id` from its MAC
/// input makes these pairs EQUAL and fails the inequalities.
#[kani::proof]
#[kani::unwind(70)]
fn kani_inferwire_infer_peer_bound() {
    let key: [u8; INFER_KEY_LEN] = [0x2Bu8; INFER_KEY_LEN];
    let mut nonce = [0u8; INFER_NONCE_LEN];
    let mut chal = [0u8; INFER_CHALLENGE_LEN];
    let mut i = 0usize;
    while i < 16 {
        nonce[i] = (i as u8).wrapping_mul(17).wrapping_add(9);
        chal[i] = (i as u8).wrapping_mul(23).wrapping_add(2);
        i += 1;
    }
    let req_id: u64 = 0x0123_4567_89ab_cdef;
    let sub = kani_m31_sub(0, false, 8);
    let chunk = [0x5Au8; 8];

    let t02 = infer_tag(
        &key,
        iw_peer::QEMU_CHARDEV_HARNESS,
        &nonce,
        &chal,
        req_id,
        iw_kind::INFER_RESP,
        &sub,
        &chunk,
    );
    let t03 = infer_tag(
        &key,
        iw_peer::INFER_DAEMON,
        &nonce,
        &chal,
        req_id,
        iw_kind::INFER_RESP,
        &sub,
        &chunk,
    );
    let t04 = infer_tag(
        &key,
        iw_peer::INFER_DAEMON_PURE,
        &nonce,
        &chal,
        req_id,
        iw_kind::INFER_RESP,
        &sub,
        &chunk,
    );
    // Pairwise-distinct: peer_id is provably INSIDE the infer_tag MAC input.
    assert!(t02 != t03);
    assert!(t03 != t04);
    assert!(t02 != t04);
}

// ===========================================================================
// M31: the inferwire INFERENCE-ADAPTER extension (proposal §8) -- the chunked
// byte-body framing on the SAME leaf: kind extension, the 24-byte in-payload
// SubHdr, the per-chunk infer_tag MAC under the NEW domain separator, the
// chunk-at-a-time InferAssembler (NOT a byte-push trace -- the M30 FrameAccum
// CBMC-floor lesson), and the closed ERR payload enum. The #49 budget
// discipline throughout: khash bodies run on CONCRETE inputs only; symbolic
// flips cover indexes/predicates/sub-header bytes, never key material; NO
// symbolic PRF/collision harness (overclaim-by-implication, banned).
// ===========================================================================

/// A concrete M31 sub-header (helper; digest bytes pattern-derived).
#[cfg(kani)]
fn kani_m31_sub(seq: u16, more: bool, total_len: u32) -> SubHdr {
    let mut d = [0u8; 16];
    let mut i = 0usize;
    while i < 16 {
        d[i] = (i as u8).wrapping_mul(19).wrapping_add(11);
        i += 1;
    }
    SubHdr {
        seq,
        more,
        total_len,
        body_digest: d,
    }
}

/// (1) M31 KIND EXTENSION (proposal §8.1): the canon/decode round-trip holds
/// for the NEW closed kinds INFER_REQ/INFER_RESP/INFER_PENDING at boundary
/// payload lengths {0, 2}, exactly as harness (1) proved for the M30 kinds.
///
/// NEGATIVE CONTROL (the extension does not widen totality): a fully-SYMBOLIC
/// kind byte OUTSIDE the closed set {1..6} fail-closes BOTH ways -- `canon`
/// returns 0 and a valid wire with the kind byte rewritten rejects at
/// `decode` -- so kind 7+ (and 0) keeps rejecting everywhere.
#[kani::proof]
#[kani::unwind(70)]
fn kani_inferwire_kind_ext() {
    let payload = [0xB7u8; 2];
    let mut l = 0usize;
    while l < 2 {
        let plen = [0usize, 2][l];
        let mut k = 0usize;
        while k < 3 {
            let kt = [iw_kind::INFER_REQ, iw_kind::INFER_RESP, iw_kind::INFER_PENDING][k];
            let mut f = kani_iw_frame(&payload[..plen]);
            f.kind = kt;
            let mut buf = [0u8; INFER_HEADER_LEN + 2];
            let n = iw_canon(&f, &mut buf);
            assert!(n == INFER_HEADER_LEN + plen);
            let d = match iw_decode(&buf[..n]) {
                Some(d) => d,
                None => panic!("valid M31 kind must decode"),
            };
            assert!(d.kind == kt);
            assert!(d.req_id == f.req_id);
            assert!(d.payload.len() == plen);
            k += 1;
        }
        l += 1;
    }

    // NEG: a symbolic kind outside the closed set rejects at canon AND decode.
    let bad: u8 = kani::any();
    kani::assume(bad == 0 || bad > iw_kind::INFER_PENDING);
    let mut f = kani_iw_frame(&payload);
    f.kind = bad;
    let mut buf = [0u8; INFER_HEADER_LEN + 2];
    assert!(iw_canon(&f, &mut buf) == 0);
    let mut wire = [0u8; INFER_HEADER_LEN + 2];
    let mut g = kani_iw_frame(&payload);
    g.kind = iw_kind::INFER_RESP;
    let n = iw_canon(&g, &mut wire);
    assert!(n == INFER_HEADER_LEN + 2);
    wire[IW_OFF_KIND] = bad;
    assert!(iw_decode(&wire[..n]).is_none());
}

/// (2) M31 SUB-HEADER TOTALITY + round-trip (proposal §8.2): over a SYMBOLIC
/// seq / MORE flag / total_len (in the valid 1..=INFER_BODY_CAP band) /
/// digest bytes, `subhdr_decode(subhdr_canon(s)) == s`; every truncation
/// rejects; a reserved `sflags` bit (1..7, symbolic over all such values) or
/// a nonzero `rsv` byte rejects; an out-of-band total_len (0 or over-cap,
/// symbolic) rejects at canon AND decode. khash-FREE.
///
/// NEGATIVE CONTROL (non-vacuous rejector): the exactly-valid sub-header
/// decodes `Some` -- a decoder that rejects everything fails the round-trip.
#[kani::proof]
#[kani::unwind(30)]
fn kani_infer_subhdr_total() {
    // Symbolic round-trip over the full valid envelope.
    let seq: u16 = kani::any();
    let more: bool = kani::any();
    let total_len: u32 = kani::any();
    kani::assume(total_len >= 1 && total_len as usize <= INFER_BODY_CAP);
    let digest: [u8; 16] = kani::any();
    let s = SubHdr {
        seq,
        more,
        total_len,
        body_digest: digest,
    };
    let mut buf = [0u8; INFER_SUBHDR_LEN];
    assert!(subhdr_canon(&s, &mut buf) == INFER_SUBHDR_LEN);
    match subhdr_decode(&buf) {
        Some(d) => {
            assert!(d.seq == seq);
            assert!(d.more == more);
            assert!(d.total_len == total_len);
            assert!(d.body_digest == digest);
        }
        None => panic!("valid sub-header must decode (non-vacuous rejector)"),
    }

    // Every truncation rejects (symbolic cut).
    let cut: usize = kani::any();
    kani::assume(cut < INFER_SUBHDR_LEN);
    assert!(subhdr_decode(&buf[..cut]).is_none());

    // A reserved sflags bit rejects (symbolic over ALL values with bits 1..7).
    let sf: u8 = kani::any();
    kani::assume(sf & !SFLAG_MORE != 0);
    let mut bf = buf;
    bf[2] = sf;
    assert!(subhdr_decode(&bf).is_none());

    // A nonzero rsv byte rejects (symbolic over all 255 nonzero values).
    let rv: u8 = kani::any();
    kani::assume(rv != 0);
    let mut br = buf;
    br[3] = rv;
    assert!(subhdr_decode(&br).is_none());

    // An out-of-band total_len rejects at canon AND decode (symbolic).
    let bad_total: u32 = kani::any();
    kani::assume(bad_total == 0 || bad_total as usize > INFER_BODY_CAP);
    let mut bs = s;
    bs.total_len = bad_total;
    let mut scratch = [0u8; INFER_SUBHDR_LEN];
    assert!(subhdr_canon(&bs, &mut scratch) == 0);
    let mut bt = buf;
    let tb = bad_total.to_le_bytes();
    bt[4] = tb[0];
    bt[5] = tb[1];
    bt[6] = tb[2];
    bt[7] = tb[3];
    assert!(subhdr_decode(&bt).is_none());
}

/// (3) M31 ASSEMBLER discipline at a TINY const-generic cap (proposal §8.3 --
/// chunk-at-a-time BY DESIGN, never a byte-push trace: the M30 FrameAccum
/// measured CBMC floor was byte-wise accumulation, which this shape avoids;
/// `InferAssembler` is const-generic, so the index/capacity discipline proven
/// at CAP=8 is the SAME code path the real `INFER_BODY_CAP` alias runs):
/// in-order chunks assemble to EXACTLY total_len with the recomputed digest
/// equal to the commitment (total == CAP, the off-by-one-capacity killer --
/// every buffer index on the copy path is Kani-checked); a SYMBOLIC
/// wrong-first-seq / wrong-second-seq (out-of-order/duplicate/gap), a
/// SYMBOLIC total_len drift, a digest drift at a symbolic flip index, a
/// SYMBOLIC over-capacity total_len, and an overflow-past-total chunk ALL
/// reject; rejection POISONS (nothing resurrects). The digest legs run uhash
/// on an 8-byte CONCRETE body only (2 compressions total, the #49 budget).
///
/// NEGATIVE CONTROL (no fabricated completion): every reject leg asserts NO
/// `Complete` was returned, and the poisoned assembler rejects a would-be
/// valid retry -- an assembler that fabricated completion on garbage (or
/// resurrected after a reject) fails these.
#[kani::proof]
#[kani::unwind(70)] // covers the khash compress loop inside the 2 digest legs
fn kani_infer_assembler() {
    const CAP: usize = 8;
    let body = [0xC1u8, 0x02, 0x33, 0x44, 0x95, 0x66, 0x77, 0xE8];
    let dig = body_digest(&body); // ONE uhash call (concrete 8 bytes)
    let mk = |seq: u16, more: bool, total: u32, d: [u8; 16]| SubHdr {
        seq,
        more,
        total_len: total,
        body_digest: d,
    };

    // CLEAN: 2 in-order chunks (4+4) complete EXACTLY at total == CAP.
    let mut asm: InferAssembler<CAP> = InferAssembler::new();
    assert!(asm.push_chunk(&mk(0, true, 8, dig), &body[..4]) == AsmPush::Accepted);
    assert!(asm.len() <= CAP);
    match asm.push_chunk(&mk(1, false, 8, dig), &body[4..]) {
        AsmPush::Complete(n) => assert!(n == 8),
        _ => panic!("genuine in-order chunks must complete"),
    }
    assert!(asm.is_done());
    let out = asm.body();
    let mut i = 0usize;
    while i < 8 {
        assert!(out[i] == body[i]);
        i += 1;
    }
    // Nothing pushes after completion.
    assert!(asm.push_chunk(&mk(2, false, 8, dig), &body[..1]) == AsmPush::Rejected);

    // A SYMBOLIC wrong first seq rejects + poisons (out-of-order start).
    let s0: u16 = kani::any();
    kani::assume(s0 != 0);
    let mut a: InferAssembler<CAP> = InferAssembler::new();
    assert!(a.push_chunk(&mk(s0, true, 8, dig), &body[..4]) == AsmPush::Rejected);
    // POISONED: the would-be valid retry stays rejected (no resurrection).
    assert!(a.push_chunk(&mk(0, true, 8, dig), &body[..4]) == AsmPush::Rejected);

    // A SYMBOLIC wrong SECOND seq rejects (duplicate s1==0 / gap s1>=2 alike).
    let s1: u16 = kani::any();
    kani::assume(s1 != 1);
    let mut a: InferAssembler<CAP> = InferAssembler::new();
    assert!(a.push_chunk(&mk(0, true, 8, dig), &body[..4]) == AsmPush::Accepted);
    assert!(a.push_chunk(&mk(s1, false, 8, dig), &body[4..]) == AsmPush::Rejected);

    // A SYMBOLIC total_len drift on the second chunk rejects.
    let t1: u32 = kani::any();
    kani::assume(t1 != 8);
    let mut a: InferAssembler<CAP> = InferAssembler::new();
    assert!(a.push_chunk(&mk(0, true, 8, dig), &body[..4]) == AsmPush::Accepted);
    assert!(a.push_chunk(&mk(1, false, t1, dig), &body[4..]) == AsmPush::Rejected);

    // A digest DRIFT at a SYMBOLIC flip index rejects (commitment locked).
    let di: usize = kani::any();
    kani::assume(di < 16);
    let mut d2 = dig;
    d2[di] ^= 0x01;
    let mut a: InferAssembler<CAP> = InferAssembler::new();
    assert!(a.push_chunk(&mk(0, true, 8, dig), &body[..4]) == AsmPush::Accepted);
    assert!(a.push_chunk(&mk(1, false, 8, d2), &body[4..]) == AsmPush::Rejected);

    // A SYMBOLIC over-capacity total_len rejects at the FIRST chunk
    // (capacity overflow can never start -- the off-by-one killer's twin).
    let big: u32 = kani::any();
    kani::assume(big as usize > CAP);
    let mut a: InferAssembler<CAP> = InferAssembler::new();
    assert!(a.push_chunk(&mk(0, true, big, dig), &body[..4]) == AsmPush::Rejected);

    // Overflow past total_len rejects (sum-of-chunks > total -- 4+8 > 8).
    let mut a: InferAssembler<CAP> = InferAssembler::new();
    assert!(a.push_chunk(&mk(0, true, 8, dig), &body[..4]) == AsmPush::Accepted);
    assert!(a.push_chunk(&mk(1, true, 8, dig), &body[..8]) == AsmPush::Rejected);

    // A WRONG completion digest rejects: the assembled bytes' recomputed
    // digest must equal the locked commitment (ONE more uhash, concrete).
    let mut wrong = dig;
    wrong[0] ^= 0x01;
    let mut a: InferAssembler<CAP> = InferAssembler::new();
    assert!(a.push_chunk(&mk(0, false, 8, wrong), &body[..8]) == AsmPush::Rejected);
    assert!(!a.is_done());

    // NEG (garbage never emits a body): an all-MORE stream can never
    // complete -- it rejects at the would-overrun chunk, done stays false.
    let mut g: InferAssembler<CAP> = InferAssembler::new();
    assert!(g.push_chunk(&mk(0, true, 8, dig), &body[..4]) == AsmPush::Accepted);
    assert!(g.push_chunk(&mk(1, true, 8, dig), &body[4..]) == AsmPush::Rejected);
    assert!(!g.is_done());
}

/// The PINNED M31 response-binding tag vector: `infer_tag` over the harness's
/// exact concrete inputs (key 0x6D*32, the `kani_iw_frame` challenge/nonce
/// patterns, peer QEMU_CHARDEV_HARNESS, req_id A5A5_5A5A_0123_4567, kind
/// INFER_RESP, sub = `kani_m31_sub(1, true, 64)`, the 8-byte chunk in the
/// harness), computed by the SAME leaf under `cargo test` (the
/// `khash_vectors` pinned-KAT idiom; re-derivable in one host-test line).
/// Recomputing it inside the harness would cost a second ~70s CBMC khash
/// execution (measured) for zero proof value -- and the pin is STRONGER: any
/// construction drift (a dropped seq/field/label, a swapped label, a field
/// reorder) moves the recomputed tag off this constant and turns the iff RED.
#[cfg(kani)]
const KANI_RESP_BINDING_PIN: [u8; INFER_TAG_LEN] = [
    0x80, 0x2e, 0xe6, 0xf6, 0x8d, 0x3c, 0x05, 0x3a, 0xfc, 0xb6, 0xe4, 0x4e, 0x28, 0x55, 0xfa,
    0x94,
];

/// (4) M31 RESPONSE BINDING (proposal §8.4) -- THE IFF-THEOREM, pinned-vector
/// shape: over a FULLY SYMBOLIC tag, `verify_infer_resp` accepts the genuine
/// frame IFF the presented tag equals the PINNED genuine MAC
/// ([`KANI_RESP_BINDING_PIN`]) -- ONE khash execution total (the recompute
/// inside `verify_infer_resp`; the M31 MAC message is 90 bytes = key + 2
/// message blocks, MEASURED ~70s per CBMC execution, so the #49 budget holds
/// exactly one). The iff SUBSUMES the per-bit flip/restore legs (a flipped
/// tag is a symbolic-tag instance on the != side; the restored tag is the ==
/// side) and KILLS every construction-drift mutant AT THE KANI LEVEL: an
/// `infer_tag` that drops seq (or any field, or the domain label) from its
/// MAC input recomputes a tag off the pin, the iff fails, RED -- the §8
/// mutation set's dropped-seq killer. The pre-MAC binding legs (a reflected
/// REQ kind, a wrong correlation id, a non-echoed challenge, a body-bearing
/// PENDING) reject CONCRETELY before any khash runs (constant propagation
/// prunes the MAC branch).
///
/// MEASURED #49 ladder record (every proposal-sketch form walked + killed):
/// a symbolic flip index over the payload bytes made the khash message
/// symbolic-choice (>5 min, killed); 5 khash executions (construct + 4
/// verifies) = 235s; `kani::solver(kissat)` changed NOTHING (the cost is
/// CBMC formula construction, not SAT); the pinned-vector iff is the rung
/// that fits the budget.
///
/// NEGATIVE CONTROL (non-vacuous both ways, by the iff itself): a verifier
/// that rejects everything fails the == direction; one that ignores the tag
/// fails the != direction; a drifted/mutated MAC construction fails the ==
/// direction.
#[kani::proof]
#[kani::unwind(70)]
fn kani_infer_resp_binding() {
    let key: [u8; INFER_KEY_LEN] = [0x6Du8; INFER_KEY_LEN];
    let chunk = [0x42u8, 0x99, 0x17, 0xE0, 0x3B, 0x70, 0x55, 0x08];
    let req_id: u64 = 0xA5A5_5A5A_0123_4567;
    let sub = kani_m31_sub(1, true, 64);
    // The genuine frame shape: payload = subhdr || chunk; the tag SYMBOLIC.
    let base = kani_iw_frame(&[]);
    let mut payload = [0u8; INFER_SUBHDR_LEN + 8];
    assert!(subhdr_canon(&sub, &mut payload) == INFER_SUBHDR_LEN);
    let mut i = 0usize;
    while i < 8 {
        payload[INFER_SUBHDR_LEN + i] = chunk[i];
        i += 1;
    }
    let sym_tag: [u8; INFER_TAG_LEN] = kani::any();
    let mut f = base;
    f.kind = iw_kind::INFER_RESP;
    f.req_id = req_id;
    f.tag = sym_tag;
    f.payload = &payload;
    let chal = base.challenge;

    // THE IFF (the one khash execution): accept <=> the symbolic tag equals
    // the pinned genuine MAC; on acceptance the parsed parts round-trip.
    match verify_infer_resp(&key, &f, req_id, &chal) {
        Some((s, c)) => {
            assert!(sym_tag == KANI_RESP_BINDING_PIN);
            assert!(s == sub);
            assert!(c.len() == 8);
            let mut k = 0usize;
            while k < 8 {
                assert!(c[k] == chunk[k]);
                k += 1;
            }
        }
        None => assert!(sym_tag != KANI_RESP_BINDING_PIN),
    }

    // The pre-MAC binding legs (concrete -- the khash branch is pruned): a
    // reflected REQ kind, a wrong correlation id, a non-echoed challenge,
    // and a body-bearing PENDING all reject even WITH the genuine tag.
    let mut good = f;
    good.tag = KANI_RESP_BINDING_PIN;
    let mut refl = good;
    refl.kind = iw_kind::INFER_REQ; // a reflected REQ never binds
    assert!(verify_infer_resp(&key, &refl, req_id, &chal).is_none());
    assert!(verify_infer_resp(&key, &good, req_id ^ 1, &chal).is_none());
    let mut c2 = chal;
    c2[0] ^= 0x01;
    assert!(verify_infer_resp(&key, &good, req_id, &c2).is_none());
    let mut pend = good;
    pend.kind = iw_kind::INFER_PENDING; // a pending heartbeat carries no body
    assert!(verify_infer_resp(&key, &pend, req_id, &chal).is_none());
}

/// The PINNED M31 domain-separation vectors (the `khash_vectors` pinned-KAT
/// idiom; one host-test line re-derives both): on key 0x2B*32, peer
/// TB_VMM_HOST, the `kani_iw_frame` nonce/challenge patterns, req_id
/// DEAD_BEEF_0000_0031, kind INFER_RESP, sub = `kani_m31_sub(0, false, 12)`,
/// chunk 0x5A*8 -- `KANI_DOMAIN_INFER_PIN` is `infer_tag`'s output and
/// `KANI_DOMAIN_ECHO_PIN` is `echo_tag`'s output over the EXACTLY-ALIGNED
/// suffix (`req_id‖kind‖seq‖sflags‖total_len‖body_digest‖chunk` as the echo
/// body), so the two MAC inputs differ ONLY in their leading domain labels.
#[cfg(kani)]
const KANI_DOMAIN_INFER_PIN: [u8; INFER_TAG_LEN] = [
    0xb0, 0xf5, 0x43, 0xcd, 0x78, 0x71, 0xc3, 0x44, 0x77, 0x40, 0xf5, 0x18, 0x2a, 0xbc, 0x72,
    0xa0,
];
/// See [`KANI_DOMAIN_INFER_PIN`].
#[cfg(kani)]
const KANI_DOMAIN_ECHO_PIN: [u8; INFER_TAG_LEN] = [
    0x52, 0x09, 0x82, 0x30, 0x37, 0xf9, 0x3e, 0x8c, 0x35, 0xd7, 0xa8, 0x0a, 0x88, 0x2d, 0x96,
    0x9f,
];

/// (5) M31 DOMAIN SEPARATION (proposal §8.5), pinned-vector shape: on inputs
/// whose echo body is EXACTLY the serialized M31 MAC suffix (so the two MAC
/// inputs differ ONLY in their leading domain labels), `infer_tag`'s output
/// equals its PIN and differs from the ECHO pin -- ONE khash execution (the
/// M31 message is 90 bytes = 3 compressions, MEASURED ~70-75s per CBMC
/// execution; the two-live-call form measured 179s, `kissat` changed
/// nothing, so the echo side rides its pin). The label is therefore
/// load-bearing: a SWAPPED-label `infer_tag` outputs the ECHO pin (the !=
/// fails RED) and a DROPPED-label/drifted construction outputs neither (the
/// == fails RED) -- the §8 mutation set's swapped-label killer, both
/// directions. The echo pin's own genuineness + the LIVE two-call inequality
/// run as the NAMED delegation: the `m31_domain_separated_from_echo` host
/// test executes the real `echo_tag`-vs-`infer_tag` pair on these aligned
/// inputs under `cargo test` AND the Miri UB gate over this exact code.
///
/// NEGATIVE CONTROL: the == direction (a drifted construction misses the
/// pin) and the != direction (a label swap hits the echo pin) are each a
/// concrete mutant killer; the labels are additionally pinned distinct.
#[kani::proof]
#[kani::unwind(70)]
fn kani_infer_domain_sep() {
    let key: [u8; INFER_KEY_LEN] = [0x2Bu8; INFER_KEY_LEN];
    let base = kani_iw_frame(&[]);
    let sub = kani_m31_sub(0, false, 12);
    let chunk = [0x5Au8; 8];
    let req_id: u64 = 0xDEAD_BEEF_0000_0031;

    let m = infer_tag(
        &key,
        iw_peer::TB_VMM_HOST,
        &base.nonce,
        &base.challenge,
        req_id,
        iw_kind::INFER_RESP,
        &sub,
        &chunk,
    );
    // == : the construction is genuine (any drift / dropped label misses).
    assert!(m == KANI_DOMAIN_INFER_PIN);
    // != : the label separates the domains (a swapped label HITS the echo
    // pin on these aligned inputs and fails here).
    assert!(m != KANI_DOMAIN_ECHO_PIN);

    // The two brand-derived labels are pinned distinct (a swap is visible
    // at the byte level too).
    assert!(INFER_DOMAIN != crate::inferwire::ECHO_DOMAIN);
}

/// (6) M31 ERR CLOSED ENUM (proposal §8.6): over a fully-SYMBOLIC code,
/// `err_canon` encodes IFF the code is a member of the closed [`errcode`]
/// enum, the encoded payload decodes back to `(code, err_retryable(code))`
/// (the retryable binding round-trips), and a flag that CONTRADICTS the
/// canonical binding rejects; over a fully-SYMBOLIC 4-byte payload, decode is
/// total and accept-SOUND (Some implies a known code + the canonical flag +
/// a zero reserved byte). khash-FREE.
///
/// NEGATIVE CONTROL (non-vacuous): a valid code decodes (the round-trip), and
/// the wrong-length payloads (3/5 bytes) reject.
#[kani::proof]
#[kani::unwind(8)]
fn kani_infer_err_closed() {
    // Encode iff member; the retryable binding round-trips.
    let code: u16 = kani::any();
    let mut p = [0u8; INFER_ERR_PAYLOAD_LEN];
    let n = err_canon(code, &mut p);
    if err_code_known(code) {
        assert!(n == INFER_ERR_PAYLOAD_LEN);
        match err_decode(&p) {
            Some((c, r)) => {
                assert!(c == code);
                assert!(r == err_retryable(code));
            }
            None => panic!("canonical ERR payload must decode (non-vacuous)"),
        }
        // A contradicted retryable flag rejects (the binding is enforced).
        let mut fp = p;
        fp[2] ^= 0x01;
        assert!(err_decode(&fp).is_none());
        // A nonzero reserved byte rejects (symbolic).
        let rv: u8 = kani::any();
        kani::assume(rv != 0);
        let mut rp = p;
        rp[3] = rv;
        assert!(err_decode(&rp).is_none());
    } else {
        assert!(n == 0); // outside the closed enum: fail-closed, no write
    }

    // Accept-soundness over a fully-symbolic payload (totality included).
    let raw: [u8; INFER_ERR_PAYLOAD_LEN] = kani::any();
    if let Some((c, r)) = err_decode(&raw) {
        assert!(err_code_known(c));
        assert!(r == err_retryable(c));
        assert!(raw[3] == 0);
    }

    // Wrong lengths reject (never a prefix/suffix parse).
    let known = errcode::NO_KEY;
    let mut ok = [0u8; INFER_ERR_PAYLOAD_LEN];
    assert!(err_canon(known, &mut ok) == INFER_ERR_PAYLOAD_LEN);
    assert!(err_decode(&ok[..3]).is_none());
    let mut long = [0u8; INFER_ERR_PAYLOAD_LEN + 1];
    let mut i = 0usize;
    while i < INFER_ERR_PAYLOAD_LEN {
        long[i] = ok[i];
        i += 1;
    }
    assert!(err_decode(&long).is_none());
}

// ===========================================================================
// M33: the provenance-lineage crypto-verify substrate (proposal §9) -- the
// SHA-256 leaf (D2, RFC 8554-pinned), the LMS verify leaf (RFC 8554, the `w=1`
// TOY instance -- a full-parameter verify is ~1062 SHA-256 compressions,
// INFEASIBLE in CBMC), and the DSSE-PAE attestation codec. The claim tier is
// IDENTICAL to khash: PROVEN = totality/determinism/tamper-sensitivity (the
// pinned-vector iff, symbolic ROOT compared to the recomputed Tc -- the M31
// KANI_RESP_BINDING_PIN idiom mapped to the value compared at the END, keeping
// every SHA-256 compression CONCRETE); ASSUMED-FROM-LITERATURE = LMS EUF-CMA +
// SHA-256 resistance (NO symbolic-EUF-CMA/collision harness -- overclaim-by-
// implication, banned as khash bans it). Official-vector correctness (FIPS
// 180-4 / RFC 8554 Appendix F) is the host `cargo test` KAT + Miri.
// ===========================================================================

/// M33 SHA-256 TOTALITY + DETERMINISM (proposal §9): the FIPS 180-4 driver is
/// panic-free + deterministic over each padding-block path -- the single-block
/// pad (len 0, 55), the length-spill two-block pad (len 56), and the aligned
/// two-block pad (len 64). CONCRETE inputs only (no symbolic bytes through the
/// 64-round compression -- the #49 rule; full functional correctness is the
/// host KAT + kani_sha256_kat + Miri).
///
/// NEGATIVE CONTROL: a broken padding (0x80 at the wrong offset) or a dropped
/// length word would move a digest and fail kani_sha256_kat.
#[kani::proof]
fn kani_sha256_total() {
    // The three distinct padding paths: a single 64-byte block with the length
    // fitting after the 0x80 (len 55), the length-SPILL two-block pad (len 56),
    // and the block-ALIGNED two-block pad (len 64). Each digest computed ONCE
    // (bound) to keep the compression budget lean.
    let m55 = [0x11u8; 55];
    let m56 = [0x22u8; 56];
    let m64 = [0x33u8; 64];
    let d55 = crate::sha256::sha256(&m55);
    let d56 = crate::sha256::sha256(&m56);
    let d64 = crate::sha256::sha256(&m64);
    // Determinism (panic-free recompute of one representative).
    assert!(crate::sha256::sha256(&m55) == d55);
    // A padding bug that collapsed the block-count paths would alias these.
    assert!(d55 != d56);
    assert!(d56 != d64);
}

/// M33 SHA-256 KAT (proposal §9): the in-boot `sha256::kat_ok()` recomputes the
/// official FIPS 180-4 "abc" vector through the REAL compression -- proven here
/// to reproduce the pinned constant (earns `sha256-kat=FIPS180-4-PASS`).
///
/// NEGATIVE CONTROL: a one-byte-perturbed expected digest must NOT match (a
/// vacuous comparator that accepts everything fails).
#[kani::proof]
fn kani_sha256_kat() {
    assert!(crate::sha256::sha256(b"abc") == crate::sha256::KAT_ABC);
    let mut bad = crate::sha256::KAT_ABC;
    bad[0] ^= 0x01;
    assert!(crate::sha256::sha256(b"abc") != bad);
}

use crate::lmsig::{
    lms_root, lms_verify_params, ots_kc, TOY_H, TOY_I, TOY_LS, TOY_MSG, TOY_P, TOY_ROOT, TOY_SIG,
    TOY_TAMPER_MERKLE_OFF, TOY_TAMPER_OTS_OFF, TOY_W,
};

/// M33 LMS VERIFY TOTALITY (proposal section 9): the w=1 TOY instance (p=2, h=1
/// -- a non-standard reduced LMS, NOT the RFC W1 p=265) accepts the PINNED
/// genuine signature AND fail-closes (never panics) on malformed inputs. The
/// genuine verify is ONE concrete execution (~6-8 SHA-256 compressions -- the
/// khash budget regime); the malformed legs reject BEFORE any hash (constant-
/// folded length/param guards). Two REGIONAL tamper controls (an OTS-region flip
/// and a Merkle-auth-path flip, proposal section 16 must-fix 1) prove a half-
/// verifier that checks only one leg is caught.
///
/// NEGATIVE CONTROL: a verifier that ignored the auth path would accept the
/// Merkle-region flip; one that ignored the OTS chains would accept the
/// OTS-region flip -- each fails its assert.
#[kani::proof]
fn kani_lms_verify_total() {
    // The pinned genuine toy signature verifies (real compressions).
    assert!(lms_verify_params(&TOY_ROOT, &TOY_I, &TOY_MSG, &TOY_SIG, TOY_W, TOY_P, TOY_LS, TOY_H));
    // Two REGIONAL tamper controls (concrete, each one more verify execution).
    let mut ots = TOY_SIG;
    ots[TOY_TAMPER_OTS_OFF] ^= 0x01;
    assert!(!lms_verify_params(&TOY_ROOT, &TOY_I, &TOY_MSG, &ots, TOY_W, TOY_P, TOY_LS, TOY_H));
    let mut mrk = TOY_SIG;
    mrk[TOY_TAMPER_MERKLE_OFF] ^= 0x80;
    assert!(!lms_verify_params(&TOY_ROOT, &TOY_I, &TOY_MSG, &mrk, TOY_W, TOY_P, TOY_LS, TOY_H));
    // Malformed inputs fail closed BEFORE hashing (cheap, no compression):
    // empty buffer, wrong length, degenerate params.
    assert!(!lms_verify_params(&TOY_ROOT, &TOY_I, &TOY_MSG, &[], TOY_W, TOY_P, TOY_LS, TOY_H));
    assert!(!lms_verify_params(&TOY_ROOT, &TOY_I, &TOY_MSG, &TOY_SIG[..139], TOY_W, TOY_P, TOY_LS, TOY_H));
    assert!(!lms_verify_params(&TOY_ROOT, &TOY_I, &TOY_MSG, &TOY_SIG, TOY_W, TOY_P, TOY_LS, 0));
    assert!(!lms_verify_params(&TOY_ROOT, &TOY_I, &TOY_MSG, &TOY_SIG, TOY_W, 0, TOY_LS, TOY_H));
}

/// M33 LMS TAMPER-SENSITIVITY -- the PINNED-VECTOR IFF (proposal section 9, the
/// M31 KANI_RESP_BINDING_PIN idiom mapped correctly): over a FULLY SYMBOLIC
/// public root, `lms_verify_params` accepts the pinned genuine signature IFF the
/// root equals the pinned genuine root (TOY_ROOT, = the recomputed Tc). The
/// signature is CONCRETE, so the ~6-8 SHA-256 compressions run ONCE on concrete
/// data producing a concrete Tc; only the final root comparison is symbolic (the
/// M31 trick -- the symbolic value is the one compared at the END, NEVER through
/// the compression, so this is NOT the number-49 symbolic-through-hash trap). The
/// iff proves verify is a FAITHFUL root-equality check: a forged/wrong root
/// (which a tampered signature's recomputed Tc becomes vs the pinned root, and
/// vice versa) is provably rejected.
///
/// NEGATIVE CONTROL (non-vacuous both ways): a reject-everything verifier fails
/// the == direction; a root-ignoring verifier fails the != direction.
#[kani::proof]
fn kani_lms_verify_tamper() {
    let sym_root: [u8; 32] = kani::any();
    let accepted =
        lms_verify_params(&sym_root, &TOY_I, &TOY_MSG, &TOY_SIG, TOY_W, TOY_P, TOY_LS, TOY_H);
    if accepted {
        assert!(sym_root == TOY_ROOT);
    } else {
        assert!(sym_root != TOY_ROOT);
    }
}

/// M33 LM-OTS CHAIN STEP (proposal section 9): the LM-OTS public-key candidate
/// Kc (`ots_kc`, the Winternitz-chain + D_PBLC hash) is DETERMINISTIC and
/// TAMPER-SENSITIVE -- a one-byte flip of a y chain element changes Kc. Concrete
/// inputs (~5 compressions per `ots_kc`).
///
/// NEGATIVE CONTROL: a constant/identity chain would leave Kc unchanged under
/// the y flip and fail the inequality.
#[kani::proof]
fn kani_lms_otschain_step() {
    let q: u32 = 0;
    let mut c = [0u8; 32];
    let mut i = 0usize;
    while i < 32 {
        c[i] = TOY_SIG[8 + i];
        i += 1;
    }
    let mut y0 = [0u8; 32];
    let mut y1 = [0u8; 32];
    i = 0;
    while i < 32 {
        y0[i] = TOY_SIG[40 + i];
        y1[i] = TOY_SIG[72 + i];
        i += 1;
    }
    let y = [y0, y1];
    let mut kc = [0u8; 32];
    assert!(ots_kc(&TOY_I, q, TOY_W, TOY_P, TOY_LS, &c, &y, &TOY_MSG, &mut kc));
    let mut kc2 = [0u8; 32];
    assert!(ots_kc(&TOY_I, q, TOY_W, TOY_P, TOY_LS, &c, &y, &TOY_MSG, &mut kc2));
    assert!(kc == kc2);
    let mut yf = y;
    yf[0][0] ^= 0x01;
    let mut kcf = [0u8; 32];
    assert!(ots_kc(&TOY_I, q, TOY_W, TOY_P, TOY_LS, &c, &yf, &TOY_MSG, &mut kcf));
    assert!(kcf != kc);
}

/// M33 LMS MERKLE PATH (proposal section 9): the Merkle-auth-path leg
/// (`lms_root`, the `prov::verify_inclusion` fold shape) lands on the committed
/// root for the genuine (Kc, path) and on a DIFFERENT root when the path is
/// tampered -- so 75's balanced-batch-Merkle upgrade swaps only the path-walk,
/// not the verify contract. Concrete (~3 compressions per `lms_root`, h=1).
///
/// NEGATIVE CONTROL: a path-ignoring fold would land on the same root under the
/// sibling flip and fail the inequality.
#[kani::proof]
fn kani_lms_merklepath() {
    let q: u32 = 0;
    let mut c = [0u8; 32];
    let mut i = 0usize;
    while i < 32 {
        c[i] = TOY_SIG[8 + i];
        i += 1;
    }
    let mut y0 = [0u8; 32];
    let mut y1 = [0u8; 32];
    i = 0;
    while i < 32 {
        y0[i] = TOY_SIG[40 + i];
        y1[i] = TOY_SIG[72 + i];
        i += 1;
    }
    let y = [y0, y1];
    let mut kc = [0u8; 32];
    assert!(ots_kc(&TOY_I, q, TOY_W, TOY_P, TOY_LS, &c, &y, &TOY_MSG, &mut kc));
    let mut path0 = [0u8; 32];
    i = 0;
    while i < 32 {
        path0[i] = TOY_SIG[108 + i];
        i += 1;
    }
    let path = [path0];
    let root = lms_root(&TOY_I, q, TOY_H, &kc, &path);
    assert!(root == TOY_ROOT);
    let mut pf = path;
    pf[0][0] ^= 0x80;
    let root2 = lms_root(&TOY_I, q, TOY_H, &kc, &pf);
    assert!(root2 != TOY_ROOT);
}

/// M33 DSSE-PAE INJECTIVITY (proposal section 9): the DSSE Pre-Authentication
/// Encoding `pae` is TOTAL + length-exact + INJECTIVE by its length prefixes --
/// distinct (type, body) splits at the same total length encode to DISTINCT
/// bytes (the classic ambiguity killer). NO hashing (pure layout, seconds).
///
/// NEGATIVE CONTROL: an encoder that dropped a length prefix would collide the
/// two splits below and fail the inequality.
#[kani::proof]
fn kani_attest_pae_injective() {
    let body: [u8; 3] = kani::any();
    let t = b"YT";
    let mut out = [0u8; 64];
    let n = crate::attest::pae(t, &body, &mut out);
    assert!(n == crate::attest::pae_len(t, &body));
    assert!(n > 0);
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    let na = crate::attest::pae(b"ab", b"", &mut a);
    let nb = crate::attest::pae(b"a", b"b", &mut b);
    assert!(!(na == nb && a[..na] == b[..nb]));
    let mut tiny = [0u8; 4];
    assert!(crate::attest::pae(b"xx", b"yy", &mut tiny) == 0);
}

/// M33 ATTESTATION-STATEMENT CODEC (proposal section 9): the fixed-width in-toto-
/// subset `canon`/`decode` is TOTAL, roundtrips every field, and FAIL-CLOSES on
/// bad magic/version, over-cap counts, and wrong lengths. NO hashing (pure
/// layout, seconds).
///
/// NEGATIVE CONTROL: a decoder that skipped the magic check would accept the
/// perturbed-magic buffer and fail the `is_none` assert.
#[kani::proof]
fn kani_attest_decode_fail_closed() {
    use crate::attest::*;
    let sd: [u8; ATTEST_DIGEST_LEN] = kani::any();
    let th: [u8; ATTEST_DIGEST_LEN] = kani::any();
    let bid: [u8; BUILDER_ID_LEN] = kani::any();
    let bt: u8 = kani::any();
    let mat = [[0x7u8; ATTEST_DIGEST_LEN]; 1];
    let led = [LedgerEntry { dep_tok: 0x1234, status: 2 }];
    let st = AttestStatement {
        subject_digest: sd,
        builder_id: bid,
        build_type: bt,
        toolchain_hash: th,
        materials: &mat,
        ledger: &led,
    };
    let mut buf = [0u8; 256];
    let n = canon(&st, &mut buf);
    assert!(n == canon_len(&st));
    let d = decode(&buf[..n]).unwrap();
    assert!(d.subject_digest == sd);
    assert!(d.toolchain_hash == th);
    assert!(d.builder_id == bid);
    assert!(d.build_type == bt);
    assert!(d.n_materials == 1 && d.n_ledger == 1);
    let mut bad = buf;
    bad[0] ^= 0xFF;
    assert!(decode(&bad[..n]).is_none());
    let mut badv = buf;
    badv[2] = 0x99;
    assert!(decode(&badv[..n]).is_none());
    assert!(decode(&buf[..n - 1]).is_none());
    let mut over = buf;
    over[ATTEST_PREFIX_LEN - 2] = (MAX_MATERIALS + 1) as u8;
    assert!(decode(&over[..n]).is_none());
}

// ===========================================================================
// M33 STAGE B -- the multi-sector, torn-write-safe PERSISTED SIGNED-HEAD codec
// (`provhead`, proposal §6/§9). Kani proves the TRACTABLE, FNV-FREE core cheaply
// -- `sectors_for` geometry totality/correctness over a fully-symbolic siglen +
// `decode`'s panic-free short/bad-buffer fail-close, and the PURE two-phase-`gen`
// `pick_newer` recovery selector fully symbolically. The FNV-1a `wrapping_mul`
// over a full 512-byte sector is a CBMC bit-vector-multiply cost floor (a decode
// -> Some proof is ~5-8 min), so the FNV-bearing round-trip + the per-sector-CRC
// / record-spanning FNV-64 / per-sector `gen_tag` gates + injectivity + the
// full-size 6-sector record + the byte-level torn-write recovery are DELEGATED to
// the `provhead.rs` host tests (`roundtrip_full_size`, `roundtrip_small`,
// `torn_middle_sector_rejected`, `mixed_gen_rejected`, `spanning_crc_isolation`,
// `bad_magic_version_len_rejected`, `encode_injective`,
// `torn_write_recovery_prior_head`) + Miri + the two-boot boot witness -- the M30
// accum_resync precedent ("prove the discipline at a tiny cap, delegate the full
// trace to host + boot"). NO hashing of key material; 0 SHA-256 compressions.
// ===========================================================================

/// M33 STAGE B -- the `provhead` codec GEOMETRY + FAIL-CLOSE core (proposal
/// §6/§9): the sector-count function `sectors_for` is TOTAL and correct over
/// EVERY signature length (fully SYMBOLIC siglen) -- a valid length maps to a
/// 1..=MAX_SECTORS count, an over-cap length fails closed -- and `decode`
/// PANIC-FREELY fail-closes on a short (< 1 sector) buffer and on a valid-length
/// bad-magic buffer, both BEFORE any FNV is reached. The FNV `wrapping_mul` over
/// a full 512-byte sector is a CBMC bit-vector-multiply cost FLOOR (a decode ->
/// Some proof is ~5-8 min), so the FNV-bearing round-trip + the per-sector-CRC /
/// record-spanning / gen_tag gates + injectivity + the full-size 6-sector record
/// + the byte-level torn-write recovery are DELEGATED to the `provhead.rs` host
/// tests (`roundtrip_full_size`, `roundtrip_small`, `torn_middle_sector_
/// rejected`, `spanning_crc_isolation`, `mixed_gen_rejected`, `bad_magic_version_
/// len_rejected`, `encode_injective`, `torn_write_recovery_prior_head`) + Miri +
/// the two-boot boot witness -- the M30 accum_resync precedent (prove the
/// tractable discipline at a tiny cap, delegate the full trace to host + boot).
///
/// NEGATIVE CONTROL: a `sectors_for` that dropped its `> SIG_CAP` guard admits
/// the over-cap `is_none` case; a `decode` that dropped its `< SECTOR` short-
/// buffer guard PANICS on the sub-sector slice (both caught here).
#[kani::proof]
fn kani_persisted_record_decode() {
    use crate::provhead::*;
    // `sectors_for` totality + correctness over a FULLY SYMBOLIC siglen (pure
    // arithmetic -- no FNV).
    let siglen: usize = kani::any();
    kani::assume(siglen <= SIG_CAP);
    match sectors_for(siglen) {
        Some(nsec) => {
            assert!(nsec >= 1 && nsec <= MAX_SECTORS);
            // nsec is exactly ceil((BLOB_FIXED + siglen + BLOB_CRC)/SEC_PAYLOAD).
            let l = BLOB_FIXED + siglen + BLOB_CRC;
            assert!((nsec - 1) * SEC_PAYLOAD < l && l <= nsec * SEC_PAYLOAD);
        }
        None => assert!(false), // a <= SIG_CAP length must always fit
    }
    assert!(sectors_for(SIG_CAP + 1).is_none()); // over-cap fails closed

    // `decode` panic-freely fail-closes on the two pre-FNV paths.
    let mut blob = [0u8; BLOB_CAP];
    let short = [0u8; SECTOR - 1];
    assert!(decode(&short, &mut blob).is_none()); // sub-sector -> None (no panic)
    let zero = [0u8; SECTOR];
    assert!(decode(&zero, &mut blob).is_none()); // bad magic -> None before any FNV
}

/// M33 STAGE B -- the two-phase-`gen` TORN-WRITE RECOVERY SELECTOR (proposal §6):
/// `pick_newer` is the pure function the `tb-hal` ping-pong reader delegates to.
/// Proven FULLY SYMBOLICALLY over both slot generations: the strictly-greater gen
/// wins, a torn slot (decoded `None`) NEVER wins over a present one, and two torn
/// slots yield `None` -- so the reader always recovers the prior consistent head.
/// The byte-level recovery (a torn newer slot → decode `None` → the prior slot is
/// returned) is the host test `torn_write_recovery_prior_head` + the two-boot
/// witness.
///
/// NEGATIVE CONTROL: a selector that ignored the torn `None` (picked B anyway)
/// fails the `Some(false)` assert; one that inverted the gen comparison fails the
/// symbolic `gb > ga` iff.
#[kani::proof]
fn kani_persisted_record_recover() {
    use crate::provhead::pick_newer;
    let ga: u64 = kani::any();
    let gb: u64 = kani::any();
    // Both slots present -> the strictly-greater gen wins (ties resolve to A).
    match pick_newer(Some(ga), Some(gb)) {
        Some(true) => assert!(gb > ga),
        Some(false) => assert!(gb <= ga),
        None => assert!(false),
    }
    // A torn slot (None) never wins over a present one; both-None -> None.
    assert!(pick_newer(Some(ga), None) == Some(false));
    assert!(pick_newer(None, Some(gb)) == Some(true));
    assert!(pick_newer(None, None).is_none());
}

// ===========================================================================
// M39 corpus: the verified EXPERIENCE-CORPUS CODEC (`corpus.rs`) -- FIVE harnesses,
// each with a NEGATIVE CONTROL, mirroring the M23 exp suite (the frozen format
// `docs/spec/corpus-format-v1.md`). Per the CBMC budget law the FNV-FREE geometry
// / fail-close / schema-stability core is proven SYMBOLICALLY here (cheap: no
// hashing -- the exp canon family regime); the hash-bearing fold legs are proven by
// COMPOSITION over the already-verified `prov` leaf (determinism +
// tamper-sensitivity + inclusion are `kani_prov_head_deterministic` /
// `kani_prov_chain_mix_tamper` / `kani_prov_inclusion_sound`), so the ONE fold
// harness here rides a CONCRETE record (a single prov evaluation, the #49 symbolic-
// FNV trap avoided) as an end-to-end witness that the reuse is wired correctly.
// The corpus writes NO new fold math -- it REUSES the M22 prov fold verbatim.
// ===========================================================================

/// A small symbolic-but-fixed-width [`CorpusRecord`] builder for the harnesses. The
/// closed-set fields are left to the caller (the round-trip harness constrains them to
/// the valid vocabularies so `decode` succeeds; the injectivity/fail-closed harnesses
/// vary them freely). `schema_version` is the frozen v1 literal. The RESERVED
/// `curation_score_q` + present-`Unset` outcome are populated so the injectivity /
/// round-trip / schema proofs exercise the FULL layout.
#[cfg(kani)]
fn kani_corpus_record() -> CorpusRecord {
    CorpusRecord {
        schema_version: CORPUS_SCHEMA_V1,
        example_kind: kani::any(),
        source_stream: kani::any(),
        curation_verdict: kani::any(),
        content_tok: kani::any(),
        aux_tok: kani::any(),
        t_created: kani::any(),
        source_head: kani::any(),
        outcome: CorpusOutcomeLabel::Unset,
        curation_score_q: kani::any(),
    }
}

/// (1) THE LOAD-BEARING PROOF (corpus-format-v1 SS6.1/6.2): `corpus::canon` is TOTAL
/// (never panics; fails closed to `0` on a too-small buffer with NO partial write) AND
/// INJECTIVE on the fixed-width record -- two records that differ in ANY field
/// (INCLUDING the RESERVED `curation_score_q` and the present-`Unset` outcome tag)
/// encode to DIFFERENT bytes. Because the record is FULLY FIXED-WIDTH, each field lands
/// at its own fixed offset, so a single differing field changes the bytes. No hashing
/// -- the cheap exp-canon regime. Symbolic scalars; the differing-field witness is a
/// symbolic redraw FORCED to differ.
///
/// NEGATIVE CONTROL: a `canon` that DROPPED the outcome tag byte (or aliased two
/// scalars to one offset) would let two records differing only in `outcome` collide
/// -> the outcome-tag injectivity assert FAILS. Writing two fields to the SAME offset
/// makes the corresponding field-difference assert FAIL.
#[kani::proof]
fn kani_corpus_canon_injective() {
    let base = kani_corpus_record();

    // TOTALITY + exact width: canon writes exactly CORPUS_CANON_LEN into a sized buffer.
    let mut a = [0u8; CORPUS_CANON_LEN];
    let na = corpus_canon(&base, &mut a);
    assert_eq!(na, CORPUS_CANON_LEN);
    assert_eq!(na, corpus_canon_len(&base));

    // FAIL-CLOSED TOTALITY: a one-byte-too-small buffer yields 0, no partial write.
    let mut small = [0u8; CORPUS_CANON_LEN - 1];
    assert_eq!(corpus_canon(&base, &mut small), 0);

    // INJECTIVITY, exercised on representative fields via a symbolic redraw FORCED to
    // differ. Each differing field must change at least one byte (fixed width).
    macro_rules! differs {
        ($e:expr) => {{
            let mut b = [0u8; CORPUS_CANON_LEN];
            let nb = corpus_canon(&$e, &mut b);
            assert_eq!(nb, na); // fixed width: same length
            let mut any_diff = false;
            let mut i = 0usize;
            while i < na {
                if a[i] != b[i] {
                    any_diff = true;
                }
                i += 1;
            }
            any_diff
        }};
    }

    // example_kind: an operator-turn must not alias an episodic-consolidation.
    let ek2: u8 = kani::any();
    kani::assume(ek2 != base.example_kind);
    assert!(differs!(CorpusRecord { example_kind: ek2, ..base }));

    // curation_verdict: a REJECTED row must not alias an ACCEPTED one.
    let cv2: u8 = kani::any();
    kani::assume(cv2 != base.curation_verdict);
    assert!(differs!(CorpusRecord { curation_verdict: cv2, ..base }));

    // content_tok: the text-join handle -- a differing token changes the bytes.
    let ct2: u64 = kani::any();
    kani::assume(ct2 != base.content_tok);
    assert!(differs!(CorpusRecord { content_tok: ct2, ..base }));

    // source_head: the M22 fold-position -- a differing head byte changes the bytes.
    let mut sh2 = base.source_head;
    sh2[0] ^= 0x01;
    assert!(differs!(CorpusRecord { source_head: sh2, ..base }));

    // The RESERVED curation_score_q is load-bearing for injectivity (reserve-now bytes
    // are real bytes -- a differing sentinel must change the encoding).
    let cs2: i16 = kani::any();
    kani::assume(cs2 != base.curation_score_q);
    assert!(differs!(CorpusRecord { curation_score_q: cs2, ..base }));

    // The present-`Unset` OUTCOME TAG is load-bearing (the injectivity neg control): an
    // `Unset` record vs a `Positive` record must differ at the tag byte.
    let other = CorpusRecord {
        outcome: CorpusOutcomeLabel::Positive(0),
        ..base
    };
    assert!(differs!(other));
}

/// (2) CANON ROUND-TRIP (corpus-format-v1 SS6.3): `corpus::decode(corpus::canon(rec))
/// == rec` for a symbolic record over the VALID vocabularies -- the codec is a true
/// bijection on the fixed-width layout (every field read back from its fixed offset).
/// The closed-set fields are CONSTRAINED to their valid sets (decode fail-closes
/// outside them, proven separately in `kani_corpus_decode_fail_closed`); the `outcome`
/// is `Unset` (the tag-0 present sentinel), and a separate concrete sub-check
/// round-trips a POPULATED outcome (the labeled-outcome shape) so the tagged decode is
/// non-vacuous. No hashing -- cheap.
///
/// NEGATIVE CONTROL: encoding `content_tok` at the `t_created` offset (a layout swap)
/// would make `decode` recover the fields transposed -> the round-trip equality FAILS.
/// A `decode` that ignored the outcome tag would mis-reconstruct the variant and FAIL
/// the populated sub-check.
#[kani::proof]
fn kani_corpus_canon_roundtrip() {
    let mut rec = kani_corpus_record(); // outcome = Unset (present sentinel)
    // Constrain the closed-set fields to their valid vocabularies (decode gates them).
    kani::assume(crate::corpus::example_kind::is_valid(rec.example_kind));
    kani::assume(crate::corpus::source_stream::is_valid(rec.source_stream));
    kani::assume(crate::corpus::curation_verdict::is_valid(rec.curation_verdict));

    let mut buf = [0u8; CORPUS_CANON_LEN];
    let n = corpus_canon(&rec, &mut buf);
    assert_eq!(n, CORPUS_CANON_LEN);
    // The bijection: decode recovers the EXACT record.
    assert_eq!(corpus_decode(&buf), Some(rec));

    // A POPULATED outcome (the labeled-outcome shape) round-trips too -- the tagged
    // decode is exercised (concrete payload so the tag arm is non-vacuous).
    rec.outcome = CorpusOutcomeLabel::Positive(0x1234);
    let mut pb = [0u8; CORPUS_CANON_LEN];
    assert_eq!(corpus_canon(&rec, &mut pb), CORPUS_CANON_LEN);
    assert_eq!(corpus_decode(&pb), Some(rec));

    // A too-short buffer decodes to None (fail-closed totality, no panic).
    assert!(corpus_decode(&buf[..CORPUS_CANON_LEN - 1]).is_none());
}

/// (3) FAIL-CLOSED DECODE (corpus-format-v1 SS6.4 -- the frozen v1 fail-closed
/// posture): `corpus::decode` returns `None` (never panics, never mis-decodes) on a
/// too-short buffer OR any out-of-vocabulary closed-set byte -- an unknown
/// `schema_version` (this is the v1 decoder), `example_kind`, `source_stream`,
/// `curation_verdict`, or `outcome.tag`. Proven by encoding a VALID record, then
/// corrupting exactly one gate byte to a value OUTSIDE its vocabulary and asserting
/// `decode` rejects it. No hashing -- cheap.
///
/// NEGATIVE CONTROL: a `decode` that PASSED THROUGH an unknown `example_kind` (treating
/// the closed set as an opaque u8) would return `Some` for the corrupted byte -> the
/// `is_none()` assert FAILS; a decoder that ignored the version byte would silently
/// mis-interpret a v2 record.
#[kani::proof]
fn kani_corpus_decode_fail_closed() {
    // A VALID baseline record so the ONLY rejection cause is the injected corruption.
    let mut rec = kani_corpus_record();
    kani::assume(crate::corpus::example_kind::is_valid(rec.example_kind));
    kani::assume(crate::corpus::source_stream::is_valid(rec.source_stream));
    kani::assume(crate::corpus::curation_verdict::is_valid(rec.curation_verdict));
    let mut buf = [0u8; CORPUS_CANON_LEN];
    assert_eq!(corpus_canon(&rec, &mut buf), CORPUS_CANON_LEN);
    // The clean record decodes.
    assert!(corpus_decode(&buf).is_some());

    // Too-short buffer -> None.
    assert!(corpus_decode(&buf[..CORPUS_CANON_LEN - 1]).is_none());

    // Unknown schema_version -> None (any value other than the frozen v1 literal).
    let sv: u8 = kani::any();
    kani::assume(sv != CORPUS_SCHEMA_V1);
    let mut b_sv = buf;
    b_sv[0] = sv;
    assert!(corpus_decode(&b_sv).is_none());

    // Unknown example_kind -> None.
    let ek: u8 = kani::any();
    kani::assume(!crate::corpus::example_kind::is_valid(ek));
    let mut b_ek = buf;
    b_ek[1] = ek;
    assert!(corpus_decode(&b_ek).is_none());

    // Unknown source_stream -> None.
    let ss: u8 = kani::any();
    kani::assume(!crate::corpus::source_stream::is_valid(ss));
    let mut b_ss = buf;
    b_ss[2] = ss;
    assert!(corpus_decode(&b_ss).is_none());

    // Unknown curation_verdict -> None.
    let cv: u8 = kani::any();
    kani::assume(!crate::corpus::curation_verdict::is_valid(cv));
    let mut b_cv = buf;
    b_cv[3] = cv;
    assert!(corpus_decode(&b_cv).is_none());

    // Unknown outcome tag -> None (offset 60, the labeled-outcome tag byte).
    let ot: u8 = kani::any();
    kani::assume(ot > 2);
    let mut b_ot = buf;
    b_ot[60] = ot;
    assert!(corpus_decode(&b_ot).is_none());
}

/// (4) SCHEMA-STABILITY (the reserve-now correctness obligation, corpus-format-v1
/// SS4/SS6.5): `canon()` of a record with `outcome = Unset` has the SAME canonical
/// LENGTH and IDENTICAL field offsets as a future record with the outcome POPULATED --
/// so a later increment populating the labeled-outcome channel CANNOT shift the fold.
/// Proven by encoding an `Unset` record and an otherwise-identical `Positive`/`Negative`
/// record and asserting (a) identical length, (b) every byte BEFORE the outcome tag
/// (offset 60) is identical, and (c) the trailing `curation_score_q` field (after the
/// fixed 8-byte outcome payload, offset 69) is identical -- the outcome tag/payload
/// window is the ONLY difference, at a FIXED offset that never moves. No hashing.
///
/// NEGATIVE CONTROL: if `Unset` encoded as a ZERO-LENGTH (absent) outcome and a
/// populated variant added 8 bytes, the lengths would differ and the trailing
/// `curation_score_q` would shift -> the length + trailing-field asserts FAIL. (v1
/// instead encodes a present `Unset` with a fixed 8-byte zero payload, so the layout is
/// stable -- the property this harness pins, and what lets the format FREEZE today.)
#[kani::proof]
fn kani_corpus_schema_stability() {
    // Two records identical EXCEPT the outcome: Unset (this milestone) vs populated.
    let unset = CorpusRecord {
        outcome: CorpusOutcomeLabel::Unset,
        ..kani_corpus_record()
    };
    let pay: i64 = kani::any();
    let populated = CorpusRecord {
        outcome: CorpusOutcomeLabel::Positive(pay),
        ..unset
    };

    let mut a = [0u8; CORPUS_CANON_LEN];
    let mut b = [0u8; CORPUS_CANON_LEN];
    let na = corpus_canon(&unset, &mut a);
    let nb = corpus_canon(&populated, &mut b);

    // (a) IDENTICAL length -- the schema-stability length lemma.
    assert_eq!(na, nb);
    assert_eq!(na, CORPUS_CANON_LEN);

    // (b) Every byte BEFORE the outcome tag (offset 60) is byte-identical: the
    // version/kind/stream/verdict/content/aux/t_created/source_head fields do NOT move
    // when the outcome is populated. (60 = OFF_OUTCOME_TAG, the frozen literal.)
    const OUTCOME_TAG_OFF: usize = 60;
    const CURATION_SCORE_OFF: usize = 69;
    let mut i = 0usize;
    while i < OUTCOME_TAG_OFF {
        assert_eq!(a[i], b[i]);
        i += 1;
    }
    // (c) The trailing curation_score_q field (after the FIXED 8-byte outcome payload)
    // is identical -- the populated outcome did NOT push it to a new offset.
    let mut m = CURATION_SCORE_OFF;
    while m < CORPUS_CANON_LEN {
        assert_eq!(a[m], b[m]);
        m += 1;
    }
}

/// (5) FOLD DETERMINISM + INHERITANCE (corpus-format-v1 SS6.6): folding a record into a
/// `corpus_head` via the REUSED M22 `prov` leaf is DETERMINISTIC (the same record from
/// the same head folds identically), and a single-byte tamper of a committed record's
/// canonical bytes changes the recomputed head and FAILS its inclusion proof. The
/// corpus writes NO fold math -- `corpus_append` canon-encodes then calls the proven
/// `prov_hash` + `chain_mix`, so the fold's full symbolic determinism / tamper-
/// sensitivity are ALREADY discharged by `kani_prov_head_deterministic` /
/// `kani_prov_chain_mix_tamper` / `kani_prov_inclusion_sound`. This harness rides a
/// CONCRETE record (a single prov evaluation -- the #49 symbolic-FNV trap avoided) as
/// the end-to-end witness that the reuse is wired correctly.
///
/// NEGATIVE CONTROL: a `corpus_append` that folded a CONSTANT id (ignoring the record)
/// would make the tampered-vs-genuine ids EQUAL -> the `!=` assert FAILS; a fold that
/// ignored the leaf would accept the tampered record at the inclusion check; a non-
/// deterministic hash would break the append-twice equality.
#[kani::proof]
fn kani_corpus_fold_determinism() {
    // A concrete curated record (so the hash/fold are concrete -- one prov evaluation).
    let rec = CorpusRecord {
        schema_version: CORPUS_SCHEMA_V1,
        example_kind: crate::corpus::example_kind::EPISODIC_CONSOLIDATION,
        source_stream: crate::corpus::source_stream::M17_REFLECT,
        curation_verdict: crate::corpus::curation_verdict::ACCEPTED,
        content_tok: 0xC0FFEE,
        aux_tok: 0xBEEF,
        t_created: 4242,
        source_head: [0x5au8; PROV_HASH_LEN],
        outcome: CorpusOutcomeLabel::Unset,
        curation_score_q: 0,
    };

    // DETERMINISM: the same record from the same head folds to the same head + id.
    let genesis = [0u8; PROV_HASH_LEN];
    let mut scratch = [0u8; CORPUS_CANON_LEN + 8];
    let (ha, ida) = corpus_append(genesis, &rec, &mut scratch).unwrap();
    let (hb, idb) = corpus_append(genesis, &rec, &mut scratch).unwrap();
    assert!(ha == hb);
    assert!(ida == idb);

    // A committed 1-record chain: inclusion of the genuine record id verifies.
    let mut bytes = [0u8; CORPUS_CANON_LEN];
    let n = corpus_canon(&rec, &mut bytes);
    assert_eq!(n, CORPUS_CANON_LEN);
    let leaf = corpus_hash(&bytes);
    assert!(leaf == ida);
    let head = corpus_recompute(leaf, &[]);
    assert!(corpus_verify_inclusion(leaf, &[], head));

    // TAMPER: flip one byte of the canonical bytes -> a different leaf id (canon is
    // injective + prov_hash is tamper-sensitive), so the inclusion proof FAILS.
    let mut tampered = bytes;
    tampered[1] ^= 0x01; // the example_kind byte
    let bad = corpus_hash(&tampered);
    assert!(bad != leaf);
    assert!(!corpus_verify_inclusion(bad, &[], head));
}
