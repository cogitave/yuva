#!/usr/bin/env bash
# Task #49 proof gate -- machine-check the PURE silicon-adjacent encoders/validators
# (VMX control-MSR adjust + CR0/CR4 clamp + TSS-base decode, page-table/EPT entry
# encoders, the 16-byte IPC frame codec + bounded ring) with Kani over the
# host-verifiable `tb-encode` crate, FAIL CLOSED.
#
# Emits the DoD marker `V1: kani-encoders OK` and exits 0 ONLY when:
#   * ZERO harnesses report `VERIFICATION:- FAILED`, AND
#   * the count of `VERIFICATION:- SUCCESSFUL` EXACTLY equals the pinned
#     EXPECTED_HARNESSES (so a silently deleted / renamed / vacuous harness can
#     never let the gate pass -- the marker is tamper-evident).
#
# Run by .github/workflows/kani.yml (the `prove-encode` job) AFTER the
# model-checking/kani-github-action step has installed Kani's own pinned
# toolchain (so `cargo kani` is on PATH). Kani is NOT invoked through the
# `kbuild` alias and NEVER via `--workspace` (that would drag tb-hal's inline
# asm into CBMC), only the per-package `-p tb-encode` form, so -Zbuild-std and
# the asm-bearing crates never contaminate this host verification. This is the
# SIBLING gate to scripts/verify-caps.sh (M11); it does NOT touch that lane.
set -euo pipefail

# The exact number of `#[kani::proof]` harnesses in
# crates/tb-encode/src/proofs.rs (VMX x4 + paging/EPT x4 + IPC frame/ring x3 +
# memscore recall-ranking-math x4: log2_fixed/ln_fixed/bla_raw panic-free+bounded
# and minmax-in-[0,SCALE] + L2.1 aarch64 stage-2/el2_trap encoders x5:
# s2_leaf_wellformed, s2_table_and_vttbr, vtcr_wellformed, esr_decode_total,
# hpfar_fault_ipa + L2.2 el2-exits classifier x1: exit_classifier_total + L2.3
# trap-and-emulate ISS decoders x2: sysreg_iss_decode_total, dabt_iss_decode_total
# + aL2.4 guest-S1-enable x1: sctlr_el1_guest_enable -- proving the guest's
# SCTLR_EL1.M|C|I enable word sets EXACTLY bits {0,2,12}, preserves all other
# baseline bits, and is idempotent (the "S1 after S2" step the aL2.4 guest runs
# under our stage-2) + aL2.5 GICH_LR encoder x1: gich_lr_encode_roundtrip --
# proving the GICv2 GICH_LRn list-register encoder round-trips every vINTID/
# pINTID/state/priority/group/HW/EOI field via independent literal shifts, sets
# NO bit outside the documented GICH_LR_MASK (no field bleed), and that
# lr_is_retired/vtr_list_regs decode correctly (the SW-injected virtual-interrupt
# value the EL2 monitor stores into GICH_LR0) + aL2.6 SMMUv3 STE/command-queue
# encoders x3: ste_s2_roundtrip -- the stage-2-only STE (Config==0b110) round-trips
# every S2VMID/VTCR/S2TTB field via independent shifts with no field bleed and the
# stage-2-only dwords zero; ste_vtcr_matches_cpu_stage2 -- THE LEMMA: the STE.VTCR
# projection is bit-identical to VTCR_EL2[18:0] (the SMMU stage-2 IS the CPU
# stage-2 geometry); smmu_cmd_encode_total -- CFGI_STE/TLBI_S12_VMALL/CMD_SYNC
# place the right opcode in word0[7:0] + operands in their fields for all inputs.
# -- one per syndrome family / encoder, each proving totality AND round-trip
# correctness) + M21 kancell verified fixed-point ADDITIVE-policy leaf x6:
# kani_kan_spline_eval_total_bounded -- the piecewise-LINEAR spline is TOTAL over
# ALL i32 x_q (the clamp proves the segment index in 0..=KAN_KNOTS-2 so [seg+1]
# never panics) + the interpolant stays within the row's [min,max] knot envelope;
# kani_kan_score_no_overflow_bounded -- kan_score NEVER overflows + the final
# saturating clamp puts the i64 EXACTLY in the M17 DEMOTE_BAND [-34_000,34_000]
# over an overflow-safe table (the closed-form KAN_FEATURES*KAN_KNOT_MAX headroom);
# kani_kan_monotone_structural -- a table kan_table_is_monotone accepts as sign=-1
# is non-increasing in x (DECIDABLE from the knot-delta signs because the basis is
# piecewise-linear -- staler is never scored more keepable);
# kani_kan_table_validators_total -- kan_table_overflow_safe + kan_table_is_monotone
# are TOTAL over all i16 tables AND overflow_safe==true SOUNDLY implies kan_score
# stays in-band; kani_kan_score_deterministic -- kan_score is bit-for-bit
# reproducible (no float on the path); kani_kan_envelope_no_widening -- the
# heuristic pin verdict (IMP_PIN/UTIL_PIN/MIN_AGE) is INVARIANT under every
# kan_score value (the safety seam keeps the policy strictly downstream of the
# gate, can rank WITHIN the safe set but never widen it) + M22 prov verified
# memory-PROVENANCE-LEDGER leaf x6: kani_prov_canon_injective -- THE LOAD-BEARING
# proof: canon is TOTAL (fails closed to 0 on a too-small buffer, no partial write)
# AND INJECTIVE (a distinct kind/tier/payload_tok/writer_cap_id/t_created/parent-
# count encodes to distinct bytes -- the length-prefixed parent list is the
# disambiguator); kani_prov_hash_total -- prov_hash is TOTAL/no-overflow (wrapping
# FNV) + deterministic + full 32-byte width over a bounded symbolic buffer;
# kani_prov_chain_mix_tamper -- the fold is TAMPER-SENSITIVE: flipping the bit at a
# symbolic index of entry_id (or head) changes chain_mix (the head folds every
# byte; an identity/constant fold fails it); kani_prov_inclusion_sound -- verify_
# inclusion is SOUND (accept IFF recompute(leaf,siblings)==head) and a single-byte
# tamper of the leaf/sibling/head is REJECTED (siblings are load-bearing -- a
# verifier that ignored them accepts a forgery and fails the harness); kani_prov_
# canon_roundtrip -- the canonical scalar fields read back from their FIXED offsets
# via independent LE shifts (the blkfmt round-trip pattern); kani_prov_head_
# deterministic -- the same entry sequence folds to the same head bit-for-bit AND
# the fold is ORDER-SENSITIVE (a swapped chain yields a different head, so a
# reordered ledger is caught -- a commutative XOR fold fails it) + M20 blkfmt
# durable-persistence codecs x6: blk_req_header_roundtrip
# -- the 16-byte virtio-blk request header {le32 type, le32 reserved, le64 sector}
# round-trips + T_IN/T_OUT/T_FLUSH are well-formed; blk_superblock_identity -- the
# 512-byte log-structured superblock encode->decode is identity over symbolic gen/
# log_head[3]/record_count[3] (the FNV-1a-64 checksum it stamps matches on read-
# back); blk_superblock_decode_total -- the decode is TOTAL + fail-closed under the
# bounded magic/version/checksum-perturbation assume-envelope (NOT full 512-byte
# nondet -- the #49 over-quantification trap); blk_frame_header_roundtrip -- the
# 24-byte record-frame header round-trips every region/len/seq/payload_crc field;
# blk_record_frame_decode_total -- a frame over a symbolic 48-byte Episode body
# decodes (Some), the payload window stays in-bounds, and the Episode round-trips
# field-for-field (frame-level replay determinism); blk_sector_math_and_gen_monotone
# -- region_extent/record_sector are no-overflow + in-extent (sectors land strictly
# inside disjoint [first,first+count) extents, never the SB sector 0), the ceiling
# fails closed (Full), record_sector is strictly monotone in the log head (replay
# reproduces on-disk order), and gen+1 strictly increases (the two-phase commit).
# + M23 exp verified EXPERIENCE-CODEC leaf x6: kani_exp_canon_injective -- THE
# LOAD-BEARING proof: the fixed-WIDTH exp::canon is TOTAL (fails closed to 0 on a
# too-small buffer, no partial write) AND INJECTIVE (a distinct decision_id/kind/
# kan_score_shadow/RESERVED logging_propensity_q/present-Unset outcome-TAG encodes to
# distinct bytes -- every field at a FIXED offset, no variable-length tail);
# kani_exp_replay_determinism -- the HEADLINE claim: a recorded feats row replayed
# through the dormant kan_score reproduces kan_score_shadow BIT-IDENTICALLY, with
# feats BOUNDED to the kancell clamp range (so the spline stays the proven kancell
# regime, the #49 trap) + a CONCRETE table (a single evaluation pair, no symbolic-
# score blow-up); kani_exp_ring_total -- ExpRing::push is fixed-capacity / no-alloc /
# no-panic and the drop-oldest FIFO never exceeds CAP (bounded #[kani::unwind]);
# kani_exp_fold_tamper -- a single-byte flip of a committed record's canonical bytes
# changes the recomputed xp_head, REUSING the proven M22 prov::chain_mix fold (a
# SYMBOLIC flip index over all EXP_CANON_LEN bytes, concrete record/sibling so the
# FNV fold stays concrete); kani_exp_canon_roundtrip -- exp::decode(exp::canon(rec))
# == rec (the fixed-width bijection, an Unset record + a populated-outcome sub-check);
# kani_exp_schema_stability -- canon of an outcome=Unset + reserved-propensity-sentinel
# record has IDENTICAL length + field offsets to a populated record, so M24 populating
# the reserved fields CANNOT shift the fold (the reserve-now correctness obligation).
# + M24 explore/bakeoff verified HONEST-GATE leaves x6: kani_explore_propensity_total_positivity
# -- the closed-form shielded epsilon-greedy explore_propensity_q is TOTAL (no panic / no
# divide-by-zero), the m==1 SINGLETON guard returns EXACTLY 1000, and POSITIVITY holds (every
# cleared action in [1,1000] when eps_num>0 & m>=2 -> IPS identifiable over the explored
# support); kani_bakeoff_label_partition -- survival_label is TOTAL on saturating tick
# subtraction, the 3-way partition is EXHAUSTIVE + MUTUALLY EXCLUSIVE, and MONOTONE-RESOLUTION
# (a resolved Negative/Positive never flips as now advances -> replay-stable);
# kani_bakeoff_bound_sound_rounddown -- value_lower_bound / eb_lower_bound / smoothness_floor_mean
# / value_upper_heuristic are TOTAL (no divide-by-zero; n_total==0 fails closed to Y_LO) and
# SOUND (the lower bound never exceeds a constant-reward overlap mean, rounds DOWN);
# kani_bakeoff_replay_determinism -- the chosen explore-vs-greedy action (keyed to the IMMUTABLE
# decision_id via the reused M22 fold, never a mutable step counter), its propensity, the survival
# label + reward, and the value lower-bound ALL replay bit-for-bit; kani_kan_envelope_no_widening_m24
# -- the M21 envelope-no-widening proof RE-ASSERTS: the heuristic pin verdict is INVARIANT under
# both the kan_score AND the explore coin (the shielded epsilon only chooses AMONG already-cleared
# candidates -- pin/grace/util-pin never explorable, zero actions added to A_safe);
# kani_bakeoff_schema_stability -- populating the M23-reserved OutcomeLabel slot with a RESOLVED
# survival label (ReRecalled/Evicted) + the soft-greedy propensity shifts NO byte offset (reusing
# the M23 reserve-now lemma -> M22 fold / M20 spill byte-identical).
# + M25 opframe verified OPERATOR-TRANSCRIPT leaf x6: kani_opframe_canon_injective -- THE
# LOAD-BEARING proof: the typed, fixed-header, LENGTH-PREFIXED opframe::canon is TOTAL (fails
# closed to 0 on a too-small buffer, no partial write) AND INJECTIVE (a distinct seq/t_logical/
# prev_head/payload-value encodes to distinct bytes, and a distinct payload LENGTH to a distinct
# total length -- the payload_len u32 prefix is the disambiguator making the variable tail self-
# delimiting); kani_opframe_partition_leak -- THE LEAKAGE GUARD negative control: canon FAIL-CLOSES
# (returns 0, no head advance) on a frame tagged the sealed partition::SAFETY_HELD_OUT (the
# Seldonian no-snoop invariant encoded in the encoder -- Thomas Science 2019 + Dwork reusable
# holdout) AND on an out-of-band severity, while a CANDIDATE valid frame DOES encode (accept half
# non-vacuous); kani_opframe_seq_monotone -- the strict-monotone reader check seq_index_exact
# ACCEPTS seqs[i]==i and REJECTS a symbolic single-position perturbation (gap/dup/reorder) + a
# non-zero start (so a dropped/reordered middle frame is caught); kani_opframe_intro_binding -- the
# genesis INTRO binds the transcript to the LIVE M22 provenance head ("which instance am I" -- RATS
# RFC 9334); intro_binds accepts IFF kind==INTRO && seq==0 && prev_head==the true head, and REJECTS
# a symbolic single-byte forged anchor / non-zero seq / non-INTRO kind; kani_opframe_fold_truncation
# -- a single-byte flip of a committed frame's canonical bytes changes the recomputed op_head
# (REUSING the proven M22 prov::chain_mix fold over the opframe bytes -- a SYMBOLIC flip index,
# concrete frame/sibling so the FNV fold stays concrete) AND the closing GATE_VERDICT's
# gate_commits_final_seq catches a truncated tail (a reader expecting a longer transcript than the
# committed final seq is rejected -- the Ma-Tsudik FssAgg fix); kani_opframe_canon_roundtrip --
# opframe::decode(opframe::canon(frame)) == frame (every header field read back from its fixed
# offset, the payload slice recovered via the length prefix).
# + M26 exittel verified EL2 EXIT-TELEMETRY leaf x5: kani_exittel_canon_injective -- THE
# LOAD-BEARING proof: the fixed-WIDTH exittel::canon is TOTAL (fails closed to 0 on a too-small
# buffer, no partial write) AND INJECTIVE (a distinct exit_class/bucket/vmid/count/logical_time
# encodes to distinct bytes -- every field at a FIXED offset); kani_exittel_canon_roundtrip --
# exittel::decode(exittel::canon(rec)) == rec (the fixed-width bijection); kani_exittel_class_total
# -- the reused L2.2 classify_exit is TOTAL over every ESR, class_tag maps EVERY ExitClass into
# 0..N_CLASSES and class_from_tag is its exact inverse (a bijection -> an exit's class always
# encodes to a valid round-trippable byte), an out-of-range tag fails closed;
# kani_exittel_histogram_saturates -- bucket_index(delta) is in 0..N_BUCKETS for ALL u64 (no panic,
# the OTel log2 idea no-float) AND ExitHistogram::record SATURATING-increments (bucket in range +
# count monotone non-decreasing, never wraps); kani_exittel_fold_tamper -- a single-byte flip of a
# committed record's canonical bytes changes the recomputed tel_head, REUSING the proven M22
# prov::chain_mix fold (a SYMBOLIC flip index, concrete record/sibling so the FNV fold stays
# concrete). PRODUCER-ONLY: the telemetry is recorded + folded, never fed to a policy (the
# confounding loop is structurally avoided; signal=OBSERVATIONAL-NONCAUSAL).
# Bump this in LOCKSTEP when adding/removing a harness; any mismatch fails the gate.
EXPECTED_HARNESSES=69

echo "==> Running Kani over tb-encode ..."
# Capture both streams; --output-format=terse prints one VERIFICATION line per
# harness. `|| true` so a non-zero Kani exit (a real proof failure) is handled by
# the explicit checks below rather than aborting under `set -e`.
OUT="$(cargo kani -p tb-encode --output-format=terse 2>&1 || true)"
printf '%s\n' "$OUT"

FAILED="$(printf '%s\n' "$OUT" | grep -c 'VERIFICATION:- FAILED' || true)"
SUCCEEDED="$(printf '%s\n' "$OUT" | grep -c 'VERIFICATION:- SUCCESSFUL' || true)"

if [ "$FAILED" -ne 0 ]; then
  echo "ENCODE PROOF GATE: FAIL -- $FAILED harness(es) reported VERIFICATION:- FAILED" >&2
  exit 1
fi

if [ "$SUCCEEDED" -ne "$EXPECTED_HARNESSES" ]; then
  echo "ENCODE PROOF GATE: FAIL -- expected $EXPECTED_HARNESSES successful harnesses, saw $SUCCEEDED (regression / tamper / build error)" >&2
  exit 1
fi

echo "V1: kani-encoders OK"
exit 0
