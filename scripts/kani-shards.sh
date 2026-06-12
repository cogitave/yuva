#!/usr/bin/env bash
# #101 -- THE single source of truth for the prove-encode 2-way shard split.
#
# Sourced (never executed) by scripts/verify-encode.sh, which is in turn the
# only thing .github/workflows/kani.yml's prove-encode-a / prove-encode-b jobs
# run -- the lists, the per-shard pinned counts (derived from the list lengths)
# and the pinned total all live HERE and nowhere else. No duplicated lists.
#
# WHY SHARDED (the option-4 trigger, docs/plans/m29-stage-c-kani-budget-plan.md):
# the pre-agreed escape-hatch trigger was "shard when a measured full pass
# exceeds ~38 min". The first post-M29-stage-C CI pass measured 41m22s of the
# 45-min cap (local WSL: 29.2 min / 1752s -- the runner delta is real), and M31
# stage A adds +6 harnesses. Sharding splits SOLVING time only (codegen is
# duplicated per shard; the #77 cache reclaims it on unchanged-crate pushes),
# so the split below balances by MEASURED per-harness cost, not by count.
#
# COST SOURCE (local WSL seconds, measured per the M29 discipline; recorded in
# the PR #27 / #30 / #32 bodies + docs/plans/m29-stage-c-plan.md SS2): the 21
# post-cutover khash/BLAKE2s-bearing harnesses are annotated inline below; the
# other 69 were assumed FNV-era-trivial, then the #101 per-shard timed runs
# CORRECTED that assumption: shard B's nominally-trivial families (the kan
# unwind loops, frame_conserved's symbolic plan, the canon-injectivity proofs)
# average ~6.5s vs ~1s for shard A's POD encoders, so the first 45/45
# cost-greedy split measured A=13m24 / B=16m36 and
# kani_khash_total_deterministic (90.3s) was moved B->A to rebalance ON THE
# MEASUREMENT (a side benefit: the whole M29 khash family now lives
# coherently in shard A). Balance is by measured COST, not count.
#   measured-heavy sum:  shard A = 799.6s (46 names), shard B = 620.0s (44)
#   measured local wall: see the #101 PR (one timed pass per final shard,
#                        guard + duplicated codegen included, ~15 min each)
#   projected CI:        ~21-24 min per shard (x1.42 runner delta + the fixed
#                        checkout/cache/smoke steps), vs the 30-min timeout
#
# THE COMPLETENESS GUARD (MANDATORY, fail-closed -- the M29 count-gate lesson):
# shards_assert_complete below is run by verify-encode.sh in EVERY mode (a, b,
# all) BEFORE Kani, and asserts
#   (1) len(SHARD_A) + len(SHARD_B) == EXPECTED_HARNESSES_TOTAL (the pin),
#   (2) grep -c '#[kani::proof]' crates/tb-encode/src/proofs.rs == the pin
#       (a harness ADDED to proofs.rs but to neither list, or DROPPED from
#       proofs.rs with stale lists, FAILS the gate -- it can never silently
#       vanish from coverage),
#   (3) the two lists are DISJOINT (no harness proven "twice" hiding a gap),
#   (4) every listed name exists as a fn in proofs.rs (a RENAME with stale
#       lists fails here, statically and loudly).
# The static grep is the LIST<->SOURCE lockstep check only; the proof gate
# itself stays execution-enforced -- verify-encode.sh counts Kani's own
# "VERIFICATION:- SUCCESSFUL" lines against the shard's pinned length.
#
# PER-MILESTONE BUMP (ONE-TOUCH -- keep it this way): a new harness is added to
# EXACTLY ONE shard list below (pick the lighter shard -- the projections
# above; annotate the measured local time if >~20s) AND EXPECTED_HARNESSES_TOTAL
# is bumped by 1. Nothing else: the per-shard counts are the list lengths,
# verify-encode.sh sources this file, and kani.yml only sets SHARD=a|b. Any
# mismatch (forgotten list add, forgotten bump, rename, dup) fails closed in
# shards_assert_complete on BOTH CI jobs and on every local run.

# The pinned total -- MUST equal the '#[kani::proof]' count in
# crates/tb-encode/src/proofs.rs (asserted below). Bump in lockstep when a
# milestone adds/removes a harness.
EXPECTED_HARNESSES_TOTAL=96

# Shard A (46): the silicon-adjacent encoder/parser families (VMX, paging/EPT,
# IPC, memscore, L2.1-L2.3, aL2.4-aL2.6, M20 blkfmt -- all measured-trivial)
# + the heavy tamper/e2e witnesses: the M22 fold non-degeneracy pair, the
# kept-FULL M23 e2e fold witness, the M28 MAC tamper, the COMPLETE M29 khash
# family, and the M30 codec + echo-soundness legs.
SHARD_A=(
  # VMX x4 (trivial)
  kani_adjust_within_allowed
  kani_adjust_idempotent
  kani_clamp_fixed_within_bounds
  kani_decode_tss_base_matches
  # paging/EPT x4 (trivial)
  kani_make_entry_roundtrip
  kani_level_index_bounds
  kani_ept_leaf_wellformed
  kani_ept_nonleaf_and_eptp
  # IPC frame/ring x3 (trivial)
  kani_ipc_frame_roundtrip
  kani_ipc_frame_decode_total
  kani_bounded_ring_framing
  # memscore x4 (trivial)
  kani_log2_fixed_panic_free_bounded
  kani_ln_fixed_panic_free_bounded
  kani_bla_raw_panic_free_bounded
  kani_minmax_in_scale_range
  # L2.1 stage-2/el2_trap x5 (trivial)
  kani_s2_leaf_wellformed
  kani_s2_table_and_vttbr
  kani_vtcr_wellformed
  kani_esr_decode_total
  kani_hpfar_fault_ipa
  # L2.2 + L2.3 x3 (trivial)
  kani_exit_classifier_total
  kani_sysreg_iss_decode_total
  kani_dabt_iss_decode_total
  # aL2.4 + aL2.5 + aL2.6 x5 (trivial)
  kani_sctlr_el1_guest_enable
  kani_gich_lr_encode_roundtrip
  kani_ste_s2_roundtrip
  kani_ste_vtcr_matches_cpu_stage2
  kani_smmu_cmd_encode_total
  # M20 blkfmt x6 (trivial)
  kani_blk_req_header_roundtrip
  kani_blk_superblock_identity
  kani_blk_superblock_decode_total
  kani_blk_frame_header_roundtrip
  kani_blk_record_frame_decode_total
  kani_blk_sector_math_and_gen_monotone
  # M22 prov heavy pair (PR #32 measured)
  kani_prov_hash_total                  # 34.7s
  kani_prov_chain_mix_tamper            # 108.2s
  # M23 -- the kept-FULL e2e fold witness (PR #32 measured)
  kani_exp_fold_tamper                  # 174.2s
  # M28 MAC tamper (PR #27 measured)
  kani_cmd_mac_tamper                   # 60s
  # M29 khash x4, the complete family (PR #27 measured;
  # total_deterministic moved B->A on the #101 timed-run rebalance)
  kani_khash_total_deterministic        # 90.3s
  kani_khash_vectors                    # 59.5s
  kani_khash_tamper                     # 112.2s
  kani_khash_keyed_distinct             # 36.5s
  # M30 inferwire x4 (PR #30 measured)
  kani_inferwire_canon_roundtrip        # 14s
  kani_inferwire_decode_total           # 7s
  kani_inferwire_echo_sound             # 100s
  kani_inferwire_accum_resync           # 3s
)

# Shard B (50): the learning-loop codec families (M21 kancell, M22 prov canon,
# M23 exp, M24 explore/bakeoff, M25 opframe, M26 exittel, M27 tpsched, M28 cmd
# -- measured ~6.5s average, NOT trivial) + the heavy iff/determinism fold
# legs (inclusion_sound, head_deterministic, bakeoff_replay), the thinned
# per-milestone fold leaves, key_evolve, the M30 peer-binding legs, and the
# M31 inference-adapter six (placed HERE per the one-touch rule -- shard B was
# the lighter shard by measured cost, 620.0s vs A's 799.6s, and the six
# measure light: see the inline annotations).
SHARD_B=(
  # M21 kancell x6 (trivial)
  kani_kan_spline_eval_total_bounded
  kani_kan_score_no_overflow_bounded
  kani_kan_monotone_structural
  kani_kan_table_validators_total
  kani_kan_score_deterministic
  kani_kan_envelope_no_widening
  # M22 prov x4 -- canon pair trivial, fold legs heavy (PR #32 measured)
  kani_prov_canon_injective
  kani_prov_inclusion_sound             # 147.9s
  kani_prov_canon_roundtrip
  kani_prov_head_deterministic          # 106.2s
  # M23 exp x5 (trivial; the fold witness lives in shard A)
  kani_exp_canon_injective
  kani_exp_replay_determinism
  kani_exp_ring_total
  kani_exp_canon_roundtrip
  kani_exp_schema_stability
  # M24 explore/bakeoff x6 -- replay heavy (PR #32 measured)
  kani_explore_propensity_total_positivity
  kani_bakeoff_label_partition
  kani_bakeoff_bound_sound_rounddown
  kani_bakeoff_replay_determinism       # 141.5s
  kani_kan_envelope_no_widening_m24
  kani_bakeoff_schema_stability
  # M25 opframe x6 -- truncation fold thinned but khash-bearing (PR #32)
  kani_opframe_canon_injective
  kani_opframe_partition_leak
  kani_opframe_seq_monotone
  kani_opframe_intro_binding
  kani_opframe_fold_truncation          # 42.7s
  kani_opframe_canon_roundtrip
  # M26 exittel x5 (PR #32 measured fold leaf)
  kani_exittel_canon_injective
  kani_exittel_canon_roundtrip
  kani_exittel_class_total
  kani_exittel_histogram_saturates
  kani_exittel_fold_tamper              # 26.1s
  # M27 tpsched x5 (PR #32 measured fold leaf)
  kani_tpsched_next_slot_roundrobin
  kani_tpsched_frame_conserved
  kani_tpsched_canon_injective
  kani_tpsched_canon_roundtrip
  kani_tpsched_fold_tamper              # 25.6s
  # M28 cmd x5 -- key_evolve heavy (PR #27 measured; mac_tamper in shard A)
  kani_cmd_canon_injective
  kani_cmd_stale_nonce
  kani_cmd_head_binding
  kani_cmd_dual_custody
  kani_cmd_key_evolve                   # 45s
  # M30 inferwire x2 (PR #30 measured)
  kani_inferwire_req_binding            # 2s
  kani_inferwire_peer_label_bound       # 83s
  # M31 inferwire adapter x6 (measured locally at landing, WSL seconds -- the
  # khash-bearing pair runs the PINNED-VECTOR one-khash-execution shape: a
  # 90-byte M31 MAC message measured ~70s per CBMC execution, so each harness
  # holds exactly one; ladder record in the harness docs + the M31 PR)
  kani_inferwire_kind_ext               # 12s
  kani_infer_subhdr_total               # 4s
  kani_infer_assembler                  # 46s
  kani_infer_resp_binding               # 89s
  kani_infer_domain_sep                 # 75s
  kani_infer_err_closed                 # 3s
)

# The fail-closed completeness/disjointness guard (#101 -- see the header).
# Runs in EVERY verify-encode.sh mode; any exit here fails the CI job.
shards_assert_complete() {
  local shards_dir proofs
  shards_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  proofs="$shards_dir/../crates/tb-encode/src/proofs.rs"

  if [ ! -f "$proofs" ]; then
    echo "SHARD GUARD: FAIL -- proofs.rs not found at $proofs" >&2
    return 1
  fi

  local a_len b_len list_total src_count
  a_len="${#SHARD_A[@]}"
  b_len="${#SHARD_B[@]}"
  list_total=$((a_len + b_len))
  src_count="$(grep -c '#\[kani::proof\]' "$proofs")"

  # (1) the two lists together must equal the pinned total.
  if [ "$list_total" -ne "$EXPECTED_HARNESSES_TOTAL" ]; then
    echo "SHARD GUARD: FAIL -- shard lists sum to $list_total (A=$a_len + B=$b_len) but EXPECTED_HARNESSES_TOTAL=$EXPECTED_HARNESSES_TOTAL (a harness was added/removed without the lockstep list edit in scripts/kani-shards.sh)" >&2
    return 1
  fi

  # (2) the pinned total must equal the #[kani::proof] count in the source --
  # a harness assigned to NEITHER shard can never silently vanish.
  if [ "$src_count" -ne "$EXPECTED_HARNESSES_TOTAL" ]; then
    echo "SHARD GUARD: FAIL -- proofs.rs has $src_count '#[kani::proof]' harnesses but EXPECTED_HARNESSES_TOTAL=$EXPECTED_HARNESSES_TOTAL (bump scripts/kani-shards.sh in lockstep: add the harness to exactly ONE shard list + the total)" >&2
    return 1
  fi

  # (3) the lists must be disjoint (also catches a duplicate within one list).
  local dups
  dups="$(printf '%s\n' "${SHARD_A[@]}" "${SHARD_B[@]}" | sort | uniq -d)"
  if [ -n "$dups" ]; then
    echo "SHARD GUARD: FAIL -- harness(es) listed more than once across/within shards:" >&2
    printf '%s\n' "$dups" >&2
    return 1
  fi

  # (4) every listed name must exist as a fn in proofs.rs (catches a rename
  # or a typo statically; the execution gate would also catch it via the
  # SUCCESSFUL-count mismatch, but this fails earlier and names the culprit).
  local h missing=0
  for h in "${SHARD_A[@]}" "${SHARD_B[@]}"; do
    if ! grep -qE "fn ${h}\b" "$proofs"; then
      echo "SHARD GUARD: FAIL -- listed harness '$h' not found as a fn in proofs.rs (renamed/removed without the lockstep list edit)" >&2
      missing=1
    fi
  done
  [ "$missing" -eq 0 ] || return 1

  echo "SHARD GUARD: OK -- A=$a_len + B=$b_len == $EXPECTED_HARNESSES_TOTAL == proofs.rs count, disjoint, all names resolve"
  return 0
}
