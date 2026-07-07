#!/usr/bin/env bash
# Task #49 proof gate -- machine-check the PURE silicon-adjacent encoders/validators
# (VMX control-MSR adjust + CR0/CR4 clamp + TSS-base decode, page-table/EPT entry
# encoders, the 16-byte IPC frame codec + bounded ring) with Kani over the
# host-verifiable `tb-encode` crate, FAIL CLOSED.
#
# SHARD MODES (#101 -- the prove-encode lane is sharded into 2 parallel CI
# jobs; trigger: the first post-M29-stage-C CI pass measured 41m22s of the
# 45-min cap and M31 stage A adds +6 harnesses):
#   SHARD=all   (default) -- the single full counted pass, local-workflow
#              behavior UNCHANGED: every harness, SUCCESSFUL must equal the
#              pinned EXPECTED_HARNESSES_TOTAL (120), marker `V1: kani-encoders OK`.
#   SHARD=a|b|c -- run ONLY that shard's pinned harness list (repeated
#              `--harness <name>` + `--exact` -- exact-name matching, never
#              substring, so e.g. kani_kan_envelope_no_widening can never
#              shadow ..._m24), SUCCESSFUL must equal that shard's pinned
#              count (the list length), marker `V1-shard-a: kani-encoders OK`
#              / `V1-shard-b: kani-encoders OK` / `V1-shard-c: kani-encoders OK`
#              (DISTINCT tokens -- a shard marker never claims the full 120).
# The shard lists + per-shard counts + the total live in ONE place,
# scripts/kani-shards.sh (sourced below) -- consumed by this script in all
# modes and by kani.yml only via SHARD=a|b|c. EVERY mode first runs the
# fail-closed completeness guard (lists disjoint + exhaustive + in lockstep
# with proofs.rs's '#[kani::proof]' count), so a renamed/added/dropped harness
# can never silently vanish from coverage even when no full pass runs on CI.
#
# Emits the DoD marker for the asserted set and exits 0 ONLY when:
#   * the completeness guard passes, AND
#   * ZERO harnesses report `VERIFICATION:- FAILED`, AND
#   * the count of `VERIFICATION:- SUCCESSFUL` EXACTLY equals the pinned
#     count for the asserted set -- counted from Kani's OWN output lines,
#     never a static grep -- (so a silently deleted / renamed / vacuous
#     harness can never let the gate pass -- the marker is tamper-evident).
#
# Run by .github/workflows/kani.yml (the `prove-encode-a` / `prove-encode-b`
# jobs, SHARD=a|b) AFTER the model-checking/kani-github-action step has
# installed Kani's own pinned toolchain (so `cargo kani` is on PATH). Kani is
# NOT invoked through the `kbuild` alias and NEVER via `--workspace` (that
# would drag tb-hal's inline asm into CBMC), only the per-package
# `-p tb-encode` form, so -Zbuild-std and the asm-bearing crates never
# contaminate this host verification. This is the SIBLING gate to
# scripts/verify-caps.sh (M11); it does NOT touch that lane.
set -euo pipefail

# The shard lists + pinned counts + the completeness guard (single source of
# truth -- see the #101 header in that file for the bump procedure).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/kani-shards.sh
. "$SCRIPT_DIR/kani-shards.sh"

# The harness INVENTORY -- what each `#[kani::proof]` harness in
# crates/tb-encode/src/proofs.rs proves; the pinned count + the shard lists
# themselves live in scripts/kani-shards.sh (sourced above).
# (VMX x4 + paging/EPT x4 + IPC frame/ring x3 +
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
# disambiguator); kani_prov_hash_total -- prov_hash is TOTAL/no-overflow (since
# M29-C the body is khash::uhash -- BLAKE2s-256 unkeyed, wrapping 32-bit ARX;
# prim=BLAKE2S-256, sec=ASSUMED-FROM-LITERATURE -- the FNV-era structural digest
# retired) + deterministic + full 32-byte width over a bounded symbolic buffer;
# kani_prov_chain_mix_tamper -- the fold is TAMPER-SENSITIVE: flipping the bit at a
# SYMBOLIC index of entry_id (or head) changes chain_mix (the head folds every one
# of the 64 head/entry byte positions; an identity/constant fold fails it; M29-C
# form: base + determinism + one symbolic entry-flip + one symbolic head-flip +
# the flip-back NEG -- flip-then-flip-back restores the base digest, proving the
# mutation reaches the hash); kani_prov_inclusion_sound -- verify_inclusion is
# SOUND (the M29-C iff over a fully-SYMBOLIC candidate head: verify(leaf,sibs,
# any_head) == (genuine head == any_head), the genuine head recomputed ONCE --
# the symbolic any_head subsumes the genuine-accept and tampered-head legs) and a
# single-byte tamper of the leaf/sibling is REJECTED (siblings are load-bearing --
# a verifier that ignored them accepts a forgery and fails the harness); kani_prov_
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
# SYMBOLIC flip index over all EXP_CANON_LEN bytes, concrete record/sibling; M29-C:
# KEPT FULL -- leaf re-hash -> head mismatch -> inclusion failure end-to-end through
# the REAL fold, THE one representative deep witness the thinned opframe/exittel/
# tpsched fold-claim= markers name as e2e=); kani_exp_canon_roundtrip -- exp::decode(exp::canon(rec))
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
# -- M29-C-thinned to LEAF-SENSITIVITY + flip-back: a SYMBOLIC-index single-byte flip of a committed
# frame's canonical bytes changes its prov_hash LEAF id, and flip-back restores it (the chain-level
# head-mismatch + inclusion-failure rejection is the documented COMPOSITION of three machine-proven
# conjuncts -- this leaf claim AND kani_prov_chain_mix_tamper AND kani_prov_inclusion_sound --
# demonstrated end-to-end by the kept-FULL kani_exp_fold_tamper;
# fold-claim=LEAF-SENSITIVITY+COMPOSED(chain_mix_tamper, inclusion_sound; e2e=exp_fold_tamper))
# AND the closing GATE_VERDICT's gate_commits_final_seq catches a truncated tail VERBATIM (a reader
# expecting a longer transcript than the
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
# count monotone non-decreasing, never wraps); kani_exittel_fold_tamper -- M29-C-thinned to
# LEAF-SENSITIVITY + flip-back: a SYMBOLIC-index single-byte flip of a committed record's canonical
# bytes changes its prov_hash LEAF id, and flip-back restores it (the chain-level tel_head-mismatch
# + inclusion-failure rejection is the documented COMPOSITION of three machine-proven conjuncts --
# this leaf claim AND kani_prov_chain_mix_tamper AND kani_prov_inclusion_sound -- demonstrated
# end-to-end by the kept-FULL kani_exp_fold_tamper;
# fold-claim=LEAF-SENSITIVITY+COMPOSED(chain_mix_tamper, inclusion_sound; e2e=exp_fold_tamper)).
# PRODUCER-ONLY: the telemetry is recorded + folded, never fed to a policy (the
# confounding loop is structurally avoided; signal=OBSERVATIONAL-NONCAUSAL).
# + M27 tpsched verified TWO-VMID TIME-PARTITION-SCHEDULER leaf x5: kani_tpsched_next_slot_roundrobin
# -- next_slot is TOTAL over ALL usize (fail-closed to 0 for an out-of-range slot), strictly cycles
# 0->1->0, and NEITHER slot is a fixed point (round-robin LIVENESS -> neither VMID starves);
# kani_tpsched_frame_conserved -- over a SYMBOLIC FramePlan, frame_total == sum of slot_deadline_delta,
# every slot's delta is clamped UP to MIN_SLOT_TICKS (no starvation) and <= frame_total (no monopoly),
# the saturating sum never overflows; kani_tpsched_canon_injective -- the fixed-WIDTH tpsched::canon is
# TOTAL (fail-closed to 0) AND INJECTIVE (a distinct frame_seq/slot/vmid_from/vmid_to/t_logical encodes
# to distinct bytes); kani_tpsched_canon_roundtrip -- tpsched::decode(tpsched::canon(rec)) == rec;
# kani_tpsched_fold_tamper -- M29-C-thinned to LEAF-SENSITIVITY + flip-back: a SYMBOLIC-index
# single-byte flip of a committed decision's canonical bytes changes its prov_hash LEAF id, and
# flip-back restores it (the chain-level sched_head-mismatch + inclusion-failure rejection is the
# documented COMPOSITION of three machine-proven conjuncts -- this leaf claim AND
# kani_prov_chain_mix_tamper AND kani_prov_inclusion_sound -- demonstrated end-to-end by the
# kept-FULL kani_exp_fold_tamper;
# fold-claim=LEAF-SENSITIVITY+COMPOSED(chain_mix_tamper, inclusion_sound; e2e=exp_fold_tamper)).
# OBSERVATIONAL not learned (fixed round-robin); NOT real-time / NOT schedulability-
# proven (realtime=NOT-CLAIMED).
# + M28 opframe_rx verified OPERATOR-INBOUND command leaf x6 (the RX dual of M25 opframe -- the CAPSTONE
# that closes the learning loop): kani_cmd_canon_injective -- the load-bearing canon totality+injectivity
# proof (the MAC'd bytes = everything EXCEPT the trailing mac; the payload_len u32 prefix disambiguates
# the variable tail; fail-closed on a too-small buffer / unknown kind; decode fails closed without the
# trailing MAC). The freshness/head-binding/dual-custody discrimination is proven at the LEAF-predicate
# level (NOT through the full decode_and_verify wrapper, whose multi-buffer round-trip CBMC cannot
# constant-fold -- the same intractability class as the #49 FNV trap; the wrapper integration is exercised
# concretely by the host tests + boot self-test): kani_cmd_stale_nonce -- decode recovers the echoed nonce
# EXACTLY (the codec half, fully symbolic, FNV-free) and the freshness predicate (echoed == expected)
# discriminates a stale replay from the fresh challenge; kani_cmd_head_binding -- decode recovers the bound
# op_head EXACTLY and the head-binding predicate (bound == live) rejects a forged cross-boot head (the
# Terrapin lesson, SYMBOLIC single-byte flip); kani_cmd_dual_custody -- decode recovers BOTH cred ids
# EXACTLY and the dual-custody predicate (cred_a != cred_b) rejects a single signer (the two-person rule,
# fully symbolic); kani_cmd_mac_tamper -- a single-byte flip of the keyed MAC's CONCRETE canon-bytes input
# changes the recomputed MAC (since M29 the body under proof is the khash-backed DERIVE-THEN-MAC, 2
# keyed-BLAKE2s calls; a SYMBOLIC flip index over CONCRETE keys+canon so every compression stays
# concrete -- the #49 trap; re-measured at the M29 swap); kani_cmd_key_evolve -- key_evolve is
# deterministic + advances (not a fixed point) + tamper-sensitive (since M29 the domain-separated
# keyed-PRF call khash(key, "YUVA-KEY-EVOLVE-V1") -- the Bellare-Yee shape; SYMBOLIC flip index,
# CONCRETE key; re-measured at the M29 swap). The MAC tier is mac=KEYED-CRYPTO (M29 --
# assumption-conditional: implementation VERIFIED, primitive security ASSUMED-FROM-LITERATURE; the
# retired KEYED-NONCRYPTO tier is guard-REJECTED); the oracle is a test key (oracle=SIMULATED-ENROLLED-KEY);
# an accepted command is necessary-not-sufficient (kan_active=0).
# + M29 khash verified KEYED-HASH primitive leaf x4 (BLAKE2s-256, RFC 7693, native keyed mode -- the
# mac=KEYED-CRYPTO primitive; ALL khash harnesses are CONCRETE-VECTOR-ONLY per the #49 discipline:
# hash inputs concrete (or one <=2-byte fully-symbolic message for totality at the ceiling), only
# flip INDEXES symbolic; a symbolic collision/preimage/PRF harness is structurally impossible here
# BY DESIGN -- no tool in the field proves primitive security, and a vacuous one would be
# overclaim-by-implication, so that tier stays ASSUMED-FROM-LITERATURE, machine-tokened):
# kani_khash_total_deterministic -- the MINIMAL §3.3 path-covering set (measured: ~9s per concrete
# compression, so digests are computed once and REUSED): khash at {0,64,65} (key-block-as-final /
# block-aligned final / full+partial final -- any 1..=63 remainder takes 65's branch) + uhash at
# {0,1,65} (empty special case / partial final / multi-block loop), panic-freedom over each path,
# compute-twice DETERMINISM pinned to keyed-64 + unkeyed-empty; the remaining boundary lengths are
# pinned by the official KAT sweep under cargo test + Miri (same code, same paths); deliberately NO
# fully-symbolic message bytes through the compression (the #49 rule -- data variation through the
# compression is the symbolic-flip-index tamper harness's job);
# NEG: khash(k,m64) != khash(k,m64||0x00) (the classic
# last-block padding/counter bug) and uhash("") != uhash("\x00") (identical padded blocks separated
# ONLY by the t counter -- a dropped §3.2 t fold fails); kani_khash_vectors -- the fail-closed boot
# KAT body kat_ok() recomputes the OFFICIAL vectors (RFC 7693 Appendix B "abc" + the BLAKE2
# reference keyed KATs, key 000102..1f, empty + 65-byte inputs) through the REAL compression (any
# wrong IV/sigma/rotation/counter/final-flag fails); NEG: the computed digest != the expected
# constant perturbed at a symbolic byte index (a vacuous comparator fails); kani_khash_tamper -- a
# one-bit flip at a SYMBOLIC index over ALL 65 message bytes AND all 32 key bytes of a concrete
# two-block input changes the tag; NEG: flip-then-flip-back RESTORES the reference tag (the
# mutation provably reaches the hash); kani_khash_keyed_distinct -- two concrete keys one byte
# apart give distinct tags on the same message AND khash(k,m) != uhash(m) (the §2.5 kk parameter
# word + key block 0 separate the modes; a skipped key block fails both asserts).
# + M30 inferwire verified INFERENCE-TRANSPORT codec leaf x6 (the frame codec + stream
# accumulator + host-keyed echo behind the guest<->host channel; CONCRETE-FRAME /
# SHORT-SYMBOLIC per the #49 discipline -- frame inputs concrete or <=8 symbolic bytes,
# only flip-indexes/predicates/lengths symbolic; every khash-consuming harness uses a
# 58-byte MAC message = key block + ONE message block = 2 compressions per call, <=4
# calls per harness -- the M29 measured budget; the codec harnesses are khash-FREE;
# MUTATION-TESTED per proposal §6: a flipped decode bounds op / a dropped
# peer_id/challenge/nonce in echo_tag's MAC input / an off-by-one FrameAccum cap each
# turn at least one harness RED -- recorded in the M30 proposal so the obligation is
# auditable): kani_inferwire_canon_roundtrip -- decode(canon(f)) recovers every field
# bit-exactly at boundary payload lengths {0,1,31} (+ the 1024 cap pinned by length
# math; the full-cap byte round-trip is host-test+Miri territory, the #49 cost rule),
# AND a one-byte perturbation at a symbolic index across req_id/challenge/nonce/peer/
# tag canons to DISTINCT bytes (injectivity); NEG: a kind-only difference canons to
# distinct bytes (a kind-blind encoder fails); kani_inferwire_decode_total -- a
# fully-symbolic short buffer + every concrete truncation + a reserved-nonzero flags
# byte (symbolic over all 255) + an oversize declared payload_len (symbolic past the
# cap) ALL reject, a fully-symbolic exact-header buffer is panic-free with
# accept-soundness (Some implies the magic/ver/flags bytes provably hold); NEG: the
# exactly-valid frame decodes Some (the rejector is non-vacuous);
# kani_inferwire_req_binding -- resp_binds_req(resp,id) IFF resp.req_id==id AND
# kind==ECHO_RESP, fully symbolic; NEG: flip-then-flip-back of a symbolic req_id byte
# breaks then RESTORES the binding (the mutation provably reaches the field);
# kani_inferwire_echo_sound -- verify_echo ACCEPTS the genuine host-keyed echo and a
# one-bit flip at a symbolic index over ALL tag+body bytes REJECTS (concrete 8-byte
# body -> 2 compressions/call, 4 calls; the key-flip range is EXCLUDED per the
# measured #49 budget -- 129s with it, key-bit sensitivity is kani_khash_tamper's
# theorem at the primitive level, verify_echo's key path is a direct khash call, and
# the wrongkey reject fires in-boot on every attached lane + in the host tests);
# NEG: flip-then-flip-back restores acceptance (a constant/length-only tag stand-in
# fails); kani_inferwire_accum_resync
# -- the capacity + resync DISCIPLINE proof, RESHAPED down the FULL measured #49
# mitigation ladder to its named last rung (split the FrameAccum trace out): (leg A,
# the off-by-one-capacity killer) a TINY-cap FrameAccum<6> driven to capacity and
# THROUGH the at-capacity consume-then-resync branch by a CONCRETE plausible-header
# stream that can never complete a frame NEVER overflows (len()<=CAP after every push,
# every index Kani-checked on that path; const-generic, so the discipline proven at
# CAP=6 is the same code path the INFER_ACCUM_CAP alias runs -- its value pinned by
# harness 1 length math); (leg B) EVERY byte-wise resync class -- non-magic /
# magic-then-bad-second / bad version / unknown kind / reserved-nonzero flags -- each
# fed concretely, every push None, the accumulator drains and stays reusable. The
# FULL emit trace (garbage -> 68-byte frame -> emitted EXACTLY ONCE at wire length ->
# emitted window decodes) is a NAMED delegation: every symbolic/trace form (symbolic
# bytes, symbolic length, kissat, chunked unwind, decode-free scan) measured >>120s --
# a structural CBMC floor for a 66-byte-header protocol (~68 sequential push inlines x
# the unwind bound on the scan/consume/resync loops); it runs as 5 dedicated host
# tests + the Miri gate over this exact code, and BOTH live CI boot lanes push the
# real host response through FrameAccum byte-at-a-time every boot with the proven
# fail-closed decode as the arbiter of the emitted window (kernel stage-0x4 reject);
# symbolic-input rejection coverage lives in kani_inferwire_decode_total, whose
# decoder IS the rule set scan enforces byte-wise; NEG: every leg asserts None on
# every push (a fabricated frame boundary fails);
# kani_inferwire_peer_label_bound -- on the same (K,N,C,body), a distinct peer_id /
# challenge / nonce each yields a DISTINCT tag (peer+challenge+nonce provably INSIDE
# the MAC'd bytes -> the run-script lane cross-pin is real); NEG: an echo_tag that
# dropped any of them from its MAC input fails the corresponding inequality.
# + M31 inferwire INFERENCE-ADAPTER extension x6 (the chunked byte-body framing on
# the SAME leaf -- kinds INFER_REQ/INFER_RESP/INFER_PENDING, the 24-byte in-payload
# SubHdr, the per-chunk infer_tag MAC under the NEW "YUVA-M31-INFER-V1" domain
# separator binding peer‖nonce‖challenge‖req_id‖kind‖seq‖sflags‖total_len‖
# body_digest‖chunk INSIDE the MAC, the compile-time INFER_BODY_CAP=8192
# reject-never-truncate bound, the chunk-at-a-time InferAssembler -- deliberately
# NOT a byte-push trace, the M30 FrameAccum CBMC-floor lesson -- and the closed ERR
# payload enum; #49 budget: khash bodies on CONCRETE short messages only, symbolic
# flips over indexes/predicates/sub-header bytes, never key material; each harness
# MUTATION-TESTED per M31 proposal §8 -- a dropped seq in infer_tag's MAC input, an
# off-by-one assembler cap, a flipped sub-header bounds check, and swapped domain
# labels each turn a named harness RED, recorded in the M31 PR):
# kani_inferwire_kind_ext -- canon/decode round-trip for the NEW kinds 4/5/6 at
# boundary payload lengths; NEG: a symbolic kind outside the closed set {1..6}
# fail-closes at canon AND decode (the extension does not widen totality);
# kani_infer_subhdr_total -- symbolic SubHdr round-trip over the full valid
# envelope, every truncation rejects, reserved sflags bits 1..7 / nonzero rsv /
# out-of-band total_len (0 or over-cap, symbolic) reject; NEG: the exactly-valid
# sub-header decodes (non-vacuous rejector); kani_infer_assembler -- at a TINY
# const-generic cap (CAP=8, the same code path the real INFER_BODY_CAP alias runs):
# in-order chunks assemble to EXACTLY total_len at total==CAP (the off-by-one
# capacity killer, every copy index Kani-checked), symbolic wrong-first/second seq
# (out-of-order/dup/gap), symbolic total_len drift, digest drift at a symbolic flip
# index, symbolic over-capacity total_len, and overflow-past-total ALL reject and
# POISON; completion requires the recomputed whole-body digest to equal the locked
# commitment; NEG: no reject leg ever returns Complete + the poisoned assembler
# rejects a valid retry (no fabricated/resurrected completion);
# kani_infer_resp_binding -- THE IFF-THEOREM, pinned-vector shape (the khash KAT
# idiom): over a FULLY SYMBOLIC tag, verify_infer_resp accepts the genuine frame
# IFF the tag equals the PINNED genuine MAC (KANI_RESP_BINDING_PIN, re-derived by
# the m31_kani_pins_rederive host test through the real leaf) -- ONE khash
# execution (the 90-byte M31 MAC message measured ~70s/execution in CBMC; the
# proposal-sketch forms all measured over budget: symbolic payload flips >5min,
# 5-execution flip/restore 235s, kissat no help -- the cost is formula
# construction, not SAT); the iff subsumes flip/restore AND kills every
# construction-drift mutant at the Kani level (dropped seq/field/label -> the
# recompute misses the pin -> RED); the pre-MAC binding legs (reflected REQ /
# wrong req_id / wrong challenge / body-bearing PENDING) reject concretely with
# the khash branch pruned; NEG: the iff itself is non-vacuous both ways (a
# reject-everything verifier fails ==, a tag-ignoring verifier fails !=);
# kani_infer_domain_sep -- pinned-vector shape: on inputs whose echo body is
# EXACTLY the serialized M31 MAC suffix (the two MAC inputs differ ONLY in their
# leading domain labels), infer_tag's output == its PIN and != the ECHO pin (one
# khash execution; a SWAPPED label hits the echo pin and fails !=, a DROPPED
# label misses the infer pin and fails ==); the live two-call inequality + both
# pins' genuineness run as the NAMED delegation m31_kani_pins_rederive under
# cargo test + Miri; NEG: both pin directions are concrete mutant killers and
# the label bytes are pinned distinct; kani_infer_err_closed -- over a fully
# symbolic code, err_canon encodes IFF the code is in the closed enum and the
# retryable binding round-trips; a contradicted flag / nonzero reserved byte /
# wrong payload length reject; accept-soundness over a fully-symbolic 4-byte
# payload; NEG: a valid code decodes.
# The pinned count + the SHARD_A/SHARD_B lists now live in
# scripts/kani-shards.sh (sourced above) -- bump THERE in LOCKSTEP when
# adding/removing a harness (the #101 one-touch procedure: the new name goes
# into exactly ONE shard list + EXPECTED_HARNESSES_TOTAL); any mismatch fails
# the completeness guard below in every mode.

SHARD="${SHARD:-all}"
case "$SHARD" in
  a|b|c|all) ;;
  *)
    echo "ENCODE PROOF GATE: FAIL -- unknown SHARD='$SHARD' (must be a, b, c, or all)" >&2
    exit 1
    ;;
esac

# #101 completeness guard -- fail-closed in EVERY mode, BEFORE any proof runs:
# the shard lists must be disjoint, exhaustive, and in lockstep with the
# '#[kani::proof]' count in proofs.rs.
shards_assert_complete

# Select the harness set, its pinned count, and its DoD marker. Shard modes
# pass every shard harness as `--harness <fully-qualified-name>` with
# `--exact` (exact matching -- cargo-kani's default filter is SUBSTRING
# matching, which could silently over-match a prefix-named sibling harness,
# e.g. kani_kan_envelope_no_widening also matches ..._m24). `--exact`
# requires the fully-qualified path: every tb-encode harness lives flat in
# the `proofs` module (verified via `cargo kani list`), so the module prefix
# is pinned ONCE here; if proofs.rs ever re-modularizes, the shard run match
# fails and the SUCCESSFUL count mismatch fails the gate closed.
HARNESS_PATH_PREFIX="proofs::"
KANI_ARGS=()
case "$SHARD" in
  all)
    EXPECTED="$EXPECTED_HARNESSES_TOTAL"
    MARKER="V1: kani-encoders OK"
    ;;
  a)
    EXPECTED="${#SHARD_A[@]}"
    MARKER="V1-shard-a: kani-encoders OK"
    KANI_ARGS+=(--exact)
    for h in "${SHARD_A[@]}"; do KANI_ARGS+=(--harness "${HARNESS_PATH_PREFIX}${h}"); done
    ;;
  b)
    EXPECTED="${#SHARD_B[@]}"
    MARKER="V1-shard-b: kani-encoders OK"
    KANI_ARGS+=(--exact)
    for h in "${SHARD_B[@]}"; do KANI_ARGS+=(--harness "${HARNESS_PATH_PREFIX}${h}"); done
    ;;
  c)
    EXPECTED="${#SHARD_C[@]}"
    MARKER="V1-shard-c: kani-encoders OK"
    KANI_ARGS+=(--exact)
    for h in "${SHARD_C[@]}"; do KANI_ARGS+=(--harness "${HARNESS_PATH_PREFIX}${h}"); done
    ;;
esac

echo "==> Running Kani over tb-encode (SHARD=$SHARD, expecting $EXPECTED harnesses) ..."
# Capture both streams; --output-format=terse prints one VERIFICATION line per
# harness. `|| true` so a non-zero Kani exit (a real proof failure) is handled by
# the explicit checks below rather than aborting under `set -e`.
OUT="$(cargo kani -p tb-encode --output-format=terse ${KANI_ARGS[@]+"${KANI_ARGS[@]}"} 2>&1 || true)"
printf '%s\n' "$OUT"

FAILED="$(printf '%s\n' "$OUT" | grep -c 'VERIFICATION:- FAILED' || true)"
SUCCEEDED="$(printf '%s\n' "$OUT" | grep -c 'VERIFICATION:- SUCCESSFUL' || true)"

if [ "$FAILED" -ne 0 ]; then
  echo "ENCODE PROOF GATE: FAIL -- $FAILED harness(es) reported VERIFICATION:- FAILED (SHARD=$SHARD)" >&2
  exit 1
fi

if [ "$SUCCEEDED" -ne "$EXPECTED" ]; then
  echo "ENCODE PROOF GATE: FAIL -- expected $EXPECTED successful harnesses for SHARD=$SHARD, saw $SUCCEEDED (regression / tamper / build error)" >&2
  exit 1
fi

echo "$MARKER"
exit 0
