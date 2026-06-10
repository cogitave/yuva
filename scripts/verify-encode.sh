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
# correctness).
# Bump this in LOCKSTEP when adding/removing a harness; any mismatch fails the gate.
EXPECTED_HARNESSES=28

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
