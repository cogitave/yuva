#!/usr/bin/env bash
# M11 proof gate -- machine-check the capability rights-subset / no-confused-deputy
# invariant with Kani over the host-verifiable `tb-caps-core` crate, FAIL CLOSED.
#
# Emits the DoD marker `M11: caps-subset PROVEN` and exits 0 ONLY when:
#   * ZERO harnesses report `VERIFICATION:- FAILED`, AND
#   * the count of `VERIFICATION:- SUCCESSFUL` EXACTLY equals the pinned
#     EXPECTED_HARNESSES (so a silently deleted / renamed / vacuous harness can
#     never let the gate pass -- the marker is tamper-evident).
#
# Run by .github/workflows/kani.yml AFTER the model-checking/kani-github-action
# step has installed Kani's own pinned toolchain (so `cargo kani` is on PATH).
# Kani is NOT invoked through the `kbuild` alias, so -Zbuild-std never
# contaminates this host verification.
set -euo pipefail

# The exact number of `#[kani::proof]` harnesses in
# crates/tb-caps-core/src/proofs.rs (Tier-1 x5 + Tier-2 x5 + Tier-3 x2). Bump
# this in LOCKSTEP when adding/removing a harness; any mismatch fails the gate.
EXPECTED_HARNESSES=12

echo "==> Running Kani over tb-caps-core ..."
# Capture both streams; --output-format=terse prints one VERIFICATION line per
# harness. `|| true` so a non-zero Kani exit (a real proof failure) is handled by
# the explicit checks below rather than aborting under `set -e`.
OUT="$(cargo kani -p tb-caps-core --output-format=terse 2>&1 || true)"
printf '%s\n' "$OUT"

FAILED="$(printf '%s\n' "$OUT" | grep -c 'VERIFICATION:- FAILED' || true)"
SUCCEEDED="$(printf '%s\n' "$OUT" | grep -c 'VERIFICATION:- SUCCESSFUL' || true)"

if [ "$FAILED" -ne 0 ]; then
  echo "M11 PROOF GATE: FAIL -- $FAILED harness(es) reported VERIFICATION:- FAILED" >&2
  exit 1
fi

if [ "$SUCCEEDED" -ne "$EXPECTED_HARNESSES" ]; then
  echo "M11 PROOF GATE: FAIL -- expected $EXPECTED_HARNESSES successful harnesses, saw $SUCCEEDED (regression / tamper / build error)" >&2
  exit 1
fi

echo "M11: caps-subset PROVEN"
exit 0
