#!/usr/bin/env bash
# Yuva-ABI stage A -- the conformance lane (DoD-4).
#
# The POSITIVE agent-agnostic demonstration: boot the kernel and assert the
# in-kernel mini-agent (a conformant agent sharing NO code with the resident
# agent's M12/M38 runtime) passed the FROZEN conformance vectors across BOTH
# planes. The witness is emitted right after `M11: caps OK` -- BEFORE M12/M19/
# M20/M30 -- so this is a LEAN, OFFLINE, DETERMINISTIC boot: no host echo peer,
# no network, no disk-replay dependency, no human, no hardware. It captures the
# serial stream, adjudicates the conformance witness, and prints the additional
# lane's SUMMARY marker `ABI: conformance OK planes=2 vectors=K`.
#
# The marker is emitted ONLY here (the lane summary), never on the required
# cumulative M0..M38 chain -- no run-*.sh verifier greps `abi-conformance:` or
# `ABI: conformance`. A skip-form, an absent witness, `all-pass != 0x1`, or a
# single-plane pass FAILS the lane BY NAME (honest-skip-is-failure).
#
# Usage: scripts/run-abi-conformance.sh [KERNEL_ELF]
#   (defaults to the debug x86_64 kernel image; build it with
#    `cargo kbuild --target targets/x86_64-yuva-none.json` first.)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/project.env
. "${REPO_ROOT}/scripts/project.env"

TARGET="${TARGET_X86}"
PROFILE="${PROFILE:-debug}"
KERNEL="${1:-${REPO_ROOT}/target/${TARGET}/${PROFILE}/${KERNEL_BIN}}"
QEMU="${QEMU:-qemu-system-x86_64}"
TIMEOUT_SECS="${TIMEOUT_SECS:-45}"

if ! command -v "${QEMU}" >/dev/null 2>&1; then
  echo ">> FAIL: ${QEMU} not found on PATH" >&2
  exit 1
fi
if [[ ! -f "${KERNEL}" ]]; then
  echo ">> FAIL: kernel image not found: ${KERNEL}" >&2
  echo "   build it: cargo kbuild --target ${REPO_ROOT}/targets/${TARGET}.json" >&2
  exit 1
fi

# TCG unless the runner exposes KVM (offline + deterministic either way).
ACCEL="tcg"
CPU="qemu64"
if [[ -r /dev/kvm && -w /dev/kvm ]]; then ACCEL="kvm"; CPU="host"; fi

IMG="$(mktemp)"                 # a scratch (empty) disk so M20 has a device shape
dd if=/dev/zero of="${IMG}" bs=1M count=8 status=none
INT_LOG="$(mktemp)"
cleanup() { rm -f "${IMG}" "${INT_LOG}"; }
trap cleanup EXIT

# A LEAN boot: rng + a scratch disk, serial to stdout, NO virtconsole/chardev
# (the M30 host-peer wiring is irrelevant to the pre-M30 conformance witness),
# NO nic (offline). Timeout-bounded; the guest is expected to keep booting past
# the witness, so we do not wait for a clean exit -- we grep what it emitted.
set +e
OUTPUT="$(timeout --foreground "${TIMEOUT_SECS}" \
  "${QEMU}" \
    -M microvm,rtc=off \
    -accel "${ACCEL}" -cpu "${CPU}" -m 256M -smp 1 \
    -kernel "${KERNEL}" \
    -d int -D "${INT_LOG}" \
    -no-reboot \
    -nic none \
    -global virtio-mmio.force-legacy=false \
    -device virtio-rng-device \
    -drive file="${IMG}",if=none,format=raw,id=vblk0 \
    -device virtio-blk-device,drive=vblk0 \
    -serial stdio -display none 2>&1)"
set -e

printf '%s\n' "${OUTPUT}"

# The abi: version LABEL must be present (planes=2), and NO abi: FAIL (a registry
# drift fail-exits and never reaches conformance).
if printf '%s' "${OUTPUT}" | grep -qE -- '^abi: FAIL'; then
  echo ">> FAIL: abi: FAIL (registry drift) on the boot wire -- the frozen registry does not match the live seam" >&2
  exit 1
fi
if ! printf '%s' "${OUTPUT}" | grep -qE -- '^abi: cap-plane=[0-9]+\.[0-9]+ .*selfcheck=0x1'; then
  echo ">> FAIL: the abi: version witness (cap-plane=.. selfcheck=0x1) was not seen" >&2
  exit 1
fi

# The conformance witness: BOTH planes, all-pass, and a NON-ZERO negative-vector
# count (the relaxed-admission catcher must have actually run and been Denied).
WITNESS="$(printf '%s' "${OUTPUT}" | grep -E -- '^abi-conformance: ' | head -1 || true)"
if [[ -z "${WITNESS}" ]]; then
  echo ">> FAIL: no 'abi-conformance:' witness on the boot wire (the mini-agent did not run -- honest-skip-is-failure)" >&2
  exit 1
fi
if ! printf '%s' "${WITNESS}" | grep -qE -- 'planes=0x0*2 .* all-pass=0x0*1 '; then
  echo ">> FAIL: the conformance witness is not planes=0x2 all-pass=0x1 (a plane failed or a vector did not pass):" >&2
  echo "   ${WITNESS}" >&2
  exit 1
fi
if ! printf '%s' "${WITNESS}" | grep -qE -- ' wire=0x0*1 conductor=0x0*1 '; then
  echo ">> FAIL: a single-plane pass -- wire and conductor (Plane 2) must both be 0x1:" >&2
  echo "   ${WITNESS}" >&2
  exit 1
fi
CAP_NEG="$(printf '%s' "${WITNESS}" | grep -oE 'cap-neg-denied=0x[0-9a-f]+' | grep -oE '0x[0-9a-f]+')"
if [[ "$((CAP_NEG))" -lt 1 ]]; then
  echo ">> FAIL: cap-neg-denied=${CAP_NEG} -- no NEGATIVE (Denied) capability vector was exercised (the relaxed-admission catcher did not run)" >&2
  exit 1
fi

# Derive K (the total vector count) from the witness for the summary marker.
VEC_HEX="$(printf '%s' "${WITNESS}" | grep -oE 'vectors=0x[0-9a-f]+' | grep -oE '0x[0-9a-f]+')"
K="$((VEC_HEX))"

echo "ABI: conformance OK planes=2 vectors=${K}"
exit 0
