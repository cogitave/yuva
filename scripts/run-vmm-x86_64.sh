#!/usr/bin/env bash
# scripts/run-vmm-x86_64.sh — tb-vmm Definition-of-Done check (L1, x86_64).
#
# Boots the SAME kernel ELF the QEMU/PVH path boots, but through tb-vmm + the
# tb-boot v0 contract (direct 64-bit long mode, NO PVH note, NO A0 trampoline),
# and asserts the exact marker "M4: user/ring OK" on the guest serial console.
# Requires a usable /dev/kvm; if absent it SKIPS (exit 0) with a clear message.
#
# Usage:   scripts/run-vmm-x86_64.sh [path/to/kernel-elf]
# Env:     PROFILE=debug|release   VMM_TIMEOUT=<secs>
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="x86_64-tabos-none"
PROFILE="${PROFILE:-debug}"
KERNEL="${1:-${REPO_ROOT}/target/${TARGET}/${PROFILE}/tabos-kernel}"
MARKER='M4: user/ring OK'
TIMEOUT_SECS="${VMM_TIMEOUT:-30}"

if [[ ! -e /dev/kvm ]]; then
  echo ">> SKIP: /dev/kvm not present (tb-vmm requires hardware KVM)" >&2
  exit 0
fi
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  echo ">> /dev/kvm not accessible; attempting 'sudo chmod 666 /dev/kvm'" >&2
  sudo chmod 666 /dev/kvm 2>/dev/null || {
    echo ">> SKIP: cannot gain access to /dev/kvm" >&2
    exit 0
  }
fi
if [[ ! -f "${KERNEL}" ]]; then
  echo "error: kernel image not found: ${KERNEL}" >&2
  echo "build it first: cargo kbuild --target targets/${TARGET}.json" >&2
  exit 2
fi

echo ">> building tb-vmm (host, release)" >&2
( cd "${REPO_ROOT}/tb-vmm" && cargo build --release )
TBVMM="${REPO_ROOT}/tb-vmm/target/release/tb-vmm"

echo ">> tb-vmm=${TBVMM}" >&2
echo ">> kernel=${KERNEL} timeout=${TIMEOUT_SECS}s" >&2

set +e
OUTPUT="$(timeout --foreground "${TIMEOUT_SECS}" \
  "${TBVMM}" --kernel "${KERNEL}" --print-exit --timeout-secs "${TIMEOUT_SECS}" 2>&1)"
RC=$?
set -e

printf '%s\n' "${OUTPUT}"

if printf '%s' "${OUTPUT}" | grep -qF -- "${MARKER}"; then
  echo ">> PASS: tb-vmm booted the kernel via tb-boot v0 (no PVH) and reached '${MARKER}'" >&2
  exit 0
fi

echo ">> FAIL: marker '${MARKER}' not seen (tb-vmm/timeout rc=${RC})" >&2
exit 1
