#!/usr/bin/env bash
# scripts/run-x86_64.sh - QEMU launcher + Definition-of-Done check for M10 (x86_64).
#
# Boots the PVH ELF kernel under QEMU 'microvm' (the machine type Firecracker is
# modelled on), wires legacy 16550 COM1 to stdio, and asserts the EXACT marker
# "M10: addrspace OK" appears on serial (the newest cumulative-boot milestone;
# each schedulable entity runs in its own top-level page table -- one cannot
# read/write another's private memory -- while the kernel half stays mapped, and
# the address-space switch folds into the M9 context switch). M0's hello, M1's
# trap round-trip, M2's ping-pong, "M3: mmu OK", "M4: user/ring OK",
# "M5: alloc OK", "M6: frame alloc OK", "M7: heap OK", "M8: timer OK" and
# "M9: preempt OK" all print earlier in the same boot, so one run proves every
# milestone. Fail-closed:
# a wall-clock timeout bounds the run (the kernel halts rather than exiting), and
# a missing marker is a non-zero exit.
#
# PVH is selected automatically by QEMU from the XEN_ELFNOTE_PHYS32_ENTRY note
# in the ELF (see crates/tb-hal/src/arch/x86_64/boot.rs + kernel/linker/x86_64.ld).
#   refs: https://xenbits.xen.org/docs/unstable/misc/pvh.html
#         https://www.qemu.org/docs/master/system/i386/microvm.html
#
# Usage:   scripts/run-x86_64.sh [path/to/kernel-elf]
# Env:     QEMU=...  QEMU_TIMEOUT=<secs>  PROFILE=debug|release
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="x86_64-tabos-none"
PROFILE="${PROFILE:-debug}"
KERNEL="${1:-${REPO_ROOT}/target/${TARGET}/${PROFILE}/tabos-kernel}"
MARKER='M19: virtio OK'
TIMEOUT_SECS="${QEMU_TIMEOUT:-15}"
QEMU="${QEMU:-qemu-system-x86_64}"

if ! command -v "${QEMU}" >/dev/null 2>&1; then
  echo "error: ${QEMU} not found on PATH (install qemu-system-x86 in WSL2)" >&2
  exit 2
fi
if [[ ! -f "${KERNEL}" ]]; then
  echo "error: kernel image not found: ${KERNEL}" >&2
  echo "build it first, e.g.:" >&2
  echo "  cargo kbuild --target ${REPO_ROOT}/targets/${TARGET}.json" >&2
  exit 2
fi

# Prefer KVM only when /dev/kvm is actually usable; otherwise pure-TCG so this
# runs in any WSL2 / CI box without nested virt.
ACCEL="tcg"
CPU="qemu64"
if [[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
  ACCEL="kvm"
  CPU="host"
fi

echo ">> qemu=${QEMU} accel=${ACCEL} cpu=${CPU} timeout=${TIMEOUT_SECS}s" >&2
echo ">> kernel=${KERNEL}" >&2

set +e
OUTPUT="$(timeout --foreground "${TIMEOUT_SECS}" \
  "${QEMU}" \
    -M microvm,rtc=off \
    -accel "${ACCEL}" -cpu "${CPU}" -m 256M -smp 1 \
    -kernel "${KERNEL}" \
    -no-reboot \
    -nic none \
    -global virtio-mmio.force-legacy=false \
    -device virtio-rng-device \
    -serial stdio -display none 2>&1)"
RC=$?
set -e

printf '%s\n' "${OUTPUT}"

if printf '%s' "${OUTPUT}" | grep -qF -- "${MARKER}"; then
  # M14.2: an explicit second assertion for the blocking-recv sub-marker (the
  # final marker already transitively gates it -- a failed self-test halts before
  # L2.0 -- but this makes the traceability direct and fail-closed.)
  if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M14.2: blocking-recv OK'; then
    echo ">> FAIL: final marker present but 'M14.2: blocking-recv OK' missing" >&2
    exit 1
  fi
  echo ">> PASS: observed marker '${MARKER}' (and 'M14.2: blocking-recv OK')" >&2
  exit 0
fi

echo ">> FAIL: marker '${MARKER}' not seen (qemu/timeout rc=${RC})" >&2
exit 1
