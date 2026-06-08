#!/usr/bin/env bash
# scripts/bench-boot.sh — TABOS boot-time benchmark harness.
#
# Measures the wall-clock from "VMM/QEMU process spawn" to two serial events,
# the same start->end convention microVM/unikernel boot-time figures use
# (cf. the Firecracker NSDI'20 "time to first userspace work" methodology):
#
#   * t_first  = spawn -> the FIRST guest serial byte ("hello from rust_main").
#                This is the purest BOOT time: VMM init + kernel entry + M0
#                serial bring-up. The closest apples-to-apples vs other kernels'
#                "boot to first output".
#   * t_full   = spawn -> the final cumulative milestone marker ("M7: heap OK").
#                This is boot + the WHOLE M0..latest self-test (incl. M2's
#                1000-round cooperative ping-pong), so it is "boot + self-test",
#                NOT pure boot — reported separately and labelled as such.
#
# As soon as the final marker is seen the guest is killed (no waiting on the
# halt), so N iterations are fast. Accel is auto: KVM when /dev/kvm is usable
# (the representative number), else pure-TCG (a portable upper bound; emulated,
# so several x slower — do NOT compare TCG numbers against other systems' KVM).
#
# Usage:   scripts/bench-boot.sh <x86_64|aarch64> [path/to/kernel-elf]
# Env:     ITER=<n> (default 10)  BENCH_TIMEOUT=<secs> (per-iter cap, default 20)
#          QEMU=...  FORCE_ACCEL=kvm|tcg
# Output:  a human summary on stderr; a machine-readable JSON line on stdout.
set -euo pipefail

ARCH="${1:-x86_64}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ITER="${ITER:-10}"
BENCH_TIMEOUT="${BENCH_TIMEOUT:-20}"
FIRST_MARKER="hello from rust_main"
FINAL_MARKER="M7: heap OK"

case "${ARCH}" in
  x86_64)
    KERNEL="${2:-${REPO_ROOT}/target/x86_64-tabos-none/debug/tabos-kernel}"
    QEMU="${QEMU:-qemu-system-x86_64}"
    ;;
  aarch64)
    KERNEL="${2:-${REPO_ROOT}/target/aarch64-tabos-none/debug/tabos-kernel}"
    QEMU="${QEMU:-qemu-system-aarch64}"
    ;;
  *) echo "usage: bench-boot.sh <x86_64|aarch64> [kernel]" >&2; exit 2 ;;
esac

command -v "${QEMU}" >/dev/null 2>&1 || { echo "error: ${QEMU} not on PATH" >&2; exit 2; }
[[ -f "${KERNEL}" ]] || { echo "error: kernel not found: ${KERNEL} (build with: cargo kbuild --target targets/${ARCH}-tabos-none.json)" >&2; exit 2; }

# Accel selection.
ACCEL="tcg"; CPU_X86="qemu64"
if [[ "${FORCE_ACCEL:-}" == "kvm" || ( -z "${FORCE_ACCEL:-}" && -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ) ]]; then
  ACCEL="kvm"; CPU_X86="host"
fi
[[ "${FORCE_ACCEL:-}" == "tcg" ]] && { ACCEL="tcg"; CPU_X86="qemu64"; }

# Build the per-arch QEMU argv (matching scripts/run-<arch>.sh exactly).
qemu_argv() {
  if [[ "${ARCH}" == "x86_64" ]]; then
    printf '%s\0' "${QEMU}" -M microvm,rtc=off -accel "${ACCEL}" -cpu "${CPU_X86}" \
      -m 256M -smp 1 -kernel "${KERNEL}" -no-reboot -nic none -serial stdio -display none
  else
    # aarch64 'virt': -nographic IS the serial-on-stdio path; KVM only on arm hosts.
    local acc="tcg"; [[ "${ACCEL}" == "kvm" ]] && acc="kvm"
    printf '%s\0' "${QEMU}" -M virt -accel "${acc}" -cpu cortex-a72 -m 128M \
      -nographic -no-reboot -nic none -kernel "${KERNEL}"
  fi
}

# Run ONE boot, print "<first_ms> <full_ms>" (or "NA NA" on miss).
one_run() {
  local -a argv; mapfile -d '' -t argv < <(qemu_argv)
  local t0 first_ts="" full_ts=""
  t0="$(date +%s.%N)"
  coproc QPROC { exec "${argv[@]}" 2>&1; }
  local qpid="${QPROC_PID}"
  ( sleep "${BENCH_TIMEOUT}"; kill "${qpid}" 2>/dev/null ) & local watch=$!
  local line ts
  while IFS= read -r line <&"${QPROC[0]}"; do
    ts="$(date +%s.%N)"
    [[ -z "${first_ts}" && "${line}" == *"${FIRST_MARKER}"* ]] && first_ts="${ts}"
    if [[ "${line}" == *"${FINAL_MARKER}"* ]]; then full_ts="${ts}"; break; fi
  done
  kill "${qpid}" 2>/dev/null || true
  kill "${watch}" 2>/dev/null || true
  wait "${qpid}" 2>/dev/null || true
  awk -v t0="${t0}" -v f="${first_ts:-NA}" -v g="${full_ts:-NA}" 'BEGIN{
    if (f=="NA") printf "NA "; else printf "%.3f ", (f-t0)*1000;
    if (g=="NA") printf "NA\n"; else printf "%.3f\n", (g-t0)*1000;
  }'
}

# median of stdin numbers
stat_of() { sort -n | awk '{a[NR]=$1} END{ if(NR==0){print "NA";exit} m=(NR%2)?a[(NR+1)/2]:(a[NR/2]+a[NR/2+1])/2; printf "%.3f", m }'; }
min_of()  { sort -n | head -1; }
max_of()  { sort -n | tail -1; }

echo ">> bench: arch=${ARCH} accel=${ACCEL} iters=${ITER} kernel=${KERNEL}" >&2
firsts=(); fulls=()
for ((i=1;i<=ITER;i++)); do
  read -r f g < <(one_run)
  [[ "${f}" != "NA" ]] && firsts+=("${f}")
  [[ "${g}" != "NA" ]] && fulls+=("${g}")
  printf '   iter %2d/%d: first=%-9s full=%-9s ms\n' "${i}" "${ITER}" "${f}" "${g}" >&2
done

fmin=$(printf '%s\n' "${firsts[@]:-NA}" | min_of); fmed=$(printf '%s\n' "${firsts[@]:-}" | stat_of); fmax=$(printf '%s\n' "${firsts[@]:-NA}" | max_of)
gmin=$(printf '%s\n' "${fulls[@]:-NA}"  | min_of); gmed=$(printf '%s\n' "${fulls[@]:-}"  | stat_of); gmax=$(printf '%s\n' "${fulls[@]:-NA}" | max_of)

{
  echo ">> RESULT (ms), n_first=${#firsts[@]} n_full=${#fulls[@]}"
  echo "   boot-to-first-output ('${FIRST_MARKER}'):  min=${fmin} median=${fmed} max=${fmax}"
  echo "   boot+selftest        ('${FINAL_MARKER}'):  min=${gmin} median=${gmed} max=${gmax}"
  [[ "${ACCEL}" == "tcg" ]] && echo "   NOTE: TCG (emulated) — several x slower than KVM; use the CI KVM run for cross-system claims."
} >&2

printf '{"arch":"%s","accel":"%s","iters":%d,"boot_first_ms":{"min":%s,"median":%s,"max":%s},"boot_full_ms":{"min":%s,"median":%s,"max":%s}}\n' \
  "${ARCH}" "${ACCEL}" "${ITER}" "${fmin}" "${fmed}" "${fmax}" "${gmin}" "${gmed}" "${gmax}"
