#!/usr/bin/env bash
# scripts/demo.sh — interactive Yuva boot: WATCH the machine come up.
#
# This is a VIEWER, not a verifier: it boots the kernel under QEMU with the
# full device set (virtio-rng + virtio-blk + the M30/M31 inference channel with a
# live host-side xport-harness peer) and puts the serial console on YOUR
# terminal so you can watch the whole M0..M31 + L2.0..L2.6 marker chain print
# in real time. It asserts NOTHING — the fail-closed verifiers with the
# anti-hollow guard blocks are scripts/run-aarch64.sh and run-x86_64.sh; CI
# runs those, not this.
#
# Yuva is a Firecracker-class DIRECT-KERNEL-BOOT guest: there is no .iso, no
# bootloader, no installer — the hypervisor (QEMU here, tb-vmm/KVM on the vmm
# lane) loads the kernel image straight into guest RAM and jumps to it. That
# is the design, not a gap (see docs/TRY-IT.md).
#
# Usage:   scripts/demo.sh [aarch64|x86_64]     (default: aarch64 — the
#          fullest chain: EL2 world-switch, stage-2, vGIC, SMMU, the M27
#          CNTHP-preempted two-VMID scheduler)
# Exit:    aarch64 exits by itself when the chain completes (semihosting);
#          x86_64 halts at the end — press Ctrl-A then X to leave QEMU.
set -euo pipefail

# `wsl -- bash script.sh` is a NON-login shell, so ~/.cargo/env is never sourced
# and cargo/rustup are off PATH. Add the standard rustup bin dir (+ source the
# env if present) so the demo works straight from `wsl -d ... bash scripts/demo.sh`.
[[ -f "${HOME}/.cargo/env" ]] && source "${HOME}/.cargo/env"
case ":${PATH}:" in *":${HOME}/.cargo/bin:"*) :;; *) PATH="${HOME}/.cargo/bin:${PATH}";; esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Build identifiers (KERNEL_BIN, TARGET_X86, TARGET_A64) — the single source of truth.
. "${REPO_ROOT}/scripts/project.env"

# Industrial Boot (#106): by DEFAULT this VIEWER shows the clean, human-meaningful
# systemd-style boot (`yuva.console=pretty`, x86 PVH `-append`). `--verbose`/`--raw`
# shows the raw developer marker stream instead (today's exact `Mxx: … OK` chain).
# `--substrate` renders the Firecracker-alt minimal (micro-VMM only) view. The
# pretty knob is wired on x86 only at stage A; the re-entrant aarch64 EL1 guest is
# unconditionally raw and the aarch64-host `/chosen/bootargs` knob is a follow-up,
# so an aarch64 demo shows the raw stream with a note.
CONSOLE="pretty"
VIEW="cogi"
ARCH=""
for a in "$@"; do
  case "$a" in
    --verbose|--raw|-v)  CONSOLE="raw" ;;
    --pretty)            CONSOLE="pretty" ;;
    --substrate)         VIEW="substrate" ;;
    --cogi)              VIEW="cogi" ;;
    aarch64|x86_64)      ARCH="$a" ;;
    *) echo "usage: scripts/demo.sh [aarch64|x86_64] [--verbose|--raw] [--substrate]" >&2; exit 2 ;;
  esac
done
ARCH="${ARCH:-aarch64}"
PROFILE="${PROFILE:-debug}"

case "${ARCH}" in
  aarch64) TARGET="${TARGET_A64}"; QEMU="${QEMU:-qemu-system-aarch64}";;
  x86_64)  TARGET="${TARGET_X86}"; QEMU="${QEMU:-qemu-system-x86_64}";;
  *) echo "usage: scripts/demo.sh [aarch64|x86_64]" >&2; exit 2;;
esac
KERNEL="${REPO_ROOT}/target/${TARGET}/${PROFILE}/${KERNEL_BIN}"

if ! command -v "${QEMU}" >/dev/null 2>&1; then
  echo "error: ${QEMU} not found (in WSL: sudo apt-get install qemu-system-x86 qemu-system-arm)" >&2
  exit 2
fi

# ALWAYS (re)build: cargo is incremental, so an up-to-date tree costs seconds —
# while a stale leftover binary silently replays YESTERDAY'S chain (learned the
# hard way: the first operator demo showed an M28-era kernel from an old
# target/, missing M27b/M29/M30 entirely — convincingly real, silently dated).
echo "[demo] cargo kbuild (${ARCH}) — incremental, seconds when fresh…" >&2
( cd "${REPO_ROOT}" && cargo kbuild --target "targets/${TARGET}.json" )

# Fresh throwaway disk for the M20 durable-persistence rung (auto-removed).
IMG="$(mktemp)"; truncate -s 4M "${IMG}"
# The M30/M31 inference channel: a unix-socket chardev + the host-side harness
# (whose serve loop also answers the M31 MAC-chunked mock inference exchange)
# peer holding a per-run key (so the REAL host-keyed echo runs, not the skip).
XSOCK="$(mktemp -u)"; XHOUT="$(mktemp)"; XKEY="$(mktemp)"
trap 'rm -f "${IMG}" "${XSOCK}" "${XHOUT}" "${XKEY}"' EXIT

HARNESS_BIN="${REPO_ROOT}/tools/xport-harness/target/release/xport-harness"
HARNESS_ARGS=()
if [[ -x "${HARNESS_BIN}" ]] || ( command -v cargo >/dev/null 2>&1 && \
     ( cd "${REPO_ROOT}/tools/xport-harness" && cargo build --release >&2 ) ); then
  "${HARNESS_BIN}" --socket "${XSOCK}" --key-out "${XKEY}" --timeout-secs 300 \
      > "${XHOUT}" 2>&1 &
  HARNESS_ARGS=( -chardev "socket,id=xport0,path=${XSOCK},server=on,wait=off"
                 -device virtio-serial-device -device "virtconsole,chardev=xport0" )
  echo "[demo] xport-harness peer running (host-custodied per-run key)" >&2
else
  echo "[demo] no cargo/harness — the M30 line will print its loud '(no host peer, skipped)'" >&2
fi

# Industrial Boot (#106): assemble the `yuva.console=`/`yuva.view=` cmdline. On
# x86 it rides the PVH `-append`. On aarch64 the host knob is a named follow-up
# (and the EL1 guest has no cmdline channel), so a pretty request there prints a
# note and shows the raw stream.
APPEND="yuva.console=${CONSOLE} yuva.view=${VIEW}"
if [[ "${CONSOLE}" == "pretty" ]]; then
  echo "[demo] presentation: clean industrial boot (${VIEW} view). Use --verbose for the raw developer markers." >&2
else
  echo "[demo] presentation: raw developer marker stream (Mxx: … OK chain)." >&2
fi
if [[ "${ARCH}" == "aarch64" && "${CONSOLE}" == "pretty" ]]; then
  echo "[demo] NOTE: the aarch64-host pretty knob is a follow-up (proposal §10); showing the raw stream. Run 'scripts/demo.sh x86_64' for the pretty industrial boot." >&2
fi

echo "[demo] booting Yuva (${ARCH}) — serial console below. Ctrl-A X quits QEMU." >&2
echo "------------------------------------------------------------------------" >&2

if [[ "${ARCH}" == "aarch64" ]]; then
  # aarch64: no wired cmdline console knob yet -> raw regardless (guest always raw).
  exec "${QEMU}" \
    -M virt,virtualization=on,gic-version=2,iommu=smmuv3 \
    -cpu cortex-a72 -m 128M -accel tcg,thread=single \
    -nographic -no-reboot -nic none \
    -global virtio-mmio.force-legacy=false \
    -device virtio-rng-device \
    -drive file="${IMG}",if=none,format=raw,id=vblk0 \
    -device virtio-blk-device,drive=vblk0 \
    "${HARNESS_ARGS[@]}" \
    -semihosting \
    -kernel "${KERNEL}"
else
  exec "${QEMU}" \
    -M microvm,rtc=off \
    -accel tcg -cpu qemu64 -m 256M -smp 1 \
    -kernel "${KERNEL}" \
    -append "${APPEND}" \
    -no-reboot -nic none \
    -global virtio-mmio.force-legacy=false \
    -device virtio-rng-device \
    -drive file="${IMG}",if=none,format=raw,id=vblk0 \
    -device virtio-blk-device,drive=vblk0 \
    "${HARNESS_ARGS[@]}" \
    -serial mon:stdio -display none
fi
