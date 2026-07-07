#!/usr/bin/env bash
# Industrial Boot (#106) — the DoD-1 empty-byte-diff PROOF, run locally against a
# pre-feature baseline. Boots a BASELINE kernel and the INDUSTRIAL-BOOT kernel in
# DEFAULT (raw, no cmdline) mode with identical QEMU args, canonicalizes away the
# per-run entropy, and asserts the two raw streams are byte-identical.
#
# Usage: empty-diff-proof.sh <baseline_repo> <indboot_repo>
set -uo pipefail
BASE="${1:?baseline repo}"
MINE="${2:?indboot repo}"
SED="${MINE}/scripts/lib/canon-serial.sed"
FAIL=0

boot_x86() {
  local kern="$1" out="$2"
  local img; img="$(mktemp)"; truncate -s 4M "$img"
  timeout 25 qemu-system-x86_64 -M microvm,rtc=off -accel tcg -cpu qemu64 -m 256M -smp 1 \
    -kernel "$kern" -no-reboot -nic none \
    -global virtio-mmio.force-legacy=false -device virtio-rng-device \
    -drive file="$img",if=none,format=raw,id=vblk0 -device virtio-blk-device,drive=vblk0 \
    -serial stdio -display none 2>&1 | sed -f "$SED" > "$out"
  rm -f "$img"
}

# The aarch64 GUEST stream: run-aarch64.sh decodes the hex-framed 'guestlog:'
# partition to GUEST_STREAM. We reuse the same decode here: capture the full
# aarch64 serial, extract the guestlog hex, decode, canonicalize.
boot_a64_gueststream() {
  local kern="$1" out="$2"
  local img; img="$(mktemp)"; truncate -s 4M "$img"
  local raw; raw="$(mktemp)"
  # Stage the SAME binary as the EL1 guest via `-device loader` (the exact
  # aL2.4b launch run-aarch64.sh uses), so the re-entrant guest — which has NO
  # cmdline channel and is therefore unconditionally raw — produces its
  # hex-framed 'guestlog:' serial.
  local gbin="${kern}.guest.bin"
  local objcopy; objcopy="$(command -v llvm-objcopy || ls "$(rustc --print sysroot)"/lib/rustlib/*/bin/llvm-objcopy 2>/dev/null | head -1)"
  "$objcopy" -O binary "$kern" "$gbin"
  timeout 90 qemu-system-aarch64 \
    -M virt,virtualization=on,gic-version=2,iommu=smmuv3 \
    -cpu cortex-a72 -m 128M -accel tcg,thread=single -nographic -no-reboot -nic none \
    -global virtio-mmio.force-legacy=false -device virtio-rng-device \
    -drive file="$img",if=none,format=raw,id=vblk0 -device virtio-blk-device,drive=vblk0 \
    -device loader,file="$gbin",addr=0x46080000,force-raw=on \
    -semihosting -kernel "$kern" > "$raw" 2>&1
  # Decode the 'guestlog: <hex>' frames to the guest's own serial bytes.
  grep '^guestlog: ' "$raw" | sed 's/^guestlog: //' | tr -d '\r\n' \
    | xxd -r -p 2>/dev/null | sed -f "$SED" > "$out"
  rm -f "$img" "$raw" "$gbin"
}

echo "== x86_64 HOST stream =="
boot_x86 "${BASE}/target/x86_64-yuva-none/debug/yuva-kernel" /tmp/base_x86.canon
boot_x86 "${MINE}/target/x86_64-yuva-none/debug/yuva-kernel" /tmp/mine_x86.canon
echo "baseline=$(wc -l < /tmp/base_x86.canon) lines  indboot=$(wc -l < /tmp/mine_x86.canon) lines"
if [ ! -s /tmp/base_x86.canon ]; then echo "x86 EMPTY-DIFF: FAIL (baseline capture empty)"; FAIL=1;
elif diff -u /tmp/base_x86.canon /tmp/mine_x86.canon; then echo "x86 EMPTY-DIFF: PASS"; else echo "x86 EMPTY-DIFF: FAIL"; FAIL=1; fi

echo "== aarch64 decoded GUEST stream =="
boot_a64_gueststream "${BASE}/target/aarch64-yuva-none/debug/yuva-kernel" /tmp/base_gs.canon
boot_a64_gueststream "${MINE}/target/aarch64-yuva-none/debug/yuva-kernel" /tmp/mine_gs.canon
echo "baseline=$(wc -l < /tmp/base_gs.canon) lines  indboot=$(wc -l < /tmp/mine_gs.canon) lines"
if [ ! -s /tmp/base_gs.canon ]; then echo "guest EMPTY-DIFF: FAIL (baseline guest capture empty)"; FAIL=1;
elif diff -u /tmp/base_gs.canon /tmp/mine_gs.canon; then echo "guest EMPTY-DIFF: PASS"; else echo "guest EMPTY-DIFF: FAIL"; FAIL=1; fi

echo "== RESULT =="
[ "$FAIL" -eq 0 ] && echo "ALL EMPTY-DIFFS PASS" || echo "SOME EMPTY-DIFF FAILED"
exit "$FAIL"
