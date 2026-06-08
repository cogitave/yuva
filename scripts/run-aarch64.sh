#!/usr/bin/env bash
# scripts/run-aarch64.sh -- QEMU `virt` runner (milestone M10: per-agent address spaces).
#
# Boots the aarch64 tb-os image under QEMU, captures the PL011 serial stream,
# and asserts the executable Definition-of-Done marker "M10: addrspace OK" (each
# schedulable entity runs in its own top-level page table -- memory isolation --
# while the kernel half stays mapped and the switch folds into the M9 context
# switch). M0's hello, M1's trap round-trip, M2's ping-pong, "M3: mmu OK",
# "M4: user/ring OK", "M5: alloc OK", "M6: frame alloc OK", "M7: heap OK",
# "M8: timer OK" and "M9: preempt OK" all print earlier in the same boot.
# Doubles as the cargo runner for target aarch64-tabos-none (cargo passes the
# freshly built ELF as $1) and is runnable by hand on WSL2.
#
# Invocation sources:
#   * QEMU `virt` board: UART0 = ARM PL011 @ 0x0900_0000, FDT pointer in x0,
#     `-kernel <ELF>` enters at EL1 (QEMU docs; dtb dumped via -machine dumpdtb).
#   * `-nographic` already routes the serial onto stdio AND muxes the monitor;
#     additionally passing `-serial stdio` makes QEMU abort with
#     "cannot use stdio by multiple character devices", so we deliberately do
#     not pass both -- `-nographic` *is* the requested serial-on-stdio path.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${PROFILE:-debug}"
KERNEL="${1:-${REPO_ROOT}/target/aarch64-tabos-none/${PROFILE}/tabos-kernel}"
QEMU="${QEMU_AARCH64:-qemu-system-aarch64}"
MARKER="L2.0: vmxroot OK"
TIMEOUT_SECS="${QEMU_TIMEOUT:-15}"

if ! command -v "${QEMU}" >/dev/null 2>&1; then
    echo "[run-aarch64] error: '${QEMU}' not found on PATH" >&2
    exit 127
fi

# -M virt          : QEMU AArch64 'virt' machine (PL011 @ 0x09000000, GICv2, FDT)
# -cpu cortex-a72  : real A72; guest entry = EL1h, MMU off, DAIF masked, x0=FDT
# -m 128M          : virt RAM = 0x4000_0000..0x4800_0000; image links at +512 KiB
# -nographic       : headless; PL011 -> this terminal's stdio (see note above)
# -no-reboot       : do not loop on a fatal guest event
# -kernel <ELF>    : load PT_LOADs at p_paddr, jump to e_entry (= _start)
set +e
OUTPUT="$(timeout --foreground "${TIMEOUT_SECS}" \
    "${QEMU}" \
        -M virt \
        -cpu cortex-a72 \
        -m 128M \
        -nographic \
        -no-reboot \
        -nic none \
        -kernel "${KERNEL}" \
    < /dev/null 2>&1)"
QEMU_RC=$?
set -e

printf '%s\n' "${OUTPUT}"

if printf '%s' "${OUTPUT}" | grep -qF -- "${MARKER}"; then
    # M14.2: explicit second assertion for the blocking-recv sub-marker (the
    # final marker already transitively gates it; this is direct traceability).
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M14.2: blocking-recv OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'M14.2: blocking-recv OK' missing" >&2
        exit 1
    fi
    echo "[run-aarch64] PASS -- observed DoD marker: '${MARKER}' (and 'M14.2: blocking-recv OK')"
    exit 0
fi

echo "[run-aarch64] FAIL -- marker '${MARKER}' not seen" >&2
echo "[run-aarch64]   (qemu exit=${QEMU_RC}; the kernel halts in wfi, so a" >&2
echo "[run-aarch64]    ${TIMEOUT_SECS}s timeout/exit=124 is expected -- the grep is the verdict)" >&2
exit 1
