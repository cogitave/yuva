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
#     `-kernel <ELF>` enters at EL2 under `virtualization=on` (the L2.0 monitor
#     drops to EL1 for M0..M18) (QEMU docs; dtb dumped via -machine dumpdtb).
#   * `-nographic` already routes the serial onto stdio AND muxes the monitor;
#     additionally passing `-serial stdio` makes QEMU abort with
#     "cannot use stdio by multiple character devices", so we deliberately do
#     not pass both -- `-nographic` *is* the requested serial-on-stdio path.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${PROFILE:-debug}"
KERNEL="${1:-${REPO_ROOT}/target/aarch64-tabos-none/${PROFILE}/tabos-kernel}"
QEMU="${QEMU_AARCH64:-qemu-system-aarch64}"
MARKER="M19: virtio OK"
# DETERMINISM (fix_plan §A.1): the aarch64 lane is PURE TCG and, on a contended
# hosted GitHub runner, TCG can spend ~15s just reaching rust_main before the
# whole M0..M19 chain prints in a fraction of a second and parks in wfi. A tight
# ceiling raced that cold start and produced intermittent rc=124 timeouts where
# the LAST serial line flushed was whatever marker had printed (on two re-runs
# of the aL2.4 branch that happened to be "frame-test: parsing boot memory map",
# which looked like an M6 hang but was a startup-race artifact -- aL2.4 boots to
# M19 deterministically under qemu-6.2 AND qemu-8.2.2 here). Two changes make the
# boot wall-time deterministic so it can NEVER race the ceiling again:
#   * default the ceiling to 90s (CI may still override via QEMU_TIMEOUT);
#   * run TCG single-threaded (-accel tcg,thread=single) so the cold-start cost
#     is stable run-to-run instead of varying with runner core contention.
TIMEOUT_SECS="${QEMU_TIMEOUT:-90}"

if ! command -v "${QEMU}" >/dev/null 2>&1; then
    echo "[run-aarch64] error: '${QEMU}' not found on PATH" >&2
    exit 127
fi

# Print the exact QEMU build FIRST (fix_plan §B): the hosted ubuntu-24.04 runner
# image may ship a different 8.2.x point-release than the apt snapshot tested
# locally, and the version line is the one variable that pins which build a
# future CI log came from. Cheap, always emitted, never gates the verdict.
echo "[run-aarch64] qemu: $(${QEMU} --version | head -1)"

# -M virt,virtualization=on,gic-version=2 : QEMU AArch64 'virt'; virtualization=on
#                    exposes EL2 so the vCPU enters at EL2h (the L2.0 nVHE EL2
#                    monitor installs there, then drops to EL1 for M0..M18);
#                    gic-version=2 pins the GICv2 GICD/GICC MMIO M8 hard-codes.
# -cpu cortex-a72  : real A72 (pure ARMv8.0 -> guaranteed nVHE, E2H RES0). With
#                    virtualization=on, guest entry = EL2h, MMU off, DAIF masked,
#                    x0=FDT; without it the vCPU enters at EL1h (green skip path).
# -m 128M          : virt RAM = 0x4000_0000..0x4800_0000; image links at +512 KiB
# -accel tcg,thread=single : DETERMINISM (fix_plan §A.1). Pin TCG to ONE
#                    translation thread so the cold-start-to-rust_main wall-time
#                    is stable run-to-run on a contended runner (no MTTCG worker
#                    scheduling jitter). The aarch64 guest is single-vCPU anyway,
#                    so this costs no boot throughput; it only removes the timing
#                    variance that let a tight ceiling race the boot and emit a
#                    spurious rc=124 mid-chain. Verified to still reach M19 under
#                    both qemu-6.2 and qemu-8.2.2.
# -nographic       : headless; PL011 -> this terminal's stdio (see note above)
# -no-reboot       : do not loop on a fatal guest event
# -kernel <ELF>    : load PT_LOADs at p_paddr, jump to e_entry (= _start)
set +e
OUTPUT="$(timeout --foreground "${TIMEOUT_SECS}" \
    "${QEMU}" \
        -M virt,virtualization=on,gic-version=2 \
        -cpu cortex-a72 \
        -m 128M \
        -accel tcg,thread=single \
        -nographic \
        -no-reboot \
        -nic none \
        -global virtio-mmio.force-legacy=false \
        -device virtio-rng-device \
        -kernel "${KERNEL}" \
    < /dev/null 2>&1)"
QEMU_RC=$?
set -e

printf '%s\n' "${OUTPUT}"

if printf '%s' "${OUTPUT}" | grep -qF -- "${MARKER}"; then
    # M4: the user/ring (EL0 drop -> svc -> trap-back) proof must print its OK
    # marker, NOT "M4: FAIL". M4 aliases ONE 4 KiB page over the EL0 stub; a stub
    # that straddles a 4 KiB boundary takes an EL0 instruction abort and prints
    # "M4: FAIL esr=0x82...0f" while the boot still parks in wfi at M19 -- so the
    # M19 grep alone would PASS a broken M4. The stub is now `.balign 64`-pinned
    # so it can't straddle, but assert M4 here too so any future layout drift
    # that re-breaks it fails CI loudly instead of silently riding through.
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M4: user/ring OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'M4: user/ring OK' missing (M4 user/ring regressed)" >&2
        exit 1
    fi
    # L2.0: the REAL EL2 world-switch proof must print BEFORE the M19 tail on
    # aarch64 (virtualization=on enters at EL2 and drives the closed round-trip);
    # assert it directly so the el2->virtio order is fail-closed + traceable.
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'L2.0: el2 OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'L2.0: el2 OK' missing" >&2
        exit 1
    fi
    # L2.1: the stage-2 demand-translation proof must ALSO print (the EL2 monitor
    # arms stage-2, the EL1 guest faults the deliberate IPA hole, the monitor
    # demand-maps + ERET-retries, and tears stage-2 down before unwinding). Assert
    # it directly so the el2 -> stage2 -> virtio order is fail-closed + traceable.
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'L2.1: stage2 OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'L2.1: stage2 OK' missing" >&2
        exit 1
    fi
    # L2.2: the EL2 exit-dispatch proof must ALSO print (the EL2 monitor arms the
    # exit window, the guest's WFx traps + resumes, its FP/SIMD access hits the
    # fail-closed inject-UNDEF default, the guest's EL1 vector catches the injected
    # UNDEF, and the window is torn down before unwinding). Assert it directly so
    # the el2 -> stage2 -> el2-exits -> virtio order is fail-closed + traceable.
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'L2.2: el2-exits OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'L2.2: el2-exits OK' missing" >&2
        exit 1
    fi
    # L2.3: the EL2 trap-and-emulate proof must ALSO print (the EL2 monitor arms
    # the trap window, the guest's `msr contextidr_el1` write traps + is emulated,
    # its STR/LDR to the unmapped device IPA trap + route through the device_mmio
    # seam, ELR is advanced past each trapped instruction, and the window is torn
    # down before unwinding). Assert it directly so the el2 -> stage2 -> el2-exits
    # -> el2-trap -> virtio order is fail-closed + traceable.
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'L2.3: el2-trap OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'L2.3: el2-trap OK' missing" >&2
        exit 1
    fi
    # aL2.4: the EL2 nested-guest (GENUINE two-stage) proof must ALSO print (the
    # monitor arms the GiB0+GiB1 identity stage-2, the EL1 guest BUILDS + ENABLES
    # its OWN stage-1 under our stage-2, stores+reads back a sentinel through a VA
    # with no flat meaning -- a genuine VA->IPA->PA two-stage walk -- takes its OWN
    # EL1 brk trap, and the monitor tears stage-2 down + restores the kernel's
    # stage-1 sysregs before unwinding). Assert it directly so the el2 -> stage2 ->
    # el2-exits -> el2-trap -> el2-guest -> virtio order is fail-closed + traceable.
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'L2.4: el2-guest OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'L2.4: el2-guest OK' missing" >&2
        exit 1
    fi
    # aL2.5: the vGIC virtual-interrupt injection + WFI scheduler-hook proof must
    # ALSO print (the monitor arms HCR_EL2.IMO|TWI, the guest enables its GICV
    # CPU interface + parks on WFI, the WFI traps to EL2 where the monitor injects
    # a pending vIRQ via GICH_LR0 and resumes the guest, the guest takes the vIRQ
    # at its EL1 IRQ vector, reads GICV_IAR == the vINTID, sets a sentinel, writes
    # GICV_EOIR, and the monitor confirms the LR retired via GICH_ELRSR0 before
    # tearing the window down). Assert it directly so the el2 -> ... -> el2-guest
    # -> vgic -> virtio order is fail-closed + traceable.
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'L2.5: vgic OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'L2.5: vgic OK' missing" >&2
        exit 1
    fi
    # M14.2: explicit second assertion for the blocking-recv sub-marker (the
    # final marker already transitively gates it; this is direct traceability).
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M14.2: blocking-recv OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'M14.2: blocking-recv OK' missing" >&2
        exit 1
    fi
    echo "[run-aarch64] PASS -- observed DoD marker: '${MARKER}' (and 'L2.0: el2 OK' + 'L2.1: stage2 OK' + 'L2.2: el2-exits OK' + 'L2.3: el2-trap OK' + 'L2.4: el2-guest OK' + 'L2.5: vgic OK' + 'M14.2: blocking-recv OK')"
    exit 0
fi

echo "[run-aarch64] FAIL -- marker '${MARKER}' not seen" >&2
echo "[run-aarch64]   (qemu exit=${QEMU_RC}; the kernel halts in wfi, so a" >&2
echo "[run-aarch64]    ${TIMEOUT_SECS}s timeout/exit=124 is expected -- the grep is the verdict)" >&2
exit 1
