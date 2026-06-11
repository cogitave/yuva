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
MARKER="M30: infer-transport OK"
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

# M20: a fresh 4 MiB raw disk per run for the virtio-blk durable-persistence
# round-trip. `mktemp` + `truncate -s 4M` gives a zeroed image (so the first
# mount finds no valid superblock and formats); the `trap` removes it on EXIT so
# the temp never leaks or gets committed. A lane that does NOT attach this disk
# (the kernel scans, finds no DeviceID==2, and renders the green
# "(no disk, skipped)" skip) is unaffected -- this lane proves the REAL path.
IMG="$(mktemp)"

# M30: the HOST-keyed echo peer (the QEMU-chardev-harness lane -- proposal
# §4/§5). QEMU exposes a virtio-console (virtio-serial-device + virtconsole,
# the spike-verified config on BOTH pinned builds: qemu-6.2 local + 8.2.2 CI)
# whose port 0 is a unix-socket chardev; the xport-harness binary CUSTODIES a
# per-run OS-RNG key K + nonce N (K is NEVER in the guest image or on this
# command line -- key=HOST-CUSTODIED-PER-RUN), answers the kernel's ECHO_REQ
# with the khash-transformed echo + the channel-layer K reveal, and prints its
# OWN `xport-harness:` witness to a SEPARATE capture stream. The guard block
# below string-compares the kernel's challenge/tag against the harness's
# (leg 2 -- CROSS-PROCESS equality with a host-custodied key is the loopback
# killer) and negatively asserts K never leaked into the guest serial output.
XSOCK="$(mktemp -u)"  # the chardev unix socket path (QEMU creates the listener)
XHOUT="$(mktemp)"     # the harness's stdout -- the SEPARATE leg-2 capture stream
XKEY="$(mktemp)"      # the harness-custodied key hex (the §5.7 key-leak check input)
trap 'rm -f "$IMG" "$XSOCK" "$XHOUT" "$XKEY"' EXIT
truncate -s 4M "$IMG"

HARNESS_BIN="${REPO_ROOT}/tools/xport-harness/target/release/xport-harness"
if [[ ! -x "${HARNESS_BIN}" ]]; then
  if command -v cargo >/dev/null 2>&1; then
    echo "[run-aarch64] building xport-harness (host, release)" >&2
    ( cd "${REPO_ROOT}/tools/xport-harness" && cargo build --release >&2 )
  else
    # The containerised CI boot has no cargo: the workflow builds the harness
    # on the runner FIRST (see ci.yml); a missing binary here is a lane fault.
    echo "[run-aarch64] FAIL: ${HARNESS_BIN} missing and cargo unavailable -- build it first:" >&2
    echo "[run-aarch64]   cargo build --release --manifest-path tools/xport-harness/Cargo.toml" >&2
    exit 1
  fi
fi
"${HARNESS_BIN}" --socket "${XSOCK}" --key-out "${XKEY}" \
  --timeout-secs $((TIMEOUT_SECS + 60)) > "${XHOUT}" 2>&1 &
XPID=$!

# Print the exact QEMU build FIRST (fix_plan §B): the hosted ubuntu-24.04 runner
# image may ship a different 8.2.x point-release than the apt snapshot tested
# locally, and the version line is the one variable that pins which build a
# future CI log came from. Cheap, always emitted, never gates the verdict.
echo "[run-aarch64] qemu: $(${QEMU} --version | head -1)"

# -M virt,virtualization=on,gic-version=2,iommu=smmuv3 : QEMU AArch64 'virt';
#                    virtualization=on exposes EL2 so the vCPU enters at EL2h (the
#                    L2.0 nVHE EL2 monitor installs there, then drops to EL1 for
#                    M0..M18); gic-version=2 pins the GICv2 GICD/GICC MMIO M8
#                    hard-codes; iommu=smmuv3 instantiates the Arm SMMUv3 as the
#                    PCIe-root-complex IOMMU at MMIO 0x0905_0000 (the aL2.6 rung).
#                    STAGE-2 SMMUv3 support (the Mostafa series) landed in QEMU 9.0
#                    (2024), NOT 8.1: BOTH local qemu-6.2 AND the current CI image
#                    (tabos-qemu8 = 8.2.2) advertise S1P=1 but IDR0.S2P=0, so L2.6
#                    correctly hits the green '(no stage-2 SMMU, skipped)'
#                    Unavailable path on both today. When the CI QEMU is bumped to
#                    >= 9.0 the Proven 'L2.6: smmu OK' (table-programming accepted)
#                    runs for real with NO kernel change (the IDR0.S2P gate flips).
#                    The iommu= is an orthogonal machine property; virtualization=on
#                    + gic-version=2 + iommu=smmuv3 coexist, and M0..M19 +
#                    L2.0..L2.5 pass unchanged with the SMMU present (S1-only here,
#                    and disabled-until-L2.6 in any case).
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
        -M virt,virtualization=on,gic-version=2,iommu=smmuv3 \
        -cpu cortex-a72 \
        -m 128M \
        -accel tcg,thread=single \
        -nographic \
        -no-reboot \
        -nic none \
        -global virtio-mmio.force-legacy=false \
        -device virtio-rng-device \
        -drive file="$IMG",if=none,format=raw,id=vblk0 \
        -device virtio-blk-device,drive=vblk0 \
        -chardev socket,id=xport0,path="${XSOCK}",server=on,wait=off \
        -device virtio-serial-device \
        -device virtconsole,chardev=xport0 \
        -semihosting \
        -kernel "${KERNEL}" \
    < /dev/null 2>&1)"
QEMU_RC=$?
set -e

printf '%s\n' "${OUTPUT}"

# M30: reap the echo harness (it exits on socket EOF once QEMU terminates;
# bounded wait + a hard kill so a wedged harness can never hang the lane), then
# surface its SEPARATE capture stream into the log for traceability. The guard
# block compares ${OUTPUT} (guest serial) against ${HARNESS_OUT} (host stdout)
# -- two independently produced streams; neither is folded into the other.
for _ in $(seq 1 50); do
  kill -0 "${XPID}" 2>/dev/null || break
  sleep 0.1
done
kill -9 "${XPID}" 2>/dev/null || true
wait "${XPID}" 2>/dev/null || true
HARNESS_OUT="$(cat "${XHOUT}" 2>/dev/null || true)"
printf '%s\n' "${HARNESS_OUT}"

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
    # M19: the virtio-rng round-trip (the M20 dependency) must STILL print before
    # the displaced M20 tail -- assert it directly so the M19 -> M20 order is
    # fail-closed + traceable (mirroring the L2.x asserts below). Two virtio-mmio
    # devices (rng + blk) now share the bus; M19 must stay green with both present.
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M19: virtio OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'M19: virtio OK' missing (M19 displaced/regressed)" >&2
        exit 1
    fi
    # M20 SOUNDNESS (anti-hollow-pass): this lane ATTACHES a real virtio-blk disk,
    # so it must prove the REAL durable-persistence round-trip -- not the graceful
    # "(no disk, skipped)" path. That skip marker, 'M20: persist OK (no disk,
    # skipped)', CONTAINS the 'M20: persist OK' substring the top-level grep
    # matches, so a silently-unattached disk (wrong QEMU, device off the scanned
    # bus, future flag drift) would otherwise pass GREEN with a hollow proof
    # (exactly the substring-grep hole that the aL2.5 "(no EL2, skipped)" variant
    # exposed). Reject the skip AND positively require the real round-trip line
    # 'persist: gen=.. records=.. replayed=..' the Proven path prints before the
    # marker.
    if printf '%s' "${OUTPUT}" | grep -qF -- 'M20: persist OK (no disk, skipped)'; then
        echo "[run-aarch64] FAIL -- M20 ran in SKIP mode (no virtio-blk disk attached) but this lane attaches one -- the durable-persistence Proven path was NOT exercised" >&2
        exit 1
    fi
    if ! printf '%s' "${OUTPUT}" | grep -qE -- 'persist: gen=0x[0-9a-fA-F]+ records=0x[0-9a-fA-F]+ replayed=0x[0-9a-fA-F]+'; then
        echo "[run-aarch64] FAIL -- M20 marker present but the real durable-persistence round-trip line 'persist: gen=.. records=.. replayed=..' was NOT seen (hollow M20 pass)" >&2
        exit 1
    fi
    # M20 is no longer the top-level grep (M21 displaced it as the cumulative tail);
    # assert it directly so the M20 -> M21 order stays fail-closed + traceable.
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M20: persist OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'M20: persist OK' missing (M20 displaced/regressed)" >&2
        exit 1
    fi
    # M21 SOUNDNESS (anti-hollow-pass, the aL2.5/M20 substring lesson): the marker
    # substring 'M21: kan-policy OK' is shared by the DORMANT variant
    # 'M21: kan-policy OK (heuristic floor, gate-not-met)' -- EXPECTED this milestone
    # (the verified spline ships dormant; the heuristic floor decides), so it is NOT
    # rejected. But a hollow pass that printed the marker WITHOUT running the
    # loader/validators must fail, so (a) positively require the real round-trip line
    # 'kan: monotone=1 ovf-safe=1 q-err=0x.. bound=0x.. active=0' (the validators
    # provably ran on the shipped integer table), and (b) reject a future
    # '(no table, skipped)' variant (a skipped loader is a hollow proof on a lane
    # that ships a table). active=0 is required: the spline is dormant this lane.
    if printf '%s' "${OUTPUT}" | grep -qF -- 'M21: kan-policy OK (no table, skipped)'; then
        echo "[run-aarch64] FAIL -- M21 ran in SKIP mode (no policy table loaded) -- the verified-leaf loader/validators were NOT exercised" >&2
        exit 1
    fi
    if ! printf '%s' "${OUTPUT}" | grep -qE -- 'kan: monotone=0x0*1 ovf-safe=0x0*1 q-err=0x[0-9a-fA-F]+ bound=0x[0-9a-fA-F]+ active=0x0+'; then
        echo "[run-aarch64] FAIL -- M21 marker present but the real round-trip line 'kan: monotone=1 ovf-safe=1 q-err=0x.. bound=0x.. active=0' was NOT seen (hollow M21 pass)" >&2
        exit 1
    fi
    # M21 is no longer the top-level grep (M22 displaced it as the cumulative tail);
    # assert it directly so the M21 -> M22 order stays fail-closed + traceable.
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M21: kan-policy OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'M21: kan-policy OK' missing (M21 displaced/regressed)" >&2
        exit 1
    fi
    # M22 SOUNDNESS (anti-hollow-pass, the aL2.5/M20/M21 substring lesson): the
    # 'M22: provenance OK' marker must be backed by the REAL verifier round-trip --
    # there is NO device to be absent, so a skip is NEVER legitimate. Reject any
    # '(no ledger, skipped)' variant, and POSITIVELY require the witness line
    # 'prov: head=0x.. entries=0x.. tamper-caught=0x1 inclusion=0x1' (so a marker
    # printed WITHOUT running the canon/hash/fold + tamper-injection verifier FAILS).
    # tamper-caught=1 AND inclusion=1 are required: the injected single-byte tamper
    # of a committed entry must be caught (head-mismatch AND inclusion-fail) and a
    # genuine inclusion proof must verify.
    if printf '%s' "${OUTPUT}" | grep -qF -- 'M22: provenance OK (no ledger, skipped)'; then
        echo "[run-aarch64] FAIL -- M22 ran in SKIP mode (no ledger) -- the provenance verifier round-trip was NOT exercised (a skip is never legitimate here)" >&2
        exit 1
    fi
    if ! printf '%s' "${OUTPUT}" | grep -qE -- 'prov: head=0x[0-9a-fA-F]+ entries=0x[0-9a-fA-F]+ tamper-caught=0x0*1 inclusion=0x0*1'; then
        echo "[run-aarch64] FAIL -- M22 marker present but the real round-trip witness 'prov: head=0x.. entries=0x.. tamper-caught=0x1 inclusion=0x1' was NOT seen (hollow M22 pass)" >&2
        exit 1
    fi
    # M22 is no longer the top-level grep (M23 displaced it as the cumulative tail);
    # assert it directly so the M22 -> M23 order stays fail-closed + traceable.
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M22: provenance OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'M22: provenance OK' missing (M22 displaced/regressed)" >&2
        exit 1
    fi
    # M23 SOUNDNESS (anti-hollow-pass, the aL2.5/M20/M21/M22 substring lesson): the
    # 'M23: experience OK' marker must be backed by the REAL verifier round-trip -- the
    # experience log is IN-RAM (durable spill is M24), so a skip is NEVER legitimate.
    # Reject any '(no log, skipped)' variant, and POSITIVELY require the witness line
    # 'exp: head=0x.. records=0x.. replay-bitexact=0x1 tamper-caught=0x1 kan_active=0x0
    # oracle=DECLARED-PROXY-DEFERRED-M24' (so a marker printed WITHOUT running the
    # canon/fold/replay/tamper verifier FAILS). replay-bitexact=1 AND tamper-caught=1
    # AND kan_active=0 are required: a recorded feats row must replay bit-exactly, the
    # injected tamper must be caught, and the learned cell must be DORMANT (the shadow
    # changed zero demotes). The oracle honesty token must be present so the marker
    # mechanically cannot overclaim validity.
    if printf '%s' "${OUTPUT}" | grep -qF -- 'M23: experience OK (no log, skipped)'; then
        echo "[run-aarch64] FAIL -- M23 ran in SKIP mode (no log) -- the experience verifier round-trip was NOT exercised (a skip is never legitimate here -- the log is in-RAM)" >&2
        exit 1
    fi
    if ! printf '%s' "${OUTPUT}" | grep -qE -- 'exp: head=0x[0-9a-fA-F]+ records=0x[0-9a-fA-F]+ replay-bitexact=0x0*1 tamper-caught=0x0*1 kan_active=0x0+ oracle=DECLARED-PROXY-DEFERRED-M24'; then
        echo "[run-aarch64] FAIL -- M23 marker present but the real round-trip witness 'exp: head=0x.. records=0x.. replay-bitexact=0x1 tamper-caught=0x1 kan_active=0x0 oracle=DECLARED-PROXY-DEFERRED-M24' was NOT seen (hollow M23 pass)" >&2
        exit 1
    fi
    # TERMINOLOGY DISCIPLINE (proposal §6): M23 claims ONLY replay-determinism +
    # structural tamper-evidence, NOT validity. Reject any 'validated'/'evaluated'
    # substring on the exp: witness or the M23 marker line so the marker can never
    # silently overclaim (the OPE-loaded words are confined to bit-exact re-derivation).
    if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M23:|exp:)' | grep -qE -- 'validated|evaluated'; then
        echo "[run-aarch64] FAIL -- M23 marker/witness carries a 'validated'/'evaluated' overclaim -- M23 records + replay-determines, it does NOT validate any policy (proposal §6 terminology discipline)" >&2
        exit 1
    fi
    # M23 is no longer the top-level grep (M24 displaced it as the cumulative tail);
    # assert it directly so the M23 -> M24 order stays fail-closed + traceable.
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M23: experience OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'M23: experience OK' missing (M23 displaced/regressed)" >&2
        exit 1
    fi
    # M24 SOUNDNESS (anti-hollow-pass, the aL2.5/M20/M21/M22/M23 substring lesson): the
    # 'M24: bakeoff OK' marker must be backed by the REAL bake-off witness -- the gate
    # machinery (label + estimator + in-RAM replay + the envelope re-assertion) provably
    # RAN. POSITIVELY require the witness 'bakeoff: vlo_kan=0x.. vhi_heur=0x.. margin=0x..
    # ... cleared=0x.. ... no-float=1 envelope-no-widening=1' (so a marker printed WITHOUT
    # running the estimator/gate FAILS). no-float=1 AND envelope-no-widening=1 are required.
    if ! printf '%s' "${OUTPUT}" | grep -qE -- 'bakeoff: vlo_kan=0x[0-9a-fA-F]+ vhi_heur=0x[0-9a-fA-F]+ margin=0x[0-9a-fA-F]+ .*no-float=1 envelope-no-widening=1'; then
        echo "[run-aarch64] FAIL -- M24 marker present but the real bake-off witness 'bakeoff: vlo_kan=.. vhi_heur=.. margin=.. .. no-float=1 envelope-no-widening=1' was NOT seen (hollow M24 pass)" >&2
        exit 1
    fi
    # M24 DORMANCY (proposal §6/§7): on the (necessarily SYNTHETIC) traces this milestone
    # the gate does NOT clear -- 'M24: bakeoff OK (gate-not-met)' (the cell stays DORMANT)
    # is the DESIGNED, CORRECT outcome (the M21 '(heuristic floor, gate-not-met)' idiom).
    # This lane does NOT assert an ACTIVE cell, so it ACCEPTS the dormant gate-not-met /
    # gate-not-evaluable variants. A 'gate-cleared' here would mean the cell flipped ACTIVE
    # on a synthetic trace -- which this milestone forbids, so reject it.
    if printf '%s' "${OUTPUT}" | grep -qF -- 'M24: bakeoff OK (gate-cleared)'; then
        echo "[run-aarch64] FAIL -- M24 gate CLEARED on a synthetic trace (cell flipped ACTIVE) -- this milestone the gate must REFUSE (gate-not-met); a real activation awaits M25's human oracle" >&2
        exit 1
    fi
    # TERMINOLOGY DISCIPLINE (proposal §6/§7): M24 lower-bounds + honestly REFUSES, it
    # does NOT validate an activation. Reject any 'validated'/'evaluated' near the marker.
    if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M24:|bakeoff:)' | grep -qE -- 'validated|evaluated'; then
        echo "[run-aarch64] FAIL -- M24 marker/witness carries a 'validated'/'evaluated' overclaim -- M24 lower-bounds + honestly REFUSES, it does NOT validate any activation (proposal §6/§7 terminology discipline)" >&2
        exit 1
    fi
    # M24 is no longer the top-level grep (M25 displaced it as the cumulative tail);
    # assert it directly so the M24 -> M25 order stays fail-closed + traceable.
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M24: bakeoff OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'M24: bakeoff OK' missing (M24 displaced/regressed)" >&2
        exit 1
    fi
    # M25 SOUNDNESS (anti-hollow-pass, the aL2.5/M20..M24 substring lesson): the
    # 'M25: operator OK' marker must be backed by the REAL transcript round-trip -- the
    # transcript is IN-RAM + TX-only (RX/auth is M26), so a skip is NEVER legitimate.
    # Reject any '(no channel, skipped)' variant, and POSITIVELY require the witness line
    # 'opframe: tx_head=0x.. frames=0x.. seq_monotone=0x1 intro_bound=0x1 fold-verified=0x1
    # tamper-caught=0x1 keyed=0 oracle=HUMAN-DEFERRED-M26' (so a marker printed WITHOUT
    # running the emit/recompute/seq/intro-binding/truncation/tamper verifier FAILS).
    # seq_monotone=1 AND intro_bound=1 AND fold-verified=1 AND tamper-caught=1 are
    # required: strictly-monotone seq, the INTRO binding the LIVE M22 head, the clean
    # fold + inclusion, and the injected tamper + tail-truncation caught. The keyed=0 +
    # oracle=HUMAN-DEFERRED-M26 honesty tokens must be present so the marker cannot claim
    # crypto authenticity or that a human replied (it proves the CHANNEL, not the ORACLE).
    if printf '%s' "${OUTPUT}" | grep -qF -- 'M25: operator OK (no channel, skipped)'; then
        echo "[run-aarch64] FAIL -- M25 ran in SKIP mode (no channel) -- the operator-transcript verifier round-trip was NOT exercised (a skip is never legitimate here -- the transcript is in-RAM)" >&2
        exit 1
    fi
    if ! printf '%s' "${OUTPUT}" | grep -qE -- 'opframe: tx_head=0x[0-9a-fA-F]+ frames=0x[0-9a-fA-F]+ seq_monotone=0x0*1 intro_bound=0x0*1 fold-verified=0x0*1 tamper-caught=0x0*1 keyed=0 oracle=HUMAN-DEFERRED-M26'; then
        echo "[run-aarch64] FAIL -- M25 marker present but the real round-trip witness 'opframe: tx_head=.. frames=.. seq_monotone=0x1 intro_bound=0x1 fold-verified=0x1 tamper-caught=0x1 keyed=0 oracle=HUMAN-DEFERRED-M26' was NOT seen (hollow M25 pass)" >&2
        exit 1
    fi
    # TERMINOLOGY DISCIPLINE (proposal §5): M25 surfaces + tamper-evidences a transcript +
    # binds the instance; it does NOT validate any policy and does NOT prove a human
    # replied. Reject any 'validated'/'evaluated' near the M25 marker/witness.
    if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M25:|opframe:)' | grep -qE -- 'validated|evaluated'; then
        echo "[run-aarch64] FAIL -- M25 marker/witness carries a 'validated'/'evaluated' overclaim -- M25 surfaces + tamper-evidences a transcript, it does NOT validate any policy or prove a human replied (proposal §5 terminology discipline)" >&2
        exit 1
    fi
    # M25 is no longer the top-level grep (M26 displaced it as the cumulative tail);
    # assert it directly so the M25 -> M26 order stays fail-closed + traceable.
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M25: operator OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'M25: operator OK' missing (M25 displaced/regressed)" >&2
        exit 1
    fi
    # M26 SOUNDNESS (anti-hollow-pass, the aL2.5/M20..M25 substring lesson): the
    # 'M26: exit-telemetry OK' marker must be backed by the REAL telemetry round-trip --
    # the exit vector is synthetic + in-RAM (a real EL2 exit producer drains here in
    # M27+), so a skip is NEVER legitimate. Reject any '(no exits, skipped)' variant, and
    # POSITIVELY require the witness line 'exittel: head=0x.. records=0x.. classes=0x..
    # class-total=0x1 buckets-exact=0x1 fold-verified=0x1 tamper-caught=0x1
    # signal=OBSERVATIONAL-NONCAUSAL' (so a marker printed WITHOUT running the
    # classifier/histogram/fold/tamper verifier FAILS). class-total=1 AND buckets-exact=1
    # AND fold-verified=1 AND tamper-caught=1 are required: every synthetic ESR must
    # classify to a distinct in-range class, the recorded buckets/counts must be exact,
    # the clean fold + inclusion must verify, and the injected tamper must be caught. The
    # signal=OBSERVATIONAL-NONCAUSAL honesty token must be present so the marker cannot
    # claim a causal state-signal (the telemetry is recorded, not learned-from).
    if printf '%s' "${OUTPUT}" | grep -qF -- 'M26: exit-telemetry OK (no exits, skipped)'; then
        echo "[run-aarch64] FAIL -- M26 ran in SKIP mode (no exits) -- the exit-telemetry verifier round-trip was NOT exercised (a skip is never legitimate here -- the exit vector is synthetic + in-RAM)" >&2
        exit 1
    fi
    if ! printf '%s' "${OUTPUT}" | grep -qE -- 'exittel: head=0x[0-9a-fA-F]+ records=0x[0-9a-fA-F]+ classes=0x[0-9a-fA-F]+ class-total=0x0*1 buckets-exact=0x0*1 fold-verified=0x0*1 tamper-caught=0x0*1 signal=OBSERVATIONAL-NONCAUSAL'; then
        echo "[run-aarch64] FAIL -- M26 marker present but the real round-trip witness 'exittel: head=.. records=.. classes=.. class-total=0x1 buckets-exact=0x1 fold-verified=0x1 tamper-caught=0x1 signal=OBSERVATIONAL-NONCAUSAL' was NOT seen (hollow M26 pass)" >&2
        exit 1
    fi
    # TERMINOLOGY DISCIPLINE (proposal §5): M26 is PRODUCER-ONLY -- it RECORDS observational
    # exit telemetry; it does NOT validate a causal state-signal and does NOT learn from the
    # stream. Reject any 'validated'/'causal'/'learned' near the M26 marker/witness.
    if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M26:|exittel:)' | grep -qE -- 'validated|causal|learned'; then
        echo "[run-aarch64] FAIL -- M26 marker/witness carries a 'validated'/'causal'/'learned' overclaim -- M26 RECORDS observational exit telemetry, it does NOT validate a causal signal or learn from it (proposal §5 terminology discipline)" >&2
        exit 1
    fi
    # M26 is no longer the top-level grep (M28 displaced it as the cumulative tail);
    # assert it directly so the M26 -> M28 order stays fail-closed + traceable.
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M26: exit-telemetry OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'M26: exit-telemetry OK' missing (M26 displaced/regressed)" >&2
        exit 1
    fi
    # M28 SOUNDNESS (anti-hollow-pass, the aL2.5/M20..M26 substring lesson): the
    # 'M28: operator-cmd OK' marker -- the CAPSTONE that closes the learning loop --
    # must be backed by the REAL operator-inbound command round-trip. The command is
    # IN-RAM + SIMULATED (a real enrolment ceremony + a trustworthy freshness clock are
    # the named successors), so a skip is NEVER legitimate. Reject any '(no key,
    # skipped)' variant, and POSITIVELY require the witness line 'opcmd: challenge=0x..
    # accepted=1 stale-rejected=1 wronghead-rejected=1 single-cred-rejected=1
    # badmac-rejected=1 oldkey-zeroized=1 kan_active=0 mac=KEYED-CRYPTO
    # kdf=DERIVE-THEN-MAC-DOMSEP keyevolve=PRF-DOMSEP oracle=SIMULATED-ENROLLED-KEY'
    # (so a marker printed WITHOUT running the decode/verify accept + the four precise
    # rejects FAILS). All six flags MUST be =1 (the valid command accepted + each of
    # the stale-nonce / wrong-head / single-credential / flipped-MAC attacks rejected +
    # the M29 old-key erasure demonstrated) AND kan_active=0 is REQUIRED: the accepted
    # command is NECESSARY-NOT-SUFFICIENT, it does NOT flip the cell (M24's statistical
    # bar still gates). The M29 token set (mac=KEYED-CRYPTO kdf=DERIVE-THEN-MAC-DOMSEP
    # keyevolve=PRF-DOMSEP) + oracle=SIMULATED-ENROLLED-KEY MUST be present so the
    # marker cannot claim a proven-secure MAC, a human oracle, or a real activation.
    if printf '%s' "${OUTPUT}" | grep -qF -- 'M28: operator-cmd OK (no key, skipped)'; then
        echo "[run-aarch64] FAIL -- M28 ran in SKIP mode (no key) -- the operator-inbound command verifier round-trip was NOT exercised (a skip is never legitimate here -- the command is in-RAM + simulated)" >&2
        exit 1
    fi
    if ! printf '%s' "${OUTPUT}" | grep -qE -- 'opcmd: challenge=0x[0-9a-fA-F]+ accepted=0x0*1 stale-rejected=0x0*1 wronghead-rejected=0x0*1 single-cred-rejected=0x0*1 badmac-rejected=0x0*1 oldkey-zeroized=0x0*1 kan_active=0x0+ mac=KEYED-CRYPTO kdf=DERIVE-THEN-MAC-DOMSEP keyevolve=PRF-DOMSEP oracle=SIMULATED-ENROLLED-KEY'; then
        echo "[run-aarch64] FAIL -- M28 marker present but the real round-trip witness 'opcmd: challenge=0x.. accepted=0x1 stale-rejected=0x1 wronghead-rejected=0x1 single-cred-rejected=0x1 badmac-rejected=0x1 oldkey-zeroized=0x1 kan_active=0x0 mac=KEYED-CRYPTO kdf=DERIVE-THEN-MAC-DOMSEP keyevolve=PRF-DOMSEP oracle=SIMULATED-ENROLLED-KEY' was NOT seen (hollow M28 pass)" >&2
        exit 1
    fi
    # M28 is no longer the top-level grep (M29 displaced it as the cumulative tail);
    # assert it directly so the M28 -> M29 order stays fail-closed + traceable.
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M28: operator-cmd OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'M28: operator-cmd OK' missing (M28 displaced/regressed)" >&2
        exit 1
    fi
    # M29 SOUNDNESS (anti-hollow-pass): the 'M29: khash-mac OK' marker must be backed
    # by the khash WITNESS line with the FULL machine-emitted prove/assume boundary --
    # 'khash: prim=BLAKE2S-256 keylen=32 tag=128 kat=RFC7693-PASS
    # sec=ASSUMED-FROM-LITERATURE sidechannel=NOT-CLAIMED'. kat=RFC7693-PASS is EARNED
    # per boot (the self-test recomputes the official RFC 7693 vectors through the
    # real compression, fail-closed) -- a marker without the witness is a hollow pass.
    # The khash leaf is pure in-RAM value computation, so a skip is NEVER legitimate.
    if printf '%s' "${OUTPUT}" | grep -qF -- 'M29: khash-mac OK (no key, skipped)'; then
        echo "[run-aarch64] FAIL -- M29 ran in SKIP mode -- the khash KAT + MAC round-trip was NOT exercised (a skip is never legitimate here -- pure in-RAM value computation)" >&2
        exit 1
    fi
    if ! printf '%s' "${OUTPUT}" | grep -qE -- 'khash: prim=BLAKE2S-256 keylen=32 tag=128 kat=RFC7693-PASS sec=ASSUMED-FROM-LITERATURE sidechannel=NOT-CLAIMED'; then
        echo "[run-aarch64] FAIL -- M29 marker present but the khash witness 'khash: prim=BLAKE2S-256 keylen=32 tag=128 kat=RFC7693-PASS sec=ASSUMED-FROM-LITERATURE sidechannel=NOT-CLAIMED' was NOT seen (hollow M29 pass -- the in-boot KAT did not provably run)" >&2
        exit 1
    fi
    # RETIRED-TIER REJECT (M29 proposal §7): the M28-era mac=KEYED-NONCRYPTO token
    # RETIRES at M29 -- it must NEVER appear anywhere in a green boot, so the old
    # keyed-FNV tier can never impersonate the khash-backed stage B chain.
    if printf '%s' "${OUTPUT}" | grep -qF -- 'KEYED-NONCRYPTO'; then
        echo "[run-aarch64] FAIL -- the RETIRED 'KEYED-NONCRYPTO' token appeared -- the M28-era keyed-FNV tier cannot impersonate the M29 KEYED-CRYPTO chain (proposal §7 retired-token discipline)" >&2
        exit 1
    fi
    # TERMINOLOGY DISCIPLINE (M29 proposal §7): the markers/witnesses prove the auth
    # PLUMBING + a verified IMPLEMENTATION of an ASSUMED-secure primitive -- never a
    # proven-secure/unforgeable/collision-resistant/constant-time MAC, a human, or an
    # activation. We FIRST strip the structured honesty tokens (KEYED-CRYPTO carries
    # 'crypto'; collision-resistance lives ONLY inside ASSUMED-FROM-LITERATURE, etc.)
    # so the post-strip overclaim grep bites on PROSE only; the reject list extends
    # the M28 set with the M29 crypto-overclaim vocabulary.
    if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M28:|M29:|opcmd:|khash:)' \
         | sed -e 's/KEYED-CRYPTO//g' -e 's/BLAKE2S-256//g' -e 's/RFC7693-PASS//g' \
               -e 's/ASSUMED-FROM-LITERATURE//g' -e 's/NOT-CLAIMED//g' \
               -e 's/DERIVE-THEN-MAC-DOMSEP//g' -e 's/PRF-DOMSEP//g' \
               -e 's/SIMULATED-ENROLLED-KEY//g' \
         | grep -qiE -- 'validated|crypto|authenticated-human|forgery|provably[- ]secure|unforgeable|collision[- ]resistant|preimage[- ]resistant|constant[- ]time|tamper[- ]proof|quantum|FIPS[- ](certified|validated)|guaranteed|unbreakable'; then
        echo "[run-aarch64] FAIL -- M28/M29 marker/witness carries an overclaim ('validated'/'crypto'/'authenticated-human'/'forgery'/'provably-secure'/'unforgeable'/'collision-resistant'/'preimage-resistant'/'constant-time'/'tamper-proof'/'quantum'/'FIPS-certified'/'guaranteed'/'unbreakable') -- the implementation is verified, the primitive is ASSUMED-FROM-LITERATURE; crypto claims live ONLY in the structured stripped tokens (M29 proposal §7 honesty discipline)" >&2
        exit 1
    fi
    # M29 is no longer the top-level grep (M30 displaced it as the cumulative tail);
    # assert it directly so the M29 -> M30 order stays fail-closed + traceable.
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M29: khash-mac OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'M29: khash-mac OK' missing (M29 displaced/regressed)" >&2
        exit 1
    fi
    # M30 GUARDS (proposal §5 -- house order: skip-reject, positive-require,
    # by-name rejects, lane-cross-pin, #71 tripwire, cross-process, key-leak,
    # strip-then-reject). This lane ATTACHES a host peer (the chardev harness),
    # so the anti-hollow composition is REQUIRED in full.
    #
    # (§5.1) Skip-variant reject BY NAME (the M20 idiom): an attached lane must
    # never take the graceful no-peer (or legacy) skip path.
    if printf '%s' "${OUTPUT}" | grep -qF -- 'M30: infer-transport OK (no host peer, skipped)'; then
        echo "[run-aarch64] FAIL -- M30 ran in SKIP mode (no host peer found) but this lane attaches the chardev harness -- the host-keyed echo round-trip was NOT exercised" >&2
        exit 1
    fi
    if printf '%s' "${OUTPUT}" | grep -qF -- 'M30: infer-transport OK (legacy transport, skipped)'; then
        echo "[run-aarch64] FAIL -- M30 took the legacy-transport skip but this lane attaches a MODERN (force-legacy=false) console -- the Version=2 negotiation regressed" >&2
        exit 1
    fi
    # (§5.2) POSITIVE-REQUIRE the full xport witness: every flag =1, every token
    # literal, the lane's own bus/transport tokens (chardev lane: SERIAL-FRAMED +
    # QEMU-CHARDEV-HARNESS). A marker without this witness is a hollow pass.
    if ! printf '%s' "${OUTPUT}" | grep -qE -- 'xport: bus=SERIAL-FRAMED qsz=0x4 tx=0x0*1 rx=0x0*1 challenge=0x[0-9a-f]{32} nonce=0x[0-9a-f]{32} tag=0x[0-9a-f]{32} req-id=0x[0-9a-f]{16} echo-verified=0x0*1 body-bitexact=0x0*1 badtag-rejected=0x0*1 wrongkey-rejected=0x0*1 partial-rejected=0x0*1 desync-rejected=0x0*1 mode=POLL transport=QEMU-CHARDEV-HARNESS echo=HOST-KEYED-VERIFIED key=HOST-CUSTODIED-PER-RUN backend=ECHO-ONLY sec=ASSUMED-FROM-LITERATURE'; then
        echo "[run-aarch64] FAIL -- M30 marker present but the real witness 'xport: bus=SERIAL-FRAMED .. challenge=.. nonce=.. tag=.. echo-verified=0x1 .. mode=POLL transport=QEMU-CHARDEV-HARNESS echo=HOST-KEYED-VERIFIED key=HOST-CUSTODIED-PER-RUN backend=ECHO-ONLY sec=ASSUMED-FROM-LITERATURE' was NOT seen (hollow M30 pass)" >&2
        exit 1
    fi
    # (§5.3) Loopback variants rejected BY NAME (case-insensitive, near the M30
    # marker/witness): the M22 mock-loopback design is structurally banned.
    if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M30:|xport:)' | grep -qiE -- 'transport=IN-KERNEL-LOOPBACK|transport=MOCK-BACKEND|transport=GUEST-SELF|echo=SELF-KEYED|echo=GUEST-KEYED|loopback|self-echo'; then
        echo "[run-aarch64] FAIL -- M30 marker/witness carries a LOOPBACK token (IN-KERNEL-LOOPBACK/MOCK-BACKEND/GUEST-SELF/SELF-KEYED/GUEST-KEYED/loopback/self-echo) -- the M22 hollow-loopback design is banned by name (M30 proposal §5.3)" >&2
        exit 1
    fi
    # (§5.4) Lane-token cross-pin: the chardev lane must NEVER carry the vmm
    # lane's evidence class (peer_id is MAC-covered; a mislabel is a fault).
    if printf '%s' "${OUTPUT}" | grep -qF -- 'transport=TB-VMM-HOST'; then
        echo "[run-aarch64] FAIL -- the chardev lane carries 'transport=TB-VMM-HOST' -- no lane borrows the other's evidence class (M30 proposal §5.4 lane cross-pin)" >&2
        exit 1
    fi
    # (§5.5) The #71 tripwire: M30 is poll-only BY GUARD PIN. Flipping this is
    # the designated visible act that forces a #71 disposition first.
    if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M30:|xport:)' | grep -qE -- 'mode=IRQ'; then
        echo "[run-aarch64] FAIL -- M30 witness carries 'mode=IRQ' -- the completion-IRQ migration is BLOCKED until a #71 (TCG ghost-IRQ) disposition is recorded (M30 proposal §5.5 tripwire)" >&2
        exit 1
    fi
    if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])xport:' | grep -vE -- 'mode=POLL' | grep -q .; then
        echo "[run-aarch64] FAIL -- an xport: witness line lacks 'mode=POLL' -- any non-poll completion mode is rejected (M30 proposal §5.5)" >&2
        exit 1
    fi
    # (§5.6) THE CROSS-PROCESS ROUND-TRIP (leg 2 -- the loopback killer): the
    # kernel-witnessed challenge/tag must STRING-EQUAL the host harness's OWN
    # line from its SEPARATE capture stream. A loopback can mint a self-
    # consistent tag but cannot equal khash(K,..) without the host-custodied K.
    if ! printf '%s\n' "${HARNESS_OUT}" | grep -qE -- 'xport-harness: peer=QEMU-CHARDEV-HARNESS challenge=0x[0-9a-f]{32} tag=0x[0-9a-f]{32} key-custody=HOST'; then
        echo "[run-aarch64] FAIL -- the host harness witness 'xport-harness: peer=QEMU-CHARDEV-HARNESS challenge=.. tag=.. key-custody=HOST' was NOT seen on the harness's capture stream (no host peer answered -- leg 2 of the anti-hollow composition is missing)" >&2
        exit 1
    fi
    K_CH="$(printf '%s\n' "${OUTPUT}" | grep -E '(^|[^[:alnum:]])xport: ' | grep -oE 'challenge=0x[0-9a-f]{32}' | head -1)"
    K_TAG="$(printf '%s\n' "${OUTPUT}" | grep -E '(^|[^[:alnum:]])xport: ' | grep -oE '(^| )tag=0x[0-9a-f]{32}' | head -1 | tr -d ' ')"
    H_CH="$(printf '%s\n' "${HARNESS_OUT}" | grep -F 'xport-harness: ' | grep -oE 'challenge=0x[0-9a-f]{32}' | head -1)"
    H_TAG="$(printf '%s\n' "${HARNESS_OUT}" | grep -F 'xport-harness: ' | grep -oE '(^| )tag=0x[0-9a-f]{32}' | head -1 | tr -d ' ')"
    if [[ -z "${K_CH}" || -z "${K_TAG}" || "${K_CH}" != "${H_CH}" || "${K_TAG}" != "${H_TAG}" ]]; then
        echo "[run-aarch64] FAIL -- CROSS-PROCESS mismatch: kernel (${K_CH:-none} ${K_TAG:-none}) vs harness (${H_CH:-none} ${H_TAG:-none}); the bytes did not provably cross the guest/host boundary both ways (M30 proposal §5.6 -- the loopback killer)" >&2
        exit 1
    fi
    # (§5.7) Key-LEAK negative: the host-custodied K's hex must appear NOWHERE
    # in the guest serial output (the kernel must never print the revealed key).
    KHEX="$(cat "${XKEY}" 2>/dev/null || true)"
    if [[ -z "${KHEX}" ]]; then
        echo "[run-aarch64] FAIL -- the harness key file is empty -- the §5.7 key-leak check has no input (harness fault)" >&2
        exit 1
    fi
    if printf '%s' "${OUTPUT}" | grep -qiF -- "${KHEX}"; then
        echo "[run-aarch64] FAIL -- the host-custodied per-run key LEAKED into the guest serial output (M30 proposal §5.7 key-leak negative)" >&2
        exit 1
    fi
    # (§5.8) Strip-then-reject overclaims: strip the declared structured tokens
    # FIRST (each carries a would-be-rejected substring), then reject the
    # network/crypto/inference overclaim vocabulary near the M30 marker/witness.
    # The M29 global rejects above stay in force.
    if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M30:|xport:)' \
         | sed -e 's/HOST-KEYED-VERIFIED//g' -e 's/HOST-CUSTODIED-PER-RUN//g' \
               -e 's/ASSUMED-FROM-LITERATURE//g' -e 's/ECHO-ONLY//g' \
               -e 's/SERIAL-FRAMED//g' -e 's/VIRTIO-MMIO//g' \
               -e 's/QEMU-CHARDEV-HARNESS//g' -e 's/TB-VMM-HOST//g' \
         | grep -qiE -- 'network|internet|online|TLS|SSL|HTTPS|encrypt|confidential|secure[- ]channel|authenticated|cloud|remote[- ]model|real[- ]infer|model[- ](served|loaded)|validated|evaluated'; then
        echo "[run-aarch64] FAIL -- M30 marker/witness carries an overclaim ('network'/'TLS'/'encrypt'/'authenticated'/'secure-channel'/'remote-model'/'real-infer'/'validated'/...) -- M30 is a LOCAL host-process echo transport; claims live ONLY in the structured stripped tokens (M30 proposal §5.8)" >&2
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
    # aL2.6: the SMMUv3 stage-2 DMA-isolation table-programming proof must ALSO
    # print (the EL1 kernel probes IDR0.S2P, builds a 1-entry stream table + a
    # stage-2-only STE whose S2TTB/S2VMID/VTCR point at the SAME stage-2 root the
    # CPU uses, programs STRTAB_BASE/CMDQ_BASE/CR0, pushes CMD_CFGI_STE + CMD_SYNC,
    # observes the SYNC drain with GERROR clean + no C_BAD_STE event, then tears
    # the SMMU down before M19). The 'L2.6: smmu OK' substring matches BOTH the
    # Proven marker (qemu>=8.1, stage-2 SMMUv3 present) AND the green
    # '(no SMMU, skipped)' skip (local qemu-6.2 / no iommu=smmuv3) -- a FAIL renders
    # 'L2.6: smmu FAIL ...' with NO 'smmu OK' substring, so this grep fails closed.
    # Assert it directly so the el2 -> ... -> vgic -> smmu -> virtio order is
    # fail-closed + traceable. (qemu>=8.1 required for the stage-2 Proven path;
    # older QEMU correctly takes the green skip via the IDR0.S2P Unavailable gate.)
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'L2.6: smmu OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'L2.6: smmu OK' missing" >&2
        exit 1
    fi
    # M27b SOUNDNESS (anti-hollow-pass, the aL2.5/L2.6/M20..M26 substring lesson): the
    # 'M27: sched OK' marker must be backed by the REAL CNTHP timer-preempted two-VMID
    # round-trip -- two guest VMIDs are time-partitioned under two stage-2 roots, each a
    # pure store-spin that NEVER yields; the slot switch is driven ONLY by the CNTHP (EL2
    # physical timer) PPI taken asynchronously at EL2's 0x480 vector (HCR_EL2.IMO window),
    # every scheduling DECISION folded into a running provenance head, and the whole thing
    # runs in its OWN HCR_EL2.IMO|VM window (teardown-FIRST). On a runner that boots at
    # EL2 the round-trip ALWAYS runs (it is self-contained + in-RAM, like the other EL2
    # rungs), so the Proven path is expected; the '(no EL2, skipped)' variant is only
    # legitimate when the kernel did NOT boot at EL2 (already LOUDLY warned via the L2.0
    # skip below). POSITIVELY require the witness line 'sched: head=0x.. frames=0x..
    # vmids=0x2 both-progressed=1 order-honored=1 fold-verified=1 tamper-caught=1
    # frame-conserved=1 timing=TCG-NON-CYCLE-ACCURATE realtime=NOT-CLAIMED' (so a marker
    # printed WITHOUT both VMIDs progressing / the round-robin order / the fold + tamper
    # verifier / the frame-conservation check FAILS). The timing=TCG-NON-CYCLE-ACCURATE
    # token must be present (the HONEST claim: real async preemption under TCG, which is
    # not cycle-accurate) and the RETIRED M27a timing=COOPERATIVE-HVC-YIELD token must NOT
    # appear (M27b must not be impersonatable by the cooperative path) AND
    # realtime=NOT-CLAIMED must be present so the marker cannot claim a real-time /
    # schedulability guarantee.
    if printf '%s' "${OUTPUT}" | grep -qF -- 'M27: sched OK'; then
        # The 'L2.0: el2 OK (no EL2, skipped)' lane already warns about a non-EL2 boot; in
        # that case M27 legitimately prints its '(no EL2, skipped)' variant and the witness
        # is absent. Only enforce the real witness when the kernel DID boot at EL2.
        if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M27: sched OK (no EL2, skipped)'; then
            if ! printf '%s' "${OUTPUT}" | grep -qE -- 'sched: head=0x[0-9a-fA-F]+ frames=0x[0-9a-fA-F]+ vmids=0x2 both-progressed=1 order-honored=1 fold-verified=1 tamper-caught=1 frame-conserved=1 timing=TCG-NON-CYCLE-ACCURATE realtime=NOT-CLAIMED'; then
                echo "[run-aarch64] FAIL -- M27 marker present but the real round-trip witness 'sched: head=.. frames=.. vmids=0x2 both-progressed=1 order-honored=1 fold-verified=1 tamper-caught=1 frame-conserved=1 timing=TCG-NON-CYCLE-ACCURATE realtime=NOT-CLAIMED' was NOT seen (hollow M27 pass)" >&2
                exit 1
            fi
            # HONESTY DISCIPLINE (M27 plan §4): M27b is the REAL CNTHP-preemption path under
            # TCG; it must not be impersonatable by the retired M27a cooperative path, and it
            # makes NO real-time / schedulability / WCET guarantee. Reject the retired
            # 'COOPERATIVE-HVC-YIELD' token and any 'validated'/'real-time'/'WCET'/'guaranteed'
            # near the M27 marker/witness.
            if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M27:|sched:)' | grep -qE -- 'COOPERATIVE-HVC-YIELD|validated|real-time|WCET|guaranteed'; then
                echo "[run-aarch64] FAIL -- M27 marker/witness carries a stale/overclaim token ('COOPERATIVE-HVC-YIELD' is the RETIRED M27a cooperative token, or a 'validated'/'real-time'/'WCET'/'guaranteed' claim) -- M27b is the CNTHP timer-preempted path with timing=TCG-NON-CYCLE-ACCURATE + realtime=NOT-CLAIMED (M27 plan §4 honesty discipline)" >&2
                exit 1
            fi
        fi
    else
        echo "[run-aarch64] FAIL -- final marker present but 'M27: sched OK' missing (M27 regressed)" >&2
        exit 1
    fi
    # LOUD when M27 silently degrades to its skip variant (the kernel did not boot at EL2):
    # the lane stays green (the cumulative chain still proves M0..M26) but the GitHub UI
    # shows a warning so reduced sovereign-scheduler proof coverage is never invisible.
    if printf "%s" "${OUTPUT}" | grep -qF -- "M27: sched OK (no EL2, skipped)"; then
        echo "::warning::aarch64 M27 sovereign-scheduler ran in SKIP mode (kernel did not boot at EL2) -- the CNTHP timer-preempted two-VMID time-partition round-trip was NOT exercised on this runner; see the boot: entry-el= serial line"
    fi
    # M14.2: explicit second assertion for the blocking-recv sub-marker (the
    # final marker already transitively gates it; this is direct traceability).
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M14.2: blocking-recv OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'M14.2: blocking-recv OK' missing" >&2
        exit 1
    fi
    # #65 PERMANENT RED LINES: the stack red-zone/guard canaries, the TASK_SP
    # bounds check, the BOOTED_AT_EL2 stomp witness and the un-armed qemu-exit
    # tripwire are all SILENT on a healthy boot; any of them in the log means
    # live memory corruption (the H1b boot-stack-overflow class) rode through
    # an otherwise green-looking chain -- fail the lane, never warn.
    for CANARY in \
        'diag: stack red-zone breached' \
        'diag: stack guard breached' \
        'diag: TASK_SP out of range' \
        'el2: DIAG BOOTED_AT_EL2 lost' \
        'qemu-exit: UNEXPECTED entry'; do
        if printf '%s' "${OUTPUT}" | grep -qF -- "${CANARY}"; then
            echo "[run-aarch64] FAIL -- corruption canary fired: '${CANARY}' (see the serial log above)" >&2
            exit 1
        fi
    done
    # LOUD when the EL2 track silently degrades to its skip variant: the lane
    # stays green (the cumulative chain still proves M0..M19) but the GitHub UI
    # shows a warning so reduced proof coverage is never invisible again.
    if printf "%s" "${OUTPUT}" | grep -qF -- "L2.0: el2 OK (no EL2, skipped)"; then
        echo "::warning::aarch64 EL2 track ran in SKIP mode (kernel did not boot at EL2) -- the L2.0..L2.5 proofs were NOT exercised on this runner; see the boot: entry-el= serial line"
    fi
    # LOUD when the aL2.6 SMMU rung degrades to its green skip (no stage-2 SMMU:
    # open-bus IDR0, or IDR0.S2P==0 on an S1-only SMMU): the lane stays green (the
    # cumulative chain still proves M0..M19, the STE/command encoders are
    # Kani-proven in the prove-encode lane) but the GitHub UI shows a warning so
    # reduced IOMMU proof coverage is never invisible. NOTE: stage-2 SMMUv3 support
    # landed in QEMU 9.0 (the Mostafa series, 2024), NOT 8.1 -- the current CI image
    # (tabos-qemu8 = 8.2.2) advertises S1P=1 but S2P=0, so it takes this honest skip
    # until the CI QEMU is bumped to >= 9.0, at which point the Proven path (the
    # table-programming acceptance) runs for real. Local qemu-6.2 also skips here.
    if printf "%s" "${OUTPUT}" | grep -qF -- "L2.6: smmu OK (no stage-2 SMMU, skipped)"; then
        echo "::warning::aarch64 SMMUv3 rung ran in SKIP mode (no stage-2 SMMU: IDR0.S2P absent -- QEMU < 9.0, e.g. the 8.2.2 CI image, or a run without iommu=smmuv3) -- the aL2.6 table-programming Proven path was NOT exercised on this runner (the STE/command encoders remain Kani-proven)"
    fi
    echo "[run-aarch64] PASS -- observed DoD marker: '${MARKER}' (and 'M29: khash-mac OK' + 'M28: operator-cmd OK' + 'M26: exit-telemetry OK' + 'M25: operator OK' + 'M24: bakeoff OK' gate-not-met + 'M23: experience OK' + 'M22: provenance OK' + 'M21: kan-policy OK' + 'M20: persist OK' + 'M19: virtio OK' + 'L2.0: el2 OK' + 'L2.1: stage2 OK' + 'L2.2: el2-exits OK' + 'L2.3: el2-trap OK' + 'L2.4: el2-guest OK' + 'L2.5: vgic OK' + 'L2.6: smmu OK' + 'M27: sched OK' + 'M14.2: blocking-recv OK'; M30 cross-process challenge/tag equality held)"
    exit 0
fi

echo "[run-aarch64] FAIL -- marker '${MARKER}' not seen" >&2
echo "[run-aarch64]   (qemu exit=${QEMU_RC}; the kernel exits qemu via semihosting after the final marker; a" >&2
echo "[run-aarch64]    ${TIMEOUT_SECS}s timeout/exit=124 is expected -- the grep is the verdict)" >&2
exit 1
