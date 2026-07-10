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
# Doubles as the cargo runner for target aarch64-yuva-none (cargo passes the
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
# Build identifiers (KERNEL_BIN, TARGET_A64, ...) — the single source of truth.
. "${REPO_ROOT}/scripts/project.env"
PROFILE="${PROFILE:-debug}"
KERNEL="${1:-${REPO_ROOT}/target/${TARGET_A64}/${PROFILE}/${KERNEL_BIN}}"
QEMU="${QEMU_AARCH64:-qemu-system-aarch64}"
# M38 (stage B) DISPLACED M31 as the cumulative tail: the kernel-integrated
# conductor loop is the newest milestone. M31 is demoted-not-deleted (asserted
# directly below per the displacement discipline); the M38 marker is the new
# top-level grep. DECIMAL grammar (turns=N organs=K), now guest-serial.
MARKER="M38: conductor OK turns=6 organs=3 verdict=ACCEPT"
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

# M20 + M33: a fresh 8 MiB raw disk per run. The low 4 MiB (sectors 0..8192) is
# M20's virtio-blk durable-persistence partition; the M33 stage-B persisted
# signed head lives ABOVE it (ping-pong slots at sector 8192 = the 4 MiB
# boundary), so the two never alias and the M33 two-boot (below) resets ONLY
# M20's region between boots while the signed head SURVIVES. `truncate -s 8M`
# gives a zeroed image (so the first mount finds no valid superblock and
# formats); the `trap` removes it on EXIT. A lane that does NOT attach this disk
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
# Preserve the pending exit code across the cleanup (bash <=5.1 resets the
# script's exit status to the EXIT trap's last command -- `rm -f` always
# succeeds -- which would mask a guard's `exit 1` locally; CI's bash 5.2
# preserves it, but pin the behaviour here so a red guard reds the lane on
# EVERY bash, never a silently-green local run).
XSOCK2="$(mktemp -u)"  # M33 stage-B second-boot echo-harness socket
XHOUT2="$(mktemp)"
XKEY2="$(mktemp)"
trap 'rc=$?; rm -f "$IMG" "$XSOCK" "$XHOUT" "$XKEY" "$XSOCK2" "$XHOUT2" "$XKEY2"; exit $rc' EXIT
truncate -s 8M "$IMG"

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

# M38 (stage B): the host conductor binary -- used ONLY for the §8.6 CROSS-PROCESS
# recompute leg (--recompute-from-trace re-folds the GUEST's OWN emitted conduct-step
# trace INDEPENDENTLY, host-side; the M38 guard string-equals its head against the
# guest-emitted `conduct: head=..`). The cargo-less CI boot container consumes the
# copy the runner step pre-built (the xport-harness prebuild pattern).
CONDUCTOR_HOST_BIN="${REPO_ROOT}/tools/conductor-host/target/release/conductor-host"
if [[ ! -x "${CONDUCTOR_HOST_BIN}" ]]; then
  if command -v cargo >/dev/null 2>&1; then
    echo "[run-aarch64] building conductor-host (host, release)" >&2
    ( cd "${REPO_ROOT}/tools/conductor-host" && cargo build --release >&2 )
  else
    echo "[run-aarch64] FAIL: ${CONDUCTOR_HOST_BIN} missing and cargo unavailable -- build it first:" >&2
    echo "[run-aarch64]   cargo build --release --manifest-path tools/conductor-host/Cargo.toml" >&2
    exit 1
  fi
fi

# aL2.4b: stage the SECOND kernel image (the full-kernel EL1 guest) as a flat
# binary for `-device loader` at the pmm-reserved carve + the canonical
# text_offset (0x4600_0000 + 0x8_0000). The image is THIS very kernel ELF,
# objcopy'd to raw (PT_LOAD bytes from the link base; .bss NOLOAD excluded --
# the guest's own boot path zeroes it). loader=QEMU-DEVICE-LOADER is the
# ledgered external-dependency decision (proposal aL2.4b SS2.2); the
# self-loading flavor is the M36-direction successor. The bin is produced
# next to the ELF; the cargo-less CI boot container consumes the copy the
# runner step pre-generated (the xport-harness prebuild pattern).
GUEST_BIN="${KERNEL}.guest.bin"
# Locate an objcopy (PATH, then the rust-toolchain.toml llvm-tools component).
GUEST_OBJCOPY="$(command -v llvm-objcopy || true)"
if [[ -z "${GUEST_OBJCOPY}" ]] && command -v rustc >/dev/null 2>&1; then
  GUEST_OBJCOPY="$(ls "$(rustc --print sysroot)"/lib/rustlib/*/bin/llvm-objcopy 2>/dev/null | head -1 || true)"
fi
if [[ -n "${GUEST_OBJCOPY}" ]]; then
  # objcopy available (the runner / a local dev box): (re)generate when stale.
  if [[ ! -s "${GUEST_BIN}" || "${KERNEL}" -nt "${GUEST_BIN}" ]]; then
    "${GUEST_OBJCOPY}" -O binary "${KERNEL}" "${GUEST_BIN}"
  fi
elif [[ ! -s "${GUEST_BIN}" ]]; then
  # No objcopy AND no prebuilt image (the cargo-less CI boot container relies
  # on the runner's pre-generate step bind-mounting ${GUEST_BIN} via /work).
  echo "[run-aarch64] FAIL: no llvm-objcopy on PATH/sysroot and no prebuilt ${GUEST_BIN} -- the aL2.4b guest image must be pre-generated on the runner (llvm-objcopy -O binary <ELF> <ELF>.guest.bin) before a cargo-less boot" >&2
  exit 1
fi
# else: no objcopy but a prebuilt image exists -> use it as-is (the container).

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
RAW_OUTPUT="$(timeout --foreground "${TIMEOUT_SECS}" \
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
        -device loader,file="${GUEST_BIN}",addr=0x46080000,force-raw=on \
        -semihosting \
        -kernel "${KERNEL}" \
    < /dev/null 2>&1)"
QEMU_RC=$?
set -e

printf '%s\n' "${RAW_OUTPUT}"

# ===========================================================================
# aL2.4b STRIP-THEN-ASSERT (proposal SS2.6 -- the host profile is provably NOT
# weakened): the guest's serial leaves the trapped PL011 ONLY as framed
# `guestlog: <hex>` lines (the Kani-proven injection-proof codec), so:
#   * HOST  = the raw stream with the guestlog-framed lines stripped; EVERY
#     existing guard below runs over ${OUTPUT} = HOST BYTE-IDENTICALLY (the
#     guard block's diff against the pre-aL2.4b script is zero -- machine-
#     checkable in review);
#   * GUEST = the decoded guestlog payload byte-stream (the in-guest chain's
#     own serial output), judged ONLY by the NEW guest guard set further down.
# ===========================================================================
OUTPUT="$(printf '%s\n' "${RAW_OUTPUT}" | grep -v '^guestlog: ' || true)"
# Decode the framed guest serial: concatenate every `guestlog:` frame's hex
# payload, then hex -> bytes. Prefer xxd (the boot container apt-installs it);
# fall back to a portable `printf '%b'` over `\xNN` escapes so a future minimal
# image without the xxd package still decodes (the guest stream is printable
# ASCII + newlines -- no NULs -- so the escape form is exact).
GUEST_HEX="$(printf '%s\n' "${RAW_OUTPUT}" | grep '^guestlog: ' | sed 's/^guestlog: //' | tr -d '\n' || true)"
if command -v xxd >/dev/null 2>&1; then
  GUEST_STREAM="$(printf '%s' "${GUEST_HEX}" | xxd -r -p || true)"
else
  # Fallback without xxd: emit one byte per hex pair via `printf '\xHH'` (the
  # FORMAT-string escape, NOT %b -- bash's %b does NOT decode \xHH). Each format
  # is exactly two hex digits, so no decoded byte can be mis-read as a % spec.
  decode_hex() {
    local h="$1" i
    for ((i = 0; i < ${#h}; i += 2)); do
      printf "\\x${h:i:2}"
    done
  }
  GUEST_STREAM="$(decode_hex "${GUEST_HEX}" || true)"
fi

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
    # M30 is no longer the top-level grep (M31 displaced it as the cumulative tail);
    # assert it directly so the M30 -> M31 order stays fail-closed + traceable.
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M30: infer-transport OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'M30: infer-transport OK' missing (M30 displaced/regressed)" >&2
        exit 1
    fi
    # M31 GUARDS (proposal §7 -- house order: skip-reject, positive-require,
    # by-name rejects, lane cross-pin, inherited tripwires, leak negatives,
    # strip-then-reject). This lane ATTACHES the chardev harness, so the
    # mock-lane e2e (the keyless wire-ERR check + the chunked MAC'd mock
    # exchange + the M25 fold) is REQUIRED in full. The LIVE half
    # (backend=ANTHROPIC-LIVE) is stage C: operator-gated, NEVER on this lane.
    #
    # (§7.1) Skip-variant reject BY NAME: an attached lane never takes the
    # graceful no-peer skip (the skip variant deliberately LACKS the backend
    # token, so it can also never satisfy the top-level cumulative grep).
    if printf '%s' "${OUTPUT}" | grep -qF -- 'M31: infer-e2e OK (no host peer, skipped)'; then
        echo "[run-aarch64] FAIL -- M31 ran in SKIP mode (no host peer) but this lane attaches the chardev harness -- the inference-adapter wire e2e was NOT exercised" >&2
        exit 1
    fi
    # (§7.2) POSITIVE-REQUIRE the full infer witness: the proposal-§7 verbatim
    # token set (every flag earned, every honesty token literal) + the exact
    # deterministic wire-evidence tail (2 chunks + exactly 1 verified PENDING).
    if ! printf '%s' "${OUTPUT}" | grep -qE -- 'infer: backend=MOCK-DETERMINISTIC context=M13-SCALAR-RECALL recalls=0x[0-9a-f]+ prompt-len=0x[0-9a-f]+ resp-len=0x[0-9a-f]+ resp-digest=0x[0-9a-f]{32} req-id=0x[0-9a-f]{16} stop=END-TURN wire-err-handled=0x0*1 fold=M25-TRANSCRIPT key=CAPREF-HOST-CUSTODIED host=RESIDUAL-TCB ambient=ZERO-IN-GUEST sec=ASSUMED-FROM-LITERATURE chunks=0x0*2 pending=0x0*1'; then
        echo "[run-aarch64] FAIL -- M31 marker present but the real e2e witness 'infer: backend=MOCK-DETERMINISTIC context=M13-SCALAR-RECALL recalls=.. prompt-len=.. resp-len=.. resp-digest=.. req-id=.. stop=END-TURN wire-err-handled=0x1 fold=M25-TRANSCRIPT key=CAPREF-HOST-CUSTODIED host=RESIDUAL-TCB ambient=ZERO-IN-GUEST sec=ASSUMED-FROM-LITERATURE chunks=0x2 pending=0x1' was NOT seen (hollow M31 pass)" >&2
        exit 1
    fi
    # (§7.3/§7.4) By-name rejects (case-insensitive, near the M31 lines): the
    # LIVE lane's evidence class -- and any live/real/network vocabulary -- is
    # structurally banned from the mock lane, so a forged live claim can never
    # enter the cumulative chain.
    if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M31:|infer:|infer-dump:)' | grep -qiE -- 'backend=ANTHROPIC-LIVE|(^|[^[:alnum:]])real|(^|[^[:alnum:]])live|network|TLS|HTTPS|cloud|api[- ]key'; then
        echo "[run-aarch64] FAIL -- M31 marker/witness carries a LIVE-lane token ('ANTHROPIC-LIVE'/'real'/'live'/'network'/'TLS'/'HTTPS'/'cloud'/'api-key') -- the mock lane never borrows the live lane's evidence class; the live half is stage C, operator-gated (M31 proposal §7.3/§7.4)" >&2
        exit 1
    fi
    # (§7.5) Inherited tripwire: a verified INFER_PENDING is a poll-budget
    # reset, NEVER a completion; reject any streaming/pending-completion
    # overclaim vocabulary outright.
    if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M31:|infer:)' | grep -qiE -- 'pending[- ]complete|streamed|streaming'; then
        echo "[run-aarch64] FAIL -- M31 witness claims streaming/pending-completion semantics -- INFER_PENDING is liveness plumbing, chunked delivery is reassembly of a COMPLETED response (M31 proposal §2f)" >&2
        exit 1
    fi
    # (§7.7) Raw-leak tripwires (the encode-before-write invariant is
    # GUARD-CHECKED, not trusted): no raw ESC byte anywhere in guest serial,
    # and every infer-dump line matches the strict lowercase-hex grammar.
    if printf '%s' "${OUTPUT}" | grep -q -- $'\x1b'; then
        echo "[run-aarch64] FAIL -- a raw ESC (0x1b) byte reached guest serial -- the M31 encode-before-write invariant is broken (M31 proposal §6 raw-leak tripwire)" >&2
        exit 1
    fi
    if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])infer-dump:' | grep -vE -- '^infer-dump: req-id=0x[0-9a-f]{16} seq=0x[0-9a-f]{16} resp-hex=[0-9a-f]+$' | grep -q .; then
        echo "[run-aarch64] FAIL -- an infer-dump line violates the strict 'infer-dump: req-id=0x<16hex> seq=0x<16hex> resp-hex=<lowercase-hex>' grammar -- model-derived bytes must cross serial ONLY hex-encoded (M31 proposal §6)" >&2
        exit 1
    fi
    # (§7.8) Strip-then-reject overclaims: strip the declared M31 structured
    # tokens FIRST, then case-insensitively reject the intelligence/semantics/
    # security overclaim vocabulary near the M31 lines -- the mock lane proves
    # PLUMBING, not intelligence (the M29/M30 global rejects stay in force).
    if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M31:|infer:|infer-dump:)' \
         | sed -e 's/MOCK-DETERMINISTIC//g' -e 's/CAPREF-HOST-CUSTODIED//g' \
               -e 's/RESIDUAL-TCB//g' -e 's/ZERO-IN-GUEST//g' \
               -e 's/M13-SCALAR-RECALL//g' -e 's/M25-TRANSCRIPT//g' \
               -e 's/ASSUMED-FROM-LITERATURE//g' -e 's/END-TURN//g' \
         | grep -qiE -- 'understood|reasoned|intelligen|knows|learned|validated|evaluated|secure|confidential|private|authenticated-human|agi'; then
        echo "[run-aarch64] FAIL -- M31 marker/witness carries an overclaim ('understood'/'reasoned'/'intelligen*'/'knows'/'learned'/'validated'/'evaluated'/'secure'/'confidential'/'private'/'authenticated-human'/'agi') -- M31's mock lane proves plumbing (recall -> prompt -> deterministic transform -> digest fold), never intelligence or semantics (M31 proposal §7.8)" >&2
        exit 1
    fi
    # M31 is no longer the top-level grep (M38 displaced it as the cumulative tail);
    # assert it directly so the M31 -> M38 order stays fail-closed + traceable (the
    # demote-not-delete displacement discipline).
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M31: infer-e2e OK backend=MOCK-DETERMINISTIC'; then
        echo "[run-aarch64] FAIL -- final marker present but 'M31: infer-e2e OK backend=MOCK-DETERMINISTIC' missing (M31 displaced/regressed)" >&2
        exit 1
    fi

    # M33 (stage B) GUARDS -- the provenance-lineage PERSISTED SIGNED HEAD
    # (proposal §8; closes #91 -- mirroring the x86_64 lane). This is BOOT 1 of the
    # two-boot cross-boot witness: the signed head is written+flushed to disk
    # (head-persisted=0x1) but nothing has survived a reboot yet on this FRESH disk
    # (head-reboot-survived=0x0). BOOT 2 (below, after the guest guards) reboots
    # against the SAME M33 sectors and requires survived=0x1. The HOST kernel's
    # prov-sig line is the un-framed one in ${OUTPUT} (the in-guest aL2.4b leg is
    # hex-framed + diskless, so it never confuses this grep).
    M33_SIG_RE='prov-sig: sig=LMS-SHA256-W4-H10 conformance=RFC8554 kat=RFC8554-PASS sha256-kat=FIPS180-4-PASS root=0x[0-9a-f]{16} i-id=0x[0-9a-f]{8} head=0x[0-9a-f]{16} leaf-idx=0x[0-9a-f]+ sig-verified=0x0*1 tamper-rejected-ots=0x0*1 tamper-rejected-merkle=0x0*1 head-persisted=0x0*1 head-reboot-survived='
    M33_SIG_TAIL=' attest-decoded=0x0*1 attest-digest=0x[0-9a-f]{16} measure=SELF-NO-HW-ROOT selfmeasure=UNATTESTED-LOADER key=SIMULATED-ENROLLED-CI-CUSTODIED exclusivity=OFF-PLATFORM-ONLY state=SIMULATED-REUSE-OK-NO-SECURITY splitview=UNDETECTED-NO-WITNESS-QUORUM sidechannel=NOT-CLAIMED sec=ASSUMED-FROM-LITERATURE'
    if ! printf '%s' "${OUTPUT}" | grep -qE -- "${M33_SIG_RE}0x0${M33_SIG_TAIL}"; then
        echo "[run-aarch64] FAIL -- M33 boot-1 marker present but the full 'prov-sig: ...' stage-B witness (root/i-id/head/leaf-idx + every earned flag =0x1 + BOTH regional tamper tokens + head-persisted=0x1 head-reboot-survived=0x0 + every honesty token) was NOT seen (hollow M33 pass)" >&2
        exit 1
    fi
    M33_BOOT1_HEAD="$(printf '%s' "${OUTPUT}" | grep -oE 'prov-sig:.*' | grep -oE 'head=0x[0-9a-f]{16}' | head -1)"
    if [[ -z "${M33_BOOT1_HEAD}" ]]; then
        echo "[run-aarch64] FAIL -- could not capture boot-1 M33 head= for the cross-boot check" >&2
        exit 1
    fi
    if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M33:|prov-sig:)' \
         | grep -qiE -- 'conformance=NONE|Ed25519|curve25519|P-256|secp|measured[- ]boot|attested[- ]boot|non[- ]falsifiable|chain[- ]of[- ]trust|RTM|TPM'; then
        echo "[run-aarch64] FAIL -- M33 line carries a disqualified-family / measure-overclaim / D1-fallback token (Ed25519/curve25519/P-256/measured-boot/RTM/TPM/conformance=NONE) -- rejected by name (proposal §8.3)" >&2
        exit 1
    fi
    if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M33:|prov-sig:)' \
         | sed -e 's/LMS-SHA256-W4-H10//g' -e 's/RFC8554-PASS//g' -e 's/RFC8554//g' \
               -e 's/FIPS180-4-PASS//g' -e 's/SELF-NO-HW-ROOT//g' -e 's/UNATTESTED-LOADER//g' \
               -e 's/SIMULATED-ENROLLED-CI-CUSTODIED//g' -e 's/OFF-PLATFORM-ONLY//g' \
               -e 's/SIMULATED-REUSE-OK-NO-SECURITY//g' -e 's/UNDETECTED-NO-WITNESS-QUORUM//g' \
               -e 's/NOT-CLAIMED//g' -e 's/ASSUMED-FROM-LITERATURE//g' \
         | grep -qiE -- 'unforgeable|tamper[- ]proof|provably[- ]secure|only[- ]the[- ]operator|reproducible|hardware[- ]root|secure[- ]boot|authenticated[- ]human|trusted[- ]boot|never[- ]reuse'; then
        echo "[run-aarch64] FAIL -- M33 line carries an overclaim after stripping the declared tokens (proposal §8.7)" >&2
        exit 1
    fi
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M33: prov-lineage OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'M33: prov-lineage OK' missing (M33 displaced/regressed)" >&2
        exit 1
    fi

    # M32 (stage B) GUARDS -- the kernel LOCAL-ORGAN receive path (#90), mirroring
    # the x86_64 lane. The HOST leg is the un-framed lines in ${OUTPUT} (the
    # guest's own channel-less infer-local-skip lives inside guestlog: frames,
    # stripped from ${OUTPUT}). The chardev harness IS attached, so the local
    # organ MUST have been received over the wire + fed to the M38 conductor.
    #
    # (1) Skip-reject on the attached HOST leg.
    if printf '%s' "${OUTPUT}" | grep -qE -- '(^|[^[:alnum:]])infer-local-skip:'; then
        echo "[run-aarch64] FAIL -- M32 ran in SKIP mode (infer-local-skip) on the HOST leg but this lane attaches the chardev harness -- the local-organ receive was NOT exercised" >&2
        exit 1
    fi
    # (2) Positive-require the FULL one-line infer-local witness (honest stand-in
    # tokens; NEVER a vendored-C/live claim at this stage), peer=0x03, flags =0x1.
    if ! printf '%s' "${OUTPUT}" | grep -qE -- 'infer-local: backend=LOCAL-STANDIN engine=NONE-DETERMINISTIC-STANDIN local-organ=DETERMINISTIC-STANDIN peer=0x03 debt=SOVEREIGNTY-OPEN-B3 memsafety=SAFE-RUST-STANDIN weights=NONE-NO-MODEL-LOADED received=OVER-M32-SEAM fed-to=M38-CONDUCTOR req-id=0x[0-9a-f]{16} resp-len=0x[0-9a-f]+ resp-digest=0x[0-9a-f]{32} chunks=0x0*2 pending=0x0*1 mac-verified=0x0*1 peer-bound=0x0*1 guestpath=RECEIVED-OVER-WIRE live-inference=NOT-CLAIMED key=CAPREF-HOST-CUSTODIED host=RESIDUAL-TCB ambient=ZERO-IN-GUEST sec=ASSUMED-FROM-LITERATURE'; then
        echo "[run-aarch64] FAIL -- M38 conductor witnessed but the real 'infer-local: backend=LOCAL-STANDIN .. peer=0x03 .. received=OVER-M32-SEAM ..' witness was NOT seen on the HOST leg (hollow M32 pass)" >&2
        exit 1
    fi
    # (3) THE CROSS-PROCESS LEG (loopback/fixture killer): the guest-witnessed
    # infer-local resp-digest MUST string-equal the HOST peer's xport-local
    # resp-digest (SEPARATE ${HARNESS_OUT} capture stream, peer_id=0x03).
    GUEST_LOCAL_DIG="$(printf '%s\n' "${OUTPUT}" | grep -oE '^infer-local: .*resp-digest=0x[0-9a-f]{32}' | grep -oE 'resp-digest=0x[0-9a-f]{32}' | head -1)"
    HOST_LOCAL_DIG="$(printf '%s\n' "${HARNESS_OUT}" | grep -oE '^xport-local: .*resp-digest=0x[0-9a-f]{32}' | grep -oE 'resp-digest=0x[0-9a-f]{32}' | head -1)"
    if [[ -z "${GUEST_LOCAL_DIG}" || -z "${HOST_LOCAL_DIG}" ]]; then
        echo "[run-aarch64] FAIL -- M32 cross-process leg has no input -- guest infer-local digest='${GUEST_LOCAL_DIG}' host xport-local digest='${HOST_LOCAL_DIG}'" >&2
        exit 1
    fi
    if [[ "${GUEST_LOCAL_DIG}" != "${HOST_LOCAL_DIG}" ]]; then
        echo "[run-aarch64] FAIL -- M32 CROSS-PROCESS mismatch -- guest infer-local ${GUEST_LOCAL_DIG} != host xport-local ${HOST_LOCAL_DIG} (loopback/fixtured, not received over the wire)" >&2
        exit 1
    fi
    if ! printf '%s\n' "${HARNESS_OUT}" | grep -qE -- '^xport-local: peer=0x03 local-organ=DETERMINISTIC-STANDIN '; then
        echo "[run-aarch64] FAIL -- the host peer did NOT emit an 'xport-local: peer=0x03 ..' line -- the M32 local leg was not served under the distinct local peer identity" >&2
        exit 1
    fi
    # (4) By-name rejects near the M32 lines: no live/real-engine/vendored-C claim
    # at this stage, no loopback/fixture vocabulary (stand-in only).
    if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(infer-local:|xport-local:)' | grep -qiE -- 'engine=PURE-RUST|backend=ANTHROPIC-LIVE|live-inference=CLAIMED|loopback|fixture|canned|replay|(^|[^[:alnum:]])real-engine'; then
        echo "[run-aarch64] FAIL -- M32 infer-local/xport-local carries a by-name reject token (real-engine/live/loopback) -- stage B serves a DETERMINISTIC STAND-IN only" >&2
        exit 1
    fi

    # M39 GUARDS -- the in-kernel EXPERIENCE-CORPUS seam (Phase-1 dataset moat),
    # mirroring the x86_64 lane. The M17 consolidation CURATES real outcomes into a
    # SEPARATE tamper-evident `corpus_head`. House order: skip-reject, positive-require
    # [anti-hollow: REAL records flowed], anti-overclaim, direct-assert. M39 displaces
    # NOTHING (M38 below stays the cumulative tail; the corpus folds on its OWN lane).
    #
    # (1) Skip-reject: honest-skip-is-FAILURE on the agent lane (the substrate skip
    # form may NOT carry the marker here -- the consolidation seam IS admitted).
    if printf '%s' "${OUTPUT}" | grep -qF -- 'M39: corpus OK (substrate profile, agent organ skipped)'; then
        echo "[run-aarch64] FAIL -- M39 ran in SKIP mode (substrate form) on an AGENT lane -- the corpus consolidation seam was NOT exercised" >&2
        exit 1
    fi
    # (2) Positive-require the FULL one-line `corpus:` witness: earned round-trip flags
    # (clean/inclusion/tamper-caught/predicate-two-sided =0x1), a records count, the
    # accept/reject counts, kan_active=0, AND every honesty token (so a hollow or
    # overclaiming marker FAILS).
    # inc-3: the witness now also carries the DURABILITY tokens. BOOT 1 (this OUTPUT) is
    # the FRESH-region control: present=0x1 + persisted=0x1 but reboot-survived=0x0 +
    # head-matches=0x0 + records-disk=0x0 (nothing survives a fresh region -- the anti-
    # hollow negative control). BOOT 2 (below) requires survived=0x1 + a matching head.
    if ! printf '%s' "${OUTPUT}" | grep -qE -- 'corpus: head=0x[0-9a-f]{16} records=0x[0-9a-f]+ accepted=0x[0-9a-f]+ rejected=0x[0-9a-f]+ clean=0x0*1 inclusion=0x0*1 tamper-caught=0x0*1 predicate-two-sided=0x0*1 kan_active=0x0+ corpus-present=0x0*1 corpus-persisted=0x0*1 corpus-reboot-survived=0x0+ corpus-head-matches=0x0+ corpus-head-disk=0x[0-9a-f]{16} corpus-records-disk=0x0+ corpus-records-total=0x[0-9a-f]+ durability=TORN-WRITE-SAFE-PING-PONG-FNV head-integrity=M22-FOLD-VERBATIM lms-signature=NONE-THIS-INCREMENT corpus=PROVENANCE-SKELETON curation=PREDICATE-DECLARED-NOT-LEARNED training=NONE-PHASE2-GATED reuse=M22-FOLD-VERBATIM sec=ASSUMED-FROM-LITERATURE'; then
        echo "[run-aarch64] FAIL -- M39 marker present but the real round-trip + durability witness (.. corpus-present=0x1 corpus-persisted=0x1 corpus-reboot-survived=0x0 corpus-head-matches=0x0 corpus-head-disk=.. corpus-records-disk=0x0 corpus-records-total=.. durability=TORN-WRITE-SAFE-PING-PONG-FNV ..) was NOT seen on BOOT 1 (hollow M39 pass or a fresh region falsely claiming survival)" >&2
        exit 1
    fi
    # (3) ANTI-HOLLOW: the records-appended count MUST be > 0 (a real consolidation
    # append genuinely flowed -- not a zero-record head printed by a stub).
    CORPUS_LINE="$(printf '%s\n' "${OUTPUT}" | grep -E -- '^corpus: head=0x' | head -1)"
    M39_REC_HEX="$(printf '%s' "${CORPUS_LINE}" | sed -E 's/.* records=0x0*([0-9a-f]+) .*/\1/')"
    if [[ -z "${M39_REC_HEX}" ]] || (( 16#${M39_REC_HEX} < 1 )); then
        echo "[run-aarch64] FAIL -- M39 records=0x${M39_REC_HEX} < 0x1 (no real corpus record flowed -- an anti-hollow stub)" >&2
        exit 1
    fi
    # (3b) DURABILITY anti-hollow: capture BOOT 1's persisted corpus-head-disk (for the
    # cross-boot check in BOOT 2) + records-total (the accumulated count, > 0).
    CORPUS_BOOT1_HEAD="$(printf '%s' "${CORPUS_LINE}" | grep -oE 'corpus-head-disk=0x[0-9a-f]{16}' | head -1)"
    CORPUS_BOOT1_TOTAL_HEX="$(printf '%s' "${CORPUS_LINE}" | sed -E 's/.* corpus-records-total=0x0*([0-9a-f]+) .*/\1/')"
    if [[ -z "${CORPUS_BOOT1_HEAD}" ]]; then
        echo "[run-aarch64] FAIL -- could not capture BOOT 1 corpus-head-disk for the M39 cross-boot check" >&2
        exit 1
    fi
    if [[ -z "${CORPUS_BOOT1_TOTAL_HEX}" ]] || (( 16#${CORPUS_BOOT1_TOTAL_HEX} < 1 )); then
        echo "[run-aarch64] FAIL -- M39 corpus-records-total=0x${CORPUS_BOOT1_TOTAL_HEX} < 0x1 on BOOT 1 (nothing accumulated -- an anti-hollow persist stub)" >&2
        exit 1
    fi
    # (4) Anti-overclaim: no live-learning / training-happened / text-bearing claim on
    # the M39 lines (the honest tokens spell the NEGATIONS, so reject only POSITIVE
    # overclaims).
    if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M39:|corpus:)' | grep -qiE -- 'kan_active=0x0*1|training=(ACTIVE|DONE|RAN)|learning=ACTIVE|(^|[^[:alnum:]])trained|weights-updated|is-text|text-stored'; then
        echo "[run-aarch64] FAIL -- M39 marker/witness carries an overclaim (live learning / training-happened / text-stored) -- the corpus trains nothing" >&2
        exit 1
    fi
    # (5) Direct-assert the marker is present (M39 is not the top-level grep -- M38
    # displaces it as the cumulative tail).
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M39: corpus OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'M39: corpus OK' missing (M39 displaced/regressed)" >&2
        exit 1
    fi

    # M40 GUARDS -- the verified LEXICAL RECALL-SCORING leaf (research-skill
    # foundation), mirroring the x86_64 lane. The BM25-family no-float leaf scores a
    # DETERMINISTIC query->ranking + the REAL organ recall runs on the SAME leaf's IDF.
    # House order: skip-reject, positive-require [anti-hollow: a real query scored + the
    # real organ hit], anti-overclaim [LEXICAL never semantic], direct-assert. M40 folds
    # on NO head (M38 below stays the cumulative tail).
    #
    # (1) Skip-reject: honest-skip-is-FAILURE on the agent lane.
    if printf '%s' "${OUTPUT}" | grep -qF -- 'M40: recall OK (substrate profile, agent organ skipped)'; then
        echo "[run-aarch64] FAIL -- M40 ran in SKIP mode (substrate form) on an AGENT lane -- the lexical recall leaf was NOT exercised" >&2
        exit 1
    fi
    # (2) Positive-require the FULL one-line `recall:` witness: earned scoring flags
    # (ranking/monotone/bounded/canon/organ =0x1), a scored count, a real top hit, AND
    # every honesty token (retrieval=LEXICAL-BM25-NO-FLOAT, semantic=0x0, embedding=NONE)
    # so a hollow or semantic-overclaiming marker FAILS.
    if ! printf '%s' "${OUTPUT}" | grep -qE -- 'recall: top-id=0x[0-9a-f]+ top-score=0x[0-9a-f]+ scored=0x[0-9a-f]+ ranking-ok=0x0*1 monotone-ok=0x0*1 bounded-ok=0x0*1 canon-ok=0x0*1 organ-ok=0x0*1 semantic=0x0+ retrieval=LEXICAL-BM25-NO-FLOAT recall=DETERMINISTIC idf-source=VERIFIED-LEAF k1=0x4b0 b=0x2ee embedding=NONE weights=NONE-FROZEN-FIXED-POINT sec=ASSUMED-FROM-LITERATURE'; then
        echo "[run-aarch64] FAIL -- M40 marker present but the real scoring witness (.. ranking-ok=0x1 .. organ-ok=0x1 semantic=0x0 retrieval=LEXICAL-BM25-NO-FLOAT ..) was NOT seen (hollow M40 pass or a semantic overclaim)" >&2
        exit 1
    fi
    # (3) ANTI-HOLLOW: the scored count MUST be > 0 (a real query was genuinely scored).
    RECALL_LINE="$(printf '%s\n' "${OUTPUT}" | grep -E -- '^recall: top-id=0x' | head -1)"
    M40_SCORED_HEX="$(printf '%s' "${RECALL_LINE}" | sed -E 's/.* scored=0x0*([0-9a-f]+) .*/\1/')"
    if [[ -z "${M40_SCORED_HEX}" ]] || (( 16#${M40_SCORED_HEX} < 1 )); then
        echo "[run-aarch64] FAIL -- M40 scored=0x${M40_SCORED_HEX} < 0x1 (no real candidate was scored -- an anti-hollow stub)" >&2
        exit 1
    fi
    # (4) Anti-overclaim: no semantic / embedding / learned retrieval claim on the M40
    # lines (the honest tokens spell the NEGATIONS, so reject only POSITIVE overclaims).
    if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M40:|recall:)' | grep -qiE -- 'semantic=0x0*1|embedding=(LEXICAL|BM25|ACTIVE|USED|ON|VECTOR)|retrieval=SEMANTIC|understood|reasoned|meaning-vector|learned-weights|weights-updated'; then
        echo "[run-aarch64] FAIL -- M40 marker/witness carries an overclaim (semantic/embedding/learned retrieval) -- the recall is LEXICAL BM25 term-overlap only" >&2
        exit 1
    fi
    # (5) Direct-assert the marker is present (M40 is not the top-level grep).
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M40: recall OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'M40: recall OK' missing (M40 displaced/regressed)" >&2
        exit 1
    fi

    # M38 (stage B) GUARDS (proposal §8 -- house order, mirroring the x86_64 lane):
    # the guest drives the verified organ-loop over the cap chokepoint; the marker
    # is the NEW cumulative tail. M38 displaces NOTHING below it (every prior fold
    # head byte-identical -- the conductor folds on its OWN lane). The HOST-leg
    # conduct lines are the un-framed ones in ${OUTPUT}; the in-guest leg's are
    # hex-framed (asserted in the GUEST guard set below).
    #
    # (§8.1) Skip-reject: honest-skip-is-FAILURE, never green-by-omission.
    if printf '%s' "${OUTPUT}" | grep -qiE -- 'M38: conductor OK \(.*(skip|single organ|always-accept)'; then
        echo "[run-aarch64] FAIL -- M38 ran in a skipped/degenerate variant -- honest-skip-is-FAILURE (proposal §8.1)" >&2
        exit 1
    fi
    # (§8.2) Positive-require the FULL one-line conductor witness (every honest
    # token + flag), AND organs>=0x2 AND revise-cycles>=0x1. NECESSARY-not-
    # sufficient; the load-bearing check is the §8.6 cross-process recompute below.
    if ! printf '%s' "${OUTPUT}" | grep -qE -- 'conduct: head=0x[0-9a-f]{16} turns=0x[0-9a-f]+ organs=0x[0-9a-f]+ roles=[TWV]+ organ-seq=0x[0-9a-f]+ verdict=ACCEPT accept-at=0x[0-9a-f]+ revise-cycles=0x[0-9a-f]+ fold-verified=0x0*1 tamper-caught=0x0*1 organ-calls=0x[0-9a-f]+ logical-ticks=0x[0-9a-f]+ attested=0x0*1 prov-tag=0x4 policy=DISCRETE-HAND-WRITTEN-NOT-LEARNED learning=DORMANT retrieval=LEXICAL-NOT-SEMANTIC external-organ=MOCK-IN-CI local-organ=RECEIVED-M32-DETERMINISTIC-STANDIN verifier=CI-DISCRETE-VERDICT m18-gate=ADMISSION-ONLY-INERT-IN-MOCK cost=HONEST-ACCOUNTED-TOKENED cost-metric=LOGICAL-SURROGATE-NOT-WALLCLOCK orchestration=RAG-AGENTS-NOT-NEW-PARADIGM live[+]web=DISPATCH-ONLY novelty=VERIFIED-PROVENANCE-SOVEREIGN-WRAPPER generativity=OPEN-FRONTIER realtime=NOT-CLAIMED benchmark=NOT-CLAIMED stub-resistance=HOST-RECOMPUTE-FROM-INDEPENDENT-TRACE host=RESIDUAL-TCB sec=ASSUMED-FROM-LITERATURE'; then
        echo "[run-aarch64] FAIL -- M38 marker present but the full one-line 'conduct: head=.. ..' witness (every honest token + flag) was NOT seen (hollow M38 pass)" >&2
        exit 1
    fi
    CONDUCT_LINE="$(printf '%s\n' "${OUTPUT}" | grep -E -- '^conduct: head=0x' | head -1)"
    M38_ORG_HEX="$(printf '%s' "${CONDUCT_LINE}" | sed -E 's/.* organs=0x0*([0-9a-f]+) .*/\1/')"
    if [[ -z "${M38_ORG_HEX}" ]] || (( 16#${M38_ORG_HEX} < 2 )); then
        echo "[run-aarch64] FAIL -- M38 organs=0x${M38_ORG_HEX} < 0x2 (a degenerate single-organ stub; the witness requires a measured >=2-organ sequence)" >&2
        exit 1
    fi
    M38_RC_HEX="$(printf '%s' "${CONDUCT_LINE}" | sed -E 's/.* revise-cycles=0x0*([0-9a-f]+) .*/\1/')"
    if [[ -z "${M38_RC_HEX}" ]] || (( 16#${M38_RC_HEX} < 1 )); then
        echo "[run-aarch64] FAIL -- M38 revise-cycles=0x${M38_RC_HEX} < 0x1 (an always-accept stub; the witness requires a measured REVISE->ACCEPT cycle)" >&2
        exit 1
    fi
    # (§8.6) THE LOAD-BEARING CROSS-PROCESS INDEPENDENT-RECOMPUTE LEG (the loopback/
    # fixture killer): feed the GUEST's OWN emitted host-leg `conduct-step:` trace
    # into the host conductor binary (--recompute-from-trace), which INDEPENDENTLY
    # re-folds the M22 lineage via the SAME verified leaf in a SEPARATE process, and
    # string-equal the host-recomputed head against the guest-emitted conduct: head.
    GUEST_HEAD="$(printf '%s' "${CONDUCT_LINE}" | grep -oE 'head=0x[0-9a-f]{16}' | head -1)"
    if [[ -z "${GUEST_HEAD}" ]]; then
        echo "[run-aarch64] FAIL -- could not extract the guest-emitted 'conduct: head=0x<hex16>' (the conductor produced no head)" >&2
        exit 1
    fi
    CONDUCT_TRACE="$(printf '%s\n' "${OUTPUT}" | grep -E -- '^conduct-step: ')"
    if [[ -z "${CONDUCT_TRACE}" ]]; then
        echo "[run-aarch64] FAIL -- the host-leg emitted NO 'conduct-step:' trace lines -- the §8.6 independent host-recompute has no input" >&2
        exit 1
    fi
    RECOMPUTE_OUT="$(printf '%s\n' "${CONDUCT_TRACE}" | "${CONDUCTOR_HOST_BIN}" --recompute-from-trace 2>/dev/null || true)"
    HOST_HEAD="$(printf '%s' "${RECOMPUTE_OUT}" | grep -oE 'head=0x[0-9a-f]{16}' | head -1)"
    if [[ -z "${HOST_HEAD}" ]]; then
        echo "[run-aarch64] FAIL -- the host conductor recompute produced no head from the guest trace (the §8.6 cross-process leg failed to run): ${RECOMPUTE_OUT}" >&2
        exit 1
    fi
    if [[ "${GUEST_HEAD}" != "${HOST_HEAD}" ]]; then
        echo "[run-aarch64] FAIL -- CROSS-PROCESS mismatch -- guest-emitted conduct head (${GUEST_HEAD}) != host independent-recompute head (${HOST_HEAD}) from the guest's OWN trace; the lineage is forged/fixtured (proposal §8.6 -- the loopback killer)" >&2
        exit 1
    fi
    # (§8.3) By-name rejects near the M38 lines.
    if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(conduct:|conduct-step:|M38:)' | grep -qiE -- 'policy=LEARNED|policy=ES|policy=CMA|KAN_ACTIVE=true|backend=ANTHROPIC-LIVE|verifier=LEARNED|verifier=CLASSIFIER|embedding|cosine|loopback|fixture|canned|replay|(^|[^[:alnum:]])real-infer'; then
        echo "[run-aarch64] FAIL -- M38 marker/witness carries a by-name reject token (learned/ES/CMA/live/embedding/cosine/loopback/fixture/replay) -- the policy is HAND-WRITTEN + the verifier is the discrete CI verdict (proposal §8.3)" >&2
        exit 1
    fi
    # (§8.5) Inherited tripwire: every host-leg conduct-step line is lowercase-hex ONLY.
    if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])conduct-step:' | grep -vE -- '^conduct-step: turn=0x[0-9a-f]+ role=0x[0-9a-f]+ organ=0x[0-9a-f]+ verdict=0x[0-9a-f]+ organ-calls=0x[0-9a-f]+ t-logical=0x[0-9a-f]+$' | grep -q .; then
        echo "[run-aarch64] FAIL -- a conduct-step line violates the strict lowercase-hex grammar -- the conductor trace must cross serial ONLY hex-encoded (proposal §8.5)" >&2
        exit 1
    fi
    # (§8.7) Strip-then-reject: strip token VALUES, then reject residual claim words.
    if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(conduct:|M38:)' \
         | sed -E 's/[a-z+-]+=[A-Za-z0-9+/.:_-]+//g' \
         | grep -qiE -- 'learned|trained|intelligen|understood|generaliz|benchmark|SOTA|real-time|semantic|cosine|float|embedding'; then
        echo "[run-aarch64] FAIL -- a residual claim word (learned/trained/intelligen/understood/generaliz/benchmark/SOTA/real-time/semantic/float/embedding) survives token-stripping near the M38 lines (proposal §8.7 razor)" >&2
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

    # =======================================================================
    # aL2.4b: the FULL-KERNEL EL1 GUEST gate (proposal SS2.6/SS3). This lane
    # ATTACHES the `-device loader` second kernel image, so the full launch
    # MUST run -- the marker is emitted by the MONITOR from witnessed evidence
    # only; the guest's framed text is corroborating. The strip-then-assert
    # split is already applied above: ${OUTPUT} == HOST (raw minus the
    # guestlog-framed lines, over which EVERY guard above ran byte-identical --
    # the diff-zero proof) and ${GUEST_STREAM} == the decoded guest serial.
    # =======================================================================

    # (1) Skip-variant reject BY NAME (the M20 anti-hollow idiom): an attached
    # lane must never take the graceful no-image/no-EL2 skip.
    if printf '%s' "${OUTPUT}" | grep -qF -- 'L2.4b: el1-kernel-guest OK (no guest image, skipped)'; then
        echo "[run-aarch64] FAIL -- aL2.4b ran in SKIP mode (no guest image) but this lane attaches '-device loader' -- the full-kernel-guest launch was NOT exercised" >&2
        exit 1
    fi
    if printf '%s' "${OUTPUT}" | grep -qF -- 'L2.4b: el1-kernel-guest OK (no EL2, skipped)'; then
        echo "[run-aarch64] FAIL -- aL2.4b ran in the (no EL2, skipped) form but this lane boots at EL2 -- the launch was NOT exercised" >&2
        exit 1
    fi
    # (2) POSITIVE-REQUIRE the MONITOR-WITNESSED evidence (non-text): the
    # guestboot/guestprobe/guestchain witnesses with EVERY =1 flag, the
    # doorbell count, hostram-faults=0, the confinement-probe fault witnessed +
    # the store dropped, and the in-guest discriminator (entryel=0xff,
    # guest-el2=0x0). A marker without these is a hollow pass.
    if ! printf '%s' "${OUTPUT}" | grep -qE -- 'guestboot: launched=1 carve=0x46000000\+32M nonce=0x[0-9a-f]+ doorbell=0x[0-9a-f]+ nonce-echo=1 final-wfi=1 hostram-faults=0 traps=0x[0-9a-f]+'; then
        echo "[run-aarch64] FAIL -- aL2.4b marker present but the monitor witness 'guestboot: launched=1 .. nonce-echo=1 final-wfi=1 hostram-faults=0 ..' was NOT seen (hollow L2.4b pass)" >&2
        exit 1
    fi
    if ! printf '%s' "${OUTPUT}" | grep -qE -- 'guestprobe: hostram-store stage2-fault=1 store-landed=0 probes=0x0*1'; then
        echo "[run-aarch64] FAIL -- aL2.4b adversarial case (a) NOT witnessed: 'guestprobe: hostram-store stage2-fault=1 store-landed=0 probes=0x1' absent (the confinement-probe fault / drop was not proven)" >&2
        exit 1
    fi
    if ! printf '%s' "${OUTPUT}" | grep -qE -- 'guestchain: contract-v0=1 entryel=0xff guest-el2=0x0 chain-done=1 m31-tail=1'; then
        echo "[run-aarch64] FAIL -- aL2.4b marker present but the chain-custody witness 'guestchain: contract-v0=1 entryel=0xff guest-el2=0x0 chain-done=1 m31-tail=1' was NOT seen" >&2
        exit 1
    fi
    # (3) POSITIVE-REQUIRE the honesty-token line verbatim (proposal SS3).
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'guest: guest=FULL-KERNEL-EL1 ram=STAGE2-CONFINED-32M loader=QEMU-DEVICE-LOADER gic=PASSTHROUGH-SOLE-GUEST timer=PHYS-PASSTHROUGH uart=TRAPPED-EMULATED virtio=OPEN-BUS-ABSENT guestlog=HEX-FRAMED-UNTRUSTED exit=WFI-PARK-DOORBELL smp=UP-ONLY rootfs=NONE timing=TCG-NON-CYCLE-ACCURATE cachemodel=TCG-COHERENT-UNTESTED realtime=NOT-CLAIMED'; then
        echo "[run-aarch64] FAIL -- aL2.4b honesty-token line absent or altered (the proposal SS3 verbatim token set is load-bearing)" >&2
        exit 1
    fi
    # (4) BY-NAME overclaim rejects near the marker/witnesses: confinement is
    # NOT yet an adversarially-proven sandbox (proposal SS5). Strip the legit
    # structured tokens FIRST (STAGE2-CONFINED-32M carries 'confined'), then
    # reject the forbidden vocabulary.
    if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(L2.4b:|guest:|guestboot:|guestchain:|guestprobe:)' \
         | sed -e 's/STAGE2-CONFINED-32M//g' -e 's/FULL-KERNEL-EL1//g' \
               -e 's/PASSTHROUGH-SOLE-GUEST//g' -e 's/PHYS-PASSTHROUGH//g' \
               -e 's/TRAPPED-EMULATED//g' -e 's/OPEN-BUS-ABSENT//g' \
               -e 's/HEX-FRAMED-UNTRUSTED//g' -e 's/WFI-PARK-DOORBELL//g' \
               -e 's/QEMU-DEVICE-LOADER//g' -e 's/smp=UP-ONLY//g' -e 's/NONE//g' \
               -e 's/TCG-NON-CYCLE-ACCURATE//g' -e 's/TCG-COHERENT-UNTESTED//g' \
               -e 's/NOT-CLAIMED//g' \
         | grep -qiE -- 'isolated|verified-guest|sandboxed|KVM-class|Firecracker-replacement|(^|[^[:alnum:]])SMP|cycle-accurate'; then
        echo "[run-aarch64] FAIL -- aL2.4b marker/witness carries an overclaim ('isolated'/'verified-guest'/'sandboxed'/'KVM-class'/'Firecracker-replacement'/'SMP'/'cycle-accurate') -- confinement is claimed only to the landed adversarial-case depth (proposal SS5)" >&2
        exit 1
    fi
    # (5) v1-IMPERSONATION reject: the aL2.4 'el2-guest OK' (the ~80-instruction
    # in-image stub) must never be able to stand in for the full-kernel guest.
    # The real marker carries 'el1-kernel-guest'; assert it is present (the
    # top-level grep is M31, so guard L2.4b directly).
    if ! printf '%s' "${OUTPUT}" | grep -qF -- 'L2.4b: el1-kernel-guest OK'; then
        echo "[run-aarch64] FAIL -- final marker present but 'L2.4b: el1-kernel-guest OK' missing (the full-kernel-guest launch regressed / did not reach the monitor verdict)" >&2
        exit 1
    fi
    # (6) HANG-class fast-red recognizer (never a silent timeout): a storm/stall
    # renders the named line; surface it as a hard fail if it ever appears.
    if printf '%s' "${OUTPUT}" | grep -qE -- 'L2.4b: HANG class=(storm|stall)'; then
        echo "[run-aarch64] FAIL -- aL2.4b guest hang: $(printf '%s' "${OUTPUT}" | grep -oE 'L2.4b: HANG class=[a-z]+.*' | head -1)" >&2
        exit 1
    fi

    # ---- The GUEST guard set (proposal SS2.6 partition over ${GUEST_STREAM}) ----
    # The in-guest chain's OWN serial (decoded from the injection-proof frames):
    # the must-prove rungs prove for real, the EL2-dependent rungs MUST take
    # their `(no EL2, skipped)` FORM, and a guest printing the REAL EL2 marker
    # is REJECTED (it would mean it was not actually deprivileged).
    if [[ -z "${GUEST_STREAM}" ]]; then
        echo "[run-aarch64] FAIL -- the decoded guest stream is EMPTY (no guestlog frames) -- the confined guest produced no serial" >&2
        exit 1
    fi
    # (G1) the in-guest discriminator + the positive handoff assertion.
    if ! printf '%s' "${GUEST_STREAM}" | grep -qF -- 'tb-boot: contract v0 OK'; then
        echo "[run-aarch64] FAIL -- GUEST: 'tb-boot: contract v0 OK' missing (the in-guest handoff did not validate)" >&2
        exit 1
    fi
    if ! printf '%s' "${GUEST_STREAM}" | grep -qE -- 'boot: entry-el=0x0*ff el2=0x0+'; then
        echo "[run-aarch64] FAIL -- GUEST: the 'boot: entry-el=0xff el2=0x0' discriminator missing (the guest did not enter via _tb_start deprivileged)" >&2
        exit 1
    fi
    # (G2) the MUST-PROVE rungs (real, any (skipped) rejected for these).
    for M in \
        'M1: traps OK' 'M3: mmu OK' 'M4: user/ring OK' 'M5: alloc OK' \
        'M6: frame alloc OK' 'M7: heap OK' 'M8: timer OK' 'M9: preempt OK' \
        'M14.2: blocking-recv OK' 'M22: provenance OK' 'M23: experience OK' \
        'M25: operator OK' 'M26: exit-telemetry OK' 'M28: operator-cmd OK' \
        'M29: khash-mac OK' 'M38: conductor OK'; do
        if ! printf '%s' "${GUEST_STREAM}" | grep -qF -- "${M}"; then
            echo "[run-aarch64] FAIL -- GUEST must-prove rung '${M}' missing from the in-guest chain" >&2
            exit 1
        fi
    done
    # (G3) the MUST-SKIP rungs: require the EXACT skip FORM, and REJECT the real
    # EL2 marker (the inverted-suspicion rule -- a deprivileged guest cannot have
    # proven its own EL2).
    for SK in \
        'L2.0: el2 OK (no EL2, skipped)' \
        'L2.1: stage2 OK (no EL2, skipped)' \
        'L2.2: el2-exits OK (no EL2, skipped)' \
        'L2.3: el2-trap OK (no EL2, skipped)' \
        'L2.4: el2-guest OK (no EL2, skipped)' \
        'L2.5: vgic OK (no EL2, skipped)' \
        'L2.6: smmu OK (no stage-2 SMMU, skipped)' \
        'M27: sched OK (no EL2, skipped)' \
        'M19: virtio OK (no device, skipped)' \
        'M20: persist OK (no disk, skipped)'; do
        if ! printf '%s' "${GUEST_STREAM}" | grep -qF -- "${SK}"; then
            echo "[run-aarch64] FAIL -- GUEST must-skip rung '${SK}' not in its required skip form (the in-guest acceptance profile rejects a wrong form)" >&2
            exit 1
        fi
    done
    # Reject a guest printing the REAL EL2/SMMU/M27 markers (deprivilege breach).
    for REAL in \
        'L2.0: el2 OK' 'L2.1: stage2 OK' 'L2.2: el2-exits OK' \
        'L2.3: el2-trap OK' 'L2.4: el2-guest OK' 'L2.5: vgic OK' \
        'M27: sched OK'; do
        # Count lines that match the marker but NOT the skip form: any such line
        # is a REAL (overclaiming) print.
        if printf '%s' "${GUEST_STREAM}" | grep -F -- "${REAL}" | grep -qvF -- '(no EL2, skipped)'; then
            echo "[run-aarch64] FAIL -- GUEST printed the REAL '${REAL}' (not the skip form) -- a deprivileged guest cannot prove its own EL2 (the inverted-suspicion rule)" >&2
            exit 1
        fi
    done
    # (G4) the in-guest tail MUST reach M31's skip + the semihosting-suppression
    # line (adversarial case (c): the guest did NOT semihost-exit the VM).
    if ! printf '%s' "${GUEST_STREAM}" | grep -qF -- 'M31: infer-e2e OK (no host peer, skipped)'; then
        echo "[run-aarch64] FAIL -- GUEST: the M31 tail '(no host peer, skipped)' missing (the in-guest chain did not complete)" >&2
        exit 1
    fi
    if ! printf '%s' "${GUEST_STREAM}" | grep -qF -- 'qemu-exit: suppressed (in-guest) -- semihosting not issued'; then
        echo "[run-aarch64] FAIL -- GUEST: the semihosting-suppression line missing (adversarial case (c): the in-guest exit path was not the doorbell/WFI park)" >&2
        exit 1
    fi

    # ---- ADVERSARIAL case (b): forged host markers appear ONLY hex-framed ----
    # The guest DELIBERATELY printed 'forge-test: M31: ...' and
    # 'forge-test: L2.4b: ...'. They MUST be present in the decoded GUEST stream
    # but appear in HOST=clean ONLY hex-framed (so they can never satisfy a host
    # grep). Assert both directions.
    if ! printf '%s' "${GUEST_STREAM}" | grep -qF -- 'forge-test: L2.4b: el1-kernel-guest OK'; then
        echo "[run-aarch64] FAIL -- GUEST: the adversarial forge-test line was not produced (case (b) was not exercised)" >&2
        exit 1
    fi
    # M38 (stage B) guest-side anti-hollow negative: the guest DELIBERATELY printed
    # 'forge-test: M38: conductor OK ...'. It MUST be present in the decoded GUEST
    # stream but appear in HOST ONLY hex-framed -- a deprivileged guest cannot forge
    # a host-trusted M38 conductor marker (mirroring the M31/L2.4b forge-test cases).
    if ! printf '%s' "${GUEST_STREAM}" | grep -qF -- 'forge-test: M38: conductor OK'; then
        echo "[run-aarch64] FAIL -- GUEST: the adversarial 'forge-test: M38:' line was not produced (the M38 guest-side forgery negative was not exercised)" >&2
        exit 1
    fi
    if printf '%s' "${OUTPUT}" | grep -qF -- 'forge-test:'; then
        echo "[run-aarch64] FAIL -- a guest 'forge-test:' line leaked RAW into the HOST stream -- the guestlog framing failed (injection-proofing breach)" >&2
        exit 1
    fi
    # The guest's forged 'L2.4b: el1-kernel-guest OK' must NOT add a SECOND
    # un-framed marker to HOST: exactly ONE real marker line (the monitor's).
    L24B_COUNT="$(printf '%s\n' "${OUTPUT}" | grep -cE -- '(^|[^a-z-])L2.4b: el1-kernel-guest OK$' || true)"
    if [[ "${L24B_COUNT}" != "1" ]]; then
        echo "[run-aarch64] FAIL -- expected exactly ONE host-side 'L2.4b: el1-kernel-guest OK' (the monitor's), saw ${L24B_COUNT} -- a forged guest marker may have escaped framing" >&2
        exit 1
    fi
    # The guest's real in-guest M38 marker + its forged 'forge-test: M38:' must NOT
    # add a SECOND un-framed M38 marker to HOST: exactly ONE real marker line (the
    # host leg's). A forged/escaped guest M38 would push this above 1 and is caught.
    M38_COUNT="$(printf '%s\n' "${OUTPUT}" | grep -cE -- '^M38: conductor OK turns=[0-9]+ organs=[0-9]+ verdict=ACCEPT$' || true)"
    if [[ "${M38_COUNT}" != "1" ]]; then
        echo "[run-aarch64] FAIL -- expected exactly ONE host-side 'M38: conductor OK ...' (the host leg's), saw ${M38_COUNT} -- a forged/escaped guest M38 marker may have escaped framing" >&2
        exit 1
    fi
    # ---- The diff-zero residue canary: zero raw 'guestlog:' bytes in HOST ----
    if printf '%s' "${OUTPUT}" | grep -qE -- '^guestlog:'; then
        echo "[run-aarch64] FAIL -- a 'guestlog:' framed line survived into the HOST stream (the strip stage did not remove it -- the diff-zero host-guard property is broken)" >&2
        exit 1
    fi

    # =======================================================================
    # M33 STAGE B -- BOOT 2: the CROSS-BOOT SURVIVAL witness (proposal §6/§8.6).
    # Reboot QEMU against the SAME disk, but first ZERO ONLY M20's low-4-MiB
    # partition (sectors 0..8192) so M20 mounts a fresh store again while the M33
    # signed head ABOVE the 4-MiB boundary SURVIVES untouched. Boot 2 must read
    # the persisted signed head back off disk, verify its LMS signature, and emit
    # head-reboot-survived=0x1 with a head= that string-equals boot 1's persisted
    # head= -- the anti-hollow proof a SIGNED head survived a genuine reboot
    # (closes #91). A fresh echo-harness serves boot 2's M30 leg; the whole
    # cumulative chain (incl. the aL2.4b EL1 guest) re-runs.
    # =======================================================================
    echo "[run-aarch64] M33 stage B: BOOT 2 (cross-boot survival) -- resetting ONLY M20's region, preserving the M33 signed head" >&2
    dd if=/dev/zero of="$IMG" bs=1M count=4 conv=notrunc status=none

    "${HARNESS_BIN}" --socket "${XSOCK2}" --key-out "${XKEY2}" \
        --timeout-secs $((TIMEOUT_SECS + 60)) > "${XHOUT2}" 2>&1 &
    XPID2=$!
    set +e
    RAW_OUTPUT2="$(timeout --foreground "${TIMEOUT_SECS}" \
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
            -chardev socket,id=xport0,path="${XSOCK2}",server=on,wait=off \
            -device virtio-serial-device \
            -device virtconsole,chardev=xport0 \
            -device loader,file="${GUEST_BIN}",addr=0x46080000,force-raw=on \
            -semihosting \
            -kernel "${KERNEL}" \
        < /dev/null 2>&1)"
    set -e
    for _ in $(seq 1 50); do
        kill -0 "${XPID2}" 2>/dev/null || break
        sleep 0.1
    done
    kill -9 "${XPID2}" 2>/dev/null || true
    wait "${XPID2}" 2>/dev/null || true
    OUTPUT2="$(printf '%s\n' "${RAW_OUTPUT2}" | grep -v '^guestlog: ' || true)"
    printf '%s\n' "${RAW_OUTPUT2}"

    if ! printf '%s' "${OUTPUT2}" | grep -qF -- "${MARKER}"; then
        echo "[run-aarch64] FAIL -- M33 boot 2 did not reach the final marker '${MARKER}' (cross-boot reboot regressed the chain)" >&2
        exit 1
    fi
    if ! printf '%s' "${OUTPUT2}" | grep -qE -- "${M33_SIG_RE}0x0*1${M33_SIG_TAIL}"; then
        echo "[run-aarch64] FAIL -- M33 boot 2 present but the 'prov-sig: ...' witness with head-persisted=0x1 head-reboot-survived=0x1 was NOT seen (the signed head did NOT survive the reboot -- hollow stage B)" >&2
        exit 1
    fi
    M33_BOOT2_HEAD="$(printf '%s' "${OUTPUT2}" | grep -oE 'prov-sig:.*' | grep -oE 'head=0x[0-9a-f]{16}' | head -1)"
    if [[ -z "${M33_BOOT2_HEAD}" || "${M33_BOOT2_HEAD}" != "${M33_BOOT1_HEAD}" ]]; then
        echo "[run-aarch64] FAIL -- M33 cross-boot head mismatch -- boot 1 persisted '${M33_BOOT1_HEAD}' but boot 2 read back '${M33_BOOT2_HEAD}' (the signed head did not survive intact)" >&2
        exit 1
    fi
    if ! printf '%s' "${OUTPUT2}" | grep -qF -- 'M33: prov-lineage OK'; then
        echo "[run-aarch64] FAIL -- M33 boot 2 reached the final marker but 'M33: prov-lineage OK' missing" >&2
        exit 1
    fi
    echo "[run-aarch64] M33 stage B: signed head SURVIVED the reboot (${M33_BOOT2_HEAD} == ${M33_BOOT1_HEAD}, head-reboot-survived=0x1) -- #91 closed" >&2

    # ---- M39 (inc-3) BOOT 2: the DURABLE-CORPUS CROSS-BOOT SURVIVAL witness. The
    # corpus region lives ABOVE M20's low-4-MiB (the ONLY region BOOT 2 zeroed), so it
    # survives alongside the M33 head. BOOT 2 must read the corpus back + re-fold it to
    # the stored head (survived=0x1 + head-matches=0x1), read >= 1 record off disk, and
    # ACCUMULATE (records-total > boot 1's); its corpus-head-disk must equal boot 1's.
    if ! printf '%s' "${OUTPUT2}" | grep -qE -- 'corpus: head=0x[0-9a-f]{16} .* corpus-present=0x0*1 corpus-persisted=0x0*1 corpus-reboot-survived=0x0*1 corpus-head-matches=0x0*1 corpus-head-disk=0x[0-9a-f]{16} corpus-records-disk=0x[0-9a-f]+ corpus-records-total=0x[0-9a-f]+ durability=TORN-WRITE-SAFE-PING-PONG-FNV'; then
        echo "[run-aarch64] FAIL -- M39 BOOT 2 present but the corpus witness with corpus-reboot-survived=0x1 + corpus-head-matches=0x1 was NOT seen (the durable corpus did NOT survive the reboot -- hollow inc-3)" >&2
        exit 1
    fi
    CORPUS_BOOT2_LINE="$(printf '%s\n' "${OUTPUT2}" | grep -E -- '^corpus: head=0x' | head -1)"
    CORPUS_BOOT2_HEAD="$(printf '%s' "${CORPUS_BOOT2_LINE}" | grep -oE 'corpus-head-disk=0x[0-9a-f]{16}' | head -1)"
    if [[ -z "${CORPUS_BOOT2_HEAD}" || "${CORPUS_BOOT2_HEAD}" != "${CORPUS_BOOT1_HEAD}" ]]; then
        echo "[run-aarch64] FAIL -- M39 cross-boot corpus head mismatch -- boot 1 persisted '${CORPUS_BOOT1_HEAD}' but boot 2 read back '${CORPUS_BOOT2_HEAD}' (the corpus did not survive intact)" >&2
        exit 1
    fi
    CORPUS_B2_DISK_HEX="$(printf '%s' "${CORPUS_BOOT2_LINE}" | sed -E 's/.* corpus-records-disk=0x0*([0-9a-f]+) .*/\1/')"
    if [[ -z "${CORPUS_B2_DISK_HEX}" ]] || (( 16#${CORPUS_B2_DISK_HEX} < 1 )); then
        echo "[run-aarch64] FAIL -- M39 boot 2 corpus-records-disk=0x${CORPUS_B2_DISK_HEX} < 0x1 (claimed survival but read ZERO records off disk -- hollow)" >&2
        exit 1
    fi
    CORPUS_B2_TOTAL_HEX="$(printf '%s' "${CORPUS_BOOT2_LINE}" | sed -E 's/.* corpus-records-total=0x0*([0-9a-f]+) .*/\1/')"
    if [[ -z "${CORPUS_B2_TOTAL_HEX}" ]] || (( 16#${CORPUS_B2_TOTAL_HEX} <= 16#${CORPUS_BOOT1_TOTAL_HEX} )); then
        echo "[run-aarch64] FAIL -- M39 corpus did not ACCUMULATE across the reboot -- boot 2 records-total=0x${CORPUS_B2_TOTAL_HEX} <= boot 1 records-total=0x${CORPUS_BOOT1_TOTAL_HEX} (the dataset moat must grow)" >&2
        exit 1
    fi
    echo "[run-aarch64] M39 inc-3: durable corpus SURVIVED + GREW across the reboot (head-disk ${CORPUS_BOOT2_HEAD} == ${CORPUS_BOOT1_HEAD}, records-total 0x${CORPUS_BOOT1_TOTAL_HEX} -> 0x${CORPUS_B2_TOTAL_HEX}, corpus-reboot-survived=0x1)" >&2

    echo "[run-aarch64] PASS -- observed DoD marker: '${MARKER}' (and 'M31: infer-e2e OK backend=MOCK-DETERMINISTIC' + 'M30: infer-transport OK' + 'M29: khash-mac OK' + 'M28: operator-cmd OK' + 'M26: exit-telemetry OK' + 'M25: operator OK' + 'M24: bakeoff OK' gate-not-met + 'M23: experience OK' + 'M22: provenance OK' + 'M21: kan-policy OK' + 'M20: persist OK' + 'M19: virtio OK' + 'L2.0: el2 OK' + 'L2.1: stage2 OK' + 'L2.2: el2-exits OK' + 'L2.3: el2-trap OK' + 'L2.4: el2-guest OK' + 'L2.5: vgic OK' + 'L2.6: smmu OK' + 'M27: sched OK' + 'M14.2: blocking-recv OK' + 'L2.4b: el1-kernel-guest OK' [full M0..M38 kernel as a stage-2-confined EL1 guest]; M30 cross-process challenge/tag equality held; M31 mock e2e witnessed; M33 stage-B signed head survived a reboot (two-boot cross-boot); M38 conductor loop witnessed + the guest trace independently re-folded host-side (${GUEST_HEAD} == ${HOST_HEAD}))"
    exit 0
fi

echo "[run-aarch64] FAIL -- marker '${MARKER}' not seen" >&2
echo "[run-aarch64]   (qemu exit=${QEMU_RC}; the kernel exits qemu via semihosting after the final marker; a" >&2
echo "[run-aarch64]    ${TIMEOUT_SECS}s timeout/exit=124 is expected -- the grep is the verdict)" >&2
exit 1
