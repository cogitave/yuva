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
# Build identifiers (KERNEL_BIN, TARGET_X86, ...) — the single source of truth.
. "${REPO_ROOT}/scripts/project.env"
TARGET="${TARGET_X86}"
PROFILE="${PROFILE:-debug}"
KERNEL="${1:-${REPO_ROOT}/target/${TARGET}/${PROFILE}/${KERNEL_BIN}}"
# M38 (stage B) DISPLACED M31 as the cumulative tail: the kernel-integrated
# conductor loop is the newest milestone. M31 is demoted-not-deleted (asserted
# directly below per the displacement discipline); the M38 marker is the new
# top-level grep. DECIMAL grammar (turns=N organs=K) -- the host-adjudicated
# stage-A marker shape, now guest-serial.
MARKER='M38: conductor OK turns=6 organs=3 verdict=ACCEPT'
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
# runs in any WSL2 / CI box without nested virt. TCG is pinned single-threaded
# (#71 / parity with run-aarch64.sh): one TCG vCPU thread removes the
# iothread-vs-vCPU interrupt-injection race window that produces the ghost-IRQ
# flake (QEMU TCG can inject cpu_get_pic_interrupt()'s -1 unguarded -> a bogus
# guest #GP with the non-architectural error code 0xfffffffa = (-1)*8+2).
ACCEL="tcg,thread=single"
CPU="qemu64"
if [[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
  ACCEL="kvm"
  CPU="host"
fi

echo ">> qemu=${QEMU} accel=${ACCEL} cpu=${CPU} timeout=${TIMEOUT_SECS}s" >&2
echo ">> kernel=${KERNEL}" >&2

# M20: a fresh 4 MiB raw disk per run for the virtio-blk durable-persistence
# round-trip. `mktemp`+`truncate -s 4M` zeroes it (so the first mount formats);
# `trap` removes it on EXIT so the temp never leaks/commits. microvm exposes the
# virtio-mmio bus the x86 M19 driver already scans, so virtio-blk-DEVICE (the
# mmio transport variant, NOT virtio-blk-pci -- microvm has no PCI by default) is
# correct + symmetric with the aarch64 rng/blk device pair.
IMG="$(mktemp)"
# #71 diagnosis: capture QEMU's interrupt/exception trace (-d int) into a side
# file (-D; NEVER bare -d -- this script merges qemu's 2>&1 into the
# marker-grepped OUTPUT below, so an inline trace would pollute the witness
# greps). The log is tiny on a green boot (~16 timer ticks + the self-test
# traps) and is printed ONLY on failure. Decisive for the ghost-IRQ flake: the
# fingerprint is a literal 'Servicing hardware INT=0xffffffff' line (QEMU
# renders the unguarded intno=-1 via %02x) right before the v=0d e=fffffffa
# exception trace. Harmless under KVM (in-kernel APIC: TCG trace points silent).
INT_LOG="$(mktemp)"

# M30: the HOST-keyed echo peer (the QEMU-chardev-harness lane -- proposal §4/§5).
# QEMU exposes a virtio-console (virtio-serial-device + virtconsole, the
# spike-verified config) whose port 0 is a unix-socket chardev; the
# xport-harness binary CUSTODIES a per-run OS-RNG key K + nonce N (K is NEVER
# in the guest image or on this command line -- key=HOST-CUSTODIED-PER-RUN),
# answers the kernel's ECHO_REQ with the khash-transformed echo + the
# channel-layer K reveal, and prints its OWN `xport-harness:` witness line to a
# SEPARATE capture stream. The guard block below string-compares the kernel's
# challenge/tag against the harness's (leg 2 -- CROSS-PROCESS equality with a
# host-custodied key is the loopback killer) and negatively asserts K never
# leaked into the guest serial output.
XSOCK="$(mktemp -u)"  # the chardev unix socket path (QEMU creates the listener)
XHOUT="$(mktemp)"     # the harness's stdout -- the SEPARATE leg-2 capture stream
XKEY="$(mktemp)"      # the harness-custodied key hex (the §5.7 key-leak check input)
trap 'rm -f "$IMG" "$INT_LOG" "$XSOCK" "$XHOUT" "$XKEY"' EXIT
truncate -s 4M "$IMG"

HARNESS_BIN="${REPO_ROOT}/tools/xport-harness/target/release/xport-harness"
if [[ ! -x "${HARNESS_BIN}" ]]; then
  if command -v cargo >/dev/null 2>&1; then
    echo ">> building xport-harness (host, release)" >&2
    ( cd "${REPO_ROOT}/tools/xport-harness" && cargo build --release >&2 )
  else
    # The containerised CI boot has no cargo: the workflow builds the harness
    # on the runner FIRST (see ci.yml); a missing binary here is a lane fault.
    echo ">> FAIL: ${HARNESS_BIN} missing and cargo unavailable -- build it first:" >&2
    echo ">>   cargo build --release --manifest-path tools/xport-harness/Cargo.toml" >&2
    exit 1
  fi
fi

# M38 (stage B): the host conductor binary -- used ONLY for the §8.6 CROSS-PROCESS
# recompute leg (--recompute-from-trace folds the GUEST's OWN emitted conduct-step
# trace INDEPENDENTLY, host-side, and the M38 guard string-equals its head against
# the guest-emitted conduct: head). The SAME verified tb_encode::conductor leaf, a
# SEPARATE process -- the anti-hollow leg now guest -> host. Zero network, zero secret.
CONDUCTOR_HOST_BIN="${REPO_ROOT}/tools/conductor-host/target/release/conductor-host"
if [[ ! -x "${CONDUCTOR_HOST_BIN}" ]]; then
  if command -v cargo >/dev/null 2>&1; then
    echo ">> building conductor-host (host, release)" >&2
    ( cd "${REPO_ROOT}/tools/conductor-host" && cargo build --release >&2 )
  else
    echo ">> FAIL: ${CONDUCTOR_HOST_BIN} missing and cargo unavailable -- build it first:" >&2
    echo ">>   cargo build --release --manifest-path tools/conductor-host/Cargo.toml" >&2
    exit 1
  fi
fi
"${HARNESS_BIN}" --socket "${XSOCK}" --key-out "${XKEY}" \
  --timeout-secs $((TIMEOUT_SECS + 60)) > "${XHOUT}" 2>&1 &
XPID=$!

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
    -drive file="$IMG",if=none,format=raw,id=vblk0 \
    -device virtio-blk-device,drive=vblk0 \
    -chardev socket,id=xport0,path="${XSOCK}",server=on,wait=off \
    -device virtio-serial-device \
    -device virtconsole,chardev=xport0 \
    -serial stdio -display none 2>&1)"
RC=$?
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
  # M14.2: an explicit second assertion for the blocking-recv sub-marker (the
  # final marker already transitively gates it -- a failed self-test halts before
  # L2.0 -- but this makes the traceability direct and fail-closed.)
  if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M14.2: blocking-recv OK'; then
    echo ">> FAIL: final marker present but 'M14.2: blocking-recv OK' missing" >&2
    exit 1
  fi
  # M19: the virtio-rng round-trip (the M20 dependency) must STILL print before
  # the displaced M20 tail -- assert it directly so the M19 -> M20 order is
  # fail-closed (two virtio-mmio devices, rng + blk, now share the microvm bus;
  # M19 must stay green with both present -- the scan matches by DeviceID).
  if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M19: virtio OK'; then
    echo ">> FAIL: final marker present but 'M19: virtio OK' missing (M19 displaced/regressed)" >&2
    exit 1
  fi
  # M20 SOUNDNESS (anti-hollow-pass): this lane ATTACHES a real virtio-blk disk,
  # so it must prove the REAL durable-persistence round-trip, not the graceful
  # "(no disk, skipped)" path. The skip marker 'M20: persist OK (no disk,
  # skipped)' CONTAINS the 'M20: persist OK' substring the top-level grep matches,
  # so a silently-unattached disk would otherwise pass green with a hollow proof
  # (the aL2.5 "(no EL2, skipped)" substring-grep hole). Reject the skip AND
  # positively require the real round-trip line 'persist: gen=.. records=..
  # replayed=..' the Proven path prints before the marker.
  if printf '%s' "${OUTPUT}" | grep -qF -- 'M20: persist OK (no disk, skipped)'; then
    echo ">> FAIL: M20 ran in SKIP mode (no virtio-blk disk attached) but this lane attaches one -- the durable-persistence Proven path was NOT exercised" >&2
    exit 1
  fi
  if ! printf '%s' "${OUTPUT}" | grep -qE -- 'persist: gen=0x[0-9a-fA-F]+ records=0x[0-9a-fA-F]+ replayed=0x[0-9a-fA-F]+'; then
    echo ">> FAIL: M20 marker present but the real durable-persistence round-trip line 'persist: gen=.. records=.. replayed=..' was NOT seen (hollow M20 pass)" >&2
    exit 1
  fi
  # M20 is no longer the top-level grep (M21 displaced it as the cumulative tail);
  # assert it directly so the M20 -> M21 order stays fail-closed + traceable.
  if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M20: persist OK'; then
    echo ">> FAIL: final marker present but 'M20: persist OK' missing (M20 displaced/regressed)" >&2
    exit 1
  fi
  # M21 SOUNDNESS (anti-hollow-pass, the aL2.5/M20 substring lesson): the marker
  # 'M21: kan-policy OK' substring is shared by the DORMANT variant
  # 'M21: kan-policy OK (heuristic floor, gate-not-met)' -- which is EXPECTED this
  # milestone (the spline ships dormant; the heuristic floor decides), so it is
  # NOT rejected. But a hollow pass that printed the marker WITHOUT running the
  # loader/validators must fail, so (a) positively require the real round-trip line
  # 'kan: monotone=1 ovf-safe=1 q-err=0x.. bound=0x.. active=0' (so the validators
  # provably ran on the shipped integer table), and (b) reject a future
  # '(no table, skipped)' variant (a skipped loader is a hollow proof on a lane
  # that ships a table). active=0 is required: the spline is dormant this lane.
  if printf '%s' "${OUTPUT}" | grep -qF -- 'M21: kan-policy OK (no table, skipped)'; then
    echo ">> FAIL: M21 ran in SKIP mode (no policy table loaded) -- the verified-leaf loader/validators were NOT exercised" >&2
    exit 1
  fi
  if ! printf '%s' "${OUTPUT}" | grep -qE -- 'kan: monotone=0x0*1 ovf-safe=0x0*1 q-err=0x[0-9a-fA-F]+ bound=0x[0-9a-fA-F]+ active=0x0+'; then
    echo ">> FAIL: M21 marker present but the real round-trip line 'kan: monotone=1 ovf-safe=1 q-err=0x.. bound=0x.. active=0' was NOT seen (hollow M21 pass)" >&2
    exit 1
  fi
  # M21 is no longer the top-level grep (M22 displaced it as the cumulative tail);
  # assert it directly so the M21 -> M22 order stays fail-closed + traceable.
  if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M21: kan-policy OK'; then
    echo ">> FAIL: final marker present but 'M21: kan-policy OK' missing (M21 displaced/regressed)" >&2
    exit 1
  fi
  # M22 SOUNDNESS (anti-hollow-pass, the aL2.5/M20/M21 substring lesson): the
  # 'M22: provenance OK' marker must be backed by the REAL verifier round-trip --
  # there is NO device to be absent, so a skip is NEVER legitimate. Reject any
  # '(no ledger, skipped)' variant, and POSITIVELY require the witness line
  # 'prov: head=0x.. entries=0x.. tamper-caught=0x1 inclusion=0x1' (so a marker
  # printed WITHOUT running the canon/hash/fold + tamper-injection verifier FAILS).
  # tamper-caught=1 AND inclusion=1 are required: the injected single-byte tamper of
  # a committed entry must be caught (head-mismatch AND inclusion-fail) and a genuine
  # inclusion proof must verify -- a hollow pass that printed the marker without the
  # tamper round-trip is rejected here.
  if printf '%s' "${OUTPUT}" | grep -qF -- 'M22: provenance OK (no ledger, skipped)'; then
    echo ">> FAIL: M22 ran in SKIP mode (no ledger) -- the provenance verifier round-trip was NOT exercised (a skip is never legitimate here)" >&2
    exit 1
  fi
  if ! printf '%s' "${OUTPUT}" | grep -qE -- 'prov: head=0x[0-9a-fA-F]+ entries=0x[0-9a-fA-F]+ tamper-caught=0x0*1 inclusion=0x0*1'; then
    echo ">> FAIL: M22 marker present but the real round-trip witness 'prov: head=0x.. entries=0x.. tamper-caught=0x1 inclusion=0x1' was NOT seen (hollow M22 pass)" >&2
    exit 1
  fi
  # M22 is no longer the top-level grep (M23 displaced it as the cumulative tail);
  # assert it directly so the M22 -> M23 order stays fail-closed + traceable.
  if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M22: provenance OK'; then
    echo ">> FAIL: final marker present but 'M22: provenance OK' missing (M22 displaced/regressed)" >&2
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
    echo ">> FAIL: M23 ran in SKIP mode (no log) -- the experience verifier round-trip was NOT exercised (a skip is never legitimate here -- the log is in-RAM)" >&2
    exit 1
  fi
  if ! printf '%s' "${OUTPUT}" | grep -qE -- 'exp: head=0x[0-9a-fA-F]+ records=0x[0-9a-fA-F]+ replay-bitexact=0x0*1 tamper-caught=0x0*1 kan_active=0x0+ oracle=DECLARED-PROXY-DEFERRED-M24'; then
    echo ">> FAIL: M23 marker present but the real round-trip witness 'exp: head=0x.. records=0x.. replay-bitexact=0x1 tamper-caught=0x1 kan_active=0x0 oracle=DECLARED-PROXY-DEFERRED-M24' was NOT seen (hollow M23 pass)" >&2
    exit 1
  fi
  # TERMINOLOGY DISCIPLINE (proposal §6): M23 claims ONLY replay-determinism +
  # structural tamper-evidence, NOT validity. Reject any 'validated'/'evaluated'
  # substring on the exp: witness or the M23 marker line so the marker can never
  # silently overclaim (the OPE-loaded words are confined to bit-exact re-derivation).
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M23:|exp:)' | grep -qE -- 'validated|evaluated'; then
    echo ">> FAIL: M23 marker/witness carries a 'validated'/'evaluated' overclaim -- M23 records + replay-determines, it does NOT validate any policy (proposal §6 terminology discipline)" >&2
    exit 1
  fi
  # M23 is no longer the top-level grep (M24 displaced it as the cumulative tail);
  # assert it directly so the M23 -> M24 order stays fail-closed + traceable.
  if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M23: experience OK'; then
    echo ">> FAIL: final marker present but 'M23: experience OK' missing (M23 displaced/regressed)" >&2
    exit 1
  fi
  # M24 SOUNDNESS (anti-hollow-pass, the aL2.5/M20/M21/M22/M23 substring lesson): the
  # 'M24: bakeoff OK' marker must be backed by the REAL bake-off witness -- the gate
  # machinery (label + estimator + in-RAM replay + the envelope re-assertion) provably
  # RAN. POSITIVELY require the witness line 'bakeoff: vlo_kan=0x.. vhi_heur=0x..
  # margin=0x.. ... cleared=0x.. ... no-float=1 envelope-no-widening=1' (so a marker
  # printed WITHOUT running the estimator/gate FAILS). no-float=1 AND
  # envelope-no-widening=1 are required: the gate path must be float-free and the M21
  # envelope-no-widening invariant must have re-asserted.
  if ! printf '%s' "${OUTPUT}" | grep -qE -- 'bakeoff: vlo_kan=0x[0-9a-fA-F]+ vhi_heur=0x[0-9a-fA-F]+ margin=0x[0-9a-fA-F]+ .*no-float=1 envelope-no-widening=1'; then
    echo ">> FAIL: M24 marker present but the real bake-off witness 'bakeoff: vlo_kan=.. vhi_heur=.. margin=.. .. no-float=1 envelope-no-widening=1' was NOT seen (hollow M24 pass)" >&2
    exit 1
  fi
  # M24 DORMANCY (proposal §6/§7): on the (necessarily SYNTHETIC) traces this milestone
  # the gate does NOT clear -- 'M24: bakeoff OK (gate-not-met)' (the cell stays DORMANT)
  # is the DESIGNED, CORRECT outcome (the M21 '(heuristic floor, gate-not-met)' idiom).
  # This lane does NOT assert an ACTIVE cell, so it ACCEPTS the dormant gate-not-met /
  # gate-not-evaluable variants. A 'gate-cleared' verdict here (cleared=0x1) would mean
  # the cell flipped ACTIVE on a synthetic trace -- which this milestone forbids, so
  # reject it (the cell must stay dormant until M25's exogenous human oracle).
  if printf '%s' "${OUTPUT}" | grep -qF -- 'M24: bakeoff OK (gate-cleared)'; then
    echo ">> FAIL: M24 gate CLEARED on a synthetic trace (cell flipped ACTIVE) -- this milestone the gate must REFUSE (gate-not-met); a real activation awaits M25's human oracle" >&2
    exit 1
  fi
  # TERMINOLOGY DISCIPLINE (proposal §6/§7): M24 claims ONLY a partial-identification
  # LOWER bound + an HONEST refusal, NOT a validated activation. Reject any
  # 'validated'/'evaluated' substring on the bakeoff: witness or the M24 marker line so
  # the marker can never silently overclaim (the honest gate REFUSES on synthetic data).
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M24:|bakeoff:)' | grep -qE -- 'validated|evaluated'; then
    echo ">> FAIL: M24 marker/witness carries a 'validated'/'evaluated' overclaim -- M24 lower-bounds + honestly REFUSES, it does NOT validate any activation (proposal §6/§7 terminology discipline)" >&2
    exit 1
  fi
  # M24 is no longer the top-level grep (M25 displaced it as the cumulative tail);
  # assert it directly so the M24 -> M25 order stays fail-closed + traceable.
  if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M24: bakeoff OK'; then
    echo ">> FAIL: final marker present but 'M24: bakeoff OK' missing (M24 displaced/regressed)" >&2
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
  # required: the seq must be strictly monotone, the INTRO must bind the live M22 head,
  # the clean fold + inclusion must verify, and the injected tamper + tail-truncation
  # must be caught. The keyed=0 + oracle=HUMAN-DEFERRED-M26 honesty tokens must be
  # present so the marker mechanically cannot claim crypto authenticity or that a human
  # replied (it proves the CHANNEL, not the ORACLE).
  if printf '%s' "${OUTPUT}" | grep -qF -- 'M25: operator OK (no channel, skipped)'; then
    echo ">> FAIL: M25 ran in SKIP mode (no channel) -- the operator-transcript verifier round-trip was NOT exercised (a skip is never legitimate here -- the transcript is in-RAM)" >&2
    exit 1
  fi
  if ! printf '%s' "${OUTPUT}" | grep -qE -- 'opframe: tx_head=0x[0-9a-fA-F]+ frames=0x[0-9a-fA-F]+ seq_monotone=0x0*1 intro_bound=0x0*1 fold-verified=0x0*1 tamper-caught=0x0*1 keyed=0 oracle=HUMAN-DEFERRED-M26'; then
    echo ">> FAIL: M25 marker present but the real round-trip witness 'opframe: tx_head=.. frames=.. seq_monotone=0x1 intro_bound=0x1 fold-verified=0x1 tamper-caught=0x1 keyed=0 oracle=HUMAN-DEFERRED-M26' was NOT seen (hollow M25 pass)" >&2
    exit 1
  fi
  # TERMINOLOGY DISCIPLINE (proposal §5): M25 claims ONLY structural tamper-evidence +
  # truncation/reorder/replay detection + instance binding, NOT crypto authenticity and
  # NOT that a human replied. Reject any 'validated'/'evaluated' substring on the
  # opframe: witness or the M25 marker line so the marker can never silently overclaim
  # (the self-test is self-graded plumbing, not the human oracle).
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M25:|opframe:)' | grep -qE -- 'validated|evaluated'; then
    echo ">> FAIL: M25 marker/witness carries a 'validated'/'evaluated' overclaim -- M25 surfaces + tamper-evidences a transcript, it does NOT validate any policy or prove a human replied (proposal §5 terminology discipline)" >&2
    exit 1
  fi
  # M25 is no longer the top-level grep (M26 displaced it as the cumulative tail);
  # assert it directly so the M25 -> M26 order stays fail-closed + traceable.
  if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M25: operator OK'; then
    echo ">> FAIL: final marker present but 'M25: operator OK' missing (M25 displaced/regressed)" >&2
    exit 1
  fi
  # M26 SOUNDNESS (anti-hollow-pass, the aL2.5/M20..M25 substring lesson): the
  # 'M26: exit-telemetry OK' marker must be backed by the REAL telemetry round-trip --
  # the exit vector is synthetic + in-RAM (a real EL2 exit producer drains here in M27+),
  # so a skip is NEVER legitimate. Reject any '(no exits, skipped)' variant, and
  # POSITIVELY require the witness line 'exittel: head=0x.. records=0x.. classes=0x..
  # class-total=0x1 buckets-exact=0x1 fold-verified=0x1 tamper-caught=0x1
  # signal=OBSERVATIONAL-NONCAUSAL' (so a marker printed WITHOUT running the
  # classifier/histogram/fold/tamper verifier FAILS). class-total=1 AND buckets-exact=1
  # AND fold-verified=1 AND tamper-caught=1 are required: every synthetic ESR must
  # classify to a distinct in-range class, the recorded buckets/counts must be exact, the
  # clean fold + inclusion must verify, and the injected tamper must be caught. The
  # signal=OBSERVATIONAL-NONCAUSAL honesty token must be present so the marker cannot
  # claim a causal state-signal (the telemetry is recorded, not learned-from).
  if printf '%s' "${OUTPUT}" | grep -qF -- 'M26: exit-telemetry OK (no exits, skipped)'; then
    echo ">> FAIL: M26 ran in SKIP mode (no exits) -- the exit-telemetry verifier round-trip was NOT exercised (a skip is never legitimate here -- the exit vector is synthetic + in-RAM)" >&2
    exit 1
  fi
  if ! printf '%s' "${OUTPUT}" | grep -qE -- 'exittel: head=0x[0-9a-fA-F]+ records=0x[0-9a-fA-F]+ classes=0x[0-9a-fA-F]+ class-total=0x0*1 buckets-exact=0x0*1 fold-verified=0x0*1 tamper-caught=0x0*1 signal=OBSERVATIONAL-NONCAUSAL'; then
    echo ">> FAIL: M26 marker present but the real round-trip witness 'exittel: head=.. records=.. classes=.. class-total=0x1 buckets-exact=0x1 fold-verified=0x1 tamper-caught=0x1 signal=OBSERVATIONAL-NONCAUSAL' was NOT seen (hollow M26 pass)" >&2
    exit 1
  fi
  # TERMINOLOGY DISCIPLINE (proposal §5): M26 is PRODUCER-ONLY -- it RECORDS its exit
  # workload, it does NOT validate any causal state-signal and does NOT learn from the
  # stream (the confounding loop is not closed). Reject any 'validated'/'causal'/'learned'
  # substring on the exittel: witness or the M26 marker line so the marker can never
  # silently overclaim.
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M26:|exittel:)' | grep -qE -- 'validated|causal|learned'; then
    echo ">> FAIL: M26 marker/witness carries a 'validated'/'causal'/'learned' overclaim -- M26 RECORDS observational exit telemetry, it does NOT validate a causal signal or learn from it (proposal §5 terminology discipline)" >&2
    exit 1
  fi
  # M26 is no longer the top-level grep (M28 displaced it as the cumulative tail);
  # assert it directly so the M26 -> M28 order stays fail-closed + traceable.
  if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M26: exit-telemetry OK'; then
    echo ">> FAIL: final marker present but 'M26: exit-telemetry OK' missing (M26 displaced/regressed)" >&2
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
    echo ">> FAIL: M28 ran in SKIP mode (no key) -- the operator-inbound command verifier round-trip was NOT exercised (a skip is never legitimate here -- the command is in-RAM + simulated)" >&2
    exit 1
  fi
  if ! printf '%s' "${OUTPUT}" | grep -qE -- 'opcmd: challenge=0x[0-9a-fA-F]+ accepted=0x0*1 stale-rejected=0x0*1 wronghead-rejected=0x0*1 single-cred-rejected=0x0*1 badmac-rejected=0x0*1 oldkey-zeroized=0x0*1 kan_active=0x0+ mac=KEYED-CRYPTO kdf=DERIVE-THEN-MAC-DOMSEP keyevolve=PRF-DOMSEP oracle=SIMULATED-ENROLLED-KEY'; then
    echo ">> FAIL: M28 marker present but the real round-trip witness 'opcmd: challenge=0x.. accepted=0x1 stale-rejected=0x1 wronghead-rejected=0x1 single-cred-rejected=0x1 badmac-rejected=0x1 oldkey-zeroized=0x1 kan_active=0x0 mac=KEYED-CRYPTO kdf=DERIVE-THEN-MAC-DOMSEP keyevolve=PRF-DOMSEP oracle=SIMULATED-ENROLLED-KEY' was NOT seen (hollow M28 pass)" >&2
    exit 1
  fi
  # M28 is no longer the top-level grep (M29 displaced it as the cumulative tail);
  # assert it directly so the M28 -> M29 order stays fail-closed + traceable.
  if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M28: operator-cmd OK'; then
    echo ">> FAIL: final marker present but 'M28: operator-cmd OK' missing (M28 displaced/regressed)" >&2
    exit 1
  fi
  # M29 SOUNDNESS (anti-hollow-pass): the 'M29: khash-mac OK' marker must be backed
  # by the khash WITNESS line with the FULL machine-emitted prove/assume boundary --
  # 'khash: prim=BLAKE2S-256 keylen=32 tag=128 kat=RFC7693-PASS
  # sec=ASSUMED-FROM-LITERATURE sidechannel=NOT-CLAIMED'. kat=RFC7693-PASS is EARNED
  # per boot (the self-test recomputes the official RFC 7693 vectors through the real
  # compression, fail-closed) -- a marker without the witness is a hollow pass. The
  # khash leaf is pure in-RAM value computation, so a skip is NEVER legitimate.
  if printf '%s' "${OUTPUT}" | grep -qF -- 'M29: khash-mac OK (no key, skipped)'; then
    echo ">> FAIL: M29 ran in SKIP mode -- the khash KAT + MAC round-trip was NOT exercised (a skip is never legitimate here -- pure in-RAM value computation)" >&2
    exit 1
  fi
  if ! printf '%s' "${OUTPUT}" | grep -qE -- 'khash: prim=BLAKE2S-256 keylen=32 tag=128 kat=RFC7693-PASS sec=ASSUMED-FROM-LITERATURE sidechannel=NOT-CLAIMED'; then
    echo ">> FAIL: M29 marker present but the khash witness 'khash: prim=BLAKE2S-256 keylen=32 tag=128 kat=RFC7693-PASS sec=ASSUMED-FROM-LITERATURE sidechannel=NOT-CLAIMED' was NOT seen (hollow M29 pass -- the in-boot KAT did not provably run)" >&2
    exit 1
  fi
  # RETIRED-TIER REJECT (proposal §7): the M28-era mac=KEYED-NONCRYPTO token RETIRES
  # at M29 -- it must NEVER appear anywhere in a green boot, so the old keyed-FNV
  # tier can never impersonate the khash-backed stage B chain.
  if printf '%s' "${OUTPUT}" | grep -qF -- 'KEYED-NONCRYPTO'; then
    echo ">> FAIL: the RETIRED 'KEYED-NONCRYPTO' token appeared -- the M28-era keyed-FNV tier cannot impersonate the M29 KEYED-CRYPTO chain (proposal §7 retired-token discipline)" >&2
    exit 1
  fi
  # TERMINOLOGY DISCIPLINE (M29 proposal §7): the markers/witnesses prove the auth
  # PLUMBING + a verified IMPLEMENTATION of an ASSUMED-secure primitive -- they never
  # claim a proven-secure/unforgeable/collision-resistant/constant-time MAC, a human,
  # or an activation. We FIRST strip the structured honesty tokens (each carries a
  # would-be-rejected substring -- KEYED-CRYPTO carries 'crypto',
  # collision-resistance lives ONLY inside ASSUMED-FROM-LITERATURE, etc.) so the
  # post-strip overclaim grep bites on PROSE only; the reject list extends the M28
  # set with the M29 crypto-overclaim vocabulary.
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M28:|M29:|opcmd:|khash:)' \
       | sed -e 's/KEYED-CRYPTO//g' -e 's/BLAKE2S-256//g' -e 's/RFC7693-PASS//g' \
             -e 's/ASSUMED-FROM-LITERATURE//g' -e 's/NOT-CLAIMED//g' \
             -e 's/DERIVE-THEN-MAC-DOMSEP//g' -e 's/PRF-DOMSEP//g' \
             -e 's/SIMULATED-ENROLLED-KEY//g' \
       | grep -qiE -- 'validated|crypto|authenticated-human|forgery|provably[- ]secure|unforgeable|collision[- ]resistant|preimage[- ]resistant|constant[- ]time|tamper[- ]proof|quantum|FIPS[- ](certified|validated)|guaranteed|unbreakable'; then
    echo ">> FAIL: M28/M29 marker/witness carries an overclaim ('validated'/'crypto'/'authenticated-human'/'forgery'/'provably-secure'/'unforgeable'/'collision-resistant'/'preimage-resistant'/'constant-time'/'tamper-proof'/'quantum'/'FIPS-certified'/'guaranteed'/'unbreakable') -- the implementation is verified, the primitive is ASSUMED-FROM-LITERATURE; crypto claims live ONLY in the structured stripped tokens (M29 proposal §7 honesty discipline)" >&2
    exit 1
  fi
  # M29 is no longer the top-level grep (M30 displaced it as the cumulative tail);
  # assert it directly so the M29 -> M30 order stays fail-closed + traceable.
  if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M29: khash-mac OK'; then
    echo ">> FAIL: final marker present but 'M29: khash-mac OK' missing (M29 displaced/regressed)" >&2
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
    echo ">> FAIL: M30 ran in SKIP mode (no host peer found) but this lane attaches the chardev harness -- the host-keyed echo round-trip was NOT exercised" >&2
    exit 1
  fi
  if printf '%s' "${OUTPUT}" | grep -qF -- 'M30: infer-transport OK (legacy transport, skipped)'; then
    echo ">> FAIL: M30 took the legacy-transport skip but this lane attaches a MODERN (force-legacy=false) console -- the Version=2 negotiation regressed" >&2
    exit 1
  fi
  # (§5.2) POSITIVE-REQUIRE the full xport witness: every flag =1, every token
  # literal, the lane's own bus/transport tokens (chardev lane: SERIAL-FRAMED +
  # QEMU-CHARDEV-HARNESS). A marker without this witness is a hollow pass.
  if ! printf '%s' "${OUTPUT}" | grep -qE -- 'xport: bus=SERIAL-FRAMED qsz=0x4 tx=0x0*1 rx=0x0*1 challenge=0x[0-9a-f]{32} nonce=0x[0-9a-f]{32} tag=0x[0-9a-f]{32} req-id=0x[0-9a-f]{16} echo-verified=0x0*1 body-bitexact=0x0*1 badtag-rejected=0x0*1 wrongkey-rejected=0x0*1 partial-rejected=0x0*1 desync-rejected=0x0*1 mode=POLL transport=QEMU-CHARDEV-HARNESS echo=HOST-KEYED-VERIFIED key=HOST-CUSTODIED-PER-RUN backend=ECHO-ONLY sec=ASSUMED-FROM-LITERATURE'; then
    echo ">> FAIL: M30 marker present but the real witness 'xport: bus=SERIAL-FRAMED .. challenge=.. nonce=.. tag=.. echo-verified=0x1 .. mode=POLL transport=QEMU-CHARDEV-HARNESS echo=HOST-KEYED-VERIFIED key=HOST-CUSTODIED-PER-RUN backend=ECHO-ONLY sec=ASSUMED-FROM-LITERATURE' was NOT seen (hollow M30 pass)" >&2
    exit 1
  fi
  # (§5.3) Loopback variants rejected BY NAME (case-insensitive, near the M30
  # marker/witness): the M22 mock-loopback design is structurally banned.
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M30:|xport:)' | grep -qiE -- 'transport=IN-KERNEL-LOOPBACK|transport=MOCK-BACKEND|transport=GUEST-SELF|echo=SELF-KEYED|echo=GUEST-KEYED|loopback|self-echo'; then
    echo ">> FAIL: M30 marker/witness carries a LOOPBACK token (IN-KERNEL-LOOPBACK/MOCK-BACKEND/GUEST-SELF/SELF-KEYED/GUEST-KEYED/loopback/self-echo) -- the M22 hollow-loopback design is banned by name (M30 proposal §5.3)" >&2
    exit 1
  fi
  # (§5.4) Lane-token cross-pin: the chardev lane must NEVER carry the vmm
  # lane's evidence class (peer_id is MAC-covered; a mislabel is a fault).
  if printf '%s' "${OUTPUT}" | grep -qF -- 'transport=TB-VMM-HOST'; then
    echo ">> FAIL: the chardev lane carries 'transport=TB-VMM-HOST' -- no lane borrows the other's evidence class (M30 proposal §5.4 lane cross-pin)" >&2
    exit 1
  fi
  # (§5.5) The #71 tripwire: M30 is poll-only BY GUARD PIN. Flipping this is
  # the designated visible act that forces a #71 disposition first.
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M30:|xport:)' | grep -qE -- 'mode=IRQ'; then
    echo ">> FAIL: M30 witness carries 'mode=IRQ' -- the completion-IRQ migration is BLOCKED until a #71 (TCG ghost-IRQ) disposition is recorded (M30 proposal §5.5 tripwire)" >&2
    exit 1
  fi
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])xport:' | grep -vE -- 'mode=POLL' | grep -q .; then
    echo ">> FAIL: an xport: witness line lacks 'mode=POLL' -- any non-poll completion mode is rejected (M30 proposal §5.5)" >&2
    exit 1
  fi
  # (§5.6) THE CROSS-PROCESS ROUND-TRIP (leg 2 -- the loopback killer): the
  # kernel-witnessed challenge/tag must STRING-EQUAL the host harness's OWN
  # line from its SEPARATE capture stream. A loopback can mint a self-
  # consistent tag but cannot equal khash(K,..) without the host-custodied K.
  if ! printf '%s\n' "${HARNESS_OUT}" | grep -qE -- 'xport-harness: peer=QEMU-CHARDEV-HARNESS challenge=0x[0-9a-f]{32} tag=0x[0-9a-f]{32} key-custody=HOST'; then
    echo ">> FAIL: the host harness witness 'xport-harness: peer=QEMU-CHARDEV-HARNESS challenge=.. tag=.. key-custody=HOST' was NOT seen on the harness's capture stream (no host peer answered -- leg 2 of the anti-hollow composition is missing)" >&2
    exit 1
  fi
  K_CH="$(printf '%s\n' "${OUTPUT}" | grep -E '(^|[^[:alnum:]])xport: ' | grep -oE 'challenge=0x[0-9a-f]{32}' | head -1)"
  K_TAG="$(printf '%s\n' "${OUTPUT}" | grep -E '(^|[^[:alnum:]])xport: ' | grep -oE '(^| )tag=0x[0-9a-f]{32}' | head -1 | tr -d ' ')"
  H_CH="$(printf '%s\n' "${HARNESS_OUT}" | grep -F 'xport-harness: ' | grep -oE 'challenge=0x[0-9a-f]{32}' | head -1)"
  H_TAG="$(printf '%s\n' "${HARNESS_OUT}" | grep -F 'xport-harness: ' | grep -oE '(^| )tag=0x[0-9a-f]{32}' | head -1 | tr -d ' ')"
  if [[ -z "${K_CH}" || -z "${K_TAG}" || "${K_CH}" != "${H_CH}" || "${K_TAG}" != "${H_TAG}" ]]; then
    echo ">> FAIL: CROSS-PROCESS mismatch -- kernel (${K_CH:-none} ${K_TAG:-none}) vs harness (${H_CH:-none} ${H_TAG:-none}); the bytes did not provably cross the guest/host boundary both ways (M30 proposal §5.6 -- the loopback killer)" >&2
    exit 1
  fi
  # (§5.7) Key-LEAK negative: the host-custodied K's hex must appear NOWHERE in
  # the guest serial output (the kernel must never print the revealed key).
  KHEX="$(cat "${XKEY}" 2>/dev/null || true)"
  if [[ -z "${KHEX}" ]]; then
    echo ">> FAIL: the harness key file is empty -- the §5.7 key-leak check has no input (harness fault)" >&2
    exit 1
  fi
  if printf '%s' "${OUTPUT}" | grep -qiF -- "${KHEX}"; then
    echo ">> FAIL: the host-custodied per-run key LEAKED into the guest serial output (M30 proposal §5.7 key-leak negative)" >&2
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
    echo ">> FAIL: M30 marker/witness carries an overclaim ('network'/'TLS'/'encrypt'/'authenticated'/'secure-channel'/'remote-model'/'real-infer'/'validated'/...) -- M30 is a LOCAL host-process echo transport; claims live ONLY in the structured stripped tokens (M30 proposal §5.8)" >&2
    exit 1
  fi
  # M30 is no longer the top-level grep (M31 displaced it as the cumulative tail);
  # assert it directly so the M30 -> M31 order stays fail-closed + traceable.
  if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M30: infer-transport OK'; then
    echo ">> FAIL: final marker present but 'M30: infer-transport OK' missing (M30 displaced/regressed)" >&2
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
    echo ">> FAIL: M31 ran in SKIP mode (no host peer) but this lane attaches the chardev harness -- the inference-adapter wire e2e was NOT exercised" >&2
    exit 1
  fi
  # (§7.2) POSITIVE-REQUIRE the full infer witness: the proposal-§7 verbatim
  # token set (every flag earned, every honesty token literal) + the exact
  # deterministic wire-evidence tail (2 chunks -- the assembler provably did
  # real wire work -- and exactly 1 verified PENDING heartbeat).
  if ! printf '%s' "${OUTPUT}" | grep -qE -- 'infer: backend=MOCK-DETERMINISTIC context=M13-SCALAR-RECALL recalls=0x[0-9a-f]+ prompt-len=0x[0-9a-f]+ resp-len=0x[0-9a-f]+ resp-digest=0x[0-9a-f]{32} req-id=0x[0-9a-f]{16} stop=END-TURN wire-err-handled=0x0*1 fold=M25-TRANSCRIPT key=CAPREF-HOST-CUSTODIED host=RESIDUAL-TCB ambient=ZERO-IN-GUEST sec=ASSUMED-FROM-LITERATURE chunks=0x0*2 pending=0x0*1'; then
    echo ">> FAIL: M31 marker present but the real e2e witness 'infer: backend=MOCK-DETERMINISTIC context=M13-SCALAR-RECALL recalls=.. prompt-len=.. resp-len=.. resp-digest=.. req-id=.. stop=END-TURN wire-err-handled=0x1 fold=M25-TRANSCRIPT key=CAPREF-HOST-CUSTODIED host=RESIDUAL-TCB ambient=ZERO-IN-GUEST sec=ASSUMED-FROM-LITERATURE chunks=0x2 pending=0x1' was NOT seen (hollow M31 pass)" >&2
    exit 1
  fi
  # (§7.3) By-name rejects (case-insensitive, near the M31 lines): the LIVE
  # lane's evidence class -- and any live/real/network vocabulary -- is
  # structurally banned from the mock lane, so a forged live claim can never
  # enter the cumulative chain (the lane cross-pin, §7.4, is the same set).
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M31:|infer:|infer-dump:)' | grep -qiE -- 'backend=ANTHROPIC-LIVE|(^|[^[:alnum:]])real|(^|[^[:alnum:]])live|network|TLS|HTTPS|cloud|api[- ]key'; then
    echo ">> FAIL: M31 marker/witness carries a LIVE-lane token ('ANTHROPIC-LIVE'/'real'/'live'/'network'/'TLS'/'HTTPS'/'cloud'/'api-key') -- the mock lane never borrows the live lane's evidence class; the live half is stage C, operator-gated (M31 proposal §7.3/§7.4)" >&2
    exit 1
  fi
  # (§7.5) Inherited tripwire: a verified INFER_PENDING is a poll-budget
  # reset, NEVER a completion -- the witness pins pending=0x1 above and the
  # kernel hard-FAILs a pendings-only run as xport-timeout; reject any
  # pending-as-completion overclaim vocabulary outright.
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M31:|infer:)' | grep -qiE -- 'pending[- ]complete|streamed|streaming'; then
    echo ">> FAIL: M31 witness claims streaming/pending-completion semantics -- INFER_PENDING is liveness plumbing, chunked delivery is reassembly of a COMPLETED response (M31 proposal §2f)" >&2
    exit 1
  fi
  # (§7.7) Raw-leak tripwires (the encode-before-write invariant is
  # GUARD-CHECKED, not trusted): (a) FAIL on a raw ESC byte anywhere in guest
  # serial (an ANSI sequence in model-derived bytes would hijack terminals
  # rendering the log); (b) every infer-dump line must match the strict
  # lowercase-hex grammar EXACTLY (regex-inert by construction -- it cannot
  # forge a marker, a token, or an escape).
  if printf '%s' "${OUTPUT}" | grep -q -- $'\x1b'; then
    echo ">> FAIL: a raw ESC (0x1b) byte reached guest serial -- the M31 encode-before-write invariant is broken (M31 proposal §6 raw-leak tripwire)" >&2
    exit 1
  fi
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])infer-dump:' | grep -vE -- '^infer-dump: req-id=0x[0-9a-f]{16} seq=0x[0-9a-f]{16} resp-hex=[0-9a-f]+$' | grep -q .; then
    echo ">> FAIL: an infer-dump line violates the strict 'infer-dump: req-id=0x<16hex> seq=0x<16hex> resp-hex=<lowercase-hex>' grammar -- model-derived bytes must cross serial ONLY hex-encoded (M31 proposal §6)" >&2
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
    echo ">> FAIL: M31 marker/witness carries an overclaim ('understood'/'reasoned'/'intelligen*'/'knows'/'learned'/'validated'/'evaluated'/'secure'/'confidential'/'private'/'authenticated-human'/'agi') -- M31's mock lane proves plumbing (recall -> prompt -> deterministic transform -> digest fold), never intelligence or semantics (M31 proposal §7.8)" >&2
    exit 1
  fi
  # M31 is no longer the top-level grep (M38 displaced it as the cumulative tail);
  # assert it directly so the M31 -> M38 order stays fail-closed + traceable (the
  # demote-not-delete displacement discipline).
  if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M31: infer-e2e OK backend=MOCK-DETERMINISTIC'; then
    echo ">> FAIL: final marker present but 'M31: infer-e2e OK backend=MOCK-DETERMINISTIC' missing (M31 displaced/regressed)" >&2
    exit 1
  fi

  # M33 (stage A) GUARDS -- the provenance-lineage crypto-VERIFY substrate
  # (proposal §8, adapted to stage A: the KAT + verify + regional-tamper witness;
  # the PERSISTED-HEAD marker 'M33: prov-lineage OK' is STAGE B, not this lane).
  # M33 emits BEFORE the M38 final marker, so it is in the captured OUTPUT.
  #
  # (positive-require) The FULL 'prov-sig:' stage-A witness: both KAT tokens on
  # THIS anchored line (disjoint from the M29 'khash: ...kat=RFC7693-PASS...'
  # line), every earned flag =0x1, BOTH regional tamper tokens, and every honesty
  # token -- a hollow M33 pass fails here.
  if ! printf '%s' "${OUTPUT}" | grep -qE -- 'prov-sig: sig=LMS-SHA256-W4-H10 conformance=RFC8554 kat=RFC8554-PASS sha256-kat=FIPS180-4-PASS root=0x[0-9a-f]{16} sig-verified=0x0*1 tamper-rejected-ots=0x0*1 tamper-rejected-merkle=0x0*1 attest-decoded=0x0*1 attest-digest=0x[0-9a-f]{16} head-persisted=0x0 head-reboot-survived=0x0 measure=SELF-NO-HW-ROOT selfmeasure=UNATTESTED-LOADER key=SIMULATED-ENROLLED-CI-CUSTODIED exclusivity=OFF-PLATFORM-ONLY state=SIMULATED-REUSE-OK-NO-SECURITY splitview=UNDETECTED-NO-WITNESS-QUORUM sidechannel=NOT-CLAIMED sec=ASSUMED-FROM-LITERATURE stage=A-VERIFY-ONLY'; then
    echo ">> FAIL: M33 marker present but the full 'prov-sig: ...' stage-A witness (every earned flag =0x1 + BOTH regional tamper tokens + both KAT tokens + every honesty token) was NOT seen (hollow M33 pass)" >&2
    exit 1
  fi
  # (by-name reject) the DISQUALIFIED signature family + the measure overclaims +
  # the D1 conformance fallback, near the M33 lines.
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M33:|prov-sig:)' \
       | grep -qiE -- 'conformance=NONE|Ed25519|curve25519|P-256|secp|measured[- ]boot|attested[- ]boot|non[- ]falsifiable|chain[- ]of[- ]trust|RTM|TPM'; then
    echo ">> FAIL: M33 line carries a disqualified-family / measure-overclaim / D1-fallback token (Ed25519/curve25519/P-256/measured-boot/RTM/TPM/conformance=NONE) -- rejected by name (proposal §8.3)" >&2
    exit 1
  fi
  # (strip-then-reject) strip the DECLARED tokens FIRST, then reject overclaim
  # vocabulary near the M33 lines (the M29/M30/M31 global rejects stay in force).
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M33:|prov-sig:)' \
       | sed -e 's/LMS-SHA256-W4-H10//g' -e 's/RFC8554-PASS//g' -e 's/RFC8554//g' \
             -e 's/FIPS180-4-PASS//g' -e 's/SELF-NO-HW-ROOT//g' -e 's/UNATTESTED-LOADER//g' \
             -e 's/SIMULATED-ENROLLED-CI-CUSTODIED//g' -e 's/OFF-PLATFORM-ONLY//g' \
             -e 's/SIMULATED-REUSE-OK-NO-SECURITY//g' -e 's/UNDETECTED-NO-WITNESS-QUORUM//g' \
             -e 's/NOT-CLAIMED//g' -e 's/ASSUMED-FROM-LITERATURE//g' -e 's/A-VERIFY-ONLY//g' \
       | grep -qiE -- 'unforgeable|tamper[- ]proof|provably[- ]secure|only[- ]the[- ]operator|reproducible|hardware[- ]root|secure[- ]boot|authenticated[- ]human|trusted[- ]boot|never[- ]reuse'; then
    echo ">> FAIL: M33 line carries an overclaim after stripping the declared tokens (unforgeable/tamper-proof/provably-secure/only-the-operator/reproducible/hardware-root/secure-boot/authenticated-human/never-reuse) (proposal §8.7)" >&2
    exit 1
  fi
  # (positive-require the marker) the STAGE-A marker -- NOT the stage-B
  # 'M33: prov-lineage OK' (which closes #91 with the persisted head).
  if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M33: prov-lineage verify OK'; then
    echo ">> FAIL: final marker present but 'M33: prov-lineage verify OK' missing (M33 displaced/regressed)" >&2
    exit 1
  fi

  # M38 (stage B) GUARDS (proposal §8 -- house order: skip-reject, positive-
  # require [the anti-hollow core + the §8.6 CROSS-PROCESS independent recompute],
  # by-name rejects, lane cross-pin, inherited tripwires, strip-then-reject). The
  # guest drives the verified organ-loop over the cap chokepoint; the marker is
  # the NEW cumulative tail. M38 displaces NOTHING below it (every prior head is
  # byte-identical -- the conductor folds on its OWN lane).
  #
  # (§8.1) Skip-reject: honest-skip-is-FAILURE, never green-by-omission. No
  # skip/single-organ/always-accept variant may carry the marker substring.
  if printf '%s' "${OUTPUT}" | grep -qiE -- 'M38: conductor OK \(.*(skip|single organ|always-accept)'; then
    echo ">> FAIL: M38 ran in a skipped/degenerate variant -- honest-skip-is-FAILURE (proposal §8.1)" >&2
    exit 1
  fi
  # (§8.2) Positive-require the FULL one-line conductor witness: every honest
  # token literal, every flag =0x0*1, AND revise-cycles>=0x1 AND organs>=0x2 AND
  # fold-verified=0x1 tamper-caught=0x1 -- the measured anti-hollow thresholds.
  # These printed numbers are NECESSARY-not-sufficient; the load-bearing check is
  # the §8.6 independent host recompute below (a stub printing them fails recompute).
  if ! printf '%s' "${OUTPUT}" | grep -qE -- 'conduct: head=0x[0-9a-f]{16} turns=0x[0-9a-f]+ organs=0x[0-9a-f]+ roles=[TWV]+ organ-seq=0x[0-9a-f]+ verdict=ACCEPT accept-at=0x[0-9a-f]+ revise-cycles=0x[0-9a-f]+ fold-verified=0x0*1 tamper-caught=0x0*1 organ-calls=0x[0-9a-f]+ logical-ticks=0x[0-9a-f]+ attested=0x0*1 prov-tag=0x4 policy=DISCRETE-HAND-WRITTEN-NOT-LEARNED learning=DORMANT retrieval=LEXICAL-NOT-SEMANTIC external-organ=MOCK-IN-CI local-organ=M38-AUTHORED-MOCK verifier=CI-DISCRETE-VERDICT m18-gate=ADMISSION-ONLY-INERT-IN-MOCK cost=HONEST-ACCOUNTED-TOKENED cost-metric=LOGICAL-SURROGATE-NOT-WALLCLOCK orchestration=RAG-AGENTS-NOT-NEW-PARADIGM live[+]web=DISPATCH-ONLY novelty=VERIFIED-PROVENANCE-SOVEREIGN-WRAPPER generativity=OPEN-FRONTIER realtime=NOT-CLAIMED benchmark=NOT-CLAIMED stub-resistance=HOST-RECOMPUTE-FROM-INDEPENDENT-TRACE host=RESIDUAL-TCB sec=ASSUMED-FROM-LITERATURE'; then
    echo ">> FAIL: M38 marker present but the full one-line 'conduct: head=.. ..' witness (every honest token + flag) was NOT seen (hollow M38 pass)" >&2
    exit 1
  fi
  CONDUCT_LINE="$(printf '%s\n' "${OUTPUT}" | grep -E -- '^conduct: head=0x' | head -1)"
  # organs >= 0x2 (the measured multi-organ sequence).
  M38_ORG_HEX="$(printf '%s' "${CONDUCT_LINE}" | sed -E 's/.* organs=0x0*([0-9a-f]+) .*/\1/')"
  if [[ -z "${M38_ORG_HEX}" ]] || (( 16#${M38_ORG_HEX} < 2 )); then
    echo ">> FAIL: M38 organs=0x${M38_ORG_HEX} < 0x2 (a degenerate single-organ stub; the witness requires a measured >=2-organ sequence)" >&2
    exit 1
  fi
  # revise-cycles >= 0x1 (the measured REVISE->ACCEPT cycle).
  M38_RC_HEX="$(printf '%s' "${CONDUCT_LINE}" | sed -E 's/.* revise-cycles=0x0*([0-9a-f]+) .*/\1/')"
  if [[ -z "${M38_RC_HEX}" ]] || (( 16#${M38_RC_HEX} < 1 )); then
    echo ">> FAIL: M38 revise-cycles=0x${M38_RC_HEX} < 0x1 (an always-accept stub; the witness requires a measured REVISE->ACCEPT cycle)" >&2
    exit 1
  fi
  # (§8.6) THE LOAD-BEARING CROSS-PROCESS INDEPENDENT-RECOMPUTE LEG (the loopback/
  # fixture killer): feed the GUEST's OWN emitted `conduct-step:` trace into the
  # host conductor binary (--recompute-from-trace), which INDEPENDENTLY re-folds
  # the M22 lineage via the SAME verified tb_encode::conductor leaf in a SEPARATE
  # process, and string-equal the host-recomputed head against the guest-emitted
  # `conduct: head=..`. A forged guest summary (or a doctored trace) yields a
  # different head -> caught here. The guest emitted >=1 conduct-step line.
  GUEST_HEAD="$(printf '%s' "${CONDUCT_LINE}" | grep -oE 'head=0x[0-9a-f]{16}' | head -1)"
  if [[ -z "${GUEST_HEAD}" ]]; then
    echo ">> FAIL: could not extract the guest-emitted 'conduct: head=0x<hex16>' (the conductor produced no head)" >&2
    exit 1
  fi
  CONDUCT_TRACE="$(printf '%s\n' "${OUTPUT}" | grep -E -- '^conduct-step: ')"
  if [[ -z "${CONDUCT_TRACE}" ]]; then
    echo ">> FAIL: the guest emitted NO 'conduct-step:' trace lines -- the §8.6 independent host-recompute has no input (a forged summary with no trace)" >&2
    exit 1
  fi
  RECOMPUTE_OUT="$(printf '%s\n' "${CONDUCT_TRACE}" | "${CONDUCTOR_HOST_BIN}" --recompute-from-trace 2>/dev/null || true)"
  HOST_HEAD="$(printf '%s' "${RECOMPUTE_OUT}" | grep -oE 'head=0x[0-9a-f]{16}' | head -1)"
  if [[ -z "${HOST_HEAD}" ]]; then
    echo ">> FAIL: the host conductor recompute produced no head from the guest trace (the §8.6 cross-process leg failed to run)" >&2
    echo ">>   recompute-out: ${RECOMPUTE_OUT}" >&2
    exit 1
  fi
  if [[ "${GUEST_HEAD}" != "${HOST_HEAD}" ]]; then
    echo ">> FAIL: CROSS-PROCESS mismatch -- guest-emitted conduct head (${GUEST_HEAD}) != host independent-recompute head (${HOST_HEAD}) from the guest's OWN trace; the lineage is forged/fixtured (proposal §8.6 -- the loopback killer)" >&2
    exit 1
  fi
  # (§8.3) By-name rejects (case-insensitive, near the M38 lines): the learned/
  # ES/CMA policy, the live backend, a learned verifier, and the embedding/cosine/
  # loopback/fixture/replay vocabulary are structurally banned from the mock chain.
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(conduct:|conduct-step:|M38:)' | grep -qiE -- 'policy=LEARNED|policy=ES|policy=CMA|KAN_ACTIVE=true|backend=ANTHROPIC-LIVE|verifier=LEARNED|verifier=CLASSIFIER|embedding|cosine|loopback|fixture|canned|replay|(^|[^[:alnum:]])real-infer'; then
    echo ">> FAIL: M38 marker/witness carries a by-name reject token (learned/ES/CMA/live/embedding/cosine/loopback/fixture/replay) -- the conductor policy is HAND-WRITTEN + the verifier is the discrete CI verdict (proposal §8.3)" >&2
    exit 1
  fi
  # (§8.5) Inherited tripwires: every conduct-step trace line is lowercase-hex
  # ONLY (regex-inert -- model-derived bytes cannot forge a marker/token/escape).
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])conduct-step:' | grep -vE -- '^conduct-step: turn=0x[0-9a-f]+ role=0x[0-9a-f]+ organ=0x[0-9a-f]+ verdict=0x[0-9a-f]+ organ-calls=0x[0-9a-f]+ t-logical=0x[0-9a-f]+$' | grep -q .; then
    echo ">> FAIL: a conduct-step line violates the strict lowercase-hex grammar -- the conductor trace must cross serial ONLY hex-encoded (proposal §8.5)" >&2
    exit 1
  fi
  # (§8.7) Strip-then-reject: strip the declared token VALUES FIRST, then reject
  # any residual claim vocabulary near the M38 lines (the M29 discipline: ALL
  # claims live in structured stripped tokens, never bare words). The inside-a-
  # token occurrences (LEXICAL-NOT-SEMANTIC, NOT-LEARNED, NOT-WALLCLOCK) survive.
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(conduct:|M38:)' \
       | sed -E 's/[a-z+-]+=[A-Za-z0-9+/.:_-]+//g' \
       | grep -qiE -- 'learned|trained|intelligen|understood|generaliz|benchmark|SOTA|real-time|semantic|cosine|float|embedding'; then
    echo ">> FAIL: a residual claim word (learned/trained/intelligen/understood/generaliz/benchmark/SOTA/real-time/semantic/float/embedding) survives token-stripping near the M38 lines (proposal §8.7 razor)" >&2
    exit 1
  fi

  echo ">> PASS: observed marker '${MARKER}' (and 'M31: infer-e2e OK backend=MOCK-DETERMINISTIC' + 'M30: infer-transport OK' + 'M29: khash-mac OK' + 'M28: operator-cmd OK' + 'M26: exit-telemetry OK' + 'M25: operator OK' + 'M24: bakeoff OK' gate-not-met + 'M23: experience OK' + 'M22: provenance OK' + 'M21: kan-policy OK' + 'M20: persist OK' + 'M19: virtio OK' + 'M14.2: blocking-recv OK'; M30 cross-process challenge/tag equality held; M31 mock e2e witnessed; M38 conductor loop witnessed + the guest trace independently re-folded host-side (${GUEST_HEAD} == ${HOST_HEAD}))" >&2
  exit 0
fi

echo ">> FAIL: marker '${MARKER}' not seen (qemu/timeout rc=${RC})" >&2
# #71 diagnosis (failure path ONLY): dump the QEMU interrupt-trace tail so a
# single CI catch is decisive. The ghost-IRQ signature -- QEMU TCG injecting
# cpu_get_pic_interrupt()'s -1 unguarded, surfacing as a guest #GP with the
# non-architectural error code 0xfffffffa = (-1)*8+2 -- prints as a literal
# 'Servicing hardware INT=0xffffffff' line immediately before the v=0d
# e=fffffffa exception trace. That line confirms the upstream emulator bug
# (kernel blameless); its absence on a caught flake falsifies the hypothesis.
if [[ -s "${INT_LOG}" ]]; then
  echo ">> [#71] qemu -d int trace tail (ghost-IRQ fingerprint = 'Servicing hardware INT=0xffffffff'):" >&2
  tail -n 80 "${INT_LOG}" >&2
  if grep -q 'Servicing hardware INT=0xffffffff' "${INT_LOG}"; then
    echo ">> [#71] GHOST-IRQ SIGNATURE CONFIRMED: QEMU TCG injected intno=-1 (upstream bug, missing intno>=0 guard) -- kernel blameless" >&2
  fi
fi
exit 1
