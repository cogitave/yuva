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
MARKER='M29: khash-mac OK'
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
trap 'rm -f "$IMG" "$INT_LOG"' EXIT
truncate -s 4M "$IMG"

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
  echo ">> PASS: observed marker '${MARKER}' (and 'M28: operator-cmd OK' + 'M26: exit-telemetry OK' + 'M25: operator OK' + 'M24: bakeoff OK' gate-not-met + 'M23: experience OK' + 'M22: provenance OK' + 'M21: kan-policy OK' + 'M20: persist OK' + 'M19: virtio OK' + 'M14.2: blocking-recv OK')" >&2
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
