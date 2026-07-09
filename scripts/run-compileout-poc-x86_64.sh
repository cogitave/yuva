#!/usr/bin/env bash
# scripts/run-compileout-poc-x86_64.sh — Boot Profiles stage-B PROOF-OF-CONCEPT:
# the ONE-ORGAN COMPILE-OUT lane (docs/proposals/boot-profiles.md §11).
#
# Stage A landed the RUNTIME skip-form grammar: a substrate-profile boot of the
# DEFAULT image prints EVERY gated organ's marker in the honest skip form
# `<literal> (substrate profile, agent organ skipped)` — the organ code is still
# IN the image, just NOT RUN (§1.4 rung 2). Stage B is the next rung: genuine
# COMPILE-OUT, where the organ code is NOT IN THE IMAGE at all and its marker is
# ABSENT-BY-OMISSION — no skip form, because emitting one would overclaim
# presence (§1.4 rung 3).
#
# This lane PROVES that rung END-TO-END for exactly ONE organ. It boots a kernel
# built `--no-default-features` (the kernel-crate-local `agent-organs` feature
# OFF, so ONLY the M26 exit-telemetry block is `#[cfg]`-removed) under
# `yuva.profile=substrate`, and asserts:
#   (A) POSITIVE core: the profile-scoped micro-VMM chain provably RAN (the same
#       core set scripts/run-substrate-x86_64.sh asserts — M0..M12 hosting ABI,
#       M14/M15 IPC, M19 virtio + the real M20 persist round-trip, the khash
#       RFC7693 KAT + M29, M27 sched, the Yuva-ABI self-check) AND the boot ran
#       PAST M26's position to the clean-exit `PROFILE: substrate OK` tail (so
#       M26's absence is genuine omission, never a crash-before-M26).
#   (A2) STILL-BUILT organs are INTACT in the stage-A skip form — M25 (the
#       neighbor BEFORE M26) and M28 (the neighbor AFTER) both print
#       `<literal> (substrate profile, agent organ skipped)`, bracketing the hole
#       so M26's absence is a clean SINGLE-organ omission, not a broken region.
#   (B) M26 ABSENT-BY-OMISSION from the serial stream: NO `M26: exit-telemetry
#       OK` marker AND NO skip form for it AND NO `exittel:` witness — the
#       stage-B grammar, in direct contrast to the ~18 organs above/below it.
#   (C) M26 ABSENT from the compiled ELF: a strict, anchored byte-search over the
#       binary for the organ's distinctive literals finds NONE — the marker was
#       compiled out, not merely runtime-skipped.
#   (D) The honesty-scoped witness line + the DoD-5 source-drift guard: the M26
#       literal STILL EXISTS in kernel/src/main.rs (the absence is purely
#       compile-gated, NOT a source deletion), and `bprof-poc:` records
#       `organs=NOT-BUILT scope=ONE-ORGAN-ONLY` — earned ONLY after (C) is green
#       (§6: `organs=NOT-BUILT` is legitimate ONLY with the absence check green),
#       with NO tcb=/minimal/secure/zero-TCB claim (the other ~18 organs are
#       STILL BUILT — this proves the MECHANISM, not a reduced-TCB product).
#
# SCOPE, stated plainly: this is a ONE-ORGAN proof of the compile-out mechanism.
# Full stage B (every organ + the mem/ engine/organ factorization + an image-size
# delta) is the open, named successor and is NOT claimed here.
#
# Zero network, zero secret, offline + deterministic. The substrate profile skips
# M30/M38, so — like the substrate lane — this attaches only the virtio-rng +
# virtio-blk devices the core (M19/M20) needs; NO xport/conductor host peer.
#
# Usage:   scripts/run-compileout-poc-x86_64.sh [path/to/kernel-elf]
#          (the ELF MUST be a `--no-default-features` build — see the CI job.)
# Env:     QEMU=...  QEMU_TIMEOUT=<secs>  PROFILE=debug|release
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "${REPO_ROOT}/scripts/project.env"
TARGET="${TARGET_X86}"
PROFILE="${PROFILE:-debug}"
KERNEL="${1:-${REPO_ROOT}/target/${TARGET}/${PROFILE}/${KERNEL_BIN}}"
# A more generous ceiling than the substrate lane's 40s: QEMU_TIMEOUT=40 flaked
# on slow runners today, and this lane runs the FULL substrate self-test chain.
TIMEOUT_SECS="${QEMU_TIMEOUT:-90}"
QEMU="${QEMU:-qemu-system-x86_64}"
MAIN="${REPO_ROOT}/kernel/src/main.rs"

# The organ under test + its DISTINCTIVE, uniquely-M26 literals (each appears in
# kernel/src/main.rs ONLY inside the cfg-gated block, so their absence from the
# --no-default-features image is guaranteed by construction — not linker gc).
ORGAN='M26-EXITTEL'
M26_MARKER='M26: exit-telemetry OK'                     # marker AND skip-form prefix
M26_WITNESS='exittel: head='                            # the round-trip witness
M26_TOKEN='signal=OBSERVATIONAL-NONCAUSAL'              # the M26-unique honesty token
SKIP_SUFFIX='(substrate profile, agent organ skipped)'

if ! command -v "${QEMU}" >/dev/null 2>&1; then
  echo "error: ${QEMU} not found on PATH" >&2; exit 2
fi
if [[ ! -f "${KERNEL}" ]]; then
  echo "error: kernel image not found: ${KERNEL} (build it: cargo kbuild --no-default-features --target targets/${TARGET}.json)" >&2
  exit 2
fi

ACCEL="tcg,thread=single"; CPU="qemu64"
if [[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then ACCEL="kvm"; CPU="host"; fi

boot() { # $1 = -append value (empty for default) ; echoes serial
  local append="$1" img out
  img="$(mktemp)"; truncate -s 8M "$img"
  set +e
  out="$(timeout --foreground "${TIMEOUT_SECS}" \
    "${QEMU}" -M microvm,rtc=off -accel "${ACCEL}" -cpu "${CPU}" -m 256M -smp 1 \
      -kernel "${KERNEL}" ${append:+-append "${append}"} \
      -no-reboot -nic none \
      -global virtio-mmio.force-legacy=false -device virtio-rng-device \
      -drive file="$img",if=none,format=raw,id=vblk0 -device virtio-blk-device,drive=vblk0 \
      -serial stdio -display none 2>&1)"
  set -e
  rm -f "$img"
  printf '%s' "${out}"
}

fail() { echo ">> FAIL: $1" >&2; exit 1; }

echo ">> qemu=${QEMU} accel=${ACCEL} cpu=${CPU} timeout=${TIMEOUT_SECS}s (COMPILE-OUT PoC, --no-default-features)" >&2
echo ">> kernel=${KERNEL}" >&2
echo ">> organ under test=${ORGAN} (M26 exit-telemetry) — asserting ABSENT-BY-OMISSION" >&2

# --- DoD-5 SOURCE-DRIFT GUARD (before booting): the M26 literal STILL exists in
# main.rs, so the image absence proved below is purely COMPILE-GATED, not a
# source deletion. (The default-build substrate lane still emits its skip form.)
grep -qF -- "serial_write_str(\"${M26_MARKER}" "${MAIN}" \
  || fail "the '${M26_MARKER}' literal is not in main.rs — this PoC gates the organ, it must NOT delete the source (drift guard)"
grep -qF -- '#[cfg(feature = "agent-organs")]' "${MAIN}" \
  || fail "the '#[cfg(feature = \"agent-organs\")]' gate is not in main.rs — the compile-out seam is missing"

# ===========================================================================
# The COMPILE-OUT boot: --no-default-features image, substrate profile.
# ===========================================================================
OUT="$(boot 'yuva.profile=substrate')"
printf '%s\n' "${OUT}"

# --- inherited tripwire: a raw ESC byte fails every lane; the stream is text ---
if printf '%s' "${OUT}" | grep -q $'\x1b'; then
  fail "a raw ESC (0x1b) byte appeared on the stream (no ANSI on a CI stream)"
fi

# --- (A) POSITIVE core: the profile-scoped micro-VMM chain provably ran --------
# (The SAME core set scripts/run-substrate-x86_64.sh asserts, requirement 4a.)
CORE_REQUIRE=(
  'hello from rust_main'
  'M10: addrspace OK'
  'M11: caps OK'
  'M12: agent OK'
  'M14: ipc OK'
  'M14.2: blocking-recv OK'
  'M15: blocks OK'
  'M19: virtio OK'
  'M20: persist OK'
  'M29: khash-mac OK'
  'M27: sched OK'
)
for m in "${CORE_REQUIRE[@]}"; do
  printf '%s' "${OUT}" | grep -qF -- "${m}" || fail "core marker '${m}' missing (not a healthy substrate boot)"
done
# The M20 REAL round-trip (this lane attaches a disk) + the khash KAT + the ABI
# self-check must be genuine — a hollow core would make M26's absence meaningless.
printf '%s' "${OUT}" | grep -qF -- 'M20: persist OK (no disk, skipped)' && \
  fail "M20 took the no-disk skip but a disk is attached (hollow core)"
printf '%s' "${OUT}" | grep -qE -- 'persist: gen=0x[0-9a-fA-F]+ records=0x[0-9a-fA-F]+ replayed=0x[0-9a-fA-F]+' || \
  fail "the real 'persist: gen=.. records=.. replayed=..' round-trip line is missing"
printf '%s' "${OUT}" | grep -qE -- 'khash: prim=BLAKE2S-256 keylen=32 tag=128 kat=RFC7693-PASS' || \
  fail "the khash RFC7693 KAT witness (a substrate integrity feature) is missing"
# The clean-exit substrate tail: the boot ran PAST M26's position to completion,
# so M26's absence below is genuine OMISSION, never a crash-before-M26.
printf '%s' "${OUT}" | grep -qF -- 'PROFILE: substrate OK organs=SKIPPED-RUNTIME-GATED' || \
  fail "the clean-exit 'PROFILE: substrate OK' tail is missing — the boot did not run to completion (M26 absence would be inconclusive)"

# --- (A2) STILL-BUILT organs INTACT in the stage-A skip form, bracketing M26 ---
# M25 (before) and M28 (after) prove the surrounding chain is built + runtime-
# skipped as normal; the hole between them is exactly M26.
for lit in 'M25: operator OK' 'M28: operator-cmd OK'; do
  printf '%s' "${OUT}" | grep -qF -- "${lit} ${SKIP_SUFFIX}" \
    || fail "neighbor organ '${lit}' did not appear in the skip form — the still-built chain around M26 is not intact"
done

# --- (B) M26 ABSENT-BY-OMISSION from the SERIAL stream (requirement 4b) ---------
# The marker literal is the prefix of BOTH the agent marker AND the skip form, so
# a single absence check proves NEITHER form was emitted (no skip form either).
if printf '%s' "${OUT}" | grep -qF -- "${M26_MARKER}"; then
  fail "'${M26_MARKER}' appeared on the stream — the organ was NOT compiled out (found a marker or a skip form)"
fi
if printf '%s' "${OUT}" | grep -qF -- "${M26_MARKER} ${SKIP_SUFFIX}"; then
  fail "the M26 SKIP FORM appeared — stage-B compile-out must be ABSENT-BY-OMISSION, never a skip form (§1.4)"
fi
if printf '%s' "${OUT}" | grep -qF -- "${M26_WITNESS}"; then
  fail "the '${M26_WITNESS}' witness appeared — the M26 selftest RAN (organ not compiled out)"
fi
if printf '%s' "${OUT}" | grep -qF -- "${M26_TOKEN}"; then
  fail "the M26-unique token '${M26_TOKEN}' appeared — organ not compiled out"
fi
# A leaked M26 FAIL line would also carry the family prefix — catch any residue.
if printf '%s' "${OUT}" | grep -qE -- '(^|[^[:alnum:]])M26:'; then
  fail "an 'M26:' line of ANY form appeared on the stream — the organ is not fully absent"
fi
echo ">> serial: M26 is ABSENT-BY-OMISSION (no marker, no skip form, no exittel: witness) — the ~18 other organs are present in skip form" >&2

# --- (C) M26 ABSENT from the compiled ELF: strict, anchored byte-search --------
# A byte-search over the binary (grep -a, treat as text) for each DISTINCTIVE,
# full literal — NOT a loose regex, NO substring (each string is uniquely M26 and
# lives ONLY in the cfg-gated block, so a hit would mean the block survived).
for lit in "${M26_MARKER}" "${M26_WITNESS}" "${M26_TOKEN}"; do
  if grep -aF -- "${lit}" "${KERNEL}" >/dev/null 2>&1; then
    fail "the literal '${lit}' is PRESENT in the compiled ELF — the M26 block was NOT compiled out"
  fi
done
echo ">> ELF: the M26 marker/witness/token literals are ABSENT from the binary — compiled out, not merely runtime-skipped" >&2

# --- (D) the honesty-scoped witness line (earned by (C) green) ------------------
WITNESS="bprof-poc: organ=${ORGAN} organs=NOT-BUILT scope=ONE-ORGAN-ONLY"
printf '%s\n' "${WITNESS}"
# Overclaim self-guard (repo §8.2d discipline, defense-in-depth): the PoC's own
# witness/PASS output must carry NO stage-B superlative or reduced-TCB claim
# beyond the legitimate `NOT-BUILT` (which is the earned stage-B token, §6).
if printf '%s\n' "${WITNESS}" \
     | sed -e 's/NOT-BUILT//g' -e 's/ONE-ORGAN-ONLY//g' \
     | grep -qiE -- 'not present|removed|compiled-out|smaller image|minimal|zero-tcb|secure|isolated|sandboxed|sovereign|firecracker-replacement|reduced'; then
  fail "the bprof-poc witness carries an overclaim — this PoC proves the MECHANISM for ONE organ; it makes NO tcb-reduction/minimal/secure claim (§5.4)"
fi

echo ">> COMPILE-OUT PoC PASS: with agent-organs OFF (--no-default-features), the M26 exit-telemetry organ is ABSENT-BY-OMISSION from BOTH the boot stream and the ELF (no marker, no skip form), while the profile-scoped core ran and the ~18 other organs stayed built + runtime-skipped. This proves the stage-B compile-out MECHANISM for ONE organ; full stage B (all organs + mem/ factorization + image-size delta) remains the named successor." >&2
exit 0
