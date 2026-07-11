#!/usr/bin/env bash
# scripts/run-compileout-x86_64.sh — Boot Profiles stage-B COMPILE-OUT lane,
# GENERALIZED to every SELF-CONTAINED agent organ (docs/proposals/boot-profiles.md
# §11). Supersedes the original one-organ compile-out PoC lane (the M26 organ):
# the mechanism it proved for ONE organ is here asserted, TABLE-DRIVEN, for all 14
# self-contained organs at once.
#
# Stage A landed the RUNTIME skip-form grammar: a substrate-profile boot of the
# DEFAULT image prints EVERY gated organ's marker in the honest skip form
# `<literal> (substrate profile, agent organ skipped)` — the organ code is still
# IN the image, just NOT RUN (§1.4 rung 2). Stage B is the next rung: genuine
# COMPILE-OUT, where the organ code is NOT IN THE IMAGE at all and its marker is
# ABSENT-BY-OMISSION — no skip form, because emitting one would overclaim
# presence (§1.4 rung 3).
#
# This lane boots a kernel built `--no-default-features` (the kernel-crate-local
# `agent-organs` feature OFF, so EVERY `#[cfg(feature = "agent-organs")]` block is
# removed) under `yuva.profile=substrate`, and asserts, per the two coexisting
# grammars:
#   (A) POSITIVE core: the profile-scoped micro-VMM chain provably RAN (the same
#       core set scripts/run-substrate-x86_64.sh asserts — M0..M12 hosting ABI,
#       M14/M15 IPC, M19 virtio + the real M20 persist round-trip, the khash
#       RFC7693 KAT + M29, M27 sched) AND the boot ran PAST every self-contained
#       organ's position to the clean-exit `PROFILE: substrate OK` tail (so each
#       absence is genuine omission, never a crash-before-organ).
#   (A2) PIPELINE organs STILL BUILT + runtime-skipped: the not-yet-migrated
#       pipeline cluster (M25, M28, M30, M31, M38) each prints its stage-A skip
#       form `<literal> (substrate profile, agent organ skipped)` — the two
#       grammars coexist. These bind values later folds consume, so they stay
#       runtime-gated this stage (NOT compiled out).
#   (B) Each SELF-CONTAINED organ ABSENT-BY-OMISSION from the serial stream: NO
#       marker, NO skip form for it, NO `<witness>` line, and NO residue of its
#       `M<n>:` family prefix — the stage-B grammar, in direct contrast to the
#       pipeline cluster above.
#   (C) Each SELF-CONTAINED organ ABSENT from the compiled ELF: a strict, anchored
#       byte-search over the binary for the organ's distinctive marker + witness
#       literals finds NONE — compiled out, not merely runtime-skipped.
#   (D) The honesty-scoped witness line + the source-drift guard: every organ's
#       marker literal STILL EXISTS in kernel/src/main.rs (the absence is purely
#       compile-gated, NOT a source deletion) and the `#[cfg]` seam is present;
#       and `bprof:` records `organs-not-built=<N> scope=SELF-CONTAINED-ONLY
#       pipeline-organs=STILL-BUILT-RUNTIME-GATED` — earned ONLY after (C) is
#       green, with NO tcb/minimal/secure claim (the pipeline organs are STILL
#       BUILT — this is the compile-out of the SELF-CONTAINED SUBSET, not a
#       reduced-TCB product).
#
# SCOPE, stated plainly: this compiles out the SELF-CONTAINED subset only. The
# FINAL crate-level organ gate + the mem/ engine/organ factorization + an
# image-size delta are the open, named successor and are NOT claimed here.
#
# Zero network, zero secret, offline + deterministic. The substrate profile skips
# M30/M38, so — like the substrate lane — this attaches only the virtio-rng +
# virtio-blk devices the core (M19/M20) needs; NO xport/conductor host peer.
#
# Usage:   scripts/run-compileout-x86_64.sh [path/to/kernel-elf]
#          (the ELF MUST be a `--no-default-features` build — see the CI job.)
# Env:     QEMU=...  QEMU_TIMEOUT=<secs>  PROFILE=debug|release
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "${REPO_ROOT}/scripts/project.env"
TARGET="${TARGET_X86}"
PROFILE="${PROFILE:-debug}"
KERNEL="${1:-${REPO_ROOT}/target/${TARGET}/${PROFILE}/${KERNEL_BIN}}"
# A generous ceiling (matches the substrate + PoC lanes): this runs the FULL
# substrate self-test chain. A ceiling is a wall-clock guard, not an assertion.
TIMEOUT_SECS="${QEMU_TIMEOUT:-90}"
QEMU="${QEMU:-qemu-system-x86_64}"
MAIN="${REPO_ROOT}/kernel/src/main.rs"

SKIP_SUFFIX='(substrate profile, agent organ skipped)'

# ---------------------------------------------------------------------------
# THE TABLE: one row per COMPILED-OUT self-contained organ.
#   MARKER   — the `M<n>: ... OK` DoD marker (the prefix of BOTH the agent marker
#              AND the stage-A skip form, so one absence check proves neither was
#              emitted). Lives ONLY inside the organ's cfg-gated if/else.
#   WITNESS  — a distinctive round-trip line emitted ONLY inside the gated block
#              (or its co-gated helper, for M18.2/M24), so its presence would mean
#              the organ RAN and its absence-in-ELF means the block was removed.
#   FAMILY   — the `M<n>:` family prefix (dots escaped) for the residue sweep;
#              a leaked FAIL line of ANY form would carry it.
# The 14 rows = the M26 PoC organ + the 13 this stage generalizes to.
# ---------------------------------------------------------------------------
ORGANS=(
  "M13: memory OK|mem: read-your-writes OK|M13:"
  "M16: infer OK|model: parse+route|M16:"
  "M17: consolidate OK|mem: consolidation cycle is CONSOLIDATE-gated|M17:"
  "M18: evolve OK|mem: skill proposed via WRITE_PROCEDURAL|M18:"
  "M18.1: approval-gate OK|mem: high-impact/EMIT_EXTERNAL merge|M18\.1:"
  "M18.2: held-out OK|mem: N>1 held-out partitions|M18\.2:"
  "M21: kan-policy OK|kan: monotone=|M21:"
  "M22: provenance OK|prov: head=|M22:"
  "M23: experience OK|exp: head=|M23:"
  "M24: bakeoff OK|bakeoff: vlo_kan=|M24:"
  "M26: exit-telemetry OK|exittel: head=|M26:"
  "M33: prov-lineage OK|prov-sig: sig=LMS-SHA256-W4-H10|M33:"
  "M39: corpus OK|corpus: head=|M39:"
  "M40: recall OK|recall: top-id=|M40:"
)
NOT_BUILT="${#ORGANS[@]}"

# The PIPELINE cluster: still built, runtime-gated — asserted PRESENT in the
# stage-A skip form (the two grammars coexist). These declarations feed later
# folds, so they are DELIBERATELY not compiled out this stage.
PIPELINE=(
  'M25: operator OK'
  'M28: operator-cmd OK'
  'M30: infer-transport OK'
  'M31: infer-e2e OK'
  'M38: conductor OK'
)

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

echo ">> qemu=${QEMU} accel=${ACCEL} cpu=${CPU} timeout=${TIMEOUT_SECS}s (COMPILE-OUT, --no-default-features)" >&2
echo ">> kernel=${KERNEL}" >&2
echo ">> self-contained organs under test=${NOT_BUILT} — asserting ABSENT-BY-OMISSION" >&2

# --- (D, part 1) SOURCE-DRIFT GUARD (before booting): every organ's marker
# literal STILL exists in main.rs, so the image absence proved below is purely
# COMPILE-GATED, not a source deletion. (The default build's substrate lane still
# emits every skip form.) The `#[cfg]` seam must also be present.
grep -qF -- '#[cfg(feature = "agent-organs")]' "${MAIN}" \
  || fail "the '#[cfg(feature = \"agent-organs\")]' gate is not in main.rs — the compile-out seam is missing"
for row in "${ORGANS[@]}"; do
  IFS='|' read -r MARKER WITNESS FAMILY <<< "${row}"
  grep -qF -- "serial_write_str(\"${MARKER}" "${MAIN}" \
    || fail "the '${MARKER}' marker literal is not in main.rs — this stage GATES organs, it must NOT delete the source (drift guard)"
done

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
# The M20 REAL round-trip (this lane attaches a disk) + the khash KAT must be
# genuine — a hollow core would make the organs' absence meaningless.
printf '%s' "${OUT}" | grep -qF -- 'M20: persist OK (no disk, skipped)' && \
  fail "M20 took the no-disk skip but a disk is attached (hollow core)"
printf '%s' "${OUT}" | grep -qE -- 'persist: gen=0x[0-9a-fA-F]+ records=0x[0-9a-fA-F]+ replayed=0x[0-9a-fA-F]+' || \
  fail "the real 'persist: gen=.. records=.. replayed=..' round-trip line is missing"
printf '%s' "${OUT}" | grep -qE -- 'khash: prim=BLAKE2S-256 keylen=32 tag=128 kat=RFC7693-PASS' || \
  fail "the khash RFC7693 KAT witness (a substrate integrity feature) is missing"
# The clean-exit substrate tail: the boot ran PAST every organ's position to
# completion, so the absences below are genuine OMISSION, never a crash.
printf '%s' "${OUT}" | grep -qF -- 'PROFILE: substrate OK organs=SKIPPED-RUNTIME-GATED' || \
  fail "the clean-exit 'PROFILE: substrate OK' tail is missing — the boot did not run to completion (the organ absences would be inconclusive)"

# --- (A2) PIPELINE organs STILL BUILT + runtime-skipped, in the skip form ------
# The not-yet-migrated cluster brackets the compiled-out holes; each proves the
# still-built chain is present and merely runtime-gated (the coexisting grammar).
for lit in "${PIPELINE[@]}"; do
  printf '%s' "${OUT}" | grep -qF -- "${lit} ${SKIP_SUFFIX}" \
    || fail "pipeline organ '${lit}' did not appear in the skip form — the still-built runtime-gated chain is not intact"
done
echo ">> serial: the ${#PIPELINE[@]} pipeline organs are PRESENT in the stage-A skip form (still built, runtime-gated)" >&2

# --- (B) each SELF-CONTAINED organ ABSENT-BY-OMISSION from the SERIAL stream ----
for row in "${ORGANS[@]}"; do
  IFS='|' read -r MARKER WITNESS FAMILY <<< "${row}"
  # The marker literal is the prefix of BOTH the agent marker AND the skip form,
  # so a single absence check proves NEITHER form was emitted (no skip form).
  if printf '%s' "${OUT}" | grep -qF -- "${MARKER}"; then
    fail "'${MARKER}' appeared on the stream — that organ was NOT compiled out (a marker or a skip form leaked)"
  fi
  if printf '%s' "${OUT}" | grep -qF -- "${MARKER} ${SKIP_SUFFIX}"; then
    fail "the '${MARKER}' SKIP FORM appeared — stage-B compile-out must be ABSENT-BY-OMISSION, never a skip form (§1.4)"
  fi
  if printf '%s' "${OUT}" | grep -qF -- "${WITNESS}"; then
    fail "the '${WITNESS}' witness appeared — that organ's selftest RAN (not compiled out)"
  fi
  # A leaked FAIL line of ANY form would also carry the family prefix.
  if printf '%s' "${OUT}" | grep -qE -- "(^|[^[:alnum:]])${FAMILY}"; then
    fail "an '${FAMILY}' line of ANY form appeared on the stream — that organ is not fully absent"
  fi
done
echo ">> serial: all ${NOT_BUILT} self-contained organs are ABSENT-BY-OMISSION (no marker, no skip form, no witness, no family residue)" >&2

# --- (C) each SELF-CONTAINED organ ABSENT from the compiled ELF -----------------
# A byte-search over the binary (grep -a, treat as text) for each DISTINCTIVE,
# full literal — NOT a loose regex, NO substring (each string is uniquely the
# organ's and lives ONLY inside its cfg-gated block, so a hit would mean the block
# survived).
for row in "${ORGANS[@]}"; do
  IFS='|' read -r MARKER WITNESS FAMILY <<< "${row}"
  for lit in "${MARKER}" "${WITNESS}"; do
    if grep -aF -- "${lit}" "${KERNEL}" >/dev/null 2>&1; then
      fail "the literal '${lit}' is PRESENT in the compiled ELF — that organ's block was NOT compiled out"
    fi
  done
done
echo ">> ELF: every self-contained organ's marker + witness literal is ABSENT from the binary — compiled out, not merely runtime-skipped" >&2

# --- (D, part 2) the honesty-scoped witness line (earned by (C) green) ----------
WITNESS_LINE="bprof: organs-not-built=${NOT_BUILT} scope=SELF-CONTAINED-ONLY pipeline-organs=STILL-BUILT-RUNTIME-GATED"
printf '%s\n' "${WITNESS_LINE}"
# Overclaim self-guard (repo §8.2d discipline, defense-in-depth): the witness must
# carry NO reduced-TCB / minimal / secure claim beyond the legitimate, earned
# tokens (`organs-not-built=<N>`, `SELF-CONTAINED-ONLY`, `STILL-BUILT-RUNTIME-
# GATED`). The pipeline organs are STILL BUILT, so no tcb-reduction is claimed.
if printf '%s\n' "${WITNESS_LINE}" \
     | sed -e 's/organs-not-built=[0-9]*//g' -e 's/SELF-CONTAINED-ONLY//g' -e 's/STILL-BUILT-RUNTIME-GATED//g' \
     | grep -qiE -- 'not present|removed|compiled-out|smaller image|minimal|zero-tcb|secure|isolated|sandboxed|sovereign|firecracker-replacement|reduced'; then
  fail "the bprof witness carries an overclaim — this stage compiles out the SELF-CONTAINED SUBSET; it makes NO tcb-reduction/minimal/secure claim (§5.4)"
fi

echo ">> COMPILE-OUT PASS: with agent-organs OFF (--no-default-features), all ${NOT_BUILT} self-contained organs are ABSENT-BY-OMISSION from BOTH the boot stream and the ELF (no marker, no skip form), while the profile-scoped core ran to the clean 'PROFILE: substrate OK' tail and the ${#PIPELINE[@]} pipeline organs stayed built + runtime-skipped. This is the compile-out of the SELF-CONTAINED SUBSET; the crate-level organ gate + mem/ factorization + image-size delta remain the named successor." >&2
exit 0
