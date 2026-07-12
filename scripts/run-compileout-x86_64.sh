#!/usr/bin/env bash
# scripts/run-compileout-x86_64.sh — Boot Profiles stage-B COMPILE-OUT lane,
# GENERALIZED to EVERY main.rs agent organ (docs/proposals/boot-profiles.md §11).
# Supersedes the original one-organ compile-out PoC lane (the M26 organ): the
# mechanism it proved for ONE organ is here asserted, TABLE-DRIVEN, for all 20
# main.rs organ blocks at once — the 15 self-contained organs AND (stage-B PR-4)
# the M25/M30/M31/M32-local/M38 PIPELINE cluster, the last runtime-gated holdouts.
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
#       RFC7693 KAT + M29, M27 sched) AND the boot ran PAST every organ's
#       position to the clean-exit `PROFILE: substrate OK` tail (so each
#       absence is genuine omission, never a crash-before-organ).
#   (A2) stage-B PR-4: NO pipeline organ remains runtime-gated. The pipeline
#       cluster (M25, M30, M31, M32-local, M38) — whose blocks bind values later
#       blocks consume — is now CO-GATED as ONE data-flow span and COMPILED OUT
#       (it joined the ORGANS absence table). No stage-A "still-built skip-form"
#       assertion remains; the cluster's absence is proven by (B)/(C) like any
#       other organ.
#   (B) Each organ ABSENT-BY-OMISSION from the serial stream: NO marker, NO skip
#       form for it, NO `<witness>` line, and NO residue of its `M<n>:` family
#       prefix — the stage-B grammar (M32 is WITNESS-ONLY: its `infer-local:`
#       prefix stands in for the marker).
#   (C) Each organ ABSENT from the compiled ELF: a strict, anchored byte-search
#       over the binary for the organ's distinctive marker + witness literals
#       finds NONE — compiled out, not merely runtime-skipped.
#   (D) The honesty-scoped witness line + the source-drift guard: every organ's
#       marker literal STILL EXISTS in kernel/src/main.rs (the absence is purely
#       compile-gated, NOT a source deletion) and the `#[cfg]` seam is present;
#       and `bprof:` records `organs-not-built=<N> scope=MAIN-RS-ORGAN-BLOCKS
#       pipeline-organs=NONE-REMAINING` — earned ONLY after (C) is green, with NO
#       tcb/minimal/secure claim and NO "zero agent code in the image" claim
#       (main.rs still LINKS tb-hal/tb-encode organ helpers — the crate-level
#       symbol check is the named PR-5 successor).
#
# SCOPE, stated plainly: this compiles out EVERY main.rs ORGAN BLOCK. It does NOT
# claim the IMAGE is organ-free — main.rs still LINKS tb-hal/tb-encode organ
# helpers; the crate-level symbol check that those are gone, the mem/ engine/organ
# factorization + an image-size delta are the open, named PR-5 successor.
#
# Zero network, zero secret, offline + deterministic. The M30/M31/M32/M38 wire
# exchange is COMPILED OUT of this image, so — like the substrate lane — this
# attaches only the virtio-rng + virtio-blk devices the core (M19/M20) needs; NO
# xport/conductor host peer is spawned (none would be reachable anyway).
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
# THE TABLE: one row per COMPILED-OUT main.rs organ block.
#   MARKER   — the `M<n>: ... OK` DoD marker (the prefix of BOTH the agent marker
#              AND the stage-A skip form, so one absence check proves neither was
#              emitted). Lives ONLY inside the organ's cfg-gated if/else.
#   WITNESS  — a distinctive round-trip line emitted ONLY inside the gated block
#              (or its co-gated helper, for M18.2/M24), so its presence would mean
#              the organ RAN and its absence-in-ELF means the block was removed.
#   FAMILY   — the `M<n>:` family prefix (dots escaped) for the residue sweep;
#              a leaked FAIL line of ANY form would carry it.
# The 20 rows = the 15 self-contained organs + the M25/M30/M31/M32/M38 PIPELINE
# cluster stage-B PR-4 compiles out. M28 is the ASYMMETRIC one: only its operator-
# cmd organ half is compiled out (marker + witness below); the M29 khash KAT it
# used to bracket is SUBSTRATE-CORE and stays in the image + the core-PRESENT
# assertions (§3.3), NEVER absent. The pipeline rows bind values consumed by LATER
# blocks, so main.rs co-gates the WHOLE data-flow span (see the M31-part-1 site).
# M32 is WITNESS-ONLY: the local-organ receive has NO `M<n>:` marker, so its
# census-forbidden `infer-local:` prefix fills the MARKER slot.
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
  "M28: operator-cmd OK|opcmd: challenge=|M28:"
  "M33: prov-lineage OK|prov-sig: sig=LMS-SHA256-W4-H10|M33:"
  "M39: corpus OK|corpus: head=|M39:"
  "M40: recall OK|recall: top-id=|M40:"
  # ---- the PIPELINE cluster, compiled out by stage-B PR-4 (was runtime-gated) ----
  # These bind values consumed by LATER blocks (the M31 leg-1 tuple -> m31_fold ->
  # M25; m31_chan -> M30 -> M31-part-2 -> M32-local -> M38), so main.rs co-gates the
  # WHOLE data-flow span behind `agent-organs`. Each has an `M<n>:` DoD marker EXCEPT
  # M32: the local-organ receive is WITNESS-ONLY, so its census-forbidden
  # `infer-local:` prefix stands in the MARKER slot (there is no `M32:` marker).
  "M25: operator OK|opframe: tx_head=|M25:"
  "M30: infer-transport OK|xport: bus=|M30:"
  "M31: infer-e2e OK|infer: backend=MOCK-DETERMINISTIC|M31:"
  "infer-local:|infer-local: backend=LOCAL-STANDIN|infer-local"
  "M38: conductor OK|conduct: head=|M38:"
)
NOT_BUILT="${#ORGANS[@]}"

# stage-B PR-4: the PIPELINE cluster (M25/M30/M31/M32-local/M38) is now COMPILED
# OUT too — moved into the ORGANS table above. NO runtime-gated pipeline organ
# remains in main.rs, so there is no stage-A skip-form ("still built") assertion
# left to make. (main.rs still LINKS tb-hal/tb-encode organ helpers; the crate-
# level symbol check that they are gone is the named PR-5 successor — NOT claimed
# here.)

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
echo ">> main.rs organ blocks under test=${NOT_BUILT} — asserting ABSENT-BY-OMISSION" >&2

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

# --- (A2) stage-B PR-4: NO pipeline organ remains runtime-gated -----------------
# The pipeline cluster (M25/M30/M31/M32-local/M38) is COMPILED OUT this PR (it
# joined the ORGANS absence table above), so there is no "still-built skip-form"
# assertion left to make. Its absence is proven by (B)/(C) below, exactly like
# every other organ. (main.rs no longer runtime-gates ANY organ block.)
echo ">> serial: NO pipeline organ remains runtime-gated — the whole cluster is compiled out (asserted absent below)" >&2

# --- (B) each organ ABSENT-BY-OMISSION from the SERIAL stream -------------------
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
echo ">> serial: all ${NOT_BUILT} main.rs organ blocks are ABSENT-BY-OMISSION (no marker, no skip form, no witness, no family residue)" >&2

# --- (C) each organ ABSENT from the compiled ELF --------------------------------
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
echo ">> ELF: every main.rs organ block's marker + witness literal is ABSENT from the binary — compiled out, not merely runtime-skipped" >&2

# --- (D, part 2) the honesty-scoped witness line (earned by (C) green) ----------
WITNESS_LINE="bprof: organs-not-built=${NOT_BUILT} scope=MAIN-RS-ORGAN-BLOCKS pipeline-organs=NONE-REMAINING"
printf '%s\n' "${WITNESS_LINE}"
# Overclaim self-guard (repo §8.2d discipline, defense-in-depth): the witness must
# carry NO reduced-TCB / minimal / secure claim beyond the legitimate, earned
# tokens (`organs-not-built=<N>`, `MAIN-RS-ORGAN-BLOCKS`, `NONE-REMAINING`). The
# scope is MAIN.RS ONLY: main.rs still LINKS tb-hal/tb-encode organ code, so this
# makes NO "zero agent code in the image" / reduced-TCB / minimal / secure claim
# (the crate-level symbol check is the named PR-5 successor).
if printf '%s\n' "${WITNESS_LINE}" \
     | sed -e 's/organs-not-built=[0-9]*//g' -e 's/MAIN-RS-ORGAN-BLOCKS//g' -e 's/NONE-REMAINING//g' \
     | grep -qiE -- 'not present|removed|compiled-out|smaller image|minimal|zero-tcb|secure|isolated|sandboxed|sovereign|firecracker-replacement|reduced'; then
  fail "the bprof witness carries an overclaim — this stage compiles out the MAIN.RS organ blocks only; it makes NO zero-image/tcb-reduction/minimal/secure claim (§5.4)"
fi

echo ">> COMPILE-OUT PASS: with agent-organs OFF (--no-default-features), all ${NOT_BUILT} main.rs organ blocks (the self-contained organs AND the M25/M30/M31/M32-local/M38 pipeline cluster) are ABSENT-BY-OMISSION from BOTH the boot stream and the ELF (no marker, no skip form), while the profile-scoped core ran to the clean 'PROFILE: substrate OK' tail. NO organ block remains runtime-gated in main.rs. main.rs still LINKS tb-hal/tb-encode organ helpers; the crate-level symbol check + mem/ factorization + image-size delta remain the named PR-5 successor." >&2
exit 0
