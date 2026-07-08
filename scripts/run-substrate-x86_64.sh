#!/usr/bin/env bash
# scripts/run-substrate-x86_64.sh — Boot Profiles stage A: the SUBSTRATE lane.
#
# Boots the SAME x86_64 PVH kernel as scripts/run-x86_64.sh but with
# `-append yuva.profile=substrate`, and asserts it boots as a genuine standalone
# SUBSTRATE (the plain sovereign micro-VMM core) with the agent organs OMITTED —
# not hidden. This is an ADDITIONAL, opt-in lane; the required agent lane
# (run-x86_64.sh, no -append) is untouched and stays the byte-identical default.
#
# Three obligations (proposal §8.2 / DoD-2 / DoD-3):
#   (A) POSITIVE core: the profile-scoped micro-VMM chain provably RAN — M0..M12
#       hosting ABI, M14/M15 IPC, M19 virtio + the real M20 persist round-trip,
#       the khash RFC7693 KAT + M29, the L2/M27 per-arch forms, the Yuva-ABI
#       self-check — plus each gated marker present in the EXACT skip form
#       `<literal> (substrate profile, agent organ skipped)` (the cumulative
#       chain verified INTACT in skip form; DoD-5 prefix parity).
#   (B) NEGATIVE census (the lane's anti-hollow core, §8.2c): NO agent-organ
#       witness family appears — organs proven NOT to have run. The ABSENT list
#       is the GENERATED scripts/witness-census.txt (re-checked below), never a
#       hand list.
#   (C) The `profile:` witness (with admission=DENIED-AT-CHOKEPOINT + the
#       promotion refusal, both EXERCISED in-boot — DoD-3) and the clean-exit
#       `PROFILE: substrate OK` tail, verbatim.
#
# Zero network, zero secret, offline + deterministic. No xport host peer / no
# conductor-host: M30/M38 are SKIPPED in the substrate profile, so this lane
# attaches only the virtio-rng + virtio-blk devices the core (M19/M20) needs.
#
# Also runs the §8.2a DEFAULT-BOOT TRIPWIRE: the SAME binary booted with NO
# cmdline must be agent-complete (M38 tail present, no profile:/skip leakage) —
# a per-run CI guard against profile bleed into the default (weaker than the
# landing-time empty-diff, but CI-enforced).
#
# Usage:   scripts/run-substrate-x86_64.sh [path/to/kernel-elf]
# Env:     QEMU=...  QEMU_TIMEOUT=<secs>  PROFILE=debug|release
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "${REPO_ROOT}/scripts/project.env"
TARGET="${TARGET_X86}"
PROFILE="${PROFILE:-debug}"
KERNEL="${1:-${REPO_ROOT}/target/${TARGET}/${PROFILE}/${KERNEL_BIN}}"
TIMEOUT_SECS="${QEMU_TIMEOUT:-40}"
QEMU="${QEMU:-qemu-system-x86_64}"
CENSUS="${REPO_ROOT}/scripts/witness-census.txt"
MAIN="${REPO_ROOT}/kernel/src/main.rs"

if ! command -v "${QEMU}" >/dev/null 2>&1; then
  echo "error: ${QEMU} not found on PATH" >&2; exit 2
fi
if [[ ! -f "${KERNEL}" ]]; then
  echo "error: kernel image not found: ${KERNEL} (build it: cargo kbuild --target targets/${TARGET}.json)" >&2
  exit 2
fi

ACCEL="tcg,thread=single"; CPU="qemu64"
if [[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then ACCEL="kvm"; CPU="host"; fi

# The census must be current (drift guard, §8.2c): a new organ's witness prefix
# must not silently escape the negative inversion.
bash "${REPO_ROOT}/scripts/gen-witness-census.sh" --check >&2

# The gated markers + their canonical LANDED literals (DoD-5: the skip-form
# prefix is STRING-EQUAL to the literal the agent arm emits). Kept in ONE place;
# the loop below both derives the skip form and pins the literal against main.rs.
GATED_MARKERS=(
  'M13: memory OK'
  'M16: infer OK'
  'M17: consolidate OK'
  'M18: evolve OK'
  'M18.1: approval-gate OK'
  'M18.2: held-out OK'
  'M21: kan-policy OK'
  'M22: provenance OK'
  'M23: experience OK'
  'M24: bakeoff OK'
  'M25: operator OK'
  'M26: exit-telemetry OK'
  'M28: operator-cmd OK'
  'M30: infer-transport OK'
  'M31: infer-e2e OK'
  'M33: prov-lineage OK'
  'M38: conductor OK'
  'M39: corpus OK'
)
SKIP_SUFFIX='(substrate profile, agent organ skipped)'

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

echo ">> qemu=${QEMU} accel=${ACCEL} cpu=${CPU} timeout=${TIMEOUT_SECS}s (SUBSTRATE profile)" >&2
echo ">> kernel=${KERNEL}" >&2

# ===========================================================================
# The SUBSTRATE boot.
# ===========================================================================
OUT="$(boot 'yuva.profile=substrate')"
printf '%s\n' "${OUT}"

# --- inherited tripwires: a raw ESC byte fails every lane; the stream is text --
if printf '%s' "${OUT}" | grep -q $'\x1b'; then
  fail "a raw ESC (0x1b) byte appeared on the substrate stream (no ANSI on a CI stream)"
fi

# --- (A) POSITIVE core: the profile-scoped micro-VMM chain provably ran --------
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
  printf '%s' "${OUT}" | grep -qF -- "${m}" || fail "substrate core marker '${m}' missing"
done
# M20 REAL round-trip (not the no-disk skip) — this lane attaches a disk.
printf '%s' "${OUT}" | grep -qF -- 'M20: persist OK (no disk, skipped)' && \
  fail "M20 took the no-disk skip but this lane attaches a disk (hollow substrate M20)"
printf '%s' "${OUT}" | grep -qE -- 'persist: gen=0x[0-9a-fA-F]+ records=0x[0-9a-fA-F]+ replayed=0x[0-9a-fA-F]+' || \
  fail "M20 marker present but the real 'persist: gen=.. records=.. replayed=..' round-trip line missing"
# khash IS a substrate integrity feature (§3.3): the KAT witness must be present
# and EARNED, on the substrate arm's standalone emission.
printf '%s' "${OUT}" | grep -qE -- 'khash: prim=BLAKE2S-256 keylen=32 tag=128 kat=RFC7693-PASS sec=ASSUMED-FROM-LITERATURE sidechannel=NOT-CLAIMED' || \
  fail "the khash RFC7693 KAT witness (a substrate integrity feature) is missing on the substrate boot"
# The Yuva-ABI self-check is CORE (agent-agnostic) — must still run + pass.
printf '%s' "${OUT}" | grep -qE -- 'abi: cap-plane=.* selfcheck=0x1 ' || \
  fail "the Yuva-ABI 'abi: .. selfcheck=0x1 ..' self-check line is missing (the ABI is core, must run in BOTH profiles)"

# --- (A) the gated chain, INTACT in the exact skip form (DoD-5 prefix parity) --
for lit in "${GATED_MARKERS[@]}"; do
  # DoD-5: the literal is a REAL landed marker in main.rs (drift guard).
  grep -qF -- "serial_write_str(\"${lit}" "${MAIN}" \
    || fail "DoD-5: gated literal '${lit}' not found in main.rs (accidental rename?)"
  # The substrate stream carries EXACTLY '<literal> <suffix>'.
  printf '%s' "${OUT}" | grep -qF -- "${lit} ${SKIP_SUFFIX}" \
    || fail "gated marker '${lit}' did not appear in the skip form '<literal> ${SKIP_SUFFIX}'"
done
# M38 skip form must NOT carry the agent tail tokens (so no required lane passes).
printf '%s' "${OUT}" | grep -qE -- 'M38: conductor OK turns=' && \
  fail "the substrate M38 skip form carries 'turns=' — it must lack the agent cumulative-tail tokens (§2.3)"

# --- (B) the NEGATIVE census (the anti-hollow core): organs did NOT run --------
while IFS= read -r tok; do
  [[ -z "${tok}" || "${tok}" == \#* ]] && continue
  if printf '%s' "${OUT}" | grep -E -- "(^|[^[:alnum:]])$(printf '%s' "${tok}" | sed 's/[.[\*^$/]/\\&/g')" | grep -q .; then
    fail "agent-organ witness token '${tok}' appeared on the SUBSTRATE stream — an organ RAN (anti-hollow inversion, §8.2c)"
  fi
done < "${CENSUS}"

# --- (C) the profile witness + the clean-exit tail (DoD-3 tokens EXERCISED) -----
printf '%s' "${OUT}" | grep -qF -- 'profile: sel=SUBSTRATE source=PVH-CMDLINE organs=SKIPPED-RUNTIME-GATED code=PRESENT-IN-IMAGE admission=DENIED-AT-CHOKEPOINT promotion=REFUSED-AT-GATE' || \
  fail "the 'profile:' witness line (with admission=DENIED-AT-CHOKEPOINT promotion=REFUSED-AT-GATE) is missing — DoD-3 non-admission not witnessed"
printf '%s' "${OUT}" | grep -qF -- 'PROFILE: substrate OK organs=SKIPPED-RUNTIME-GATED' || \
  fail "the clean-exit 'PROFILE: substrate OK' tail is missing (anti-hollow tail)"
# The substrate tail must NOT claim guest-running: no '-vmm' qualifier (§2.5).
printf '%s' "${OUT}" | grep -qF -- 'PROFILE: substrate-vmm' && \
  fail "the substrate tail claimed '-vmm' — no stage-A substrate boot witnesses EL2/guest-running (§2.5)"
# A crash-before-organs must not impersonate omission: the profile witness fail
# form (deny not exercised) must be absent.
printf '%s' "${OUT}" | grep -qF -- 'profile: FAIL substrate' && \
  fail "the profile witness reported the structural-non-admission exercise FAILED (the chokepoint denial did not fire)"

# --- (D) overclaim vocabulary near the profile/skip lines (stage-A discipline) --
# Strip the DECLARED structured honesty tokens FIRST (each deliberately carries a
# would-be-rejected substring — e.g. tcb=ATTACK-SURFACE-REDUCED-NOT-BYTES-REMOVED
# concedes bytes are NOT removed), so the reject bites on PROSE overclaims only.
if printf '%s' "${OUT}" | grep -E -- '(^|[^[:alnum:]])(profile:|PROFILE:)' \
     | sed -e 's/ATTACK-SURFACE-REDUCED-NOT-BYTES-REMOVED//g' \
           -e 's/EXECUTION-ADMISSION-LEVEL//g' -e 's/DENIED-AT-CHOKEPOINT//g' \
           -e 's/REFUSED-AT-GATE//g' -e 's/SKIPPED-RUNTIME-GATED//g' \
           -e 's/CODE-PRESENT-IN-IMAGE//g' -e 's/PRESENT-IN-IMAGE//g' \
           -e 's/AARCH64-AGENT-LANE-ONLY//g' -e 's/SUBSTRATE-DEFAULTED//g' \
     | grep -qiE -- 'not present|removed|compiled-out|smaller image|minimal|zero-tcb|secure|isolated|sandboxed|sovereign|firecracker-replacement'; then
  fail "the profile witness/tail carries a stage-B or superlative overclaim (not present/removed/minimal/secure/sovereign/...) — stage A is attack-surface reduction, code PRESENT-IN-IMAGE (§5.4)"
fi

echo ">> SUBSTRATE PASS: micro-VMM core ran (M0..M12/M14/M15/M19/M20/M29/L2/M27/ABI), the M13..M38 chain is intact in the honest skip form, every agent-organ witness is ABSENT-BY-OMISSION (census-derived), the M11 chokepoint denial + M18.1 promotion refusal were EXERCISED in-boot, and the profile witness + 'PROFILE: substrate OK' tail are honest." >&2

# ===========================================================================
# (§8.2a) The DEFAULT-BOOT TRIPWIRE: same binary, NO cmdline ⇒ agent-complete.
# A weaker-than-byte-diff, per-run CI guard against profile leakage into the
# default. (The full empty-byte-diff is the landing-time local proof, DoD-1.)
# ===========================================================================
echo ">> default-boot tripwire (§8.2a): same binary, NO cmdline, must be agent-complete" >&2
DEF="$(boot '')"
printf '%s' "${DEF}" | grep -qF -- 'M38: conductor OK turns=6 organs=3 verdict=ACCEPT' || \
  fail "default boot (no cmdline) did NOT reach the agent M38 tail — the agent profile is not the default"
if printf '%s' "${DEF}" | grep -qF -- "${SKIP_SUFFIX}"; then
  fail "default boot carried a '(substrate profile, agent organ skipped)' skip form — profile leaked into the default"
fi
if printf '%s' "${DEF}" | grep -qE -- '(^|[^[:alnum:]])(profile:|PROFILE:)'; then
  fail "default boot emitted a profile: / PROFILE: line — the witness must be non-default-selection ONLY (byte-identity)"
fi
echo ">> default-boot tripwire PASS: the no-cmdline boot is agent-complete (M38 tail, no profile/skip leakage)." >&2

echo ">> ALL SUBSTRATE-LANE CHECKS PASS" >&2
exit 0
