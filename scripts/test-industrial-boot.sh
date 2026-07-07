#!/usr/bin/env bash
# Industrial Boot (#106) — the COMMITTED DoD gate (DoD-1/2/3).
#
# This is a self-contained x86_64 test (the arch with the wired PVH cmdline
# knob) that boots the SAME kernel image three ways and asserts the invariants
# the whole feature rests on. It is additive: it never touches the three
# verifier lanes (run-{x86_64,aarch64}.sh, run-vmm-x86_64.sh), which pass NO
# cmdline and therefore only ever see the raw DEFAULT.
#
#   DoD-1  DEFAULT is raw + pretty-not-emitted, and DEFAULT == explicit raw.
#          The raw markers CI greps appear; NO pretty line leaks into default.
#   DoD-2  the honesty derivation + overclaim/ESC lint on a pretty capture.
#   DoD-3  the substrate vs agent view render-filter parity.
#
# Requires: a built x86_64 kernel + qemu-system-x86_64. Builds if missing.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "${REPO_ROOT}/scripts/project.env"
[[ -f "${HOME}/.cargo/env" ]] && source "${HOME}/.cargo/env"
case ":${PATH}:" in *":${HOME}/.cargo/bin:"*) :;; *) PATH="${HOME}/.cargo/bin:${PATH}";; esac

QEMU="${QEMU:-qemu-system-x86_64}"
KERNEL="${REPO_ROOT}/target/${TARGET_X86}/debug/${KERNEL_BIN}"
TIMEOUT_SECS="${TIMEOUT_SECS:-30}"
FAILED=0
note() { printf '%s\n' ">> $*" >&2; }
fail() { printf '%s\n' ">> FAIL: $*" >&2; FAILED=1; }

command -v "${QEMU}" >/dev/null 2>&1 || { echo "error: ${QEMU} not found" >&2; exit 2; }
[[ -x "${KERNEL}" ]] || ( cd "${REPO_ROOT}" && CARGO_INCREMENTAL=0 cargo kbuild --target "targets/${TARGET_X86}.json" )

# The M30/M31 inference peer: attaching the xport-harness makes M31 take the
# real backend=MOCK-DETERMINISTIC path (so pretty renders [ MOCK ]) rather than
# the (no host peer, skipped) path. Built once, reused across boots.
HARNESS_BIN="${REPO_ROOT}/tools/xport-harness/target/release/xport-harness"
if [[ ! -x "${HARNESS_BIN}" ]] && command -v cargo >/dev/null 2>&1; then
  ( cd "${REPO_ROOT}/tools/xport-harness" && cargo build --release >&2 )
fi

# Boot x86 with the full device set + inference peer; $1 is the optional cmdline.
boot() {
  local append="$1"
  local img; img="$(mktemp)"; truncate -s 4M "$img"
  local xsock; xsock="$(mktemp -u)"; local xkey; xkey="$(mktemp)"; local xhout; xhout="$(mktemp)"
  local xpid=""
  local args=( -M microvm,rtc=off -accel tcg -cpu qemu64 -m 256M -smp 1
    -kernel "${KERNEL}" -no-reboot -nic none
    -global virtio-mmio.force-legacy=false -device virtio-rng-device
    -drive "file=${img},if=none,format=raw,id=vblk0" -device virtio-blk-device,drive=vblk0 )
  if [[ -x "${HARNESS_BIN}" ]]; then
    "${HARNESS_BIN}" --socket "${xsock}" --key-out "${xkey}" --timeout-secs $((TIMEOUT_SECS + 30)) > "${xhout}" 2>&1 &
    xpid=$!
    args+=( -chardev "socket,id=xport0,path=${xsock},server=on,wait=off"
            -device virtio-serial-device -device virtconsole,chardev=xport0 )
  fi
  args+=( -serial stdio -display none )
  [[ -n "${append}" ]] && args+=( -append "${append}" )
  timeout "${TIMEOUT_SECS}" "${QEMU}" "${args[@]}" 2>&1
  [[ -n "${xpid}" ]] && kill "${xpid}" 2>/dev/null
  rm -f "$img" "$xkey" "$xhout"
}

# The pretty prefixes (distinct human tags — never a marker/witness substring).
PRETTY_TAGS='\[  OK  \]|\[ MOCK \]|\[STANDBY\]|\[ SKIP \]|\[ INFO \]|\[FAILED\]|Reached target Ready'

echo "== capturing three boots =="
OUT_DEFAULT="$(boot '')"
OUT_RAW="$(boot 'yuva.console=raw')"
OUT_PRETTY="$(boot 'yuva.console=pretty')"
OUT_SUBSTRATE="$(boot 'yuva.console=pretty yuva.view=substrate')"

# ---------------------------------------------------------------------------
# DoD-1 — DEFAULT is raw, pretty NOT emitted; DEFAULT ≡ explicit raw.
# ---------------------------------------------------------------------------
echo "== DoD-1: default-raw / pretty-not-emitted =="
# The raw markers CI greps must be present in DEFAULT mode.
for m in 'M31: infer-e2e OK backend=MOCK-DETERMINISTIC' 'M38: conductor OK' 'M29: khash-mac OK' 'persist: gen='; do
  printf '%s' "${OUT_DEFAULT}" | grep -qF -- "$m" || fail "DoD-1: raw marker '$m' missing from DEFAULT boot"
done
# NO pretty line may appear in DEFAULT mode (the load-bearing CI invariant).
if printf '%s' "${OUT_DEFAULT}" | grep -qE -- "${PRETTY_TAGS}"; then
  fail "DoD-1: a pretty tag leaked into the DEFAULT (raw) boot — CI would see non-marker bytes"
else note "DoD-1: DEFAULT carries the raw markers and NO pretty tag (pretty-not-emitted)"; fi
# DEFAULT and explicit raw must be byte-identical modulo per-run entropy.
canon() { sed -f "${REPO_ROOT}/scripts/lib/canon-serial.sed"; }
if diff <(printf '%s' "${OUT_DEFAULT}" | canon) <(printf '%s' "${OUT_RAW}" | canon) >/dev/null; then
  note "DoD-1: DEFAULT ≡ explicit yuva.console=raw (canonical byte-identical)"
else fail "DoD-1: DEFAULT differs from explicit raw"; fi

# ---------------------------------------------------------------------------
# DoD-2 — the honesty derivation + overclaim/ESC lint on a pretty capture.
# ---------------------------------------------------------------------------
echo "== DoD-2: pretty honesty + lint =="
# Pretty mode DOES render the human boot and SUPPRESSES the raw markers.
printf '%s' "${OUT_PRETTY}" | grep -qE -- "${PRETTY_TAGS}" || fail "DoD-2: pretty boot rendered no [ STATUS ] lines"
printf '%s' "${OUT_PRETTY}" | grep -qF -- 'Reached target Ready.' || fail "DoD-2: pretty boot missing 'Reached target Ready.'"
for raw in 'M31: infer-e2e OK' 'M38: conductor OK' 'persist: gen=' 'khash: prim='; do
  printf '%s' "${OUT_PRETTY}" | grep -qF -- "$raw" && fail "DoD-2: raw marker/witness '$raw' leaked into the SUPPRESSED pretty screen"
done
# Derivation: a mock backend is [ MOCK ], never [ OK ] Local AI; the standby cell
# is [STANDBY]; the EL2 rows are [ SKIP ] on x86.
printf '%s' "${OUT_PRETTY}" | grep -qF -- '[ MOCK ] Agent inference' || fail "DoD-2: mock inference not rendered [ MOCK ]"
printf '%s' "${OUT_PRETTY}" | grep -qF -- 'not live AI'            || fail "DoD-2: mock inference missing the 'not live AI' disclaimer"
printf '%s' "${OUT_PRETTY}" | grep -qF -- '[STANDBY] Adaptive policy' || fail "DoD-2: dormant policy not rendered [STANDBY]"
printf '%s' "${OUT_PRETTY}" | grep -qF -- '[ SKIP ] Guest isolation'  || fail "DoD-2: x86 guest-isolation not rendered [ SKIP ]"
# The overclaim VOCABULARY lint — FAIL if any banned word appears in pretty.
if printf '%s' "${OUT_PRETTY}" | grep -qiE -- 'Local AI|AI Learning|semantic|live inference|learned|reasoned|intelligen|[^-]secure'; then
  fail "DoD-2: a banned overclaim word appeared in the pretty capture"
else note "DoD-2: no banned overclaim vocabulary in the pretty capture"; fi
# The ESC tripwire — the pretty renderer emits NO ANSI color (a kernel has no isatty).
if printf '%s' "${OUT_PRETTY}" | grep -q -- $'\x1b'; then
  fail "DoD-2: a raw ESC (0x1b) byte reached the pretty stream — no ANSI color is permitted"
else note "DoD-2: no ESC byte in the pretty stream (no ANSI color)"; fi
# M38 gate: the Cognitive-orchestrator line is DEFERRED (operator veto point §11.3).
printf '%s' "${OUT_PRETTY}" | grep -qF -- 'Cognitive orchestrator' && fail "DoD-2: the deferred 'Cognitive orchestrator' line was rendered (operator veto point)"

# ---------------------------------------------------------------------------
# DoD-3 — the view render-filter parity (substrate vs agent).
# ---------------------------------------------------------------------------
echo "== DoD-3: view parity =="
# Substrate view: micro-VMM rows + the honest HIDDEN note; NO inference/learning row.
printf '%s' "${OUT_SUBSTRATE}" | grep -qF -- 'HIDDEN in the substrate view' || fail "DoD-3: substrate view missing the honest 'HIDDEN in the substrate view' line"
printf '%s' "${OUT_SUBSTRATE}" | grep -qF -- 'Agent inference' && fail "DoD-3: substrate view leaked the agent inference row"
printf '%s' "${OUT_SUBSTRATE}" | grep -qF -- 'not present' && fail "DoD-3: substrate view claimed 'not present' (organs DID execute — must say HIDDEN)"
# Agent view: the mock/standby glyphs + the trailing INFO disclaimer.
printf '%s' "${OUT_PRETTY}" | grep -qF -- '[ INFO ] retrieval=lexical-only' || fail "DoD-3: agent view missing the trailing [ INFO ] disclaimer"

echo "== RESULT =="
if [[ "${FAILED}" -eq 0 ]]; then echo ">> Industrial Boot DoD-1/2/3: ALL PASS"; else echo ">> Industrial Boot DoD: FAILURES ABOVE"; fi
exit "${FAILED}"
