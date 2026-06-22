#!/usr/bin/env bash
# M32 stage-A witness adjudication (proposal §8 — the workflow-level guards).
#
# This is the INDEPENDENT-STREAM golden compare (§4 leg 1): it string-compares
# the daemon's emitted resp-digest / neg-digest against the REPO-PINNED golden
# constants in tools/infer-daemon/src/pins.rs — a hash-stub or broken engine
# cannot produce the golden. The repo constant vs the daemon stdout is a second
# stream, not daemon self-report.
#
# House order (the M30 §5 / M31 §7 template): skip-reject, positive-require,
# by-name rejects, inherited tripwires, strip-then-reject.
#
# Usage: m32-adjudicate.sh <witness.log> <nonce-hex>

set -euo pipefail

LOG="${1:?usage: m32-adjudicate.sh <witness.log> <nonce-hex>}"
NONCE_HEX="${2:?nonce hex required}"
PINS="tools/infer-daemon/src/pins.rs"

fail() { echo "::error::M32 adjudicate FAIL: $*" >&2; exit 1; }

# --- (§8.1) skip-reject ------------------------------------------------------
# The lane FAILS by name on any skip variant; weights/daemon unavailable is the
# loud exit-3 refusal + lane FAIL, never green-by-omission.
if grep -qiE 'M32: local-infer OK \(.*skip' "$LOG"; then
  fail "M32 ran in SKIP mode — honest-skip-is-FAILURE (§8.1)"
fi

# At least one daemon witness line must exist (the required 260K smoke).
if ! grep -qE '^infer-daemon: backend=LOCAL-ENGINE ' "$LOG"; then
  fail "no 'infer-daemon: backend=LOCAL-ENGINE' witness line (the daemon produced no LOCAL-ENGINE evidence)"
fi

# --- (§8.2) positive-require: the full one-line witness regex -----------------
# Every debt token literal, every flag =0x0*1, all digests, on the SAME line.
WITNESS_RE='^infer-daemon: backend=LOCAL-ENGINE engine=VENDORED-C-LLAMACPP debt=SOVEREIGNTY-OPEN-B3 memsafety=UNSAFE-C-PROCESS-CONFINED weights=UNTRUSTED-INPUT-NAMED gguf=SHA256:[0-9a-f]{64} model=(STORIES260K|STORIES15M-Q8_0) enginepin=[a-z0-9]+-g[0-9a-f]+ threads=1 parallel=1 blas=OFF openmp=OFF isa=[A-Z0-9-]+ dispatch=STATIC sysinfo-pinned=0x0*1 sampler=GREEDY-TOPK1 cache-prompt=OFF batch=PINNED seed=MOOT-GREEDY runner-image=[^ ]+ glibc=[^ ]+ prompt-digest=0x[0-9a-f]{32} resp-digest=0x[0-9a-f]{32} resp-digest-run2=0x[0-9a-f]{32} golden=REPO-PINNED-MATCHED neg-prompt=FROZEN-PINNED neg-digest=0x[0-9a-f]{32} neg-golden=REPO-PINNED-MATCHED nonce=0x[0-9a-f]{32} nonce-digest=0x[0-9a-f]{32} nonce-digest-run2=0x[0-9a-f]{32} repro=BIT-IDENTICAL-2RUN determinism=BUILD-PINNED-SINGLE-THREAD-GREEDY digest=TUPLE-CONDITIONAL xmachine=NOT-CLAIMED xarch=NOT-CLAIMED sandbox=SECCOMP-LANDLOCK-PRE-PARSE net-denied=0x0*1 fs-denied=0x0*1 envclear=0x0*1 guestpath=MOCK-PINNED-HOST-ADJUDICATED key=CAPREF-HOST-CUSTODIED host=RESIDUAL-TCB ambient=ZERO-IN-GUEST sec=ASSUMED-FROM-LITERATURE$'

# The required 260K line MUST match the full regex.
if ! grep -E -- "$WITNESS_RE" "$LOG" | grep -qF 'model=STORIES260K'; then
  fail "the STORIES260K witness line did not match the full §8 positive-require regex"
fi

# Every LOCAL-ENGINE line present must match the full regex (no malformed line).
while IFS= read -r line; do
  if ! printf '%s\n' "$line" | grep -qE -- "$WITNESS_RE"; then
    fail "a LOCAL-ENGINE witness line failed the full §8 regex: ${line}"
  fi
  # The 2-run + nonce-2run equalities (adjudication level).
  rd="$(printf '%s' "$line" | grep -oE 'resp-digest=0x[0-9a-f]{32}' | head -1)"
  rd2="$(printf '%s' "$line" | grep -oE 'resp-digest-run2=0x[0-9a-f]{32}' | head -1 | sed 's/-run2//')"
  [ "$rd" = "$rd2" ] || fail "resp-digest != resp-digest-run2 (envelope broke): ${line}"
  nd="$(printf '%s' "$line" | grep -oE ' nonce-digest=0x[0-9a-f]{32}' | head -1 | sed 's/^ //')"
  nd2="$(printf '%s' "$line" | grep -oE 'nonce-digest-run2=0x[0-9a-f]{32}' | head -1 | sed 's/-run2//')"
  [ "$nd" = "$nd2" ] || fail "nonce-digest != nonce-digest-run2 (fresh-prompt nondeterminism): ${line}"
  # The per-run nonce on the line MUST equal the workflow-sampled nonce (the
  # independent-stream freshness binding — a canned table cannot carry it).
  ln_nonce="$(printf '%s' "$line" | grep -oE 'nonce=0x[0-9a-f]{32}' | head -1 | sed 's/nonce=0x//')"
  [ "$ln_nonce" = "$NONCE_HEX" ] || fail "the witness nonce (${ln_nonce}) != the workflow-sampled nonce (${NONCE_HEX}) — freshness binding broken (a canned/replayed witness)"
done < <(grep -E '^infer-daemon: backend=LOCAL-ENGINE ' "$LOG")

# --- (§4 leg 1) the INDEPENDENT-STREAM golden compare ------------------------
# Pull the repo-pinned goldens from pins.rs and string-compare them against the
# emitted digests. The daemon ALSO self-checks (golden=REPO-PINNED-MATCHED), but
# THIS is the independent stream the §17.10 single-stream finding demanded.
golden_for() { # golden_for <MODEL-token> <primary|neg>
  local model="$1" which="$2"
  # The pins.rs ModelPin blocks are ordered STORIES260K then STORIES15M_Q8.
  awk -v m="$model" -v w="$which" '
    /pub const STORIES260K/ {blk="STORIES260K"}
    /pub const STORIES15M_Q8/ {blk="STORIES15M-Q8_0"}
    blk==m && /golden_primary:/ && w=="primary" {if (match($0, /"[0-9a-f]+"/)) {print substr($0, RSTART+1, RLENGTH-2); exit}}
    blk==m && /golden_neg:/ && w=="neg" {if (match($0, /"[0-9a-f]+"/)) {print substr($0, RSTART+1, RLENGTH-2); exit}}
  ' "$PINS"
}

while IFS= read -r line; do
  model="$(printf '%s' "$line" | grep -oE 'model=[A-Z0-9_-]+' | head -1 | sed 's/model=//')"
  rd="$(printf '%s' "$line" | grep -oE 'resp-digest=0x[0-9a-f]{32}' | head -1 | sed 's/resp-digest=0x//')"
  ndg="$(printf '%s' "$line" | grep -oE 'neg-digest=0x[0-9a-f]{32}' | head -1 | sed 's/neg-digest=0x//')"
  gp="$(golden_for "$model" primary)"
  gn="$(golden_for "$model" neg)"
  [ -n "$gp" ] || fail "no repo-pinned primary golden found for ${model} in ${PINS}"
  [ "$rd" = "$gp" ] || fail "INDEPENDENT-STREAM golden mismatch for ${model} primary: daemon=${rd} repo=${gp} (envelope broke or stub forged)"
  [ "$ndg" = "$gn" ] || fail "INDEPENDENT-STREAM golden mismatch for ${model} neg: daemon=${ndg} repo=${gn}"
  # Neg-distinctness re-asserted at adjudication (the §4 leg-3 measured-distinct).
  [ "$rd" != "$ndg" ] || fail "neg-digest == resp-digest for ${model} (collision — a pin drifted)"
  echo ">> ${model}: golden MATCHED (independent stream), neg distinct, 2-run + nonce-2run equal, freshness bound"
done < <(grep -E '^infer-daemon: backend=LOCAL-ENGINE ' "$LOG")

# --- (§8.3) by-name rejects (case-insensitive, near M32 lines) ---------------
if grep -E -- '(^|[^[:alnum:]])(infer-daemon:|M32:)' "$LOG" \
     | grep -qiE -- 'backend=MOCK-DETERMINISTIC|backend=ANTHROPIC-LIVE|backend=LLAMACPP-LOCAL|engine=PURE-RUST|loopback|fixture|canned|replay|LLAMACPP-CXX'; then
  fail "a by-name-rejected token appeared near an M32 line (§8.3: MOCK/ANTHROPIC-LIVE/LLAMACPP-LOCAL/PURE-RUST/loopback/fixture/canned/replay/LLAMACPP-CXX)"
fi

# --- (§8.5) inherited tripwires ----------------------------------------------
# Raw ESC anywhere in the witness stream would let crafted model text hijack a
# terminal; the daemon hex-encodes all model-derived bytes, so none must appear.
if grep -q -- $'\x1b' "$LOG"; then
  fail "a raw ESC (0x1b) byte reached the witness stream (the §6 hex-encode invariant is broken)"
fi

# --- (§8.9) strip-then-reject overclaims -------------------------------------
# Strip the DECLARED tokens first, then reject the pure-Rust/C-free/security/
# determinism overclaim vocabulary near M32 lines (pre-closure, the pure-Rust/
# C-free vocabulary IS the overclaim).
if grep -E -- '(^|[^[:alnum:]])(infer-daemon:|M32:)' "$LOG" \
     | sed -e 's/LOCAL-ENGINE//g' -e 's/VENDORED-C-LLAMACPP//g' \
           -e 's/SOVEREIGNTY-OPEN-B3//g' -e 's/UNSAFE-C-PROCESS-CONFINED//g' \
           -e 's/UNTRUSTED-INPUT-NAMED//g' -e 's/SHA256:[0-9a-f]*//g' \
           -e 's/BIT-IDENTICAL-2RUN//g' -e 's/BUILD-PINNED-SINGLE-THREAD-GREEDY//g' \
           -e 's/TUPLE-CONDITIONAL//g' -e 's/REPO-PINNED-MATCHED//g' \
           -e 's/FROZEN-PINNED//g' -e 's/NOT-CLAIMED//g' -e 's/MOOT-GREEDY//g' \
           -e 's/GREEDY-TOPK1//g' -e 's/X86-64-[A-Z0-9-]*PINNED//g' \
           -e 's/SECCOMP-LANDLOCK-PRE-PARSE//g' -e 's/MOCK-PINNED-HOST-ADJUDICATED//g' \
     | grep -qiE -- 'pure[- ]rust|c[- ]free|zero[- ]c|memory[- ]safe|sovereign|secure|sandboxed|isolated|trusted|hardened|deterministic|reproducible|bit[- ]identical|batch[- ]invariant|model[- ]canonical|full[- ]parity|gpu|cuda|network|TLS|cloud|intelligen|understood|learned|validated'; then
  fail "an M32 line carries an overclaim after stripping the declared tokens (§8.9 — pre-closure the pure-Rust/C-free/secure/deterministic vocabulary IS the overclaim)"
fi

echo ">> M32 adjudicate PASS: LOCAL-ENGINE witness positive-required, goldens matched (independent stream), all §8 guards held"
