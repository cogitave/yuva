#!/usr/bin/env bash
# M38 stage-A witness adjudication (proposal §8 — the workflow-level guards).
#
# This adjudicates the conductor-host witness: the LOAD-BEARING stub-killer is the
# INDEPENDENT HOST RECOMPUTE of the M22 lineage head from a SEPARATE capture of
# the organ-call trace (§8.6) — `policy-head` (the policy fold) must string-equal
# `host-head` (the host's independent fold over the observed trace). Printed
# organs/revise-cycles numbers are NECESSARY-not-sufficient; a stub printing them
# over a fabricated trace fails the independent fold.
#
# House order (the M30 §5 / M31 §7 / M32 template): skip-reject, positive-require,
# by-name rejects, inherited tripwires, strip-then-reject.
#
# Usage: conductor-adjudicate.sh <witness.log>

set -euo pipefail

LOG="${1:?usage: conductor-adjudicate.sh <witness.log>}"

fail() { echo "::error::M38 adjudicate FAIL: $*" >&2; exit 1; }

# --- (§8.1) skip-reject ------------------------------------------------------
# The lane FAILS by name on any skip / single-organ / always-accept variant;
# honest-skip-is-FAILURE, never green-by-omission.
if grep -qiE 'M38: conductor OK \(.*(skip|single organ|always-accept)' "$LOG"; then
  fail "M38 ran in a skipped/degenerate variant — honest-skip-is-FAILURE (§8.1)"
fi

# At least one conductor witness line must exist.
if ! grep -qE '^conduct: head=0x' "$LOG"; then
  fail "no 'conduct: head=0x..' witness line (the conductor produced no evidence)"
fi
if ! grep -qE '^conductor-host: policy-head=0x' "$LOG"; then
  fail "no 'conductor-host: policy-head=0x..' independent-recompute line"
fi

# --- (§8.2) positive-require: the full one-line witness regex -----------------
# Every honest token literal, every flag =0x0*1, on the SAME line; AND
# revise-cycles>=0x1 AND organs>=0x2 (the measured anti-hollow thresholds).
WITNESS_RE='^conduct: head=0x[0-9a-f]{16} turns=0x[0-9a-f]+ organs=0x[0-9a-f]+ roles=[TWV]+ organ-seq=0x[0-9a-f]+ verdict=ACCEPT accept-at=0x[0-9a-f]+ revise-cycles=0x[0-9a-f]+ fold-verified=0x0*1 tamper-caught=0x0*1 organ-calls=0x[0-9a-f]+ logical-ticks=0x[0-9a-f]+ attested=0x0*1 prov-tag=0x4 policy=DISCRETE-HAND-WRITTEN-NOT-LEARNED learning=DORMANT retrieval=LEXICAL-NOT-SEMANTIC external-organ=MOCK-IN-CI local-organ=M38-AUTHORED-MOCK verifier=CI-DISCRETE-VERDICT m18-gate=ADMISSION-ONLY-INERT-IN-MOCK cost=HONEST-ACCOUNTED-TOKENED cost-metric=LOGICAL-SURROGATE-NOT-WALLCLOCK orchestration=RAG-AGENTS-NOT-NEW-PARADIGM live\+web=DISPATCH-ONLY novelty=VERIFIED-PROVENANCE-SOVEREIGN-WRAPPER generativity=OPEN-FRONTIER realtime=NOT-CLAIMED benchmark=NOT-CLAIMED stub-resistance=HOST-RECOMPUTE-FROM-INDEPENDENT-TRACE host=RESIDUAL-TCB sec=ASSUMED-FROM-LITERATURE$'

if ! grep -qE -- "$WITNESS_RE" "$LOG"; then
  fail "the full one-line conductor witness regex did not match (a token/flag is missing or an overclaim crept in)"
fi

WLINE="$(grep -E -- '^conduct: head=0x' "$LOG" | head -1)"

# revise-cycles >= 0x1 (the measured >=1 REVISE->ACCEPT cycle).
RC_HEX="$(printf '%s' "$WLINE" | sed -E 's/.* revise-cycles=0x([0-9a-f]+) .*/\1/')"
if [ "$((16#${RC_HEX}))" -lt 1 ]; then
  fail "revise-cycles=0x${RC_HEX} < 0x1 (an always-accept stub; the witness requires a measured REVISE->ACCEPT cycle)"
fi
# organs >= 0x2 (the measured multi-organ sequence).
ORG_HEX="$(printf '%s' "$WLINE" | sed -E 's/.* organs=0x([0-9a-f]+) .*/\1/')"
if [ "$((16#${ORG_HEX}))" -lt 2 ]; then
  fail "organs=0x${ORG_HEX} < 0x2 (a degenerate single-organ stub; the witness requires a measured >=2-organ sequence)"
fi

# --- (§8.6) THE LOAD-BEARING INDEPENDENT-RECOMPUTE LEG ------------------------
# policy-head and host-head are two independently-folded heads (the policy fold
# vs the host's fold over its SEPARATE captured trace). They MUST string-equal,
# and the witness must declare lineage-equal=0x1. A fabricated trace yields a
# different host-head -> caught here (the loopback/fixture killer).
HLINE="$(grep -E -- '^conductor-host: policy-head=0x' "$LOG" | head -1)"
PHEAD="$(printf '%s' "$HLINE" | sed -E 's/.*policy-head=0x([0-9a-f]+) .*/\1/')"
HHEAD="$(printf '%s' "$HLINE" | sed -E 's/.*host-head=0x([0-9a-f]+) .*/\1/')"
if [ -z "$PHEAD" ] || [ -z "$HHEAD" ]; then
  fail "could not extract policy-head/host-head from the conductor-host line"
fi
if [ "$PHEAD" != "$HHEAD" ]; then
  fail "policy-head (0x${PHEAD}) != host independent-recompute head (0x${HHEAD}) — the lineage is forged/fixtured (§8.6 cross-process recompute caught it)"
fi
if ! printf '%s' "$HLINE" | grep -qE 'lineage-equal=0x0*1 .*trace=SEPARATE-CAPTURE recompute=INDEPENDENT'; then
  fail "the conductor-host line does not declare lineage-equal=0x1 / SEPARATE-CAPTURE / INDEPENDENT recompute"
fi
# The witness fold-verified flag must also be set (necessary corroboration).
if ! printf '%s' "$WLINE" | grep -qE 'fold-verified=0x0*1 tamper-caught=0x0*1'; then
  fail "the witness does not carry fold-verified=0x1 tamper-caught=0x1"
fi

# --- (§8.3) hard by-name rejects on the RAW lines ----------------------------
# These spellings are NEVER part of a legitimate declared token, so they are
# rejected on the raw conductor lines (case-insensitive). NOTE: `semantic` /
# `float` are NOT in this set — they legitimately appear inside the honest
# tokens retrieval=LEXICAL-NOT-SEMANTIC and no-float context, so the razor for
# them is the strip-then-reject pass below, not a raw substring match.
if grep -E -- '(^|[^[:alnum:]])(conduct:|conductor-host:|M38:)' "$LOG" \
   | grep -qiE 'policy=LEARNED|policy=ES|policy=CMA|KAN_ACTIVE=true|backend=ANTHROPIC-LIVE|verifier=LEARNED|verifier=CLASSIFIER|embedding|cosine|loopback|fixture|canned|replay'; then
  fail "a by-name reject token (learned/ES/CMA/live/embedding/cosine/fixture/replay) appears on a conductor line (§8.3)"
fi

# --- (§8.5) inherited tripwires ---------------------------------------------
# ESC byte on the witness; every hex dump field is lowercase-hex only.
if grep -qP '\x1b' "$LOG" 2>/dev/null; then
  fail "an ESC (0x1b) byte appears in the witness log (§8.5 tripwire)"
fi

# --- (§8.7) strip-then-reject (the load-bearing razor) -----------------------
# Strip the declared token VALUES FIRST, THEN reject any residual claim/overclaim
# vocabulary near the conduct lines (the M29 discipline: ALL claims live in
# structured stripped tokens, never bare words). This is where `semantic`,
# `float`, `learned`, `SOTA`, `real-time` etc. are caught — a BARE occurrence
# survives stripping; the inside-a-token occurrence (LEXICAL-NOT-SEMANTIC,
# NOT-LEARNED, NOT-WALLCLOCK) does not.
STRIPPED="$(grep -E -- '(^|[^[:alnum:]])(conduct:|M38:)' "$LOG" \
  | sed -E 's/[a-z+-]+=[A-Za-z0-9+/.:_-]+//g')"
if printf '%s' "$STRIPPED" | grep -qiE 'learned|trained|intelligen|understood|generaliz|benchmark|SOTA|real-time|semantic|cosine|float|embedding'; then
  fail "a residual claim word (learned/trained/intelligen/understood/generaliz/benchmark/SOTA/real-time/semantic/float/embedding) survives token-stripping near the M38 lines (§8.7 razor)"
fi

# --- the marker ---------------------------------------------------------------
if ! grep -qE '^M38: conductor OK turns=[0-9]+ organs=[0-9]+ verdict=ACCEPT$' "$LOG"; then
  fail "the 'M38: conductor OK turns=N organs=K verdict=ACCEPT' marker was not emitted"
fi

echo ">> M38 adjudicate OK: independent host-recompute MATCHED (policy-head == host-head), organs>=2, revise-cycles>=1, all honest tokens present, no overclaim"
