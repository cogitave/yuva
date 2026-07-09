#!/usr/bin/env bash
# Yuva-ABI stage A — the agent-neutrality lint (DoD-6).
#
# Yuva is AGENT-AGNOSTIC: the OS hosts ANY conformant agent, so the specific
# resident-agent identity name "Cogi" (the cogitave/cogi project's identity)
# MUST NOT appear in the load-bearing OS surfaces. This lint FAILS CLOSED if
# "Cogi" reappears in `kernel/src` or `crates/` (both clean today, after the
# merged agent-terminology neutralization of `kernel/src/bootreport.rs`).
#
# SCOPE + the one named exception. The lint covers `kernel/src` + `crates/`
# (the OS itself). It deliberately does NOT cover `tools/`, where
# `tools/xport-harness/src/live.rs` carries "Cogi" as the SEMANTIC CONTENT of a
# historical MERHABA greeting FIXTURE (host-side witness content, not an OS
# coupling). Neutralizing that fixture is an operator judgment call and is
# DEFERRED (spec §8); until then it is a named historical-witness exception,
# OUTSIDE this lint's scope by construction (it is not under kernel/src|crates/).
#
# "cogitave" (the org/project name) is ALLOWED everywhere — it is the project
# namespace, not the agent identity — so it is excluded from the match.
#
# The lint is the machine-checked half of the change-control rule in
# docs/spec/yuva-abi-v1.md §8 and docs/LANGUAGE-AND-STANDARDS.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Match the agent identity name in any case (Cogi / cogi / COGI) but NOT the
# allowed project namespace "cogitave". The negative lookahead is done with a
# post-filter (grep -P is not portable) rather than a single regex.
HITS="$(grep -rniE 'cogi' kernel/src crates/ 2>/dev/null | grep -viE 'cogitave' || true)"

if [ -n "$HITS" ]; then
  echo ">> FAIL: agent-identity name 'Cogi' found in kernel/src or crates/ -- Yuva is AGENT-AGNOSTIC (docs/spec/yuva-abi-v1.md §8). Neutralize to the generic term 'agent'." >&2
  echo "$HITS" >&2
  exit 1
fi

echo "ABI: agent-neutral OK (no 'Cogi' in kernel/src or crates/)"
exit 0
