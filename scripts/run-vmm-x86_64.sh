#!/usr/bin/env bash
# scripts/run-vmm-x86_64.sh — tb-vmm Definition-of-Done check (L1 + M30 stage C, x86_64).
#
# Boots the SAME kernel ELF the QEMU/PVH path boots, but through tb-vmm + the
# tb-boot v0 contract (direct 64-bit long mode, NO PVH note, NO A0 trampoline),
# and asserts the FULL cumulative chain tail on the guest serial console.
#
# M30 STAGE C (the marker bump): tb-vmm now carries its FIRST virtio device —
# a modern virtio-mmio virtio-console (DeviceID 3) backend fronting an
# IN-PROCESS host peer that speaks the SAME Kani-proven tb-encode inferwire
# math as the QEMU-lane xport-harness (`transport=TB-VMM-HOST`,
# `bus=VIRTIO-MMIO`). The whole M0..M31 chain is therefore CI-required under
# tb-vmm/KVM for the first time. MARKER RESOLUTION (documented deviation): the
# M30 proposal §8/§11C wrote this lane's bump as M19 -> 'M30: infer-transport
# OK', but the M31 stage A+B tail landed BEFORE stage C did — with the peer
# attached, the kernel runs the M31 wire legs too, so the honest lane target is
# the full CURRENT tail (the same cumulative-tail discipline as run-x86_64.sh);
# pinning M30 here would leave the M31 vmm evidence ungated.
#
# Anti-hollow legs on THIS lane (M30 proposal §4/§5, ported):
#   * the kernel's xport witness must carry THIS lane's tokens
#     (bus=VIRTIO-MMIO transport=TB-VMM-HOST) — the QEMU-chardev evidence class
#     is rejected by name (the §5.4 cross-pin, mirrored from run-x86_64.sh);
#   * the vmm-side host peer writes its OWN `xport-harness:` witness line to a
#     SEPARATE capture stream (the --xport-out file; guest serial rides
#     tb-vmm's stdout — the guest cannot write that file), and this script
#     string-compares challenge/tag CROSS-PROCESS (leg 2, the loopback
#     killer);
#   * the per-run key K (born from host OS RNG inside tb-vmm, never on any
#     command line) must appear NOWHERE in the guest serial output (§5.7).
#
# M8 makes tb-vmm create an in-kernel interrupt controller (KVM_CREATE_IRQCHIP)
# so the guest's LAPIC timer fires; with an in-kernel LAPIC the kernel's
# terminal `cli; hlt` parks IN-kernel (no KVM_EXIT_HLT), so tb-vmm runs to the
# wall-clock timeout while the serial device has already flushed every marker
# byte to the captured OUTPUT — the grep over OUTPUT is the verdict, exactly
# like the QEMU runners.
# Requires a usable /dev/kvm; if absent it SKIPS (exit 0) with a clear message.
#
# Usage:   scripts/run-vmm-x86_64.sh [path/to/kernel-elf]
# Env:     PROFILE=debug|release   VMM_TIMEOUT=<secs>
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Build identifiers (KERNEL_BIN, TARGET_X86, ...) — the single source of truth.
. "${REPO_ROOT}/scripts/project.env"
TARGET="${TARGET_X86}"
PROFILE="${PROFILE:-debug}"
KERNEL="${1:-${REPO_ROOT}/target/${TARGET}/${PROFILE}/${KERNEL_BIN}}"
# M19/M20 on this lane: tb-vmm attaches NO virtio-rng and NO virtio-blk, so the
# kernel's scans find only the M30 console (DeviceID 3 — the DeviceID-matching
# scan skips it for rng/blk) and print the graceful skip variants
# 'M19: virtio OK (no device, skipped)' / 'M20: persist OK (no disk, skipped)'
# — both POSITIVELY pinned below, so silently attaching either device class
# later forces a reviewed guard edit.
# M38 (stage B) DISPLACED M31 as the cumulative tail (mirroring run-x86_64.sh):
# the kernel-integrated conductor loop is the newest milestone. M31 is
# demoted-not-deleted (asserted directly below). The M38 marker is the new
# top-level grep, witnessed under tb-vmm/KVM too (the full CURRENT tail).
MARKER='M38: conductor OK turns=6 organs=3 verdict=ACCEPT'
TIMEOUT_SECS="${VMM_TIMEOUT:-30}"

if [[ ! -e /dev/kvm ]]; then
  echo ">> SKIP: /dev/kvm not present (tb-vmm requires hardware KVM)" >&2
  exit 0
fi
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  echo ">> /dev/kvm not accessible; attempting 'sudo chmod 666 /dev/kvm'" >&2
  sudo chmod 666 /dev/kvm 2>/dev/null || {
    echo ">> SKIP: cannot gain access to /dev/kvm" >&2
    exit 0
  }
fi
if [[ ! -f "${KERNEL}" ]]; then
  echo "error: kernel image not found: ${KERNEL}" >&2
  echo "build it first: cargo kbuild --target targets/${TARGET}.json" >&2
  exit 2
fi

echo ">> building tb-vmm (host, release)" >&2
( cd "${REPO_ROOT}/tb-vmm" && cargo build --release )

# M38 (stage B): the host conductor binary -- used ONLY for the §8.6 CROSS-PROCESS
# recompute leg (--recompute-from-trace re-folds the GUEST's OWN emitted conduct-step
# trace INDEPENDENTLY, host-side; the M38 guard string-equals its head against the
# guest-emitted `conduct: head=..`). Built on demand (this lane runs on a runner
# with cargo, the same as tb-vmm above).
CONDUCTOR_HOST_BIN="${REPO_ROOT}/tools/conductor-host/target/release/conductor-host"
if [[ ! -x "${CONDUCTOR_HOST_BIN}" ]]; then
  echo ">> building conductor-host (host, release)" >&2
  ( cd "${REPO_ROOT}/tools/conductor-host" && cargo build --release >&2 )
fi
TBVMM="${REPO_ROOT}/tb-vmm/target/release/tb-vmm"

# M30: the SEPARATE leg-2 capture stream + the key-leak-negative input. The
# host peer lives IN-PROCESS (tb-vmm's virtio-console backend), so its witness
# cannot ride a second process's stdout the way the QEMU lanes' harness does —
# instead tb-vmm writes it to a file the GUEST has no path to (guest serial is
# the stdout stream; the witness file is opened by the VMM before the guest
# runs). Two independently produced streams, same §5.6 discipline.
XOUT="$(mktemp)"   # the vmm-side host-peer witness lines (leg 2)
XKEY="$(mktemp)"   # the host-custodied key hex (the §5.7 key-leak check input)
trap 'rm -f "$XOUT" "$XKEY"' EXIT

echo ">> tb-vmm=${TBVMM}" >&2
echo ">> kernel=${KERNEL} timeout=${TIMEOUT_SECS}s" >&2

set +e
OUTPUT="$(timeout --foreground "${TIMEOUT_SECS}" \
  "${TBVMM}" --kernel "${KERNEL}" --print-exit --timeout-secs "${TIMEOUT_SECS}" \
  --xport-out "${XOUT}" --xport-key-out "${XKEY}" 2>&1)"
RC=$?
set -e

printf '%s\n' "${OUTPUT}"

# Surface the vmm-side witness stream into the log for traceability. The guard
# block compares ${OUTPUT} (guest serial) against ${HARNESS_OUT} (the host
# peer's file) — two independently produced streams; neither folds into the
# other before the comparison.
HARNESS_OUT="$(cat "${XOUT}" 2>/dev/null || true)"
printf '%s\n' "${HARNESS_OUT}"

if printf '%s' "${OUTPUT}" | grep -qF -- "${MARKER}"; then
  # ---- the cumulative chain under tb-vmm (displaced-marker asserts) --------
  # The full witness-level anti-hollow guards for M14..M29 are enforced on the
  # REQUIRED QEMU lanes (run-x86_64.sh/run-aarch64.sh) on every PR; this
  # lane's NEW evidence is the M30/M31 transport class, so the older markers
  # get direct fail-closed greps (order/displacement tripwires), with the
  # M19/M20 skip VARIANTS pinned positively (this lane attaches no rng/blk —
  # a real Proven line here would mean an unreviewed device grew in tb-vmm).
  for M in 'M14.2: blocking-recv OK' \
           'M19: virtio OK (no device, skipped)' \
           'M20: persist OK (no disk, skipped)' \
           'M21: kan-policy OK' \
           'M22: provenance OK' \
           'M23: experience OK' \
           'M24: bakeoff OK' \
           'M25: operator OK' \
           'M26: exit-telemetry OK' \
           'M28: operator-cmd OK' \
           'M29: khash-mac OK'; do
    if ! printf '%s' "${OUTPUT}" | grep -qF -- "${M}"; then
      echo ">> FAIL: final marker present but '${M}' missing (displaced/regressed under tb-vmm)" >&2
      exit 1
    fi
  done
  # M30 GUARDS (proposal §5, the run-x86_64.sh block ported to THIS lane's
  # tokens — house order: skip-reject, positive-require, by-name rejects,
  # lane-cross-pin, #71 tripwire, cross-process, key-leak, strip-then-reject).
  # This lane ATTACHES a host peer (tb-vmm's in-process backend), so the
  # anti-hollow composition is REQUIRED in full.
  #
  # (§5.1) Skip-variant reject BY NAME (the M20 idiom): an attached lane must
  # never take the graceful no-peer (or legacy) skip path.
  if printf '%s' "${OUTPUT}" | grep -qF -- 'M30: infer-transport OK (no host peer, skipped)'; then
    echo ">> FAIL: M30 ran in SKIP mode (no host peer found) but this lane attaches the tb-vmm virtio-console backend -- the host-keyed echo round-trip was NOT exercised" >&2
    exit 1
  fi
  if printf '%s' "${OUTPUT}" | grep -qF -- 'M30: infer-transport OK (legacy transport, skipped)'; then
    echo ">> FAIL: M30 took the legacy-transport skip but the tb-vmm backend is MODERN (Version=2) -- the Version=2 negotiation regressed" >&2
    exit 1
  fi
  # (§5.2) POSITIVE-REQUIRE the full xport witness: every flag =1, every token
  # literal, THIS lane's bus/transport tokens (vmm lane: VIRTIO-MMIO +
  # TB-VMM-HOST). A marker without this witness is a hollow pass.
  if ! printf '%s' "${OUTPUT}" | grep -qE -- 'xport: bus=VIRTIO-MMIO qsz=0x4 tx=0x0*1 rx=0x0*1 challenge=0x[0-9a-f]{32} nonce=0x[0-9a-f]{32} tag=0x[0-9a-f]{32} req-id=0x[0-9a-f]{16} echo-verified=0x0*1 body-bitexact=0x0*1 badtag-rejected=0x0*1 wrongkey-rejected=0x0*1 partial-rejected=0x0*1 desync-rejected=0x0*1 mode=POLL transport=TB-VMM-HOST echo=HOST-KEYED-VERIFIED key=HOST-CUSTODIED-PER-RUN backend=ECHO-ONLY sec=ASSUMED-FROM-LITERATURE'; then
    echo ">> FAIL: M30 marker present but the real witness 'xport: bus=VIRTIO-MMIO .. challenge=.. nonce=.. tag=.. echo-verified=0x1 .. mode=POLL transport=TB-VMM-HOST echo=HOST-KEYED-VERIFIED key=HOST-CUSTODIED-PER-RUN backend=ECHO-ONLY sec=ASSUMED-FROM-LITERATURE' was NOT seen (hollow M30 pass)" >&2
    exit 1
  fi
  # (§5.3) Loopback variants rejected BY NAME (case-insensitive, near the M30
  # marker/witness): the M22 mock-loopback design is structurally banned.
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M30:|xport:)' | grep -qiE -- 'transport=IN-KERNEL-LOOPBACK|transport=MOCK-BACKEND|transport=GUEST-SELF|echo=SELF-KEYED|echo=GUEST-KEYED|loopback|self-echo'; then
    echo ">> FAIL: M30 marker/witness carries a LOOPBACK token (IN-KERNEL-LOOPBACK/MOCK-BACKEND/GUEST-SELF/SELF-KEYED/GUEST-KEYED/loopback/self-echo) -- the M22 hollow-loopback design is banned by name (M30 proposal §5.3)" >&2
    exit 1
  fi
  # (§5.4) Lane-token cross-pin: the vmm lane must NEVER carry the chardev
  # lanes' evidence class (peer_id is MAC-covered; a mislabel is a fault).
  if printf '%s' "${OUTPUT}" | grep -qF -- 'transport=QEMU-CHARDEV-HARNESS'; then
    echo ">> FAIL: the vmm lane carries 'transport=QEMU-CHARDEV-HARNESS' -- no lane borrows the other's evidence class (M30 proposal §5.4 lane cross-pin)" >&2
    exit 1
  fi
  if printf '%s' "${OUTPUT}" | grep -qF -- 'bus=SERIAL-FRAMED'; then
    echo ">> FAIL: the vmm lane carries 'bus=SERIAL-FRAMED' -- the chardev lanes' bus token cannot appear under the tb-vmm virtio backend (M30 proposal §5.4 lane cross-pin)" >&2
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
  # kernel-witnessed challenge/tag must STRING-EQUAL the vmm-side host peer's
  # OWN line from its SEPARATE capture stream (the --xport-out file -- a
  # stream the guest mechanically cannot write; guest serial is stdout). A
  # loopback can mint a self-consistent tag but cannot equal khash(K,..)
  # without the host-custodied K.
  if ! printf '%s\n' "${HARNESS_OUT}" | grep -qE -- 'xport-harness: peer=TB-VMM-HOST challenge=0x[0-9a-f]{32} tag=0x[0-9a-f]{32} key-custody=VMM'; then
    echo ">> FAIL: the vmm-side host witness 'xport-harness: peer=TB-VMM-HOST challenge=.. tag=.. key-custody=VMM' was NOT seen on the --xport-out capture stream (no host peer answered -- leg 2 of the anti-hollow composition is missing)" >&2
    exit 1
  fi
  K_CH="$(printf '%s\n' "${OUTPUT}" | grep -E '(^|[^[:alnum:]])xport: ' | grep -oE 'challenge=0x[0-9a-f]{32}' | head -1)"
  K_TAG="$(printf '%s\n' "${OUTPUT}" | grep -E '(^|[^[:alnum:]])xport: ' | grep -oE '(^| )tag=0x[0-9a-f]{32}' | head -1 | tr -d ' ')"
  H_CH="$(printf '%s\n' "${HARNESS_OUT}" | grep -F 'xport-harness: ' | grep -oE 'challenge=0x[0-9a-f]{32}' | head -1)"
  H_TAG="$(printf '%s\n' "${HARNESS_OUT}" | grep -F 'xport-harness: ' | grep -oE '(^| )tag=0x[0-9a-f]{32}' | head -1 | tr -d ' ')"
  if [[ -z "${K_CH}" || -z "${K_TAG}" || "${K_CH}" != "${H_CH}" || "${K_TAG}" != "${H_TAG}" ]]; then
    echo ">> FAIL: CROSS-PROCESS mismatch -- kernel (${K_CH:-none} ${K_TAG:-none}) vs vmm host peer (${H_CH:-none} ${H_TAG:-none}); the bytes did not provably cross the guest/host boundary both ways (M30 proposal §5.6 -- the loopback killer)" >&2
    exit 1
  fi
  # (§5.7) Key-LEAK negative: the host-custodied K's hex must appear NOWHERE
  # in the guest serial output (the kernel must never print the revealed key;
  # K is also never on the tb-vmm command line -- it is born in-process).
  KHEX="$(cat "${XKEY}" 2>/dev/null || true)"
  if [[ -z "${KHEX}" ]]; then
    echo ">> FAIL: the vmm key file is empty -- the §5.7 key-leak check has no input (host-peer fault)" >&2
    exit 1
  fi
  if printf '%s' "${OUTPUT}" | grep -qiF -- "${KHEX}"; then
    echo ">> FAIL: the host-custodied per-run key LEAKED into the guest serial output (M30 proposal §5.7 key-leak negative)" >&2
    exit 1
  fi
  # (§5.8) Strip-then-reject overclaims: strip the declared structured tokens
  # FIRST (each carries a would-be-rejected substring), then reject the
  # network/crypto/inference overclaim vocabulary near the M30 marker/witness.
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M30:|xport:)' \
       | sed -e 's/HOST-KEYED-VERIFIED//g' -e 's/HOST-CUSTODIED-PER-RUN//g' \
             -e 's/ASSUMED-FROM-LITERATURE//g' -e 's/ECHO-ONLY//g' \
             -e 's/SERIAL-FRAMED//g' -e 's/VIRTIO-MMIO//g' \
             -e 's/QEMU-CHARDEV-HARNESS//g' -e 's/TB-VMM-HOST//g' \
       | grep -qiE -- 'network|internet|online|TLS|SSL|HTTPS|encrypt|confidential|secure[- ]channel|authenticated|cloud|remote[- ]model|real[- ]infer|model[- ](served|loaded)|validated|evaluated'; then
    echo ">> FAIL: M30 marker/witness carries an overclaim ('network'/'TLS'/'encrypt'/'authenticated'/'secure-channel'/'remote-model'/'real-infer'/'validated'/...) -- M30 is a LOCAL host-process echo transport; claims live ONLY in the structured stripped tokens (M30 proposal §5.8)" >&2
    exit 1
  fi
  # M30 is no longer the top-level grep (M31 displaced it as the cumulative
  # tail); assert it directly so the M30 -> M31 order stays fail-closed.
  if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M30: infer-transport OK'; then
    echo ">> FAIL: final marker present but 'M30: infer-transport OK' missing (M30 displaced/regressed)" >&2
    exit 1
  fi
  # M31 GUARDS (M31 proposal §7, the run-x86_64.sh block ported verbatim --
  # the mock-lane witness tokens are lane-independent; only the transport
  # underneath differs and is pinned by the M30 block above). The LIVE half
  # (backend=ANTHROPIC-LIVE) is operator-gated and NEVER on this lane.
  #
  # (§7.1) Skip-variant reject BY NAME: an attached lane never takes the
  # graceful no-peer skip.
  if printf '%s' "${OUTPUT}" | grep -qF -- 'M31: infer-e2e OK (no host peer, skipped)'; then
    echo ">> FAIL: M31 ran in SKIP mode (no host peer) but this lane attaches the tb-vmm backend -- the inference-adapter wire e2e was NOT exercised" >&2
    exit 1
  fi
  # (§7.2) POSITIVE-REQUIRE the full infer witness (every flag earned, every
  # honesty token literal, the exact deterministic wire shape: 2 chunks + 1
  # verified PENDING).
  if ! printf '%s' "${OUTPUT}" | grep -qE -- 'infer: backend=MOCK-DETERMINISTIC context=M13-SCALAR-RECALL recalls=0x[0-9a-f]+ prompt-len=0x[0-9a-f]+ resp-len=0x[0-9a-f]+ resp-digest=0x[0-9a-f]{32} req-id=0x[0-9a-f]{16} stop=END-TURN wire-err-handled=0x0*1 fold=M25-TRANSCRIPT key=CAPREF-HOST-CUSTODIED host=RESIDUAL-TCB ambient=ZERO-IN-GUEST sec=ASSUMED-FROM-LITERATURE chunks=0x0*2 pending=0x0*1'; then
    echo ">> FAIL: M31 marker present but the real e2e witness 'infer: backend=MOCK-DETERMINISTIC .. wire-err-handled=0x1 .. chunks=0x2 pending=0x1' was NOT seen (hollow M31 pass)" >&2
    exit 1
  fi
  # (§7.3) By-name rejects (case-insensitive, near the M31 lines): the LIVE
  # lane's evidence class -- and any live/real/network vocabulary -- is
  # structurally banned from this unattended lane.
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M31:|infer:|infer-dump:)' | grep -qiE -- 'backend=ANTHROPIC-LIVE|(^|[^[:alnum:]])real|(^|[^[:alnum:]])live|network|TLS|HTTPS|cloud|api[- ]key'; then
    echo ">> FAIL: M31 marker/witness carries a LIVE-lane token ('ANTHROPIC-LIVE'/'real'/'live'/'network'/'TLS'/'HTTPS'/'cloud'/'api-key') -- the unattended vmm lane never borrows the live lane's evidence class (M31 proposal §7.3/§7.4)" >&2
    exit 1
  fi
  # (§7.5) Inherited tripwire: INFER_PENDING is liveness plumbing, never a
  # completion; reject pending-as-completion vocabulary outright.
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M31:|infer:)' | grep -qiE -- 'pending[- ]complete|streamed|streaming'; then
    echo ">> FAIL: M31 witness claims streaming/pending-completion semantics -- INFER_PENDING is liveness plumbing, chunked delivery is reassembly of a COMPLETED response (M31 proposal §2f)" >&2
    exit 1
  fi
  # (§7.7) Raw-leak tripwires: no raw ESC byte in guest serial; every
  # infer-dump line matches the strict lowercase-hex grammar EXACTLY.
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
  # security overclaim vocabulary near the M31 lines.
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(M31:|infer:|infer-dump:)' \
       | sed -e 's/MOCK-DETERMINISTIC//g' -e 's/CAPREF-HOST-CUSTODIED//g' \
             -e 's/RESIDUAL-TCB//g' -e 's/ZERO-IN-GUEST//g' \
             -e 's/M13-SCALAR-RECALL//g' -e 's/M25-TRANSCRIPT//g' \
             -e 's/ASSUMED-FROM-LITERATURE//g' -e 's/END-TURN//g' \
       | grep -qiE -- 'understood|reasoned|intelligen|knows|learned|validated|evaluated|secure|confidential|private|authenticated-human|agi'; then
    echo ">> FAIL: M31 marker/witness carries an overclaim ('understood'/'reasoned'/'intelligen*'/'knows'/'learned'/'validated'/'evaluated'/'secure'/'confidential'/'private'/'authenticated-human'/'agi') -- M31's mock lane proves plumbing, never intelligence or semantics (M31 proposal §7.8)" >&2
    exit 1
  fi
  # M31 is no longer the top-level grep (M38 displaced it as the cumulative tail);
  # assert it directly so the M31 -> M38 order stays fail-closed (demote-not-delete).
  if ! printf '%s' "${OUTPUT}" | grep -qF -- 'M31: infer-e2e OK backend=MOCK-DETERMINISTIC'; then
    echo ">> FAIL: final marker present but 'M31: infer-e2e OK backend=MOCK-DETERMINISTIC' missing (M31 displaced/regressed)" >&2
    exit 1
  fi
  # M38 (stage B) GUARDS (proposal §8, the run-x86_64.sh block ported to THIS lane
  # -- the conductor witness tokens are lane-independent; the loop runs the SAME
  # cap-chokepoint organ execution under tb-vmm/KVM). The marker is the NEW tail.
  if printf '%s' "${OUTPUT}" | grep -qiE -- 'M38: conductor OK \(.*(skip|single organ|always-accept)'; then
    echo ">> FAIL: M38 ran in a skipped/degenerate variant -- honest-skip-is-FAILURE (proposal §8.1)" >&2
    exit 1
  fi
  if ! printf '%s' "${OUTPUT}" | grep -qE -- 'conduct: head=0x[0-9a-f]{16} turns=0x[0-9a-f]+ organs=0x[0-9a-f]+ roles=[TWV]+ organ-seq=0x[0-9a-f]+ verdict=ACCEPT accept-at=0x[0-9a-f]+ revise-cycles=0x[0-9a-f]+ fold-verified=0x0*1 tamper-caught=0x0*1 organ-calls=0x[0-9a-f]+ logical-ticks=0x[0-9a-f]+ attested=0x0*1 prov-tag=0x4 policy=DISCRETE-HAND-WRITTEN-NOT-LEARNED learning=DORMANT retrieval=LEXICAL-NOT-SEMANTIC external-organ=MOCK-IN-CI local-organ=M38-AUTHORED-MOCK verifier=CI-DISCRETE-VERDICT m18-gate=ADMISSION-ONLY-INERT-IN-MOCK cost=HONEST-ACCOUNTED-TOKENED cost-metric=LOGICAL-SURROGATE-NOT-WALLCLOCK orchestration=RAG-AGENTS-NOT-NEW-PARADIGM live[+]web=DISPATCH-ONLY novelty=VERIFIED-PROVENANCE-SOVEREIGN-WRAPPER generativity=OPEN-FRONTIER realtime=NOT-CLAIMED benchmark=NOT-CLAIMED stub-resistance=HOST-RECOMPUTE-FROM-INDEPENDENT-TRACE host=RESIDUAL-TCB sec=ASSUMED-FROM-LITERATURE'; then
    echo ">> FAIL: M38 marker present but the full one-line 'conduct: head=.. ..' witness was NOT seen (hollow M38 pass)" >&2
    exit 1
  fi
  CONDUCT_LINE="$(printf '%s\n' "${OUTPUT}" | grep -E -- '^conduct: head=0x' | head -1)"
  M38_ORG_HEX="$(printf '%s' "${CONDUCT_LINE}" | sed -E 's/.* organs=0x0*([0-9a-f]+) .*/\1/')"
  if [[ -z "${M38_ORG_HEX}" ]] || (( 16#${M38_ORG_HEX} < 2 )); then
    echo ">> FAIL: M38 organs=0x${M38_ORG_HEX} < 0x2 (a degenerate single-organ stub)" >&2
    exit 1
  fi
  M38_RC_HEX="$(printf '%s' "${CONDUCT_LINE}" | sed -E 's/.* revise-cycles=0x0*([0-9a-f]+) .*/\1/')"
  if [[ -z "${M38_RC_HEX}" ]] || (( 16#${M38_RC_HEX} < 1 )); then
    echo ">> FAIL: M38 revise-cycles=0x${M38_RC_HEX} < 0x1 (an always-accept stub)" >&2
    exit 1
  fi
  # (§8.6) THE CROSS-PROCESS INDEPENDENT-RECOMPUTE LEG (the loopback/fixture killer).
  GUEST_HEAD="$(printf '%s' "${CONDUCT_LINE}" | grep -oE 'head=0x[0-9a-f]{16}' | head -1)"
  CONDUCT_TRACE="$(printf '%s\n' "${OUTPUT}" | grep -E -- '^conduct-step: ')"
  if [[ -z "${GUEST_HEAD}" || -z "${CONDUCT_TRACE}" ]]; then
    echo ">> FAIL: the guest emitted no conduct head / no conduct-step trace -- the §8.6 independent host-recompute has no input" >&2
    exit 1
  fi
  RECOMPUTE_OUT="$(printf '%s\n' "${CONDUCT_TRACE}" | "${CONDUCTOR_HOST_BIN}" --recompute-from-trace 2>/dev/null || true)"
  HOST_HEAD="$(printf '%s' "${RECOMPUTE_OUT}" | grep -oE 'head=0x[0-9a-f]{16}' | head -1)"
  if [[ -z "${HOST_HEAD}" || "${GUEST_HEAD}" != "${HOST_HEAD}" ]]; then
    echo ">> FAIL: CROSS-PROCESS mismatch -- guest conduct head (${GUEST_HEAD}) != host independent-recompute head (${HOST_HEAD:-none}); the lineage is forged/fixtured (proposal §8.6)" >&2
    exit 1
  fi
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(conduct:|conduct-step:|M38:)' | grep -qiE -- 'policy=LEARNED|policy=ES|policy=CMA|KAN_ACTIVE=true|backend=ANTHROPIC-LIVE|verifier=LEARNED|verifier=CLASSIFIER|embedding|cosine|loopback|fixture|canned|replay|(^|[^[:alnum:]])real-infer'; then
    echo ">> FAIL: M38 marker/witness carries a by-name reject token (proposal §8.3)" >&2
    exit 1
  fi
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])conduct-step:' | grep -vE -- '^conduct-step: turn=0x[0-9a-f]+ role=0x[0-9a-f]+ organ=0x[0-9a-f]+ verdict=0x[0-9a-f]+ organ-calls=0x[0-9a-f]+ t-logical=0x[0-9a-f]+$' | grep -q .; then
    echo ">> FAIL: a conduct-step line violates the strict lowercase-hex grammar (proposal §8.5)" >&2
    exit 1
  fi
  if printf '%s' "${OUTPUT}" | grep -E -- '(^|[^[:alnum:]])(conduct:|M38:)' \
       | sed -E 's/[a-z+-]+=[A-Za-z0-9+/.:_-]+//g' \
       | grep -qiE -- 'learned|trained|intelligen|understood|generaliz|benchmark|SOTA|real-time|semantic|cosine|float|embedding'; then
    echo ">> FAIL: a residual claim word survives token-stripping near the M38 lines (proposal §8.7 razor)" >&2
    exit 1
  fi
  echo ">> PASS: tb-vmm booted the kernel via tb-boot v0 (no PVH) to '${MARKER}' (full M0..M38 chain under KVM; M30 transport=TB-VMM-HOST cross-process challenge/tag equality held; key-leak negative clean; M31 mock e2e witnessed; M38 conductor loop witnessed + the guest trace independently re-folded host-side ${GUEST_HEAD} == ${HOST_HEAD})" >&2
  exit 0
fi

echo ">> FAIL: marker '${MARKER}' not seen (tb-vmm/timeout rc=${RC})" >&2
exit 1
