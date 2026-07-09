---
type: Design Decision
title: "M31 — the real Anthropic adapter (inferwire byte framing + live lane)"
description: "Chunked inferwire byte framing + infer_bytes path; two backends: CI-required deterministic mock and secret-gated live Anthropic bridge."
tags: ["m31", "inference", "anthropic", "inferwire", "liveness", "prompt-injection"]
timestamp: 2026-06-11T21:41:22+03:00
status: locked
diataxis: explanation
---

# M31 — the real Anthropic adapter (`inferwire` byte framing + the `infer_bytes` path + the secret-gated live lane)

**Status:** **stages A+B LANDED, CI-green both arches (the cumulative tail is `M31: infer-e2e OK backend=MOCK-DETERMINISTIC`); stage C LANDED — the ANTHROPIC-LIVE bridge (`tools/xport-harness/src/live.rs`: `--anthropic`/`XPORT_ANTHROPIC=1` + env-only key, the §4 deps `ureq`+`rustls`+`serde_json`, the §2e closed taxonomy, the §5 host-leg liveness on the kernel's per-boot wire challenge (transform v3 `HEX-REVERSE-ANY` — see the amendment below), model pinned `claude-haiku-4-5` @ `max_tokens=64`, ONE call per run latched, key-scrub-tested, fixture-seam unit tests) + the secret-gated `real-infer.yml` (`workflow_dispatch` ONLY, never a required check, missing secret = the §7.1 LOUD named skip, the workflow-level dual-marker verdict `M31: real-infer OK backend=ANTHROPIC-LIVE`); the trigger remains the OPERATOR'S secret + dispatch (`docs/RUN-THE-HELLO.md`), never unattended.** Stage-C landing notes vs this spec: the stage-B kernel pins the wire exchange to the deterministic mock shape BIT-EXACTLY (`selftests.rs` stages 0x21 exact receive-window / 0x25 `pending==1` + exact chunk count / 0x26 bit-equality) — so (1) the live response NEVER rides to the guest (the guest-bound answer stays the mock shape on every lane; the live response is host-witnessed by digest on the bridge's `xport-harness-infer: backend=ANTHROPIC-LIVE` line, the §7 bridge-witness field set), (2) the §5.5 KERNEL leg (in-guest transform search, the guest-serial live witness/marker, the live digest in the M25 fold) is a NAMED kernel follow-up — the §5.6 adjudication is therefore host-leg-only at stage C and the `M31: real-infer OK` verdict is printed by the WORKFLOW after asserting the §5.4 witness + the untouched cumulative chain, and (3) the live call rides AFTER the guest is answered (answer-first: `POLL_CAP` is sub-second under KVM and the exact-shape check forbids extra PENDINGs, so HTTP latency may never sit inside the wire exchange). Additionally (the witnessable-hello amendment): the prompt envelope asks for a SECOND line greeting Yuva — §5-COMPATIBLE because acceptance is unchanged (the transform substring remains the ONLY liveness criterion; the greeting can neither pass a non-compliant answer nor fail a compliant one, unit-asserted), and the response text is hex-framed (scrub-then-hex, capped at 2048 bytes, explicit `truncated` flag) on EXACTLY ONE `xport-harness-infer-body:` line (prefix disjoint from the verdict grep by construction; the verdict's `resp-digest` still commits to the RAW text) — every log stays §6 inert-alphabet-only, and the human-readable decode exists ONLY on the `real-infer.yml` run-summary page, labeled untrusted model output. **The transform-v3 amendment (supersedes the §5.2 sketch's char-reversal AND the v2 group-only narrowing): `transform=HEX-REVERSE-ANY`, with a forensic `matched=GROUP|BYTE|CHAR` field on the OK witness (`NONE` only on `transform-ok=0`).** The v1→v2→v3 record: v1 asked for character-level reversal — a well-known LLM TOKENIZATION weakness, a model-CAPABILITY test wearing a liveness token; the FIRST live dispatch (run 27408247558) returned a REAL 200 that missed it (`outcome=TRANSFORM-MISS`, fail-closed as designed). v2 narrowed to group-ORDER reversal of the pre-grouped challenge hex — a trivial sequence task — but was INTERPRETATION-FRAGILE: it accepted ONLY that one rendering. The SECOND live dispatch (run 27959048211) returned a REAL 200 (`http=200`, request-id present) whose model produced the BYTE-order reversal instead (challenge `8c3f1a587275a8d8567b73b8926cb1a1` → response line `a1b16c92 b8737b56 d8a87572 581a3f8c`, the 16 challenge bytes in reverse order) — an equally-valid reversal that proves freshness exactly as well, yet v2 logged `transform-ok=0 outcome=TRANSFORM-MISS`: the gate was simply too strict about WHICH reversal. v3 accepts ANY of the three STANDARD reversals of the 32-char lowercase challenge hex under the same lowercase/strip-whitespace normalization — (1) **group-reverse** (`chunk[3]chunk[2]chunk[1]chunk[0]`, the v2 form), (2) **byte-reverse** (the `[u8;16]` reversed then hexed = the form the live model produced), (3) **char-reverse** (the full 32-char hex reversed) — and names the matched form on the witness. Every liveness property is PRESERVED: each form is non-identity vs the FORWARD hex for any non-palindromic nonce (a prompt PARROT echoing the forward groups still matches NONE — the anti-echo teeth), and each derives from THIS boot's kernel-minted challenge (a stale/replayed nonce matches NONE — the anti-replay teeth); the three forms collide with the forward hex only for a degenerate palindromic challenge (~2^-64), and since the challenge is kernel-minted and cannot be re-minted host-side, that astronomically unlikely case fails honestly (assert-and-proceed, acceptance never widened). Rationale in one line: char-reversal was tokenization-unrealistic, group-only was interpretation-fragile, any-standard-reversal is robust while keeping anti-parrot/anti-replay. And the body line now ALSO rides the 200-class failures (`TRANSFORM-MISS`/`REFUSAL`, whose verdict lines additionally print `resp-digest=`): a failed hello is witnessable — decoded on the summary page under an explicit "the lane still FAILED" label — while transport/auth/no-body outcomes stay body-less. Earlier landing notes vs this spec: the §8.4/§8.5 khash-bearing harnesses landed in the PINNED-VECTOR one-khash-execution shape (the measured #49 budget: a 90-byte M31 MAC message costs ~70s per CBMC execution; every proposal-sketch form measured over budget — the ladder record lives in the harness docs + the landing PR); the stage-B mock lane additionally serves the deterministic `mock_infer` response OVER the wire (one PENDING + 2 MAC'd chunks answered by the keyless harness), so the chunked assembler does real wire work every boot beyond the §3d keyless `ERR NO-KEY` check; the §3d fold rides `opframe_selftest` (the M25 transcript grew frame seq 3 = the inference-digest MARKER before the closing GATE_VERDICT — `tx_head` displaced by design, every other fold head byte-identical). · **Pillar:** communication (the first real model traffic over the sovereignty channel) + honesty (dual markers, injection-proof serial, the liveness proof) · **Depends on:** M30 (the landed inferwire leaf + virtio-console channel + the `xport-harness` host peer + the two-leg anti-hollow lanes), M29 (`tb-encode::khash`; **stage-C `prov_hash` cutover is a HARD sequencing gate — a code agent is cutting `prov.rs` FNV→khash concurrently, and the M31 M25-fold + body-digest design targets the POST-cutover fold; no M31 `tb-encode`/`prov`/`opframe` edit lands before stage C does**), M16 (`InferBackend`/`ModelSession`/caps dispatch), M13 (`M_MEM_RECALL`/`read_touch` — the mock lane's context source), M25/M22 (the opframe transcript fold) · **Tasks:** #89 / A2 real Anthropic adapter (sovereignty-plan §M31; absorbs BACKLOG row 24's Anthropic slice — the OpenAI adapter stays parked, claimed by no item) · **Markers (DUAL, both binding spellings from the plan):** CI-required `M31: infer-e2e OK backend=MOCK-DETERMINISTIC` (the ONLY variant in the cumulative chain) + secret-gated optional `M31: real-infer OK backend=ANTHROPIC-LIVE` (never a required check, never in unattended runs).

> **One-line:** the **byte-prompt/byte-response framing is the bulk** (the plan's own amendment): the landed `inferwire` leaf grows closed kinds `INFER_REQ`/`INFER_RESP`(+`INFER_PENDING`, +`ERR` semantics) with MAC-bound chunking and a Kani-proven reassembler, `InferBackend` grows the `infer_bytes` path that retires the u64 toy, and TWO backends sit behind the one trait: **MOCK-DETERMINISTIC** (in-kernel pure transform over real M13-recalled context — the CI-required, network-free, cumulative-chain lane) and **ANTHROPIC-LIVE** (the `xport-harness` host bridge speaks HTTPS to the Messages API — TLS lives ONLY in the host process, the API key is `CAPREF-HOST-CUSTODIED`, and the optional lane proves LIVENESS via a per-run challenge nonce whose transform must appear in the response, with request-id + response digest folded into the M25 transcript). **Untrusted model bytes are hex-encoded before they touch serial** — the guards are not line-anchored, so raw model text could forge a marker; the inert alphabet makes that structurally impossible.

Synthesis of [`docs/research/m31-real-infer-literature.md`](../research/m31-real-infer-literature.md) (the Messages API shape, framing/chunking precedent, injection neutralization, secret-lane patterns, liveness design). **Decisions: chunked stop-and-wait framing via an in-payload sub-header under the untouched `INFER_PAYLOAD_CAP` (research §3, CoAP block-wise precedent); hex-encode-before-serial (research §4, Spotlighting/CWE-117); the host bridge is the `xport-harness` serve loop, NOT tb-vmm (§4 below); `ureq`+`rustls`+`serde_json` as the minimal host dep tree, `reqwest` runner-up (drags tokio).**

---

## 1. Why this milestone, and why these choices

M30 landed a verified channel that proves bytes cross the guest/host boundary — but `backend=ECHO-ONLY`: no meaning rides it. M31 puts the first inference semantics on top, and the plan's amendments fix the three places a naive "call the API" milestone would rot:

1. **The framing is the bulk, not the HTTPS call.** `InferRequest`/`InferResponse` are u64 scalars (`crates/tb-hal/src/infer.rs:40-45,69-74`) with the variable-length path explicitly deferred (`infer.rs:22-27`). Real prompts/responses are byte bodies that exceed `INFER_PAYLOAD_CAP=1024`, and that cap transitively pins `ECHO_MSG_CAP`, `INFER_ACCUM_CAP`, the kernel's fixed stack buffers, and every Kani bound (#49) — so the answer is **chunking under the existing cap**, not a cap raise (§2).
2. **The honest marker must survive the dishonest input.** Model output is untrusted bytes, and the house guard filters are token-boundary, NOT line-anchored (`grep -E '(^|[^[:alnum:]])(M30:|xport:)'`, `scripts/run-x86_64.sh:476`). Model text containing `M31: real-infer OK backend=ANTHROPIC-LIVE` would satisfy a naive grep. Hence §6: **all model-derived bytes are hex-encoded to a regex-inert alphabet before any serial/stdout write.**
3. **The live lane must prove liveness, never gate CI.** Network + a secret = flake + exfil surface. So: dual markers (only the mock variant in the cumulative chain), a challenge-nonce transform proving the round-trip is fresh (§5), missing secret = LOUD skip, and the milestone is **explicitly NOT fit for unattended overnight runs** — the plan says so verbatim, and §13's landing plan repeats it.

## 2. The leaf extension — `crates/tb-encode/src/inferwire.rs` (the bulk)

Same leaf, same magic `0x5444`, same `ver=1`, same `no_std`/`forbid(unsafe_code)`/zero-dep discipline. The kind set is CLOSED and fail-closed (`kind_known`, `inferwire.rs:249-251`); `ERR=3` was reserved exactly so this adapter never overloads `ECHO_*` (`:146-148`). Every change below touches `kind_known`, the negative-set tests, and the inferwire Kani harnesses — accounted in §8/§9.

### 2a. New kinds (closed set, fail-closed preserved)

```text
ECHO_REQ=1, ECHO_RESP=2          (M30, untouched — the echo lane stays green)
ERR=3                            (reserved at M30; M31 gives it payload semantics)
INFER_REQ=4, INFER_RESP=5        (chunked byte bodies, §2b)
INFER_PENDING=6                  (bridge heartbeat while awaiting HTTP, §2f)
```

Unknown kinds (7+) keep rejecting at `canon`/`decode`/`FrameAccum::scan` — the extension must not widen totality.

### 2b. Chunking — the in-payload sub-header (ver=1 kept; the header `flags` byte CANNOT carry seq bits)

The header's reserved `flags` byte is forced zero by `canon` and rejected nonzero by `decode` (`:278,:324-326`) — chunk metadata in the header would force `INFER_VER=2` and re-prove the whole codec. **Decision: a fixed 24-byte sub-header INSIDE the payload of kinds 4/5** (the layered-payload convention `opframe.rs:146-149` already sanctions), leaving the M30 header codec byte-identical:

```text
seq:u16 LE          chunk index, 0-based, strictly in-order (stop-and-wait lockstep)
sflags:u8           bit0 = MORE (another chunk follows); bits1..7 reserved-zero fail-closed
rsv:u8              = 0 (fail-closed)
total_len:u32 LE    whole-body byte length — IDENTICAL in every chunk of a sequence
body_digest:[u8;16] truncated digest of the WHOLE body — IDENTICAL in every chunk
chunk bytes…        ≤ INFER_CHUNK_CAP = INFER_PAYLOAD_CAP − 24 = 1000
```

`body_digest` uses the post-M29-stage-C `prov_hash`/`op_hash` construction (khash under the fixed public domain label) — ONE digest discipline, so the on-wire commitment and the M25 transcript fold (§3d) are the same function. The whole-body bound is a **compile-time shared const** `INFER_BODY_CAP = 8192`: `tb-encode` builds for the host triple, both ends compile the SAME leaf — compile-time agreement is the negotiation (research §3, the MQTT/RFC-8449 analog without a handshake to get wrong). Overflow on either end is **reject, never truncate** (`ERR code=TOO-LARGE`, the 413 mirror).

### 2c. The MAC — `infer_tag`/`verify_infer_resp`, a NEW domain separator

`verify_echo` demands body-bitexact response==request (`:474-486`) — structurally wrong for inference. Sibling pair, reusing `echo_tag`'s construction with the new label **`TABOS-M31-INFER-V1`** (the `ECHO_DOMAIN`/`KDF_DOMAIN` precedent `:128-132`), ONE khash call per chunk:

```text
T = khash(K, "TABOS-M31-INFER-V1" ‖ peer_id ‖ nonce ‖ challenge ‖ req_id ‖ kind ‖ seq ‖ sflags ‖ total_len ‖ body_digest ‖ chunk)[..16]
```

**Everything that adjudicates rides INSIDE the MAC** — chunk index included (the M28/Terrapin bind-inside-the-MAC rule): a reordered, spliced, or cross-sequence chunk fails verification, not just assembly. `K` is the M30 host-custodied per-run channel key, custody unchanged. The #89 liveness rule (§5) is enforced ON TOP of the MAC, not instead of it.

### 2d. The reassembler — `InferAssembler` (new, Kani-proven)

Fixed-capacity, fail-closed, the `FrameAccum`/`BoundedRing` lineage: `push_chunk(subhdr, bytes) -> Option<body_complete_len>`. Rejects out-of-order/duplicate/gapped `seq`, `total_len` or `body_digest` drift across chunks, sum-of-chunks ≠ `total_len`, and capacity overflow (every index Kani-checked at a tiny const-generic cap — the landed `FrameAccum` at-capacity discipline, the §8 harness). On completion the assembled body's recomputed digest MUST equal `body_digest` — the dump is never trusted over the commitment.

### 2e. `ERR=3` gains semantics (closed enum, no raw provider text)

Payload = `{code:u16, retryable:u8, rsv:u8}`. Codes (closed): `NO-BACKEND`, `NO-KEY`, `TOO-LARGE` (413 mirror), `RATE-LIMITED` (429, retryable), `OVERLOADED` (529, retryable), `API-ERROR` (500, retryable), `AUTH` (401/403), `BAD-REQUEST` (400), `REFUSAL` (stop_reason=refusal with empty content), `TIMEOUT`. **Raw provider error JSON is untrusted text and never crosses to the guest or serial unencoded** — the bridge maps to this enum; at most a digest of the raw body is logged host-side.

### 2f. `INFER_PENDING=6` — "API is slow" must never equal "peer is dead"

Real-API latency (seconds) vs the guest's `POLL_CAP` is the new hazard (research §3). The bridge emits a MAC'd empty-payload `INFER_PENDING` (same `req_id`) on a fixed cadence while the HTTP call is in flight; each VERIFIED pending resets the guest's poll budget, with a hard cap on total pendings. A dead peer still hits M30's hard `FAIL xport-timeout`; a slow API does not. This is liveness plumbing, **not flow control** — stop-and-wait with ONE outstanding `req_id` is the backpressure (CoAP-lockstep), and no token claims otherwise.

## 3. The kernel seam — the `infer_bytes` byte path (retiring the u64 toy)

### 3a. The trait method — object-safe, zero-alloc, Result-bearing

```rust
fn infer_bytes(&self, model: ModelId, prompt: &[u8], resp_out: &mut [u8])
    -> Result<(usize, StopReason), InferError> { Err(InferError::Unavailable) }
```

Default body keeps `MockBackend` and the M16 marker source-compatible; `InferError` (incl. `ContextExceeded`/`Unavailable`, `infer.rs:79-91`) finally becomes returnable. `ModelSession` gains `invoke_bytes`. The scalar `infer()` stays for M16 compatibility — deprecated in doc-comment, removed at a named future cleanup, never silently.

### 3b. Dispatch — `M_MODEL_INVOKE_BYTES` beside `M_MODEL_INVOKE`

Caps args are `[u64;4]` scalars, so prompt/response bytes ride exactly the path `infer.rs:22-27` deferred to: a block/channel handle + length through a new method id in `caps.rs`, gated by the same `Rights::INVOKE_MODEL`-class right at the M11 chokepoint. `resolve()`/longest-prefix routing (`tb_encode::route`) is untouched.

### 3c. The two backends behind one trait (the agnosticity pillar, made checkable)

- **`MOCK-DETERMINISTIC`** — in-kernel pure byte transform: `resp = op_hash-derived expansion of (prompt)`, no clock, no RNG, CI-reproducible bit-for-bit. The ONLY variant in the cumulative chain. Registered in the static `ROUTES`.
- **`ANTHROPIC-LIVE`** — `infer_bytes` frames the prompt into `INFER_REQ` chunks over the M30 channel via `arch::chan_send_recv` (the seam `xport_selftest` already drives), reassembles `INFER_RESP`, MAC-verifies every chunk. **The static-registration wrinkle, resolved:** `ROUTES` is an immutable `&'static` slice and the channel slot is runtime-probed — so the live backend is constructed at the selftest/agent seam with the probed slot passed in (stack-local, not in `ROUTES`); static registration of a channel-backed route is a NAMED deferral.

### 3d. The mock-lane story — context from M13, fold into M25 (real substrate state, zero network)

The in-kernel selftest agent, through the capability chokepoint (the M13/M16 dispatch idiom): `M_MEM_RECALL` (`Rights::RECALL`, the 3-stage ranked pipeline) recalls record ids by query token → `M_MEM_READ`/`read_touch(id)` returns each u64 value AND stamps the unfiltered `RECALL_TOUCH` xp record — **context-gathering automatically leaves the M24 survival-label trace**. The recalled scalars are serialized LE into the byte prompt → `infer_bytes` on MOCK-DETERMINISTIC → response → **one additional M25 transcript frame whose payload is `req_id (u64 LE) ‖ op_hash(response-bytes)`** — the DIGEST, never raw model bytes (fixed-width, injection-inert): kind = `MARKER` with the layered-payload convention (lowest churn, sanctioned at `opframe.rs:146-149`; runner-up `kind::INFER_DIGEST=5` rejected for codec+harness churn), partition `CANDIDATE` (`SAFETY_HELD_OUT` fail-closes at canon, `opframe.rs:99-111`), folded via `op_append` BEFORE the closing `GATE_VERDICT` so the committed final seq covers it (the tail-truncation catch). The live lane folds the same frame shape — request-id digest + response digest. **Honest limit, tokened:** M13 stores u64 value scalars, not byte blobs — the prompt is scalar-derived (`context=M13-SCALAR-RECALL`); byte-payload memory records are a separate, nameable deferral.

So `M31: infer-e2e OK` proves, end-to-end and deterministically: recall → prompt assembly → `infer_bytes` → response → digest fold — with no network and no channel dependency beyond what M30 already proves every boot. Additionally the CI lanes exercise the NEW kinds on the wire without claiming live inference: the kernel sends one `INFER_REQ` to the keyless harness, which answers a MAC'd `ERR code=NO-KEY`; the kernel verifies and reports `wire-err-handled=0x1` — the new framing transits the boundary in-boot, fail-closed path included.

## 4. The host bridge — the `xport-harness` serve loop (NOT tb-vmm), and the dependency decision

**Graft point:** `tools/xport-harness/src/main.rs` after the `FrameAccum` read loop + decode (`:133-170`) — today it accepts exactly ONE `ECHO_REQ`, answers, and lingers to EOF (`:213-224`). M31 turns this into a **serve loop dispatching on `frame.kind`**: `ECHO_REQ` keeps the M30 echo verbatim (that lane stays green); `INFER_REQ` reassembles chunks and either (keyless) answers `ERR NO-KEY` or (live) calls the Messages API and returns MAC'd `INFER_RESP` chunks + `INFER_PENDING` heartbeats, printing its own witness line for the §7.6 cross-process leg.

**Honesty note on the plan's "tb-vmm host bridge" wording:** tb-vmm's bus is only "extensible to virtio" — no virtio backend exists (M30 stage C is still the open BACKLOG row 23 remainder). The chardev harness is the ONLY existing seam, and it serves BOTH arch lanes (`run-aarch64.sh` uses the same binary). The bridge therefore lands in the harness; when M30 stage C lands, the same `infer_host` logic is the reuse target. The harness stays unix-socket/Linux-host-only (`std::os::unix::net`) — a stated lane constraint, not a new one.

**Dependencies — the FIRST non-zero-dep host peer (the ledger entry the plan demands).** The harness's `Cargo.toml` currently depends ONLY on `tb-encode`, inside its own nested workspace (the tb-vmm precedent) — so the kernel `no_std`/kbuild lanes are already firewalled. M31 adds: **`ureq` + `rustls` + `serde_json`** (minimal tree; **runner-up `reqwest`**, rejected for dragging tokio into a one-call bridge). Streaming SSE, retries, model choice, `max_tokens` clamping (worst-case response bytes must fit `INFER_BODY_CAP` — UTF-8 ~3-4 bytes/token, clamp conservatively) are ALL host-side policy; **SSE never crosses the virtio boundary** — the bridge accumulates and delivers one reassembled chunk sequence.

**Secret custody (`key=CAPREF-HOST-CUSTODIED`).** `ANTHROPIC_API_KEY` lives ONLY in the bridge process env (sourced from the Actions secret / operator shell). The guest image, cmdline, channel, and serial never carry it — STRICTER than M30's K (which is revealed on-channel by design; the API key is never revealed anywhere). The bridge never prints the key, its prefix, or its length (GitHub log-masking fails on transformed values); a `--key-leak-probe-out` file carries a per-run canary derivative for the §7.7 negative the same way `XKEY` does today.

## 5. The liveness protocol — challenge-nonce transform (NAMED section; the live lane's anti-hollow)

**The threat is hollow evidence again, one level up:** a lane that prints `real-infer OK` from a canned fixture, a replayed transcript, or the mock backend wearing the live token. The mechanism is the TPM/ACME freshness discipline adapted to an LLM (research §6):

1. **Per-run nonce.** The run script generates `N:[u8;16]` from host RNG at run start and hands it to the bridge (env/fd, like K).
2. **The prompt carries the challenge.** The bridge appends a host-side instruction block to the guest's prompt: "reply including the reverse of the hex string `<hex(N)>`" — `transform=HEX-REVERSE`, trivial-but-non-identity (a prompt echo cannot pass; model compliance is near-certain).
3. **One pinned call.** Cheapest adequate model, small `max_tokens` (≤64 for the liveness call), no retries beyond SDK defaults.
4. **Acceptance, host leg:** HTTP 200 + request-id header present + `reverse(hex(N))` substring in the response text. The bridge prints its witness line (§7) with `nonce`, `transform-ok`, hex-encoded request-id, response digest.
5. **Acceptance, kernel leg:** the MAC'd `INFER_RESP` carries N in the header nonce field (bound inside the MAC with this boot's challenge C and `req_id`); the kernel independently computes `reverse(hex(N))`, searches the DECODED response bytes in memory (never raw on serial), and prints its witness with `nonce`/`transform-ok`/`resp-digest`.
6. **The run script adjudicates** M30-style: kernel line and bridge line must string-equal on `nonce`/`reqid-hex`/`resp-digest`, both with `transform-ok`. A guest-side forgery fails the host leg; a host-side stale fixture fails the kernel leg (stale N).
7. **Distinct outcomes, never conflated:** `TRANSFORM-MISS` (200 + request-id, transform absent — a compliant-but-wrong model answer; reported, never silently retried into a pass) ≠ `LIVENESS-FAIL` (no fresh round-trip evidence) ≠ `FAIL-RETRYABLE` (429/529 — never a pass, never a liveness verdict).
8. **What is and is not proven (the `assumptions.md` entry, verbatim destination):** the composition proves "**a process holding the key obtained a fresh nonce-dependent transform from an endpoint behaving as the live Anthropic API over TLS**". It does NOT prove absence of a MITM beyond the rustls/OS trust roots, does NOT bound model behavior, and is **bridge-honesty-conditional** — the bridge is trusted ground (`host=RESIDUAL-TCB`), exactly like M30's host peer; host exclusivity awaits the M33 signature primitive. The transcript's request-id + digest are third-party-correlatable per-request evidence (Anthropic's logs), not a verified signature.

## 6. Injection-proofing — hex-encode before serial (NAMED section; binding per task #89)

**The threat, stated plainly: the guards are not line-anchored.** The house lane filter is `grep -E '(^|[^[:alnum:]])(M31:|infer:)'` (the M30 shape, `run-x86_64.sh:476`) — model output containing `M31: real-infer OK backend=ANTHROPIC-LIVE`, an honesty token, or an ANSI escape would (1) forge a marker past CI, (2) hijack any terminal rendering the logs (Terminal DiLLMa / Trail-of-Bits MCP class). The canonical fix is ENCODE-BEFORE-WRITE (CWE-117), and encoding is the measured strongest mode against injected text (Spotlighting: >50% attack success with delimiters → <2% encoded).

**Mechanism (kernel side AND bridge side, no exceptions):**

- **ALL model-derived bytes are lowercase-hex-encoded before ANY serial/stdout write.** `[0-9a-f]` is regex-inert by construction: it cannot contain `:`, space, newline, uppercase `M`, `=`, or ESC `0x1b` — it can neither forge an `M31:`-prefixed marker/token nor carry an ANSI sequence. Cost: 2× length, bounded by capping the dump.
- **Emission grammar:** `infer-dump: req-id=0x<16hex> seq=0x<hex> resp-hex=<lowercase hex, fixed per-line cap>` lines, with the authoritative `resp-len=` OUT of band on the `infer:` witness (truncation-evident) and `resp-digest=` as the fixed-size commitment the transcript folds — the dump is never the evidence, the digest is.
- **Hex-encoded request-id too:** `reqid-hex=` — the request-id is remote-derived text; same rule, no exceptions for "it looks safe".
- **Decoded model text is NEVER echoed raw on any lane** — markers and tokens are printed only by kernel code paths after verification; the kernel's transform search (§5.5) happens in memory.
- **Defense-in-depth (each cheap, none sufficient alone — encode-first is the load-bearer):** (a) the M31 greps anchor as tightly as the harness allows anyway; (b) a **raw-leak tripwire** in the guards: FAIL on ESC `0x1b` anywhere in guest serial, and any `resp-hex=` field must match the strict `[0-9a-f]+` grammar; (c) strip-then-reject stays: the mock lane actively rejects `real|ANTHROPIC-LIVE` near its marker (§7.3), so even a hypothetical forged live claim cannot enter the cumulative chain.

## 7. DoD — witness lines, honesty tokens, guard blocks (verbatim)

**Mock lane (guest serial; both arches; CI-required — the only cumulative-chain variant):**

```
infer: backend=MOCK-DETERMINISTIC context=M13-SCALAR-RECALL recalls=0x<hex> prompt-len=0x<hex> resp-len=0x<hex> resp-digest=0x<32hex> req-id=0x<16hex> stop=END-TURN wire-err-handled=0x1 fold=M25-TRANSCRIPT key=CAPREF-HOST-CUSTODIED host=RESIDUAL-TCB ambient=ZERO-IN-GUEST sec=ASSUMED-FROM-LITERATURE
M31: infer-e2e OK backend=MOCK-DETERMINISTIC
```

**Live lane (guest serial; secret-gated optional):**

```
infer: backend=ANTHROPIC-LIVE nonce=0x<32hex> transform=HEX-REVERSE transform-ok=0x1 req-id=0x<16hex> reqid-hex=<hex> resp-len=0x<hex> resp-digest=0x<32hex> chunks=0x<hex> pending=0x<hex> stop=<token> mac-verified=0x1 fold=M25-TRANSCRIPT key=CAPREF-HOST-CUSTODIED host=RESIDUAL-TCB ambient=ZERO-IN-GUEST sec=ASSUMED-FROM-LITERATURE
M31: real-infer OK backend=ANTHROPIC-LIVE
```

**Bridge witness (host stdout, NOT guest serial):**

```
infer-bridge: backend=ANTHROPIC-LIVE nonce=0x<32hex> transform=HEX-REVERSE transform-ok=1 http=200 reqid-hex=<hex> resp-digest=0x<32hex> key-custody=HOST-ENV
```

**Token semantics (machine-emitted, strip-then-reject covered):** `key=CAPREF-HOST-CUSTODIED` — the inference secret is a host-env capability the guest references but NEVER holds (on the mock lane no secret exists anywhere; the token is the standing custody rule, asserted on every lane). `host=RESIDUAL-TCB` — the host peer process (and on the live lane its TLS stack + trust roots + egress) is trusted ground, named not hidden. `ambient=ZERO-IN-GUEST` — **the zero-ambient-authority claim is scoped in-GUEST only** (the bridge holds ambient authority by construction: env key + network egress; claiming otherwise would be the exact overclaim the tokens exist to prevent). `context=M13-SCALAR-RECALL` — the prompt is real-substrate-derived but scalar-derived. `sec=ASSUMED-FROM-LITERATURE` inherited from M29.

**Guard blocks** (house order, the M30 §5 template; new filter `(^|[^[:alnum:]])(M31:|infer:|infer-dump:)`; M31 lines never match the M30 filter — distinct prefixes — and M31 token spellings survive M30's strip list, checked by name):

1. **Skip-reject (§5.1).** The mock lane NEVER skips: attached lanes FAIL on any `M31: infer-e2e OK (…skipped)` variant. The live lane's missing-secret skip is LOUD AND NAMED: the workflow emits `::warning::M31 real-infer SKIPPED reason=ANTHROPIC_API_KEY-absent` + the script line `M31-live: SKIP reason=ANTHROPIC_API_KEY-absent` (script-emitted, pre-boot, never in guest serial), and the live workflow asserts EXACTLY ONE of {the OK pair, the named SKIP} — silence is FAIL (present-then-silent is the M30 hard-FAIL discipline).
2. **Positive-require (§5.2).** The full `infer:` witness regex above (every flag `=0x0*1`, every token literal) + the marker, plus the cumulative-tail displacement: **M31 displaces M30 as the top MARKER grep; M30 then asserted directly** (the M29→M30 precedent, `run-x86_64.sh:446-451`).
3. **By-name rejects (§5.3).** Mock/CI lanes: case-insensitive near M31 lines, reject `backend=ANTHROPIC-LIVE`, `real`, `live`, `network|TLS|HTTPS|cloud|api[- ]key` — **the lane rejects `real` nearby, per the plan, so a forged live claim cannot enter the cumulative chain.** Live lane: reject `backend=MOCK-DETERMINISTIC`, `loopback`, `fixture|canned|replay` near its marker.
4. **Lane cross-pin (§5.4).** No lane borrows the other's backend token, ever.
5. **Inherited tripwires (§5.5).** `mode=POLL` pin stays on all `xport:` lines (#71); `INFER_PENDING` frames are budget-resets, never completions — a run that ends on pendings is `FAIL xport-timeout`.
6. **Cross-process round-trip, live lane (§5.6 — the fixture killer).** `nonce`/`reqid-hex`/`resp-digest` extracted from the guest `infer:` line and the bridge `infer-bridge:` line (separate capture streams) must string-equal; both must carry `transform-ok`.
7. **Leak negatives (§5.7).** The API key (via the canary-derivative file, the `XKEY` mechanism `run-x86_64.sh:512-522`) appears NOWHERE in guest serial or echoed cmdline; PLUS the raw-leak tripwire: FAIL on byte `0x1b` in guest serial, and every `resp-hex=` field must match `^[0-9a-f]+$`.
8. **Strip-then-reject (§5.8).** Strip the new tokens FIRST (`MOCK-DETERMINISTIC`, `ANTHROPIC-LIVE`, `CAPREF-HOST-CUSTODIED`, `RESIDUAL-TCB`, `ZERO-IN-GUEST`, `M13-SCALAR-RECALL`, `HEX-REVERSE`, `M25-TRANSCRIPT`), then case-insensitive reject near M31 lines: `understood|reasoned|intelligen|knows|learned|validated|evaluated|secure|confidential|private|authenticated-human|agi`. The M29/M30 global rejects stay in force; M30's §5.8 `real-infer` reject applies only to `M30:|xport:` lines, so the live marker never trips it — by construction, stated here so a future guard edit doesn't "fix" it.

## 8. Kani obligations (each with a genuine negative control; #49 throughout)

**#49 budget discipline for every NEW khash use:** khash bodies run on CONCRETE inputs only (the M29 rule); symbolic flips cover indexes/predicates/sub-header bytes, never key material in the same harness (the M30 §6.4 measured lesson); NEVER a symbolic PRF/collision harness (overclaim-by-implication, banned). Mitigation ladder if any harness exceeds the local budget: pin flip positions → `kani::solver(kissat)` → shrink length sets → split the assembler harness out (the FrameAccum precedent — its >>120s CBMC floor for byte-wise accumulation is KNOWN; the assembler harness is designed chunk-at-a-time, not byte-at-a-time, to stay under it).

1. **`kani_inferwire_kind_ext`** — canon/decode round-trip for kinds 4/5/6 at boundary payload lengths; *neg:* kind 7 (and the old negative set) still rejects everywhere — the extension didn't widen totality.
2. **`kani_infer_subhdr_total`** — sub-header round-trip; reserved `sflags` bits1..7 / `rsv` nonzero reject; truncated sub-header rejects; *neg:* the exactly-valid sub-header decodes (non-vacuous rejector).
3. **`kani_infer_assembler`** — at a tiny const-generic cap: in-order chunks assemble to exactly `total_len`, indexes never overflow at capacity; out-of-order/duplicate/gap `seq`, `total_len`/`body_digest` drift, and overflow all reject; *neg:* pure-garbage chunk stream never emits a body.
4. **`kani_infer_resp_binding`** — `verify_infer_resp` iff-theorem over `req_id` + `seq` + `kind`; symbolic flip over tag and sub-header bytes rejects (concrete khash inputs); *neg:* flip-then-flip-back restores acceptance.
5. **`kani_infer_domain_sep`** — `echo_tag` vs `infer_tag` on identical `(K, peer, nonce, challenge, body)` yield distinct tags (the label is load-bearing); *neg:* an implementation dropping the label fails the inequality.
6. **`kani_infer_err_closed`** — ERR payload codes outside the closed enum reject; `retryable` binding round-trips; *neg:* a valid code decodes.

**Existing-harness churn (named):** the 4 landed inferwire harnesses (`canon_roundtrip`/`decode_total`/`req_binding`/`accum_resync`) and the negative-set tests are touched by the kind extension — re-measured, not just re-run. **Mutation pass before landing** (the M30 §6 discipline): drop `seq` from the MAC input; off-by-one the assembler cap; flip a sub-header bounds check; swap the two domain labels — each mutant must be killed by a named harness; a surviving mutant means a vacuous harness, fix the harness.

## 9. EXPECTED_HARNESSES bump plan

`EXPECTED_HARNESSES = 90` today (`scripts/verify-encode.sh:288`). M31 adds +6 (§8) → **target 96, EXACT COUNT MEASURED LOCALLY pre-landing** (the M29/M30 discipline — the count is the gate, not the estimate). `verify-encode.sh` count + doc block (concrete-frame/short-symbolic per #49, chunk-at-a-time assembler, mutation obligation noted) + the `kani.yml` comment in lockstep, fail-closed.

## 10. CI lane plan — dual lanes, asymmetry stated

| Lane | Trigger | Backend | Marker | Status |
|---|---|---|---|---|
| `ci.yml` x86_64 + aarch64 (TCG, chardev harness) | every PR/push | MOCK-DETERMINISTIC (in-kernel) + the keyless `ERR NO-KEY` wire check | `M31: infer-e2e OK backend=MOCK-DETERMINISTIC` | **REQUIRED — the only cumulative-chain variant** |
| `real-infer.yml` (NEW) | `workflow_dispatch` (operator-initiated; optionally same-repo push — **NEVER `pull_request_target`**, the pwn-request footgun) | ANTHROPIC-LIVE via the bridge | `M31: real-infer OK backend=ANTHROPIC-LIVE` or the named LOUD skip | **OPTIONAL — never a required check, never unattended** |
| `vmm-boot.yml` | unchanged | — | unchanged at its M30 stage-C disposition | — |

Secret gating: job-level `if: ${{ secrets.ANTHROPIC_API_KEY != '' }}` (or the probe-step pattern); fork PRs never see the secret by platform design. Cost containment: ONE pinned call per dispatch, cheapest adequate model, `max_tokens` ≤ 64; 429/529 → `FAIL-RETRYABLE` (distinct, never pass, never liveness-fail).

## 11. The `LANGUAGE-AND-STANDARDS.md` decision — written BEFORE M31 lands (binding amendment)

The TLS-outside-kernel decision is verified absent from the doc today (only the §0 "Local inference engines … network boundary" row and §7's vLLM notes are adjacent). Two edits, both carrying the house **[DECISION]** tag, landed in stage A's docs lockstep:

**(1) New §0 Decision-Summary table row** (+ a one-clause touch to the "In one sentence" line):

> | **Remote inference bridge (HTTPS/TLS)** | **Rust HOST process only** (`rustls` + `ureq` class; `reqwest` acceptable) | TLS/HTTPS/network code NEVER enters the kernel, the guest image, or the `no_std` workspace — the bridge is a host peer on the M30 channel; the guest sees only MAC'd inferwire frames |

**(2) New §6 Standards-Stack axis row — the dependency-policy ledger entry** (sovereignty-plan principle 1 vocabulary):

> | **Remote-API host deps** | `rustls`, `ureq` (runner-up `reqwest`), `serde_json` — host-bridge-only, nested-workspace-firewalled from the kernel's zero-dep/zero-unsafe lanes | Sovereignty-ledger status: **ACCEPTED-PERMANENT (host-bridge-confined)** — the communication pillar's cost, not closable debt; the kernel never inherits it; any widening (new dep, new process) is a new ledger row |

`docs/assumptions.md` gains the §5.8 host-bridge residual entry (the §3a M30-entry house shape): the bridge process, its TLS stack and trust roots, and runner egress are trusted ground for the live marker; the liveness proof is bridge-honesty-conditional; zero-ambient-authority is claimed in-GUEST only.

## 12. Failure modes (each with its designed observable)

- **Missing secret:** LOUD named skip (§7.1) — never silent, never green-by-omission. **Secret present, bridge silent:** hard FAIL (M30's present-then-silent rule).
- **429/529/500:** `ERR` retryable codes → lane outcome `FAIL-RETRYABLE` — never a pass, never reported as liveness failure.
- **`stop_reason=refusal`:** possibly EMPTY content — the bridge branches on `stop_reason` BEFORE reading `content[0]`; guest sees `ERR code=REFUSAL`; live-lane outcome `REFUSAL` (distinct).
- **Transform absent with 200 + request-id:** `TRANSFORM-MISS` — distinct from `LIVENESS-FAIL`, never silently retried into a pass.
- **Oversize prompt/response:** reject, never truncate — `ERR TOO-LARGE` guest-side mirror of the API's 413; the bridge clamps `max_tokens` against `INFER_BODY_CAP` up front.
- **Chunk desync/splice/reorder:** per-chunk MAC (seq inside the MAC) + assembler fail-closed; witnessed by the §8.3/8.4 harness classes and the in-boot negative flags.
- **Slow API vs dead peer:** verified `INFER_PENDING` resets the poll budget; a dead peer still hard-FAILs `xport-timeout` (§2f).
- **Key leak:** the §7.7 canary negative; the bridge never prints key/prefix/length (masking fails on transforms).
- **Raw model bytes reach serial:** the §7.7 ESC/hex-grammar tripwire — the encode-before-write invariant is guard-checked, not trusted.

## 13. Landing plan — staged, CI-green; the live lane is operator-gated

- **(A)** Leaf extension (§2: kinds, sub-header, `infer_tag`/`verify_infer_resp`, `InferAssembler`, ERR/PENDING) + host tests + the +6 harnesses + the mutation pass + `EXPECTED_HARNESSES` 90→96 (measured) + **the §11 `LANGUAGE-AND-STANDARDS.md` [DECISION] edits + the ledger row + the `assumptions.md` residual, in the same landing** (the binding "written before M31 lands" amendment). **Hard sequencing: (A) does not start in `tb-encode` until M29 stage C (`prov_hash` FNV→khash) lands** — a code agent is in those files now; the body-digest and M25 fold target the post-cutover construction.
- **(B)** `infer_bytes` path (§3a-3c) + MOCK-DETERMINISTIC + the M13-context assembly + the M25 fold (§3d) + the harness serve loop + the keyless `ERR NO-KEY` wire check + the kernel M31 block + run-script guard blocks + `ci.yml`. **After (B) the CI-required both-arches DoD is met — zero network, zero secrets.**
- **(C)** The live bridge (`ureq`/`rustls`/`serde_json`) + `real-infer.yml` + the §5 liveness protocol + the live guard block + ONE pinned call. **(C) requires the operator to provision `ANTHROPIC_API_KEY` as a repo secret and to trigger `workflow_dispatch` — the LIVE lane is NEVER part of unattended runs** (network + secrets; the plan's explicit unfitness note). If (C) flakes, (A)+(B) alone already discharge the CI-required DoD; (C) re-runs are operator-initiated only.

**Doc/honesty fan-out checklist:** `kernel/src/main.rs` (M31 block + token literals); `scripts/run-{x86_64,aarch64}.sh` (M31 guard blocks + the M30 displacement); `scripts/verify-encode.sh` + `.github/workflows/{ci,kani}.yml` (+ NEW `real-infer.yml`); `crates/tb-encode/src/inferwire.rs` module docs; `crates/tb-hal/src/{infer.rs,caps.rs,lib.rs,mem/selftests.rs}`; `tools/xport-harness/` (serve loop + deps + its own README note); `docs/LANGUAGE-AND-STANDARDS.md` (§11 — verified absent today, the binding edit); `docs/assumptions.md` (host-bridge residual); `docs/BACKLOG.md` row 24 (Anthropic slice absorbed; OpenAI parked, unclaimed); `docs/MILESTONES.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP-V2.md`, `docs/plans/INDEX.md`; `.claude/skills/tabos-milestone/SKILL.md`.

## 14. Honest caveats (conceded — encoded as witness tokens where applicable)

- **`M31: infer-e2e OK` proves PLUMBING, not intelligence.** The mock lane's end-to-end chain (recall → prompt → `infer_bytes` → digest fold) runs a deterministic transform — `backend=MOCK-DETERMINISTIC` says so; no model claim, no semantics claim, and the §7.8 reject list bans the vocabulary.
- **The live liveness proof is bridge-honesty-conditional.** It defeats stale fixtures, replays, reflectors, and the mock-wearing-the-live-token — under an HONEST bridge. The bridge is trusted ground (`host=RESIDUAL-TCB`), exactly as M30's host peer was; a deliberately forging bridge is out of scope until M33 signatures upgrade host participation to host exclusivity. The request-id is provider-asserted, third-party-correlatable evidence, not a verified signature.
- **No confidentiality on the guest channel.** inferwire is MAC'd, NOT encrypted — the prompt and response transit the virtio channel in cleartext; TLS protects only the host↔API leg. (M13-scalar context makes the mock-lane exposure trivial today; this becomes a real decision before sensitive context ever rides the channel — a named successor, not an M31 claim.)
- **`ambient=ZERO-IN-GUEST` is a scoped claim.** The host bridge holds ambient authority by construction (env secret + egress). Claiming system-wide zero ambient authority would be false; the token's scope is the honesty mechanism.
- **`context=M13-SCALAR-RECALL`** — M13 stores u64 scalars, not byte blobs; the prompt is scalar-derived. Byte-payload memory records are a named deferral.
- **`INFER_BODY_CAP=8192` is a compile-time product constraint** — reject-don't-truncate, both ends compile the same const; a HELLO/CAPS negotiation frame is the named successor if the cap ever needs to move per-deployment.
- **The transform check is probabilistic** — `TRANSFORM-MISS` is a distinct, reported outcome; one pinned call means one sample, by design (cost containment beats statistical confidence here, and the lane is optional).
- **Streaming semantics never reach the guest** — chunked delivery is reassembly of a completed response; no token pretends to streaming, and `INFER_PENDING` is liveness plumbing, not flow control.
- **Hex-encoding costs 2× serial volume** — the dump is line-capped and the digest is the commitment; the transcript folds fixed-width evidence, never the dump.
- **NOT fit for unattended runs** (network + secrets) — stated in the plan, restated in §13, enforced by the trigger policy (operator `workflow_dispatch`).
- **`sec=ASSUMED-FROM-LITERATURE`** inherited: khash PRF strength assumed, never proven; no symbolic PRF/collision harness exists, deliberately.

## 15. Roadmap context

M31 closes the sovereignty A-chain's first real round-trip (#89): byte prompts assembled from real substrate state, a verified chunked codec on the M30 channel, the first live LLM bytes through the system — with the honesty regime extended to survive its own model's output. Named successors: **M32** (the local llama.cpp daemon serving `model:local/llama` over the SAME `INFER_REQ`/`INFER_RESP` framing, #90 — the byte path is built once here), **M33** (signatures: bridge participation → exclusivity; signed prov heads carry the inference digests), **M37/FAZ-D** (real inference traffic begins accumulating the trace data Phase D's distilled-model leg has been blocked on), and the byte-payload M13 records + static channel-backend registration deferrals named in §3. The OpenAI adapter slice of BACKLOG row 24 stays parked and unclaimed.

---

### References
Full survey in [`docs/research/m31-real-infer-literature.md`](../research/m31-real-infer-literature.md). Key: Anthropic Messages API docs (request/response/stop_reason/streaming/errors/rate-limits) · RFC 6587 (octet-counting) · RFC 7959 (CoAP block-wise — the lockstep chunking precedent) · RFC 8449 / MQTT 5.0 (max-size declaration precedent) · CWE-117 + SMTP smuggling + Terminal DiLLMa + Trail-of-Bits MCP-ANSI + Microsoft Spotlighting (the encode-before-write case) · RFC 8555 / RFC 9683 (nonce freshness) · GitHub Security Lab (pwn requests). In-repo: `crates/tb-encode/src/inferwire.rs` (the landed leaf: closed kinds :249, reserved ERR :146, cap :103, reserved-zero flags :278/:324, `verify_echo` :474), `crates/tb-hal/src/infer.rs` (:22-27, :40-45, :79-91), `crates/tb-encode/src/opframe.rs` (:64-71, :99-111, :146-149), `tools/xport-harness/src/main.rs` (:133-224), `scripts/run-x86_64.sh:446-537` (the M30 guard template; non-anchored filter :476; XKEY :512), `scripts/verify-encode.sh:288` (`EXPECTED_HARNESSES=90`), `docs/LANGUAGE-AND-STANDARDS.md` (§0/§6 slots), [`docs/proposals/M30-infer-transport.md`](M30-infer-transport.md), the sovereignty plan §M31 + tracker task #89 (binding).
