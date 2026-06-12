# Run the hello — the first real model call (M31 stage C, operator-triggered)

> TL;DR: **two commands and the OS's inference channel speaks to a real model
> once.** The live lane is yours alone to fire: it never runs on push/PR, it is
> never a required check, and a missing secret is a loud green skip — by
> design (M31 proposal §10/§13).

## The two steps

From the repo root, with the [`gh` CLI](https://cli.github.com/) authenticated:

```sh
# 1. Provision the secret (prompts for the key; stored as a repo Actions secret)
gh secret set ANTHROPIC_API_KEY

# 2. Fire the hello (one boot, one pinned call)
gh workflow run real-infer.yml
```

Watch it: `gh run watch` (or the Actions tab → **real-infer**). To confirm the
spend pin before firing, see [What it costs](#what-it-costs--the-spend-pin).

## What happens

One x86_64 QEMU boot of the **unchanged** cumulative chain
(`scripts/run-x86_64.sh`, byte-identical to the required CI lanes), with the
`xport-harness` host bridge in live mode (`XPORT_ANTHROPIC=1` + the secret in
its env — env ONLY, never a flag, never logged). When the kernel's real-prompt
`INFER_REQ` completes on the M30 channel, the bridge:

1. answers the guest the deterministic wire exchange first (the kernel chain
   stays green — see the honest scope below),
2. then makes **exactly one** Messages API call: the prompt envelope asks for
   two lines — line 1 the character-REVERSED hex of the kernel's per-boot
   wire challenge (`transform=HEX-REVERSE` — the §5 liveness proof: fresh
   every boot, so a canned fixture or replay fails; the reversal substring is
   the ONLY acceptance criterion), line 2 one short sentence greeting Yuva —
   the hello this lane exists for,
3. verifies the transform, digests the response text, prints its witness, and
   frames the (scrubbed, capped at 2048 bytes) response text as lowercase hex
   on one `xport-harness-infer-body:` line.

## What the expected output looks like

In the run log, on success:

```
xport-harness-infer: backend=ANTHROPIC-LIVE nonce=0x<32 hex> transform=HEX-REVERSE transform-ok=1 http=200 reqid-hex=<hex> resp-digest=0x<32 hex> model=claude-haiku-4-5 max-tokens=64 stop=END-TURN key-custody=HOST-ENV
xport-harness-infer-body: len=<dec> truncated=<0|1> hex=<lowercase hex of the response text>
M31: real-infer OK backend=ANTHROPIC-LIVE
```

plus the untouched kernel tail on the same boot:

```
M31: infer-e2e OK backend=MOCK-DETERMINISTIC
```

**Where to read the hello itself:** the run's **Summary page** (Actions → the
run → Summary). The workflow decodes the body line's hex there — and ONLY
there — under the heading *"The machine's first hello (UNTRUSTED MODEL
OUTPUT, decoded from the hex-framed lane log)"*. Every log (guest serial,
harness stream, job log) stays hex-only; the decode never appears in any log.

Without the secret, the run is a **loud green skip**, never red:

```
::warning::M31 real-infer SKIPPED reason=ANTHROPIC_API_KEY-absent ...
M31-live: SKIP reason=ANTHROPIC_API_KEY-absent
```

On failure the verdict line carries a distinct closed outcome (proposal §12,
never conflated): `TRANSFORM-MISS` (the model answered but missed the
reversal — reported, never silently retried into a pass) ≠ `REFUSAL` ≠
`LIVENESS-FAIL` (no fresh round-trip evidence) ≠ the retryables
`RATE-LIMITED`/`OVERLOADED`/`API-ERROR`/`TIMEOUT` (re-dispatch when the
provider recovers) ≠ `AUTH` (the provisioned key is invalid).

## What it costs — the spend pin

**One call per dispatch**, model **`claude-haiku-4-5`** (haiku-class — the
cheapest adequate model for a 32-character reversal), **`max_tokens=64`**.
Both are compile-time consts in `tools/xport-harness/src/live.rs`
(`LIVE_MODEL`, `LIVE_MAX_TOKENS`) — no env var or flag can raise the spend;
changing it is a reviewed code change. The harness latches at most one call
per process; the workflow runs one job, no retries; stacked dispatches are
serialized.

## The honest scope (read before quoting the marker)

- **One call, haiku-class, ≤64 output tokens.** The prompt is the kernel's
  scalar-derived M13-recall bytes (hex-encoded) plus the liveness
  instruction — plumbing and liveness, not intelligence; no semantics claim.
- **The model's text appears hex-framed only.** Never in the guest, never
  raw in any log: the witness carries its `resp-digest` (the same
  `body_digest` discipline as the wire — computed over the raw text, the
  commitment to what the model actually said) and the hex-encoded provider
  request-id; the body line frames the scrubbed text in the §6 inert
  alphabet, capped at 2048 bytes with an explicit `truncated` flag. The
  human-readable decode exists only on the run's Summary page, explicitly
  labeled untrusted model output.
- **The guest exchange stays deterministic.** The stage-B kernel pins the
  wire exchange to the bit-exact mock shape (`tb-hal` selftests 0x21/0x25/
  0x26), so the live response does NOT ride the channel and the response
  digest folded into the M25 transcript on the wire is the deterministic
  exchange's digest. Putting the LIVE digest through the kernel's transcript
  fold — and the in-guest §5.5 transform search with a guest-serial live
  marker — is the named kernel-side follow-up.
- **The proof is bridge-honesty-conditional** (proposal §5.8): a process
  holding the key obtained a fresh nonce-dependent transform from an endpoint
  behaving as the live Anthropic API over TLS. The bridge is trusted ground
  (`host=RESIDUAL-TCB`); host exclusivity awaits the M33 signature primitive.
- **Never unattended.** Network + a secret: the lane exists only behind your
  explicit `workflow_dispatch`, and the mock CI lanes reject its vocabulary
  by name — a forged live claim cannot enter the cumulative chain.

## Key hygiene

The key lives only in the repo secret and the bridge process env
(`key-custody=HOST-ENV`). The bridge never prints it (every live-path line is
scrubbed, unit-tested); the workflow's key-leak negative greps the whole lane
log for it and fails the run if it ever appears. Revoke/rotate with
`gh secret set ANTHROPIC_API_KEY` again, or remove it with
`gh secret delete ANTHROPIC_API_KEY` (the lane then returns to the loud skip).
