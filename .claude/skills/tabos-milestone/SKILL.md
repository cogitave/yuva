---
name: tabos-milestone
description: The end-to-end pipeline for shipping ONE TABOS kernel milestone (the cumulative M0..M28 + L2.0..L2.6 chain, or any new milestone from a research-first proposal). Use whenever implementing/continuing a TABOS milestone so NO step — research proposal, code, the tb-encode verified-leaf, adversarial review, both-arch build+boot (CARGO_INCREMENTAL=0), anti-hollow-pass guards, benchmark, every doc/script update, AND the PR-loop landing — is ever skipped. Invoke at the start of each milestone increment.
---

# TABOS milestone pipeline

TABOS is a from-scratch `no_std`, memory-centric, agent-native, LLM-agnostic Rust
OS. Every milestone is shipped the SAME way and is only "done" when it is **CI-green
on both arches across the ~9 lanes**, with all docs aligned. This skill is the
checklist; follow it in order and do not skip the proposal, the anti-hollow-pass
guards, the documentation, or the PR loop.

Repo: `/c/Users/Arda/workspaces/@cogitave/tabos` (build/run/git via Git-Bash;
edits via Windows paths). Build: `cargo kbuild --target targets/<arch>-tabos-none.json`
(the `.cargo/config.toml` alias = `build -p tabos-kernel -Zbuild-std=… -Zjson-target-spec`;
never hand-write the `-Z` flags). Kani IS installed locally in WSL (`cargo-kani`,
run via `wsl.exe -d Ubuntu-22.04`) — ALWAYS measure a new/changed harness with
`cargo kani -p tb-encode --harness <name>` BEFORE pushing (Step 4); the `prove-encode`
CI lane has a hard `timeout-minutes` and ONE slow harness silently times the whole
lane out (this cost three blind ~30-min CI round-trips once — never again).

## Operating mode (standing directives — do not ask)
- **Always ultracode.** Every substantive step (research, design, generate, review,
  synthesize) runs as a multi-agent `Workflow`, never solo. The user has made this
  standing for the whole project — do **not** ask whether to use a workflow; use one.
  Solo is only for trivial mechanical edits and conversation.
- **Research-first.** A new milestone is born from an honest, literature-grounded
  proposal — not from a naive plan. The verdict can RESHAPE or DEFER the work
  (M21 was reshaped: drop the KAN framing, ship dormant, gate on a trace bake-off).
- **Design Thinking × Success by Design.** Each milestone passes the same
  principled loop, mapped onto the concrete pipeline so it stays trackable:
  - *Empathize / Define* — who is this milestone for, and what EXACTLY must it do?
    Produce the research proposal; state the one capability + the exact DoD marker
    before any code (Steps 1–2). Every subsystem answers "what does this give an agent?"
  - *Ideate* — diverse options before committing: the multi-agent generate +
    3-lens adversarial review panel (Step 3). Surface and resolve the contested
    decisions explicitly (no open decisions left dangling).
  - *Prototype* — the strong implementation agent writes files to disk + builds +
    boots; the human applies/verifies on a branch (Steps 4–6).
  - *Test* — the build + both-arch boot-assert (CARGO_INCREMENTAL=0) + anti-hollow
    guards + benchmark + your own audit are the empirical test. "The build is the
    arbiter" (Steps 5–8).
  - *Success-by-Design gates* — "done" only when it clears the well-architected
    pillars, each already a pipeline step: **reliability** (cumulative regression
    stays green), **security** (framekernel / forbid-unsafe intact + Kani/Miri/clippy
    leaf gates green), **performance** (boot benchmark current — `docs/BENCHMARKS.md`),
    **operational excellence** (~9 CI lanes green on both arches; docs/roadmap/trackers
    aligned). A skipped gate = not done.
  - *Learn forward* — carry each milestone's hard-won lessons into the next iteration
    and into this skill.

## Non-negotiable invariants
- **Framekernel**: ALL real `unsafe` + ALL silicon-unsafe asm/MMIO live ONLY in
  `crates/tb-hal`. `kernel/` and the forbid-unsafe leaf crates (`tb-encode`,
  `tb-caps-core`, `tb-boot`) carry `#![forbid(unsafe_code)]`; the kernel's only
  concession is `#[unsafe(no_mangle)]` ATTRIBUTES on entry points (zero `unsafe {}`).
- **Verified-leaf default**: value-computation ships as a pure leaf in `tb-encode`
  (`#![no_std]` `#![forbid(unsafe_code)]`, zero-dep, host-buildable, NO float on any
  kernel path) + Kani harnesses + the Miri gate. tb-hal CALLS the leaf byte-identically.
- **No float** on any kernel path (fixed-point only).
- **Cumulative DoD**: each milestone prints an EXACT serial marker; the kernel runs
  M0..latest every boot. The current tail is **`M30: infer-transport OK`** — the marker
  both run scripts grep for, printed after M29 (its `xport:` witness is ALSO
  cross-process-compared against the `xport-harness` host peer's own line). (Chain: M0…M18, M18.1/.2, then on
  aarch64 L2.0…L2.6 and M27 sovereign-scheduler [two-VMID, M27a cooperative —
  mid-chain, before M19], then M19 virtio-rng, M20 persist, M21 kan-policy [DORMANT],
  M22 provenance, then the learning-loop arc M23 experience, M24 bakeoff [honest gate,
  gate-not-met], M25 operator-transcript, M26 exit-telemetry [PRODUCER-only], then
  M28 operator-cmd [the INBOUND dual of M25 — closes the loop; an Accept is
  necessary-NOT-sufficient: kan_active=0, M24's statistical bar still gates], then
  M29 khash-mac [the M28 MAC re-pointed at the verified BLAKE2s-256 khash leaf —
  mac=KEYED-CRYPTO, sec=ASSUMED-FROM-LITERATURE, kat=RFC7693-PASS earned per boot],
  then M30 infer-transport [stages A+B: the inferwire codec leaf + the two-queue
  virtio-console seam + the host-keyed echo, two-leg anti-hollow (kernel verify
  x cross-process challenge/tag equality vs the xport-harness host peer);
  backend=ECHO-ONLY, key=HOST-CUSTODIED-PER-RUN, mode=POLL #71-pinned; stage C
  (the tb-vmm TB-VMM-HOST backend) split to its own follow-up].)
- **Two arches** (x86_64 + aarch64) and **multiple boot paths** (PVH/microvm, tb-boot/
  tb-vmm, KVM/TCG) must stay green.
- **The build + boot are the arbiter.** A reviewer that says "sound" is not enough;
  the real `cargo kbuild` + QEMU boot has repeatedly caught what review missed
  (M5's `alloc` missing from `-Zbuild-std`; the aL2.5 boot-stack saga). An agent's
  self-reported "green" means nothing until the REAL CI lane confirms it.

## Steps (per milestone)

1. **Research-first proposal (Workflow).** Run a design/research ultracode workflow
   that produces an honest proposal in `docs/proposals/Mn-*.md` (+ a literature survey
   in `docs/research/`) BEFORE any code. The verdict may RESHAPE or DEFER the naive
   plan. Mark the tracking task `in_progress`.

2. **Lock scope from the proposal.** State the id, the EXACT DoD marker string, the
   mechanism, the framekernel unsafe placement (which goes in `tb-hal`, which is a
   pure `tb-encode` leaf), arch notes, deps, risks, and the anti-hollow WITNESS line
   the run scripts will require.

3. **Generate via ultracode (Workflow).** Author the milestone with a
   `generate -> 3-lens adversarial review -> finalize` workflow. CRITICAL:
   - **Do NOT use `isolation: 'worktree'`.** Worktree isolation DOES NOT WORK in this
     @cogitave checkout. The real pattern is a single strong implementation agent that
     writes files to disk, builds (CARGO_INCREMENTAL=0, dual-arch), boots, and returns
     a **COMPACT MANIFEST** (file list + integration anchors + marker/witness lines) —
     **NEVER inline file bodies** (the 64K output-cap lesson).
   - Tell agents to compile-check with Git-Bash `cargo kbuild` (NOT raw `rustc` on
     Windows paths — that hangs).
   - Review lenses: (a) correctness/soundness of the new mechanism, (b) framekernel +
     cumulative regression + both-arch/both-boot-path, (c) Rust/nightly build +
     trait/ABI correctness + the verified-leaf totality/overflow story.
   - Ground every agent with the framekernel rule, the verified-leaf pattern, the exact
     files (`kernel/src/main.rs`, `crates/tb-hal/`, `crates/tb-encode/`), and the
     current state (read the files).

4. **Add the tb-encode verified leaf (when it ships value-computation).** Add a pure
   leaf in `crates/tb-encode/src/<leaf>.rs` (existing leaves — 20: vmx, paging,
   ipc_frame, route, memscore, stage2, smmuv3, el2_trap, blkfmt, kancell, prov, exp,
   explore, bakeoff, opframe, exittel, tpsched, opframe_rx, khash, inferwire). Add `#[kani::proof]`
   harnesses in `proofs.rs`, each:
   - **TRACTABLE — and MEASURED locally before pushing.** Run `cargo kani -p tb-encode
     --harness <name>` (WSL) on EVERY new/changed harness; the full gate is
     `bash scripts/verify-encode.sh` (it must report "N successfully verified, 0 failures"
     in a few minutes). The `#49` symbolic-array state-explosion is the documented trap,
     and **the slow harness is rarely the obvious one — MEASURE, do not guess.** Worst
     offenders: a symbolic hash/FNV over more than ~2-3 bytes, OR a digest computed MORE
     THAN ONCE (e.g. for a determinism check). Fixes: shrink the symbolic input to ~2
     bytes (totality is structural over the loop), compute the digest ONCE, assert
     determinism over a CONCRETE input, and concretely-unroll any "for every byte" loop
     instead of using a symbolic index. (Real example: M22 `hash_total` ran prov_hash
     over 6 symbolic bytes TWICE → >220s, timing the 35-min lane out; N=6→2 + single
     digest → 3s, and the whole gate then verifies in ~6 min locally.) SECOND
     structural offender (M30 lesson): a SEQUENTIAL BYTE-PUSH TRACE through a
     stateful accumulator — ~68 push-call inlines × the per-harness unwind bound
     on the inner scan/shift loops is a formula floor (>>120s) that survives
     concrete data, kissat, chunked loops, and hot-path slimming; prove the
     index/capacity/rejection-class discipline at a tiny const-generic cap and
     DELEGATE the full trace to host tests + Miri + the live boot lanes, NAMED
     in the gate docs (the M30 accum_resync precedent).
   - carrying a **NEGATIVE CONTROL** (an identity/constant/commutative variant the
     harness must REJECT).
   - **MUTATION-TESTED when it gates.** Every gate-level harness (one whose green
     light admits a security/acceptance verdict) must be proven non-vacuous by
     MUTATION: delete/neutralize the gated reject branch and the harness MUST go RED
     (`VERIFICATION FAILED`). Tautology is the sneaky form of vacuity — a harness
     that re-derives its expectation from the same predicate the code uses passes
     forever, even over a broken gate. (M28: deleting each reject branch in turn →
     VERIFICATION FAILED ×3.)
   - **Extract the decision core when Kani cannot drive the wrapper.** If the
     wrapper's buffers/arrays blow the proof up (the `#49` trap again), do NOT
     imitate the wrapper with a weakened predicate harness — extract the verdict as
     a PURE buffer-free/hash-free function the wrapper delegates to VERBATIM, and
     prove THAT fully symbolically; the wrapper's buffer/MAC plumbing is then
     host-tested (run under the Miri CI lane) + boot self-tested. (M28:
     `opframe_rx::verify_decoded(frame, expected_nonce, live_head, mac_ok)` is the
     proven core — each reject arm iff its condition, plus the Accept-iff-all-conjuncts
     theorem over a fully-symbolic live head — and `decode_and_verify` delegates its
     verdict to it verbatim; all 7 verdict arms of the wrapper are host-tested.)
   - Bump `scripts/verify-encode.sh` `EXPECTED_HARNESSES` (currently **90**) AND the
     `kani.yml` "currently 90" comment **in LOCKSTEP** — a vacuous/deleted harness must
     fail the gate. The kani lane has 2 jobs: `prove-caps` (tb-caps-core, M11 rights-subset,
     12 harnesses, marker `M11: caps-subset PROVEN`) and `prove-encode` (tb-encode, 90
     harnesses, marker `V1: kani-encoders OK`, 45-min hard timeout). Never `--workspace`
     (drags tb-hal asm into CBMC).

5. **Build — the real arbiter (CARGO_INCREMENTAL=0).** `export CARGO_INCREMENTAL=0`
   then `cargo kbuild` BOTH arches. This is THE CI discriminator: dtolnay/rust-toolchain
   injects it in CI; it changes `.bss` symbol ordering vs local incremental builds and
   has exposed layout-sensitive bugs (the aL2.5 boot-stack saga). The run scripts do NOT
   export it — it must be set on the `cargo kbuild` invocation (per-invocation discipline).
   Fix every error (build-std crate list, features, missing docs in tb-hal which `deny`s
   them). Zero warnings from our code.

6. **Boot + assert + regress (anti-hollow-pass).** Run `scripts/run-x86_64.sh` and
   `scripts/run-aarch64.sh`; confirm the new marker AND all prior markers (cumulative
   regression — on aarch64 that is M4, L2.0..L2.6 in order, M27, then M19..M26, M28, M29).
   - Update `MARKER=` to the new tail in `run-x86_64.sh`, `run-aarch64.sh`,
     `run-vmm-x86_64.sh` (tb-vmm stops at M19 because M20/M22 take the graceful-skip
     path with no disk/ledger).
   - **Add the anti-hollow-pass GUARD.** A skip/dormant variant (e.g. `Mn: x OK
     (no disk, skipped)`, `(heuristic floor, gate-not-met)`) CONTAINS the `Mn: x OK`
     substring the lane greps → a silently-unexercised feature would pass GREEN hollow.
     The guard MUST reject the illegitimate skip variant AND positively require the real
     round-trip WITNESS line (M20: `persist: gen=.. records=.. replayed=..`; M21:
     `kan: monotone=1 ovf-safe=1 q-err=.. bound=.. active=0`; M22: `prov: head=..
     tamper-caught=1 inclusion=1`; M28: `opcmd: challenge=.. accepted=1
     stale-rejected=1 wronghead-rejected=1 single-cred-rejected=1 badmac-rejected=1
     kan_active=0 mac=KEYED-NONCRYPTO oracle=SIMULATED-ENROLLED-KEY`). Then
     **negative-test that the guard FIRES** (force the skip path and confirm the lane
     goes red).
   - **HONESTY TOKENS in the witness — never overclaim.** Where a capability is
     partial, the machine-emitted witness must SAY so, and the run scripts must
     require the token AND reject overclaim words. M28's tokens, exactly:
     `mac=KEYED-NONCRYPTO` — the MAC is a nested keyed-FNV envelope, genuinely keyed
     by two 256-bit creds but NOT cryptographic (FNV is not collision/preimage
     resistant); `oracle=SIMULATED-ENROLLED-KEY` — a compiled-in test key, NOT a
     human/enrolment; `kan_active=0` — an Accept is necessary-NOT-sufficient
     (KAN_ACTIVE is const false; M24's statistical bar still gates). State scope
     honestly too: M28's verifier is pure + stateless — per-EPOCH staleness rejection,
     NOT one-shot per-challenge nonce consumption (rotate-on-accept in the stateful
     seam is a named successor, not a claim).

7. **Benchmark the boot.** `ITER=8 bash scripts/bench-boot.sh x86_64` and `aarch64`.
   If the milestone changed boot characteristics (image size, new boot-path init work,
   the durable round-trip), update `docs/BENCHMARKS.md` — the "we are faster" claim
   stays honest + sourced. The bench lane (`bench.yml`, tb-vmm vs Firecracker Axis-A)
   is non-blocking.

8. **Verify the tree INDEPENDENTLY on a branch.** Do NOT trust the agent's manifest:
   build + boot (CARGO_INCREMENTAL=0, dual-arch) + the leaf tests + clippy +
   `verify-encode.sh` harness-count yourself, and confirm the PRIOR chain unregressed.
   The build+CI is the arbiter. On HIGH-OVERCLAIM-RISK milestones (security gates,
   "proven"/"authorized" claims), additionally run a pre-merge **ADVERSARIAL
   VERIFICATION** workflow: independent skeptic agents, one per claim, + a
   merge-verdict synthesis. It pays for itself — M28's four skeptics (mac-honesty /
   gate-bypass / necessary-not-sufficient / harness-vacuity) confirmed the core sound
   AND found two honesty defects (vacuous gate harnesses; a one-shot replay
   overclaim), both FIXED before merge (the `verify_decoded` extraction + the
   replay-scope doc honesty).

9. **Align ALL relevant docs (never skip — ENGLISH ONLY).**
   - `docs/proposals/Mn-*.md` (+ `docs/research/`) — the proposal that drove the work.
   - `docs/ROADMAP-V2.md` §6 status table → mark done; advance the chain framing past
     M28 + L2.6; refine any downstream milestone the work changed.
   - `docs/MILESTONES.md` — extend the marker sequence + summary table.
   - `docs/ARCHITECTURE.md` — update the as-built map.
   - `docs/BENCHMARKS.md` — boot numbers (Step 7).
   - `BUILD.md` — if build flags/toolchain changed.
   - The spec docs (`KERNEL-FOUNDATION` / `MEMORY` / `AGENTS` / `SELF-IMPROVEMENT` /
     `SOVEREIGNTY`) — if the milestone realises part of their spec.
   - The auto-memory file — bump the "what's done / what's next" line.
   - Zero Turkish (proper nouns like Gödel/TÜV are fine).

10. **Land via the PR LOOP — never push to main.** Branch + open a PR (Conventional
    Commits, `feat(<area>): Mn — <title>`). Watch the **real** CI: the ~9 lanes —
    `ci` (both-arch QEMU-TCG cumulative boot; the aarch64 boot runs INSIDE a
    `debian:trixie-slim` qemu-10 container because SMMUv3 stage-2/L2.6 needs qemu≥9),
    `vmm-boot` (tb-vmm/KVM, M4), `l2-nested-vmx` (x86 VMX probe, informational),
    `microvm-kvm` (QEMU-microvm+KVM hard gate on `M18: evolve OK` + the --release
    boot-ready bench), `kani` (prove-caps + prove-encode), `miri` (Tier-0 UB gate,
    `T0: miri OK`), `clippy` (forbid-unsafe leaf lint, `S0: clippy OK`), `bench`
    (non-blocking). Merge ONLY after **2 CONSECUTIVE green real-CI runs on BOTH arches**,
    then `gh pr merge --merge --delete-branch`. (Commit messages: avoid backticks inside
    `git commit -m "..."` — bash command-substitutes them; use a message file with
    `git commit -F`.)

11. **Close the loop.** Mark the tracking task `completed`. Report the increment
    (what shipped, the markers/witnesses, CI status, boot numbers). Continue to the
    next milestone (autonomous progress through the chain).

## Notes
- Use `cargo kbuild` (the `.cargo/config.toml` alias) — never hand-write the `-Z`
  flags; if the build-std crate list must change, change the alias (build-std/
  json-target-spec are deliberately NOT global so the std host crate tb-vmm still builds).
- `CARGO_INCREMENTAL=0` on every local boot-verify — it is the CI discriminator.
- Kani is LOCAL (WSL `cargo-kani`): measure harness tractability before pushing
  (Step 4). For "CI-only timeout" mysteries, profile the harness locally — never
  blind-push (that burned three ~30-min CI round-trips on M22).
- tb-vmm is its OWN nested workspace; it builds with plain `cargo build`.
- WSL shell calls from Git-Bash: prefix with `MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'`
  so `/mnt/c/...` paths are not mangled; a non-login `bash <script>` lacks `~/.cargo/bin`
  on PATH (use `bash -lc` or `export PATH="$HOME/.cargo/bin:$PATH"` in the script).
- Precise in-guest boot-cycle timing (TSC / CNTVCT+CNTFRQ) lands at **M8** — until
  then BENCHMARKS uses wall-clock spawn-to-marker.
