---
name: tabos-milestone
description: The end-to-end pipeline for shipping ONE TABOS kernel milestone (M5..M18 of docs/ROADMAP-V2.md, or any new milestone). Use whenever implementing/continuing a TABOS milestone so NO step — code, adversarial review, both-arch build+boot, boot-time benchmark, AND every doc/research/script/roadmap update — is ever skipped. Invoke at the start of each milestone increment.
---

# TABOS milestone pipeline

TABOS is a from-scratch `no_std` Rust agent-native OS. Every milestone is shipped
the SAME way and is only "done" when it is **CI-green on both arches AND under
tb-vmm on /dev/kvm**, with all docs updated. This skill is the checklist; follow
it in order and do not skip the documentation/benchmark steps.

Repo: `/mnt/c/Users/Arda/workspaces/@cogitave/tabos` (build/run/git via WSL bash;
edits via Windows paths). Build: `cargo kbuild --target targets/<arch>-tabos-none.json`.

## Operating mode (standing directives — do not ask)
- **Always ultracode.** Every substantive step (design, generate, review,
  synthesize, research) runs as a multi-agent `Workflow`, never solo. The user
  has made this standing for the whole project — do **not** ask whether to use a
  workflow; use one. Solo is only for trivial mechanical edits and conversation.
- **Design Thinking × Success by Design.** Each milestone passes the same
  principled loop, mapped onto the concrete pipeline so it stays trackable:
  - *Empathize / Define* — who is this milestone for, and what EXACTLY must it
    do? Read its ROADMAP-V2 section; state the one capability + the exact DoD
    marker before any code (Step 1). Every subsystem answers "what does this give
    an agent?" (the four pillars).
  - *Ideate* — diverse options before committing: the multi-agent generate +
    3-lens adversarial review panel (Step 2). Never a single attempt; surface and
    resolve the contested decisions explicitly (no open decisions left dangling).
  - *Prototype* — the generated code applied to a clean tree (Step 3).
  - *Test* — the build + both-arch boot-assert + benchmark + your own audit are
    the empirical test. "The build is the arbiter" (Steps 4–6).
  - *Success-by-Design gates* — "done" only when it clears the well-architected
    pillars, each already a pipeline step: **reliability** (cumulative regression
    stays green), **security** (framekernel / forbid-unsafe intact), **performance**
    (boot benchmark current — `docs/BENCHMARKS.md`), **operational excellence**
    (CI green on both arches + `/dev/kvm`; docs/roadmap/trackers updated). A
    skipped gate = not done.
  - *Learn forward* — carry each milestone's lessons (the "actual build catches
    what review missed" findings) into the next iteration and into this skill.

## Non-negotiable invariants
- **Framekernel**: ALL `unsafe` + ALL assembly live ONLY in `crates/tb-hal`.
  `kernel/` and any future service crate stay free of `unsafe {}` (the kernel's
  only concession is `#[unsafe(no_mangle)]` on `rust_main`).
- **Cumulative DoD**: each milestone prints an EXACT serial marker
  (`"Mn: <slug> OK"`); the kernel runs M0..latest every boot. The run scripts
  grep the NEWEST marker — update `MARKER=` in all three run scripts when a
  milestone lands.
- **Two arches** (x86_64 + aarch64) and **two boot paths** (PVH/QEMU +
  tb-boot/tb-vmm) must stay green.
- **The build + boot are the arbiter.** A reviewer that says "sound" is not
  enough; the real `cargo kbuild` + QEMU boot has repeatedly caught what review
  missed (e.g. M5's `alloc` missing from `-Zbuild-std`). Trust the boot.

## Steps (per milestone)

1. **Scope from the roadmap.** Read the milestone's section in
   `docs/ROADMAP-V2.md` (id, exact DoD marker, mechanisms, framekernel unsafe
   placement, arch notes, deps, risks). Mark its tracking task `in_progress`.

2. **Generate via ultracode (Workflow).** Author the milestone with a
   `generate -> 3-lens adversarial review -> finalize` workflow. CRITICAL:
   - Give the **gen + finalize agents `isolation: 'worktree'`** so their
     scratch writes/compiles never touch the shared working tree (a general
     agent WILL write to the repo otherwise — this bit M5).
   - Tell agents to compile-check with WSL `cargo kbuild` (NOT raw `rustc` with
     Windows paths — that hangs).
   - Review lenses: (a) correctness/soundness of the new mechanism, (b)
     framekernel + regression + both-arch/both-boot-path, (c)
     Rust/nightly build + trait/ABI correctness.
   - Ground every agent with: the framekernel rule, the cumulative-marker
     pattern, the exact files (`kernel/src/main.rs`, `crates/tb-hal/src/lib.rs`
     + `arch/`), and the current state (read the files).
   - Have the workflow RETURN structured artifacts (new-file bodies + precise
     integration edits). Save the gen output to `research/raw/<mn>-gen.json`.

3. **Apply to a CLEAN tree yourself.** `git checkout -- .` any agent scribbles
   first. Then write the new files + apply the integration edits with the
   Edit/Write tools (you own the regression-sensitive edits). Do your OWN
   adversarial audit of the core mechanism (do not outsource final soundness).

4. **Build — the real arbiter.** `cargo kbuild` BOTH arches. Fix every error
   (build-std crate list, features, missing docs in tb-hal which `deny`s them).
   Zero warnings from our code.

5. **Boot + assert + regress.** Run `scripts/run-x86_64.sh` and
   `scripts/run-aarch64.sh`; confirm the new marker AND all prior markers
   (cumulative regression). Update `MARKER=` to the new marker in
   `scripts/run-x86_64.sh`, `run-aarch64.sh`, `run-vmm-x86_64.sh`.

6. **Benchmark the boot.** `ITER=8 bash scripts/bench-boot.sh x86_64` and
   `aarch64`. If the milestone changed boot characteristics (image size, new
   init work on the boot path), update `docs/BENCHMARKS.md` with the new
   numbers and keep the cited cross-system comparison current. The "we are
   faster" claim must stay honest + sourced.

7. **Update ALL relevant docs (never skip).**
   - `docs/ROADMAP-V2.md` §6 status table → mark the milestone done; refine
     any downstream milestone the work changed.
   - `docs/MILESTONES.md` — add/extend a milestone section if it warrants one.
   - `docs/BENCHMARKS.md` — boot numbers (step 6).
   - `BUILD.md` — if build flags/toolchain changed.
   - `KERNEL-FOUNDATION-SPEC.md` / `MEMORY-SPEC` / `AGENTS-SPEC` /
     `SELF-IMPROVEMENT-SPEC` / `SOVEREIGNTY*` — if the milestone realises part
     of their spec.
   - The auto-memory file (`memory/agent-native-os-project.md`) — bump the
     "what's done / what's next" line.
   - ALL docs are **English only** (zero Turkish; proper nouns like Gödel/TÜV
     are fine). The kernel-foundation chain status lines must stay accurate.

8. **Commit + push + CI.** Use the **Commit tool** (Conventional Commits;
   `feat(<area>): Mn — <title>`). Push. Watch BOTH `ci` (QEMU matrix) and
   `vmm-boot` (/dev/kvm) to green via `gh run watch`. The milestone is NOT done
   until both are green.

9. **Close the loop.** Mark the tracking task `completed`. Report the increment
   (what shipped, the markers, CI status, boot numbers). Continue to the next
   milestone (the `/goal` is autonomous progress through the chain).

## Notes
- Use `cargo kbuild` (the alias in `.cargo/config.toml`) — never hand-write the
  `-Z` flags; if the build-std crate list must change, change the alias.
- tb-vmm is its OWN nested workspace; it builds with plain `cargo build`.
- Precise in-guest boot-cycle timing (TSC / CNTVCT+CNTFRQ) lands at **M8**
  (the timer milestone) — until then BENCHMARKS uses wall-clock VMM-spawn-to-marker.
