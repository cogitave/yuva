# Contributing to Yuva

Yuva is a solo-operator research project with an unusually strict engineering
discipline. The discipline *is* the contributor guide: a change that skips any
step below will not land, no matter how good the code is.

## The rules

1. **Research first.** Non-trivial changes start as a written proposal in
   `docs/proposals/` (cited sources, alternatives considered, an explicit DoD
   marker). Code without a proposal is reviewed as a prototype, not a candidate.

2. **Every codec is a verified leaf.** Anything that encodes, decodes, or
   validates bits the kernel trusts goes in `crates/tb-encode` as a pure,
   `#![forbid(unsafe_code)]`, zero-dependency leaf with Kani proof harnesses.
   The harness lists, per-shard counts, and pinned total live in ONE place —
   `scripts/kani-shards.sh` — consumed fail-closed by
   `scripts/verify-encode.sh` (whose header documents the shard modes and the
   bump procedure). Adding a harness means adding its exact name to a shard
   list (cost-balanced by measurement, rule 3); the completeness guard keeps
   the lists in lockstep with `proofs.rs` and CI rejects any mismatch in
   either direction.

3. **Measure every new Kani harness locally first.** Run the new harness on
   your machine and record its time/memory before pushing (the
   compression-budget rule): CI shards are cost-balanced, and an unmeasured
   harness that blows the budget blocks every lane.

4. **Mutation-test gate-level harnesses.** A harness that guards a verdict
   (accept/reject logic) must be shown to FAIL when its reject branches are
   deleted — a proof that cannot catch the bug it names is theater.

5. **Markers, witnesses, and anti-hollow guards.** Every milestone prints a
   positive serial marker plus a witness line with machine-emitted honesty
   tokens. Run scripts must require the witness, reject skip variants **by
   name**, and reject overclaim words. Never weaken a guard to make a lane
   green.

6. **Boot is the proof.** Kernel-touching changes must pass BOTH architecture
   run scripts (`scripts/run-x86_64.sh`, `scripts/run-aarch64.sh`) locally,
   **twice consecutively**, built with `CARGO_INCREMENTAL=0` (and after an
   `rm -rf target/` if you have any doubt about staleness). Then the PR loop:
   open a PR, wait for ALL CI gates green, never merge red.

7. **Honest commit messages.** Say what is proven, what is assumed, and what
   is deferred. Overclaim words (secure, production-ready, validated) are
   rejected in witness output by CI — hold prose to the same standard.

## License of contributions

Yuva is licensed under [PolyForm Noncommercial 1.0.0](LICENSE.md). By
submitting a contribution you agree it is provided under the same terms, with
the project's copyright holder as licensor.

## Practical notes

- Build/run setup: [BUILD.md](BUILD.md); the 2-minute boot: [docs/TRY-IT.md](docs/TRY-IT.md).
- The milestone pipeline and DoD definitions: [docs/MILESTONES.md](docs/MILESTONES.md).
- The residual trusted base (what the proofs do NOT discharge): [docs/assumptions.md](docs/assumptions.md).
