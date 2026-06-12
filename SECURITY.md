# Security Policy

Yuva is a **research-stage** operating system project. Honest scope first:

- There is **no SLA** and **no bug bounty**.
- Nothing here is claimed to be secure or production-ready. The kernel's own
  boot output states its claim boundary in machine-emitted honesty tokens
  (e.g. `sec=ASSUMED-FROM-LITERATURE`, `sidechannel=NOT-CLAIMED`,
  `key=HOST-CUSTODIED-PER-RUN` — custody, not confidentiality).
- "Verified" means Kani-proven leaf crates plus boot-asserted witnesses, not a
  whole-kernel functional-correctness proof.

## Reporting

Open a [GitHub issue](../../issues) for anything you find — including proof
gaps, hollow witnesses, or overclaims in prose, which this project treats as
seriously as memory bugs. If the finding is sensitive enough that a public
issue feels wrong, use GitHub's private vulnerability reporting on this
repository (or contact the repository owner directly).

There is no embargo process; fixes land through the normal PR loop with the
full CI gate set.

## Threat model pointers

- [docs/assumptions.md](docs/assumptions.md) — the residual trusted computing
  base the proofs do NOT discharge (hardware, QEMU/KVM, the toolchain, the
  hand-written assembly), stated assumption by assumption.
- The honesty-token discipline — every witness line names what is *not*
  claimed, and CI rejects boots that overclaim or skip; see the run scripts
  under [scripts/](scripts/).
