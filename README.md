# TABOS

**Turkiye's Agent Based Operating System** — a from-scratch operating system in
which AI agents are first-class citizens.

> License: **PolyForm Noncommercial 1.0.0** — source-available; free for any
> noncommercial use, commercial use requires permission. See [LICENSE](LICENSE.md).
>
> Name note: "TABOS" is the project's **code name** (working title), not a final
> brand — it may change. Anything name-derived (the `tb_` kernel prefix, CLI
> names, domain suggestions) is a placeholder and is hardcoded nowhere. Final
> name + reservation decision: [OPEN-QUESTIONS §G](docs/OPEN-QUESTIONS.md).

## Status: the kernel boots and runs

The v1 kernel-foundation chain **M0 → M4 is complete and green on both
architectures** (x86_64 + aarch64), verified by booting under QEMU on every
change. A successful boot prints this cumulative self-test over serial:

```
hello from rust_main          # M0  boot + serial
M1: traps OK                  # M1  CPU exceptions -> safe-Rust dispatch -> resume
M2: context-switch OK         # M2  cooperative task switch (1000-round + register canary)
M3: mmu OK                    # M3  MMU bring-up + own page tables
syscall from user: arg=0xcafe # M4  trapped back from user mode...
M4: user/ring OK              # M4  ...privilege separation works
```

The kernel boots, catches hardware traps and runs the policy in
`#![forbid(unsafe_code)]` safe Rust, switches between tasks, manages its own
virtual memory, and can drop code to an unprivileged level (ring 3 / EL0) and be
re-entered safely via a syscall — the hardware foundation for running agents at
lower privilege. See [docs/MILESTONES.md](docs/MILESTONES.md) for the full
breakdown, and [BUILD.md](BUILD.md) to build and run it yourself.

## What is TABOS?

TABOS is an OS design with **zero inherited Linux code or design** (see
[docs/SOVEREIGNTY.md](docs/SOVEREIGNTY.md)) that manages an agent's **mind**
(context, memory, in-flight inference) and its **computer** (sandbox, file
system, tools) as a single kernel object, and offers memory, self-improvement,
and multi-agent life as an **operating-system guarantee** rather than a framework
courtesy.

- **From-scratch kernel** — everything down to the syscall ABI is designed for
  agents; every subsystem justifies itself by what it enables an agent to do.
- **LLM-agnostic** — `model:anthropic/...` and `model:local/llama` are two
  drivers behind one contract.
- **Memory-first** — every agent is born with persistent, tiered, recall-capable
  memory.
- **Self-improvement as an OS service** — reflection on by default; skills are
  not committed without verification; the measurer is isolated from the measured.
- **One = many agents** — a single-agent session is the |members|=1 special case
  of an N-agent session.

## Engineering

- **Language:** Rust everywhere. *Framekernel* pattern — all `unsafe` and all
  assembly are confined to one foundation crate (`tb-hal`); every layer above is
  `#![forbid(unsafe_code)]`. ([docs/LANGUAGE-AND-STANDARDS.md](docs/LANGUAGE-AND-STANDARDS.md))
- **Targets:** `x86_64` (PVH boot) and `aarch64` (QEMU `virt`), built `no_std`
  with `-Zbuild-std` against checked-in custom target specs.
- **Substrate:** boots as a guest on a Firecracker/KVM-class VMM; developed under
  QEMU. The project's own thin VMM (`tb-vmm`) and sovereign boot contract are the
  next milestone. ([docs/SOVEREIGNTY.md](docs/SOVEREIGNTY.md))
- **CI:** every push builds both architectures and boots them under QEMU,
  asserting the milestone marker — [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Quickstart

On a Linux host (or WSL2) with Rust nightly (`rust-src` + `llvm-tools`) and
`qemu-system-x86` / `qemu-system-arm` installed (full setup in [BUILD.md](BUILD.md)):

```sh
cargo kbuild --target targets/x86_64-tabos-none.json
bash scripts/run-x86_64.sh      # boots under QEMU, asserts the milestone marker

cargo kbuild --target targets/aarch64-tabos-none.json
bash scripts/run-aarch64.sh
```

## Repository layout

```
kernel/             entry shim + cumulative milestone self-tests (#![forbid(unsafe_code)])
crates/tb-hal/      the ONLY crate where unsafe + asm live (per-arch under src/arch/)
targets/            custom no_std target specs
scripts/            QEMU launch + serial-marker assertion (the executable DoD)
docs/               design + research documents (see map below)
research/raw/       raw research and code-generation provenance (JSON)
.github/workflows/  CI
```

## Documentation map

| Document | Contents |
|---|---|
| [docs/MILESTONES.md](docs/MILESTONES.md) | The M0→M4 chain, executable DoDs, the dev pipeline, build/run, what's next |
| [docs/RESEARCH-REPORT.md](docs/RESEARCH-REPORT.md) | Cited deep-research report — 26 arXiv papers + 20 system docs; 25 core claims adversarially verified, 100 area findings |
| [docs/VISION.md](docs/VISION.md) | Rationale, five design principles, gap analysis, success criteria, roadmap |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Kernel decision (capability core + unikernel body + exokernel spirit), object model, namespaces, syscall surface, schedulers, security |
| [docs/MEMORY-SPEC.md](docs/MEMORY-SPEC.md) | Default memory: T0–T5 tiers + blocks, bi-temporal record schema, op ABI, consolidation, forgetting, multi-agent namespaces |
| [docs/AGENTS-SPEC.md](docs/AGENTS-SPEC.md) | Agent-process object, `.taf` image format, spawn protocol, lifecycle, IPC, identity, sessions |
| [docs/SELF-IMPROVEMENT-SPEC.md](docs/SELF-IMPROVEMENT-SPEC.md) | Three Laws (Endure>Excel>Evolve), frozen kernel, skill tier, sleep-time class, archive evolution, safety |
| [docs/SOVEREIGNTY.md](docs/SOVEREIGNTY.md) | Clean-slate sovereignty: silicon-mandated vs Linux-legacy vs TABOS-owned; `tb-boot`/`tb-vmm`; the "no old bugs" ledger |
| [docs/SOVEREIGNTY-ROADMAP.md](docs/SOVEREIGNTY-ROADMAP.md) | The full-sovereignty ladder L0→L3: why "full sovereignty" = L2 (own Type-1 microhypervisor) not L3; split-VMM architecture, the IOMMU requirement, the permanent GPU tax quarantined in a driver VM, and the build-ready `tb-vmm`/`tb-boot v0` spec |
| [docs/KERNEL-FOUNDATION-SPEC.md](docs/KERNEL-FOUNDATION-SPEC.md) | Kernel + assembly plan: the `tb-hal` crate, boot path, asm unit inventory, ABI register sets, MMU asm-vs-Rust boundary, test gates, M0–M4 WBS |
| [docs/LANGUAGE-AND-STANDARDS.md](docs/LANGUAGE-AND-STANDARDS.md) | Language decision (Rust, per layer) + industrial standards (NSA/CISA/ONCD/EU CRA, Ferrocene, SLSA/SBOM, fuzzing) |
| [docs/PROCESS.md](docs/PROCESS.md) | Process record + Design Thinking / Success by Design mapping, personas/JTBD, risk register, review gates (G0–G3) |
| [docs/OPEN-QUESTIONS.md](docs/OPEN-QUESTIONS.md) | 53 open questions, prioritized P0/P1/P2 — no spec freeze until the P0s close |

Spec markers: **[DECISION]** a made decision · **[PROPOSAL]** a research-derived
proposal (to be tested by prototyping) · **[OPEN]** tracked in OPEN-QUESTIONS.

## Provenance

The design corpus is the product of staged multi-agent research waves
(deep-research → verify+expand → naming → language/standards → kernel-asm), each
passed through independent adversarial review; the kernel code was generated and
adversarially reviewed milestone-by-milestone, then verified by actually booting
under QEMU. Raw research and code-generation records live in
[research/raw/](research/raw/).
