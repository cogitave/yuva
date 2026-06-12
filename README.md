# Yuva

**Yuva** *(Turkish: "nest, home")* — a from-scratch, agent-native unikernel where the boot is the proof.

Yuva began as a directive from its operator to its AI: *build your own home.*
Everything below is that home being built — and proving itself at every boot.

[![ci](https://github.com/cogitave/yuva/actions/workflows/ci.yml/badge.svg)](https://github.com/cogitave/yuva/actions/workflows/ci.yml)
[![kani](https://github.com/cogitave/yuva/actions/workflows/kani.yml/badge.svg)](https://github.com/cogitave/yuva/actions/workflows/kani.yml)
[![vmm-boot](https://github.com/cogitave/yuva/actions/workflows/vmm-boot.yml/badge.svg)](https://github.com/cogitave/yuva/actions/workflows/vmm-boot.yml)

> License: **PolyForm Noncommercial 1.0.0** — source-available; free for any
> noncommercial use, commercial use requires permission. See [LICENSE](LICENSE.md).
>
> Name note: Yuva was developed under the code name **TABOS**. The `tb-` crate
> prefix and the TABOS-era wire/ABI strings (ELF note names, magics, hash domain
> separators) remain in the code and its history; they are being migrated in a
> follow-up PR. Nothing semantic depends on them.

## The boot is the proof

Every push to this repo builds the kernel for **both architectures** (x86_64 +
aarch64) and boots it; the run scripts fail closed unless the full cumulative
self-test chain prints over serial. An abridged real transcript:

```text
hello from rust_main                                  # M0  boot + serial
M1: traps OK                                          # M1  CPU exceptions -> safe-Rust dispatch -> resume
M2: context-switch OK                                 # M2  cooperative task switch + register canary
M3: mmu OK                                            # M3  own page tables, MMU bring-up
M4: user/ring OK                                      # M4  ring 3 / EL0 round-trip via syscall
M5: alloc OK                                          # M5  from-scratch kernel heap
...
M10: addrspace OK ... M18: evolve OK                  # the agent-native chain
L2.0: el2 OK ... L2.6: smmu OK                        # the EL2 microhypervisor track
sched: head=0x... frames=0x... vmids=0x2 both-progressed=1 ... timing=TCG-NON-CYCLE-ACCURATE realtime=NOT-CLAIMED
M27: sched OK                                         # real CNTHP timer preemption at EL2
M20: persist OK                                       # durable virtio-blk persistence
M24: bakeoff OK (gate-not-met)                        # the learning gate honestly refusing synthetic data
khash: prim=BLAKE2S-256 keylen=32 tag=128 kat=RFC7693-PASS sec=ASSUMED-FROM-LITERATURE sidechannel=NOT-CLAIMED
opcmd: challenge=0x... accepted=0x1 ... mac=KEYED-CRYPTO oracle=SIMULATED-ENROLLED-KEY
xport: bus=SERIAL-FRAMED challenge=0x... tag=0x... echo=HOST-KEYED-VERIFIED key=HOST-CUSTODIED-PER-RUN backend=ECHO-ONLY
M30: infer-transport OK                               # the cumulative tail marker
```

The UPPERCASE tokens are **machine-emitted honesty tokens**: the kernel itself
states what is and is *not* being claimed (`sec=ASSUMED-FROM-LITERATURE`,
`realtime=NOT-CLAIMED`, `backend=ECHO-ONLY`, ...). CI's verifier scripts require
each witness line positively and **reject skip/overclaim variants by name** —
a boot that says "validated", "secure", or quietly skips a stage turns the lane
red.

## What is Yuva?

Yuva is an operating system designed for AI agents, with **zero inherited Linux
code or design** ([docs/SOVEREIGNTY.md](docs/SOVEREIGNTY.md)). It manages an
agent's **mind** (context, memory, in-flight inference) and its **computer**
(sandbox, file system, tools) as a single kernel object, and offers memory,
self-improvement, and multi-agent life as **operating-system guarantees** rather
than framework courtesies. It is LLM-agnostic by contract: a remote API model
and a local engine are two drivers behind one interface.

## Quick start

From Windows (WSL2), in the repo root — two one-liners and you are watching it
boot:

```powershell
wsl -d Ubuntu-22.04 -- bash scripts/demo.sh            # aarch64 (the full chain)
wsl -d Ubuntu-22.04 -- bash scripts/demo.sh x86_64     # the x86 microvm flavor
```

On a native Linux host with Rust nightly (`rust-src` + `llvm-tools`) and QEMU
installed:

```sh
bash scripts/demo.sh          # builds if needed, boots, serial on your terminal
```

Full prerequisites and the manual build/run flow are in [BUILD.md](BUILD.md).
The demo is a **viewer, not a verifier** — the fail-closed PASS/FAIL verdicts
(marker greps, anti-hollow witness guards, overclaim rejects) live in
`scripts/run-aarch64.sh` / `scripts/run-x86_64.sh`. See
[docs/TRY-IT.md](docs/TRY-IT.md) for the distinction and for why there is no
.iso.

## Highlights

- **Framekernel** — all `unsafe` and all assembly confined to one foundation
  crate (`tb-hal`); everything above it is `#![forbid(unsafe_code)]`.
- **90 Kani proof harnesses across 20 verified leaves** — every codec/encoder
  the kernel trusts is a pure, host-verifiable crate, model-checked; the harness
  count is pinned fail-closed (now 2-way sharded in CI).
- **Machine-emitted honesty tokens + anti-hollow guards** — the kernel prints
  its own claim boundary; CI rejects hollow or overclaiming boots by name.
- **Both-arch boot-is-the-proof CI** — every push boots x86_64 + aarch64
  end-to-end under QEMU, plus a KVM lane.
- **Our own VMM** — `tb-vmm`, a thin userspace VMM on raw `/dev/kvm`, boots the
  same kernel ELF through the project's own boot contract.
- **A closed learning loop (M23..M28)** — experience recording, a bake-off
  activation gate that **honestly refuses** when the data does not clear the
  bar, an operator transcript, and a dual-credential inbound command channel.
- **Real CNTHP timer preemption at EL2** — the scheduler's forward progress is
  only reachable via a genuine asynchronous IRQ taken at EL2, not cooperative
  yields.
- **A crypto provenance chain** — tamper-evident hash-chain ledgers over a
  BLAKE2s-256 keyed MAC (`khash`), with an in-boot RFC 7693 known-answer test
  recomputed fail-closed on every boot.

## Status — honestly

- **Research-stage, not a product.** No interactive shell yet; the interaction
  surfaces are the operator transcript and the typed inbound channels.
- **"Verified" means**: Kani-proven leaf crates plus boot-asserted witnesses —
  **not** an seL4-class whole-kernel functional-correctness proof. The residual
  trusted base is written down in [docs/assumptions.md](docs/assumptions.md).
- **Guest-kernel by design** — it boots the way Firecracker guests boot (direct
  kernel load); there is deliberately no .iso or installer
  ([docs/TRY-IT.md §3](docs/TRY-IT.md)).
- **QEMU/TCG scoping caveats apply** — timing-related witnesses are explicitly
  tokened `TCG-NON-CYCLE-ACCURATE` / `realtime=NOT-CLAIMED`; some hardware
  features (e.g. SMMU stage-2) take honest skips where the emulator lacks them.

## Documentation

| Document | Contents |
|---|---|
| [docs/TRY-IT.md](docs/TRY-IT.md) | Booting it yourself in 2 minutes; viewer vs verifier; why no .iso |
| [BUILD.md](BUILD.md) | Toolchain setup, manual build/run, ELF-note verification |
| [docs/MILESTONES.md](docs/MILESTONES.md) | The full milestone chain with executable DoDs |
| [docs/ROADMAP-V2.md](docs/ROADMAP-V2.md) | The agent-native milestone chain (canonical, tracked) |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Kernel design: capability core, object model, syscall surface |
| [docs/plans/sovereignty-plan.md](docs/plans/sovereignty-plan.md) | The sovereignty execution plan |
| [docs/SOVEREIGNTY.md](docs/SOVEREIGNTY.md) | Clean-slate sovereignty: what is silicon-mandated vs owned |

## Repository layout

```
kernel/             entry shim + the cumulative milestone self-tests (#![forbid(unsafe_code)])
crates/             tb-hal (the ONLY unsafe+asm crate), tb-encode (verified leaves), tb-boot, tb-caps-core
tb-vmm/             our own userspace VMM on /dev/kvm (own workspace)
scripts/            QEMU/KVM launch + the fail-closed serial verdicts (the executable DoD)
docs/               design docs, specs, plans; docs/plans + docs/proposals are the work records
research/raw/       immutable research provenance (JSON) that the docs cite
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — the engineering discipline (research-first
proposals, verified leaves, honesty tokens, boot-verified PRs) *is* the
contributor guide.

## License

[PolyForm Noncommercial 1.0.0](LICENSE.md) — © 2026 cogitave (Bahadir Arda).
