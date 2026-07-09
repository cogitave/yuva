<!-- okf
type: Index
title: Yuva
description: >-
  From-scratch, agent-native sovereign unikernel / micro-VMM in no_std Rust;
  a kernel with zero unsafe blocks above one audited HAL crate; Kani-verified
  leaves (counts pinned fail-closed in CI); boots x86_64 + aarch64 on every
  push and fails closed unless the full cumulative self-test marker chain
  prints over serial. Live inference is MOCK; learning is DORMANT
  (gate-not-met); the kernel says so itself in uppercase honesty tokens.
tags: [readme, index]
timestamp: 2026-07-09T00:00:00Z
status: active
diataxis: explanation
-->

<div align="center">

# Yuva

**The agent-native operating system where the boot is the proof.**

*Yuva (Turkish: "nest, home") began as a directive from its operator to its AI: **build your own home.***

[![ci](https://github.com/cogitave/yuva/actions/workflows/ci.yml/badge.svg)](https://github.com/cogitave/yuva/actions/workflows/ci.yml)
[![kani](https://github.com/cogitave/yuva/actions/workflows/kani.yml/badge.svg)](https://github.com/cogitave/yuva/actions/workflows/kani.yml)
[![vmm-boot](https://github.com/cogitave/yuva/actions/workflows/vmm-boot.yml/badge.svg)](https://github.com/cogitave/yuva/actions/workflows/vmm-boot.yml)

[Try it](docs/TRY-IT.md) · [Architecture](docs/ARCHITECTURE.md) · [Docs](docs/index.md) · [Roadmap](docs/ROADMAP-V2.md) · [Contributing](CONTRIBUTING.md)

</div>

Yuva is a from-scratch sovereign unikernel / micro-VMM: `no_std` Rust, a kernel
with zero `unsafe` blocks above one audited HAL crate, and 140+ machine-checked
proof harnesses at the leaves. Every push builds it for **both** x86_64 and
aarch64, boots it, and **fails closed** unless the full cumulative self-test
chain prints over serial.

Most systems ask you to trust their claims. Yuva prints its claim boundary from
the machine at every boot — what is proven, what is mock, what is dormant, what
is merely assumed — and CI turns the lane red if a boot overclaims, skips, or
goes hollow.

## Why this exists

In today's ecosystem the agent's *mind* and its *hands* tend to live in
separate systems — a sandbox owns the computer (e.g. E2B), a memory layer owns
the context (e.g. Letta), a scheduler owns the run loop (e.g. AIOS) — and
stitching them together is left to the application.

The join itself — treating `{context + memory tiers + in-flight inference +
sandbox + file system}` as **one object** you can suspend, resume, or fork — is
what tends to fall through the cracks.

Yuva's reason for being is to own that join at the kernel level: the agent and
its computer as a single kernel object, with memory, self-improvement, and
multi-agent life offered as operating-system guarantees — not framework
courtesies. It is LLM-agnostic by contract: a remote API model and a local
engine are two drivers behind one interface. Full gap analysis:
[docs/VISION.md](docs/VISION.md).

## The boot is the proof

An abridged real transcript (`...` elides witness fields; every line below is a
literal string the CI verifier greps for):

```text
hello from rust_main                                   # M0   first breath over serial
M1: traps OK ... M4: user/ring OK                      # exceptions, context switch, MMU, ring3/EL0
M10: addrspace OK ... M18: evolve OK                   # the agent-native chain: caps, memory, skills
L2.0: el2 OK ... L2.6: smmu OK                         # the EL2 microhypervisor track
M27: sched OK                                          # real CNTHP timer preemption at EL2
M24: bakeoff OK (gate-not-met)                         # the learning gate honestly refusing
khash: prim=BLAKE2S-256 ... kat=RFC7693-PASS sec=ASSUMED-FROM-LITERATURE sidechannel=NOT-CLAIMED
infer: backend=MOCK-DETERMINISTIC ... key=CAPREF-HOST-CUSTODIED host=RESIDUAL-TCB ambient=ZERO-IN-GUEST
M31: infer-e2e OK backend=MOCK-DETERMINISTIC           # the wire is proven; the model is deliberately absent
prov-sig: sig=LMS-SHA256-W4-H10 conformance=RFC8554 kat=RFC8554-PASS ... sec=ASSUMED-FROM-LITERATURE
M33: prov-lineage OK                                   # the signed provenance head survives a REAL reboot
infer-local: backend=LOCAL-STANDIN ... weights=NONE-NO-MODEL-LOADED ... live-inference=NOT-CLAIMED
corpus: ... corpus-reboot-survived=0x1 corpus-head-matches=0x1 ... durability=TORN-WRITE-SAFE-PING-PONG-FNV
M39: corpus OK                                         # the experience corpus survived — and grew — across reboot
M38: conductor OK turns=6 organs=3 verdict=ACCEPT      # the cumulative tail marker
```

The UPPERCASE tokens are **machine-emitted honesty tokens**: the kernel itself
states what is and is *not* being claimed. This is enforced, not aspirational:

1. **The kernel prints its own claim boundary** — `sec=ASSUMED-FROM-LITERATURE`,
   `realtime=NOT-CLAIMED`, `backend=MOCK-DETERMINISTIC`,
   `weights=NONE-NO-MODEL-LOADED` are emitted by the kernel, not written in docs.
2. **CI requires each witness positively and rejects overclaim and skip variants
   by name** — strip the declared tokens first, then any "secure", "validated",
   "learned", "live" vocabulary near a witness line turns the lane red.
3. **Retired weaker claims stay rejected forever** — when the MAC was upgraded,
   the old `mac=KEYED-NONCRYPTO` token became a by-name reject, so an old tier
   can never impersonate a new one.
4. **Anti-hollow legs are cross-process** — the host peer independently
   recomputes challenge tags, response digests, and decision lineages and
   string-compares them against the kernel's, so a self-consistent in-kernel
   forgery still fails.

## What Yuva is

Every claim below names its witness.

- **A framekernel** — all real `unsafe` and all assembly confined to one
  foundation crate (`crates/tb-hal`). The kernel crate above it contains zero
  `unsafe` blocks — its single unsafe token is the `#[unsafe(no_mangle)]`
  entry-symbol attribute, which is why crate-level `forbid` cannot be applied
  there; the verified leaf crates are `#![forbid(unsafe_code)]`.
- **Verified at the leaves** — every codec and invariant the kernel trusts is a
  pure, host-checkable crate under Kani/CBMC: **128 harnesses** over the codec
  leaves plus **12** over the capability core, and both counts are **pinned
  fail-closed** (`scripts/kani-shards.sh`, `scripts/verify-caps.sh`) — a harness
  added or lost without the lockstep edit fails CI.
- **Capability-only authority** — no ambient authority; the no-widening
  invariant of the rights mask is machine-proven (M11, the 12 caps harnesses).
- **A provenance chain that survives reboot** — memory writes fold into a keyed
  BLAKE2s tamper-evident chain (M22/M29) whose LMS-signed head (M33, RFC 8554,
  verify-only in kernel; the private key never enters the image) is proven by a
  two-boot CI witness to survive a real reboot.
- **Its own stack, top to bottom** — zero lines of Linux code, zero Linux design
  inherited ([docs/SOVEREIGNTY.md](docs/SOVEREIGNTY.md)); its own boot contract,
  its own userspace VMM (`tb-vmm` on raw `/dev/kvm`), its own EL2
  microhypervisor track with real CNTHP timer preemption (M27).
- **A boot-enforced ABI** — the Yuva↔agent contract is a frozen-literal registry
  ([docs/spec/yuva-abi-v1.md](docs/spec/yuva-abi-v1.md)) the kernel cross-checks
  against its live seams at boot and **fail-closes on drift**.
- **A durable experience corpus** — the M39 corpus accumulates
  provenance-folded records, survives reboot (CI fails unless it *grows* across
  a real reboot), and exports host-side for a future operator-gated fine-tune.
  It trains nothing today — and that is machine-enforced.
- **Two boot profiles** — `yuva.profile=agent` (default) or `substrate`: a
  substrate boot is a plain, agent-agnostic micro-VMM core with the agent organs
  not run and **not admitted** (denied at the capability chokepoint), verified
  by a generated negative census on its own CI lane. It is **not yet a usable
  Firecracker alternative** — the sanctioned framing and the stage-A caveats
  live in [the boot-profiles proposal](docs/proposals/boot-profiles.md).

## Status by pillar

| Pillar | State | The evidence — and the boundary |
|---|---|---|
| **Sovereignty** | **STRONG** | Zero inherited Linux, capability-only authority (no-widening machine-proven), reboot-surviving signed provenance, boot-enforced ABI ([SOVEREIGNTY.md](docs/SOVEREIGNTY.md)); x86 VMX-root takes a graceful skip on hosted CI. |
| **Memory** | **STRONG** (storage + recall) | Tiered T0–T3 journal + BM25+ lexical recall as OS guarantees, durable over virtio-blk via Kani-proven codecs — `retrieval=LEXICAL-NOT-SEMANTIC` by design: no floats, no embeddings, no vector DB. |
| **Continuous learning** | **DORMANT — by its own gate** | The M23–M28 loop is built, closed, and switched off by its own evidence bar — every boot prints `M24: bakeoff OK (gate-not-met)` because the gate refuses synthetic data; **an honest gate that refuses is a success** ([forward-plan](docs/proposals/forward-plan.md)). |
| **Operator communication** | **GOOD** | Typed tamper-evident transcript out (M25), exit telemetry (M26), dual-credential inbound channel (M28) — `oracle=SIMULATED-ENROLLED-KEY`: a compiled-in test key, no real enrolment ceremony yet. |
| **Live inference** | **MOCK — plumbing proven, model absent** | The wire path is proven every boot (MAC'd chunked codec, host-custodied per-run key, cross-process digest equality); what rides it is `backend=MOCK-DETERMINISTIC` with `weights=NONE-NO-MODEL-LOADED` — the operator-gated live lane is [RUN-THE-HELLO](docs/RUN-THE-HELLO.md). |

## Why you shouldn't use Yuva (yet)

- **It is a research substrate, not a product.** No interactive shell — the
  interaction surfaces are the operator transcript and the typed channels.
- **No model is resident.** Live inference is a deterministic mock; the e2e
  proves plumbing, never smarts.
- **Learning is dormant** until real (non-synthetic) experience clears the gate.
- **Uniprocessor** — `smp=UP-ONLY`.
- **QEMU/TCG scoping caveats apply** — timing witnesses are tokened
  `TCG-NON-CYCLE-ACCURATE` / `realtime=NOT-CLAIMED`; some hardware features take
  honest skips where the emulator lacks them.
- **"Verified" is bounded**: Kani-proven leaves plus boot-asserted witnesses —
  **not** an seL4-class whole-kernel functional-correctness proof. Crypto
  *implementations* are proven and KAT-checked; the *primitives* are
  `sec=ASSUMED-FROM-LITERATURE`. The residual trusted base is enumerated in
  [docs/assumptions.md](docs/assumptions.md) — that is where scrutiny should aim.

## Try it

On a native Linux host with Rust nightly (`rust-src` + `llvm-tools`) and QEMU:

```sh
bash scripts/demo.sh          # builds if needed, boots, serial on your terminal
```

From Windows (WSL2):

```powershell
wsl -- bash scripts/demo.sh            # aarch64 (the full chain)
wsl -- bash scripts/demo.sh x86_64     # the x86 microvm flavor
```

On x86_64 (`scripts/demo.sh x86_64`) the demo renders a systemd-style boot
readout where honesty is in the UI itself — a mock can never render as OK. The
pretty knob is wired on x86 only at stage A, so the default aarch64 demo shows
the raw `Mxx` marker chain with a note saying so:

```text
[  OK  ] Durable storage            virtio-blk, replayed on boot
[  OK  ] Inference transport        host-custodied key, cross-process recompute — plumbing only
[ MOCK ] Agent inference            deterministic stub — NO model loaded, not live AI
[STANDBY] Adaptive policy            experience logged; activation gate not met
[  OK  ] Reached target Ready.
```

The demo is a **viewer, not a verifier** — the fail-closed PASS/FAIL verdicts
(marker greps, anti-hollow guards, overclaim rejects) live in
`scripts/run-aarch64.sh` / `scripts/run-x86_64.sh`. See
[docs/TRY-IT.md](docs/TRY-IT.md) for the distinction, the raw `--verbose` marker
stream, and why there is deliberately no .iso (Yuva boots the way Firecracker
guests boot: direct kernel load). Full toolchain setup: [BUILD.md](BUILD.md).

## The Cogitave family

*Namzu runs agents the way Unix runs processes. Yuva is the OS an agent can
call home. Cogi is the agent that lives there.*

| Repo | Role | Honest relationship |
|---|---|---|
| **Yuva** (here) | the **home** — a sovereign, agent-agnostic OS / micro-VMM | hosts any conformant agent, or none (substrate profile) |
| [**Cogi**](https://github.com/cogitave/cogi) *(private until the operator cut)* | the **mind** — the resident agent's portable host-side core | speaks the Yuva-ABI as a pinned git dependency; `extraction=DUAL-HOMED-NOT-YET-CUT` |
| [**Namzu**](https://github.com/cogitave/namzu) | the **agent kernel for TypeScript** | Cogi's planned action/skills layer — deferred; no bridge exists today |

## Documentation

[docs/index.md](docs/index.md) is the progressive-disclosure hub, with reading
paths for the skeptic, the contributor, and the operator. Shortcuts:

| Document | Contents |
|---|---|
| [docs/TRY-IT.md](docs/TRY-IT.md) | Boot it yourself in 2 minutes; viewer vs verifier; why no .iso |
| [BUILD.md](BUILD.md) | Toolchain setup, manual build/run, ELF-note verification |
| [docs/VISION.md](docs/VISION.md) | Why Yuva exists: the four pillars, the gap analysis |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Kernel design + the honest design→reality as-built map |
| [docs/SOVEREIGNTY.md](docs/SOVEREIGNTY.md) | Clean-slate sovereignty: silicon-mandated vs owned |
| [docs/ROADMAP-V2.md](docs/ROADMAP-V2.md) | The canonical milestone chain; DoD = exact serial markers |
| [docs/spec/yuva-abi-v1.md](docs/spec/yuva-abi-v1.md) | The normative Yuva↔agent contract, boot-enforced |
| [docs/assumptions.md](docs/assumptions.md) | What the proofs do NOT discharge — the residual trusted base |

## Repository layout

```
kernel/             entry shim + the cumulative milestone self-tests (zero unsafe blocks; all real unsafe+asm confined to tb-hal)
crates/             tb-hal (the ONLY unsafe+asm crate), tb-encode (verified leaves), tb-boot, tb-caps-core, brand
tb-vmm/             our own userspace VMM on /dev/kvm (own workspace)
tools/              host-side peers: transport harness, conductor host, infer daemon, corpus export
scripts/            QEMU/KVM launch + the fail-closed serial verdicts (the executable DoD)
docs/               typed, statused docs — start at docs/index.md
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — the engineering discipline
(research-first proposals, verified leaves, honesty tokens, boot-verified PRs)
*is* the contributor guide. The README holds itself to the boot's own standard:
no adjective without a witness.

## License

[PolyForm Noncommercial 1.0.0](LICENSE.md) — source-available; free for
noncommercial use. © 2026 cogitave (Bahadir Arda).

---

<sub>Yuva was developed under the code name **TABOS**; every name-bearing
wire/ABI byte now derives from `crates/brand`, and the `tb-` crate prefix is
history — nothing semantic depends on it. Full naming record:
[docs/VISION.md §5](docs/VISION.md).</sub>
