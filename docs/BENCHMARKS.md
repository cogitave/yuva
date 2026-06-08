# TABOS Benchmarks — boot time

> Why an agent-native OS measures boot time at all: an agent's cold-start
> latency is the floor on how fast a new agent (or a fresh per-task sandbox) can
> begin thinking. Dense, multi-tenant agent fleets live or die on it. So from M5
> onward TABOS measures its own boot time on every change, and compares — *
> honestly, with cited sources and matched metrics* — against the systems it
> competes with. This file is generated/maintained by the milestone pipeline
> (`.claude/skills/tabos-milestone`); the harness is
> [`scripts/bench-boot.sh`](../scripts/bench-boot.sh); raw cited data is
> [`research/raw/bootbench-research.json`](../research/raw/bootbench-research.json).

## 1. The one rule that makes boot numbers comparable

Published "boot time" figures span **at least five incompatible start→end
definitions**, and most of the spread *between projects* is metric choice, not
kernel speed. Before any number goes on a chart it must declare: **(a)** the
exact start and end events, **(b)** the setup (CPU, VMM, **KVM vs TCG**,
vCPU/RAM, page backing), **(c)** the source. We refuse to compare across metric
classes. The classes:

1. **Guest-only kernel boot** — first guest instruction → `main()`/ready
   (Unikraft's metric, Firecracker `--boot-timer`, Zephyr `_start→main`).
   *Tens of µs to low-single-digit ms. Excludes the VMM.*
2. **Full-stack microVM boot** — VMM process fork → guest forks `/sbin/init`
   (the Firecracker NSDI'20 metric). *~100–250 ms, almost all of it a real
   Linux kernel + the VMM.*
3. **Per-phase firmware/bootloader trace** — isolates exactly the phases a
   PVH/direct-boot guest removes (SeaBIOS/OVMF/GRUB/decompress).
4. **End-to-end product orchestration** — host setup + API + boot + app init
   (AWS Lambda 100 ms–1 s+; NumaVM ~1.13 s).
5. **Container/sandbox/Wasm cold start** — *no guest kernel boots at all*
   (runc/gVisor ~1 s lifecycle; Wasmtime ~5 µs; V8 isolate <5 ms).

## 2. How TABOS measures its own boot

[`scripts/bench-boot.sh`](../scripts/bench-boot.sh) records wall-clock from the
**VMM/QEMU process spawn** to two serial events (matching class **2**'s
convention — VMM-start as t0):

- **boot-to-first-output** = spawn → the first guest serial byte
  (`hello from rust_main`). The purest boot figure: VMM init + kernel entry +
  M0 serial bring-up.
- **boot+selftest** = spawn → the final cumulative marker (currently
  `M18: evolve OK`). This is boot **plus the entire M0…M18 self-test** (M2's
  1000-round ping-pong, M6's ~65 k free-frame `seed()`, M7's three 4 MiB heap
  growths, M8's interrupt canary, M9's ≥100 involuntary switches, and the
  M10–M18 isolation / capability / memory / IPC / inference / consolidation /
  evolve self-tests), so it is labelled separately and is **emphatically not** a
  boot number — it is an exhaustive correctness suite that happens to run at boot.

**In-guest cycle counters (the VMM-independent, honest guest-only figures).**
The kernel reads `rdtsc` (x86_64) / `CNTPCT_EL0` (aarch64) at `rust_main` entry
and prints two deltas on serial — these exclude the VMM/host floor entirely:

- **`boot-ready-cycles`** = `rust_main` entry → **serial up (M0 done), before any
  self-test**. This is the unikernel-class *first-guest-instruction → ready*
  figure (the apples-to-apples metric vs Unikraft ~1 ms / OSv ~4–5 ms, **class 1**).
  Measured: it is a *tiny fraction of a percent* of the self-test span — e.g.
  locally under TCG, `boot-ready` ≈ 2.0 M cycles (x86_64) vs the `boot-cycles`
  self-test span ≈ 5.2 B (≈0.04 %); aarch64 ≈ 32 k vs ≈ 63 M — i.e. **TABOS's
  actual boot is essentially instantaneous; every large number elsewhere on this
  page is self-test work or the VMM floor, not boot.** The quotable figure is
  this counter from a `--release` build under KVM (see §5) — and because it is an
  **in-guest** cycle delta it is VMM-independent (`tb-vmm` or QEMU-`microvm` give
  the same guest-only span). **MEASURED (2026-06-09):** the `microvm-kvm` CI
  lane's bench step boots a `--release` build under `-M microvm -accel kvm
  -cpu host` and reports `boot-ready-cycles=0x14a396` = **1,352,598 cycles ≈
  0.5 ms** (§3) — Bucket 1's fast end, peer to Unikraft's sub-ms.
- **`boot-cycles`** = `rust_main` entry → just after the **M8** marker. Spans the
  M0–M8 self-test; a *correctness*-cost gauge, NOT a boot figure.

> Caveat on the harness wall-clock: `bench-boot.sh`'s `full=NA` under
> `qemu -M microvm -accel kvm` is an **untested config** — CI exercises `ci`
> (QEMU/TCG) and `vmm-boot` (our own `tb-vmm`/KVM, which DOES reach
> `M18: evolve OK`); the QEMU-microvm+KVM path is not yet a CI lane, so treat its
> `full` as unverified until that lane (or the in-guest counter above) lands.

**Accel is auto-detected.** **Only the KVM number is a boot figure.** TCG
(software emulation) inflates boot 10–50× and is reported solely as a portable
upper bound — *never* compared against another system's KVM result. (This is
the single most common way "microVM boot" numbers become accidentally
non-comparable.)

### TABOS measured — today (M8, kernel boots a self-test then halts)

| Build | Accel | boot-to-first-output (median) | boot+selftest (median) | Notes |
|---|---|---|---|---|
| x86_64 (QEMU `microvm`) | **KVM** (GitHub CI runner) | **~47 ms** (VMM-spawn-bound) | refreshed each `vmm-boot` CI run's step summary | nested-virt CI runner; **VMM/host-spawn-bound, not guest-bound** (see below) |
| x86_64 (QEMU `microvm`) | TCG (local WSL2) | ~28 ms (median) | ~1.09 s | emulated; **not** a comparable boot figure |
| aarch64 (QEMU `virt`) | TCG (local WSL2) | ~28 ms | ~1.16 s | emulated; **not** a comparable boot figure |

> **boot-to-first-output** is stable across M5→M8 (~28 ms TCG — just VMM-spawn +
> M0 serial). **boot+selftest** keeps growing as each milestone adds *self-test*
> work that TCG emulates byte-by-byte: M6 added ~65 k free-frame `seed()`
> link-writes (~51→135 ms), and M7's self-test allocates + page-table-maps +
> writes + reads back **three 4 MiB buffers (12 MiB)** through the growable
> kernel-heap window — ~3 k frame mappings plus 24 MiB of pattern traffic — which
> pushes the TCG figure to ~1.1 s. **None of this is "boot":** it is one-time
> init + an exhaustive correctness self-test, all hardware-fast under KVM (the
> guest boot to first output is unchanged at ~28 ms). The honest TABOS claim
> stays architectural (§4), measured guest-only at M8.

> **Read these numbers correctly — they measure the harness's t0 (VMM process
> spawn), not the TABOS kernel.** The clearest evidence: the KVM run on the CI
> box (~47 ms) is *slower* than local TCG emulation (~26 ms). A faster CPU +
> hardware virt producing a *larger* number is only possible if the figure is
> dominated by **QEMU process startup + (on CI) nested-KVM overhead on a
> contended shared runner**, not by the guest — exactly the methodology trap §1
> warns about. The TABOS kernel itself (a few-KB uncompressed image, no firmware,
> no bootloader, no decompress, direct long-mode entry) is a *small fraction* of
> either number; the wall-clock is the VMM/host floor every guest on that host
> shares. (Caveat: the harness reliably times first-output but currently captures
> the final marker on only some fast-KVM runs — `n=4/20` above — because under
> KVM the whole self-test streams out before the reader settles; this is a
> harness-robustness limitation, tracked, not a kernel issue.)
>
> A clean, VMM-independent **guest-only** boot figure (the one that places TABOS
> next to Unikraft/OSv in Bucket 1) needs **in-guest cycle timing** — which
> **landed at M8**: `tb_hal::read_cycle_counter()` reads `rdtsc` (x86_64) /
> `CNTPCT_EL0` (aarch64), the kernel samples it at `rust_main` entry and just
> after the `M8: timer OK` marker, and prints the guest-only delta as a
> `boot-cycles=0x…` serial line — a monotonic span (vCPU-first-instruction →
> M0..M8 self-test done) independent of the VMM/host floor. The next refinement
> is a true guest-first-instruction → agent-ready second clock once an
> agent-ready state exists. The standing architectural claim (§4) is unchanged:
> the firmware + bootloader + decompress + Linux-kernel-init budget — tens to
> hundreds of ms in Bucket 2 — that a from-scratch PVH/`tb-boot` kernel **never
> executes at all**.

## 3. The comparison — grouped so it is apples-to-apples

Three buckets. TABOS is a **Bucket 1** system (a from-scratch unikernel-class
kernel). Bucket 2 is what TABOS *avoids the init cost of*; Bucket 3 is a
different model entirely (shared host kernel) and is context only.

### Bucket 1 — kernel-only, no firmware (guest first-instruction → ready) · *TABOS's peer group*

| System | Boot | Metric / setup | Source | Conf. |
|---|---|---|---|---|
| **Unikraft** | **~1 ms / sub-ms** (Firecracker) | first guest instr → `main()`, i7-9700K/KVM | EuroSys'21, [arXiv:2104.12721](https://arxiv.org/abs/2104.12721) | high |
| **MirageOS** | **1–2 ms** (Solo5) | first instr → `main()` (Unikraft cross-measure); Jitsu NSDI'15 | [NSDI'15](https://www.usenix.org/conference/nsdi15/technical-sessions/presentation/madhavapeddy) | high |
| **LightVM** | **~2 ms** (Xen, no-op unikernel) | optimized Xen toolstack boot | [SOSP'17](https://doi.org/10.1145/3132747.3132763) | medium |
| **OSv** | **4–5 ms** (Firecracker) | first instr → `main()`, read-only rootfs (cross-measure); ATC'14 origin | [ATC'14](https://www.usenix.org/conference/atc14/technical-sessions/presentation/kivity) | high |
| Minimal **custom Linux** | **6 ms** (Firecracker `--boot-timer`) | vCPU start → userland MMIO write; SMP off, 2 MiB hugepages | [davidv.dev](https://blog.davidv.dev/posts/minimizing-linux-boot-times/) | low |
| **Hermitux** | **30–32 ms** (uHyve) | boot → application (cross-measure) | [arXiv:2104.12721](https://arxiv.org/abs/2104.12721) | medium |
| **TABOS** | **~0.5 ms measured** (≈1.35 M cycles, `--release`, KVM) | **guest-only, in-guest rdtsc**: `rust_main` entry → serial-ready (M0 done), BEFORE the M0+ self-test span. `boot-ready-cycles=0x14a396` = **1,352,598 cycles** under `-M microvm -accel kvm -cpu host`, ÷ a ~2.6–2.8 GHz runner ≈ **0.48–0.52 ms** (the pre-`rust_main` `_start` asm is a handful of instructions, so first-instr→ready ≈ this + ε). Tiny no_std image, no driver/FS/ACPI/SMP probing — strictly *less* to do than OSv (ZFS) or minimal Linux (SMP/ACPI); lands at Bucket 1's fast end, peer to Unikraft's guest-only sub-ms. | this repo (`microvm-kvm` CI bench step) | medium |

### Bucket 2 — full-stack microVM/VM: (firmware?) + Linux kernel + init (VMM-start → `/sbin/init`)

| System | Boot | Metric / setup | Source | Conf. |
|---|---|---|---|---|
| **AWS Firecracker** | **≤ 125 ms** to `/sbin/init` | VMM fork → guest forks init; m5d.metal/KVM, minimal Linux 4.14. FC's *own* part ~38 ms; VMM→API-ready ≤8 ms | [NSDI'20](https://www.usenix.org/system/files/nsdi20-paper-agache.pdf) | high |
| **Cloud Hypervisor** | **~100–150 ms** (p99 158 ms @1000 VMs) | same NSDI harness | [NSDI'20](https://www.usenix.org/system/files/nsdi20-paper-agache.pdf) | medium |
| **QEMU** fast-boot (microvm+qboot) | **~250 ms class** (~2× FC) | same harness, compressed kernel | [NSDI'20](https://www.usenix.org/system/files/nsdi20-paper-agache.pdf) | high |
| **QEMU q35 + SeaBIOS** | **~245 ms** (exec→userspace) | per-phase: QEMU init 34 ms · SeaBIOS **8.9 ms** · fw→`start_kernel` (decompress) **78.8 ms** · `start_kernel`→init **122 ms** | [Garzarella](https://stefano-garzarella.github.io/posts/2019-08-24-qemu-linux-boot-time/) | low |
| **Alpine** on Firecracker | **~330 ms** | first instr → app (cross-measure) | [arXiv:2104.12721](https://arxiv.org/abs/2104.12721) | medium |
| **Stock Ubuntu kernel** on Firecracker | **~1 s** (+900 ms vs minimal) | *same* Firecracker, stock kernel | [NSDI'20](https://www.usenix.org/system/files/nsdi20-paper-agache.pdf) | high |

### Bucket 3 — container/sandbox/FaaS/Wasm cold start (no guest kernel) · *context only*

| System | Cold start | Metric | Source | Conf. |
|---|---|---|---|---|
| Docker / runc | ~1.0 s | full create+destroy lifecycle | [HotCloud'19](https://www.usenix.org/conference/hotcloud19/presentation/young) | high |
| gVisor (runsc) | ~1.1 s | same lifecycle, ~10% over runc | [HotCloud'19](https://www.usenix.org/conference/hotcloud19/presentation/young) | high |
| AWS Lambda | 100 ms – 1 s+ | Init phase (on a Firecracker microVM) | [AWS docs](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtime-environment.html) | medium |
| Wasmtime | **~5 µs** | instantiate pre-compiled module (no OS) | [Bytecode Alliance](https://bytecodealliance.org/articles/wasmtime-10-performance) | medium |
| V8 isolates / Cloudflare Workers | <5 ms | isolate warm-up (no OS) | [Cloudflare](https://blog.cloudflare.com/eliminating-cold-starts-with-cloudflare-workers/) | low |

## 4. Why a from-scratch PVH / `tb-boot` kernel starts ahead

The genuine, defensible TABOS win is the **firmware + bootloader + decompress +
Linux-kernel-init budget it simply never pays.** A legacy
`SeaBIOS/OVMF → GRUB → compressed bzImage` path spends, *before the kernel's
first instruction*:

- **Firmware:** SeaBIOS ~9 ms stripped (up to ~150 ms default), or OVMF/UEFI —
  the heaviest (SEC→PEI→DXE→BDS plus decompressing the main firmware volume into
  RAM before any kernel loads).
- **Bootloader:** a general-purpose loader's dominant cost is its menu/timeout —
  U-Boot 2.9 s default (~83 ms stripped); **GRUB's `GRUB_TIMEOUT` is the
  identical trap** — plus device/FS/EFI-loader probing.
- **Decompression:** bzImage self-decompress ~78 ms (Garzarella's q35 run).

A Firecracker / QEMU-`microvm` / **PVH direct-boot** guest collapses that whole
budget to **~0–20 ms** (qboot ~20 ms; a true PVH/direct *uncompressed* image
~0). TABOS is built precisely for this: its dual ELF entry notes (Xen PVH for
QEMU/Firecracker, the TABOS note for `tb-vmm`) mean **no SeaBIOS/OVMF, no
real-mode stub, no GRUB, no self-decompress** (tiny uncompressed image). Its
`t0` is essentially *"the vCPU starts executing TABOS"* — there is no firmware
tax to pay. Within Bucket 1, guest-only boot is determined by *image size +
work-before-ready*, not language: a no_std kernel with no driver probing, no
module loading, no FS mount, and a direct long-mode entry has strictly less to
do than OSv (ZFS rootfs) or minimal Linux (which had to *disable SMP* and use
huge pages just to reach 6 ms). So TABOS belongs at Bucket 1's fast end, and
runs **orders of magnitude** below any full-Linux microVM (Bucket 2's
18–330 ms) — because most of *their* time is Linux kernel init that a
from-scratch kernel never runs.

## 5. What we do **not** claim (honesty guardrails)

- **We never compare a TCG number against another system's KVM number.** TCG
  inflates boot 10–50×.
- **We do not claim to beat the shared VMM floor.** Firecracker's fork + KVM
  setup + vCPU bring-up (~3 ms on Firecracker/Solo5 per Unikraft; ~38 ms
  `InstanceStart` on a less-tuned path) is **VMM-bound and shared** — a 0.3 ms
  guest cannot make it disappear. Any guest on Firecracker inherits it.
- **We never headline a guest-only µs figure against a competitor's end-to-end
  ms figure.** That exact metric mismatch is what makes most published unikernel
  boot claims non-comparable.
- **TABOS today boots a self-test and halts** — it has no userspace/agent-ready
  state yet, so the only honest metric right now is *VMM-start → serial marker,
  KVM*. When TABOS gains an agent-ready state, the second clock
  (guest-first-instruction → agent-ready) is added and reported alongside.
- **Quotable figures come from a `--release` build under `tb-vmm`, timed by an
  in-guest cycle counter — never a `debug` build or QEMU wall-clock.** (Standing
  rule, 2026-06-07.) A `debug/tabos-kernel` wall-clock number under QEMU/KVM
  conflates three things we do *not* want in a TABOS figure: unoptimized guest
  code, QEMU's heavyweight device-model VMM floor (tens of ms vs Firecracker's
  ~6 ms thin-VMM floor — i.e. **a QEMU wall-clock can be *slower* than
  Firecracker purely from the VMM, telling us nothing about TABOS**), and host
  scheduling noise. The defensible number is **`rdtsc` (x86_64) / `CNTPCT_EL0`
  (aarch64) read in-guest, release build, under `tb-vmm`** — which **landed at
  M8**: `tb_hal::read_cycle_counter()` is sampled at `rust_main` entry and just
  after the `M8: timer OK` marker, and the kernel prints the guest-only
  `boot-cycles=0x…` delta. `boot-to-first-output` under QEMU/KVM remains only a
  coarse, VMM-floor-dominated sanity figure, not a competitor comparison.
- Figures marked low-confidence (marketing: "<125 ms" bare, "2 orders faster
  than docker", "fastest Wasm VM", "zero cold start") are flagged, never quoted
  bare.

## 6. Reproduce

```bash
# Build, then benchmark (auto KVM if /dev/kvm is usable, else TCG):
cargo kbuild --target targets/x86_64-tabos-none.json
ITER=20 bash scripts/bench-boot.sh x86_64        # add FORCE_ACCEL=kvm to require KVM
ITER=20 bash scripts/bench-boot.sh aarch64

# CI records the KVM number on every push: .github/workflows/vmm-boot.yml
# (job "tb-vmm boot" → step "Boot-time benchmark (QEMU, KVM-accelerated)").
```

The harness prints a human summary on stderr and a machine-readable JSON line on
stdout. The most reproducible external templates we model on:
[Garzarella's `qemu-boot-time`](https://stefano-garzarella.github.io/posts/2019-08-24-qemu-linux-boot-time/)
(perf `kvm_pio` trace points) and Firecracker's `--boot-timer` MMIO timestamp —
both have explicit start/end events.
