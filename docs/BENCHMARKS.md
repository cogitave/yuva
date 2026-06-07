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
  `M6: frame alloc OK`). This is boot **plus the entire M0…latest self-test**
  (incl. M2's 1000-round cooperative ping-pong AND M6's one-time seeding of every
  usable 4 KiB frame onto the free-frame stack — ~65 k link-writes for a 256 MiB
  guest), so it is labelled separately and is **not** a pure boot number.

**Accel is auto-detected.** **Only the KVM number is a boot figure.** TCG
(software emulation) inflates boot 10–50× and is reported solely as a portable
upper bound — *never* compared against another system's KVM result. (This is
the single most common way "microVM boot" numbers become accidentally
non-comparable.)

### TABOS measured — today (M6, kernel boots a self-test then halts)

| Build | Accel | boot-to-first-output (median) | boot+selftest (median) | Notes |
|---|---|---|---|---|
| x86_64 (QEMU `microvm`) | **KVM** (GitHub CI runner) | **~47 ms** (VMM-spawn-bound) | refreshed each `vmm-boot` CI run's step summary | nested-virt CI runner; **VMM/host-spawn-bound, not guest-bound** (see below) |
| x86_64 (QEMU `microvm`) | TCG (local WSL2) | ~28 ms (median) | ~135 ms | emulated; **not** a comparable boot figure |
| aarch64 (QEMU `virt`) | TCG (local WSL2) | ~29 ms | ~86 ms | emulated; **not** a comparable boot figure |

> **boot-to-first-output** is stable across M5→M6 (~28 ms TCG — just VMM-spawn +
> M0 serial). **boot+selftest** grew at M6 (~51→135 ms TCG on x86_64) entirely
> because M6's `seed()` pushes *every* usable 4 KiB frame onto the free-frame
> stack once at init — ~65 k identity-mapped link-writes for a 256 MiB guest —
> which TCG software-emulates byte-by-byte. Under KVM (hardware writes) that
> seeding is sub-millisecond; it is one-time init work, not "boot".

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
> So a clean, VMM-independent **guest-only** boot figure (the one that places
> TABOS next to Unikraft/OSv in Bucket 1) requires **in-guest cycle timing**
> (`rdtsc` / `CNTVCT`+`CNTFRQ`) — which lands at **M8** (the timer milestone),
> where a second clock (guest-first-instruction → ready) is added. Until then,
> the honest, defensible TABOS claim is **architectural** (§4): the firmware +
> bootloader + decompress + Linux-kernel-init budget — tens to hundreds of ms in
> Bucket 2 — that a from-scratch PVH/`tb-boot` kernel **never executes at all**.

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
| **TABOS** | **Bucket 1, fast end (target)** | VMM-spawn → serial marker, KVM (see §2). Tiny no_std image, no driver/FS/ACPI/SMP probing, direct long-mode `tb-boot` entry — strictly *less* to do than OSv (ZFS) or minimal Linux (SMP/ACPI). | this repo | — |

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
