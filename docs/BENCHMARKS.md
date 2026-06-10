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
- **boot+selftest** = spawn → the final cumulative marker (now
  `M26: exit-telemetry OK`). This is boot **plus the entire M0…M26 self-test** (M2's
  1000-round ping-pong, M6's ~65 k free-frame `seed()`, M7's three 4 MiB heap
  growths, M8's interrupt canary, M9's ≥100 involuntary switches, the
  M10–M18 isolation / capability / memory / IPC / inference / consolidation /
  evolve / approval-gate / held-out self-tests, then the L2.0…L2.6 aarch64
  EL2-sovereignty chain, and finally M19 virtio-rng / M20 durable-persist /
  M21 dormant-policy / M22 provenance self-tests), so it is labelled separately
  and is **emphatically not** a boot number — it is an exhaustive correctness
  suite that happens to run at boot.

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
  this counter from a `--release` build under KVM (see §6) — and because it is an
  **in-guest** cycle delta it is VMM-independent (`tb-vmm` or QEMU-`microvm` give
  the same guest-only span). **MEASURED (2026-06-09):** the `microvm-kvm` CI
  lane's bench step boots a `--release` build under `-M microvm -accel kvm
  -cpu host` and reports `boot-ready-cycles=0x14a396` = **1,352,598 cycles ≈
  0.5 ms** (§3) — Bucket 1's fast end, peer to Unikraft's sub-ms.
- **`boot-cycles`** = `rust_main` entry → just after the **M8** marker. Spans the
  M0–M8 self-test; a *correctness*-cost gauge, NOT a boot figure.

**Counter-frequency correctness — divide by the MEASURED base, never an inferred
GHz.** A cycle count means nothing without the frequency of the clock that
produced it — and that frequency is **not** the core's GHz. `rdtsc` (x86_64)
ticks at the **invariant-TSC base rate** (read via CPUID leaf `0x15`), not the
turbo core frequency; `CNTPCT_EL0`/`CNTVCT_EL0` (aarch64) tick at the **fixed
`CNTFRQ_EL0` nominal rate** — often 62.5 MHz or 1 GHz under QEMU, *not* the CPU
GHz. So the kernel **reads and prints the counter base on the same boot** (CPUID
`0x15` for x86_64, `CNTFRQ_EL0` for aarch64), and the harness derives wall-time
by dividing the cycle delta by that **measured** base. We never run it backwards
(never "1.35 M cycles ≈ 0.5 ms ⟹ ~2.7 GHz"): inferring a GHz from a cycle/time
pair launders an assumption into a measurement.

| Target | In-guest counter | Measured base (printed same boot) | `boot-ready` (cycles) | `boot-ready` (÷ measured base) | Accel |
|---|---|---|---|---|---|
| x86_64 | `rdtsc` | TSC base via CPUID leaf `0x15` | `0x14a396` = **1,352,598** | ÷ measured TSC base ≈ **0.48–0.52 ms** | `microvm`+KVM, `--release` |
| aarch64 | `CNTPCT_EL0` | `CNTFRQ_EL0` (often 62.5 MHz / 1 GHz under QEMU — **not** CPU GHz) | **KVM/hardware-only** (TCG cycle counts meaningless — see caveat) | KVM / bare-metal-Arm only | KVM / real board |

> Caveat on the harness wall-clock: `bench-boot.sh`'s `full=NA` under
> `qemu -M microvm -accel kvm` is an **untested config for the wall-clock
> harness** — `bench-boot.sh` itself exercises `ci` (QEMU/TCG) and `vmm-boot`
> (our own `tb-vmm`/KVM, which DOES reach the final `M26: exit-telemetry OK`). The
> QEMU-microvm+KVM path now has its **own** required `microvm-kvm` CI lane (it
> boots `-M microvm -accel kvm -cpu host`, asserts the cumulative chain, and is
> where the in-guest `--release` boot-ready figure in §3 is measured); only
> `bench-boot.sh`'s own wall-clock `full` under that accel is still uncaptured, so
> treat that harness `full` as unverified (use the in-guest counter above).

**Accel is auto-detected.** **Only the KVM number is a boot figure.** TCG
(software emulation) inflates boot 10–50× and is reported solely as a portable
upper bound — *never* compared against another system's KVM result. (This is
the single most common way "microVM boot" numbers become accidentally
non-comparable.)

> **aarch64 under TCG is functional-green only — its timing is meaningless.**
> QEMU's TCG is *instruction-accurate, not cycle-accurate*, so aarch64
> boot-time, world-switch, and exit-latency cycle counts taken from the TCG CI
> (where the L2.1 stage-2 chain runs **REAL** on `cortex-a72`,
> `virt,virtualization=on`) verify **correctness**, never **performance**. Every
> aarch64 perf figure on this page must come from a **KVM-accelerated or
> bare-metal Arm host** — an open hardware question (no Arm KVM box in CI yet);
> until one exists the aarch64 lane publishes only the green functional marker
> (`L2.1: stage2 OK`), no quotable latency (§5–§6).

### TABOS measured — today (kernel boots the cumulative M0…M26 self-test then halts)

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
> stays architectural (§4), with the guest-only boot figure now **MEASURED at
> ~0.5 ms** (`--release`, microvm+KVM; §3).

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
| **TABOS** | **~0.5 ms measured** (≈1.35 M cycles, `--release`, KVM) | **guest-only, in-guest rdtsc**: `rust_main` entry → serial-ready (M0 done), BEFORE the M0+ self-test span. `boot-ready-cycles=0x14a396` = **1,352,598 cycles** under `-M microvm -accel kvm -cpu host`, ÷ the **measured TSC base** (CPUID leaf `0x15`, printed on the same boot — never an inferred core GHz; see §2) ≈ **0.48–0.52 ms** (the pre-`rust_main` `_start` asm is a handful of instructions, so first-instr→ready ≈ this + ε). Tiny no_std image, no driver/FS/ACPI/SMP probing — strictly *less* to do than OSv (ZFS) or minimal Linux (SMP/ACPI); lands at Bucket 1's fast end, peer to Unikraft's guest-only sub-ms. | this repo (`microvm-kvm` CI bench step) | medium |

### Bucket 2 — full-stack microVM/VM: (firmware?) + Linux kernel + init (VMM-start → `/sbin/init`)

| System | Boot | Metric / setup | Source | Conf. |
|---|---|---|---|---|
| **AWS Firecracker** | **≤ 125 ms** to `/sbin/init` | VMM fork → guest forks init; m5d.metal/KVM, minimal Linux 4.14. FC's *own* part ~38 ms; VMM→API-ready ≤8 ms | [NSDI'20](https://www.usenix.org/system/files/nsdi20-paper-agache.pdf) | high |
| **Cloud Hypervisor** | **~100–150 ms** (p99 158 ms @1000 VMs) | same NSDI harness | [NSDI'20](https://www.usenix.org/system/files/nsdi20-paper-agache.pdf) | medium |
| **QEMU** fast-boot (microvm+qboot) | **~250 ms class** (~2× FC) | same harness, compressed kernel | [NSDI'20](https://www.usenix.org/system/files/nsdi20-paper-agache.pdf) | high |
| **QEMU q35 + SeaBIOS** | **~245 ms** (exec→userspace) | per-phase: QEMU init 34 ms · SeaBIOS **8.9 ms** · fw→`start_kernel` (decompress) **78.8 ms** · `start_kernel`→init **122 ms** | [Garzarella](https://stefano-garzarella.github.io/posts/2019-08-24-qemu-linux-boot-time/) | low |
| **Alpine** on Firecracker | **~330 ms** | first instr → app (cross-measure) | [arXiv:2104.12721](https://arxiv.org/abs/2104.12721) | medium |
| **Stock Ubuntu kernel** on Firecracker | **~1 s** (+900 ms vs minimal) | *same* Firecracker, stock kernel | [NSDI'20](https://www.usenix.org/system/files/nsdi20-paper-agache.pdf) | high |
| **TABOS** *(band-C, VMM-inclusive — MEASURED)* | **~3.0 ms** (`tb-vmm` spawn → guest boot-ready; median, n=30; p99 ~3.9 ms) | host `clock_gettime` from `tb-vmm` process spawn → the guest's `0x510` boot-ready PIO write (the FC `--boot-timer` analog), on the **SAME** GitHub KVM runner where **Firecracker `v1.12.1`** booting a minimal Linux guest took **~103 ms** (median, n=30; p99 ~184 ms) spawn → its guest's first serial byte — a **~34×** gap. **CAVEAT (load-bearing):** this compares *different guests* — TABOS (no_std, unikernel-class, **no Linux to boot**) vs full Linux — so it reflects "TABOS has no Linux" **+** "`tb-vmm` is thin", **not** a pure VMM-overhead claim (that needs the same trivial guest under both — **see the axis-A row below**, which measures exactly that: **11.1×** on one common nano-guest). Absolute ms are **runner-relative** (nested-virt); only the **same-runner ratio** is the fair cross-system point. The guest-only **0.5 ms** figure (Bucket 1) is a *different* metric class and is **not** comparable to this band. | `bench.yml` CI (`fc6322c`) | medium |
| **TABOS `tb-vmm` vs Firecracker** *(axis-A, TRUE apples-to-apples — MEASURED)* | **11.1×** — `tb-vmm` **13.2 ms** vs Firecracker **146.3 ms** (median, n=30; p99 16.6 / 186.8 ms) | The **same** ~4.8 KiB dual-note PVH + `tb-boot` **nano-guest** (`bench/nano-guest/`) — whose only work is to emit one COM1 line then `hlt` — booted under **both** VMMs on the **same** KVM runner; host `date` from process spawn → the guest's standalone `A` serial line (`grep -qx A`, byte-identical method both sides). **No different-guest confound:** the binary is byte-identical — Firecracker auto-selects PVH from the `.note.Xen` PHYS32_ENTRY note, `tb-vmm` enters 64-bit via the `.note.TABOS` note. `tb-vmm`'s **native in-process `0x510`** clock puts its *internal* spawn at **0.985 ms** (FC has no equivalent, so the ratio uses the host-poll column for both). **Finding:** Firecracker needs ~146 ms to bring even a *trivial* guest to its first instruction — so its cold start is dominated by **VMM spawn/setup**, NOT guest boot. Absolute ms are **runner-relative**; the same-runner **ratio** is the fair cross-system claim. | `bench.yml` axis-A (`c4b7460`) | medium |

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

## 5. L2 world-switch / exit-latency micro-benchmark axis (hardware-only)

Boot time (§1–§4) is one axis; a **microhypervisor** lives or dies on a second,
orthogonal one — **world-switch / exit latency**, the cycles a guest pays to
cross into EL2 and back. This is **not** a boot row and never enters the buckets
of §3; it is reported in **`CNTPCT_EL0` cycles**, on real Arm silicon, against
the canonical microhypervisor exit baseline.

Two paths, both already exercised by the committed L2.0/L2.1 chain:

- **L2.0 — HVC EL1↔EL2 round-trip.** The synchronous-exception world switch: a
  guest `HVC` traps to the EL2 vector, EL2 handles it, `ERET`s back. This is the
  path the **two L2.0 world-switch probes** (printed during the cumulative
  self-test, before `M19`, §2) already walk; the micro-benchmark simply brackets
  it with `CNTPCT_EL0` reads.
- **L2.1 — stage-2 demand-translation round-trip** (the ARM analog of an x86
  EPT-violation): a guest access faults, EL2 takes a stage-2 abort, reads the
  faulting IPA from **`HPFAR_EL2`**, demand-maps the page, and `ERET`-retries the
  faulting instruction. Stage-2 is armed by `HVC #2` and torn down by `HVC #3`;
  the pure encoders are Kani-proven in `tb-encode/{stage2,el2_trap}.rs`, the
  silicon glue lives in `tb-hal/arch/aarch64/{stage2,el2}.rs`, and the green
  marker is `L2.1: stage2 OK`.

**Baseline.** NOVA — the reference ~9 KLOC microhypervisor — reports a
**~3900-cycle VM exit** (x86 VT-x) [[EuroSys'10](https://hypervisor.org/eurosys2010.pdf)].
That cross-ISA number is what a from-scratch EL2 core must be measured against on
this axis — **not** a boot figure, and never placed in the boot buckets.

**Why this axis is hardware-only.** Under QEMU TCG — where the L2.1 chain runs
**REAL** on `cortex-a72`, `virt,virtualization=on`, and is CI-green for
*correctness* — the emulator is instruction-accurate, **not cycle-accurate**, so
a `CNTPCT_EL0` exit-latency count from TCG is meaningless. This axis therefore
stays empty in the TCG CI and is filled only from a **KVM-accelerated or
bare-metal Arm host** (an open hardware question; no Arm KVM box in CI yet). On
the *boot* axis TABOS's peers are Unikraft's sub-ms and OSv's 4–5 ms guest-only
figures [[EuroSys'21](https://arxiv.org/abs/2104.12721); [ATC'14](https://www.usenix.org/conference/atc14/technical-sessions/presentation/kivity)];
on *this* axis the peer is NOVA's exit latency [[EuroSys'10](https://hypervisor.org/eurosys2010.pdf)]
— keeping the two axes apart is itself part of the honesty discipline (§6).

## 6. What we do **not** claim (honesty guardrails)

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
- **Every aarch64 performance number is footnoted as KVM/hardware-sourced —
  never TCG.** QEMU TCG is instruction-accurate, not cycle-accurate, so an
  aarch64 boot, world-switch, or exit-latency cycle count taken under TCG is
  *meaningless as a perf figure* — it verifies correctness only. Until a
  KVM-accelerated or bare-metal Arm host is in CI, the aarch64 lane publishes
  the green functional marker (`L2.1: stage2 OK`) and **no** quotable latency
  (§2, §5).
- **Every cycle figure carries its measured counter base.** A `boot-ready` /
  world-switch / exit-latency cycle count is published only alongside the
  frequency that produced it — the **TSC base** (CPUID leaf `0x15`, x86_64) or
  **`CNTFRQ_EL0`** (aarch64), read and printed on the *same* boot — and
  wall-time is the cycle delta ÷ that **measured** base. We never infer a core
  GHz from a cycle/time pair (§2).
- Figures marked low-confidence (marketing: "<125 ms" bare, "2 orders faster
  than docker", "fastest Wasm VM", "zero cold start") are flagged, never quoted
  bare.

## 7. Reproduce

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
