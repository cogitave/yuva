# TABOS Milestones & Development Pipeline

> Status: the v1 kernel-foundation chain **M0 → M4 is complete and green on both
> architectures** (x86_64 + aarch64), verified by booting under QEMU on every
> change. This document records what each milestone delivers, how it is proven,
> and how the codebase is built and run.
> Related: [KERNEL-FOUNDATION-SPEC](KERNEL-FOUNDATION-SPEC.md) (the assembly plan
> these milestones implement) · [SOVEREIGNTY](SOVEREIGNTY.md) · [BUILD](../BUILD.md).

---

## 1. Architecture in one paragraph

TABOS is a from-scratch, `no_std` Rust kernel with **zero Linux code or design**
inherited (see [SOVEREIGNTY](SOVEREIGNTY.md)). It follows the *framekernel*
pattern: **all `unsafe` and all assembly live in one foundation crate,
`tb-hal`**; every layer above it is compiled with `#![forbid(unsafe_code)]`. The
kernel boots as a guest on a Firecracker/KVM-class virtual machine (for
development we boot it under QEMU). Two architectures are first-class:
**x86_64** (PVH boot) and **aarch64** (PE/Linux Image boot on QEMU `virt`).

```
kernel/                 #![forbid(unsafe_code)] — the entry shim + milestone self-tests
crates/tb-hal/          the ONLY crate where unsafe + asm is allowed
  src/mmu.rs            shared typed page-table layer (PageTable512)
  src/arch/x86_64/      boot, serial, gdt, idt, trap, sched, mmu, user
  src/arch/aarch64/     boot, serial, vectors, trap, sched, mmu, user
targets/*.json          custom no_std target specs (build-std)
kernel/linker/*.ld      per-arch linker scripts
scripts/run-*.sh        QEMU launch + serial-marker assertion (the executable DoD)
```

## 2. The milestone chain (M0 → M4)

Each milestone has an **executable Definition-of-Done (DoD)**: a marker string
the kernel prints over serial once that capability works. The kernel runs the
milestones cumulatively, so every boot is a full regression of M0 through the
latest. Today a successful boot prints all 14 lines below.

| Milestone | Capability | x86_64 mechanism | aarch64 mechanism | DoD marker |
|---|---|---|---|---|
| **M0** | Boot + serial | PVH ELF note → 32→64 trampoline (`A0`) → `rust_main`; 16550 UART @ `0x3F8` | PE image, EL1h entry, `x0`=FDT; PL011 UART @ `0x0900_0000` | `hello from rust_main` |
| **M1** | Traps / exceptions + safe dispatch | permanent GDT+TSS(IST) + 256-entry IDT; `int3` → `__alltraps` → safe hook → `iretq` | `VBAR_EL1` 16×128B table; `brk #0` → ESR_EL1.EC=0x3C → `ELR_EL1+=4` → `eret` | `M1: traps OK` |
| **M2** | Cooperative context switch | naked `ctx_switch` saving SysV callee-saved set; fabricated initial frame | `stp/ldp` x19–x30 + SP; resume via `ret` to x30; entry trampoline + exit guard | `M2: context-switch OK` |
| **M3** | MMU + page tables | splice a 4 KiB mapping into the live boot tables; remap + `invlpg` | **cold MMU bring-up**: MAIR/TCR/TTBR0 → `SCTLR.M\|C\|I`; Break-Before-Make remap + TLBI | `M3: mmu OK` |
| **M4** | User/ring boundary | ring3 via `iretq`; user `int 0x80` through a DPL=3 gate; `TSS.rsp0`; user pages `U/S=1` | EL0 via `eret` (SPSR=EL0t); user `svc #0` → Lower-EL Sync handler; ESR.EC=0x15; pages AP=0b01/AF/UXN | `M4: user/ring OK` |

Full cumulative serial output of a green boot:

```
hello from rust_main
trap-test: triggering breakpoint
trap: breakpoint, resuming
trap-test: resumed past breakpoint
M1: traps OK
ctx-test: starting ping-pong
M2: context-switch OK
mmu-test: init
mmu-test: enabled, serial alive
M3: mmu OK
user-test: entering unprivileged mode
syscall from user: arg=0x000000000000cafe
M4: user/ring OK
```

### What M4 means

The kernel can drop the CPU to its unprivileged mode (x86 ring 3 / aarch64
EL0), run code there on user-accessible pages, and that code can make a syscall
that traps cleanly back into the kernel — observed by a safe-Rust handler with
the user-supplied argument intact. This is the hardware foundation for running
agents and daemons at lower privilege than the kernel.

## 3. Development pipeline

Each milestone was built with the same loop, and the same loop applies going
forward:

1. **Generate** — a multi-agent workflow authors the milestone code against a
   fixed contract plus the verified hardware facts (3 generator agents:
   x86_64 / aarch64 / integration+test).
2. **Adversarially review** — 2 independent reviewer agents check
   privilege/boot/MMU correctness and build/regression, returning concrete
   blockers with fixes.
3. **Apply** — the generated files are written into the tree and reviewer
   findings are applied.
4. **Build** — both architectures are cross-compiled on a Linux host
   (see [BUILD](../BUILD.md)).
5. **Boot & assert** — each arch is booted under QEMU; the run script greps the
   serial output for the milestone marker and fails closed otherwise. This step
   is where real bugs surface (it has repeatedly caught issues a static review
   missed).
6. **Commit** — one conventional commit per milestone.

## 4. Build & run (quickstart)

Full instructions and toolchain bootstrap are in [BUILD.md](../BUILD.md). In
short, on a Linux host (or WSL2) with a Rust nightly that has `rust-src` +
`llvm-tools`, and `qemu-system-x86`/`qemu-system-arm` installed:

```sh
# Build (per arch)
cargo build -p tabos-kernel --target targets/x86_64-tabos-none.json
cargo build -p tabos-kernel --target targets/aarch64-tabos-none.json

# Boot under QEMU and assert the milestone marker (exit 0 = PASS)
bash scripts/run-x86_64.sh
bash scripts/run-aarch64.sh
```

CI runs exactly this matrix on every push — see
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

### The run scripts

- `scripts/run-x86_64.sh` — boots the PVH ELF under QEMU `microvm` (the machine
  type Firecracker is modelled on), wires the 16550 COM1 to stdio, and asserts
  the marker. Uses KVM only if `/dev/kvm` is usable; otherwise pure TCG, so it
  runs in any CI box without nested virtualization.
- `scripts/run-aarch64.sh` — boots under QEMU `virt` (`cortex-a72`), PL011
  serial on stdio, same marker assertion.

Both bound the run with a wall-clock timeout (the kernel halts after the last
milestone rather than exiting), so a missing marker is always a non-zero exit.

## 5. What's next

- **MV — `tb-vmm`** (the **L1** sovereignty rung): the project's own thin
  **userspace** VMM on the rust-vmm crates, producing the sovereign `tb-boot v0`
  contract that enters the guest directly in 64-bit long mode (deleting the
  bootstrap PVH note + the `A0` trampoline). Build-ready: verified `KVM_SET_SREGS`
  long-mode constants + the aarch64 `KVM_ARM_VCPU_INIT` path, one console device.
  Needs a Linux host with `/dev/kvm` (the GitHub Actions Linux runners qualify).
  See [SOVEREIGNTY-ROADMAP §7](SOVEREIGNTY-ROADMAP.md).
- **L2 — `tb-core`** (the **north-star**): TABOS as its own minimal Type-1
  microhypervisor (own VMX/SVM/EL2 + EPT/stage-2 + IOMMU + scheduling, <10K-LOC
  TCB), with the proprietary GPU/CUDA stack quarantined in a confined Linux driver
  VM. This is where "full sovereignty" lands. See
  [SOVEREIGNTY-ROADMAP](SOVEREIGNTY-ROADMAP.md).
- **v2 layers**: the agent-native subsystems proper — the default memory tiers
  ([MEMORY-SPEC](MEMORY-SPEC.md)), the agent runtime and scheduler
  ([AGENTS-SPEC](AGENTS-SPEC.md)), the self-improvement service
  ([SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md)), and the inter-agent IPC
  layer.
- **G0 spec-freeze**: closing the remaining P0 open questions
  ([OPEN-QUESTIONS](OPEN-QUESTIONS.md)) before freezing the v1 ABI.
