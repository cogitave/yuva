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

### MV — owned boot via `tb-vmm` (the L1 sovereignty rung)

M0–M4 above boot under QEMU using the bootstrap **PVH** ELF note (and, on x86_64,
the 32→64 `A0` trampoline). **MV** removes that external dependency from the boot
path: the project ships its own thin **userspace** VMM, [`tb-vmm`](../tb-vmm/),
built on the rust-vmm crates (`kvm-ioctls`, `kvm-bindings`, `vm-memory`), which
boots the *same* kernel through the project's own **`tb-boot v0`** contract —
entering the guest **directly in 64-bit long mode** with page tables, GDT, and a
`TbBootInfo` block that `tb-vmm` itself programs via `KVM_SET_SREGS`/`KVM_SET_REGS`.

To support both paths, the kernel now carries **two** ELF entry notes (see
`crates/tb-hal/src/arch/x86_64/boot.rs` and the [`tb-boot`](../crates/tb-boot/)
ABI crate):

| Note | Owner / type | Entry | Used by |
|---|---|---|---|
| Xen PVH | `Xen` / `0x12` (`XEN_ELFNOTE_PHYS32_ENTRY`) | `_start` (32-bit) | QEMU `-kernel`, Firecracker |
| TABOS tb-boot | `TABOS` / `0x54420001` (`TB_NOTE_TYPE_ENTRY64`) | `_tb_start` (64-bit) | `tb-vmm` |

`tb-vmm` resolves the **TABOS note only** — it refuses to fall back to `e_entry`
(which is the 32-bit PVH `_start`, and would triple-fault if entered in long
mode). The DoD is unchanged and shared: a `tb-vmm` boot must print the same
`M4: user/ring OK` marker, proving the entire M0–M4 stack runs **identically**
under the project's own VMM + boot contract. Because the host VMM needs
`/dev/kvm`, its CI job (`.github/workflows/vmm-boot.yml`) runs on the GitHub
Actions Linux runners; the WSL2 dev box has no nested virt, so locally `tb-vmm`
is exercised by its unit tests (ELF loader, boot-info serialisation, device bus)
plus the `tb-boot` ABI tests. Status: **implemented and green** (kernel boots
M0–M4 under both PVH/QEMU and tb-boot/tb-vmm). The next rung, **L2**, replaces
the host kernel's KVM with the project's own Type-1 microhypervisor —
see [SOVEREIGNTY-ROADMAP](SOVEREIGNTY-ROADMAP.md).

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
cargo kbuild --target targets/x86_64-tabos-none.json
cargo kbuild --target targets/aarch64-tabos-none.json

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

- **MV — `tb-vmm`** (the **L1** sovereignty rung) — **done.** The project's own
  thin **userspace** VMM on the rust-vmm crates now boots the kernel through the
  sovereign `tb-boot v0` contract (64-bit long-mode entry; no PVH note, no `A0`
  trampoline on that path). Implemented and green; see **§2 → "MV — owned boot
  via `tb-vmm`"** above. Remaining follow-up: an aarch64 `tb-vmm` arch backend
  (`KVM_ARM_VCPU_INIT`) — today `tb-vmm` configures the x86_64 vCPU only.
- **L2 — `tb-core`** (the **north-star**): TABOS as its own minimal Type-1
  microhypervisor (own VMX/SVM/EL2 + EPT/stage-2 + IOMMU + scheduling, <10K-LOC
  TCB), with the proprietary GPU/CUDA stack quarantined in a confined Linux driver
  VM. This is where "full sovereignty" lands. See
  [SOVEREIGNTY-ROADMAP](SOVEREIGNTY-ROADMAP.md).
- **v2 — the agent-native milestone chain (M5 → M18)**: the active track. M0–M4
  built the hardware foundation; v2 turns it into the agent-native OS the four
  pillars describe — dynamic memory (M5–M7), preemption (M8–M9), address spaces
  (M10), the capability-based syscall ABI (M11 — whose rights-subset /
  no-confused-deputy invariant is now machine-proven by Kani over the
  host-verifiable `crates/tb-caps-core` (the SAME Rights/CapTable code the kernel
  runs), CI marker `M11: caps-subset PROVEN`), the agent runtime (M12), the
  default tiered memory substrate (M13/M15/M17), inter-agent IPC (M14), the
  LLM-agnostic inference bridge (M16), and the frozen-kernel self-improvement
  harness (M18). Each is one cumulative serial-marker DoD under the same QEMU +
  tb-vmm harness. The full, sequenced, risk-analysed plan — with the exact DoD
  marker and framekernel `unsafe` placement per milestone — is
  **[ROADMAP-V2](ROADMAP-V2.md)**. Currently building **M5** (`M5: alloc OK`).
- **L2 — `tb-core`** (the **north-star**, parallel track): TABOS as its own
  minimal Type-1 microhypervisor; where "full sovereignty" lands. See
  [SOVEREIGNTY-ROADMAP](SOVEREIGNTY-ROADMAP.md).
- **G0 spec-freeze**: closing the remaining P0 open questions
  ([OPEN-QUESTIONS](OPEN-QUESTIONS.md)) before freezing the v1 ABI.
