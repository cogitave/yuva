# Yuva Sovereignty and Clean-Slate Decision

> Status: v1.0 · **All [DECISION]** — no open decisions.
> Question (Arda, 2026-06-07): *"Are we writing the kernel from scratch? It will not be a Linux system, it will be entirely our own build; we will inherit recent academic sources and we are not obliged to carry old bugs."*
> This document answers that question **sourced and honestly**: it draws what is silicon-mandatory, what is a neutral open standard, what is rejected Linux heritage, and what belongs to Yuva.
> Basis: [`cleanslate-research.json`](research/raw/cleanslate-research.json) · [`cleanslate-verified.json`](research/raw/cleanslate-verified.json) · Related: [KERNEL-FOUNDATION-SPEC](KERNEL-FOUNDATION-SPEC.md) · [ARCHITECTURE](ARCHITECTURE.md) · [VISION](VISION.md)

---

## 0. The Clear Answer

**Yes — the kernel is 100% from scratch, entirely Yuva's own build. Zero lines of Linux code, zero Linux *design* inherited.** Yuva is not a Linux system; nor is it "Linux compatible" like Asterinas/Redox — deliberately the opposite: agents are native citizens, no Linux/POSIX compatibility is targeted.

Honesty clause: no OS can escape silicon. The table below draws precisely what is **truly unavoidable** (the CPU itself), what is an **OS-independent open standard**, what is **rejected Linux heritage**, and what is **owned/invented by Yuva**. Conclusion: Yuva owes **nothing** to Linux; it owes a debt to the CPU (Intel/ARM) and to a few neutral standards (virtio=OASIS, devicetree=devicetree.org) — which every OS shares.

> **Sovereignty roadmap (2026-06-07):** "Full sovereignty" is now resolved to land at **L2 — Yuva as its own minimal Type-1 hypervisor** (own VMX/SVM/EL2 + EPT/stage-2 + IOMMU + scheduling, with **no host kernel in the TCB**), **not** L3 (owning every driver). The unavoidable proprietary GPU/CUDA stack is *quarantined* in a confined Linux driver VM, not eliminated. The full L0→L3 ladder, the split-VMM architecture, the IOMMU requirement, the <10K-LOC TCB budget, and the build-ready `tb-vmm` / `tb-boot v0` spec are in [SOVEREIGNTY-ROADMAP](SOVEREIGNTY-ROADMAP.md).

## 1. Sovereignty Boundary — Precise Classification [verified]

| Layer | Category | Authority | What Yuva does |
|---|---|---|---|
| x86_64/aarch64 **instruction set**, register file, **privilege ring/EL** | 🔴 **silicon-mandatory** | Intel SDM / ARM ARM | Complies; isolates it in `tb-hal`. *What runs* in Ring0/EL1 is ours; the *existence* of the ring is silicon |
| **MMU page-table FORMAT** (x86 PML4E bits; aarch64 VMSAv8 descriptor) | 🔴 **silicon-mandatory** | Intel SDM §4.5 / ARM ARM D8 | Emits the format (the MMU walks it in hardware); but frame allocator + mapping policy are 100% Yuva |
| **virtio** ring + wire format | 🟢 **open standard (neutral)** | **OASIS** VIRTIO TC (v1.1/1.2 ratified; v1.3 draft) | Writes virtio-mmio drivers *in its own code*; the in-kernel device model is Yuva-native, virtio is a replaceable driver layer |
| **devicetree (DTB)** / PVH start_info | 🟢 **open standard (neutral)** | devicetree.org / Xen | Writes its own parser; the format is OS-neutral |
| **boot handoff** (which register holds what) | 🔵 **Yuva owns** | VMM's choice (not silicon!) | **tb-boot v0** is our own contract; PVH only at bootstrap |
| **C psABI** (SysV/AAPCS64) at the asm boundary | 🟢 **open standard (neutral)** | System V psABI / ARM | Complies because LLVM+CPU expect it; not Linux, a cross-OS platform ABI |
| **ELF** boot image container | 🟢 **open standard (neutral)** | System V gABI / TIS | Merely the shell the VMM loader parses; the agent format `.taf` is already Yuva-native |
| syscall ABI, **fork/exec/process/PID**, VFS, POSIX, signals, ioctl, errno, fd-int, /proc-text | ⛔ **Linux/Unix heritage — REJECTED** | Linux/Unix tradition | None of it adopted (§4) |
| capability/object-cap security, agent-as-principal, memory-first, DAG-inference | 🟣 **Yuva-novel / neutral-model** | KeyKOS/EROS/seL4 lineage (OS-neutral) | Yuva's core identity |

**Verified hard facts** (14 facts, 11 clean 2-0 + 3 with corrections):
- "Same silicon, three **incompatible** register contracts" — Linux/x86 64-bit `%rsi→boot_params` (64-bit, paging ON), PVH `%ebx→hvm_start_info` (32-bit, paging OFF), Multiboot2 `EAX=0x36d76289,EBX→info` (paging off). → **boot handoff is a free choice, not silicon** (2-0).
- `rust-vmm linux-loader`: *"register handoff is the VMM's job, not a fixed library"* (2-0).
- virtio = **OASIS** TC standard, does not belong to the OS (2-0; correction: v1.3 is still Committee Draft, the ratified ones are 1.1/1.2 — Yuva writes to the ratified version).
- devicetree = OS-neutral "hardware description data structure", devicetree.org TSC (2-0).
- **Correction/reinforcement:** aarch64 "MMU off + DAIF-masked entry" comes from `kernel.org/arm64/booting.html` — this is **Linux's boot contract, not pure silicon**. So with our own VMM (tb-vmm) we define **our own entry condition**; even this is not a debt to Linux, it is a choice.

## 2. Boot Handoff Decision — Maximum Sovereignty [DECISION, revises the prior decision]

**Canonical = `tb-boot v0`:** Yuva's owned, frozen, capability-oriented handoff contract. Our own thin VMM (`tb-vmm`) produces it, `tb-hal` consumes it. Enters directly in 64-bit long mode (we write the VMM's initial register file) → **no trampoline, no Linux, no Xen**. boot_params/PVH/Image header are reduced to **compat shims**.

**`tb-vmm` (owned VMM) [DECISION]:** with the rust-vmm crate set (`kvm-ioctls`, `vm-memory`, `linux-loader`, `vm-superio`, `virtio-queue`, `vm-allocator`, `event-manager`) we build our own thin Mirage-single-vCPU VMM. rust-vmm is a **neutral community** project (Firecracker, crosvm, Cloud Hypervisor use the same crates — not Linux). This gives us the boot contract + machine model + device interface **end-to-end**.

**Bootstrap exception (M0 only, temporary scaffold):** until `tb-vmm` is ready we boot on stock Firecracker. For this we choose **PVH** (Xen-origin, a neutral protocol that **does not carry the Linux name**; `linux-loader` provides it for free) — instead of Linux/x86 zero-page. Because PVH enters in 32-bit, a small, **explicitly-temporary 32→64 trampoline** (`A0`, ~40 lines) lives in `tb-hal` and is **deleted** once `tb-vmm`/`tb-boot` arrive.

> **Revision honesty:** [KERNEL-FOUNDATION-SPEC §0](KERNEL-FOUNDATION-SPEC.md) initially chose **LinuxBoot** — the rationale was only "delete the trampoline". Your sovereignty directive changed the priority: the canonical path (`tb-boot`/`tb-vmm`) is already trampoline-free; in the bootstrap scaffold we accept a neutral PVH + a small trampoline to be deleted instead of a Linux-named contract. Net result: **nowhere in the real system is named/shaped by Linux.** (If the trampoline causes trouble, fallback: Linux/x86 64-bit protocol at bootstrap — again ~30 struct fields, not kernel code.)

## 3. virtio and the Device Model [DECISION]

- virtio is an **OASIS open standard** (not Linux) → adopting it = adopting an open standard. We write virtio-mmio transport + virtio-net/vsock drivers **in our own code** (block optional — an agent OS can be diskless/memory-backed).
- **The in-kernel device model is Yuva-native;** virtio is only a **driver layer**, not a structural bond → replaceable. Long-term `tb-vmm` may offer its own Solo5-style minimal interface.
- PC-legacy emulation (i8042/PIT/PS2/PIC) is **ignored** (except the single register Firecracker uses for reset).

## 4. "We Do Not Carry Old Bugs" — The Concrete Ledger [DECISION]

The sourced counterpart of your statement "we are not obliged to carry old bugs". Design decisions of Linux/Unix that are today widely considered **mistakes**, and Yuva's structural alternative:

| Linux/Unix heritage (rejected) | Source/critique | Yuva structural alternative |
|---|---|---|
| **Ambient authority** (a program runs with all of the user's authority) | Shapiro EROS, Capsicum | Every process asks for a narrow, explicit capability; zero ambient authority (POLA) |
| **fork()** | *"A fork() in the road"*, HotOS'19 (Baumann, Appavoo et al.) | No fork/clone; tasks are **spawn-from-manifest** (Hubris app.toml model) + capability-gated |
| **ioctl** untyped escape | untyped, unauditable | Every op a typed capability invocation (declared method + typed args) |
| **POSIX signals** (broken async primitive) | async-signal-safety nightmare | No signals; typed, queued notification → explicit endpoint, with task draining |
| **Path-based ambient access** (TOCTOU) | designation≠authority | Handles only; designation+authority **coupled** (capability) → TOCTOU structurally absent |
| **Global integer fd table** (forgeable/predictable) | — | Unforgeable capability handles, per-task CSpace, narrow rights |
| **C-string / errno** | thread-local errno, silent failure | Rust-native ABI: typed `Result`, enumerable, **model-readable** error variants |
| **Synchronous-blocking syscall** as the only model | — | Default async capability-invocation; long LLM work submitted as a typed **DAG** |
| **/proc text parsing** fragility | format drift | We define the synthetic agent tree **ourselves**, structural introspection |

This is the concrete side of the thesis of leveraging the fact that recent academic sources (the capability-OS lineage, framekernel, the agent-memory literature) have "solved the progress".

## 5. Sovereign-Kernel Precedents — Where We Fall [DECISION]

| Kernel | What it did | Relative to Yuva |
|---|---|---|
| **seL4** | Its own API, its own boot, not Unix-shaped | Sovereignty precedent (capability lineage) |
| **Theseus** (OSDI'20) | Rejected the traditional process/address-space model, intralingual | Novel-structure precedent |
| **Hubris** (Oxide) | No fork/exec, all tasks static | We took spawn-from-manifest from it (but Yuva is dynamic+capability-gated — static is not enough for a self-evolving OS) |
| **managarm** | From scratch, async-first; Linux-ABI an *optional choice* | We took its async structure, **did not take** its Linux compat |
| **Asterinas** | **Counter-example**: deliberately Linux-ABI compatible | We took the framekernel pattern, **rejected** its Linux-ABI |
| **Redox** | **Counter-example**: deliberately Unix-like | The opposite of Yuva |

**Conclusion:** The decision criterion is "what application-compatibility do you want". Yuva's citizen is the **native agent**; legacy application compat is not required → Yuva owes **nothing** to the Unix/Linux shape. Native execution principal = **LLM agent** (not Unix process / seL4 thread / Hubris task / Theseus cell) — this is Yuva-novel.

## 6. Follow-on Effects (WBS)

- **New milestone `MV — tb-vmm` (owned VMM):** rust-vmm-based thin single-vCPU VMM + the `tb-boot v0` contract. Can be developed in parallel after M0; the canonical target. Landing → the bootstrap PVH path + the `A0` trampoline are deleted.
- **`A0` (new asm unit, bootstrap-only):** PVH 32→64 trampoline; tagged "temporary, deleted in MV" in `tb-hal`.
- M0 DoD updated: stock Firecracker + **PVH** (not Linux zero-page).

---

### Verification note
Of the 14 "is-this-Linux" facts, 11 are 2-0 confirmed; 3 corrections strengthened the sovereignty thesis (aarch64 entry conditions are a Linux boot-contract; virtio v1.3 draft→write to ratified 1.1/1.2; SDM section number is edition-dependent). The boot contradiction (PVH-neutral vs LinuxBoot-trampoline-free) was, per the sovereignty directive, resolved in favor of **tb-boot canonical + PVH bootstrap** (§2). The [DECISION]s will be tested with executable DoD at the prototype M/MV-gates.