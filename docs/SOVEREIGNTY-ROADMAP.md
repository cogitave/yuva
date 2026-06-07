# TABOS Sovereignty Roadmap

> Status: v1.0 — all items are **[DECISION]** (no open "should we"); resolved from
> a 7-area research wave whose 18 hard facts each passed 2-vote adversarial
> verification.
> Answers the question: *what does "full sovereignty" concretely mean for TABOS,
> where does it land, and in what order do we get there?*
> Source data: [`sovereignty-research.json`](../research/raw/sovereignty-research.json) ·
> [`sovereignty-verified.json`](../research/raw/sovereignty-verified.json) ·
> Builds on: [SOVEREIGNTY](SOVEREIGNTY.md) · [KERNEL-FOUNDATION-SPEC](KERNEL-FOUNDATION-SPEC.md) · [MILESTONES](MILESTONES.md)

---

## 0. The headline decision

**Full sovereignty lands at L2 — TABOS as its own minimal Type-1 hypervisor — not
at L3 (owning every device driver).** The real sovereignty win is *removing the
host kernel from the trusted computing base*: owning the CPU-virtualization layer
(VMX / SVM / EL2), second-stage memory translation (EPT / NPT / stage-2), the
isolation boundary, the IOMMU, and scheduling — directly on the silicon
extensions, with **no host kernel underneath**. That is fully achieved at L2.

Owning real drivers (L3) is a *separate, optional, and largely infeasible*
burden, and — decisively — **even the canonical Type-1 hypervisor (Xen) refuses to
own drivers**: it keeps them in a `dom0` driver domain. We copy that. Sovereignty
is therefore **OWN + CONFINE, not reimplement**: TABOS owns the machine, the
hypervisor, scheduling, memory, agents, and policy; the unavoidable proprietary
GPU/CUDA stack and the unstable mass of device drivers are *confined* to a
least-privileged, disposable Linux driver VM that TABOS controls.

## 1. The sovereignty ladder (L0 → L3)

| Rung | What it is | TABOS owns | Still depends on | Real cost |
|---|---|---|---|---|
| **L0** *(today)* | Guest on a stock third-party VMM (Firecracker/QEMU) | nothing below the guest boundary | host Linux + KVM + VMM + firmware (all in TCB) | none — but zero sovereignty |
| **L1** *(MV milestone)* | Own thin **userspace** VMM (`tb-vmm`) on the host's `/dev/kvm` | boot contract + machine model + device model | host Linux still owns hardware + KVM (still in TCB) | low — proven path |
| **L2** *(north-star)* | Own **Type-1 microhypervisor** (VMX/SVM/EL2 directly, **no host kernel**) | the virtualization layer + EPT/stage-2 + IOMMU + scheduling | firmware floor (UEFI/SMM/ME/PSP) only | high — new privileged silicon code |
| **L3** *(descoped)* | Own all native device drivers (no virtualization for itself) | + real NVMe/NIC/USB drivers | proprietary GPU firmware regardless | very high — and **does not remove the GPU tax** |

**Resolution:** L1 now → L2 is the north-star → **L3 is gated behind a concrete
security-identity test, not sovereignty maximalism** (pursue L3 only if owning the
silicon directly is itself the product). The strongest sovereignty-driven teams
(Oxide) and the smallest production hypervisors (Google pKVM) all stop at the L2
shape and delegate drivers downward.

## 2. Why L2 is the real line (verified precedents)

- **Type-1 vs Type-2 is the dividing line.** Xen is *"an open-source type-1 or
  baremetal hypervisor … the first program running after the bootloader exits"*;
  KVM (and thus any `/dev/kvm` VMM) is hosted and *"delegates workload scheduling
  to the host kernel."* Removing that host kernel from the TCB is the L1→L2 jump.
- **A sovereign hypervisor can be tiny.** Google **pKVM** (protected KVM, shipped
  on Android) is a ~10k-LOC EL2 monitor with *"three orders of magnitude less
  attack surface compared to the entire Linux kernel (roughly 10 thousand versus
  20 million lines of code)"* — and it still *delegates scheduling, physical
  interrupt handling, and the device model to the host*. **NOVA/Hedron** is *"a
  microhypervisor [combining] microkernel and hypervisor functionality [with] an
  extremely small trusted computing base,"* capability-based, running each VM from
  *"a virtual machine monitor running in user space."*
- **Even a Type-1 does not own drivers.** Xen: *"A special domain, called domain 0
  contains the drivers for all the devices in the system."* L3 is optional.

**Lesson, adopted:** own only what defines your security and identity (the tiny
privileged core + boot contract + agent model); reuse the commodity mechanism for
everything else.

## 3. The split-VMM architecture [DECISION]

Every minimal-TCB precedent **splits** the tiny privileged core from an untrusted
userspace device model. TABOS does the same at every rung:

```
            ┌─────────────────────────────────────────────┐
  TRUSTED   │  tb-core  (the sovereign TCB, < ~10K LOC)     │   L2: EL2 / VMX-root
  (tiny)    │  world-switch · EPT/stage-2 · IOMMU · sched   │   L1: (host KVM plays this role)
            └─────────────────────────────────────────────┘
  UNTRUSTED   tb-vmm (per-guest userspace device model)  ·  driver VM (Linux + GPU)
            └ device emulation, VM-exit handling ────────┘  └ VFIO-passthrough NVIDIA/CUDA ┘
  NATIVE      tb-kernel agent guests (memory-centric, forbid(unsafe))
```

- **`tb-vmm` is deliberately UNTRUSTED, per-guest, userspace** — all device
  emulation and VM-exit handling live there; nothing security-critical does. It is
  a `std`, Linux-hosted binary in its **own audited-unsafe domain, explicitly
  OUTSIDE** the framekernel's `#![forbid(unsafe_code)]` boundary. Do not conflate
  it with the sovereign kernel.
- **`tb-core`** (the L2 privileged core) keeps the pKVM-style tiny root but —
  unlike pKVM/KVM — **retains TABOS-sovereign scheduling and memory ownership**
  (Xen-like), because owning scheduling is part of being the agent OS.
- **TCB budget [DECISION]:** target **< ~10K LOC of privileged code** (all of
  TABOS's unsafe+asm surface, kernel + hypervisor core). Exceeding it is proof the
  split is wrong. **Do not formally verify `tb-vmm`** (seL4's own lesson: verifying
  a VMM over a large guest ABI is impractical); treat `forbid(unsafe)` Rust
  memory-safety as the realistic assurance ceiling, and reserve any future
  verification effort exclusively for `tb-core`.

## 4. The framekernel invariant at L2 [DECISION]

The `#![forbid(unsafe_code)]` framekernel rule **survives L2 but `tb-hal` grows**:
VMX/SVM/EL2 entry, VMCS/VMCB management, EPT/NPT/stage-2 tables, and IOMMU
programming are all new silicon-mandated `unsafe`+asm — they go *inside* `tb-hal`
(the one allowed-unsafe crate), keeping every higher layer safe. This is a
**large new privileged block**, budgeted against §3's TCB ceiling, and it is
**per-silicon-ABI** (three disjoint surfaces: Intel VMX/VMCS/EPT, AMD SVM/VMCB/NPT,
ARM EL2/stage-2). Sequence the architectures — **one vendor/arch first**, not
parity (Hedron itself dropped AMD support "due to lack of testing").

## 5. The IOMMU is now a hard requirement [DECISION — was a gap]

Absent from all prior TABOS research, and **non-negotiable** for L2/L3: a hardware
IOMMU (Intel **VT-d** with interrupt remapping / AMD **AMD-Vi** / ARM **SMMU**).
Xen states it plainly: *"Without IOMMU support, there's nothing to stop the driver
domain from using the network card's DMA engine to read and write any system
memory."* Decisions:

- TABOS L2 **owns IOMMU programming**; a passed-through device's DMA is confined by
  VT-d/AMD-Vi/SMMU or it can read/write all TABOS+agent memory.
- The **IOMMU group** (not the individual device) is the unit of assignment;
  require **ACS-clean** platforms on a TABOS "certified hardware" list, since
  `tb-hal` PCIe code must enumerate IOMMU groups.
- Device assignment uses the **VFIO** model (*"IOMMU/device agnostic framework for
  exposing direct device access to userspace"*): unbind from the host driver, bind
  to the passthrough path, DMA confined by the IOMMU.

## 6. The GPU / inference tax — permanent and quarantined [DECISION]

The honest center of the whole roadmap:

- **Local LLM inference (vLLM / llama.cpp + CUDA) NEVER runs inside the sovereign
  tb-kernel guest.** CUDA is *"a Linux + proprietary-driver dependency"* (NVIDIA's
  closed kernel module + GSP firmware + CUDA userspace); it is unportable to a
  non-Linux kernel and **cannot be reimplemented**.
- The only path above L1 is **VFIO GPU passthrough into a confined Linux "driver/
  inference VM"** that hosts the NVIDIA modules + CUDA + vLLM (the Qubes/Xen-style
  driver-domain). TABOS owns the machine and the hypervisor; the GPU stack is
  sandboxed, least-privileged, and disposable.
- TABOS-native agents reach inference through a **narrow vsock/virtio control+data
  channel** (an OpenAI-compatible / gRPC API over vsock, qrexec-style) — never by
  linking CUDA. This is exactly the LLM-agnostic seam: the driver VM is one
  pluggable backend behind the `model:` contract.
- The **trusted display/console stays owned by TABOS** on a simple framebuffer
  (UEFI GOP / `simple-framebuffer`); the passed-through GPU is **headless, compute
  only** — no display path runs on the proprietary stack.
- **Brutal honesty:** the driver/inference VM *is a Linux*, and the proprietary GPU
  tax is **permanent** — there is **no L3 "bare-metal, zero-Linux, full-speed local
  LLM" endpoint**. (Consumer NVIDIA/AMD GPUs also lack SR-IOV/MIG, so one VM owns
  the whole GPU; it cannot be natively shared.) Sovereignty is owning *everything
  except* that quarantined box.

## 7. L1 — `tb-vmm` is build-ready now (the MV milestone)

The MV milestone is L1 and is fully specified by verified facts:

- **rust-vmm crate matrix (mandatory):** `kvm-ioctls` (safe `/dev/kvm` wrappers) +
  `kvm-bindings` (FFI structs) + `vm-memory` (`GuestMemoryMmap`) + `vmm-sys-util`
  (`EventFd`/ioctl) + `event-manager` (the run loop) + `vm-superio` (16550/PL011).
  Reference VMMs (Firecracker, cloud-hypervisor, crosvm) are all rust-vmm Type-2
  VMMs on KVM. Firecracker pins `kvm-ioctls 0.24.0`, `kvm-bindings 0.14.0` — a sane
  baseline. **Do not adopt rust-vmm's virtio stack for MV**; one console device is
  enough for M0–M4 parity, and we will write our own MMIO transport when virtio
  lands.
- **`tb-boot v0` (x86_64) [DECISION, verified constants]:** before the first
  `KVM_RUN`, `tb-vmm` writes a flat long-mode GDT + identity page tables into guest
  RAM (`KVM_SET_USER_MEMORY_REGION`), then `KVM_SET_SREGS` with `cr0 |= PE(0x1) |
  PG(0x8000_0000)`, `cr4 |= PAE(0x20)`, `efer |= LME(0x100) | LMA(0x400)`, a 64-bit
  (L=1) code segment, `cr3` → the page table; `KVM_SET_REGS` with `rflags=0x2`,
  `rip=entry`, and our info pointer in a register. This **enters the guest directly
  in 64-bit long mode — deleting the bootstrap PVH note and the A0 32→64
  trampoline**.
- **`tb-boot v0` (aarch64) [DECISION, verified]:** `VmFd::get_preferred_target()` →
  `VcpuFd::vcpu_init(&kvi)` (`KVM_ARM_VCPU_INIT`, `PSCI_0_2`), then `KVM_SET_ONE_REG`
  with `PSTATE=PSTATE_FAULT_BITS_64` (EL1h, DAIF masked), `PC=entry`, `X0`=info
  pointer (KVM `core_reg_base=0x6030_0000_0010_0000`; PC at `base + 2*32`). Heavier
  than x86 — budget for it.
- **`tb-vmm` is OUTSIDE `forbid(unsafe)`** (it's a Linux `std` binary over thin
  KVM FFI); it is its own audited domain, not part of the sovereign kernel.
- **"No guest kernel" micro-VM mode [DECISION]:** the framekernel *is* the guest
  library — the natural shape for the memory-centric agent model and the cleanest
  way to delete the L0 bootstrap-OS dependency.

> L1 honesty: `tb-vmm` wins a **sovereign boot contract + device model**, *not*
> independence from Linux. The world switch (VMX/SVM), second-stage paging, vCPU
> scheduling, and physical interrupt routing still belong to host KVM. That
> independence is the L2 jump.

## 8. The firmware floor (honesty about "bare metal")

Even L3 is **not truly bare**: TABOS would still run atop closed, un-displaceable
firmware — **UEFI/SMM, Intel ME / AMD PSP, and GPU firmware**. A correct Type-1
(ring −1 / EL2) still sits *below* firmware SMM (ring −2). "Sovereignty" is
therefore always *relative to the firmware floor* — state it plainly and do not
promise more.

## 9. What this changes in the plan (gap closure)

Prior research gaps now resolved or tracked:

1. **Ladder never split L0–L3** → §1 (resolved).
2. **IOMMU ownership absent** → §5, now a hard L2 requirement (resolved).
3. **`forbid(unsafe)` vs L2 silicon code** → §4, grows `tb-hal`, stays inside it
   (resolved).
4. **GPU/CUDA never architected** → §6 driver-domain quarantine (resolved).
5. **Split-VMM pattern missing** → §3 (resolved).
6. **Bare-metal platform bring-up** (UEFI/ACPI/APIC/PCIe/SMMU/SMP) → tracked as
   the L2/L3 work body in [OPEN-QUESTIONS §J](OPEN-QUESTIONS.md).
7. **SMP / AP bring-up** (M0–M4 are single-core; a Type-1 needs per-pCPU VMXON +
   per-vCPU VMCS) → tracked, §J.
8. **Which arch first for L2** (disjoint VMX/SVM/EL2 surfaces) → decided to sequence
   one first; the specific pick is the first L2-milestone gate.

## 10. Roadmap sequence

```
L0 (done) ──► L1: MV = tb-vmm (own userspace VMM + tb-boot v0; deletes PVH/A0)
                 │   reference: Firecracker patterns; one console device
                 ▼
            L2: tb-core minimal Type-1 microhypervisor
                 │   one arch first (ARM EL2 / pKVM-shape is the lightest study);
                 │   own VMX/SVM/EL2 + EPT/stage-2 + IOMMU + scheduling (<10K LOC TCB);
                 │   tb-vmm becomes the untrusted userspace device model
                 ▼
            Driver-domain: confined Linux inference VM (VFIO GPU), vsock model: API
                 │   permanent GPU tax quarantined here; TABOS owns everything else
                 ▼
            L3 (gated): native Rust drivers only for stable sovereignty-critical
                        devices (NVMe, one NIC, xHCI) — only if owning silicon is the product
```

---

### Verification note
18/18 hard facts confirmed 2-0 (Type-1/Type-2 taxonomy, pKVM ~10k-LOC/3-orders
figure, Xen dom0 + IOMMU-DMA quote, KVM ioctl flow, rust-vmm crate identities,
Firecracker `KVM_SET_SREGS` long-mode constants, aarch64 `KVM_ARM_VCPU_INIT` path,
VFIO/CUDA dependency). [DECISION]s are scenario-resolved (maximize sovereignty,
honest about silicon + the permanent GPU tax) and will be tested at the L1/L2
milestone gates.
