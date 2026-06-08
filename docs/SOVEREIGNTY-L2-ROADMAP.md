# TABOS L2 Sovereignty Roadmap — `tb-core`, the from-scratch Type-1 microhypervisor

> The L2 rung of the sovereignty ladder (L0 guest → L1 own userspace VMM `tb-vmm` → **L2 own minimal Type-1 microhypervisor, no host OS** → L3 own drivers, descoped). **Full sovereignty = L2.** This document is the canonical, tracked plan, produced by a 5-agent ultracode research+recon+synthesis panel (VMX-root, EL2, minimal-TCB/IOMMU, codebase recon). It follows the same executable cumulative-serial-marker discipline as the M0→M18 kernel chain: each sub-milestone prints an exact marker and is independently CI-greenable. Companion: [SOVEREIGNTY-ROADMAP.md](SOVEREIGNTY-ROADMAP.md) (the L0–L3 ladder) · raw design [research/raw/L2-design.json](../research/raw/L2-design.json).

## 1. Summary

L2 = remove the host Linux kernel from the TCB: replace `/dev/kvm` with tb-core, a from-scratch <10K-LOC Type-1 microhypervisor in x86 VMX-root / aarch64 EL2 that creates+runs the existing TABOS M0-M18 kernel as its guest. The decided model is a SPLIT-VMM: a tiny trusted core (tb-core: world-switch + EPT/stage-2 + IOMMU + sovereign Xen-like scheduling) plus the existing tb-vmm logic DEMOTED to a deprivileged, re-hosted device model that tb-core forwards MMIO/PIO exits to. Recommended arch-first = x86_64 VMX, because (a) the task's L2.0 hint is VMX, (b) tb-vmm is already x86-only and its KVM_SET_SREGS/REGS register file is reused VERBATIM as VMCS guest-state, and (c) the x86 guest already has a working tb-boot v0 handoff (`_tb_start`), so the guest needs ZERO changes. The genius enabler for shipping NOW: L2.0-L2.6 run tb-core's VMX code INSIDE the already-booted TABOS guest (which becomes L1), spawning a trivial nested L2 guest under stock QEMU/KVM nested virt or tb-vmm — reusing the entire existing build+boot+grep-the-serial harness with NO new bare-metal/UEFI/ACPI stack. Only L2.7 (UEFI Type-1, NO /dev/kvm) needs the firmware-baremetal platform body. All new silicon-unsafe (VMXON/VMCS/EPT/IOMMU asm) is confined to a new tb-hal subtree; tb-core itself is a new no_std mostly-safe orchestrator crate that stays #![forbid(unsafe_code)], exactly as `kernel` stays safe over tb-hal today. Ten serial-DoD sub-milestones L2.0..L2.9, each independently CI-greenable.

## 2. Architecture — split-VMM

SPLIT-VMM (Xen/NOVA/pKVM-consensus shape), realized in the existing crate topology.

TRUSTED CORE — tb-core (new no_std crate `crates/tb-core`, #![forbid(unsafe_code)], a thin mostly-safe orchestrator over tb-hal's new silicon-unsafe wrappers — analogous to how `kernel` stays safe over tb-hal today). Runs in x86 VMX-root (ring -1) / aarch64 EL2. Owns: the world-switch (VMXON/VMLAUNCH/VMRESUME + VMCS, or EL2 ERET + VTTBR/stage-2); the second-stage tables (EPT/NPT/stage-2) + a pKVM-style physical-page ownership tracker; the IOMMU (VT-d/SMMU) — sole writer; the minimal VM-exit demultiplexer; the sovereign scheduler (RETAINED Xen-style, unlike pKVM/KVM which delegate scheduling — owning scheduling is part of being the agent OS); tb-core's own GDT/IDT/TSS for root-mode NMI/MCE; and the hypercall/portal entry.

DEPRIVILEGED DEVICE MODEL — the existing tb-vmm logic (device.rs 16550 UART, serial.rs, loader.rs ELF, the device-exit arms of the run loop, write_system_memory's guest-RAM boot-block writer), RE-HOSTED off Linux as a no_std deprivileged native component (NOVA/Bareflank-extension shape, one per guest), OUTSIDE forbid(unsafe). The KVM-facing parts (memory.rs register_with_kvm, vmm.rs KVM_RUN loop, arch/x86_64/boot.rs ioctls) MOVE into tb-core; the surviving device code is demoted.

THE HYPERCALL ABI (tb-core <-> device model) — modeled on KVM's userspace-exit loop, deprivileged, capability/grant-oriented, tiny: vm_create / vm_destroy; vcpu_create; vcpu_run (the world-switch entry — RETURNS an exit reason); mem_grant / mem_share / mem_reclaim (page-ownership transfer into a guest stage-2; default owned-private, shared only by explicit grant — the pKVM rule mapped onto TABOS capability handles); irq_inject (virtual interrupt); iommu_map / iommu_unmap (DMA grant, gated so only tb-core writes IOMMU tables); and the EXIT UPCALL — tb-core forwards an unhandled MMIO (EPT-violation reason 48) / PIO (I/O reason 30) to the device model, which emulates and returns the value. This is exactly the shape of tb-vmm's current VcpuExit loop (IoIn/IoOut/MmioRead/MmioWrite/Hlt), so the L1->L2 port is "swap the kvm-ioctls surface for the tb-core hypercall surface" — a strong reason the device-model exit-handling stays arch-clean. Transport at L2.0-L2.6 is a direct in-tree call; at L2.9 it becomes a real deprivileged-guest <-> tb-core shared-ring/VMCALL boundary.

CRATE TOPOLOGY: tb-core is no_std bare-metal (NOT a sibling of the std tb-vmm nested workspace); it joins the no_std family as a new root-workspace member or its own no_std workspace. tb-hal grows the per-arch VMX/EL2/IOMMU unsafe. tb-boot v0 is unchanged.

## 3. The `tb-core` TCB boundary (<10K LOC)

The <~10K-LOC privileged TCB (exceeding it is, per SOVEREIGNTY-ROADMAP §3, proof the split is wrong). Reserve any future formal-verification budget for tb-core ONLY.

IN THE TRUSTED CORE (VMX-root / EL2):
- World-switch: VMXON/VMXOFF, VMCLEAR/VMPTRLD, VMLAUNCH/VMRESUME, the asm GPR save/restore stub (the CPU does NOT save RAX..R15 across the switch — the host RIP stub owns it), VMREAD/VMWRITE typed wrappers. aarch64: ERET into EL1, EL2 vector table, context save/restore.
- Second-stage translation: EPT/stage-2 table builder + walker; the R/W/X leaf triple is THE isolation primitive replacing /dev/kvm; a pKVM-style page-ownership/donation ledger.
- IOMMU programming: VT-d DMAR root/context + second-level tables (mirroring each guest's EPT) + interrupt remapping. Sole writer.
- The minimal exit demultiplexer (the §4 MUST set: CPUID, HLT, CR-access, I/O, RDMSR/WRMSR, EPT-violation, EPT-misconfig=fatal, triple-fault=fatal, VMCALL=hypercall, VMX-preemption-timer=sched tick).
- The sovereign scheduler (RETAINED, Xen-like — the one place tb-core diverges from pKVM).
- The hypercall/portal entry + capability dispatch; tb-core's own GDT/IDT/TSS for root-mode faults; per-pCPU VMXON + per-vCPU VMCS bookkeeping for SMP.

OUT (deprivileged, untrusted, re-hosted off Linux, OUTSIDE forbid(unsafe)):
- ALL device emulation (16550 UART, future virtio backends); VM-exit MMIO/PIO emulation; the ELF loader (loader.rs); the guest-RAM boot-block writer (write_system_memory — it needs only guest-RAM write access, not privilege); the toolstack/launch policy; any guest-ABI-shaped logic.
- The Linux GPU/CUDA driver-VM (a SEPARATE permanently-quarantined VFIO box, §6) — must NOT be conflated with the trusted device model.

forbid(unsafe) INVERSION: tb-vmm's single audited unsafe (the KVM_SET_USER_MEMORY_REGION FFI in memory.rs) VANISHES; in its place tb-hal grows an order-of-magnitude-larger silicon-unsafe block — the largest single new unsafe surface in the project. Assurance rests on review of that block (memory-safe Rust everywhere above it).

## 4. x86_64 VMX-root bring-up plan

Intel VMX-root bring-up, eight pieces; all silicon-unsafe in `crates/tb-hal/src/arch/x86_64/vmx/`. Constants from Intel SDM Vol 3C/3D + the `x86` crate's vmcs encodings. The guest register file is REUSED VERBATIM from tb-vmm/src/arch/x86_64/boot.rs (CR0.PE|PG, CR4.PAE, EFER.LME|LMA, flat L=1 CS, CR3=PML4, rdi=TbBootInfo*, rsi=0, rflags=0x2) — just written into VMCS guest-state fields instead of KVM_SET_SREGS/REGS.

1. FEATURE-ENABLE (vmxon.rs): CPUID.1:ECX.VMX[bit5]==1; IA32_FEATURE_CONTROL(0x3A) — if locked && "VMX-outside-SMX"(bit2) clear => BIOS disabled VT-x, SKIP gracefully; else set bit2|bit0(lock); CR4.VMXE(bit13)=1; clamp CR0/CR4 to legal VMX values via IA32_VMX_CR0_FIXED0/1(0x486/0x487) + CR4_FIXED0/1(0x488/0x489) (CR0.NE, CR4.VMXE become mandatory).
2. VMXON: 4KiB-aligned region (from the M6 frame allocator); first dword = rev-id = IA32_VMX_BASIC(0x480)[30:0], bit31=0; VMXON with its PHYSICAL address.
3. VMCS (vmcs.rs): per-vCPU 4KiB region, rev-id in dword0; VMCLEAR(phys) then VMPTRLD(phys).
4. VMCS PROGRAMMING via the control-MSR ADJUST algorithm (controls.rs): final=(desired|allowed0)&allowed1 against PINBASED(0x481)/PROCBASED(0x482)/PROCBASED2(0x48B)/EXIT(0x483)/ENTRY(0x484) and their TRUE_* variants — SKIPPING THIS is the #1 cause of VM-entry failure. HOST-STATE: CR0/CR3(tb-core page tables)/CR4, RSP=per-vCPU host stack, RIP=&vmexit_stub, CS/SS/DS/ES/FS/GS/TR selectors (RPL=TI=0, TR->valid TSS), FS/GS/TR/GDTR/IDTR bases, SYSENTER, EFER. GUEST-STATE: the tb-boot v0 register file above + DR7, segment {sel,base,limit,access} for all, GDTR/IDTR, activity=0, interruptibility=0, VMCS-link-pointer=0xFFFF_FFFF_FFFF_FFFF (mandatory, no shadow VMCS). CONTROLS: primary=HLT-exiting+use-MSR-bitmaps+activate-secondary; secondary=enable-EPT+enable-VPID; exit-ctl=host-addr-space-size(64-bit host)+save/load-EFER; entry-ctl=IA-32e-mode-guest(64-bit guest)+load-EFER; exception-bitmap=0; EPTP; VPID!=0.
5. EPT (ept.rs): 4-level; EPTP = PML4-base | memtype=6(WB) | walk-len-1=3. Identity- or relocated-map the guest RAM slice with 2MiB/1GiB RWX large leaves (a 256MiB guest = a handful of pages); leave MMIO/device windows UNMAPPED so they fault out as EPT-violations routed to the device model. INVEPT after edits.
6. WORLD-SWITCH (world_switch.rs, global_asm!): push guest GPRs to the per-vCPU save area on exit, pop before VMRESUME; VMLAUNCH first entry, VMRESUME after.
7. EXIT DISPATCHER (exit.rs): VMREAD exit-reason(0x4402)/qualification(0x6400)/guest-physical(0x2400)/instruction-length(0x440C). MUST set: 10 CPUID (execute+forge), 12 HLT, 28 CR-access, 30 I/O (->device model), 31/32 RDMSR/WRMSR (MSR bitmap), 48 EPT-violation (map or ->device model), 49 EPT-misconfig (fatal), 2 triple-fault (fatal), 18 VMCALL (hypercall), 52 preemption-timer (sched). RIP-ADVANCE discipline: advance by instruction-length after trapping-instruction exits; NEVER after EPT-violations/exceptions. On entry failure read VM-instruction-error(0x4400).
8. tb-core's own GDT/IDT/TSS for root-mode NMI/MCE.
Precedents to mine: Barbervisor (Rust, boots a guest with its own VMX+EPT — closest), hvpp (EPT identity-map + dispatch), SimpleVisor (smallest VMXON skeleton), NOVA/Hedron (~10K-LOC capability VMX root).

## 5. aarch64 EL2 bring-up plan

aarch64 EL2 monitor (nVHE) — the documented SECOND arch; the split-VMM/stage-2/exit-dispatch SHAPE transfers directly from x86, but the three surfaces are disjoint so it is sequenced separately. All silicon-unsafe in `crates/tb-hal/src/arch/aarch64/{el2.rs,stage2.rs,smmu.rs}`. Constants from Arm ARM (DDI 0487) D-stage + pKVM as the architectural template for the page-ownership layer.

Insight: tb-core EL2 is essentially the existing EL1 cold-MMU bring-up code (M3's MAIR/TCR/TTBR0->SCTLR.M|C|I) lifted "one EL up", PLUS stage-2. nVHE (not VHE) keeps tb-core a thin separate EL2 monitor while the guest owns EL1.

Bring-up:
1. Enter EL2 (firmware/QEMU `virt -machine virtualization=on` boots at EL2; or pKVM-style de-privilege). Set up SP_EL2, VBAR_EL2 (the EL2 vector table) + ISB.
2. HCR_EL2: RW=1 (EL1 is aarch64), VM=1 (enable stage-2 translation for EL1&0), plus TGE=0, and trap bits (TWI/TWE/etc) as desired. This is the master "I am the hypervisor" register.
3. VTCR_EL2: PS (physical size, bits[18:16] from ID_AA64MMFR0_EL1.PARange), TG0 (granule), SL0 (start level), T0SZ (IPA size), SH0/ORGN0/IRGN0 (cacheability) — the stage-2 walk geometry.
4. VTTBR_EL2 = physical base of the stage-2 (IPA->PA) tables + VMID. Build the stage-2 like x86 EPT: map the guest RAM slice RWX, leave virtio-mmio/device windows UNMAPPED so they fault as stage-2 aborts. TLBI VMALLS12E1 after edits.
5. Guest entry: SPSR_EL2 = EL1h (so the guest enters EL1 with the same PSTATE the tb-boot aarch64 contract specifies — PSTATE=EL1h, DAIF masked), ELR_EL2 = guest entry, X0 = the boot-info pointer (see GAP below), then ERET into the guest at EL1.
6. EXIT HANDLER (ESR_EL2.EC dispatch on synchronous EL2 entry): EC=0x16 HVC (the TABOS hypercall ABI / hypercall from EL1), EC=0x24 Data Abort / EC=0x20 Instruction Abort from lower EL with a stage-2 fault (read FAR_EL2/HPFAR_EL2 for the faulting IPA -> map a page or forward MMIO to the device model), plus WFI/WFE traps (scheduler yield) and the EL2 physical/virtual timer for the sched tick (CNTHCTL_EL2/CNTVOFF_EL2). Advance ELR_EL2 only for emulated synchronous instructions, never for re-executed aborts.

GAP that gates ARM-first (recon-confirmed): on aarch64 there is NO tb-boot handoff even at L1 — the kernel `_start` (crates/tb-hal/src/arch/aarch64/boot.rs) consumes x0=FDT/DTB (the QEMU `virt` contract), NOT a TbBootInfo, and tb-vmm has no aarch64 backend. So before ARM L2 can claim "zero guest changes", an aarch64 tb-boot PRODUCER and an `_tb_start`-equivalent EL1 entry (PSTATE=EL1h, X0=TbBootInfo*) must be built first. CI UPSIDE that argues for an ARM smoke-track in parallel: QEMU `virt -machine virtualization=on -cpu cortex-a57|max` provides EL2 to the guest under PURE TCG — no nested KVM, no /dev/kvm — so an aarch64 "el2 OK" world-switch proof can run on ANY stock GitHub-hosted runner.

## 6. IOMMU plan

The IOMMU is a HARD, non-negotiable L2 requirement (SOVEREIGNTY-ROADMAP §5): a device doing DMA bypasses the CPU MMU/EPT entirely, so without an IOMMU a passed-through device's DMA can read/write ALL TABOS+agent memory. tb-core (NEVER the device model) is the sole writer of IOMMU tables.

TARGET VT-d FIRST (matches the x86-first track, the existing x86 L1 path, and QEMU's mature emulated `-device intel-iommu`). In tb-hal (`arch/x86_64/iommu_vtd.rs`):
- DMAR ACPI table parse, with DEFENSIVE handling of broken BIOS DMAR/RMRR — adopt Xen's posture: disable IO-virtualization and REFUSE passthrough rather than trust a malformed table.
- Root table + per-bus context tables.
- Second-level (stage-2) DMA page tables that MIRROR each guest's EPT, so device-DMA and CPU-EPT see the SAME constrained address space (the same R/W/X confinement).
- MANDATORY interrupt remapping (VT-d IR) — without it a passed-through device can forge MSIs to inject interrupts into the hypervisor or other VMs.
- Enforce IOMMU-GROUP granularity as the unit of assignment (not the single function); require ACS-clean topology (so peer-to-peer DMA can't bypass the IOMMU) and FLR-capable functions for safe re-assignment; gate all of it behind a TABOS "certified hardware" allow-list. Use the VFIO conceptual flow (unbind host driver -> passthrough -> IOMMU-confined).
aarch64 mirror later: Arm SMMUv3 stream/context tables mirroring stage-2.

WHEN: a device-less "run one guest" first light (L2.0-L2.7) can PRECEDE the IOMMU — the EPT/stage-2 already confines CPU accesses. The IOMMU becomes mandatory the moment ANY DMA-capable device is passed through, i.e. it gates the post-L2 GPU/inference driver-VM (§6). Hence it is sub-milestone L2.8, after the bare-metal boot and before any passthrough.

TWO-TIER TEST (a real coverage hole): emulated VT-d in QEMU (`-device intel-iommu`) exercises the DMAR/root/context/IR table-PROGRAMMING logic in CI; but the actual DMA-ISOLATION guarantee can only be FINALLY validated on real ACS-clean hardware — emulation cannot prove isolation. So the isolation claim needs a real-HW gate, separate from the CI unit/integration coverage.

## 7. Sub-milestone chain (L2.0 → L2.9)

| # | Title | DoD marker | Depends on | Risk |
|---|---|---|---|---|
| **L2.0** | VMX-root + 1-instruction guest VM-exit (the 'we are the hypervisor' proof). VMXON inside the already-booted TABOS guest (now playing L1) + minimal VMCS + EPT identity-map of one guest page + world-switch + a 1-instruction guest (CPUID or VMCALL) + catch its VM-exit via VMREAD(exit-reason) + VMXOFF. Reuses the existing QEMU-microvm+KVM-nested OR tb-vmm harness; NO new bare-metal stack. | `L2.0: vmxroot OK` | M6 (frame allocator for VMXON/VMCS/EPT pages), M3 (paging live) | Nested-VMX may be unavailable on the CI runner (hosted runners are cloud VMs); gate allow-skip like vmm-boot.yml's KVM_OK. Control-MSR adjust algorithm bugs cause silent VM-entry failure — always read VM-instruction-error(0x4400). |
| **L2.1** | EPT-violation demand handling. The trivial guest touches an UNMAPPED guest-physical address; tb-core catches exit reason 48, reads guest-physical-address, maps a frame, INVEPT, resumes. Proves the R/W/X stage-2 triple is THE isolation primitive that replaces /dev/kvm. | `L2.1: ept OK` | L2.0 | EPT-misconfig (reason 49) is fatal — malformed entries; INVEPT must follow every edit or stale TLB causes non-deterministic faults. |
| **L2.2** | The full §4 MUST exit set: CPUID forge, RDMSR/WRMSR via MSR bitmap, CR-access (28), HLT (12), triple-fault teardown (2), and VMCALL (18) wired as the tb-core hypercall entry. Enforce RIP-advance discipline (advance by instruction-length after trapping exits; NEVER after EPT-violations/exceptions). | `L2.2: exits OK` | L2.1 | Forgetting to advance guest RIP causes an infinite re-exit loop; advancing after a fault re-executes wrongly. The hidden GPR save/restore (CPU does not preserve RAX..R15) must be exact. |
| **L2.3** | Device-model seam: forward an I/O-exit (reason 30, COM1 0x3f8) to a deprivileged device-model callback that emulates a 16550 and prints. Defines the tb-core<->device-model EXIT-UPCALL + vcpu_run-returns-exit-reason ABI. The nested guest prints via the emulated UART. | `L2.3: devmodel OK` | L2.2 | The device model must be re-hosted off Linux (std->no_std port of tb-vmm's device.rs/serial.rs); the ABI must be complete enough that the guest console is byte-faithful to the KVM path. |
| **L2.4** | tb-core runs the REAL TABOS kernel as its NESTED guest. Boot the existing M0-M4 (then full M0-M18) kernel as the L2 guest using the SAME tb-boot v0 register file (written into VMCS guest-state) + the device-model console; the nested guest reaches its OWN markers, forwarded out. Confirms ZERO guest changes. | `L2.4: tabos-guest OK` | L2.3 | Guest RAM sizing + EPT coverage for the full kernel; behavioural parity with KVM (e.g. CPUID/MSR leaves the kernel reads). Still nested (a host KVM underneath), not yet sovereign. |
| **L2.5** | Sovereign scheduling: VMX-preemption-timer (reason 52) drives a tb-core scheduler tick; >1 vCPU time-sliced. TABOS RETAINS Xen-like scheduling ownership (the one divergence from pKVM/KVM). | `L2.5: sched OK` | L2.4 | Preemption-timer rate uses the VMX_MISC scale factor — easy to mis-scale; the scheduler must fit the <10K-LOC privileged budget. |
| **L2.6** | SMP / AP bring-up: per-pCPU VMXON + per-vCPU VMCS; run the guest across >1 physical CPU. Closes the OPEN-QUESTIONS §J P1 'type1-x86-vmx' SMP gap. | `L2.6: smp OK` | L2.5 | M0-M18 are single-core; AP startup (INIT-SIPI-SIPI, APIC) is new platform code with no prior TABOS surface. Per-pCPU VMXON state isolation must be airtight. |
| **L2.7** | UEFI Type-1 launch — NO /dev/kvm. tb-core as an EFI app (uefi-rs): capture memory map + ACPI RSDP + GOP framebuffer, ExitBootServices, install in VMX-root with NO host kernel underneath, build EPT, boot the TABOS M0-M18 kernel from bare metal. THIS is where full sovereignty lands. | `L2.7: baremetal OK` | L2.6 + the firmware-baremetal platform body (ACPI MADT/MCFG, PCIe ECAM, APIC, timer calibration) | The largest single work stream (§J P2), plausibly bigger than tb-core itself, and untracked beyond a note. Sovereignty stays RELATIVE to the firmware floor (below SMM/ME/PSP). Needs a real or nesting-capable machine — not stock hosted CI. |
| **L2.8** | IOMMU (VT-d): DMAR parse (defensive on broken BIOS) + root/context tables + second-level tables mirroring each guest's EPT + MANDATORY interrupt remapping. Confine a passed-through device's DMA to its owner. Mandatory before any driver-VM/GPU passthrough. | `L2.8: iommu OK` | L2.7 | Needs ACS-clean 'certified hardware'; consumer platforms with poor ACS/grouping cannot be confined. Table-programming is CI-testable on emulated intel-iommu, but the isolation CLAIM is only provable on real silicon. |
| **L2.9** | Full split-VMM: demote the complete tb-vmm device model to a deprivileged guest/VM; tb-core forwards ALL MMIO/PIO exits to it over the hypercall/shared-ring ABI; the trusted core contains zero device emulation. Verify the <10K-LOC TCB budget holds. | `L2.9: split-vmm OK` | L2.8 | ABI completeness (every exit the device model must service); structural budget pressure — if tb-core exceeds ~10K LOC the split is wrong (§3). The std->no_std device-model re-host is a non-trivial port. |

## 8. L2.0 design (the first sub-milestone — implementable now)

CONCRETE, implementable NOW. The smallest step that proves we are the hypervisor: VMXON + a 1-instruction guest that VM-exits, caught. Prints "L2.0: vmxroot OK".

WHERE IT RUNS (the key enabler): NOT bare metal. L2.0 runs INSIDE the already-booted TABOS guest — the existing kernel, booted to M18 by QEMU-microvm+KVM (run-x86_64.sh with /dev/kvm) or by tb-vmm, becomes the L1 guest, and tb-core's VMX code spins up a trivial L2 NESTED guest. This reuses the ENTIRE existing harness (cargo kbuild + boot + grep-the-serial-marker) with NO new UEFI/ACPI/PCIe/bare-metal stack — the firmware-baremetal gap is deferred to L2.7. Prereq on the substrate: nested VMX must be exposed to the TABOS guest (L0 host kvm_intel nested=1 + CPUID VMX bit), i.e. run QEMU with `-cpu host` (+vmx) and KVM accel; if absent, SKIP gracefully (see step 0).

CODE LANDING: a new tb-hal subtree `crates/tb-hal/src/arch/x86_64/vmx/{vmxon.rs,vmcs.rs,controls.rs,ept.rs,world_switch.rs,exit.rs}` (all the new silicon-unsafe+asm), driven by a SAFE self-test added to the cumulative milestone chain (after M18) — prototype it inside the existing kernel crate first; extract into `crates/tb-core` at L2.3/L2.4 when the device-model seam forms.

EXACT STEPS:
0. PROBE/SKIP: CPUID.1:ECX.VMX[bit5]; read IA32_FEATURE_CONTROL(0x3A) — if locked && VMX-outside-SMX(bit2)==0, print "L2.0: vmx unavailable (skip)" and continue (matches the §J VMX-reachability-probe requirement and the vmm-boot KVM_OK allow-skip discipline). Else set bit2|bit0(lock).
1. ENABLE: CR4.VMXE=1; clamp CR0/CR4 to IA32_VMX_CR0/CR4_FIXED0/1 (0x486-0x489).
2. VMXON: one 4KiB frame from M6's allocator; dword0 = IA32_VMX_BASIC(0x480)[30:0] (bit31=0); VMXON(phys).
3. VMCS: one 4KiB frame, rev-id in dword0; VMCLEAR(phys); VMPTRLD(phys).
4. PROGRAM (controls via the adjust algorithm — final=(desired|allowed0)&allowed1): HOST-STATE from the LIVE kernel context (host CR3 = current CR3, GDT/IDT/TR from the running kernel, host RSP = a per-vCPU stack, host RIP = &vmexit_stub); CONTROLS minimal — primary=activate-secondary, secondary=enable-EPT, exit-ctl=host-addr-space-size+save/load-EFER, entry-ctl=IA-32e-mode-guest+load-EFER, VMCS-link-pointer=0xFFFF_FFFF_FFFF_FFFF; GUEST-STATE = long-mode (CR0.PE|PG, CR4.PAE, EFER.LME|LMA, flat L=1 CS) with guest RIP pointing at a single CPUID (or VMCALL) instruction placed in a mapped guest page, guest RSP into that slice.
5. EPT: a tiny 4-level identity map (EPTP = PML4 | WB(6) | walk-len-1(3)) covering the one page holding the guest instruction, RWX 2MiB leaf. INVEPT.
6. WORLD-SWITCH (world_switch.rs, global_asm!): save host GPRs, VMLAUNCH; on exit the stub restores and returns to safe Rust.
7. CATCH: VMREAD exit-reason(0x4402) — assert == 10 (CPUID) or 18 (VMCALL). On any VM-entry failure VMREAD VM-instruction-error(0x4400) and print it.
8. VMXOFF; print "L2.0: vmxroot OK".

CI HOOK: extend run-x86_64.sh / vmm-boot.yml MARKER to "L2.0: vmxroot OK" (or a dedicated nested job), gated allow-skip when nested VMX is absent. Proves the world switch — the single highest-value milestone.

## 9. Test strategy (QEMU nested virt)

Three-tier, extending the existing pattern (ci.yml: TCG both arches; vmm-boot.yml: gated on /dev/kvm with a KVM_OK allow-skip). The L2 problem is that tb-core is itself a hypervisor, so CI must give it a virtualization layer to run ON while it virtualizes the TABOS guest = NESTED virtualization (L0=host KVM, L1=tb-core, L2=TABOS kernel — the Turtles model). This differs sharply by arch.

TIER 1 — every PR, any runner, no virt: pure-function unit tests of the new tb-hal builders — VMCS guest-state encoders, the control-MSR adjust algorithm, EPT/stage-2 table builders, VT-d DMAR/context builders — over synthetic inputs, exactly as tb-vmm already unit-tests gdt_table()/setup_page_tables()/the ELF-note parser and tb-boot tests its PODs. Always runs.

TIER 2 — primary L2 DoD for L2.0-L2.6 (NESTED): tb-core's VMX code runs inside the already-booted TABOS guest under QEMU-microvm+KVM with `-cpu host` (+vmx) and L0 `kvm_intel nested=1`, spawning the trivial/real nested L2 guest. The grep-the-serial verdict is unchanged — the booted guest prints M0...M18 then L2.0...L2.n cumulatively. For L2.4+ the NESTED guest is the real TABOS kernel, which prints its OWN M0-M18 (forwarded through the device-model console); tb-core then prints "L2.4: tabos-guest OK" after the nested marker is seen — a nesting of markers, one grep per level. Gate this job allow-skip exactly like vmm-boot's KVM_OK guard: if nested VMX / /dev/kvm is absent, SKIP-with-message (hosted runners are cloud VMs and nested VMX is not guaranteed). Software fallback: QEMU-TCG can emulate VMX/EPT (slow, historically less complete) as a no-nesting correctness smoke.

TIER 3 — gated/self-hosted: L2.7 (bare-metal UEFI Type-1, no /dev/kvm) and the real IOMMU DMA-isolation claim (L2.8) need a real or nesting-capable machine — run on a self-hosted runner; allow-skip on hosted CI.

ARM ADVANTAGE (parallel smoke-track): QEMU `virt -machine virtualization=on -cpu cortex-a57|max` provides EL2 to the guest under PURE TCG — NO nested KVM, NO /dev/kvm — so an aarch64 EL2 world-switch proof ("el2 OK") runs on ANY stock GitHub-hosted runner, like today's TCG aarch64 path. This makes ARM the CI-friendliest way to de-risk the world-switch SHAPE even though x86 stays the design-primary critical path. IOMMU: emulated `-device intel-iommu` / virtual SMMUv3 exercises table-programming in CI; the isolation guarantee needs the real-HW gate.

## 10. New unsafe surface

The forbid(unsafe) framekernel rule SURVIVES L2; tb-hal just grows a large new privileged block (SOVEREIGNTY-ROADMAP §4 [DECISION]). All VMX/EL2/IOMMU silicon-unsafe + asm lands INSIDE tb-hal (the one allowed-unsafe crate), mirroring its existing arch/<arch>/{boot,mmu,trap,user,timer}.rs pattern.

NEW x86_64 SUBTREE — crates/tb-hal/src/arch/x86_64/vmx/:
- vmxon.rs — feature-enable (CPUID + IA32_FEATURE_CONTROL + CR4.VMXE + CR0/CR4 fixed-bit clamp) + VMXON region.
- vmcs.rs — region alloc + typed VMREAD/VMWRITE wrappers over the x86::vmx::vmcs {guest,host,control,ro} encodings.
- controls.rs — the control-MSR adjust algorithm (the legality gate).
- ept.rs — 4-level stage-2 tables + EPTP + INVEPT.
- world_switch.rs — global_asm! GPR save/restore around VMLAUNCH/VMRESUME (the CPU does NOT save RAX..R15).
- exit.rs — raw exit-reason/qualification/instruction-length readout.
- iommu_vtd.rs — DMAR parse + root/context + second-level tables + interrupt remapping (added at L2.8).

NEW aarch64 SUBTREE — crates/tb-hal/src/arch/aarch64/: el2.rs (HCR_EL2/VTCR_EL2/VTTBR_EL2 + EL2 vectors + ERET), stage2.rs (IPA->PA tables + TLBI), smmu.rs (SMMUv3).

tb-core ITSELF: a new no_std crate crates/tb-core, #![forbid(unsafe_code)], a thin mostly-safe orchestrator (the Vcpu struct, exit dispatch, scheduler, EPT/IOMMU policy, hypercall handlers) that calls the thin tb-hal wrappers — exactly as the `kernel` crate stays safe over tb-hal today. It is no_std bare-metal, so it joins the no_std family (a new root-workspace member or its own no_std workspace), NOT a sibling of the std tb-vmm nested workspace.

INVERSION: tb-vmm's single audited unsafe (the KVM_SET_USER_MEMORY_REGION FFI in memory.rs) DISAPPEARS at L2; in its place comes this order-of-magnitude-larger silicon-unsafe block — the largest single new unsafe surface in the project, budgeted against the <~10K-LOC privileged ceiling. Reserve any formal-verification effort for tb-core only.

## 11. Open decisions

- ARCH-FIRST GATE (§J P1, must decide before opening the tb-hal vmx/ tree): x86_64 VMX (RECOMMENDED — matches the L2.0 hint, reuses tb-vmm's exact register file + x86-only L1 reality, the x86 guest already has a working tb-boot _tb_start so ZERO guest changes) vs aarch64 EL2 (lighter pKVM-shape study + free TCG-EL2 CI on stock runners). Surfaces are disjoint; do NOT chase parity (Hedron dropped AMD for lack of testing).
- WHERE L2.0-L2.6 CODE LIVES: a self-test inside the existing kernel crate (fastest — reuses the whole boot+grep harness) vs a separate crates/tb-core from day one. Recommend: prototype the VMX primitives as a kernel milestone, extract into no_std crates/tb-core at L2.3/L2.4 when the device-model seam forms.
- DEVICE-MODEL RE-HOST (the hidden cost): tb-vmm is std+Linux+kvm-ioctls; at L2 there is no /dev/kvm. NOVA/Bareflank-extension shape (a no_std deprivileged native VMM per guest — RECOMMENDED, most sovereign, Linux fully out) vs Xen-dom0 shape (tb-vmm inside a tiny control VM). Distinct from the permanently-quarantined GPU/CUDA driver-VM (§6).
- NESTED-VMX CI SUBSTRATE: is a self-hosted / nesting-capable runner acceptable for the Tier-2 boot DoD, or must hosted CI rely only on slow QEMU-TCG-VMX emulation? Hosted GitHub runners do not guarantee nested VMX.
- aarch64 tb-boot HANDOFF (prereq for ARM-first claiming zero-guest-changes): build an aarch64 tb-boot PRODUCER + an _tb_start-equivalent EL1 entry (PSTATE=EL1h, X0=TbBootInfo*). Today the aarch64 kernel _start consumes x0=FDT and tb-vmm has no aarch64 backend.
- INTERRUPT VIRTUALIZATION: hardware-assisted APICv/AVIC (and the VMX-preemption-timer or LAPIC-timer as the sched/timer source) vs trap-and-emulate LAPIC. Affects the <10K-LOC budget and how M8's timer source is reproduced under tb-core.
- EPT MAPPING POLICY: gpa==hpa identity for the guest slice (simplest) vs a fixed relocated base (slightly cleaner isolation). Either is fine; pick one and standardize.
- VMX-REACHABILITY PROBE POLICY (§J P1): the exact SKIP behaviour when IA32_FEATURE_CONTROL is BIOS-locked / VMX disabled — modeled on the vmm-boot KVM_OK allow-skip so hosted CI stays green.

## 12. Risks

- x86 nested-VMX is not reliably available on stock GitHub-hosted runners (cloud VMs; needs the cloud host's kvm_intel nested=1 + VMX advertised in guest CPUID). The real VMXON boot DoD likely needs a self-hosted/bare-metal runner or slow QEMU-TCG-VMX; only the ARM EL2 path (QEMU virt virtualization=on under TCG) is CI-testable on stock runners without nesting. Mitigate with allow-skip gating like vmm-boot's KVM_OK.
- The <~10K-LOC TCB budget is very tight for the full L2 scope (VMX/VMCS + EPT + VT-d + LAPIC/APIC virtualization + timer + per-pCPU SMP + sovereign scheduling, PLUS the existing kernel unsafe). §3 makes exceeding it 'proof the split is wrong' — scope pressure is structural, not cosmetic.
- tb-core needs an entirely NEW bare-metal HOST/EL2 boot+platform stack that does not exist today: every current tb-hal entry (_start PVH, _tb_start, aarch64 _start) is a GUEST entry. The §J 'firmware-baremetal gap' (UEFI/uefi-rs + ACPI MADT/DMAR/MCFG + PCIe ECAM + APIC/GIC + SMMU + timer calibration) is a large separate work stream, plausibly bigger than tb-core itself, untracked beyond a P2 note. This gates L2.7 only — L2.0-L2.6 sidestep it by running nested.
- SMP/AP bring-up is undesigned (§J P1): M0-M18 are single-core, but a Type-1 needs per-pCPU VMXON + per-vCPU VMCS + INIT-SIPI AP startup — foundational new code (L2.6).
- IOMMU (mandatory, §5) depends on ACS-clean 'certified hardware' + correct IOMMU-group enumeration; consumer platforms with poor ACS cannot be confined, narrowing supported hardware. The DMA-isolation claim is unprovable in pure QEMU — a coverage hole between unit tests and real silicon.
- aarch64 has NO tb-boot handoff even at L1 (kernel _start consumes x0=FDT; tb-vmm is x86-only). ARM-first L2 (the CI-friendly path) FIRST requires building the aarch64 tb-boot producer + an _tb_start-equivalent EL1 entry — a prerequisite not on the active track.
- The 'tb-vmm becomes the device model' demotion is not in-place reuse: its KVM-facing spine (memory.rs, vmm.rs run loop, arch/boot.rs ioctls) is exactly the MOVED part, and the surviving device code (device.rs/serial.rs/loader.rs) must be re-hosted on a non-Linux no_std runtime talking to tb-core via the hypercall ABI instead of ioctls — a non-trivial std->no_std re-port.
- Correctness pitfalls that must be encoded as tb-core invariants: GPRs are not CPU-saved across the switch (the asm stub owns it); always run the control-MSR adjust algorithm (never write raw control bits); advance guest RIP after trapping-instruction exits but NEVER after EPT-violations/exceptions; VMCS-link-pointer must be ~0; clamp CR0/CR4 to the FIXED MSRs; host needs its own TR+IDT for root-mode NMI/MCE; read VM-instruction-error(0x4400) on every entry failure.
- Firmware-floor honesty (§8): even a correct Type-1 at ring -1/EL2 sits BELOW SMM (ring -2), Intel ME / AMD PSP, and GPU firmware. 'Full sovereignty' at L2 is always relative to that floor; the permanent GPU/CUDA tax stays quarantined in a Linux driver VM (§6) — there is no zero-Linux full-speed local-inference endpoint. Do not over-promise.
