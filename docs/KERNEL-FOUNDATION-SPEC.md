---
type: Architecture
title: "Yuva Kernel Foundation & Assembly Specification"
description: "Locked v1.0 spec: tb-hal is the sole asm/unsafe crate; defines boot path (PVH bootstrap to tb-boot), ABI, traps, MMU, and M0-M4/MV WBS."
tags: ["kernel", "assembly", "boot", "hal", "abi", "milestones"]
timestamp: 2026-06-07T01:48:32+03:00
status: locked
diataxis: explanation
---

# Yuva Kernel Foundation & Assembly Specification

> Status: v1.0 · **All items [DECISION]** — this document deliberately contains no open decisions (locked to scenario).
> Scope: the `tb-hal` foundation crate — the layer where ALL of the kernel's `unsafe` + ALL assembly is confined. Every crate above it is `#![forbid(unsafe_code)]`.
> Target arch: **x86_64 + aarch64** (the two arches Firecracker supports); riscv64 = future, not planned.
> Basis: [SOVEREIGNTY](SOVEREIGNTY.md) (boot/VMM sovereignty decision) · [LANGUAGE-AND-STANDARDS](LANGUAGE-AND-STANDARDS.md) · [ARCHITECTURE](ARCHITECTURE.md) · Raw data: [`kernel-asm-research.json`](research/raw/kernel-asm-research.json) · Verification: [`kernel-asm-verified.json`](research/raw/kernel-asm-verified.json)
> Related: [PROCESS](PROCESS.md) (gates) · [OPEN-QUESTIONS](OPEN-QUESTIONS.md)

---

## 0. Decision Summary and Resolved Conflict

The Yuva kernel boots **as a guest on a Firecracker/KVM-class VMM**; not bare-metal. This **deletes** a large amount of assembly without costing the agent anything. All remaining assembly is written in a single `tb-hal` foundation crate, using Rust 1.88+ `#[unsafe(naked)]` + `naked_asm!` / `global_asm!`.

**Boot path — sovereignty revision** (detail: [SOVEREIGNTY §2](SOVEREIGNTY.md)): This document originally chose **LinuxBoot** (solely on the trampoline-deletion rationale). Arda's directive "entirely our own build, no Linux" (2026-06-07) shifted the priority. **New decision:**
- **Canonical = `tb-boot v0`** — our own owned handoff contract, produced by our own thin VMM **`tb-vmm`** (rust-vmm based, single-vCPU Mirage); enters directly in 64-bit long mode → **no trampoline, no Linux, no Xen**.
- **Bootstrap (M0 only, temporary) = stock Firecracker + PVH** — Xen-originated **neutral** protocol (not the Linux zero-page); `linux-loader` provides it for free. PVH enters 32-bit → small **temporary** trampoline `A0` (deleted once `tb-vmm` arrives).
- Net: in the real system, nothing is named after or shaped by Linux. (Fallback: if the trampoline causes trouble, the Linux/x86 64-bit protocol in bootstrap — again ~30 struct fields, not kernel code.)

---

## 1. `tb-hal` Foundation Crate Boundary [DECISION]

```
tb-hal/                         # THE single unsafe/asm crate; the rest of the kernel is safe on top of it
├── src/lib.rs                  # safe trait Hal + safe wrapper types (TaskContext, TrapFrame, PageTableEntry, Mmio<T>, Port<T>)
├── src/arch/mod.rs             # #[cfg(target_arch)] dispatch
├── src/arch/x86_64/{boot,gdt,idt,trap,switch,mmu}.rs
└── src/arch/aarch64/{boot,vectors,trap,switch,mmu}.rs
```

- **Single API surface:** `trait Hal { boot_init, install_traps, context_switch, flush_tlb_page, flush_tlb_all, switch_address_space, serial_putb, ... }` — upper layers see only this safe trait.
- **CI gate (mandatory):** `#![forbid(unsafe_code)]` in every crate other than `tb-hal`; `cargo-geiger`/grep verifies that `unsafe`/`asm!`/`naked_asm!`/`global_asm!` is **zero** outside the foundation.
- **Toolchain pin:** `rust-toolchain.toml` channel ≥ **1.88.0** (naked function stabilization — verified: 2025-06-26 release, `#[unsafe(naked)]` + `naked_asm!`).

## 2. Boot Path [DECISION]

| | **x86_64** | **aarch64** |
|---|---|---|
| Image format | ELF + **PHYS32_ENTRY note present** → PVH (bootstrap); canonical `tb-vmm` → `tb-boot` 64-bit direct | arm64 PE Image (bootstrap compat shim); canonical `tb-boot` |
| Load address | 1 MiB (`0x0010_0000`, FC `HIMEM_START`) | DRAM+2 MiB (`0x8020_0000`) |
| vCPU entry state (bootstrap/PVH) | **32-bit protected, paging OFF**, `cr0=PE\|ET`, `%ebx→hvm_start_info` → `A0` trampoline → 64-bit. Canonical `tb-boot`: 64-bit direct, no trampoline | **EL1h, MMU OFF**, `PSTATE=0x3c5`; canonical `tb-boot` has its own entry condition |
| Single boot input | zero page @ RSI; cmdline @ `0x20000` (≤2048B) | FDT (DTB) @ x0 |
| Device discovery | cmdline token: `virtio_mmio.device=<sz>@<base>:<irq>` | FDT walk (memory, GIC, timer, virtio-MMIO, **NS16550A** serial, **PL031** RTC, psci) |

> **Correction (verification):** aarch64 serial = **NS16550A** (FDT `compatible="ns16550a"`), *not* PL011; only the RTC is a PrimeCell (PL031). The spec follows this.

**Deleted assembly (relative to bare-metal):** x86 real→protected→long-mode trampoline, A20 gate, GDT-in-real-mode from scratch, CR0.PE flip; BIOS/UEFI firmware + services; ACPI/MPTable enumeration (for boot); PCI bus scan; AP/SMP trampoline (single-vCPU). None of these are needed to reach `rust_main`.

## 3. Assembly Unit Inventory — Traceable WBS Core [DECISION]

Each row is a **traceable work item**; the "asm or Rust" column draws the foundation boundary. (× = none/deleted)

| # | Unit | x86_64 | aarch64 | Layer |
|---|---|---|---|---|
| A0 | **(bootstrap-only, deleted in MV)** PVH 32→64 trampoline | `global_asm!`: 4-entry boot page table, EFER.LME set, CR0.PG, far-jump 64-bit CS (~40 lines) | × (no aarch64 PVH) | **asm (temporary)** |
| A1 | `_start` boot entry | `global_asm!`: `lgdt` our own GDT, CS/segment reload, `rsp←boot stack`, zero BSS, `%ebx/rsi→rdi` shuffle, `call rust_main` | `global_asm!`: `sp←boot stack`, zero BSS, `msr VBAR_EL1`, `isb`, `b rust_main` (x0=FDT preserved) | **asm** |
| A2 | Boot stack + linker symbols | guarded `BOOT_STACK` in `.bss`; `__bss_start/__bss_end`, entry=`_start`, .text@0x100000 | same + Image header emit | **asm/linker** |
| A3 | Cooperative context switch | `#[unsafe(naked)] extern "C"`: 6 GPR `{rbx,rbp,r12-r15}` + rsp save/restore; resume from stack | `#[unsafe(naked)] extern "C"`: 12 GPR `{x19-x28,x29,x30}` + SP; resume `ret`→x30 | **asm** |
| A4 | Trap/IRQ/exception entry | `global_asm!` `__alltraps`: push 15 GPR → TrapFrame, `mov rdi,rsp`, `call trap_handler`, `iretq`; 256 per-vector thunks (no-errcode ones push a dummy 0) | `global_asm!` `__alltraps`: save x0-x30 + ELR_EL1 + SPSR_EL1, `mov x0,sp`, `bl trap_handler`, `eret`; 16×128B VBAR table | **asm** |
| A5 | GDT/IDT vs. vector table | `global_asm!`: permanent flat 64-bit GDT (null+code 0x9A+data 0x92+TSS) + 256-entry IDT; #DF/NMI/#MC → IST stack | `global_asm!`: 2KB-aligned VBAR_EL1, 16 entries; no IST analog | **asm** |
| A6 | Privileged MMU wrappers | `asm!` `unsafe fn`: `read_cr3/write_cr3/invlpg/cr4_pge_toggle/wrmsr_efer(NXE)/wrmsr_pat` (~6 units) | `asm!` `unsafe fn`: `msr_ttbr0/ttbr1/tcr/mair_el1, rmw_sctlr, tlbi(vae1/vale1/vmalle1 ±is), dsb, isb` (~9 units) | **asm** |
| A7 | MMU bring-up | × (FC hands over paging on; CR3 inherited) | **mandatory**: program MAIR/TCR/TTBR → `isb` → SCTLR.M=1 → `isb` (VA==PA window) | **asm** |
| A8 | Page-table ENTRY manipulation | **safe Rust** over typed `PageTableEntry` (PML4/PDPT/PD/PT walk, split/coalesce) | same (VALID/AP/AF/SH/UXN/PXN bits) | **safe Rust** |
| A9 | TLB invalidation | `invlpg [addr]` (self-ordering) | `dsb ishst; tlbi vale1is,Xt; dsb ish; isb` (4-instr template) | **asm** |
| A10 | Serial debug (early) | `Port<u8>` 0x3F8 (`out`/`in`) | `Mmio<u8>` NS16550A @ FDT base | **asm wrapper** |
| A11 | Privileged one-liners | `cli/sti/hlt/lidt/lgdt/ltr/rdmsr/wrmsr` | `wfi/wfe/dsb/isb/msr/mrs` | **asm wrapper** |
| A12 | **(v2-reserved)** user/ring boundary | `swapgs`+`STAR/LSTAR/SFMASK`+`syscall/sysretq`+TSS.rsp0 | EL0 entry (Lower-EL slot)+`SP_EL0` banking+`svc/eret` | **asm (NOT in v1)** |
| A13 | **(deleted)** AP/SMP bringup | INIT-SIPI-SIPI + real-mode trampoline | PSCI CPU_ON HVC | **× (single-vCPU)** |

## 4. ABI / Register Sets (which context-switch + trap must obey) [verified: 2-0]

- **x86_64 System V:** callee-saved `{rbx, rbp, rsp, r12, r13, r14, r15}`; caller-saved `{rax, rcx, rdx, rsi, rdi, r8-r11}`; arg order `rdi, rsi, rdx, rcx, r8, r9`; return `rax(/rdx)`. **DF (direction flag) clear on call entry/exit**; **RSP 16-byte aligned** immediately before `call` (RSP%16==8 on handler entry); the 128-byte **red zone** is removed (`x86_64-unknown-none` target).
- **aarch64 AAPCS64:** callee-saved `x19-x28, x29(FP), SP`; caller-saved `x0-x18`; arg `x0-x7`; return `x0(/x1)`. SIMD: **only the lower 64-bit** of `v8-v15` is callee-saved (FP off in v1). **SP mod 16 == 0** on all public interfaces.
- **Cooperative switch register difference:** x86 6 GPR vs. aarch64 12 GPR (AAPCS64 keeps more callee-saved); on aarch64 the resume address is **in a register** (x30/LR), on x86 it's **on the stack** → LR is explicitly banked.
- **FP/SIMD policy [DECISION]:** **zero FP/SIMD** in v1. Targets: `x86_64-unknown-none` (SSE/AVX off, no red zone) + `aarch64-unknown-none-softfloat` (NEON off). No xmm/v-register field in TrapFrame. (Lazy-FP trap, capability-gated in v2 once user FP threads are accepted.)

## 5. Trap / Privilege Model [DECISION]

- **v1 single privilege level:** ALL scheme daemons run in-image, in a single address space, as **ring0/EL1 safe Rust**. The ring3/EL0 hardware-userspace boundary is a **named work-unit deferred to v2** (A12) — v2 opens this without touching the v1 fault path at all. On x86 EFER.SCE/STAR/LSTAR/SFMASK/swapgs are **absent**; on aarch64 only the "Current EL with SPx" vector quadrant is live.
- **Cause decode is NOT in asm:** the entry stub only does marshal/call/restore. x86: the handler reads the asm-pushed vector index + CPU error code. aarch64: the handler reads **ESR_EL1.EC+ISS** (the stub only encodes the slot via `mov x0,#src; movk`). Both arches meet in a single Rust dispatch function.
- **Capability check is entirely in the safe-Rust handler** — no comparison/table-walk/privilege logic in asm at all. In v1 a capability invocation is an ordinary safe-Rust call guarded by an unforgeable capability-token type.

## 6. MMU asm-vs-Rust Boundary [DECISION]

- **Privileged register writes + TLB maintenance + barriers = asm** (A6/A7/A9). **Page-table setup/walk = safe Rust** (A8) — if `asm!` appears here the CI lint breaks.
- **x86_64:** **inherit** FC's boot page-table from CR3 (Asterinas `BootPageTable::from_current_pt`); build the higher-half + 4KiB maps in Rust. At boot, program **WRMSR EFER.NXE + IA32_PAT** (FC does not) — for the NX bit / cache policy.
- **aarch64:** the MMU comes up **cold** → A7 bring-up is mandatory (MAIR/TCR/TTBR → `isb` → SCTLR.M=1 → `isb`). If the OA/attr of a live valid descriptor changes, **Break-Before-Make** is mandatory (invalid store → TLBI+barrier → new descriptor → barrier).
- **Barriers:** ordinary ordering via `core::sync::atomic` (Release/Acquire PTE publish, `fence`); raw `dsb/isb/mfence` only where arch-mandated (after TTBR/MAIR). Since we are single-vCPU, the **local (non-IS)** variant instead of inner-shareable may suffice for TLBI — measure it (M3 DoD).

## 7. Standards Applied to Assembly [DECISION]

- **Ferrocene scope [verified inference]:** inline asm + naked functions are **OUTSIDE the Ferrocene normative qualified subset** → this is a **tracked constraint**: every asm unit is subject to the Ferrocene Safety Manual §9 unsafe discipline (extra manual review + test). The safe Rust layer stays within the qualified subset.
- **Mandatory 3-part header on every asm unit:** (a) pre/postcondition contract comment, (b) clobber+ABI annotation (`clobber_abi`, explicit clobbers, FLS hard rules), (c) paired test reference (M-gate).
- **Two-phase early boot:** **Phase 0** (from `_start` until SP+BSS are ready) only spin (`hlt`/`wfe`) + a single raw UART byte; **TigerStyle `assert!()` is FORBIDDEN until Phase 1** (no stack/serial). After Phase 1, ≥2 assertions per function (TigerStyle).
- **Unsafe/asm CI budget:** the count of `unsafe` blocks + asm statement-lines in the foundation is counted against a committed budget file (Asterinas/VeriSMo "31 lines" discipline); an overage blocks the merge.
- **Reproducible build:** single rustc + Nix flake; ALL asm in-language (`naked_asm!`/`global_asm!`, no external `.S` → no need to pin a separate assembler); bit-reproducibility is verified.
- **Layout/ABI const-assert:** struct offsets, GDT/IDT descriptor values, page-table bit positions, UART register offsets are **compile-time const assertions** — drift breaks the **build**, not the boot.

## 8. Test Gates — The "Done" Definition of Every Asm Unit [DECISION]

- **Two tiers:** (a) the safe-Rust layer via host `cargo test` (capability algebra, page-table index/permission math, scheduler); (b) on-target custom runner (phil-opp pattern: `Testable` trait, per-test serial `name ... [ok]`, write pass/fail to the platform exit device + halt) — **distributed test registration via linker-section**.
- **Boot bring-up = the executable DoD of `_start`:** the no_std image boots under QEMU `microvm`(x86)/`virt`(aarch64), and the `hello from rust_main` serial line is asserted.
- **Context-switch canary test (A3 DoD):** two kernel tasks yield ≥1000 times; (a) deterministic A,B,A,B alternation + (b) a unique sentinel preloaded into each callee-saved register **survives** the switch.
- **Trap test (A4/A5 DoD):** (a) `int3`/`brk #0` → the handler ran + continued; (b) a deliberate fault (unmapped write / `udf`) → handler with correct fault info.
- **Fail-closed exit channel + 60s wall-clock timeout:** a deterministic VM-exit STATUS in addition to serial scraping (x86: `isa-debug-exit`/port; aarch64: PSCI `SYSTEM_OFF`/semihosting).
- **CI matrix:** {x86_64, aarch64} × {QEMU primary, Firecracker secondary}; a merge does not pass without being green **on both arches**. Every `#[cfg(target_arch)]` split must be tested on both arches.
- **Formal scope:** Kani/Verus only on **safe Rust** (page-table arithmetic, address-translation round-trip, capability-derivation monotonicity, bitflag well-formedness); raw asm remains **test-covered** (not formal).

## 9. Milestone WBS — Tracking Backbone [DECISION]

Phase-1 kernel foundation in 5 milestones; each tied to the asm units above and to executable DoDs. **Ultracode follows this backbone.**

| Milestone | Scope (asm units) | Executable DoD |
|---|---|---|
| **M0 — Boot bring-up** | A0(x86 bootstrap), A1, A2, A10, A11 (both arches) | `hello from rust_main` serial; stock Firecracker **+ PVH** & QEMU, both arches green |
| **M1 — Traps** | A4, A5 + Rust dispatch | `int3`/`brk` + fault tests pass; ESR/error-code correct |
| **M2 — Context switch** | A3 + scheduler skeleton | 1000-yield canary + register-sentinel test |
| **M3 — MMU** | A6, A7, A8, A9 + typed page-table | higher-half map + TLB-flush test; aarch64 BBM; single-vCPU TLBI variant measurement |
| **M4 — (v2 gate) user/ring** | A12 (ring3/EL0) | transition to EL0/ring3 + back; syscall fast-path; capability dispatch edge |

| **MV — `tb-vmm` (owned VMM)** | rust-vmm crates + `tb-boot v0` contract; single-vCPU | Yuva boots on its own VMM; `tb-boot` 64-bit direct; the A0 trampoline + PVH dependency is **deleted** |

**Dependency:** M0 → M1 → M2 → M3 (sequential); **MV** parallel after M0 (canonical target; A0 is deleted on landing); M4 a separate phase (v2), after v1 is frozen. Thanks to the single-vCPU decision, **A13 (AP/SMP) is in no milestone** — the next major phase.

---

### Verification note
Of 16 hard facts including boot register values, ABI register sets, `naked_asm!` stabilization (1.88.0 / 2025-06-26), PSTATE=0x3c5, and the Image header, 14 were confirmed 2-0; 2 with corrections (source attribution of the zero-page fields; aarch64 serial = NS16550A, not PL011) — the corrections are folded into this spec. The PVH-vs-LinuxBoot conflict was resolved in favor of LinuxBoot based on verified facts (§0). [DECISION] units will be tested with executable DoD in prototype M-gates.

> **Errata (2026-07-10, docs-reconcile):** this note predates the §0 revision. Arda's 2026-06-07 directive ("entirely our own build, no Linux") shifted the boot-path decision AFTER this note was written; §0 is the current, binding text — canonical = `tb-boot v0` (owned handoff, no Linux), with stock Firecracker + PVH kept only as the temporary M0 bootstrap. This note is retained as historical record, not as the landed truth.