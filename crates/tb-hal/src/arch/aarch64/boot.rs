//! aarch64 boot entry (`_start`) and the minimal EL1 exception vector table.
//!
//! All assembly in TABOS is confined to `tb-hal`; this module is the aarch64
//! half of unit **A1/A2** in KERNEL-FOUNDATION-SPEC §3. It is compiled purely
//! for its `global_asm!` side effects -- nothing here is referenced from Rust;
//! the linker keeps `_start` via `ENTRY(_start)` + `KEEP()` in
//! `kernel/linker/aarch64.ld`.
//!
//! Boot contract (QEMU `virt`, `-kernel <ELF>`; verified -- Firecracker sets
//! the parity state PSTATE = 0x3c5 = EL1h with D/A/I/F masked): the vCPU enters
//! at **EL1h, MMU OFF, DAIF masked, x0 = FDT pointer**. QEMU loads the PT_LOAD
//! segments at their p_paddr and jumps to e_entry (`_start`).

use core::arch::global_asm;

// -- _start -----------------------------------------------------------------
// (a) PRE : EL1h, MMU OFF, DAIF masked, x0 = FDT/DTB pointer (QEMU `virt` boot
//           ABI). POST: SP = top of the 16 KiB boot stack, .bss zeroed,
//           VBAR_EL1 = exception table, control tail-branched to
//           rust_main(x0) with x0 (FDT) preserved as AAPCS64 arg0.
// (b) ABI : clobbers x1, x2 only; x0 preserved end-to-end; no stack used before
//           SP is set; `b` (not `bl`) -- rust_main is `-> !`, never returns.
// (c) TEST: scripts/run-aarch64.sh asserts "hello from rust_main".
global_asm!(
    r#"
    .section .text._start, "ax"
    .globl _start
_start:
    // x0 holds the FDT pointer on entry; it is never touched below, so it
    // survives untouched into rust_main as AAPCS64 argument 0.

    // (1) Establish the boot stack (linker guarantees 16-byte alignment).
    adrp x1, __boot_stack_top
    add  x1, x1, :lo12:__boot_stack_top
    mov  sp, x1

    // (2) Zero .bss [__bss_start, __bss_end) eight bytes at a time. Both bounds
    //     are 16-byte aligned, so the doubleword stores never overrun.
    adrp x1, __bss_start
    add  x1, x1, :lo12:__bss_start
    adrp x2, __bss_end
    add  x2, x2, :lo12:__bss_end
0:  cmp  x1, x2
    b.hs 1f
    str  xzr, [x1], #8
    b    0b
1:

    // (3) Point VBAR_EL1 at our (spin-on-fault) table and synchronize, so the
    //     new vector base is in effect before anything could trap.
    adrp x1, __exception_vectors
    add  x1, x1, :lo12:__exception_vectors
    msr  vbar_el1, x1
    isb

    // (4) Enter safe Rust. x0 still = FDT pointer.
    b    rust_main
"#
);

// -- __exception_vectors ----------------------------------------------------
// (a) PRE : VBAR_EL1 set to this 2 KiB-aligned label. POST: any synchronous
//           exception / IRQ / FIQ / SError from any level lands in its 0x80
//           slot and spins in place (M0 has no trap handling -- that is unit
//           A4 / milestone M1).
// (b) ABI : pure code, 16 x 128-byte slots, no registers/memory touched.
// (c) TEST: scripts/run-aarch64.sh -- installing the table must not perturb the
//           happy path (print + halt); a real fault would visibly hang.
global_asm!(
    r#"
    .section .text._vectors, "ax"
    .balign 0x800
    .globl __exception_vectors
__exception_vectors:
    .rept 16
    .balign 0x80
    b   .
    .endr
"#
);
