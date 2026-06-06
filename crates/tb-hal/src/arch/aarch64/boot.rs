//! aarch64 boot entry (`_start`): stack, `.bss`, and the initial `VBAR_EL1` arm.
//!
//! All assembly in TABOS is confined to `tb-hal`; this module is the aarch64
//! half of unit **A1/A2** in KERNEL-FOUNDATION-SPEC SS3. It is compiled purely
//! for its `global_asm!` side effects -- nothing here is referenced from Rust;
//! the linker keeps `_start` via `ENTRY(_start)` + `KEEP()` in
//! `kernel/linker/aarch64.ld`.
//!
//! The exception vector table itself moved to `vectors.rs` at M1 (unit A4):
//! `_start` only *pre-arms* `VBAR_EL1` with the `__exception_vectors` symbol so
//! a fault during early boot is still vectored (the default policy halts).
//! `mod.rs::install_traps()` re-arms the same table from `rust_main` once the
//! console is up; the two writes are identical and idempotent.
//!
//! Boot contract (QEMU `virt`, `-kernel <ELF>`; verified -- Firecracker sets
//! the parity state PSTATE = 0x3c5 = EL1h with D/A/I/F masked): the vCPU enters
//! at **EL1h, MMU OFF, DAIF masked, x0 = FDT pointer**. QEMU loads the PT_LOAD
//! segments at their p_paddr and jumps to e_entry (`_start`).

use core::arch::global_asm;

// -- _start -----------------------------------------------------------------
// (a) PRE : EL1h, MMU OFF, DAIF masked, x0 = FDT/DTB pointer (QEMU `virt` boot
//           ABI). POST: SP = top of the 16 KiB boot stack, .bss zeroed,
//           VBAR_EL1 = __exception_vectors (vectors.rs), control tail-branched
//           to rust_main(x0) with x0 (FDT) preserved as AAPCS64 arg0.
// (b) ABI : clobbers x1, x2 only; x0 preserved end-to-end; no stack used before
//           SP is set; `b` (not `bl`) -- rust_main is `-> !`, never returns.
// (c) TEST: scripts/run-aarch64.sh asserts the milestone marker on serial.
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

    // (3) Pre-arm VBAR_EL1 with the M1 exception vector table (vectors.rs) and
    //     synchronize, so any early fault is vectored before we enter Rust.
    //     install_traps() re-arms this same table once the console is up.
    adrp x1, __exception_vectors
    add  x1, x1, :lo12:__exception_vectors
    msr  vbar_el1, x1
    isb

    // (4) Enter safe Rust. x0 still = FDT pointer.
    b    rust_main
"#
);
