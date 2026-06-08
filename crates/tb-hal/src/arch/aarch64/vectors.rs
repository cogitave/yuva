//! aarch64 EL1 exception vector table (`VBAR_EL1`) and the trap entry/exit path.
//!
//! This is unit **A4 / milestone M1** on aarch64 (extended at **M4**). Like
//! `boot.rs` it is compiled purely for its `global_asm!` side effects: nothing
//! here is referenced from Rust except by symbol -- the table label
//! `__exception_vectors` (loaded into `VBAR_EL1` by `boot.rs::_start` and
//! re-armed by `mod.rs::install_traps`), the extern `aarch64_trap_handler`
//! (defined in `trap.rs`, M1), and the extern `aarch64_el0_sync_handler`
//! (defined in `user.rs`, M4). The linker keeps the whole table via
//! `KEEP(*(.text._vectors))` in `kernel/linker/aarch64.ld`.
//!
//! Layout (verified facts -- obey exactly):
//!  * `VBAR_EL1` points at a **2 KiB-aligned** table of **16 entries x 128 B**.
//!    The 16 slots are, in order, the cross product
//!    {Current-EL-SP0, Current-EL-SPx, Lower-EL-AArch64, Lower-EL-AArch32}
//!    x {Synchronous, IRQ/vIRQ, FIQ/vFIQ, SError/vSError}.
//!      - Arm Architecture Reference Manual (DDI 0487), D1 "AArch64 Exception
//!        model" / "Exception vectors" (the VBAR_ELx + 16x0x80 table).
//!      - OSDev Wiki, "Exception handling in AArch64" (vector table base must be
//!        2 KiB aligned; each of the 16 entries is 0x80 bytes).
//!      - Cross-checked against Linux `arch/arm64/kernel/entry.S`:
//!        `SYM_CODE_START(vectors)` is `.align 11` (2^11 = 2 KiB) and each
//!        `kernel_ventry` is `.align 7` (2^7 = 128 B); the ventry order is
//!        EL1t{sync,irq,fiq,err}, EL1h{sync,irq,fiq,err}, EL0_64{...}, EL0_32{...}.
//!  * The kernel boots and runs at **EL1h** (handler, `SP_EL1` == "SPx"), so a
//!    synchronous exception from our own code -- e.g. `brk #0` -- is taken
//!    through the **"Current EL with SPx, Synchronous"** slot: index 4, byte
//!    offset **0x200** (M1, real handler -> `trap.rs`).
//!  * A synchronous exception from **EL0** -- e.g. the M4 user stub's `svc #0`
//!    -- is taken through the **"Lower EL using AArch64, Synchronous"** slot:
//!    index 8, byte offset **0x400**. M4 makes this a REAL handler
//!    (`__vec_el0_sync` -> `aarch64_el0_sync_handler` in `user.rs`). Every
//!    OTHER slot still routes to the common stub (`__vec_other`), reported as
//!    `TrapKind::Other` (the default policy then halts).
//!  * Save / restore mirrors Linux `entry.S` `kernel_entry` / `kernel_exit`:
//!    push x0..x30 + `ELR_EL1` + `SPSR_EL1`; `mov x0, sp`; `bl` into Rust;
//!    reload `ELR_EL1`/`SPSR_EL1` (the handler may have advanced `ELR_EL1` by 4
//!    to resume past a `brk`); pop x0..x30; `eret`.
//!  * The target spec `targets/aarch64-tabos-none.json` is `abi: softfloat`
//!    with `-fp-armv8,-neon`, so the V/SIMD registers carry no live state and
//!    are intentionally NOT part of the frame (FP context save lands with
//!    preemption / userspace FP, not M1/M4).

use core::arch::global_asm;

// -- __exception_vectors + trap entry/exit ----------------------------------
// (a) PRE : VBAR_EL1 == &__exception_vectors (2 KiB aligned); a synchronous
//           exception is taken at Current-EL-SPx (M1) or Lower-EL-AArch64 (M4).
//           POST: a TrapFrame of x0..x30 + ELR_EL1 + SPSR_EL1 is built on the
//           exception stack (SP_EL1 -- the kernel stack), Rust dispatch runs,
//           then for the EL1 path state is restored and `eret` resumes the
//           interrupted context; for the EL0 SVC path the handler longjmps
//           into the kernel instead (see user.rs) and never returns here.
// (b) ABI  : SP must be 16-aligned on entry (kernel maintains it); the 0x110
//           frame keeps it aligned across `bl` (AAPCS64 arg0 = x0 = &TrapFrame,
//           arg1 = x1 = source tag). `bl` clobbers x30, which was already
//           saved. `eret` restores PSTATE from SPSR_EL1.
// (c) TEST : scripts/run-aarch64.sh -- breakpoint() takes slot 0x200 ("M1:
//           traps OK"); the user stub's `svc` takes slot 0x400 ("M4: user/ring
//           OK").
global_asm!(
    r#"
    // ---- context save: x0..x30, ELR_EL1, SPSR_EL1 -> 0x110-byte TrapFrame ----
    .macro SAVE_CONTEXT
    sub  sp, sp, #0x110
    stp  x0,  x1,  [sp, #0x00]
    stp  x2,  x3,  [sp, #0x10]
    stp  x4,  x5,  [sp, #0x20]
    stp  x6,  x7,  [sp, #0x30]
    stp  x8,  x9,  [sp, #0x40]
    stp  x10, x11, [sp, #0x50]
    stp  x12, x13, [sp, #0x60]
    stp  x14, x15, [sp, #0x70]
    stp  x16, x17, [sp, #0x80]
    stp  x18, x19, [sp, #0x90]
    stp  x20, x21, [sp, #0xA0]
    stp  x22, x23, [sp, #0xB0]
    stp  x24, x25, [sp, #0xC0]
    stp  x26, x27, [sp, #0xD0]
    stp  x28, x29, [sp, #0xE0]
    str  x30,      [sp, #0xF0]
    mrs  x9,  elr_el1            // x9/x10 already saved above; free to reuse
    mrs  x10, spsr_el1
    stp  x9,  x10, [sp, #0xF8]   // elr @ 0xF8, spsr @ 0x100
    .endm

    // ---- context restore (elr/spsr first, then GPRs reclaim x9/x10) ----------
    .macro RESTORE_CONTEXT
    ldp  x9,  x10, [sp, #0xF8]   // handler may have written elr (brk resume)
    msr  elr_el1,  x9
    msr  spsr_el1, x10
    ldp  x0,  x1,  [sp, #0x00]
    ldp  x2,  x3,  [sp, #0x10]
    ldp  x4,  x5,  [sp, #0x20]
    ldp  x6,  x7,  [sp, #0x30]
    ldp  x8,  x9,  [sp, #0x40]   // restores the real x9
    ldp  x10, x11, [sp, #0x50]   // restores the real x10
    ldp  x12, x13, [sp, #0x60]
    ldp  x14, x15, [sp, #0x70]
    ldp  x16, x17, [sp, #0x80]
    ldp  x18, x19, [sp, #0x90]
    ldp  x20, x21, [sp, #0xA0]
    ldp  x22, x23, [sp, #0xB0]
    ldp  x24, x25, [sp, #0xC0]
    ldp  x26, x27, [sp, #0xD0]
    ldp  x28, x29, [sp, #0xE0]
    ldr  x30,      [sp, #0xF0]
    add  sp, sp, #0x110
    .endm

    // ---- one 128-byte vector slot: align, then branch to a trampoline --------
    .macro VEC_SLOT target
    .balign 0x80
    b   \target
    .endm

    .section .text._vectors, "ax"
    .balign 0x800                 // VBAR_EL1 requires 2 KiB alignment
    .globl __exception_vectors
__exception_vectors:
    // --- Current EL with SP0 (EL1t) -- we never run on SP0; treat as fatal ---
    VEC_SLOT __vec_other          // 0x000 Synchronous
    VEC_SLOT __vec_other          // 0x080 IRQ / vIRQ
    VEC_SLOT __vec_other          // 0x100 FIQ / vFIQ
    VEC_SLOT __vec_other          // 0x180 SError / vSError
    // --- Current EL with SPx (EL1h) -- this is where our kernel runs ---------
    VEC_SLOT __vec_sync           // 0x200 Synchronous  <-- real handler (M1)
    VEC_SLOT __vec_irq            // 0x280 IRQ / vIRQ   <-- real handler (M8)
    VEC_SLOT __vec_other          // 0x300 FIQ / vFIQ   (masked in M1)
    VEC_SLOT __vec_other          // 0x380 SError / vSError
    // --- Lower EL using AArch64 (EL0) ---------------------------------------
    VEC_SLOT __vec_el0_sync       // 0x400 Synchronous  <-- real handler (M4/M11/M12 SVC)
    VEC_SLOT __vec_irq            // 0x480 IRQ          <-- M12: preempt an EL0 agent
    VEC_SLOT __vec_other          // 0x500 FIQ
    VEC_SLOT __vec_other          // 0x580 SError
    // --- Lower EL using AArch32 -- no AArch32 guests; fatal ------------------
    VEC_SLOT __vec_other          // 0x600 Synchronous
    VEC_SLOT __vec_other          // 0x680 IRQ
    VEC_SLOT __vec_other          // 0x700 FIQ
    VEC_SLOT __vec_other          // 0x780 SError
    .balign 0x80                  // pad slot 15 to a full 128 B: table == 0x800

    // ---- trampolines (live just past the 2 KiB table, still KEEP'd) ----------
__vec_sync:                       // Current-EL-SPx synchronous: brk/undef/abort
    SAVE_CONTEXT
    mov  x1, #0                   // source = 0: synchronous, current EL (SPx)
    b    __trap_dispatch
__vec_other:                      // every other vector: unexpected -> fatal
    SAVE_CONTEXT
    mov  x1, #1                   // source = 1: unexpected vector
    b    __trap_dispatch
__vec_irq:                        // Current-EL-SPx IRQ: the M8 periodic timer
    SAVE_CONTEXT
    mov  x1, #2                   // source = 2: asynchronous IRQ (current EL)
    b    __trap_dispatch
__vec_el0_sync:                   // Lower-EL-AArch64 synchronous: EL0 SVC (M4/M11/M12)
    SAVE_CONTEXT
    mov  x0, sp                   // AAPCS64 arg0 = &Frame (x0..x30, ELR, SPSR)
    bl   aarch64_el0_sync_handler // user.rs: M12 agents DISPATCH + return here;
                                  //   M4/M11 probes longjmp out (never return)
    RESTORE_CONTEXT               // M12 agent path: restore x0..x30 (x0/x1=result)
    eret                          // -> back to EL0 at the instruction after svc
__trap_dispatch:
    mov  x0, sp                   // AAPCS64 arg0 = &TrapFrame
    bl   aarch64_trap_handler     // extern "C" in trap.rs; may halt (Halt path)
    RESTORE_CONTEXT               // Resume path: pop state (elr maybe +4)
    eret
"#
);
