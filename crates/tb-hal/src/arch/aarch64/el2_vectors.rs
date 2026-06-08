//! aarch64 **L2.0** resident-EL2-monitor vector table (`VBAR_EL2`) and its
//! save path -- the EL2 mirror of `vectors.rs`.
//!
//! Like `boot.rs`/`vectors.rs` this is compiled purely for its `global_asm!`
//! side effects: nothing here is referenced from Rust except by symbol -- the
//! table label `__el2_exception_vectors` (loaded into `VBAR_EL2` by
//! `boot.rs::_start`), and the extern handlers `aarch64_el2_sync_handler` /
//! `aarch64_el2_fault_handler` (both in `el2.rs`). The linker keeps the whole
//! table via `KEEP(*(.text._el2_vectors))` in `kernel/linker/aarch64.ld`.
//!
//! Layout (identical structure to the EL1 `VBAR_EL1` table -- obey exactly):
//!  * `VBAR_EL2` points at a **2 KiB-aligned** table of **16 entries x 128 B**:
//!    {Current-EL-SP0, Current-EL-SPx, Lower-EL-AArch64, Lower-EL-AArch32}
//!    x {Synchronous, IRQ, FIQ, SError}. (Arm ARM D1 exception vectors.)
//!  * An `HVC` from EL1 (AArch64) is taken through the **"Lower EL using
//!    AArch64, Synchronous"** slot: index 8, byte offset **0x400**. That is the
//!    ONLY real handler (`__el2_vec_lower_sync` -> `aarch64_el2_sync_handler`),
//!    which disambiguates the kernel bootstrap `HVC #0` from the guest's
//!    `HVC #1` via `ESR_EL2.ISS`. Every OTHER slot routes to `__el2_vec_other`
//!    -> `aarch64_el2_fault_handler`, which surfaces a FAIL by unwinding back
//!    to the kernel with a nonzero code (never a silent loop / hang).
//!  * `SAVE_CONTEXT_EL2` mirrors the EL1 `SAVE_CONTEXT` byte-for-byte but uses
//!    `ELR_EL2`/`SPSR_EL2`: push x0..x30 + `ELR_EL2` + `SPSR_EL2` into a
//!    **0x110-byte** frame on `SP_EL2` (the dedicated monitor stack). The
//!    matching restore + `eret` is done by `el2.rs` (it is state-dependent:
//!    the bootstrap-HVC path erets INTO the guest, the guest-HVC path unwinds
//!    BACK to the kernel), so there is no `RESTORE_CONTEXT_EL2` macro here.
//!  * softfloat target (`-fp-armv8,-neon`): the V/SIMD registers carry no live
//!    state and are intentionally NOT part of the frame (same as `vectors.rs`).

use core::arch::global_asm;

// -- __el2_exception_vectors + the EL2 save path ----------------------------
// (a) PRE : VBAR_EL2 == &__el2_exception_vectors (2 KiB aligned); a synchronous
//           exception from EL1 (an HVC) is taken at Lower-EL-AArch64 (0x400).
//           POST: a 0x110 frame {x0..x30, ELR_EL2, SPSR_EL2} is built on the
//           dedicated EL2 stack (SP_EL2), x0 = &frame, and Rust dispatch runs.
//           The handler never returns here (it erets itself: into the guest for
//           the bootstrap HVC, or back to the kernel for the guest HVC).
// (b) ABI : SP_EL2 is 16-aligned (linker) and the 0x110 frame keeps it aligned
//           across `bl` (AAPCS64 arg0 = x0 = &frame). `bl` clobbers x30, which
//           was already saved.
// (c) TEST: scripts/run-aarch64.sh -- the kernel's `hvc #0` then the guest's
//           `hvc #1` both land at 0x400; the round-trip prints "L2.0: el2 OK".
global_asm!(
    r#"
    // ---- EL2 context save: x0..x30, ELR_EL2, SPSR_EL2 -> 0x110-byte frame ----
    .macro SAVE_CONTEXT_EL2
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
    mrs  x9,  elr_el2            // x9/x10 already saved above; free to reuse
    mrs  x10, spsr_el2
    stp  x9,  x10, [sp, #0xF8]   // elr @ 0xF8, spsr @ 0x100
    .endm

    // ---- one 128-byte vector slot: align, then branch to a trampoline --------
    .macro VEC_SLOT_EL2 target
    .balign 0x80
    b   \target
    .endm

    .section .text._el2_vectors, "ax"
    .balign 0x800                 // VBAR_EL2 requires 2 KiB alignment
    .globl __el2_exception_vectors
__el2_exception_vectors:
    // --- Current EL with SP0 (EL2t) -- we never run on SP0; fatal ------------
    VEC_SLOT_EL2 __el2_vec_other  // 0x000 Synchronous
    VEC_SLOT_EL2 __el2_vec_other  // 0x080 IRQ
    VEC_SLOT_EL2 __el2_vec_other  // 0x100 FIQ
    VEC_SLOT_EL2 __el2_vec_other  // 0x180 SError
    // --- Current EL with SPx (EL2h) -- the monitor's own EL; unexpected ------
    VEC_SLOT_EL2 __el2_vec_other  // 0x200 Synchronous
    VEC_SLOT_EL2 __el2_vec_other  // 0x280 IRQ
    VEC_SLOT_EL2 __el2_vec_other  // 0x300 FIQ
    VEC_SLOT_EL2 __el2_vec_other  // 0x380 SError
    // --- Lower EL using AArch64 (EL1) -- HVC #imm lands here -----------------
    VEC_SLOT_EL2 __el2_vec_lower_sync // 0x400 Synchronous <-- the HVC handler
    VEC_SLOT_EL2 __el2_vec_other  // 0x480 IRQ (IMO=0: stays at EL1, never here)
    VEC_SLOT_EL2 __el2_vec_other  // 0x500 FIQ
    VEC_SLOT_EL2 __el2_vec_other  // 0x580 SError
    // --- Lower EL using AArch32 -- no AArch32 guests; fatal ------------------
    VEC_SLOT_EL2 __el2_vec_other  // 0x600 Synchronous
    VEC_SLOT_EL2 __el2_vec_other  // 0x680 IRQ
    VEC_SLOT_EL2 __el2_vec_other  // 0x700 FIQ
    VEC_SLOT_EL2 __el2_vec_other  // 0x780 SError
    .balign 0x80                  // pad slot 15 to a full 128 B: table == 0x800

    // ---- trampolines (live just past the 2 KiB table, still KEEP'd) ----------
__el2_vec_lower_sync:             // Lower-EL-AArch64 synchronous: HVC #0 / #1
    SAVE_CONTEXT_EL2
    mov  x0, sp                   // AAPCS64 arg0 = &frame (x0..x30, ELR/SPSR_EL2)
    bl   aarch64_el2_sync_handler // el2.rs: erets itself (to guest / to kernel)
    b    .                        // guard: the handler never returns
__el2_vec_other:                  // every other vector: unexpected -> FAIL
    SAVE_CONTEXT_EL2
    mov  x0, sp                   // AAPCS64 arg0 = &frame
    bl   aarch64_el2_fault_handler// el2.rs: unwind to the kernel with a FAIL code
    b    .                        // guard: the handler never returns
"#
);
