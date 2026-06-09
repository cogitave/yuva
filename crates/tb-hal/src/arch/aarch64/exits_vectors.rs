//! aarch64 **L2.2** guest EL1 vector table (`__l2_guest_vectors`) -- the target
//! of the monitor's software-synthesized UNDEF injection.
//!
//! Like `vectors.rs`/`el2_vectors.rs` this is compiled purely for its
//! `global_asm!` side effects: nothing here is referenced from Rust except by
//! symbol -- the table label `__l2_guest_vectors`, which [`super::el2`]'s
//! `el2_exits_selftest` loads into `VBAR_EL1` for the duration of the exits
//! window (and restores on exit). The linker keeps the whole section via
//! `KEEP(*(.text._l2_guest_vectors))` in `kernel/linker/aarch64.ld`.
//!
//! ## Why a Current-EL-SPx slot (the #1 inject-vectoring trap)
//!
//! The monitor injects an Undefined-Instruction exception into the guest's OWN
//! EL1 (`el2_inject_undef`): it programs `ESR_EL1`/`ELR_EL1`/`SPSR_EL1`,
//! redirects `ELR_EL2` to `VBAR_EL1 + 0x200`, and `eret`s. Because the source EL
//! == the target EL (both EL1h, using SP_ELx), the exception is delivered to the
//! **"Current EL with SPx, Synchronous"** slot at byte offset **0x200** -- NOT
//! the Lower-EL `+0x400` slot (that would land in the wrong/empty slot and
//! hang). Authority: KVM `enter_exception64`'s `mode == target_mode ->
//! CURRENT_EL_SP_ELx_VECTOR = 0x200`. So ONLY the `+0x200` slot needs a real
//! handler; every other slot routes to a fail trampoline.
//!
//! ## The handlers (echo a magic through `HVC #5`)
//!
//! `+0x200`: confirm a GENUINE UNKNOWN was delivered (`ESR_EL1.EC == 0`), load
//! the agreed magic into x0, and `HVC #5` to close the round-trip (the monitor's
//! done handler verifies x0 == magic AND the WFx|UNDEF served bits). Any OTHER
//! slot (a stray EL1 IRQ/abort while `VBAR_EL1` is hijacked) routes to a fail
//! trampoline that `HVC #5`s a WRONG magic, so a stray exception surfaces as
//! `Faulted` (the monitor sees the wrong magic), NEVER a silent hang. The facade
//! masks IRQs across the whole window, so the fail slots are a belt-and-suspenders
//! net.
//!
//! `mov x0, #0xE22` (UNDEF_GUEST_MAGIC) and `mov x0, #0xBAD` (a wrong magic) are
//! single MOVZ encodings; the magic value MUST match `el2.rs`'s
//! `UNDEF_GUEST_MAGIC` (locked there by a `const _: () = assert!(...)`).

use core::arch::global_asm;

// -- __l2_guest_vectors (VBAR_EL1 during the L2.2 exits window) --------------
// (a) PRE : VBAR_EL1 == &__l2_guest_vectors (2 KiB aligned), set by the facade;
//           the monitor's injected UNDEF redirects ELR_EL2 to this base + 0x200
//           and `eret`s into the guest at EL1h. POST: the +0x200 handler echoes
//           UNDEF_GUEST_MAGIC through `HVC #5`; the monitor unwinds and never
//           returns here (the `b .` guards are unreachable).
// (b) ABI : each 128-byte slot is `b <target>` (PC-relative, in range); the
//           handlers live just past the 2 KiB table, still inside the KEEP'd
//           section. They use NO stack (SP_EL1 untouched) and only x0/x1.
// (c) TEST: scripts/run-aarch64.sh -- the inject round-trip prints
//           "L2.2: el2-exits OK".
global_asm!(
    r#"
    // ---- one 128-byte vector slot: align, then branch to a handler ----------
    .macro VEC_SLOT_GUEST target
    .balign 0x80
    b   \target
    .endm

    .section .text._l2_guest_vectors, "ax"
    .balign 0x800                     // VBAR_EL1 requires 2 KiB alignment
    .globl __l2_guest_vectors
__l2_guest_vectors:
    // --- Current EL with SP0 (EL1t) -- the guest runs on SPx; fatal ----------
    VEC_SLOT_GUEST __l2_guest_vec_fail   // 0x000 Synchronous
    VEC_SLOT_GUEST __l2_guest_vec_fail   // 0x080 IRQ
    VEC_SLOT_GUEST __l2_guest_vec_fail   // 0x100 FIQ
    VEC_SLOT_GUEST __l2_guest_vec_fail   // 0x180 SError
    // --- Current EL with SPx (EL1h) -- the injected UNDEF lands at 0x200 ------
    VEC_SLOT_GUEST __l2_guest_vec_undef  // 0x200 Synchronous <-- the inject target
    VEC_SLOT_GUEST __l2_guest_vec_fail   // 0x280 IRQ
    VEC_SLOT_GUEST __l2_guest_vec_fail   // 0x300 FIQ
    VEC_SLOT_GUEST __l2_guest_vec_fail   // 0x380 SError
    // --- Lower EL using AArch64 -- no lower EL under this guest; fatal --------
    VEC_SLOT_GUEST __l2_guest_vec_fail   // 0x400 Synchronous
    VEC_SLOT_GUEST __l2_guest_vec_fail   // 0x480 IRQ
    VEC_SLOT_GUEST __l2_guest_vec_fail   // 0x500 FIQ
    VEC_SLOT_GUEST __l2_guest_vec_fail   // 0x580 SError
    // --- Lower EL using AArch32 -- no AArch32 guests; fatal ------------------
    VEC_SLOT_GUEST __l2_guest_vec_fail   // 0x600 Synchronous
    VEC_SLOT_GUEST __l2_guest_vec_fail   // 0x680 IRQ
    VEC_SLOT_GUEST __l2_guest_vec_fail   // 0x700 FIQ
    VEC_SLOT_GUEST __l2_guest_vec_fail   // 0x780 SError
    .balign 0x80                      // pad slot 15 to a full 128 B: table == 0x800

    // ---- handlers (just past the 2 KiB table, still in the KEEP'd section) ---
__l2_guest_vec_undef:                 // injected UNDEF: confirm EC==0, echo magic
    mrs  x1, esr_el1
    lsr  x1, x1, #26                  // x1 = ESR_EL1.EC of the injected exception
    mov  x0, #0xE22                   // UNDEF_GUEST_MAGIC (must match el2.rs)
    cbz  x1, 1f                       // EC==0 (genuine UNKNOWN) -> keep good magic
    mov  x0, #0xBAD                   // EC!=0 -> not a genuine UNDEF: a wrong magic
1:  hvc  #5                           // back to EL2 (done): verify + unwind
    b    .                            // guard: the monitor unwinds, never here
__l2_guest_vec_fail:                  // any other guest vector: surface a FAIL
    mov  x0, #0xBAD                   // a WRONG magic -> HVC #5 -> FAIL_EXITS_BAD_MAGIC
    hvc  #5
    b    .                            // guard: the monitor unwinds, never here
"#
);
