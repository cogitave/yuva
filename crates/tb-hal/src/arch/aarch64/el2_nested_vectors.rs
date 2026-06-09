//! aarch64 **aL2.4** nested-guest EL1 vector table (`__l2_nested_guest_vectors`)
//! -- the guest's OWN `VBAR_EL1`, installed by the guest itself before it takes
//! a deliberate `brk #0` EL1 exception UNDER our EL2 stage-2.
//!
//! Like `vectors.rs`/`el2_vectors.rs`/`exits_vectors.rs` this is compiled purely
//! for its `global_asm!` side effects: nothing here is referenced from Rust
//! except by symbol -- the table label `__l2_nested_guest_vectors`, whose
//! address the aL2.4 guest stub (`el2_nested_guest_stub` in `el2.rs`) loads into
//! its OWN `VBAR_EL1` after it has built and enabled its first-stage MMU. The
//! linker keeps the whole section via
//! `KEEP(*(.text._el2_nested_vectors))` in `kernel/linker/aarch64.ld`.
//!
//! ## Why a Current-EL-SPx slot (the guest's own M1-style trap)
//!
//! The aL2.4 guest, running at EL1h on `SP_EL1`, executes a `brk #0`. Because
//! the source EL == the target EL (both EL1h, using `SP_ELx`), the exception is
//! delivered to the **"Current EL with SPx, Synchronous"** slot at byte offset
//! **0x200** (the same `enter_exception64` `mode == target_mode ->
//! CURRENT_EL_SP_ELx_VECTOR = 0x200` rule the L2.2 inject path relies on). The
//! whole point is that this is an EL1->EL1 exception delivered INSIDE the guest
//! WITHOUT any exit to EL2 -- which is itself proof the guest's own exception
//! delivery works under our live stage-2. So ONLY the `+0x200` slot has a real
//! handler; every other slot is a fail trampoline.
//!
//! ## The handler (record "trap taken" and return)
//!
//! `+0x200`: confirm a GENUINE BRK was delivered (`ESR_EL1.EC == 0x3C`, the
//! AArch64 `BRK` exception class), advance `ELR_EL1` past the 32-bit `brk`
//! (`+4`) so the return does NOT re-trap, set a guest-side "trap taken"
//! sentinel into a callee-saved register the stub agreed on (x28 == the magic
//! `0x2E5` "trap-taken" marker), and `eret` back into the guest body. The stub
//! then checks x28 before presenting its final magic. Any OTHER slot (a stray
//! EL1 IRQ/abort -- e.g. an S1PTW that wrongly vectored to EL1 instead of EL2,
//! or a stage-2 abort surfacing as an EL1 SError) routes to a fail trampoline
//! that `hvc #9`s with a WRONG x0 magic (`0xBAD`), so a stray exception surfaces
//! as `Faulted`, NEVER a silent hang. The facade masks IRQs across the whole
//! window, so the fail slots are belt-and-suspenders.
//!
//! ## ABI contract with the stub
//!
//! The handler uses NO stack (SP_EL1 carries the guest's own SP, untouched) and
//! only x27/x28 (callee-saved registers the stub deliberately leaves free for
//! this handshake). `mov x28, #0x2E5` is a single MOVZ encoding; the value MUST
//! match `el2.rs`'s `NESTED_TRAP_TAKEN` (locked there by a
//! `const _: () = assert!(...)`). The `brk #0` instruction has `ESR_EL1.EC ==
//! 0x3C` (`ESR_ELx_EC_BRK64`), `ISS = imm16` -- the handler checks EC only.

use core::arch::global_asm;

// -- __l2_nested_guest_vectors (VBAR_EL1 the GUEST installs in the aL2.4 window) -
// (a) PRE : VBAR_EL1 == &__l2_nested_guest_vectors (2 KiB aligned), set by the
//           GUEST itself (not the facade) AFTER it enabled its own stage-1 MMU;
//           the guest's `brk #0` vectors here at base + 0x200 (Current-EL-SPx
//           Synchronous). POST: the +0x200 handler advances ELR_EL1 past the brk,
//           sets x28 = NESTED_TRAP_TAKEN, and `eret`s back to the guest body.
// (b) ABI : each 128-byte slot is `b <target>` (PC-relative, in range); the
//           handlers live just past the 2 KiB table, still inside the KEEP'd
//           section. They use NO stack (SP_EL1 untouched) and only x27/x28.
// (c) TEST: scripts/run-aarch64.sh -- the two-stage round-trip prints
//           "L2.4: el2-guest OK".
global_asm!(
    r#"
    // ---- one 128-byte vector slot: align, then branch to a handler ----------
    .macro VEC_SLOT_NESTED target
    .balign 0x80
    b   \target
    .endm

    .section .text._el2_nested_vectors, "ax"
    .balign 0x800                       // VBAR_EL1 requires 2 KiB alignment
    .globl __l2_nested_guest_vectors
__l2_nested_guest_vectors:
    // --- Current EL with SP0 (EL1t) -- the guest runs on SPx; fatal ----------
    VEC_SLOT_NESTED __l2_nested_vec_fail   // 0x000 Synchronous
    VEC_SLOT_NESTED __l2_nested_vec_fail   // 0x080 IRQ
    VEC_SLOT_NESTED __l2_nested_vec_fail   // 0x100 FIQ
    VEC_SLOT_NESTED __l2_nested_vec_fail   // 0x180 SError
    // --- Current EL with SPx (EL1h) -- the guest's own brk lands at 0x200 -----
    VEC_SLOT_NESTED __l2_nested_vec_brk    // 0x200 Synchronous <-- the brk target
    VEC_SLOT_NESTED __l2_nested_vec_fail   // 0x280 IRQ
    VEC_SLOT_NESTED __l2_nested_vec_fail   // 0x300 FIQ
    VEC_SLOT_NESTED __l2_nested_vec_fail   // 0x380 SError
    // --- Lower EL using AArch64 -- no lower EL under this guest; fatal --------
    VEC_SLOT_NESTED __l2_nested_vec_fail   // 0x400 Synchronous
    VEC_SLOT_NESTED __l2_nested_vec_fail   // 0x480 IRQ
    VEC_SLOT_NESTED __l2_nested_vec_fail   // 0x500 FIQ
    VEC_SLOT_NESTED __l2_nested_vec_fail   // 0x580 SError
    // --- Lower EL using AArch32 -- no AArch32 guests; fatal ------------------
    VEC_SLOT_NESTED __l2_nested_vec_fail   // 0x600 Synchronous
    VEC_SLOT_NESTED __l2_nested_vec_fail   // 0x680 IRQ
    VEC_SLOT_NESTED __l2_nested_vec_fail   // 0x700 FIQ
    VEC_SLOT_NESTED __l2_nested_vec_fail   // 0x780 SError
    .balign 0x80                        // pad slot 15 to a full 128 B: table == 0x800

    // ---- handlers (just past the 2 KiB table, still in the KEEP'd section) ---
__l2_nested_vec_brk:                    // the guest's OWN EL1 brk: confirm + record
    mrs  x27, esr_el1
    lsr  x27, x27, #26                  // x27 = ESR_EL1.EC of the brk exception
    cmp  x27, #0x3C                     // EC == 0x3C (BRK from AArch64)?
    b.ne __l2_nested_vec_fail           // not a genuine brk -> fail-closed
    mrs  x27, elr_el1
    add  x27, x27, #4                   // step past the 32-bit `brk #0`
    msr  elr_el1, x27
    mov  x28, #0x2E5                    // NESTED_TRAP_TAKEN sentinel (must match el2.rs)
    eret                                // return to the guest body (NO EL2 exit)
__l2_nested_vec_fail:                   // any other guest vector: surface a FAIL
    mov  x0, #0xBAD                     // a WRONG magic -> hvc #9 -> FAIL_NG_BAD_MAGIC
    hvc  #9
    b    .                              // guard: the monitor unwinds, never here
"#
);
