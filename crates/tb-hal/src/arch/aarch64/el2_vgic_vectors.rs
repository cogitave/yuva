//! aarch64 **aL2.5** vGIC guest EL1 vector table (`__l2_vgic_guest_vectors`) --
//! the guest's OWN `VBAR_EL1`, installed by the aL2.5 guest stub before it parks
//! on `WFI` so the injected VIRTUAL interrupt it is woken by vectors to a REAL
//! EL1 IRQ handler that acks + EOIs the vIRQ through the GICV virtual CPU
//! interface.
//!
//! Like `vectors.rs`/`el2_vectors.rs`/`exits_vectors.rs`/`el2_nested_vectors.rs`
//! this is compiled purely for its `global_asm!` side effects: nothing here is
//! referenced from Rust except by symbol -- the table label
//! `__l2_vgic_guest_vectors`, whose address the aL2.5 guest stub
//! (`el2_vgic_guest_stub` in `el2.rs`) loads into its OWN `VBAR_EL1`. The linker
//! keeps the whole section via `KEEP(*(.text._l2_vgic_vectors))` in
//! `kernel/linker/aarch64.ld`.
//!
//! ## Why the 0x280 Current-EL-SPx IRQ slot (a VIRTUAL interrupt at EL1)
//!
//! The aL2.5 guest runs at EL1h on `SP_EL1` with `PSTATE.I` UNMASKED. The EL2
//! monitor (on the guest's trapped `WFI`) injects a PENDING virtual interrupt
//! via `GICH_LR0`; with `GICH_HCR.En` set, `HCR_EL2.IMO` routing the VIRQ line
//! to EL1, the guest's `GICV_CTLR.En` set and a permissive `GICV_PMR`, the VIRQ
//! is delivered to the guest as an IRQ. Because the source EL == the target EL
//! (both EL1h, using `SP_ELx`), the IRQ is taken to the **"Current EL with SPx,
//! IRQ"** slot at byte offset **0x280** (NOT the SP0 `+0x080` slot, NOR the
//! Lower-EL `+0x480` slot). So ONLY the `+0x280` slot has a real handler; every
//! other slot is a fail trampoline.
//!
//! ## The handler (ack the vIRQ via GICV, record, EOI, return)
//!
//! `+0x280`: read `GICV_IAR` (`GICV_BASE + 0x00C`) -- the side-effecting ack that
//! transitions the injected `GICH_LR0` PENDING -> ACTIVE and returns the
//! vINTID in bits[9:0]. Compare it against the injected vINTID (`VGIC_VINTID`):
//! ONLY on a match set the trap-taken sentinel `x28 = VGIC_IRQ_TAKEN` (a single
//! MOVZ, locked against `el2.rs`'s const by a `const _: () = assert!(...)`).
//! Then write `GICV_EOIR` (`GICV_BASE + 0x010`) with the IAR value to end the
//! interrupt -- the LR retires (ACTIVE -> INVALID, `GICH_ELRSR0` bit0 -> 1), the
//! monitor-side completion proof. Finally `eret` back to the post-`WFI` guest
//! body (NO EL2 exit -- the whole ack/EOI is an EL1->EL1 IRQ taken and returned
//! inside the guest). Any OTHER slot (a stray exception) routes to a fail
//! trampoline that `hvc #11`s with a WRONG x0 magic, so a stray exception
//! surfaces as `Faulted`, NEVER a silent hang.
//!
//! ## ABI contract with the stub
//!
//! The handler uses NO stack (SP_EL1 carries the guest's own SP, untouched) and
//! only the caller-saved x9..x11 scratch + the callee-saved x27/x28 handshake
//! registers the stub deliberately leaves free. `GICV_BASE = 0x0804_0000` is
//! materialised with a single `movz #0x0804, lsl #16`; the GICV register offsets
//! (IAR 0x0C, EOIR 0x10) are immediates. `mov x28, #VGIC_IRQ_TAKEN` is a single
//! MOVZ; the value MUST match `el2.rs`'s `VGIC_IRQ_TAKEN` (locked there). The
//! injected vINTID `VGIC_VINTID` MUST match `el2.rs`'s const too (locked there).

use core::arch::global_asm;

// -- __l2_vgic_guest_vectors (VBAR_EL1 the GUEST installs in the aL2.5 window) --
// (a) PRE : VBAR_EL1 == &__l2_vgic_guest_vectors (2 KiB aligned), set by the
//           GUEST itself (not the facade) BEFORE it parks on WFI; the injected
//           VIRQ (woken from WFI by the monitor) vectors here at base + 0x280
//           (Current-EL-SPx IRQ). POST: the +0x280 handler reads GICV_IAR, sets
//           x28 = VGIC_IRQ_TAKEN iff IAR == VGIC_VINTID, writes GICV_EOIR, and
//           `eret`s back to the guest body.
// (b) ABI : each 128-byte slot is `b <target>` (PC-relative, in range); the
//           handlers live just past the 2 KiB table, still inside the KEEP'd
//           section. They use NO stack (SP_EL1 untouched) and only x9..x11 +
//           x27/x28.
// (c) TEST: scripts/run-aarch64.sh -- the vGIC round-trip prints "L2.5: vgic OK".
global_asm!(
    r#"
    // ---- one 128-byte vector slot: align, then branch to a handler ----------
    .macro VEC_SLOT_VGIC target
    .balign 0x80
    b   \target
    .endm

    .section .text._l2_vgic_vectors, "ax"
    .balign 0x800                       // VBAR_EL1 requires 2 KiB alignment
    .globl __l2_vgic_guest_vectors
__l2_vgic_guest_vectors:
    // --- Current EL with SP0 (EL1t) -- the guest runs on SPx; fatal ----------
    VEC_SLOT_VGIC __l2_vgic_vec_fail    // 0x000 Synchronous
    VEC_SLOT_VGIC __l2_vgic_vec_fail    // 0x080 IRQ
    VEC_SLOT_VGIC __l2_vgic_vec_fail    // 0x100 FIQ
    VEC_SLOT_VGIC __l2_vgic_vec_fail    // 0x180 SError
    // --- Current EL with SPx (EL1h) -- the injected vIRQ lands at 0x280 ------
    VEC_SLOT_VGIC __l2_vgic_vec_fail    // 0x200 Synchronous
    VEC_SLOT_VGIC __l2_vgic_vec_irq     // 0x280 IRQ <-- the vIRQ target
    VEC_SLOT_VGIC __l2_vgic_vec_fail    // 0x300 FIQ
    VEC_SLOT_VGIC __l2_vgic_vec_fail    // 0x380 SError
    // --- Lower EL using AArch64 -- no lower EL under this guest; fatal --------
    VEC_SLOT_VGIC __l2_vgic_vec_fail    // 0x400 Synchronous
    VEC_SLOT_VGIC __l2_vgic_vec_fail    // 0x480 IRQ
    VEC_SLOT_VGIC __l2_vgic_vec_fail    // 0x500 FIQ
    VEC_SLOT_VGIC __l2_vgic_vec_fail    // 0x580 SError
    // --- Lower EL using AArch32 -- no AArch32 guests; fatal ------------------
    VEC_SLOT_VGIC __l2_vgic_vec_fail    // 0x600 Synchronous
    VEC_SLOT_VGIC __l2_vgic_vec_fail    // 0x680 IRQ
    VEC_SLOT_VGIC __l2_vgic_vec_fail    // 0x700 FIQ
    VEC_SLOT_VGIC __l2_vgic_vec_fail    // 0x780 SError
    .balign 0x80                        // pad slot 15 to a full 128 B: table == 0x800

    // ---- handlers (just past the 2 KiB table, still in the KEEP'd section) ---
__l2_vgic_vec_irq:                      // the injected VIRTUAL IRQ at EL1 (no EL2 exit)
    // x9 = GICV_BASE (0x0804_0000): the guest's VIRTUAL CPU interface.
    movz x9, #0x0804, lsl #16
    // x10 = GICV_IAR (read = ACKNOWLEDGE; returns the vINTID in [9:0], LR
    // pending -> active). This is the side-effecting ack on the vCPU interface.
    ldr  w10, [x9, #0x0C]               // GICV_IAR @ 0x00C
    and  x10, x10, #0x3FF               // mask to the 10-bit vINTID
    // Compare to the injected vINTID (VGIC_VINTID); set the trap-taken sentinel
    // ONLY on a match (so a spurious/wrong vIRQ leaves x28 clear -> Faulted).
    movz x11, #0x2A                     // VGIC_VINTID (must match el2.rs)
    cmp  x10, x11
    b.ne 1f                             // wrong vINTID -> do NOT set x28
    movz x28, #0x5A5                    // VGIC_IRQ_TAKEN sentinel (must match el2.rs)
1:
    // EOI: write the IAR value back to GICV_EOIR to end the interrupt (LR
    // active -> invalid; GICH_ELRSR0 bit0 -> 1 -- the monitor's retire proof).
    str  w10, [x9, #0x10]              // GICV_EOIR @ 0x010
    eret                                // return to the post-WFI guest body (NO EL2 exit)
__l2_vgic_vec_fail:                     // any other guest vector: surface a FAIL
    mov  x0, #0xBAD                     // a WRONG magic -> hvc #11 -> Faulted
    hvc  #11
    b    .                              // guard: the monitor unwinds, never here
"#
);
