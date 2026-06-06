//! aarch64 trap dispatch: the one place that derefs the raw exception frame.
//!
//! `vectors.rs` marshals a `TrapFrame` on the exception stack and `bl`s into
//! [`aarch64_trap_handler`] here. This module reads the cause from `ESR_EL1`
//! (and the faulting VA from `FAR_EL1`), builds a *safe* [`crate::TrapInfo`],
//! and hands it to the crate-level policy hook via [`crate::dispatch_trap`].
//! Per the framekernel rule, POLICY lives in safe Rust (the kernel crate's
//! `set_trap_hook`); this file only does the unavoidable raw-frame plumbing.
//!
//! Contract with `lib.rs` (the crate facade, owned separately). M1 expects:
//! ```ignore
//! pub struct TrapInfo { pub kind: TrapKind, pub cause: u64,
//!                       pub fault_addr: u64, pub pc: u64 }
//! pub enum TrapKind  { Breakpoint, PageFault, Undefined, Other }  // Clone+Copy
//! pub enum TrapAction { Resume, Halt }
//! pub fn set_trap_hook(f: fn(&TrapInfo) -> TrapAction);  // default hook = Halt
//! pub(crate) fn dispatch_trap(info: &TrapInfo) -> TrapAction; // loads the hook
//! ```
//! Both arch back-ends call `crate::dispatch_trap`; `aarch64::mod::install_traps`
//! arms `VBAR_EL1` and [`breakpoint`] raises the test `brk #0`.
//!
//! Verified facts (obey exactly):
//!  * `ESR_EL1.EC` is bits[31:26] (6 bits). Arm ARM (DDI 0487) D17.2.37
//!    "ESR_EL1, Exception Syndrome Register (EL1)". Cross-checked vs Linux
//!    `arch/arm64/include/asm/esr.h`: `ESR_ELx_EC_SHIFT == 26`.
//!  * EC values (Linux `esr.h`, Arm ARM D17.2.37 "EC encodings"):
//!      - `0x3C` `ESR_ELx_EC_BRK64`   : BRK instruction in AArch64 state.
//!      - `0x00` `ESR_ELx_EC_UNKNOWN` : "Unknown reason" (covers UDF/undefined).
//!      - `0x24` `ESR_ELx_EC_DABT_LOW`: Data Abort from a lower EL.
//!      - `0x25` `ESR_ELx_EC_DABT_CUR`: Data Abort without a change in EL.
//!  * `FAR_EL1` holds the faulting virtual address for data/instruction aborts
//!    (Arm ARM D17.2.40 "FAR_EL1").
//!  * `brk #0` is a SYNCHRONOUS exception: `ELR_EL1` points AT the `brk`
//!    instruction (Arm ARM D1: the preferred return address of a synchronous
//!    exception is the faulting instruction). To resume you MUST advance
//!    `ELR_EL1` by 4 before `eret`. This is the opposite of x86 `#BP` (int3),
//!    a *trap* whose saved RIP already points to the following instruction
//!    (Intel SDM Vol.3 SS6.15, interrupt 3), so x86 needs no RIP adjustment.

use crate::{TrapAction, TrapInfo, TrapKind};

/// Saved CPU context for one aarch64 exception, built on the exception stack by
/// `SAVE_CONTEXT` in `vectors.rs`. `#[repr(C)]`; the byte offsets are part of
/// the ABI shared with that assembly (`gpr[i]` at `i*8`, `elr` at 0xF8,
/// `spsr` at 0x100). `_pad` keeps the frame a multiple of 16 so SP stays
/// 16-byte aligned across the handler call.
#[repr(C)]
pub(super) struct TrapFrame {
    /// x0..x30 (x30 = LR), offsets 0x00..0xF0.
    gpr: [u64; 31],
    /// ELR_EL1 at exception entry (the preferred return address), offset 0xF8.
    /// Writing this and returning makes `eret` resume there (brk: advance +4).
    elr: u64,
    /// SPSR_EL1 at exception entry (saved PSTATE), offset 0x100.
    spsr: u64,
    /// Alignment pad; frame size is 0x110 (16-aligned).
    _pad: u64,
}

// Compile-time lock on the layout the assembly in `vectors.rs` assumes.
const _: () = assert!(core::mem::size_of::<TrapFrame>() == 0x110);
const _: () = assert!(core::mem::offset_of!(TrapFrame, elr) == 0xF8);
const _: () = assert!(core::mem::offset_of!(TrapFrame, spsr) == 0x100);

// ESR_EL1 exception-class field and the EC codes we classify (see file note).
const ESR_EC_SHIFT: u64 = 26;
const ESR_EC_MASK: u64 = 0x3F;
const EC_UNKNOWN: u64 = 0x00; // undefined / UDF
const EC_DABT_LOWER: u64 = 0x24; // data abort, lower EL
const EC_DABT_CURRENT: u64 = 0x25; // data abort, current EL
const EC_BRK64: u64 = 0x3C; // BRK from AArch64

// Source tag passed in x1 by the `vectors.rs` trampolines.
const SOURCE_SYNC_CURRENT_SPX: u64 = 0; // real handler (synchronous, our EL)

#[inline(always)]
fn read_esr_el1() -> u64 {
    let v: u64;
    // SAFETY: ESR_EL1 is an EL1-readable system register; `mrs` has no memory
    // or stack effect and leaves NZCV unchanged. We run at EL1.
    unsafe {
        core::arch::asm!("mrs {0}, esr_el1", out(reg) v,
            options(nomem, nostack, preserves_flags));
    }
    v
}

#[inline(always)]
fn read_far_el1() -> u64 {
    let v: u64;
    // SAFETY: as `read_esr_el1`; FAR_EL1 is an EL1-readable system register.
    unsafe {
        core::arch::asm!("mrs {0}, far_el1", out(reg) v,
            options(nomem, nostack, preserves_flags));
    }
    v
}

/// Trap handler invoked from `vectors.rs` (`bl aarch64_trap_handler`).
///
/// `frame` is `sp` immediately after `SAVE_CONTEXT`; `source` is 0 for the
/// Current-EL-SPx synchronous slot and 1 for every other (unexpected) vector.
/// Reads the cause, builds a safe [`crate::TrapInfo`], and runs the registered
/// policy hook. On [`TrapAction::Resume`] of a `brk` it advances the saved
/// `ELR_EL1` by 4 (one A64 instruction) so `eret` lands past the `brk`; on
/// [`TrapAction::Halt`] it parks the core via [`crate::halt`] and never returns.
#[no_mangle]
pub extern "C" fn aarch64_trap_handler(frame: *mut TrapFrame, source: u64) {
    // SAFETY: `frame` is the SP that the vector trampoline produced after its
    // 0x110-byte `SAVE_CONTEXT` push -- a fully-initialised, 16-aligned
    // `TrapFrame` that stays live for this whole call. Single core, with
    // interrupts masked while we run, so we are the only accessor.
    let frame = unsafe { &mut *frame };

    let esr = read_esr_el1();
    let far = read_far_el1();
    let ec = (esr >> ESR_EC_SHIFT) & ESR_EC_MASK;

    // Classify. Only the synchronous current-EL slot has a meaningful ESR EC;
    // any other vector is an unexpected fault -> Other (default policy halts).
    let (kind, is_breakpoint) = if source != SOURCE_SYNC_CURRENT_SPX {
        (TrapKind::Other, false)
    } else {
        match ec {
            EC_BRK64 => (TrapKind::Breakpoint, true),
            EC_UNKNOWN => (TrapKind::Undefined, false),
            EC_DABT_LOWER | EC_DABT_CURRENT => (TrapKind::PageFault, false),
            _ => (TrapKind::Other, false),
        }
    };

    let info = TrapInfo {
        kind,
        cause: esr,
        fault_addr: far,
        pc: frame.elr,
    };

    match crate::dispatch_trap(&info) {
        TrapAction::Resume => {
            // brk: ELR points AT the instruction; step over its 4 bytes so the
            // `eret` in `vectors.rs` resumes at the following instruction.
            if is_breakpoint {
                frame.elr = frame.elr.wrapping_add(4);
            }
        }
        // Fatal: the hook already reported it; park the core (never returns, so
        // the trampoline's restore/eret is intentionally not reached).
        TrapAction::Halt => crate::halt(),
    }
}

/// Raise a software breakpoint (`brk #0`) -- the safe M1 trap-test trigger.
///
/// With traps installed this is taken through the Current-EL-SPx synchronous
/// vector (`ESR_EL1.EC == 0x3C`), classified as [`TrapKind::Breakpoint`], and,
/// when the hook returns [`TrapAction::Resume`], resumed at the next
/// instruction (the handler advances `ELR_EL1` by 4). The `unsafe` is confined
/// here so the caller (the `#![forbid(unsafe_code)]` kernel) stays safe.
pub fn breakpoint() {
    // SAFETY: `brk #0` raises a synchronous Breakpoint exception and has no
    // memory, stack, or flag effects of its own; the handler save/restores
    // (incl. SPSR/NZCV) so the caller's state is preserved across the trap.
    unsafe {
        core::arch::asm!("brk #0", options(nostack, preserves_flags));
    }
}
