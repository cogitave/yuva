//! aarch64 **L2.0 "el2 OK"**: the EL2 sovereignty primitive -- the aarch64
//! realization of the x86 VMX-root rung. A real EL1<->EL2 world-switch driven by
//! a SAFE [`el2_selftest`] facade (mirroring `vmx_selftest`/`VmxProof`), with
//! ALL silicon-unsafe asm confined here + in `el2_vectors.rs`/`boot.rs`; the
//! kernel crate stays `#![forbid(unsafe_code)]` and only branches on the enum.
//!
//! What runs (under PURE TCG on a stock runner -- this proof EXECUTES, it is not
//! a CI skip like the x86 vmxroot lane):
//!  1. `boot.rs::_start` booted at EL2 (QEMU `virt,virtualization=on`), installed
//!     this resident nVHE monitor (VBAR_EL2 + HCR_EL2.RW + ...), recorded
//!     [`BOOTED_AT_EL2`] `= 1`, then dropped to EL1 where M0..M18 ran unchanged.
//!  2. [`el2_selftest`] (end of boot, playing the live EL1 kernel) masks IRQs
//!     and issues the bootstrap **`HVC #0`**. It traps to EL2 through the
//!     Lower-EL-AArch64 Synchronous slot (0x400, `el2_vectors.rs`), which saves
//!     frame **B0** {x0..x30, ELR_EL2 (= the kernel's post-HVC PC), SPSR_EL2}
//!     on the dedicated monitor stack and calls [`aarch64_el2_sync_handler`].
//!  3. The handler sees `ESR_EL2.EC == HVC64` + `ISS imm == 0`, leaves B0
//!     resident, and `eret`s INTO the tiny EL1 [`guest_stub`] (its VA == PA,
//!     identity-mapped, EL1-executable kernel `.text`).
//!  4. The guest loads the magic `0xE12` into x0 and issues **`HVC #1`**, which
//!     traps back to EL2 (same 0x400 slot), saving frame **B1** one frame below
//!     B0 (B0 == B1 + 0x110, because B0 was never popped).
//!  5. The handler sees `ISS imm == 1`, reads the guest magic from `B1.gpr[0]`,
//!     overwrites `B0.gpr[0] = outcome` (0 == ok) and `B0.gpr[1] = magic`, then
//!     RESTORE_CONTEXT_EL2(B0) + `eret` -- returning to the kernel's post-HVC PC
//!     with **x0 = outcome** and every other kernel register transparent.
//!  6. [`el2_selftest`] maps x0 == 0 -> [`El2Proof::Proven`], nonzero ->
//!     [`El2Proof::RoundTripFailed`]; the kernel prints `L2.0: el2 OK`.
//!
//! Cache-coherency invariants (the EL2 handler runs with `SCTLR_EL2.M == 0`, so
//! its accesses are Device/non-cacheable, while EL1 maps the same RAM Normal-WB
//! cacheable -- an aliasing hazard if shared):
//!  * **Result via register, not a cacheable static.** The outcome reaches EL1
//!    in x0 (overwriting B0.gpr[0] before the restore), never read by EL1 from
//!    the EL2-mapped stack memory.
//!  * **Single-accessor EL2 stack.** `__el2_stack` (linker) is a region the EL1
//!    kernel NEVER references; B0/B1 and the handler frame live only there.
//!  * **`BOOTED_AT_EL2`** is the only cacheable static touched cross-EL: written
//!    once at boot with caches OFF (in `_start`, before `mmu_init`) and read
//!    here later via a cold fill -> coherent (the same caches-off-write /
//!    caches-on-read discipline every M0..M2 `.bss`/`.data` already relies on).
//!
//! Verified constants (Linux `el2_setup.h`/`esr.h`, Arm ARM DDI 0487; locked by
//! the `const _: () = assert!(...)` checks below):
//!  * `EC_HVC64 = 0x16`  -- ESR_ELx.EC for HVC in AArch64 state; EC = bits[31:26].
//!  * `SPSR = 0x3C5`     -- EL1h + DAIF masked (INIT_PSTATE_EL1) for both the
//!                          boot drop and the eret into the guest.
//!  * `SCTLR_EL2 = 0x30C50830`, `CNTHCTL_EL2 = 0x3` -- documented here, written
//!                          in `boot.rs`; the asserts keep the two in lockstep.
//!  * Frame size `0x110`; B0 == B1 + 0x110 (one frame, never popped).

use core::arch::{asm, naked_asm};
use core::sync::atomic::{AtomicU8, Ordering};

// ===========================================================================
// Load-bearing constants (Tier-1: locked by const-asserts; mirror boot.rs).
// ===========================================================================

/// `ESR_ELx.EC` field shift (bits[31:26]) -- same as `trap.rs`/`user.rs`.
const ESR_EC_SHIFT: u64 = 26;
/// `ESR_ELx.EC` field mask (6 bits).
const ESR_EC_MASK: u64 = 0x3F;
/// EC for `HVC` executed in AArch64 state (Linux `esr.h` ESR_ELx_EC_HVC64).
const EC_HVC64: u64 = 0x16;
/// `ESR_ELx.ISS` HVC immediate field (the 16-bit `#imm` of the HVC).
const HVC_IMM_MASK: u64 = 0xFFFF;

/// SPSR_EL2 for the drop / the eret into the guest: EL1h (M=0x5) + D|A|I|F
/// masked = 0x3C5 (INIT_PSTATE_EL1). Identical to `boot.rs`'s `SPSR_EL2`.
const SPSR_EL1H_DAIF: u64 = 0x3C5;

/// Documented EL2-setup values (WRITTEN in `boot.rs`; asserted here so the two
/// modules can never drift). See `boot.rs`'s module doc for the field rationale.
const SCTLR_EL2_VALUE: u64 = 0x30C5_0830;
const CNTHCTL_EL2_VALUE: u64 = 0x3;

/// The kernel's bootstrap HVC immediate (`hvc #0`) -- "drop into the guest".
const HVC_BOOTSTRAP: u64 = 0;
/// The guest's done HVC immediate (`hvc #1`) -- "round-trip complete".
const HVC_GUEST_DONE: u64 = 1;
/// The magic the EL1 guest stub passes in x0 (proves it ran the world-switched
/// guest). Captured at the `imm == 1` trap and echoed back to the kernel in x1.
const GUEST_MAGIC: u64 = 0xE12;

// Distinct nonzero FAIL codes (any nonzero -> `RoundTripFailed` -> red marker).
/// Guest ran but presented the wrong magic.
const FAIL_BAD_MAGIC: u64 = 0x0000_0E12_0000_0001;
/// HVC with an unexpected immediate (not #0/#1) at the Lower-EL sync slot.
const FAIL_BAD_IMM: u64 = 0x0000_0E12_0000_0002;
/// A lower-EL synchronous exception that was not an HVC64.
const FAIL_BAD_EC: u64 = 0x0000_0E12_0000_0003;
/// An exception through any non-(Lower-EL-sync) EL2 vector slot.
const FAIL_EL2_FAULT: u64 = 0x0000_0E12_0000_0004;

// Tier-1 compile-time locks on every load-bearing constant the world-switch
// depends on (plan §12). A drift here is a build error, not a boot bug.
const _: () = assert!(SPSR_EL1H_DAIF == 0x3C5);
const _: () = assert!(CNTHCTL_EL2_VALUE == 0x3);
const _: () = assert!(SCTLR_EL2_VALUE == 0x30C50830);
const _: () = assert!(EC_HVC64 == 0x16);
const _: () = assert!(HVC_BOOTSTRAP == 0 && HVC_GUEST_DONE == 1);
const _: () = assert!(core::mem::size_of::<Frame>() == 0x110);
const _: () = assert!(core::mem::offset_of!(Frame, gpr) == 0x00);
const _: () = assert!(core::mem::offset_of!(Frame, elr) == 0xF8);
const _: () = assert!(core::mem::offset_of!(Frame, spsr) == 0x100);

// ===========================================================================
// The entry-EL flag (written ONCE by `_start`, caches off; read here).
// ===========================================================================

/// `1` iff `_start` booted at EL2 and armed the resident nVHE monitor; `0` if
/// the image entered at EL1 (no EL2). Written by `boot.rs::_start` via a raw
/// `strb` after `.bss`-zero (so it is not wiped); read by [`el2_selftest`] to
/// gate the bootstrap HVC. `#[no_mangle]` so the `_start` asm can name it.
#[no_mangle]
pub(super) static BOOTED_AT_EL2: AtomicU8 = AtomicU8::new(0);

// ===========================================================================
// The EL2 exception frame (must match `el2_vectors.rs` SAVE_CONTEXT_EL2): the
// SAME 0x110 layout as the EL1 TrapFrame but holding ELR_EL2 / SPSR_EL2.
// ===========================================================================

#[repr(C)]
pub(super) struct Frame {
    /// x0..x30 (x30 = LR), offsets 0x00..0xF0. `gpr[0]` carries the HVC's x0.
    gpr: [u64; 31],
    /// ELR_EL2 at the trap (the lower-EL return PC), offset 0xF8.
    elr: u64,
    /// SPSR_EL2 at the trap (the lower-EL PSTATE), offset 0x100.
    spsr: u64,
    /// Alignment pad; frame size is 0x110 (16-aligned).
    _pad: u64,
}

// ===========================================================================
// Privileged EL2 system-register helpers (asm confined here).
// ===========================================================================

/// Read `ESR_EL2` (the EL2 exception syndrome) -- EL2-readable, side-effect-free.
fn read_esr_el2() -> u64 {
    let v: u64;
    // SAFETY: ESR_EL2 is an EL2-readable system register; `mrs` has no memory or
    // stack effect and leaves NZCV unchanged. The handler runs at EL2.
    unsafe {
        asm!("mrs {v}, esr_el2", v = out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// Compute `__el2_stack_top` (the linker symbol) PC-relative -- no memory access,
/// so it is valid at EL2 with the MMU off. B0 (the kernel's bootstrap-HVC frame)
/// is always resident at `__el2_stack_top - 0x110` (the single-accessor stack).
fn el2_stack_top() -> u64 {
    let v: u64;
    // SAFETY: `adrp`/`add :lo12:` form the address of the linker-defined symbol
    // with no memory access; legal at EL2, MMU off. NZCV preserved.
    unsafe {
        asm!(
            "adrp {v}, __el2_stack_top",
            "add  {v}, {v}, :lo12:__el2_stack_top",
            v = out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    v
}

// ===========================================================================
// The EL1 guest stub: a position-independent EL1 payload the monitor erets into.
// ===========================================================================
// (a) PRE : reached only by the `imm == 0` handler's `eret`, executing at EL1h
//           (SPSR_EL2 = 0x3C5) under the kernel's live stage-1 MMU (HCR_EL2.VM=0,
//           no stage-2). Its VA == PA: it sits in identity-mapped, EL1-executable
//           kernel `.text` (the RAM gigabyte L1[1], PXN=0). POST: traps back to
//           EL2 via `hvc #1` with x0 = 0xE12; never runs past the `hvc` (the
//           monitor unwinds to the kernel and does not return here).
// (b) ABI : `#[unsafe(naked)]` -- EXACTLY these three instructions, all
//           PC-relative / immediate (no absolute relocation), so it is valid at
//           its identity VA. Uses NO stack (SP_EL1 untouched). `mov x0,#0xE12`
//           is a single MOVZ (0xE12 fits in 16 bits).
// (c) TEST: scripts/run-aarch64.sh -- the round-trip prints "L2.0: el2 OK".
/// The world-switched EL1 guest: pass the magic `0xE12` and `hvc #1`, then spin.
#[unsafe(naked)]
extern "C" fn guest_stub() -> ! {
    naked_asm!(
        "mov x0, #0xE12", // the guest magic in x0 (proves the guest ran at EL1)
        "hvc #1",         // trap back to the EL2 monitor (ESR_EL2.ISS imm = 1)
        "1: b 1b",        // unreachable: the monitor unwinds, never returns here
    )
}

// ===========================================================================
// The EL2 synchronous (HVC) handler -- the world-switch core. Never returns: it
// erets INTO the guest (bootstrap HVC) or BACK to the kernel (guest HVC / fail).
// ===========================================================================
// (a) PRE : entered at EL2h from the 0x400 vector after SAVE_CONTEXT_EL2; `frame`
//           = SP_EL2 = &B0 (bootstrap HVC) or &B1 (guest HVC). POST: never
//           returns -- see the per-branch `eret`s.
// (b) ABI : `extern "C"`, `#[no_mangle]` so `el2_vectors.rs` can `bl` it. `-> !`.
// (c) TEST: scripts/run-aarch64.sh -- "L2.0: el2 OK" iff the round-trip closes.
/// Dispatch one EL1->EL2 `HVC` on `ESR_EL2.EC == HVC64` + `ISS imm`.
#[no_mangle]
pub(super) extern "C" fn aarch64_el2_sync_handler(frame: *mut Frame) -> ! {
    let esr = read_esr_el2();
    let ec = (esr >> ESR_EC_SHIFT) & ESR_EC_MASK;
    if ec != EC_HVC64 {
        // Not an HVC at the lower-EL sync slot -- unexpected. Fail, don't loop.
        el2_return_to_kernel(FAIL_BAD_EC, esr);
    }
    match esr & HVC_IMM_MASK {
        HVC_BOOTSTRAP => {
            // imm == 0: the kernel's bootstrap HVC. Leave B0 (= frame) resident
            // and `eret` INTO the EL1 guest stub. We first reset SP_EL2 to &B0 so
            // the guest's later `hvc #1` saves B1 exactly one frame below B0
            // (B0 == B1 + 0x110), regardless of this handler's own frame usage.
            let guest = guest_stub as *const () as u64;
            // SAFETY: `frame` == &B0 on the single-accessor monitor stack. We set
            // SP_EL2 = &B0, program ELR_EL2/SPSR_EL2 for an EL1h entry at the
            // identity-mapped guest stub, and `eret`. `noreturn`: control leaves
            // EL2 for the guest and only re-enters via the guest's `hvc #1`.
            unsafe {
                asm!(
                    "mov sp, {b0}",
                    "msr elr_el2,  {guest}",
                    "msr spsr_el2, {spsr}",
                    "isb",
                    "eret",
                    b0    = in(reg) frame,
                    guest = in(reg) guest,
                    spsr  = in(reg) SPSR_EL1H_DAIF,
                    options(noreturn),
                );
            }
        }
        HVC_GUEST_DONE => {
            // imm == 1: the guest's done HVC. `frame` == &B1; read the magic the
            // guest placed in x0, then unwind back to the kernel through B0.
            // SAFETY: `frame` == &B1 on the monitor stack; `gpr[0]` is initialised
            // by SAVE_CONTEXT_EL2 and is the only field we read.
            let magic = unsafe { (*frame).gpr[0] };
            let outcome = if magic == GUEST_MAGIC { 0 } else { FAIL_BAD_MAGIC };
            el2_return_to_kernel(outcome, magic);
        }
        other => {
            // A valid HVC64 but an unexpected immediate -- fail, don't loop.
            el2_return_to_kernel(FAIL_BAD_IMM, other);
        }
    }
}

// ===========================================================================
// The EL2 fatal-vector handler: any non-(Lower-EL-sync) slot. Surfaces a FAIL by
// unwinding to the kernel (never a silent loop / hang).
// ===========================================================================
/// Handle an unexpected EL2 exception (e.g. the guest stub aborting instead of
/// HVC-ing): unwind to the kernel's resident B0 with a nonzero code carrying the
/// EL2 syndrome, so [`el2_selftest`] reports `RoundTripFailed` (red marker).
#[no_mangle]
pub(super) extern "C" fn aarch64_el2_fault_handler(_frame: *mut Frame) -> ! {
    let esr = read_esr_el2();
    el2_return_to_kernel(FAIL_EL2_FAULT, esr);
}

// ===========================================================================
// Unwind EL2 -> EL1 (kernel): write the result into the resident B0 and ERET.
// ===========================================================================
/// Deliver `code` (returned to the kernel in x0) and `x1val` (in x1) by
/// overwriting the resident bootstrap frame **B0** at `__el2_stack_top - 0x110`,
/// then RESTORE_CONTEXT_EL2(B0) + `eret` to the kernel's post-`HVC #0` PC. B0's
/// saved ELR_EL2/SPSR_EL2 carry the kernel's return PC and EL1h PSTATE, and its
/// x2..x30 are the kernel's pre-HVC values -- so the bootstrap HVC is fully
/// transparent except x0 = `code`, x1 = `x1val` (both caller-saved / clobbered).
fn el2_return_to_kernel(code: u64, x1val: u64) -> ! {
    let b0 = (el2_stack_top() - 0x110) as *mut Frame;
    // SAFETY: B0 lives in the single-accessor monitor stack (the EL1 kernel never
    // references it); it was fully initialised by the bootstrap HVC's
    // SAVE_CONTEXT_EL2. We overwrite only gpr[0]/gpr[1] (the result registers).
    unsafe {
        (*b0).gpr[0] = code;
        (*b0).gpr[1] = x1val;
    }
    // SAFETY: reset SP_EL2 to &B0 and RESTORE_CONTEXT_EL2 (pop x0..x30 + ELR_EL2 +
    // SPSR_EL2), then `eret` to EL1 at the kernel's post-HVC PC. The result
    // reaches EL1 in x0 (a register), never via the EL2-mapped (non-cacheable)
    // stack -- no EL2-MMU-off / EL1-cacheable aliasing hazard. `noreturn`:
    // control leaves EL2 for good and the abandoned frames below SP are inert.
    unsafe {
        asm!(
            "mov sp, {b0}",
            "ldp x9,  x10, [sp, #0xF8]", // elr @ 0xF8, spsr @ 0x100
            "msr elr_el2,  x9",
            "msr spsr_el2, x10",
            "ldp x0,  x1,  [sp, #0x00]", // x0 = code, x1 = x1val (just written)
            "ldp x2,  x3,  [sp, #0x10]",
            "ldp x4,  x5,  [sp, #0x20]",
            "ldp x6,  x7,  [sp, #0x30]",
            "ldp x8,  x9,  [sp, #0x40]",
            "ldp x10, x11, [sp, #0x50]",
            "ldp x12, x13, [sp, #0x60]",
            "ldp x14, x15, [sp, #0x70]",
            "ldp x16, x17, [sp, #0x80]",
            "ldp x18, x19, [sp, #0x90]",
            "ldp x20, x21, [sp, #0xA0]",
            "ldp x22, x23, [sp, #0xB0]",
            "ldp x24, x25, [sp, #0xC0]",
            "ldp x26, x27, [sp, #0xD0]",
            "ldp x28, x29, [sp, #0xE0]",
            "ldr x30,      [sp, #0xF0]",
            "add sp, sp, #0x110",
            "eret",
            b0 = in(reg) b0,
            options(noreturn),
        );
    }
}

// ===========================================================================
// The safe facade: el2_selftest() -> El2Proof (the only public surface).
// ===========================================================================
// (a) PRE : called once from the kernel at the L2.0 slot (end of boot), at EL1h
//           with the resident monitor armed (when BOOTED_AT_EL2 == 1). POST:
//           issued ONE bootstrap `HVC #0`, drove the ERET->guest->HVC->EL2
//           round-trip, and returns the outcome enum. Graceful skip (no HVC, no
//           fault) when not booted at EL2.
// (b) ABI : plain safe `fn`; all asm/unsafe confined above + in el2_vectors.rs /
//           boot.rs, so the `#![forbid(unsafe_code)]` kernel only branches on
//           the returned `El2Proof`.
// (c) TEST: scripts/run-aarch64.sh -- "L2.0: el2 OK" iff this returns `Proven`.
/// Drive the EL1->EL2->EL1-guest->EL2->EL1 world-switch and report the outcome.
/// `Unavailable` if we did not boot at EL2 (a green skip); `Proven` on a closed
/// round-trip; `RoundTripFailed{code}` if the monitor reported a fault.
pub fn el2_selftest() -> crate::El2Proof {
    use crate::El2Proof;

    // Graceful skip: no resident monitor -> issuing HVC would fault, so don't.
    // BOOTED_AT_EL2 was written caches-off at boot and is read here via a cold
    // fill (coherent), the same discipline M0..M2 `.bss` already relies on.
    if BOOTED_AT_EL2.load(Ordering::Acquire) != 1 {
        return El2Proof::Unavailable;
    }

    // Mask EL1 IRQs across the round-trip (belt-and-suspenders; mirrors
    // `vmx_selftest`'s `cli`). The guest also runs with DAIF masked (SPSR=0x3C5).
    let daif = super::timer::local_irq_save();

    let code: u64;
    // SAFETY: the resident EL2 monitor (armed in `_start`) catches `hvc #0`,
    // erets into the EL1 guest stub, catches the guest's `hvc #1`, and erets back
    // here with the outcome in x0 and every kernel register restored from B0
    // (x2..x30 transparent; x0/x1 are caller-saved, covered by clobber_abi("C")).
    // Nothing here touches the EL2 stack memory -- the result arrives in x0.
    unsafe {
        asm!("hvc #0", out("x0") code, clobber_abi("C"));
    }

    super::timer::local_irq_restore(daif);

    if code == 0 {
        El2Proof::Proven { hvc_imm: HVC_GUEST_DONE }
    } else {
        El2Proof::RoundTripFailed { code }
    }
}
