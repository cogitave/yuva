//! `tb-hal` — TABOS Hardware Abstraction Layer (M0 surface + M1 traps).
//!
//! This crate is the single place where `unsafe` and assembly are allowed in
//! TABOS (framekernel rule, KERNEL-FOUNDATION-SPEC.md §1). The raw pokes live in
//! the per-arch submodules under `arch/`; THIS file is a thin, mostly-safe
//! facade exposing the symbols the `kernel` crate is allowed to call:
//!
//! M0 serial + park:
//!   * [`serial_init`], [`serial_write_byte`], [`serial_write_str`], [`halt`]
//!
//! M1 traps (this milestone):
//!   * [`install_traps`]  — load the permanent GDT+TSS+IDT (x86_64) / set
//!     `VBAR_EL1` (aarch64). Idempotent, called once from `rust_main`.
//!   * [`breakpoint`]     — execute a software breakpoint (`int3` / `brk #0`).
//!   * [`set_trap_hook`]  — register the safe dispatch policy hook.
//!   * [`TrapInfo`] / [`TrapKind`] / [`TrapAction`] — the safe trap-dispatch ABI.
//!
//! POLICY lives in safe Rust: tb-hal's per-arch assembly marshals a raw
//! `TrapFrame`, an `extern "C"` handler in tb-hal (the ONLY place that derefs
//! the raw frame, `unsafe`) builds a safe [`TrapInfo`] and calls the registered
//! hook via [`dispatch_trap`]. The default hook returns [`TrapAction::Halt`].

#![no_std]
#![deny(missing_docs)]

use core::sync::atomic::{AtomicUsize, Ordering};

mod arch;

/// Initialise the early serial console for the current architecture.
///
/// * x86_64: legacy 16550 UART, COM1 @ I/O port `0x3F8`.
/// * aarch64: PL011 UART0 @ MMIO `0x0900_0000` (QEMU `virt` first-light).
///
/// Must be called once before any [`serial_write_byte`] / [`serial_write_str`].
pub fn serial_init() {
    arch::serial_init();
}

/// Write a single byte to the early serial console, blocking until the UART can
/// accept it.
pub fn serial_write_byte(b: u8) {
    arch::serial_write_byte(b);
}

/// Write a string to the early serial console, byte by byte (blocking).
///
/// Pure safe Rust: this is just a loop over [`serial_write_byte`]; it performs
/// no `unsafe` itself.
pub fn serial_write_str(s: &str) {
    for &b in s.as_bytes() {
        arch::serial_write_byte(b);
    }
}

/// Halt the (single) vCPU forever. Never returns.
///
/// * x86_64: masked `cli; hlt` spin.
/// * aarch64: `wfi` spin with interrupts masked.
pub fn halt() -> ! {
    arch::halt()
}

// ===========================================================================
// M1: trap installation + safe dispatch ABI
// ===========================================================================

/// Install real CPU exception/interrupt handling for the current architecture.
///
/// * x86_64: build and load a PERMANENT flat 64-bit GDT (null, ring0 code,
///   ring0 data, 64-bit TSS), reload `CS`/data segments, `ltr` the TSS, then
///   load a 256-entry IDT of 64-bit interrupt gates. `#DF`/NMI/`#MC` are routed
///   through TSS IST stacks.
/// * aarch64: point `VBAR_EL1` at the 2 KiB-aligned, 16×128-byte vector table.
///
/// Idempotent: safe to call more than once (each call rebuilds the descriptor
/// tables from scratch). Call once early from `rust_main`, before [`breakpoint`].
pub fn install_traps() {
    arch::install_traps();
}

/// Execute a software breakpoint trap on the current architecture.
///
/// * x86_64: `int3` (`#BP`, vector 3) — a TRAP whose CPU-saved `RIP` already
///   points PAST the instruction, so it resumes automatically on
///   [`TrapAction::Resume`].
/// * aarch64: `brk #0` — a SYNCHRONOUS exception (`ESR_EL1.EC = 0x3C`) whose
///   `ELR_EL1` points AT the instruction; the trap entry advances `ELR_EL1` by
///   4 on [`TrapAction::Resume`].
pub fn breakpoint() {
    arch::breakpoint();
}

/// The architecture-neutral classification of a trap, derived in the per-arch
/// `extern "C"` handler from the raw cause (vector + error code on x86_64,
/// `ESR_EL1.EC` on aarch64).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrapKind {
    /// Software breakpoint: x86 `#BP` (vector 3) / aarch64 `brk` (EC `0x3C`).
    Breakpoint,
    /// Page / data fault: x86 `#PF` (vector 14) / aarch64 data abort
    /// (EC `0x24`/`0x25`). [`TrapInfo::fault_addr`] holds the faulting address.
    PageFault,
    /// Undefined / invalid instruction: x86 `#UD` (vector 6) / aarch64 Unknown
    /// (EC `0x00`).
    Undefined,
    /// Any other trap not specially classified above.
    Other,
}

/// What the dispatch hook asks tb-hal to do after a trap is handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrapAction {
    /// Return from the trap entry so execution continues past the trapping
    /// instruction (x86: `iretq`; aarch64: `eret`, advancing `ELR_EL1` by 4 for
    /// the at-instruction synchronous breakpoint).
    Resume,
    /// Do not return; park the vCPU forever. Used for fatal faults and as the
    /// default policy when no hook is registered.
    Halt,
}

/// A safe, fully-owned description of a trap, handed to the dispatch hook.
///
/// Built inside tb-hal's per-arch handler from the raw `TrapFrame`; it borrows
/// nothing from the raw frame, so the hook (in the otherwise-`forbid(unsafe)`
/// kernel crate) can read it freely.
#[derive(Clone, Copy, Debug)]
pub struct TrapInfo {
    /// The architecture-neutral kind of this trap.
    pub kind: TrapKind,
    /// Raw cause word. x86_64: `(vector << 32) | (error_code & 0xFFFF_FFFF)`.
    /// aarch64: the full `ESR_EL1` value (EC = bits `[31:26]`).
    pub cause: u64,
    /// Faulting address for memory faults (x86 `CR2` for `#PF`; aarch64
    /// `FAR_EL1` for a data abort), otherwise `0`.
    pub fault_addr: u64,
    /// The trapping instruction pointer (x86 saved `RIP`; aarch64 `ELR_EL1`).
    pub pc: u64,
}

/// Storage for the registered trap hook: a `fn(&TrapInfo) -> TrapAction`
/// reinterpreted as `usize`. `0` means "no hook registered → use the default
/// halt policy". `AtomicUsize` because tb-hal is `no_std` with no locks; the
/// pointer is written once at boot and read on every trap.
static TRAP_HOOK: AtomicUsize = AtomicUsize::new(0);

/// The default policy when no hook has been registered: always halt.
fn default_trap_hook(_info: &TrapInfo) -> TrapAction {
    TrapAction::Halt
}

/// Register the safe trap-dispatch policy hook.
///
/// The hook is a plain function pointer `fn(&TrapInfo) -> TrapAction`; it lives
/// in safe Rust (e.g. the kernel crate under `#![forbid(unsafe_code)]`) and
/// decides per-trap whether to [`TrapAction::Resume`] or [`TrapAction::Halt`].
pub fn set_trap_hook(hook: fn(&TrapInfo) -> TrapAction) {
    TRAP_HOOK.store(hook as usize, Ordering::Release);
}

/// Dispatch a trap to the registered hook (or the default halt policy).
///
/// Called by each per-arch `extern "C"` handler with a [`TrapInfo`] it built
/// from the raw frame. This is the safe boundary between the raw-frame deref
/// (per-arch, `unsafe`) and the policy hook (safe).
pub(crate) fn dispatch_trap(info: &TrapInfo) -> TrapAction {
    let raw = TRAP_HOOK.load(Ordering::Acquire);
    if raw == 0 {
        return default_trap_hook(info);
    }
    // SAFETY: `raw` is non-zero here, so it was produced by `set_trap_hook`
    // from a valid `fn(&TrapInfo) -> TrapAction` via `hook as usize`. A function
    // pointer and `usize` are both pointer-sized; this transmute is the exact
    // inverse of that cast.
    let hook: fn(&TrapInfo) -> TrapAction =
        unsafe { core::mem::transmute::<usize, fn(&TrapInfo) -> TrapAction>(raw) };
    hook(info)
}
