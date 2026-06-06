//! x86_64 architecture backend for `tb-hal`.
//!
//! Exposes the safe primitives that `tb-hal`'s public API
//! (`serial_init`, `serial_write_byte`, `serial_write_str`, `halt`,
//! `install_traps`, `breakpoint`) delegates to via `arch::mod`. ALL x86_64
//! `unsafe` and assembly is confined to this `arch::x86_64` subtree
//! (KERNEL-FOUNDATION-SPEC §1); every other crate is `#![forbid(unsafe_code)]`.
//!
//! M0 boot path is PVH: `boot` emits the `XEN_ELFNOTE_PHYS32_ENTRY` note and
//! the (bootstrap-only) 32->64 trampoline; `serial` is the 16550 COM1 driver.
//! M1 adds CPU trap handling: `gdt` installs a permanent flat 64-bit GDT + TSS
//! (IST stacks), `idt` installs the 256-gate IDT, and `trap` holds the entry
//! thunks + the extern "C" handler that dispatches into safe Rust policy.

// `_start`, the PVH note and the 32->64 trampoline live here. The module is
// pulled into the final link because the linker script's `ENTRY(_start)`
// turns `_start` into a needed symbol, forcing extraction from the rlib.
pub mod boot;
pub mod serial;

// M1 trap stack: GDT/TSS, IDT, and the trap entry/dispatch asm + handler.
pub mod gdt;
pub mod idt;
pub mod trap;

pub use serial::{serial_init, serial_write_byte};

// `breakpoint()` is re-exported as part of tb-hal's public trap surface; the
// `int3` lives in `trap.rs`. `set_trap_hook`/`TrapInfo`/`TrapKind`/`TrapAction`
// and the `dispatch_trap` glue live at the crate root (`lib.rs`).
pub use trap::breakpoint;

use core::sync::atomic::{AtomicBool, Ordering};

/// Guards `install_traps()` so the permanent GDT/TSS/IDT are only built once
/// per vCPU even if it is called more than once.
static TRAPS_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Install real CPU exception/interrupt handling: load the permanent GDT+TSS
/// (with IST stacks) FIRST, then the IDT (whose #DF/NMI/#MC gates reference
/// those IST stacks). Idempotent; called once from `rust_main` via
/// `tb_hal::install_traps()`.
pub fn install_traps() {
    if TRAPS_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    // Order matters: the IDT's IST indices select TSS stacks the GDT installs.
    gdt::init();
    idt::init();
}

/// Halt the calling (single) vCPU forever.
///
/// Masks interrupts and parks the core in a `hlt` loop. Used as the M0
/// Definition-of-Done terminator after the marker is printed, as the fatal
/// (`TrapAction::Halt`) trap terminator, and as the `#[panic_handler]`
/// fallback in the kernel crate. Never returns.
#[inline]
pub fn halt() -> ! {
    loop {
        // (a) PRE: any CPU state. POST: interrupts masked, core parked; the
        //     function never observably returns (the surrounding loop re-arms
        //     `hlt` after any spurious NMI/SMI wake).
        // (b) ABI: no operands; clobbers nothing; nomem/nostack. `hlt` clears
        //     no caller state; `cli` only affects IF.
        // (c) Tested by: scripts/run-x86_64.sh (kernel halts after emitting
        //     its markers; the runner times out and scrapes COM1).
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack, preserves_flags));
        }
    }
}
