//! x86_64 architecture backend for `tb-hal`.
//!
//! Exposes the safe primitives that `tb-hal`'s public API
//! (`serial_init`, `serial_write_byte`, `serial_write_str`, `halt`) delegates
//! to via `arch::mod`. ALL x86_64 `unsafe` and assembly is confined to this
//! `arch::x86_64` subtree (KERNEL-FOUNDATION-SPEC §1); every other crate is
//! `#![forbid(unsafe_code)]`.
//!
//! M0 boot path is PVH: `boot` emits the `XEN_ELFNOTE_PHYS32_ENTRY` note and
//! the (bootstrap-only) 32->64 trampoline; `serial` is the 16550 COM1 driver.

// `_start`, the PVH note and the 32->64 trampoline live here. The module is
// pulled into the final link because the linker script's `ENTRY(_start)`
// turns `_start` into a needed symbol, forcing extraction from the rlib.
pub mod boot;
pub mod serial;

pub use serial::{serial_init, serial_write_byte};

/// Halt the calling (single) vCPU forever.
///
/// Masks interrupts and parks the core in a `hlt` loop. Used as the M0
/// Definition-of-Done terminator after the marker is printed, and as the
/// `#[panic_handler]` fallback in the kernel crate. Never returns.
#[inline]
pub fn halt() -> ! {
    loop {
        // (a) PRE: any CPU state. POST: interrupts masked, core parked; the
        //     function never observably returns (the surrounding loop re-arms
        //     `hlt` after any spurious NMI/SMI wake).
        // (b) ABI: no operands; clobbers nothing; nomem/nostack. `hlt` clears
        //     no caller state; `cli` only affects IF.
        // (c) Tested by: scripts/run-x86_64.sh (kernel halts after emitting
        //     "hello from rust_main\n"; the runner times out and scrapes COM1).
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack, preserves_flags));
        }
    }
}
