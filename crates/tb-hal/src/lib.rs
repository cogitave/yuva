//! `tb-hal` — TABOS Hardware Abstraction Layer (M0 surface).
//!
//! This crate is the single место where `unsafe` and assembly are allowed in
//! TABOS (framekernel rule, KERNEL-FOUNDATION-SPEC.md §1). The raw pokes live in
//! the per-arch submodules under `arch/`; THIS file is a thin, fully-safe facade
//! exposing the four symbols the `kernel` crate is allowed to call:
//!
//!   * [`serial_init`]
//!   * [`serial_write_byte`]
//!   * [`serial_write_str`]
//!   * [`halt`]
//!
//! Nothing else is public. `serial_write_str` is implemented here in safe Rust
//! (it just iterates bytes and calls the arch byte-writer), so the only code
//! that ever touches a port/MMIO register is inside `arch/<arch>/serial.rs`.

#![no_std]
#![deny(missing_docs)]

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
/// * aarch64: `wfe`/`wfi` spin with interrupts masked.
pub fn halt() -> ! {
    arch::halt()
}
