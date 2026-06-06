//! PL011 UART driver for the QEMU `virt` board (UART0).
//!
//! M0 first-light hardcodes the QEMU `virt` PL011 base and a polled,
//! transmit-only path -- just enough to emit the DoD marker. Register offsets
//! are from the ARM PrimeCell UART (PL011) Technical Reference Manual, ARM DDI
//! 0183G, §3 "Programmers Model"; the 0x0900_0000 base and 24 MHz UARTCLK are
//! the QEMU `virt` device-tree values (node `pl011@9000000`, clock `clk24mhz`),
//! confirmable via `qemu-system-aarch64 -M virt -machine dumpdtb`.
//!
//! All MMIO is `volatile`. This module lives inside `tb-hal`, the only crate
//! permitted `unsafe`; the two raw-MMIO helpers encapsulate it so the public
//! `serial_init` / `serial_write_byte` surface is safe.

// QEMU `virt` UART0 base. (Firecracker instead exposes an NS16550A -- see the
// FDT note at the bottom of this file.)
const PL011_BASE: usize = 0x0900_0000;

// Register offsets (bytes) -- ARM DDI 0183G, Table 3-1.
const UARTDR: usize = 0x000; // Data register (write = transmit).
const UARTFR: usize = 0x018; // Flag register.
const UARTIBRD: usize = 0x024; // Integer baud-rate divisor.
const UARTFBRD: usize = 0x028; // Fractional baud-rate divisor.
const UARTLCR_H: usize = 0x02C; // Line control.
const UARTCR: usize = 0x030; // Control.
const UARTIMSC: usize = 0x038; // Interrupt mask set/clear.
const UARTDMACR: usize = 0x048; // DMA control.

// Flag register (UARTFR) bits -- DDI 0183G §3.3.3.
const FR_BUSY: u32 = 1 << 3; // UART busy transmitting.
const FR_TXFF: u32 = 1 << 5; // Transmit FIFO full.

// Line control (UARTLCR_H) bits -- DDI 0183G §3.3.7.
const LCR_H_FEN: u32 = 1 << 4; // Enable FIFOs.
const LCR_H_WLEN_8: u32 = 0b11 << 5; // Word length = 8 data bits.

// Control (UARTCR) bits -- DDI 0183G §3.3.8.
const CR_UARTEN: u32 = 1 << 0; // UART enable.
const CR_TXE: u32 = 1 << 8; // Transmit enable.
const CR_RXE: u32 = 1 << 9; // Receive enable.

const IMSC_MASK_ALL: u32 = 0x7FF; // Mask every UART interrupt source.

#[inline(always)]
fn write_reg(offset: usize, value: u32) {
    // SAFETY: `offset` is one of the fixed PL011 register offsets above, so the
    // computed address is a valid, 4-byte-aligned MMIO location for the QEMU
    // `virt` UART0. Early boot is single-threaded; we are the sole accessor.
    unsafe { core::ptr::write_volatile((PL011_BASE + offset) as *mut u32, value) }
}

#[inline(always)]
fn read_reg(offset: usize) -> u32 {
    // SAFETY: as `write_reg`; status reads are side-effect-free loads.
    unsafe { core::ptr::read_volatile((PL011_BASE + offset) as *const u32) }
}

/// Initialise the PL011 for polled, 8N1 transmission at 115200 baud.
///
/// Programming order follows DDI 0183G §3.3.8 (disable, drain, configure,
/// re-enable). On QEMU the divisors are cosmetic, but we set the correct
/// 115200-from-24 MHz values for real-hardware fidelity.
pub fn serial_init() {
    // 1. Disable the UART before reconfiguring it.
    write_reg(UARTCR, 0);
    // 2. Wait for any character currently in flight to drain.
    while read_reg(UARTFR) & FR_BUSY != 0 {}
    // 3. Mask all interrupts and disable DMA (polled, no IRQs in M0).
    write_reg(UARTIMSC, IMSC_MASK_ALL);
    write_reg(UARTDMACR, 0);
    // 4. Baud = UARTCLK / (16 * baud); 24e6 / (16 * 115200) = 13.0208 ->
    //    IBRD = 13, FBRD = round(0.0208 * 64) = 1.
    write_reg(UARTIBRD, 13);
    write_reg(UARTFBRD, 1);
    // 5. 8 data bits, 1 stop, no parity, FIFOs on. LCR_H must be written after
    //    IBRD/FBRD: writing it latches the divisors.
    write_reg(UARTLCR_H, LCR_H_FEN | LCR_H_WLEN_8);
    // 6. Enable the UART and transmitter (RX enabled too, harmlessly).
    write_reg(UARTCR, CR_UARTEN | CR_TXE | CR_RXE);
}

/// Transmit one byte, blocking until the TX FIFO has room.
///
/// Byte-transparent on purpose: no `\n` -> `\r\n` translation, so the serial
/// stream contains the DoD marker `"hello from rust_main\n"` verbatim. Newline
/// policy belongs to a higher layer, not this HAL primitive.
pub fn serial_write_byte(b: u8) {
    while read_reg(UARTFR) & FR_TXFF != 0 {}
    write_reg(UARTDR, b as u32);
}

// ---------------------------------------------------------------------------
// TODO (FDT-driven UART -- Firecracker / `tb-vmm` profile, milestone MV).
//
// Firecracker's aarch64 microVM does NOT provide a PL011: it advertises an
// NS16550A 8250-class UART whose MMIO base is discoverable only by walking the
// FDT handed to `_start` in x0 (node `compatible = "ns16550a"`, or the
// `/chosen` `stdout-path`). M0 hardcodes the QEMU `virt` PL011 above; the
// runtime-selected path lands with the device-tree parser. Sketch of the
// cfg-gated entry point that will supersede the hardcoded base:
//
//   #[cfg(feature = "fdt-uart")]
//   pub fn serial_init_from_fdt(fdt_ptr: usize) {
//       // parse /chosen stdout-path -> match "arm,pl011" | "ns16550a"
//       // -> install the matching driver + base. (NS16550A: THR @ +0x0,
//       //    LSR @ +0x5 bit 5 = THR-empty -- mirrors the x86 16550 @ 0x3F8.)
//   }
// ---------------------------------------------------------------------------
