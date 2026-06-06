//! Legacy 16550 UART driver — COM1 @ I/O port 0x3F8 (the earliest serial out).
//!
//! Polled, interrupt-free TX. Works on QEMU `microvm` (ISA serial, on by
//! default) and on Firecracker (whose serial is a 16550A at 0x3F8 as well).
//! Register offsets and the init sequence follow the National 16550 datasheet
//! as documented on the OSDev wiki "Serial Ports" page; LSR bit 5 (0x20) is
//! THRE — Transmit Holding Register Empty.

/// COM1 base I/O port.
const COM1: u16 = 0x3F8;

// 16550 register offsets from the base port. With LCR.DLAB=1, offset 0/1 become
// the divisor latches DLL/DLM instead of THR/IER.
const THR: u16 = 0; // W: Transmit Holding Reg (DLAB=0) / DLL divisor-low (DLAB=1)
const IER: u16 = 1; // Interrupt Enable Reg    (DLAB=0) / DLM divisor-high (DLAB=1)
const FCR: u16 = 2; // W: FIFO Control Register
const LCR: u16 = 3; // Line Control Register (bit 7 = DLAB)
const MCR: u16 = 4; // Modem Control Register
const LSR: u16 = 5; // Line Status Register (bit 5 = THRE)

const LSR_THRE: u8 = 0x20; // TX holding register empty

/// Write one byte to an x86 I/O port.
///
/// (a) PRE: `port` is a valid 16-bit I/O port. POST: `val` is written to it.
/// (b) ABI: `out dx, al`; reads dx/al, writes nothing; nomem/nostack/
///     preserves_flags (port I/O has a side effect but touches no RAM).
/// (c) Tested by: scripts/run-x86_64.sh (every emitted serial byte).
#[inline]
unsafe fn outb(port: u16, val: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Read one byte from an x86 I/O port.
///
/// (a) PRE: `port` is a valid 16-bit I/O port. POST: returns the byte read.
/// (b) ABI: `in al, dx`; reads dx, writes al; nomem/nostack/preserves_flags.
///     NOT `pure`, so the LSR poll loop re-reads on every iteration.
/// (c) Tested by: scripts/run-x86_64.sh (LSR polling in `serial_write_byte`).
#[inline]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    unsafe {
        core::arch::asm!(
            "in al, dx",
            out("al") val,
            in("dx") port,
            options(nomem, nostack, preserves_flags),
        );
    }
    val
}

/// Initialise COM1: 115200 baud, 8N1, FIFOs enabled, interrupts disabled.
///
/// Divisor 1 against the 1.8432 MHz UART clock => 115200 baud. Idempotent.
pub fn serial_init() {
    unsafe {
        outb(COM1 + IER, 0x00); // disable all UART interrupts
        outb(COM1 + LCR, 0x80); // DLAB = 1 (expose divisor latches)
        outb(COM1 + THR, 0x01); // DLL: divisor low  = 1  -> 115200 baud
        outb(COM1 + IER, 0x00); // DLM: divisor high = 0
        outb(COM1 + LCR, 0x03); // DLAB = 0; 8 data bits, no parity, 1 stop bit
        outb(COM1 + FCR, 0xC7); // FIFO on, clear RX+TX, 14-byte trigger level
        outb(COM1 + MCR, 0x0B); // DTR | RTS | OUT2
    }
}

/// Write one byte to COM1, blocking until the TX holding register is empty.
pub fn serial_write_byte(b: u8) {
    unsafe {
        while inb(COM1 + LSR) & LSR_THRE == 0 {
            core::hint::spin_loop();
        }
        outb(COM1 + THR, b);
    }
}
