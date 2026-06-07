//! A minimal 16550A UART (COM1-class) device.
//!
//! It carries guest serial output to a host writer (stdout in production) so CI
//! can grep the milestone markers, and supports input via an injectable queue.
//! It is matched exactly to the kernel's polled TX driver
//! (crates/tb-hal/src/arch/x86_64/serial.rs): the guest writes one byte at a
//! time after spinning on LSR bit 5 (THRE), so we must always report THRE set,
//! and we must honour DLAB so the init-time divisor write to THR is NOT printed.
//!
//! Register map (offsets from base, National 16550 / OSDev \"Serial Ports\"):
//!   0  THR/RBR  (DLAB=0) | DLL  (DLAB=1)
//!   1  IER      (DLAB=0) | DLM  (DLAB=1)
//!   2  IIR (r) / FCR (w)
//!   3  LCR  (bit 7 = DLAB)
//!   4  MCR
//!   5  LSR  (bit 5 = THRE, bit 6 = TEMT, bit 0 = DR)
//!   6  MSR
//!   7  SCR  (scratch)

use std::collections::VecDeque;
use std::io::Write;

use crate::device::BusDevice;

const REG_DATA: u64 = 0; // THR (w) / RBR (r) / DLL (DLAB)
const REG_IER: u64 = 1; // IER / DLM (DLAB)
const REG_IIR_FCR: u64 = 2;
const REG_LCR: u64 = 3;
const REG_MCR: u64 = 4;
const REG_LSR: u64 = 5;
const REG_MSR: u64 = 6;
const REG_SCR: u64 = 7;

const LCR_DLAB: u8 = 0x80;
const LSR_DR: u8 = 0x01; // data ready (input available)
const LSR_THRE: u8 = 0x20; // transmit holding register empty
const LSR_TEMT: u8 = 0x40; // transmitter empty
const MSR_DEFAULT: u8 = 0xB0; // DCD | DSR | CTS asserted (typical idle modem state)
const IIR_NO_INT: u8 = 0x01; // no interrupt pending

/// A 16550A UART writing transmitted bytes to `out`.
pub struct Serial {
    ier: u8,
    lcr: u8,
    mcr: u8,
    scr: u8,
    fcr: u8,
    dll: u8,
    dlm: u8,
    input: VecDeque<u8>,
    out: Box<dyn Write + Send>,
}

impl Serial {
    /// A new UART transmitting to `out`.
    pub fn new(out: Box<dyn Write + Send>) -> Self {
        Serial {
            ier: 0,
            lcr: 0,
            mcr: 0,
            scr: 0,
            fcr: 0,
            dll: 0,
            dlm: 0,
            input: VecDeque::new(),
            out,
        }
    }

    /// Queue bytes as guest input (drained by guest reads of RBR). Unused by the
    /// M0-M4 boot, which is output-only, but keeps the device complete.
    #[allow(dead_code)]
    pub fn enqueue_input(&mut self, bytes: &[u8]) {
        self.input.extend(bytes.iter().copied());
    }

    fn dlab(&self) -> bool {
        self.lcr & LCR_DLAB != 0
    }

    fn line_status(&self) -> u8 {
        let mut lsr = LSR_THRE | LSR_TEMT; // always ready to transmit
        if !self.input.is_empty() {
            lsr |= LSR_DR;
        }
        lsr
    }

    fn transmit(&mut self, byte: u8) {
        // Best-effort: a closed stdout must not crash the VMM. Flush each byte
        // so piped CI output (block-buffered) shows markers promptly.
        let _ = self.out.write_all(&[byte]);
        let _ = self.out.flush();
    }
}

impl BusDevice for Serial {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        let value = match offset {
            REG_DATA => {
                if self.dlab() {
                    self.dll
                } else {
                    self.input.pop_front().unwrap_or(0)
                }
            }
            REG_IER => {
                if self.dlab() {
                    self.dlm
                } else {
                    self.ier
                }
            }
            REG_IIR_FCR => IIR_NO_INT,
            REG_LCR => self.lcr,
            REG_MCR => self.mcr,
            REG_LSR => self.line_status(),
            REG_MSR => MSR_DEFAULT,
            REG_SCR => self.scr,
            _ => 0,
        };
        if let Some(b) = data.first_mut() {
            *b = value;
        }
        for b in data.iter_mut().skip(1) {
            *b = 0;
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        let Some(&value) = data.first() else {
            return;
        };
        match offset {
            REG_DATA => {
                if self.dlab() {
                    self.dll = value; // divisor latch low — NOT transmitted
                } else {
                    self.transmit(value);
                }
            }
            REG_IER => {
                if self.dlab() {
                    self.dlm = value; // divisor latch high
                } else {
                    self.ier = value;
                }
            }
            REG_IIR_FCR => self.fcr = value, // FIFO control
            REG_LCR => self.lcr = value,     // updates DLAB
            REG_MCR => self.mcr = value,
            REG_SCR => self.scr = value,
            // LSR (5) and MSR (6) are read-only; ignore writes.
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A `Write` that appends into a shared buffer the test can inspect.
    #[derive(Clone)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);
    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn serial_with_buf() -> (Serial, Arc<Mutex<Vec<u8>>>) {
        let buf = Arc::new(Mutex::new(Vec::new()));
        (Serial::new(Box::new(SharedBuf(buf.clone()))), buf)
    }

    #[test]
    fn lsr_always_reports_thre() {
        let (mut s, _) = serial_with_buf();
        let mut d = [0u8; 1];
        s.read(REG_LSR, &mut d);
        assert_ne!(d[0] & LSR_THRE, 0, "guest TX loop spins forever without THRE");
    }

    #[test]
    fn init_divisor_write_is_not_printed_then_char_is() {
        // Mirror the kernel's serial_init() ordering for the DLAB-sensitive part.
        let (mut s, buf) = serial_with_buf();
        s.write(REG_LCR, &[0x80]); // DLAB = 1
        s.write(REG_DATA, &[0x01]); // DLL divisor — must NOT be emitted
        s.write(REG_IER, &[0x00]); // DLM divisor
        s.write(REG_LCR, &[0x03]); // DLAB = 0, 8N1
        assert!(buf.lock().unwrap().is_empty(), "divisor latch byte leaked to output");

        s.write(REG_DATA, &[b'H']); // now a real character
        s.write(REG_DATA, &[b'i']);
        assert_eq!(&*buf.lock().unwrap(), b"Hi");
    }

    #[test]
    fn input_queue_sets_dr_and_drains() {
        let (mut s, _) = serial_with_buf();
        s.enqueue_input(b"AB");
        let mut lsr = [0u8; 1];
        s.read(REG_LSR, &mut lsr);
        assert_ne!(lsr[0] & LSR_DR, 0);

        let mut d = [0u8; 1];
        s.read(REG_DATA, &mut d);
        assert_eq!(d[0], b'A');
        s.read(REG_DATA, &mut d);
        assert_eq!(d[0], b'B');
        s.read(REG_LSR, &mut lsr);
        assert_eq!(lsr[0] & LSR_DR, 0, "DR clears when the input queue empties");
    }
}
