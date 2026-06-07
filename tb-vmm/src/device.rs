//! Device-bus abstraction: a PIO/MMIO address-range registry that dispatches
//! guest I/O to registered devices. Deliberately transport-agnostic so a virtio
//! MMIO transport can be added later as just another [`BusDevice`].
//!
//! Modelled on the rust-vmm / Firecracker `Bus` pattern (a sorted map from base
//! address to device, dispatched by the largest base <= addr).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

/// A device that occupies a contiguous address range on a bus. Offsets passed
/// to [`BusDevice::read`]/[`BusDevice::write`] are relative to the device base.
///
/// `Send` so devices can later be shared with an I/O thread (e.g. a serial
/// input pump); the current single-threaded run loop never contends the mutex.
pub trait BusDevice: Send {
    /// Handle a guest read at `offset` within this device, filling `data`.
    fn read(&mut self, offset: u64, data: &mut [u8]);
    /// Handle a guest write of `data` at `offset` within this device.
    fn write(&mut self, offset: u64, data: &[u8]);
}

/// Shared, lockable device handle stored on a bus.
pub type SharedDevice = Arc<Mutex<dyn BusDevice>>;

/// Error registering a device on a bus.
#[derive(Debug, PartialEq, Eq)]
pub enum BusError {
    /// A zero-length range was requested.
    ZeroLength,
    /// The requested range overlaps an already-registered device.
    Overlap {
        /// Requested base.
        base: u64,
        /// Requested length.
        len: u64,
    },
}

impl fmt::Display for BusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BusError::ZeroLength => write!(f, "device range has zero length"),
            BusError::Overlap { base, len } => {
                write!(f, "device range [{base:#x}, {:#x}) overlaps an existing device", base + len)
            }
        }
    }
}

impl std::error::Error for BusError {}

struct Entry {
    len: u64,
    device: SharedDevice,
}

/// An I/O bus: a sorted registry of devices keyed by base address.
#[derive(Default)]
pub struct Bus {
    entries: BTreeMap<u64, Entry>,
}

impl Bus {
    /// A new, empty bus.
    pub fn new() -> Self {
        Bus {
            entries: BTreeMap::new(),
        }
    }

    /// Register `device` covering `[base, base + len)`. Errors on overlap.
    pub fn register(&mut self, base: u64, len: u64, device: SharedDevice) -> Result<(), BusError> {
        if len == 0 {
            return Err(BusError::ZeroLength);
        }
        let end = base.saturating_add(len);
        // Overlap check against the neighbour at-or-before and the one after.
        if let Some((&pbase, pentry)) = self.entries.range(..=base).next_back() {
            if pbase + pentry.len > base {
                return Err(BusError::Overlap { base, len });
            }
        }
        if let Some((&nbase, _)) = self.entries.range(base..).next() {
            if nbase < end {
                return Err(BusError::Overlap { base, len });
            }
        }
        self.entries.insert(base, Entry { len, device });
        Ok(())
    }

    /// Find the device whose range contains `addr`, returning its base.
    fn lookup(&self, addr: u64) -> Option<(u64, &SharedDevice)> {
        let (&base, entry) = self.entries.range(..=addr).next_back()?;
        if addr < base + entry.len {
            Some((base, &entry.device))
        } else {
            None
        }
    }

    /// Dispatch a guest read at absolute `addr`. Unclaimed reads return all-ones
    /// (open-bus), matching real hardware and never stalling the guest.
    pub fn read(&self, addr: u64, data: &mut [u8]) {
        match self.lookup(addr) {
            Some((base, device)) => device
                .lock()
                .expect("device mutex poisoned")
                .read(addr - base, data),
            None => data.fill(0xff),
        }
    }

    /// Dispatch a guest write at absolute `addr`. Unclaimed writes are dropped.
    pub fn write(&self, addr: u64, data: &[u8]) {
        if let Some((base, device)) = self.lookup(addr) {
            device
                .lock()
                .expect("device mutex poisoned")
                .write(addr - base, data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Probe {
        last_write: Option<(u64, Vec<u8>)>,
        read_fill: u8,
    }
    impl BusDevice for Probe {
        fn read(&mut self, offset: u64, data: &mut [u8]) {
            data.fill(self.read_fill);
            // encode the offset in the first byte so tests can check dispatch
            if let Some(b) = data.first_mut() {
                *b = offset as u8;
            }
        }
        fn write(&mut self, offset: u64, data: &[u8]) {
            self.last_write = Some((offset, data.to_vec()));
        }
    }

    fn probe() -> Arc<Mutex<Probe>> {
        Arc::new(Mutex::new(Probe::default()))
    }

    #[test]
    fn dispatch_translates_offset() {
        let mut bus = Bus::new();
        let p = probe();
        bus.register(0x3f8, 8, p.clone()).unwrap();

        bus.write(0x3fd, &[0xAB]);
        let got = p.lock().unwrap().last_write.clone().unwrap();
        assert_eq!(got.0, 5); // 0x3fd - 0x3f8
        assert_eq!(got.1, vec![0xAB]);

        let mut data = [0u8; 1];
        bus.read(0x3fa, &mut data);
        assert_eq!(data[0], 2); // offset 2 echoed back
    }

    #[test]
    fn unclaimed_read_is_open_bus() {
        let bus = Bus::new();
        let mut data = [0u8; 2];
        bus.read(0x1234, &mut data);
        assert_eq!(data, [0xff, 0xff]);
    }

    #[test]
    fn overlap_is_rejected() {
        let mut bus = Bus::new();
        bus.register(0x100, 0x10, probe()).unwrap();
        assert_eq!(
            bus.register(0x108, 0x10, probe()).unwrap_err(),
            BusError::Overlap { base: 0x108, len: 0x10 }
        );
        // Adjacent, non-overlapping is fine.
        bus.register(0x110, 0x10, probe()).unwrap();
    }

    #[test]
    fn zero_length_is_rejected() {
        let mut bus = Bus::new();
        assert_eq!(bus.register(0x100, 0, probe()).unwrap_err(), BusError::ZeroLength);
    }
}
