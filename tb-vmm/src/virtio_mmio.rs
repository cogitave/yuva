//! M30 stage C: tb-vmm's FIRST virtio device backend — a minimal MODERN
//! virtio-mmio (Version=2) **virtio-console** (DeviceID 3) transport as a
//! [`crate::device::BusDevice`], fronting the in-process
//! [`crate::infer_host::InferHost`] peer (proposal §3d, BACKLOG row 23's
//! deferred remainder).
//!
//! SCOPE — exactly the register file the kernel driver touches, nothing more
//! (the proposal-§3d rule; the kernel side is
//! `crates/tb-hal/src/arch/x86_64/virtio.rs::chan_send_recv`, landed in stage
//! B and UNTOUCHED here): Magic/Version/DeviceID/VendorID,
//! DeviceFeatures(Sel) offering ONLY the `VERSION_1` high-dword bit,
//! DriverFeatures(Sel), QueueSel/QueueNumMax/QueueNum/QueueReady latched per
//! queue, QueueNotify, Status (reset + FEATURES_OK validation),
//! InterruptStatus/ACK inert (the guest is poll-only — `mode=POLL`, the #71
//! pin), and Queue{Desc,Driver,Device}{Low,High}. Register layout per virtio
//! v1.2 §4.2.2; split-virtqueue walk per §2.7 with the §2.7.8.2 used-ring
//! publish order (write the buffer bytes, then `used.ring[idx]`, then
//! `used.idx` — trivially ordered here because the vCPU is parked in the
//! `KVM_EXIT_MMIO` handler for the whole walk, the in-process dividend).
//!
//! The console collapses to receiveq(0)+transmitq(1) on port 0 because the
//! driver negotiates ONLY `VERSION_1` (F_MULTIPORT/F_SIZE/F_EMERG_WRITE are
//! offered as 0 and would be rejected at FEATURES_OK if a driver tried them) —
//! §5.3.2: no control queue, no config space.
//!
//! Data path: a transmitq notify pops the guest's request bytes off the
//! descriptor chain and feeds them to the peer
//! ([`InferHost::push_guest_bytes`] — the SAME proven `FrameAccum`/`decode`
//! re-framing the chardev harness runs); the peer's queued response bytes are
//! then drained into POSTED receiveq buffers (the kernel posts its rx window
//! BEFORE `DRIVER_OK`, §5.3.6.1, and re-posts + re-notifies queue 0 on partial
//! reads — both paths land in [`VirtioMmio::drain_rx`]). A guest status-write
//! of 0 resets the TRANSPORT state (queues, features, counters) but never the
//! PEER state (key/nonce/stream/outbuf persist, exactly as the chardev socket
//! and the harness process persist across the kernel's per-session device
//! resets).
//!
//! Fail-soft discipline: a malformed ring/descriptor (bad guest address,
//! absurd chain) aborts THAT walk with a stderr diagnostic and publishes
//! nothing — the kernel's `POLL_CAP`-bounded spin then turns the silence into
//! a LOUD `M30/M31: FAIL xport-timeout`, never a hang and never a forged
//! completion.

use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use crate::device::BusDevice;
use crate::infer_host::InferHost;

/// Guest-physical base of the device window: slot 0 of the kernel's hard-coded
/// virtio-mmio scan table (`SLOT_BASE_PA = 0xFEB0_0000`, stride 0x200 — the
/// QEMU `microvm` map the M19 driver scans; the kernel UC-maps the window and
/// matches by DeviceID, so slot 0 is found regardless of where QEMU would have
/// plugged it). This GPA is ABOVE the registered guest RAM (256 MiB at GPA 0),
/// so every access arrives as a `KVM_EXIT_MMIO` for free.
pub const XPORT_MMIO_BASE: u64 = 0xFEB0_0000;
/// One virtio-mmio transport stride.
pub const XPORT_MMIO_LEN: u64 = 0x200;

// ---- virtio-mmio register offsets (v1.2 §4.2.2; mirrors the kernel driver) --
const R_MAGIC: u64 = 0x000;
const R_VERSION: u64 = 0x004;
const R_DEVICE_ID: u64 = 0x008;
const R_VENDOR_ID: u64 = 0x00C;
const R_DEVICE_FEATURES: u64 = 0x010;
const R_DEVICE_FEATURES_SEL: u64 = 0x014;
const R_DRIVER_FEATURES: u64 = 0x020;
const R_DRIVER_FEATURES_SEL: u64 = 0x024;
const R_QUEUE_SEL: u64 = 0x030;
const R_QUEUE_NUM_MAX: u64 = 0x034;
const R_QUEUE_NUM: u64 = 0x038;
const R_QUEUE_READY: u64 = 0x044;
const R_QUEUE_NOTIFY: u64 = 0x050;
const R_INTERRUPT_STATUS: u64 = 0x060;
const R_INTERRUPT_ACK: u64 = 0x064;
const R_STATUS: u64 = 0x070;
const R_QUEUE_DESC_LOW: u64 = 0x080;
const R_QUEUE_DESC_HIGH: u64 = 0x084;
const R_QUEUE_DRIVER_LOW: u64 = 0x090; // avail ring
const R_QUEUE_DRIVER_HIGH: u64 = 0x094;
const R_QUEUE_DEVICE_LOW: u64 = 0x0A0; // used ring
const R_QUEUE_DEVICE_HIGH: u64 = 0x0A4;
const R_CONFIG_GENERATION: u64 = 0x0FC;

const VIRTIO_MAGIC: u32 = 0x7472_6976; // "virt", little-endian
const VIRTIO_VERSION_MODERN: u32 = 2;
/// virtio-console DeviceID (v1.2 §5.3) — the M30 channel device class, chosen
/// in research §3 because it is the ONLY class with a stock-QEMU virtio-mmio
/// peer on both arches AND a tb-vmm-emulable register file.
const VIRTIO_DEV_CONSOLE: u32 = 3;
/// Vendor ID: "YVMM" LE — informational only (the kernel driver never reads
/// it; virtio v1.2 §4.2.2 leaves the value free).
const VENDOR_ID: u32 = 0x4D4D_5659;

/// `VIRTIO_F_VERSION_1` (bit 32) as it appears in the HIGH feature dword
/// (DeviceFeaturesSel=1, bit 0) — the ONLY feature this device offers.
const VIRTIO_F_VERSION_1_HI: u32 = 1 << 0;

// Status bits (v1.2 §2.1).
const S_FEATURES_OK: u32 = 8;
const S_DRIVER_OK: u32 = 4;

// Split-virtqueue descriptor flags (v1.2 §2.7.5).
const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

/// The QueueNumMax this device reports for both queues. The kernel driver
/// programs `QueueNum = 4` (its `CHAN_Q_SIZE`); reporting exactly that keeps
/// the device pinned to the negotiated session shape (a driver asking for more
/// is out of contract).
const QUEUE_NUM_MAX: u32 = 4;
/// Number of virtqueues: receiveq(0) + transmitq(1) — the non-MULTIPORT §5.3.2
/// port-0 pair, nothing else.
const NUM_QUEUES: usize = 2;
/// The transmitq queue index (guest->host) / receiveq index (host->guest).
const TXQ: usize = 1;
const RXQ: usize = 0;

/// Per-virtqueue transport state (reset by a guest status-write of 0).
#[derive(Clone, Copy, Default)]
struct QueueState {
    /// Driver-programmed queue size (the ring modulus).
    num: u32,
    /// QueueReady latch.
    ready: bool,
    /// Descriptor-table / avail-ring / used-ring guest-physical addresses,
    /// latched from the Low/High register pairs.
    desc: u64,
    driver: u64,
    device: u64,
    /// Device-side consumed-avail counter (free-running, ring-mod on use).
    next_avail: u16,
    /// Device-side published-used counter (mirrors guest-visible `used.idx`).
    used_count: u16,
}

impl QueueState {
    /// Compose a Low/High latched address pair.
    fn set_addr(addr: &mut u64, half: u64, high: bool) {
        if high {
            *addr = (*addr & 0xFFFF_FFFF) | (half << 32);
        } else {
            *addr = (*addr & !0xFFFF_FFFF) | (half & 0xFFFF_FFFF);
        }
    }
}

/// The modern virtio-mmio console transport + queue walker. Registered on the
/// `mmio_bus` at [`XPORT_MMIO_BASE`]; owns a clone of the guest memory (the
/// vm-memory mmap regions are internally shared, so this is a cheap handle)
/// and the in-process host peer.
pub struct VirtioMmio {
    mem: GuestMemoryMmap,
    host: InferHost,
    status: u32,
    device_features_sel: u32,
    driver_features_sel: u32,
    /// Driver-acked feature dwords ([0]=low, [1]=high).
    driver_features: [u32; 2],
    queue_sel: u32,
    queues: [QueueState; NUM_QUEUES],
}

impl VirtioMmio {
    /// A new transport fronting `host`, walking rings in `mem`.
    pub fn new(mem: GuestMemoryMmap, host: InferHost) -> Self {
        VirtioMmio {
            mem,
            host,
            status: 0,
            device_features_sel: 0,
            driver_features_sel: 0,
            driver_features: [0; 2],
            queue_sel: 0,
            queues: [QueueState::default(); NUM_QUEUES],
        }
    }

    /// Guest status-write of 0: reset the TRANSPORT (v1.2 §2.1.2 — queues
    /// detach, counters clear). The PEER (key/nonce/stream/outbuf) is NOT
    /// transport state and persists — the chardev-lane equivalence (the
    /// harness process + socket survive the kernel's per-session resets).
    fn reset(&mut self) {
        self.status = 0;
        self.device_features_sel = 0;
        self.driver_features_sel = 0;
        self.driver_features = [0; 2];
        self.queue_sel = 0;
        self.queues = [QueueState::default(); NUM_QUEUES];
    }

    /// The selected queue, if the driver's QueueSel names a real one.
    fn selq(&mut self) -> Option<&mut QueueState> {
        self.queues.get_mut(self.queue_sel as usize)
    }

    fn read_reg(&mut self, offset: u64) -> u32 {
        match offset {
            R_MAGIC => VIRTIO_MAGIC,
            R_VERSION => VIRTIO_VERSION_MODERN,
            R_DEVICE_ID => VIRTIO_DEV_CONSOLE,
            R_VENDOR_ID => VENDOR_ID,
            // Feature dwords by the latched selector: ONLY VERSION_1 (high
            // dword bit 0) is offered; the low dword is 0, so
            // F_SIZE/F_MULTIPORT/F_EMERG_WRITE are structurally un-offerable.
            R_DEVICE_FEATURES => match self.device_features_sel {
                0 => 0,
                1 => VIRTIO_F_VERSION_1_HI,
                _ => 0,
            },
            R_QUEUE_NUM_MAX => {
                if (self.queue_sel as usize) < NUM_QUEUES {
                    QUEUE_NUM_MAX
                } else {
                    0 // no such queue (v1.2 §4.2.2.1)
                }
            }
            R_QUEUE_READY => self.selq().map(|q| q.ready as u32).unwrap_or(0),
            // Poll-only lane: no interrupt is ever asserted (the guest sets
            // VIRTQ_AVAIL_F_NO_INTERRUPT and spins on used.idx — mode=POLL).
            R_INTERRUPT_STATUS => 0,
            R_STATUS => self.status,
            R_CONFIG_GENERATION => 0,
            _ => 0, // unimplemented/config space: inert zero (never open-bus
                    // 0xFFFF_FFFF — that would alias the M19 absent-slot probe)
        }
    }

    fn write_reg(&mut self, offset: u64, v: u32) {
        match offset {
            R_DEVICE_FEATURES_SEL => self.device_features_sel = v,
            R_DRIVER_FEATURES => {
                if (self.driver_features_sel as usize) < 2 {
                    self.driver_features[self.driver_features_sel as usize] = v;
                }
            }
            R_DRIVER_FEATURES_SEL => self.driver_features_sel = v,
            R_QUEUE_SEL => self.queue_sel = v,
            R_QUEUE_NUM => {
                if let Some(q) = self.selq() {
                    // Accept only a sane power-of-two size within the offered
                    // max (v1.2 §2.7: queue size is a power of 2). The kernel
                    // driver always writes 4.
                    if (1..=QUEUE_NUM_MAX).contains(&v) && v.is_power_of_two() {
                        q.num = v;
                    } else {
                        q.num = 0; // out-of-contract: the queue stays unusable
                    }
                }
            }
            R_QUEUE_READY => {
                if let Some(q) = self.selq() {
                    q.ready = v & 1 == 1;
                }
            }
            R_QUEUE_NOTIFY => self.notify(v),
            R_INTERRUPT_ACK => {} // inert: no interrupt is ever raised
            R_STATUS => {
                if v == 0 {
                    self.reset();
                    return;
                }
                let mut s = v;
                if v & S_FEATURES_OK != 0 {
                    // FEATURES_OK validation (v1.2 §2.1.2 device requirements):
                    // the driver must ack EXACTLY the offered set — VERSION_1
                    // and nothing else. Anything different clears the bit on
                    // readback and the kernel fails the session closed.
                    let ok = self.driver_features[0] == 0
                        && self.driver_features[1] == VIRTIO_F_VERSION_1_HI;
                    if !ok {
                        s &= !S_FEATURES_OK;
                    }
                }
                self.status = s;
            }
            R_QUEUE_DESC_LOW => {
                if let Some(q) = self.selq() {
                    QueueState::set_addr(&mut q.desc, v as u64, false);
                }
            }
            R_QUEUE_DESC_HIGH => {
                if let Some(q) = self.selq() {
                    QueueState::set_addr(&mut q.desc, v as u64, true);
                }
            }
            R_QUEUE_DRIVER_LOW => {
                if let Some(q) = self.selq() {
                    QueueState::set_addr(&mut q.driver, v as u64, false);
                }
            }
            R_QUEUE_DRIVER_HIGH => {
                if let Some(q) = self.selq() {
                    QueueState::set_addr(&mut q.driver, v as u64, true);
                }
            }
            R_QUEUE_DEVICE_LOW => {
                if let Some(q) = self.selq() {
                    QueueState::set_addr(&mut q.device, v as u64, false);
                }
            }
            R_QUEUE_DEVICE_HIGH => {
                if let Some(q) = self.selq() {
                    QueueState::set_addr(&mut q.device, v as u64, true);
                }
            }
            _ => {} // unimplemented: dropped (write-inert)
        }
    }

    /// QueueNotify: the value is the QUEUE INDEX being kicked (v1.2 §4.2.2).
    /// A transmitq(1) kick consumes the guest's request bytes into the peer;
    /// EITHER kick then drains any peer output into posted receiveq buffers
    /// (the kernel's initial rx post happens pre-DRIVER_OK with NO kick — the
    /// tx kick is what makes its bytes deliverable; the kernel's re-post path
    /// kicks queue 0 explicitly).
    fn notify(&mut self, q: u32) {
        if self.status & S_DRIVER_OK == 0 {
            return; // not driven yet: a kick before DRIVER_OK is out of contract
        }
        if q as usize == TXQ {
            self.process_tx();
        }
        if (q as usize) < NUM_QUEUES {
            self.drain_rx();
        }
    }

    /// Consume every new transmitq avail entry: gather the chain's
    /// device-READABLE bytes, feed them to the peer, publish a used entry
    /// (len=0 — the device wrote nothing into a read-only chain, §2.7.8.2).
    fn process_tx(&mut self) {
        loop {
            let q = self.queues[TXQ];
            if !q.ready || q.num == 0 {
                return;
            }
            let Some(avail_idx) = self.read_u16(q.driver.wrapping_add(2)) else {
                return; // unreadable ring: fail-soft, publish nothing
            };
            if q.next_avail == avail_idx {
                return; // no new entries
            }
            let slot = (q.next_avail as u64) % (q.num as u64);
            let Some(head) = self.read_u16(q.driver.wrapping_add(4 + 2 * slot)) else {
                return;
            };
            let Some(bytes) = self.gather_readable(&q, head) else {
                return; // malformed chain: fail-soft (kernel's POLL_CAP REDs)
            };
            self.host.push_guest_bytes(&bytes);
            self.queues[TXQ].next_avail = q.next_avail.wrapping_add(1);
            self.publish_used(TXQ, head as u32, 0);
        }
    }

    /// Drain peer output into posted receiveq buffers: one used entry per
    /// posted descriptor chain, carrying as many bytes as fit (§2.7.8.2 — the
    /// buffer bytes land BEFORE the used publish). Never consumes a posted
    /// buffer when there is nothing to deliver (the kernel re-posts its
    /// remaining window per completion and counts completions).
    fn drain_rx(&mut self) {
        loop {
            if self.host.out_len() == 0 {
                return;
            }
            let q = self.queues[RXQ];
            if !q.ready || q.num == 0 {
                return;
            }
            let Some(avail_idx) = self.read_u16(q.driver.wrapping_add(2)) else {
                return;
            };
            if q.next_avail == avail_idx {
                return; // no posted rx buffer: bytes wait in the peer outbuf
            }
            let slot = (q.next_avail as u64) % (q.num as u64);
            let Some(head) = self.read_u16(q.driver.wrapping_add(4 + 2 * slot)) else {
                return;
            };
            let Some(written) = self.scatter_writable(&q, head) else {
                return; // malformed chain: fail-soft
            };
            self.queues[RXQ].next_avail = q.next_avail.wrapping_add(1);
            self.publish_used(RXQ, head as u32, written as u32);
        }
    }

    /// Collect the device-READABLE bytes of the descriptor chain at `head`
    /// (transmitq direction). `None` on a malformed chain/address.
    fn gather_readable(&self, q: &QueueState, head: u16) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut idx = head;
        let mut hops = 0u32;
        loop {
            // Chain-length bound: a ring of `num` descriptors can express at
            // most `num` hops; more is a loop (malformed).
            hops += 1;
            if hops > q.num {
                eprintln!("tb-vmm xport: tx descriptor chain exceeds queue size (loop?)");
                return None;
            }
            let d = q.desc.wrapping_add(16 * idx as u64);
            let addr = self.read_u64(d)?;
            let len = self.read_u32(d.wrapping_add(8))?;
            let flags = self.read_u16(d.wrapping_add(12))?;
            let next = self.read_u16(d.wrapping_add(14))?;
            if flags & VIRTQ_DESC_F_WRITE == 0 {
                let mut buf = vec![0u8; len as usize];
                self.mem.read_slice(&mut buf, GuestAddress(addr)).ok()?;
                out.extend_from_slice(&buf);
            }
            if flags & VIRTQ_DESC_F_NEXT == 0 {
                return Some(out);
            }
            idx = next;
        }
    }

    /// Write peer output into the device-WRITABLE segments of the chain at
    /// `head` (receiveq direction), up to what is queued. Returns the bytes
    /// written; `None` on a malformed chain/address.
    fn scatter_writable(&mut self, q: &QueueState, head: u16) -> Option<usize> {
        let mut written = 0usize;
        let mut idx = head;
        let mut hops = 0u32;
        loop {
            hops += 1;
            if hops > q.num {
                eprintln!("tb-vmm xport: rx descriptor chain exceeds queue size (loop?)");
                return None;
            }
            let d = q.desc.wrapping_add(16 * idx as u64);
            let addr = self.read_u64(d)?;
            let len = self.read_u32(d.wrapping_add(8))?;
            let flags = self.read_u16(d.wrapping_add(12))?;
            let next = self.read_u16(d.wrapping_add(14))?;
            if flags & VIRTQ_DESC_F_WRITE != 0 && self.host.out_len() > 0 {
                let chunk = self.host.take_output(len as usize);
                self.mem.write_slice(&chunk, GuestAddress(addr)).ok()?;
                written += chunk.len();
            }
            if flags & VIRTQ_DESC_F_NEXT == 0 || self.host.out_len() == 0 {
                return Some(written);
            }
            idx = next;
        }
    }

    /// Publish ONE used-ring entry for queue `qi` (§2.7.8.2 order: the data
    /// bytes are already in guest RAM; write `used.ring[used_count % num] =
    /// {id, len}`, THEN bump the guest-visible `used.idx`). The vCPU is parked
    /// in this MMIO exit, so the order is trivially observed.
    fn publish_used(&mut self, qi: usize, id: u32, len: u32) {
        let q = self.queues[qi];
        let entry = q
            .device
            .wrapping_add(4 + 8 * ((q.used_count as u64) % (q.num as u64)));
        if self.write_u32(entry, id).is_none()
            || self.write_u32(entry.wrapping_add(4), len).is_none()
        {
            eprintln!("tb-vmm xport: used-ring write failed (bad ring address)");
            return;
        }
        let new_count = q.used_count.wrapping_add(1);
        self.queues[qi].used_count = new_count;
        if self
            .write_u16(q.device.wrapping_add(2), new_count)
            .is_none()
        {
            eprintln!("tb-vmm xport: used.idx write failed (bad ring address)");
        }
    }

    // ---- guest-RAM scalar accessors (explicit LE, fail-soft Option) --------

    fn read_u16(&self, gpa: u64) -> Option<u16> {
        let mut b = [0u8; 2];
        self.mem.read_slice(&mut b, GuestAddress(gpa)).ok()?;
        Some(u16::from_le_bytes(b))
    }

    fn read_u32(&self, gpa: u64) -> Option<u32> {
        let mut b = [0u8; 4];
        self.mem.read_slice(&mut b, GuestAddress(gpa)).ok()?;
        Some(u32::from_le_bytes(b))
    }

    fn read_u64(&self, gpa: u64) -> Option<u64> {
        let mut b = [0u8; 8];
        self.mem.read_slice(&mut b, GuestAddress(gpa)).ok()?;
        Some(u64::from_le_bytes(b))
    }

    fn write_u16(&self, gpa: u64, v: u16) -> Option<()> {
        self.mem
            .write_slice(&v.to_le_bytes(), GuestAddress(gpa))
            .ok()
    }

    fn write_u32(&self, gpa: u64, v: u32) -> Option<()> {
        self.mem
            .write_slice(&v.to_le_bytes(), GuestAddress(gpa))
            .ok()
    }
}

impl BusDevice for VirtioMmio {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        // The kernel driver issues only naturally-aligned 32-bit reads
        // (`reg_read`); anything else reads as zero (inert, never a stall).
        if data.len() == 4 && offset & 3 == 0 {
            data.copy_from_slice(&self.read_reg(offset).to_le_bytes());
        } else {
            data.fill(0);
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if data.len() == 4 && offset & 3 == 0 {
            let v = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            self.write_reg(offset, v);
        } // non-u32 writes: dropped (the kernel driver never issues one)
    }
}

#[cfg(test)]
mod tests {
    //! Transport tests that drive the EXACT register/ring sequence the kernel's
    //! `chan_send_recv` performs (stage B, byte-for-byte from
    //! `crates/tb-hal/src/arch/x86_64/virtio.rs`) against a real
    //! `GuestMemoryMmap`, then verify the delivered bytes with the SAME
    //! tb-encode leaf the kernel uses — the in-process mirror of the lane's
    //! anti-hollow legs.

    use super::*;
    use crate::infer_host::InferHost;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tb_encode::inferwire::{
        canon, decode, kind, peer, verify_echo, wire_len, InferFrame, INFER_HEADER_LEN,
        INFER_KEY_REVEAL_LEN,
    };

    #[derive(Clone, Default)]
    struct SharedSink(Arc<Mutex<Vec<u8>>>);
    impl Write for SharedSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    const KEY: [u8; 32] = [0x42u8; 32];
    const NONCE: [u8; 16] = [0x24u8; 16];

    // The kernel driver's in-frame session layout (chan_send_recv) at an
    // arbitrary identity "frame" GPA.
    const FRAME: u64 = 0x10_0000;
    const RX_DESC: u64 = FRAME;
    const RX_AVAIL: u64 = FRAME + 0x040;
    const RX_USED: u64 = FRAME + 0x080;
    const TX_DESC: u64 = FRAME + 0x0C0;
    const TX_AVAIL: u64 = FRAME + 0x100;
    const TX_USED: u64 = FRAME + 0x140;
    const TX_BUF: u64 = FRAME + 0x200;
    const RX_BUF: u64 = FRAME + 0x400;
    const Q_SIZE: u32 = 4;

    struct Rig {
        dev: VirtioMmio,
        mem: GuestMemoryMmap,
    }

    impl Rig {
        fn new() -> (Self, SharedSink) {
            let mem =
                GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4 << 20)]).expect("guest mem");
            let sink = SharedSink::default();
            let host = InferHost::with_key_nonce(KEY, NONCE, Box::new(sink.clone()));
            let dev = VirtioMmio::new(mem.clone(), host);
            (Rig { dev, mem }, sink)
        }

        fn r(&mut self, off: u64) -> u32 {
            let mut b = [0u8; 4];
            self.dev.read(off, &mut b);
            u32::from_le_bytes(b)
        }

        fn w(&mut self, off: u64, v: u32) {
            self.dev.write(off, &v.to_le_bytes());
        }

        fn mem_w16(&self, gpa: u64, v: u16) {
            self.mem.write_slice(&v.to_le_bytes(), GuestAddress(gpa)).unwrap();
        }
        fn mem_w32(&self, gpa: u64, v: u32) {
            self.mem.write_slice(&v.to_le_bytes(), GuestAddress(gpa)).unwrap();
        }
        fn mem_w64(&self, gpa: u64, v: u64) {
            self.mem.write_slice(&v.to_le_bytes(), GuestAddress(gpa)).unwrap();
        }
        fn mem_r16(&self, gpa: u64) -> u16 {
            let mut b = [0u8; 2];
            self.mem.read_slice(&mut b, GuestAddress(gpa)).unwrap();
            u16::from_le_bytes(b)
        }
        fn mem_r32(&self, gpa: u64) -> u32 {
            let mut b = [0u8; 4];
            self.mem.read_slice(&mut b, GuestAddress(gpa)).unwrap();
            u32::from_le_bytes(b)
        }

        /// The kernel's chan_send_recv, transliterated (reset -> handshake ->
        /// rx posted pre-DRIVER_OK -> tx kick -> poll tx used -> collect rx
        /// completions, re-posting the remaining window). Returns the response
        /// bytes, or None where the kernel would chan_fail.
        fn chan_send_recv(&mut self, req: &[u8], resp_len: usize) -> Option<Vec<u8>> {
            // reset -> ACK -> DRIVER
            self.w(R_STATUS, 0);
            self.w(R_STATUS, 1);
            self.w(R_STATUS, 1 | 2);
            // negotiate VERSION_1 only
            self.w(R_DEVICE_FEATURES_SEL, 1);
            if self.r(R_DEVICE_FEATURES) & 1 == 0 {
                return None;
            }
            self.w(R_DRIVER_FEATURES_SEL, 0);
            self.w(R_DRIVER_FEATURES, 0);
            self.w(R_DRIVER_FEATURES_SEL, 1);
            self.w(R_DRIVER_FEATURES, 1);
            self.w(R_STATUS, 1 | 2 | 8);
            if self.r(R_STATUS) & 8 == 0 {
                return None;
            }
            // queue 0 (receiveq): rings + the POSTED rx window, pre-DRIVER_OK
            self.w(R_QUEUE_SEL, 0);
            if self.r(R_QUEUE_NUM_MAX) == 0 {
                return None;
            }
            self.w(R_QUEUE_NUM, Q_SIZE);
            self.w(R_QUEUE_DESC_LOW, RX_DESC as u32);
            self.w(R_QUEUE_DESC_HIGH, (RX_DESC >> 32) as u32);
            self.w(R_QUEUE_DRIVER_LOW, RX_AVAIL as u32);
            self.w(R_QUEUE_DRIVER_HIGH, (RX_AVAIL >> 32) as u32);
            self.w(R_QUEUE_DEVICE_LOW, RX_USED as u32);
            self.w(R_QUEUE_DEVICE_HIGH, (RX_USED >> 32) as u32);
            self.mem_w64(RX_DESC, RX_BUF);
            self.mem_w32(RX_DESC + 8, resp_len as u32);
            self.mem_w16(RX_DESC + 12, VIRTQ_DESC_F_WRITE);
            self.mem_w16(RX_DESC + 14, 0);
            self.mem_w16(RX_AVAIL, 1); // NO_INTERRUPT
            self.mem_w16(RX_AVAIL + 4, 0); // ring[0] = desc 0
            self.mem_w16(RX_AVAIL + 2, 1); // avail.idx = 1: POSTED
            self.w(R_QUEUE_READY, 1);
            if self.r(R_QUEUE_READY) != 1 {
                return None;
            }
            // queue 1 (transmitq)
            self.w(R_QUEUE_SEL, 1);
            if self.r(R_QUEUE_NUM_MAX) == 0 {
                return None;
            }
            self.w(R_QUEUE_NUM, Q_SIZE);
            self.w(R_QUEUE_DESC_LOW, TX_DESC as u32);
            self.w(R_QUEUE_DESC_HIGH, (TX_DESC >> 32) as u32);
            self.w(R_QUEUE_DRIVER_LOW, TX_AVAIL as u32);
            self.w(R_QUEUE_DRIVER_HIGH, (TX_AVAIL >> 32) as u32);
            self.w(R_QUEUE_DEVICE_LOW, TX_USED as u32);
            self.w(R_QUEUE_DEVICE_HIGH, (TX_USED >> 32) as u32);
            self.mem_w16(TX_AVAIL, 1); // NO_INTERRUPT
            self.w(R_QUEUE_READY, 1);
            if self.r(R_QUEUE_READY) != 1 {
                return None;
            }
            self.w(R_STATUS, 1 | 2 | 8 | 4); // DRIVER_OK
            // stage + send the request
            self.mem.write_slice(req, GuestAddress(TX_BUF)).unwrap();
            self.mem_w64(TX_DESC, TX_BUF);
            self.mem_w32(TX_DESC + 8, req.len() as u32);
            self.mem_w16(TX_DESC + 12, 0);
            self.mem_w16(TX_DESC + 14, 0);
            self.mem_w16(TX_AVAIL + 4, 0);
            self.mem_w16(TX_AVAIL + 2, 1);
            self.w(R_QUEUE_NOTIFY, 1); // kick the TRANSMITQ
            if self.mem_r16(TX_USED + 2) == 0 {
                return None; // the kernel's tx-used poll would spin to POLL_CAP
            }
            // collect rx completions (the kernel's re-post loop, poll-free
            // because the device completes synchronously inside the notify)
            let mut resp = vec![0u8; resp_len];
            let mut written = 0usize;
            let mut rx_avail_idx: u16 = 1;
            let mut rx_used_seen: u16 = 0;
            while written < resp_len {
                if self.mem_r16(RX_USED + 2) == rx_used_seen {
                    return None; // would spin to POLL_CAP: present-then-silent
                }
                let entry = RX_USED + 4 + 8 * ((rx_used_seen as u64) % (Q_SIZE as u64));
                let len = self.mem_r32(entry + 4) as usize;
                rx_used_seen = rx_used_seen.wrapping_add(1);
                let remain = resp_len - written;
                let take = usize::min(len, remain);
                let mut chunk = vec![0u8; take];
                self.mem.read_slice(&mut chunk, GuestAddress(RX_BUF)).unwrap();
                resp[written..written + take].copy_from_slice(&chunk);
                written += take;
                if written < resp_len {
                    // re-post the remaining window (the kernel's partial path)
                    self.mem_w64(RX_DESC, RX_BUF);
                    self.mem_w32(RX_DESC + 8, (resp_len - written) as u32);
                    self.mem_w16(RX_DESC + 12, VIRTQ_DESC_F_WRITE);
                    self.mem_w16(RX_DESC + 14, 0);
                    self.mem_w16(
                        RX_AVAIL + 4 + 2 * ((rx_avail_idx as u64) % (Q_SIZE as u64)),
                        0,
                    );
                    rx_avail_idx = rx_avail_idx.wrapping_add(1);
                    self.mem_w16(RX_AVAIL + 2, rx_avail_idx);
                    self.w(R_QUEUE_NOTIFY, 0); // kick the RECEIVEQ
                }
            }
            self.w(R_STATUS, 0); // session teardown (the kernel's clean reset)
            Some(resp)
        }
    }

    fn echo_req(challenge: [u8; 16], req_id: u64, body: &[u8]) -> Vec<u8> {
        let req = InferFrame {
            kind: kind::ECHO_REQ,
            req_id,
            challenge,
            nonce: [0u8; 16],
            peer_id: 0,
            tag: [0u8; 16],
            payload: body,
        };
        let mut wire = vec![0u8; wire_len(&req)];
        assert_eq!(canon(&req, &mut wire), wire.len());
        wire
    }

    // ---- the device-identity probe the kernel's chan_probe performs ---------

    #[test]
    fn probe_registers_match_the_kernel_scan() {
        let (mut rig, _sink) = Rig::new();
        assert_eq!(rig.r(R_MAGIC), 0x7472_6976);
        assert_eq!(rig.r(R_VERSION), 2, "MODERN (Version=2) -- never legacy");
        assert_eq!(rig.r(R_DEVICE_ID), 3, "virtio-console");
        // Feature dwords: ONLY VERSION_1 (high bit 0); low dword all-zero so
        // F_SIZE/F_MULTIPORT/F_EMERG_WRITE can never be negotiated.
        rig.w(R_DEVICE_FEATURES_SEL, 0);
        assert_eq!(rig.r(R_DEVICE_FEATURES), 0);
        rig.w(R_DEVICE_FEATURES_SEL, 1);
        assert_eq!(rig.r(R_DEVICE_FEATURES), 1);
        // Both queues exist; a third does not.
        rig.w(R_QUEUE_SEL, 0);
        assert_eq!(rig.r(R_QUEUE_NUM_MAX), 4);
        rig.w(R_QUEUE_SEL, 1);
        assert_eq!(rig.r(R_QUEUE_NUM_MAX), 4);
        rig.w(R_QUEUE_SEL, 2);
        assert_eq!(rig.r(R_QUEUE_NUM_MAX), 0);
    }

    #[test]
    fn features_ok_rejects_an_unoffered_bit() {
        let (mut rig, _sink) = Rig::new();
        rig.w(R_STATUS, 0);
        rig.w(R_STATUS, 1);
        rig.w(R_STATUS, 1 | 2);
        // The driver tries to ack F_MULTIPORT (low dword bit 1) + VERSION_1.
        rig.w(R_DRIVER_FEATURES_SEL, 0);
        rig.w(R_DRIVER_FEATURES, 1 << 1);
        rig.w(R_DRIVER_FEATURES_SEL, 1);
        rig.w(R_DRIVER_FEATURES, 1);
        rig.w(R_STATUS, 1 | 2 | 8);
        assert_eq!(rig.r(R_STATUS) & 8, 0, "FEATURES_OK must clear");
        // Rejecting VERSION_1 itself also clears.
        rig.w(R_STATUS, 0);
        rig.w(R_STATUS, 1);
        rig.w(R_STATUS, 1 | 2);
        rig.w(R_DRIVER_FEATURES_SEL, 0);
        rig.w(R_DRIVER_FEATURES, 0);
        rig.w(R_DRIVER_FEATURES_SEL, 1);
        rig.w(R_DRIVER_FEATURES, 0);
        rig.w(R_STATUS, 1 | 2 | 8);
        assert_eq!(rig.r(R_STATUS) & 8, 0, "VERSION_1 is mandatory");
    }

    // ---- the full kernel session against the real ring walker ---------------

    #[test]
    fn full_echo_session_round_trip() {
        let (mut rig, sink) = Rig::new();
        let challenge = [0xC7u8; 16];
        let body: Vec<u8> = (0..16u8).map(|b| b.wrapping_mul(29).wrapping_add(0xB0)).collect();
        let req = echo_req(challenge, 0xDEAD_BEEF, &body);
        let resp_len = INFER_HEADER_LEN + body.len() + INFER_KEY_REVEAL_LEN;
        let resp = rig
            .chan_send_recv(&req, resp_len)
            .expect("the session must complete");
        // LEG 1, exactly as the kernel verifies it: decode + verify_echo
        // against the channel-revealed key.
        let frame_len = INFER_HEADER_LEN + body.len();
        let frame = decode(&resp[..frame_len]).expect("ECHO_RESP decodes");
        assert_eq!(frame.kind, kind::ECHO_RESP);
        assert_eq!(frame.peer_id, peer::TB_VMM_HOST);
        let mut revealed = [0u8; 32];
        revealed.copy_from_slice(&resp[frame_len..]);
        let reqf = InferFrame {
            kind: kind::ECHO_REQ,
            req_id: 0xDEAD_BEEF,
            challenge,
            nonce: [0u8; 16],
            peer_id: 0,
            tag: [0u8; 16],
            payload: &body,
        };
        assert!(verify_echo(&revealed, &frame, &reqf), "leg-1 verify");
        // LEG 2's shape: the witness line carries the SAME challenge/tag.
        let w = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        let chal_hex: String = challenge.iter().map(|b| format!("{b:02x}")).collect();
        let tag_hex: String = frame.tag.iter().map(|b| format!("{b:02x}")).collect();
        assert!(w.contains(&format!(
            "xport-harness: peer=TB-VMM-HOST challenge=0x{chal_hex} tag=0x{tag_hex} key-custody=VMM"
        )));
    }

    #[test]
    fn three_sessions_share_one_per_run_key() {
        // The kernel runs THREE chan_send_recv sessions per boot (M30 echo +
        // M31 probe + M31 exchange), each with a full device reset between --
        // the peer's K/N must persist across the resets (one per-RUN key).
        let (mut rig, _sink) = Rig::new();
        let body = [0x55u8; 8];
        let resp_len = INFER_HEADER_LEN + body.len() + INFER_KEY_REVEAL_LEN;
        let r1 = rig
            .chan_send_recv(&echo_req([1u8; 16], 1, &body), resp_len)
            .expect("session 1");
        let r2 = rig
            .chan_send_recv(&echo_req([2u8; 16], 2, &body), resp_len)
            .expect("session 2 (after reset)");
        let frame_len = INFER_HEADER_LEN + body.len();
        assert_eq!(&r1[frame_len..], &r2[frame_len..], "same revealed K");
        assert_eq!(
            decode(&r1[..frame_len]).unwrap().nonce,
            decode(&r2[..frame_len]).unwrap().nonce,
            "same per-run nonce"
        );
    }

    #[test]
    fn partial_rx_window_repost_path_delivers_everything() {
        // Force the multi-completion path: post an rx window SMALLER than the
        // response, so the device fills it, the guest re-posts, and the
        // remainder arrives in a second completion (the kernel's re-post leg).
        let (mut rig, _sink) = Rig::new();
        let challenge = [0xABu8; 16];
        let body = [0x77u8; 16];
        let req = echo_req(challenge, 42, &body);
        let total = INFER_HEADER_LEN + body.len() + INFER_KEY_REVEAL_LEN;

        // Manual session with a 40-byte first window.
        rig.w(R_STATUS, 0);
        rig.w(R_STATUS, 1);
        rig.w(R_STATUS, 1 | 2);
        rig.w(R_DRIVER_FEATURES_SEL, 0);
        rig.w(R_DRIVER_FEATURES, 0);
        rig.w(R_DRIVER_FEATURES_SEL, 1);
        rig.w(R_DRIVER_FEATURES, 1);
        rig.w(R_STATUS, 1 | 2 | 8);
        assert_ne!(rig.r(R_STATUS) & 8, 0);
        rig.w(R_QUEUE_SEL, 0);
        rig.w(R_QUEUE_NUM, Q_SIZE);
        rig.w(R_QUEUE_DESC_LOW, RX_DESC as u32);
        rig.w(R_QUEUE_DESC_HIGH, 0);
        rig.w(R_QUEUE_DRIVER_LOW, RX_AVAIL as u32);
        rig.w(R_QUEUE_DRIVER_HIGH, 0);
        rig.w(R_QUEUE_DEVICE_LOW, RX_USED as u32);
        rig.w(R_QUEUE_DEVICE_HIGH, 0);
        rig.mem_w64(RX_DESC, RX_BUF);
        rig.mem_w32(RX_DESC + 8, 40); // deliberately small first window
        rig.mem_w16(RX_DESC + 12, VIRTQ_DESC_F_WRITE);
        rig.mem_w16(RX_DESC + 14, 0);
        rig.mem_w16(RX_AVAIL, 1);
        rig.mem_w16(RX_AVAIL + 4, 0);
        rig.mem_w16(RX_AVAIL + 2, 1);
        rig.w(R_QUEUE_READY, 1);
        rig.w(R_QUEUE_SEL, 1);
        rig.w(R_QUEUE_NUM, Q_SIZE);
        rig.w(R_QUEUE_DESC_LOW, TX_DESC as u32);
        rig.w(R_QUEUE_DESC_HIGH, 0);
        rig.w(R_QUEUE_DRIVER_LOW, TX_AVAIL as u32);
        rig.w(R_QUEUE_DRIVER_HIGH, 0);
        rig.w(R_QUEUE_DEVICE_LOW, TX_USED as u32);
        rig.w(R_QUEUE_DEVICE_HIGH, 0);
        rig.mem_w16(TX_AVAIL, 1);
        rig.w(R_QUEUE_READY, 1);
        rig.w(R_STATUS, 1 | 2 | 8 | 4);
        rig.mem.write_slice(&req, GuestAddress(TX_BUF)).unwrap();
        rig.mem_w64(TX_DESC, TX_BUF);
        rig.mem_w32(TX_DESC + 8, req.len() as u32);
        rig.mem_w16(TX_DESC + 12, 0);
        rig.mem_w16(TX_DESC + 14, 0);
        rig.mem_w16(TX_AVAIL + 4, 0);
        rig.mem_w16(TX_AVAIL + 2, 1);
        rig.w(R_QUEUE_NOTIFY, 1);

        // First completion: exactly the 40-byte window.
        assert_eq!(rig.mem_r16(RX_USED + 2), 1);
        assert_eq!(rig.mem_r32(RX_USED + 4 + 4), 40);
        let mut first = vec![0u8; 40];
        rig.mem.read_slice(&mut first, GuestAddress(RX_BUF)).unwrap();

        // Guest re-posts the remainder; the queue-0 kick drains the rest.
        rig.mem_w64(RX_DESC, RX_BUF);
        rig.mem_w32(RX_DESC + 8, (total - 40) as u32);
        rig.mem_w16(RX_DESC + 12, VIRTQ_DESC_F_WRITE);
        rig.mem_w16(RX_DESC + 14, 0);
        rig.mem_w16(RX_AVAIL + 4 + 2, 0); // ring[1] = desc 0
        rig.mem_w16(RX_AVAIL + 2, 2);
        rig.w(R_QUEUE_NOTIFY, 0);
        assert_eq!(rig.mem_r16(RX_USED + 2), 2);
        let entry1 = RX_USED + 4 + 8;
        assert_eq!(rig.mem_r32(entry1 + 4) as usize, total - 40);
        let mut rest = vec![0u8; total - 40];
        rig.mem.read_slice(&mut rest, GuestAddress(RX_BUF)).unwrap();

        let mut whole = first;
        whole.extend_from_slice(&rest);
        let frame_len = INFER_HEADER_LEN + body.len();
        let frame = decode(&whole[..frame_len]).expect("reassembled ECHO_RESP decodes");
        assert_eq!(frame.payload, &body[..]);
    }

    #[test]
    fn notify_before_driver_ok_is_inert() {
        let (mut rig, _sink) = Rig::new();
        // No handshake at all: a kick must not walk uninitialised rings.
        rig.w(R_QUEUE_NOTIFY, 1);
        rig.w(R_QUEUE_NOTIFY, 0);
        // Nothing published anywhere (ring addresses are 0 -> guest RAM byte 0
        // must stay untouched because the walk never ran).
        assert_eq!(rig.mem_r16(2), 0);
    }

    #[test]
    fn reset_clears_transport_but_not_the_peer_outbuf() {
        let (mut rig, _sink) = Rig::new();
        let body = [9u8; 4];
        let resp_len = INFER_HEADER_LEN + body.len() + INFER_KEY_REVEAL_LEN;
        // Run a full session, then check a reset clears registers.
        rig.chan_send_recv(&echo_req([3u8; 16], 3, &body), resp_len)
            .expect("session");
        rig.w(R_STATUS, 0);
        assert_eq!(rig.r(R_STATUS), 0);
        rig.w(R_QUEUE_SEL, 0);
        assert_eq!(rig.r(R_QUEUE_READY), 0, "reset must drop QueueReady");
        // And the device still serves a fresh session after the reset.
        rig.chan_send_recv(&echo_req([4u8; 16], 4, &body), resp_len)
            .expect("post-reset session");
    }
}
