//! aarch64 **M19 "virtio OK"**: the kernel's FIRST real device I/O — a poll-only
//! modern virtio-mmio (Version=2) virtio-rng (DeviceID 4) round-trip. ALL of
//! M19's aarch64 `unsafe` (device-register MMIO, the DMA-ring volatile pokes,
//! the `dmb`/`dsb` ordering barriers) lives HERE; the kernel crate stays
//! unsafe-free and only branches on the returned [`crate::VirtioProof`]
//! (KERNEL-FOUNDATION-SPEC §1).
//!
//! Design decisions (no open questions), each pinned to a verified fact:
//!  * TRANSPORT = **virtio-mmio, MODERN** (`Version` register == 2). DEVICE =
//!    **virtio-rng** (`DeviceID` == 4). The smallest device that proves a full
//!    descriptor/avail/used round-trip with NO config-space negotiation.
//!  * DISCOVERY = a hard-coded slot scan, mirroring M6/M8's "hard-code the QEMU
//!    map" discipline (NO FDT walker). QEMU `virt` lays 32 virtio-mmio
//!    transports at PA `0x0A00_0000`, stride `0x200`. That whole window sits
//!    INSIDE the `L1[0]` Device-nGnRnE identity gigabyte `mmu_init` already
//!    mapped, so — unlike the x86 arm — NO new mapping is needed: each slot `i`
//!    is accessed at its physical address `0x0A00_0000 + i*0x200`. A probe reads
//!    `MagicValue` == 0x74726976 then `DeviceID` == 4.
//!  * IRQ = **POLL-ONLY** (the whole reason M19 is low-risk). `avail.flags` is
//!    set to `VIRTQ_AVAIL_F_NO_INTERRUPT` so the device never asserts its SPI,
//!    and after `QueueNotify` we SPIN reading `used.idx` under a fail-closed cap
//!    ([`POLL_CAP`], mirroring the M8 timer `CANARY_CAP`) — a dead device bails
//!    to [`crate::VirtioProof::Failed`], never hangs. ZERO interrupt-controller
//!    work: no GIC SPI enable, no IRQ-dispatch change.
//!  * DMA = ONE 4 KiB frame from [`crate::frame_alloc`] (identity-mapped Normal
//!    WB RAM, PA == VA — NEVER the higher-half heap, or the device would DMA
//!    into the void). It holds the 16-byte descriptor, the 6-byte avail ring,
//!    the 12-byte used ring and a small entropy buffer at fixed offsets.
//!  * aarch64 is **WEAKLY ORDERED** — the #1 hang/garbage risk. We emit a real
//!    `dmb ishst` BEFORE publishing `avail.idx` (so the ring stores precede the
//!    publish the device reads), a `dsb` BEFORE the `QueueNotify` Device store
//!    (so every ring write has completed to the point of coherency the device
//!    DMAs from), and a `dmb ishld` after observing the new `used.idx` (so the
//!    `len`/buffer loads are ordered AFTER the index load). A missing barrier
//!    yields a stale ring -> the bounded poll turns it into a fail-closed
//!    `Failed` (red), never a hang.
//!
//! Verified register/ABI facts (virtio v1.2 §4.2 MMIO + §2.7 split virtqueue):
//!  * MMIO regs: Magic@0x00, Version@0x04, DeviceID@0x08, DeviceFeatures@0x10,
//!    DeviceFeaturesSel@0x14, DriverFeatures@0x20, DriverFeaturesSel@0x24,
//!    QueueSel@0x30, QueueNumMax@0x34, QueueNum@0x38, QueueReady@0x44,
//!    QueueNotify@0x50, Status@0x70, QueueDescLow/High@0x80/0x84,
//!    QueueDriverLow/High@0x90/0x94 (avail), QueueDeviceLow/High@0xA0/0xA4 (used).
//!  * Status bits: ACKNOWLEDGE=1, DRIVER=2, DRIVER_OK=4, FEATURES_OK=8, FAILED=128.
//!  * `VIRTIO_F_VERSION_1` is feature bit 32 -> DeviceFeaturesSel=1, bit 0.
//!  * Split-queue desc = {le64 addr, le32 len, le16 flags, le16 next}; avail =
//!    {le16 flags, le16 idx, le16 ring[]}; used = {le16 flags, le16 idx,
//!    {le32 id, le32 len} ring[]}. `VIRTQ_DESC_F_WRITE=2` (device writes the
//!    buffer); `VIRTQ_AVAIL_F_NO_INTERRUPT=1`.

use core::arch::asm;
use core::ptr::{read_volatile, write_volatile};

// ---------------------------------------------------------------------------
// Per-arch hard-coded slot table (QEMU `virt` virtio-mmio bus). The whole
// window is already Device-nGnRnE identity-mapped (L1[0]), so NO new mapping.
// ---------------------------------------------------------------------------

/// QEMU `virt` virtio-mmio transport #0 physical base (inside the L1[0]
/// Device-nGnRnE identity gigabyte — accessed directly at its PA).
const SLOT_BASE: u64 = 0x0A00_0000;
/// Per-transport stride.
const SLOT_STRIDE: u64 = 0x200;
/// Number of virtio-mmio transports `virt` exposes.
const N_SLOTS: u32 = 32;

// ---------------------------------------------------------------------------
// virtio-mmio register map + bit constants (verified — see module header).
// ---------------------------------------------------------------------------

const VIRTIO_MAGIC: u32 = 0x7472_6976; // "virt", little-endian
const VIRTIO_VERSION_MODERN: u32 = 2;
const VIRTIO_DEV_ENTROPY: u32 = 4;

const R_MAGIC: u64 = 0x000;
const R_VERSION: u64 = 0x004;
const R_DEVICE_ID: u64 = 0x008;
const R_DEVICE_FEATURES: u64 = 0x010;
const R_DEVICE_FEATURES_SEL: u64 = 0x014;
const R_DRIVER_FEATURES: u64 = 0x020;
const R_DRIVER_FEATURES_SEL: u64 = 0x024;
const R_QUEUE_SEL: u64 = 0x030;
const R_QUEUE_NUM_MAX: u64 = 0x034;
const R_QUEUE_NUM: u64 = 0x038;
const R_QUEUE_READY: u64 = 0x044;
const R_QUEUE_NOTIFY: u64 = 0x050;
const R_STATUS: u64 = 0x070;
const R_QUEUE_DESC_LOW: u64 = 0x080;
const R_QUEUE_DESC_HIGH: u64 = 0x084;
const R_QUEUE_DRIVER_LOW: u64 = 0x090; // avail ring
const R_QUEUE_DRIVER_HIGH: u64 = 0x094;
const R_QUEUE_DEVICE_LOW: u64 = 0x0A0; // used ring
const R_QUEUE_DEVICE_HIGH: u64 = 0x0A4;

const S_ACKNOWLEDGE: u32 = 1;
const S_DRIVER: u32 = 2;
const S_DRIVER_OK: u32 = 4;
const S_FEATURES_OK: u32 = 8;
const S_FAILED: u32 = 128;

/// `VIRTIO_F_VERSION_1` (bit 32) as it appears in the HIGH feature dword (sel 1).
const VIRTIO_F_VERSION_1_HI: u32 = 1 << 0;

const VIRTQ_DESC_F_WRITE: u16 = 2;
const VIRTQ_AVAIL_F_NO_INTERRUPT: u16 = 1;

/// Spec-minimum single-entry queue (QEMU accepts QueueNum == 1).
const Q_SIZE: u32 = 1;

// In-frame layout (one 4 KiB DMA frame; all offsets meet the split-queue
// alignment: desc 16, avail 2, used 4):
const DESC_OFF: u64 = 0x000; // 16 bytes
const AVAIL_OFF: u64 = 0x010; // flags@+0, idx@+2, ring[0]@+4 (6 bytes)
const USED_OFF: u64 = 0x020; // flags@+0, idx@+2, ring[0]{id@+4,len@+8} (12 bytes)
const BUF_OFF: u64 = 0x200; // entropy destination buffer
const BUF_LEN: u32 = 64;

/// Fail-closed `used.idx` poll bound: a dead device bails here instead of
/// hanging (mirrors the M8 timer `CANARY_CAP`).
const POLL_CAP: u64 = 100_000_000;

// Failure stages (rendered as `M19: virtio FAIL stage=<n>` by the kernel; no
// "virtio OK" substring -> red). Stage 1 (MAP) is x86-only (the UC-window map);
// aarch64 needs no mapping, so its stages start at 2 to stay numbered in lockstep
// with the x86 arm.
const STAGE_FRAME: u32 = 2; // could not allocate the DMA frame
const STAGE_FEATURES: u32 = 3; // FEATURES_OK cleared / VERSION_1 not offered
const STAGE_QUEUE: u32 = 4; // QueueNumMax == 0 or QueueReady did not latch
const STAGE_POLL: u32 = 5; // used.idx never advanced before POLL_CAP
const STAGE_LEN: u32 = 6; // used.idx advanced but len == 0 / buffer not filled

// ---------------------------------------------------------------------------
// MMIO + DMA-RAM accessors (all the M19 aarch64 unsafe).
// ---------------------------------------------------------------------------

/// Read a 32-bit virtio-mmio register at `base + off`.
#[inline]
fn reg_read(base: u64, off: u64) -> u32 {
    // SAFETY: `base` is `SLOT_BASE + i*SLOT_STRIDE` — inside the L1[0]
    // Device-nGnRnE identity gigabyte `mmu_init` mapped — and `off` is a
    // verified, 4-byte-aligned register offset, so the pointer is valid +
    // aligned and addresses the transport. Volatile: an MMIO load.
    unsafe { read_volatile((base + off) as *const u32) }
}

/// Write a 32-bit virtio-mmio register at `base + off`.
#[inline]
fn reg_write(base: u64, off: u64, v: u32) {
    // SAFETY: as `reg_read`; a Device-nGnRnE MMIO store to a verified offset.
    unsafe { write_volatile((base + off) as *mut u32, v) }
}

// The virtqueue + buffer live in ONE identity-mapped Normal-WB RAM frame
// (PA == VA), so the same address is a valid CPU pointer AND the physical
// address the device DMAs against. Each accessor is a single naturally-aligned
// volatile access at a fixed offset within that owned 4 KiB frame.
#[inline]
fn ram_w16(pa: u64, v: u16) {
    // SAFETY: `pa` is a 2-byte-aligned offset within the owned DMA frame.
    unsafe { write_volatile(pa as *mut u16, v) }
}
#[inline]
fn ram_w32(pa: u64, v: u32) {
    // SAFETY: `pa` is a 4-byte-aligned offset within the owned DMA frame.
    unsafe { write_volatile(pa as *mut u32, v) }
}
#[inline]
fn ram_w64(pa: u64, v: u64) {
    // SAFETY: `pa` is an 8-byte-aligned offset within the owned DMA frame.
    unsafe { write_volatile(pa as *mut u64, v) }
}
#[inline]
fn ram_r8(pa: u64) -> u8 {
    // SAFETY: as `ram_w8`; the device DMAs entropy bytes here, so volatile.
    unsafe { read_volatile(pa as *const u8) }
}
#[inline]
fn ram_r16(pa: u64) -> u16 {
    // SAFETY: 2-byte-aligned offset in the owned DMA frame; `used.idx` is written
    // by the device, so volatile (re-read each poll iteration).
    unsafe { read_volatile(pa as *const u16) }
}
#[inline]
fn ram_r32(pa: u64) -> u32 {
    // SAFETY: 4-byte-aligned offset in the owned DMA frame (`used.ring[0].len`).
    unsafe { read_volatile(pa as *const u32) }
}

// ---------------------------------------------------------------------------
// Weak-memory barriers (the aarch64-specific part of M19). All ordered memory
// is touched via `read_volatile`/`write_volatile` (never reordered with these
// non-pure asm blocks at compile time), so these `dmb`/`dsb` supply the HARDWARE
// ordering the device requires. `nomem` matches `timer.rs`'s barrier style.
// ---------------------------------------------------------------------------

/// `dmb ishst` — order prior ring STORES before the `avail.idx` publish store.
#[inline]
fn dmb_ishst() {
    // SAFETY: an unprivileged store-store barrier; no memory/stack effect, NZCV
    // preserved. Orders the descriptor/avail-ring stores before `avail.idx`.
    unsafe {
        asm!("dmb ishst", options(nomem, nostack, preserves_flags));
    }
}

/// `dsb sy` — ensure every prior memory access has completed (visible to the
/// device at the point of coherency) before the `QueueNotify` Device store.
#[inline]
fn dsb_sy() {
    // SAFETY: an unprivileged completion barrier; no memory/stack effect, NZCV
    // preserved. Pushes the published ring out before the device is kicked.
    unsafe {
        asm!("dsb sy", options(nomem, nostack, preserves_flags));
    }
}

/// `dmb ishld` — order the `used.idx` LOAD before the subsequent `len`/buffer
/// loads, so observing the new index implies the device's data writes are seen.
#[inline]
fn dmb_ishld() {
    // SAFETY: an unprivileged load-load barrier; no memory/stack effect, NZCV
    // preserved. The acquire half of the used-ring handshake.
    unsafe {
        asm!("dmb ishld", options(nomem, nostack, preserves_flags));
    }
}

// ---------------------------------------------------------------------------
// The public self-test: tb_hal::virtio_selftest() -> VirtioProof (arch arm).
// ---------------------------------------------------------------------------

/// Run the full M19 poll-based virtio-rng round-trip and report the outcome.
///
/// `Absent` (no DeviceID==4 in any slot) and `LegacyUnsupported` (found but
/// `Version` != 2) are GRACEFUL skips; `Proven{slot,device_id,len}` is the full
/// handshake + one write-only descriptor + polled used-ring completion with a
/// non-trivially filled entropy buffer; `Failed{stage}` is fail-closed red.
pub fn virtio_selftest() -> crate::VirtioProof {
    use crate::VirtioProof;

    // 1. No mapping needed (the bus is in the Device identity gigabyte). Scan the
    //    hard-coded slot table for a MODERN virtio-rng (DeviceID == 4,
    //    Version == 2). Remember a legacy (Version != 2) entropy device so an
    //    honest "legacy, skipped" is reported only if NO modern one is found.
    let base = SLOT_BASE;
    let mut found: Option<u32> = None;
    let mut saw_legacy = false;
    let mut i: u32 = 0;
    while i < N_SLOTS {
        let s = base + (i as u64) * SLOT_STRIDE;
        if reg_read(s, R_MAGIC) == VIRTIO_MAGIC && reg_read(s, R_DEVICE_ID) == VIRTIO_DEV_ENTROPY {
            if reg_read(s, R_VERSION) == VIRTIO_VERSION_MODERN {
                found = Some(i);
                break;
            }
            saw_legacy = true;
        }
        i += 1;
    }
    let slot = match found {
        Some(s) => s,
        None => {
            return if saw_legacy {
                VirtioProof::LegacyUnsupported
            } else {
                VirtioProof::Absent
            };
        }
    };
    let dev = base + (slot as u64) * SLOT_STRIDE;

    // 2. One identity-mapped DMA frame for the whole virtqueue + entropy buffer.
    let frame = match crate::frame_alloc() {
        Some(f) => f,
        None => return VirtioProof::Failed { stage: STAGE_FRAME },
    };
    // Clean slate: zero the frame (pmm frames are not guaranteed zeroed) so the
    // "buffer non-trivially filled" check below is meaningful.
    let mut z: u64 = 0;
    while z < 4096 {
        ram_w64(frame + z, 0);
        z += 8;
    }
    let desc = frame + DESC_OFF;
    let avail = frame + AVAIL_OFF;
    let used = frame + USED_OFF;
    let buf = frame + BUF_OFF;

    // 3. Modern handshake: reset -> ACKNOWLEDGE -> DRIVER -> feature negotiate.
    reg_write(dev, R_STATUS, 0); // reset
    reg_write(dev, R_STATUS, S_ACKNOWLEDGE);
    reg_write(dev, R_STATUS, S_ACKNOWLEDGE | S_DRIVER);

    // Read both device-feature dwords; negotiate ONLY VIRTIO_F_VERSION_1.
    reg_write(dev, R_DEVICE_FEATURES_SEL, 0);
    let _df_lo = reg_read(dev, R_DEVICE_FEATURES);
    reg_write(dev, R_DEVICE_FEATURES_SEL, 1);
    let df_hi = reg_read(dev, R_DEVICE_FEATURES);
    if df_hi & VIRTIO_F_VERSION_1_HI == 0 {
        // A modern (Version==2) device MUST offer VERSION_1; absence is a fault.
        return fail(dev, frame, STAGE_FEATURES);
    }
    reg_write(dev, R_DRIVER_FEATURES_SEL, 0);
    reg_write(dev, R_DRIVER_FEATURES, 0);
    reg_write(dev, R_DRIVER_FEATURES_SEL, 1);
    reg_write(dev, R_DRIVER_FEATURES, VIRTIO_F_VERSION_1_HI);

    reg_write(dev, R_STATUS, S_ACKNOWLEDGE | S_DRIVER | S_FEATURES_OK);
    if reg_read(dev, R_STATUS) & S_FEATURES_OK == 0 {
        // Device cleared FEATURES_OK -> it rejected our feature set.
        return fail(dev, frame, STAGE_FEATURES);
    }

    // 4. Set up the single requestq (queue 0).
    reg_write(dev, R_QUEUE_SEL, 0);
    if reg_read(dev, R_QUEUE_NUM_MAX) == 0 {
        return fail(dev, frame, STAGE_QUEUE);
    }
    reg_write(dev, R_QUEUE_NUM, Q_SIZE);
    reg_write(dev, R_QUEUE_DESC_LOW, desc as u32);
    reg_write(dev, R_QUEUE_DESC_HIGH, (desc >> 32) as u32);
    reg_write(dev, R_QUEUE_DRIVER_LOW, avail as u32);
    reg_write(dev, R_QUEUE_DRIVER_HIGH, (avail >> 32) as u32);
    reg_write(dev, R_QUEUE_DEVICE_LOW, used as u32);
    reg_write(dev, R_QUEUE_DEVICE_HIGH, (used >> 32) as u32);

    // Descriptor 0: a single WRITE-ONLY buffer the device fills with entropy.
    ram_w64(desc, buf); // addr
    ram_w32(desc + 8, BUF_LEN); // len
    ram_w16(desc + 12, VIRTQ_DESC_F_WRITE); // flags
    ram_w16(desc + 14, 0); // next
    // Avail ring: suppress the device's used-notification interrupt (poll-only),
    // descriptor 0 in ring[0]; idx published AFTER the barrier below.
    ram_w16(avail, VIRTQ_AVAIL_F_NO_INTERRUPT); // flags
    ram_w16(avail + 4, 0); // ring[0] = desc 0
    // Used ring starts empty (idx 0) — already zeroed above; we poll against 0.

    reg_write(dev, R_QUEUE_READY, 1);
    if reg_read(dev, R_QUEUE_READY) != 1 {
        return fail(dev, frame, STAGE_QUEUE);
    }
    reg_write(dev, R_STATUS, S_ACKNOWLEDGE | S_DRIVER | S_FEATURES_OK | S_DRIVER_OK);

    // 5. Publish avail.idx after a store barrier (ring stores precede the
    //    publish), then a completion barrier before the QueueNotify Device store
    //    (the whole ring is visible to the device before it is kicked).
    dmb_ishst();
    ram_w16(avail + 2, 1); // avail.idx = 1
    dsb_sy();
    reg_write(dev, R_QUEUE_NOTIFY, 0);

    // 6. POLL used.idx until it advances past 0, fail-closed at POLL_CAP.
    let mut spins: u64 = 0;
    let mut used_idx: u16 = 0;
    while spins < POLL_CAP {
        used_idx = ram_r16(used + 2);
        if used_idx != 0 {
            break;
        }
        spins += 1;
    }
    if used_idx == 0 {
        return fail(dev, frame, STAGE_POLL);
    }
    dmb_ishld(); // order the data loads after observing the new used.idx

    // 7. Validate the completion: used.ring[0].len > 0 AND the buffer was
    //    non-trivially filled (the zeroed buffer now carries a nonzero byte).
    let len = ram_r32(used + 8); // ring[0].len
    if len == 0 {
        return fail(dev, frame, STAGE_LEN);
    }
    let check = if len < BUF_LEN { len } else { BUF_LEN };
    let mut nonzero = false;
    let mut k: u32 = 0;
    while k < check {
        if ram_r8(buf + k as u64) != 0 {
            nonzero = true;
            break;
        }
        k += 1;
    }
    if !nonzero {
        return fail(dev, frame, STAGE_LEN);
    }

    // Success: reset the device (it detaches the queue and stops DMA) before we
    // hand the frame back, then free it — no leak, no dangling device reference.
    reg_write(dev, R_STATUS, 0);
    crate::frame_free(frame);
    VirtioProof::Proven {
        slot,
        device_id: VIRTIO_DEV_ENTROPY,
        len,
    }
}

/// Reset the device + reclaim the DMA frame on a fail-closed exit, returning a
/// `Failed{stage}` proof. Setting the `FAILED` status bit (virtio §2.1.2, OR-ed
/// onto the ACKNOWLEDGE|DRIVER bits already latched) tells the device the driver
/// gave up, so it stops processing the queue BEFORE `frame` returns to the free
/// list — no leak, no dangling device reference. `dev` is the live transport base.
#[inline]
fn fail(dev: u64, frame: u64, stage: u32) -> crate::VirtioProof {
    reg_write(dev, R_STATUS, S_ACKNOWLEDGE | S_DRIVER | S_FAILED);
    crate::frame_free(frame);
    crate::VirtioProof::Failed { stage }
}
