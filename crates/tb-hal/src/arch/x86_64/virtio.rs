//! x86_64 **M19 "virtio OK"**: the kernel's FIRST real device I/O — a poll-only
//! modern virtio-mmio (Version=2) virtio-rng (DeviceID 4) round-trip. ALL of
//! M19's x86_64 `unsafe` (device-register MMIO, the DMA-ring volatile pokes,
//! the ordering fence) lives HERE; the kernel crate stays unsafe-free and only
//! branches on the returned [`crate::VirtioProof`] (KERNEL-FOUNDATION-SPEC §1).
//!
//! Design decisions (no open questions), each pinned to a verified fact:
//!  * TRANSPORT = **virtio-mmio, MODERN** (`Version` register == 2). DEVICE =
//!    **virtio-rng** (`DeviceID` == 4). The smallest device that proves a full
//!    descriptor/avail/used round-trip with NO config-space negotiation.
//!  * DISCOVERY = a hard-coded slot scan, mirroring M6/M8's "hard-code the QEMU
//!    map" discipline (NO x86 cmdline / ACPI parser). QEMU `microvm` lays its
//!    virtio-mmio transports at PA `0xFEB0_0000`, stride `0x200`, and plugs a
//!    `-device` into the HIGHEST free transport (it fills top-down: a single
//!    `virtio-rng-device` lands on bus .23 @ `0xFEB0_2E00`, VERIFIED via QEMU
//!    `info qtree`), so we scan [`N_SLOTS`] = 32 slots. Those span
//!    `0xFEB0_0000..+0x4000` in the 4th GiB ABOVE the boot identity map
//!    `[0, 1 GiB)`, so (exactly like the M8 LAPIC at `0xFEE0_0000`) they are
//!    UNMAPPED: we map [`N_WINDOW_PAGES`] = 4 contiguous UC device pages via
//!    `super::mmu::map_device_page` starting at [`VIRTIO_WINDOW_VA`] — in the
//!    SAME `PML4[3]` device window the LAPIC uses, the pages ABOVE it (PT indices
//!    1..4; the LAPIC owns PT index 0), reusing the existing PDPT/PD/PT chain.
//!    Each slot `i` is then at `VIRTIO_WINDOW_VA + i*0x200`. A probe reads
//!    `MagicValue` == 0x74726976 then `DeviceID` == 4.
//!  * IRQ = **POLL-ONLY** (the whole reason M19 is low-risk). `avail.flags` is
//!    set to `VIRTQ_AVAIL_F_NO_INTERRUPT` so the device never asserts its line,
//!    and after `QueueNotify` we SPIN reading `used.idx` under a fail-closed cap
//!    ([`POLL_CAP`], mirroring the M8 timer `CANARY_CAP`) — a dead device bails
//!    to [`crate::VirtioProof::Failed`], never hangs. ZERO interrupt-controller
//!    work: no IOAPIC, no IDT change, no IRQ-dispatch change.
//!  * DMA = ONE 4 KiB frame from [`crate::frame_alloc`] (identity-mapped low
//!    RAM, PA == VA — NEVER the higher-half heap, or the device would DMA into
//!    the void). It holds the 16-byte descriptor, the 6-byte avail ring, the
//!    12-byte used ring and a small entropy buffer at fixed offsets.
//!  * x86 is **TSO**: stores are not reordered with older stores and UC accesses
//!    are strongly ordered, so a single `compiler_fence` before publishing
//!    `avail.idx` and before the `QueueNotify` UC store is sufficient (no `mfence`
//!    needed — the aarch64 arm carries the real `dmb`/`dsb` barriers).
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

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{compiler_fence, Ordering};

// ---------------------------------------------------------------------------
// Per-arch hard-coded slot table (QEMU `microvm` virtio-mmio bus) + UC window.
// ---------------------------------------------------------------------------

/// QEMU `microvm` virtio-mmio transport #0 physical base (4th GiB, ABOVE the
/// boot identity map `[0, 1 GiB)` — so UNMAPPED until we map a UC window).
const SLOT_BASE_PA: u64 = 0xFEB0_0000;
/// Per-transport stride.
const SLOT_STRIDE: u64 = 0x200;
/// Transports to scan. `microvm` exposes ~24 and plugs a `-device` into the
/// HIGHEST free one (top-down: one `virtio-rng-device` -> bus .23 @ 0xFEB0_2E00);
/// 32 covers every slot with headroom (unpopulated/undecoded slots read open-bus
/// `0xFFFF_FFFF` != magic, so the scan simply skips them).
const N_SLOTS: u32 = 32;
/// Contiguous 4 KiB UC pages mapped over the bus: 32 * 0x200 = 0x4000 = 4 pages.
const N_WINDOW_PAGES: u64 = 4;
/// VA the FIRST UC device page is mapped at: `LAPIC_WINDOW_VA` (`0x180_0000_0000`,
/// `PML4[3]`) + 0x1000 — the device window ABOVE the M8 LAPIC (which owns PT
/// index 0); the 4 virtio pages take PT indices 1..4, reusing the existing
/// `PML4[3] -> PDPT -> PD -> PT` chain. Canonical, currently-unmapped, OUTSIDE
/// the identity map. Slot `i` is then at `VIRTIO_WINDOW_VA + i*0x200`.
const VIRTIO_WINDOW_VA: u64 = 0x0000_0180_0000_1000;

// ---------------------------------------------------------------------------
// virtio-mmio register map + bit constants (verified — see module header).
// ---------------------------------------------------------------------------

const VIRTIO_MAGIC: u32 = 0x7472_6976; // "virt", little-endian
const VIRTIO_VERSION_MODERN: u32 = 2;
const VIRTIO_DEV_ENTROPY: u32 = 4;
/// M20: virtio-blk DeviceID (the block device the `VirtioBlkStore` drives).
const VIRTIO_DEV_BLK: u32 = 2;

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

const VIRTQ_DESC_F_NEXT: u16 = 1; // M20: the descriptor chains to `next`.
const VIRTQ_DESC_F_WRITE: u16 = 2;
const VIRTQ_AVAIL_F_NO_INTERRUPT: u16 = 1;

/// Spec-minimum single-entry queue (QEMU accepts QueueNum == 1).
const Q_SIZE: u32 = 1;

/// M20: virtio-blk config-space base (capacity in 512-byte sectors @ +0x00).
const R_CONFIG: u64 = 0x100;

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
// "virtio OK" substring -> red).
const STAGE_MAP: u32 = 1; // could not map the UC device window (frame OOM)
const STAGE_FRAME: u32 = 2; // could not allocate the DMA frame
const STAGE_FEATURES: u32 = 3; // FEATURES_OK cleared / VERSION_1 not offered
const STAGE_QUEUE: u32 = 4; // QueueNumMax == 0 or QueueReady did not latch
const STAGE_POLL: u32 = 5; // used.idx never advanced before POLL_CAP
const STAGE_LEN: u32 = 6; // used.idx advanced but len == 0 / buffer not filled

// ---------------------------------------------------------------------------
// MMIO + DMA-RAM accessors (all the M19 x86_64 unsafe).
// ---------------------------------------------------------------------------

/// Read a 32-bit virtio-mmio register at `base + off` through the UC window.
#[inline]
fn reg_read(base: u64, off: u64) -> u32 {
    // SAFETY: `virtio_selftest` maps the N_WINDOW_PAGES UC device pages over
    // `SLOT_BASE_PA` BEFORE any access; `base` is `VIRTIO_WINDOW_VA + i*
    // SLOT_STRIDE` for a slot inside that window and `off` is a verified, 4-byte-
    // aligned register offset, so the pointer is valid + aligned. Volatile: MMIO.
    unsafe { read_volatile((base + off) as *const u32) }
}

/// Write a 32-bit virtio-mmio register at `base + off` through the UC window.
#[inline]
fn reg_write(base: u64, off: u64, v: u32) {
    // SAFETY: as `reg_read`; a UC MMIO store to a verified register offset.
    unsafe { write_volatile((base + off) as *mut u32, v) }
}

// The virtqueue + buffer live in ONE identity-mapped low-RAM frame (PA == VA),
// so the same address is a valid CPU pointer AND the physical address the device
// DMAs against. Each accessor is a single naturally-aligned volatile access at a
// fixed offset within that owned 4 KiB frame.
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
    // SAFETY: a 1-byte read at `buf + k` (k < BUF_LEN) in the owned DMA frame;
    // the device DMAs entropy bytes here, so volatile.
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

/// x86 is TSO + UC accesses are strongly ordered, so a compiler fence is the
/// only barrier the publish/notify ordering needs (the aarch64 arm uses real
/// `dmb`/`dsb`). One named helper keeps the two arms structurally identical.
#[inline]
fn dma_fence() {
    compiler_fence(Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// The public self-test: tb_hal::virtio_selftest() -> VirtioProof (arch arm).
// ---------------------------------------------------------------------------

/// Map the [`N_WINDOW_PAGES`] contiguous UC device pages over the `microvm`
/// virtio-mmio bus and return the VA base, or `None` on page-table-frame OOM.
/// Each page `j` maps `VIRTIO_WINDOW_VA + j*4K` -> `SLOT_BASE_PA + j*4K`, so a
/// slot VA `VIRTIO_WINDOW_VA + i*0x200` resolves to PA `SLOT_BASE_PA + i*0x200`.
/// Reuses the M8 `PML4[3]` chain (the pages land at PT indices 1..N_WINDOW_PAGES).
fn map_window() -> Option<u64> {
    let mut j: u64 = 0;
    while j < N_WINDOW_PAGES {
        let off = j * 0x1000;
        if !super::mmu::map_device_page(VIRTIO_WINDOW_VA + off, SLOT_BASE_PA + off) {
            return None;
        }
        j += 1;
    }
    Some(VIRTIO_WINDOW_VA)
}

/// Run the full M19 poll-based virtio-rng round-trip and report the outcome.
///
/// `Absent` (no DeviceID==4 in any slot) and `LegacyUnsupported` (found but
/// `Version` != 2) are GRACEFUL skips; `Proven{slot,device_id,len}` is the full
/// handshake + one write-only descriptor + polled used-ring completion with a
/// non-trivially filled entropy buffer; `Failed{stage}` is fail-closed red.
///
/// Under `tb-vmm` (vmm-boot, NO `-device`) the window maps over `0xFEB0_0000`
/// and the open-bus read returns `0xFFFF_FFFF` != magic -> `Absent` -> green
/// skip, so vmm-boot stays green with no tb-vmm virtio backend.
pub fn virtio_selftest() -> crate::VirtioProof {
    use crate::VirtioProof;

    // 1. Map the UC device window (arch-specific; aarch64 needs none).
    let base = match map_window() {
        Some(b) => b,
        None => return VirtioProof::Failed { stage: STAGE_MAP },
    };

    // 2. Scan the hard-coded slot table for a MODERN virtio-rng (DeviceID == 4,
    //    Version == 2). Remember a legacy (Version != 2) entropy device so an
    //    honest "legacy, skipped" is reported only if NO modern one is found.
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

    // 3. One identity-mapped DMA frame for the whole virtqueue + entropy buffer.
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

    // 4. Modern handshake: reset -> ACKNOWLEDGE -> DRIVER -> feature negotiate.
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

    // 5. Set up the single requestq (queue 0).
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
    // Used ring starts empty (idx 0) — already zeroed above; we polled against 0.

    reg_write(dev, R_QUEUE_READY, 1);
    if reg_read(dev, R_QUEUE_READY) != 1 {
        return fail(dev, frame, STAGE_QUEUE);
    }
    reg_write(dev, R_STATUS, S_ACKNOWLEDGE | S_DRIVER | S_FEATURES_OK | S_DRIVER_OK);

    // 6. Publish avail.idx (after a fence so the ring writes are visible), then
    //    notify (after a fence so the publish precedes the UC notify store).
    dma_fence();
    ram_w16(avail + 2, 1); // avail.idx = 1
    dma_fence();
    reg_write(dev, R_QUEUE_NOTIFY, 0);

    // 7. POLL used.idx until it advances past 0, fail-closed at POLL_CAP.
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
    dma_fence(); // order the data loads after observing the new used.idx

    // 8. Validate the completion: used.ring[0].len > 0 AND the buffer was
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

/// Reclaim the DMA frame on a fail-closed exit, returning a `Failed{stage}`
/// proof. Setting the `FAILED` status bit (virtio §2.1.2, OR-ed onto the
/// ACKNOWLEDGE|DRIVER bits already latched) tells the device the driver gave up,
/// so it stops processing the queue BEFORE `frame` returns to the free list —
/// no leak, no dangling device reference. `dev` is the live device-window base.
#[inline]
fn fail(dev: u64, frame: u64, stage: u32) -> crate::VirtioProof {
    reg_write(dev, R_STATUS, S_ACKNOWLEDGE | S_DRIVER | S_FAILED);
    crate::frame_free(frame);
    crate::VirtioProof::Failed { stage }
}

// ===========================================================================
// M20: the poll-only modern virtio-blk (DeviceID 2) driver. BYTE-SYMMETRIC with
// the aarch64 arm: same 3-descriptor request chain, same in-frame layout, same
// `tb_encode::blkfmt` codecs. The ONLY x86 delta is `dma_fence` (TSO) where
// aarch64 uses dmb/dsb, and the UC device-window `map_window()` (aarch64 needs
// none). The safe `VirtioBlkStore` layer calls blk_probe/blk_read/blk_write/
// blk_flush. The `microvm` machine exposes the virtio-mmio bus virtio-blk-device
// attaches to (NOT virtio-blk-pci -- microvm has no PCI by default).
// ===========================================================================

/// One additional byte accessor (the status byte the device writes; volatile).
#[inline]
fn ram_w8(pa: u64, v: u8) {
    // SAFETY: `pa` is a 1-byte offset within the owned DMA frame.
    unsafe { write_volatile(pa as *mut u8, v) }
}

// In-frame layout for the blk request (Q_SIZE=4 desc table is 64 bytes).
const BLK_DESC_OFF: u64 = 0x000; // 4 * 16 = 64 bytes
const BLK_AVAIL_OFF: u64 = 0x040; // flags@+0, idx@+2, ring[4]@+4
const BLK_USED_OFF: u64 = 0x080; // flags@+0, idx@+2, ring[4]{id,len}
const BLK_HDR_OFF: u64 = 0x100; // 16-byte request header (RO)
const BLK_STATUS_OFF: u64 = 0x110; // 1-byte status (WO)
const BLK_DATA_OFF: u64 = 0x200; // 512-byte data sector
const BLK_Q_SIZE: u32 = 4;

/// Probe the virtio-mmio bus for a MODERN (Version==2) virtio-blk (DeviceID==2).
/// Maps the UC device window first (it shares the M19 PML4[3] chain). Returns
/// `Some((slot, capacity_sectors))` if found + modern, `None` if absent, legacy,
/// or the window could not be mapped.
pub fn blk_probe() -> Option<(u32, u64)> {
    let base = map_window()?;
    let mut i: u32 = 0;
    while i < N_SLOTS {
        let s = base + (i as u64) * SLOT_STRIDE;
        if reg_read(s, R_MAGIC) == VIRTIO_MAGIC && reg_read(s, R_DEVICE_ID) == VIRTIO_DEV_BLK {
            if reg_read(s, R_VERSION) != VIRTIO_VERSION_MODERN {
                return None; // legacy
            }
            let cap_lo = reg_read(s, R_CONFIG) as u64;
            let cap_hi = reg_read(s, R_CONFIG + 4) as u64;
            return Some((i, (cap_hi << 32) | cap_lo));
        }
        i += 1;
    }
    None
}

/// Whether the bus carries a LEGACY blk device but no modern one (Absent vs
/// LegacyUnsupported disambiguation for the safe layer).
pub fn blk_saw_legacy() -> bool {
    let base = match map_window() {
        Some(b) => b,
        None => return false,
    };
    let mut i: u32 = 0;
    let mut legacy = false;
    while i < N_SLOTS {
        let s = base + (i as u64) * SLOT_STRIDE;
        if reg_read(s, R_MAGIC) == VIRTIO_MAGIC && reg_read(s, R_DEVICE_ID) == VIRTIO_DEV_BLK {
            if reg_read(s, R_VERSION) == VIRTIO_VERSION_MODERN {
                return false;
            }
            legacy = true;
        }
        i += 1;
    }
    legacy
}

/// Run ONE virtio-blk request. See the aarch64 twin for the descriptor-chain
/// contract; this arm is byte-identical save the `dma_fence` (TSO) barriers.
fn blk_request(slot: u32, req_type: u32, sector: u64, data: Option<&mut [u8; 512]>) -> bool {
    use tb_encode::blkfmt;
    let base = match map_window() {
        Some(b) => b,
        None => return false,
    };
    let dev = base + (slot as u64) * SLOT_STRIDE;
    let frame = match crate::frame_alloc() {
        Some(f) => f,
        None => return false,
    };
    let mut z: u64 = 0;
    while z < 4096 {
        ram_w64(frame + z, 0);
        z += 8;
    }
    let desc = frame + BLK_DESC_OFF;
    let avail = frame + BLK_AVAIL_OFF;
    let used = frame + BLK_USED_OFF;
    let hdr = frame + BLK_HDR_OFF;
    let status = frame + BLK_STATUS_OFF;
    let dbuf = frame + BLK_DATA_OFF;

    let hbytes = blkfmt::req_header_encode(req_type, sector);
    let mut k = 0u64;
    while k < blkfmt::REQ_HEADER_LEN as u64 {
        ram_w8(hdr + k, hbytes[k as usize]);
        k += 1;
    }
    let is_flush = req_type == blkfmt::T_FLUSH;
    let is_in = req_type == blkfmt::T_IN;
    if req_type == blkfmt::T_OUT {
        if let Some(ref d) = data {
            let mut i = 0u64;
            while i < 512 {
                ram_w8(dbuf + i, d[i as usize]);
                i += 1;
            }
        }
    }
    ram_w8(status, 0xFF);

    reg_write(dev, R_STATUS, 0);
    reg_write(dev, R_STATUS, S_ACKNOWLEDGE);
    reg_write(dev, R_STATUS, S_ACKNOWLEDGE | S_DRIVER);
    reg_write(dev, R_DEVICE_FEATURES_SEL, 1);
    let df_hi = reg_read(dev, R_DEVICE_FEATURES);
    if df_hi & VIRTIO_F_VERSION_1_HI == 0 {
        reg_write(dev, R_STATUS, S_ACKNOWLEDGE | S_DRIVER | S_FAILED);
        crate::frame_free(frame);
        return false;
    }
    reg_write(dev, R_DRIVER_FEATURES_SEL, 0);
    reg_write(dev, R_DRIVER_FEATURES, 0);
    reg_write(dev, R_DRIVER_FEATURES_SEL, 1);
    reg_write(dev, R_DRIVER_FEATURES, VIRTIO_F_VERSION_1_HI);
    reg_write(dev, R_STATUS, S_ACKNOWLEDGE | S_DRIVER | S_FEATURES_OK);
    if reg_read(dev, R_STATUS) & S_FEATURES_OK == 0 {
        reg_write(dev, R_STATUS, S_ACKNOWLEDGE | S_DRIVER | S_FAILED);
        crate::frame_free(frame);
        return false;
    }

    reg_write(dev, R_QUEUE_SEL, 0);
    if reg_read(dev, R_QUEUE_NUM_MAX) == 0 {
        reg_write(dev, R_STATUS, S_ACKNOWLEDGE | S_DRIVER | S_FAILED);
        crate::frame_free(frame);
        return false;
    }
    reg_write(dev, R_QUEUE_NUM, BLK_Q_SIZE);
    reg_write(dev, R_QUEUE_DESC_LOW, desc as u32);
    reg_write(dev, R_QUEUE_DESC_HIGH, (desc >> 32) as u32);
    reg_write(dev, R_QUEUE_DRIVER_LOW, avail as u32);
    reg_write(dev, R_QUEUE_DRIVER_HIGH, (avail >> 32) as u32);
    reg_write(dev, R_QUEUE_DEVICE_LOW, used as u32);
    reg_write(dev, R_QUEUE_DEVICE_HIGH, (used >> 32) as u32);

    ram_w64(desc, hdr);
    ram_w32(desc + 8, blkfmt::REQ_HEADER_LEN as u32);
    if is_flush {
        ram_w16(desc + 12, VIRTQ_DESC_F_NEXT);
        ram_w16(desc + 14, 1);
        ram_w64(desc + 16, status);
        ram_w32(desc + 16 + 8, 1);
        ram_w16(desc + 16 + 12, VIRTQ_DESC_F_WRITE);
        ram_w16(desc + 16 + 14, 0);
    } else {
        ram_w16(desc + 12, VIRTQ_DESC_F_NEXT);
        ram_w16(desc + 14, 1);
        ram_w64(desc + 16, dbuf);
        ram_w32(desc + 16 + 8, 512);
        let data_flags = if is_in {
            VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT
        } else {
            VIRTQ_DESC_F_NEXT
        };
        ram_w16(desc + 16 + 12, data_flags);
        ram_w16(desc + 16 + 14, 2);
        ram_w64(desc + 32, status);
        ram_w32(desc + 32 + 8, 1);
        ram_w16(desc + 32 + 12, VIRTQ_DESC_F_WRITE);
        ram_w16(desc + 32 + 14, 0);
    }

    ram_w16(avail, VIRTQ_AVAIL_F_NO_INTERRUPT);
    ram_w16(avail + 4, 0);

    reg_write(dev, R_QUEUE_READY, 1);
    if reg_read(dev, R_QUEUE_READY) != 1 {
        reg_write(dev, R_STATUS, S_ACKNOWLEDGE | S_DRIVER | S_FAILED);
        crate::frame_free(frame);
        return false;
    }
    reg_write(dev, R_STATUS, S_ACKNOWLEDGE | S_DRIVER | S_FEATURES_OK | S_DRIVER_OK);

    dma_fence();
    ram_w16(avail + 2, 1);
    dma_fence();
    reg_write(dev, R_QUEUE_NOTIFY, 0);

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
        reg_write(dev, R_STATUS, S_ACKNOWLEDGE | S_DRIVER | S_FAILED);
        crate::frame_free(frame);
        return false;
    }
    dma_fence();

    let st = blkfmt::status_decode(ram_r8(status));
    let ok = st == blkfmt::S_OK;
    if ok && is_in {
        if let Some(d) = data {
            let mut i = 0u64;
            while i < 512 {
                d[i as usize] = ram_r8(dbuf + i);
                i += 1;
            }
        }
    }

    reg_write(dev, R_STATUS, 0);
    crate::frame_free(frame);
    ok
}

/// Read 512 bytes from `sector` into `buf`. Returns `true` on success.
pub fn blk_read(slot: u32, sector: u64, buf: &mut [u8; 512]) -> bool {
    blk_request(slot, tb_encode::blkfmt::T_IN, sector, Some(buf))
}

/// Write 512 bytes from `buf` to `sector`. Returns `true` on success.
pub fn blk_write(slot: u32, sector: u64, buf: &[u8; 512]) -> bool {
    let mut tmp = *buf;
    blk_request(slot, tb_encode::blkfmt::T_OUT, sector, Some(&mut tmp))
}

/// Issue a VIRTIO_BLK_T_FLUSH durability barrier. Returns `true` on success.
pub fn blk_flush(slot: u32) -> bool {
    blk_request(slot, tb_encode::blkfmt::T_FLUSH, 0, None)
}
