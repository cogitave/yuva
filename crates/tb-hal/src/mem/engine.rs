//! The memory SUBSTRATE ENGINE -- the durable-storage half of `mem` (M13/M20).
//!
//! This is the substrate-side half of the engine/organ factorization
//! (docs/proposals/boot-profiles.md §3.4): the tier-tagged durability seam
//! ([`BackingStore`]), the RAM-backed default ([`RamStore`]), and the M20
//! durable virtio-blk store ([`VirtioBlkStore`]). It depends on NOTHING in the
//! agent organ ([`super::organ`]) -- only `tb_encode::blkfmt` (the Kani-proven
//! on-disk codecs) and the safe `crate::arch::blk_*` MMIO facades -- so a future
//! substrate-profile build keeps this compiled while the organ is gated out.
//! ZERO unsafe (inherited `#![forbid(unsafe_code)]` from the `mem` parent).

use alloc::vec::Vec;

// --- the durability seam (BackingStore) --------------------------------------

/// A tier-tagged backing stream (one segment == one future virtio-blk region).
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Region {
    /// T2 episodic journal stream.
    Episodic,
    /// T3 semantic store stream.
    Semantic,
    /// T1 working-graph stream.
    Working,
}

/// A backing-store failure (closed set; never panics on a full/io store).
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum MemErr {
    /// The store is at capacity.
    Full,
    /// The requested offset/region does not exist.
    NotFound,
    /// An underlying I/O failure (durable backing only).
    Io,
}

/// The durability seam: a future `VirtioBlkStore` (the eventual sole new unsafe,
/// isolated in `arch`) drops in here WITHOUT touching any tier logic.
#[allow(dead_code)]
pub(crate) trait BackingStore {
    /// Append `bytes` to `region`, returning the start offset.
    fn append(&mut self, region: Region, bytes: &[u8]) -> Result<u64, MemErr>;
    /// Read up to `buf.len()` bytes from `region` at `off` into `buf`.
    fn read_at(&self, region: Region, off: u64, buf: &mut [u8]) -> Result<usize, MemErr>;
    /// Flush durable state (a no-op for the RAM-backed default).
    fn flush(&mut self) -> Result<(), MemErr>;
    /// The monotonic freshness epoch (bumped on every append).
    fn epoch(&self) -> u64;
}

/// The M13 default RAM-backed store over the M5/M7 kernel heap (durable
/// virtio-blk deferred to M16+). `flush` is a no-op; `epoch` is the T3 freshness
/// marker.
#[allow(dead_code)]
#[derive(Default)]
pub(crate) struct RamStore {
    ep: Vec<u8>,
    sem: Vec<u8>,
    wm: Vec<u8>,
    epoch: u64,
}

impl BackingStore for RamStore {
    fn append(&mut self, region: Region, bytes: &[u8]) -> Result<u64, MemErr> {
        let buf = match region {
            Region::Episodic => &mut self.ep,
            Region::Semantic => &mut self.sem,
            Region::Working => &mut self.wm,
        };
        let off = buf.len() as u64;
        buf.extend_from_slice(bytes);
        self.epoch = self.epoch.wrapping_add(1);
        Ok(off)
    }

    fn read_at(&self, region: Region, off: u64, buf: &mut [u8]) -> Result<usize, MemErr> {
        let src = match region {
            Region::Episodic => &self.ep,
            Region::Semantic => &self.sem,
            Region::Working => &self.wm,
        };
        let start = off as usize;
        if start > src.len() {
            return Err(MemErr::NotFound);
        }
        let n = core::cmp::min(buf.len(), src.len() - start);
        buf[..n].copy_from_slice(&src[start..start + n]);
        Ok(n)
    }

    fn flush(&mut self) -> Result<(), MemErr> {
        Ok(())
    }

    fn epoch(&self) -> u64 {
        self.epoch
    }
}

// --- M20: the durable virtio-blk-backed store (the real BackingStore) --------

/// Map a [`Region`] onto its on-disk record tag (the `tb_encode::blkfmt` extent
/// index). The three regions map 1:1 onto the three log extents.
#[allow(dead_code)]
fn region_tag(region: Region) -> u8 {
    match region {
        Region::Episodic => tb_encode::blkfmt::REGION_EPISODIC,
        Region::Semantic => tb_encode::blkfmt::REGION_SEMANTIC,
        Region::Working => tb_encode::blkfmt::REGION_WORKING,
    }
}

#[allow(dead_code)]
pub(crate) fn region_index(region: Region) -> usize {
    match region {
        Region::Episodic => 0,
        Region::Semantic => 1,
        Region::Working => 2,
    }
}

/// The M20 durable [`BackingStore`]: a log-structured virtio-blk store. ALL the
/// MMIO/DMA `unsafe` is in `arch::*::virtio` (called via the safe
/// `crate::arch::blk_read`/`blk_write`/`blk_flush` facades); this layer is 100% safe
/// value-staging + a TWO-PHASE COMMIT. Appends are buffered per-Region until
/// [`flush`](BackingStore::flush), which (1) writes each staged record frame to
/// its log sector, (2) `blk_flush` barrier, (3) writes the superblock at `gen+1`
/// (the one-sector atomic commit point), (4) `blk_flush`. A crash before step 3
/// leaves the prior committed superblock as truth (the staged tail "never
/// happened"). `mount` validates the superblock fail-closed, formats a fresh
/// disk, and replays each Region's committed log into the in-RAM image `read_at`
/// serves from. `epoch = (gen << 32) | appends_since_mount` so freshness is
/// monotonic across reboots.
#[allow(dead_code)]
pub(crate) struct VirtioBlkStore {
    /// The probed virtio-mmio slot the blk device sits at.
    slot: u32,
    /// The committed checkpoint generation (bumped by exactly 1 per flush).
    /// `pub(crate)` so the organ-side M20 `persist_selftest` can assert gen
    /// continuity across the engine/organ seam (the DoD-6 entanglement, §3.4).
    pub(crate) gen: u64,
    /// Per-Region committed log-head BYTE watermark (one frame == one sector).
    log_head: [u64; 3],
    /// Per-Region committed replayable record count. `pub(crate)` for the same
    /// cross-seam `persist_selftest` replay-count assertion as `gen` above.
    pub(crate) record_count: [u64; 3],
    /// Per-Region append sequence (strictly increasing; the replay witness).
    seq: [u64; 3],
    /// Per-Region STAGED (not-yet-committed) record payloads (heap, never stack).
    staged: [Vec<Vec<u8>>; 3],
    /// Per-Region committed in-RAM image (replayed payloads) `read_at` serves.
    image: [Vec<u8>; 3],
    /// Appends since the last mount (the low half of `epoch`).
    appends_since_mount: u64,
}

#[allow(dead_code)]
impl VirtioBlkStore {
    /// Probe + mount a virtio-blk device. Returns `None` if absent/legacy (the
    /// caller renders the graceful skip). On a formatted disk, replays the
    /// committed logs into the in-RAM image; on an unformatted/torn disk, formats
    /// a fresh store (gen 0). All scratch is a SINGLE static-free 512-byte sector
    /// buffer reused in a loop (no large stack arrays; #65 discipline).
    pub(crate) fn mount(slot: u32) -> Result<Self, MemErr> {
        use tb_encode::blkfmt;
        let mut s = VirtioBlkStore {
            slot,
            gen: 0,
            log_head: [0; 3],
            record_count: [0; 3],
            seq: [0; 3],
            staged: [Vec::new(), Vec::new(), Vec::new()],
            image: [Vec::new(), Vec::new(), Vec::new()],
            appends_since_mount: 0,
        };
        // Read the superblock (LBA 0) into one reusable sector buffer.
        let mut sec = [0u8; 512];
        if !crate::arch::blk_read(slot, blkfmt::SB_SECTOR, &mut sec) {
            return Err(MemErr::Io);
        }
        match blkfmt::superblock_decode(&sec) {
            Some(sb) => {
                // A committed checkpoint: adopt its watermarks + replay.
                s.gen = sb.gen;
                s.log_head = sb.log_head;
                s.record_count = sb.record_count;
                s.replay()?;
            }
            None => {
                // Fresh/unformatted/torn disk: format gen 0 (an empty committed
                // superblock), so a subsequent flush advances to gen 1.
                s.write_superblock(0)?;
            }
        }
        Ok(s)
    }

    /// Replay each Region's committed log [0..record_count) into the in-RAM
    /// image, verifying each frame's CRC + monotone seq. A torn frame (CRC fail)
    /// truncates the replay of that Region (the committed tail is honoured, the
    /// rest ignored). Reads sector-by-sector into ONE 512-byte buffer.
    fn replay(&mut self) -> Result<(), MemErr> {
        use tb_encode::blkfmt;
        let mut sec = [0u8; 512];
        for r in 0..3usize {
            let tag = r as u8;
            let count = self.record_count[r];
            let mut last_seq: Option<u64> = None;
            let mut i: u64 = 0;
            while i < count {
                let head = i * blkfmt::SECTOR_SIZE;
                let sector = match blkfmt::record_sector(tag, head) {
                    Some(x) => x,
                    None => break, // past the extent -> stop (defensive)
                };
                if !crate::arch::blk_read(self.slot, sector, &mut sec) {
                    return Err(MemErr::Io);
                }
                match blkfmt::record_frame_decode(&sec) {
                    Some((h, off)) => {
                        // monotone-seq witness: a non-increasing seq is a torn /
                        // reordered tail -> stop replaying this Region.
                        if let Some(p) = last_seq {
                            if h.seq <= p {
                                break;
                            }
                        }
                        last_seq = Some(h.seq);
                        let len = h.len as usize;
                        self.image[r].extend_from_slice(&sec[off..off + len]);
                    }
                    None => break, // torn frame -> committed tail honoured, rest ignored
                }
                i += 1;
            }
            // The next append continues past the committed seq.
            self.seq[r] = last_seq.map(|x| x + 1).unwrap_or(0);
        }
        Ok(())
    }

    /// Encode + write the superblock at `gen`, then FLUSH. The one-sector atomic
    /// commit point.
    fn write_superblock(&mut self, gen: u64) -> Result<(), MemErr> {
        use tb_encode::blkfmt;
        let sb = blkfmt::superblock_encode(gen, self.log_head, self.record_count);
        if !crate::arch::blk_write(self.slot, blkfmt::SB_SECTOR, &sb) {
            return Err(MemErr::Io);
        }
        if !crate::arch::blk_flush(self.slot) {
            return Err(MemErr::Io);
        }
        self.gen = gen;
        Ok(())
    }
}

impl BackingStore for VirtioBlkStore {
    /// Stage `bytes` as a record-frame payload for `region` (no disk write yet;
    /// committed on flush). Returns the staged byte offset within the Region's
    /// committed+staged image. `Full` if the Region's log would pass its extent.
    fn append(&mut self, region: Region, bytes: &[u8]) -> Result<u64, MemErr> {
        use tb_encode::blkfmt;
        let r = region_index(region);
        if bytes.len() > blkfmt::MAX_PAYLOAD {
            return Err(MemErr::Full); // a never-fitting payload
        }
        // Would the new frame pass the extent ceiling?
        let next_sector_idx = self.record_count[r] + self.staged[r].len() as u64;
        let (_, count) = blkfmt::region_extent(region_tag(region)).ok_or(MemErr::Io)?;
        if next_sector_idx >= count {
            return Err(MemErr::Full);
        }
        let off = self.image[r].len() as u64
            + self.staged[r].iter().map(|v| v.len() as u64).sum::<u64>();
        self.staged[r].push(bytes.to_vec());
        self.appends_since_mount = self.appends_since_mount.wrapping_add(1);
        Ok(off)
    }

    /// Serve from the committed in-RAM image (post-mount replay) plus any staged-
    /// but-not-yet-flushed appends, so reads are instant + reflect read-your-writes.
    fn read_at(&self, region: Region, off: u64, buf: &mut [u8]) -> Result<usize, MemErr> {
        let r = region_index(region);
        // Logical stream = committed image ++ staged payloads (concatenated).
        let start = off as usize;
        let img_len = self.image[r].len();
        let staged_len: usize = self.staged[r].iter().map(|v| v.len()).sum();
        let total = img_len + staged_len;
        if start > total {
            return Err(MemErr::NotFound);
        }
        let mut written = 0usize;
        let mut pos = start;
        while written < buf.len() && pos < total {
            let byte = if pos < img_len {
                self.image[r][pos]
            } else {
                // walk the staged payloads
                let mut rem = pos - img_len;
                let mut b = 0u8;
                for v in self.staged[r].iter() {
                    if rem < v.len() {
                        b = v[rem];
                        break;
                    }
                    rem -= v.len();
                }
                b
            };
            buf[written] = byte;
            written += 1;
            pos += 1;
        }
        Ok(written)
    }

    /// The TWO-PHASE COMMIT. (1) Write each staged record frame to its log
    /// sector; (2) FLUSH barrier; (3) write the superblock at `gen+1` (the atomic
    /// commit point) + FLUSH. On success the staged appends fold into the
    /// committed image + watermarks and the staging buffers clear.
    fn flush(&mut self) -> Result<(), MemErr> {
        use tb_encode::blkfmt;
        // Nothing staged: still advance the generation so a flush is a witnessable
        // checkpoint (the selftest asserts gen continuity).
        let mut sec = [0u8; 512];
        // Phase 1: write every staged frame at its Region's next log sector.
        for r in 0..3usize {
            let tag = r as u8;
            let mut idx = self.record_count[r];
            for payload in self.staged[r].iter() {
                let head = idx * blkfmt::SECTOR_SIZE;
                let sector = match blkfmt::record_sector(tag, head) {
                    Some(x) => x,
                    None => return Err(MemErr::Full),
                };
                if !blkfmt::record_frame_encode(tag, self.seq[r], payload, &mut sec) {
                    return Err(MemErr::Io);
                }
                if !crate::arch::blk_write(self.slot, sector, &sec) {
                    return Err(MemErr::Io);
                }
                self.seq[r] = self.seq[r].wrapping_add(1);
                idx += 1;
            }
        }
        // Phase 2: data-durability barrier.
        if !crate::arch::blk_flush(self.slot) {
            return Err(MemErr::Io);
        }
        // Fold staged -> committed image + watermarks (now durable).
        for r in 0..3usize {
            for payload in core::mem::take(&mut self.staged[r]) {
                self.image[r].extend_from_slice(&payload);
                self.record_count[r] += 1;
                self.log_head[r] += blkfmt::SECTOR_SIZE;
            }
        }
        // Phase 3: the one-sector atomic commit -- superblock at gen+1, then FLUSH.
        let next_gen = self.gen.wrapping_add(1);
        self.write_superblock(next_gen)?;
        Ok(())
    }

    /// `(gen << 32) | appends_since_mount` -- monotonic ACROSS reboots (the gen
    /// is the durable checkpoint counter; the low half is per-boot freshness).
    fn epoch(&self) -> u64 {
        (self.gen << 32) | (self.appends_since_mount & 0xFFFF_FFFF)
    }
}
