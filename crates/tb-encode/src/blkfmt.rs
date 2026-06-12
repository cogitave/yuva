//! `blkfmt` -- the M20 durable-persistence ON-DISK + virtio-blk REQUEST codecs.
//!
//! This is the PURE value-computation leaf that sits one millimetre in front of
//! the M20 virtio-blk silicon-`unsafe` (the MMIO ring in
//! `tb-hal::arch::*::virtio`) and the on-disk byte layout the `VirtioBlkStore`
//! reads/writes. EVERYTHING here is total, panic/overflow-free, `#![no_std]`-
//! clean, zero-dep, host-buildable, and Kani-proven -- so the kernel side that
//! COMMITS these bytes to the device is byte-identical to a model the CI machine-
//! checks, with NO model drift (mirrors `vmx`/`paging`/`smmuv3`).
//!
//! Three codec families + the fixed-partition sector math:
//!
//!  * **virtio-blk request header** (`req_header_encode`/`req_header_decode`):
//!    the 16-byte `{le32 type, le32 reserved, le64 sector}` the device reads RO
//!    from descriptor 0, plus the closed status-byte decode (`S_OK=0`,
//!    `S_IOERR=1`, `S_UNSUPP=2`). Request types: `T_IN=0` (read sector),
//!    `T_OUT=1` (write sector), `T_FLUSH=4` (the durability barrier).
//!  * **superblock** (`superblock_encode`/`superblock_decode`): the 512-byte
//!    LBA-0 sector -- magic `YUVAMEM0` (from `brand`), version, checkpoint generation `gen`,
//!    per-Region committed `log_head[3]` + `record_count[3]` watermarks, and an
//!    FNV-1a-64 checksum over bytes `[0..504]`. The decode is TOTAL and fail-
//!    closed: wrong magic / version / checksum -> `None` (treated by the mount
//!    layer as a fresh/unformatted disk -> format).
//!  * **record frame** (`record_frame_encode`/`record_frame_decode`): the
//!    24-byte append-only header (`region_tag`, `len`, `seq`, `payload_crc` via
//!    FNV-1a-32) + payload, plus the 48-byte LE Episode body
//!    (`episode_encode`/`episode_decode`) the T2 journal replays field-for-field.
//!  * **sector/extent math** (`region_extent`/`record_sector`): the const fixed
//!    partition (SB @ sector 0; Episodic 1..4096; Semantic 4096..6144; Working
//!    6144..8192 over a >=4 MiB image) with no-overflow + in-extent lemmas.

// ---------------------------------------------------------------------------
// virtio-blk request header + status (virtio v1.2 §5.2).
// ---------------------------------------------------------------------------

/// `VIRTIO_BLK_T_IN` -- read a sector FROM the device into guest memory.
pub const T_IN: u32 = 0;
/// `VIRTIO_BLK_T_OUT` -- write a sector FROM guest memory to the device.
pub const T_OUT: u32 = 1;
/// `VIRTIO_BLK_T_FLUSH` -- the durability barrier (no data descriptor).
pub const T_FLUSH: u32 = 4;

/// `VIRTIO_BLK_S_OK` -- the request completed successfully.
pub const S_OK: u8 = 0;
/// `VIRTIO_BLK_S_IOERR` -- a device-side I/O error.
pub const S_IOERR: u8 = 1;
/// `VIRTIO_BLK_S_UNSUPP` -- the device does not support the request.
pub const S_UNSUPP: u8 = 2;

/// The fixed virtio-blk request-header length (le32 type, le32 reserved, le64 sector).
pub const REQ_HEADER_LEN: usize = 16;

/// Encode a 16-byte virtio-blk request header: `{le32 type, le32 reserved=0,
/// le64 sector}`. Total over all inputs (no panic). For `T_FLUSH` the caller
/// passes `sector == 0` per the spec; this codec does not enforce that (it is a
/// pure byte layout).
#[inline]
#[must_use]
pub fn req_header_encode(req_type: u32, sector: u64) -> [u8; REQ_HEADER_LEN] {
    let mut out = [0u8; REQ_HEADER_LEN];
    let t = req_type.to_le_bytes();
    let s = sector.to_le_bytes();
    out[0] = t[0];
    out[1] = t[1];
    out[2] = t[2];
    out[3] = t[3];
    // bytes [4..8] = reserved, left zero.
    out[8] = s[0];
    out[9] = s[1];
    out[10] = s[2];
    out[11] = s[3];
    out[12] = s[4];
    out[13] = s[5];
    out[14] = s[6];
    out[15] = s[7];
    out
}

/// Decode the `(req_type, sector)` pair from a 16-byte request header. Total;
/// the reserved dword is ignored. Returns the raw fields (well-formedness of
/// `req_type` is a caller concern -- the encoder/decoder are a pure byte layout).
#[inline]
#[must_use]
pub fn req_header_decode(bytes: &[u8; REQ_HEADER_LEN]) -> (u32, u64) {
    let req_type = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let sector = u64::from_le_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]);
    (req_type, sector)
}

/// `true` iff `t` is one of the three request types this driver issues.
#[inline]
#[must_use]
pub fn req_type_is_known(t: u32) -> bool {
    t == T_IN || t == T_OUT || t == T_FLUSH
}

/// Decode a status byte into the closed status set, mapping any unknown value to
/// `S_IOERR` (fail-closed: an undocumented status is treated as an error).
#[inline]
#[must_use]
pub fn status_decode(b: u8) -> u8 {
    match b {
        S_OK => S_OK,
        S_UNSUPP => S_UNSUPP,
        _ => S_IOERR,
    }
}

// ---------------------------------------------------------------------------
// FNV-1a checksums (the canonical, dependency-free integrity hash).
// ---------------------------------------------------------------------------

const FNV64_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV64_PRIME: u64 = 0x0000_0100_0000_01b3;
const FNV32_OFFSET: u32 = 0x811c_9dc5;
const FNV32_PRIME: u32 = 0x0100_0193;

/// FNV-1a-64 over `data`. Total, panic/overflow-free (wrapping arithmetic).
#[inline]
#[must_use]
pub fn fnv1a64(data: &[u8]) -> u64 {
    let mut h = FNV64_OFFSET;
    let mut i = 0;
    while i < data.len() {
        h ^= data[i] as u64;
        h = h.wrapping_mul(FNV64_PRIME);
        i += 1;
    }
    h
}

/// FNV-1a-32 over `data`. Total, panic/overflow-free (wrapping arithmetic).
#[inline]
#[must_use]
pub fn fnv1a32(data: &[u8]) -> u32 {
    let mut h = FNV32_OFFSET;
    let mut i = 0;
    while i < data.len() {
        h ^= data[i] as u32;
        h = h.wrapping_mul(FNV32_PRIME);
        i += 1;
    }
    h
}

// ---------------------------------------------------------------------------
// Fixed log-structured partition geometry (const; the bounds are static).
// ---------------------------------------------------------------------------

/// One on-disk sector is 512 bytes (the virtio-blk fixed sector size).
pub const SECTOR_SIZE: u64 = 512;

/// The superblock occupies LBA 0.
pub const SB_SECTOR: u64 = 0;

/// First sector of the Episodic log extent.
pub const EP_FIRST: u64 = 1;
/// Sector count of the Episodic log extent (sectors 1..4096).
pub const EP_COUNT: u64 = 4095;
/// First sector of the Semantic log extent.
pub const SEM_FIRST: u64 = 4096;
/// Sector count of the Semantic log extent (sectors 4096..6144).
pub const SEM_COUNT: u64 = 2048;
/// First sector of the Working log extent.
pub const WM_FIRST: u64 = 6144;
/// Sector count of the Working log extent (sectors 6144..8192).
pub const WM_COUNT: u64 = 2048;

/// The Region tag a record frame carries (mirrors `tb-hal::mem::Region`).
pub const REGION_EPISODIC: u8 = 0;
/// The Semantic region tag.
pub const REGION_SEMANTIC: u8 = 1;
/// The Working region tag.
pub const REGION_WORKING: u8 = 2;

/// Return `(first_sector, sector_count)` for a region tag, or `None` for an
/// unknown tag (total fail-closed). The bounds are const, so no overflow is
/// possible.
#[inline]
#[must_use]
pub fn region_extent(region_tag: u8) -> Option<(u64, u64)> {
    match region_tag {
        REGION_EPISODIC => Some((EP_FIRST, EP_COUNT)),
        REGION_SEMANTIC => Some((SEM_FIRST, SEM_COUNT)),
        REGION_WORKING => Some((WM_FIRST, WM_COUNT)),
        _ => None,
    }
}

/// The absolute sector for a region's log at byte watermark `log_head`. Returns
/// `None` if the tag is unknown OR the resulting sector would pass the extent
/// ceiling (the `Full` fail-closed case). No overflow: `log_head / SECTOR_SIZE`
/// is bounded and `first + idx` is checked against `first + count`.
#[inline]
#[must_use]
pub fn record_sector(region_tag: u8, log_head: u64) -> Option<u64> {
    let (first, count) = region_extent(region_tag)?;
    let idx = log_head / SECTOR_SIZE; // floor; the log head is sector-granular in use
    if idx >= count {
        return None; // past the extent ceiling -> Full
    }
    // `first + idx` cannot overflow: first <= WM_FIRST + WM_COUNT (8192) and
    // idx < count <= EP_COUNT (4095), so the sum is far below u64::MAX.
    Some(first + idx)
}

// ---------------------------------------------------------------------------
// Superblock (512 bytes, LBA 0). All multi-byte fields little-endian.
// ---------------------------------------------------------------------------

/// The superblock magic (`b"YUVAMEM0"` -- the brand + the fixed `MEM0`
/// mnemonic). Derived in `brand::SB_MAGIC`, never re-spelled here. Disks are
/// mktemp-fresh per run; nothing on-disk migrates across the rename.
pub const SB_MAGIC: [u8; 8] = brand::SB_MAGIC;
/// The on-disk format version this codec writes + accepts.
pub const SB_VERSION: u32 = 1;
/// The number of bytes the FNV-1a-64 checksum covers (`[0..504]`).
pub const SB_CKSUM_OFF: usize = 504;

/// The decoded superblock (the image's table of contents).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Superblock {
    /// The on-disk format version.
    pub version: u32,
    /// The checkpoint generation -- the monotonic two-phase-commit counter.
    pub gen: u64,
    /// Per-Region committed log-head byte watermark (Episodic=0/Semantic=1/Working=2).
    pub log_head: [u64; 3],
    /// Per-Region replayable record count.
    pub record_count: [u64; 3],
}

/// Encode a 512-byte superblock sector. Layout:
///   `[0..8]`   magic `YUVAMEM0`
///   `[8..12]`  version (le32)
///   `[12..16]` reserved zero
///   `[16..24]` gen (le64)
///   `[24..48]` log_head[3] (3 * le64)
///   `[48..72]` record_count[3] (3 * le64)
///   `[72..504]` reserved zero
///   `[504..512]` FNV-1a-64 checksum over bytes `[0..504]` (le64)
/// Total over all inputs (no panic).
#[must_use]
pub fn superblock_encode(gen: u64, log_head: [u64; 3], record_count: [u64; 3]) -> [u8; 512] {
    let mut s = [0u8; 512];
    s[0..8].copy_from_slice(&SB_MAGIC);
    s[8..12].copy_from_slice(&SB_VERSION.to_le_bytes());
    // [12..16] reserved
    s[16..24].copy_from_slice(&gen.to_le_bytes());
    s[24..32].copy_from_slice(&log_head[0].to_le_bytes());
    s[32..40].copy_from_slice(&log_head[1].to_le_bytes());
    s[40..48].copy_from_slice(&log_head[2].to_le_bytes());
    s[48..56].copy_from_slice(&record_count[0].to_le_bytes());
    s[56..64].copy_from_slice(&record_count[1].to_le_bytes());
    s[64..72].copy_from_slice(&record_count[2].to_le_bytes());
    // [72..504] reserved zero
    let ck = fnv1a64(&s[0..SB_CKSUM_OFF]);
    s[SB_CKSUM_OFF..512].copy_from_slice(&ck.to_le_bytes());
    s
}

#[inline]
fn rd_u64(s: &[u8; 512], off: usize) -> u64 {
    u64::from_le_bytes([
        s[off],
        s[off + 1],
        s[off + 2],
        s[off + 3],
        s[off + 4],
        s[off + 5],
        s[off + 6],
        s[off + 7],
    ])
}

/// Decode a 512-byte superblock, TOTAL + fail-closed: wrong magic, wrong
/// version, or a checksum mismatch all return `None` (the mount layer formats a
/// fresh disk). A `Some` is a structurally + integrity-valid checkpoint.
#[must_use]
pub fn superblock_decode(s: &[u8; 512]) -> Option<Superblock> {
    // magic gate
    let mut i = 0;
    while i < 8 {
        if s[i] != SB_MAGIC[i] {
            return None;
        }
        i += 1;
    }
    let version = u32::from_le_bytes([s[8], s[9], s[10], s[11]]);
    if version != SB_VERSION {
        return None;
    }
    // checksum gate (recompute over [0..504], compare the stored le64 tail)
    let want = fnv1a64(&s[0..SB_CKSUM_OFF]);
    let got = rd_u64(s, SB_CKSUM_OFF);
    if want != got {
        return None;
    }
    Some(Superblock {
        version,
        gen: rd_u64(s, 16),
        log_head: [rd_u64(s, 24), rd_u64(s, 32), rd_u64(s, 40)],
        record_count: [rd_u64(s, 48), rd_u64(s, 56), rd_u64(s, 64)],
    })
}

// ---------------------------------------------------------------------------
// Record frame (24-byte header + payload). The append-only log unit.
// ---------------------------------------------------------------------------

/// The fixed record-frame header length.
pub const FRAME_HEADER_LEN: usize = 24;
/// The Episode body length (the 48-byte LE T2 record).
pub const EPISODE_LEN: usize = 48;
/// The maximum payload a single-sector frame can carry (`512 - 24`).
pub const MAX_PAYLOAD: usize = SECTOR_SIZE as usize - FRAME_HEADER_LEN;

/// A decoded record-frame header (the payload follows in the same sector).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FrameHeader {
    /// The Region tag (0/1/2).
    pub region_tag: u8,
    /// The payload byte length (`<= MAX_PAYLOAD`).
    pub len: u16,
    /// The per-Region append sequence (strictly increasing -- replay witness).
    pub seq: u64,
    /// FNV-1a-32 over the payload (the torn-write detector).
    pub payload_crc: u32,
}

/// Encode a 24-byte frame header. Layout:
///   `[0]`      region_tag
///   `[1]`      reserved
///   `[2..4]`   len (le16)
///   `[4..12]`  seq (le64)
///   `[12..16]` payload_crc (le32)
///   `[16..24]` reserved zero
/// Total (no panic).
#[must_use]
pub fn frame_header_encode(region_tag: u8, len: u16, seq: u64, payload_crc: u32) -> [u8; 24] {
    let mut h = [0u8; 24];
    h[0] = region_tag;
    // h[1] reserved
    h[2..4].copy_from_slice(&len.to_le_bytes());
    h[4..12].copy_from_slice(&seq.to_le_bytes());
    h[12..16].copy_from_slice(&payload_crc.to_le_bytes());
    // [16..24] reserved zero
    h
}

/// Decode a 24-byte frame header (total; no validation -- raw fields).
#[inline]
#[must_use]
pub fn frame_header_decode(h: &[u8; 24]) -> FrameHeader {
    FrameHeader {
        region_tag: h[0],
        len: u16::from_le_bytes([h[2], h[3]]),
        seq: u64::from_le_bytes([h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11]]),
        payload_crc: u32::from_le_bytes([h[12], h[13], h[14], h[15]]),
    }
}

/// Encode a full single-sector record frame (header + payload) into `out` (a
/// 512-byte sector buffer), zeroing the unused tail. Returns `false` fail-closed
/// if the payload exceeds `MAX_PAYLOAD` (so a never-fitting frame is rejected
/// rather than silently truncated). `payload_crc` is FNV-1a-32 over the payload.
#[must_use]
pub fn record_frame_encode(
    region_tag: u8,
    seq: u64,
    payload: &[u8],
    out: &mut [u8; 512],
) -> bool {
    if payload.len() > MAX_PAYLOAD {
        return false;
    }
    let crc = fnv1a32(payload);
    let hdr = frame_header_encode(region_tag, payload.len() as u16, seq, crc);
    let mut i = 0;
    while i < 512 {
        out[i] = 0;
        i += 1;
    }
    out[0..FRAME_HEADER_LEN].copy_from_slice(&hdr);
    out[FRAME_HEADER_LEN..FRAME_HEADER_LEN + payload.len()].copy_from_slice(payload);
    true
}

/// Decode a single-sector record frame from a 512-byte sector. TOTAL + fail-
/// closed: returns `Some((header, payload_offset))` ONLY when the declared `len`
/// is in-bounds AND the recomputed payload CRC matches the header (the torn-tail
/// rejector); otherwise `None`. The caller reads the payload from
/// `sector[payload_offset .. payload_offset + header.len]`.
#[must_use]
pub fn record_frame_decode(sector: &[u8; 512]) -> Option<(FrameHeader, usize)> {
    let mut hb = [0u8; 24];
    hb.copy_from_slice(&sector[0..FRAME_HEADER_LEN]);
    let h = frame_header_decode(&hb);
    let len = h.len as usize;
    if len > MAX_PAYLOAD {
        return None; // declared length cannot fit a single sector
    }
    let start = FRAME_HEADER_LEN;
    let end = start + len; // end <= 24 + 488 = 512, no overflow
    let crc = fnv1a32(&sector[start..end]);
    if crc != h.payload_crc {
        return None; // torn / corrupt payload
    }
    Some((h, start))
}

// ---------------------------------------------------------------------------
// Episode body (48-byte LE; mirrors tb-hal::mem::Episode).
// ---------------------------------------------------------------------------

/// A decoded Episode body (the T2 journal record, field-for-field).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EpisodeBody {
    /// The record id.
    pub id: u64,
    /// The content token.
    pub content_tok: u64,
    /// The stored value scalar.
    pub value: u64,
    /// The bi-temporal creation stamp.
    pub t_created: u64,
    /// The bi-temporal invalidation stamp (0 == live).
    pub t_invalid: u64,
    /// The producing task id.
    pub producing_task: u32,
}

/// Encode the 48-byte LE Episode body. Layout (all le):
///   id:u64, content_tok:u64, value:u64, t_created:u64, t_invalid:u64,
///   producing_task:u32, _pad:u32. Total (no panic).
#[must_use]
pub fn episode_encode(e: &EpisodeBody) -> [u8; EPISODE_LEN] {
    let mut b = [0u8; EPISODE_LEN];
    b[0..8].copy_from_slice(&e.id.to_le_bytes());
    b[8..16].copy_from_slice(&e.content_tok.to_le_bytes());
    b[16..24].copy_from_slice(&e.value.to_le_bytes());
    b[24..32].copy_from_slice(&e.t_created.to_le_bytes());
    b[32..40].copy_from_slice(&e.t_invalid.to_le_bytes());
    b[40..44].copy_from_slice(&e.producing_task.to_le_bytes());
    // [44..48] pad zero
    b
}

/// Decode a 48-byte LE Episode body (total; the pad dword is ignored).
#[inline]
#[must_use]
pub fn episode_decode(b: &[u8; EPISODE_LEN]) -> EpisodeBody {
    let rd8 = |o: usize| {
        u64::from_le_bytes([
            b[o],
            b[o + 1],
            b[o + 2],
            b[o + 3],
            b[o + 4],
            b[o + 5],
            b[o + 6],
            b[o + 7],
        ])
    };
    EpisodeBody {
        id: rd8(0),
        content_tok: rd8(8),
        value: rd8(16),
        t_created: rd8(24),
        t_invalid: rd8(32),
        producing_task: u32::from_le_bytes([b[40], b[41], b[42], b[43]]),
    }
}

// ---------------------------------------------------------------------------
// Host tests (run under Miri via `cargo test -p tb-encode`). Round-trip +
// torn-tail truncation, the concrete companions to the symbolic Kani harnesses.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn req_header_roundtrip() {
        for &(t, sec) in &[(T_IN, 0u64), (T_OUT, 7), (T_FLUSH, 0), (T_IN, u64::MAX)] {
            let enc = req_header_encode(t, sec);
            let (dt, ds) = req_header_decode(&enc);
            assert_eq!(dt, t);
            assert_eq!(ds, sec);
            assert!(req_type_is_known(t));
        }
        assert_eq!(status_decode(0), S_OK);
        assert_eq!(status_decode(1), S_IOERR);
        assert_eq!(status_decode(2), S_UNSUPP);
        assert_eq!(status_decode(99), S_IOERR); // unknown -> fail-closed
    }

    #[test]
    fn superblock_roundtrip_and_failclose() {
        let lh = [512u64, 1024, 2048];
        let rc = [3u64, 1, 0];
        let s = superblock_encode(5, lh, rc);
        let d = superblock_decode(&s).expect("valid superblock decodes");
        assert_eq!(d.gen, 5);
        assert_eq!(d.log_head, lh);
        assert_eq!(d.record_count, rc);
        assert_eq!(d.version, SB_VERSION);

        // bad magic -> None
        let mut bad = s;
        bad[0] ^= 0xFF;
        assert!(superblock_decode(&bad).is_none());

        // flipped checksum byte -> None
        let mut bad2 = s;
        bad2[510] ^= 0x01;
        assert!(superblock_decode(&bad2).is_none());

        // a fresh (all-zero) disk -> None (format)
        let zero = [0u8; 512];
        assert!(superblock_decode(&zero).is_none());
    }

    #[test]
    fn record_frame_roundtrip_and_torn() {
        let e = EpisodeBody {
            id: 42,
            content_tok: 0xDEAD,
            value: 0xBEEF,
            t_created: 7,
            t_invalid: 0,
            producing_task: 3,
        };
        let body = episode_encode(&e);
        let mut sector = [0u8; 512];
        assert!(record_frame_encode(REGION_EPISODIC, 9, &body, &mut sector));
        let (h, off) = record_frame_decode(&sector).expect("frame decodes");
        assert_eq!(h.region_tag, REGION_EPISODIC);
        assert_eq!(h.seq, 9);
        assert_eq!(h.len as usize, EPISODE_LEN);
        let mut bb = [0u8; EPISODE_LEN];
        bb.copy_from_slice(&sector[off..off + EPISODE_LEN]);
        assert_eq!(episode_decode(&bb), e);

        // torn payload -> None
        let mut torn = sector;
        torn[FRAME_HEADER_LEN] ^= 0xFF;
        assert!(record_frame_decode(&torn).is_none());

        // a frame with an absurd declared len -> None
        let mut huge = sector;
        huge[2] = 0xFF;
        huge[3] = 0xFF;
        assert!(record_frame_decode(&huge).is_none());

        // an all-zero sector is NOT a valid frame: its header carries
        // payload_crc=0, but FNV-1a-32 of the empty payload is the nonzero
        // offset basis, so the CRC gate fails -> None (the torn-tail / unwritten-
        // sector rejector; a fresh log past the watermark reads as zeros).
        let zero = [0u8; 512];
        assert!(record_frame_decode(&zero).is_none());

        // an explicitly-encoded zero-length frame DOES round-trip (the CRC of the
        // empty payload is written into the header by the encoder).
        let mut empty = [0u8; 512];
        assert!(record_frame_encode(REGION_WORKING, 1, &[], &mut empty));
        let de = record_frame_decode(&empty).expect("empty frame decodes");
        assert_eq!(de.0.len, 0);
        assert_eq!(de.0.region_tag, REGION_WORKING);
    }

    #[test]
    fn sector_math_bounds() {
        assert_eq!(region_extent(REGION_EPISODIC), Some((EP_FIRST, EP_COUNT)));
        assert_eq!(region_extent(REGION_SEMANTIC), Some((SEM_FIRST, SEM_COUNT)));
        assert_eq!(region_extent(REGION_WORKING), Some((WM_FIRST, WM_COUNT)));
        assert_eq!(region_extent(7), None);

        // first record of each region lands at its first sector
        assert_eq!(record_sector(REGION_EPISODIC, 0), Some(EP_FIRST));
        assert_eq!(record_sector(REGION_SEMANTIC, 0), Some(SEM_FIRST));
        assert_eq!(record_sector(REGION_WORKING, 0), Some(WM_FIRST));
        // one sector in
        assert_eq!(record_sector(REGION_EPISODIC, SECTOR_SIZE), Some(EP_FIRST + 1));
        // past the ceiling -> Full (None)
        assert_eq!(record_sector(REGION_EPISODIC, EP_COUNT * SECTOR_SIZE), None);
        assert_eq!(record_sector(REGION_SEMANTIC, SEM_COUNT * SECTOR_SIZE), None);
    }

    #[test]
    fn episode_roundtrip() {
        let e = EpisodeBody {
            id: u64::MAX,
            content_tok: 1,
            value: 2,
            t_created: 3,
            t_invalid: 4,
            producing_task: u32::MAX,
        };
        assert_eq!(episode_decode(&episode_encode(&e)), e);
    }
}
