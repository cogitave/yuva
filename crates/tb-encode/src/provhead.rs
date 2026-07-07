//! `provhead` -- the M33 stage-B MULTI-SECTOR, TORN-WRITE-SAFE persisted
//! signed-head codec (proposal §6). The M20 `blkfmt::record_frame_*` primitive
//! hard-caps at ONE 512-byte sector (`MAX_PAYLOAD = 488`, a per-sector FNV-1a-32
//! torn detector); an LMS-`W4`/`H10` signature is **2508 bytes**, so the signed
//! prov-head record spans SIX sectors and needs genuinely new codec work:
//!
//!   (a) a **cross-sector** torn-write detector -- a record-spanning FNV-1a-64
//!       over the whole logical blob, so a torn MIDDLE sector (whose own
//!       per-sector checksum a naive scheme might not even reach) is caught;
//!   (b) a **per-sector generation stamp** (`gen_tag`) so a torn multi-sector
//!       commit that mixes NEW sectors with STALE ones left from an older record
//!       (the ping-pong slot reuse of `tb-hal`) is rejected -- every sector of a
//!       decodable record MUST carry the SAME `gen`;
//!   (c) a **fail-closed decode**: a partial / torn / mixed-gen / bad-magic /
//!       bad-length record returns `None` (treated as unsigned/fresh, NEVER a
//!       partial read, NEVER a panic) -- the `blkfmt::record_frame_decode`
//!       discipline extended across sectors.
//!
//! The two-phase `gen` DISCIPLINE (mirrors M20's superblock two-phase commit)
//! lives in `tb-hal` as a PING-PONG of two slots A/B: a torn write to the newer
//! slot leaves the older slot's consistent record intact, and the reader
//! `recover`s the prior consistent head by picking the decodable slot with the
//! greater `gen`. This leaf proves the byte-level codec (injectivity, torn/
//! mixed-gen/bad-field fail-close) + the pure `pick_newer` selector the `tb-hal`
//! recovery delegates to; the full-size disk round-trip is the host test + the
//! two-boot cross-boot witness (the M30 accum_resync precedent: prove the
//! discipline at a small cap, delegate the full trace to host + boot).
//!
//! The signature's AUTHENTICITY is verified SEPARATELY by `lmsig::lms_verify`
//! against the image-embedded public root; the checksums here are torn-write
//! detection ONLY and are NEVER trusted as a security property (§6).
//!
//! `#![no_std]`, zero-dep, panic/overflow-free, host-buildable, Kani-proven --
//! the `tb-encode` leaf discipline; the FNV primitives are reused from `blkfmt`.

use crate::blkfmt::{fnv1a32, fnv1a64};

/// One on-disk sector (the virtio-blk fixed sector size).
pub const SECTOR: usize = 512;
/// Per-sector metadata: `[0..4] gen_tag (le32)`, `[4..8] sec_crc (FNV-1a-32)`.
pub const SEC_META: usize = 8;
/// Payload bytes carried by one sector (`512 - 8`).
pub const SEC_PAYLOAD: usize = SECTOR - SEC_META;

/// The 2-byte record magic (`b"YH"` -- Yuva signed-Head; a fixed layout tag,
/// disjoint from `blkfmt`'s `YUVAMEM0` superblock magic and the attest `0x5959`).
pub const PROV_MAGIC: [u8; 2] = *b"YH";
/// The on-disk format version this codec writes + accepts.
pub const PROV_VERSION: u8 = 1;

/// Head / identifier / public-root fixed field lengths.
pub const HEAD_LEN: usize = 32;
/// LMS identifier `I` length (16 bytes, RFC 8554).
pub const I_LEN: usize = 16;
/// LMS public-root length.
pub const ROOT_LEN: usize = 32;

/// The maximum signature the record carries: LMS `W4`/`H10` = `4+4+32+32*67+4+32*10`.
pub const SIG_CAP: usize = 2508;

/// The fixed logical-blob prefix + fields, before the variable-length signature.
/// Layout: `[0..2] magic`, `[2] version`, `[3] reserved`, `[4..12] gen (le64)`,
/// `[12..16] q (le32)`, `[16..18] siglen (le16)`, `[18..50] head`,
/// `[50..66] i_id`, `[66..98] pubroot`.
pub const BLOB_FIXED: usize = 2 + 1 + 1 + 8 + 4 + 2 + HEAD_LEN + I_LEN + ROOT_LEN; // 98
/// The record-spanning FNV-1a-64 trailer length.
pub const BLOB_CRC: usize = 8;
/// The largest logical blob: fixed fields + max signature + the spanning CRC.
pub const BLOB_CAP: usize = BLOB_FIXED + SIG_CAP + BLOB_CRC; // 2614

/// The maximum number of sectors one record occupies (`ceil(BLOB_CAP/SEC_PAYLOAD)`).
pub const MAX_SECTORS: usize = BLOB_CAP.div_ceil(SEC_PAYLOAD); // 6
/// The byte size of one on-disk record slab (a fixed reservation per ping-pong slot).
pub const SLAB_BYTES: usize = MAX_SECTORS * SECTOR; // 3072

// Blob field offsets (const, so no overflow is possible).
const OFF_MAGIC: usize = 0;
const OFF_VERSION: usize = 2;
const OFF_GEN: usize = 4;
const OFF_Q: usize = 12;
const OFF_SIGLEN: usize = 16;
const OFF_HEAD: usize = 18;
const OFF_I: usize = OFF_HEAD + HEAD_LEN; // 50
const OFF_ROOT: usize = OFF_I + I_LEN; // 66
/// The signature always begins immediately after the fixed fields.
pub const OFF_SIG: usize = OFF_ROOT + ROOT_LEN; // 98

/// The decoded signed-head metadata. The variable-length signature is left in
/// the caller-provided reassembly `blob` at `[OFF_SIG .. OFF_SIG + siglen]`, so
/// this small struct never carries the 2508-byte signature by value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DecodedHead {
    /// The record generation (the ping-pong monotone counter).
    pub gen: u64,
    /// The LM-OTS leaf index used to sign (`leaf-idx` witness).
    pub q: u32,
    /// The signature byte length (`<= SIG_CAP`).
    pub siglen: u16,
    /// The 32-byte signed prov head.
    pub head: [u8; HEAD_LEN],
    /// The 16-byte LMS identifier `I`.
    pub i_id: [u8; I_LEN],
    /// The 32-byte LMS public root the signature commits to.
    pub pubroot: [u8; ROOT_LEN],
    /// The number of sectors the record occupied on disk.
    pub n_sectors: usize,
}

/// The number of sectors a record with `siglen` occupies, or `None` if the
/// signature exceeds `SIG_CAP`. Const arithmetic, no overflow.
#[inline]
#[must_use]
pub fn sectors_for(siglen: usize) -> Option<usize> {
    if siglen > SIG_CAP {
        return None;
    }
    let l = BLOB_FIXED + siglen + BLOB_CRC;
    Some(l.div_ceil(SEC_PAYLOAD))
}

#[inline]
fn put_u16(b: &mut [u8], off: usize, v: u16) {
    let x = v.to_le_bytes();
    b[off] = x[0];
    b[off + 1] = x[1];
}

#[inline]
fn put_u32(b: &mut [u8], off: usize, v: u32) {
    let x = v.to_le_bytes();
    let mut k = 0;
    while k < 4 {
        b[off + k] = x[k];
        k += 1;
    }
}

#[inline]
fn put_u64(b: &mut [u8], off: usize, v: u64) {
    let x = v.to_le_bytes();
    let mut k = 0;
    while k < 8 {
        b[off + k] = x[k];
        k += 1;
    }
}

#[inline]
fn rd_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

#[inline]
fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

#[inline]
fn rd_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
        b[off + 6],
        b[off + 7],
    ])
}

/// The per-sector CRC input is `gen_tag (4 bytes) || payload (504 bytes)`; the
/// FNV-1a-32 over that is stored at `sector[4..8]`. Computing it over BOTH the
/// gen stamp and the payload means a flipped `gen_tag` OR a flipped payload byte
/// both fail the per-sector gate. Total.
#[inline]
fn sector_crc(sector: &[u8]) -> u32 {
    // FNV-1a-32 over [0..4] (gen_tag) then [8..512] (payload) -- i.e. everything
    // but the stored CRC field itself. `fnv1a32` seeds the offset basis over the
    // 4 gen_tag bytes; `fnv1a32_chain` continues that accumulator over the
    // payload, so the two regions checksum as one stream with no scratch buffer.
    fnv1a32_chain(fnv1a32(&sector[0..4]), &sector[SEC_META..SECTOR])
}

/// Continue an FNV-1a-32 accumulator `h` over `data` (the streaming form of
/// `fnv1a32`, so a two-region checksum needs no intermediate buffer). Total.
#[inline]
fn fnv1a32_chain(mut h: u32, data: &[u8]) -> u32 {
    const FNV32_PRIME: u32 = 0x0100_0193;
    let mut i = 0;
    while i < data.len() {
        h ^= data[i] as u32;
        h = h.wrapping_mul(FNV32_PRIME);
        i += 1;
    }
    h
}

/// Encode a signed-head record into `out` (a byte buffer of at least the record's
/// `n_sectors * SECTOR`), using `blob` (>= `BLOB_CAP`) as reassembly scratch.
/// Returns the number of BYTES written (`n_sectors * SECTOR`), or `0` fail-closed
/// if `sig` exceeds `SIG_CAP` or either buffer is too small. Every unused tail
/// byte is zeroed. Total (no panic, no alloc).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn encode(
    gen: u64,
    q: u32,
    head: &[u8; HEAD_LEN],
    i_id: &[u8; I_LEN],
    pubroot: &[u8; ROOT_LEN],
    sig: &[u8],
    blob: &mut [u8],
    out: &mut [u8],
) -> usize {
    let siglen = sig.len();
    let n_sectors = match sectors_for(siglen) {
        Some(n) => n,
        None => return 0,
    };
    let l = BLOB_FIXED + siglen + BLOB_CRC;
    if blob.len() < l || out.len() < n_sectors * SECTOR {
        return 0;
    }

    // Build the logical blob.
    let mut k = 0;
    while k < l {
        blob[k] = 0;
        k += 1;
    }
    blob[OFF_MAGIC] = PROV_MAGIC[0];
    blob[OFF_MAGIC + 1] = PROV_MAGIC[1];
    blob[OFF_VERSION] = PROV_VERSION;
    put_u64(blob, OFF_GEN, gen);
    put_u32(blob, OFF_Q, q);
    put_u16(blob, OFF_SIGLEN, siglen as u16);
    let mut b = 0;
    while b < HEAD_LEN {
        blob[OFF_HEAD + b] = head[b];
        b += 1;
    }
    b = 0;
    while b < I_LEN {
        blob[OFF_I + b] = i_id[b];
        b += 1;
    }
    b = 0;
    while b < ROOT_LEN {
        blob[OFF_ROOT + b] = pubroot[b];
        b += 1;
    }
    b = 0;
    while b < siglen {
        blob[OFF_SIG + b] = sig[b];
        b += 1;
    }
    // The record-spanning FNV-1a-64 over blob[0 .. l-8].
    let span = fnv1a64(&blob[0..l - BLOB_CRC]);
    put_u64(blob, l - BLOB_CRC, span);

    // Chunk the blob into sectors, each stamped with gen_tag + a per-sector CRC.
    let gen_tag = (gen & 0xffff_ffff) as u32;
    let mut s = 0;
    while s < n_sectors {
        let sbase = s * SECTOR;
        // zero the whole sector first (pads the last partial sector).
        let mut z = 0;
        while z < SECTOR {
            out[sbase + z] = 0;
            z += 1;
        }
        put_u32(out, sbase, gen_tag);
        // copy this sector's payload slice from the blob.
        let pstart = s * SEC_PAYLOAD;
        let mut i = 0;
        while i < SEC_PAYLOAD && pstart + i < l {
            out[sbase + SEC_META + i] = blob[pstart + i];
            i += 1;
        }
        let crc = sector_crc(&out[sbase..sbase + SECTOR]);
        put_u32(out, sbase + 4, crc);
        s += 1;
    }
    n_sectors * SECTOR
}

/// Decode a signed-head record from the raw `sectors` bytes (as read off disk),
/// reassembling the logical blob into `blob` (>= `BLOB_CAP`). Returns the
/// `DecodedHead` metadata (the signature lives in `blob[OFF_SIG .. OFF_SIG +
/// siglen]`) on a fully-consistent record, else `None`. TOTAL + FAIL-CLOSED:
///
///   * sector 0's per-sector CRC must hold (else `None`);
///   * magic + version must match (else `None`);
///   * `siglen` must be `<= SIG_CAP` and the sector count must fit `sectors`
///     (else `None`);
///   * EVERY sector's per-sector CRC must hold AND its `gen_tag` must equal
///     sector 0's `gen` low-32 (a mixed-gen torn commit → `None`);
///   * the record-spanning FNV-1a-64 must match (a torn MIDDLE sector → `None`).
///
/// Never panics, never allocates.
#[must_use]
pub fn decode(sectors: &[u8], blob: &mut [u8]) -> Option<DecodedHead> {
    if sectors.len() < SECTOR {
        return None;
    }
    // Read the header from sector 0 to learn the record geometry (magic / version
    // / gen / siglen). Sector 0's integrity -- like every other sector's -- is
    // validated by the ONE per-sector CRC + gen_tag gate in the reassembly loop
    // below (there is no duplicate sector-0 pre-check), so a torn sector 0 is
    // caught there (or by the magic / length / record-spanning gates); reading a
    // corrupt geometry only leads to a fail-closed `None`.
    let s0 = &sectors[0..SECTOR];
    if s0[SEC_META + OFF_MAGIC] != PROV_MAGIC[0]
        || s0[SEC_META + OFF_MAGIC + 1] != PROV_MAGIC[1]
        || s0[SEC_META + OFF_VERSION] != PROV_VERSION
    {
        return None;
    }
    let gen = rd_u64(&s0[SEC_META..SECTOR], OFF_GEN);
    let q = rd_u32(&s0[SEC_META..SECTOR], OFF_Q);
    let siglen = rd_u16(&s0[SEC_META..SECTOR], OFF_SIGLEN) as usize;
    let n_sectors = sectors_for(siglen)?;
    let l = BLOB_FIXED + siglen + BLOB_CRC;
    // The reassembly buffer must hold the actual record (l bytes) -- the caller
    // sizes it to `BLOB_CAP` in the kernel, but a proof/test may pass a buffer
    // sized to the small record it decodes.
    if sectors.len() < n_sectors * SECTOR || blob.len() < l {
        return None;
    }
    let gen_tag = (gen & 0xffff_ffff) as u32;

    // Validate every sector (CRC + gen_tag) AND reassemble the blob.
    let mut s = 0;
    while s < n_sectors {
        let sbase = s * SECTOR;
        let sec = &sectors[sbase..sbase + SECTOR];
        if sector_crc(sec) != rd_u32(sec, 4) {
            return None; // torn sector
        }
        if rd_u32(sec, 0) != gen_tag {
            return None; // stale sector from an older ping-pong write
        }
        let pstart = s * SEC_PAYLOAD;
        let mut i = 0;
        while i < SEC_PAYLOAD && pstart + i < l {
            blob[pstart + i] = sec[SEC_META + i];
            i += 1;
        }
        s += 1;
    }

    // The record-spanning checksum: catches a torn middle sector whose per-sector
    // CRC somehow passed AND any cross-sector inconsistency.
    let span = fnv1a64(&blob[0..l - BLOB_CRC]);
    if span != rd_u64(blob, l - BLOB_CRC) {
        return None;
    }

    // Extract the small fixed fields (the signature stays in `blob` at OFF_SIG).
    let mut head = [0u8; HEAD_LEN];
    let mut b = 0;
    while b < HEAD_LEN {
        head[b] = blob[OFF_HEAD + b];
        b += 1;
    }
    let mut i_id = [0u8; I_LEN];
    b = 0;
    while b < I_LEN {
        i_id[b] = blob[OFF_I + b];
        b += 1;
    }
    let mut pubroot = [0u8; ROOT_LEN];
    b = 0;
    while b < ROOT_LEN {
        pubroot[b] = blob[OFF_ROOT + b];
        b += 1;
    }
    Some(DecodedHead {
        gen,
        q,
        siglen: siglen as u16,
        head,
        i_id,
        pubroot,
        n_sectors,
    })
}

/// Recompute + store a sector's per-sector CRC over its current `gen_tag` +
/// payload. Test/harness helper: after tampering a sector's PAYLOAD or `gen_tag`
/// this refreshes the per-sector CRC so that ONLY the record-spanning checksum
/// (payload tamper) or the `gen_tag` gate (gen tamper) -- not the per-sector CRC
/// -- can catch it, isolating each gate for the mutation pass. Total.
#[inline]
pub fn refresh_sector_crc(sector: &mut [u8]) {
    let crc = sector_crc(&sector[0..SECTOR]);
    put_u32(sector, 4, crc);
}

/// The pure two-phase-`gen` RECOVERY selector the `tb-hal` ping-pong reader
/// delegates to: given the decoded `gen` of slot A and slot B (either `None` if
/// that slot is torn/empty/mixed-gen), return which slot holds the newer
/// CONSISTENT record -- `Some(false)` for A, `Some(true)` for B, `None` if
/// NEITHER decodes. A torn newer slot (its `gen` is `None`) never wins, so the
/// reader recovers the prior consistent head. Total; ties (equal gens, a
/// degenerate case that the monotone writer never produces) resolve to A.
#[inline]
#[must_use]
pub fn pick_newer(a_gen: Option<u64>, b_gen: Option<u64>) -> Option<bool> {
    match (a_gen, b_gen) {
        (None, None) => None,
        (Some(_), None) => Some(false),
        (None, Some(_)) => Some(true),
        (Some(ga), Some(gb)) => Some(gb > ga),
    }
}

// ---------------------------------------------------------------------------
// Host tests (run under Miri via `cargo test -p tb-encode`) -- the concrete
// companions to the symbolic Kani harness, exercising the FULL-SIZE (2508-byte
// signature, 6-sector) record the boot path persists.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(siglen: usize) -> ([u8; HEAD_LEN], [u8; I_LEN], [u8; ROOT_LEN], std::vec::Vec<u8>) {
        let mut head = [0u8; HEAD_LEN];
        let mut i_id = [0u8; I_LEN];
        let mut root = [0u8; ROOT_LEN];
        for (k, b) in head.iter_mut().enumerate() {
            *b = (0x10 + k) as u8;
        }
        for (k, b) in i_id.iter_mut().enumerate() {
            *b = (0x40 + k) as u8;
        }
        for (k, b) in root.iter_mut().enumerate() {
            *b = (0x80 + k) as u8;
        }
        let sig: std::vec::Vec<u8> = (0..siglen).map(|k| (k * 7 + 3) as u8).collect();
        (head, i_id, root, sig)
    }

    #[test]
    fn roundtrip_full_size() {
        let (head, i_id, root, sig) = mk(SIG_CAP);
        let mut blob = [0u8; BLOB_CAP];
        let mut out = [0u8; SLAB_BYTES];
        let n = encode(7, 3, &head, &i_id, &root, &sig, &mut blob, &mut out);
        assert_eq!(n, MAX_SECTORS * SECTOR);
        let mut dblob = [0u8; BLOB_CAP];
        let d = decode(&out[..n], &mut dblob).expect("full-size record decodes");
        assert_eq!(d.gen, 7);
        assert_eq!(d.q, 3);
        assert_eq!(d.siglen as usize, SIG_CAP);
        assert_eq!(d.head, head);
        assert_eq!(d.i_id, i_id);
        assert_eq!(d.pubroot, root);
        assert_eq!(d.n_sectors, MAX_SECTORS);
        assert_eq!(&dblob[OFF_SIG..OFF_SIG + SIG_CAP], &sig[..]);
    }

    #[test]
    fn roundtrip_small() {
        let (head, i_id, root, sig) = mk(10);
        let mut blob = [0u8; BLOB_CAP];
        let mut out = [0u8; SLAB_BYTES];
        let n = encode(1, 0, &head, &i_id, &root, &sig, &mut blob, &mut out);
        assert_eq!(n, SECTOR); // 10-byte sig -> l=116 -> 1 sector
        let mut dblob = [0u8; BLOB_CAP];
        let d = decode(&out[..n], &mut dblob).expect("small record decodes");
        assert_eq!(d.head, head);
        assert_eq!(&dblob[OFF_SIG..OFF_SIG + 10], &sig[..]);
    }

    #[test]
    fn torn_middle_sector_rejected() {
        // A 2-sector record (siglen ~600 -> l=706 -> 2 sectors); corrupt a byte in
        // the SECOND sector's payload -> the per-sector CRC catches it.
        let (head, i_id, root, sig) = mk(600);
        let mut blob = [0u8; BLOB_CAP];
        let mut out = [0u8; SLAB_BYTES];
        let n = encode(5, 1, &head, &i_id, &root, &sig, &mut blob, &mut out);
        assert_eq!(n, 2 * SECTOR);
        let mut torn = out;
        torn[SECTOR + SEC_META + 20] ^= 0xFF; // a payload byte of sector 1
        let mut dblob = [0u8; BLOB_CAP];
        assert!(decode(&torn[..n], &mut dblob).is_none());
    }

    #[test]
    fn encode_injective() {
        // Records differing in ANY field (head / gen / q / sig) encode to DISTINCT
        // sector bytes (the Kani-delegated injectivity property).
        let (head, i_id, root, sig) = mk(10);
        let mut blob = [0u8; BLOB_CAP];
        let mut a = [0u8; SLAB_BYTES];
        let na = encode(1, 0, &head, &i_id, &root, &sig, &mut blob, &mut a);
        let mut head2 = head;
        head2[0] ^= 0x01;
        let variants: [([u8; HEAD_LEN], u64, u32); 3] =
            [(head2, 1, 0), (head, 2, 0), (head, 1, 9)];
        for (h, g, q) in variants {
            let mut b = [0u8; SLAB_BYTES];
            let nb = encode(g, q, &h, &i_id, &root, &sig, &mut blob, &mut b);
            assert_eq!(nb, na);
            assert_ne!(&a[..na], &b[..nb], "distinct records must encode distinctly");
        }
    }

    #[test]
    fn spanning_crc_isolation() {
        // ISOLATE the record-spanning FNV-64 gate (the Kani-delegated multi-sector
        // property): flip a payload byte in the SECOND sector AND refresh that
        // sector's per-sector CRC, so ONLY the record-spanning checksum -- not the
        // per-sector CRC -- can catch the tamper. A decoder missing the spanning
        // gate would wrongly accept this.
        let (head, i_id, root, sig) = mk(600);
        let mut blob = [0u8; BLOB_CAP];
        let mut out = [0u8; SLAB_BYTES];
        let n = encode(5, 1, &head, &i_id, &root, &sig, &mut blob, &mut out);
        assert_eq!(n, 2 * SECTOR);
        let mut tampered = out;
        tampered[SECTOR + SEC_META + 30] ^= 0x01; // a payload byte of sector 1
        refresh_sector_crc(&mut tampered[SECTOR..2 * SECTOR]);
        let mut dblob = [0u8; BLOB_CAP];
        assert!(decode(&tampered[..n], &mut dblob).is_none());
    }

    #[test]
    fn mixed_gen_rejected() {
        // Sector 0 says gen=9; leave sector 1 stamped with a stale gen_tag -> the
        // gen_tag gate rejects the mixed record (the ping-pong torn-commit case).
        let (head, i_id, root, sig) = mk(600);
        let mut blob = [0u8; BLOB_CAP];
        let mut out = [0u8; SLAB_BYTES];
        let n = encode(9, 0, &head, &i_id, &root, &sig, &mut blob, &mut out);
        let mut mixed = out;
        // rewrite sector 1's gen_tag to a stale value + fix its per-sector CRC so
        // ONLY the gen_tag gate (not the CRC) can catch it.
        put_u32(&mut mixed, SECTOR, 0x0000_0008);
        let crc = sector_crc(&mixed[SECTOR..2 * SECTOR]);
        put_u32(&mut mixed, SECTOR + 4, crc);
        let mut dblob = [0u8; BLOB_CAP];
        assert!(decode(&mixed[..n], &mut dblob).is_none());
    }

    #[test]
    fn bad_magic_version_len_rejected() {
        let (head, i_id, root, sig) = mk(10);
        let mut blob = [0u8; BLOB_CAP];
        let mut out = [0u8; SLAB_BYTES];
        let n = encode(1, 0, &head, &i_id, &root, &sig, &mut blob, &mut out);
        let mut dblob = [0u8; BLOB_CAP];

        // bad magic (then fix the per-sector CRC so the magic gate is what fires)
        let mut bad = out;
        bad[SEC_META + OFF_MAGIC] ^= 0xFF;
        let crc = sector_crc(&bad[0..SECTOR]);
        put_u32(&mut bad, 4, crc);
        assert!(decode(&bad[..n], &mut dblob).is_none());

        // bad version
        let mut badv = out;
        badv[SEC_META + OFF_VERSION] = 0x99;
        let crc = sector_crc(&badv[0..SECTOR]);
        put_u32(&mut badv, 4, crc);
        assert!(decode(&badv[..n], &mut dblob).is_none());

        // a truncated buffer (fewer bytes than one sector) -> None
        assert!(decode(&out[..SECTOR - 1], &mut dblob).is_none());

        // an all-zero slab (fresh disk) -> None (magic gate; CRC of zeros != stored 0)
        let zero = [0u8; SLAB_BYTES];
        assert!(decode(&zero[..], &mut dblob).is_none());
    }

    #[test]
    fn oversize_sig_rejected() {
        let (head, i_id, root, _sig) = mk(0);
        let big = std::vec![0u8; SIG_CAP + 1];
        let mut blob = [0u8; BLOB_CAP];
        let mut out = [0u8; SLAB_BYTES];
        assert_eq!(encode(1, 0, &head, &i_id, &root, &big, &mut blob, &mut out), 0);
        assert_eq!(sectors_for(SIG_CAP + 1), None);
    }

    #[test]
    fn torn_write_recovery_prior_head() {
        // The two-phase-gen RECOVERY: slot A holds a consistent gen=1 record; slot
        // B is a TORN gen=2 write (a byte flipped in its second sector). The reader
        // decodes A -> Some(gen 1), decodes B -> None, and `pick_newer` recovers A
        // (the prior consistent head), NOT the torn newer slot.
        let (head_a, i_id, root, sig_a) = mk(600);
        let mut head_b = head_a;
        head_b[0] ^= 0xAA; // a DIFFERENT head in the torn newer slot
        let mut blob = [0u8; BLOB_CAP];
        let mut slot_a = [0u8; SLAB_BYTES];
        let mut slot_b = [0u8; SLAB_BYTES];
        let na = encode(1, 0, &head_a, &i_id, &root, &sig_a, &mut blob, &mut slot_a);
        let nb = encode(2, 1, &head_b, &i_id, &root, &sig_a, &mut blob, &mut slot_b);
        slot_b[SECTOR + SEC_META + 4] ^= 0x01; // tear slot B's second sector

        let mut da = [0u8; BLOB_CAP];
        let mut db = [0u8; BLOB_CAP];
        let a = decode(&slot_a[..na], &mut da);
        let b = decode(&slot_b[..nb], &mut db);
        assert!(a.is_some());
        assert!(b.is_none());
        let winner = pick_newer(a.map(|x| x.gen), b.map(|x| x.gen));
        assert_eq!(winner, Some(false)); // slot A recovered
        assert_eq!(a.unwrap().head, head_a); // the PRIOR consistent head
    }

    #[test]
    fn pick_newer_selects_greater_gen() {
        assert_eq!(pick_newer(None, None), None);
        assert_eq!(pick_newer(Some(3), None), Some(false));
        assert_eq!(pick_newer(None, Some(3)), Some(true));
        assert_eq!(pick_newer(Some(3), Some(4)), Some(true));
        assert_eq!(pick_newer(Some(5), Some(4)), Some(false));
    }
}
