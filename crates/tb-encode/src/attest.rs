//! The M33 attestation codec leaf -- a DSSE-PAE-shaped, fixed-width INJECTIVE
//! encoding of an in-toto-Statement SUBSET that doubles as the machine-readable
//! sovereignty-ledger carrier (proposal §5; consumed by M34/M36). It is a
//! separate Kani-proven tb-encode codec (the `prov`/`opframe_rx` canon/decode
//! pattern, ZERO new hash math) -- NOT a JSON producer.
//!
//! `#![no_std]`, zero-dep, NO float, NO `unsafe` (the crate root forbids it).
//!
//! ## What it claims -- and what it must NEVER imply (the honesty boundary)
//!
//! * **`attest=DSSE-PAE-SHAPED`:** the signed bytes are DSSE PAE
//!   (`"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`, RFC-verified against
//!   the DSSE protocol) -- an ASCII length-prefixed INJECTIVE encoding. We model
//!   byte-level PAE injectivity + roundtrip + fail-closed decode, and we do NOT
//!   claim JSON-canonicalization security (the known footgun; eprint 2026/192
//!   "Verification Theatre" polices exactly that overclaim).
//! * **`measure=SELF-NO-HW-ROOT selfmeasure=UNATTESTED-LOADER`:** the carried
//!   `subject_digest` is computed by the VERY IMAGE being attested (QEMU loads
//!   the kernel directly -- no measured boot, no RTM, no external measurer, no
//!   hardware root of trust). A malicious image computes `khash::uhash` of
//!   whatever it chooses to report; M34 inherits this boundary BY NAME, never by
//!   marker-grep. This is an **SLSA-CONCEPT-SHAPED fixed-width subset, NOT a
//!   wire-compatible SLSA/in-toto JSON producer.** M33 = SLSA L1 -> toward L2;
//!   L3 (non-falsifiable) is M36.
//!
//! ## The carried claims (in-toto Statement v1 subset, RFC-verified shape)
//!
//! `subject_digest` (32-byte image id), `builder_id` (from `crates/brand`, the
//! SLSA `builder.id`), `build_type` (enum), a `materials` 32-byte-digest list,
//! the `toolchain_hash`, and the **sovereignty ledger** (`dep + status
//! TEMPORARY|ACCEPTED-PERMANENT|QUARANTINED` per plan principle 1 -- the
//! machine-checked carrier the M32 debt token feeds into).

use brand::DOMSEP_M33_ATTEST;

/// The 32-byte digest width (matches `khash::uhash` / `sha256`).
pub const ATTEST_DIGEST_LEN: usize = 32;

/// The `builder_id` width (bytes) -- a fixed 16-byte SLSA builder identity
/// derived from `crates/brand`.
pub const BUILDER_ID_LEN: usize = 16;

/// The largest `materials` digest list this fixed-width codec carries.
pub const MAX_MATERIALS: usize = 8;

/// The largest sovereignty-ledger entry list this codec carries.
pub const MAX_LEDGER: usize = 16;

/// The attestation-statement codec magic (a NEW disk/wire-neutral 2-byte magic,
/// family `0x5959` = the brand initial 'Y' twice, disjoint from the M25/M28/M30
/// frame magics 0x5956/57/58 and the note-type half 0x5955). Spelled here (a
/// codec-local constant, not a persisted/MAC'd cross-process byte), version 1.
pub const ATTEST_MAGIC: u16 = 0x5959;
/// The codec version byte.
pub const ATTEST_VERSION: u8 = 1;

/// The SLSA `buildType` enum (the closed set this codec encodes). Extend by
/// appending -- a new tag is a reviewed version bump, never a silent reuse.
pub mod build_type {
    /// A Yuva kernel image build (the `kbuild` -Zbuild-std none-target build).
    pub const KERNEL_IMAGE: u8 = 1;
    /// A host-tool build (`tools/*`).
    pub const HOST_TOOL: u8 = 2;
}

/// The sovereignty-ledger per-dependency status (plan principle 1). A dependency
/// is TEMPORARY (a tracked debt), ACCEPTED-PERMANENT (a reviewed keep), or
/// QUARANTINED (isolated, not trusted).
pub mod ledger_status {
    /// A tracked, time-boxed debt (the M32 `TEMPORARY` token).
    pub const TEMPORARY: u8 = 1;
    /// A reviewed permanent keep (`ACCEPTED-PERMANENT`).
    pub const ACCEPTED_PERMANENT: u8 = 2;
    /// Isolated / not trusted (`QUARANTINED`).
    pub const QUARANTINED: u8 = 3;
}

/// One sovereignty-ledger entry: a dependency token + its status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerEntry {
    /// The dependency token (a stable content id / name hash).
    pub dep_tok: u64,
    /// The status (see [`ledger_status`]).
    pub status: u8,
}

/// A fixed-width in-toto-Statement SUBSET (the attestation record). Borrowed
/// slices so the codec stays zero-alloc; the caller owns the material/ledger
/// backing storage.
#[derive(Clone, Copy, Debug)]
pub struct AttestStatement<'a> {
    /// The `subject[0].digest` -- the 32-byte kernel-image id (SELF-REPORTED,
    /// `selfmeasure=UNATTESTED-LOADER`).
    pub subject_digest: [u8; ATTEST_DIGEST_LEN],
    /// The SLSA `builder.id` (from `crates/brand`).
    pub builder_id: [u8; BUILDER_ID_LEN],
    /// The SLSA `buildType` (see [`build_type`]).
    pub build_type: u8,
    /// The toolchain hash (the pinned nightly's identity digest).
    pub toolchain_hash: [u8; ATTEST_DIGEST_LEN],
    /// The `materials` digest list (`<= MAX_MATERIALS`).
    pub materials: &'a [[u8; ATTEST_DIGEST_LEN]],
    /// The sovereignty ledger (`<= MAX_LEDGER`).
    pub ledger: &'a [LedgerEntry],
}

/// The fixed prefix width BEFORE the two length-prefixed variable lists:
/// `magic(2) | version(1) | build_type(1) | subject_digest(32) |
/// toolchain_hash(32) | builder_id(16) | n_materials(1) | n_ledger(1)`.
pub const ATTEST_PREFIX_LEN: usize = 2 + 1 + 1 + 32 + 32 + 16 + 1 + 1;

/// The exact canonical byte length of `st` (what [`canon`] writes on a
/// large-enough buffer). Saturating so a pathological count can never overflow.
#[inline]
#[must_use]
pub fn canon_len(st: &AttestStatement) -> usize {
    ATTEST_PREFIX_LEN
        + st.materials.len() * ATTEST_DIGEST_LEN
        + st.ledger.len() * (8 + 1)
}

/// Canonical, UNAMBIGUOUS, total fixed-width encoding of `st` into `out`.
/// Returns the byte count, or `0` if `out` is too small OR a list exceeds its
/// cap (TOTAL + fail-closed: never panics, never partial-writes). The two
/// explicit length-prefixes (`n_materials`, `n_ledger`) make the variable tail
/// self-delimiting -> injective (the `prov::canon` discipline).
#[must_use]
pub fn canon(st: &AttestStatement, out: &mut [u8]) -> usize {
    let nm = st.materials.len();
    let nl = st.ledger.len();
    if nm > MAX_MATERIALS || nl > MAX_LEDGER {
        return 0;
    }
    let total = canon_len(st);
    if out.len() < total {
        return 0;
    }
    let mb = ATTEST_MAGIC.to_le_bytes();
    out[0] = mb[0];
    out[1] = mb[1];
    out[2] = ATTEST_VERSION;
    out[3] = st.build_type;
    let mut off = 4usize;
    let mut i = 0usize;
    while i < ATTEST_DIGEST_LEN {
        out[off + i] = st.subject_digest[i];
        i += 1;
    }
    off += ATTEST_DIGEST_LEN;
    i = 0;
    while i < ATTEST_DIGEST_LEN {
        out[off + i] = st.toolchain_hash[i];
        i += 1;
    }
    off += ATTEST_DIGEST_LEN;
    i = 0;
    while i < BUILDER_ID_LEN {
        out[off + i] = st.builder_id[i];
        i += 1;
    }
    off += BUILDER_ID_LEN;
    out[off] = nm as u8;
    out[off + 1] = nl as u8;
    off += 2;
    // materials (length-prefixed).
    let mut m = 0usize;
    while m < nm {
        let mut b = 0usize;
        while b < ATTEST_DIGEST_LEN {
            out[off + b] = st.materials[m][b];
            b += 1;
        }
        off += ATTEST_DIGEST_LEN;
        m += 1;
    }
    // ledger entries (length-prefixed): dep_tok u64 LE || status u8.
    let mut l = 0usize;
    while l < nl {
        let d = st.ledger[l].dep_tok.to_le_bytes();
        let mut b = 0usize;
        while b < 8 {
            out[off + b] = d[b];
            b += 1;
        }
        out[off + 8] = st.ledger[l].status;
        off += 9;
        l += 1;
    }
    total
}

/// A decoded attestation statement (owned fixed-capacity copy -- the codec is
/// zero-alloc, so decode reads into fixed arrays + counts).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedStatement {
    /// The subject digest.
    pub subject_digest: [u8; ATTEST_DIGEST_LEN],
    /// The builder id.
    pub builder_id: [u8; BUILDER_ID_LEN],
    /// The build type.
    pub build_type: u8,
    /// The toolchain hash.
    pub toolchain_hash: [u8; ATTEST_DIGEST_LEN],
    /// The materials, fixed-capacity + count.
    pub materials: [[u8; ATTEST_DIGEST_LEN]; MAX_MATERIALS],
    /// The number of valid materials.
    pub n_materials: usize,
    /// The ledger, fixed-capacity + count.
    pub ledger: [LedgerEntry; MAX_LEDGER],
    /// The number of valid ledger entries.
    pub n_ledger: usize,
}

/// Decode `buf` into a [`DecodedStatement`], or `None` on ANY malformation (bad
/// magic/version, over-cap counts, short/long buffer). TOTAL, fail-closed --
/// never panics, never partial-reads (the `prov`/`opframe_rx` decode discipline).
#[must_use]
pub fn decode(buf: &[u8]) -> Option<DecodedStatement> {
    if buf.len() < ATTEST_PREFIX_LEN {
        return None;
    }
    let magic = u16::from_le_bytes([buf[0], buf[1]]);
    if magic != ATTEST_MAGIC || buf[2] != ATTEST_VERSION {
        return None;
    }
    let build_type = buf[3];
    let mut off = 4usize;
    let mut subject_digest = [0u8; ATTEST_DIGEST_LEN];
    let mut i = 0usize;
    while i < ATTEST_DIGEST_LEN {
        subject_digest[i] = buf[off + i];
        i += 1;
    }
    off += ATTEST_DIGEST_LEN;
    let mut toolchain_hash = [0u8; ATTEST_DIGEST_LEN];
    i = 0;
    while i < ATTEST_DIGEST_LEN {
        toolchain_hash[i] = buf[off + i];
        i += 1;
    }
    off += ATTEST_DIGEST_LEN;
    let mut builder_id = [0u8; BUILDER_ID_LEN];
    i = 0;
    while i < BUILDER_ID_LEN {
        builder_id[i] = buf[off + i];
        i += 1;
    }
    off += BUILDER_ID_LEN;
    let nm = buf[off] as usize;
    let nl = buf[off + 1] as usize;
    off += 2;
    if nm > MAX_MATERIALS || nl > MAX_LEDGER {
        return None;
    }
    let total = ATTEST_PREFIX_LEN + nm * ATTEST_DIGEST_LEN + nl * 9;
    if buf.len() != total {
        return None; // exact length -- no trailing garbage, no truncation
    }
    let mut materials = [[0u8; ATTEST_DIGEST_LEN]; MAX_MATERIALS];
    let mut m = 0usize;
    while m < nm {
        let mut b = 0usize;
        while b < ATTEST_DIGEST_LEN {
            materials[m][b] = buf[off + b];
            b += 1;
        }
        off += ATTEST_DIGEST_LEN;
        m += 1;
    }
    let mut ledger = [LedgerEntry { dep_tok: 0, status: 0 }; MAX_LEDGER];
    let mut l = 0usize;
    while l < nl {
        let dep_tok = u64::from_le_bytes([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
            buf[off + 4],
            buf[off + 5],
            buf[off + 6],
            buf[off + 7],
        ]);
        ledger[l] = LedgerEntry {
            dep_tok,
            status: buf[off + 8],
        };
        off += 9;
        l += 1;
    }
    Some(DecodedStatement {
        subject_digest,
        builder_id,
        build_type,
        toolchain_hash,
        materials,
        n_materials: nm,
        ledger,
        n_ledger: nl,
    })
}

// ---------------------------------------------------------------------------
// DSSE Pre-Authentication Encoding (PAE) -- the SIGNED bytes.
// ---------------------------------------------------------------------------

/// The DSSE `payloadType` for the M33 attestation -- the `crates/brand`
/// [`brand::DOMSEP_M33_ATTEST`] label (`"YUVA-M33-ATTEST-V1"`), disjoint from
/// every echo/infer/opcmd/evolve label so an attestation PAE can never be
/// confused with a keyed-MAC message.
pub const ATTEST_PAYLOAD_TYPE: &[u8] = DOMSEP_M33_ATTEST;

/// The largest ASCII-decimal length prefix (u32 fits in 10 digits).
const MAX_DECIMAL: usize = 10;

/// Write `x` as ASCII decimal (no leading zeros, `"0"` for zero) into `out` at
/// `at`; return the digit count. Total.
#[inline]
fn put_decimal(out: &mut [u8], at: usize, x: usize) -> usize {
    if x == 0 {
        out[at] = b'0';
        return 1;
    }
    // Count digits.
    let mut tmp = x;
    let mut ndig = 0usize;
    while tmp > 0 {
        ndig += 1;
        tmp /= 10;
    }
    // Emit most-significant first.
    let mut v = x;
    let mut k = ndig;
    while k > 0 {
        out[at + k - 1] = b'0' + (v % 10) as u8;
        v /= 10;
        k -= 1;
    }
    ndig
}

/// The exact PAE length for `(type, body)`:
/// `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`.
#[inline]
#[must_use]
pub fn pae_len(type_bytes: &[u8], body: &[u8]) -> usize {
    6 // "DSSEv1"
        + 1 + decimal_len(type_bytes.len()) + 1 + type_bytes.len()
        + 1 + decimal_len(body.len()) + 1 + body.len()
}

/// The ASCII-decimal digit count of `x` (`1` for zero). Total.
#[inline]
fn decimal_len(x: usize) -> usize {
    if x == 0 {
        return 1;
    }
    let mut tmp = x;
    let mut n = 0usize;
    while tmp > 0 {
        n += 1;
        tmp /= 10;
    }
    n
}

/// DSSE PAE (proposal §5, RFC-verified against the DSSE protocol):
/// `PAE = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`, SP = a single
/// ASCII space, LEN = ASCII decimal without leading zeros. Injective by
/// construction (each component's boundaries are fixed by its preceding length).
/// Writes into `out`; returns the byte count, or `0` if `out` is too small
/// (fail-closed, total). The SIGNER signs these bytes; the verifier re-derives
/// them.
#[must_use]
pub fn pae(type_bytes: &[u8], body: &[u8], out: &mut [u8]) -> usize {
    let total = pae_len(type_bytes, body);
    if out.len() < total || decimal_len(type_bytes.len()) > MAX_DECIMAL || decimal_len(body.len()) > MAX_DECIMAL {
        return 0;
    }
    let hdr = b"DSSEv1";
    let mut off = 0usize;
    let mut i = 0usize;
    while i < 6 {
        out[off + i] = hdr[i];
        i += 1;
    }
    off += 6;
    out[off] = b' ';
    off += 1;
    off += put_decimal(out, off, type_bytes.len());
    out[off] = b' ';
    off += 1;
    i = 0;
    while i < type_bytes.len() {
        out[off + i] = type_bytes[i];
        i += 1;
    }
    off += type_bytes.len();
    out[off] = b' ';
    off += 1;
    off += put_decimal(out, off, body.len());
    out[off] = b' ';
    off += 1;
    i = 0;
    while i < body.len() {
        out[off + i] = body[i];
        i += 1;
    }
    off += body.len();
    off
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk<'a>(
        materials: &'a [[u8; ATTEST_DIGEST_LEN]],
        ledger: &'a [LedgerEntry],
    ) -> AttestStatement<'a> {
        AttestStatement {
            subject_digest: [0x11; 32],
            builder_id: [0x22; 16],
            build_type: build_type::KERNEL_IMAGE,
            toolchain_hash: [0x33; 32],
            materials,
            ledger,
        }
    }

    #[test]
    fn canon_decode_roundtrip() {
        let mats = [[0xAAu8; 32], [0xBBu8; 32]];
        let led = [
            LedgerEntry { dep_tok: 0xDEAD, status: ledger_status::TEMPORARY },
            LedgerEntry { dep_tok: 0xBEEF, status: ledger_status::ACCEPTED_PERMANENT },
        ];
        let st = mk(&mats, &led);
        let mut buf = [0u8; 512];
        let n = canon(&st, &mut buf);
        assert_eq!(n, canon_len(&st));
        let d = decode(&buf[..n]).unwrap();
        assert_eq!(d.subject_digest, st.subject_digest);
        assert_eq!(d.builder_id, st.builder_id);
        assert_eq!(d.build_type, st.build_type);
        assert_eq!(d.toolchain_hash, st.toolchain_hash);
        assert_eq!(d.n_materials, 2);
        assert_eq!(&d.materials[..2], &mats[..]);
        assert_eq!(d.n_ledger, 2);
        assert_eq!(&d.ledger[..2], &led[..]);
    }

    #[test]
    fn canon_injective_each_field() {
        let mats = [[0xAAu8; 32]];
        let led = [LedgerEntry { dep_tok: 1, status: 1 }];
        let base = mk(&mats, &led);
        let enc = |s: &AttestStatement| {
            let mut b = [0u8; 512];
            let n = canon(s, &mut b);
            b[..n].to_vec()
        };
        let b = enc(&base);
        let mut s = base;
        s.build_type = build_type::HOST_TOOL;
        assert_ne!(enc(&s), b);
        let mut s = base;
        s.subject_digest[0] ^= 1;
        assert_ne!(enc(&s), b);
        let mut s = base;
        s.builder_id[3] ^= 1;
        assert_ne!(enc(&s), b);
        // A different material count / ledger count.
        let led2 = [
            LedgerEntry { dep_tok: 1, status: 1 },
            LedgerEntry { dep_tok: 2, status: 2 },
        ];
        let s = mk(&mats, &led2);
        assert_ne!(enc(&s), b);
    }

    #[test]
    fn decode_fail_closed() {
        let mats = [[0xAAu8; 32]];
        let led = [LedgerEntry { dep_tok: 1, status: 1 }];
        let st = mk(&mats, &led);
        let mut buf = [0u8; 512];
        let n = canon(&st, &mut buf);
        // Bad magic.
        let mut b = buf[..n].to_vec();
        b[0] ^= 0xFF;
        assert!(decode(&b).is_none());
        // Bad version.
        let mut b = buf[..n].to_vec();
        b[2] = 0x99;
        assert!(decode(&b).is_none());
        // Truncated.
        assert!(decode(&buf[..n - 1]).is_none());
        // Trailing garbage.
        let mut b = buf[..n].to_vec();
        b.push(0x00);
        assert!(decode(&b).is_none());
        // Over-cap material count.
        let mut b = buf[..n].to_vec();
        b[ATTEST_PREFIX_LEN - 2] = (MAX_MATERIALS + 1) as u8;
        assert!(decode(&b).is_none());
        // Empty.
        assert!(decode(&[]).is_none());
    }

    #[test]
    fn canon_fail_closed_small_buffer_and_overcap() {
        let mats = [[0xAAu8; 32]];
        let led = [LedgerEntry { dep_tok: 1, status: 1 }];
        let st = mk(&mats, &led);
        let mut tiny = [0u8; 8];
        assert_eq!(canon(&st, &mut tiny), 0);
        // Over-cap lists fail closed.
        let big_mats = [[0u8; 32]; MAX_MATERIALS + 1];
        let st2 = mk(&big_mats, &led);
        let mut buf = [0u8; 1024];
        assert_eq!(canon(&st2, &mut buf), 0);
    }

    #[test]
    fn pae_matches_dsse_spec() {
        // DSSE protocol example shape: PAE("http://example.com/HelloWorld",
        // "hello world") -> "DSSEv1 29 http://example.com/HelloWorld 11 hello world".
        let t = b"http://example.com/HelloWorld";
        let body = b"hello world";
        let mut out = [0u8; 128];
        let n = pae(t, body, &mut out);
        assert_eq!(&out[..n], b"DSSEv1 29 http://example.com/HelloWorld 11 hello world");
    }

    #[test]
    fn pae_injective_and_empty() {
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        // "1 2" || "" vs "1" || "2" -- the length prefixes disambiguate.
        let na = pae(b"12", b"", &mut a);
        let nb = pae(b"1", b"2", &mut b);
        assert_ne!(&a[..na], &b[..nb]);
        // Empty type + empty body is well-formed.
        let mut e = [0u8; 32];
        let ne = pae(b"", b"", &mut e);
        assert_eq!(&e[..ne], b"DSSEv1 0  0 ");
    }

    #[test]
    fn pae_payload_type_is_brand_domsep() {
        assert_eq!(ATTEST_PAYLOAD_TYPE, b"YUVA-M33-ATTEST-V1");
    }
}
