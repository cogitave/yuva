//! The M33 verified LMS signature VERIFY leaf -- RFC 8554 "Leighton-Micali
//! Hash-Based Signatures", LM-OTS parameter set `LMOTS_SHA256_N32_W4` over an
//! `LMS_SHA256_M32_H10` Merkle tree (the operational set; `W8`/`H5` also parse,
//! for the official RFC 8554 Appendix F conformance vector). VERIFY ONLY -- the
//! kernel holds the 32-byte public root and this routine; signing + the
//! never-reuse leaf-index state live host/operator-side (`tools/prov-signer`,
//! the cfg-gated [`signer`] module below), NEVER in the kernel TCB (proposal
//! §2, the VERIFY/SIGN split).
//!
//! `#![no_std]`, zero-dep, NO float, NO `unsafe` (the crate root forbids it).
//! The hash is [`crate::sha256`] (SHA-256), NOT the house [`crate::khash`]
//! BLAKE2s -- RFC 8554 PINS SHA-256 and the `conformance=RFC8554` claim depends
//! on it (proposal §4, decision D2). A pure hash chain: the whole reason LMS was
//! chosen over Ed25519/P-256, whose `2^255-19` field arithmetic is the
//! documented CBMC SAT-explosion case and is Kani-INFEASIBLE (proposal §1.1).
//!
//! ## The value proposition (what M33 buys over M29)
//!
//! M29 made the prov head a keyed MAC -- tamper-evident, but SYMMETRIC: anyone
//! holding K can mint a head (PARTICIPATION). LMS adds public-verify /
//! private-sign ASYMMETRY: the public root is a 32-byte image constant, the
//! private key never enters the kernel, so only the signing-key holder can
//! extend the signed head and ANY party verifies with only the root
//! (EXCLUSIVITY). A signature proves exclusivity against parties OUTSIDE the
//! signing host and **nothing** against the host holding the key
//! (`exclusivity=OFF-PLATFORM-ONLY`, the central honesty token -- never buried).
//!
//! ## Honest scope (identical claim tier to [`crate::khash`], proposal §9)
//!
//! * **PROVEN (Kani toy instance + Miri + host tests + the in-boot KAT):**
//!   totality / panic-freedom / determinism of `lms_verify`, and
//!   tamper-sensitivity (the pinned-vector iff -- a genuine signature verifies,
//!   a one-byte flip in the OTS-signature region OR the Merkle-auth-path region
//!   is rejected). Full-parameter (W4/H10) correctness is host `cargo test` +
//!   the in-boot SMALL-parameter roundtrip KAT (a full-param verify is ~1062
//!   SHA-256 compressions -- infeasible in CBMC AND against the 90s aarch64 boot
//!   ceiling, so the Kani obligation is a `w=1` toy and the boot KAT is small).
//! * **ASSUMED-FROM-LITERATURE (NEVER proven):** LMS EUF-CMA unforgeability +
//!   SHA-256 2nd-preimage/collision resistance. No symbolic-EUF-CMA harness
//!   exists -- overclaim-by-implication, banned exactly as khash bans the
//!   symbolic-collision harness (`sec=ASSUMED-FROM-LITERATURE`).
//! * **`splitview=UNDETECTED-NO-WITNESS-QUORUM`:** a single signer signing two
//!   divergent heads is undetectable without an external witness/gossip quorum
//!   (RFC 6962; a named successor, not an M33 claim).
//! * **`sidechannel=NOT-CLAIMED`:** verification is over PUBLIC data; the
//!   data-dependent branches are not timing-analyzed (informational residual).
//!
//! ## Numeric format (RFC 8554 §3.1: BIG-ENDIAN, no float)
//!
//! `u32str`/`u16str`/`u8str` are network-byte-order (big-endian) integer
//! encodings; `coef(S,i,w)` extracts the i-th w-bit field big-endian. Pure
//! integer/byte arithmetic, zero alloc in the verify path, fixed-size buffers.

use crate::sha256::{Sha256, SHA256_DIGEST_LEN as N};

/// The SHA-256 digest / LMS node width (bytes). RFC 8554 pins `n = m = 32`.
pub const LMS_NODE_LEN: usize = N; // 32

/// The RFC 8554 §16 identifier `I` width (bytes). RFC pins a 16-byte `I` (the
/// "23+n = 55-byte, one-compression" chain-input arithmetic of the proposal §2
/// depends on `I=16`; the sketch's `[u8;4]` contradicted that arithmetic and is
/// superseded -- conformance=RFC8554 REQUIRES the 16-byte `I`).
pub const LMS_I_LEN: usize = 16;

/// The largest LM-OTS `p` (chain-element count) this leaf supports: `W4` p=67
/// (RFC 8554 Table 1). `W8` (p=34) also fits; `W1`/`W2` (p=265/133) are NOT
/// supported by the standard dispatch (they blow the fixed buffers and are not
/// used -- fail-closed). The `w=1` TOY instance (Kani/boot KAT) uses a small
/// explicit `p` via [`ots_kc`] directly, never this dispatch.
const MAX_P: usize = 67;

/// The largest LMS tree height supported: `H10` (RFC 8554 Table 2). `H5` fits.
const MAX_H: usize = 10;

/// The message-length cap for the D_MESG hash input buffer (the M33 signed
/// message is a 32-byte prov head; RFC 8554 Appendix F vectors are short). A
/// longer message fails closed to `false` -- never a panic, never a partial
/// hash (the fixed-buffer, no-alloc, no-streaming discipline).
const MSG_CAP: usize = 256;

// RFC 8554 §4.1 / §5.1 IANA type codes (the values embedded in a signature).
/// `LMOTS_SHA256_N32_W4` (RFC 8554 Table 1, numeric id 0x03) -- the operational
/// parameter set (w=4, p=67, ls=4).
pub const LMOTS_SHA256_N32_W4: u32 = 0x0000_0003;
/// `LMOTS_SHA256_N32_W8` (RFC 8554 Table 1, numeric id 0x04) -- the official
/// Appendix F Test Case 1 vector's parameter set (w=8, p=34, ls=0).
pub const LMOTS_SHA256_N32_W8: u32 = 0x0000_0004;
/// `LMS_SHA256_M32_H5` (RFC 8554 Table 2, numeric id 0x05).
pub const LMS_SHA256_M32_H5: u32 = 0x0000_0005;
/// `LMS_SHA256_M32_H10` (RFC 8554 Table 2, numeric id 0x06) -- the operational
/// tree height.
pub const LMS_SHA256_M32_H10: u32 = 0x0000_0006;

// RFC 8554 §7.1 domain separators (the 16-bit prefixes that keep the four hash
// uses disjoint -- a leaf can never be confused with an interior node, etc.).
const D_PBLC: u16 = 0x8080; // LM-OTS public-key hash
const D_MESG: u16 = 0x8181; // LM-OTS message hash
const D_LEAF: u16 = 0x8282; // LMS tree leaf hash
const D_INTR: u16 = 0x8383; // LMS tree interior-node hash

/// The LM-OTS parameters `(w, p, ls)` for a type code, or `None` if unsupported
/// by this leaf's fixed buffers (`W1`/`W2` fail closed). Total.
#[inline]
fn ots_params(otstype: u32) -> Option<(u32, usize, u32)> {
    match otstype {
        LMOTS_SHA256_N32_W4 => Some((4, 67, 4)), // 0x03: w=4, p=67, ls=4
        LMOTS_SHA256_N32_W8 => Some((8, 34, 0)), // 0x04: w=8, p=34, ls=0
        _ => None,
    }
}

/// The LMS tree height for a type code, or `None` if unsupported. Total.
#[inline]
fn lms_height(lmstype: u32) -> Option<u32> {
    match lmstype {
        LMS_SHA256_M32_H5 => Some(5),
        LMS_SHA256_M32_H10 => Some(10),
        _ => None,
    }
}

/// RFC 8554 §3.1.3 `coef(S, i, w)`: the i-th `w`-bit field of `S`, big-endian.
/// `w` is one of {1,2,4,8}; the shift is `8 - (w*(i mod (8/w)) + w)`. Total (a
/// caller passing an out-of-range `i` would index past `S`; every internal
/// caller stays in range by construction, and the fixed-buffer bound guards it).
#[inline]
fn coef(s: &[u8], i: usize, w: u32) -> u32 {
    let per_byte = (8 / w) as usize; // fields per byte: 8/w
    let byte = s[(i * w as usize) / 8];
    let shift = 8u32 - (w * ((i % per_byte) as u32) + w);
    let mask = (1u32 << w) - 1;
    (byte as u32 >> shift) & mask
}

/// RFC 8554 §4.4 checksum `Cksm(Q)`: `sum_{i=0}^{u-1} (2^w-1 - coef(Q,i,w))`
/// left-shifted by `ls`, as a u16. `u = 8n/w` message coefficients. Total.
#[inline]
fn cksm(q: &[u8; N], w: u32, ls: u32) -> u16 {
    let u = (8 * N) / (w as usize); // message coefficients
    let maxc = (1u32 << w) - 1;
    let mut sum: u32 = 0;
    let mut i = 0usize;
    while i < u {
        sum = sum.wrapping_add(maxc - coef(q, i, w));
        i += 1;
    }
    ((sum << ls) & 0xFFFF) as u16
}

/// Write `u32str(x)` (big-endian) into `buf[at..at+4]`. Total (caller sizes).
/// Used only by the cfg-gated signer (the verify path streams via
/// `Sha256::update(&x.to_be_bytes())`).
#[cfg(any(test, feature = "signer"))]
#[inline]
fn put_u32(buf: &mut [u8], at: usize, x: u32) {
    let b = x.to_be_bytes();
    buf[at] = b[0];
    buf[at + 1] = b[1];
    buf[at + 2] = b[2];
    buf[at + 3] = b[3];
}

/// Write `u16str(x)` (big-endian) into `buf[at..at+2]`. Total. Used only by the
/// cfg-gated signer (the verify path streams).
#[cfg(any(test, feature = "signer"))]
#[inline]
fn put_u16(buf: &mut [u8], at: usize, x: u16) {
    let b = x.to_be_bytes();
    buf[at] = b[0];
    buf[at + 1] = b[1];
}

/// RFC 8554 §4.5 Algorithm 4b: compute the LM-OTS public-key CANDIDATE `Kc`
/// from a signature `(c, y[0..p])` over `msg`, under identifier `i_id` and leaf
/// index `q`, with parameters `(w, p, ls)`. Writes the 32-byte candidate into
/// `out`; returns `false` (fail-closed, no panic) if `msg` exceeds [`MSG_CAP`]
/// or `p > MAX_P`. Each chain-step / the D_MESG and D_PBLC hashes are one
/// SHA-256 compression (the sub-64-byte input, RFC-exact).
///
/// This is called BOTH by the standard [`lms_verify`] dispatch (with W4/W8
/// params) AND directly by the Kani toy harness / the boot KAT (with `w=1`,
/// small `p`), so the parameters are explicit, never type-code-derived here.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn ots_kc(
    i_id: &[u8; LMS_I_LEN],
    q: u32,
    w: u32,
    p: usize,
    ls: u32,
    c: &[u8; N],
    y: &[[u8; N]],
    msg: &[u8],
    out: &mut [u8; N],
) -> bool {
    if p > MAX_P || p == 0 || y.len() < p || msg.len() > MSG_CAP {
        return false;
    }
    // Q = H(I || u32str(q) || u16str(D_MESG) || C || message) -- STREAMED, so no
    // large intermediate buffer (the CBMC-tractability fix, proposal §9).
    let qbe = q.to_be_bytes();
    let mut hq = Sha256::new();
    hq.update(i_id);
    hq.update(&qbe);
    hq.update(&D_MESG.to_be_bytes());
    hq.update(c);
    hq.update(msg);
    let qhash = hq.finalize();

    // The coefficient string is Q || u16str(Cksm(Q)); coef() reads it directly.
    let ck = cksm(&qhash, w, ls);
    let mut qc = [0u8; N + 2];
    let mut j = 0usize;
    while j < N {
        qc[j] = qhash[j];
        j += 1;
    }
    let ckb = ck.to_be_bytes();
    qc[N] = ckb[0];
    qc[N + 1] = ckb[1];

    // z[i] = complete the i-th Winternitz chain from y[i] up to 2^w-1; then
    // Kc = H(I || u32str(q) || u16str(D_PBLC) || z[0] || ... || z[p-1]) -- the
    // D_PBLC hash STREAMED so the p*32-byte concatenation is never materialized.
    let mut hk = Sha256::new();
    hk.update(i_id);
    hk.update(&qbe);
    hk.update(&D_PBLC.to_be_bytes());

    let maxj = (1u32 << w) - 1; // 2^w - 1
    let mut i = 0usize;
    while i < p {
        let a = coef(&qc, i, w);
        let ibe = (i as u16).to_be_bytes();
        // tmp = y[i]; for j = a .. 2^w-1: tmp = H(I||q||u16(i)||u8(j)||tmp).
        let mut tmp = y[i];
        let mut jj = a;
        while jj < maxj {
            let mut hc = Sha256::new();
            hc.update(i_id);
            hc.update(&qbe);
            hc.update(&ibe);
            hc.update(&[jj as u8]); // u8str(j)
            hc.update(&tmp);
            tmp = hc.finalize();
            jj += 1;
        }
        hk.update(&tmp); // append z[i]
        i += 1;
    }
    let kc = hk.finalize();
    let mut b = 0usize;
    while b < N {
        out[b] = kc[b];
        b += 1;
    }
    true
}

/// RFC 8554 §5.4.2 Algorithm 6a (the Merkle leg): recompute the tree root from
/// the LM-OTS public-key candidate `kc` at leaf `q`, walking the `h`-node
/// authentication `path` up to the root. Structurally the `prov::verify_inclusion`
/// fold -- accepted iff it lands on the committed value -- so #75's future
/// balanced-batch-Merkle upgrade swaps only this path-walk shape, not the verify
/// contract. Returns the candidate root `Tc`. Total (no panic; `path.len() >= h`
/// and `h <= MAX_H` guarded by the caller). `pub` so the `kani_lms_merklepath`
/// harness can exercise the Merkle leg directly at the toy height.
#[inline]
#[must_use]
pub fn lms_root(i_id: &[u8; LMS_I_LEN], q: u32, h: u32, kc: &[u8; N], path: &[[u8; N]]) -> [u8; N] {
    // node_num = 2^h + q; tmp = H(I || u32str(node_num) || u16str(D_LEAF) || Kc)
    // -- all hashes STREAMED (no intermediate buffer, the CBMC-tractability fix).
    let mut node_num: u32 = (1u32 << h) + q;
    let mut hl = Sha256::new();
    hl.update(i_id);
    hl.update(&node_num.to_be_bytes());
    hl.update(&D_LEAF.to_be_bytes());
    hl.update(kc);
    let mut tmp = hl.finalize();

    // Walk the auth path. At each level: interior = H(I || u32str(node_num/2) ||
    // u16str(D_INTR) || (odd ? path||tmp : tmp||path)).
    let mut i = 0usize;
    while node_num > 1 {
        let mut hi = Sha256::new();
        hi.update(i_id);
        hi.update(&(node_num / 2).to_be_bytes());
        hi.update(&D_INTR.to_be_bytes());
        let sib = path[i];
        if node_num & 1 == 1 {
            hi.update(&sib); // odd: path[i] || tmp
            hi.update(&tmp);
        } else {
            hi.update(&tmp); // even: tmp || path[i]
            hi.update(&sib);
        }
        tmp = hi.finalize();
        node_num /= 2;
        i += 1;
    }
    tmp
}

/// Verify an LMS signature `sig` over `msg` against the 32-byte public `root`
/// (+ the 16-byte identifier `i_id`). TOTAL: fail-closed to `false` on ANY
/// malformed byte (bad type word, unsupported parameter set, wrong sig length,
/// short buffer, out-of-range leaf index) -- never panics, never allocates (the
/// `prov::verify_inclusion` canon discipline: bad input -> false).
///
/// The RFC 8554 §5.4.1 signature wire format parsed here:
/// `u32str(q) || u32str(otstype) || C || y[0..p] || u32str(lmstype) || path[0..h]`.
#[must_use]
pub fn lms_verify(root: &[u8; N], i_id: &[u8; LMS_I_LEN], msg: &[u8], sig: &[u8]) -> bool {
    // Minimum: q(4) + otstype(4) + C(32) + at least the lmstype after y.
    if sig.len() < 4 + 4 + N + 4 {
        return false;
    }
    // q is validated (against 2^h) inside lms_verify_params, which re-reads it.
    let otstype = u32::from_be_bytes([sig[4], sig[5], sig[6], sig[7]]);
    let (w, p, ls) = match ots_params(otstype) {
        Some(v) => v,
        None => return false,
    };
    // The lmstype sits AFTER the p-element y array; read it to get h.
    let lmstype_off = 8 + N + N * p;
    if sig.len() < lmstype_off + 4 {
        return false;
    }
    let lmstype = u32::from_be_bytes([
        sig[lmstype_off],
        sig[lmstype_off + 1],
        sig[lmstype_off + 2],
        sig[lmstype_off + 3],
    ]);
    let h = match lms_height(lmstype) {
        Some(v) => v,
        None => return false,
    };
    lms_verify_params(root, i_id, msg, sig, w, p, ls, h)
}

/// The parameter-EXPLICIT verify core, shared by the standard [`lms_verify`]
/// dispatch AND the `w=1` toy KAT / Kani harness (which use a non-standard
/// reduced instance whose wire type codes this function does NOT validate).
/// Parses `q` + the `(C, y[0..p], path[0..h])` slices from the EXPLICIT
/// `(w,p,ls,h)` layout, fail-closed on any bound violation, and accepts iff the
/// recomputed tree root equals `root`. TOTAL (no panic, no alloc).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn lms_verify_params(
    root: &[u8; N],
    i_id: &[u8; LMS_I_LEN],
    msg: &[u8],
    sig: &[u8],
    w: u32,
    p: usize,
    ls: u32,
    h: u32,
) -> bool {
    if p == 0 || p > MAX_P || (h as usize) > MAX_H || h == 0 {
        return false;
    }
    if sig.len() < 8 + N {
        return false;
    }
    let q = u32::from_be_bytes([sig[0], sig[1], sig[2], sig[3]]);
    if q >= (1u32 << h) {
        return false;
    }
    let c_off = 8;
    let y_off = c_off + N;
    let lmstype_off = y_off + N * p;
    let path_off = lmstype_off + 4;
    let total = path_off + N * (h as usize);
    if sig.len() != total {
        return false; // exact length -- no trailing garbage, no truncation
    }

    // Copy C, y[0..p], path[0..h] into fixed arrays.
    let mut c = [0u8; N];
    let mut b = 0usize;
    while b < N {
        c[b] = sig[c_off + b];
        b += 1;
    }
    let mut y = [[0u8; N]; MAX_P];
    let mut i = 0usize;
    while i < p {
        let base = y_off + i * N;
        let mut bb = 0usize;
        while bb < N {
            y[i][bb] = sig[base + bb];
            bb += 1;
        }
        i += 1;
    }
    let mut path = [[0u8; N]; MAX_H];
    i = 0;
    while i < h as usize {
        let base = path_off + i * N;
        let mut bb = 0usize;
        while bb < N {
            path[i][bb] = sig[base + bb];
            bb += 1;
        }
        i += 1;
    }

    // Recompute Kc, then the tree root, and accept iff it equals `root`.
    let mut kc = [0u8; N];
    if !ots_kc(i_id, q, w, p, ls, &c, &y[..p], msg, &mut kc) {
        return false;
    }
    let tc = lms_root(i_id, q, h, &kc, &path[..h as usize]);
    ct_eq(&tc, root)
}

// ===========================================================================
// The in-boot KAT (the small-parameter `w=1` toy roundtrip; proposal §4). The
// kernel VERIFIES a PINNED genuine toy signature through REAL SHA-256
// compressions and emits `kat=RFC8554-PASS` ONLY on success, PLUS two REGIONAL
// tamper controls (an OTS-region flip and a Merkle-auth-path flip, proposal §16
// must-fix #1) so a half-verifier that checks only one leg turns the boot RED.
// The pinned toy vectors are REGENERATED by the cfg-gated signer (the round-trip
// is host-test-reproduced in `toy_kat_vectors_are_signer_reproducible`), never a
// constant compared to itself. Full-parameter W4/H10 + the OFFICIAL RFC 8554
// Appendix F vector are the host `cargo test` KATs (`rfc8554_appendix_f_*`),
// NOT an every-boot cost (a full verify is ~1062 compressions vs the 90s
// aarch64 boot ceiling).
// ===========================================================================

/// The toy instance parameters `(w, p, ls, h)` -- a NON-STANDARD reduced LMS
/// (`p=2` is NOT the RFC W1 `p=265`) that exercises the verify STRUCTURE over
/// real SHA-256 at a khash-regime compression budget (~6-8 compressions).
pub const TOY_W: u32 = 1;
/// The toy chain-element count (2 -- small enough for the CBMC budget).
pub const TOY_P: usize = 2;
/// The toy Winternitz checksum left-shift (RFC 8554 `ls` for w=1).
pub const TOY_LS: u32 = 7;
/// The toy tree height (1 -- a single interior node).
pub const TOY_H: u32 = 1;

/// The toy identifier `I` (the pinned-vector generator's `I`).
pub const TOY_I: [u8; LMS_I_LEN] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
];

/// The toy signed message (1 byte -> the D_MESG hash is a single 55-byte block,
/// one compression).
pub const TOY_MSG: [u8; 1] = [0x33];

/// The PINNED toy public root `T[1]` (regenerated by the signer; the host test
/// `toy_kat_vectors_are_signer_reproducible` re-derives it, so it is never a
/// self-referential constant).
pub const TOY_ROOT: [u8; N] = [
    0x5d, 0xa0, 0x28, 0xeb, 0x55, 0x15, 0xed, 0xe1, 0xc3, 0x13, 0x1c, 0x63, 0x0f, 0xfa, 0xc6, 0x0f,
    0x8a, 0x37, 0x90, 0xe0, 0x0f, 0x2e, 0x6a, 0x84, 0x5a, 0xf4, 0x66, 0xa5, 0x43, 0x15, 0x0d, 0x13,
];

/// The PINNED toy signature (140 bytes: q(4), otstype(4), C(32), y[0..2](64),
/// lmstype(4), path[0..1](32)). The kernel verifies THIS against [`TOY_ROOT`]
/// every boot through real compressions.
pub const TOY_SIG: [u8; 140] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x84, 0x96, 0x92, 0x2b, 0x02, 0xf8, 0x10, 0x2b,
    0xdb, 0xd4, 0x91, 0x2e, 0xe6, 0xf5, 0xcf, 0xba, 0xf3, 0xfd, 0x03, 0x63, 0xa6, 0x82, 0x26, 0x5e,
    0xdd, 0x60, 0x67, 0x88, 0x5c, 0xd8, 0xdb, 0xf2, 0x2a, 0xe3, 0x93, 0x16, 0x2d, 0x55, 0xc2, 0x14,
    0x6e, 0xc3, 0xd6, 0x22, 0xf9, 0xed, 0x23, 0x4a, 0xe2, 0xde, 0x1e, 0x40, 0x14, 0xdb, 0x40, 0xc7,
    0x98, 0xe8, 0x27, 0x47, 0x8f, 0x4c, 0x95, 0x7c, 0xd9, 0xb6, 0x02, 0x7c, 0x48, 0xd8, 0xfe, 0x89,
    0x77, 0x27, 0xfe, 0xc7, 0xc6, 0x7f, 0x0b, 0xe1, 0xab, 0x03, 0xda, 0x4b, 0xaa, 0x26, 0x5a, 0xeb,
    0x53, 0xb3, 0xd8, 0x32, 0x9f, 0xd0, 0xf1, 0xd3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x65, 0x9c,
    0x0c, 0x44, 0x5a, 0xf4, 0xd0, 0x9b, 0x28, 0xf2, 0x7d, 0xc6, 0xa2, 0x48, 0x66, 0xe7, 0xa0, 0xd0,
    0x5b, 0x8d, 0xe3, 0x3b, 0xb6, 0x9b, 0xb5, 0x28, 0x78, 0x64, 0x36, 0x29,
];

/// A byte offset INSIDE the LM-OTS-signature region (the `C` randomizer) -- a
/// regional tamper control that a Merkle-only half-verifier cannot catch.
pub const TOY_TAMPER_OTS_OFF: usize = 8;
/// A byte offset INSIDE the Merkle auth-path region (`path[0]`) -- a regional
/// tamper control that an OTS-only half-verifier cannot catch.
pub const TOY_TAMPER_MERKLE_OFF: usize = 108;

/// The three in-boot KAT results (proposal §8 witness flags).
#[derive(Clone, Copy, Debug)]
pub struct LmsKat {
    /// The pinned genuine toy signature verifies against the pinned root.
    pub verified: bool,
    /// A one-byte flip in the OTS-signature region is rejected.
    pub tamper_ots_rejected: bool,
    /// A one-byte flip in the Merkle-auth-path region is rejected.
    pub tamper_merkle_rejected: bool,
}

/// Run the in-boot small-parameter roundtrip KAT (real SHA-256 compressions).
/// Total. Emits the three witness flags; `kat_ok` is their conjunction.
#[must_use]
pub fn kat() -> LmsKat {
    let verified = lms_verify_params(&TOY_ROOT, &TOY_I, &TOY_MSG, &TOY_SIG, TOY_W, TOY_P, TOY_LS, TOY_H);
    let mut ots = TOY_SIG;
    ots[TOY_TAMPER_OTS_OFF] ^= 0x01;
    let tamper_ots_rejected =
        !lms_verify_params(&TOY_ROOT, &TOY_I, &TOY_MSG, &ots, TOY_W, TOY_P, TOY_LS, TOY_H);
    let mut mrk = TOY_SIG;
    mrk[TOY_TAMPER_MERKLE_OFF] ^= 0x80;
    let tamper_merkle_rejected =
        !lms_verify_params(&TOY_ROOT, &TOY_I, &TOY_MSG, &mrk, TOY_W, TOY_P, TOY_LS, TOY_H);
    LmsKat {
        verified,
        tamper_ots_rejected,
        tamper_merkle_rejected,
    }
}

/// The fail-closed in-boot KAT conjunction: the genuine toy signature verifies
/// AND both regional tampers are rejected. The kernel emits `kat=RFC8554-PASS`
/// ONLY on `true`. Total.
#[must_use]
pub fn kat_ok() -> bool {
    let k = kat();
    k.verified && k.tamper_ots_rejected && k.tamper_merkle_rejected
}

/// Constant-time-SHAPED 32-byte equality (no early-out branch on the compared
/// bytes -- a code-shape property; the verify path is over PUBLIC data, so this
/// is informational, `sidechannel=NOT-CLAIMED`). Total.
#[inline]
fn ct_eq(a: &[u8; N], b: &[u8; N]) -> bool {
    let mut acc = 0u8;
    let mut i = 0usize;
    while i < N {
        acc |= a[i] ^ b[i];
        i += 1;
    }
    acc == 0
}

// The PINNED stage-B operational W4/H10 signed-head KAT vectors --
// REGENERATED by the signer (host test `prov_kat_vectors_are_signer_reproducible`),
// NEVER a self-referential constant. HEAD = sha256("YUVA-M33-stageB-prov-head")
// signed at leaf q=0 under the SIMULATED enrolled key (SIM seed 0x5A*32, I =
// TOY_I). The kernel persists + verifies THIS full-parameter signature across
// the two-boot reboot (proposal SS6/SS8); `state=SIMULATED-REUSE-OK-NO-SECURITY`.
/// The pinned stage-B signed prov head (32 bytes).
pub const PROV_KAT_HEAD: [u8; N] = [
    0x8d, 0x81, 0x20, 0xa9, 0x99, 0xa1, 0xdf, 0x98, 0xd7, 0x92, 0x6d, 0xe8, 0x1a, 0xc2, 0xd0, 0x6c, 
    0x19, 0x8c, 0xc2, 0x40, 0xd3, 0xc5, 0x62, 0x75, 0xd5, 0xfe, 0xfb, 0x5d, 0x4b, 0xcb, 0x0d, 0x8a, 
];
/// The pinned stage-B W4/H10 public root the persisted signature verifies against.
pub const PROV_KAT_ROOT: [u8; N] = [
    0x4e, 0xd9, 0x95, 0xcd, 0xf5, 0xab, 0xe9, 0x09, 0x18, 0xdc, 0x32, 0xff, 0x7a, 0xfe, 0xf2, 0xac, 
    0x0b, 0x62, 0xa4, 0x08, 0x95, 0xb9, 0x87, 0x18, 0xc5, 0xfb, 0x6a, 0xeb, 0x39, 0xb8, 0x55, 0xd7, 
];
/// The LM-OTS leaf index used to sign the pinned head (stage-A reuse of leaf 0).
pub const PROV_KAT_Q: u32 = 0;
/// The pinned W4/H10 signature length (4+4+32+32*67+4+32*10 = 2508 bytes).
pub const PROV_KAT_SIGLEN: usize = 2508;
/// The pinned W4/H10 signature over PROV_KAT_HEAD (the multi-sector persisted record body).
pub const PROV_KAT_SIG: [u8; PROV_KAT_SIGLEN] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x84, 0x96, 0x92, 0x2b, 0x02, 0xf8, 0x10, 0x2b, 
    0xdb, 0xd4, 0x91, 0x2e, 0xe6, 0xf5, 0xcf, 0xba, 0xf3, 0xfd, 0x03, 0x63, 0xa6, 0x82, 0x26, 0x5e, 
    0xdd, 0x60, 0x67, 0x88, 0x5c, 0xd8, 0xdb, 0xf2, 0x72, 0xc7, 0x03, 0x6c, 0x5a, 0xc4, 0x0b, 0x5a, 
    0xb0, 0x41, 0xaf, 0x38, 0xe3, 0x1d, 0x40, 0x99, 0xf5, 0xfc, 0xfd, 0x9a, 0x09, 0xac, 0x4b, 0x28, 
    0xe6, 0xf0, 0x0b, 0x3c, 0xa8, 0x61, 0x62, 0xe8, 0x9a, 0xa2, 0xfd, 0x89, 0x1c, 0x06, 0x54, 0x63, 
    0xde, 0x79, 0xda, 0x2b, 0x32, 0x07, 0x90, 0x3c, 0xe5, 0x1f, 0xf4, 0x16, 0xe2, 0x9d, 0x9b, 0xf5, 
    0x91, 0x56, 0xcc, 0xa5, 0x87, 0xeb, 0x44, 0x19, 0xc0, 0xa8, 0xa7, 0x97, 0x85, 0x50, 0x33, 0xe9, 
    0x64, 0x19, 0x52, 0x3c, 0xcf, 0x23, 0x0c, 0x18, 0x2a, 0x5c, 0xf6, 0xd5, 0x88, 0x0d, 0x63, 0xda, 
    0x38, 0x94, 0xdf, 0x51, 0xe6, 0xde, 0x72, 0x4c, 0xf3, 0xe5, 0x1f, 0x7a, 0xac, 0xdc, 0x53, 0x27, 
    0x86, 0xf7, 0xb0, 0x68, 0x46, 0xbc, 0xaa, 0x1d, 0x4a, 0x82, 0x38, 0xf3, 0x00, 0x6b, 0x29, 0x6b, 
    0xe0, 0x81, 0x13, 0xd2, 0xe8, 0x85, 0x7b, 0xa3, 0x38, 0xbd, 0x38, 0x2d, 0xfa, 0xec, 0xf2, 0x0a, 
    0x54, 0xa9, 0x21, 0x62, 0xd9, 0x61, 0xd7, 0x04, 0x71, 0x23, 0x5f, 0xab, 0xc9, 0xf2, 0xc0, 0x07, 
    0xfb, 0x3b, 0x5b, 0x41, 0x12, 0x51, 0x21, 0x38, 0x2d, 0x4c, 0xc7, 0xb2, 0x28, 0x8b, 0xc8, 0xa7, 
    0xad, 0x64, 0x65, 0x81, 0xff, 0x23, 0x9a, 0xf0, 0x1a, 0xfe, 0xeb, 0x83, 0xd8, 0x37, 0xe3, 0xb6, 
    0x9e, 0x37, 0xfb, 0x42, 0xe0, 0x1f, 0x20, 0x07, 0x89, 0x01, 0x8c, 0x47, 0x71, 0x90, 0x2d, 0x85, 
    0x21, 0x1e, 0xb8, 0x3e, 0x92, 0xcd, 0x06, 0x30, 0x6a, 0x3d, 0x68, 0x88, 0xa2, 0xd7, 0xd8, 0x7b, 
    0xe2, 0xf5, 0x34, 0xfb, 0x20, 0x1c, 0x69, 0x29, 0xd4, 0xd3, 0x6f, 0x04, 0xfb, 0xdf, 0x5e, 0x52, 
    0x59, 0x29, 0x78, 0x4d, 0xa3, 0xd9, 0xe6, 0x2b, 0xd7, 0x06, 0x92, 0xaf, 0xb9, 0x04, 0x28, 0x38, 
    0x5e, 0x33, 0x74, 0xe8, 0x01, 0x93, 0xb1, 0x53, 0x68, 0x1d, 0xfc, 0x92, 0x53, 0xd3, 0x7b, 0xef, 
    0xf3, 0x24, 0x4c, 0x6f, 0x69, 0x48, 0xd3, 0x45, 0x6a, 0x97, 0xdf, 0x7b, 0xc8, 0xa8, 0x84, 0xc5, 
    0x33, 0xf8, 0x7e, 0x1f, 0x08, 0x64, 0xab, 0x99, 0xde, 0x86, 0xcd, 0x1b, 0xbe, 0x15, 0x4a, 0xf8, 
    0x17, 0x04, 0xb0, 0xe4, 0xc0, 0xa6, 0x4d, 0x80, 0x27, 0x64, 0x53, 0xf4, 0xf8, 0x6a, 0x25, 0xe3, 
    0x03, 0x34, 0x45, 0x85, 0xec, 0x4a, 0x0d, 0xec, 0xd7, 0x9f, 0x0a, 0xb6, 0xb9, 0xaf, 0x34, 0x39, 
    0xdf, 0xf2, 0xc3, 0x05, 0xc8, 0xb3, 0x6d, 0x42, 0xa9, 0x48, 0x9b, 0x23, 0x2c, 0x99, 0xf6, 0x54, 
    0x6a, 0xdb, 0x09, 0xe7, 0xe4, 0x1f, 0x06, 0x08, 0x75, 0x61, 0x50, 0xd2, 0x48, 0x64, 0xc0, 0x7d, 
    0x96, 0xac, 0xa6, 0xf6, 0x98, 0xbb, 0x64, 0xa2, 0xd6, 0xe0, 0x46, 0xe7, 0x60, 0xab, 0xa6, 0xa7, 
    0xf5, 0xd6, 0x62, 0x7d, 0x36, 0x6d, 0x9f, 0xdb, 0xb5, 0xa0, 0x40, 0x11, 0xff, 0x01, 0x3c, 0x30, 
    0xae, 0xde, 0x24, 0xe0, 0xa2, 0x95, 0xcb, 0x79, 0x4b, 0x14, 0xed, 0xe7, 0x52, 0x5a, 0x21, 0x1a, 
    0xce, 0xbd, 0x2e, 0x4b, 0xe1, 0x8f, 0xc9, 0xca, 0xcb, 0x74, 0x26, 0x27, 0x90, 0xd0, 0x8f, 0x89, 
    0x86, 0xed, 0x21, 0xb4, 0xcf, 0x7c, 0x4c, 0x5a, 0xf1, 0x7b, 0xcf, 0xb3, 0x88, 0x5d, 0xe6, 0x54, 
    0x2c, 0xa0, 0x0d, 0x86, 0x5b, 0xaf, 0xae, 0xbf, 0xd6, 0x84, 0xf4, 0xc5, 0x21, 0x8c, 0x70, 0x82, 
    0xf7, 0x7d, 0xe5, 0x5b, 0xf3, 0x19, 0x7a, 0x48, 0xf4, 0x8e, 0xa1, 0xd2, 0xa6, 0x48, 0x97, 0x9c, 
    0xe8, 0x25, 0xc8, 0x32, 0x4e, 0x69, 0x25, 0x65, 0xc6, 0x82, 0x86, 0xfa, 0xeb, 0xc1, 0x33, 0x05, 
    0x54, 0x44, 0x17, 0xb8, 0xe0, 0x68, 0x21, 0x72, 0x36, 0x38, 0x37, 0xea, 0x65, 0xc0, 0xd7, 0x8d, 
    0x90, 0xe3, 0xd3, 0xf5, 0x43, 0x38, 0x2c, 0xe0, 0xe9, 0xc7, 0x23, 0xde, 0xbe, 0xe0, 0xc9, 0xb8, 
    0xcc, 0xc4, 0xa1, 0xd5, 0x9e, 0xd0, 0x60, 0xb0, 0x8e, 0x87, 0xe9, 0x65, 0x41, 0xca, 0x3c, 0x72, 
    0x45, 0x7c, 0x4d, 0x26, 0xcd, 0xf4, 0x7f, 0x73, 0x4b, 0x6a, 0x38, 0x80, 0x59, 0x4c, 0x0d, 0x58, 
    0x2e, 0x56, 0xf5, 0x0a, 0xa8, 0x03, 0x07, 0x2e, 0x87, 0x89, 0xd5, 0x51, 0xb7, 0xf1, 0x8f, 0xd7, 
    0xcc, 0x01, 0xb8, 0xdf, 0xbe, 0xf5, 0x6d, 0xe7, 0xad, 0x91, 0x65, 0xcc, 0x5f, 0x6a, 0x8c, 0x5d, 
    0x5a, 0x7c, 0xb5, 0x64, 0x97, 0x99, 0x13, 0xd5, 0xf9, 0xba, 0x89, 0xaf, 0x27, 0x00, 0x10, 0x0a, 
    0xec, 0x68, 0x00, 0x7d, 0xad, 0xd3, 0xc9, 0xf3, 0x90, 0x64, 0x28, 0x99, 0x72, 0x7d, 0x32, 0xbe, 
    0x34, 0x6d, 0xfc, 0x48, 0x0f, 0x85, 0x1f, 0xe2, 0x16, 0xbb, 0x83, 0xe0, 0xa2, 0x13, 0x1a, 0x09, 
    0x3f, 0x15, 0x24, 0xb3, 0x1b, 0x47, 0x2d, 0x4a, 0x47, 0x50, 0x42, 0x06, 0xfc, 0x3a, 0xcb, 0xcd, 
    0x38, 0x20, 0x6b, 0x03, 0x4b, 0xc1, 0x1b, 0xe5, 0x5e, 0x99, 0x55, 0x22, 0xa1, 0x86, 0x8c, 0xd8, 
    0xfd, 0x41, 0xf8, 0x23, 0x9e, 0xe5, 0x14, 0x88, 0xd7, 0xa0, 0xc0, 0x2e, 0x4d, 0x95, 0x98, 0xc2, 
    0x55, 0x1f, 0xf1, 0x7e, 0x69, 0x82, 0xb3, 0x90, 0x74, 0x75, 0x2e, 0xce, 0x3a, 0xe3, 0xa5, 0x80, 
    0x7f, 0x2d, 0xa2, 0xb2, 0x00, 0x9e, 0xc1, 0x6c, 0x26, 0xcf, 0x0c, 0x14, 0x46, 0x74, 0xae, 0xd8, 
    0x5d, 0x7c, 0x53, 0x9d, 0x7e, 0xe6, 0x66, 0x0b, 0x90, 0xe1, 0x6d, 0x34, 0xd9, 0x2d, 0xa4, 0x4e, 
    0x53, 0xad, 0x82, 0xbb, 0x61, 0x52, 0x18, 0x8d, 0x37, 0x29, 0x28, 0x57, 0x94, 0xd9, 0x54, 0x74, 
    0xbc, 0x21, 0x52, 0xe5, 0x1d, 0x5d, 0x7c, 0x06, 0x12, 0x2f, 0xba, 0x46, 0x32, 0x13, 0x97, 0x4e, 
    0x20, 0x95, 0xf7, 0x19, 0xf5, 0xc2, 0xa7, 0xf7, 0x2f, 0x59, 0x8e, 0x29, 0x15, 0x5e, 0x64, 0x2c, 
    0x15, 0xed, 0x6e, 0x7a, 0xbe, 0x58, 0x45, 0x1f, 0x4b, 0x1b, 0xae, 0xf0, 0xfd, 0x8e, 0x50, 0x18, 
    0xc1, 0x47, 0xe6, 0x08, 0x0f, 0x96, 0xcf, 0xd1, 0xd8, 0xc8, 0x6a, 0x1c, 0xde, 0x07, 0xd2, 0x88, 
    0x4b, 0x80, 0xc2, 0xdc, 0x0a, 0x57, 0xbc, 0xf5, 0x86, 0xeb, 0x95, 0x72, 0x84, 0xa0, 0xe6, 0xae, 
    0xcc, 0x34, 0x50, 0x1a, 0x30, 0x36, 0x1c, 0xf8, 0xb2, 0x96, 0x15, 0xf8, 0x89, 0xc8, 0xab, 0xf4, 
    0x16, 0xfe, 0x48, 0xf4, 0xe6, 0xcf, 0x3c, 0xcd, 0xde, 0xfb, 0x36, 0x59, 0x92, 0x9d, 0x73, 0x27, 
    0x93, 0x50, 0xe2, 0x30, 0x0a, 0xb0, 0x6a, 0x4e, 0x6a, 0x2c, 0xec, 0x2d, 0xdf, 0xd7, 0x47, 0x98, 
    0xa6, 0xaa, 0xc3, 0xc4, 0x42, 0x61, 0xab, 0xdd, 0x0f, 0x7e, 0x86, 0x86, 0xdd, 0x8e, 0x4c, 0x41, 
    0x7f, 0xaf, 0xb9, 0x3a, 0x35, 0x49, 0x42, 0x76, 0x96, 0x48, 0xd9, 0x17, 0x19, 0x57, 0xbe, 0x2d, 
    0x25, 0x82, 0x71, 0x73, 0x87, 0xfa, 0xe0, 0x54, 0x20, 0x79, 0xf7, 0xfc, 0x11, 0x04, 0x48, 0x7e, 
    0x41, 0x8b, 0x81, 0xff, 0x2f, 0xaa, 0x00, 0x00, 0xb4, 0x07, 0x86, 0x47, 0x0f, 0x9b, 0xe6, 0x16, 
    0xdd, 0x33, 0x94, 0x4f, 0x8a, 0x06, 0xd1, 0x75, 0x92, 0x32, 0xaa, 0xe7, 0x03, 0x3f, 0x3a, 0xd2, 
    0x6f, 0x49, 0xf1, 0x41, 0x4e, 0x33, 0x8c, 0x54, 0x57, 0x42, 0x4d, 0x27, 0xeb, 0xb6, 0x60, 0x5f, 
    0x1a, 0x46, 0xe2, 0xe5, 0x2e, 0x63, 0xeb, 0xb1, 0x0a, 0xae, 0x01, 0x99, 0x17, 0xfa, 0xd8, 0xe5, 
    0x13, 0xc8, 0xe9, 0x4b, 0x00, 0x5f, 0x61, 0x76, 0x22, 0x3d, 0x9a, 0x65, 0x75, 0x63, 0xd2, 0x62, 
    0xf7, 0x4e, 0x5c, 0xdd, 0x5d, 0xa4, 0x78, 0xab, 0x13, 0xf0, 0x2e, 0x76, 0x2b, 0x8f, 0x88, 0x2b, 
    0x42, 0xa2, 0x7d, 0x08, 0xc0, 0xc0, 0x6b, 0xc4, 0x3c, 0x56, 0xf3, 0x59, 0xa3, 0x50, 0x21, 0x23, 
    0x8b, 0x84, 0x38, 0xcd, 0xda, 0x74, 0x78, 0x83, 0x32, 0x76, 0x3f, 0xd4, 0x6e, 0xb1, 0x9d, 0xa0, 
    0xc9, 0x99, 0x6a, 0x77, 0xf2, 0xd7, 0x85, 0x7a, 0x5a, 0x7f, 0xd6, 0x46, 0x9f, 0x21, 0x59, 0xba, 
    0x5d, 0x64, 0xbb, 0xb2, 0x1c, 0x2f, 0x6e, 0x5d, 0x70, 0xf0, 0x84, 0xeb, 0x02, 0x41, 0x43, 0x29, 
    0x31, 0x02, 0x4f, 0xcf, 0x3d, 0xb1, 0xf7, 0x5e, 0xd1, 0x30, 0xad, 0x7e, 0xe8, 0xec, 0xa8, 0x45, 
    0x93, 0x9c, 0x3a, 0xee, 0x0d, 0x3d, 0xc9, 0xf7, 0x6e, 0x86, 0x66, 0x7f, 0x60, 0xdc, 0xbb, 0x4c, 
    0xea, 0x7b, 0xf5, 0xf7, 0xfa, 0xe6, 0x4f, 0xa8, 0xbc, 0x68, 0x2a, 0x5e, 0x46, 0x27, 0xaa, 0xb9, 
    0xe9, 0x40, 0x4e, 0xcb, 0x5d, 0x77, 0xbe, 0x64, 0x70, 0xdf, 0xdf, 0x0e, 0x86, 0x15, 0xae, 0xca, 
    0xaf, 0x09, 0xd7, 0xe9, 0x9f, 0x6d, 0x36, 0x2a, 0xd8, 0xb3, 0x6c, 0x75, 0xb3, 0x64, 0xc3, 0x5e, 
    0x95, 0x7a, 0x91, 0x87, 0xb7, 0x4d, 0xea, 0xef, 0xf7, 0x2c, 0x80, 0xc5, 0x27, 0x58, 0x67, 0xbe, 
    0xa5, 0xf7, 0x4f, 0xfa, 0x2f, 0xc1, 0x2f, 0x01, 0x9e, 0x97, 0xa2, 0x85, 0x6a, 0x8e, 0xc2, 0xf1, 
    0x7d, 0xa4, 0x0a, 0x65, 0x9c, 0xd7, 0x3e, 0x96, 0x96, 0x44, 0x53, 0xad, 0x60, 0xa2, 0x18, 0xe8, 
    0x4f, 0x8d, 0x36, 0x42, 0x37, 0xf7, 0x1b, 0xde, 0x03, 0x0a, 0x3d, 0xdf, 0xda, 0x2d, 0x22, 0x56, 
    0x40, 0x68, 0xdf, 0xaa, 0x7f, 0x27, 0x01, 0x86, 0xc1, 0x28, 0x07, 0xcf, 0xfa, 0xf1, 0xa7, 0x0a, 
    0xc9, 0xec, 0x6a, 0x6f, 0x18, 0xd3, 0x82, 0x40, 0x50, 0x9d, 0x72, 0x1a, 0xb7, 0x1c, 0xb3, 0xe7, 
    0xa0, 0x32, 0x89, 0x17, 0x89, 0x32, 0x10, 0xf2, 0x9c, 0xab, 0x63, 0x84, 0x9d, 0xf4, 0xbe, 0xaa, 
    0xf1, 0xe3, 0xc7, 0x11, 0x7f, 0x9e, 0x24, 0x04, 0xfa, 0x43, 0xc0, 0x5a, 0xa7, 0x9b, 0xe3, 0x93, 
    0xd3, 0xf8, 0x35, 0x90, 0x4c, 0x64, 0xf6, 0x3b, 0xbf, 0xc8, 0x57, 0x18, 0x09, 0x7b, 0x46, 0x37, 
    0xe7, 0x07, 0x94, 0x53, 0x64, 0xfc, 0x4f, 0x63, 0x08, 0x71, 0xfc, 0xb5, 0x72, 0x6d, 0xd5, 0x78, 
    0xb7, 0x63, 0x05, 0x7b, 0x3e, 0x89, 0xf3, 0x41, 0xfa, 0x42, 0x8b, 0xed, 0xee, 0x32, 0xbc, 0x3e, 
    0x21, 0xa6, 0x6c, 0xbc, 0xd7, 0xc6, 0xa1, 0xfc, 0xa4, 0xea, 0x6d, 0x88, 0xf0, 0xfd, 0x2a, 0x48, 
    0xad, 0x34, 0xc9, 0xfa, 0xb5, 0x55, 0x97, 0xe0, 0x87, 0x76, 0x8a, 0xce, 0x88, 0xd8, 0x3f, 0x39, 
    0xbf, 0xbe, 0xfd, 0x10, 0xd8, 0xa3, 0x9c, 0x3e, 0xb3, 0xe3, 0xc3, 0x3d, 0xf0, 0x25, 0xbd, 0x7f, 
    0x78, 0xeb, 0xdd, 0x87, 0x08, 0x57, 0xf9, 0xc6, 0x01, 0xe8, 0xca, 0xd8, 0xdb, 0x7e, 0x0a, 0xa7, 
    0x1a, 0xe1, 0x0c, 0x70, 0x8d, 0x3c, 0x3c, 0xee, 0x8c, 0x71, 0xa8, 0xb1, 0x1d, 0x8a, 0xa7, 0xf7, 
    0x4c, 0x22, 0x65, 0xea, 0x99, 0xd8, 0x06, 0x0f, 0x11, 0xc1, 0xbd, 0x3a, 0xd0, 0x77, 0x39, 0x23, 
    0xdc, 0xde, 0xe5, 0xf3, 0x7c, 0xcb, 0x4d, 0x3f, 0xfc, 0xdc, 0x25, 0x3e, 0x0c, 0x79, 0x37, 0x86, 
    0xdf, 0x1f, 0xf5, 0xd2, 0xed, 0xf5, 0x42, 0x0b, 0x5e, 0x6b, 0xd7, 0xd6, 0x8c, 0x6e, 0x20, 0x14, 
    0x43, 0xd4, 0x14, 0x24, 0x58, 0x38, 0x3c, 0x0f, 0x52, 0x2e, 0xc2, 0xe1, 0xa0, 0xae, 0xce, 0x80, 
    0xec, 0x10, 0xf2, 0x0d, 0xdb, 0xa2, 0x39, 0x2f, 0x0a, 0xa1, 0xe6, 0xa9, 0x06, 0x4d, 0x7b, 0x10, 
    0xe5, 0x18, 0xe5, 0x99, 0xae, 0x17, 0x95, 0xb1, 0xa2, 0x01, 0x35, 0x10, 0x73, 0x26, 0x40, 0x76, 
    0xc9, 0xa4, 0x21, 0x35, 0x5d, 0x12, 0xd9, 0x7e, 0x4e, 0x1d, 0x59, 0x47, 0x80, 0xe9, 0xe0, 0xb7, 
    0xe4, 0x01, 0x29, 0xcb, 0xe3, 0x49, 0xfb, 0xe2, 0xc3, 0x90, 0x3a, 0x1e, 0xcd, 0xe7, 0x42, 0xf0, 
    0x8a, 0x26, 0xf1, 0x40, 0x8d, 0xfd, 0x02, 0xaf, 0x27, 0xbe, 0x3d, 0xb1, 0x8c, 0x32, 0xb4, 0x19, 
    0x7d, 0x24, 0x02, 0x4f, 0x97, 0xf1, 0xb0, 0xd9, 0x04, 0xdb, 0x33, 0x97, 0x4a, 0x9c, 0x0b, 0x72, 
    0xfd, 0x88, 0xfa, 0x69, 0xfd, 0x20, 0x4f, 0x6c, 0x29, 0x12, 0xba, 0xa1, 0x05, 0x73, 0x2c, 0xca, 
    0x33, 0xe1, 0x73, 0x69, 0xc6, 0xf3, 0x74, 0x36, 0x89, 0x8b, 0x42, 0x1c, 0x9b, 0x02, 0x74, 0x83, 
    0x32, 0x47, 0x63, 0x12, 0xd8, 0x35, 0x50, 0x0f, 0x84, 0x3f, 0x3a, 0x74, 0x77, 0x73, 0xc4, 0xee, 
    0x86, 0xc6, 0xa4, 0x45, 0x01, 0xaf, 0xa5, 0xa5, 0xd4, 0x93, 0xf4, 0x67, 0xd5, 0xf6, 0xd9, 0x77, 
    0xd4, 0x44, 0xcb, 0xe9, 0x4e, 0x77, 0xba, 0xf7, 0x5f, 0x4f, 0xfb, 0x05, 0xd4, 0x46, 0x4d, 0xe5, 
    0xab, 0x5e, 0x58, 0xe3, 0xd1, 0xd1, 0x70, 0x23, 0x9b, 0xc8, 0xc0, 0x1b, 0x2a, 0x4f, 0x58, 0xd7, 
    0x59, 0xa7, 0x63, 0x3f, 0x92, 0xba, 0xa5, 0xa8, 0x0e, 0xd8, 0x13, 0x80, 0x85, 0x06, 0xf3, 0x79, 
    0xd7, 0xfb, 0xf9, 0x1f, 0xa1, 0xc3, 0x34, 0x5f, 0x40, 0x08, 0xbd, 0x7c, 0xd5, 0xa5, 0x99, 0x14, 
    0x73, 0x90, 0xe6, 0x08, 0x54, 0x03, 0xf1, 0x51, 0x21, 0x48, 0x98, 0x87, 0xb4, 0x9b, 0x8c, 0xe1, 
    0x9e, 0x26, 0xbd, 0xa4, 0x54, 0xda, 0x1a, 0x3c, 0x33, 0xeb, 0x47, 0x20, 0x33, 0x91, 0x41, 0xfc, 
    0xcc, 0xfd, 0x6f, 0x87, 0x2b, 0xb6, 0x25, 0x7b, 0x21, 0xb0, 0x8e, 0x93, 0x92, 0x67, 0x4b, 0x32, 
    0x14, 0xc7, 0xd5, 0xf4, 0xaa, 0x55, 0xeb, 0x85, 0xd9, 0xec, 0xe0, 0x90, 0x69, 0xef, 0x17, 0x8d, 
    0x84, 0x4d, 0x54, 0x8b, 0xbe, 0x8d, 0x30, 0xa4, 0x1d, 0xa3, 0x09, 0x38, 0x44, 0xb2, 0xde, 0x75, 
    0xd5, 0x52, 0xed, 0x4e, 0xff, 0xd8, 0x5c, 0xae, 0x3d, 0x77, 0xaa, 0x8e, 0xa4, 0x7d, 0xe1, 0x73, 
    0xd3, 0xaa, 0x39, 0xbe, 0xf6, 0x8f, 0x72, 0x4d, 0x0f, 0xdb, 0x35, 0xec, 0xd1, 0xa3, 0xf0, 0xc3, 
    0x86, 0xff, 0x33, 0x18, 0x2d, 0xdf, 0x83, 0x5a, 0x0b, 0xc7, 0xd2, 0xfd, 0xd5, 0x15, 0x41, 0xee, 
    0xf8, 0xbd, 0x7a, 0x11, 0x81, 0xa3, 0x77, 0x7c, 0x40, 0xe3, 0x3d, 0x34, 0x14, 0xbd, 0x45, 0x0b, 
    0xd4, 0x95, 0x68, 0x0f, 0x7a, 0x50, 0x22, 0xe8, 0x05, 0xda, 0x85, 0xf4, 0x5e, 0x2d, 0x0a, 0x5a, 
    0x64, 0x08, 0x08, 0x12, 0x6f, 0x3d, 0x8e, 0xc6, 0x49, 0x56, 0x8f, 0xb9, 0x39, 0xe5, 0x22, 0x6c, 
    0xf5, 0x75, 0x2e, 0xf9, 0x6c, 0xea, 0x5f, 0x1c, 0x9f, 0x44, 0x12, 0x25, 0x1b, 0xe9, 0xa6, 0x89, 
    0x27, 0x89, 0xac, 0x47, 0x46, 0xef, 0x78, 0xb7, 0xf2, 0xe9, 0x35, 0x44, 0x68, 0x36, 0x8c, 0xf6, 
    0xac, 0x1e, 0x92, 0x6f, 0x03, 0x01, 0xef, 0x62, 0xd8, 0x26, 0x82, 0x5a, 0xab, 0x4b, 0xdc, 0xcb, 
    0xad, 0xfd, 0x4f, 0x07, 0x2c, 0x1a, 0x00, 0x2d, 0x3a, 0x54, 0x98, 0x8c, 0xab, 0xab, 0x04, 0xfc, 
    0x6c, 0x53, 0x26, 0xc0, 0x80, 0x61, 0x0c, 0xc6, 0x1c, 0x65, 0xdf, 0x63, 0x26, 0xdc, 0x10, 0xb7, 
    0x38, 0x61, 0xd5, 0x34, 0xc3, 0x15, 0xcc, 0xe4, 0x72, 0xa4, 0x4a, 0x69, 0xde, 0xc7, 0xce, 0xac, 
    0x15, 0xd8, 0xfc, 0xc1, 0x53, 0x87, 0xbf, 0x56, 0x3c, 0x8e, 0x5c, 0x32, 0xd3, 0x0a, 0x65, 0x03, 
    0xc8, 0x6c, 0x86, 0x7f, 0xbf, 0x72, 0xc6, 0x47, 0xb2, 0x3c, 0x40, 0x25, 0xb6, 0x3b, 0xdf, 0x2e, 
    0x9d, 0x76, 0x54, 0xdc, 0xef, 0xce, 0x27, 0x71, 0xb2, 0x72, 0x6c, 0xb3, 0x87, 0xe3, 0xdc, 0x01, 
    0xbf, 0x07, 0xd4, 0xcc, 0xab, 0xcb, 0xa3, 0x7a, 0x63, 0xcd, 0x47, 0x42, 0x16, 0xaf, 0x05, 0x66, 
    0xae, 0x75, 0x40, 0x9f, 0x4c, 0xea, 0x8b, 0xad, 0xc2, 0x91, 0xac, 0x0d, 0x91, 0xbd, 0x1d, 0xcb, 
    0x81, 0x07, 0xe5, 0x57, 0xc3, 0x37, 0x20, 0x7b, 0x1d, 0x9b, 0xb9, 0xb7, 0xed, 0x06, 0xcf, 0xbf, 
    0xe7, 0x16, 0xd6, 0xb7, 0x21, 0xc0, 0x7b, 0xa8, 0x41, 0x77, 0x86, 0x9e, 0x76, 0x10, 0x15, 0xaa, 
    0xc8, 0x56, 0x25, 0xff, 0xaa, 0xdb, 0xc1, 0xe0, 0xcc, 0x22, 0x41, 0xa0, 0x02, 0x27, 0xc3, 0x44, 
    0x9b, 0x31, 0x80, 0xe8, 0x2d, 0xc2, 0xf8, 0x98, 0xe3, 0xaf, 0x04, 0xc6, 0xb9, 0xf6, 0xd9, 0x57, 
    0x94, 0x0e, 0x61, 0x07, 0xb3, 0x7f, 0xcf, 0xcd, 0xe0, 0x40, 0xaf, 0x09, 0x08, 0xae, 0x84, 0xea, 
    0xa1, 0x0c, 0x61, 0xaf, 0x05, 0x12, 0xbe, 0x1f, 0x00, 0x00, 0x00, 0x06, 0xc4, 0x96, 0x1f, 0x20, 
    0xed, 0x3a, 0x62, 0x8b, 0x53, 0x8c, 0x9f, 0xe4, 0x99, 0xe0, 0x1e, 0x20, 0xc3, 0xfa, 0x76, 0x22, 
    0x65, 0x38, 0xcd, 0x3f, 0x6b, 0xa7, 0x84, 0x72, 0xdd, 0x69, 0xd7, 0x58, 0xbf, 0x7a, 0x0c, 0x65, 
    0x71, 0x26, 0x33, 0xaa, 0xdb, 0x05, 0x51, 0xe1, 0xfe, 0x06, 0x82, 0x60, 0x43, 0xe7, 0xf0, 0xe4, 
    0x37, 0x91, 0xcc, 0x96, 0x80, 0x07, 0x23, 0xf2, 0xe6, 0xe9, 0x0c, 0xd2, 0x07, 0xef, 0xec, 0x25, 
    0x8b, 0x55, 0x2f, 0xb7, 0x90, 0x50, 0xa3, 0xe2, 0x65, 0x2c, 0xd0, 0x93, 0x05, 0x74, 0x08, 0x4f, 
    0xab, 0x2b, 0xe1, 0x5f, 0x8b, 0x89, 0xaf, 0xc8, 0x26, 0x0c, 0xd0, 0xd6, 0x5f, 0xb4, 0x0d, 0xa9, 
    0x20, 0xec, 0x6a, 0x81, 0x14, 0x34, 0xcd, 0x53, 0x95, 0xb8, 0xcd, 0x6c, 0xd5, 0x19, 0x6a, 0xb7, 
    0xa9, 0xb7, 0x0e, 0xcb, 0x28, 0x19, 0xc7, 0x6a, 0x7c, 0xaf, 0x0c, 0xd1, 0x90, 0x5c, 0xa2, 0xa3, 
    0x7f, 0x3c, 0xfc, 0xfb, 0x1e, 0xa9, 0xf1, 0x1a, 0xa2, 0xf6, 0x78, 0xc4, 0xc8, 0x90, 0x25, 0x88, 
    0xfe, 0x7c, 0xa3, 0x91, 0x2a, 0x6d, 0x24, 0x63, 0x9d, 0x7a, 0x6d, 0xa5, 0xf0, 0x5b, 0x31, 0xd4, 
    0x0a, 0xa8, 0xe0, 0x88, 0x85, 0x7f, 0xaa, 0x64, 0x54, 0x00, 0x46, 0x94, 0xa6, 0x22, 0x0b, 0x17, 
    0x19, 0x55, 0x93, 0x9e, 0x15, 0x7b, 0xb7, 0xa1, 0xac, 0xa9, 0xe0, 0x2b, 0x78, 0xd7, 0xb1, 0xa9, 
    0x59, 0xd0, 0xb5, 0xe8, 0xdb, 0x96, 0xb8, 0xb4, 0x9b, 0x6d, 0x73, 0xfe, 0x87, 0xef, 0xaf, 0x21, 
    0x5f, 0x0e, 0xb2, 0xa3, 0x20, 0xbd, 0x69, 0xca, 0x7a, 0xfe, 0xa6, 0x07, 0x19, 0x7e, 0xf5, 0x1e, 
    0x96, 0x25, 0x3e, 0x8b, 0x84, 0x01, 0xdb, 0x7b, 0x3f, 0xcd, 0xe9, 0x8d, 0x2b, 0xb5, 0xa2, 0xbd, 
    0x00, 0x24, 0x29, 0x51, 0xc8, 0x73, 0x8d, 0x60, 0x7e, 0x36, 0xe5, 0x25, 0x60, 0xb0, 0xc9, 0x7f, 
    0xb8, 0x42, 0x15, 0xae, 0x0c, 0x1a, 0x2f, 0xae, 0xe5, 0x51, 0x8c, 0xda, 0xa0, 0xe7, 0x17, 0x08, 
    0x01, 0xb5, 0x39, 0x90, 0x33, 0x95, 0x7a, 0x8a, 0x78, 0x82, 0xfc, 0xd9, 0xf7, 0x8d, 0x5c, 0x2d, 
    0xfd, 0x08, 0x13, 0x7b, 0x05, 0x46, 0xe0, 0x37, 0x56, 0x4d, 0x98, 0x0e, 0x36, 0xe2, 0x35, 0xaf, 
    0xbf, 0xd5, 0x75, 0xf3, 0x23, 0x10, 0x84, 0xd3, 0x1f, 0x70, 0x63, 0x31, 
];

// ===========================================================================
// The host/operator SIGNER -- cfg-gated OUT of the kernel build (the private
// key + the stateful leaf-index counter must NEVER enter the verified,
// stateless kernel TCB; proposal §2/§3). Available to `#[cfg(test)]` and to
// `tools/prov-signer` (via the `signer` cargo feature). Fixed-buffer, no-alloc,
// deterministic RFC 8554 Appendix A pseudorandom keygen -- so it is transparent
// and reproducible (the pinned KAT constants are regenerated by it).
// ===========================================================================

#[cfg(any(test, feature = "signer"))]
pub mod signer {
    //! Deterministic RFC 8554 LMS signer (host/operator side, NEVER the kernel).
    //! `key=SIMULATED-ENROLLED-CI-CUSTODIED`: a fixed compiled-in simulated key;
    //! at stage A the CI lane DELIBERATELY reuses leaf indices across runs
    //! (`state=SIMULATED-REUSE-OK-NO-SECURITY`) -- acceptable ONLY because the
    //! simulated key carries no security value. A real never-decrement durable
    //! leaf-index counter is the M35 obligation (`leafidx=DEFERRED-TO-M35-MONITOR`).

    use super::*;
    // The one-shot SHA-256 is used ONLY by the signer's keygen/chain (the verify
    // path streams); imported here so the no_std kernel build (no signer) has no
    // unused import.
    use crate::sha256::sha256;

    /// The largest tree this signer builds: `H10` = 1024 leaves, 2047 nodes.
    const MAX_LEAVES: usize = 1 << MAX_H; // 1024

    /// RFC 8554 Appendix A pseudorandom private element:
    /// `x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED)`.
    fn priv_elt(i_id: &[u8; LMS_I_LEN], q: u32, i: usize, seed: &[u8; N]) -> [u8; N] {
        let mut buf = [0u8; LMS_I_LEN + 4 + 2 + 1 + N];
        let mut off = 0usize;
        let mut k = 0usize;
        while k < LMS_I_LEN {
            buf[off + k] = i_id[k];
            k += 1;
        }
        off += LMS_I_LEN;
        put_u32(&mut buf, off, q);
        off += 4;
        put_u16(&mut buf, off, i as u16);
        off += 2;
        buf[off] = 0xff;
        off += 1;
        k = 0;
        while k < N {
            buf[off + k] = seed[k];
            k += 1;
        }
        sha256(&buf)
    }

    /// One full Winternitz chain from `x` up: `H^(count)(x)` under `(q, i)`.
    fn chain(i_id: &[u8; LMS_I_LEN], q: u32, i: usize, x: &[u8; N], from: u32, to: u32) -> [u8; N] {
        let mut tmp = *x;
        let mut j = from;
        while j < to {
            let mut buf = [0u8; LMS_I_LEN + 4 + 2 + 1 + N];
            let mut off = 0usize;
            let mut k = 0usize;
            while k < LMS_I_LEN {
                buf[off + k] = i_id[k];
                k += 1;
            }
            off += LMS_I_LEN;
            put_u32(&mut buf, off, q);
            off += 4;
            put_u16(&mut buf, off, i as u16);
            off += 2;
            buf[off] = j as u8;
            off += 1;
            let mut b = 0usize;
            while b < N {
                buf[off + b] = tmp[b];
                b += 1;
            }
            tmp = sha256(&buf);
            j += 1;
        }
        tmp
    }

    /// The LM-OTS public key `K = H(I || u32str(q) || D_PBLC || full-chain[0..p])`.
    fn ots_pubkey(i_id: &[u8; LMS_I_LEN], q: u32, w: u32, p: usize, seed: &[u8; N]) -> [u8; N] {
        let maxj = (1u32 << w) - 1;
        let mut kcbuf = [0u8; LMS_I_LEN + 4 + 2 + N * MAX_P];
        let mut off = 0usize;
        let mut k = 0usize;
        while k < LMS_I_LEN {
            kcbuf[off + k] = i_id[k];
            k += 1;
        }
        off += LMS_I_LEN;
        put_u32(&mut kcbuf, off, q);
        off += 4;
        put_u16(&mut kcbuf, off, D_PBLC);
        off += 2;
        let mut i = 0usize;
        while i < p {
            let x = priv_elt(i_id, q, i, seed);
            let full = chain(i_id, q, i, &x, 0, maxj);
            let mut b = 0usize;
            while b < N {
                kcbuf[off + b] = full[b];
                b += 1;
            }
            off += N;
            i += 1;
        }
        sha256(&kcbuf[..off])
    }

    /// One tree leaf hash `H(I || u32str(2^h+q) || D_LEAF || K_q)`.
    fn leaf_hash(i_id: &[u8; LMS_I_LEN], h: u32, q: u32, k_q: &[u8; N]) -> [u8; N] {
        let mut buf = [0u8; LMS_I_LEN + 4 + 2 + N];
        let mut off = 0usize;
        let mut k = 0usize;
        while k < LMS_I_LEN {
            buf[off + k] = i_id[k];
            k += 1;
        }
        off += LMS_I_LEN;
        put_u32(&mut buf, off, (1u32 << h) + q);
        off += 4;
        put_u16(&mut buf, off, D_LEAF);
        off += 2;
        k = 0;
        while k < N {
            buf[off + k] = k_q[k];
            k += 1;
        }
        sha256(&buf)
    }

    /// One interior node `H(I || u32str(node) || D_INTR || left || right)`.
    fn intr_hash(i_id: &[u8; LMS_I_LEN], node: u32, left: &[u8; N], right: &[u8; N]) -> [u8; N] {
        let mut buf = [0u8; LMS_I_LEN + 4 + 2 + N + N];
        let mut off = 0usize;
        let mut k = 0usize;
        while k < LMS_I_LEN {
            buf[off + k] = i_id[k];
            k += 1;
        }
        off += LMS_I_LEN;
        put_u32(&mut buf, off, node);
        off += 4;
        put_u16(&mut buf, off, D_INTR);
        off += 2;
        k = 0;
        while k < N {
            buf[off + k] = left[k];
            buf[off + N + k] = right[k];
            k += 1;
        }
        sha256(&buf)
    }

    /// Build the full Merkle tree; return `(root, nodes)` where `nodes[i]` is
    /// tree node number `i` (1-indexed; `nodes[1]` is the root, `nodes[2^h+q]`
    /// is leaf `q`). Deterministic in `(i_id, seed, w, p, h)`.
    fn build_tree(
        i_id: &[u8; LMS_I_LEN],
        seed: &[u8; N],
        w: u32,
        p: usize,
        h: u32,
    ) -> ([u8; N], [[u8; N]; 2 * MAX_LEAVES]) {
        let leaves = 1u32 << h;
        let mut nodes = [[0u8; N]; 2 * MAX_LEAVES];
        // Leaves at [2^h .. 2^h + leaves).
        let mut q = 0u32;
        while q < leaves {
            let k_q = ots_pubkey(i_id, q, w, p, seed);
            nodes[(leaves + q) as usize] = leaf_hash(i_id, h, q, &k_q);
            q += 1;
        }
        // Interior nodes, top-down index but computed bottom-up.
        let mut node = leaves - 1;
        while node >= 1 {
            let left = nodes[(2 * node) as usize];
            let right = nodes[(2 * node + 1) as usize];
            nodes[node as usize] = intr_hash(i_id, node, &left, &right);
            if node == 1 {
                break;
            }
            node -= 1;
        }
        (nodes[1], nodes)
    }

    /// The public root `T[1]` of a key `(i_id, seed)` at parameters `(w,p,h)`.
    #[must_use]
    pub fn public_root(i_id: &[u8; LMS_I_LEN], seed: &[u8; N], w: u32, p: usize, h: u32) -> [u8; N] {
        build_tree(i_id, seed, w, p, h).0
    }

    /// Deterministic per-signature randomizer `C` (RFC leaves it free; we derive
    /// it from the seed + q so the whole signer is reproducible):
    /// `C = H(I || u32str(q) || u8str(0x01) || SEED)`.
    fn randomizer(i_id: &[u8; LMS_I_LEN], q: u32, seed: &[u8; N]) -> [u8; N] {
        let mut buf = [0u8; LMS_I_LEN + 4 + 1 + N];
        let mut off = 0usize;
        let mut k = 0usize;
        while k < LMS_I_LEN {
            buf[off + k] = i_id[k];
            k += 1;
        }
        off += LMS_I_LEN;
        put_u32(&mut buf, off, q);
        off += 4;
        buf[off] = 0x01;
        off += 1;
        k = 0;
        while k < N {
            buf[off + k] = seed[k];
            k += 1;
        }
        sha256(&buf)
    }

    /// Sign `msg` with leaf `q`, parameters `(w,p,ls,h)` and type codes
    /// `(otstype, lmstype)`, writing the RFC 8554 §5.4.1 signature bytes into
    /// `out`; returns the signature length, or `0` on any bound violation
    /// (fail-closed). Deterministic. `state=SIMULATED-REUSE-OK-NO-SECURITY` --
    /// this signer does NOT enforce never-reuse (the M35 durable counter does).
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        i_id: &[u8; LMS_I_LEN],
        seed: &[u8; N],
        q: u32,
        w: u32,
        p: usize,
        ls: u32,
        h: u32,
        otstype: u32,
        lmstype: u32,
        msg: &[u8],
        out: &mut [u8],
    ) -> usize {
        if p > MAX_P || (h as usize) > MAX_H || q >= (1u32 << h) || msg.len() > MSG_CAP {
            return 0;
        }
        let total = 4 + 4 + N + N * p + 4 + N * (h as usize);
        if out.len() < total {
            return 0;
        }
        let c = randomizer(i_id, q, seed);

        // Q and coefficients (same as verify's ots_kc, but we descend the chain).
        let mut qbuf = [0u8; LMS_I_LEN + 4 + 2 + N + MSG_CAP];
        let mut off = 0usize;
        let mut k = 0usize;
        while k < LMS_I_LEN {
            qbuf[off + k] = i_id[k];
            k += 1;
        }
        off += LMS_I_LEN;
        put_u32(&mut qbuf, off, q);
        off += 4;
        put_u16(&mut qbuf, off, D_MESG);
        off += 2;
        k = 0;
        while k < N {
            qbuf[off + k] = c[k];
            k += 1;
        }
        off += N;
        k = 0;
        while k < msg.len() {
            qbuf[off + k] = msg[k];
            k += 1;
        }
        off += msg.len();
        let qhash = sha256(&qbuf[..off]);
        let ck = cksm(&qhash, w, ls);
        let mut qc = [0u8; N + 2];
        let mut j = 0usize;
        while j < N {
            qc[j] = qhash[j];
            j += 1;
        }
        let ckb = ck.to_be_bytes();
        qc[N] = ckb[0];
        qc[N + 1] = ckb[1];

        // Emit the signature: q || otstype || C || y[0..p] || lmstype || path.
        let mut w_off = 0usize;
        put_u32(out, w_off, q);
        w_off += 4;
        put_u32(out, w_off, otstype);
        w_off += 4;
        let mut b = 0usize;
        while b < N {
            out[w_off + b] = c[b];
            b += 1;
        }
        w_off += N;
        // y[i] = H^(a_i)(x[i]) where a_i = coef(Q||Cksm, i, w).
        let mut i = 0usize;
        while i < p {
            let a = coef(&qc, i, w);
            let x = priv_elt(i_id, q, i, seed);
            let yi = chain(i_id, q, i, &x, 0, a);
            b = 0;
            while b < N {
                out[w_off + b] = yi[b];
                b += 1;
            }
            w_off += N;
            i += 1;
        }
        put_u32(out, w_off, lmstype);
        w_off += 4;
        // The authentication path: the sibling of each node on the leaf->root path.
        let (_root, nodes) = build_tree(i_id, seed, w, p, h);
        let mut node = (1u32 << h) + q;
        while node > 1 {
            let sib = nodes[(node ^ 1) as usize];
            b = 0;
            while b < N {
                out[w_off + b] = sib[b];
                b += 1;
            }
            w_off += N;
            node /= 2;
        }
        w_off
    }

    /// The operational parameter set (`W4`/`H10`) as `(w, p, ls, h, otstype,
    /// lmstype)` -- the `sig=LMS-SHA256-W4-H10` token.
    pub const W4_H10: (u32, usize, u32, u32, u32, u32) =
        (4, 67, 4, 10, LMOTS_SHA256_N32_W4, LMS_SHA256_M32_H10);
}

#[cfg(test)]
mod tests {
    use super::signer::*;
    use super::*;

    mod alloc_vec {
        pub use std::vec::Vec;
    }

    const SEED: [u8; N] = [0x5Au8; N];
    const IID: [u8; LMS_I_LEN] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];

    // A small operational-shape roundtrip: W4 with the SMALLEST tree (H5) so the
    // test builds fast, exercising the full LM-OTS W4 chain + Merkle path.
    #[test]
    #[cfg_attr(miri, ignore)] // 32-leaf tree build (~34k compressions) -- too slow under Miri
    fn w4_h5_roundtrip_verifies_and_rejects_tamper() {
        let (w, p, ls, h) = (4u32, 67usize, 4u32, 5u32);
        let root = public_root(&IID, &SEED, w, p, h);
        let msg = *b"an example prov head 32-bytes!!!";
        assert_eq!(msg.len(), 32);
        let mut sig = [0u8; 4096];
        let n = sign(
            &IID,
            &SEED,
            3,
            w,
            p,
            ls,
            h,
            LMOTS_SHA256_N32_W4,
            LMS_SHA256_M32_H5,
            &msg,
            &mut sig,
        );
        assert!(n > 0);
        assert!(lms_verify(&root, &IID, &msg, &sig[..n]), "genuine sig must verify");

        // Tamper in the OTS-signature region (the C randomizer / y-chain area).
        let mut bad = sig[..n].to_vec();
        bad[8] ^= 0x01; // first byte of C
        assert!(!lms_verify(&root, &IID, &msg, &bad), "OTS-region tamper must reject");

        // Tamper in the Merkle auth-path region (the last node).
        let mut bad2 = sig[..n].to_vec();
        let last = n - 1;
        bad2[last] ^= 0x80;
        assert!(!lms_verify(&root, &IID, &msg, &bad2), "Merkle-region tamper must reject");

        // A different message must not verify against the same signature.
        let mut msg2 = msg;
        msg2[0] ^= 0x01;
        assert!(!lms_verify(&root, &IID, &msg2, &sig[..n]), "wrong message must reject");

        // A wrong root must not verify.
        let mut bad_root = root;
        bad_root[0] ^= 0x01;
        assert!(!lms_verify(&bad_root, &IID, &msg, &sig[..n]), "wrong root must reject");
    }

    #[test]
    #[cfg_attr(miri, ignore)] // 1024-leaf tree build (~1.1M compressions) -- too slow under Miri
    fn full_w4_h10_operational_roundtrip() {
        let (w, p, ls, h, ots, lms) = W4_H10;
        let root = public_root(&IID, &SEED, w, p, h);
        let msg = [0xABu8; 32];
        let mut sig = [0u8; 4096];
        let n = sign(&IID, &SEED, 1000, w, p, ls, h, ots, lms, &msg, &mut sig);
        assert!(n > 0);
        // The W4/H10 signature size (proposal ~2516 bytes: 4+4+32+32*67+4+32*10).
        assert_eq!(n, 4 + 4 + 32 + 32 * 67 + 4 + 32 * 10);
        assert!(lms_verify(&root, &IID, &msg, &sig[..n]));
    }

    /// The pinned stage-B W4/H10 KAT vectors (`PROV_KAT_HEAD/ROOT/SIG`) are the
    /// SIGNER'S OWN OUTPUT, not self-referential constants: re-derive them from
    /// the seed + `I` and assert byte-equality with the pinned consts, then prove
    /// the kernel verify path accepts them + rejects a one-byte flip. This is the
    /// non-vacuity guarantee for the persisted-head witness (the TOY-vector
    /// `toy_kat_vectors_are_signer_reproducible` discipline at the operational
    /// parameter set).
    #[test]
    #[cfg_attr(miri, ignore)] // 1024-leaf tree build (~1.1M compressions) -- too slow under Miri
    fn prov_kat_vectors_are_signer_reproducible() {
        use crate::sha256::sha256;
        let (w, p, ls, h, ots, lms) = W4_H10;
        let head = sha256(b"YUVA-M33-stageB-prov-head");
        assert_eq!(head, PROV_KAT_HEAD, "pinned head drifted from the signer");
        let root = public_root(&IID, &SEED, w, p, h);
        assert_eq!(root, PROV_KAT_ROOT, "pinned root drifted from the signer");
        let mut sig = [0u8; 4096];
        let n = sign(&IID, &SEED, PROV_KAT_Q, w, p, ls, h, ots, lms, &head, &mut sig);
        assert_eq!(n, PROV_KAT_SIGLEN, "pinned siglen drifted");
        assert_eq!(&sig[..n], &PROV_KAT_SIG[..], "pinned signature drifted from the signer");
        // The kernel verify path accepts the pinned signature + rejects a flip.
        assert!(lms_verify(&PROV_KAT_ROOT, &IID, &PROV_KAT_HEAD, &PROV_KAT_SIG));
        let mut bad = PROV_KAT_SIG;
        bad[100] ^= 0x01;
        assert!(!lms_verify(&PROV_KAT_ROOT, &IID, &PROV_KAT_HEAD, &bad));
    }

    fn unhex(s: &str) -> alloc_vec::Vec<u8> {
        assert!(s.len().is_multiple_of(2));
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    // The OFFICIAL RFC 8554 Appendix F Test Case 1 vector (the `final_signature`
    // = the level-1 LMS signature over the real message, verified against the
    // level-1 LMS public key root). This is a GENUINE RFC 8554 vector -- it
    // rules out a shared signer/verifier bug that a self-roundtrip cannot (the
    // conformance oracle; earns `conformance=RFC8554`). LMOTS_SHA256_N32_W8 /
    // LMS_SHA256_M32_H5, q=0x0a.
    #[test]
    #[cfg_attr(miri, ignore)] // W8/H5 official-vector verify (~8.7k compressions) -- too slow under Miri
    fn rfc8554_appendix_f_test_case_1_official_vector() {
        const TC1_SIG: &str = concat!(
            "0000000a000000040703c491e7558b35011ece3592eaa5da4d918786771233e8",
            "353bc4f62323185c95cae05b899e35dffd717054706209988ebfdf6e37960bb5",
            "c38d7657e8bffeef9bc042da4b4525650485c66d0ce19b317587c6ba4bffcc42",
            "8e25d08931e72dfb6a120c5612344258b85efdb7db1db9e1865a73caf96557eb",
            "39ed3e3f426933ac9eeddb03a1d2374af7bf77185577456237f9de2d60113c23",
            "f846df26fa942008a698994c0827d90e86d43e0df7f4bfcdb09b86a373b98288",
            "b7094ad81a0185ac100e4f2c5fc38c003c1ab6fea479eb2f5ebe48f584d7159b",
            "8ada03586e65ad9c969f6aecbfe44cf356888a7b15a3ff074f771760b26f9c04",
            "884ee1faa329fbf4e61af23aee7fa5d4d9a5dfcf43c4c26ce8aea2ce8a2990d7",
            "ba7b57108b47dabfbeadb2b25b3cacc1ac0cef346cbb90fb044beee4fac2603a",
            "442bdf7e507243b7319c9944b1586e899d431c7f91bcccc8690dbf59b28386b2",
            "315f3d36ef2eaa3cf30b2b51f48b71b003dfb08249484201043f65f5a3ef6bbd",
            "61ddfee81aca9ce60081262a00000480dcbc9a3da6fbef5c1c0a55e48a0e729f",
            "9184fcb1407c31529db268f6fe50032a363c9801306837fafabdf957fd97eafc",
            "80dbd165e435d0e2dfd836a28b354023924b6fb7e48bc0b3ed95eea64c2d402f",
            "4d734c8dc26f3ac591825daef01eae3c38e3328d00a77dc657034f287ccb0f0e",
            "1c9a7cbdc828f627205e4737b84b58376551d44c12c3c215c812a0970789c83d",
            "e51d6ad787271963327f0a5fbb6b5907dec02c9a90934af5a1c63b72c8265360",
            "5d1dcce51596b3c2b45696689f2eb382007497557692caac4d57b5de9f5569bc",
            "2ad0137fd47fb47e664fcb6db4971f5b3e07aceda9ac130e9f38182de994cff1",
            "92ec0e82fd6d4cb7f3fe00812589b7a7ce515440456433016b84a59bec6619a1",
            "c6c0b37dd1450ed4f2d8b584410ceda8025f5d2d8dd0d2176fc1cf2cc06fa8c8",
            "2bed4d944e71339ece780fd025bd41ec34ebff9d4270a3224e019fcb444474d4",
            "82fd2dbe75efb20389cc10cd600abb54c47ede93e08c114edb04117d714dc1d5",
            "25e11bed8756192f929d15462b939ff3f52f2252da2ed64d8fae88818b1efa2c",
            "7b08c8794fb1b214aa233db3162833141ea4383f1a6f120be1db82ce3630b342",
            "9114463157a64e91234d475e2f79cbf05e4db6a9407d72c6bff7d1198b5c4d6a",
            "ad2831db61274993715a0182c7dc8089e32c8531deed4f7431c07c02195eba2e",
            "f91efb5613c37af7ae0c066babc69369700e1dd26eddc0d216c781d56e4ce47e",
            "3303fa73007ff7b949ef23be2aa4dbf25206fe45c20dd888395b2526391a7249",
            "96a44156beac808212858792bf8e74cba49dee5e8812e019da87454bff9e847e",
            "d83db07af313743082f880a278f682c2bd0ad6887cb59f652e155987d61bbf6a",
            "88d36ee93b6072e6656d9ccbaae3d655852e38deb3a2dcf8058dc9fb6f2ab3d3",
            "b3539eb77b248a661091d05eb6e2f297774fe6053598457cc61908318de4b826",
            "f0fc86d4bb117d33e865aa805009cc2918d9c2f840c4da43a703ad9f5b580616",
            "3d7161696b5a0adc00000005d5c0d1bebb06048ed6fe2ef2c6cef305b3ed6339",
            "41ebc8b3bec9738754cddd60e1920ada52f43d055b5031cee6192520d6a51155",
            "14851ce7fd448d4a39fae2ab2335b525f484e9b40d6a4a969394843bdcf6d14c",
            "48e8015e08ab92662c05c6e9f90b65a7a6201689999f32bfd368e5e3ec9cb70a",
            "c7b8399003f175c40885081a09ab3034911fe125631051df0408b3946b0bde79",
            "0911e8978ba07dd56c73e7ee",
        );
        const TC1_MSG: &str = concat!(
            "54686520706f77657273206e6f742064656c65676174656420746f2074686520",
            "556e69746564205374617465732062792074686520436f6e737469747574696f",
            "6e2c206e6f722070726f6869626974656420627920697420746f207468652053",
            "74617465732c2061726520726573657276656420746f20746865205374617465",
            "7320726573706563746976656c792c206f7220746f207468652070656f706c65",
            "2e0a",
        );
        const TC1_ROOT: &str = "6c5004917da6eafe4d9ef6c6407b3db0e5485b122d9ebe15cda93cfec582d7ab";
        const TC1_I: &str = "d2f14ff6346af964569f7d6cb880a1b6";

        let sig = unhex(TC1_SIG);
        let msg = unhex(TC1_MSG);
        let root_v = unhex(TC1_ROOT);
        let i_v = unhex(TC1_I);
        let mut root = [0u8; N];
        root.copy_from_slice(&root_v);
        let mut i_id = [0u8; LMS_I_LEN];
        i_id.copy_from_slice(&i_v);

        assert_eq!(sig.len(), 1292, "W8/H5 sig len");
        assert_eq!(msg.len(), 162);
        // THE conformance assertion: the official vector verifies.
        assert!(
            lms_verify(&root, &i_id, &msg, &sig),
            "RFC 8554 Appendix F Test Case 1 official vector must verify"
        );
        // Non-vacuity: a one-byte flip anywhere must reject.
        let mut bad = sig.clone();
        bad[600] ^= 0x01;
        assert!(!lms_verify(&root, &i_id, &msg, &bad));
        let mut bad_root = root;
        bad_root[0] ^= 0x01;
        assert!(!lms_verify(&bad_root, &i_id, &msg, &sig));
    }

    #[test]
    fn malformed_inputs_fail_closed_never_panic() {
        let root = [0u8; N];
        // Empty / short buffers.
        assert!(!lms_verify(&root, &IID, b"x", &[]));
        assert!(!lms_verify(&root, &IID, b"x", &[0u8; 10]));
        // A buffer with a valid-looking otstype but wrong length.
        let mut sig = [0u8; 100];
        sig[7] = LMOTS_SHA256_N32_W4 as u8; // otstype = W4 (0x03), but wrong length
        assert!(!lms_verify(&root, &IID, b"x", &sig));
        // Unknown otstype rejects.
        let mut sig2 = [0u8; 4096];
        sig2[7] = 0x09;
        assert!(!lms_verify(&root, &IID, b"x", &sig2));
    }

    #[test]
    fn toy_w1_instance_roundtrips() {
        // The w=1, p=2, h=1 TOY the Kani harness + boot KAT use, via the
        // param-explicit core lms_verify_params (non-standard reduced instance,
        // p != the RFC W1 p=265).
        let root = public_root(&IID, &SEED, TOY_W, TOY_P, TOY_H);
        let msg = [0x11u8; 32];
        let mut sig = [0u8; 512];
        let n = sign(&IID, &SEED, 0, TOY_W, TOY_P, TOY_LS, TOY_H, 0xDEAD, 0xBEEF, &msg, &mut sig);
        assert!(n > 0);
        assert!(lms_verify_params(&root, &IID, &msg, &sig[..n], TOY_W, TOY_P, TOY_LS, TOY_H));
        let mut bad = sig[..n].to_vec();
        bad[8] ^= 0x01;
        assert!(!lms_verify_params(&root, &IID, &msg, &bad, TOY_W, TOY_P, TOY_LS, TOY_H));
    }

    #[test]
    fn toy_kat_vectors_are_signer_reproducible() {
        // The pinned in-boot KAT vectors (TOY_ROOT / TOY_SIG) are REGENERATED by
        // the signer here -- so they are never self-referential constants
        // (the khash::kat_ok non-vacuity discipline). Any drift in the leaf or
        // the signer moves these and fails the assert.
        let root = public_root(&TOY_I, &SEED, TOY_W, TOY_P, TOY_H);
        assert_eq!(root, TOY_ROOT, "pinned TOY_ROOT must equal the signer's root");
        let mut sig = [0u8; 512];
        let n = sign(&TOY_I, &SEED, 0, TOY_W, TOY_P, TOY_LS, TOY_H, 0, 0, &TOY_MSG, &mut sig);
        assert_eq!(n, TOY_SIG.len());
        assert_eq!(&sig[..n], &TOY_SIG[..], "pinned TOY_SIG must equal the signer's output");
        // The in-boot KAT (real compressions) passes and is non-vacuous.
        let k = kat();
        assert!(k.verified && k.tamper_ots_rejected && k.tamper_merkle_rejected);
        assert!(kat_ok());
    }
}
