//! The M29 verified KEYED-HASH primitive leaf -- BLAKE2s-256 (RFC 7693) in its
//! NATIVE KEYED MODE, the ONE cryptographic primitive the M28 operator-MAC
//! (`mac=KEYED-CRYPTO`), the forward key evolution, the #74 provenance hash and
//! the #75 Merkle successor all consume. `no_std`, zero-dep, NO float, NO
//! `unsafe` (the crate root forbids it), 32-bit integer/byte ops only; .rodata
//! is the 32-byte IV + the 160-byte sigma schedule. ONE-SHOT API over a bounded
//! contiguous slice -- deliberately NOT init/update/final (every consumer passes
//! a single contiguous slice; streaming state would be dead weight for
//! Kani/Miri).
//!
//! ## Honest scope (proposal §9 -- the claim boundary the field uses)
//!
//! * **PROVEN (Kani + Miri + host tests + the in-boot KAT):** totality /
//!   panic-freedom, determinism, functional correctness against the OFFICIAL
//!   test vectors (RFC 7693 Appendix B + the BLAKE2 reference KAT --
//!   <https://github.com/BLAKE2/BLAKE2> `testvectors/blake2s-kat.txt`), and
//!   tamper-sensitivity at symbolic flip positions over concrete inputs (the
//!   #49 discipline). This is the implementation-verification tier of Appel
//!   (TOPLAS 2015), HACL*, aws-lc-verification and mlkem-native.
//! * **ASSUMED-FROM-LITERATURE (NEVER proven, deliberately):** collision /
//!   preimage / PRF / forgery resistance of the BLAKE2s primitive itself. Best
//!   published attacks reach ~6.75-7.5 of 10 rounds in pseudo/compression-
//!   function settings only (Guo et al. CT-RSA 2014; Espitau-Fouque-Karpman
//!   CRYPTO 2015); the full hash and the keyed mode are unbroken, and the
//!   keyed mode carries a PRF/MAC proof under standard assumptions
//!   (Luykx-Mennink-Neves FSE 2016). NO symbolic collision/preimage/PRF Kani
//!   harness exists -- no tool in the field proves these, and a vacuous one
//!   would be overclaim-by-implication. The boot witness emits
//!   `sec=ASSUMED-FROM-LITERATURE` so the boundary is machine-visible.
//! * **`sidechannel=NOT-CLAIMED`:** the code is constant-time-SHAPED (no
//!   secret-dependent branches or table indices -- a code-shape property), but
//!   NO timing/cache/power/EM model is claimed; QEMU TCG timing is not
//!   physically meaningful.
//! * **`prim=BLAKE2S-256`:** RFC 7693 is an INFORMATIONAL RFC, not a NIST
//!   standard. The trade (width-exact fit to `KEY_LEN`/`PROV_HASH_LEN`/
//!   `MAC_LEN`, a proven native keyed mode instead of an HMAC wrapper, 2
//!   compressions per 65-byte fold step) is recorded in
//!   `docs/research/m29-crypto-mac-literature.md` §3.
//!
//! ## Numeric format (no float, ever -- mirrors `prov`/`blkfmt`)
//!
//! Pure wrapping/rotating 32-bit integer arithmetic (ARX), zero alloc, zero
//! deps. All words are LITTLE-ENDIAN (RFC 7693 §2.4). Domain separation for
//! consumers stays WHERE IT LIVES TODAY (leading domain bytes inside the
//! message, e.g. the `prov::MIX_DOMAIN` fold tag) -- khash bakes in NO fold.

/// The fixed key width of the native keyed mode (bytes) == `opframe_rx::KEY_LEN`.
/// RFC 7693 §2.1: BLAKE2s key length 0..=32; M29 pins the maximum (a full key
/// block 0, zero-padded to the 64-byte block -- §2.5/§2.10).
pub const KHASH_KEY_LEN: usize = 32;

/// The fixed digest width (bytes) == `prov::PROV_HASH_LEN`. RFC 7693 §2.1:
/// BLAKE2s digest length 1..=32; M29 pins the maximum (BLAKE2s-256). The M28
/// MAC truncates this digest to `opframe_rx::MAC_LEN` (16 bytes) -- the
/// spec-sanctioned truncation (RFC 7693 §2.1 "nn" applies to the digest
/// parameter; tag truncation per RFC 2104 §5 / SP 800-107r1 §5.3.4).
pub const KHASH_TAG_LEN: usize = 32;

/// The BLAKE2s block width in bytes (RFC 7693 §2.1: bb = 64).
const BLOCK_LEN: usize = 64;

/// The BLAKE2s round count (RFC 7693 §2.1: r = 10).
const ROUNDS: usize = 10;

/// The BLAKE2s initialization vector (RFC 7693 §2.6) -- the same constants as
/// SHA-256's IV (the fractional parts of the square roots of the first eight
/// primes), little-endian words.
const IV: [u32; 8] = [
    0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
    0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19,
];

/// The BLAKE2 message-word schedule SIGMA (RFC 7693 §2.7): ten fixed
/// permutations of `0..16`; round `r` of the compression feeds the G functions
/// the message words in the order `SIGMA[r]`. `usize` entries so the harnesses
/// and the compression index `m[]` with the SAME literals (no cast drift).
const SIGMA: [[usize; 16]; ROUNDS] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// The BLAKE2s mixing function G (RFC 7693 §3.1): mix message words `x`/`y`
/// into the four working-vector lanes `a`/`b`/`c`/`d` with the BLAKE2s
/// rotation set (R1,R2,R3,R4) = (16,12,8,7) (§2.1). WRAPPING adds + fixed
/// rotates only -- total, no panic, no overflow trap, no float, and no
/// secret-dependent branch/index (constant-time-SHAPED; see the module
/// honesty note -- the SHAPE is a code property, never a timing claim).
///
/// PRE: `a`,`b`,`c`,`d` are distinct indices in `0..16` (the eight call sites
/// in [`compress`] pass the fixed §3.2 literals, so the indexing never panics).
/// POST: `v` is updated in place per the §3.1 sequence, all other lanes
/// untouched.
#[inline]
fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

/// The BLAKE2s compression function F (RFC 7693 §3.2): fold one 64-byte
/// `block` into the chaining state `h` under the 64-bit offset counter `t`,
/// with `last` selecting the final-block flag f0 (`v[14]` inversion). The
/// block is read as 16 LITTLE-ENDIAN u32 words (§2.4); ten rounds of eight G
/// mixes (column step + diagonal step) over the §2.7 schedule; then the
/// feed-forward `h[i] ^= v[i] ^ v[i+8]`.
///
/// PRE: none beyond the types (a fixed-width block; any `t`; any `h`).
/// POST: `h` holds the §3.2 result; total -- wrapping arithmetic only, fixed
/// loop bounds, no panic (every index is a literal or a `< 16` counter).
fn compress(h: &mut [u32; 8], block: &[u8; BLOCK_LEN], t: u64, last: bool) {
    // m[0..16]: the message block as 16 LE words (RFC 7693 §2.4).
    let mut m = [0u32; 16];
    let mut w = 0usize;
    while w < 16 {
        let base = w * 4;
        m[w] = u32::from_le_bytes([
            block[base],
            block[base + 1],
            block[base + 2],
            block[base + 3],
        ]);
        w += 1;
    }
    // The 16-word working vector: state in v[0..8], IV in v[8..16] (§3.2).
    let mut v = [0u32; 16];
    let mut i = 0usize;
    while i < 8 {
        v[i] = h[i];
        v[i + 8] = IV[i];
        i += 1;
    }
    // Fold the 64-bit offset counter t into v[12]/v[13] (§3.2) -- the counter
    // is what separates two messages whose PADDED final blocks are identical
    // (e.g. the empty message vs a single 0x00 byte); the
    // `kani_khash_total_deterministic` boundary sweep covers exactly that pair.
    v[12] ^= t as u32;
    v[13] ^= (t >> 32) as u32;
    // The final-block flag f0 (§3.2): invert v[14] on the LAST block only.
    if last {
        v[14] = !v[14];
    }
    // Ten rounds (§2.1 r=10) of the §3.2 column+diagonal G schedule.
    let mut r = 0usize;
    while r < ROUNDS {
        let s = &SIGMA[r];
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        r += 1;
    }
    // The feed-forward (§3.2): XOR both halves of v back into h.
    let mut j = 0usize;
    while j < 8 {
        h[j] ^= v[j] ^ v[j + 8];
        j += 1;
    }
}

/// Serialize the chaining state to the 32-byte digest: the eight `h` words as
/// LITTLE-ENDIAN bytes (RFC 7693 §2.4/§3.3 "first nn bytes of the LE word
/// array"; nn == [`KHASH_TAG_LEN`] == 32, so the whole state). Total.
#[inline]
fn digest_bytes(h: &[u32; 8]) -> [u8; KHASH_TAG_LEN] {
    let mut out = [0u8; KHASH_TAG_LEN];
    let mut w = 0usize;
    while w < 8 {
        let b = h[w].to_le_bytes();
        let base = w * 4;
        out[base] = b[0];
        out[base + 1] = b[1];
        out[base + 2] = b[2];
        out[base + 3] = b[3];
        w += 1;
    }
    out
}

/// The RFC 7693 §3.3 BLAKE2s driver over an optional 32-byte key and a single
/// contiguous `msg` slice -- the shared body of [`khash`] (keyed) and
/// [`uhash`] (unkeyed). Parameter-block word 0 is XORed into `h[0]` as
/// `0x0101_kknn` (§2.5: digest_length nn, key_length kk, fanout 1, depth 1 --
/// sequential mode). KEYED MODE (§2.5/§2.10): the key is zero-padded into a
/// full data block 0 compressed BEFORE the message; per §3.3 the key block
/// advances the offset counter by a full `bb` (so the final block's `t` is
/// `ll + bb` when keyed), and a keyed hash of the EMPTY message finalizes ON
/// the key block itself.
///
/// PRE: none (any `msg` length; totality over the loop is structural -- the
/// full-block loop strictly decreases the remainder, the final block handles
/// `1..=64` remaining bytes, the empty cases return early).
/// POST: the official BLAKE2s-256 digest of (`key?`, `msg`) -- the host-test
/// sweep + the Kani KAT harness + the in-boot [`kat_ok`] pin it to the
/// published vectors. Total: wrapping arithmetic, bounded copies, no alloc,
/// no panic.
fn blake2s(key: Option<&[u8; KHASH_KEY_LEN]>, msg: &[u8]) -> [u8; KHASH_TAG_LEN] {
    let mut h = IV;
    // Parameter-block word 0 (§2.5): 0x0101_kknn -- depth 1 | fanout 1 |
    // key_length kk | digest_length nn.
    let kk: u32 = match key {
        Some(_) => KHASH_KEY_LEN as u32,
        None => 0,
    };
    h[0] ^= 0x0101_0000 ^ (kk << 8) ^ (KHASH_TAG_LEN as u32);

    // The 64-bit byte-offset counter t (§3.2/§3.3). Wrapping adds for
    // totality (a >2^64-byte message cannot exist in an address space, but
    // the leaf never traps regardless).
    let mut t: u64 = 0;

    if let Some(k) = key {
        // KEYED MODE (§2.5/§2.10): block 0 = the key, zero-padded to bb bytes.
        let mut block = [0u8; BLOCK_LEN];
        let mut i = 0usize;
        while i < KHASH_KEY_LEN {
            block[i] = k[i];
            i += 1;
        }
        // §3.3: the key block counts one full bb toward t (final t = ll + bb).
        t = BLOCK_LEN as u64;
        let key_is_final = msg.is_empty();
        compress(&mut h, &block, t, key_is_final);
        if key_is_final {
            // §3.3: keyed + empty input -- the key block IS the final block.
            return digest_bytes(&h);
        }
    } else if msg.is_empty() {
        // §3.3: unkeyed empty input -- one all-zero padded block, t = 0, final.
        compress(&mut h, &[0u8; BLOCK_LEN], 0, true);
        return digest_bytes(&h);
    }

    // Every block EXCEPT the last is compressed non-final at t = bytes-so-far
    // (§3.3). Strict `>` keeps a block-aligned tail (rem == 64) for the final
    // compression, exactly as the RFC's dd-block split does.
    let mut off = 0usize;
    while msg.len() - off > BLOCK_LEN {
        let mut block = [0u8; BLOCK_LEN];
        let mut i = 0usize;
        while i < BLOCK_LEN {
            block[i] = msg[off + i];
            i += 1;
        }
        t = t.wrapping_add(BLOCK_LEN as u64);
        compress(&mut h, &block, t, false);
        off += BLOCK_LEN;
    }
    // The final block: 1..=64 remaining bytes, zero-padded (§3.3); t = the
    // TRUE total byte count (ll, +bb if keyed), NOT the padded length -- the
    // classic last-block bug the negative controls target.
    let rem = msg.len() - off;
    let mut block = [0u8; BLOCK_LEN];
    let mut i = 0usize;
    while i < rem {
        block[i] = msg[off + i];
        i += 1;
    }
    t = t.wrapping_add(rem as u64);
    compress(&mut h, &block, t, true);
    digest_bytes(&h)
}

/// BLAKE2s-256 in its NATIVE KEYED MODE (RFC 7693 §2.5/§2.10): the 32-byte
/// `key` is zero-padded into data block 0 and compressed before `msg`. This
/// IS the MAC -- the keyed mode is proven a secure PRF/MAC under standard
/// assumptions (Luykx-Mennink-Neves FSE 2016), so NO envelope and NO HMAC
/// wrapper sit on top (the M28 nested-FNV envelope retires). Tag truncation
/// (e.g. to `opframe_rx::MAC_LEN`) is the CALLER's, per RFC 2104 §5 /
/// SP 800-107r1 §5.3.4.
///
/// PRE: none (any `msg` length). POST: the official keyed BLAKE2s-256 digest;
/// deterministic; total (no panic, no alloc, no float). Security of the
/// primitive: ASSUMED-FROM-LITERATURE (module honesty note).
#[must_use]
pub fn khash(key: &[u8; KHASH_KEY_LEN], msg: &[u8]) -> [u8; KHASH_TAG_LEN] {
    blake2s(Some(key), msg)
}

/// BLAKE2s-256 UNKEYED (RFC 7693 §3.3 with kk = 0) -- the #74 `prov_hash`
/// replacement body and the #75 Merkle-node hash. Domain separation stays the
/// CALLER's (leading domain bytes inside `msg`, e.g. `prov::MIX_DOMAIN`).
///
/// PRE: none (any `msg` length). POST: the official unkeyed BLAKE2s-256
/// digest; deterministic; total (no panic, no alloc, no float). Security of
/// the primitive: ASSUMED-FROM-LITERATURE (module honesty note).
#[must_use]
pub fn uhash(msg: &[u8]) -> [u8; KHASH_TAG_LEN] {
    blake2s(None, msg)
}

// ---------------------------------------------------------------------------
// The OFFICIAL test vectors (the in-boot KAT set). Sources:
//   * RFC 7693 Appendix B: BLAKE2s-256("abc"), unkeyed.
//   * The BLAKE2 reference KAT (github.com/BLAKE2/BLAKE2,
//     testvectors/blake2s-kat.txt): key = 00 01 02 .. 1f, input = the
//     sequential byte string 00 01 .. (n-1); the len=0 and len=65 entries
//     (the key-block-as-final path and the key+full+partial two-message-block
//     path). The full sweep runs under `cargo test` (below); these three are
//     ALSO recomputed fail-closed by every boot via [`kat_ok`] BEFORE the
//     kernel emits `kat=RFC7693-PASS` -- the token is EARNED per boot through
//     the real compression, never a compiled-in constant compared to itself.
// ---------------------------------------------------------------------------

/// RFC 7693 Appendix B: BLAKE2s-256("abc"), unkeyed.
pub(crate) const KAT_ABC_UNKEYED: [u8; 32] = [
    0x50, 0x8C, 0x5E, 0x8C, 0x32, 0x7C, 0x14, 0xE2,
    0xE1, 0xA7, 0x2B, 0xA3, 0x4E, 0xEB, 0x45, 0x2F,
    0x37, 0x45, 0x8B, 0x20, 0x9E, 0xD6, 0x3A, 0x29,
    0x4D, 0x99, 0x9B, 0x4C, 0x86, 0x67, 0x59, 0x82,
];

/// BLAKE2 reference KAT, keyed (key=000102..1f), empty input -- the
/// key-block-as-final §3.3 path.
pub(crate) const KAT_KEYED_EMPTY: [u8; 32] = [
    0x48, 0xA8, 0x99, 0x7D, 0xA4, 0x07, 0x87, 0x6B,
    0x3D, 0x79, 0xC0, 0xD9, 0x23, 0x25, 0xAD, 0x3B,
    0x89, 0xCB, 0xB7, 0x54, 0xD8, 0x6A, 0xB7, 0x1A,
    0xEE, 0x04, 0x7A, 0xD3, 0x45, 0xFD, 0x2C, 0x49,
];

/// BLAKE2 reference KAT, keyed (key=000102..1f), input 00..40 (65 bytes) --
/// the key block + one full message block + a 1-byte final block (every
/// compression path of the keyed mode in one vector).
pub(crate) const KAT_KEYED_65: [u8; 32] = [
    0x21, 0xFE, 0x0C, 0xEB, 0x00, 0x52, 0xBE, 0x7F,
    0xB0, 0xF0, 0x04, 0x18, 0x7C, 0xAC, 0xD7, 0xDE,
    0x67, 0xFA, 0x6E, 0xB0, 0x93, 0x8D, 0x92, 0x76,
    0x77, 0xF2, 0x39, 0x8C, 0x13, 0x23, 0x17, 0xA8,
];

/// The reference-KAT key: `00 01 02 .. 1f` (every keyed vector in the
/// official `blake2s-kat.txt` uses this key).
pub(crate) const KAT_KEY: [u8; KHASH_KEY_LEN] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
];

/// The sequential-byte KAT message `00 01 .. 40` (65 bytes -- the official
/// KAT input prefix), shared by [`kat_ok`] and the proof harnesses.
pub(crate) const fn kat_msg_65() -> [u8; 65] {
    let mut m = [0u8; 65];
    let mut i = 0usize;
    while i < 65 {
        m[i] = i as u8;
        i += 1;
    }
    m
}

/// The fail-closed in-boot KAT (proposal §6.4): RECOMPUTE the three official
/// vectors above through the REAL compression and accept IFF all three match.
/// The boot self-test calls this and emits `kat=RFC7693-PASS` ONLY on `true`
/// -- the token is earned per boot, never compiled-in. (The expected digests
/// are constants; the COMPUTED side runs the full keyed/unkeyed §3.3 driver,
/// so a wrong IV / sigma / rotation / counter / flag turns every boot red.)
///
/// PRE: none. POST: `true` iff this build's compression reproduces the
/// official RFC 7693 Appendix B + BLAKE2 reference KAT digests. Total.
#[must_use]
pub fn kat_ok() -> bool {
    let abc = uhash(b"abc");
    let keyed_empty = khash(&KAT_KEY, b"");
    let keyed_65 = khash(&KAT_KEY, &kat_msg_65());
    let mut ok = true;
    let mut i = 0usize;
    while i < KHASH_TAG_LEN {
        ok = ok
            && abc[i] == KAT_ABC_UNKEYED[i]
            && keyed_empty[i] == KAT_KEYED_EMPTY[i]
            && keyed_65[i] == KAT_KEYED_65[i];
        i += 1;
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The official keyed-KAT input: the sequential byte string 00 01 .. (n-1).
    fn kat_input(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i & 0xFF) as u8).collect()
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        let b = s.as_bytes();
        assert_eq!(b.len(), 64);
        for i in 0..32 {
            let hi = (b[2 * i] as char).to_digit(16).unwrap() as u8;
            let lo = (b[2 * i + 1] as char).to_digit(16).unwrap() as u8;
            out[i] = (hi << 4) | lo;
        }
        out
    }

    // ---- the OFFICIAL vectors --------------------------------------------

    #[test]
    fn rfc7693_appendix_b_abc() {
        // RFC 7693 Appendix B (BLAKE2s-256 of "abc", unkeyed).
        assert_eq!(uhash(b"abc"), KAT_ABC_UNKEYED);
    }

    #[test]
    fn unkeyed_empty_and_counter_discrimination() {
        // The unkeyed empty-input vector (BLAKE2 reference implementations).
        assert_eq!(
            uhash(b""),
            hex32("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")
        );
        // "" vs "\x00": the PADDED final blocks are byte-identical -- ONLY the
        // t counter separates them (the classic broken-counter collision).
        assert_eq!(
            uhash(b"\x00"),
            hex32("e34d74dbaf4ff4c6abd871cc220451d2ea2648846c7757fbaac82fe51ad64bea")
        );
        assert_ne!(uhash(b""), uhash(b"\x00"));
    }

    /// The official keyed KAT sweep (github.com/BLAKE2/BLAKE2
    /// testvectors/blake2s-kat.txt; key=000102..1f, input=00 01 .. (n-1)) at
    /// every boundary length: empty (key block final), 1/2 (tiny final),
    /// 31/32 (key-width boundary), 55/63 (partial final), 64 (block-aligned
    /// final), 65 (full + 1-byte final), 128 (two full + aligned final),
    /// 129 (three-block path).
    #[test]
    fn official_keyed_kat_sweep() {
        let expected: &[(usize, &str)] = &[
            (0, "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49"),
            (1, "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1"),
            (2, "6bb71300644cd3991b26ccd4d274acd1adeab8b1d7914546c1198bbe9fc9d803"),
            (31, "b6156f72d380ee9ea6acd190464f2307a5c179ef01fd71f99f2d0f7a57360aea"),
            (32, "c03bc642b20959cbe133a0303e0c1abff3e31ec8e1a328ec8565c36decff5265"),
            (55, "f16012d93f28851a1eb989f5d0b43f3f39ca73c9a62d5181bff237536bd348c3"),
            (63, "c65382513f07460da39833cb666c5ed82e61b9e998f4b0c4287cee56c3cc9bcd"),
            (64, "8975b0577fd35566d750b362b0897a26c399136df07bababbde6203ff2954ed4"),
            (65, "21fe0ceb0052be7fb0f004187cacd7de67fa6eb0938d927677f2398c132317a8"),
            (128, "0c311f38c35a4fb90d651c289d486856cd1413df9b0677f53ece2cd9e477c60a"),
            (129, "46a73a8dd3e70f59d3942c01df599def783c9da82fd83222cd662b53dce7dbdf"),
        ];
        for (n, hexs) in expected {
            let msg = kat_input(*n);
            assert_eq!(
                khash(&KAT_KEY, &msg),
                hex32(hexs),
                "official keyed KAT len={n} mismatch"
            );
        }
    }

    #[test]
    fn in_boot_kat_passes_and_is_not_vacuous() {
        // The exact fail-closed check every boot runs before emitting
        // kat=RFC7693-PASS.
        assert!(kat_ok());
        // NON-VACUITY: a one-byte-perturbed expected digest must NOT match
        // (guards a broken comparator that accepts everything).
        let mut perturbed = KAT_ABC_UNKEYED;
        perturbed[0] ^= 0x01;
        assert_ne!(uhash(b"abc"), perturbed);
    }

    // ---- determinism / mode separation / sensitivity ---------------------

    #[test]
    fn deterministic_across_boundary_lengths() {
        let key = KAT_KEY;
        for n in [0usize, 1, 31, 32, 55, 63, 64, 65, 127, 128, 129, 200] {
            let msg = kat_input(n);
            assert_eq!(khash(&key, &msg), khash(&key, &msg), "khash len={n}");
            assert_eq!(uhash(&msg), uhash(&msg), "uhash len={n}");
        }
    }

    #[test]
    fn keyed_and_unkeyed_modes_are_distinct() {
        let msg = kat_input(40);
        // kk lives in the parameter word, so keyed != unkeyed on ANY message.
        assert_ne!(khash(&KAT_KEY, &msg), uhash(&msg));
        // A single key-byte change moves the tag.
        let mut k2 = KAT_KEY;
        k2[17] ^= 0x80;
        assert_ne!(khash(&k2, &msg), khash(&KAT_KEY, &msg));
    }

    #[test]
    fn single_byte_and_extension_sensitivity() {
        let msg = kat_input(65);
        let base = khash(&KAT_KEY, &msg);
        // Flip every message byte in turn -> the tag must move each time.
        let mut m2 = msg.clone();
        for i in 0..m2.len() {
            m2[i] ^= 0x01;
            assert_ne!(khash(&KAT_KEY, &m2), base, "msg byte {i} flip missed");
            m2[i] ^= 0x01;
        }
        // The m || 0x00 extension (the last-block/padding negative control).
        let mut ext = msg.clone();
        ext.push(0x00);
        assert_ne!(khash(&KAT_KEY, &ext), base);
        // Block-aligned variant: m64 vs m64 || 0x00.
        let m64 = kat_input(64);
        let mut m64e = m64.clone();
        m64e.push(0x00);
        assert_ne!(khash(&KAT_KEY, &m64), khash(&KAT_KEY, &m64e));
    }
}
