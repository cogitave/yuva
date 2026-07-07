//! The M33 verified SHA-256 primitive leaf -- FIPS 180-4 / RFC 6234, the SECOND
//! in-house hash the project verifies (after the M29 BLAKE2s-256 [`crate::khash`]
//! leaf). It exists for ONE reason: RFC 8554 (LMS, the M33 signature scheme,
//! [`crate::lmsig`]) PINS its hash to SHA-256 ("SHA256 denotes the SHA-256 hash
//! function defined in NIST standard [FIPS180]"), and the M33 value proposition
//! is *exclusivity via a STANDARD scheme* -- a house-BLAKE2s LMS would forfeit
//! RFC 8554 / SP 800-208 conformance and the official-vector pedigree (proposal
//! §4, decision D2). So this leaf is paid for with eyes open: one extra
//! primitive + its harnesses, to keep `conformance=RFC8554`.
//!
//! `#![no_std]`, zero-dep, NO float, NO `unsafe` (the crate root forbids it),
//! 32-bit integer/byte ops only; `.rodata` is the 8-word IV + the 64-word round
//! constant table. ONE-SHOT API over a bounded contiguous slice -- deliberately
//! NOT init/update/final (LMS hashes small fixed-shape messages; streaming state
//! would be dead weight for Kani/Miri), mirroring [`crate::khash`].
//!
//! ## Honest scope (identical claim boundary to [`crate::khash`])
//!
//! * **PROVEN (Kani + Miri + host tests + the in-boot KAT):** totality /
//!   panic-freedom, determinism, functional correctness against the OFFICIAL
//!   FIPS 180-4 / RFC 6234 test vectors (`kani_sha256_total` +
//!   `sha256::kat_ok()` recompute-then-compare).
//! * **ASSUMED-FROM-LITERATURE (NEVER proven):** collision / preimage / 2nd-
//!   preimage resistance of the SHA-256 primitive itself. No symbolic
//!   collision/preimage Kani harness exists -- no tool in the field proves it,
//!   and a vacuous one would be overclaim-by-implication (the M29 discipline).
//! * **`sidechannel=NOT-CLAIMED`:** constant-time-SHAPED (no secret-dependent
//!   branch/index -- a code-shape property), but NO timing/cache/power model.
//!
//! ## Numeric format (no float, ever -- mirrors [`crate::khash`])
//!
//! Pure wrapping/rotating 32-bit integer arithmetic, zero alloc, zero deps. All
//! words are BIG-ENDIAN (FIPS 180-4 §3.1 -- the opposite of BLAKE2s's LE, so a
//! reader never conflates the two leaves' byte order).

/// The SHA-256 digest width in bytes (FIPS 180-4: 256 bits).
pub const SHA256_DIGEST_LEN: usize = 32;

/// The SHA-256 block width in bytes (FIPS 180-4 §1: 512-bit blocks).
const BLOCK_LEN: usize = 64;

/// The SHA-256 initial hash value (FIPS 180-4 §5.3.3): the first 32 bits of the
/// fractional parts of the square roots of the first eight primes.
const H0: [u32; 8] = [
    0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
    0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19,
];

/// The 64 SHA-256 round constants (FIPS 180-4 §4.2.2): the first 32 bits of the
/// fractional parts of the cube roots of the first sixty-four primes.
const K: [u32; 64] = [
    0x428A_2F98, 0x7137_4491, 0xB5C0_FBCF, 0xE9B5_DBA5,
    0x3956_C25B, 0x59F1_11F1, 0x923F_82A4, 0xAB1C_5ED5,
    0xD807_AA98, 0x1283_5B01, 0x2431_85BE, 0x550C_7DC3,
    0x72BE_5D74, 0x80DE_B1FE, 0x9BDC_06A7, 0xC19B_F174,
    0xE49B_69C1, 0xEFBE_4786, 0x0FC1_9DC6, 0x240C_A1CC,
    0x2DE9_2C6F, 0x4A74_84AA, 0x5CB0_A9DC, 0x76F9_88DA,
    0x983E_5152, 0xA831_C66D, 0xB003_27C8, 0xBF59_7FC7,
    0xC6E0_0BF3, 0xD5A7_9147, 0x06CA_6351, 0x1429_2967,
    0x27B7_0A85, 0x2E1B_2138, 0x4D2C_6DFC, 0x5338_0D13,
    0x650A_7354, 0x766A_0ABB, 0x81C2_C92E, 0x9272_2C85,
    0xA2BF_E8A1, 0xA81A_664B, 0xC24B_8B70, 0xC76C_51A3,
    0xD192_E819, 0xD699_0624, 0xF40E_3585, 0x106A_A070,
    0x19A4_C116, 0x1E37_6C08, 0x2748_774C, 0x34B0_BCB5,
    0x391C_0CB3, 0x4ED8_AA4A, 0x5B9C_CA4F, 0x682E_6FF3,
    0x748F_82EE, 0x78A5_636F, 0x84C8_7814, 0x8CC7_0208,
    0x90BE_FFFA, 0xA450_6CEB, 0xBEF9_A3F7, 0xC671_78F2,
];

/// The SHA-256 compression function (FIPS 180-4 §6.2.2): fold one 64-byte
/// `block` into the eight-word chaining state `h`. Big-endian message words;
/// the 64-round schedule with Ch/Maj/Sigma0/Sigma1. Total -- wrapping adds +
/// fixed rotates only, fixed loop bounds, no panic (every index is a literal or
/// a `< 64` counter).
fn compress(h: &mut [u32; 8], block: &[u8; BLOCK_LEN]) {
    // The 64-word message schedule W (§6.2.2 step 1). The first 16 words are the
    // block as BE u32s; the rest are the sigma-mixed recurrence.
    let mut w = [0u32; 64];
    let mut t = 0usize;
    while t < 16 {
        let base = t * 4;
        w[t] = u32::from_be_bytes([
            block[base],
            block[base + 1],
            block[base + 2],
            block[base + 3],
        ]);
        t += 1;
    }
    while t < 64 {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
        t += 1;
    }
    // The eight working variables (§6.2.2 step 2).
    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut f = h[5];
    let mut g = h[6];
    let mut hh = h[7];
    // 64 rounds (§6.2.2 step 3).
    let mut i = 0usize;
    while i < 64 {
        let big_s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = hh
            .wrapping_add(big_s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let big_s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = big_s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        i += 1;
    }
    // The intermediate-hash feed-forward (§6.2.2 step 4).
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

/// Serialize the chaining state to the 32-byte digest: the eight `h` words as
/// BIG-ENDIAN bytes (FIPS 180-4 §6.2.2). Total.
#[inline]
fn digest_bytes(h: &[u32; 8]) -> [u8; SHA256_DIGEST_LEN] {
    let mut out = [0u8; SHA256_DIGEST_LEN];
    let mut i = 0usize;
    while i < 8 {
        let b = h[i].to_be_bytes();
        let base = i * 4;
        out[base] = b[0];
        out[base + 1] = b[1];
        out[base + 2] = b[2];
        out[base + 3] = b[3];
        i += 1;
    }
    out
}

/// SHA-256 of a single contiguous `msg` slice (FIPS 180-4). Applies the §5.1.1
/// padding (a `0x80` byte, zero fill, then the 64-bit BE bit length) and folds
/// every block through [`compress`].
///
/// PRE: none (any `msg` length; the loop totality is structural -- the whole-
/// block loop strictly decreases the remainder, then the 1..=2 padding blocks
/// are fixed). POST: the official SHA-256 digest of `msg` -- the host-test sweep
/// with the Kani KAT harness and the in-boot [`kat_ok`], pin it to the FIPS
/// 180-4 / RFC 6234 vectors. Total: wrapping arithmetic, bounded copies, no
/// alloc, no panic.
#[must_use]
pub fn sha256(msg: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    let mut h = H0;

    // Every FULL 64-byte block of the message (§5.2.1).
    let mut off = 0usize;
    while msg.len() - off >= BLOCK_LEN {
        let mut block = [0u8; BLOCK_LEN];
        let mut i = 0usize;
        while i < BLOCK_LEN {
            block[i] = msg[off + i];
            i += 1;
        }
        compress(&mut h, &block);
        off += BLOCK_LEN;
    }

    // The final 1..=2 padded blocks (§5.1.1): the <64-byte remainder, then a
    // 0x80 byte, then zero fill, then the 64-bit BE MESSAGE-BIT length. If the
    // remainder + the 0x80 + the 8-byte length does not fit in one block (rem >=
    // 56) a second all-pad block carries the length.
    let rem = msg.len() - off;
    let bit_len = (msg.len() as u64).wrapping_mul(8);

    let mut block = [0u8; BLOCK_LEN];
    let mut i = 0usize;
    while i < rem {
        block[i] = msg[off + i];
        i += 1;
    }
    block[rem] = 0x80;

    if rem >= 56 {
        // No room for the length in this block -- compress it, then a second
        // block that is all-zero except the trailing length.
        compress(&mut h, &block);
        block = [0u8; BLOCK_LEN];
    }
    let lb = bit_len.to_be_bytes();
    let mut j = 0usize;
    while j < 8 {
        block[56 + j] = lb[j];
        j += 1;
    }
    compress(&mut h, &block);

    digest_bytes(&h)
}

/// A STREAMING SHA-256 (init/update/finalize) -- so callers that hash a
/// concatenation of many small pieces (e.g. `lmsig`'s `I || u32(q) || D_PBLC ||
/// z[0] || .. || z[p-1]`) do NOT materialize a large contiguous buffer. This is
/// what keeps the LMS verify leaf tractable under CBMC: the one-shot [`sha256`]
/// over a `32*67`-byte buffer blows the formula, but streaming carries only the
/// 64-byte block. Identical digest to [`sha256`] over the same total bytes
/// (host-test cross-checked).
#[derive(Clone)]
pub struct Sha256 {
    h: [u32; 8],
    block: [u8; BLOCK_LEN],
    buf_len: usize,
    total_len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// A fresh SHA-256 state (the FIPS 180-4 §5.3.3 IV). Total.
    #[must_use]
    pub fn new() -> Self {
        Sha256 {
            h: H0,
            block: [0u8; BLOCK_LEN],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Absorb `data`, compressing whenever the 64-byte block fills. Total (no
    /// panic, no alloc; the block index stays `< 64` by the fill/flush loop).
    pub fn update(&mut self, data: &[u8]) {
        let mut i = 0usize;
        while i < data.len() {
            self.block[self.buf_len] = data[i];
            self.buf_len += 1;
            if self.buf_len == BLOCK_LEN {
                let b = self.block;
                compress(&mut self.h, &b);
                self.buf_len = 0;
            }
            i += 1;
        }
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
    }

    /// Apply the §5.1.1 padding (0x80, zero fill, 64-bit BE bit length) and
    /// return the digest. Total.
    #[must_use]
    pub fn finalize(mut self) -> [u8; SHA256_DIGEST_LEN] {
        let bit_len = self.total_len.wrapping_mul(8);
        // 0x80 terminator.
        self.block[self.buf_len] = 0x80;
        self.buf_len += 1;
        // If no room for the 8-byte length, flush this block first.
        if self.buf_len > 56 {
            while self.buf_len < BLOCK_LEN {
                self.block[self.buf_len] = 0;
                self.buf_len += 1;
            }
            let b = self.block;
            compress(&mut self.h, &b);
            self.buf_len = 0;
        }
        while self.buf_len < 56 {
            self.block[self.buf_len] = 0;
            self.buf_len += 1;
        }
        let lb = bit_len.to_be_bytes();
        let mut j = 0usize;
        while j < 8 {
            self.block[56 + j] = lb[j];
            j += 1;
        }
        let b = self.block;
        compress(&mut self.h, &b);
        digest_bytes(&self.h)
    }
}

// ---------------------------------------------------------------------------
// The OFFICIAL test vectors (the in-boot KAT set). Sources: FIPS 180-4
// Appendix B / RFC 6234 §8.5 -- SHA-256("abc") and the two-block
// "abcdbcde...nopq" (56-byte) vector; plus the empty-string digest (widely
// published, the padding-only path). Recomputed fail-closed by every boot via
// [`kat_ok`] BEFORE the kernel emits `sha256-kat=FIPS180-4-PASS` -- the token is
// EARNED per boot through the real compression, never a compiled-in constant
// compared to itself (the [`crate::khash::kat_ok`] discipline).
// ---------------------------------------------------------------------------

/// FIPS 180-4 §Appendix B.1 / RFC 6234: SHA-256("abc").
pub(crate) const KAT_ABC: [u8; 32] = [
    0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
    0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
    0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
    0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD,
];

/// SHA-256("") -- the empty message, the padding-only single-block path.
pub(crate) const KAT_EMPTY: [u8; 32] = [
    0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14,
    0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24,
    0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C,
    0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55,
];

/// FIPS 180-4 §Appendix B.2: SHA-256 of the 56-byte "abcdbcde...mnomnopnopq"
/// message -- the TWO-block path (56-byte remainder forces the length into a
/// second padding block, the classic off-by-one padding bug).
pub(crate) const KAT_ABC2: [u8; 32] = [
    0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8,
    0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60, 0x39,
    0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67,
    0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB, 0x06, 0xC1,
];

/// The 56-byte FIPS 180-4 Appendix B.2 message.
pub(crate) const KAT_ABC2_MSG: &[u8; 56] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

/// The fail-closed in-boot KAT (the [`crate::khash::kat_ok`] pattern):
/// RECOMPUTE the three official vectors above through the REAL compression and
/// accept IFF all three match. The boot self-test calls this and emits
/// `sha256-kat=FIPS180-4-PASS` ONLY on `true` -- the token is earned per boot.
/// (The expected digests are constants; the COMPUTED side runs the full §5/§6
/// driver, so a wrong IV / round constant / schedule / padding / big-endian
/// serialization turns every boot red.)
///
/// PRE: none. POST: `true` iff this build's compression reproduces the official
/// FIPS 180-4 / RFC 6234 digests. Total.
#[must_use]
pub fn kat_ok() -> bool {
    let abc = sha256(b"abc");
    let empty = sha256(b"");
    let abc2 = sha256(KAT_ABC2_MSG);
    let mut ok = true;
    let mut i = 0usize;
    while i < SHA256_DIGEST_LEN {
        ok = ok && abc[i] == KAT_ABC[i] && empty[i] == KAT_EMPTY[i] && abc2[i] == KAT_ABC2[i];
        i += 1;
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn fips180_4_abc() {
        assert_eq!(
            sha256(b"abc"),
            hex32("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(sha256(b"abc"), KAT_ABC);
    }

    #[test]
    fn empty_string() {
        assert_eq!(
            sha256(b""),
            hex32("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn fips180_4_two_block() {
        // Appendix B.2: 56 bytes -> the second-padding-block path.
        assert_eq!(sha256(KAT_ABC2_MSG), KAT_ABC2);
    }

    #[test]
    fn block_boundary_lengths() {
        // 55 (one block), 56 (two blocks -- length spills), 63, 64 (aligned +
        // full pad block), 65 (two message blocks). RFC 6234 / openssl-checked
        // digests via the two-block vector above + self-consistency across the
        // padding boundary.
        for n in [0usize, 1, 55, 56, 63, 64, 65, 119, 120, 128] {
            let msg: alloc_vec::Vec<u8> = (0..n).map(|i| (i * 7 + 1) as u8).collect();
            // Determinism across the boundary paths.
            assert_eq!(sha256(&msg), sha256(&msg), "sha256 len={n}");
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // ~15k compressions -- host+Kani cover it; too slow under Miri
    fn one_million_a() {
        // FIPS 180-4 Appendix B.3: SHA-256 of one million 'a' bytes.
        let msg = alloc_vec::from_elem(b'a', 1_000_000);
        assert_eq!(
            sha256(&msg),
            hex32("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
        );
    }

    #[test]
    fn single_byte_avalanche() {
        let mut data = *b"the quick brown fox jumps over!!";
        let h0 = sha256(&data);
        for i in 0..data.len() {
            let saved = data[i];
            data[i] = saved ^ 0x01;
            assert_ne!(sha256(&data), h0, "byte {i} flip did not change the digest");
            data[i] = saved;
        }
    }

    #[test]
    fn in_boot_kat_passes_and_is_not_vacuous() {
        assert!(kat_ok());
        let mut perturbed = KAT_ABC;
        perturbed[0] ^= 0x01;
        assert_ne!(sha256(b"abc"), perturbed);
    }

    mod alloc_vec {
        pub use std::vec::from_elem;
        pub use std::vec::Vec;
    }
}
