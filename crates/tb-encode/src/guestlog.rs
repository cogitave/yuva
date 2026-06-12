//! Pure **`guestlog:` frame codec** -- the aL2.4b injection-proofing leaf
//! (proposal §2.5) and, deliberately, the same untrusted-bytes encoder shape
//! the M31/M34 arc needs.
//!
//! ## The verified problem this solves
//!
//! The host guards in `scripts/run-aarch64.sh` are UNANCHORED substring greps
//! over the whole serial stream. The aL2.4b full-kernel EL1 guest prints its
//! ENTIRE M0..M31 chain -- including lines like `M20: persist OK (no disk,
//! skipped)` that the host lane's own anti-hollow guards explicitly REJECT,
//! and (adversarially) any byte sequence at all, including forged host
//! markers. Mere line-prefixing does NOT fix substring greps. The fix: every
//! guest serial byte leaves the trapped PL011 ONLY re-encoded through this
//! codec, as bounded `guestlog: <lowercase-hex>\n` lines, so guest bytes are
//! **regex-inert to every existing guard by construction** -- no byte of any
//! marker/guard alphabet (uppercase letters, `:`, space, parens, ...) passes
//! through raw; the hex region is drawn from the 16-character alphabet
//! `[0-9a-f]` only.
//!
//! Frame grammar (one frame per line; the decoder is the run-script's
//! `grep '^guestlog: ' | sed 's/^guestlog: //' | xxd -r -p` -- frames carry a
//! BYTE STREAM, so concatenating the decoded payloads of all frames in order
//! reconstructs the guest's exact serial output, newlines included):
//!
//! ```text
//! guestlog: 4d32303a2070657273697374204f4b0a\n
//! ^^^^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//! PREFIX    2*len lowercase hex digits      LF terminator
//! ```
//!
//! Proven in `proofs.rs` (each with a documented negative control + the house
//! mutation-test rule): bounded frame length, total encode/decode + exact
//! round-trip, injectivity over equal-length payloads (and length-prefix-free
//! framing via the LF terminator), and the load-bearing safety property --
//! the payload region is lowercase-hex-only, so NO guard-alphabet byte
//! survives raw.

#![allow(dead_code)]

/// The frame line prefix, including the trailing space.
pub const GUESTLOG_PREFIX: &[u8] = b"guestlog: ";
/// Max payload bytes per frame (the EL2 emitter flushes at this bound or at a
/// guest `\n`, whichever comes first). Small enough that one encoded frame
/// fits comfortably in a fixed EL2 buffer; large enough that overhead stays
/// ~17% on marker-sized lines.
pub const GUESTLOG_MAX_PAYLOAD: usize = 64;
/// Encoded length of a frame carrying `len` payload bytes:
/// `prefix + 2*len hex + 1 LF`.
pub const fn guestlog_frame_len(len: usize) -> usize {
    GUESTLOG_PREFIX.len() + 2 * len + 1
}
/// The largest encoded frame (the EL2 emitter's out-buffer size).
pub const GUESTLOG_MAX_FRAME: usize = guestlog_frame_len(GUESTLOG_MAX_PAYLOAD);

/// Lowercase-hex digit for a nibble `n < 16`. The ONLY alphabet any payload
/// byte is rendered through -- `[0-9a-f]`, disjoint from every host marker's
/// discriminating bytes (uppercase, `:`, space, parens).
#[inline]
const fn hex_digit(n: u8) -> u8 {
    if n < 10 {
        b'0' + n
    } else {
        b'a' + (n - 10)
    }
}

/// Value of one lowercase-hex digit, or `None` for any non-`[0-9a-f]` byte
/// (fail-closed: the decoder never guesses).
#[inline]
const fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Encode one `guestlog:` frame over `payload` into `out`. Returns the number
/// of bytes written (`guestlog_frame_len(payload.len())`), or `0` (fail-closed,
/// nothing written beyond bounds) when the payload exceeds
/// [`GUESTLOG_MAX_PAYLOAD`] or `out` is too small. Total: never panics for any
/// input (proven in `kani_guestlog_roundtrip_total`).
pub fn guestlog_encode(payload: &[u8], out: &mut [u8]) -> usize {
    let n = payload.len();
    if n > GUESTLOG_MAX_PAYLOAD {
        return 0;
    }
    let total = guestlog_frame_len(n);
    if out.len() < total {
        return 0;
    }
    let p = GUESTLOG_PREFIX.len();
    out[..p].copy_from_slice(GUESTLOG_PREFIX);
    let mut i = 0usize;
    while i < n {
        let b = payload[i];
        out[p + 2 * i] = hex_digit(b >> 4);
        out[p + 2 * i + 1] = hex_digit(b & 0xF);
        i += 1;
    }
    out[total - 1] = b'\n';
    total
}

/// Decode one `guestlog:` frame line (`frame` = the full encoded line,
/// terminator included) into `out`. Returns `Some(payload_len)` on an exact
/// grammar match (prefix, even-length lowercase hex, LF terminator, payload
/// within bounds), `None` otherwise (fail-closed). Total: never panics.
pub fn guestlog_decode(frame: &[u8], out: &mut [u8]) -> Option<usize> {
    let p = GUESTLOG_PREFIX.len();
    if frame.len() < p + 1 || &frame[..p] != GUESTLOG_PREFIX {
        return None;
    }
    if frame[frame.len() - 1] != b'\n' {
        return None;
    }
    let hex = &frame[p..frame.len() - 1];
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let n = hex.len() / 2;
    if n > GUESTLOG_MAX_PAYLOAD || out.len() < n {
        return None;
    }
    let mut i = 0usize;
    while i < n {
        let hi = hex_val(hex[2 * i])?;
        let lo = hex_val(hex[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Some(n)
}

/// `true` iff `b` is a lowercase-hex byte (`[0-9a-f]`) -- the regex-inertness
/// predicate the safety harness quantifies over the payload region.
#[inline]
pub const fn is_hex_lower(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'a'..=b'f')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_marker_line_is_inert() {
        // The exact guard-colliding line the survey names: framed, its bytes
        // must surface ONLY as lowercase hex (no raw 'M', ':', '(' survive).
        let payload = b"M20: persist OK (no disk, skipped)\n";
        let mut enc = [0u8; GUESTLOG_MAX_FRAME];
        let n = guestlog_encode(payload, &mut enc);
        assert_eq!(n, guestlog_frame_len(payload.len()));
        // The payload region is lowercase-hex-only.
        let hex = &enc[GUESTLOG_PREFIX.len()..n - 1];
        assert!(hex.iter().all(|&b| is_hex_lower(b)));
        // The encoded frame does NOT contain the forbidden substring raw.
        let window = |hay: &[u8], needle: &[u8]| {
            hay.windows(needle.len()).any(|w| w == needle)
        };
        assert!(!window(&enc[..n], b"persist OK"));
        assert!(!window(&enc[..n], b"M20"));
        // Round-trip recovers the exact bytes.
        let mut dec = [0u8; GUESTLOG_MAX_PAYLOAD];
        let m = guestlog_decode(&enc[..n], &mut dec).unwrap();
        assert_eq!(&dec[..m], payload);
    }

    #[test]
    fn encode_fail_closed_on_oversize_and_short_out() {
        let big = [0u8; GUESTLOG_MAX_PAYLOAD + 1];
        let mut out = [0u8; GUESTLOG_MAX_FRAME];
        assert_eq!(guestlog_encode(&big, &mut out), 0);
        let mut tiny = [0u8; 4];
        assert_eq!(guestlog_encode(b"hello", &mut tiny), 0);
    }

    #[test]
    fn decode_rejects_bad_grammar() {
        let mut out = [0u8; GUESTLOG_MAX_PAYLOAD];
        assert_eq!(guestlog_decode(b"guestlog: 4d\n", &mut out), Some(1));
        assert_eq!(out[0], 0x4d);
        assert_eq!(guestlog_decode(b"guestlog: 4D\n", &mut out), None); // uppercase
        assert_eq!(guestlog_decode(b"guestlog: 4\n", &mut out), None); // odd
        assert_eq!(guestlog_decode(b"guestlog: 4d", &mut out), None); // no LF
        assert_eq!(guestlog_decode(b"guestlog:4d\n", &mut out), None); // bad prefix
        assert_eq!(guestlog_decode(b"", &mut out), None);
    }

    #[test]
    fn empty_payload_frames() {
        let mut enc = [0u8; GUESTLOG_MAX_FRAME];
        let n = guestlog_encode(b"", &mut enc);
        assert_eq!(n, GUESTLOG_PREFIX.len() + 1);
        let mut dec = [0u8; GUESTLOG_MAX_PAYLOAD];
        assert_eq!(guestlog_decode(&enc[..n], &mut dec), Some(0));
    }
}
