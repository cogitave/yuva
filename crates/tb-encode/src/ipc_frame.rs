//! The mature 16-byte on-wire IPC message frame codec + a fixed-capacity ring.
//!
//! `tb-hal::ipc` today moves an INLINE scalar payload + an in-transit capability
//! through a `VecDeque`-backed ring; the variable-length BYTE payload IPC
//! (`copy_to/from_user`) is deferred. This module defines the STABLE 16-byte
//! frame the byte-payload path will (de)serialize across the user/kernel
//! boundary, NOW, so that future work lands on a pre-verified codec with a real
//! round-trip + malformed-rejection proof -- rather than inventing a throwaway
//! wire format later.
//!
//! Pure, `#![forbid(unsafe_code)]`, zero-alloc: the frame is a fixed `[u8; 16]`
//! and the ring is a fixed `[T; N]`, so both are model-checkable by Kani with no
//! symbolic-heap blow-up.

/// On-wire size of one [`MessageFrame`] in bytes.
pub const FRAME_SIZE: usize = 16;

/// Bit 0 of the flags byte: a capability accompanies this message.
const FLAG_CAP_PRESENT: u8 = 0x01;

/// All flag bits that carry meaning in v0. Any OTHER bit set in the flags byte
/// is reserved and makes [`MessageFrame::decode`] fail closed.
const FLAG_KNOWN_MASK: u8 = FLAG_CAP_PRESENT;

/// A decoded IPC message frame: an inline scalar `payload`, a `cap_present`
/// flag (whether a moved capability rides alongside), and the moved capability's
/// `rights` bitset (meaningful only when `cap_present`).
///
/// Wire layout (v0, little-endian, 16 bytes):
/// ```text
/// off  size  field        notes
///   0    8   payload      u64 LE
///   8    4   rights       u32 LE
///  12    1   flags        bit0 = cap_present; bits[7:1] reserved (0)
///  13    3   reserved     must be 0
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageFrame {
    /// The inline scalar payload (the M14 inline-ABI "bytes").
    pub payload: u64,
    /// Whether a moved capability accompanies this message.
    pub cap_present: bool,
    /// The moved capability's rights bitset (meaningful iff `cap_present`).
    pub rights: u32,
}

/// Why decoding a byte buffer into a [`MessageFrame`] failed. `Copy` so the
/// kernel can log it without allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// Fewer than [`FRAME_SIZE`] bytes were available.
    ShortBuffer {
        /// Bytes required ([`FRAME_SIZE`]).
        need: usize,
        /// Bytes actually available.
        got: usize,
    },
    /// A reserved flag bit or a reserved trailing byte was non-zero -- a
    /// malformed/forward-incompatible frame, rejected fail-closed.
    ReservedBitsSet,
}

impl MessageFrame {
    /// Construct a frame.
    pub const fn new(payload: u64, cap_present: bool, rights: u32) -> Self {
        MessageFrame {
            payload,
            cap_present,
            rights,
        }
    }

    /// Serialize to the fixed 16-byte little-endian wire form. Total (cannot
    /// fail); every reserved bit/byte is written as 0.
    pub fn encode(&self) -> [u8; FRAME_SIZE] {
        let mut out = [0u8; FRAME_SIZE];
        out[0..8].copy_from_slice(&self.payload.to_le_bytes());
        out[8..12].copy_from_slice(&self.rights.to_le_bytes());
        out[12] = if self.cap_present { FLAG_CAP_PRESENT } else { 0 };
        // out[13..16] stay 0 (reserved).
        out
    }

    /// Parse a frame from the front of `bytes`. Fail-closed: a short buffer or
    /// ANY reserved flag-bit / trailing-byte set returns `Err` -- it NEVER
    /// panics for any input. On success `encode()` reproduces these 16 bytes
    /// exactly (proven in `proofs.rs`).
    pub fn decode(bytes: &[u8]) -> Result<MessageFrame, FrameError> {
        if bytes.len() < FRAME_SIZE {
            return Err(FrameError::ShortBuffer {
                need: FRAME_SIZE,
                got: bytes.len(),
            });
        }
        let flags = bytes[12];
        if flags & !FLAG_KNOWN_MASK != 0 {
            return Err(FrameError::ReservedBitsSet);
        }
        if bytes[13] != 0 || bytes[14] != 0 || bytes[15] != 0 {
            return Err(FrameError::ReservedBitsSet);
        }
        let mut p = [0u8; 8];
        p.copy_from_slice(&bytes[0..8]);
        let mut r = [0u8; 4];
        r.copy_from_slice(&bytes[8..12]);
        Ok(MessageFrame {
            payload: u64::from_le_bytes(p),
            cap_present: flags & FLAG_CAP_PRESENT != 0,
            rights: u32::from_le_bytes(r),
        })
    }
}

/// A fixed-capacity, single-owner FIFO over an inline `[T; N]` (no alloc): the
/// pure shape behind a bounded IPC ring. `push` into a full ring is rejected
/// (returns `false`) -- never unbounded growth, never a panic. `N` must be `> 0`.
///
/// Invariants (proven in `proofs.rs`): `len() <= N` always; FIFO order; a
/// `push` succeeds iff the ring was not full.
#[derive(Clone, Copy, Debug)]
pub struct BoundedRing<T: Copy, const N: usize> {
    buf: [T; N],
    head: usize,
    len: usize,
}

impl<T: Copy + Default, const N: usize> Default for BoundedRing<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy + Default, const N: usize> BoundedRing<T, N> {
    /// A new empty ring of capacity `N`.
    pub fn new() -> Self {
        BoundedRing {
            buf: [T::default(); N],
            head: 0,
            len: 0,
        }
    }

    /// The capacity bound `N`.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// The number of queued elements (always `<= N`).
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the ring holds no elements.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether the ring is at capacity (a further `push` is rejected).
    pub const fn is_full(&self) -> bool {
        self.len == N
    }

    /// Enqueue `v` at the tail. Returns `false` (and changes nothing) if the
    /// ring is already full -- fail-closed backpressure, no growth, no panic.
    pub fn push(&mut self, v: T) -> bool {
        if self.len == N {
            return false;
        }
        let tail = (self.head + self.len) % N;
        self.buf[tail] = v;
        self.len += 1;
        true
    }

    /// Dequeue from the head in FIFO order, or `None` if empty.
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let v = self.buf[self.head];
        self.head = (self.head + 1) % N;
        self.len -= 1;
        Some(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrips() {
        for &(p, c, r) in &[
            (0u64, false, 0u32),
            (0xDEAD_BEEF_F00D_CAFE, true, 0x0000_00FF),
            (u64::MAX, true, u32::MAX),
            (1, false, 0xA5A5_A5A5),
        ] {
            let f = MessageFrame::new(p, c, r);
            assert_eq!(MessageFrame::decode(&f.encode()), Ok(f));
        }
    }

    #[test]
    fn decode_rejects_short_buffer() {
        assert_eq!(
            MessageFrame::decode(&[0u8; FRAME_SIZE - 1]),
            Err(FrameError::ShortBuffer {
                need: FRAME_SIZE,
                got: FRAME_SIZE - 1
            })
        );
    }

    #[test]
    fn decode_rejects_reserved_bits() {
        let mut b = MessageFrame::new(7, true, 9).encode();
        b[12] |= 0x80; // a reserved flag bit
        assert_eq!(MessageFrame::decode(&b), Err(FrameError::ReservedBitsSet));

        let mut b2 = MessageFrame::new(7, true, 9).encode();
        b2[15] = 1; // a reserved trailing byte
        assert_eq!(MessageFrame::decode(&b2), Err(FrameError::ReservedBitsSet));
    }

    #[test]
    fn ring_is_fifo_and_bounded() {
        let mut r: BoundedRing<u32, 3> = BoundedRing::new();
        assert!(r.push(1));
        assert!(r.push(2));
        assert!(r.push(3));
        assert!(!r.push(4)); // full -> rejected
        assert_eq!(r.len(), 3);
        assert_eq!(r.pop(), Some(1));
        assert_eq!(r.pop(), Some(2));
        assert!(r.push(5)); // space again
        assert_eq!(r.pop(), Some(3));
        assert_eq!(r.pop(), Some(5));
        assert_eq!(r.pop(), None);
    }

    // -----------------------------------------------------------------------
    // Extra UB-surface coverage for the Tier-0 Miri gate
    // (.github/workflows/miri.yml). `decode` is the UNTRUSTED-input parser, so
    // we drive it over a spread of buffer lengths + fill patterns (Miri checks
    // every path for OOB / uninitialized reads), and we sweep the ring to
    // capacity + overflow + index wrap-around.
    // -----------------------------------------------------------------------

    #[test]
    fn frame_roundtrip_covers_flag_rights_payload_matrix() {
        for &cap in &[false, true] {
            for &rights in &[0u32, 1, 0x8000_0000, u32::MAX, 0x1234_5678] {
                for &payload in &[0u64, 1, u64::MAX, 0xDEAD_BEEF_0000_0001] {
                    let f = MessageFrame::new(payload, cap, rights);
                    let bytes = f.encode();
                    // Reserved discipline: byte 12 carries only the cap bit;
                    // bytes 13..16 are always zero.
                    assert_eq!(bytes[12] & 0xFE, 0);
                    assert_eq!(bytes[13], 0);
                    assert_eq!(bytes[14], 0);
                    assert_eq!(bytes[15], 0);
                    assert_eq!(MessageFrame::decode(&bytes), Ok(f));
                }
            }
        }
    }

    #[test]
    fn decode_is_total_over_every_buffer_length() {
        // Buffers of EVERY length 0..=FRAME_SIZE+2 under several fill patterns.
        // `decode` must never panic and must be fail-closed on short input.
        let mut full = [0u8; FRAME_SIZE + 2];
        for &fill in &[0u8, 0xFF, 0x80, 0x01, 0xA5] {
            for b in full.iter_mut() {
                *b = fill;
            }
            for len in 0..=FRAME_SIZE + 2 {
                let buf = &full[..len];
                match MessageFrame::decode(buf) {
                    Ok(f) => {
                        // Only a >=16-byte, all-reserved-clear buffer decodes Ok;
                        // here only the all-zero fill is well-formed, and
                        // re-encoding reproduces the consumed 16 bytes exactly.
                        assert!(len >= FRAME_SIZE);
                        assert_eq!(fill, 0);
                        assert_eq!(&f.encode()[..], &buf[..FRAME_SIZE]);
                    }
                    Err(FrameError::ShortBuffer { need, got }) => {
                        assert!(len < FRAME_SIZE);
                        assert_eq!(need, FRAME_SIZE);
                        assert_eq!(got, len);
                    }
                    Err(FrameError::ReservedBitsSet) => {
                        // A full-length buffer whose reserved bits/bytes are set.
                        assert!(len >= FRAME_SIZE);
                        assert_ne!(fill, 0);
                    }
                }
            }
        }
    }

    #[test]
    fn decode_rejects_each_reserved_bit_independently() {
        // Each reserved flag bit (bits 1..=7 of byte 12) and each reserved
        // trailing byte (13,14,15) must INDEPENDENTLY force a fail-closed reject.
        let base = MessageFrame::new(0xAA55, true, 0x0F0F).encode();
        for bit in 1..8u32 {
            let mut b = base;
            b[12] |= 1u8 << bit;
            assert_eq!(MessageFrame::decode(&b), Err(FrameError::ReservedBitsSet));
        }
        for idx in 13..16usize {
            let mut b = base;
            b[idx] = 0xFF;
            assert_eq!(MessageFrame::decode(&b), Err(FrameError::ReservedBitsSet));
        }
        // Control: the untouched base frame still decodes Ok.
        assert_eq!(
            MessageFrame::decode(&base),
            Ok(MessageFrame::new(0xAA55, true, 0x0F0F))
        );
    }

    #[test]
    fn ring_capacity_one_cycles_without_growth() {
        let mut r: BoundedRing<u8, 1> = BoundedRing::new();
        assert!(r.is_empty());
        assert_eq!(r.capacity(), 1);
        assert!(r.push(7));
        assert!(r.is_full());
        assert!(!r.push(8)); // overflow rejected, no growth, no panic
        assert_eq!(r.len(), 1);
        assert_eq!(r.pop(), Some(7));
        assert!(r.is_empty());
        assert_eq!(r.pop(), None);
    }

    #[test]
    fn ring_wraps_head_around_the_buffer() {
        // Sustain 2 in flight while pushing/popping 20 more, so head and tail
        // sweep past the end of the [T; N] repeatedly; Miri validates that each
        // indexed access stays in-bounds across every modular wrap.
        let mut r: BoundedRing<u32, 4> = BoundedRing::new();
        let mut next_in = 0u32;
        let mut next_out = 0u32;
        assert!(r.push(next_in));
        next_in += 1;
        assert!(r.push(next_in));
        next_in += 1;
        for _ in 0..20 {
            assert!(r.push(next_in));
            next_in += 1;
            assert_eq!(r.pop(), Some(next_out));
            next_out += 1;
        }
        // Drain the remaining 2 in FIFO order.
        assert_eq!(r.pop(), Some(next_out));
        next_out += 1;
        assert_eq!(r.pop(), Some(next_out));
        next_out += 1;
        assert_eq!(r.pop(), None);
        assert_eq!(next_in, next_out);
    }

    #[test]
    fn ring_fills_then_rejects_overflow_then_drains_fifo() {
        let mut r: BoundedRing<u16, 8> = BoundedRing::new();
        for k in 0..8u16 {
            assert_eq!(r.len(), k as usize);
            assert!(r.push(k));
        }
        assert!(r.is_full());
        // Repeated overflow attempts are all rejected; state is unchanged.
        for _ in 0..3 {
            assert!(!r.push(0xFFFF));
            assert_eq!(r.len(), 8);
        }
        for k in 0..8u16 {
            assert_eq!(r.pop(), Some(k));
        }
        assert!(r.is_empty());
        assert_eq!(r.pop(), None);
    }

    #[test]
    fn ring_default_is_empty_with_capacity() {
        let mut r: BoundedRing<u64, 5> = BoundedRing::default();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert_eq!(r.capacity(), 5);
        assert!(r.push(99));
        assert_eq!(r.pop(), Some(99));
    }
}
