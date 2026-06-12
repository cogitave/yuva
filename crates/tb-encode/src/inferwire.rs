//! The M30 verified INFERENCE-TRANSPORT wire codec -- the pure, verified value-
//! computation leaf behind the guest<->host inference CHANNEL: a typed, fixed-
//! header, length-prefixed, INJECTIVE [`InferFrame`] the kernel exchanges with a
//! HOST peer over a modern virtio-mmio console channel (DeviceID 3), plus the
//! length-delimited [`FrameAccum`] byte-STREAM accumulator and the host-keyed
//! [`echo_tag`]/[`verify_echo`] pair (ONE domain-separated [`crate::khash`]
//! call). This is the sovereignty A-chain's transport (#87): the channel a host
//! model peer will speak in M31+; M30 itself is TRANSPORT-ONLY (`backend=
//! ECHO-ONLY` -- no model, no inference semantics).
//!
//! ## What this is FOR (proposal §1/§4 -- the anti-hollow echo)
//!
//! The M22 runner-up shipped this exact design but its round-trip terminated at
//! an in-kernel mock loopback (a hollow pass). M30's DoD is a HOST-APPLIED
//! khash-transformed echo: the kernel emits an `ECHO_REQ` carrying a per-boot
//! CHALLENGE; the HOST peer (which custodies a per-run OS-RNG key K and nonce N
//! -- NEVER compiled into the guest image or its command line) answers with an
//! `ECHO_RESP` whose [`echo_tag`] binds `peer_id || N || challenge || body`
//! INSIDE the MAC (the M28/Terrapin bind-inside-the-MAC lesson, arXiv:
//! 2312.12422), revealing K on the channel for the kernel-side recompute. The
//! kernel verifies via [`verify_echo`] (leg 1, kernel-scope) AND the run script
//! string-compares the kernel-witnessed challenge/tag against the host peer's
//! independently printed line (leg 2, the loopback killer). Anti-hollow is the
//! COMPOSITION of both legs; neither alone is the DoD (proposal §4).
//!
//! ## Honest scope (proposal §12 -- the marker claims ONLY what is proved)
//!
//! * **`echo=HOST-KEYED-VERIFIED` is kernel-scope, NOT loopback-exclusion.** A
//!   loopback can mint its own `K*`/`N*` and self-verify with this same leaf;
//!   in-guest verification proves only khash-correctness of whatever arrived
//!   against the CHANNEL-REVEALED key, plus that the response binds THIS boot's
//!   challenge. Loopback exclusion lives in the GUARD's cross-process
//!   tag-equality against the host-custodied key (proposal §5.6).
//! * **`key=HOST-CUSTODIED-PER-RUN` -- no confidentiality, no forward auth.** K
//!   is REVEALED in cleartext on the channel (the [`INFER_KEY_REVEAL_LEN`]
//!   trailer); the echo is a per-run liveness/integrity WITNESS against hollow
//!   evidence, NOT a secure channel and NOT authentication against an
//!   adversarial host (the host is trusted ground). Host *participation* is
//!   proven (host-held nonce + the script cross-check), host *exclusivity* is
//!   NOT (a signature primitive is the named M33 successor).
//! * **`sec=ASSUMED-FROM-LITERATURE`** (inherited from M29): the PRF strength
//!   of [`crate::khash`] is assumed, never proven; there is deliberately NO
//!   symbolic collision/preimage/PRF harness (overclaim-by-implication, banned).
//! * **No network / TLS / encryption** -- the peer is a local host process.
//!
//! ## Wire format (canonical little-endian, fixed offsets, proposal §2)
//!
//! ```text
//!   [0..2]    magic        u16 LE  (== INFER_MAGIC 0x5958, the next house magic
//!                                   after opframe 0x5956 / opframe_rx 0x5957)
//!   [2]       ver          u8      (== INFER_VER)
//!   [3]       kind         u8      (ECHO_REQ=1 | ECHO_RESP=2 | ERR=3)
//!   [4]       flags        u8      reserved-zero (fail-closed)
//!   [5..13]   req_id       u64 LE  correlation id (in-flight window = 1 today,
//!                                   on the wire from day one -- 9p2000 tag
//!                                   precedent, so pipelining/IRQ migration
//!                                   never forces a frame-version bump)
//!   [13..29]  challenge    [u8;16] kernel-chosen per boot (REQ); echoed
//!                                   verbatim + MAC-bound (RESP)
//!   [29..45]  nonce        [u8;16] HOST-chosen per run (zero in a REQ)
//!   [45]      peer_id      u8      0x01=TB-VMM-HOST 0x02=QEMU-CHARDEV-HARNESS
//!                                   (zero in a REQ; MAC-covered in a RESP)
//!   [46..62]  tag          [u8;16] truncated khash echo (zero in a REQ)
//!   [62..66]  payload_len  u32 LE  <-- the length-prefix (injectivity
//!                                   disambiguator; capped at INFER_PAYLOAD_CAP)
//!   [66..]    payload[i]   u8      verbatim (a RESP echoes the REQ body
//!                                   verbatim -- body-bitexact)
//! ```
//!
//! The byte-stream lane (QEMU `virtconsole` + chardev) does NOT preserve message
//! boundaries, so [`FrameAccum`] (the [`crate::ipc_frame::BoundedRing`] pattern,
//! length-delimited) re-frames the stream fail-closed with scan-to-next-magic
//! resync -- stronger than COBS for this 8-bit-clean reliable channel (research
//! §5: COBS delimits but cannot detect corruption; a magic+length+MAC frame does
//! both). The tb-vmm lane (stage C) delivers whole descriptor-chain buffers and
//! decodes directly -- SAME [`decode`], one codec.
//!
//! ## Numeric format (no float, ever -- mirrors `opframe_rx`/`khash`)
//!
//! Pure integer/byte arithmetic, zero alloc, zero deps. [`canon`] is total +
//! fail-closed (returns 0, never panics, never partial-writes); [`decode`] is
//! its fail-closed inverse (`None` on ANY malformed input). The MAC math is the
//! verified [`crate::khash`] BLAKE2s-256 leaf (M29) -- NO new hash math is
//! written here, exactly as M28/M29 reuse one primitive.
//!
//! ## The M31 inference-ADAPTER extension (same leaf, same magic, same ver)
//!
//! M31 (proposal `docs/proposals/M31-real-infer.md` §2) EXTENDS this leaf --
//! deliberately not a 21st leaf -- with the byte-prompt/byte-response framing:
//! the closed kinds [`kind::INFER_REQ`]/[`kind::INFER_RESP`]/
//! [`kind::INFER_PENDING`], the closed-enum [`kind::ERR`] payload semantics
//! ([`errcode`]), the 24-byte in-payload chunk [`SubHdr`] (chunked
//! stop-and-wait under the UNCHANGED [`INFER_PAYLOAD_CAP`]), the per-chunk
//! [`infer_tag`]/[`verify_infer_resp`]/[`verify_infer_req`] MAC under the NEW
//! [`INFER_DOMAIN`] separator, the Kani-proven fail-closed [`InferAssembler`],
//! the compile-time shared [`INFER_BODY_CAP`] (reject-never-truncate), and the
//! shared deterministic [`mock_infer`] transform. The M30 header codec --
//! including the reserved-zero `flags` byte -- is BYTE-IDENTICAL; the only
//! observable widening is the kind set (7+ still rejects everywhere).

use crate::khash::{khash, KHASH_KEY_LEN};

/// The fixed inference-transport frame magic (`0x5958`) -- the next house
/// magic after the M25 opframe (`0x5956`) and the M28 opframe_rx (`0x5957`),
/// so a transport frame is never mistaken for an operator frame.
/// [`canon`]/[`decode`] reject any other value. Derived in
/// `brand::MAGIC_INFERWIRE` (the brand wire-magic family +2), never
/// re-spelled here.
pub const INFER_MAGIC: u16 = brand::MAGIC_INFERWIRE;

/// The inference-transport frame format version. [`canon`]/[`decode`] reject
/// any other value (fail-closed -- an unknown version is incompatible).
pub const INFER_VER: u8 = 1;

/// The maximum payload length a frame may carry (bytes). Keeps the frame --
/// and every Kani harness over it -- BOUNDED (the #49 discipline), and pins
/// the [`FrameAccum`] capacity to the worst-case wire length. [`canon`] and
/// [`decode`] both fail closed past it (an oversize `payload_len` is a
/// desync/garbage indicator on a stream, never a bigger buffer).
pub const INFER_PAYLOAD_CAP: usize = 1024;

/// The truncated echo-tag width (bytes): the leading 16 bytes of the keyed
/// BLAKE2s-256 tag (truncation precedent: `opframe_rx::MAC_LEN`; RFC 2104 §5 /
/// SP 800-107r1 §5.3.4 sanction t=128).
pub const INFER_TAG_LEN: usize = 16;

/// The kernel-chosen per-boot challenge width (bytes).
pub const INFER_CHALLENGE_LEN: usize = 16;

/// The host-chosen per-run nonce width (bytes).
pub const INFER_NONCE_LEN: usize = 16;

/// The host echo-key width (bytes) == the khash native key width.
pub const INFER_KEY_LEN: usize = KHASH_KEY_LEN;

/// The M30 CHANNEL-layer key-reveal convention (proposal §4/§12): after the
/// `ECHO_RESP` frame bytes, the host peer reveals its per-run key K as exactly
/// this many raw cleartext bytes on the stream, so the kernel can recompute the
/// tag with [`verify_echo`]. The reveal is a CHANNEL convention, not a frame
/// field -- K MACs itself, so it cannot ride inside the MAC'd bytes. HONEST:
/// this is why `key=HOST-CUSTODIED-PER-RUN` claims custody (where K was BORN
/// and who printed it), never confidentiality (K is cleartext on the wire).
pub const INFER_KEY_REVEAL_LEN: usize = KHASH_KEY_LEN;

/// The echo-MAC domain separator (proposal §2): the fixed leading label inside
/// the keyed-hash message, keeping the M30 echo disjoint from every other keyed
/// use of the primitive (the M28 `KDF_DOMAIN`/`EVOLVE_DOMAIN` precedent). The
/// MAC'd message is `ECHO_DOMAIN || peer_id || nonce || challenge || body`.
/// The bytes (`"YUVA-M30-ECHO-V1"`) DERIVE from `brand::DOMSEP_M30_ECHO` --
/// the kernel and `tools/xport-harness` share this one const, so the leg-2
/// cross-process tag equality can never drift on the label.
pub const ECHO_DOMAIN: &[u8] = brand::DOMSEP_M30_ECHO;

// Width sanity (compile-time): the khash leaf is width-exact to this seam.
const _: () = assert!(INFER_KEY_LEN == KHASH_KEY_LEN);
const _: () = assert!(INFER_TAG_LEN <= crate::khash::KHASH_TAG_LEN); // sanctioned truncation

/// The fixed frame KIND tags (M30 proposal §2 + M31 proposal §2a -- the typed
/// transport vocabulary). A closed set; [`canon`]/[`decode`] reject any other
/// value (fail-closed). The M31 extension adds the INFERENCE kinds 4..6 and
/// gives the reserved `ERR` payload semantics ([`err_canon`]/[`err_decode`]);
/// unknown kinds (7+) keep rejecting at `canon`/`decode`/[`FrameAccum`] scan
/// -- the extension does not widen totality (`kani_inferwire_kind_ext`).
pub mod kind {
    /// Kernel -> host: the echo REQUEST carrying the per-boot challenge.
    pub const ECHO_REQ: u8 = 1;
    /// Host -> kernel: the keyed echo RESPONSE (nonce + peer_id + tag set,
    /// body echoed verbatim).
    pub const ECHO_RESP: u8 = 2;
    /// Host -> kernel: a typed error indication. Reserved at M30 (so the
    /// adapter never overloads `ECHO_*`); M31 gives it a CLOSED-enum payload
    /// (`{code:u16, retryable:u8, rsv:u8}` -- [`super::errcode`],
    /// [`super::err_canon`]/[`super::err_decode`]). Raw provider error text
    /// NEVER rides this frame (M31 proposal §2e).
    pub const ERR: u8 = 3;
    /// Kernel -> host: ONE chunk of a byte-prompt inference REQUEST (M31
    /// proposal §2b -- payload = the 24-byte [`super::SubHdr`] + chunk bytes,
    /// stop-and-wait lockstep under the UNTOUCHED [`super::INFER_PAYLOAD_CAP`]).
    pub const INFER_REQ: u8 = 4;
    /// Host -> kernel: ONE chunk of a byte inference RESPONSE (same chunked
    /// sub-header layout; every chunk MAC'd via [`super::infer_tag`]).
    pub const INFER_RESP: u8 = 5;
    /// Host -> kernel: a MAC'd empty-payload liveness heartbeat while the
    /// host-side call is in flight (M31 proposal §2f). A verified PENDING
    /// resets the guest's poll budget; it is liveness plumbing, NOT flow
    /// control, and NEVER a completion (a run that ends on pendings is a
    /// hard `xport-timeout` FAIL).
    pub const INFER_PENDING: u8 = 6;
}

/// The host peer-identity bytes (proposal §2) -- MAC-covered in every RESP, so
/// the run-script lane-token cross-pin (§5.4) is bound INSIDE the tag and a
/// host cannot be mislabeled after the fact.
pub mod peer {
    /// The tb-vmm in-process device backend (stage C -- the vmm lane).
    pub const TB_VMM_HOST: u8 = 0x01;
    /// The stock-QEMU `virtconsole`+chardev harness (the TCG lanes).
    pub const QEMU_CHARDEV_HARNESS: u8 = 0x02;
}

/// A fixed, canonical inference-transport frame (proposal §2). Every header
/// field sits at a FIXED offset and the variable `payload` is LENGTH-PREFIXED
/// (the `payload_len` u32), so [`canon`] is injective. Borrowed `payload` so
/// the leaf stays zero-alloc. The reserved `flags` byte is NOT represented:
/// [`canon`] always writes 0 and [`decode`] rejects nonzero (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InferFrame<'a> {
    /// The frame kind (see [`kind`]): echo-req | echo-resp | err.
    pub kind: u8,
    /// The correlation id ([`resp_binds_req`] is the binding theorem). 9p2000
    /// `tag` / EIP CorrelationID precedent; window = 1 in M30, wire-ready for
    /// pipelining.
    pub req_id: u64,
    /// The kernel-chosen per-boot challenge (REQ), echoed verbatim AND
    /// MAC-bound in the RESP (freshness -- a canned cross-boot response binds
    /// a different challenge and fails [`verify_echo`]).
    pub challenge: [u8; INFER_CHALLENGE_LEN],
    /// The HOST-chosen per-run nonce (zero in a REQ; host-set + MAC-bound in
    /// the RESP -- the host-participation anchor).
    pub nonce: [u8; INFER_NONCE_LEN],
    /// The host peer identity (see [`peer`]; zero in a REQ; MAC-covered in the
    /// RESP so the lane token cannot be forged after the tag is fixed).
    pub peer_id: u8,
    /// The truncated keyed echo tag (zero in a REQ; [`echo_tag`] in a RESP).
    pub tag: [u8; INFER_TAG_LEN],
    /// The opaque payload bytes (length-prefixed in [`canon`]; a RESP echoes
    /// the REQ body verbatim -- body-bitexact).
    pub payload: &'a [u8],
}

/// The fixed frame HEADER length (everything before the variable payload):
/// `magic(2) | ver(1) | kind(1) | flags(1) | req_id(8) | challenge(16) |
/// nonce(16) | peer_id(1) | tag(16) | payload_len(4)` = 66 bytes.
pub const INFER_HEADER_LEN: usize =
    2 + 1 + 1 + 1 + 8 + INFER_CHALLENGE_LEN + INFER_NONCE_LEN + 1 + INFER_TAG_LEN + 4;

// Fixed field offsets (the header layout above). Named consts so the encoder,
// the decoder, the tests and the Kani harnesses all read the SAME literals
// (pub(crate) so `proofs.rs` perturbs the EXACT offsets the encoder writes).
pub(crate) const OFF_MAGIC: usize = 0;
pub(crate) const OFF_VER: usize = 2;
pub(crate) const OFF_KIND: usize = 3;
pub(crate) const OFF_FLAGS: usize = 4;
pub(crate) const OFF_REQ_ID: usize = 5;
pub(crate) const OFF_CHALLENGE: usize = 13;
pub(crate) const OFF_NONCE: usize = 29;
pub(crate) const OFF_PEER: usize = 45;
pub(crate) const OFF_TAG: usize = 46;
/// The offset of the `payload_len` u32 LE length-prefix (the disambiguator).
pub const OFF_PAYLOAD_LEN: usize = 62;
/// The offset at which the variable payload begins (== [`INFER_HEADER_LEN`]).
pub const OFF_PAYLOAD: usize = 66;

// The offset table and INFER_HEADER_LEN must agree (compile-time).
const _: () = assert!(OFF_PAYLOAD == INFER_HEADER_LEN);

/// The exact canonical byte length of a frame carrying `payload_len` payload
/// bytes: [`INFER_HEADER_LEN`] + `payload_len`, computed with SATURATING
/// arithmetic so a pathological length can never overflow `usize` (total --
/// never panics). The M30 frame has NO trailing MAC (the tag sits INSIDE the
/// header at a fixed offset), so canon == wire for the frame itself; the
/// channel-layer key reveal ([`INFER_KEY_REVEAL_LEN`]) trails OUTSIDE the frame.
#[inline]
#[must_use]
pub fn canon_len(payload_len: usize) -> usize {
    INFER_HEADER_LEN.saturating_add(payload_len)
}

/// The exact on-wire byte length of `frame` (== [`canon_len`] of its payload
/// length -- the tag is in-header, nothing trails). Total -- never panics.
#[inline]
#[must_use]
pub fn wire_len(frame: &InferFrame) -> usize {
    canon_len(frame.payload.len())
}

/// Whether a payload of `payload_len` bytes is wire-representable:
/// `payload_len <= INFER_PAYLOAD_CAP`. [`canon`] fail-closes (returns 0) when
/// this is false; [`decode`] rejects a declared length past it. Total.
#[inline]
#[must_use]
pub fn frame_is_encodable(payload_len: usize) -> bool {
    payload_len <= INFER_PAYLOAD_CAP
}

/// Whether `k` is a known frame [`kind`] tag (the closed set; M31 widens it
/// to the inference kinds 4..6 -- 7+ keeps rejecting, fail-closed).
#[inline]
#[must_use]
fn kind_known(k: u8) -> bool {
    matches!(
        k,
        kind::ECHO_REQ
            | kind::ECHO_RESP
            | kind::ERR
            | kind::INFER_REQ
            | kind::INFER_RESP
            | kind::INFER_PENDING
    )
}

/// Canonical, UNAMBIGUOUS, total, length-delimited LE encoding of `frame` into
/// `out`. Returns the number of bytes written, or `0` if `out` is too small,
/// the payload exceeds [`INFER_PAYLOAD_CAP`], or the kind is unknown (TOTAL +
/// fail-closed: never panics, never partial-writes -- mirrors
/// [`crate::opframe_rx::canon`]). The reserved `flags` byte is FORCED to 0 (a
/// set reserved bit can never ride out). See the module header for the layout.
///
/// INJECTIVITY: two encodable frames that differ in ANY field encode to
/// different bytes -- fixed-width header fields at fixed offsets + the explicit
/// `payload_len` prefix making the variable tail self-delimiting (the
/// `kani_inferwire_canon_roundtrip` harness discharges this).
#[must_use]
pub fn canon(frame: &InferFrame, out: &mut [u8]) -> usize {
    // Fail-closed VALIDATION FIRST (before any write).
    if !frame_is_encodable(frame.payload.len()) || !kind_known(frame.kind) {
        return 0;
    }
    let plen = frame.payload.len();
    let total = canon_len(plen);
    if out.len() < total {
        return 0; // too-small buffer -> 0 bytes, no partial write (totality)
    }
    write_u16(out, OFF_MAGIC, INFER_MAGIC);
    out[OFF_VER] = INFER_VER;
    out[OFF_KIND] = frame.kind;
    out[OFF_FLAGS] = 0; // reserved-zero, forced
    write_u64(out, OFF_REQ_ID, frame.req_id);
    let mut c = 0usize;
    while c < INFER_CHALLENGE_LEN {
        out[OFF_CHALLENGE + c] = frame.challenge[c];
        c += 1;
    }
    let mut n = 0usize;
    while n < INFER_NONCE_LEN {
        out[OFF_NONCE + n] = frame.nonce[n];
        n += 1;
    }
    out[OFF_PEER] = frame.peer_id;
    let mut t = 0usize;
    while t < INFER_TAG_LEN {
        out[OFF_TAG + t] = frame.tag[t];
        t += 1;
    }
    write_u32(out, OFF_PAYLOAD_LEN, plen as u32);
    let mut p = 0usize;
    while p < plen {
        out[OFF_PAYLOAD + p] = frame.payload[p];
        p += 1;
    }
    total
}

/// The exact inverse of [`canon`]: decode the header at fixed offsets + borrow
/// the length-prefixed payload, or `None` if `buf` is too short for the header,
/// carries a bad magic / version / nonzero reserved `flags` / unknown kind, the
/// declared `payload_len` exceeds [`INFER_PAYLOAD_CAP`], or `buf` is too short
/// for the declared payload (TOTAL, fail-closed: never panics for ANY input --
/// the `kani_inferwire_decode_total` harness). Trailing bytes BEYOND the frame
/// are permitted and ignored (the channel-layer key reveal rides there); the
/// returned frame borrows `buf` for its payload (zero-copy).
#[must_use]
pub fn decode(buf: &[u8]) -> Option<InferFrame<'_>> {
    if buf.len() < INFER_HEADER_LEN {
        return None; // truncated header
    }
    if read_u16(buf, OFF_MAGIC) != INFER_MAGIC {
        return None; // foreign byte stream
    }
    if buf[OFF_VER] != INFER_VER {
        return None; // incompatible version
    }
    if buf[OFF_FLAGS] != 0 {
        return None; // a set reserved bit is a malformed frame (fail-closed)
    }
    let kind = buf[OFF_KIND];
    if !kind_known(kind) {
        return None; // unknown kind -- fail closed
    }
    let plen = read_u32(buf, OFF_PAYLOAD_LEN) as usize;
    if !frame_is_encodable(plen) {
        return None; // oversize declared length: desync/garbage, never a frame
    }
    let end = INFER_HEADER_LEN + plen; // no overflow: plen <= 1024
    if buf.len() < end {
        return None; // truncated payload
    }
    let req_id = read_u64(buf, OFF_REQ_ID);
    let mut challenge = [0u8; INFER_CHALLENGE_LEN];
    let mut c = 0usize;
    while c < INFER_CHALLENGE_LEN {
        challenge[c] = buf[OFF_CHALLENGE + c];
        c += 1;
    }
    let mut nonce = [0u8; INFER_NONCE_LEN];
    let mut n = 0usize;
    while n < INFER_NONCE_LEN {
        nonce[n] = buf[OFF_NONCE + n];
        n += 1;
    }
    let mut tag = [0u8; INFER_TAG_LEN];
    let mut t = 0usize;
    while t < INFER_TAG_LEN {
        tag[t] = buf[OFF_TAG + t];
        t += 1;
    }
    Some(InferFrame {
        kind,
        req_id,
        challenge,
        nonce,
        peer_id: buf[OFF_PEER],
        tag,
        payload: &buf[OFF_PAYLOAD..end],
    })
}

/// THE correlation-binding theorem (proposal §2): `resp` answers the request
/// with id `req_id` IFF its `req_id` equals it AND its kind is
/// [`kind::ECHO_RESP`] (an ERR or a reflected REQ never binds). Pure compares,
/// total -- the `kani_inferwire_req_binding` harness proves the iff both ways.
#[inline]
#[must_use]
pub fn resp_binds_req(resp: &InferFrame, req_id: u64) -> bool {
    resp.kind == kind::ECHO_RESP && resp.req_id == req_id
}

/// The maximum khash message the echo MAC ever sees: the domain label + the
/// MAC-covered fields + a cap-bounded body.
const ECHO_MSG_CAP: usize =
    ECHO_DOMAIN.len() + 1 + INFER_NONCE_LEN + INFER_CHALLENGE_LEN + INFER_PAYLOAD_CAP;

/// The host-keyed echo tag (proposal §2/§4): EXACTLY ONE call of the verified
/// [`crate::khash`] BLAKE2s-256 leaf, domain-separated --
///
/// ```text
///   T = khash(K, ECHO_DOMAIN || peer_id || nonce || challenge || body)[..INFER_TAG_LEN]
/// ```
///
/// The challenge, nonce AND `peer_id` are bound INSIDE the MAC'd bytes (the
/// M28/Terrapin bind-inside-the-MAC lesson) -- so the run script's lane-token
/// cross-pin is itself MAC-covered, and a canned cross-boot response (different
/// challenge) or a relabeled host (different peer_id) moves the tag. All
/// MAC-covered fields before `body` are FIXED-WIDTH, so the concatenation is
/// injective in its parts. TOTAL -- no panic, no alloc (one fixed in-function
/// buffer); `body` is read through `body[..min(len, INFER_PAYLOAD_CAP)]` --
/// bodies past the wire cap are NOT representable in a frame ([`canon`]/
/// [`decode`] fail closed first), so the clamp is unreachable through any wire
/// path and exists only to keep this function total over raw slices.
/// CALLS [`crate::khash::khash`] -- NO new hash math.
#[must_use]
pub fn echo_tag(
    key: &[u8; INFER_KEY_LEN],
    peer_id: u8,
    nonce: &[u8; INFER_NONCE_LEN],
    challenge: &[u8; INFER_CHALLENGE_LEN],
    body: &[u8],
) -> [u8; INFER_TAG_LEN] {
    let blen = if body.len() > INFER_PAYLOAD_CAP {
        INFER_PAYLOAD_CAP // unreachable via any wire path (see doc above)
    } else {
        body.len()
    };
    let mut msg = [0u8; ECHO_MSG_CAP];
    let mut o = 0usize;
    let mut i = 0usize;
    while i < ECHO_DOMAIN.len() {
        msg[o] = ECHO_DOMAIN[i];
        o += 1;
        i += 1;
    }
    msg[o] = peer_id;
    o += 1;
    let mut n = 0usize;
    while n < INFER_NONCE_LEN {
        msg[o] = nonce[n];
        o += 1;
        n += 1;
    }
    let mut c = 0usize;
    while c < INFER_CHALLENGE_LEN {
        msg[o] = challenge[c];
        o += 1;
        c += 1;
    }
    let mut b = 0usize;
    while b < blen {
        msg[o] = body[b];
        o += 1;
        b += 1;
    }
    let full = khash(key, &msg[..o]); // the ONE khash call
    let mut tag = [0u8; INFER_TAG_LEN];
    let mut t = 0usize;
    while t < INFER_TAG_LEN {
        tag[t] = full[t];
        t += 1;
    }
    tag
}

/// LEG 1 -- the kernel-scope echo verification (proposal §4 step 3): accept IFF
/// `resp` is an [`kind::ECHO_RESP`] that BINDS `req` (same `req_id`,
/// [`resp_binds_req`]), ECHOES the request's challenge verbatim, carries the
/// request body BIT-EXACTLY, and its tag equals the recomputed
/// [`echo_tag`]`(key, resp.peer_id, resp.nonce, req.challenge, resp.payload)`.
/// Conjunctive + fail-closed: any single failing leg rejects. TOTAL -- pure
/// compares plus the one khash recompute.
///
/// HONEST (the load-bearing §4 caveat): this verifies against the
/// CHANNEL-REVEALED key the caller passes in -- it proves khash-correctness +
/// challenge/body binding of whatever arrived, NEVER "not a loopback".
/// Loopback exclusion is the run-script guard's cross-process check, outside
/// this leaf.
#[must_use]
pub fn verify_echo(key: &[u8; INFER_KEY_LEN], resp: &InferFrame, req: &InferFrame) -> bool {
    if !resp_binds_req(resp, req.req_id) {
        return false; // wrong kind or wrong correlation id
    }
    if resp.challenge != req.challenge {
        return false; // does not echo THIS boot's challenge
    }
    if resp.payload.len() != req.payload.len() {
        return false; // body length moved
    }
    let mut i = 0usize;
    while i < resp.payload.len() {
        if resp.payload[i] != req.payload[i] {
            return false; // body not bit-exact
        }
        i += 1;
    }
    let expect = echo_tag(key, resp.peer_id, &resp.nonce, &req.challenge, resp.payload);
    expect == resp.tag
}

/// The byte-STREAM frame accumulator (proposal §2 -- the chardev lane's
/// re-framer; the [`crate::ipc_frame::BoundedRing`] fixed-capacity pattern,
/// length-delimited). A stream transport preserves NO message boundaries, so
/// bytes are pushed ONE AT A TIME and the accumulator emits `Some(frame_len)`
/// exactly when a complete, BYTE-WISE-VALIDATED frame sits at the front of its
/// buffer (decodable by construction -- the Kani harness proves emitted =>
/// `decode(..).is_some()`; every CALLER then runs the proven [`decode`] on the
/// emitted window, keeping the codec the fail-closed arbiter at the
/// consumption point). Fail-closed RESYNC: any byte that makes the buffered
/// prefix implausible (wrong magic/version/reserved/kind, an oversize declared
/// length) drops the front byte(s) and re-scans to the next [`INFER_MAGIC`]
/// candidate -- garbage can delay a frame, never overflow the buffer or fake
/// one past the byte-wise rule set [`decode`] re-checks downstream.
///
/// INVARIANTS (proven in `kani_inferwire_accum_resync` at a tiny `CAP` + held
/// by construction at the real cap): `len() <= CAP` ALWAYS; a `push_byte` never
/// panics; a pure-garbage stream (no magic byte) never emits a frame. `CAP`
/// must be >= the longest expected wire frame ([`INFER_ACCUM_CAP`] for the M30
/// channel) or such frames can never complete and are dropped by resync --
/// fail-closed, never unsound. NOTE (proposal §10, the honesty note): this
/// recovers the DECODER's framing on a byte stream; it is NOT live virtqueue
/// reset-and-reinit (a named deferral).
#[derive(Clone, Copy, Debug)]
pub struct FrameAccum<const CAP: usize> {
    buf: [u8; CAP],
    len: usize,
}

/// The [`FrameAccum`] capacity sized for the M30 channel: ONE worst-case frame
/// ([`INFER_HEADER_LEN`] + [`INFER_PAYLOAD_CAP`] = 1090 bytes), so every valid
/// frame can complete.
pub const INFER_ACCUM_CAP: usize = INFER_HEADER_LEN + INFER_PAYLOAD_CAP;

impl<const CAP: usize> Default for FrameAccum<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAP: usize> FrameAccum<CAP> {
    /// A new, empty accumulator.
    #[must_use]
    pub const fn new() -> Self {
        FrameAccum {
            buf: [0u8; CAP],
            len: 0,
        }
    }

    /// The number of buffered bytes (always `<= CAP`).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the accumulator holds no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The buffered bytes (a complete frame occupies `[..frame_len]` exactly
    /// when [`push_byte`](Self::push_byte) returned `Some(frame_len)`).
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Drop the front `n` buffered bytes (consume an emitted frame so the next
    /// one can accumulate). Clamped to `len` (total -- never panics).
    pub fn consume(&mut self, n: usize) {
        let n = if n > self.len { self.len } else { n };
        let remain = self.len - n;
        let mut i = 0usize;
        while i < remain {
            self.buf[i] = self.buf[n + i];
            i += 1;
        }
        self.len = remain;
    }

    /// Append one stream byte, then re-scan. Returns `Some(frame_len)` when
    /// the buffer now BEGINS with a complete, byte-wise-validated frame
    /// (decodable by construction; the caller runs [`decode`] on the emitted
    /// window), else `None`. NEVER overflows: at capacity with no complete
    /// frame the front byte is dropped first (resync -- a full buffer of
    /// non-frame bytes is garbage by construction, since `CAP` >= any valid
    /// frame for the M30 alias). NEVER panics for any input byte (total).
    pub fn push_byte(&mut self, b: u8) -> Option<usize> {
        if self.len == CAP {
            self.consume(1); // resync at capacity -- never overflow
        }
        self.buf[self.len] = b;
        self.len += 1;
        self.scan()
    }

    /// Fail-closed front-of-buffer scan: drop bytes until the buffered prefix
    /// is a PLAUSIBLE frame prefix (every [`decode`] header rule enforced
    /// byte-by-byte as it arrives), and emit `Some(total)` once the candidate
    /// is complete.
    fn scan(&mut self) -> Option<usize> {
        loop {
            if self.len == 0 {
                return None;
            }
            // Byte-by-byte plausibility of the front candidate (each check
            // fires as soon as that byte exists, so garbage drops EAGERLY and
            // the buffer only ever fills behind a plausible header).
            if self.buf[0] != (INFER_MAGIC & 0xFF) as u8 {
                self.resync_to_magic();
                continue;
            }
            if self.len >= 2 && self.buf[1] != (INFER_MAGIC >> 8) as u8 {
                self.consume(1);
                continue;
            }
            if self.len > OFF_VER && self.buf[OFF_VER] != INFER_VER {
                self.consume(1);
                continue;
            }
            if self.len > OFF_KIND && !kind_known(self.buf[OFF_KIND]) {
                self.consume(1);
                continue;
            }
            if self.len > OFF_FLAGS && self.buf[OFF_FLAGS] != 0 {
                self.consume(1);
                continue;
            }
            if self.len < INFER_HEADER_LEN {
                return None; // plausible so far, header incomplete
            }
            let plen = read_u32(&self.buf, OFF_PAYLOAD_LEN) as usize;
            if !frame_is_encodable(plen) {
                self.consume(1); // oversize length: desync, resync
                continue;
            }
            let total = INFER_HEADER_LEN + plen;
            if self.len < total {
                return None; // payload incomplete
            }
            // Full candidate buffered. Every rule [`decode`] enforces on the
            // header was already enforced BYTE-WISE as it arrived (magic /
            // version / kind / reserved flags above; the declared-length cap
            // just checked; the payload window is complete by `total`), so
            // the emitted window is decodable BY CONSTRUCTION -- the
            // `kani_inferwire_accum_resync` harness proves emitted =>
            // `decode(..).is_some()`. The CALLER runs the proven [`decode`]
            // on the emitted window (every consumer does -- the kernel
            // selftest, the host harness, the tests), so the codec stays the
            // fail-closed arbiter at the consumption point without being
            // re-inlined into this per-byte hot path (the #49 formula-size
            // discipline).
            return Some(total);
        }
    }

    /// Drop front bytes up to (and aligning on) the next [`INFER_MAGIC`] first
    /// byte, or empty the buffer if none remains.
    fn resync_to_magic(&mut self) {
        let mut i = 1usize; // buf[0] is already known-bad
        while i < self.len {
            if self.buf[i] == (INFER_MAGIC & 0xFF) as u8 {
                self.consume(i);
                return;
            }
            i += 1;
        }
        self.len = 0;
    }
}

// ===========================================================================
// M31: the verified INFERENCE-ADAPTER extension (proposal §2 -- the bulk).
// Same leaf, same magic, same ver=1: byte prompts/responses ride the NEW
// closed kinds INFER_REQ/INFER_RESP/INFER_PENDING as CHUNKED stop-and-wait
// sequences under the UNTOUCHED INFER_PAYLOAD_CAP, each chunk carrying a
// fixed 24-byte IN-PAYLOAD sub-header ([`SubHdr`] -- the header `flags` byte
// stays reserved-zero, so the M30 codec is byte-identical) and a per-chunk
// MAC ([`infer_tag`], ONE khash call under the NEW [`INFER_DOMAIN`] label)
// binding peer_id‖nonce‖challenge‖req_id‖kind‖seq‖sflags‖total_len‖
// body_digest‖chunk INSIDE the MAC (the M28/Terrapin rule -- a reordered,
// spliced, or cross-sequence chunk fails VERIFICATION, not just assembly).
// The whole-body bound is the compile-time shared const [`INFER_BODY_CAP`]:
// both ends compile this SAME leaf, so compile-time agreement is the
// negotiation (research §3, the MQTT/RFC-8449 analog without a handshake to
// get wrong); overflow is REJECT, never truncate (the 413 mirror). The
// fail-closed [`InferAssembler`] (the FrameAccum/BoundedRing lineage,
// chunk-at-a-time -- NOT a byte-push trace, the M30 CBMC-floor lesson)
// reassembles in-order chunks and accepts ONLY when the recomputed whole-body
// digest equals the [`SubHdr::body_digest`] commitment. `ERR` gains a CLOSED
// payload enum ([`errcode`]); raw provider text never rides the wire.
// [`mock_infer`] is the MOCK-DETERMINISTIC backend transform (a pure
// uhash-keystream expansion -- no clock, no RNG, CI-reproducible bit-for-bit)
// shared by the in-kernel backend AND the `xport-harness` host serve loop, so
// the boot self-test can cross-check the wire response against an
// independently computed expectation.
// ===========================================================================

/// The compile-time whole-BODY byte cap for a chunked `INFER_REQ`/`INFER_RESP`
/// sequence (M31 proposal §2b -- a FROZEN product constraint, adopted from the
/// proposal's recommendation). Both wire ends compile this same const; a body
/// larger than this is REJECTED on either end (`ERR code=TOO-LARGE`, the 413
/// mirror), NEVER truncated. A HELLO/CAPS negotiation frame is the named
/// successor if the cap ever needs to move per-deployment.
pub const INFER_BODY_CAP: usize = 8192;

/// The fixed in-payload chunk SUB-HEADER length (bytes): `seq(2) | sflags(1) |
/// rsv(1) | total_len(4) | body_digest(16)` = 24. Lives INSIDE the payload of
/// kinds 4/5 (the `opframe` layered-payload convention), so the M30 frame
/// header -- whose reserved `flags` byte canon forces to zero -- is untouched.
pub const INFER_SUBHDR_LEN: usize = 24;

/// The maximum chunk bytes one frame can carry: the untouched payload cap
/// minus the in-payload sub-header.
pub const INFER_CHUNK_CAP: usize = INFER_PAYLOAD_CAP - INFER_SUBHDR_LEN;

/// The truncated whole-body digest width carried in every [`SubHdr`] (the
/// leading bytes of the M29-C [`crate::khash::uhash`] digest -- the SAME
/// construction as `prov::prov_hash`/`opframe::op_hash`, ONE digest
/// discipline, truncated to the house 16-byte witness width).
pub const INFER_BODY_DIGEST_LEN: usize = 16;

/// The `SubHdr::sflags` MORE bit: another chunk follows. Bits 1..7 are
/// reserved-zero fail-closed ([`subhdr_decode`] rejects them).
pub const SFLAG_MORE: u8 = 0x01;

/// The M31 inference-adapter chunk-MAC domain separator (proposal §2c): the
/// fixed leading label inside the keyed-hash message, keeping every M31 chunk
/// tag disjoint from the M30 echo MAC and every other keyed use of the
/// primitive. The bytes (`"YUVA-M31-INFER-V1"`) DERIVE from
/// `brand::DOMSEP_M31_INFER` -- the kernel and `tools/xport-harness` share
/// this one const (the `kani_infer_domain_sep` harness proves the label is
/// load-bearing: swapping/dropping it collapses the echo and infer domains).
pub const INFER_DOMAIN: &[u8] = brand::DOMSEP_M31_INFER;

/// The closed `ERR` payload byte length: `code(2) | retryable(1) | rsv(1)`.
pub const INFER_ERR_PAYLOAD_LEN: usize = 4;

/// The fixed deterministic MOCK-DETERMINISTIC response length (bytes).
/// DELIBERATELY larger than [`INFER_PAYLOAD_CAP`], so the wire mock exchange
/// always exercises the chunked path + the [`InferAssembler`] (>= 2 chunks),
/// and within [`INFER_BODY_CAP`].
pub const INFER_MOCK_RESP_LEN: usize = 1280;

/// The designated stage-B "would you serve a LIVE model?" probe body: a
/// keyless host peer answers a MAC'd `ERR code=NO-KEY` (the proposal-§3d
/// fail-closed wire check, `wire-err-handled=0x1`). Brand-derived wire bytes
/// (never re-spelled); stage C replaces this rule with real key-presence.
pub const INFER_NOKEY_PROBE: &[u8] =
    concat!(brand::brand_upper!(), "-M31-NOKEY-PROBE-V1").as_bytes();

/// The MOCK-DETERMINISTIC keystream label (brand-derived at the use site, the
/// M30 challenge-label precedent). NOT a keyed-MAC domain separator -- the
/// mock transform is an UNKEYED deterministic expansion.
const MOCK_LABEL: &[u8] = concat!(brand::brand_upper!(), "-M31-MOCK-V1").as_bytes();

// Compile-time pins: the sub-header arithmetic, the seq-width headroom (chunk
// count can never overflow the u16 seq), and the mock-forces-chunking rule.
const _: () = assert!(INFER_SUBHDR_LEN == 24);
const _: () = assert!(INFER_CHUNK_CAP == 1000);
const _: () = assert!(INFER_BODY_CAP < 65536);
const _: () = assert!(INFER_MOCK_RESP_LEN > INFER_PAYLOAD_CAP);
const _: () = assert!(INFER_MOCK_RESP_LEN <= INFER_BODY_CAP);

/// The closed `ERR` payload code set (M31 proposal §2e -- the bridge maps the
/// provider's HTTP error taxonomy to THIS enum; raw provider error JSON is
/// untrusted text and never crosses to the guest or serial unencoded).
/// [`err_decode`] rejects any other value (fail-closed,
/// `kani_infer_err_closed`).
pub mod errcode {
    /// No backend is registered for the requested model.
    pub const NO_BACKEND: u16 = 1;
    /// The host peer holds no API key (the stage-B keyless answer to
    /// [`super::INFER_NOKEY_PROBE`]; 401-adjacent but distinct from AUTH).
    pub const NO_KEY: u16 = 2;
    /// The body exceeds [`super::INFER_BODY_CAP`] (the HTTP 413 mirror) --
    /// reject, never truncate.
    pub const TOO_LARGE: u16 = 3;
    /// HTTP 429 (retryable).
    pub const RATE_LIMITED: u16 = 4;
    /// HTTP 529 (retryable).
    pub const OVERLOADED: u16 = 5;
    /// HTTP 500 (retryable).
    pub const API_ERROR: u16 = 6;
    /// HTTP 401/403 (permanent).
    pub const AUTH: u16 = 7;
    /// HTTP 400 (permanent).
    pub const BAD_REQUEST: u16 = 8;
    /// `stop_reason=refusal` with empty content (the bridge branches on
    /// stop_reason BEFORE reading content -- proposal §12).
    pub const REFUSAL: u16 = 9;
    /// Connection-class timeout (408-class, retryable).
    pub const TIMEOUT: u16 = 10;
}

/// Whether `code` is a member of the closed [`errcode`] enum.
#[inline]
#[must_use]
pub fn err_code_known(code: u16) -> bool {
    matches!(
        code,
        errcode::NO_BACKEND
            | errcode::NO_KEY
            | errcode::TOO_LARGE
            | errcode::RATE_LIMITED
            | errcode::OVERLOADED
            | errcode::API_ERROR
            | errcode::AUTH
            | errcode::BAD_REQUEST
            | errcode::REFUSAL
            | errcode::TIMEOUT
    )
}

/// The CANONICAL retryability of a closed [`errcode`] member (research §2:
/// retryable = 429/500/529 + the connection-timeout class; other 4xx are
/// permanent). The wire `retryable` byte is BOUND to this mapping --
/// [`err_decode`] rejects a flag that contradicts it (fail-closed binding,
/// never a free bit a peer could flip to smuggle retry semantics).
#[inline]
#[must_use]
pub fn err_retryable(code: u16) -> bool {
    matches!(
        code,
        errcode::RATE_LIMITED | errcode::OVERLOADED | errcode::API_ERROR | errcode::TIMEOUT
    )
}

/// Encode the closed `ERR` payload `{code, retryable, rsv}` into `out`.
/// Returns [`INFER_ERR_PAYLOAD_LEN`], or 0 fail-closed if `code` is outside
/// the closed enum or `out` is too small (total, no partial write). The
/// `retryable` byte is DERIVED from [`err_retryable`] -- a caller cannot
/// emit a contradictory flag.
#[must_use]
pub fn err_canon(code: u16, out: &mut [u8]) -> usize {
    if !err_code_known(code) || out.len() < INFER_ERR_PAYLOAD_LEN {
        return 0;
    }
    write_u16(out, 0, code);
    out[2] = err_retryable(code) as u8;
    out[3] = 0; // rsv -- fail-closed reserved-zero
    INFER_ERR_PAYLOAD_LEN
}

/// The exact inverse of [`err_canon`]: decode `{code, retryable}` from an
/// EXACTLY-[`INFER_ERR_PAYLOAD_LEN`] payload, or `None` fail-closed on a
/// wrong length, an unknown code, a nonzero reserved byte, or a `retryable`
/// flag that contradicts the canonical [`err_retryable`] binding. Total.
#[must_use]
pub fn err_decode(payload: &[u8]) -> Option<(u16, bool)> {
    if payload.len() != INFER_ERR_PAYLOAD_LEN {
        return None;
    }
    let code = read_u16(payload, 0);
    if !err_code_known(code) {
        return None; // outside the closed enum -- fail closed
    }
    if payload[3] != 0 {
        return None; // reserved-nonzero is malformed
    }
    let retryable = err_retryable(code);
    if payload[2] != retryable as u8 {
        return None; // the retryable binding round-trips or rejects
    }
    Some((code, retryable))
}

/// The fixed 24-byte in-payload chunk SUB-HEADER (M31 proposal §2b). Rides at
/// the FRONT of the payload of kinds [`kind::INFER_REQ`]/[`kind::INFER_RESP`];
/// `total_len` and `body_digest` are IDENTICAL in every chunk of a sequence
/// (drift rejects at the [`InferAssembler`]), `seq` is 0-based strictly
/// in-order (stop-and-wait lockstep), and the reserved `sflags` bits 1..7 +
/// the `rsv` byte are zero fail-closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubHdr {
    /// The 0-based chunk index (strictly in-order; bound INSIDE the MAC).
    pub seq: u16,
    /// The MORE flag (bit 0 of the wire `sflags` byte): another chunk follows.
    pub more: bool,
    /// The WHOLE-body byte length, identical in every chunk (1..=[`INFER_BODY_CAP`]).
    pub total_len: u32,
    /// The truncated [`crate::khash::uhash`] digest of the WHOLE body,
    /// identical in every chunk -- the commitment the assembled body must
    /// re-derive ([`InferAssembler::push_chunk`]'s completion check).
    pub body_digest: [u8; INFER_BODY_DIGEST_LEN],
}

impl SubHdr {
    /// The all-zero sub-header stand-in used when MAC'ing the sub-header-FREE
    /// kinds ([`kind::INFER_PENDING`]/[`kind::ERR`]) -- the `kind` byte inside
    /// the MAC keeps those domains disjoint from a real chunk 0.
    #[must_use]
    pub const fn empty() -> Self {
        SubHdr {
            seq: 0,
            more: false,
            total_len: 0,
            body_digest: [0u8; INFER_BODY_DIGEST_LEN],
        }
    }

    /// The wire `sflags` byte this sub-header encodes to (bit 0 = MORE).
    #[inline]
    #[must_use]
    pub const fn sflags(&self) -> u8 {
        self.more as u8
    }
}

/// Encode `sub` into the leading [`INFER_SUBHDR_LEN`] bytes of `out`. Returns
/// [`INFER_SUBHDR_LEN`], or 0 fail-closed if `out` is too small or
/// `total_len` is outside `1..=INFER_BODY_CAP` (total, no partial write).
#[must_use]
pub fn subhdr_canon(sub: &SubHdr, out: &mut [u8]) -> usize {
    if out.len() < INFER_SUBHDR_LEN {
        return 0;
    }
    if sub.total_len == 0 || sub.total_len as usize > INFER_BODY_CAP {
        return 0; // an empty or over-cap body is never encodable (reject>truncate)
    }
    write_u16(out, 0, sub.seq);
    out[2] = sub.sflags();
    out[3] = 0; // rsv -- forced zero
    write_u32(out, 4, sub.total_len);
    let mut d = 0usize;
    while d < INFER_BODY_DIGEST_LEN {
        out[8 + d] = sub.body_digest[d];
        d += 1;
    }
    INFER_SUBHDR_LEN
}

/// The exact inverse of [`subhdr_canon`] over the leading bytes of `buf`:
/// `None` fail-closed if `buf` is shorter than [`INFER_SUBHDR_LEN`], any
/// reserved `sflags` bit (1..7) or the `rsv` byte is nonzero, or `total_len`
/// is outside `1..=INFER_BODY_CAP`. Total -- never panics
/// (`kani_infer_subhdr_total`).
#[must_use]
pub fn subhdr_decode(buf: &[u8]) -> Option<SubHdr> {
    if buf.len() < INFER_SUBHDR_LEN {
        return None;
    }
    let sflags = buf[2];
    if sflags & !SFLAG_MORE != 0 {
        return None; // reserved sflags bits 1..7 -- fail closed
    }
    if buf[3] != 0 {
        return None; // reserved byte -- fail closed
    }
    let total_len = read_u32(buf, 4);
    if total_len == 0 || total_len as usize > INFER_BODY_CAP {
        return None; // empty / over-cap body declarations are malformed
    }
    let mut body_digest = [0u8; INFER_BODY_DIGEST_LEN];
    let mut d = 0usize;
    while d < INFER_BODY_DIGEST_LEN {
        body_digest[d] = buf[8 + d];
        d += 1;
    }
    Some(SubHdr {
        seq: read_u16(buf, 0),
        more: sflags & SFLAG_MORE != 0,
        total_len,
        body_digest,
    })
}

/// The truncated whole-body digest commitment every chunk of a sequence
/// carries: the leading [`INFER_BODY_DIGEST_LEN`] bytes of
/// [`crate::khash::uhash`] over the body (the M29-C `prov_hash` construction
/// truncated to the house witness width -- ONE digest discipline, so the
/// on-wire commitment and the M25 transcript fold are the same function).
#[must_use]
pub fn body_digest(body: &[u8]) -> [u8; INFER_BODY_DIGEST_LEN] {
    let full = crate::khash::uhash(body);
    let mut out = [0u8; INFER_BODY_DIGEST_LEN];
    let mut i = 0usize;
    while i < INFER_BODY_DIGEST_LEN {
        out[i] = full[i];
        i += 1;
    }
    out
}

/// The maximum khash message the M31 chunk MAC ever sees: the domain label +
/// every MAC-covered fixed-width field + a cap-bounded chunk.
const INFER_MSG_CAP: usize = INFER_DOMAIN.len()
    + 1 // peer_id
    + INFER_NONCE_LEN
    + INFER_CHALLENGE_LEN
    + 8 // req_id
    + 1 // kind
    + 2 // seq
    + 1 // sflags
    + 4 // total_len
    + INFER_BODY_DIGEST_LEN
    + INFER_CHUNK_CAP;

/// The M31 per-chunk MAC (proposal §2c): EXACTLY ONE call of the verified
/// [`crate::khash`] BLAKE2s-256 leaf under the NEW [`INFER_DOMAIN`] label --
///
/// ```text
///   T = khash(K, INFER_DOMAIN || peer_id || nonce || challenge || req_id
///                || kind || seq || sflags || total_len || body_digest
///                || chunk)[..INFER_TAG_LEN]
/// ```
///
/// EVERYTHING that adjudicates rides INSIDE the MAC (the M28/Terrapin
/// bind-inside-the-MAC rule): the chunk index `seq` included, so a reordered,
/// spliced, or cross-sequence chunk fails VERIFICATION, not just assembly.
/// All MAC-covered fields before `chunk` are FIXED-WIDTH, so the
/// concatenation is injective in its parts. `K` is the M30 host-custodied
/// per-run channel key -- custody unchanged. TOTAL -- no panic, no alloc;
/// `chunk` reads through a cap clamp unreachable via any wire path (the
/// [`echo_tag`] totality idiom). CALLS [`crate::khash::khash`] -- NO new hash
/// math.
#[must_use]
#[allow(clippy::too_many_arguments)] // the MAC input IS the argument list, spelled explicitly
pub fn infer_tag(
    key: &[u8; INFER_KEY_LEN],
    peer_id: u8,
    nonce: &[u8; INFER_NONCE_LEN],
    challenge: &[u8; INFER_CHALLENGE_LEN],
    req_id: u64,
    kind_tag: u8,
    sub: &SubHdr,
    chunk: &[u8],
) -> [u8; INFER_TAG_LEN] {
    let clen = if chunk.len() > INFER_CHUNK_CAP {
        INFER_CHUNK_CAP // unreachable via any wire path (payload cap), totality only
    } else {
        chunk.len()
    };
    let mut msg = [0u8; INFER_MSG_CAP];
    let mut o = 0usize;
    let mut i = 0usize;
    while i < INFER_DOMAIN.len() {
        msg[o] = INFER_DOMAIN[i];
        o += 1;
        i += 1;
    }
    msg[o] = peer_id;
    o += 1;
    let mut n = 0usize;
    while n < INFER_NONCE_LEN {
        msg[o] = nonce[n];
        o += 1;
        n += 1;
    }
    let mut c = 0usize;
    while c < INFER_CHALLENGE_LEN {
        msg[o] = challenge[c];
        o += 1;
        c += 1;
    }
    let rid = req_id.to_le_bytes();
    let mut r = 0usize;
    while r < 8 {
        msg[o] = rid[r];
        o += 1;
        r += 1;
    }
    msg[o] = kind_tag;
    o += 1;
    let sq = sub.seq.to_le_bytes();
    msg[o] = sq[0];
    msg[o + 1] = sq[1];
    o += 2;
    msg[o] = sub.sflags();
    o += 1;
    let tl = sub.total_len.to_le_bytes();
    let mut t = 0usize;
    while t < 4 {
        msg[o] = tl[t];
        o += 1;
        t += 1;
    }
    let mut d = 0usize;
    while d < INFER_BODY_DIGEST_LEN {
        msg[o] = sub.body_digest[d];
        o += 1;
        d += 1;
    }
    let mut b = 0usize;
    while b < clen {
        msg[o] = chunk[b];
        o += 1;
        b += 1;
    }
    let full = khash(key, &msg[..o]); // the ONE khash call
    let mut tag = [0u8; INFER_TAG_LEN];
    let mut g = 0usize;
    while g < INFER_TAG_LEN {
        tag[g] = full[g];
        g += 1;
    }
    tag
}

/// Split an M31 frame payload into its `(SubHdr, chunk)` parts by KIND,
/// fail-closed (proposal §2b/§2e/§2f layered-payload rules):
///
/// * [`kind::INFER_REQ`]/[`kind::INFER_RESP`] -- a leading [`SubHdr`]
///   ([`subhdr_decode`] rules) + a NON-EMPTY chunk tail.
/// * [`kind::INFER_PENDING`] -- the payload must be EMPTY ([`SubHdr::empty`]
///   stands in for the MAC input).
/// * [`kind::ERR`] -- the payload must be EXACTLY the closed
///   [`INFER_ERR_PAYLOAD_LEN`] bytes AND pass [`err_decode`].
/// * any other kind -- `None` (a reflected REQ is not a response part;
///   `verify_infer_resp` composes this with the kind set).
///
/// Total -- never panics for any input.
#[must_use]
pub fn infer_payload_parts(kind_tag: u8, payload: &[u8]) -> Option<(SubHdr, &[u8])> {
    match kind_tag {
        kind::INFER_REQ | kind::INFER_RESP => {
            let sub = subhdr_decode(payload)?;
            let chunk = &payload[INFER_SUBHDR_LEN..];
            if chunk.is_empty() {
                return None; // a no-progress chunk is desync, never valid
            }
            Some((sub, chunk))
        }
        kind::INFER_PENDING => {
            if !payload.is_empty() {
                return None; // a pending heartbeat carries no body
            }
            Some((SubHdr::empty(), payload))
        }
        kind::ERR => {
            let _ = err_decode(payload)?; // closed-enum + binding rules
            Some((SubHdr::empty(), payload))
        }
        _ => None,
    }
}

/// The M31 RESPONSE-side verification (proposal §2c -- the sibling of
/// [`verify_echo`], the iff-discipline of `resp_binds_req` lifted to the
/// chunked kinds): accept IFF `frame` is a host->kernel M31 kind
/// ([`kind::INFER_RESP`] | [`kind::INFER_PENDING`] | [`kind::ERR`] -- a
/// reflected REQ never verifies), BINDS the in-flight `req_id`, ECHOES this
/// boot's `challenge` verbatim, its payload parses by the kind's layered
/// rules ([`infer_payload_parts`]), AND its tag equals the recomputed
/// [`infer_tag`] over every bound field. Returns the parsed `(SubHdr, chunk)`
/// on acceptance, `None` fail-closed otherwise. TOTAL -- pure compares plus
/// the one khash recompute (`kani_infer_resp_binding`).
#[must_use]
pub fn verify_infer_resp<'a>(
    key: &[u8; INFER_KEY_LEN],
    frame: &InferFrame<'a>,
    req_id: u64,
    challenge: &[u8; INFER_CHALLENGE_LEN],
) -> Option<(SubHdr, &'a [u8])> {
    if !matches!(
        frame.kind,
        kind::INFER_RESP | kind::INFER_PENDING | kind::ERR
    ) {
        return None; // wrong direction/kind (a reflected REQ never binds)
    }
    if frame.req_id != req_id {
        return None; // wrong correlation id
    }
    if frame.challenge != *challenge {
        return None; // does not echo THIS boot's challenge (canned response)
    }
    let (sub, chunk) = infer_payload_parts(frame.kind, frame.payload)?;
    let expect = infer_tag(
        key,
        frame.peer_id,
        &frame.nonce,
        challenge,
        req_id,
        frame.kind,
        &sub,
        chunk,
    );
    if expect != frame.tag {
        return None; // MAC mismatch -- fail closed
    }
    Some((sub, chunk))
}

/// The M31 REQUEST-side verification (the host peer's leg): accept IFF
/// `frame` is an [`kind::INFER_REQ`] whose request-shape invariants hold (a
/// REQ carries NO host nonce and NO peer label -- both zero, the M30 §2
/// request convention), its payload parses as a sub-header + chunk, and its
/// tag equals the recomputed [`infer_tag`] (the kernel MACs its requests with
/// the channel-revealed K, so the host verifies symmetrically). Returns the
/// parsed parts, `None` fail-closed.
#[must_use]
pub fn verify_infer_req<'a>(
    key: &[u8; INFER_KEY_LEN],
    frame: &InferFrame<'a>,
) -> Option<(SubHdr, &'a [u8])> {
    if frame.kind != kind::INFER_REQ {
        return None;
    }
    if frame.nonce != [0u8; INFER_NONCE_LEN] || frame.peer_id != 0 {
        return None; // a REQ carries no host nonce / peer label (fail-closed)
    }
    let (sub, chunk) = infer_payload_parts(frame.kind, frame.payload)?;
    let expect = infer_tag(
        key,
        frame.peer_id,
        &frame.nonce,
        &frame.challenge,
        frame.req_id,
        frame.kind,
        &sub,
        chunk,
    );
    if expect != frame.tag {
        return None;
    }
    Some((sub, chunk))
}

/// One [`InferAssembler::push_chunk`] outcome (closed, pure-data).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsmPush {
    /// The chunk was accepted; the body is not yet complete (MORE expected).
    Accepted,
    /// The FINAL chunk was accepted, the assembled length equals `total_len`,
    /// AND the recomputed whole-body digest equals the [`SubHdr::body_digest`]
    /// commitment -- the body (this many bytes) is ready via
    /// [`InferAssembler::body`].
    Complete(usize),
    /// The chunk was REJECTED (out-of-order/duplicate/gap seq, total_len or
    /// body_digest drift, overflow past `total_len`/capacity, an empty or
    /// mis-terminated chunk, or a failed completion digest). The assembler is
    /// POISONED fail-closed: every later push also rejects (stop-and-wait has
    /// no retransmit -- the caller restarts the whole exchange).
    Rejected,
}

/// The fixed-capacity, fail-closed chunk REASSEMBLER (M31 proposal §2d -- the
/// `FrameAccum`/`BoundedRing` lineage, CHUNK-at-a-time by design so the Kani
/// harness stays under the measured M30 byte-push CBMC floor). The FIRST
/// accepted chunk (seq 0) LOCKS `total_len` + `body_digest`; every later
/// chunk must match them exactly (drift rejects), arrive strictly in-order,
/// and stay within both `total_len` and `CAP`; on the final (`more == false`)
/// chunk the assembled body's recomputed [`body_digest`] MUST equal the
/// locked commitment -- the dump is never trusted over the commitment.
/// INVARIANTS (proven in `kani_infer_assembler` at a tiny `CAP`, held by
/// construction at the real [`INFER_BODY_CAP`]): `len() <= CAP` ALWAYS; a
/// `push_chunk` never panics; any rejection POISONS the assembler (garbage
/// can never resurrect a transfer -- fail-closed, never unsound).
#[derive(Clone, Copy, Debug)]
pub struct InferAssembler<const CAP: usize> {
    buf: [u8; CAP],
    len: usize,
    next_seq: u16,
    total_len: u32,
    digest: [u8; INFER_BODY_DIGEST_LEN],
    started: bool,
    done: bool,
    poisoned: bool,
}

impl<const CAP: usize> Default for InferAssembler<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAP: usize> InferAssembler<CAP> {
    /// A new, empty assembler.
    #[must_use]
    pub const fn new() -> Self {
        InferAssembler {
            buf: [0u8; CAP],
            len: 0,
            next_seq: 0,
            total_len: 0,
            digest: [0u8; INFER_BODY_DIGEST_LEN],
            started: false,
            done: false,
            poisoned: false,
        }
    }

    /// The number of assembled body bytes so far (always `<= CAP`).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether no chunk has been accepted yet.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether the body completed (a [`AsmPush::Complete`] was returned).
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.done
    }

    /// The assembled body bytes (the full body exactly when [`Self::is_done`]).
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Push ONE verified chunk (the caller MAC-verifies FIRST via
    /// [`verify_infer_resp`]/[`verify_infer_req`] -- assembly never
    /// substitutes for verification). See [`AsmPush`] for the closed outcome
    /// set and the struct doc for the fail-closed rule set. TOTAL -- never
    /// panics for any input (every index is bounded by the pre-copy checks).
    pub fn push_chunk(&mut self, sub: &SubHdr, chunk: &[u8]) -> AsmPush {
        if self.poisoned || self.done {
            return AsmPush::Rejected; // poisoned/finished -- nothing resurrects
        }
        // Reject-then-poison helper discipline: validate EVERYTHING before
        // any copy, so a rejected chunk never partially lands.
        let total = sub.total_len as usize;
        if !self.started {
            // The first chunk LOCKS the sequence parameters.
            if sub.seq != 0 || sub.total_len == 0 || total > INFER_BODY_CAP || total > CAP {
                self.poisoned = true;
                return AsmPush::Rejected;
            }
        } else {
            // Strictly in-order, no drift (out-of-order/dup/gap/splice).
            if sub.seq != self.next_seq
                || sub.total_len != self.total_len
                || sub.body_digest != self.digest
            {
                self.poisoned = true;
                return AsmPush::Rejected;
            }
        }
        // (in the started case the drift check above pins sub.total_len ==
        // self.total_len, so `total` is the locked value either way)
        if chunk.is_empty() || chunk.len() > INFER_CHUNK_CAP {
            self.poisoned = true;
            return AsmPush::Rejected; // no-progress / over-cap chunk
        }
        let new_len = match self.len.checked_add(chunk.len()) {
            Some(n) if n <= total => n,
            _ => {
                self.poisoned = true;
                return AsmPush::Rejected; // sum of chunks would exceed total_len
            }
        };
        // MORE/termination consistency: a MORE chunk must leave room; the
        // final chunk must land EXACTLY on total_len (reject, never truncate).
        if sub.more && new_len >= total {
            self.poisoned = true;
            return AsmPush::Rejected;
        }
        if !sub.more && new_len != total {
            self.poisoned = true;
            return AsmPush::Rejected;
        }
        // Accept: lock (first chunk) + copy + advance. new_len <= total <= CAP,
        // so every index below is in-bounds (the Kani harness checks them all).
        if !self.started {
            self.started = true;
            self.total_len = sub.total_len;
            self.digest = sub.body_digest;
        }
        let mut i = 0usize;
        while i < chunk.len() {
            self.buf[self.len + i] = chunk[i];
            i += 1;
        }
        self.len = new_len;
        self.next_seq = self.next_seq.wrapping_add(1); // bounded: <= CAP pushes
        if sub.more {
            return AsmPush::Accepted;
        }
        // Completion: the recomputed whole-body digest MUST equal the locked
        // commitment (the dump is never trusted over the commitment).
        if body_digest(&self.buf[..self.len]) != self.digest {
            self.poisoned = true;
            return AsmPush::Rejected;
        }
        self.done = true;
        AsmPush::Complete(self.len)
    }
}

/// The number of chunks a `total_len`-byte body splits into under the FIXED
/// discipline (full [`INFER_CHUNK_CAP`] chunks, then the remainder), or 0 for
/// an invalid (empty / over-cap) length. Total.
#[must_use]
pub fn infer_chunk_count(total_len: usize) -> usize {
    if total_len == 0 || total_len > INFER_BODY_CAP {
        return 0;
    }
    total_len.div_ceil(INFER_CHUNK_CAP)
}

/// The exact on-wire byte length of a whole chunked sequence for a
/// `total_len`-byte body under the fixed discipline: a frame header plus a
/// sub-header per chunk, plus the body bytes once. 0 for an invalid length.
/// Total -- both ends derive the SAME expected wire length from the shared
/// consts (the poll-driven channel sizes its receive window a priori with
/// this).
#[must_use]
pub fn infer_chunks_wire_len(total_len: usize) -> usize {
    let n = infer_chunk_count(total_len);
    if n == 0 {
        return 0;
    }
    n * (INFER_HEADER_LEN + INFER_SUBHDR_LEN) + total_len
}

/// The MOCK-DETERMINISTIC backend transform (M31 proposal §3c): a PURE,
/// unkeyed, deterministic expansion of the prompt into EXACTLY
/// [`INFER_MOCK_RESP_LEN`] bytes -- an [`crate::khash::uhash`] keystream
/// (`block_k = uhash(MOCK_LABEL || uhash(prompt) || k_le)`), no clock, no
/// RNG, CI-reproducible bit-for-bit. SHARED by the in-kernel
/// MOCK-DETERMINISTIC backend and the `xport-harness` host serve loop, so the
/// boot self-test can require the wire-delivered body to EQUAL an
/// independently computed expectation (the cross-process determinism check).
/// Returns the response length, or 0 fail-closed (empty/over-cap prompt or a
/// too-small `out`). HONEST: this is a deterministic TRANSFORM, not a model
/// -- `backend=MOCK-DETERMINISTIC` says so on every witness line.
#[must_use]
pub fn mock_infer(prompt: &[u8], out: &mut [u8]) -> usize {
    if prompt.is_empty() || prompt.len() > INFER_BODY_CAP || out.len() < INFER_MOCK_RESP_LEN {
        return 0;
    }
    let seed = crate::khash::uhash(prompt);
    // block input: MOCK_LABEL || seed(32) || k as u32 LE
    let mut blk = [0u8; MOCK_LABEL.len() + 32 + 4];
    let mut i = 0usize;
    while i < MOCK_LABEL.len() {
        blk[i] = MOCK_LABEL[i];
        i += 1;
    }
    let mut s = 0usize;
    while s < 32 {
        blk[MOCK_LABEL.len() + s] = seed[s];
        s += 1;
    }
    let mut off = 0usize;
    let mut k: u32 = 0;
    while off < INFER_MOCK_RESP_LEN {
        let kb = k.to_le_bytes();
        let mut j = 0usize;
        while j < 4 {
            blk[MOCK_LABEL.len() + 32 + j] = kb[j];
            j += 1;
        }
        let stream = crate::khash::uhash(&blk);
        let take = if INFER_MOCK_RESP_LEN - off < 32 {
            INFER_MOCK_RESP_LEN - off
        } else {
            32
        };
        let mut b = 0usize;
        while b < take {
            out[off + b] = stream[b];
            b += 1;
        }
        off += take;
        k = k.wrapping_add(1);
    }
    INFER_MOCK_RESP_LEN
}

// --- fixed-width LE scalar helpers (pure, total on a pre-checked buffer) -----
// The caller guarantees the offset window fits (canon/decode check the length
// FIRST). Tiny + inlined so CBMC constant-folds them (mirrors `opframe_rx.rs`).

#[inline]
fn write_u16(out: &mut [u8], off: usize, v: u16) {
    let b = v.to_le_bytes();
    out[off] = b[0];
    out[off + 1] = b[1];
}

#[inline]
fn write_u32(out: &mut [u8], off: usize, v: u32) {
    let b = v.to_le_bytes();
    let mut i = 0usize;
    while i < 4 {
        out[off + i] = b[i];
        i += 1;
    }
}

#[inline]
fn write_u64(out: &mut [u8], off: usize, v: u64) {
    let b = v.to_le_bytes();
    let mut i = 0usize;
    while i < 8 {
        out[off + i] = b[i];
        i += 1;
    }
}

#[inline]
fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

#[inline]
fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

#[inline]
fn read_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; INFER_KEY_LEN] = [0x42u8; INFER_KEY_LEN];

    fn fill(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| seed.wrapping_add(i as u8).wrapping_mul(31))
            .collect()
    }

    fn arr16(seed: u8) -> [u8; 16] {
        let mut a = [0u8; 16];
        for (i, b) in a.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8).wrapping_mul(37);
        }
        a
    }

    fn req<'a>(payload: &'a [u8]) -> InferFrame<'a> {
        InferFrame {
            kind: kind::ECHO_REQ,
            req_id: 0x1122_3344_5566_7788,
            challenge: arr16(5),
            nonce: [0u8; 16],
            peer_id: 0,
            tag: [0u8; 16],
            payload,
        }
    }

    fn resp_for<'a>(rq: &InferFrame, payload: &'a [u8], key: &[u8; 32]) -> InferFrame<'a> {
        let nonce = arr16(9);
        let tag = echo_tag(key, peer::QEMU_CHARDEV_HARNESS, &nonce, &rq.challenge, payload);
        InferFrame {
            kind: kind::ECHO_RESP,
            req_id: rq.req_id,
            challenge: rq.challenge,
            nonce,
            peer_id: peer::QEMU_CHARDEV_HARNESS,
            tag,
            payload,
        }
    }

    // ---- canon: layout, length, fail-closed totality -------------------------

    #[test]
    fn canon_layout_and_lengths() {
        let p = [1u8, 2, 3, 4];
        let f = req(&p);
        assert_eq!(canon_len(4), INFER_HEADER_LEN + 4);
        assert_eq!(wire_len(&f), INFER_HEADER_LEN + 4);
        let mut buf = [0u8; 128];
        let n = canon(&f, &mut buf);
        assert_eq!(n, INFER_HEADER_LEN + 4);
        assert_eq!(read_u16(&buf, OFF_MAGIC), INFER_MAGIC);
        assert_eq!(buf[OFF_VER], INFER_VER);
        assert_eq!(buf[OFF_KIND], kind::ECHO_REQ);
        assert_eq!(buf[OFF_FLAGS], 0);
        assert_eq!(read_u64(&buf, OFF_REQ_ID), 0x1122_3344_5566_7788);
        assert_eq!(&buf[OFF_CHALLENGE..OFF_CHALLENGE + 16], &arr16(5));
        assert_eq!(read_u32(&buf, OFF_PAYLOAD_LEN), 4);
        assert_eq!(&buf[OFF_PAYLOAD..OFF_PAYLOAD + 4], &p);
    }

    #[test]
    fn canon_fail_closed_small_buffer_and_caps() {
        let p = [9u8; 8];
        let f = req(&p);
        let need = wire_len(&f);
        let mut small = vec![0u8; need - 1];
        assert_eq!(canon(&f, &mut small), 0);
        assert!(small.iter().all(|&b| b == 0)); // no partial write
        // Oversize payload fail-closes.
        let big = vec![0u8; INFER_PAYLOAD_CAP + 1];
        let mut fb = req(&big);
        fb.payload = &big;
        let mut out = vec![0u8; INFER_HEADER_LEN + INFER_PAYLOAD_CAP + 1];
        assert_eq!(canon(&fb, &mut out), 0);
        assert!(!frame_is_encodable(INFER_PAYLOAD_CAP + 1));
        assert!(frame_is_encodable(INFER_PAYLOAD_CAP));
        // Unknown kind fail-closes.
        let mut fk = req(&p);
        fk.kind = 0;
        let mut buf = [0u8; 128];
        assert_eq!(canon(&fk, &mut buf), 0);
        fk.kind = 99;
        assert_eq!(canon(&fk, &mut buf), 0);
    }

    // ---- canon <-> decode round-trip + the proposal negative set -------------

    #[test]
    fn canon_decode_roundtrip_boundary_lengths() {
        for &plen in &[0usize, 1, 31, INFER_PAYLOAD_CAP] {
            let p = fill(7, plen);
            let f = resp_for(&req(&p), &p, &KEY);
            let mut buf = vec![0u8; INFER_HEADER_LEN + plen];
            let n = canon(&f, &mut buf);
            assert_eq!(n, INFER_HEADER_LEN + plen);
            let d = decode(&buf[..n]).expect("valid frame must decode");
            assert_eq!(d.kind, f.kind);
            assert_eq!(d.req_id, f.req_id);
            assert_eq!(d.challenge, f.challenge);
            assert_eq!(d.nonce, f.nonce);
            assert_eq!(d.peer_id, f.peer_id);
            assert_eq!(d.tag, f.tag);
            assert_eq!(d.payload, &p[..]);
        }
    }

    #[test]
    fn decode_fail_closed_negative_set() {
        let p = [0xAAu8, 0xBB];
        let f = req(&p);
        let mut wire = [0u8; 128];
        let n = canon(&f, &mut wire);
        assert!(n > 0);
        // Every truncation rejects (the proposal's partial-frame negative).
        for cut in 0..n {
            assert!(decode(&wire[..cut]).is_none(), "truncation {cut} decoded");
        }
        // Bad magic.
        let mut bad = wire;
        bad[OFF_MAGIC] ^= 0xFF;
        assert!(decode(&bad[..n]).is_none());
        // Bad version.
        let mut bv = wire;
        bv[OFF_VER] = INFER_VER.wrapping_add(1);
        assert!(decode(&bv[..n]).is_none());
        // Reserved-nonzero flags (every bit independently).
        for bit in 0..8u32 {
            let mut bf = wire;
            bf[OFF_FLAGS] = 1u8 << bit;
            assert!(decode(&bf[..n]).is_none());
        }
        // Unknown kind.
        let mut bk = wire;
        bk[OFF_KIND] = 0x7F;
        assert!(decode(&bk[..n]).is_none());
        // Oversize declared payload_len (the desync negative).
        let mut bl = wire;
        bl[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 4]
            .copy_from_slice(&((INFER_PAYLOAD_CAP as u32) + 1).to_le_bytes());
        assert!(decode(&bl[..n]).is_none());
        // Declared length past the buffer (bad-len desync).
        let mut bs = wire;
        bs[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 4].copy_from_slice(&64u32.to_le_bytes());
        assert!(decode(&bs[..n]).is_none());
        // Control: the untouched wire still decodes, and trailing bytes (the
        // channel key-reveal convention) are permitted.
        assert!(decode(&wire[..n]).is_some());
        let mut trailed = wire.to_vec();
        trailed.truncate(n);
        trailed.extend_from_slice(&[0x55u8; INFER_KEY_REVEAL_LEN]);
        let d = decode(&trailed).expect("frame + trailer must decode");
        assert_eq!(d.payload, &p[..]);
    }

    // ---- correlation binding --------------------------------------------------

    #[test]
    fn resp_binding_iff() {
        let p = [1u8];
        let rq = req(&p);
        let rs = resp_for(&rq, &p, &KEY);
        assert!(resp_binds_req(&rs, rq.req_id));
        // Wrong id never binds.
        assert!(!resp_binds_req(&rs, rq.req_id ^ 1));
        // Right id but not an ECHO_RESP never binds (an ERR or reflected REQ).
        let mut e = rs;
        e.kind = kind::ERR;
        assert!(!resp_binds_req(&e, rq.req_id));
        let mut r2 = rs;
        r2.kind = kind::ECHO_REQ;
        assert!(!resp_binds_req(&r2, rq.req_id));
    }

    // ---- echo_tag / verify_echo ------------------------------------------------

    #[test]
    fn echo_tag_is_the_pinned_one_khash_call() {
        // The exact proposal-§2 construction asserted against the khash leaf
        // directly -- drift in the label/field order breaks this even if every
        // behavioral property survives (the opframe_rx pinned-construction idiom).
        let nonce = arr16(3);
        let chal = arr16(4);
        let body = [0xD1u8, 0xD2, 0xD3];
        let mut msg = Vec::new();
        msg.extend_from_slice(ECHO_DOMAIN);
        msg.push(peer::TB_VMM_HOST);
        msg.extend_from_slice(&nonce);
        msg.extend_from_slice(&chal);
        msg.extend_from_slice(&body);
        let full = crate::khash::khash(&KEY, &msg);
        assert_eq!(
            echo_tag(&KEY, peer::TB_VMM_HOST, &nonce, &chal, &body),
            full[..INFER_TAG_LEN]
        );
    }

    #[test]
    fn verify_echo_accepts_genuine_and_rejects_each_leg() {
        let p = fill(11, 16);
        let rq = req(&p);
        let rs = resp_for(&rq, &p, &KEY);
        assert!(verify_echo(&KEY, &rs, &rq));

        // (a) badtag: a single flipped tag byte rejects.
        let mut bt = rs;
        bt.tag[0] ^= 0x01;
        assert!(!verify_echo(&KEY, &bt, &rq));
        // (b) wrongkey: a single flipped key byte rejects.
        let mut wk = KEY;
        wk[31] ^= 0x80;
        assert!(!verify_echo(&wk, &rs, &rq));
        // (c) body not bit-exact rejects (value and length).
        let mut pb = p.clone();
        pb[3] ^= 0x01;
        let mut rb = rs;
        rb.payload = &pb;
        assert!(!verify_echo(&KEY, &rb, &rq));
        let mut rl = rs;
        rl.payload = &p[..15];
        assert!(!verify_echo(&KEY, &rl, &rq));
        // (d) a non-echoed challenge rejects (a canned cross-boot response).
        let mut rc = rs;
        rc.challenge[0] ^= 0x01;
        assert!(!verify_echo(&KEY, &rc, &rq));
        // (e) a flipped nonce rejects (it is MAC-covered).
        let mut rn = rs;
        rn.nonce[7] ^= 0x01;
        assert!(!verify_echo(&KEY, &rn, &rq));
        // (f) a relabeled peer rejects (peer_id is MAC-covered -- the lane
        //     cross-pin is bound inside the tag).
        let mut rp = rs;
        rp.peer_id = peer::TB_VMM_HOST;
        assert!(!verify_echo(&KEY, &rp, &rq));
        // (g) a wrong correlation id rejects.
        let mut ri = rs;
        ri.req_id ^= 0x10;
        assert!(!verify_echo(&KEY, &ri, &rq));
    }

    #[test]
    fn echo_tag_distinct_peers_and_domains() {
        let nonce = arr16(1);
        let chal = arr16(2);
        let body = [7u8; 4];
        let a = echo_tag(&KEY, peer::TB_VMM_HOST, &nonce, &chal, &body);
        let b = echo_tag(&KEY, peer::QEMU_CHARDEV_HARNESS, &nonce, &chal, &body);
        assert_ne!(a, b); // peer_id is MAC-covered
        // Distinct nonces and challenges move the tag too.
        assert_ne!(a, echo_tag(&KEY, peer::TB_VMM_HOST, &arr16(8), &chal, &body));
        assert_ne!(a, echo_tag(&KEY, peer::TB_VMM_HOST, &nonce, &arr16(8), &body));
    }

    // ---- FrameAccum: stream re-framing, resync, never-overflow ------------------

    #[test]
    fn accum_emits_frame_after_garbage_and_split_delivery() {
        let p = fill(3, 8);
        let f = resp_for(&req(&p), &p, &KEY);
        let mut wire = vec![0u8; wire_len(&f)];
        let n = canon(&f, &mut wire);
        assert_eq!(n, wire.len());

        let mut acc: FrameAccum<INFER_ACCUM_CAP> = FrameAccum::new();
        // Garbage prefix (no magic first-byte).
        for g in [0x00u8, 0xFF, 0x53, 0x99, 0x01] {
            assert!(acc.push_byte(g).is_none());
        }
        // The frame delivered byte-by-byte (worst-case stream split): Some
        // exactly at the last byte.
        let mut emitted = None;
        for (i, &b) in wire.iter().enumerate() {
            let r = acc.push_byte(b);
            if i + 1 < wire.len() {
                assert!(r.is_none(), "premature emit at byte {i}");
            } else {
                emitted = r;
            }
        }
        assert_eq!(emitted, Some(n));
        let d = decode(&acc.bytes()[..n]).expect("emitted frame must decode");
        assert_eq!(d.payload, &p[..]);
        // Consume the frame; the accumulator is reusable.
        acc.consume(n);
        assert!(acc.is_empty());
    }

    #[test]
    fn accum_pure_garbage_never_emits_never_overflows() {
        let mut acc: FrameAccum<INFER_ACCUM_CAP> = FrameAccum::new();
        for i in 0..(3 * INFER_ACCUM_CAP) {
            let b = (i as u8).wrapping_mul(13).wrapping_add(1);
            let b = if b == (INFER_MAGIC & 0xFF) as u8 { 0x99 } else { b };
            assert!(acc.push_byte(b).is_none());
            assert!(acc.len() <= INFER_ACCUM_CAP);
        }
    }

    #[test]
    fn accum_resyncs_past_plausible_garbage_header() {
        // Garbage that LOOKS like a frame start (magic+ver+kind+flags ok) but
        // declares an oversize length: the resync drops it and the real frame
        // that follows still emits. (The honest stream-framing limit -- garbage
        // that mimics a SHORT VALID frame is indistinguishable from one on a
        // raw byte stream; the M30 channel carries only one well-known peer.)
        let mut garbage_hdr = vec![0u8; INFER_HEADER_LEN];
        let g = InferFrame {
            kind: kind::ECHO_REQ,
            req_id: 1,
            challenge: [0u8; 16],
            nonce: [0u8; 16],
            peer_id: 0,
            tag: [0u8; 16],
            payload: &[],
        };
        assert_eq!(canon(&g, &mut garbage_hdr), INFER_HEADER_LEN);
        // Corrupt the declared length to an oversize value (desync garbage).
        garbage_hdr[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 4]
            .copy_from_slice(&((INFER_PAYLOAD_CAP as u32) + 7).to_le_bytes());

        let p = fill(6, 4);
        let f = resp_for(&req(&p), &p, &KEY);
        let mut wire = vec![0u8; wire_len(&f)];
        let n = canon(&f, &mut wire);

        let mut acc: FrameAccum<INFER_ACCUM_CAP> = FrameAccum::new();
        let mut hits = 0;
        for &b in garbage_hdr.iter().chain(wire.iter()) {
            if let Some(len) = acc.push_byte(b) {
                hits += 1;
                assert_eq!(len, n);
            }
        }
        assert_eq!(hits, 1, "exactly one frame must emerge");
    }

    #[test]
    fn accum_max_size_frame_completes_at_capacity() {
        // The worst-case frame (payload == INFER_PAYLOAD_CAP) is EXACTLY the
        // accumulator capacity -- it must complete, not be resync-dropped (the
        // off-by-one capacity negative, mirrored by the tiny-CAP Kani leg).
        let p = fill(1, INFER_PAYLOAD_CAP);
        let f = resp_for(&req(&p), &p, &KEY);
        let mut wire = vec![0u8; wire_len(&f)];
        let n = canon(&f, &mut wire);
        assert_eq!(n, INFER_ACCUM_CAP);
        let mut acc: FrameAccum<INFER_ACCUM_CAP> = FrameAccum::new();
        let mut emitted = None;
        for &b in &wire {
            emitted = acc.push_byte(b);
            assert!(acc.len() <= INFER_ACCUM_CAP);
        }
        assert_eq!(emitted, Some(INFER_ACCUM_CAP));
    }

    #[test]
    fn accum_tiny_cap_never_overflows() {
        // A deliberately under-sized accumulator can never complete a frame --
        // it must stay bounded + total (fail-closed), never overflow or panic.
        let mut tiny: FrameAccum<6> = FrameAccum::new();
        let p = [1u8, 2];
        let f = req(&p);
        let mut wire = [0u8; 128];
        let n = canon(&f, &mut wire);
        for _ in 0..3 {
            for &b in &wire[..n] {
                assert!(tiny.push_byte(b).is_none());
                assert!(tiny.len() <= 6);
            }
        }
    }

    // =======================================================================
    // M31: the inference-adapter extension (kinds 4..6, SubHdr, infer_tag,
    // InferAssembler, ERR semantics, mock_infer)
    // =======================================================================

    /// A canonical M31 sub-header over `seed`-derived digest bytes.
    fn sub(seq: u16, more: bool, total_len: u32, dseed: u8) -> SubHdr {
        let mut d = [0u8; INFER_BODY_DIGEST_LEN];
        for (i, b) in d.iter_mut().enumerate() {
            *b = dseed.wrapping_add(i as u8).wrapping_mul(41);
        }
        SubHdr {
            seq,
            more,
            total_len,
            body_digest: d,
        }
    }

    /// A fully-populated M31 host->kernel frame of `k` kind over a payload.
    fn m31_frame<'a>(k: u8, req_id: u64, payload: &'a [u8]) -> InferFrame<'a> {
        InferFrame {
            kind: k,
            req_id,
            challenge: arr16(5),
            nonce: arr16(9),
            peer_id: peer::QEMU_CHARDEV_HARNESS,
            tag: [0u8; INFER_TAG_LEN],
            payload,
        }
    }

    #[test]
    fn m31_kind_extension_roundtrips_and_stays_closed() {
        // Kinds 4/5/6 canon+decode round-trip (the codec is kind-agnostic
        // about payload semantics; the layered rules live above decode).
        for &k in &[kind::INFER_REQ, kind::INFER_RESP, kind::INFER_PENDING] {
            let p = fill(3, 8);
            let f = m31_frame(k, 7, &p);
            let mut buf = [0u8; 128];
            let n = canon(&f, &mut buf);
            assert_eq!(n, INFER_HEADER_LEN + 8);
            let d = decode(&buf[..n]).expect("M31 kind must decode");
            assert_eq!(d.kind, k);
            assert_eq!(d.payload, &p[..]);
        }
        // The set stays CLOSED: 0, 7 and beyond reject at canon AND decode.
        let p = [1u8, 2];
        for bad in [0u8, 7, 8, 0x7F, 0xFF] {
            let f = m31_frame(bad, 7, &p);
            let mut buf = [0u8; 128];
            assert_eq!(canon(&f, &mut buf), 0, "kind {bad} must not canon");
            let mut wire = [0u8; 128];
            let g = m31_frame(kind::INFER_RESP, 7, &p);
            let n = canon(&g, &mut wire);
            wire[OFF_KIND] = bad;
            assert!(decode(&wire[..n]).is_none(), "kind {bad} must not decode");
        }
        // The stream accumulator emits an M31 frame (kind plausibility widened).
        let p = fill(6, 4);
        let f = m31_frame(kind::INFER_RESP, 9, &p);
        let mut wire = vec![0u8; wire_len(&f)];
        let n = canon(&f, &mut wire);
        let mut acc: FrameAccum<INFER_ACCUM_CAP> = FrameAccum::new();
        let mut emitted = None;
        for &b in &wire[..n] {
            emitted = acc.push_byte(b);
        }
        assert_eq!(emitted, Some(n));
    }

    #[test]
    fn m31_subhdr_roundtrip_and_fail_closed() {
        let s = sub(3, true, 1280, 7);
        let mut buf = [0u8; INFER_SUBHDR_LEN];
        assert_eq!(subhdr_canon(&s, &mut buf), INFER_SUBHDR_LEN);
        assert_eq!(subhdr_decode(&buf), Some(s));
        // Reserved sflags bits 1..7 reject (every bit independently).
        for bit in 1..8u32 {
            let mut bad = buf;
            bad[2] |= 1u8 << bit;
            assert!(subhdr_decode(&bad).is_none(), "sflags bit {bit} accepted");
        }
        // Reserved byte rejects.
        let mut bad = buf;
        bad[3] = 1;
        assert!(subhdr_decode(&bad).is_none());
        // Truncation rejects.
        for cut in 0..INFER_SUBHDR_LEN {
            assert!(subhdr_decode(&buf[..cut]).is_none());
        }
        // total_len bounds: 0 and over-cap reject at canon AND decode.
        let mut z = s;
        z.total_len = 0;
        assert_eq!(subhdr_canon(&z, &mut buf), 0);
        let mut o = s;
        o.total_len = (INFER_BODY_CAP as u32) + 1;
        assert_eq!(subhdr_canon(&o, &mut buf), 0);
        let mut good = [0u8; INFER_SUBHDR_LEN];
        assert_eq!(subhdr_canon(&s, &mut good), INFER_SUBHDR_LEN);
        good[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert!(subhdr_decode(&good).is_none());
        good[4..8].copy_from_slice(&((INFER_BODY_CAP as u32) + 1).to_le_bytes());
        assert!(subhdr_decode(&good).is_none());
        // Too-small canon buffer fails closed with no partial write.
        let mut small = [0u8; INFER_SUBHDR_LEN - 1];
        assert_eq!(subhdr_canon(&s, &mut small), 0);
        assert!(small.iter().all(|&b| b == 0));
    }

    #[test]
    fn m31_err_codec_closed_enum_and_retryable_binding() {
        use super::errcode::*;
        let all = [
            (NO_BACKEND, false),
            (NO_KEY, false),
            (TOO_LARGE, false),
            (RATE_LIMITED, true),
            (OVERLOADED, true),
            (API_ERROR, true),
            (AUTH, false),
            (BAD_REQUEST, false),
            (REFUSAL, false),
            (TIMEOUT, true),
        ];
        for (code, retry) in all {
            let mut p = [0u8; INFER_ERR_PAYLOAD_LEN];
            assert_eq!(err_canon(code, &mut p), INFER_ERR_PAYLOAD_LEN);
            assert_eq!(err_decode(&p), Some((code, retry)));
            // A contradicted retryable flag REJECTS (the binding round-trips).
            let mut flip = p;
            flip[2] ^= 1;
            assert!(err_decode(&flip).is_none(), "code {code} flag flip accepted");
            // A nonzero reserved byte rejects.
            let mut rsv = p;
            rsv[3] = 0x80;
            assert!(err_decode(&rsv).is_none());
        }
        // Outside the closed enum: canon fail-closes, decode rejects.
        let mut p = [0u8; INFER_ERR_PAYLOAD_LEN];
        for bad in [0u16, 11, 999, u16::MAX] {
            assert_eq!(err_canon(bad, &mut p), 0, "code {bad} canoned");
            let mut w = [0u8; INFER_ERR_PAYLOAD_LEN];
            w[..2].copy_from_slice(&bad.to_le_bytes());
            assert!(err_decode(&w).is_none(), "code {bad} decoded");
        }
        // Wrong payload length rejects (exactly 4, never a prefix).
        let ok = {
            let mut w = [0u8; INFER_ERR_PAYLOAD_LEN];
            assert_eq!(err_canon(NO_KEY, &mut w), INFER_ERR_PAYLOAD_LEN);
            w
        };
        assert!(err_decode(&ok[..3]).is_none());
        let mut long = [0u8; INFER_ERR_PAYLOAD_LEN + 1];
        long[..4].copy_from_slice(&ok);
        assert!(err_decode(&long).is_none());
    }

    #[test]
    fn m31_infer_tag_is_the_pinned_one_khash_call() {
        // The exact proposal-§2c construction asserted against the khash leaf
        // directly (the echo_tag pinned-construction idiom): label drift or
        // field-order drift breaks this even if every behavioral property
        // survives.
        let nonce = arr16(3);
        let chal = arr16(4);
        let s = sub(2, true, 1280, 7);
        let chunk = [0xD1u8, 0xD2, 0xD3];
        let req_id = 0x1122_3344_5566_7788u64;
        let mut msg = Vec::new();
        msg.extend_from_slice(INFER_DOMAIN);
        msg.push(peer::QEMU_CHARDEV_HARNESS);
        msg.extend_from_slice(&nonce);
        msg.extend_from_slice(&chal);
        msg.extend_from_slice(&req_id.to_le_bytes());
        msg.push(kind::INFER_RESP);
        msg.extend_from_slice(&s.seq.to_le_bytes());
        msg.push(s.sflags());
        msg.extend_from_slice(&s.total_len.to_le_bytes());
        msg.extend_from_slice(&s.body_digest);
        msg.extend_from_slice(&chunk);
        let full = crate::khash::khash(&KEY, &msg);
        assert_eq!(
            infer_tag(
                &KEY,
                peer::QEMU_CHARDEV_HARNESS,
                &nonce,
                &chal,
                req_id,
                kind::INFER_RESP,
                &s,
                &chunk
            ),
            full[..INFER_TAG_LEN]
        );
    }

    #[test]
    fn m31_domain_separated_from_echo() {
        // Align the post-label MAC suffixes EXACTLY (body := the serialized
        // infer fields), so the ONLY difference between the two MAC inputs is
        // the leading domain label -- an implementation that dropped or
        // swapped the labels makes the tags EQUAL and fails this.
        let nonce = arr16(1);
        let chal = arr16(2);
        let s = sub(0, false, 64, 3);
        let chunk = [0x5Au8; 4];
        let req_id = 0xAA55_AA55_AA55_AA55u64;
        let mut suffix = Vec::new();
        suffix.extend_from_slice(&req_id.to_le_bytes());
        suffix.push(kind::INFER_RESP);
        suffix.extend_from_slice(&s.seq.to_le_bytes());
        suffix.push(s.sflags());
        suffix.extend_from_slice(&s.total_len.to_le_bytes());
        suffix.extend_from_slice(&s.body_digest);
        suffix.extend_from_slice(&chunk);
        let echo = echo_tag(&KEY, peer::TB_VMM_HOST, &nonce, &chal, &suffix);
        let infer = infer_tag(
            &KEY,
            peer::TB_VMM_HOST,
            &nonce,
            &chal,
            req_id,
            kind::INFER_RESP,
            &s,
            &chunk,
        );
        assert_ne!(echo, infer, "the domain label is load-bearing");
        // And the labels themselves are distinct brand-derived constants.
        assert_ne!(ECHO_DOMAIN, INFER_DOMAIN);
        assert_eq!(INFER_DOMAIN, b"YUVA-M31-INFER-V1");
    }

    /// Build a MAC'd single-chunk M31 RESP frame (the harness's emit path).
    fn resp_chunk<'a>(
        req_id: u64,
        chal: &[u8; 16],
        s: &SubHdr,
        payload_buf: &'a mut Vec<u8>,
        chunk: &[u8],
        key: &[u8; INFER_KEY_LEN],
    ) -> InferFrame<'a> {
        let nonce = arr16(9);
        payload_buf.clear();
        payload_buf.resize(INFER_SUBHDR_LEN, 0);
        assert_eq!(subhdr_canon(s, payload_buf), INFER_SUBHDR_LEN);
        payload_buf.extend_from_slice(chunk);
        let tag = infer_tag(
            key,
            peer::QEMU_CHARDEV_HARNESS,
            &nonce,
            chal,
            req_id,
            kind::INFER_RESP,
            s,
            chunk,
        );
        InferFrame {
            kind: kind::INFER_RESP,
            req_id,
            challenge: *chal,
            nonce,
            peer_id: peer::QEMU_CHARDEV_HARNESS,
            tag,
            payload: payload_buf,
        }
    }

    #[test]
    fn m31_verify_infer_resp_accepts_and_rejects_each_leg() {
        let chal = arr16(4);
        let req_id = 0x0123_4567_89AB_CDEFu64;
        let body = fill(11, 64);
        let s = SubHdr {
            seq: 0,
            more: false,
            total_len: 64,
            body_digest: body_digest(&body),
        };
        let mut pb = Vec::new();
        let f = resp_chunk(req_id, &chal, &s, &mut pb, &body, &KEY);
        let (ds, dc) = verify_infer_resp(&KEY, &f, req_id, &chal).expect("genuine must verify");
        assert_eq!(ds, s);
        assert_eq!(dc, &body[..]);

        // (a) a reflected REQ kind never verifies.
        let mut refl = f;
        refl.kind = kind::INFER_REQ;
        assert!(verify_infer_resp(&KEY, &refl, req_id, &chal).is_none());
        // (b) wrong correlation id rejects.
        assert!(verify_infer_resp(&KEY, &f, req_id ^ 1, &chal).is_none());
        // (c) a non-echoed challenge rejects (canned cross-boot response).
        let mut c2 = chal;
        c2[0] ^= 1;
        assert!(verify_infer_resp(&KEY, &f, req_id, &c2).is_none());
        // (d) a flipped tag byte rejects.
        let mut bt = f;
        bt.tag[0] ^= 1;
        assert!(verify_infer_resp(&KEY, &bt, req_id, &chal).is_none());
        // (e) a flipped CHUNK byte rejects (the chunk is MAC'd).
        let mut pb2 = f.payload.to_vec();
        let last = pb2.len() - 1;
        pb2[last] ^= 1;
        let mut bc = f;
        bc.payload = &pb2;
        assert!(verify_infer_resp(&KEY, &bc, req_id, &chal).is_none());
        // (f) a flipped SEQ rejects (the chunk index is INSIDE the MAC --
        //     a spliced/reordered chunk fails VERIFICATION, not just assembly).
        let mut pb3 = f.payload.to_vec();
        pb3[0] ^= 1;
        let mut bs = f;
        bs.payload = &pb3;
        assert!(verify_infer_resp(&KEY, &bs, req_id, &chal).is_none());
        // (g) a wrong key rejects.
        let mut wk = KEY;
        wk[31] ^= 0x80;
        assert!(verify_infer_resp(&wk, &f, req_id, &chal).is_none());
        // (h) PENDING with a non-empty payload rejects; the genuine MAC'd
        //     empty PENDING verifies.
        let tag = infer_tag(
            &KEY,
            peer::QEMU_CHARDEV_HARNESS,
            &f.nonce,
            &chal,
            req_id,
            kind::INFER_PENDING,
            &SubHdr::empty(),
            &[],
        );
        let pend = InferFrame {
            kind: kind::INFER_PENDING,
            req_id,
            challenge: chal,
            nonce: f.nonce,
            peer_id: peer::QEMU_CHARDEV_HARNESS,
            tag,
            payload: &[],
        };
        assert!(verify_infer_resp(&KEY, &pend, req_id, &chal).is_some());
        let mut pendbad = pend;
        pendbad.payload = &body[..1];
        assert!(verify_infer_resp(&KEY, &pendbad, req_id, &chal).is_none());
        // (i) a MAC'd closed-enum ERR verifies and its payload decodes.
        let mut ep = [0u8; INFER_ERR_PAYLOAD_LEN];
        assert_eq!(err_canon(errcode::NO_KEY, &mut ep), INFER_ERR_PAYLOAD_LEN);
        let etag = infer_tag(
            &KEY,
            peer::QEMU_CHARDEV_HARNESS,
            &f.nonce,
            &chal,
            req_id,
            kind::ERR,
            &SubHdr::empty(),
            &ep,
        );
        let errf = InferFrame {
            kind: kind::ERR,
            req_id,
            challenge: chal,
            nonce: f.nonce,
            peer_id: peer::QEMU_CHARDEV_HARNESS,
            tag: etag,
            payload: &ep,
        };
        let (_, echunk) = verify_infer_resp(&KEY, &errf, req_id, &chal).expect("ERR verifies");
        assert_eq!(err_decode(echunk), Some((errcode::NO_KEY, false)));
    }

    #[test]
    fn m31_verify_infer_req_shape_rules() {
        let chal = arr16(6);
        let req_id = 42u64;
        let body = fill(2, 24);
        let s = SubHdr {
            seq: 0,
            more: false,
            total_len: 24,
            body_digest: body_digest(&body),
        };
        let mut payload = vec![0u8; INFER_SUBHDR_LEN];
        assert_eq!(subhdr_canon(&s, &mut payload), INFER_SUBHDR_LEN);
        payload.extend_from_slice(&body);
        let tag = infer_tag(&KEY, 0, &[0u8; 16], &chal, req_id, kind::INFER_REQ, &s, &body);
        let f = InferFrame {
            kind: kind::INFER_REQ,
            req_id,
            challenge: chal,
            nonce: [0u8; 16],
            peer_id: 0,
            tag,
            payload: &payload,
        };
        let (ds, dc) = verify_infer_req(&KEY, &f).expect("genuine REQ verifies");
        assert_eq!(ds, s);
        assert_eq!(dc, &body[..]);
        // A REQ with a nonzero nonce or peer label rejects (shape rule).
        let mut bn = f;
        bn.nonce = arr16(1);
        assert!(verify_infer_req(&KEY, &bn).is_none());
        let mut bp = f;
        bp.peer_id = peer::QEMU_CHARDEV_HARNESS;
        assert!(verify_infer_req(&KEY, &bp).is_none());
        // A non-REQ kind rejects.
        let mut bk = f;
        bk.kind = kind::INFER_RESP;
        assert!(verify_infer_req(&KEY, &bk).is_none());
        // A flipped tag rejects.
        let mut bt = f;
        bt.tag[5] ^= 1;
        assert!(verify_infer_req(&KEY, &bt).is_none());
    }

    #[test]
    fn m31_assembler_in_order_complete_and_each_reject() {
        // A 2-chunk body at a small total (chunk caps exercised separately).
        let body = fill(7, 96);
        let dig = body_digest(&body);
        let mk = |seq: u16, more: bool| SubHdr {
            seq,
            more,
            total_len: 96,
            body_digest: dig,
        };
        // CLEAN: in-order chunks assemble to exactly total_len + digest holds.
        let mut asm: InferAssembler<256> = InferAssembler::new();
        assert_eq!(asm.push_chunk(&mk(0, true), &body[..64]), AsmPush::Accepted);
        assert_eq!(
            asm.push_chunk(&mk(1, false), &body[64..]),
            AsmPush::Complete(96)
        );
        assert!(asm.is_done());
        assert_eq!(asm.body(), &body[..]);
        // Pushes after completion reject.
        assert_eq!(asm.push_chunk(&mk(2, false), &body[..1]), AsmPush::Rejected);

        // OUT-OF-ORDER first chunk rejects + poisons.
        let mut a: InferAssembler<256> = InferAssembler::new();
        assert_eq!(a.push_chunk(&mk(1, true), &body[..64]), AsmPush::Rejected);
        assert_eq!(a.push_chunk(&mk(0, true), &body[..64]), AsmPush::Rejected);

        // DUPLICATE / GAP seq rejects.
        let mut a: InferAssembler<256> = InferAssembler::new();
        assert_eq!(a.push_chunk(&mk(0, true), &body[..32]), AsmPush::Accepted);
        assert_eq!(a.push_chunk(&mk(0, true), &body[32..64]), AsmPush::Rejected);
        let mut a: InferAssembler<256> = InferAssembler::new();
        assert_eq!(a.push_chunk(&mk(0, true), &body[..32]), AsmPush::Accepted);
        assert_eq!(a.push_chunk(&mk(2, false), &body[32..]), AsmPush::Rejected);

        // total_len DRIFT rejects.
        let mut a: InferAssembler<256> = InferAssembler::new();
        assert_eq!(a.push_chunk(&mk(0, true), &body[..32]), AsmPush::Accepted);
        let mut drift = mk(1, false);
        drift.total_len = 97;
        assert_eq!(a.push_chunk(&drift, &body[32..]), AsmPush::Rejected);

        // body_digest DRIFT rejects.
        let mut a: InferAssembler<256> = InferAssembler::new();
        assert_eq!(a.push_chunk(&mk(0, true), &body[..32]), AsmPush::Accepted);
        let mut ddrift = mk(1, false);
        ddrift.body_digest[0] ^= 1;
        assert_eq!(a.push_chunk(&ddrift, &body[32..]), AsmPush::Rejected);

        // OVERFLOW past total_len rejects (sum-of-chunks > total).
        let mut a: InferAssembler<256> = InferAssembler::new();
        assert_eq!(a.push_chunk(&mk(0, true), &body[..64]), AsmPush::Accepted);
        assert_eq!(a.push_chunk(&mk(1, true), &body[32..96]), AsmPush::Rejected);

        // CAPACITY overflow: total_len > CAP rejects at the FIRST chunk.
        let mut tiny: InferAssembler<64> = InferAssembler::new();
        assert_eq!(tiny.push_chunk(&mk(0, true), &body[..32]), AsmPush::Rejected);

        // MORE-but-already-complete rejects; final-not-exact rejects.
        let mut a: InferAssembler<256> = InferAssembler::new();
        assert_eq!(a.push_chunk(&mk(0, true), &body[..96]), AsmPush::Rejected);
        let mut a: InferAssembler<256> = InferAssembler::new();
        assert_eq!(a.push_chunk(&mk(0, false), &body[..64]), AsmPush::Rejected);

        // DIGEST MISMATCH on completion rejects (the commitment arbitrates).
        let mut wrong = mk(0, false);
        wrong.body_digest[3] ^= 1;
        let mut a: InferAssembler<256> = InferAssembler::new();
        assert_eq!(a.push_chunk(&wrong, &body[..]), AsmPush::Rejected);
        assert!(!a.is_done());

        // EMPTY chunk rejects (no-progress).
        let mut a: InferAssembler<256> = InferAssembler::new();
        assert_eq!(a.push_chunk(&mk(0, true), &[]), AsmPush::Rejected);
    }

    #[test]
    fn m31_chunk_math_and_full_wire_roundtrip() {
        // The fixed chunk discipline: 1280 -> 2 chunks (1000 + 280).
        assert_eq!(infer_chunk_count(INFER_MOCK_RESP_LEN), 2);
        assert_eq!(infer_chunk_count(1), 1);
        assert_eq!(infer_chunk_count(INFER_CHUNK_CAP), 1);
        assert_eq!(infer_chunk_count(INFER_CHUNK_CAP + 1), 2);
        assert_eq!(infer_chunk_count(INFER_BODY_CAP), 9);
        assert_eq!(infer_chunk_count(0), 0);
        assert_eq!(infer_chunk_count(INFER_BODY_CAP + 1), 0);
        assert_eq!(
            infer_chunks_wire_len(INFER_MOCK_RESP_LEN),
            2 * (INFER_HEADER_LEN + INFER_SUBHDR_LEN) + INFER_MOCK_RESP_LEN
        );
        assert_eq!(infer_chunks_wire_len(0), 0);

        // FULL wire round-trip at the mock length: split per the discipline,
        // canon + MAC each chunk frame, stream it byte-at-a-time through
        // FrameAccum, verify each chunk, assemble -- the body returns
        // bit-exact (the in-boot path in miniature).
        let mut body = vec![0u8; INFER_MOCK_RESP_LEN];
        for (i, b) in body.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        let dig = body_digest(&body);
        let chal = arr16(8);
        let req_id = 0xFEED_F00D_0000_0031u64;
        let n_chunks = infer_chunk_count(body.len());
        let mut stream: Vec<u8> = Vec::new();
        for c in 0..n_chunks {
            let lo = c * INFER_CHUNK_CAP;
            let hi = usize::min(lo + INFER_CHUNK_CAP, body.len());
            let s = SubHdr {
                seq: c as u16,
                more: hi < body.len(),
                total_len: body.len() as u32,
                body_digest: dig,
            };
            let mut pb = Vec::new();
            let f = resp_chunk(req_id, &chal, &s, &mut pb, &body[lo..hi], &KEY);
            let mut wire = vec![0u8; wire_len(&f)];
            let n = canon(&f, &mut wire);
            assert_eq!(n, wire.len());
            stream.extend_from_slice(&wire);
        }
        assert_eq!(stream.len(), infer_chunks_wire_len(body.len()));

        let mut acc: FrameAccum<INFER_ACCUM_CAP> = FrameAccum::new();
        let mut asm: InferAssembler<INFER_BODY_CAP> = InferAssembler::new();
        let mut completed = None;
        for &b in &stream {
            if let Some(fl) = acc.push_byte(b) {
                let frame = decode(&acc.bytes()[..fl]).expect("emitted frame decodes");
                let (s, chunk) =
                    verify_infer_resp(&KEY, &frame, req_id, &chal).expect("chunk verifies");
                match asm.push_chunk(&s, chunk) {
                    AsmPush::Accepted => {}
                    AsmPush::Complete(n) => completed = Some(n),
                    AsmPush::Rejected => panic!("genuine chunk rejected"),
                }
                acc.consume(fl);
            }
        }
        assert_eq!(completed, Some(body.len()));
        assert_eq!(asm.body(), &body[..]);
    }

    #[test]
    fn m31_mock_infer_deterministic_expansion() {
        let prompt = fill(9, 24);
        let mut a = vec![0u8; INFER_MOCK_RESP_LEN];
        let mut b = vec![0u8; INFER_MOCK_RESP_LEN];
        assert_eq!(mock_infer(&prompt, &mut a), INFER_MOCK_RESP_LEN);
        assert_eq!(mock_infer(&prompt, &mut b), INFER_MOCK_RESP_LEN);
        assert_eq!(a, b, "the mock transform must be bit-for-bit reproducible");
        // A different prompt expands to a different stream (non-constant).
        let mut p2 = prompt.clone();
        p2[0] ^= 1;
        let mut c = vec![0u8; INFER_MOCK_RESP_LEN];
        assert_eq!(mock_infer(&p2, &mut c), INFER_MOCK_RESP_LEN);
        assert_ne!(a, c);
        // Non-identity: the response never embeds the prompt verbatim at the
        // front (an echo cannot pass for the transform).
        assert_ne!(&a[..prompt.len()], &prompt[..]);
        // Fail-closed: empty prompt, over-cap prompt, too-small out.
        let mut out = vec![0u8; INFER_MOCK_RESP_LEN];
        assert_eq!(mock_infer(&[], &mut out), 0);
        let big = vec![1u8; INFER_BODY_CAP + 1];
        assert_eq!(mock_infer(&big, &mut out), 0);
        let mut small = vec![0u8; INFER_MOCK_RESP_LEN - 1];
        assert_eq!(mock_infer(&prompt, &mut small), 0);
        // The pinned first keystream block (construction drift breaks this).
        let seed = crate::khash::uhash(&prompt);
        let mut blk = Vec::new();
        blk.extend_from_slice(b"YUVA-M31-MOCK-V1");
        blk.extend_from_slice(&seed);
        blk.extend_from_slice(&0u32.to_le_bytes());
        let first = crate::khash::uhash(&blk);
        assert_eq!(&a[..32], &first[..]);
    }

    #[test]
    fn m31_body_digest_is_truncated_uhash_and_probe_is_brandish() {
        let b = fill(5, 33);
        let full = crate::khash::uhash(&b);
        assert_eq!(body_digest(&b), full[..INFER_BODY_DIGEST_LEN]);
        // The stage-B probe body is the pinned brand-derived constant and
        // fits a single chunk.
        assert_eq!(INFER_NOKEY_PROBE, b"YUVA-M31-NOKEY-PROBE-V1");
        assert!(INFER_NOKEY_PROBE.len() <= INFER_CHUNK_CAP);
    }

    /// THE RE-DERIVATION ANCHOR for the Kani pinned-vector constants
    /// (`KANI_RESP_BINDING_PIN` / `KANI_DOMAIN_INFER_PIN` /
    /// `KANI_DOMAIN_ECHO_PIN` in `proofs.rs` -- the #49 measured-budget
    /// shape: one ~70s CBMC khash execution per harness, the genuine tag
    /// riding a pinned constant exactly like the `khash` official KATs).
    /// This test recomputes all three through the REAL leaf on the
    /// harnesses' exact inputs, so the pins, the harnesses, and the leaf can
    /// never silently drift apart; it ALSO executes the LIVE echo-vs-infer
    /// aligned-suffix pair -- the named delegation of the two-call
    /// domain-separation inequality, run under cargo test AND the Miri gate.
    #[test]
    fn m31_kani_pins_rederive() {
        let pat16 = |m: u8, a: u8| {
            let mut x = [0u8; 16];
            for (i, b) in x.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(m).wrapping_add(a);
            }
            x
        };
        let chal = pat16(7, 1); // the kani_iw_frame challenge pattern
        let nonce = pat16(11, 3); // the kani_iw_frame nonce pattern
        let dig = pat16(19, 11); // the kani_m31_sub digest pattern

        // (1) KANI_RESP_BINDING_PIN.
        let key = [0x6Du8; INFER_KEY_LEN];
        let s = SubHdr {
            seq: 1,
            more: true,
            total_len: 64,
            body_digest: dig,
        };
        let chunk = [0x42u8, 0x99, 0x17, 0xE0, 0x3B, 0x70, 0x55, 0x08];
        let t = infer_tag(
            &key,
            peer::QEMU_CHARDEV_HARNESS,
            &nonce,
            &chal,
            0xA5A5_5A5A_0123_4567,
            kind::INFER_RESP,
            &s,
            &chunk,
        );
        assert_eq!(
            t,
            [
                0x80, 0x2e, 0xe6, 0xf6, 0x8d, 0x3c, 0x05, 0x3a, 0xfc, 0xb6, 0xe4, 0x4e, 0x28,
                0x55, 0xfa, 0x94
            ]
        );

        // (2) KANI_DOMAIN_INFER_PIN + (3) KANI_DOMAIN_ECHO_PIN -- and the
        // LIVE aligned-suffix inequality (the named two-call delegation).
        let key2 = [0x2Bu8; INFER_KEY_LEN];
        let s2 = SubHdr {
            seq: 0,
            more: false,
            total_len: 12,
            body_digest: dig,
        };
        let chunk2 = [0x5Au8; 8];
        let rid = 0xDEAD_BEEF_0000_0031u64;
        let ti = infer_tag(
            &key2,
            peer::TB_VMM_HOST,
            &nonce,
            &chal,
            rid,
            kind::INFER_RESP,
            &s2,
            &chunk2,
        );
        let mut suffix = Vec::new();
        suffix.extend_from_slice(&rid.to_le_bytes());
        suffix.push(kind::INFER_RESP);
        suffix.extend_from_slice(&s2.seq.to_le_bytes());
        suffix.push(s2.sflags());
        suffix.extend_from_slice(&s2.total_len.to_le_bytes());
        suffix.extend_from_slice(&s2.body_digest);
        suffix.extend_from_slice(&chunk2);
        let te = echo_tag(&key2, peer::TB_VMM_HOST, &nonce, &chal, &suffix);
        assert_eq!(
            ti,
            [
                0xb0, 0xf5, 0x43, 0xcd, 0x78, 0x71, 0xc3, 0x44, 0x77, 0x40, 0xf5, 0x18, 0x2a,
                0xbc, 0x72, 0xa0
            ]
        );
        assert_eq!(
            te,
            [
                0x52, 0x09, 0x82, 0x30, 0x37, 0xf9, 0x3e, 0x8c, 0x35, 0xd7, 0xa8, 0x0a, 0x88,
                0x2d, 0x96, 0x9f
            ]
        );
        // The LIVE pair inequality on the aligned inputs (label load-bearing).
        assert_ne!(ti, te);
    }
}

