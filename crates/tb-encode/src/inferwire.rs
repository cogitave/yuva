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

/// The fixed frame KIND tags (proposal §2 -- the typed transport vocabulary).
/// A closed set; [`canon`]/[`decode`] reject any other value (fail-closed).
pub mod kind {
    /// Kernel -> host: the echo REQUEST carrying the per-boot challenge.
    pub const ECHO_REQ: u8 = 1;
    /// Host -> kernel: the keyed echo RESPONSE (nonce + peer_id + tag set,
    /// body echoed verbatim).
    pub const ECHO_RESP: u8 = 2;
    /// Either direction: a typed error indication (no semantics in M30 beyond
    /// "not an echo"; reserved so a future adapter never overloads ECHO_*).
    pub const ERR: u8 = 3;
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

/// Whether `k` is a known frame [`kind`] tag (the closed set).
#[inline]
#[must_use]
fn kind_known(k: u8) -> bool {
    matches!(k, kind::ECHO_REQ | kind::ECHO_RESP | kind::ERR)
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
}
