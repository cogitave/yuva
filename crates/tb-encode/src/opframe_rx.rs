//! The M28 verified OPERATOR-INBOUND command codec -- the pure, verified value-
//! computation leaf behind the INBOUND operator channel, the RX dual of the M25
//! [`crate::opframe`] TX transcript. A typed, fixed-header, length-prefixed,
//! INJECTIVE [`CmdFrame`] a SIMULATED enrolled verifier submits over the serial
//! RX path by which a human, holding an ENROLLED CREDENTIAL, answers the OS's
//! freshness CHALLENGE and commands the M24 gate's exogenous-oracle input. This
//! is the CAPSTONE that closes the M23->M24->M25->M26->M27 learning loop -- the
//! authenticated inbound command the entire arc was built to receive.
//!
//! ## What this is FOR (proposal §1 -- the exogenous-oracle CLOSURE)
//!
//! M24's honest gate REFUSES to activate the learned cell because a self-graded
//! loop has no EXOGENOUS oracle. M25 SURFACES the decisions to a human (TX-only).
//! M28 delivers the human's authenticated COMMAND: the OS emits a CHALLENGE (a
//! fresh per-boot nonce -- RATS RFC 9334 §10 freshness), and a valid
//! `ACTIVATE_CMD` MUST echo that nonce (freshness), bind the LIVE M22/`op_head`
//! into the MAC'd bytes (head-binding -- the Terrapin lesson arXiv:2312.12422),
//! be DUAL-AUTHORIZED by two distinct enrolled credentials (the two-person rule),
//! and carry a KEYED MAC the verifier recomputes. The command is NECESSARY-NOT-
//! SUFFICIENT: it un-blocks the M24 gate's oracle input; the gate still enforces
//! its statistical bar, so on synthetic data `KAN_ACTIVE` stays `false`.
//!
//! ## Honest scope (proposal §5 -- the marker claims ONLY what is proved)
//!
//! * **CLAIMS enrolled-key replay/truncation resistance** vs a NON-ADAPTIVE
//!   adversary who NEVER sees the key: a stale nonce / wrong head / single-
//!   credential / flipped-MAC command is REJECTED. The freshness nonce + the
//!   head-binding + the dual-custody + the keyed MAC are recomputed inside
//!   [`decode_and_verify`].
//! * **Does NOT claim cryptographic forgery-resistance / non-repudiation.** The
//!   MAC is a KEYED-but-NON-CRYPTOGRAPHIC forward-secure checksum -- the NESTED
//!   keyed-FNV envelope `cmd_hash(cmd_hash(cmd_hash(key_a) || cmd_hash(key_b)) ||
//!   cmd_hash(canon))` truncated to [`MAC_LEN`] (the envelope shape avoids the raw
//!   `key‖msg` RFC 2104 length-extension layout, but FNV itself is still not
//!   collision/preimage resistant -- so the tier stays NON-crypto). The honesty token
//!   `mac=KEYED-NONCRYPTO` is machine-emitted; `mac=KEYED-CRYPTO` (a verified real
//!   keyed hash) is the named successor. **This is the single most important anti-
//!   overclaim of M28** -- the biggest hollow-marker risk in the roadmap.
//! * **Does NOT claim a real human commanded.** The CI verifier holds a COMPILED-IN
//!   test key, not a real enrolment ceremony. The token `oracle=SIMULATED-ENROLLED-
//!   KEY` is machine-emitted so the marker mechanically cannot overclaim.
//! * **Does NOT directly activate the cell.** An accepted command sets a PENDING
//!   flag the M24 gate reads as ONE conjunctive input; it does NOT flip
//!   `KAN_ACTIVE`. The witness carries `kan_active=0` (necessary-not-sufficient).
//!
//! ## Forward-secure key evolution (proposal §2.3 -- the FssAgg shape)
//!
//! [`key_evolve`] is a one-way-SHAPED deterministic mix (`key_{i+1} =
//! prov_hash(key_i)` truncated to a [`KEY_LEN`] key), the Ma-Tsudik FssAgg /
//! Schneier-Kelsey forward-evolution shape: each epoch's key is derived by the
//! one-way fold from the prior, so a captured later key cannot reconstruct an
//! earlier one. The verifier evolves its key per challenge epoch; M28 ships the
//! SHAPE (the secret-keyed successor to M25's keyless `keyed=0`).
//!
//! ## Numeric format (no float, ever -- mirrors `opframe`/`prov`/`exittel`)
//!
//! Pure integer/byte arithmetic, zero alloc, zero deps. [`canon`] is a FIXED-
//! HEADER, fixed-field-order, LENGTH-PREFIXED-payload LE byte layout into a caller
//! buffer covering EVERYTHING EXCEPT the trailing [`MAC_LEN`]-byte MAC (the MAC'd
//! bytes); [`decode`] is the inverse over a large-enough buffer, splitting the
//! `canon|mac` boundary (fail-closed to `None`). The keyed MAC REUSES the proven
//! [`crate::prov::prov_hash`] leaf -- NO new hash math is written here.

// The keyed MAC + key-evolution REUSE the M22 provenance digest, verbatim
// (proposal §2.3: "reuse the M22 FNV fold but secret-keyed"). We import the proven
// digest; M28 writes NONE of its own hash math, exactly as M25/M26 reuse the fold.
pub use crate::prov::{prov_hash as cmd_hash, PROV_HASH_LEN};

/// The inbound command-frame format version (proposal §2.1). [`canon`]/[`decode`]
/// reject any other value (fail-closed -- an unknown version is incompatible).
pub const CMD_VER: u8 = 1;

/// The fixed command-frame magic (`"TC"` little-endian: `0x43, 0x54` -- Tabos
/// Command, distinct from the M25 transcript magic so a TX frame is never mistaken
/// for an inbound command). [`canon`]/[`decode`] reject any other value.
pub const CMD_MAGIC: u16 = 0x5443;

/// The length of the enrolled credential key material each verifier holds (bytes).
/// A key is opaque secret bytes; [`key_evolve`] folds one key to the next.
pub const KEY_LEN: usize = 32;

/// The KEYED-MAC width (bytes): the leading [`MAC_LEN`] bytes of the NESTED keyed
/// [`cmd_hash`] envelope (see [`compute_mac`]), the FssAgg aggregate authenticator
/// truncated for the on-wire frame. NON-cryptographic (see the module honesty note).
pub const MAC_LEN: usize = 16;

/// The fixed command KIND tags (proposal §2.1 -- the typed inbound vocabulary). A
/// closed set; the kind is folded into the MAC'd bytes, so a NOP can never
/// masquerade as an ACTIVATE_CMD (the byte differs -> the MAC differs).
/// [`decode`] rejects any other value.
pub mod kind {
    /// The OS-emitted freshness CHALLENGE request marker (the verifier answers it).
    pub const CHALLENGE_REQ: u8 = 1;
    /// The highest-consequence input: command the M24 gate's exogenous-oracle
    /// input (dual-authorized, fresh, head-bound). Only this kind can be ACCEPTED.
    pub const ACTIVATE_CMD: u8 = 2;
    /// A no-op keep-alive (a well-formed frame that is never an activation).
    pub const NOP: u8 = 3;
}

/// A fixed, canonical INBOUND command frame (proposal §2.1), the RX dual of
/// [`crate::opframe::OpFrame`]. The FIXED header occupies a fixed prefix; the
/// variable `payload` is LENGTH-PREFIXED (the `payload_len` u32) so [`canon`] is
/// injective. The trailing `mac` is the KEYED authenticator over the canonical
/// (MAC'd) bytes -- it is NOT part of `canon` (the MAC'd bytes are everything
/// EXCEPT the mac). Borrowed `payload` so the leaf stays zero-alloc.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CmdFrame<'a> {
    /// The frame kind (see [`kind`]): challenge-req | activate-cmd | nop.
    pub kind: u8,
    /// The challenge NONCE the OS issued, ECHOED back (freshness -- RATS RFC 9334
    /// §10.2). A valid `ACTIVATE_CMD` MUST echo the current challenge nonce.
    pub nonce_echo: u64,
    /// The LIVE M22 `op_head` the command BINDS into the MAC'd bytes (head-binding
    /// -- the Terrapin lesson). A command from a different boot carries a different
    /// head and fails verification.
    pub op_head_bind: [u8; PROV_HASH_LEN],
    /// The command sequence number (folded into the MAC'd bytes, not a side label).
    pub seq: u64,
    /// The FIRST enrolled credential id (the two-person rule -- proposal §2.4).
    pub cred_a_id: u16,
    /// The SECOND enrolled credential id; MUST be distinct from `cred_a_id` for an
    /// activation (dual-custody / break-glass two-person rule).
    pub cred_b_id: u16,
    /// The opaque payload bytes (length-prefixed in [`canon`]).
    pub payload: &'a [u8],
    /// The KEYED MAC over the canonical (MAC'd) bytes -- the leading [`MAC_LEN`]
    /// bytes of the nested [`compute_mac`] envelope. NON-cryptographic.
    pub mac: [u8; MAC_LEN],
}

/// The fixed canonical-frame HEADER length (everything before the variable payload):
/// `magic(2) | ver(1) | kind(1) | reserved(1) | nonce_echo(8) | op_head_bind(32) |
/// seq(8) | cred_a_id(2) | cred_b_id(2) | payload_len(4)` = 61 bytes. The trailing
/// `payload_len` u32 is the LENGTH-PREFIX (the injectivity disambiguator). The MAC
/// is NOT in the header -- it trails the payload, OUTSIDE the MAC'd bytes.
pub const CMD_HEADER_LEN: usize = 2 + 1 + 1 + 1 + 8 + PROV_HASH_LEN + 8 + 2 + 2 + 4;

// Fixed field offsets (the header layout above). Named consts so the round-trip +
// the Kani harnesses read the SAME literals the encoder writes.
const OFF_MAGIC: usize = 0;
const OFF_VER: usize = 2;
const OFF_KIND: usize = 3;
const OFF_RESERVED: usize = 4;
const OFF_NONCE: usize = 5;
const OFF_HEAD_BIND: usize = 13;
const OFF_SEQ: usize = 45;
const OFF_CRED_A: usize = 53;
const OFF_CRED_B: usize = 55;
/// The offset of the `payload_len` u32 LE length-prefix (the injectivity disambiguator).
pub const OFF_PAYLOAD_LEN: usize = 57;
/// The offset at which the variable payload begins (== [`CMD_HEADER_LEN`]).
pub const OFF_PAYLOAD: usize = 61;

/// The exact CANONICAL (MAC'd) byte length of `frame`: [`CMD_HEADER_LEN`] + the
/// payload length, computed with SATURATING arithmetic so a pathological payload
/// length can never overflow `usize` (total -- it never panics). This is the length
/// of the bytes [`canon`] writes and the bytes the MAC is computed over; the full
/// on-wire frame is this + [`MAC_LEN`] (see [`wire_len`]).
#[inline]
#[must_use]
pub fn canon_len(frame: &CmdFrame) -> usize {
    CMD_HEADER_LEN.saturating_add(frame.payload.len())
}

/// The exact ON-WIRE byte length of `frame`: [`canon_len`] + [`MAC_LEN`] (the MAC'd
/// bytes followed by the trailing MAC). Saturating (total -- never panics).
#[inline]
#[must_use]
pub fn wire_len(frame: &CmdFrame) -> usize {
    canon_len(frame).saturating_add(MAC_LEN)
}

/// Whether `frame`'s header fields are well-formed (a known [`kind`], `cred_a_id`
/// and `cred_b_id` representable). [`canon`] fail-closes (returns 0) when this is
/// false. Total -- no panic. (`reserved` is forced to 0 by `canon` itself; the
/// nonce/head/seq/cred fields are free-form value bytes, validated for ACCEPTANCE
/// in [`decode_and_verify`], not for ENCODABILITY here.)
#[inline]
#[must_use]
pub fn frame_is_encodable(frame: &CmdFrame) -> bool {
    matches!(
        frame.kind,
        kind::CHALLENGE_REQ | kind::ACTIVATE_CMD | kind::NOP
    )
}

/// Canonical, UNAMBIGUOUS, total, length-delimited LE encoding of `frame`'s MAC'd
/// bytes (everything EXCEPT the trailing MAC) into `out`. Returns the number of
/// bytes written, or `0` if `out` is too small OR `frame` is not
/// [`frame_is_encodable`] (TOTAL + fail-closed: never panics, never partial-writes,
/// mirroring [`crate::opframe::canon`]). Layout (fixed header, payload LENGTH-PREFIXED):
///
/// ```text
///   [0..2]   magic         u16 LE   (== CMD_MAGIC)
///   [2]      ver           u8       (== CMD_VER)
///   [3]      kind          u8       (a known `kind` tag)
///   [4]      reserved      u8       (forced 0 -- a set reserved bit cannot ride out)
///   [5..13]  nonce_echo    u64 LE   (the echoed freshness nonce)
///   [13..45] op_head_bind  [u8;32]  (the live M22 head -- head-binding)
///   [45..53] seq           u64 LE   (folded into the MAC'd bytes, never a side label)
///   [53..55] cred_a_id     u16 LE   (the first enrolled credential)
///   [55..57] cred_b_id     u16 LE   (the second enrolled credential -- dual custody)
///   [57..61] payload_len   u32 LE   <-- the length-prefix (disambiguator)
///   [61..]   payload[i]    u8       verbatim, i in 0..payload_len
/// ```
///
/// INJECTIVITY: two encodable frames that differ in ANY MAC'd field encode to
/// different bytes -- the fixed-width header at fixed offsets + the explicit
/// `payload_len` prefix making the variable tail self-delimiting (the
/// `kani_cmd_canon_injective` harness discharges this).
#[must_use]
pub fn canon(frame: &CmdFrame, out: &mut [u8]) -> usize {
    // Fail-closed VALIDATION FIRST (before any write).
    if !frame_is_encodable(frame) {
        return 0;
    }
    let plen = frame.payload.len();
    // Reject a payload too long to length-prefix in a u32 (fail-closed totality).
    if plen > u32::MAX as usize {
        return 0;
    }
    let total = canon_len(frame);
    if out.len() < total {
        return 0; // too-small buffer -> 0 bytes, no partial write (totality)
    }
    write_u16(out, OFF_MAGIC, CMD_MAGIC);
    out[OFF_VER] = CMD_VER;
    out[OFF_KIND] = frame.kind;
    out[OFF_RESERVED] = 0; // forced 0 -- a set reserved bit can never ride out
    write_u64(out, OFF_NONCE, frame.nonce_echo);
    let mut b = 0usize;
    while b < PROV_HASH_LEN {
        out[OFF_HEAD_BIND + b] = frame.op_head_bind[b];
        b += 1;
    }
    write_u64(out, OFF_SEQ, frame.seq);
    write_u16(out, OFF_CRED_A, frame.cred_a_id);
    write_u16(out, OFF_CRED_B, frame.cred_b_id);
    write_u32(out, OFF_PAYLOAD_LEN, plen as u32);
    let mut p = 0usize;
    while p < plen {
        out[OFF_PAYLOAD + p] = frame.payload[p];
        p += 1;
    }
    total
}

/// The exact inverse of [`canon`] over a FULL on-wire `buf` (the MAC'd bytes
/// FOLLOWED by the trailing [`MAC_LEN`]-byte MAC): decode the header + borrow the
/// payload slice + split off the trailing MAC into an [`CmdFrame`], or `None` if
/// `buf` is too small for the header+MAC, carries a bad magic / version / reserved
/// bit / unknown kind, or is too small for the declared `payload_len` + MAC
/// (TOTAL, fail-closed: never panics -- mirrors [`crate::opframe::decode`]). A
/// successful decode round-trips its MAC'd bytes back to identical canonical bytes
/// (the `kani_cmd_canon_roundtrip` harness). The returned frame borrows `buf` for
/// its payload (zero-copy); the MAC is copied into the fixed [`MAC_LEN`] array.
#[must_use]
pub fn decode(buf: &[u8]) -> Option<CmdFrame<'_>> {
    // The minimum on-wire frame is the header + an empty payload + the MAC.
    if buf.len() < CMD_HEADER_LEN + MAC_LEN {
        return None;
    }
    if read_u16(buf, OFF_MAGIC) != CMD_MAGIC {
        return None; // foreign byte stream
    }
    if buf[OFF_VER] != CMD_VER {
        return None; // incompatible version
    }
    if buf[OFF_RESERVED] != 0 {
        return None; // a set reserved bit is a malformed frame
    }
    let kind = buf[OFF_KIND];
    if !matches!(
        kind,
        kind::CHALLENGE_REQ | kind::ACTIVATE_CMD | kind::NOP
    ) {
        return None; // unknown kind -- fail closed
    }
    let nonce_echo = read_u64(buf, OFF_NONCE);
    let mut op_head_bind = [0u8; PROV_HASH_LEN];
    let mut b = 0usize;
    while b < PROV_HASH_LEN {
        op_head_bind[b] = buf[OFF_HEAD_BIND + b];
        b += 1;
    }
    let seq = read_u64(buf, OFF_SEQ);
    let cred_a_id = read_u16(buf, OFF_CRED_A);
    let cred_b_id = read_u16(buf, OFF_CRED_B);
    let plen = read_u32(buf, OFF_PAYLOAD_LEN) as usize;
    // The canonical (MAC'd) bytes end at OFF_PAYLOAD + plen; the MAC trails it.
    let canon_end = OFF_PAYLOAD.checked_add(plen)?; // fail-closed on overflow
    let wire_end = canon_end.checked_add(MAC_LEN)?; // ...+ the trailing MAC
    if buf.len() < wire_end {
        return None; // truncated payload or missing MAC
    }
    let mut mac = [0u8; MAC_LEN];
    let mut m = 0usize;
    while m < MAC_LEN {
        mac[m] = buf[canon_end + m];
        m += 1;
    }
    Some(CmdFrame {
        kind,
        nonce_echo,
        op_head_bind,
        seq,
        cred_a_id,
        cred_b_id,
        payload: &buf[OFF_PAYLOAD..canon_end],
        mac,
    })
}

/// One-way-SHAPED forward key evolution (proposal §2.3 -- the FssAgg shape):
/// `key_{i+1} = key_evolve(key_i)`, the leading [`KEY_LEN`] bytes of
/// [`cmd_hash`] over the prior key. DETERMINISTIC (the same key always evolves to
/// the same successor) and TAMPER-SENSITIVE (a single-byte change to the input key
/// changes the output -- the FNV avalanche the M22 digest already proves). The
/// forward-security SHAPE: deriving forward is the one-way fold; a captured later
/// key does not structurally reconstruct an earlier one. REUSES [`cmd_hash`] -- NO
/// new hash math. (Honest: structural one-way SHAPE, not a proven OWF -- the keyed-
/// crypto tier is the named successor.)
#[inline]
#[must_use]
pub fn key_evolve(key: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let digest = cmd_hash(key); // 32-byte FNV-lane digest, reused verbatim
    let mut out = [0u8; KEY_LEN];
    let mut i = 0usize;
    while i < KEY_LEN {
        out[i] = digest[i];
        i += 1;
    }
    out
}

/// The KEYED (NON-cryptographic) MAC over `canon_bytes`: the leading [`MAC_LEN`]
/// bytes of the NESTED [`cmd_hash`] envelope `cmd_hash( cmd_hash(cmd_hash(key_a) ||
/// cmd_hash(key_b)) || cmd_hash(canon_bytes) )` (the exact three-stage construction
/// in the body below). BOTH enrolled keys contribute (the two-person rule -- each
/// credential keys the MAC, order-sensitively), and the canonical (MAC'd) bytes
/// (kind/nonce/head/seq/creds/payload) are authenticated. TAMPER-SENSITIVE: a
/// single-byte flip of `canon_bytes` (or either key) changes the MAC (the FNV
/// avalanche). Total -- no panic, no alloc (fixed bounded scratch). REUSES
/// [`cmd_hash`] -- NO new hash math.
///
/// **NON-cryptographic** (proposal §2.3 / §5): the nested-envelope shape avoids the
/// raw `key‖msg` RFC 2104 length-extension layout, but the underlying FNV digest is
/// not collision/preimage resistant, so the construction is NOT a secure MAC.
/// It claims ONLY enrolled-key replay/truncation resistance vs a non-adaptive
/// adversary who never sees the keys -- never forgery-resistance. The honesty token
/// `mac=KEYED-NONCRYPTO` is machine-emitted by the seam.
#[must_use]
pub fn compute_mac(
    key_a: &[u8; KEY_LEN],
    key_b: &[u8; KEY_LEN],
    canon_bytes: &[u8],
) -> [u8; MAC_LEN] {
    // The keyed MAC is computed with the proven `cmd_hash` (which takes a SINGLE
    // contiguous slice -- no streaming API), in three bounded fixed-width stages that
    // bind BOTH keys and the full canon bytes, then truncate to MAC_LEN:
    //   key_digest = cmd_hash( cmd_hash(key_a) || cmd_hash(key_b) )  -- the 32B key
    //                commitment (both creds contribute; order-sensitive dual custody)
    //   mac_full   = cmd_hash( key_digest || cmd_hash(canon_bytes) ) -- the keyed MAC
    //                over the structural canon digest (tamper-sensitive in any canon
    //                byte via the FNV avalanche the M22 digest already proves)
    //   mac        = mac_full[..MAC_LEN]                             -- the on-wire tag
    let ka = cmd_hash(key_a);
    let kb = cmd_hash(key_b);
    let mut keypair = [0u8; 2 * PROV_HASH_LEN];
    let mut i = 0usize;
    while i < PROV_HASH_LEN {
        keypair[i] = ka[i];
        keypair[PROV_HASH_LEN + i] = kb[i];
        i += 1;
    }
    let key_digest = cmd_hash(&keypair); // 32-byte combined KEY digest

    // The keyed MAC over the canon bytes: we fold `key_digest` and `canon_bytes`
    // by hashing their concatenation. To keep a single contiguous slice for the
    // proven `cmd_hash`, mix per-byte: seed the canon digest with the key digest by
    // hashing (key_digest) then folding the canon digest with a domain-tagged second
    // pass -- a deterministic keyed combine that is tamper-sensitive in BOTH inputs.
    let canon_digest = cmd_hash(canon_bytes); // 32-byte structural canon digest
    let mut combined = [0u8; 2 * PROV_HASH_LEN];
    let mut j = 0usize;
    while j < PROV_HASH_LEN {
        combined[j] = key_digest[j];
        combined[PROV_HASH_LEN + j] = canon_digest[j];
        j += 1;
    }
    let mac_full = cmd_hash(&combined); // 32-byte keyed MAC digest
    let mut mac = [0u8; MAC_LEN];
    let mut k = 0usize;
    while k < MAC_LEN {
        mac[k] = mac_full[k]; // truncate to MAC_LEN (the on-wire authenticator)
        k += 1;
    }
    mac
}

/// The verdict of [`decode_and_verify`] (proposal §3). A closed, pure-data enum the
/// seam + kernel branch on; only [`CmdVerdict::Accept`] un-blocks the M24 gate's
/// oracle input, and ONLY when every conjunctive check passes. Each REJECT names
/// the precise failure (the negative-control surface the Kani harnesses + the boot
/// self-test exercise).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmdVerdict {
    /// THE ACCEPT: the frame decodes, is an `ACTIVATE_CMD`, echoes the expected
    /// nonce (fresh), binds the live head (head-bound), is dual-authorized (two
    /// DISTINCT creds), AND the recomputed keyed MAC equals the frame's MAC. NECESSARY-
    /// NOT-SUFFICIENT: it un-blocks the M24 gate; the gate still enforces its bar.
    Accept,
    /// The frame did not decode (bad magic/ver/reserved/kind, truncation, missing MAC).
    Malformed,
    /// Decoded but the kind is not `ACTIVATE_CMD` (a CHALLENGE_REQ / NOP is never an
    /// activation).
    NotActivate,
    /// The echoed nonce != the expected challenge nonce (a stale replay from a prior
    /// challenge epoch -- the freshness check).
    RejectStale,
    /// The bound head != the live `op_head` (a command captured from a different boot
    /// / transcript position -- the Terrapin head-binding check).
    RejectWrongHead,
    /// `cred_a_id == cred_b_id` (a single-signer command -- the dual-custody / two-
    /// person rule negative control).
    RejectSingleCred,
    /// The recomputed keyed MAC != the frame's MAC (a tampered / forged command -- the
    /// keyed-MAC tamper check).
    RejectBadMac,
}

/// THE CONJUNCTIVE GATE over an already-decoded frame -- the pure, buffer-free,
/// hash-free core [`decode_and_verify`] delegates to VERBATIM (the wrapper only adds
/// the `decode` + MAC-recompute plumbing). Returns [`CmdVerdict::Accept`] IFF, in
/// conjunction: the kind is [`kind::ACTIVATE_CMD`], the echoed nonce equals
/// `expected_nonce` (FRESHNESS), the bound head equals `live_head` (HEAD-BINDING --
/// the Terrapin lesson), the two credential ids are DISTINCT (DUAL-CUSTODY -- the
/// two-person rule), AND `mac_ok` (the caller's recomputed-MAC comparison). Otherwise
/// the PRECISE reject, in this fixed precedence: `NotActivate` / `RejectStale` /
/// `RejectWrongHead` / `RejectSingleCred` / `RejectBadMac`. TOTAL, pure compares only
/// (no buffers, no FNV) -- which is exactly why the Kani gate harnesses
/// (`kani_cmd_stale_nonce`/`_head_binding`/`_dual_custody`) can drive THIS function
/// fully symbolically and prove every reject branch live + `Accept` unreachable with
/// any violated conjunct.
#[must_use]
pub fn verify_decoded(
    frame: &CmdFrame<'_>,
    expected_nonce: u64,
    live_head: &[u8; PROV_HASH_LEN],
    mac_ok: bool,
) -> CmdVerdict {
    if frame.kind != kind::ACTIVATE_CMD {
        return CmdVerdict::NotActivate;
    }
    // FRESHNESS: the echoed nonce must equal the current challenge nonce.
    if frame.nonce_echo != expected_nonce {
        return CmdVerdict::RejectStale;
    }
    // HEAD-BINDING: the bound head must equal the live M22 head (Terrapin lesson).
    if frame.op_head_bind != *live_head {
        return CmdVerdict::RejectWrongHead;
    }
    // DUAL-CUSTODY: the two enrolled credentials must be DISTINCT (two-person rule).
    if frame.cred_a_id == frame.cred_b_id {
        return CmdVerdict::RejectSingleCred;
    }
    // KEYED MAC: the caller recomputed the MAC over the frame's canonical bytes.
    if !mac_ok {
        return CmdVerdict::RejectBadMac;
    }
    CmdVerdict::Accept
}

/// Decode + VERIFY an inbound command (proposal §3) -- the RX dual of the M25 emit.
/// Decodes `buf` (fail-closed to `Malformed`), recomputes the keyed MAC over the
/// decoded frame's canonical (MAC'd) bytes with `key_a`/`key_b`, then delegates the
/// verdict to the pure conjunctive gate [`verify_decoded`] -- Accept IFF kind ==
/// [`kind::ACTIVATE_CMD`] AND fresh nonce AND head-bound AND dual-custody AND the
/// recomputed MAC equals the frame's MAC; otherwise the PRECISE reject. TOTAL -- no
/// panic, no alloc beyond the caller scratch (`scratch` must hold the frame's
/// [`canon_len`] MAC'd bytes; an undersized scratch yields `mac_ok == false`, so the
/// MAC conjunct fails closed, never a partial accept). FAIL-CLOSED: any single
/// failing conjunct REJECTS -- no field is ignored.
///
/// HONEST: the MAC is `mac=KEYED-NONCRYPTO` (a keyed FNV envelope, NOT forgery-
/// resistant) and an `Accept` is NECESSARY-NOT-SUFFICIENT (it does NOT flip
/// `KAN_ACTIVE`; the M24 gate still enforces its statistical bar). REPLAY SCOPE:
/// this verifier is PURE + STATELESS -- it rejects a nonce from a DIFFERENT
/// challenge epoch (`RejectStale`), but it does NOT consume the nonce on Accept, so
/// an identical valid wire re-verifies within the SAME epoch. The leaf claims
/// per-epoch staleness rejection, NOT one-shot/per-challenge consumption; nonce
/// consumption (rotate-on-accept / a used-nonce high-water mark in the stateful
/// seam) is the named successor, exactly as `mac=KEYED-CRYPTO` is for the MAC tier.
#[must_use]
pub fn decode_and_verify(
    buf: &[u8],
    expected_nonce: u64,
    live_head: [u8; PROV_HASH_LEN],
    key_a: &[u8; KEY_LEN],
    key_b: &[u8; KEY_LEN],
    scratch: &mut [u8],
) -> CmdVerdict {
    let frame = match decode(buf) {
        Some(f) => f,
        None => return CmdVerdict::Malformed,
    };
    // KEYED MAC: recompute over the canonical (MAC'd) bytes and compare. We re-canon
    // the decoded frame into the caller scratch (the MAC'd bytes are exactly canon),
    // so the MAC is verified over the PARSED fields -- no wire/parse desync.
    let n = canon(&frame, scratch);
    let mac_ok = n != 0 && compute_mac(key_a, key_b, &scratch[..n]) == frame.mac;
    verify_decoded(&frame, expected_nonce, &live_head, mac_ok)
}

/// Convenience for the seam/tests: ENCODE a full on-wire command frame (the MAC'd
/// bytes followed by the keyed MAC) for `frame`'s fields, computing the MAC over the
/// canonical bytes with `key_a`/`key_b`. Returns the number of bytes written, or `0`
/// if `out` is too small for [`wire_len`] OR the frame is not [`frame_is_encodable`]
/// (TOTAL + fail-closed). The written `frame.mac` is OVERWRITTEN by the freshly
/// computed MAC (so the caller need not pre-fill it). This is the exact bytes a
/// verifier would put on the RX wire; [`decode_and_verify`] is its inverse+check.
#[must_use]
pub fn seal(
    frame: &CmdFrame,
    key_a: &[u8; KEY_LEN],
    key_b: &[u8; KEY_LEN],
    out: &mut [u8],
) -> usize {
    let total = wire_len(frame);
    if out.len() < total {
        return 0; // too-small buffer (totality)
    }
    let n = canon(frame, out);
    if n == 0 {
        return 0; // not encodable -- fail closed, no partial frame
    }
    let mac = compute_mac(key_a, key_b, &out[..n]);
    let mut m = 0usize;
    while m < MAC_LEN {
        out[n + m] = mac[m];
        m += 1;
    }
    n + MAC_LEN
}

// --- fixed-width LE scalar helpers (pure, total, no panic on a sized buffer) -----
// The caller guarantees the offset window fits (canon/decode check the length FIRST),
// so these index a known-large-enough slice. Tiny + inlined so CBMC constant-folds
// them and the harnesses stay cheap (mirrors `opframe.rs`).

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

    fn key(seed: u8) -> [u8; KEY_LEN] {
        let mut k = [0u8; KEY_LEN];
        let mut i = 0usize;
        while i < KEY_LEN {
            k[i] = seed.wrapping_add(i as u8).wrapping_mul(37);
            i += 1;
        }
        k
    }

    fn head(seed: u8) -> [u8; PROV_HASH_LEN] {
        let mut h = [0u8; PROV_HASH_LEN];
        let mut i = 0usize;
        while i < PROV_HASH_LEN {
            h[i] = seed.wrapping_add(i as u8).wrapping_mul(31);
            i += 1;
        }
        h
    }

    fn sample<'a>(payload: &'a [u8], live: [u8; PROV_HASH_LEN]) -> CmdFrame<'a> {
        CmdFrame {
            kind: kind::ACTIVATE_CMD,
            nonce_echo: 0xC0FFEE,
            op_head_bind: live,
            seq: 7,
            cred_a_id: 11,
            cred_b_id: 22,
            payload,
            mac: [0u8; MAC_LEN],
        }
    }

    // ---- canon: layout, length, fail-closed totality ------------------------

    #[test]
    fn canon_len_matches_written() {
        let p = [1u8, 2, 3, 4];
        let f = sample(&p, head(1));
        assert_eq!(canon_len(&f), CMD_HEADER_LEN + 4);
        assert_eq!(wire_len(&f), CMD_HEADER_LEN + 4 + MAC_LEN);
        let mut buf = [0u8; 128];
        let n = canon(&f, &mut buf);
        assert_eq!(n, canon_len(&f));
        assert_eq!(read_u16(&buf, OFF_MAGIC), CMD_MAGIC);
        assert_eq!(buf[OFF_VER], CMD_VER);
        assert_eq!(buf[OFF_KIND], kind::ACTIVATE_CMD);
        assert_eq!(buf[OFF_RESERVED], 0);
        assert_eq!(read_u64(&buf, OFF_NONCE), 0xC0FFEE);
        assert_eq!(read_u64(&buf, OFF_SEQ), 7);
        assert_eq!(read_u16(&buf, OFF_CRED_A), 11);
        assert_eq!(read_u16(&buf, OFF_CRED_B), 22);
        assert_eq!(read_u32(&buf, OFF_PAYLOAD_LEN), 4);
    }

    #[test]
    fn canon_fail_closed_on_small_buffer() {
        let p = [9u8; 8];
        let f = sample(&p, head(2));
        let need = canon_len(&f);
        let mut small = vec![0u8; need - 1];
        assert_eq!(canon(&f, &mut small), 0);
        assert!(small.iter().all(|&b| b == 0)); // no partial write
        let mut exact = vec![0u8; need];
        assert_eq!(canon(&f, &mut exact), need);
    }

    #[test]
    fn canon_rejects_unknown_kind() {
        let p = [1u8];
        let mut f = sample(&p, head(3));
        f.kind = 0;
        let mut buf = [0u8; 128];
        assert_eq!(canon(&f, &mut buf), 0);
        f.kind = 99;
        assert_eq!(canon(&f, &mut buf), 0);
    }

    // ---- canon round-trip (MAC'd bytes + trailing MAC) ----------------------

    #[test]
    fn seal_decode_roundtrip() {
        let p = [0xAAu8, 0xBB, 0xCC];
        let live = head(4);
        let (ka, kb) = (key(1), key(2));
        let f = sample(&p, live);
        let mut wire = [0u8; 128];
        let n = seal(&f, &ka, &kb, &mut wire);
        assert_eq!(n, wire_len(&f));
        let d = decode(&wire[..n]).unwrap();
        // Every field round-trips, INCLUDING the freshly computed MAC.
        assert_eq!(d.kind, f.kind);
        assert_eq!(d.nonce_echo, f.nonce_echo);
        assert_eq!(d.op_head_bind, f.op_head_bind);
        assert_eq!(d.seq, f.seq);
        assert_eq!(d.cred_a_id, f.cred_a_id);
        assert_eq!(d.cred_b_id, f.cred_b_id);
        assert_eq!(d.payload, &p[..]);
        // The MAC'd bytes re-canon to identical bytes.
        let mut buf2 = [0u8; 128];
        let n2 = canon(&d, &mut buf2);
        assert_eq!(&wire[..n2], &buf2[..n2]);
    }

    #[test]
    fn decode_fail_closed() {
        let p = [1u8, 2];
        let live = head(5);
        let (ka, kb) = (key(3), key(4));
        let f = sample(&p, live);
        let mut wire = [0u8; 128];
        let n = seal(&f, &ka, &kb, &mut wire);
        // too short (header+mac boundary)
        assert!(decode(&wire[..CMD_HEADER_LEN + MAC_LEN - 1]).is_none());
        // bad magic
        let mut bad = wire;
        bad[OFF_MAGIC] ^= 0xFF;
        assert!(decode(&bad[..n]).is_none());
        // bad version
        let mut bv = wire;
        bv[OFF_VER] = 2;
        assert!(decode(&bv[..n]).is_none());
        // set reserved bit
        let mut br = wire;
        br[OFF_RESERVED] = 1;
        assert!(decode(&br[..n]).is_none());
        // unknown kind
        let mut bk = wire;
        bk[OFF_KIND] = 0x55;
        assert!(decode(&bk[..n]).is_none());
        // truncated: declares plen=2 but only the header+1 byte present
        assert!(decode(&wire[..CMD_HEADER_LEN + 1]).is_none());
    }

    // ---- key evolution: deterministic + tamper-sensitive --------------------

    #[test]
    fn key_evolve_deterministic_and_sensitive() {
        let k = key(7);
        assert_eq!(key_evolve(&k), key_evolve(&k)); // deterministic
        // A single-byte change to the key changes every evolution.
        let mut k2 = k;
        k2[5] ^= 0x01;
        assert_ne!(key_evolve(&k2), key_evolve(&k));
        // Forward chain advances (not a fixed point).
        let k1 = key_evolve(&k);
        assert_ne!(k1, k);
        let k2n = key_evolve(&k1);
        assert_ne!(k2n, k1);
    }

    // ---- compute_mac: tamper-sensitive in canon AND keys --------------------

    #[test]
    fn mac_tamper_sensitive() {
        let (ka, kb) = (key(8), key(9));
        let canon_bytes = b"the-canonical-maced-bytes-of-a-command-frame";
        let base = compute_mac(&ka, &kb, canon_bytes);
        // Flip one canon byte -> different MAC.
        let mut tampered = canon_bytes.to_vec();
        tampered[3] ^= 0x01;
        assert_ne!(compute_mac(&ka, &kb, &tampered), base);
        // Flip key_a -> different MAC.
        let mut ka2 = ka;
        ka2[0] ^= 0x01;
        assert_ne!(compute_mac(&ka2, &kb, canon_bytes), base);
        // Flip key_b -> different MAC.
        let mut kb2 = kb;
        kb2[31] ^= 0x80;
        assert_ne!(compute_mac(&ka, &kb2, canon_bytes), base);
        // Swapping the two keys changes the MAC (order-sensitive dual custody).
        assert_ne!(compute_mac(&kb, &ka, canon_bytes), base);
    }

    // ---- decode_and_verify: ACCEPT the valid command, REJECT each leg -------

    #[test]
    fn verify_accepts_valid_and_rejects_each_leg() {
        let p = [0x10u8, 0x20, 0x30];
        let live = head(6);
        let nonce = 0xABCDEF;
        let (ka, kb) = (key(10), key(20));
        let f = CmdFrame {
            kind: kind::ACTIVATE_CMD,
            nonce_echo: nonce,
            op_head_bind: live,
            seq: 3,
            cred_a_id: 100,
            cred_b_id: 200,
            payload: &p,
            mac: [0u8; MAC_LEN],
        };
        let mut wire = [0u8; 160];
        let n = seal(&f, &ka, &kb, &mut wire);
        let mut scratch = [0u8; 160];

        // ACCEPT the well-formed fresh head-bound dual-authorized command.
        assert_eq!(
            decode_and_verify(&wire[..n], nonce, live, &ka, &kb, &mut scratch),
            CmdVerdict::Accept
        );

        // (a) STALE nonce: the verifier expects a DIFFERENT (newer) nonce.
        assert_eq!(
            decode_and_verify(&wire[..n], nonce ^ 1, live, &ka, &kb, &mut scratch),
            CmdVerdict::RejectStale
        );

        // (b) WRONG head: the live head moved (a cross-boot command).
        let mut wrong = live;
        wrong[0] ^= 0x01;
        assert_eq!(
            decode_and_verify(&wire[..n], nonce, wrong, &ka, &kb, &mut scratch),
            CmdVerdict::RejectWrongHead
        );

        // (d) FLIPPED MAC: a single tampered MAC byte is caught.
        let mut tampered = wire;
        let mac_off = n - MAC_LEN;
        tampered[mac_off] ^= 0x01;
        assert_eq!(
            decode_and_verify(&tampered[..n], nonce, live, &ka, &kb, &mut scratch),
            CmdVerdict::RejectBadMac
        );

        // A tampered CANON byte (e.g. the seq) is also a bad MAC (the MAC covers it).
        let mut tcanon = wire;
        tcanon[OFF_SEQ] ^= 0x01;
        assert_eq!(
            decode_and_verify(&tcanon[..n], nonce, live, &ka, &kb, &mut scratch),
            CmdVerdict::RejectBadMac
        );
    }

    // (c) SINGLE credential: cred_a_id == cred_b_id is rejected (dual custody).
    #[test]
    fn verify_rejects_single_cred() {
        let p = [1u8];
        let live = head(7);
        let nonce = 42;
        let (ka, kb) = (key(11), key(21));
        let single = CmdFrame {
            kind: kind::ACTIVATE_CMD,
            nonce_echo: nonce,
            op_head_bind: live,
            seq: 1,
            cred_a_id: 5,
            cred_b_id: 5, // SAME credential -- a single signer
            payload: &p,
            mac: [0u8; MAC_LEN],
        };
        let mut wire = [0u8; 128];
        let n = seal(&single, &ka, &kb, &mut wire);
        let mut scratch = [0u8; 128];
        assert_eq!(
            decode_and_verify(&wire[..n], nonce, live, &ka, &kb, &mut scratch),
            CmdVerdict::RejectSingleCred
        );
    }

    // A NOP / CHALLENGE_REQ is never an activation.
    #[test]
    fn verify_rejects_non_activate() {
        let p: [u8; 0] = [];
        let live = head(8);
        let nonce = 1;
        let (ka, kb) = (key(12), key(22));
        let nop = CmdFrame {
            kind: kind::NOP,
            nonce_echo: nonce,
            op_head_bind: live,
            seq: 0,
            cred_a_id: 1,
            cred_b_id: 2,
            payload: &p,
            mac: [0u8; MAC_LEN],
        };
        let mut wire = [0u8; 128];
        let n = seal(&nop, &ka, &kb, &mut wire);
        let mut scratch = [0u8; 128];
        assert_eq!(
            decode_and_verify(&wire[..n], nonce, live, &ka, &kb, &mut scratch),
            CmdVerdict::NotActivate
        );
    }

    // A foreign byte stream is Malformed.
    #[test]
    fn verify_malformed_on_garbage() {
        let live = head(9);
        let (ka, kb) = (key(13), key(23));
        let mut scratch = [0u8; 128];
        let garbage = [0u8; CMD_HEADER_LEN + MAC_LEN];
        assert_eq!(
            decode_and_verify(&garbage, 0, live, &ka, &kb, &mut scratch),
            CmdVerdict::Malformed
        );
    }
}
