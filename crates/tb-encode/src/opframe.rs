//! The M25 verified OPERATOR-TRANSCRIPT codec math -- the pure, verified value-
//! computation leaf behind the OUTBOUND operator channel: a typed, fixed-header,
//! length-prefixed, INJECTIVE, tamper-evident frame the OS emits over the serial
//! console to SURFACE what it recorded (M23) and decided (M24) to a human, lifted
//! into `tb-encode` exactly as the M22 provenance ledger ([`crate::prov`]) and the
//! M23 experience codec ([`crate::exp`]) were. Each frame folds into a running
//! per-instance `op_head` via the M22 [`crate::prov`] fold (REUSED verbatim -- M25
//! writes NO new fold math), with a STRICTLY-MONOTONE `seq` folded INTO the
//! canonical bytes so a reader detects any mutation / reorder / drop / truncation.
//!
//! ## What this is FOR (proposal §1 -- the exogenous-oracle channel)
//!
//! M24's honest gate REFUSES to activate the learned cell because a self-graded
//! loop has no EXOGENOUS oracle. M25 is the channel that surfaces the decisions to
//! a human (the only valid exogenous oracle -- Christiano RLHF arXiv:1706.03741;
//! Thomas Seldonian Science 2019), realizing the COMMUNICATION pillar. This
//! milestone is TX-ONLY: the inbound RX + an enrolled credential by which a human
//! could COMMAND the M24 gate is M26 (it fails the no-human CI gate today).
//!
//! ## Honest scope (proposal §5 -- the marker claims ONLY what is proved)
//!
//! * **CLAIMS structural tamper-EVIDENCE** under NON-ADVERSARIAL corruption (line
//!   drops, serial glitches, accidental reorder, benign byte flips): any single-byte
//!   mutation of a committed frame changes the recomputed `op_head` AND its inclusion
//!   proof -- the M22 fold reused verbatim. The strictly-monotone `seq` (folded INTO
//!   `canon`) + the closing `GATE_VERDICT` (committing the final seq) catch reorder,
//!   gap, duplication, and TAIL-TRUNCATION (the Schneier-Kelsey / Ma-Tsudik FssAgg
//!   construction). The honesty token `keyed=0` is machine-emitted.
//! * **CLAIMS instance binding.** The `INTRO` frame's `prev_head` binds the
//!   transcript genesis to the LIVE M22 provenance head ("which instance am I" --
//!   RATS RFC 9334 layered attestation; a structural UEID per EAT RFC 9711). The
//!   token `intro_bound=1` is machine-emitted.
//! * **Does NOT claim cryptographic authenticity / non-repudiation / forgery-
//!   resistance.** The fold is the same KEYLESS structural FNV as M22 -- publicly
//!   recomputable, so a stream-rewriting adversary can forge a self-consistent
//!   transcript. A secret-keyed forward-secure aggregate MAC + a signed history-tree
//!   (RFC 6962/9162) is a tracked successor (M26+, it needs the inbound credential).
//! * **Does NOT claim a human read or believed the transcript.** The boot self-test
//!   plays a SIMULATED operator-verifier that grades the OS's own plumbing -- it
//!   proves the CHANNEL, not the ORACLE. The token `oracle=HUMAN-DEFERRED-M26` is
//!   machine-emitted so the marker mechanically cannot overclaim.
//!
//! ## The held-out leakage guard (proposal §2.4 -- a canon-time fail-closed invariant)
//!
//! Every frame carries a `partition_id`; [`canon`] FAIL-CLOSES (returns 0, no bytes
//! written) on a frame tagged [`partition::SAFETY_HELD_OUT`]. The transcript can
//! therefore NEVER surface a record/label/statistic from the sealed M24 safety
//! partition (the Seldonian no-snoop requirement -- Thomas Science 2019 + Dwork
//! reusable holdout Science 2015 -- encoded as a Kani-proven encoder invariant, not
//! operational discipline). A human's eventual labels stay a one-shot pre-registered
//! gate input that adaptive resurfacing cannot overfit.
//!
//! ## Numeric format (no float, ever -- mirrors `exp`/`prov`/`blkfmt`)
//!
//! Pure integer/byte arithmetic, zero alloc, zero deps. [`canon`] is a FIXED-HEADER,
//! fixed-field-order, LENGTH-PREFIXED-payload LE byte layout into a caller buffer
//! (total + fail-closed: returns `0` if the buffer is too small OR the frame fails
//! validation OR carries the held-out partition, never panics -- mirroring
//! [`crate::prov::canon`]). [`decode`] is the inverse over a large-enough buffer
//! (fail-closed to `None`). The fold over the canonical bytes REUSES the proven
//! [`crate::prov`] leaf ([`op_append`] / [`op_chain_mix`] / [`op_verify_inclusion`] /
//! [`op_head_witness`]) -- NO new fold math is written here.

// The fold is the M22 provenance leaf, REUSED verbatim (proposal §2.1: "fold into a
// running `op_head` via the M22 `chain_mix`"). We import the proven digest / fold /
// verify / witness functions; M25 writes NONE of its own fold math, exactly as M23.
pub use crate::prov::{
    append as op_append, chain_mix as op_chain_mix, head_witness as op_head_witness,
    prov_hash as op_hash, recompute as op_recompute, verify_inclusion as op_verify_inclusion,
    PROV_HASH_LEN,
};

/// The transcript-frame format version (proposal §2.1). [`canon`] rejects any other
/// value (fail-closed -- an unknown version is a forward/backward-incompatible frame).
pub const OPFRAME_VER: u8 = 1;

/// The fixed frame magic (`"TB"` little-endian: `0x42, 0x54`). [`canon`] rejects any
/// other value so a foreign byte stream is not mistaken for a transcript frame.
pub const OPFRAME_MAGIC: u16 = 0x5442;

/// The fixed frame KIND tags (proposal §2.1 -- the typed transcript vocabulary,
/// mirroring an OpenTelemetry LogRecord EventName). A closed set the seam emits; the
/// kind is folded into the digest, so an INTRO can never masquerade as a GATE_VERDICT
/// (the byte differs -> the head differs). [`canon`] rejects any other value.
pub mod kind {
    /// The genesis frame (`seq == 0`): binds the transcript to the live M22
    /// provenance head ("which instance am I" -- the RATS/DICE identity anchor).
    pub const INTRO: u8 = 1;
    /// A milestone/phase marker (a human-readable checkpoint in the transcript).
    pub const MARKER: u8 = 2;
    /// A surfaced BORDERLINE decision digest (active-learning query -- the payload
    /// carries the M23 record the human is asked to adjudicate).
    pub const EXPERIENCE_DIGEST: u8 = 3;
    /// The closing frame: carries the FINAL `seq` in its payload, committing the
    /// transcript length so a reader detects TAIL-truncation (the FssAgg fix).
    pub const GATE_VERDICT: u8 = 4;
}

/// The partition tags for the held-out leakage guard (proposal §2.4). EVERY frame
/// carries one; [`canon`] FAIL-CLOSES on [`SAFETY_HELD_OUT`](partition::SAFETY_HELD_OUT)
/// and on any unknown value -- only [`CANDIDATE`](partition::CANDIDATE) is emittable.
pub mod partition {
    /// The candidate-SELECTION partition: records eligible to be surfaced (the only
    /// partition [`super::canon`] accepts).
    pub const CANDIDATE: u8 = 0;
    /// The SEALED M24 safety held-out partition: NEVER emittable. [`super::canon`]
    /// returns 0 (fail-closed) on a frame tagged this -- the Seldonian no-snoop
    /// invariant encoded in the encoder (the `kani_opframe_partition_leak` negative
    /// control fires if this guard is removed).
    pub const SAFETY_HELD_OUT: u8 = 1;
}

/// The minimum / maximum OpenTelemetry integer SeverityNumber (proposal §2.1): the
/// closed `1..=24` band (1=TRACE .. 9=INFO .. 13=WARN .. 17=ERROR .. 21=FATAL).
/// [`canon`] rejects `sev == 0` or `sev > 24` (fail-closed -- no float, a recognized
/// standard vocabulary rather than an ad-hoc one).
pub const SEV_MIN: u8 = 1;
/// See [`SEV_MIN`].
pub const SEV_MAX: u8 = 24;

/// A fixed, canonical transcript frame (proposal §2.1). The FIXED header occupies a
/// fixed prefix; the variable `payload` is LENGTH-PREFIXED (the `payload_len` u32 at
/// [`OFF_PAYLOAD_LEN`]) so [`canon`] is injective: distinct frames always encode to
/// distinct bytes. Borrowed `payload` so the leaf stays zero-alloc; the seam owns the
/// (heap or stack) payload slice (e.g. an [`crate::exp::canon`]-encoded record).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpFrame<'a> {
    /// The frame kind (see [`kind`]): intro | marker | experience-digest | gate-verdict.
    pub kind: u8,
    /// The OTel integer SeverityNumber (`1..=24`; see [`SEV_MIN`]/[`SEV_MAX`]).
    pub sev: u8,
    /// The held-out leakage-guard partition (see [`partition`]). [`canon`] rejects
    /// [`partition::SAFETY_HELD_OUT`].
    pub partition_id: u8,
    /// The STRICTLY-MONOTONE sequence number (`0` for the genesis INTRO, `+1` per
    /// frame). Folded INTO the canonical bytes (NOT a side label) so renumbering a
    /// frame perturbs the head (the Terrapin lesson, arXiv:2312.12422).
    pub seq: u64,
    /// The logical (boot-relative) clock at emission -- an epoch-id SELF-assertion
    /// (no trusted wall clock / no verifier nonce -> no freshness claim, proposal §5).
    pub t_logical: u64,
    /// The prior running head this frame extends. For the genesis `INTRO` this is the
    /// LIVE M22 provenance head (the instance-binding anchor); for later frames it is
    /// informational (the AUTHORITATIVE chain is the fold, not this field).
    pub prev_head: [u8; PROV_HASH_LEN],
    /// The opaque payload bytes (length-prefixed in [`canon`]). The leaf treats these
    /// as opaque; the seam's meaning (an `exp` record for a DIGEST, the final-seq LE
    /// for a `GATE_VERDICT`) is layered ON TOP, keeping the codec decidable.
    pub payload: &'a [u8],
}

/// The fixed canonical-frame HEADER length (everything before the variable payload):
/// `magic(2) | ver(1) | kind(1) | sev(1) | partition(1) | reserved(1) | seq(8) |
/// t_logical(8) | prev_head(32) | payload_len(4)` = 59 bytes. The trailing
/// `payload_len` u32 is the LENGTH-PREFIX (the disambiguator that makes the variable
/// payload self-delimiting -> [`canon`] injective, exactly like the prov parent count).
pub const OPFRAME_HEADER_LEN: usize = 2 + 1 + 1 + 1 + 1 + 1 + 8 + 8 + PROV_HASH_LEN + 4;

// Fixed field offsets (the header layout above). Named consts so the round-trip + the
// Kani harnesses read the SAME literals the encoder writes.
const OFF_MAGIC: usize = 0;
const OFF_VER: usize = 2;
const OFF_KIND: usize = 3;
const OFF_SEV: usize = 4;
const OFF_PARTITION: usize = 5;
const OFF_RESERVED: usize = 6;
const OFF_SEQ: usize = 7;
const OFF_TLOGICAL: usize = 15;
const OFF_PREV_HEAD: usize = 23;
/// The offset of the `payload_len` u32 LE length-prefix (the injectivity disambiguator).
pub const OFF_PAYLOAD_LEN: usize = 55;
/// The offset at which the variable payload begins (== [`OPFRAME_HEADER_LEN`]).
pub const OFF_PAYLOAD: usize = 59;

/// The exact canonical byte length of `frame`: [`OPFRAME_HEADER_LEN`] + the payload
/// length, computed with SATURATING arithmetic so a pathological payload length can
/// never overflow `usize` (total -- it never panics). Mirrors [`crate::prov::canon_len`].
#[inline]
#[must_use]
pub fn canon_len(frame: &OpFrame) -> usize {
    OPFRAME_HEADER_LEN.saturating_add(frame.payload.len())
}

/// Whether `frame`'s VALIDATED header fields are well-formed AND emittable: the magic
/// is [`OPFRAME_MAGIC`], the version is [`OPFRAME_VER`], the `kind` is a known tag,
/// the `sev` is in `1..=24`, and the `partition_id` is [`partition::CANDIDATE`] (NOT
/// the held-out partition, NOT unknown). [`canon`] fail-closes (returns 0) when this
/// is false. Total -- no panic. (`reserved` is forced to 0 by `canon` itself.)
#[inline]
#[must_use]
pub fn frame_is_emittable(frame: &OpFrame) -> bool {
    let kind_ok = matches!(
        frame.kind,
        kind::INTRO | kind::MARKER | kind::EXPERIENCE_DIGEST | kind::GATE_VERDICT
    );
    let sev_ok = frame.sev >= SEV_MIN && frame.sev <= SEV_MAX;
    // THE LEAKAGE GUARD: only the candidate-selection partition is emittable. The
    // held-out partition (and any unknown value) is fail-closed REJECTED here.
    let partition_ok = frame.partition_id == partition::CANDIDATE;
    kind_ok && sev_ok && partition_ok
}

/// Canonical, UNAMBIGUOUS, total, length-delimited LE encoding of `frame` into `out`.
/// Returns the number of bytes written, or `0` if `out` is too small OR `frame` is
/// not [`frame_is_emittable`] -- INCLUDING the held-out-partition leakage guard
/// (TOTAL + fail-closed: never panics, never partial-writes, mirroring
/// [`crate::prov::canon`]). Layout (fixed header, the payload LENGTH-PREFIXED):
///
/// ```text
///   [0..2]   magic        u16 LE   (== OPFRAME_MAGIC)
///   [2]      ver          u8       (== OPFRAME_VER)
///   [3]      kind         u8       (a known `kind` tag)
///   [4]      sev          u8       (1..=24)
///   [5]      partition_id u8       (== partition::CANDIDATE; held-out REJECTED)
///   [6]      reserved     u8       (forced 0 -- a set reserved bit cannot ride out)
///   [7..15]  seq          u64 LE   (strictly-monotone, FOLDED into the digest)
///   [15..23] t_logical    u64 LE
///   [23..55] prev_head    [u8;32]  (INTRO: the live M22 head; the instance anchor)
///   [55..59] payload_len  u32 LE   <-- the length-prefix (disambiguator)
///   [59..]   payload[i]   u8       verbatim, i in 0..payload_len
/// ```
///
/// INJECTIVITY: two emittable frames that differ in ANY field encode to different
/// bytes -- the fixed-width header occupies fixed offsets and the explicit
/// `payload_len` prefix makes the variable tail self-delimiting, so no field-boundary
/// ambiguity can let two distinct frames collide (the `kani_opframe_canon_injective`
/// harness discharges this; the held-out guard is the `kani_opframe_partition_leak`
/// negative control).
#[must_use]
pub fn canon(frame: &OpFrame, out: &mut [u8]) -> usize {
    // Fail-closed VALIDATION + the held-out leakage guard FIRST (before any write).
    if !frame_is_emittable(frame) {
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
    write_u16(out, OFF_MAGIC, OPFRAME_MAGIC);
    out[OFF_VER] = OPFRAME_VER;
    out[OFF_KIND] = frame.kind;
    out[OFF_SEV] = frame.sev;
    out[OFF_PARTITION] = frame.partition_id;
    out[OFF_RESERVED] = 0; // forced 0 -- a set reserved bit can never ride out
    write_u64(out, OFF_SEQ, frame.seq);
    write_u64(out, OFF_TLOGICAL, frame.t_logical);
    let mut b = 0usize;
    while b < PROV_HASH_LEN {
        out[OFF_PREV_HEAD + b] = frame.prev_head[b];
        b += 1;
    }
    write_u32(out, OFF_PAYLOAD_LEN, plen as u32);
    let mut p = 0usize;
    while p < plen {
        out[OFF_PAYLOAD + p] = frame.payload[p];
        p += 1;
    }
    total
}

/// The exact inverse of [`canon`] over `buf`: decode the header + borrow the payload
/// slice back into an [`OpFrame`], or `None` if `buf` is too small for the header,
/// carries a bad magic / version / reserved bit, is not [`frame_is_emittable`], or is
/// too small for the declared `payload_len` (TOTAL + fail-closed: never panics --
/// mirrors the `blkfmt` fail-closed decoders). A successful decode round-trips back to
/// identical canonical bytes (the `kani_opframe_canon_roundtrip` harness). The
/// returned frame borrows `buf` for its payload (zero-copy).
#[must_use]
pub fn decode(buf: &[u8]) -> Option<OpFrame<'_>> {
    if buf.len() < OPFRAME_HEADER_LEN {
        return None;
    }
    if read_u16(buf, OFF_MAGIC) != OPFRAME_MAGIC {
        return None; // foreign byte stream
    }
    if buf[OFF_VER] != OPFRAME_VER {
        return None; // incompatible version
    }
    if buf[OFF_RESERVED] != 0 {
        return None; // a set reserved bit is a malformed frame
    }
    let kind = buf[OFF_KIND];
    let sev = buf[OFF_SEV];
    let partition_id = buf[OFF_PARTITION];
    let seq = read_u64(buf, OFF_SEQ);
    let t_logical = read_u64(buf, OFF_TLOGICAL);
    let mut prev_head = [0u8; PROV_HASH_LEN];
    let mut b = 0usize;
    while b < PROV_HASH_LEN {
        prev_head[b] = buf[OFF_PREV_HEAD + b];
        b += 1;
    }
    let plen = read_u32(buf, OFF_PAYLOAD_LEN) as usize;
    let end = OFF_PAYLOAD.checked_add(plen)?; // fail-closed on overflow
    if buf.len() < end {
        return None; // truncated payload
    }
    let frame = OpFrame {
        kind,
        sev,
        partition_id,
        seq,
        t_logical,
        prev_head,
        payload: &buf[OFF_PAYLOAD..end],
    };
    // Reject a decoded frame that would not be emittable (bad kind/sev/partition) --
    // so decode and canon agree on the emittable set (the held-out guard holds on the
    // read side too: a held-out frame can never have been emitted, so it never decodes).
    if !frame_is_emittable(&frame) {
        return None;
    }
    Some(frame)
}

/// Fold `frame` into the running transcript head in one step (the exact step the seam
/// runs per emitted frame): [`canon`]-encode into a caller scratch buffer,
/// [`op_hash`] the canonical bytes, and [`op_chain_mix`] the resulting frame id into
/// `head`. Returns `(new_head, frame_id)`, or `None` if `scratch` is too small OR the
/// frame is not emittable (fail-closed -- NO head advance on a rejected frame, so a
/// held-out frame can never perturb the transcript). REUSES [`crate::prov::append`]'s
/// shape over the opframe bytes -- no new fold math.
#[must_use]
pub fn fold_frame(
    head: [u8; PROV_HASH_LEN],
    frame: &OpFrame,
    scratch: &mut [u8],
) -> Option<([u8; PROV_HASH_LEN], [u8; PROV_HASH_LEN])> {
    let n = canon(frame, scratch);
    if n == 0 {
        return None; // too-small scratch OR not emittable -- fail closed, no advance
    }
    let frame_id = op_hash(&scratch[..n]);
    let new_head = op_chain_mix(head, frame_id);
    Some((new_head, frame_id))
}

/// Whether `seqs` is the well-formed transcript sequence: `seqs[i] == i` for every
/// `i` (the genesis INTRO at 0, strictly `+1` per frame, NO gap / dup / reorder /
/// middle-truncation). This is the strict-monotone reader check (proposal §2.3); the
/// `seq` is folded INTO `canon`, so this check + the fold together catch every
/// reorder/renumber. Total -- no panic, no alloc. (TAIL-truncation is caught by
/// [`gate_commits_final_seq`] on the closing frame.)
#[inline]
#[must_use]
pub fn seq_index_exact(seqs: &[u64]) -> bool {
    let mut i = 0usize;
    while i < seqs.len() {
        if seqs[i] != i as u64 {
            return false;
        }
        i += 1;
    }
    true
}

/// Whether `frame` is a genesis INTRO that BINDS the transcript to `m22_head` (the
/// live M22 provenance head): `kind == INTRO`, `seq == 0`, and `prev_head ==
/// m22_head` (the "which instance am I" attestation -- RATS RFC 9334 §3.2). A replayed
/// transcript from a DIFFERENT boot carries a different `m22_head` and fails this.
/// Total -- no panic. (The `kani_opframe_intro_binding` harness proves a forged anchor
/// fails.)
#[inline]
#[must_use]
pub fn intro_binds(frame: &OpFrame, m22_head: [u8; PROV_HASH_LEN]) -> bool {
    frame.kind == kind::INTRO && frame.seq == 0 && frame.prev_head == m22_head
}

/// Read the committed FINAL seq from a closing `GATE_VERDICT` frame's payload: the
/// payload's leading 8 bytes are the final seq LE (the transcript-length commit).
/// Returns `None` if `frame` is not a `GATE_VERDICT` or its payload is shorter than 8
/// bytes (fail-closed). The reader uses this for TAIL-truncation detection (the
/// FssAgg / Ma-Tsudik fix): a valid transcript MUST end with a `GATE_VERDICT` whose
/// committed final seq equals its own `seq` (see [`gate_commits_final_seq`]). Total.
#[inline]
#[must_use]
pub fn gate_final_seq(frame: &OpFrame) -> Option<u64> {
    if frame.kind != kind::GATE_VERDICT || frame.payload.len() < 8 {
        return None;
    }
    Some(u64::from_le_bytes([
        frame.payload[0],
        frame.payload[1],
        frame.payload[2],
        frame.payload[3],
        frame.payload[4],
        frame.payload[5],
        frame.payload[6],
        frame.payload[7],
    ]))
}

/// Whether `frame` is a closing `GATE_VERDICT` that SELF-CONSISTENTLY commits the
/// transcript length: it is a `GATE_VERDICT`, its payload-encoded final seq equals
/// `expected_final_seq`, AND that equals the frame's own `seq` (so the closing frame
/// names its own position). A reader rejects a transcript whose last frame fails this
/// (TAIL-truncation: lopping frames off the end removes the closing commit, so the
/// reader sees no valid terminator). Total -- no panic. (`kani_opframe_truncation`.)
#[inline]
#[must_use]
pub fn gate_commits_final_seq(frame: &OpFrame, expected_final_seq: u64) -> bool {
    match gate_final_seq(frame) {
        Some(committed) => committed == expected_final_seq && frame.seq == expected_final_seq,
        None => false,
    }
}

/// The active-learning BORDERLINE score (proposal §2.4 -- Settles margin sampling): a
/// decision is more worth surfacing to the scarce human the SMALLER the absolute gap
/// between the dormant cell's shadow score and the heuristic demote threshold. Returns
/// the absolute distance `|kan_score_shadow - threshold|` SATURATING (total, no panic,
/// no float) -- the seam ranks ascending and surfaces the smallest gaps first. A
/// purely structural ranking helper; it folds no new policy.
#[inline]
#[must_use]
pub fn borderline_gap(kan_score_shadow: i64, threshold: i64) -> u64 {
    let d = kan_score_shadow.saturating_sub(threshold);
    // |d| without overflow at i64::MIN (its abs is not representable).
    d.unsigned_abs()
}

// --- fixed-width LE scalar helpers (pure, total, no panic on a sized buffer) -----
// The caller guarantees the offset window fits (canon/decode check the length FIRST),
// so these index a known-large-enough slice. Tiny + inlined so CBMC constant-folds
// them and the harnesses stay cheap (mirrors `exp.rs`).

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

    fn sample_payload() -> [u8; 8] {
        [1, 2, 3, 4, 5, 6, 7, 8]
    }

    fn sample<'a>(payload: &'a [u8]) -> OpFrame<'a> {
        OpFrame {
            kind: kind::EXPERIENCE_DIGEST,
            sev: 9, // INFO
            partition_id: partition::CANDIDATE,
            seq: 3,
            t_logical: 0xCAFE,
            prev_head: [0x5a; PROV_HASH_LEN],
            payload,
        }
    }

    // ---- canon: layout, length, fail-closed totality ------------------------

    #[test]
    fn canon_len_matches_written() {
        let p = sample_payload();
        let f = sample(&p);
        assert_eq!(canon_len(&f), OPFRAME_HEADER_LEN + 8);
        let mut buf = [0u8; 128];
        let n = canon(&f, &mut buf);
        assert_eq!(n, canon_len(&f));
        // Header fields land at their fixed offsets.
        assert_eq!(read_u16(&buf, OFF_MAGIC), OPFRAME_MAGIC);
        assert_eq!(buf[OFF_VER], OPFRAME_VER);
        assert_eq!(buf[OFF_KIND], kind::EXPERIENCE_DIGEST);
        assert_eq!(buf[OFF_SEV], 9);
        assert_eq!(buf[OFF_PARTITION], partition::CANDIDATE);
        assert_eq!(buf[OFF_RESERVED], 0);
        assert_eq!(read_u64(&buf, OFF_SEQ), 3);
        assert_eq!(read_u32(&buf, OFF_PAYLOAD_LEN), 8);
    }

    #[test]
    fn canon_fail_closed_on_small_buffer() {
        let p = sample_payload();
        let f = sample(&p);
        let need = canon_len(&f);
        let mut small = vec![0u8; need - 1];
        assert_eq!(canon(&f, &mut small), 0);
        assert!(small.iter().all(|&b| b == 0)); // no partial write
        let mut exact = vec![0u8; need];
        assert_eq!(canon(&f, &mut exact), need);
    }

    #[test]
    fn canon_rejects_bad_header() {
        let p = sample_payload();
        let mut buf = [0u8; 128];
        // bad kind
        let mut k = sample(&p);
        k.kind = 0;
        assert_eq!(canon(&k, &mut buf), 0);
        k.kind = 99;
        assert_eq!(canon(&k, &mut buf), 0);
        // sev out of band
        let mut s = sample(&p);
        s.sev = 0;
        assert_eq!(canon(&s, &mut buf), 0);
        s.sev = 25;
        assert_eq!(canon(&s, &mut buf), 0);
    }

    // ---- THE LEAKAGE GUARD: held-out partition is never emittable -----------

    #[test]
    fn canon_fail_closed_on_held_out_partition() {
        let p = sample_payload();
        let mut f = sample(&p);
        f.partition_id = partition::SAFETY_HELD_OUT;
        let mut buf = [0u8; 128];
        assert_eq!(canon(&f, &mut buf), 0, "held-out partition must NOT encode");
        assert!(buf.iter().all(|&b| b == 0)); // no partial write
        assert!(fold_frame([0u8; PROV_HASH_LEN], &f, &mut buf).is_none());
        // An unknown partition is also rejected (fail-closed).
        f.partition_id = 200;
        assert_eq!(canon(&f, &mut buf), 0);
    }

    // ---- canon round-trip + injectivity ------------------------------------

    #[test]
    fn canon_decode_roundtrip() {
        let p = sample_payload();
        let f = sample(&p);
        let mut buf = [0u8; 128];
        let n = canon(&f, &mut buf);
        let d = decode(&buf[..n]).unwrap();
        assert_eq!(d, f);
        // re-encoding the decoded frame reproduces identical bytes.
        let mut buf2 = [0u8; 128];
        let n2 = canon(&d, &mut buf2);
        assert_eq!(&buf[..n], &buf2[..n2]);
    }

    #[test]
    fn decode_fail_closed() {
        let p = sample_payload();
        let f = sample(&p);
        let mut buf = [0u8; 128];
        let n = canon(&f, &mut buf);
        // short header
        assert!(decode(&buf[..OPFRAME_HEADER_LEN - 1]).is_none());
        // bad magic
        let mut bad = buf;
        bad[OFF_MAGIC] ^= 0xFF;
        assert!(decode(&bad[..n]).is_none());
        // bad version
        let mut bv = buf;
        bv[OFF_VER] = 2;
        assert!(decode(&bv[..n]).is_none());
        // set reserved bit
        let mut br = buf;
        br[OFF_RESERVED] = 1;
        assert!(decode(&br[..n]).is_none());
        // truncated payload (declares 8 but only header present)
        assert!(decode(&buf[..OPFRAME_HEADER_LEN]).is_none());
    }

    fn enc(f: &OpFrame) -> alloc_vec::Vec<u8> {
        let mut b = vec![0u8; canon_len(f)];
        let n = canon(f, &mut b);
        b.truncate(n);
        b
    }

    #[test]
    fn canon_injective_each_field() {
        let p = sample_payload();
        let base = sample(&p);
        let b = enc(&base);

        let mut k = base;
        k.kind = kind::MARKER;
        assert_ne!(enc(&k), b, "kind change must alter the bytes");

        let mut s = base;
        s.sev = 13;
        assert_ne!(enc(&s), b, "sev change must alter the bytes");

        let mut sq = base;
        sq.seq ^= 1;
        assert_ne!(enc(&sq), b, "seq change must alter the bytes");

        let mut tl = base;
        tl.t_logical ^= 1;
        assert_ne!(enc(&tl), b, "t_logical change must alter the bytes");

        let mut ph = base;
        ph.prev_head[0] ^= 1;
        assert_ne!(enc(&ph), b, "prev_head change must alter the bytes");

        // A different payload LENGTH (the length-prefix disambiguator).
        let p2 = [1u8, 2, 3];
        let shorter = sample(&p2);
        let a = enc(&shorter);
        assert_ne!(a, b);
        assert_ne!(a.len(), b.len());

        // A different payload VALUE at the same length.
        let mut p3 = sample_payload();
        p3[0] ^= 1;
        let diffval = sample(&p3);
        assert_ne!(enc(&diffval), b, "payload value change must alter the bytes");
    }

    // ---- seq monotonicity ---------------------------------------------------

    #[test]
    fn seq_index_exact_catches_anomalies() {
        assert!(seq_index_exact(&[0, 1, 2, 3]));
        assert!(seq_index_exact(&[])); // vacuous
        assert!(!seq_index_exact(&[1, 2, 3])); // does not start at 0
        assert!(!seq_index_exact(&[0, 2, 3])); // gap
        assert!(!seq_index_exact(&[0, 1, 1])); // duplicate
        assert!(!seq_index_exact(&[0, 2, 1])); // reorder
    }

    // ---- intro binding ------------------------------------------------------

    #[test]
    fn intro_binds_to_live_head() {
        let head = [0x77u8; PROV_HASH_LEN];
        let intro = OpFrame {
            kind: kind::INTRO,
            sev: 9,
            partition_id: partition::CANDIDATE,
            seq: 0,
            t_logical: 0,
            prev_head: head,
            payload: &[],
        };
        assert!(intro_binds(&intro, head));
        // A forged anchor (different head) fails.
        let mut bad = head;
        bad[0] ^= 1;
        assert!(!intro_binds(&intro, bad));
        // A non-genesis seq fails.
        let mut notgenesis = intro;
        notgenesis.seq = 1;
        assert!(!intro_binds(&notgenesis, head));
        // A non-INTRO kind fails.
        let mut notintro = intro;
        notintro.kind = kind::MARKER;
        assert!(!intro_binds(&notintro, head));
    }

    // ---- closing gate-verdict: tail-truncation commit -----------------------

    #[test]
    fn gate_commits_final_seq_detects_truncation() {
        // A GATE_VERDICT at seq=4 whose payload commits final_seq=4.
        let payload = 4u64.to_le_bytes();
        let gate = OpFrame {
            kind: kind::GATE_VERDICT,
            sev: 9,
            partition_id: partition::CANDIDATE,
            seq: 4,
            t_logical: 0,
            prev_head: [0u8; PROV_HASH_LEN],
            payload: &payload,
        };
        assert_eq!(gate_final_seq(&gate), Some(4));
        assert!(gate_commits_final_seq(&gate, 4));
        // If the reader expected a longer transcript (5), the commit fails -> a
        // truncated tail is caught.
        assert!(!gate_commits_final_seq(&gate, 5));
        // A non-GATE_VERDICT frame never commits.
        let mut notgate = gate;
        notgate.kind = kind::MARKER;
        assert_eq!(gate_final_seq(&notgate), None);
        assert!(!gate_commits_final_seq(&notgate, 4));
    }

    // ---- fold reuse: the M22 chain folds the canonical bytes ----------------

    #[test]
    fn fold_is_tamper_sensitive_via_prov() {
        let p0 = sample_payload();
        let f0 = sample(&p0);
        let mut f1 = sample(&p0);
        f1.seq = 4;
        let mut scratch = [0u8; 256];
        let (h0, id0) = fold_frame([0u8; PROV_HASH_LEN], &f0, &mut scratch).unwrap();
        let (head, id1) = fold_frame(h0, &f1, &mut scratch).unwrap();
        // A genuine inclusion proof for the first frame verifies.
        assert!(op_verify_inclusion(id0, &[id1], head));
        assert_eq!(op_recompute(id0, &[id1]), head);
        // Tamper one byte of f0's canonical bytes -> a different id -> head mismatch.
        let mut tampered = [0u8; 256];
        let n = canon(&f0, &mut tampered);
        tampered[OFF_SEQ] ^= 0x01; // perturb a real canonical byte (seq low byte)
        let bad_id = op_hash(&tampered[..n]);
        assert!(!op_verify_inclusion(bad_id, &[id1], head));
    }

    #[test]
    fn fold_order_sensitive() {
        let p = sample_payload();
        let mut f0 = sample(&p);
        f0.seq = 0;
        let mut f1 = sample(&p);
        f1.seq = 1;
        let mut scratch = [0u8; 256];
        let (h0, id0) = fold_frame([0u8; PROV_HASH_LEN], &f0, &mut scratch).unwrap();
        let (head, id1) = fold_frame(h0, &f1, &mut scratch).unwrap();
        assert!(op_verify_inclusion(id0, &[id1], head));
        // Reversed order is a different fold -> reject.
        assert!(!op_verify_inclusion(id1, &[id0], head));
    }

    #[test]
    fn borderline_gap_is_total_abs() {
        assert_eq!(borderline_gap(10, 4), 6);
        assert_eq!(borderline_gap(4, 10), 6);
        assert_eq!(borderline_gap(0, 0), 0);
        // No overflow panic at the extremes.
        let _ = borderline_gap(i64::MIN, i64::MAX);
        let _ = borderline_gap(i64::MAX, i64::MIN);
    }

    // Test-only `Vec` shim alias so the no_std crate can use `vec!` on the host.
    mod alloc_vec {
        pub use std::vec::Vec;
    }
}
