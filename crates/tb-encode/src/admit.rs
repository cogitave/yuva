//! The ADMISSION codec + the strength-index attenuation algebra -- the pure,
//! host-verifiable value layer of the self-modification admission gate
//! (`docs/cogi-cognitive-architecture.md` / `cogi-substrate-architecture.md`).
//!
//! Self-modification is ONE capability-gated protocol: an UNTRUSTED proposer
//! submits an [`AdmissionRequest`] (an organ + its evidence), and the TRUSTED
//! verifier plane returns an [`AdmissionVerdict`] (admit XOR reject, with the
//! GRANTED trust strength + rights). This module is the injective on-wire codec
//! for those two records plus the [`strength_attenuate`] lemma: a verdict can only
//! ever DOWNGRADE the claimed trust to what the checker actually warrants, never
//! inflate it -- the [`crate::proofs`] analogue of `tb_caps_core::Rights::intersect`
//! (monotone attenuation), so `EMPIRICAL` evidence can never be laundered into a
//! `PROVEN` grant.
//!
//! HONEST (the four strengths are NOT interchangeable; see the substrate-arch doc):
//!   * [`STRENGTH_PROVEN`] -- a machine proof over a decidable, bounded fragment
//!     (Kani/CBMC). The ONLY strength that is actually SOUND.
//!   * [`STRENGTH_CONFORMANCE`] -- a known-answer test (one vector); a TEST, not a
//!     proof.
//!   * [`STRENGTH_EFFECT_BOUNDED`] -- a witness over a decidable fragment + a
//!     sandbox bound; as strong as its (unstated) spec.
//!   * [`STRENGTH_EMPIRICAL`] -- a held-out eval; EVIDENCE for a human, not a proof.
//!
//! `#![no_std]` + `#![forbid(unsafe_code)]` (inherited) + ZERO deps -- so
//! `cargo kani -p tb-encode` model-checks the EXACT bytes the kernel admits.

// --- strength index (the closed trust lattice) -------------------------------

/// A machine proof over a decidable, bounded fragment (Kani/CBMC) -- SOUND.
pub const STRENGTH_PROVEN: u8 = 1;
/// A known-answer conformance test (one vector) -- a test, not a proof.
pub const STRENGTH_CONFORMANCE: u8 = 2;
/// A proof-carrying witness over a decidable fragment + sandbox bound.
pub const STRENGTH_EFFECT_BOUNDED: u8 = 3;
/// A held-out empirical eval -- evidence for a human, not a proof (the WEAKEST).
pub const STRENGTH_EMPIRICAL: u8 = 4;

/// True iff `s` is one of the four closed strength levels (`1..=4`).
#[must_use]
pub fn strength_is_valid(s: u8) -> bool {
    (STRENGTH_PROVEN..=STRENGTH_EMPIRICAL).contains(&s)
}

/// Attenuate a claimed strength against what the checker actually warrants: the
/// GRANTED strength is the WEAKER of the two (numerically LARGER -- `PROVEN`=1 is
/// the strongest, `EMPIRICAL`=4 the weakest), so an admission can only DOWNGRADE
/// trust, never inflate it. Any out-of-range input is clamped to the weakest
/// (`EMPIRICAL`) fail-closed. This is the strength analogue of the capability
/// `Rights::intersect` monotone-attenuation lemma.
#[must_use]
pub fn strength_attenuate(claimed: u8, warranted: u8) -> u8 {
    let c = if strength_is_valid(claimed) { claimed } else { STRENGTH_EMPIRICAL };
    let w = if strength_is_valid(warranted) { warranted } else { STRENGTH_EMPIRICAL };
    if c >= w { c } else { w } // the weaker (numerically larger) trust
}

// --- admission REQUEST (the untrusted proposer's ask) ------------------------

/// A decoded [`AdmissionRequest`]: an untrusted proposer's ask to admit an organ.
/// The digests are content addresses (e.g. `khash`); nothing here is authority --
/// authority is granted only by the verifier's [`AdmissionVerdict`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AdmissionRequest {
    /// Content digest of the proposed organ/skill artifact.
    pub organ_digest: [u8; 32],
    /// Content digest of the machine-checkable witness shipped WITH the organ.
    pub witness_digest: [u8; 32],
    /// Content digest of the spec the witness is checked against. HONEST: the spec
    /// must originate in / be countersigned by the trusted ring -- a sound proof of
    /// a vacuous proposer-authored spec still admits an unsafe organ.
    pub spec_digest: [u8; 32],
    /// The strength the proposer CLAIMS (attenuated by the checker at admit time).
    pub claimed_strength: u8,
    /// The proposing principal id (the untrusted author, for provenance).
    pub proposer_id: u64,
    /// The declared effect-interface bits the organ says it touches.
    pub effect_mask: u32,
    /// The resource/budget bound the organ declares.
    pub budget: u64,
}

/// The encoded length of an [`AdmissionRequest`] (LE, fixed): 3x32 digests + u8 +
/// u64 + u32 + u64.
pub const ADMIT_REQ_LEN: usize = 32 + 32 + 32 + 1 + 8 + 4 + 8;

/// Encode an [`AdmissionRequest`] to its fixed `ADMIT_REQ_LEN` LE byte form (total,
/// no panic).
#[must_use]
pub fn admit_req_encode(r: &AdmissionRequest) -> [u8; ADMIT_REQ_LEN] {
    let mut b = [0u8; ADMIT_REQ_LEN];
    b[0..32].copy_from_slice(&r.organ_digest);
    b[32..64].copy_from_slice(&r.witness_digest);
    b[64..96].copy_from_slice(&r.spec_digest);
    b[96] = r.claimed_strength;
    b[97..105].copy_from_slice(&r.proposer_id.to_le_bytes());
    b[105..109].copy_from_slice(&r.effect_mask.to_le_bytes());
    b[109..117].copy_from_slice(&r.budget.to_le_bytes());
    b
}

/// Decode a fixed `ADMIT_REQ_LEN` byte form into an [`AdmissionRequest`] (total;
/// every byte pattern is a well-formed record -- enum-field validity is a SEPARATE
/// predicate, [`strength_is_valid`], the caller checks fail-closed).
#[must_use]
pub fn admit_req_decode(b: &[u8; ADMIT_REQ_LEN]) -> AdmissionRequest {
    let mut organ_digest = [0u8; 32];
    let mut witness_digest = [0u8; 32];
    let mut spec_digest = [0u8; 32];
    organ_digest.copy_from_slice(&b[0..32]);
    witness_digest.copy_from_slice(&b[32..64]);
    spec_digest.copy_from_slice(&b[64..96]);
    AdmissionRequest {
        organ_digest,
        witness_digest,
        spec_digest,
        claimed_strength: b[96],
        proposer_id: rd_u64(b, 97),
        effect_mask: rd_u32(b, 105),
        budget: rd_u64(b, 109),
    }
}

// --- admission VERDICT (the trusted gate's decision) -------------------------

/// The verdict decision: REJECT (the organ is discarded atomically, zero trace).
pub const ADMIT_DECISION_REJECT: u8 = 0;
/// The verdict decision: ADMIT (the organ is granted an attenuated rights subset).
pub const ADMIT_DECISION_ADMIT: u8 = 1;

/// A decoded [`AdmissionVerdict`]: the TRUSTED verifier plane's admit-XOR-reject
/// decision, folded into the provenance chain. The proposer can never mint this --
/// the admit right lives only in the trusted core.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AdmissionVerdict {
    /// Content digest of the [`AdmissionRequest`] this verdict answers.
    pub request_digest: [u8; 32],
    /// [`ADMIT_DECISION_ADMIT`] XOR [`ADMIT_DECISION_REJECT`].
    pub decision: u8,
    /// The GRANTED strength -- `<=` (weaker-or-equal to) the claimed, never inflated.
    pub granted_strength: u8,
    /// The monotone-attenuated rights SUBSET granted to the admitted organ.
    pub granted_rights: u32,
    /// Content digest of the (trusted-ring-countersigned) spec that was checked.
    pub spec_digest: [u8; 32],
    /// The verifying principal id (which trusted-core verifier decided).
    pub verifier_id: u64,
    /// The monotone decision sequence number (the append-only admission order).
    pub decision_seq: u64,
}

/// The encoded length of an [`AdmissionVerdict`] (LE, fixed).
pub const ADMIT_VERDICT_LEN: usize = 32 + 1 + 1 + 4 + 32 + 8 + 8;

/// Encode an [`AdmissionVerdict`] to its fixed `ADMIT_VERDICT_LEN` LE byte form
/// (total, no panic).
#[must_use]
pub fn admit_verdict_encode(v: &AdmissionVerdict) -> [u8; ADMIT_VERDICT_LEN] {
    let mut b = [0u8; ADMIT_VERDICT_LEN];
    b[0..32].copy_from_slice(&v.request_digest);
    b[32] = v.decision;
    b[33] = v.granted_strength;
    b[34..38].copy_from_slice(&v.granted_rights.to_le_bytes());
    b[38..70].copy_from_slice(&v.spec_digest);
    b[70..78].copy_from_slice(&v.verifier_id.to_le_bytes());
    b[78..86].copy_from_slice(&v.decision_seq.to_le_bytes());
    b
}

/// Decode a fixed `ADMIT_VERDICT_LEN` byte form into an [`AdmissionVerdict`]
/// (total; enum-field validity is a SEPARATE predicate, [`verdict_is_wellformed`]).
#[must_use]
pub fn admit_verdict_decode(b: &[u8; ADMIT_VERDICT_LEN]) -> AdmissionVerdict {
    let mut request_digest = [0u8; 32];
    let mut spec_digest = [0u8; 32];
    request_digest.copy_from_slice(&b[0..32]);
    spec_digest.copy_from_slice(&b[38..70]);
    AdmissionVerdict {
        request_digest,
        decision: b[32],
        granted_strength: b[33],
        granted_rights: rd_u32(b, 34),
        spec_digest,
        verifier_id: rd_u64(b, 70),
        decision_seq: rd_u64(b, 78),
    }
}

/// True iff a verdict's closed enum fields are in range: `decision` is
/// admit-XOR-reject AND `granted_strength` is a valid strength level. (The
/// no-inflation property between a request and its verdict is checked at admit
/// time via [`strength_attenuate`]; this is the standalone well-formedness gate.)
#[must_use]
pub fn verdict_is_wellformed(v: &AdmissionVerdict) -> bool {
    (v.decision == ADMIT_DECISION_ADMIT || v.decision == ADMIT_DECISION_REJECT)
        && strength_is_valid(v.granted_strength)
}

// --- little-endian readers (no external deps, no unsafe) ---------------------

#[inline]
fn rd_u64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([
        b[o], b[o + 1], b[o + 2], b[o + 3], b[o + 4], b[o + 5], b[o + 6], b[o + 7],
    ])
}

#[inline]
fn rd_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
