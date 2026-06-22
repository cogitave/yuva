//! The M22 memory-PROVENANCE LEDGER math -- the pure, verified value-computation
//! leaf behind a per-agent, append-only, content-addressed HASH-CHAIN provenance
//! ledger over the M13 memory substrate, lifted into `tb-encode` exactly as the
//! M20 on-disk codecs ([`crate::blkfmt`]) and the M21 forget policy
//! ([`crate::kancell`]) were. Every memory mutation (write / demote-tombstone /
//! skill-admit) appends a typed [`ProvEntry`]; its 256-bit BLAKE2s-256 digest
//! ([`crate::khash::uhash`] since M29 stage C) folds
//! into a running per-agent `chain_head`, and an inclusion verifier recomputes the
//! fold to prove a known entry is committed. The kernel/`tb-hal` seam CALLS these
//! exact functions next to the existing mutation sites; the Kani lane PROVES
//! canon-injectivity / totality / fold tamper-sensitivity / inclusion-soundness /
//! determinism over the SAME bytes, with NO model drift.
//!
//! ## Honest scope (M29 stage C -- the claim boundary the witness uses)
//!
//! * **CLAIMS cryptographic tamper-evidence (assumption-conditional, since
//!   M29-C).** Any single-byte mutation to a committed entry's canonical bytes
//!   provably invalidates the recomputed head AND its inclusion proof. Deletion
//!   is provable: an M17 demote emits a TOMBSTONE entry, not a silent drop.
//! * **The digest is BLAKE2s-256 (`prim=BLAKE2S-256`) since M29 stage C** --
//!   the [`crate::khash::uhash`] unkeyed mode (RFC 7693) replaced the retired
//!   4-lane FNV-1a-64 STRUCTURAL digest (the #74 hash half; the M22 "NOT
//!   cryptographic" concession closes). Implementation totality / determinism /
//!   official-vector correctness / tamper-sensitivity are PROVEN (Kani + Miri +
//!   host tests + the fail-closed in-boot KAT); the primitive's collision /
//!   preimage resistance is `sec=ASSUMED-FROM-LITERATURE` -- NEVER proven,
//!   deliberately (no tool in the field proves primitive security; see the
//!   [`crate::khash`] honesty note, the single source of truth). A SIGNED root
//!   (authenticity over the head) remains the tracked #74 successor.
//! * **A linear hash-CHAIN head, not a balanced Merkle tree.** The `parent_ids`
//!   DAG edges are DATA inside an entry; the per-agent *head* is a fold. Balanced
//!   batch-Merkle proofs are deferred to a successor (the Kani state-space reason).
//!
//! ## Numeric format (no float, ever -- mirrors `kancell`/`blkfmt`)
//!
//! Pure integer/byte arithmetic, zero alloc, zero deps. `canon` is a fixed-field-
//! order, LENGTH-PREFIXED-parents LE byte layout into a caller buffer (total +
//! fail-closed: returns `0` if the buffer is too small, never panics). `prov_hash`
//! is BLAKE2s-256 unkeyed (pure wrapping/rotating 32-bit ARX -- the verified
//! [`crate::khash`] leaf). `chain_mix` folds the
//! 32-byte entry id into the 32-byte head by hashing their concatenation under a
//! fold domain tag. `verify_inclusion` re-runs the fold over `(leaf, siblings)`
//! and accepts iff it lands on the committed head -- a TOTAL, no-`unsafe`,
//! `#![no_std]` leaf (the crate root forbids `unsafe_code`).

use crate::khash::{uhash, KHASH_TAG_LEN};

/// The fixed canonical-entry digest width: a 256-bit (32-byte) content id.
pub const PROV_HASH_LEN: usize = 32;

/// The fixed prefix every [`canon`] encoding stamps BEFORE the variable parent
/// list: `kind(1) | tier(1) | payload_tok(8 LE) | writer_cap_id(8 LE) |
/// t_created(8 LE) | n_parents(8 LE)` -- 26 bytes. The two single-byte tags lead
/// (so a `kind`/`tier` flip changes byte 0/1), then the three u64 scalars, then
/// the parent COUNT as an LE u64 length-prefix (the disambiguator that makes the
/// variable-length parent list unambiguous -> `canon` injective).
pub const CANON_PREFIX_LEN: usize = 1 + 1 + 8 + 8 + 8 + 8;

/// Each typed DAG parent edge is a 32-byte content id, appended verbatim after the
/// length-prefix. The canonical length of an entry with `n` parents is therefore
/// `CANON_PREFIX_LEN + n * PROV_HASH_LEN`.
pub const CANON_PARENT_LEN: usize = PROV_HASH_LEN;

/// The fixed digest width of the [`crate::khash`] leaf is EXACTLY the prov
/// digest width (BLAKE2s-256 == 32 bytes) -- the M29-C cutover is
/// width-transparent, compile-pinned here so a drift can never build.
const _: () = assert!(KHASH_TAG_LEN == PROV_HASH_LEN);

/// The domain-separator byte that leads the [`chain_mix`] fold input, so folding
/// `(head, id)` is domain-separated from a bare [`prov_hash`] over the same 64
/// concatenated bytes (the head is a DISTINCT computation from a leaf digest).
pub const MIX_DOMAIN: u8 = 0xC3;

/// The provenance entry KIND tags (the typed write chain-of-custody vocabulary,
/// proposal §3). `tb-hal` stamps one per mutation site; the digest folds them in,
/// so a write can never masquerade as a tombstone (the byte differs -> the head
/// differs). These are the closed set the seam emits.
pub mod kind {
    /// A T2/T3 memory WRITE (the `MemSubstrate::write` add/update path).
    pub const WRITE: u8 = 1;
    /// An M17 forget/demote TOMBSTONE -- deletion made PROVABLE (the demote site
    /// emits this instead of silently dropping the record).
    pub const FORGET: u8 = 2;
    /// A T4 skill admission (`skill_add_class`) -- a learned-skill provenance edge.
    pub const SKILL_ADMIT: u8 = 3;
    /// An M38 CONDUCTOR decision ([`crate::conductor::ConductDecision`]) -- one
    /// orchestration step (select-organ / assign-role / Verifier verdict)
    /// folded into the per-session `conduct_head` via the REUSED fold. The
    /// conductor leaf writes NO new fold math; it stamps this tag and reuses
    /// `append`/`chain_mix`/`recompute`/`verify_inclusion` verbatim (the
    /// M23/M25/M26/M27 prov-reuse discipline).
    pub const CONDUCT_DECISION: u8 = 4;
}

/// A fixed, canonical provenance entry (proposal §3). Field order + an explicit
/// LENGTH-PREFIX on the parent list make [`canon`] injective: distinct entries
/// always encode to distinct bytes. Borrowed `parent_ids` so the leaf stays
/// zero-alloc; `tb-hal` owns the (heap) parent slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvEntry<'a> {
    /// The mutation kind (see [`kind`]): write | forget/tombstone | skill-admit.
    pub kind: u8,
    /// The mutated payload token (the M13 content/skill token id).
    pub payload_tok: u64,
    /// The memory tier the mutation touched (T2/T3/T4 region tag).
    pub tier: u8,
    /// The M11 writer capability id that AUTHORIZED the mutation (chain of custody).
    pub writer_cap_id: u64,
    /// The logical clock at which the entry was created (the substrate `clock`).
    pub t_created: u64,
    /// The typed DAG edges to PARENT entry ids (length-prefixed in [`canon`]).
    pub parent_ids: &'a [[u8; PROV_HASH_LEN]],
}

/// The exact canonical byte length of `entry` (the value [`canon`] returns on a
/// large-enough buffer). `CANON_PREFIX_LEN + n_parents * PROV_HASH_LEN`, computed
/// with SATURATING arithmetic so a pathological parent count can never overflow
/// `usize` (total -- it never panics).
#[inline]
#[must_use]
pub fn canon_len(entry: &ProvEntry) -> usize {
    CANON_PREFIX_LEN.saturating_add(entry.parent_ids.len().saturating_mul(PROV_HASH_LEN))
}

/// Canonical, UNAMBIGUOUS, total length-delimited LE encoding of `entry` into
/// `out`. Returns the number of bytes written, or `0` if `out` is too small to
/// hold the full encoding (TOTAL + fail-closed: never panics, never partial-
/// writes). Layout (fixed field order, the parent list LENGTH-PREFIXED):
///
/// ```text
///   [0]      kind          u8
///   [1]      tier          u8
///   [2..10]  payload_tok   u64 LE
///   [10..18] writer_cap_id u64 LE
///   [18..26] t_created     u64 LE
///   [26..34] n_parents     u64 LE   <-- the length-prefix (disambiguator)
///   [34..]   parent_ids[i] [u8;32]  verbatim, i in 0..n_parents
/// ```
///
/// INJECTIVITY: two entries that differ in ANY field encode to different bytes --
/// the fixed-width scalars occupy fixed offsets, and the explicit `n_parents`
/// prefix makes the variable-length tail self-delimiting, so no field-boundary
/// ambiguity can let two distinct entries collide (the proposal §5.1 load-bearing
/// property the `kani_prov_canon_injective` harness discharges).
#[must_use]
pub fn canon(entry: &ProvEntry, out: &mut [u8]) -> usize {
    let n = entry.parent_ids.len();
    let total = canon_len(entry);
    // Fail-closed: too-small buffer -> 0 bytes, no partial write (totality).
    if out.len() < total {
        return 0;
    }
    out[0] = entry.kind;
    out[1] = entry.tier;
    let pt = entry.payload_tok.to_le_bytes();
    let wc = entry.writer_cap_id.to_le_bytes();
    let tc = entry.t_created.to_le_bytes();
    let np = (n as u64).to_le_bytes();
    let mut i = 0usize;
    while i < 8 {
        out[2 + i] = pt[i];
        out[10 + i] = wc[i];
        out[18 + i] = tc[i];
        out[26 + i] = np[i];
        i += 1;
    }
    // The length-prefixed parent tail, verbatim and in order.
    let mut p = 0usize;
    while p < n {
        let base = CANON_PREFIX_LEN + p * PROV_HASH_LEN;
        let mut b = 0usize;
        while b < PROV_HASH_LEN {
            out[base + b] = entry.parent_ids[p][b];
            b += 1;
        }
        p += 1;
    }
    total
}

/// 256-bit digest of `bytes`: BLAKE2s-256 UNKEYED ([`crate::khash::uhash`],
/// RFC 7693) -- the M29 stage C cutover body (the #74 hash half). TOTAL,
/// deterministic, NO float, no alloc, no panic (the khash leaf's Kani/Miri/
/// KAT-proven properties). The retired FNV-era body (four domain-separated
/// `fnv1a64` lanes + a length separator) was STRUCTURAL tamper-evidence only;
/// this body is a real cryptographic hash whose collision / preimage
/// resistance is `sec=ASSUMED-FROM-LITERATURE` (see the module honesty note +
/// [`crate::khash`] -- the implementation is verified, the primitive's
/// security is never prose-claimed). Width-exact by construction:
/// `KHASH_TAG_LEN == PROV_HASH_LEN == 32` (compile-pinned above). Domain
/// separation stays the CALLER's, exactly as before (e.g. the [`MIX_DOMAIN`]
/// fold tag leads the [`chain_mix`] buffer).
#[must_use]
pub fn prov_hash(bytes: &[u8]) -> [u8; PROV_HASH_LEN] {
    uhash(bytes)
}

/// The running per-agent FOLD step: `head' = chain_mix(head, entry_id)`. Hashes
/// the [`MIX_DOMAIN`]-tagged concatenation `domain | head | entry_id` (65 bytes)
/// with [`prov_hash`], so the new head depends on BOTH the prior head and the new
/// entry id. TAMPER-SENSITIVE: flipping any byte of `entry_id` (or `head`) changes
/// the output (the `kani_prov_chain_mix_tamper` harness proves the fold is a non-
/// degenerate function of every input byte -- an identity/constant fold fails it).
/// Domain-separated from a bare [`prov_hash`] so a fold can never collide a leaf.
#[must_use]
pub fn chain_mix(
    head: [u8; PROV_HASH_LEN],
    entry_id: [u8; PROV_HASH_LEN],
) -> [u8; PROV_HASH_LEN] {
    let mut buf = [0u8; 1 + PROV_HASH_LEN + PROV_HASH_LEN];
    buf[0] = MIX_DOMAIN;
    let mut i = 0usize;
    while i < PROV_HASH_LEN {
        buf[1 + i] = head[i];
        buf[1 + PROV_HASH_LEN + i] = entry_id[i];
        i += 1;
    }
    prov_hash(&buf)
}

/// Recompute the running fold over `(leaf, siblings)` starting from the genesis
/// (all-zero) head: `acc = genesis`, then `acc = chain_mix(acc, leaf)` and
/// `acc = chain_mix(acc, sibling_i)` for each sibling in order. This is the SAME
/// fold the per-agent head accumulates as entries are appended, so the recomputed
/// value equals the committed head iff `leaf` followed by `siblings` is exactly
/// the committed append sequence. Total (no panic, no alloc).
#[must_use]
pub fn recompute(leaf: [u8; PROV_HASH_LEN], siblings: &[[u8; PROV_HASH_LEN]]) -> [u8; PROV_HASH_LEN] {
    let mut acc = [0u8; PROV_HASH_LEN]; // genesis head (all zeros)
    acc = chain_mix(acc, leaf);
    let mut i = 0usize;
    while i < siblings.len() {
        acc = chain_mix(acc, siblings[i]);
        i += 1;
    }
    acc
}

/// Inclusion verifier: recompute the fold over `(leaf, siblings)` and accept iff
/// it lands EXACTLY on the committed `head`. SOUND by construction:
/// `verify_inclusion(leaf, siblings, head) == true` IFF
/// `recompute(leaf, siblings) == head` -- so a mutated `leaf`, a mutated/missing
/// sibling, or a tampered `head` drives it to `false` (the
/// `kani_prov_inclusion_sound` harness; a verifier that ignored `siblings` would
/// accept a forged proof and fail it). Total (no panic).
#[inline]
#[must_use]
pub fn verify_inclusion(
    leaf: [u8; PROV_HASH_LEN],
    siblings: &[[u8; PROV_HASH_LEN]],
    head: [u8; PROV_HASH_LEN],
) -> bool {
    recompute(leaf, siblings) == head
}

/// Convenience: fold `entry` into `head` in one step -- canon-encode into a
/// caller-supplied scratch buffer, [`prov_hash`] the canonical bytes, and
/// [`chain_mix`] the resulting entry id into `head`. Returns `(new_head,
/// entry_id)`, or `None` if `scratch` is too small for the entry's canonical bytes
/// (fail-closed -- the caller sizes `scratch >= canon_len(entry)`). This is the
/// exact step `tb-hal::mem::ledger_append` runs at each mutation site.
#[must_use]
pub fn append(
    head: [u8; PROV_HASH_LEN],
    entry: &ProvEntry,
    scratch: &mut [u8],
) -> Option<([u8; PROV_HASH_LEN], [u8; PROV_HASH_LEN])> {
    let n = canon(entry, scratch);
    if n == 0 {
        return None; // buffer too small -- fail closed, no head advance
    }
    let entry_id = prov_hash(&scratch[..n]);
    let new_head = chain_mix(head, entry_id);
    Some((new_head, entry_id))
}

/// Fold a u64 head-WITNESS out of a 32-byte head for the boot witness line (the
/// kernel renders `head=<hex16>` via `write_hex_u64`). XOR-folds the four LE
/// lanes so every head byte contributes (a non-degenerate witness: a single-byte
/// head change flips the witness with high probability). Pure, total.
#[inline]
#[must_use]
pub fn head_witness(head: [u8; PROV_HASH_LEN]) -> u64 {
    let mut acc = 0u64;
    let mut l = 0usize;
    while l < 4 {
        let mut w = [0u8; 8];
        let base = l * 8;
        let mut b = 0usize;
        while b < 8 {
            w[b] = head[base + b];
            b += 1;
        }
        acc ^= u64::from_le_bytes(w);
        l += 1;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> [u8; PROV_HASH_LEN] {
        let mut a = [0u8; PROV_HASH_LEN];
        let mut i = 0usize;
        while i < PROV_HASH_LEN {
            a[i] = seed.wrapping_add(i as u8).wrapping_mul(31);
            i += 1;
        }
        a
    }

    fn sample<'a>(parents: &'a [[u8; PROV_HASH_LEN]]) -> ProvEntry<'a> {
        ProvEntry {
            kind: kind::WRITE,
            payload_tok: 0xA11CE,
            tier: 1,
            writer_cap_id: 0xCA9_F00D,
            t_created: 42,
            parent_ids: parents,
        }
    }

    // ---- canon: layout, length, fail-closed totality ------------------------

    #[test]
    fn canon_len_matches_written() {
        let parents = [id(1), id(2)];
        let e = sample(&parents);
        assert_eq!(canon_len(&e), CANON_PREFIX_LEN + 2 * PROV_HASH_LEN);
        let mut buf = [0u8; 256];
        let n = canon(&e, &mut buf);
        assert_eq!(n, canon_len(&e));
        // Length-prefix at [26..34] reads back the parent count.
        let np = u64::from_le_bytes([
            buf[26], buf[27], buf[28], buf[29], buf[30], buf[31], buf[32], buf[33],
        ]);
        assert_eq!(np, 2);
        // The scalar fields land at their fixed offsets.
        assert_eq!(buf[0], kind::WRITE);
        assert_eq!(buf[1], 1);
        assert_eq!(
            u64::from_le_bytes([buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9]]),
            0xA11CE
        );
    }

    #[test]
    fn canon_fail_closed_on_small_buffer() {
        let parents = [id(1)];
        let e = sample(&parents);
        let need = canon_len(&e);
        let mut small = vec![0u8; need - 1];
        // Too small -> 0 bytes, NO partial write (the buffer stays all-zero).
        assert_eq!(canon(&e, &mut small), 0);
        assert!(small.iter().all(|&b| b == 0));
        // Exactly-sized succeeds.
        let mut exact = vec![0u8; need];
        assert_eq!(canon(&e, &mut exact), need);
    }

    #[test]
    fn canon_zero_parents() {
        let e = sample(&[]);
        assert_eq!(canon_len(&e), CANON_PREFIX_LEN);
        let mut buf = [0u8; 64];
        let n = canon(&e, &mut buf);
        assert_eq!(n, CANON_PREFIX_LEN);
        assert_eq!(
            u64::from_le_bytes([
                buf[26], buf[27], buf[28], buf[29], buf[30], buf[31], buf[32], buf[33]
            ]),
            0
        );
    }

    // ---- canon INJECTIVITY: every field perturbation changes the bytes ------

    fn enc(e: &ProvEntry) -> alloc_vec::Vec<u8> {
        let mut buf = vec![0u8; canon_len(e) + 8];
        let n = canon(e, &mut buf);
        buf.truncate(n);
        buf
    }

    #[test]
    fn canon_injective_each_field() {
        let p0 = [id(7)];
        let base = sample(&p0);
        let b = enc(&base);

        let mut k = base;
        k.kind = kind::FORGET;
        assert_ne!(enc(&k), b, "kind change must alter the bytes");

        let mut t = base;
        t.tier = 9;
        assert_ne!(enc(&t), b, "tier change must alter the bytes");

        let mut pt = base;
        pt.payload_tok = base.payload_tok ^ 1;
        assert_ne!(enc(&pt), b, "payload_tok change must alter the bytes");

        let mut wc = base;
        wc.writer_cap_id = base.writer_cap_id ^ 1;
        assert_ne!(enc(&wc), b, "writer_cap_id change must alter the bytes");

        let mut tc = base;
        tc.t_created = base.t_created ^ 1;
        assert_ne!(enc(&tc), b, "t_created change must alter the bytes");

        // A different parent COUNT (length-prefix) and a different parent VALUE.
        let p1 = [id(7), id(8)];
        let more = sample(&p1);
        assert_ne!(enc(&more), b, "extra parent must alter the bytes");
        let p2 = [id(99)];
        let diff = sample(&p2);
        assert_ne!(enc(&diff), b, "different parent id must alter the bytes");
    }

    #[test]
    fn canon_length_prefix_disambiguates() {
        // The length-prefix is what stops a 1-parent entry from aliasing a
        // 0-parent entry whose trailing scalar happened to look like a parent.
        // Two entries with the SAME prefix scalars but different parent counts
        // must differ even though the shorter is a prefix of the longer's start.
        let p = [id(3)];
        let with = sample(&p);
        let without = sample(&[]);
        let a = enc(&with);
        let b = enc(&without);
        assert_ne!(a, b);
        assert_ne!(a.len(), b.len());
    }

    // ---- prov_hash: totality, determinism, avalanche ------------------------

    #[test]
    fn prov_hash_total_and_deterministic() {
        for len in [0usize, 1, 7, 26, 34, 100] {
            let data: alloc_vec::Vec<u8> = (0..len).map(|i| (i * 7 + 1) as u8).collect();
            let h1 = prov_hash(&data);
            let h2 = prov_hash(&data);
            assert_eq!(h1, h2, "prov_hash must be deterministic");
        }
        // The four 8-byte digest windows are not all identical (a degenerate
        // digest that smeared one 64-bit word four times would fail here).
        let h = prov_hash(b"the quick brown fox");
        assert_ne!(&h[0..8], &h[8..16]);
        assert_ne!(&h[8..16], &h[16..24]);
        assert_ne!(&h[16..24], &h[24..32]);
    }

    #[test]
    fn prov_hash_single_byte_avalanche() {
        let mut data = *b"provenance-ledger-entry-bytes!!";
        let h0 = prov_hash(&data);
        // Flip every single byte in turn; the digest must change each time.
        for i in 0..data.len() {
            let saved = data[i];
            data[i] = saved ^ 0x01;
            assert_ne!(prov_hash(&data), h0, "byte {i} flip did not change the digest");
            data[i] = saved;
        }
    }

    // ---- chain_mix: tamper-sensitivity + determinism ------------------------

    #[test]
    fn chain_mix_deterministic_and_domain_separated() {
        let h = id(1);
        let e = id(2);
        assert_eq!(chain_mix(h, e), chain_mix(h, e));
        // The fold is domain-separated from a bare prov_hash over head||id, so it
        // is NOT just prov_hash(concat) -- a distinct computation.
        let mut concat = [0u8; 64];
        concat[..32].copy_from_slice(&h);
        concat[32..].copy_from_slice(&e);
        assert_ne!(chain_mix(h, e), prov_hash(&concat));
    }

    #[test]
    fn chain_mix_tamper_sensitive_in_entry_id() {
        let head = id(5);
        let mut eid = id(9);
        let base = chain_mix(head, eid);
        for i in 0..PROV_HASH_LEN {
            let saved = eid[i];
            eid[i] = saved ^ 0x01;
            assert_ne!(chain_mix(head, eid), base, "entry_id byte {i} flip not folded");
            eid[i] = saved;
        }
    }

    #[test]
    fn chain_mix_tamper_sensitive_in_head() {
        let mut head = id(5);
        let eid = id(9);
        let base = chain_mix(head, eid);
        for i in 0..PROV_HASH_LEN {
            let saved = head[i];
            head[i] = saved ^ 0x01;
            assert_ne!(chain_mix(head, eid), base, "head byte {i} flip not folded");
            head[i] = saved;
        }
    }

    // ---- verify_inclusion: accept the genuine proof, reject tampered ones ----

    #[test]
    fn inclusion_accepts_genuine_and_rejects_tamper() {
        // Build a real 3-entry chain via append; the head is the fold over all 3.
        let mut head = [0u8; PROV_HASH_LEN];
        let mut scratch = [0u8; 256];
        let e0 = ProvEntry { kind: kind::WRITE, payload_tok: 10, tier: 0, writer_cap_id: 1, t_created: 1, parent_ids: &[] };
        let e1 = ProvEntry { kind: kind::WRITE, payload_tok: 20, tier: 1, writer_cap_id: 1, t_created: 2, parent_ids: &[] };
        let e2 = ProvEntry { kind: kind::FORGET, payload_tok: 10, tier: 0, writer_cap_id: 2, t_created: 3, parent_ids: &[] };
        let (h0, id0) = append(head, &e0, &mut scratch).unwrap();
        head = h0;
        let (h1, id1) = append(head, &e1, &mut scratch).unwrap();
        head = h1;
        let (h2, id2) = append(head, &e2, &mut scratch).unwrap();
        head = h2;

        // The genuine inclusion proof for the FIRST entry: leaf=id0, siblings=[id1,id2].
        assert!(verify_inclusion(id0, &[id1, id2], head));
        // recompute equals the committed head.
        assert_eq!(recompute(id0, &[id1, id2]), head);

        // Tamper the leaf -> reject.
        let mut bad_leaf = id0;
        bad_leaf[0] ^= 0x01;
        assert!(!verify_inclusion(bad_leaf, &[id1, id2], head));
        // Tamper a sibling -> reject.
        let mut bad_sib = id2;
        bad_sib[5] ^= 0x80;
        assert!(!verify_inclusion(id0, &[id1, bad_sib], head));
        // Drop a sibling (wrong length) -> reject.
        assert!(!verify_inclusion(id0, &[id1], head));
        // Tamper the head -> reject.
        let mut bad_head = head;
        bad_head[31] ^= 0x01;
        assert!(!verify_inclusion(id0, &[id1, id2], bad_head));
    }

    #[test]
    fn inclusion_order_sensitive() {
        // Swapping two siblings (a reordered chain) must NOT verify -- the fold is
        // order-dependent, so a permuted proof is caught.
        let mut head = [0u8; PROV_HASH_LEN];
        let mut scratch = [0u8; 128];
        let e0 = ProvEntry { kind: kind::WRITE, payload_tok: 1, tier: 0, writer_cap_id: 1, t_created: 1, parent_ids: &[] };
        let e1 = ProvEntry { kind: kind::WRITE, payload_tok: 2, tier: 0, writer_cap_id: 1, t_created: 2, parent_ids: &[] };
        let (h0, id0) = append(head, &e0, &mut scratch).unwrap();
        head = h0;
        let (h1, id1) = append(head, &e1, &mut scratch).unwrap();
        head = h1;
        assert!(verify_inclusion(id0, &[id1], head));
        // Reversed (id1 as leaf, id0 as sibling) is a different fold -> reject.
        assert!(!verify_inclusion(id1, &[id0], head));
    }

    // ---- append + head_witness: end-to-end determinism ----------------------

    #[test]
    fn append_is_deterministic_head() {
        let mut scratch = [0u8; 128];
        let e = sample(&[]);
        let (ha, _) = append([0u8; 32], &e, &mut scratch).unwrap();
        let (hb, _) = append([0u8; 32], &e, &mut scratch).unwrap();
        assert_eq!(ha, hb, "same entry from same head must fold identically");
    }

    #[test]
    fn append_fail_closed_on_small_scratch() {
        let parents = [id(1), id(2), id(3)];
        let e = sample(&parents);
        let mut tiny = [0u8; 8]; // far too small
        assert!(append([0u8; 32], &e, &mut tiny).is_none());
    }

    #[test]
    fn head_witness_changes_with_head() {
        let h = id(1);
        let w = head_witness(h);
        let mut h2 = h;
        h2[0] ^= 0xFF;
        assert_ne!(head_witness(h2), w, "a head change must move the witness");
    }

    // Test-only `Vec` shim alias so the `#![cfg_attr(not(test), no_std)]` crate
    // (which has no `extern crate alloc` on the host-test path) can use `vec!`.
    mod alloc_vec {
        pub use std::vec::Vec;
    }
}
