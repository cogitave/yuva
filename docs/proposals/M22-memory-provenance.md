---
type: Design Decision
title: "M22 — Verified Memory Provenance"
description: "Proposes a per-agent hash-chain memory-provenance ledger (Kani-proven FNV fold) giving structural — not cryptographic — tamper-evidence."
tags: ["m22", "provenance", "memory", "tamper-evidence", "hash-chain", "kani"]
timestamp: 2026-06-10T08:42:16+03:00
status: locked
diataxis: explanation
---

# M22 — Verified memory provenance (mnemonic sovereignty)

**Status:** proposed (build-as-designed, autonomously buildable) · **Depends on:** M13 (memory substrate), M11 (writer capability), M17 (forget/tombstone), M20 (durable head) · **Marker:** `M22: provenance OK`

> **One-line:** a per-agent, append-only, **content-addressed hash-chain provenance ledger** over the M13 memory substrate. Every memory mutation (write, demote/tombstone, skill admit) appends a typed entry whose 256-bit structural digest folds into a running per-agent `chain_head`; a new Kani-proven `tb-encode::prov` leaf provides the canonical encoder, the digest, the fold, and an inclusion verifier; a deterministic **tamper-injection** boot self-test proves the head/inclusion-proof catch any single-byte mutation. This makes deletion *provable* (M17's silent demote becomes a verifiable tombstone) and the whole memory store **tamper-evident** — the foundational ledger that future shared-memory / snapshot / governance milestones attest against.

This is the output of the M22 research pass (recon + 3 survey arms + synthesis). It was the convergent #1 candidate once filtered through **both** the thesis-value and the autonomous-buildability gates (QEMU/TCG-only, no hardware, no network, no human — the constraint for the overnight autonomous run).

---

## 1. Why this is M22

**No doc names an "M22"** — the cumulative chain officially ends at M21. The research filtered every declared next-step and natural seam through two gates: *thesis value* and *autonomously CI-greenable*. Most of the L2 north-star is gated out for autonomous work (Track A x86-VMX needs the #37 nested-VMX hardware substrate; L2.7 UEFI bare-metal and L2.8 real IOMMU need silicon; real inference needs network). What passes both gates is the M21 mold: **a new verified `tb-encode` leaf + a kernel/tb-hal seam exercised by a deterministic boot self-test marker.** Among those, verified provenance wins:

1. **Thesis-defining, not derivative.** The *Mnemonic Sovereignty* survey (arXiv:2604.16548) ranks **typed-write chain-of-custody provenance** and **verified forgetting** as the two top *missing* governance primitives for agent memory ("forgetting is the strongest test of mnemonic sovereignty"; ~5% of the literature covers store+forget integrity). *Portable Agent Memory* (arXiv:2605.11032) builds exactly this structure (a BLAKE3 Merkle-DAG + signed root) but **explicitly disclaims formal verification** — precisely the gap a Kani-proven `no_std`/no-float core is uniquely positioned to close. The memory-poisoning corpus (MINJA 95%+ injection success; MemoryGraft; RSB "defenses largely ineffective") makes integrity urgent for the memory-central pillar.

2. **Composes every existing milestone with almost no new surface.** `MemRecord` already carries `links: Vec<(u8,u64)>` typed DAG edges + a `provenance: u8` tag (mem.rs:812,816); `SkillRecord` already carries `lineage: Vec<u64>` — "the immutable provenance log" (mem.rs:884). The writer capability comes from M11, the tiers from M13, the now-verifiable forget/tombstone from M17, and the chain head **persists + survives reboot** via M20's two-phase-commit `VirtioBlkStore`.

3. **The hash is a textbook pure leaf in the regime `tb-encode` already ships.** `blkfmt` already has Kani-proven `fnv1a64`/`fnv1a32` (blkfmt.rs:123,137), and `route`/`memscore`/`kancell` establish the no-float fixed-point pattern. A canonical encoder + fold accumulator + inclusion verifier is a **low-risk extension of a green pattern, not new math**.

4. **It upgrades M17's silent demote into a verifiable redaction/tombstone** in the ledger — advancing the self-improvement pillar's auditability.

**Runner-up:** a verified *inference-transport* framing leaf + virtio-mmio seam against the deterministic M16 `MockBackend` (`M22: infer-transport OK`). It lost because it advances device-I/O breadth more than the four core pillars, its "real" round-trip terminates at an in-kernel mock loopback (higher hollow-pass exposure), and it doesn't close a convergent #1 literature gap. It is the correct buildable slice of the (network-blocked) real-inference thesis and a strong **M23/M24** candidate. **(Promoted as M30, anti-hollow amended:** the loopback weakness named here became the design constraint — M30's DoD is a HOST-keyed echo verified two ways, kernel-side `verify_echo` AND a cross-process challenge/tag equality against the host peer's own printed line, so the mock-loopback pass this paragraph rejected is structurally impossible; see `M30-infer-transport.md`.)**

---

## 2. Honest scope — what M22 does and does NOT claim

- **Claims: structural tamper-evidence.** Any single-byte mutation to a committed entry's canonical bytes invalidates the recomputed head and its inclusion proof — *Kani-proved* over the fold. Deletion is provable (a tombstone entry, not a silent drop).
- **Does NOT claim: cryptographic collision / second-preimage resistance.** The 256-bit digest is built from two domain-separated FNV-1a-64 lanes — fast, total, no-float, zero-dep, but **not** a cryptographic hash. An adversary who can *choose* inputs is out of scope. A real keyed/crypto hash (e.g. BLAKE3) + an in-VM deterministic-keypair signature over the root is a **tracked successor** (kept out of M22 to stay zero-dep + no-float + inside the proven regime).
- **Linear hash-CHAIN head, not a balanced Merkle tree.** The DAG `parent_ids` are data; the *head* is a fold. Batched balanced-Merkle inclusion proofs would balloon the Kani state space — deferred to a successor.

These limits are stated in the milestone's own assumptions and the boot marker claims only what is proved.

---

## 3. The `tb-encode::prov` leaf (NEW, `#![no_std] #![forbid(unsafe_code)]`, no float, zero-dep)

```rust
/// A fixed, canonical provenance entry. Field order + length-prefixing make
/// canon() injective (distinct entries -> distinct bytes).
pub struct ProvEntry<'a> {
    pub kind: u8,            // write | demote/tombstone | skill-admit | reflect | ...
    pub payload_tok: u64,
    pub tier: u8,
    pub writer_cap_id: u64, // the M11 capability that authorized the mutation
    pub t_created: u64,
    pub parent_ids: &'a [[u8; 32]], // typed DAG edges (length-prefixed in canon)
}

/// Canonical, unambiguous, total length-delimited LE encoding into a fixed buffer.
pub fn canon(entry: &ProvEntry, out: &mut [u8]) -> usize;

/// 256-bit structural digest: two domain-separated, already-Kani-proven FNV-1a-64
/// lanes (NOT cryptographic) + a length domain-separator. Total, wrapping, no float.
pub fn prov_hash(bytes: &[u8]) -> [u8; 32];

/// The running per-agent fold step: head' = chain_mix(head, entry_id).
pub fn chain_mix(head: [u8; 32], entry_id: [u8; 32]) -> [u8; 32];

/// Inclusion verifier: recompute the fold over (leaf, siblings) and accept iff it
/// lands on the committed head. accept == true  <=>  recompute(leaf, siblings) == head.
pub fn verify_inclusion(leaf: [u8; 32], siblings: &[[u8; 32]], head: [u8; 32]) -> bool;
```

Reuses `blkfmt::fnv1a64`/`fnv1a32` (same crate). Bumps `verify-encode.sh` `EXPECTED_HARNESSES` 40 → ~46.

---

## 4. The seam (`crates/tb-hal/src/mem.rs`, 100% safe)

- `MemSubstrate` gains `chain_head: [u8; 32]` and a thin `ledger_append(kind, payload_tok, tier, writer_cap_id, parents)`.
- `ledger_append` is invoked from the **existing** mutation sites: `write()` / `skill_add_class()` / `forget_sweep()`. Each memory mutation appends a typed entry and rolls the head forward. **On M17 forget, the demote emits a TOMBSTONE entry** (`kind = forget`) so deletion is provable, not silent.
- The head is staged into the M20 `VirtioBlkStore` (a reserved superblock field or a dedicated region tag) so it **commits + survives reboot** via the existing two-phase commit — *without* perturbing the M20 `persist_selftest` gen-continuity assertion (the head rides a reserved field; the M20/M21 markers stay byte-identical).

`MemRecord.links`/`provenance` and `SkillRecord.lineage` are the in-place DAG/lineage substrate already present — M22 makes them *verifiable*, it does not add a parallel structure.

---

## 5. Kani proof obligations (~6 new, 40 → ~46), each with a negative control

1. **`canon` injectivity + totality** — `canon` never panics on any field values and is injective on the fixed entry struct (distinct entries → distinct canonical bytes), by the fixed-field + length-prefixed-parents argument. *This is the load-bearing proof and must be written before the kernel seam.*
2. **`prov_hash` totality + no-overflow** — total over any `&[u8]`, wrapping FNV arithmetic, no panic (mirrors the existing `fnv1a64` harness).
3. **`chain_mix` tamper-sensitivity** — flipping any single byte of any `entry_id` changes `chain_mix` output (fold non-degeneracy — the head is a function of every entry), over bounded symbolic inputs. *Negative control:* an identity/constant mix fails this.
4. **`verify_inclusion` soundness** — `verify_inclusion(leaf, siblings, head) == true` implies `recompute(leaf, siblings) == head`; a mutated leaf or sibling drives it to `false`. *Negative control:* a verifier that ignores siblings accepts a forged proof and fails the harness.
5. **canonical round-trip** — `decode(canon(entry)) == entry` for the fixed struct (companion concrete Miri test + symbolic harness, the `blkfmt` round-trip pattern).
6. **head-determinism** — the same entry sequence folds to the same head bit-for-bit (no float, no platform dependence), the determinism/reproducibility guarantee.

---

## 6. Definition of Done — `M22: provenance OK`

The boot self-test `prov_selftest() -> ProvProof` (kernel/src/main.rs, immediately after the M21 block) prints, **in order**, a positive round-trip **witness** line then the marker, both grepped fail-closed by CI:

1. **Witness (non-vacuity, mirrors the M21 `kan:` line):**
   `prov: head=<hex16> entries=<n> tamper-caught=1 inclusion=1`
   — proving the verifiers provably **ran** at boot over real written + demoted records.
2. **Marker** `M22: provenance OK` — emitted **only when** the clean ledger's recomputed head matches the committed head **AND** a known entry's inclusion proof verifies `== true` **AND** an injected single-byte tamper into a *committed* entry is **caught** (head mismatch) **AND** the tampered entry's inclusion proof now **fails**.

**The self-test must:** (a) write N ≥ 3 real Region records and demote one through the actual M17 `forget_sweep` (a tombstone entry); (b) build a genuine inclusion proof and assert `verify == true` on the clean ledger; (c) flip one stored byte and assert **both** head-mismatch **and** inclusion-fail. If the tamper is not detected (or the clean proof does not verify), the marker is **withheld**, the kernel renders a FAIL line with **no** `provenance OK` substring, and it `fail_exit()`s red now (the M20/M21/#65 fail-closed idiom).

**Anti-hollow-pass (the aL2.5/M20/M21 substring lesson):** the run-scripts positively **require** the `prov:` witness line (a marker without it is a hollow pass) and **reject** any `(no ledger, skipped)` variant — there is no device to be absent, so a skip is *never* legitimate here. The tamper must be injected into a *committed* entry's canonical bytes (not an obviously-zero region) and assert **both** head-mismatch and inclusion-failure, so the test exercises the real verifier path, not a constant comparison.

---

## 7. Risks & mitigations

| Risk | Mitigation |
|---|---|
| **Hollow tamper test** the FNV chain would catch trivially | Inject into a *committed* entry's canonical bytes; assert **both** head-mismatch **and** inclusion-proof failure — exercise the real verifier path. |
| **Over-claiming crypto strength** | Claim **structural** tamper-evidence only (any single mutation invalidates the head/proof, Kani-proved); explicitly **not** second-preimage resistance. Crypto hash + signed root is a tracked successor. |
| **Perturbing M20/M21 markers** when persisting the head | Head rides a reserved superblock field / dedicated region tag; the two-phase commit + `persist_selftest` gen-continuity assertion stay untouched; land behind `CARGO_INCREMENTAL=0` + dual-arch 2-green-run discipline. |
| **Kani state-space blowup** from a full Merkle tree | Keep M22 to a **linear hash-chain head** + a simple verified inclusion check; defer balanced-Merkle batch proofs to a successor. |
| **Ambiguous canonical encoder** breaks injectivity | Length-prefixed parent list + fixed field order; the injectivity harness is load-bearing and written **before** wiring the kernel seam. |

---

## 8. Tracked successors (created as tasks)

- **Cryptographic provenance:** replace the FNV-fold digest with a real keyed/crypto hash (e.g. BLAKE3) + an in-VM deterministic-keypair **signature over the root** (second-preimage resistance + authenticity). Likely needs a vetted no_std crypto dep — a dependency-policy decision for Arda. **HASH HALF LANDED (M29 stage C, #99):** `prov_hash` is cryptographic (khash/BLAKE2s-256 unkeyed, zero-dep in-tree, `sec=ASSUMED-FROM-LITERATURE`) since M29-C; the **signed root** (authenticity) remains the open successor half.
- **Balanced Merkle batch inclusion proofs** (logarithmic proofs over a tree, not a linear chain) — a later milestone once the linear ledger is proven.
- **Provenance-attested shared memory / snapshot-migration** — the shared-memory (alt-A) and snapshot (alt-B) successors attest against this ledger; provenance is the correct *first* cut.

---

### References
Mnemonic Sovereignty survey arXiv:2604.16548 · Portable Agent Memory arXiv:2605.11032 (Merkle-DAG ledger, disclaims formal verification) · memory-poisoning: MINJA / MemoryGraft / RSB · in-repo: `crates/tb-hal/src/mem.rs:800-887` (MemRecord.links/provenance, SkillRecord.lineage), `crates/tb-encode/src/blkfmt.rs:123,137` (Kani-proven FNV), `crates/tb-hal/src/mem.rs:307-552` (M20 two-phase commit), `kernel/src/main.rs` (M21 `kan:` witness pattern).
