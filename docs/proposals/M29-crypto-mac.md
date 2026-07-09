---
type: Design Decision
title: "M29 — the KEYED-CRYPTO MAC (verified khash leaf)"
description: "Replaces M28's non-cryptographic FNV MAC with a BLAKE2s-256 keyed leaf; Kani proves correctness/tamper only, security assumed."
tags: ["m29", "cryptography", "mac", "blake2s", "formal-verification"]
timestamp: 2026-06-11T12:53:51+03:00
status: locked
diataxis: explanation
---

# M29 — the KEYED-CRYPTO MAC (verified `tb-encode::khash` leaf): the M28 named successor lands

**Status:** LANDED (all three stages — A+B: the leaf + the M28 MAC cutover; **stage C: the #74 `prov_hash` → `khash::uhash` cutover, LANDED (#99)** with the compression-budgeted fold-harness restructuring per [`docs/plans/m29-stage-c-plan.md`](../plans/m29-stage-c-plan.md)). Historical note: stage C was first implemented as a scratch swap, MEASURED, and split out per the §5/§8 budget gate — the measured deltas (the cheapest fold-tamper harness alone went 29s → 185s; `kani_prov_chain_mix_tamper`'s 66-fold concrete unroll projects ~20 min at the measured ~9s per concrete BLAKE2s compression) put the prove-encode lane far past the ~42-min target; the per-harness numbers are recorded in the landing PR. · **Pillar:** communication (the M28 MAC honesty upgrade) + memory (the #74 provenance-hash first half) · **Depends on:** M22 (provenance fold), M28 (`opframe_rx` + the `mac=KEYED-NONCRYPTO` concession) · **Tasks:** the M28 §5 named successor; #74 (hash half); #75 (enabler) · **Marker:** `M29: khash-mac OK`

> **One-line:** M28 shipped the inbound dual-custody channel with an honest concession — the MAC is a keyed-but-NON-cryptographic FNV envelope (`mac=KEYED-NONCRYPTO`: no forgery-resistance against a cryptanalytic adversary). M29 lands the named successor: **ONE new verified primitive leaf, `tb-encode::khash` — BLAKE2s-256 (RFC 7693) in its native keyed mode** — consumed by the M28 MAC (`mac=KEYED-CRYPTO`), by `key_evolve` (forward security upgrades from one-way-SHAPED to reduction-backed), and in a second stage by the #74 provenance chain (`prov_hash` body swap). **Honest by construction:** Kani proves totality/determinism/official-KAT correctness/tamper-sensitivity on CONCRETE inputs (the #49 discipline); collision/preimage/PRF/forgery resistance of the primitive is **ASSUMED-FROM-LITERATURE** and the witness token says so. `oracle=SIMULATED-ENROLLED-KEY` and `kan_active=0` stay verbatim — a real hash does not make the key a human nor meet M24's bar.

Synthesis of [`docs/research/m29-crypto-mac-literature.md`](../research/m29-crypto-mac-literature.md) (candidate table, verified-crypto precedent, claim boundary). **Decision: BLAKE2s-256 keyed; runner-up Ascon (NIST SP 800-232)** — see research §3 for the full trade (width-exact fit to `KEY_LEN=32`/`PROV_HASH_LEN=32`/`MAC_LEN=16`, proven native keyed mode = no envelope and no HMAC wrapper, 2 compressions per 65-byte fold step vs Ascon's ~13 rate-8 permutation calls in the budget-critical fold harnesses; the conceded cost: RFC 7693 is informational, not a NIST standard, named on the witness as `prim=BLAKE2S-256`).

---

## 1. Why this milestone, and why ONE leaf

The M28 honesty token `mac=KEYED-NONCRYPTO` is the single most important anti-overclaim on the roadmap: keyed FNV is algebraically transparent (XOR-absorb + invertible odd-prime multiply), and the nested envelope `cmd_hash(cmd_hash(cmd_hash(ka)||cmd_hash(kb))||cmd_hash(canon))` has the right NMAC/HMAC *topology* but a broken *primitive*. M29 swaps the primitive and keeps every seam. The reuse discipline (M23/M25/M26/M27/M28 all consume the M22 fold verbatim) carries over: **one new verified primitive, three consumers** — `opframe_rx` (this MAC), `prov` (#74 hash half), and #75's Merkle nodes later. Per-consumer crypto is rejected.

What KEYED-CRYPTO defeats that KEYED-NONCRYPTO does not: the **adaptive existential forger** (full algebraic knowledge, chosen-message MAC-oracle access, q_v verification attempts) — forgery probability ≤ q_v·2⁻¹²⁸ + Adv_PRF(BLAKE2s), tag t=128 satisfying RFC 2104 §5 / SP 800-107r1 §5.3.4 truncation floors. That bound is **assumption-conditional** (the PRF leg is assumed, never proven — research §4/§5). What NEITHER tier defeats stays conceded in §7.

## 2. The leaf — `crates/tb-encode/src/khash.rs`

`no_std`, `#![forbid(unsafe_code)]`, zero deps, no floats, 32-bit integer/byte ops only; .rodata = IV (32 B) + sigma schedule (160 B). **One-shot API over a bounded contiguous slice — NOT init/update/final** (every existing consumer already passes a single contiguous slice; streaming state would be dead weight for Kani/Miri):

```rust
pub const KHASH_KEY_LEN: usize = 32;   // == opframe_rx::KEY_LEN
pub const KHASH_TAG_LEN: usize = 32;   // == prov::PROV_HASH_LEN

/// RFC 7693 BLAKE2s-256, native keyed mode (key padded into block 0).
pub fn khash(key: &[u8; KHASH_KEY_LEN], msg: &[u8]) -> [u8; KHASH_TAG_LEN];

/// RFC 7693 BLAKE2s-256, unkeyed — the #74 `prov_hash` replacement body.
pub fn uhash(msg: &[u8]) -> [u8; KHASH_TAG_LEN];
```

Domain separation stays EXACTLY where it lives today — the leading domain bytes inside the message (`chain_mix`'s `0xC3`-style prefixes are untouched). The linear fold is NOT baked into khash — #75 reuses the bare primitive for Merkle nodes. `pub mod khash;` joins the lib.rs module list.

## 3. Stage B — the M28 MAC swap (signature-stable, seam-minimal)

- **The seam is one line:** repoint `opframe_rx.rs:67` (`pub use crate::prov::{prov_hash as cmd_hash, ...}`) at khash. Wire format (`CMD_HEADER_LEN=61`), offsets, `decode`, `canon`, `MAC_LEN=16` (now RFC-sanctioned truncation): byte-identical. The four hash-free Kani harnesses (canon_injective / stale_nonce / head_binding / dual_custody) are untouched.
- **`compute_mac` — envelope OUT, derive-then-MAC in** (the sweep-4 decision, simplified by the native keyed mode): the five-hash nested envelope existed only to compensate for an unkeyed primitive. New body, signature `(&[u8;32], &[u8;32], &[u8]) -> [u8;16]` UNCHANGED (so `seal`, `decode_and_verify`, selftests, harnesses all call through):
  ```text
  K_s = khash(key_a, "TABOS-OPCMD-KDF-V1" || key_b)   // order-sensitive: dual custody preserved
  tag = khash(K_s, canon)[..MAC_LEN]
  ```
  Two khash calls per frame (vs five `cmd_hash` passes today). Literature anchors: keyed-BLAKE2 PRF proof (Luykx–Mennink–Neves) for both calls; libsodium `crypto_kdf` precedent for the derive step. **Named, not claimed-around:** the case "one custodian's component adversarially chosen" rests on a dual-PRF-style assumption (Backendal–Bellare–Günther–Scarlata, CRYPTO 2023) — recorded in the research survey, covered by `sec=ASSUMED-FROM-LITERATURE`. Epoch + op_head binding stays where it is (explicit `nonce_echo`/`op_head_bind` fields inside the MAC'd canon + their iff-theorems — defense in depth unchanged).
- **`key_evolve`** becomes `khash(key, "TABOS-KEY-EVOLVE-V1")` — signature unchanged; one-wayness upgrades from one-way-SHAPED to assumed-from-literature; the evolve label is domain-separated from MAC use (`keyevolve=PRF-DOMSEP`). Forward security is now the Bellare–Yee reduction shape, conditional on (a) the PRF assumption (tokened), (b) domain separation (tokened), (c) old-key ERASURE — a stateful-seam property the pure leaf cannot claim, so `opcmd_selftest` gains a snapshot-evolve-zeroize-assert step and the witness gains `oldkey-zeroized=1` (TESTED, not proven). What forward security still does NOT give: post-compromise healing — a stolen K_i yields all K_{j>i} (§7).
- `verify_decoded` / `decode_and_verify` / `seal` / `decode` / `canon` / `opcmd_selftest` logic: ZERO changes beyond the zeroize step (doc comments only). Per-boot key/MAC/challenge VALUES change harmlessly — see §4.

## 4. Stage C — the #74 provenance cutover (head re-baseline protocol)

**Heads WILL change, and that is FREE here** (verified in-tree): heads/MACs/challenges are per-boot, in-RAM, recomputed on both producer and verifier sides within one run; M20 persists memory records, not prov heads; CI builds fresh images; the run-script gates pin FORMAT only (`head=0x[0-9a-fA-F]+`, `challenge=0x[0-9a-fA-F]+`); host tests assert determinism/inequality, never digest literals. There is NO byte-identity baseline to preserve.

**Protocol — FULL CUTOVER, not a parallel chain, not a versioned fold:** replace only the `lane()`+`prov_hash` body (prov.rs ~176–222) with `khash::uhash`; `chain_mix`/`recompute`/`verify_inclusion`/`append`/`head_witness`/`canon` stay byte-for-byte. All of M23/M25/M26/M27/M28 inherit through the existing re-export aliases (`xp_*`, `tel_*`, `sched_*`, `cmd_hash`, the opframe TX fold) with zero per-consumer edits. A parallel keyed chain would double boot-fold cost for nothing; a version byte would version a value nobody persists. The **signed-root half of #74 is a separate signature primitive, explicitly out of khash scope.**

## 5. Landing plan — three CI-green commits

- **(A)** khash leaf + host tests (full official KAT sweep under `cargo test`; boundary-length subset under Miri) + 4 Kani harnesses, NO consumer. **Measure every harness locally before landing.** `EXPECTED_HARNESSES` 80 → 84.
- **(B)** `opframe_rx` swap (§3) + token flip `mac=KEYED-NONCRYPTO → KEYED-CRYPTO` + new `khash:` witness line + run-script guard updates (§6.2) + zeroize step. Re-measure `kani_cmd_mac_tamper`, `kani_cmd_key_evolve`.
- **(C)** prov body swap (§4) + M22-family honesty-text updates. Re-measure the fold harnesses (§6.3). If (C)'s measurements eat the lane headroom, (C) splits to its own follow-up landing — (A)+(B) alone already discharge the M28 named successor. **LANDED (#99)** as the split-out follow-up, with the six fold-harness bodies restructured per the budget plan (option 1) so the lane stays inside the cap.

Doc/honesty fan-out checklist (stages B/C): kernel/src/main.rs (~4360–4431 comment + token literal), scripts/run-x86_64.sh + run-aarch64.sh (M28 blocks), scripts/verify-encode.sh (count + doc block ~182–203), .github/workflows/kani.yml (~141), docs/ARCHITECTURE.md, docs/MILESTONES.md, docs/ROADMAP-V2.md, docs/proposals/M28-operator-inbound.md §5 (successor LANDED note), docs/research/m28-operator-inbound-literature.md claims table, tb-encode lib.rs + opframe_rx.rs module docs, tb-hal verified_leaf.rs + mem/selftests.rs docs, .claude/skills/tabos-milestone/SKILL.md; stage C additionally prov.rs ("NOT cryptographic" block) + the mirrored notes in exp.rs/exittel.rs/tpsched.rs.

## 6. Kani obligations (each with a genuine negative control; the #49 strategy throughout)

**#49 strategy:** hash INPUTS concrete (or ≤2–3 symbolic bytes for totality), only flip-indexes/predicates symbolic; NEVER a symbolic collision/preimage/PRF harness (no tool in the field proves these — a vacuous one would be overclaim-by-implication). Mitigation ladder if any harness exceeds ~5 min locally: pin flip positions concrete → `kani::solver(kissat)` → shrink sibling/length counts → split stage C out.

**6.1 New harnesses (+4, stage A):**
1. **`kani_khash_total_deterministic`** — concrete key; messages at boundary lengths {0, 1, 31, 32, 55, 64, 65, 128}; compute twice, assert equal (determinism + panic-freedom + the two-block path); plus one ≤2-byte fully-symbolic message for totality at the #49 ceiling. *Neg:* assert `khash(k, m64) != khash(k, m65)` where m65 = m64 ‖ 0x00 — a broken finalization counter / padding branch (the classic last-block bug) fails it.
2. **`kani_khash_vectors`** — RFC 7693 Appendix B unkeyed "abc" vector + selected official keyed KATs (key 000102…1f) as concrete asserts; the same vectors re-run under Miri and in-boot (§6.4). *Neg:* in-harness assert that a one-byte-perturbed expected digest does NOT match (guards a vacuous comparator); any wrong rotation/IV/sigma constant fails the KAT.
3. **`kani_khash_tamper`** — concrete key + concrete 65-byte message (forces both blocks); symbolic flip index ranging over ALL 65 message bytes AND all 32 key bytes; assert tag != reference. *Neg:* assert flip-then-flip-back restores the reference tag (proves the harness actually mutates); a constant/length-only stand-in fails the inequality.
4. **`kani_khash_keyed_distinct`** — two concrete keys differing in one byte → distinct tags on the same message; `khash(k, m) != uhash(m)` (keyed and unkeyed modes separated). *Neg:* an implementation that skips the key block fails both asserts.

**6.2 Changed-body, same-asserts (stage B — re-measure):** `kani_cmd_mac_tamper` (the M28 symbolic-flip MAC harness now drives 2 khash calls ≈ 4–6 compressions), `kani_cmd_key_evolve`. Existing negative controls (M28 §4) carry over unchanged.

**6.3 Changed-body, same-asserts (stage C — re-measure, the budget-critical set):** `kani_prov_hash_total`, `kani_prov_chain_mix_tamper`, `kani_prov_inclusion_sound`, `kani_prov_head_deterministic`, `kani_prov_canon_roundtrip` (head leg), and the reuse-fold harnesses `kani_exp_fold_tamper`, `kani_exittel_fold_tamper`, `kani_tpsched_fold_tamper`, `kani_opframe_fold_truncation`, `kani_opframe_intro_binding`. Each fold step becomes 2 BLAKE2s compressions over 65 bytes (~160 G evaluations, concrete). If a multi-sibling harness blows budget, shrink its sibling count first.

**6.4 Anti-hollow in-boot KATs:** the boot self-test recomputes 2–3 official vectors fail-closed BEFORE emitting `kat=RFC7693-PASS` — the token is earned per boot, never compiled-in.

## 7. DoD — witness lines, honesty tokens, guard changes

The boot self-test (QEMU/TCG, both arches) prints, fail-closed:

```
khash: prim=BLAKE2S-256 keylen=32 tag=128 kat=RFC7693-PASS sec=ASSUMED-FROM-LITERATURE sidechannel=NOT-CLAIMED
opcmd: challenge=<hex16> accepted=1 stale-rejected=1 wronghead-rejected=1 single-cred-rejected=1 badmac-rejected=1 oldkey-zeroized=1 kan_active=0 mac=KEYED-CRYPTO kdf=DERIVE-THEN-MAC-DOMSEP keyevolve=PRF-DOMSEP oracle=SIMULATED-ENROLLED-KEY
M29: khash-mac OK
```

(Marker deliberately avoids the substring 'crypto': all crypto claims live ONLY in structured stripped tokens, so the bare-'crypto' prose reject stays maximally strict.)

**Run-script guards (run-x86_64.sh ~330–362, run-aarch64.sh ~344–376 + a new M29 block):**
1. Positive-require regexes: the `opcmd:` witness with all flags `=0x0*1`, `kan_active=0x0+`, and the literal token set above; the `khash:` line in full; the `M29:` marker.
2. Strip-before-grep list grows: `KEYED-CRYPTO`, `BLAKE2S-256`, `RFC7693-PASS`, `ASSUMED-FROM-LITERATURE`, `NOT-CLAIMED`, `DERIVE-THEN-MAC-DOMSEP`, `PRF-DOMSEP` (keeping `SIMULATED-ENROLLED-KEY`; `KEYED-NONCRYPTO` retires) — then the existing case-insensitive rejects (`validated`/`crypto`/`authenticated-human`/`forgery`) STAY.
3. Overclaim reject extends (case-insensitive, post-strip): `provably[- ]secure|unforgeable|collision[- ]resistant|preimage[- ]resistant|constant[- ]time|tamper[- ]proof|quantum|FIPS[- ](certified|validated)|guaranteed|unbreakable` — forgery/collision/preimage resistance are ASSUMED, never prose-claimable.
4. `scripts/verify-encode.sh`: `EXPECTED_HARNESSES` 80 → 84 + doc block rewrite stating the khash harnesses are CONCRETE-VECTOR-ONLY per the #49 discipline (symbolic security claims structurally impossible, by design); `.github/workflows/kani.yml` comment updated in lockstep.

## 8. CI-budget impact estimate

- **prove-encode lane:** currently ~30–37 min of the 45-min cap with 80 harnesses. Stage A adds 4 concrete-input harnesses (estimate: seconds–2 min each; +~2–5 min worst case). Stage B re-measures 2 harnesses (the symbolic-flip MAC tamper is the watch item — mitigation ladder §6 applies). Stage C is the risk concentration: ~10 fold-family harnesses each multiplying per-step cost by ~2 compressions; estimated ×1.5–3 on those bodies. **Gate: every harness measured locally pre-landing; lane target ≤ ~42 min; stage C splits out if measurements say so.**
- **Boot budget:** a MAC = 2 khash calls ≈ 4–6 compressions ≈ tens of µs under TCG; the M22-family boot folds at 2 compressions per entry stay well inside the self-test budget. ~200 B .rodata.

## 9. Honest caveats (conceded — encoded as witness tokens)

- **`sec=ASSUMED-FROM-LITERATURE`** — the load-bearing token. Kani proves totality, determinism, official-KAT functional correctness, and tamper-sensitivity at flip positions — on CONCRETE inputs. Collision/preimage/PRF/forgery resistance of BLAKE2s is ASSUMED from the cryptanalysis literature (best published attacks: ~6.75–7.5 of 10 rounds, pseudo/compression-function settings only). This is the field-standard claim boundary (Appel TOPLAS 2015; HACL*; aws-lc caveat ledger; mlkem-native SOUNDNESS) — verified implementation, assumed primitive. No symbolic collision/preimage harness exists, deliberately.
- **`prim=BLAKE2S-256`** — RFC 7693 is an informational RFC, not a NIST standard. The trade (width-exact fit, proven native keyed mode, fold-harness economy over the NIST stamp) is recorded in research §3; runner-up Ascon (SP 800-232) is the named fallback if local Kani measurement falsifies the cost estimate.
- **`sidechannel=NOT-CLAIMED`** — no timing/cache/power/EM model; TCG timing is not physically meaningful. The code is constant-time-SHAPED (no secret-dependent branches/indices — a code-shape property), never "constant-time".
- **`oracle=SIMULATED-ENROLLED-KEY`** (unchanged) — a compiled-in test key, not a human, not an enrolment ceremony. A real hash does not change this one bit. Key management stays the named successor.
- **`kan_active=0`** (unchanged, REQUIRED) — the command stays necessary-not-sufficient; M24's statistical bar still gates; on synthetic data the cell stays dormant even with a cryptographically-MAC'd command.
- **Same-epoch nonce consumption** (unchanged from M28 §5) — the verifier is pure/stateless; rotate-on-accept in the stateful seam remains a named successor.
- **Forward security is past-only and conditional** — `keyevolve=PRF-DOMSEP` + `oldkey-zeroized=1` (erasure TESTED in the seam, not proven); a stolen K_i still yields all future keys deterministically; post-compromise healing needs fresh entropy (successor, alongside enrolment).
- **The signed root (#74 second half) and #75 Merkle proofs are OUT of M29 scope** — khash is their enabler, not their delivery.

## 10. Roadmap context

M29 closes the loudest honesty concession on the board: the M28 capstone's `KEYED-NONCRYPTO` MAC becomes `KEYED-CRYPTO` through one verified primitive leaf that the provenance chain (#74) and the Merkle successor (#75) reuse — the M22..M28 reuse discipline extended to real cryptography, with the prove/assume boundary machine-emitted instead of implied. Named successors after M29: the #74 signed root (signature primitive), #75 inclusion proofs, rotate-on-accept nonce consumption, real enrolment, a trustworthy freshness clock.

---

### References
Full survey in [`docs/research/m29-crypto-mac-literature.md`](../research/m29-crypto-mac-literature.md). Key: RFC 7693 (BLAKE2) · Luykx–Mennink–Neves FSE 2016 (keyed-mode PRF proof) · Guo et al. CT-RSA 2014 + Espitau–Fouque–Karpman CRYPTO 2015 (attack record) · RFC 2104 / SP 800-107r1 (truncation floors) · Bellare–Yee CT-RSA 2003 (forward security) · Backendal et al. CRYPTO 2023 (dual-PRF, the named derive-step assumption) · Appel TOPLAS 2015 / HACL* / aws-lc-verification / mlkem-native (the prove-vs-assume convention) · s2n-quic Kani patterns (kissat, harness discipline) · NIST SP 800-232 (the Ascon runner-up).
