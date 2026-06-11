# M29 literature survey — the KEYED-CRYPTO successor (one verified keyed hash, `tb-encode::khash`)

Companion to [`docs/proposals/M29-crypto-mac.md`](../proposals/M29-crypto-mac.md). This survey discharges the research half of the **named successor** that M28 §5 conceded (`mac=KEYED-NONCRYPTO` → `mac=KEYED-CRYPTO`, a verified REAL keyed hash) and the hash half of task **#74** (crypto provenance) with **#75** (Merkle inclusion) in view. Where M29 goes beyond a source it is flagged **[BEYOND]**.

---

## 1. The decision frame (from the project's own constraints)

The successor must be **ONE primitive leaf** serving three consumers (the M23–M28 reuse discipline: no per-consumer crypto):

- **(a)** the M28 dual-key MAC over ~60–200-byte canons (`opframe_rx::compute_mac`, 16-byte tag);
- **(b)** the #74 hash-chain compression replacing the 256-bit structural FNV fold (`prov::prov_hash`, 32-byte digest, **unkeyed**);
- **(c)** #75 Merkle node hashing (unkeyed, domain-separated).

(b) and (c) require **collision resistance with no secret key** — the discriminating axis that eliminates pure-PRF designs immediately. Every candidate below passes the hard gates (`#![no_std]`, `#![forbid(unsafe_code)]`, zero deps, no floats, integer/byte ops only, .rodata ≤ a few KB); they differ in width-fit to the existing constants (`KEY_LEN=32`, `PROV_HASH_LEN=32`, `MAC_LEN=16`), Kani/CBMC formula weight under the #49 discipline, LOC/audit surface, and standardization.

## 2. Candidate comparison

| | **BLAKE2s-256 keyed** | **Ascon (p12: Hash256 + MAC)** | **HMAC-SHA-256** | **KMAC128** | **SipHash-2-4** |
|---|---|---|---|---|---|
| Standard | RFC 7693 (informational); SHA-3-finalist lineage | NIST SP 800-232 (final 2025); MAC: CT-RSA 2024, **not yet in the standard** | RFC 2104 / FIPS 198-1 + 180-4 | FIPS 202 / SP 800-185 | de-facto (Linux kernel); no NIST |
| Security claim | 128-bit collision/preimage/PRF (256-bit digest); keyed mode has a **PRF/MAC proof** ([Luykx–Mennink–Neves, FSE 2016](https://eprint.iacr.org/2016/827)) | 128-bit hash + MAC | 256/128-bit; HMAC-PRF proof (Bellare 2006) | 128-bit | 128-bit **PRF only**, 64-bit native tag |
| Best attack vs full rounds | ~6.75–7.5 / 10, compression-fn/pseudo settings only ([Guo et al., CT-RSA 2014](https://eprint.iacr.org/2013/467); [Espitau–Fouque–Karpman, CRYPTO 2015](https://eprint.iacr.org/2015/515)); full hash + keyed mode unbroken | 4–5 / 12 collisions ([ePrint 2023/1453](https://eprint.iacr.org/2023/1453), [2024/371](https://eprint.iacr.org/2024/371), [2025/1259](https://eprint.iacr.org/2025/1259.pdf)) | 31 / 64 practical collision ([ASIACRYPT 2024](https://dl.acm.org/doi/10.1007/978-981-96-0941-3_8); [ePrint 2024/349](https://eprint.iacr.org/2024/349.pdf)); HMAC itself unbroken | 5–6 / 24 ([J. Cryptology 2019](https://dl.acm.org/doi/abs/10.1007/s00145-019-09313-3)) | none on full; finalization distinguishers ([SAC 2014](https://link.springer.com/chapter/10.1007/978-3-319-13051-4_10)) |
| Collision-resistant for (b)/(c) | yes | yes | yes | yes | **NO — disqualified** |
| Width fit to `KEY_LEN=32`/`PROV_HASH_LEN=32`/`MAC_LEN=16` | **exact / exact / sanctioned truncation** (RFC 7693 §2.1 digest 1..32, key 0..32) | 16-byte key (adapter needed) / exact / truncation | adapter / exact / RFC 2104 §5 truncation | adapter / exact / truncation | 16-byte key / **NO 32-byte digest** |
| State + tables | 64-byte core + IV 32 B + sigma 160 B | 40 B + ~16 B consts | ~40 B + 256 B K-table + 256 B schedule | 200 B + ~192 B RC | 32 B, none |
| Ops | ARX, 32-bit | XOR/AND/NOT/ROT (no adds) | ADD-heavy, 64 steps | XOR/AND/NOT/ROT | ARX, 64-bit |
| Compressions per 65-byte `chain_mix` | **2** (3 keyed) | ~13 p12 calls (rate 64 bits) | ~2 raw; ~7 per HMAC | 1–2 (huge state) | n/a |
| no_std Rust LOC (est.) | 200–300 | 250–350 | 250–300 | 350–450 | 80–130 |
| Official KATs | RFC 7693 App. B + [blake2s KAT set](https://github.com/BLAKE2/BLAKE2) (256 keyed vectors) | [ascon-c](https://github.com/ascon/ascon-c) / NIST ACVP | RFC 4231 / NIST CAVP (best pedigree) | SP 800-185 examples | official 64-vector set |

Eliminations: **SipHash** is the best M28-only MAC ever designed (the two native 64-bit key halves even map onto key_a/key_b) but is PRF-only — with a known key it is trivially collidable, the [authors say explicitly](https://cr.yp.to/siphash/siphash-20120918.pdf) it is not a general hash — so adopting it forces a second primitive for #74/#75 and breaks the one-leaf reuse discipline. **KMAC128** is the same one-primitive story with the largest margin but 200 bytes of state, 24 rounds and the most encoding machinery (cSHAKE bytepad/left_encode) — oversized for 60–200-byte canons in a boot-time kernel leaf. **BLAKE3 keyed** (considered and dropped from the table): fastest, natively keyed, but IETF-draft-only, a deliberately thin 7-round margin, and the largest spec surface (chunk/parent/flag/root tree logic) buying parallelism this workload can never use at 200 bytes.

## 3. The recommendation — BLAKE2s-256 keyed (RFC 7693); runner-up Ascon

**Chosen: BLAKE2s-256 in its native keyed mode.**

1. **Width-exact drop-in.** It is the ONLY candidate that natively fits all three existing constants: 32-byte key == `KEY_LEN`, 32-byte digest == `PROV_HASH_LEN`, spec-sanctioned 16-byte truncation == `MAC_LEN`. No adapter code, no signature churn at the seam (`opframe_rx.rs:67` is a one-line re-export repoint).
2. **Native keyed mode IS the MAC.** RFC 7693's keyed mode (key padded into block 0) is proven a secure PRF/MAC under standard assumptions ([Luykx–Mennink–Neves](https://eprint.iacr.org/2016/827)) — so M29 sheds BOTH the M28 nested-FNV envelope AND an HMAC wrapper: one primitive, one literature-anchored composition, no bespoke nesting needing its own ASSUMED token.
3. **Kani #49 fit.** A 65-byte `chain_mix` input costs **2 BLAKE2s compressions** (~160 G-function evaluations); Ascon-Hash256's 64-bit rate needs ~13 p12 calls (~156 rounds over a 320-bit state) for the same input. The multi-step **fold harnesses** (`kani_prov_inclusion_sound`, the exp/exittel/tpsched/opframe fold tampers) are exactly where the 45-minute prove-encode lane has only ~8–15 min headroom — fewer compressions per fold step is the budget-relevant number, and concrete-input ARX is constant-propagation-cheap for CBMC (the carry-chain penalty bites only on symbolic data; see §5).
4. **Deployment precedent in exactly this niche.** The Linux kernel ships a zero-dependency BLAKE2s (`lib/crypto/blake2s`) as WireGuard's hash/MAC/KDF ([Donenfeld, NDSS 2017](https://www.wireguard.com/papers/wireguard.pdf)); libsodium's `crypto_kdf` derives subkeys with keyed BLAKE2 ([docs](https://doc.libsodium.org/key_derivation)) — precedent for the derive-then-MAC composition M29 uses.
5. **Budgets.** ~200 B .rodata (IV + sigma), 32-bit integer ops only, ~4–6 cpb scalar — a full MAC is 4–6 compressions, tens of microseconds under QEMU TCG.

**Runner-up: Ascon (NIST SP 800-232).** Why not, despite being the 2025 NIST lightweight standard with the cleanest SAT profile (no integer adds): (i) its MAC/PRF parameters ([ePrint 2021/1574](https://eprint.iacr.org/2021/1574), CT-RSA 2024) are **not yet in SP 800-232** — the honesty token would have to carry that caveat, or the MAC be rebuilt from keyed CXOF128 (a bespoke composition); (ii) the 128-bit key mismatches `KEY_LEN=32`, forcing adapter/derive code at the seam; (iii) the 64-bit hash rate multiplies permutation calls ~6× per chain-fold step versus BLAKE2s compressions, hitting the fold harnesses hardest. If local Kani measurement falsifies the BLAKE2s estimate (see proposal §6), Ascon is the named fallback — the leaf API and token spec are primitive-agnostic (`prim=`/`kat=`).

**The honest trade, recorded:** RFC 7693 is an informational RFC, not a NIST standard. M29 chooses width-exact fit + a proven native keyed mode + fold-harness economy over the NIST stamp, and the witness line names the primitive (`prim=BLAKE2S-256`) so the trade is machine-visible, not buried.

## 4. The verified-crypto precedent — what the field PROVES vs ASSUMES

The universal claim boundary across every serious verified-crypto effort, and the convention M29 adopts verbatim:

**PROVEN (machine-checked):** memory safety / absence of UB and panics; functional correctness against a spec "derived directly from the official cryptographic standards" (HACL*'s phrasing); conformance to official test vectors; sometimes source-level secret independence.

**ASSUMED (never proven, explicitly conceded):** the cryptographic security of the primitive itself.

- **Appel, "Verification of a Cryptographic Primitive: SHA-256" ([TOPLAS 2015](https://www.cs.princeton.edu/~appel/papers/verif-sha.pdf))** — the canonical precedent: functional correctness of OpenSSL SHA-256 proven in Coq/VST against FIPS 180-4; collision/preimage resistance explicitly **assumed from cryptanalysis**, "categorically different from proving mathematical hardness assumptions."
- **HACL\*/EverCrypt ([overview](https://hacl-star.github.io/Overview.html), [Project Everest](https://project-everest.github.io/))** — memory safety + functional correctness + secret independence in F*; primitive security never claimed, by design.
- **AWS-LC verification ([aws-lc-verification](https://github.com/awslabs/aws-lc-verification); [CAV 2021](https://assets.amazon.science/4e/23/177acd514c799204ae22f98e193d/verified-cryptographic-code-for-everybody.pdf))** — SAW/Coq/NSym functional-correctness proofs shipped with an explicit machine-readable **caveat ledger** (specific input lengths, CPUs, compiler, unverified error paths) — the strongest precedent for TABOS's honesty-token style.
- **mlkem-native ([SOUNDNESS scoping](https://github.com/pq-code-package/mlkem-native))** — the best modern template: CBMC proves memory/type safety of the full C (including the Keccak permutation — CBMC **can** swallow real round-function code for safety properties); HOL Light proves functional correctness; explicitly NOT proven: "cryptographic security (the underlying math)", binary-level constant-time, fault/EM.
- **Galois SAW on s2n HMAC ([blog](https://galois.com/blog/2016/09/verifying-s2n-hmac-with-saw/), [proof maintenance](https://saw.galois.com/intro/HMACProblem.html))** — equivalence to a Cryptol spec with **bounded loops / fixed sizes**, proofs re-run in CI on every change — the proof-maintenance precedent for the `EXPECTED_HARNESSES` lockstep gate.
- **Kani in AWS practice (correction):** Kani runs on **s2n-quic and Firecracker** (panic-freedom, overflow, differential equivalence with `kani::solver(kissat)` — [harness patterns](https://model-checking.github.io/kani-verifier-blog/2023/05/30/how-s2n-quic-uses-kani-to-inspire-confidence.html)), NOT on aws-lc's crypto cores. Zero cryptographic-strength claims anywhere. A Kani-proven keyed-hash leaf is **novel, not derivative** — no published machine-checked BLAKE2s implementation proof was found.
- **Cryspen ([strengths and limits](https://cryspen.com/post/strengths-and-limitations/))** — real-world bugs cluster in "unverified components — platform stubs, API wrappers, interface code": the **seam** between the verified leaf and the kernel caller deserves its own harness coverage (M29 keeps the M28 conjunctive-gate harnesses untouched for exactly this reason). The field is actively policing overclaim ([ePrint 2026/192, "Verification Theatre"](https://eprint.iacr.org/2026/192.pdf)) — which validates the run-scripts' anti-overclaim guards.

**[honesty boundary]** Nobody in the field proves symbolic collision resistance. The literature-standard claim for `mac=KEYED-CRYPTO` is exactly the project's existing pattern: **a verified implementation of an assumed-secure primitive** — proven: totality/panic-freedom, determinism, functional correctness against official test vectors (concrete inputs), tamper-sensitivity at flip positions; **ASSUMED-FROM-LITERATURE**: collision/preimage/PRF/forgery resistance. The witness token `sec=ASSUMED-FROM-LITERATURE` is not a TABOS-specific compromise — it is what HACL*, Appel, AWS, and Galois all claim, made machine-checkable.

## 5. CBMC/Kani tractability — the #49 trap, re-confirmed against the field

- **Concrete-input, full-width proofs are the field norm, not a cop-out**: SAW fixes sizes; aws-lc enumerates specific lengths/IVs; mlkem-native bounds everything. The M22..M28 discipline (hash inputs CONCRETE, only flip-indexes/predicates symbolic) is how everyone keeps SAT backends alive.
- **Where formulas explode**: symbolic lengths (unbounded unwinding), symbolic data through many rounds (state ~ rounds × width), and — for ARX — **carry chains on symbolic adds**. With concrete inputs, 10 rounds × 8 G-functions is constant propagation: seconds. The one harness where data turns partially symbolic is the flip-index tamper harness; it stays cheap because the symbolic part is the CHOICE over concrete data, with the fallback of pinning flip positions concrete if measurement says otherwise.
- **Never write a symbolic collision/preimage/PRF harness.** No tool in the literature proves these; a vacuous or trivially-bounded "collision harness" would itself be overclaim-by-implication and is banned from the proposal's obligation list.
- Solver hint from the field: `kani::solver(kissat)` gave s2n-quic large speedups; available as a per-harness mitigation.

## 6. Honesty boundary (encoded as witness tokens)

| Property | M29? | Token |
|---|---|---|
| Implementation totality / determinism / panic-freedom (Kani, concrete + short-symbolic) | YES | harness count gate |
| Functional correctness vs RFC 7693 official vectors (Kani + Miri + in-boot fail-closed) | YES | `kat=RFC7693-PASS` |
| Tamper-sensitivity at flip positions (symbolic index, concrete data) | YES | `badmac-rejected=1` |
| A REAL keyed hash replaces the keyed FNV (the M28 named successor) | YES | `mac=KEYED-CRYPTO` |
| Forward-secure key evolution via a real PRF, domain-separated | YES (conditional) | `keyevolve=PRF-DOMSEP` |
| Collision/preimage/PRF/forgery resistance of the primitive | **NO — assumed** | `sec=ASSUMED-FROM-LITERATURE` |
| Side-channel resistance (timing/cache/power/EM) | **NO** (constant-time-SHAPED only; TCG timing is not physically meaningful) | `sidechannel=NOT-CLAIMED` |
| NIST standardization of the primitive | **NO** (RFC 7693 informational) | `prim=BLAKE2S-256` |
| A real human / real enrolment / key management | **NO** (unchanged from M28) | `oracle=SIMULATED-ENROLLED-KEY` |
| Same-epoch nonce consumption | **NO** (unchanged; named successor) | (prose, M28 §5) |
| The command directly activates the cell | **NO** | `kan_active=0` |

## 7. [BEYOND] the literature

A **Kani-proven, `no_std`/forbid-unsafe/zero-dep keyed-hash leaf whose single primitive serves a dual-custody operator MAC, a provenance hash-chain, and Merkle inclusion — with the prove/assume boundary machine-emitted as witness tokens and enforced by anti-overclaim CI guards** — is a synthesis in no single source: the verified-crypto literature proves implementations (HACL*, Appel, mlkem-native) but does not token-encode its assumptions into boot witnesses; the Kani literature (s2n-quic) avoids crypto cores entirely; no machine-checked BLAKE2s implementation proof exists. The construction is standard; the verification packaging is novel; primitive security is **assumed-not-proven** at the `sec=ASSUMED-FROM-LITERATURE` tier — the honest frontier, machine-encoded.

---

### Sources
- [RFC 7693 — BLAKE2 Cryptographic Hash and MAC](https://www.rfc-editor.org/rfc/rfc7693) · [BLAKE2 paper (ACNS 2013)](https://www.blake2.net/blake2.pdf) · [official KAT vectors](https://github.com/BLAKE2/BLAKE2)
- [Luykx, Mennink, Neves — Security Analysis of BLAKE2's Modes of Operation (FSE 2016, ePrint 2016/827)](https://eprint.iacr.org/2016/827)
- [Guo, Karpman, Nikolić, Wang, Wu — Analysis of BLAKE2 (CT-RSA 2014, ePrint 2013/467)](https://eprint.iacr.org/2013/467) · [Espitau, Fouque, Karpman — higher-order differential MitM preimages (CRYPTO 2015, ePrint 2015/515)](https://eprint.iacr.org/2015/515)
- [Backendal, Bellare, Günther, Scarlata — When Messages Are Keys: Is HMAC a Dual-PRF? (CRYPTO 2023, ePrint 2023/861)](https://eprint.iacr.org/2023/861) (the derive-step assumption, named not claimed-around)
- [Bellare, Yee — Forward-Security in Private-Key Cryptography (CT-RSA 2003)](https://eprint.iacr.org/2001/035) · Ma & Tsudik FssAgg (M28 survey)
- [NIST SP 800-232 (Ascon, final)](https://csrc.nist.gov/pubs/sp/800/232/final) · [Ascon spec](https://ascon.isec.tugraz.at/specification.html) · [Ascon-MAC/PRF (ePrint 2021/1574)](https://eprint.iacr.org/2021/1574) · reduced-round attacks: [2023/1453](https://eprint.iacr.org/2023/1453), [2024/371](https://eprint.iacr.org/2024/371), [2025/1259](https://eprint.iacr.org/2025/1259.pdf)
- [RFC 2104 — HMAC](https://www.rfc-editor.org/rfc/rfc2104) · [FIPS 198-1](https://csrc.nist.gov/publications/detail/fips/198/1/final) · SHA-2 attack records: [ePrint 2024/349](https://eprint.iacr.org/2024/349.pdf), [31-step practical collision (ASIACRYPT 2024)](https://dl.acm.org/doi/10.1007/978-981-96-0941-3_8), [bicliques (ePrint 2011/286)](https://eprint.iacr.org/2011/286.pdf)
- [FIPS 202 / SP 800-185 (KMAC)](https://csrc.nist.gov/pubs/sp/800/185/final) · [Keccak third-party cryptanalysis](https://keccak.team/third_party.html)
- [SipHash (Aumasson–Bernstein)](https://cr.yp.to/siphash/siphash-20120918.pdf) · [reference + vectors](https://github.com/veorq/SipHash) · [SAC 2014 differential analysis](https://link.springer.com/chapter/10.1007/978-3-319-13051-4_10) · [Linux kernel SipHash doc](https://www.kernel.org/doc/html/v5.15/security/siphash.html)
- [BLAKE3 IETF draft](https://www.ietf.org/archive/id/draft-aumasson-blake3-00.html) · [boomerang attacks on BLAKE/BLAKE2 (ePrint 2014/1012)](https://eprint.iacr.org/2014/1012.pdf)
- Verified-crypto precedent: [Appel TOPLAS 2015](https://www.cs.princeton.edu/~appel/papers/verif-sha.pdf) · [HACL* overview](https://hacl-star.github.io/Overview.html) · [Project Everest](https://project-everest.github.io/) · [aws-lc-verification](https://github.com/awslabs/aws-lc-verification) · [CAV 2021 (AWS/Galois)](https://assets.amazon.science/4e/23/177acd514c799204ae22f98e193d/verified-cryptographic-code-for-everybody.pdf) · [Galois s2n-HMAC](https://galois.com/blog/2016/09/verifying-s2n-hmac-with-saw/) · [fiat-crypto](https://github.com/mit-plv/fiat-crypto) · [mlkem-native](https://github.com/pq-code-package/mlkem-native) · [s2n-quic Kani patterns](https://model-checking.github.io/kani-verifier-blog/2023/05/30/how-s2n-quic-uses-kani-to-inspire-confidence.html) · [Cryspen limits](https://cryspen.com/post/strengths-and-limitations/) · [Verification Theatre (ePrint 2026/192)](https://eprint.iacr.org/2026/192.pdf)
- Deployment precedent: [WireGuard (NDSS 2017)](https://www.wireguard.com/papers/wireguard.pdf) · [libsodium crypto_kdf (BLAKE2-based)](https://doc.libsodium.org/key_derivation)
