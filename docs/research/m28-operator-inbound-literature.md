# M28 literature survey — the operator INBOUND channel (opframe RX + enrolled-key activation)

Companion to [`docs/proposals/M28-operator-inbound.md`](../proposals/M28-operator-inbound.md). This is **Strand C** of the M26 research-first survey, promoted to its own milestone — the **capstone** that closes the learning loop by delivering the human's authenticated command to the M24 gate. Where M28 goes beyond a source it is flagged **[BEYOND]**.

---

## Freshness — the gap M25 named
- **RFC 9334 — RATS Architecture, §10 (Freshness).** TX-only M25, with `t_logical` a self-asserted epoch, has **no freshness** (a captured transcript replays wholesale). The two grounded remedies: **§10.2 nonce** (verifier-generated random Handle — gold standard, needs verifier state) and **§10.3 epoch-ID** (no trustworthy clock needed). For RX, the operator's **challenge nonce** is the freshness anchor M25 lacked. M28 uses a per-boot epoch + counter nonce echoed inside the MAC'd `ACTIVATE_CMD`.

## Keyed authentication without a crypto library — the honesty boundary
- **Ma & Tsudik, "A New Approach to Secure Logging" (FssAgg), IFIP DBSec 2008 / ACM TOS 2009; Schneier & Kelsey, "Secure Audit Logs…", ACM TISSEC 1999.** The forward-secure aggregate MAC: a one-way **key-evolution** (`key_{i+1} = OWF(key_i)`, forward security) + an aggregated authenticator (truncation resistance). M28's keyed checksum reuses the M22 FNV fold over this *shape* (secret-keyed, key-evolving) — the cryptographic successor to M25's keyless `keyed=0`.
- **RFC 2104 — HMAC.** The **honest yardstick**: a naive `keyed-FNV` / `key‖msg` is **NOT** a secure MAC (length-extension; FNV is not collision/preimage resistant). HMAC's nested construction exists precisely to defeat that. **[honesty boundary]** M28 therefore ships `mac=KEYED-NONCRYPTO` — claiming only enrolled-key replay/truncation resistance vs a **non-adaptive adversary who never sees the key**, never forgery-resistance. `mac=KEYED-CRYPTO` (a verified real keyed hash) is the named successor. **This token is the single most important anti-overclaim in the whole roadmap** — the biggest hollow-marker risk, which is why M28 lands last + alone.

## Replay/injection on a serial command channel
- **Bäumer, Brinkmann, Schwenk, "Terrapin Attack," arXiv:2312.12422 / USENIX Sec 2024 / CVE-2023-48795.** The integrity lesson: unauthenticated optional/handshake messages + sequence numbers not bound/reset at key activation enable prefix-truncation/injection. M28 MUST: bind `seq` + the channel epoch + the live `op_head` **inside** the MAC'd bytes from message zero (never a side label), and fold the challenge/enrolment exchange itself into the authenticated transcript (an unauthenticated pre-MAC frame is the exact Terrapin hole). `opframe`'s seq-folded-into-`canon` design already anticipates this; RX extends it to the *authenticated* setting.

## Authorization for the highest-consequence command
- **Two-person rule / dual-custody (NSA / military lineage); break-glass / N-man-rule emergency access (SOC2 / ISO 27001).** "Activate the learned policy" is the highest-consequence input the system accepts. M28 requires **two distinct enrolled credentials**, each contributing to the MAC, time-bound to the live challenge epoch, tamper-logged into the M22/M25 chain. Even with a non-crypto MAC, the *structure* (fresh + head-bound + dual-authorized + logged) is the sound part.

## Why the human is the only valid oracle (the reason M28 exists)
- **Christiano et al., "Deep RL from Human Preferences," arXiv:1706.03741, NeurIPS 2017; Thomas et al., "Preventing undesirable behavior…" (Seldonian), *Science* 2019; Maurer & Pontil empirical-Bernstein, arXiv:0907.3740.** A self-graded policy has no exogenous ground truth; the human's authenticated command is the **pre-registered, one-shot input** the Seldonian/HCPI gate (M24) needs. **Critically:** M28 makes the command **necessary-not-sufficient** — `KAN_ACTIVE` still requires M24's statistical lower-bound bar (`V_lower(kancell) - V_upper(heuristic) >= MARGIN`). So the command un-blocks the gate's exogenous-oracle input; the gate still enforces the bar. On synthetic data the gate refuses even WITH the command (`kan_active=0` REQUIRED on the witness).

---

## The CI self-test WITHOUT a human (mirroring M24/M25 self-grading)
A **simulated enrolled verifier** holds a compiled-in test key: the OS emits a `CHALLENGE`; the verifier answers a well-formed, fresh, head-bound, dual-authorized `ACTIVATE_CMD`; the self-test asserts ACCEPT-valid + REJECT (stale-nonce / wrong-head / single-credential / flipped-MAC), and that the accepted command sets the pending flag but the M24 gate STILL refuses on synthetic data so `KAN_ACTIVE` stays false. Token `oracle=SIMULATED-ENROLLED-KEY` — proves the auth PLUMBING, never that a real human commanded; key enrolment/management is out of scope (deferred).

## Honesty boundary (encoded as witness tokens)
| Property | M28? | Token |
|---|---|---|
| Enrolled-key replay/truncation resistance vs a non-adaptive no-key adversary | YES | `mac=KEYED-NONCRYPTO` |
| Freshness via challenge nonce + head-binding (Terrapin-aware) | YES | `stale-rejected=1 wronghead-rejected=1` |
| Dual-custody (two-person rule) on activation | YES | `single-cred-rejected=1` |
| Cryptographic forgery-resistance / non-repudiation | **NO** (keyed FNV) | `mac=KEYED-NONCRYPTO` |
| A real human commanded (vs a test key) | **NO** | `oracle=SIMULATED-ENROLLED-KEY` |
| The command directly activated the cell | **NO** (necessary-not-sufficient) | `kan_active=0` |
| A real enrolment ceremony / key management | **NO** (deferred) | (prose) |

## [BEYOND] the literature
Composing FssAgg forward-secure keyed aggregation + RATS nonce freshness + the two-person rule + Terrapin head/seq-binding into a **no-float, verified-leaf, inbound, dual-authorized activation channel anchored to a live provenance head that is necessary-not-sufficient for a Seldonian gate** is a synthesis in no single source. The construction is novel; its security is **asserted-not-proven** at the `KEYED-NONCRYPTO` tier — the honest frontier, machine-encoded as the witness token. Successors: `KEYED-CRYPTO` (a verified real MAC), a real enrolment ceremony, a trustworthy freshness clock.
