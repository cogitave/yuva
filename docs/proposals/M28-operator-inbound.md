# M28 — The operator INBOUND channel (opframe RX + enrolled-key activation): the exogenous-oracle CAPSTONE

**Status:** proposed (build) · **Pillar:** communication (the INBOUND half) — and the **closure of the learning loop** · **Depends on:** M22 (provenance fold + live head), M24 (the honest gate + `KAN_ACTIVE`), M25 (the `opframe` TX transcript) · **Marker:** `M28: operator-cmd OK`

> **One-line:** M25 surfaces the OS's decisions to a human over a TX-only transcript; M24's honest gate REFUSES to activate the learned cell because it has no exogenous oracle. M28 builds the **inbound** half: a verified `tb-encode::opframe_rx` leaf — a typed, fixed-width, injective `CmdFrame` over serial RX — by which a human, holding an **enrolled credential**, answers the OS's freshness **challenge** and submits a **dual-authorized** `ACTIVATE_CMD` bound to the live M22 head, so a human can finally **command** the M24 gate activation. This is the **exogenous-oracle CLOSURE** the entire M23→M24→M25→(M26)→M27 arc was built to receive. **Honest by construction:** the MAC is a keyed-but-non-cryptographic forward-secure checksum (`mac=KEYED-NONCRYPTO`), the CI self-test uses a SIMULATED enrolled key (`oracle=SIMULATED-ENROLLED-KEY`) that proves the auth plumbing but **must NOT actually flip `KAN_ACTIVE`** (that would defeat M24's refusal).

This is the synthesis of the M26 research survey's **Strand C** (promoted to its own milestone — see [`docs/research/m28-operator-inbound-literature.md`](../research/m28-operator-inbound-literature.md)). It is the **biggest hollow-marker risk in the whole roadmap** (the keyed-MAC honesty boundary), so it lands last + alone, with the honesty boundary getting full attention.

---

## 1. Why this is the capstone

The four pillars are built: memory (M20–22), learning (M23–24 + M26 producer), communication-outbound (M25), sovereignty (M27). But the learning loop is still **open**: M24's gate REFUSES, correctly, because a self-graded policy has no exogenous oracle (the conceded adversary verdict). M25 surfaces the decisions to a human (the only valid oracle — Christiano RLHF arXiv:1706.03741; Thomas Seldonian *Science* 2019) but is **TX-only** — the human can read, not command. M28 delivers the **command**: the channel + auth by which a human's adjudication becomes the M24 gate's pre-registered exogenous input. It **closes the loop**. (Honest scope: the verified leaf rejects a nonce from a *different* challenge epoch, but it is pure/stateless — it does NOT consume the nonce on accept, so the leaf claims per-epoch staleness rejection, **not** one-shot/per-challenge consumption; nonce consumption in the stateful seam is a named successor — see §5.)

---

## 2. The design (cited, mechanism by mechanism)

### 2.1 The inbound frame — a verified `tb-encode::opframe_rx` leaf
A new leaf (no_std, forbid-unsafe, no-float, zero-dep, Kani-proven), the RX dual of M25's `opframe`. A typed, fixed-width, injective `CmdFrame { magic, ver, kind, reserved, nonce_echo:u64, op_head_bind:[u8;32], seq:u64, payload_len, payload, mac:[u8;MAC_LEN] }` with **fail-closed-total** `decode` (reject bad magic/ver/reserved/kind, truncated payload, unknown kind) exactly like `opframe::decode`. Kinds: `CHALLENGE_REQ`, `ACTIVATE_CMD`, `NOP`.

### 2.2 Freshness — a challenge NONCE (RATS RFC 9334 §10)
The OS emits (on the M25 TX channel) a `CHALLENGE` frame carrying a fresh per-boot epoch + a counter (the verifier-nonce model RFC 9334 §10.2 — the freshness M25 explicitly LACKED). A valid `ACTIVATE_CMD` MUST echo that nonce **and** bind the current live M22/`op_head` into the MAC'd bytes (`op_head_bind`), so a command captured from a different boot / transcript position fails (the Terrapin seq/epoch-binding lesson, arXiv:2312.12422 — bind from message zero, inside the MAC'd bytes, never a side label).

### 2.3 Keyed verification — honestly scoped (`mac=KEYED-NONCRYPTO`)
A **keyed forward-secure aggregate checksum** over the FssAgg key-evolution shape (`key_{i+1} = mix(key_i)`, one-way), reusing the M22 FNV fold but now **secret-keyed**. It claims *enrolled-key replay/truncation resistance against a non-adaptive adversary who never sees the key* — explicitly **NOT** cryptographic forgery-resistance (a naive keyed-FNV / `key‖msg` is NOT a secure MAC — RFC 2104; the honesty token says so). The successor (`mac=KEYED-CRYPTO`, a verified real keyed hash) is named. This honesty distinction is the load-bearing anti-overclaim of M28.

### 2.4 Dual-authorized activation (two-person rule)
`ACTIVATE_CMD` — the highest-consequence input the system accepts — requires **TWO distinct enrolled credentials** (the dual-custody / break-glass rule; NSA two-person lineage, SOC2/ISO 27001 emergency-access), each contributing to the MAC, time-bound to the live challenge epoch, and tamper-logged into the M22/M25 chain. Even with a non-crypto MAC, the *structure* (fresh + head-bound + dual-authorized + tamper-logged) is the sound part.

### 2.5 The activation seam — fail-closed, M24-respecting
A valid, fresh, dual-authorized `ACTIVATE_CMD` sets a **pending-activation** flag that the M24 gate reads as ONE of its conjunctive inputs — it does NOT directly flip `KAN_ACTIVE`. `KAN_ACTIVE` still requires M24's real-data verdict (`V_lower(kancell) - V_upper(heuristic) >= MARGIN` + envelope-no-widening) AND the human command. So the human command is **necessary, not sufficient** — it un-blocks the gate's exogenous-oracle input, the gate still enforces the statistical bar. On synthetic data the gate still refuses, so `KAN_ACTIVE` stays false even WITH the command (the designed, correct outcome).

---

## 3. DoD — `M28: operator-cmd OK` (the SIMULATED enrolled-key self-test)
The boot self-test (QEMU/TCG, no human/network/hw) plays a **simulated enrolled verifier** holding a fixed test key: the OS emits a `CHALLENGE`; the verifier answers with a well-formed, fresh, head-bound, **dual-authorized** `ACTIVATE_CMD`; the self-test asserts the RX path **ACCEPTS** the valid command AND **REJECTS** (a) a stale-nonce replay, (b) a wrong-head command, (c) a single-credential command (dual-custody negative control), (d) a flipped-MAC command. **CRITICALLY** the accepted command sets the pending flag but the M24 gate is then run on the synthetic data and STILL refuses, so `KAN_ACTIVE` stays `false`. It prints, fail-closed:
```
opcmd: challenge=<hex16> accepted=1 stale-rejected=1 wronghead-rejected=1 single-cred-rejected=1 badmac-rejected=1 kan_active=0 mac=KEYED-NONCRYPTO oracle=SIMULATED-ENROLLED-KEY
M28: operator-cmd OK
```
The run-scripts require the witness with all `=1` flags + `kan_active=0` + both honesty tokens; reject any `validated`/`crypto`/`authenticated-human` overclaim. `EXPECTED_HARNESSES` 74 → ~80.

---

## 4. Kani obligations (each with a negative control)
1. **canon injectivity + totality + decode fail-closed** (mirror `opframe`).
2. **stale-nonce rejection** — the REAL gate (`verify_decoded`, the pure conjunctive core `decode_and_verify` delegates its verdict to) returns the precise `RejectStale` iff the echoed nonce mismatches the symbolic challenge, and an `Accept` proves freshness; plus the kind conjunct dominates (any non-ACTIVATE kind is `NotActivate`). *Neg:* deleting the freshness branch makes the iff-assert fail — a stale echo would Accept.
3. **head-binding rejection** — the gate returns the precise `RejectWrongHead` iff the bound head differs from a FULLY SYMBOLIC live head (every cross-boot head), and an `Accept` proves the heads matched. *Neg:* deleting the head-binding branch accepts a cross-boot command.
4. **dual-custody + Accept-iff-all** — with kind/freshness/head pinned true, the verdict is EXACTLY determined by the remaining symbolic conjuncts: `RejectSingleCred` iff `cred_a == cred_b`, `RejectBadMac` iff distinct-creds AND MAC-failed, `Accept` iff distinct-creds AND MAC-passed (the conjunctive-gate theorem). *Neg:* a one-credential check or an ignored MAC makes the corresponding iff fail.
5. **MAC tamper-sensitivity** — a single-byte flip of the MAC'd bytes (or the MAC) is rejected (the keyed fold is sensitive). *Neg:* a constant/identity MAC accepts a forgery.
6. **key forward-evolution** — `key_{i+1} = mix(key_i)` is one-way-shaped + deterministic (the FssAgg property, structurally).

---

## 5. Honest caveats (conceded — encoded as witness tokens)
- **`mac=KEYED-NONCRYPTO`** — a keyed FNV is NOT a cryptographic MAC; no forgery-resistance against a cryptanalytic / key-recovering adversary. Claims only enrolled-key replay/truncation resistance vs a non-adaptive no-key adversary. Successor: a verified real keyed hash (`mac=KEYED-CRYPTO`).
- **`oracle=SIMULATED-ENROLLED-KEY`** — the CI verifier is a compiled-in test key, NOT a real human + NOT a real enrolment ceremony. Key management / enrolment is out of scope (deferred). The marker proves the auth PLUMBING, never that a human commanded.
- **The command never directly activates the cell** — `kan_active=0` is REQUIRED on the witness; the human command is necessary-not-sufficient (M24's statistical bar still gates). On synthetic data the cell stays dormant even with the command.
- **No real freshness clock** — the nonce is a per-boot epoch + counter (RFC 9334 §10.3 epoch-ID-style), not a trusted wall clock.
- **No nonce consumption (same-epoch replay)** — `decode_and_verify` is a PURE, STATELESS verifier: it rejects a nonce from a different challenge epoch (`RejectStale`), but it does NOT consume the nonce on Accept, so an identical valid wire re-verifies within the same epoch. The leaf claims per-epoch staleness rejection, NOT one-shot/per-challenge consumption. (Not an activation bypass — `KAN_ACTIVE` stays `false` regardless; M24 still gates.) Successor: rotate-on-accept / a used-nonce high-water mark in the stateful seam.

---

## 6. Where M28 goes beyond the literature
Composing **FssAgg forward-secure keyed aggregation + RATS nonce freshness + the two-person rule + the Terrapin head/seq-binding** into a **no-float, verified-leaf, inbound, dual-authorized activation channel anchored to a live provenance head, that is necessary-not-sufficient for a Seldonian gate** is a synthesis present in no single source. The construction is novel; its security is *asserted-not-proven* at the `KEYED-NONCRYPTO` tier — the honest frontier, machine-encoded as the witness token.

---

## 7. Roadmap context
M28 closes the M23→M28 learning-loop + communication arc: the OS records (M23), honestly refuses to self-activate (M24), surfaces decisions to a human (M25), records its own workload (M26), schedules sovereignly (M27), and now **receives the human's authenticated command** (M28) — the exogenous oracle that lets the gate ever clear, on real data, with a human in the loop. The keyed-crypto MAC + a real enrolment ceremony + a trustworthy freshness clock are the named successors.

---

### References
Full survey in [`docs/research/m28-operator-inbound-literature.md`](../research/m28-operator-inbound-literature.md). Key: RFC 9334 (RATS §10 freshness) · Ma & Tsudik (FssAgg) · Schneier & Kelsey (TISSEC 1999) · RFC 2104 (HMAC, the honest yardstick) · Terrapin (arXiv:2312.12422) · two-person rule / break-glass (SOC2/ISO 27001) · Christiano RLHF (arXiv:1706.03741) · Thomas Seldonian (*Science* 2019) · Maurer-Pontil empirical-Bernstein (arXiv:0907.3740).
