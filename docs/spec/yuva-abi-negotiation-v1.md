# Yuva↔agent ABI — version negotiation (offer / accept / reject) — v1 SPEC

**Status:** NORMATIVE-SHAPE SPEC, **runtime GATE DEFERRED**
(`negotiation=SPEC-DEFINED-RUNTIME-DEFERRED`). This is the Yuva-ABI **stage B**
version-discovery hardening: it specifies HOW a future peer offers, accepts, or
rejects an ABI version across the two planes of `docs/spec/yuva-abi-v1.md`. It
builds **no runtime mechanism** — nothing in-tree consumes a version token to
admit or reject a peer, and the version token remains a discoverable LABEL
(`version-token=DISCOVERY-ONLY-LABEL-NOT-A-GATE`). It is the frozen TARGET a later
implementation lands against, not the implementation. Keywords **MUST / MUST NOT /
SHALL / SHOULD / MAY** are RFC 2119.

Where this and `yuva-abi-v1.md` disagree, the v1 contract (the as-built registry)
wins; this document only adds the negotiation protocol shape that v1 §11 names as a
successor.

---

## 1. Scope and honest tokens

Stage B (this doc) delivers: (1) the two-axis COMPATIBILITY PREDICATE a peer and
Yuva evaluate; (2) the OFFER / ACCEPT / REJECT exchange and its machine-readable
reason codes; (3) the fixed-width token SHAPES a future codec freezes; (4) the
named seams a runtime gate would plug into.

Stage B is **NOT**: a runtime version GATE (`gate=DEFERRED` — nothing consumes the
token to reject); a new wire codec or a new frame magic (`negotiation-codec=
RESERVED-NOT-BUILT` — no magic is assigned, no `tb-encode` leaf is added); a
handshake channel (`handshake-frame=UNBUILT`); the generic-host degraded runtime
(`backends=DEFERRED`); or the agent extraction (`extraction=DEFERRED`, still gated
on the EL0 trap gate + the `mem/` factorization, `yuva-abi-v1.md` §9). A version
MATCH does not confer sovereignty on a degraded host — the sovereign guarantees are
absent by construction there regardless of a clean negotiation
(`degraded-sovereignty=SURRENDERED-BY-CONSTRUCTION`).

The industry model is **virtio 1.x feature negotiation** (device offers, driver
accepts a subset, unknown bits ignored, a version bit detects legacy) adapted to
Yuva's **two INDEPENDENT version axes** and its **sovereign, host-authoritative**
admission. The critical adaptation: the frame magics, domain labels, and organ
tags are NAMESPACE IDENTITY, not optional features — they are never "downgraded",
only matched or rejected.

---

## 2. What is OFFERED — the discovery surface, reused

The OFFER is not new bytes. Yuva already publishes its full version token over the
two stage-A discovery surfaces (`yuva-abi-v1.md` §5), and the negotiation OFFER IS
that token:

- the boot witness `abi: cap-plane=<M>.<m> wire-plane=<w> method-ceiling=<c>
  rights=<u> magics=<lo>..<hi> organs=<n> planes=2 selfcheck=0x1
  ceiling-closed=0x1 …`, and
- `M_OBJECT_INSPECT=0` on the root capability, reporting `YUVA_ABI_VERSION`.

A conformant peer reads this token BEFORE binding. The `ceiling-closed=0x1`
discovery field (stage B) additionally certifies that the host's method space is
CLOSED at the ceiling — the caps-side `required_right` pin — so a peer knows no
method exists past `method-ceiling` even if a future host bumps `cap_minor`.

`offer=DISCOVERY-TOKEN-REUSED-NO-NEW-BYTES`.

---

## 3. The compatibility predicate — the two axes, evaluated independently

A peer declares the MINIMUM it needs on each axis: cap-plane `(need_major,
need_minor)` and wire-plane `need_wire`. Given the host OFFER `(host_major,
host_minor, host_wire)`:

### 3.1 Cap-plane (M11 capability dispatch) — SEMVER

```
cap_compatible  ⟺  host_major == need_major  ∧  host_minor >= need_minor
```

- **MAJOR must be EQUAL.** A cap-plane MAJOR bump marks a BREAKING change (a
  renumber, a removed method, or a RELAXED `required_right()` — each forced explicit
  by the frozen cross-check, `yuva-abi-v1.md` §12). Different majors are
  incompatible generations: hard REJECT `MAJOR_MISMATCH`, never a downgrade.
- **MINOR must be host >= peer.** A MINOR bump is append-only (a new method / a new
  right, the Linux-syscall rule), so a higher minor is a STRICT SUPERSET. A host at
  minor ≥ the peer's need can serve it; a host BELOW the peer's need lacks methods
  the peer requires: REJECT `MINOR_TOO_LOW` (`detail = need_minor`).

### 3.2 Wire-plane (M25/M28/M30/M33 frame family) — `u8` ceiling

```
wire_compatible  ⟺  host_wire >= need_wire
```

The wire-plane `u8` is the CEILING over the per-frame `ver` bytes. Frame `ver`s are
append-only within a magic, so a host whose ceiling is ≥ the highest `ver` the peer
emits understands every frame the peer sends. A peer emitting a `ver` above the
host ceiling: REJECT `WIRE_TOO_LOW` (`detail = need_wire`).

### 3.3 Frozen IDENTITY — matched, never negotiated

The four wire magics (`FROZEN_WIRE_MAGICS`), the domain labels (`FROZEN_DOMSEP`),
and the organ tags (`FROZEN_ORGANS`) are the NAMESPACE, not features. A peer MUST
use them byte-unchanged. A peer that presents an unknown frame magic, domain label,
or organ tag is REJECTED (`UNKNOWN_MAGIC` / `UNKNOWN_LABEL` / `UNKNOWN_ORGAN`,
`detail = the offending value`) — there is no fallback and no partial bind.

`predicate=CAP-SEMVER(major==,minor>=) ∧ WIRE(ceiling>=) ∧ IDENTITY(exact-match)`.

---

## 4. The exchange — OFFER / ACCEPT / REJECT, host-authoritative

1. **OFFER** (host → peer): the discovery token of §2.
2. **ACCEPT** (peer → host): the peer, having evaluated §3 locally, replies with the
   axes it binds to — `(need_major, need_minor, need_wire)` — and an assertion that
   it uses the frozen magics/labels/organs unchanged. ACCEPT is a PROPOSAL, not a
   grant.
3. **Host re-check** (authoritative): the host re-evaluates §3 against ITS OWN
   frozen registry — it MUST NOT trust the peer's self-assessment (the sovereignty
   rule). Only on a host-side pass is the peer admitted.
4. **REJECT** (either side, fail-closed): on any predicate failure a REJECT carrying
   a reason code (§5). NO binding occurs. On yuva-native the reject fail-closes the
   M18.1 admission; on a host-degraded peer it refuses to bind.

The host is the DEVICE-role offerer AND the final admission authority — a
deliberate divergence from virtio (where the driver accepts unilaterally), because
Yuva is the sovereign and never delegates the admission decision to the peer.
`exchange=HOST-OFFERS-AND-RE-CHECKS / PEER-ACCEPT-IS-A-PROPOSAL / FAIL-CLOSED`.

---

## 5. Reject reason codes (the frozen enumeration)

A future codec freezes these as a closed `u8` enum (append-only, like the organ
tags). Named here so an implementation and a peer agree on the vocabulary:

| Code | Name | Meaning | `detail` |
|---|---|---|---|
| 0 | `OK` | not a reject (accept) | 0 |
| 1 | `MAJOR_MISMATCH` | cap-plane majors differ | peer `need_major` |
| 2 | `MINOR_TOO_LOW` | host `cap_minor` < peer `need_minor` | peer `need_minor` |
| 3 | `WIRE_TOO_LOW` | host `wire` < peer `need_wire` | peer `need_wire` |
| 4 | `UNKNOWN_MAGIC` | frame magic not in `FROZEN_WIRE_MAGICS` | the magic |
| 5 | `UNKNOWN_LABEL` | domain label not in `FROZEN_DOMSEP` | label index |
| 6 | `UNKNOWN_ORGAN` | organ tag past `FROZEN_ORGANS` | the tag |

A REJECT MUST fail-close: no degraded/partial binding on any non-`OK` code.

---

## 6. Token SHAPES — RESERVED, not a codec

The fixed-width shapes a future `tb-encode` leaf would freeze (no magic assigned, no
leaf added at stage B — `negotiation-codec=RESERVED-NOT-BUILT`):

- **OfferToken** (host): `cap_major:u16, cap_minor:u16, wire:u8, method_ceiling:u16,
  rights_union:u32, planes:u8` — the discovery fields, already emitted.
- **AcceptToken** (peer): `need_major:u16, need_minor:u16, need_wire:u8, flags:u8`
  (`flags` reserved zero).
- **RejectToken**: `reason:u8` (§5), `detail:u16`.

When implemented, these would ride a handshake sub-frame; the two candidate homes
are a new reserved frame magic OR a `ver`-negotiation sub-frame under the existing
M30 magic. Neither is chosen here — assigning a magic or adding a codec is
implementation work, deliberately out of stage-B scope.

---

## 7. Where a runtime gate would plug in (named seams, UNBUILT)

- **Cap-plane admission gate:** the M18.1 admission gate (`crates/tb-hal/src/caps.rs`
  `harness_merge` / `carries_approval`). The §3.1 predicate would be an additional
  admission precondition on a binding peer. UNBUILT.
- **Wire-plane handshake:** the M30 `FrameAccum` resync path
  (`crates/tb-encode/src/inferwire.rs`). The ACCEPT/REJECT would ride a handshake
  frame there. UNBUILT.

The runtime GATE is deferred **precisely because** it needs both the handshake frame
(§6) and a consuming admission precondition (this section) — and building an
unexercised gate over a peer that cannot yet separately bind (the EL0 trap gate is
unbuilt) would be anti-hollow. `gate-blockers=HANDSHAKE-FRAME + M18.1-PRECONDITION +
EL0-TRAP-GATE`.

---

## 8. Honest deferrals

- No frame magic is assigned; no `tb-encode` codec leaf is added; no gate consumes
  the token. `negotiation=SPEC-DEFINED-RUNTIME-DEFERRED`.
- The version token stays `DISCOVERY-ONLY-LABEL-NOT-A-GATE` — this doc defines what a
  gate WOULD do, and changes nothing that runs.
- The extraction blockers (EL0 trap gate UNBUILT, `mem/` UNFACTORED) still gate a
  separately-privileged peer actually binding; a clean version match does not lift
  them (`yuva-abi-v1.md` §9).
- On a host-degraded peer, a successful negotiation still surrenders the sovereign
  guarantees by construction — negotiation governs COMPATIBILITY, not sovereignty.

---

## 9. Change control

The reason-code enum (§5) and the two-axis predicate (§3) are append-only once an
out-of-repo peer exists (the `brand`/`abi.rs` freeze discipline). Adding a reason
code is a new tag, never a reuse. Relaxing the predicate (e.g. accepting a MAJOR
mismatch) is a BREAKING change requiring an explicit, reviewed version bump — never
silent.
