# Yuva↔agent ABI — v1 (the normative contract)

**Status:** NORMATIVE SPEC, stage A (`abi=IN-REPO-SPEC-AT-STAGE-A`). Promoted from
`docs/proposals/yuva-abi.md` (the proposal, which remains as the rationale +
adversarial-review record). This document is the binding contract; where the two
disagree, THIS document is as-built and wins. Keywords **MUST / MUST NOT / SHALL
/ SHOULD / MAY** are used in the RFC 2119 sense.

This is the versioned, agent-agnostic contract across which a conformant agent
speaks to Yuva. It is FORMALIZED from the existing seams — it invents no new
mechanism, moves no code, and rewrites nothing. It is the PRECONDITION for the
future `cogitave/cogi` extraction, NOT the extraction.

---

## 1. Scope and honest tokens

Stage A delivers: (1) this spec; (2) the frozen-literal registry leaf
`crates/tb-encode/src/abi.rs` + its two cross-check sites; (3) the discoverable
version LABEL (`M_OBJECT_INSPECT` root report + the `abi:` boot witness); (4) the
frozen conformance-vector skeleton + the mini-agent + the additional
`abi-conformance` lane; (5) the `Cogi` lint over `kernel/src` + `crates/`.

Stage A is **NOT**: the extraction (`extraction=DEFERRED-SEPARATE-MILESTONE`); a
rewrite (`this-spec=CONTRACT-NOT-REWRITE`); the pluggable generic-host runtime
(`backends=DEFERRED`); a clean code cut of the seams (two named blockers, §9);
runtime feature-negotiation or version GATING (`negotiation=SPEC-ONLY-AT-STAGE-A`,
`version-token=DISCOVERY-ONLY-LABEL-NOT-A-GATE`); or a signed ABI attestation
(`abi-attestation=UNSIGNED-KEYLESS`, `sec=ASSUMED-FROM-LITERATURE`).

---

## 2. The two planes

The agent and Yuva are coupled across two distinct ABI planes that exist in the
code today. This spec names and version-stamps them; it does not create them.

### 2.1 Plane 1 — in-process capability dispatch (M11)

`crates/tb-hal/src/caps.rs`. A conformant agent runs as an M12 `AgentProcess` and
invokes numbered, rights-masked methods against the kernel's `HandleTable`. The
surface is a CLEAN chokepoint: zero ambient authority, fail-closed, generation-
checked, rights-masked. The method space is CLOSED (`33+` is `SysStatus::
BadMethod`).

- Method numbers `M_OBJECT_INSPECT=0 … M_MODEL_INVOKE_BYTES=32` (`caps.rs:189-264`).
- `required_right()` maps each method to exactly one `Rights` bit (`caps.rs:268-298`).
- The `Rights` bitset (`tb-caps-core::rights`, 13 named single bits + `NONE`).

A conformant agent MUST agree with Yuva on the method numbers, the
`required_right()` mapping, and the `Rights` bit values. These are frozen in
`abi::FROZEN_METHODS` + `abi::FROZEN_RIGHTS` (§4).

### 2.2 Plane 2 — cross-process wire (M25/M28/M30/M33)

The agent's organs speak serial-framed, khash-authenticated frames to host-side
peers. The namespace is four u16 frame magics, each carrying a per-frame `ver`
byte, under `YUVA-*` domain-separator labels:

| Magic | Name | Frame | Source |
|---|---|---|---|
| `0x5956` | `MAGIC_OPFRAME` | M25 operator transcript | `brand` |
| `0x5957` | `MAGIC_OPFRAME_RX` | M28 operator inbound command | `brand` |
| `0x5958` | `MAGIC_INFERWIRE` | M30 inference transport | `brand` |
| `0x5959` | `MAGIC_ATTEST` | M33 attestation statement | `brand` |

As of Yuva-ABI **stage B**, ALL FOUR magics are single-sourced in `brand`: the
former standalone `ATTEST_MAGIC=0x5959` literal in `tb-encode::attest` was unified
into `brand::MAGIC_ATTEST` (byte-identical `0x5959`, `= MAGIC_OPFRAME + 3`, pinned
by a `brand` known-answer test), and `tb-encode::attest::ATTEST_MAGIC` now
RE-EXPORTS it. `brand`'s KAT covers all four (pairwise distinct + disjoint from the
note-type half); `abi::FROZEN_WIRE_MAGICS` enumerates all four together with its own
four-way disjointness const-assert and cross-checks each against the live `brand`
constant. Domain labels are frozen in `abi::FROZEN_DOMSEP` (`wire-labels=
ALREADY-YUVA` — the historical "TABOS-*" leak is CLOSED). A conformant agent MUST
use these magics and labels unchanged.

### 2.3 The spine — the organ registry (M38)

`crates/tb-encode/src/conductor.rs`: `Organ { RetrievalOverMemory=0x00,
LocalM32=0x01, ExternalMock=0x02 }`, a closed append-only `u8` enum. The `Organ`
tags ARE the enumerated agent-organ contract; a new organ is a NEW tag, never a
renumber. Frozen in `abi::FROZEN_ORGANS`.

---

## 3. The two version axes

`abi::YUVA_ABI_VERSION` (`abi.rs`, the single source of truth) carries two
INDEPENDENT axes (the Firecracker independent-version discipline):

- **Cap-plane SEMVER** `(cap_major: u16, cap_minor: u16)` — governs Plane 1.
  A MINOR bump is REQUIRED on an append-only method or rights addition (backward
  compatible, the Linux-syscall rule). A MAJOR bump is REQUIRED — and MUST NOT be
  silent — on any breaking change: a renumber, a removed method, or a RELAXED
  `required_right()`. The frozen cross-check (§4) forces the bump to be explicit.
- **Wire-plane `u8`** (`wire`) — governs Plane 2 (the frame magics + per-frame
  `ver` bytes + labels). A new frame `ver` bumps this axis only.

Today's snapshot: `cap-plane = (1, 0)` (methods `0..=32`), `wire-plane = 1`
(`INFER_VER=1`, `ATTEST_VERSION=1`). The two axes move independently: a memory
method addition bumps `cap_minor` and leaves `wire` untouched, and vice versa.

---

## 4. The frozen-literal registry and its enforcement

`crates/tb-encode/src/abi.rs` holds a FROZEN INDEPENDENT LITERAL copy of every
load-bearing seam constant: `FROZEN_METHODS` (`(id, name, required_right_bits)`),
`FROZEN_RIGHTS` (`(bits, name)`), `FROZEN_WIRE_MAGICS` (`(u16, name)`, all four),
`FROZEN_DOMSEP` (labels), `FROZEN_ORGANS` (`(tag, name)`), and
`YUVA_ABI_VERSION`. The copy is DELIBERATE: a re-export would make the cross-check
a tautology (`X == X`, fails on nothing). The copy is the mechanism.

Enforcement is SPLIT across two sites by the crate boundary — `tb-encode` is
UPSTREAM of `tb-hal::caps`, so a `tb-encode` test cannot see `caps.rs`. Both
halves are genuine drift detectors:

### 4.1 Site A — the `tb-encode` host cross-check (wire magics, labels, organs)

`abi::abi_snapshot` (`#[cfg(test)]` in `abi.rs`) asserts each frozen wire magic
equals its LIVE `brand::MAGIC_*` constant (all four, incl. `brand::MAGIC_ATTEST` —
stage B; it also asserts the `attest::ATTEST_MAGIC` re-export resolves to the same
`brand` source), each frozen domain label equals its LIVE `brand::DOMSEP_*` bytes,
and each frozen organ tag equals the LIVE `conductor::Organ` tag/decode (and count
`== N_ORGANS`), plus the four-way live-magic disjointness. It runs under `cargo test
-p tb-encode` / `cargo miri test -p tb-encode` — the existing CI host-test lane
(`miri.yml`). A renumbered magic, a relabelled separator, or a renumbered organ
FAILS it. (Verified: FAILS on a seeded live-`MAGIC_ATTEST` renumber and on a seeded
frozen relabel.)

### 4.2 Site B — the in-kernel boot self-test (methods, `required_right`, rights)

The method numbers, the `required_right()` mapping, and the `Rights` bits live in
`tb-hal::caps` (downstream of `tb-encode`, and `required_right()` is private), and
`tb-hal` is `#![no_std]` and does not host-compile, so this half CANNOT be a
`tb-encode` host test. It is instead `caps::abi_registry_selfcheck()`, which
consumes `abi::FROZEN_METHODS` + `abi::FROZEN_RIGHTS` and asserts, against the
LIVE `caps` constants + the private `required_right()` + the live `Rights::*`
bits: (1) each frozen method id equals its live named constant (a renumber
FAILS); (2) each frozen `required_right_bits` equals `required_right(id).bits()`
(a RELAXED right — e.g. `M_EMIT_EXTERNAL` weakened to `NONE` — FAILS); (3) the
frozen ceiling equals `max(id) == 32`, the live method count over `0..=ceiling`
matches the frozen row count, AND — the stage-B `required_right` pin
(`AbiSelfcheck::CeilingOpen`) — no live method is registered in a bounded window
ABOVE the ceiling, so an addition-past-ceiling (`ceiling+k`, invisible to both the
`0..=ceiling` count scan and the frozen-side `max(id)` check) now FAILS on the LIVE
side too; (4) each frozen right bit equals its live `Rights::*`. The kernel calls it
once at boot on BOTH arches, asserts success, and emits the `abi:` witness (with the
`ceiling-closed=0x1` discovery field, §5). A drift therefore reddens EVERY boot on
both arches — a STRONGER enforcement than a host unit test.

> **Deviation from the proposal (§3.2), noted.** The proposal specified the whole
> cross-check as a single host `#[test]`. The crate boundary + `tb-hal`'s
> non-host-compilability make a host test of the method/rights half impossible
> without moving code (which the contract forbids). Splitting enforcement — host
> test for Plane 2 + brand, in-kernel boot self-test for Plane 1 — preserves
> "moves no code", keeps `required_right()` private, and is strictly stronger for
> the Plane-1 half. `enforcement=SPLIT-HOST-TEST(WIRE)+IN-KERNEL-SELFTEST(CAPS)`.

### 4.3 What the freeze does and does NOT catch

The cross-check catches a renumber, a relaxed `required_right()`, an
addition-past-ceiling, a relabelled domain separator, and a renumbered magic/
organ. It does NOT catch every semantic change under a STABLE signature (a
behavioral change to a method that keeps its number and right).
`freeze=CROSSCHECK-CATCHES-SIGNATURE-BREAKS-NOT-ALL-SEMANTICS`.

---

## 5. Runtime discovery — a LABEL, not a GATE

An agent discovers the host ABI version over two zero-risk surfaces:

- The boot witness line `abi: cap-plane=1.0 wire-plane=1 methods-verified=0x17
  method-ceiling=0x20 rights=0x1fff magics=0x5956..0x5959 organs=0x3 planes=2
  selfcheck=0x1 ceiling-closed=0x1 inspect-root=0x1
  negotiation=SPEC-DEFINED-RUNTIME-DEFERRED
  version-token=DISCOVERY-ONLY-LABEL-NOT-A-GATE`, emitted at a stream position that
  is OUTSIDE every required cumulative marker grep. As of stage B the `negotiation`
  token reads `SPEC-DEFINED-RUNTIME-DEFERRED` (the offer/accept/reject protocol is
  now specified in `docs/spec/yuva-abi-negotiation-v1.md`, but NO runtime gate is
  built), and `ceiling-closed=0x1` certifies the closed-method-space pin (§4.2).
- `M_OBJECT_INSPECT=0` on the root capability, wired to REPORT
  `YUVA_ABI_VERSION`.

Stage A ships DISCOVERY only, and stage B keeps it discovery-only: nothing consumes
the token to REJECT a mismatched agent — there is one version and no rejection path.
A version cannot GATE until
there is an offer/accept + reject mechanism (stage B).
`version-token=DISCOVERY-ONLY-LABEL-NOT-A-GATE`.

---

## 6. Conformance — a FROZEN skeleton a mini-agent passes

Agent-agnosticism is demonstrated POSITIVELY: a MINI/MOCK conformant agent that
shares NO code with the resident agent binds through the two planes and passes
FROZEN golden vectors. The vectors MUST be committed literals, not recomputed at
test time (a recomputed "golden" is a round-trip identity that catches nothing).
Three families:

1. **Capability-dispatch vectors** — `(manifest, method, args) → SysStatus`,
   expected `SysStatus` pinned as a literal, INCLUDING NEGATIVE vectors: a
   manifest LACKING `EMIT_EXTERNAL` invoking `M_EMIT_EXTERNAL` MUST expect
   `Denied` as a frozen literal, so a relaxed admission returning `Ok` FAILS the
   lane. This family runs in-kernel (Plane 1 is `tb-hal`, not host-buildable).
2. **Wire-codec vectors** — `frame → canon bytes + echo tag`, reusing the landed
   `inferwire` encode/verify and the pinned-vector literal idiom. Host-runnable.
3. **Conductor-invariant vectors** — `transcript → head / turns / verdict`,
   pinned against the landed `conductor` fold. Host-runnable.

**Honest ceiling.** Because the EL0 trap gate is unbuilt (§9), the mini-agent
runs IN-PROCESS in the SAME binary. A pass DEMONSTRATES the surface is SPEAKABLE
by non-resident in-process code — NOT that a separately-compiled/separately-
privileged agent can bind, and NOT that the resident agent is cleanly
extractable. `conformance-ceiling=SPEAKABILITY-BY-IN-PROCESS-CODE-NOT-EXTRACTABILITY`.

The additional `abi-conformance` lane (offline, deterministic, no network/secret/
hardware) runs the vectors and emits `ABI: conformance OK planes=2 vectors=K` on
the LANE SUMMARY only — structurally outside every guest-serial cumulative grep. A
skip-form or a single-plane pass FAILS the lane by name.

---

## 7. The Yuva-optional axis — SOVEREIGN vs DEGRADED

The agent is specified to run sovereign on yuva-native or degraded on a generic
host. Stage A specifies only the SCHEMA SYMMETRY; it builds no degraded runtime.

| Binding | Transport | Guarantees | Status |
|---|---|---|---|
| **YUVA-SOVEREIGN** | M11 caps in-process + M30 serial-frame, khash-auth | full: capability confinement, provenance fold, signed head | REAL TODAY |
| **HOST-DEGRADED** | the SAME schemas over a POSIX socket/stdio | sovereign guarantees ABSENT | `backends=DEFERRED` — schema symmetry only |

On a generic host the sovereignty pillar is SURRENDERED BY CONSTRUCTION (no
capability kernel, no verified fold). Stage A names this so the "Jarvis" story is
never mistaken for a sovereign one. `substrate=YUVA-SOVEREIGN-REAL|HOST-DEGRADED-SPEC-ONLY`.

---

## 8. Terminology

The load-bearing seams (the capability surface, the M12 hosting socket) are
agent-neutral: generic `agent-a..d` principals, the word "agent", no "Cogi". As
of the merged `agent-terminology` work, `kernel/src/bootreport.rs` is ALSO
neutralized (`View::Agent`, `yuva.view=agent`, "agent view", "The agent runtime
is resident"). The only residual "Cogi" is the host-side greeting fixture in
`tools/xport-harness/src/live.rs` (historical witness content, not a coupling).

The in-repo neutral term is **agent**. A lint (`scripts/check-agent-neutral.sh`)
bans `Cogi` in `kernel/src` + `crates/` (both already clean), with the `live.rs`
greeting fixture a NAMED historical-witness exception (an operator judgment call;
neutralizing it is deferred). The `cogitave/cogi` project MAY be discussed by
name; the in-repo neutral term is never "Cogi".

---

## 9. Separability — honest about TWO blockers

The seams are SPEC-ABLE at stage A but not cleanly CUTTABLE, for two named
reasons:

- **Plane-1 privilege blocker.** The capability surface dispatches in-kernel; the
  EL0 trap gate that would let a separately-privileged agent enter is UNBUILT
  (`caps.rs:240,249`). `plane1-extraction-blocker=EL0-TRAP-GATE-UNBUILT`.
- **Memory-cut blocker.** The M20 storage engine and the M13 memory organ cohabit
  `crates/tb-hal/src/mem/` unfactored — the memory seam (`M_MEM_*`) is spec-able
  but not cuttable until the factorization lands (shared with boot-profiles stage
  B). `mem-engine-organ=UNFACTORED-SHARED-BLOCKER`.

`separability=EXECUTION-ADMISSION-LEVEL-AT-STAGE-A`,
`extraction-blockers=EL0-TRAP-GATE + MEM-FACTORIZATION`.

---

## 10. Zero CI regression

The required cumulative M0..M38 + M33 two-boot marker chain is BYTE-UNTOUCHED on
both arches; the cumulative tail stays `M38: conductor OK turns=6 organs=3
verdict=ACCEPT`. The three required verifier scripts change ZERO lines. The
`abi:` witness and the `ABI: conformance OK` marker are additive and stream-
positioned outside every cumulative grep. The Kani harness pin
(`EXPECTED_HARNESSES_TOTAL`) is UNCHANGED — the registry cross-checks are a host
unit test + an in-kernel boot self-test, not Kani harnesses
(`kani-budget=ZERO-VECTOR-HARNESS` at stage A).

---

## 11. Successors (named, not blocked-on)

- **Version-negotiation SPEC — stage B, LANDED as a spec** (the offer/accept/reject
  protocol + the two-axis compatibility predicate + reject reason codes):
  `docs/spec/yuva-abi-negotiation-v1.md`. The runtime GATE it targets stays DEFERRED
  (`negotiation=SPEC-DEFINED-RUNTIME-DEFERRED`) — no gate consumes the token, which
  remains a discoverable LABEL. The gate's own blockers are the unbuilt handshake
  frame + the M18.1 admission precondition + the EL0 trap gate.
- The generic-host DEGRADED runtime — `backends=DEFERRED`.
- The `cogitave/cogi` repo split + code move — `extraction=DEFERRED-SEPARATE-MILESTONE`,
  gated on BOTH the `mem/` factorization AND the EL0 trap gate.
- A signed/keyed ABI-version attestation — the M33 successor.
- aarch64 `/chosen/bootargs` + tb-vmm cmdline version pass-through.

---

## 12. Change control (append-only, machine-forced)

A change to any registered method number, `required_right()` mapping, `Rights`
bit, wire magic, domain label, or organ tag MUST update the frozen literal in
`abi.rs` in the same commit — the cross-check (§4) FAILS otherwise. A breaking
Plane-1 change (renumber / removed method / relaxed right) additionally REQUIRES a
cap-plane MAJOR bump of `YUVA_ABI_VERSION`; an append-only addition REQUIRES a
cap-plane MINOR bump and moving `METHOD_CEILING` in lockstep. A new frame `ver`
REQUIRES a wire-plane bump. None of these can be silent.
