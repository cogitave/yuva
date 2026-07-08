# Industrial Boot — the human-meaningful boot presentation over the untouched machine-truth markers

> **Dated correction (2026-07-08, from the Boot-Profiles landing).** Two claims
> below are now STALE: (1) M38 stage B has since LANDED IN-KERNEL — `grep -c M38
> kernel/src/main.rs` is no longer 0, and `M38: conductor OK turns=N organs=K
> verdict=ACCEPT` is the cumulative guest-serial tail (`scripts/run-x86_64.sh`).
> The "Cognitive orchestrator" PRETTY line remains an operator-veto deferral
> (`bootreport::observe_m38_ok` records the gate but does not render it), so the
> DoD-2 assertion "no Cognitive-orchestrator line" still holds — only the
> `grep -c M38 = 0` justification is stale. (2) The §10 `substrate-compile-out=
> DEFERRED` named successor is now picked up by `docs/proposals/boot-profiles.md`
> (Boot Profiles), whose stage A landed the runtime profile gate (its stage B is
> the compile-out). The render-filter-vs-execution-gate honesty ruling this
> proposal established is exactly what Boot Profiles builds on.


**Status:** **PROPOSAL (research-first; nothing landed) — a purely ADDITIVE presentation layer that gives a normal person booting Yuva a Linux/systemd-grade readout, while the raw milestone markers stay byte-identical underneath for CI.** · **Pillars:** sovereignty (Yuva prints its OWN branded, non-Linux boot — idiomatic for a micro-VMM of its class, the Firecracker/Solo5 precedent) + honesty (the core value made load-bearing at the USER-FACING layer: where a status glyph is DERIVED, it is derived from a token that is PROVABLY ON THE BOOT WIRE — `backend=MOCK-DETERMINISTIC`, `gate-not-met`/`KAN_ACTIVE=0x0`, and the literal `(… skipped)` marker forms — so a derived line can NEVER say more than the machine truth; every remaining human suffix is an AUTHORED-HONEST CONSTANT that is reviewed and lint-gated, and is NOT claimed to be token-derived) + verification (ZERO CI regression enforced by a committed empty-byte-diff acceptance TEST on both arches AND on the decoded aarch64 guest stream, resting on the invariant DEFAULT=raw / pretty-not-emitted, not on "by construction") + profile-awareness (the substrate view = the Firecracker-alt minimal boot render; the agent view = the full resident-agent boot render). · **Depends on:** the **83** inline `tb_hal::serial_write_str("Mxx: … OK\n")` marker sites (`kernel/src/main.rs` — e.g. `:3914` `M20: persist OK`, `:4903` `M31: infer-e2e OK backend=MOCK-DETERMINISTIC`), the **~20 anti-hollow witness-line families** each ASSEMBLED FROM MANY interleaved `serial_write_str` calls emitted BEFORE their marker (`persist:`, `kan:`, `prov:`, `exp:`, `bakeoff:`, `opframe:`, `exittel:`, `opcmd:`, `khash:`, `xport:`, `infer:`, `infer-dump:`, `sched:`, `guestboot:`, `guestprobe:`, `guestchain:`, the aL2.4b `guest:` honesty line, `xport-harness:`, `boot: entry-el=`, `tb-boot: contract v0 OK`), the **in-boot honesty tokens that actually reach the wire** (`backend=MOCK-DETERMINISTIC` ×6, `gate-not-met` ×5, `KAN_ACTIVE` ×3, `sec=ASSUMED-FROM-LITERATURE`, `sidechannel=NOT-CLAIMED`, the guest `guest=FULL-KERNEL-EL1 …` line), the three verifier scripts (`scripts/run-x86_64.sh` with 100+ greps, `run-aarch64.sh` which additionally decodes a hex-framed GUEST stream, `run-vmm-x86_64.sh` which pins storage SKIPs), the boot cmdline channel (x86 PVH `hvm_start_info.cmdline_paddr`; aarch64 `-M virt -kernel` DTB `/chosen/bootargs`; the tb-vmm-only `TbBootInfo.cmdline` field, `crates/tb-boot/src/lib.rs:317-320`), the brand crate (`crates/brand/src/lib.rs:54-57`), and the demo (`scripts/demo.sh` + `docs/TRY-IT.md`). · **Tasks:** #106 — **#106 closes at the presentation-layer + demo stage (stage A); the branded splash / graphical polish is a named later stage that #106 does NOT block on.** · **Markers (DUAL, the M27/M31/M32 discipline):** the CI-required cumulative markers and their witness lines are **NEVER removed, renamed, or reordered.** The pretty `[ STATUS ] <subsystem>` lines carry a **distinct human prefix**, are **never** the literal marker/witness substrings CI greps, and — critically — are **never emitted at all** in the default mode CI runs under, so they cannot create a false positive, mask an anti-hollow negative, or trip a global tripwire.

> **One-line:** A person who boots Yuva today sees a wall of `Mxx: … OK` markers and machine-tokened witness lines and has no idea what any of it means. Industrial Boot adds a second presentation pass — a branded header, a column of `[  OK  ] <human subsystem name>` lines in the systemd grammar, and a `Reached target Ready` line — rendered ONLY when a viewer explicitly opts in via a runtime `yuva.console=pretty` cmdline token, whose ABSENCE (the state every CI lane and every re-entrant guest is in) preserves today's exact raw-marker stream byte-for-byte. Where the status glyph is derived, it is derived from a token PROVEN to be on the boot wire; every other human word is an authored-honest constant that is lint-gated against an overclaim vocabulary. CI keeps grepping the raw markers and witnesses, untouched.

This proposal is the convergent synthesis of three research strands (§ References), amended to survive an adversarial review (§ Adversarial review). The mechanism is chosen so that the three verifier scripts change by **zero lines**, every raw-marker / witness / global-tripwire assertion sees byte-identical input, and the re-entrant aarch64 EL1 guest — which boots the SAME binary with NO cmdline channel — is UNCONDITIONALLY raw.

---

## 1. Why this feature, and why these choices

Yuva's boot serial is a **Definition-of-Done instrument**: **83** milestone marker sites (`M1`..`M31`, `L2.0`..`L2.6`, `L2.4b`) plus ~20 anti-hollow witness-line families, each emitted INLINE by direct `tb_hal::serial_write_str` calls, and each grepped by exact substring across `scripts/run-x86_64.sh` (100+ assertions), `run-aarch64.sh`, and `run-vmm-x86_64.sh`. Each witness (e.g. `persist: gen=.. records=..`, `khash: prim=BLAKE2S-256 …`) is ASSEMBLED FROM MANY interleaved `serial_write_str` calls that are written to the wire BEFORE the marker they justify (`main.rs:3905` `persist: gen=` precedes `:3914` `M20: persist OK`). That instrument is load-bearing — the cumulative-chain displacement discipline, the anti-hollow positive-witness requirements, the skip-variant rejects, the strip-then-reject overclaim greps, the global raw-ESC tripwire, and the aarch64 hex-framed GUEST partition all read this stream. **It must not change.**

But it is also the ONLY thing a human sees, and it is unreadable to one. The operator's request is an industrial-standard boot. The tension is only apparent: the machine stream and the human stream are two PRESENTATIONS of the same underlying pass/fail booleans. Industrial Boot adds the human presentation without touching the machine one — and, per the adversarial review, ONLY where the human claim can be tied to something already on the wire.

Four places a naive "make the boot pretty" feature would rot, each fixed by construction:

1. **A two-value `OK`/`FAILED` vocabulary would force the UI to overclaim.** If Yuva printed only `[  OK  ]`/`[FAILED]`, a mock inference backend and a dormant learning cell would BOTH read `[  OK  ]` — "Local AI works", "AI Learning works" — when the wire says `backend=MOCK-DETERMINISTIC` and the gate is `gate-not-met`. The resolution is an **honesty-extended vocabulary** (§2.2) split into two provenance classes: glyphs DERIVED from a token proven to be on the boot wire, and suffixes that are AUTHORED-HONEST CONSTANTS (reviewed + lint-gated, never claimed derived). `token=vocab=DERIVED-FROM-BOOT-TOKEN + AUTHORED-HONEST-CONSTANT`.

2. **Controlling the pretty output must SUPPRESS DISPLAY, never delete the machine truth.** The Linux `quiet`/`loglevel=` model hides console messages without deleting them. Industrial Boot mirrors it: a runtime `yuva.console=raw|pretty|both` cmdline token controls which presentation is DISPLAYED; the raw markers are ALWAYS computed. The DEFAULT (absence of the token — the state of every CI lane and every re-entrant guest) is `raw`. `token=knob=DISPLAY-NOT-EXISTENCE`.

3. **A sovereign micro-VMM printing its own branded boot is IDIOMATIC.** Firecracker disables the serial console by default and, when enabled, relays raw dmesg then a one-line banner; MirageOS/Solo5 prints a compact self-branded `Solo5:` block then app lines then `Halted`. A terse branded non-Linux boot is the EXPECTED shape for this class. `token=class=BRANDED-MICROVM-BOOT-IDIOMATIC`.

4. **The color-and-TTY story a kernel cannot honor must be dropped, not imported.** systemd emits ANSI color "only on a capable TTY" using userspace `isatty`/termcap. A freestanding Yuva kernel writing a raw 16550/PL011/virtio-console has NO `isatty`, NO termcap, and cannot tell a TTY from a pipe. The systemd analogy therefore CANNOT be relied on to keep ESC bytes out of a CI stream — and every lane hard-fails on any ESC byte (§2.3). Resolution: **the pretty/both renderer emits NO ANSI color at all; color is a compile-time-off option, never on any CI-visible or default path.** `token=color=COMPILE-OUT-OFF-BY-DEFAULT-NO-ISATTY`.

**And one thing this feature deliberately is:** *the honesty discipline extended to the user-facing surface.* The machine tokens already refuse to overclaim to a verifier; Industrial Boot refuses to overclaim to a human — and, per the review, refuses to derive a human claim from a token that is not on the boot wire.

## 2. The industrial boot GRAMMAR (branded header + `[ STATUS ] <subsystem>` + reached-target)

### 2.1 The three structural elements

- **Line 1 — the branded header:** `Yuva <ver> — sovereign agent-native OS  ·  <view>`, `<ver>` and brand from `crates/brand` (single source of truth).
- **Body — one `[ STATUS ] <human subsystem name>` line per subsystem.** A fixed-width bracket tag (`[  OK  ]`, 6-column) followed by an authored-honest human name and suffix. Subsystem names come from the §4 mapping, not from marker ids. **No ANSI color is emitted** (§2.3); the tag is plain brackets on every path.
- **Final — the reached-target line + one-line summary:** `[  OK  ] Reached target Ready.` then a summary carrying the logical-surrogate boot-time (§9) and an honest tally that NAMES non-OK cells: `… — N subsystems (1 mock, 1 standby, K skipped, 0 failed).`

### 2.2 The honesty-extended status vocabulary (two provenance classes)

Each glyph is either DERIVED from a token proven on the boot wire, or (for a suffix) an AUTHORED-HONEST CONSTANT. The two are never conflated.

| Glyph | Meaning | Provenance |
|---|---|---|
| `[  OK  ]` | subsystem is real and its round-trip boolean passed THIS boot on THIS lane | the milestone's real round-trip boolean (the SAME flag a run script positively requires, e.g. `persist: gen=.. records=..`) |
| `[ MOCK ]` | plumbing real, backend a deterministic stub | **DERIVED** from `backend=MOCK-DETERMINISTIC` (`main.rs:4903`, on the wire ×6) — NEVER `[ OK ]` |
| `[STANDBY]` | capability shipped, inactive BY DESIGN | **DERIVED** from `gate-not-met` (on the wire ×5, `M21:3991`/`M24:4198`) and/or `KAN_ACTIVE=0x0` (×3) — NEVER `[ OK ] AI Learning` |
| `[ SKIP ]` | not exercised on THIS lane — a real `(… skipped)` code path was taken | **DERIVED** from the literal skip-form marker substring on the wire (`(no disk, skipped)`, `(no device, skipped)`, `(no EL2, skipped)`, `(no host peer, skipped)`) |
| `[ INFO ]` | an honest disclaimer, not a subsystem claim | **AUTHORED-HONEST CONSTANT** — the LEXICAL / OPEN-FRONTIER / novelty caveats are HOST-conductor artifacts NOT on the boot wire, so this line is a reviewed constant, explicitly NOT token-derived |
| `[FAILED]` | a REAL failure | the milestone's fail path — never cosmetic |

**The load-bearing rule, corrected:** the DERIVED glyphs (`MOCK`/`STANDBY`/`SKIP`) are a pure function of a substring PROVEN to be on the boot wire; the renderer computes no new state. The AUTHORED-HONEST suffixes (the "lexical recall", "host residual-TCB", "logical-surrogate timing", and the entire `[ INFO ]` line) are static English constants — honest, reviewed, and lint-gated against the overclaim vocabulary, but they are NOT derived, because their justifying tokens (`retrieval=LEXICAL-NOT-SEMANTIC`, `learning=DORMANT`, `generativity=OPEN-FRONTIER`, `policy=DISCRETE-HAND-WRITTEN-NOT-LEARNED`, `novelty=…`) have ZERO occurrences in `kernel/src/main.rs` and appear only in the host conductor summary, off the boot wire. `token=glyph=DERIVED-ONLY-FROM-ONWIRE-TOKEN`, `token=suffix=AUTHORED-HONEST-CONSTANT-LINT-GATED`.

### 2.3 Two hard CI-facing constraints the renderer MUST honor

- **No ESC byte, ever, on any CI-visible or default stream.** `run-x86_64.sh:588`, `run-aarch64.sh:663`, `run-vmm-x86_64.sh:263` each `grep -q -- $'\x1b'` over the WHOLE guest serial and hard-FAIL on ANY `0x1b`. The pretty/both renderer therefore emits **no ANSI color** (§1.4); color is a compile-time-off knob that is never enabled on a path any verifier reads.
- **`both` mode is FORBIDDEN on the three run lanes.** `both` is NOT CI-safe as originally claimed: it would place pretty lines on the same stream as the global negative greps (§2.4/§5.3). `both` is a developer-only convenience reachable solely via an explicit interactive cmdline, and the run scripts pass no cmdline, so they never reach it.

### 2.4 Why the global negatives — not "prefix anchoring" — are what pretty must respect

The zero-regression argument does NOT rest on "pretty lines never emit the `M..:` prefix". Several load-bearing negatives are GLOBAL/unanchored and would fire on ANY matching byte anywhere: the ESC `\x1b` tripwire; `grep -qF KEYED-NONCRYPTO` (`x86:427`, `a64:508`); `transport=TB-VMM-HOST` (`x86:484`); `transport=QEMU-CHARDEV-HARNESS` / `bus=SERIAL-FRAMED` (`vmm:164-171`); the key-hex leak `grep -qiF ${KHEX}`; the `forge-test:` HOST-leak grep (`a64:1001`); the `^guestlog:` residue canary (`a64:1013`). The ACTUAL sufficient reason pretty cannot trip any of these is **DEFAULT=raw: the pretty layer is not emitted at all on any lane** — not prefix anchoring. Prefix distinctness is a belt-and-suspenders second line for `both`, not the primary guarantee.

## 3. Full concrete boot examples

### 3.1 agent view, aarch64 EL2-host lane (the full resident-agent boot — Guest isolation + scheduler REAL here)

```
Yuva 0.9 — sovereign agent-native OS  ·  agent view (aarch64 EL2 host)
──────────────────────────────────────────────────────────────
[  OK  ] Kernel core                traps, paging, preemptive scheduler
[  OK  ] Isolation & capabilities   per-entity address spaces, capability ABI
[  OK  ] Guest isolation            full kernel as EL1 guest under EL2 (stage-2, vGIC, IOMMU)
[  OK  ] Virtio devices             entropy (rng), block
[  OK  ] Durable storage            virtio-blk, replayed on boot
[  OK  ] Sovereign scheduler        CNTHP-preempted (timing: logical, not wall-clock)
[  OK  ] Message-authenticated integrity   keyed BLAKE2s-256 MAC (primitive assumed-from-literature)
[  OK  ] Agent runtime & memory     tiered store, lexical recall, consolidation
[  OK  ] Provenance ledger          tamper-evident fold (host TCB residual)
[  OK  ] Inference transport        host-custodied key, cross-process recompute — plumbing only
[ MOCK ] Agent inference            deterministic stub — NO model loaded, not live AI
[STANDBY] Adaptive policy           experience logged; learning gate not met
[  OK  ] Operator channel           transcript, exit telemetry, inbound command
[  OK  ] Reached target Ready.
[ INFO ] retrieval=lexical (not semantic) · generativity=open frontier (not claimed) · security=assumed-from-literature
──────────────────────────────────────────────────────────────
The agent runtime is resident. Yuva ready in ~0.9s (logical surrogate) — 13 subsystems (1 mock, 1 standby, 0 failed).
```

> **Per-arch note (honest, not cosmetic):** on the **x86_64** lane there is no EL2, so `Guest isolation` and `Sovereign scheduler` are DERIVED to `[ SKIP ] … (no EL2, skipped)` from the on-wire skip form — they are NOT rendered `[  OK  ]`. The `[  OK  ]` above is honest ONLY on the aarch64 EL2-host lane. **The Cognitive-orchestrator (M38) line is intentionally absent** — see §4 and the Adversarial review; it renders only once an in-guest M38 marker lands.

### 3.2 substrate view (Firecracker-alt minimal render)

```
Yuva 0.9 — sovereign agent-native OS  ·  substrate view (render filter, stage A)
──────────────────────────────────────────────────────────────
[  OK  ] Kernel core                traps, paging, preemptive scheduler
[  OK  ] Isolation & capabilities   per-entity address spaces, capability ABI
[  OK  ] Guest isolation            (aarch64 EL2 host: real; else [ SKIP ] no EL2)
[  OK  ] Virtio devices             entropy (rng), block        (vmm lane: [ SKIP ] no device)
[  OK  ] Durable storage            virtio-blk, replayed on boot (vmm lane: [ SKIP ] no disk)
[  OK  ] Sovereign scheduler        CNTHP-preempted (aarch64 EL2 host only; else [ SKIP ])
[  OK  ] Message-authenticated integrity   keyed BLAKE2s-256 MAC (primitive assumed-from-literature)
[ INFO ] Cognitive subsystems present in this build but HIDDEN in the substrate view
[  OK  ] Reached target Ready.
──────────────────────────────────────────────────────────────
Yuva ready (logical surrogate) — substrate view, micro-VMM subsystems only.
```

> **Honesty correction (§ Adversarial review, V2-must-fix-3):** stage A ships NO profile build variant — `rust_main` runs the M12-M18 organs and M31 mock inference UNCONDITIONALLY. The substrate "profile" at stage A is therefore a pure **render filter**, so the line reads `[ INFO ] Cognitive subsystems present in this build but HIDDEN in the substrate view` — it must NOT say "not present in substrate profile", which would be a pretty-boot-that-lies (the organs DID execute). A genuine compile-out substrate build (`#[cfg]` that removes the organs so the claim "not present" becomes true) is a **named later stage**, explicitly NOT scoped by #106 stage A.

### 3.3 what CI actually greps — DEFAULT (no cmdline → raw), byte-identical, on THREE surfaces

CI does not read one flat stream. The DEFAULT-raw invariant must hold across all of it:

```
# (a) x86_64 / vmm HOST serial — the cumulative markers + assembled witnesses:
persist: gen=0x1 records=0x2 replayed=0x2
M20: persist OK
khash: prim=BLAKE2S-256 keylen=32 tag=128 kat=RFC7693-PASS sec=ASSUMED-FROM-LITERATURE sidechannel=NOT-CLAIMED
M29: khash-mac OK
infer: backend=MOCK-DETERMINISTIC ... pending=0x1
M31: infer-e2e OK backend=MOCK-DETERMINISTIC

# (b) vmm lane — POSITIVELY PINNED skips (this lane legitimately skips storage):
M19: virtio OK (no device, skipped)
M20: persist OK (no disk, skipped)

# (c) aarch64 lane — the SAME kernel re-entered as an EL1 guest, its serial
#     HEX-FRAMED as 'guestlog:' then DECODED to GUEST_STREAM and grepped there:
GUEST_STREAM ⊃ 'tb-boot: contract v0 OK'
GUEST_STREAM ⊃ 'boot: entry-el=0xff el2=0x0'
GUEST_STREAM ⊃ 'M1: traps OK' … 'M29: khash-mac OK'          (G2 must-prove, literal)
GUEST_STREAM ⊃ 'L2.0: el2 OK (no EL2, skipped)' … 'M27: sched OK (no EL2, skipped)'
GUEST_STREAM ⊃ 'M31: infer-e2e OK (no host peer, skipped)'    (G4 tail)
```

Note what is NOT here: there is **no `M38: conductor OK` line and no `conduct:` honesty line on the boot serial** — M38 stage A is host-only (`tools/conductor-host`), its witness lives in `conductor-host.yml`'s summary OUTSIDE every guest-serial grep, and the in-guest M38 marker is stage-B UNLANDED (`grep -c M38 kernel/src/main.rs` = 0). Those lines are not part of the DoD-1 baseline.

### 3.4 forbidden renderings (DoD-2 lint FAILS if any appears in a pretty capture)

```
[  OK  ] Local AI            ← FORBIDDEN: wire says backend=MOCK-DETERMINISTIC → [ MOCK ]
[  OK  ] AI Learning         ← FORBIDDEN: wire says gate-not-met/KAN_ACTIVE=0 → [STANDBY]
[  OK  ] Live inference      ← FORBIDDEN: no live model → [ MOCK ]
[  OK  ] Semantic memory     ← FORBIDDEN: no semantic backend → say "lexical recall"
[ MOCK ] Cognitive orchestrator  ← FORBIDDEN AT ALL until an in-guest M38 marker exists
[  OK  ] Secure inference channel ← FORBIDDEN: 'secure' is a banned adjective (run-x86_64.sh:445)
```

## 4. The honest milestone → subsystem MAPPING TABLE

Every mapped name is justified below against the token on the wire. The **Status basis** column states, for each row, whether the glyph is DERIVED (from an on-wire token) or a real round-trip boolean, and every suffix is an AUTHORED-HONEST CONSTANT unless marked DERIVED.

| Human subsystem line | Rolls up | Lanes where `[ OK ]` is honest | Status basis | Honest suffix (authored constant unless DERIVED) |
|---|---|---|---|---|
| Kernel core | M1..M9 | all | round-trip booleans | traps, paging, preemptive scheduler |
| Isolation & capabilities | M10, M11 | all | round-trip booleans | per-entity address spaces, capability ABI |
| Guest isolation | L2.0..L2.6, L2.4b, tb-vmm | **aarch64 EL2 host only** | DERIVED: real vs `(no EL2, skipped)` | full kernel as EL1 guest under EL2; **`[ SKIP ]` on x86 and in the aarch64 guest** |
| Virtio devices | M19 | non-vmm | DERIVED: real vs `(no device, skipped)` | entropy (rng), block; **`[ SKIP ]` on the vmm lane** |
| Durable storage | M20 | lanes with a disk | DERIVED: real vs `(no disk, skipped)` | virtio-blk, replayed; **`[ SKIP ]` on the vmm lane / guest** |
| Sovereign scheduler | M27 | **aarch64 EL2 host only** | DERIVED: real vs `(no EL2, skipped)` | CNTHP-preempted; timing logical, not wall-clock |
| Message-authenticated integrity | M29 khash-mac | all | round-trip boolean + `sec=ASSUMED-FROM-LITERATURE` | keyed BLAKE2s-256 MAC; primitive assumed-from-literature — **name avoids every banned word (no "secure/crypto/authenticated-human/validated", `run-x86_64.sh:445`)** |
| Agent runtime & memory | M12..M18 | agent lanes | round-trip booleans | tiered store, **lexical** recall (AUTHORED constant — no boot token; NOT claimed derived) — never "semantic" |
| Provenance ledger | M22 | agent lanes | round-trip boolean | tamper-evident fold; **host=residual-TCB** (authored). **M33 lineage is HOST-only → NOT a boot row** |
| Inference transport | M30 | lanes with an echo peer | DERIVED: real vs `(no host peer, skipped)` | host-custodied key, cross-process recompute — **plumbing only; renamed from "Secure inference channel" to drop the banned "Secure"** |
| Agent inference | M31 | — | **DERIVED `[ MOCK ]`** from `backend=MOCK-DETERMINISTIC`; `[ SKIP ]` in guest from `(no host peer, skipped)` | deterministic stub, NO model loaded, not live AI |
| Adaptive policy | M21, M23, M24 | — | **DERIVED `[STANDBY]`** from `gate-not-met` / `KAN_ACTIVE=0x0` | experience logged; learning gate not met |
| Operator channel | M25, M26, M28 | agent lanes | round-trip booleans | transcript, exit telemetry, inbound command |
| *(disclaimer, not a subsystem)* | LEXICAL / OPEN-FRONTIER / novelty / realtime=NOT-CLAIMED | agent lanes | **AUTHORED-HONEST CONSTANT — these tokens are HOST-only, NOT on the boot wire** | folded into ONE trailing `[ INFO ]` note — never a green line |
| ~~Cognitive orchestrator (M38)~~ | ~~M38~~ | **NONE — DROPPED** | **`grep -c M38 main.rs` = 0; host-only; guest marker stage-B UNLANDED** | **rendered ONLY once an in-guest M38 marker lands; gated on `bootreport` seeing that marker** |

**The ambiguous cells, ruled explicitly:**

- **Agent inference (M31) → `[ MOCK ]`, mandatory "not live AI".** The transport under it (M30) is real, so `[ OK ] Inference transport` is honest for the *plumbing*; the model does not exist. NEVER `[ OK ] Local AI`. The run scripts ban `understood/reasoned/intelligent/knows/learned/secure/private/agi` on `M31:`/`infer:`; the human renderer respects the same list (DoD-2).
- **Adaptive policy (M21/M23/M24) → `[STANDBY]`, DERIVED.** The KAN spline ships dormant (`KAN_ACTIVE=false`, `mem/mod.rs:273`; on the wire ×3) and M24 prints `gate-not-met` (×5). The `[STANDBY]` glyph is DERIVED from those on-wire substrings. `run-x86_64.sh:316-318` rejects a `validated`/`evaluated`/`gate-cleared` overclaim; the pretty line reintroduces none.
- **Message-authenticated integrity (M29) → `[  OK  ]`, name scrubbed of banned adjectives.** `run-x86_64.sh:445` bans `validated/crypto/authenticated-human/forgery/provably-secure/…` on `M29:` lines. The human name and suffix use "keyed BLAKE2s-256 MAC (primitive assumed-from-literature)" and contain NONE of the banned tokens.
- **Inference transport (M30) → `[  OK  ]` only with an echo peer.** On any lane WITHOUT the `xport-harness` echo peer, M30 takes `(no host peer, skipped)` and renders `[ SKIP ]`. The word "Secure" is removed from the name (it is banned on M29/M30 witness lines).

**M38 (Cognitive orchestrator) is DROPPED from the boot presentation.** It is not on the boot wire; presenting it as a green boot subsystem was a fabrication. It renders only when `bootreport` observes a real in-guest `M38:` marker — i.e. after M38 stage-B lands. `token=m38=NOT-A-BOOT-SUBSYSTEM-UNTIL-GUEST-MARKER-LANDS`.

**Frontier is NOT shown as a subsystem** and, per the review, its glyph is NOT claimed derived: `OPEN-FRONTIER`/`NOT-CLAIMED`/`LEXICAL` are HOST-only tokens, so the `[ INFO ]` line is an AUTHORED-HONEST CONSTANT, folded into one trailing note. `token=frontier=AUTHORED-DISCLAIMER-NEVER-A-SUBSYSTEM`.

## 5. The mechanism — choke point + runtime knob + the concrete ZERO-CI-REGRESSION proof

### 5.1 The kernel boot-report choke point

Today there is **no central emitter** — each of the 83 marker sites is a direct inline `serial_write_str` call, and each witness family is assembled from many such calls emitted BEFORE its marker. Industrial Boot introduces a kernel `bootreport` module:

```
bootreport::report(id, raw_marker, human_name, state, view_tag)
    where state ∈ { Ok, Mock, Standby, Skip, Info, Failed }
```

**Honest about scope (§ Adversarial review, V1-must-fix-3):** rerouting the 83 marker sites alone does NOT yield the clean §3 boot, because the ~20 witness families are still written to the wire before their markers. Producing a truly clean pretty screen requires the pretty branch to ALSO suppress the byte-sensitive witness assembly for the lines it replaces — a materially larger change than "one call site each". Two consequences are accepted, not hidden: (a) at minimum, the raw branch must re-emit BOTH markers AND their pre-marker witness assemblies byte-for-byte; (b) a glyph cannot be "derived at `report()` time" from a witness already flushed to the wire earlier — so DERIVED glyphs key only off tokens the kernel still holds as booleans/consts at report time (`MOCK-DETERMINISTIC`, `gate-not-met`, `KAN_ACTIVE`, the skip-form flag), which is exactly the set §2.2 restricts them to.

The module has two branches:
- **raw branch:** prints the EXACT current bytes — markers AND their interleaved witness assemblies — validated by the DoD-1 empty-diff test.
- **pretty branch:** prints the mapped `[ STATUS ] <human name>` line and SUPPRESSES both the raw marker and the witness lines it replaces; emits NO ESC byte.

### 5.2 The runtime verbosity knob (cmdline only — the guest depends on it)

A boot-cmdline token `yuva.console=raw|pretty|both`:
- **`raw` (the DEFAULT — the state of absent cmdline)** — today's exact bytes.
- **`pretty`** — the `[ STATUS ]` stream only; opt-in.
- **`both`** — developer-only; **forbidden on the three run lanes** (§2.3).

**Why the mechanism MUST be runtime cmdline, not a compile-time feature flag (§ Adversarial review, V1-must-fix-1):** the aarch64 lane re-enters the SAME kernel binary as a stage-2-confined EL1 guest (aL2.4b) via `-device loader`, a flat binary with **NO PVH/DTB/TbBootInfo cmdline channel**. The guest's `bootreport` therefore inherits purely the COMPILED DEFAULT. A compile-time `--features industrial-boot` interim would compile the guest pretty too, so `GUEST_STREAM` would carry `[  OK  ] Kernel core` instead of `M1: traps OK` and every G1/G2/G3/G4 guard (`run-aarch64.sh:930-995`) would fail. Therefore:

> **Load-bearing invariant:** `bootreport` is **UNCONDITIONALLY raw inside the EL1 guest**. Pretty is reachable ONLY via a runtime cmdline token, which the re-entrant guest never receives; the compiled default is raw; neither `pretty` nor `both` is reachable in the guest. The feature-flag interim is **WITHDRAWN** — it cannot keep the guest raw. `token=guest=UNCONDITIONALLY-RAW-NO-CMDLINE-CHANNEL`.

A cost is accepted honestly: because the interim is withdrawn, stage A must include real x86 PVH `cmdline_paddr` parsing (aarch64-host `pretty` via DTB `/chosen/bootargs` may be a named follow-up), and the aarch64 GUEST is raw regardless.

### 5.3 The concrete ZERO-CI-REGRESSION proof (a committed test, not "by construction")

Zero regression rests on ONE invariant and ONE committed test:

- **Invariant:** the DEFAULT is `raw` (absence of cmdline), and CI passes no cmdline, and the re-entrant guest has no cmdline channel — so **the pretty layer is NEVER EMITTED on any CI-visible stream**. This — not prefix anchoring — is the sufficient reason no pretty byte can trip any global negative (the ESC tripwire, `KEYED-NONCRYPTO`, `transport=…`, the key-hex leak, the `forge-test:` HOST-leak, the `^guestlog:` canary; §2.4).
- **DoD-1, a COMMITTED CI regression test (not a one-time acceptance check):** on **every** run, boot BEFORE-image and AFTER-image at the default and assert the serial diff is EMPTY on (a) the x86_64 HOST stream, (b) the vmm lane HOST stream INCLUDING its pinned `(… skipped)` witnesses, and (c) the DECODED aarch64 `GUEST_STREAM`. This mechanically proves the 100+ greps, the vmm skip pins, and the guest G1-G4 partition all see byte-identical input. The proof is the empty diff, asserted continuously — the header phrase is amended from "by construction" to "enforced by a committed empty-diff test across all three surfaces".

Gate-by-mode is preferred over always-both because always-both clutters the user screen; but `both` is developer-only and forbidden on the lanes (§2.3). `token=ci-preservation=DEFAULT-RAW-PRETTY-NOT-EMITTED + DOD1-EMPTY-DIFF-3-SURFACES`.

### 5.4 Flag plumbing — honest about the cost

The mechanism is parsing `yuva.console=` from the boot cmdline: x86 PVH via `hvm_start_info.cmdline_paddr` (`-append`); aarch64-host via the DTB `/chosen/bootargs`. This is real new kernel code, and (per §5.2) there is **no feature-flag shortcut**, because the interim would corrupt the re-entrant guest stream. `token=flag=RUNTIME-CMDLINE-MANDATORY-NO-FEATURE-INTERIM`.

## 6. View-awareness (substrate vs agent RENDER views)

Each `bootreport` row is tagged `substrate` or `agent`. At stage A the tag drives a **render filter only** — no build variant exists yet (§3.2):

- **substrate view:** renders the micro-VMM rows (Kernel core, Isolation, Guest isolation, Virtio, Durable storage, Sovereign scheduler, Message-authenticated integrity) plus a single honest `[ INFO ] Cognitive subsystems present in this build but HIDDEN in the substrate view` line — NEVER "not present", because the organs did execute.
- **agent view:** additionally renders Agent runtime & memory, Provenance ledger, Inference transport, Agent inference `[ MOCK ]`, Adaptive policy `[STANDBY]`, Operator channel, and the trailing `[ INFO ]` disclaimer.

A genuine compile-out substrate build (where "not present" becomes true) is a **named later stage**, not #106. The final line is honest per view: the agent view says "The agent runtime is resident" (presence, from real markers), never "the agent is thinking". `token=view=RENDER-FILTER-AT-STAGE-A / COMPILE-OUT-DEFERRED`, `token=final-line=PRESENCE-NOT-CAPABILITY`.

## 7. The demo update (`scripts/demo.sh` + `docs/TRY-IT.md`)

`scripts/demo.sh` is a VIEWER — it asserts nothing and is never run by CI — so it is the safe place to opt into pretty:

- **`demo.sh` defaults to `pretty`** by passing `-append 'yuva.console=pretty'` (x86 PVH). **It uses NO `--features industrial-boot`** — that interim is withdrawn (§5.2). On aarch64, the demo either shows the raw stream (guest is always raw) or renders host-side pretty only if the DTB-bootargs follow-up has landed.
- **`demo.sh --verbose`** boots the default `raw` (or interactive `both`), showing the exact marker stream.
- **`docs/TRY-IT.md`** shows the clean §3 boot as expected output, with a "for raw developer markers, run `demo.sh --verbose`" note.

**The three verifier scripts change by ZERO lines** and never pass a cmdline, so they get `raw`. The `.github/workflows` lanes inherit the raw default via `run-*.sh`. `token=demo=PRETTY-VIA-RUNTIME-CMDLINE / --verbose-RAW / CI-UNTOUCHED`.

## 8. DoD — three committed proof obligations

**DoD-1 — the empty-byte-diff regression test (COMMITTED, per-run, THREE surfaces).** As §5.3: assert an EMPTY serial diff at the default on the x86_64 HOST stream, the vmm HOST stream (including its pinned skip witnesses), and the decoded aarch64 `GUEST_STREAM`. This is a standing CI gate, not a one-time acceptance check. `token=dod1=DEFAULT-BOOT-BYTE-DIFF-EMPTY-3-SURFACES-COMMITTED`.

**DoD-2 — the honesty-derivation + lint test.** For the DERIVED cells, assert the glyph is the derived one: given `backend=MOCK-DETERMINISTIC` the renderer emits `[ MOCK ]` (+ "not live AI"), never `[ OK ] … AI`; given `gate-not-met`/`KAN_ACTIVE=0` it emits `[STANDBY]`; given a `(… skipped)` marker it emits `[ SKIP ]`. A negative lint greps a pretty capture for the banned vocabulary (`Local AI`, `AI Learning`, `semantic`, `live inference`, `learned`, `reasoned`, `intelligent`, `secure`) and for any ESC `\x1b` byte, and FAILS if any appears. The lint ALSO asserts no `Cognitive orchestrator` line is emitted while `grep -c M38 main.rs` = 0. `token=dod2=DERIVED-GLYPH-ASSERTED + BANNED-VOCAB+ESC-LINT`.

**DoD-3 — the view/lane-parity check (lane-aware).** Boot both views in `pretty`; assert the substrate view renders the micro-VMM rows + the honest `[ INFO ] … HIDDEN in the substrate view` line and NO inference/learning line; assert the agent view renders the mock/standby glyphs and the `[ INFO ]` disclaimer. **The status of Guest isolation, Sovereign scheduler, Virtio, and Durable storage is asserted PER LANE from the real round-trip boolean** — `[ SKIP ]` on the vmm lane for M19/M20, `[ SKIP ]` on x86 for the EL2 rows — so DoD-3 does NOT assert a fixed "6 green lines" block, which would contradict the vmm lane's pinned skips. `token=dod3=LANE-DERIVED-STATUS-NOT-FIXED-OK-BLOCK`.

Evidence is these three committed tests + the §5 invariant, honestly NOT Kani proofs (no new no-float leaf). `token=evidence=EMPTY-DIFF+DERIVATION+LANE-PARITY-TESTS-NOT-KANI`.

## 9. Honest caveats (conceded — encoded as witness tokens)

- **The clean boot proves PRESENTATION, not capability.** A green line means the marker fired and its round-trip boolean passed on that lane, not that Yuva reasons. `token=pretty=PRESENTATION-OF-MARKERS-NOT-NEW-CLAIM`.
- **`[ MOCK ] Agent inference` is the honest ceiling.** `backend=MOCK-DETERMINISTIC`. Never a live-AI implication.
- **`[STANDBY] Adaptive policy` is DERIVED from `gate-not-met`/`KAN_ACTIVE=0`, not "AI Learning working".**
- **The `[ INFO ]`/lexical/host/timing suffixes are AUTHORED CONSTANTS, not derived** — their tokens (`LEXICAL-NOT-SEMANTIC`, `OPEN-FRONTIER`, `learning=DORMANT`, `novelty=…`) are HOST-conductor artifacts with ZERO occurrences on the boot wire; the proposal does not claim otherwise.
- **Timing is the logical surrogate, not wall-clock** (`timing=TCG-NON-CYCLE-ACCURATE`).
- **Provenance is verified-but-host-residual** (`host=RESIDUAL-TCB`, `sec=ASSUMED-FROM-LITERATURE`).
- **A `(… skipped)` subsystem renders `[ SKIP ]`, never `[ OK ]`** — DERIVED from the on-wire skip form.
- **No ANSI color is emitted** on any CI-visible or default path (a kernel has no `isatty`).
- **M38 is not a boot subsystem** until an in-guest marker lands.

## 10. Frontier / named deferrals

- **A genuine compile-out substrate build** (organs `#[cfg]`-removed so "not present" is literally true). Deferred; NOT #106. `token=substrate-compile-out=DEFERRED`.
- **aarch64-host `pretty` via DTB `/chosen/bootargs`.** The x86 PVH parse ships in stage A; the aarch64-host render knob is a named follow-up (the guest stays raw regardless). `token=aarch64-pretty=FOLLOW-UP`.
- **A Plymouth-style graphical splash.** Cosmetic; deferred. `token=splash=DEFERRED-COSMETIC`.
- **A dmesg-style severity ring buffer.** Yuva has no ring/`dmesg` today; frontier. `token=ring-buffer=DEFERRED`.
- **Per-subsystem progress spinners; localized names.** Deferred. `token=progress-animation,i18n=DEFERRED`.
- **The Cognitive-orchestrator boot line**, once M38 stage-B lands a real in-guest marker. `token=m38-line=DEFERRED-UNTIL-GUEST-MARKER`.

## 11. Landing plan — staged, CI-green, offline; operator veto points

- **(A) The presentation layer + demo (offline, CI-preserving; #106 closes HERE).** The `bootreport` module (choke point, derived-glyph state machine over ONLY on-wire tokens, the §4 mapping, the render-view tags) + the 83 marker sites AND their pre-marker witness assemblies rerouted so the raw branch is byte-identical + the runtime `yuva.console=` knob (DEFAULT raw, **x86 PVH cmdline parse; NO feature-flag interim; guest unconditionally raw**) + `demo.sh` defaulting to `pretty` with `--verbose` + `docs/TRY-IT.md` + DoD-1/2/3 as committed tests. The three verifiers, the cumulative chain, the aarch64 guest partition, the vmm skip pins, the mock lane: **untouched**. DoD-1 (empty diff on all three surfaces) is the standing gate.
- **(B) Branding / splash polish** (named later; does NOT block #106).
- **(C) The dmesg-style ring buffer + aarch64-host runtime knob + genuine compile-out substrate build** (frontier, §10).

**Operator veto points (none reachable from an unattended run):** (1) any change to the DEFAULT away from `raw` (touches CI's input — operator-reviewed, never silent); (2) any subsystem NAME or glyph change that could read as an overclaim, or any attempt to reintroduce the feature-flag interim (which would corrupt the guest stream); (3) landing the M38 boot line (requires the in-guest marker first); (4) the branding/splash direction.

## 12. Ledger + docs fan-out

- **`crates/brand/src/lib.rs`** — banner + `yuva.console=` key from `BRAND`/`BRAND_LOWER`.
- **`kernel/src/main.rs`** — the 83 marker sites AND their pre-marker witness assemblies rerouted through `bootreport::report(...)`; the x86 PVH cmdline read; the **guest-forced-raw** wiring; the render-view tags. (Correction: there is NO kernel honesty-token witness line at `:5153-5165` — that range is a canary counter loop; the DORMANT/LEXICAL/FRONTIER tokens are host-conductor artifacts.)
- **NEW `bootreport` module** — the choke point, the derived-glyph `State` enum (over on-wire tokens only), the §4 mapping, the render tags, the raw/pretty/both branches, the **guest-raw guard**.
- **`scripts/demo.sh`** — `pretty` default (runtime cmdline) + `--verbose`; **`scripts/run-{x86_64,aarch64}.sh` + `run-vmm-x86_64.sh` — ZERO lines changed**.
- **`docs/TRY-IT.md`** — clean §3 boot + `--verbose` note.
- **`docs/{MILESTONES,ARCHITECTURE,ROADMAP-V2}.md`** — the presentation layer, the `yuva.console=` knob, the two-class vocabulary, the render-view split, and the M38-deferred note.
- **`LANGUAGE-AND-STANDARDS.md`** — the derived-only-from-on-wire-token rule; the authored-honest-constant + lint rule; the DEFAULT-raw / pretty-not-emitted invariant; the guest-unconditionally-raw invariant; the no-ESC/no-color rule.
- **`assumptions.md` NEW row** — presentation-only; DEFAULT-raw preserves byte-identical markers/witnesses on all three surfaces; derived glyphs come only from on-wire tokens; timing is a logical surrogate; the guest is always raw.
- **`.claude/skills/tabos-milestone/SKILL.md`; `docs/plans/INDEX.md`; `docs/BACKLOG.md`; tracker task #106.**

## 13. Roadmap context

Industrial Boot is the **user-facing capstone of the two-view line**: the substrate view is the Firecracker-alt micro-VMM render; the agent view honestly shows what is real (`[ OK ]`), what is a stub (`[ MOCK ]`), what is dormant-by-design (`[STANDBY]`), what is skipped on a lane (`[ SKIP ]`), and what is frontier (an authored `[ INFO ]` disclaimer). It extends the project's honesty discipline — enforced against a verifier by the on-wire tokens — to the human surface, WITHOUT deriving a human claim from a token that is not on the boot wire, so a normal person and a CI grep read the SAME truth in two presentations. Named successors: the M38 boot line (post stage-B), the branded splash, the ring buffer + aarch64-host knob, and the genuine compile-out substrate build.

---

## Adversarial review

This section records the adversarial verdicts (both `SOUND-WITH-AMENDMENTS`) and the exact amendment applied to each, verified against the code.

### Must-fix items — resolution

1. **aarch64 GUEST re-entrancy (V1-must-fix-1, "the single largest gap").** `run-aarch64.sh` re-enters the SAME binary as a stage-2 EL1 guest with NO cmdline channel, hex-frames its serial as `guestlog:`, decodes to `GUEST_STREAM`, and greps the guest's OWN raw markers there (G1 `tb-boot: contract v0 OK` `:930`, `boot: entry-el=0xff` `:934`; G2 literal `M1..M29` loop `:945`; G3 exact skip forms `:964`; G4 `M31 (no host peer, skipped)` `:983`). **Resolution:** §5.2 makes `bootreport` **unconditionally raw in the guest** a load-bearing invariant, **withdraws the feature-flag interim** (which would compile the guest pretty and break every G-guard), and makes pretty reachable only via a runtime cmdline token the guest never receives. DoD-1 (§5.3/§8) extends the empty-diff test to the decoded `GUEST_STREAM`.

2. **ESC tripwire + no kernel `isatty` (V1-must-fix-2).** `run-x86_64.sh:588`, `run-aarch64.sh:663`, `run-vmm-x86_64.sh:263` hard-fail on ANY `0x1b`. **Resolution:** §1.4/§2.3 make the renderer emit **NO ANSI color** (compile-time-off, never on a CI/default path); the "color only on a capable TTY" claim is dropped as unattainable for a freestanding kernel; **`both` is forbidden on the three run lanes**.

3. **Choke-point scope: 83 sites, witnesses are pre-marker multi-call assemblies (V1-must-fix-3).** Verified: `grep -oE 'serial_write_str\("M[0-9L]'` = 83. **Resolution:** counts corrected throughout (83, not ~40); §5.1 concedes the raw branch must re-emit witnesses too, that a glyph cannot be derived from an already-flushed witness (so DERIVED glyphs use only still-held booleans/consts), and that this is NOT "one call site each"; DoD-1 is a COMMITTED per-run test on both arches and the guest stream.

4. **DoD-3 false for the tb-vmm lane (V1-must-fix-4).** `run-vmm-x86_64.sh:118-119` pin `M19/M20 … (… skipped)`. **Resolution:** §4/§8 derive status PER LANE from the real round-trip boolean and drop the "fixed 6-OK block" assertion; §3.2 shows the vmm-lane skips explicitly.

5. **M38 fabricated at boot (V2-must-fix-1).** Verified `grep -c M38 kernel/src/main.rs` = 0. **Resolution:** the Cognitive-orchestrator line is DROPPED from the one-liner, §3.1, §3.3, and §4, and gated on a future in-guest M38 marker (§4, §10, DoD-2).

6. **Glyph derivation re-anchored to on-wire tokens (V2-must-fix-2).** Verified: `learning=DORMANT` and `LEXICAL-NOT-SEMANTIC` = 0 in `main.rs`; `MOCK-DETERMINISTIC`=6, `gate-not-met`=5, `KAN_ACTIVE`=3; `main.rs:5150-5168` is a canary counter loop, not a witness line. **Resolution:** §2.2 restricts DERIVED glyphs to `MOCK-DETERMINISTIC`, `gate-not-met`/`KAN_ACTIVE`, and the literal `(… skipped)` forms; the lexical suffix and the whole `[ INFO ]` line are relabeled AUTHORED-HONEST CONSTANTS (lint-gated, not derived); the false `:5153-5165` citation is corrected in §12.

7. **Profile equivocation (V2-must-fix-3).** No `#[cfg]`/feature exists; organs run unconditionally. **Resolution:** §3.2/§6 make substrate a pure RENDER FILTER at stage A and relabel the line `[ INFO ] Cognitive subsystems present in this build but HIDDEN in the substrate view` (never "not present"); a genuine compile-out build is deferred to §10.

### Overclaims — neutralization

- **"can never trip an anchored negative-grep" (§5.3).** Replaced: §2.4/§5.3 state the sufficient reason is DEFAULT-raw / pretty-not-emitted, and enumerate the GLOBAL negatives (ESC, `KEYED-NONCRYPTO`, `transport=…`, key-hex, `forge-test:`, `^guestlog:`).
- **"~40 … mechanical one-call-each."** Corrected to 83 sites + pre-marker witness assemblies; explicitly not mechanical (§1, §5.1).
- **"ZERO CI regression by construction."** Downgraded to "enforced by a committed empty-diff test across three surfaces" (header, §5.3, §8).
- **"ANSI color only on a capable TTY."** Removed; no color emitted (§1.4, §2.3, §9).
- **§3.3 undercount.** Rewritten to show all three grepped surfaces (x86/vmm host, vmm skip pins, decoded aarch64 guest) and to exclude the host-only M38/`conduct:` lines from the DoD-1 baseline.
- **"Secure inference channel" (M30).** Renamed to "Inference transport (plumbing)"; "Secure" is banned on M29/M30 lines (`run-x86_64.sh:445`); M30 honors its `(no host peer, skipped)` skip form.
- **M27 / L2.x rendered flat `[ OK ]`.** Now per-arch DERIVED: `[ OK ]` only on the aarch64 EL2 host lane, `[ SKIP ] (no EL2, skipped)` on x86 and in the guest (§3.1 note, §4).
- **"honest by construction" as a blanket claim.** Scoped: it holds only for the on-wire-derived subset; every other human word is an authored constant, gated by the DoD-2 lint, not "construction".

## Terminology note (2026-07-08)

Yuva is agent-agnostic: the OS never names a specific agent. "Cogi" is the identity of the SEPARATE `cogitave/agent` project, not part of Yuva; the neutral term on every Yuva surface is "the agent" (e.g. `yuva.view=agent`, the "Agent inference" row, "The agent runtime is resident"). Occurrences of "Cogi" that survive in per-landing history, run quotes, or the research records are preserved as written.
