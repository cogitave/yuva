# Yuva Architecture Draft

> Status: v1.0 design draft — decision items are marked **[DECISION]**, strong recommendations **[PROPOSAL]**, open issues **[OPEN]**. Much of this design is now **built and CI-green**: the M0→M38 agent-native milestone chain plus the full sovereignty-L2 aarch64 chain (L2.0→L2.6) are implemented on both architectures — see **[Implementation status (as built)](#implementation-status-as-built)** below for the design→reality map and what is still proposal-stage.
> Basis: [RESEARCH-REPORT](RESEARCH-REPORT.md) · Related: [VISION](VISION.md) · [MILESTONES](MILESTONES.md) · [ROADMAP-V2](ROADMAP-V2.md) · [SOVEREIGNTY-L2-ROADMAP](SOVEREIGNTY-L2-ROADMAP.md) · [MEMORY-SPEC](MEMORY-SPEC.md) · [AGENTS-SPEC](AGENTS-SPEC.md) · [SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md) · [LANGUAGE-AND-STANDARDS](LANGUAGE-AND-STANDARDS.md) · [OPEN-QUESTIONS](OPEN-QUESTIONS.md)

---

## Implementation status (as built)

This document is the design north-star; the honest design→reality map as of the
M38 cumulative tail is below. The authoritative, executable record is the
cumulative serial-marker chain the kernel prints on every boot
([MILESTONES](MILESTONES.md) · [ROADMAP-V2](ROADMAP-V2.md)); the markers cited
below are exactly those strings. Both run scripts grep for the final
`M38: conductor OK turns=N organs=K verdict=ACCEPT` marker (the M38 stage-B
kernel-integrated conductor — M31 is demoted-not-deleted), then assert each
milestone directly and reject
the skip/dormant variant while positively requiring its witness line (and, for
M30, ALSO string-compare the kernel-witnessed challenge/tag against the
`xport-harness` host peer's own line -- the cross-process anti-hollow leg; for
M31, ALSO pin the injection-proofed dump grammar + the ESC tripwire and reject
the live-lane vocabulary by name; for M38, ALSO feed the guest's OWN emitted
`conduct-step:` trace to `conductor-host --recompute-from-trace` and string-equal
the independently re-folded head against the guest's `conduct: head=..` — the
cross-process anti-hollow leg now guest->host).

**Built and CI-green on both architectures (x86_64 + aarch64):**

- **Kernel approach (§1.2–1.4).** The framekernel decision is realized: all
  `unsafe` + asm is confined to `crates/tb-hal`; the `kernel` crate carries
  **zero `unsafe {}` blocks** (not literally crate-level `#![forbid(unsafe_code)]`
  only because `#[unsafe(no_mangle)]` on `rust_main` is itself an unsafe
  attribute); and the pure leaves (`crates/tb-caps-core`, and `tb-hal`'s
  `caps`/`mem`/`ipc`/`blocks`/`infer` modules) are `#![forbid(unsafe_code)]`. The
  hardware foundation (boot, traps, context switch, MMU, user/ring) is M0–M4;
  dynamic memory is M5–M7; preemption M8–M9; per-agent address spaces M10.
  Single-vCPU throughout (SMP is the biggest deferred debt, first designed at L2.6).
- **Kernel object model + capability handles (§2).** M11 (`M11: caps OK`) ships
  the per-principal, generation-checked, rights-masked `Handle` table, the closed
  `SysStatus` enum (not negative-errno), and a single numbered capability-checked
  syscall dispatcher — zero ambient authority. The `Rights` bitset includes the
  §2 agent-semantic rights (`INVOKE_MODEL`/`SPAWN_AGENT`/`WRITE_PROCEDURAL`/
  `RECALL`/`CONSOLIDATE`/`EMIT_EXTERNAL`/`DELEGATE_BUDGET`). The birth protocol is
  M12 (`M12: agent OK`): `tb_agent_spawn(manifest)` mints an `AgentProcess` in its
  own address space holding **only** its manifest-declared handles. The
  rights-subset / no-confused-deputy invariant of this model is **machine-proven
  by Kani** (see Verification posture below).
- **Syscall surface (§4).** Realized as additive method numbers routed through the
  one M11 dispatch chokepoint: `mem` (M13 — `tb_mem_write/read/recall/consolidate`),
  `agent` spawn (M12), `cap` meta-ops narrow/transfer/revoke (M11/M14), channel IPC
  (M14), shared blocks (M15) and `infer` invoke (M16). The richer DAG/QoS/budget/
  consent surface of §4–§6 is partially landed (ordered streams + capability-passing
  channels at M14; the `{cost,speed,intelligence}` preference vector + `model:`
  router at M16) and partly still [PROPOSAL].
- **IPC + protocol layering (§9).** M14 (`M14: ipc OK`) is the single canonical
  kernel IPC dialect: capability-passing channels (a `Handle` **moves** across
  address spaces via the TRANSFER right with dup-attenuation — the auditable
  authority-flow edge), bounded ordered rings, peer-closed semantics. **M14.1**
  (`M14.1: payload OK`) adds variable-length byte payloads via a kernel-heap bounce
  buffer (`copy_to_user`/`copy_from_user`, the only new unsafe, confined to the
  per-arch `arch/*/uaccess.rs` modules); **M14.2** (`M14.2: blocking-recv OK`)
  closes the recv-blocks-on-empty / send-wakes-peer scheduler↔IPC round-trip. The
  MCP/A2A/ACP/ANP userspace bridge daemons remain future work.
- **Memory-central (§3 union dirs, §8 persistence).** M13 (`M13: memory OK`) gives
  every agent a default tiered substrate (T0 context registers / T1 working graph /
  T2 append-only bi-temporal episodic journal / lexical T3 semantic store with
  activation-ranked recall — all fixed-point/deterministic) behind the born-with
  memory-home handle. M15 (`M15: blocks OK`) adds shared memory blocks + a session
  blackboard; M16 fills the inert T3 dense channel; M17 (`M17: consolidate OK`)
  adds the sleep-time consolidation / reflection / forgetting daemons (a
  deterministic heuristic floor decides demote/forget). The §8 orthogonal-
  persistence vision is now realized: **M20** (`M20: persist OK`) lands durable
  virtio-blk backing — a log-structured `BackingStore` with a two-phase commit
  whose on-wire bytes are the Kani-proven `tb-encode::blkfmt` codecs (superblock
  + record-frame + sector/extent math), the round-trip witnessed by
  `persist: gen=.. records=.. replayed=.. prior=..` (the run scripts reject the
  `(no disk, skipped)` variant and require this line). **M21** (`M21: kan-policy
  OK`) adds a *learned ranker strictly inside the M17 heuristic safety envelope*:
  a verified fixed-point ADDITIVE policy cell (`tb-encode::kancell`, a piecewise-
  linear integer GAM, not a neural net) that can re-rank only WITHIN the safe set
  the heuristic gate already admits — it can never widen it (proven by the
  envelope-no-widening harness). It **ships dormant** (`active=0`, the heuristic
  floor still decides) behind a fail-closed loader, pending an offline trace
  bake-off; witness `kan: monotone=1 ovf-safe=1 q-err=.. bound=.. active=0`.
- **LLM-agnostic (§4 infer, §6 context scheduler).** M16 (`M16: infer OK`) is the
  `model:` scheme: a safe in-kernel **router** binds whichever backend registered
  the scheme (`model:anthropic/opus` ≡ `model:local/llama` behind one contract,
  gated by `INVOKE_MODEL`), proven backend-agnostic with a deterministic mock
  provider; the real Anthropic/OpenAI adapters + the vsock GPU/CUDA driver-VM sit
  behind the same `InferBackend` trait on the L2 track.
- **Frozen kernel boundary (§7.6, §10).** M18 (`M18: evolve OK`) realizes the
  frozen-kernel / evolving-userspace split as **capability geometry** on the M11
  rights layer: the held-out evaluators + append-only lineage live in a kernel
  domain that is **never** minted into any agent's handle table, so the whole
  self-improvement safety guarantee **reduces to the M11 rights-mask invariant**
  (which is exactly why that invariant carries a Kani proof). Adds the T4
  procedural/skill tier with verification-before-commit.
- **Tamper-evident memory provenance (§7 audit, §8 persistence).** M22
  (`M22: provenance OK`) makes the memory store **tamper-evident**: a per-agent,
  content-addressed, append-only **hash-chain ledger** over the M13 substrate.
  Every write/forget/skill-admit mutation site folds a canonical, length-prefixed
  `ProvEntry` into the agent's running head via the Kani-proven `tb-encode::prov`
  leaf (injective `canon`, a 256-bit digest -- BLAKE2s-256 unkeyed via the M29
  `khash` leaf since M29 stage C (four domain-separated FNV-1a-64 lanes at
  landing), an order-sensitive `chain_mix` fold, and a sound
  `verify_inclusion`); a forget writes a **tombstone** rather than erasing the
  chain. The boot self-test proves any single-byte tamper of a committed entry
  invalidates both the head and its inclusion proof, witnessed by
  `prov: head=.. entries=.. tamper-caught=1 inclusion=1`. Tamper-evidence is
  **cryptographic since M29 stage C** (khash/BLAKE2s-256,
  `sec=ASSUMED-FROM-LITERATURE` -- the at-landing structural-FNV concession
  closed); a SIGNED root (authenticity) remains the tracked successor.
- **The learning loop (§7 self-improvement) — M23 → M24 → M25.** On top of the
  memory substrate the OS now grows a verified, HONEST learning loop. **M23**
  (`M23: experience OK`) is the Monitor/log layer: each M17 forget/recall decision
  records an injective `ExperienceRecord` (the features + the heuristic action + the
  COUNTERFACTUAL `kan_score` the dormant M21 cell WOULD produce) into a ring folded
  into a SEPARATE `xp_head` (reusing the M22 fold), a recorded row replaying through
  the dormant scorer BIT-IDENTICALLY — claiming ONLY replay-determinism + tamper-
  evidence, never validity. **M24** (`M24: bakeoff OK (gate-not-met)`) is the honest
  activation gate: shielded ε-greedy + a 3-way right-censored survival label + a
  partial-identification lower bound + a one-shot HCPI gate that, on synthetic data,
  correctly **REFUSES** (the cell stays dormant — an honest gate that refuses is a
  success). **M25** (`M25: operator OK`) is the COMMUNICATION pillar's outbound half:
  a typed, tamper-evident operator TRANSCRIPT the OS emits over serial to SURFACE its
  decisions to a human exogenous oracle (the only valid source the self-graded gate
  lacks), anchored to the live M22 provenance head ("which instance am I"), with a
  strictly-monotone `seq` + a closing `GATE_VERDICT` so a reader detects
  mutation/reorder/drop/truncation, and a canon-time held-out-leakage guard
  (Seldonian no-snoop). All four (`prov`/`exp`/`explore`+`bakeoff`/`opframe`) are
  Kani-proven leaves over the SAME M22 fold; M25 is witnessed by
  `opframe: tx_head=.. frames=.. seq_monotone=1
  intro_bound=1 fold-verified=1 tamper-caught=1 keyed=0 oracle=HUMAN-DEFERRED-M26`
  (TX-only; tamper-evidence (cryptographic-hash since M29-C, keyless) + instance binding, NOT crypto authenticity
  and NOT that a human replied — the inbound RX/auth half is **M28**, below).
- **The exit-telemetry producer (§7 self-improvement) — M26.** `M26: exit-telemetry
  OK` adds the learning loop's SECOND experience producer: the EL2 (nVHE) monitor's
  guest-exit demux (the already-Kani-proven L2.2 `el2_trap::classify_exit`) becomes a
  BOUNDED, no-float, injective telemetry record (exit-class + a saturating log2 cost-
  proxy histogram + logical time) folded into a per-instance `tel_head` via the M22
  fold reused verbatim, so the OS *records* its own virtualization workload. It is
  **PRODUCER-ONLY**: the telemetry is recorded + folded, NEVER fed to a policy whose
  decisions change the future exit distribution (the confounding loop the M24 adversary
  named is structurally avoided), and the `tel_head` is SEPARATE from the M23 `xp_head`
  (M22/M23 + M20's two-phase commit stay byte-identical). Witnessed by `exittel:
  head=.. records=.. classes=.. class-total=1 buckets-exact=1 fold-verified=1
  tamper-caught=1 signal=OBSERVATIONAL-NONCAUSAL` — the token machine-forbids claiming
  a causal state-signal.
- **The sovereign time-partition scheduler (§5 scheduling) — M27.** `M27: sched OK`
  is the sovereignty pillar's "Yuva owns time for two guests" rung, printed in the
  L2-track position (after L2.6, before M19): the EL2 (nVHE) monitor arms TWO
  distinct stage-2 roots (VMID 0 + 1) and alternates two EL1 guest stubs in a fixed
  two-slot major frame, each bumping a DISTINCT per-VMID MMIO forward-progress cell
  (a guest cannot fake a non-trapping store), with every `SchedDecision` folded into
  a tamper-evident `sched_head` via the M22 fold — the slot-successor /
  frame-conservation / decision-codec math is the verified `tb-encode::tpsched`
  leaf. **Landed as M27a (the cooperative green floor) then upgraded by M27b to
  REAL CNTHP timer-preemption — the first asynchronous IRQ ever taken at EL2**
  (the 0x480 Lower-EL IRQ vector, `HCR_EL2.IMO=1` only inside the armed window;
  the guest stubs are pure store-spins with NO voluntary yield, so
  `both-progressed=1` is only reachable via genuine timer preemption;
  re-arm-before-EOI + IAR==26 verify + ISTATUS read-back + a hard EOI cap turn
  any storm into a fast red), witnessed by `sched: head=.. frames=.. vmids=0x2
  both-progressed=1 order-honored=1 fold-verified=1 tamper-caught=1
  frame-conserved=1 timing=TCG-NON-CYCLE-ACCURATE realtime=NOT-CLAIMED` — the
  tokens machine-forbid claiming cycle accuracy under TCG or any
  real-time/schedulability guarantee, and the guard REJECTS the retired
  cooperative token (M27a cannot impersonate M27b).
- **The LITERAL full kernel as a stage-2-confined EL1 guest (sovereignty —
  "replace Firecracker"; the M34 prerequisite) — aL2.4b.** `L2.4b:
  el1-kernel-guest OK` is the aarch64-only tail (after M31; x86 prints the loud
  `(aarch64-only, hardware-gated #37, skipped)` token): a SECOND copy of this
  very kernel image, `-device loader`-staged at a pmm-reserved top-32 MiB carve,
  booted as an EL1 guest under the resident EL2 monitor's FIRST NON-IDENTITY
  stage-2 (guest IPA `0x4000_0000+off` → carve PA `0x4600_0000+off`; the
  Kani-proven `tb_encode::stage2::guest_carve_pa` map; NOTHING outside the carve
  + one GIC pass-through block is mapped, so a guest store to a host-RAM IPA
  stage-2-faults). It runs ITS full M0..M31 chain confined — the EL2-gated rungs
  (L2.0..L2.6, M26, M27) take their machine-emitted `(no EL2, skipped)` form
  (BOOTED_AT_EL2=0 via the `_tb_start` path), the device rungs skip via open-bus
  RAZ/WI absence — its serial trapped and re-emitted as injection-proof
  `guestlog:` hex frames (the Kani-proven `tb_encode::guestlog` codec). The
  marker is emitted by the MONITOR from non-text witnessed evidence ONLY (the
  doorbell store-count + the per-boot nonce echo at a watched unmapped IPA, the
  `HVC #17` done hypercall, the final WFI trapped under `HCR_EL2.TWI`, the
  confinement-probe fault, the in-guest discriminator read back from guest
  memory) — never from guest text; the guest's framed chain is corroborating
  (pre-M34 it is OUR trusted image; at the M34 boundary the same bytes drop to
  zero weight — same plumbing). Witnessed by `guestboot: launched=1
  carve=0x46000000+32M nonce=.. doorbell=.. nonce-echo=1 final-wfi=1
  hostram-faults=0 ..` + `guestprobe: ..stage2-fault=1 store-landed=0..` +
  `guestchain: contract-v0=1 entryel=0xff guest-el2=0x0 chain-done=1 m31-tail=1`
  + the honesty-token `guest: guest=FULL-KERNEL-EL1 ram=STAGE2-CONFINED-32M
  loader=QEMU-DEVICE-LOADER gic=PASSTHROUGH-SOLE-GUEST timer=PHYS-PASSTHROUGH
  uart=TRAPPED-EMULATED virtio=OPEN-BUS-ABSENT guestlog=HEX-FRAMED-UNTRUSTED
  exit=WFI-PARK-DOORBELL smp=UP-ONLY rootfs=NONE timing=TCG-NON-CYCLE-ACCURATE
  cachemodel=TCG-COHERENT-UNTESTED realtime=NOT-CLAIMED` line. **Landed as
  Stages 1+2 (confined boot + guestlog + the in-guest acceptance profile);
  Stage 3 — the monitor-PREEMPTIBLE guest (`IMO=1` + the CNTHP deadline + GICD
  emulate + GICC→GICV remap + multi-LR injection) — is deferred.** The monitor
  does NOT yet witness preemption or recursive isolation; the marker claims only
  that the literal full-chain kernel runs as the EL1 guest, stage-2-confined to
  its carve, with zero guest source changes.
- **The operator INBOUND channel (§7.5 human approval, §9) — M28, the
  exogenous-oracle CAPSTONE.** `M28: operator-cmd OK` is the NEW cumulative tail
  marker (printed after M26; M27 stays mid-chain): the RX dual of M25's transcript —
  a typed, fixed-width, injective `CmdFrame` over serial RX
  (`tb-encode::opframe_rx`) by which a human holding TWO enrolled credentials
  answers the OS's freshness challenge and submits a dual-authorized `ACTIVATE_CMD`
  bound to the live M22 head — the channel that finally lets a human command the
  M24 gate. The gate is MACHINE-PROVEN: the conjunctive verdict core is the pure,
  buffer-free/hash-free
  `opframe_rx::verify_decoded(frame, expected_nonce, live_head, mac_ok)`, to which
  `decode_and_verify` delegates its verdict verbatim; Kani drives it fully
  symbolically — `RejectStale` iff echo ≠ challenge, `RejectWrongHead` iff the
  bound head ≠ a fully-symbolic live head, `RejectSingleCred` iff
  `cred_a == cred_b`, `RejectBadMac` iff distinct-creds AND `!mac_ok`, and `Accept`
  IFF every conjunct holds (the Accept-iff-all theorem), plus kind-dominance
  (`NotActivate`) — with the negative controls MUTATION-TESTED (deleting each
  reject branch → VERIFICATION FAILED ×3), while the wrapper's buffer/MAC plumbing
  is host-tested (all 7 verdict arms, run under the Miri CI lane) plus a boot
  self-test. Witness (post-M29): `opcmd: challenge=<hex16> accepted=1
  stale-rejected=1 wronghead-rejected=1 single-cred-rejected=1 badmac-rejected=1
  oldkey-zeroized=1 kan_active=0 mac=KEYED-CRYPTO kdf=DERIVE-THEN-MAC-DOMSEP
  keyevolve=PRF-DOMSEP oracle=SIMULATED-ENROLLED-KEY`, whose machine-emitted
  HONESTY TOKENS the run scripts enforce (overclaim words are rejected):
  `mac=KEYED-CRYPTO` — at the M28 landing the MAC was a NESTED keyed-FNV envelope
  (`mac=KEYED-NONCRYPTO`, genuinely keyed by two 256-bit creds but NOT
  cryptographic — the loudest honesty concession on the board); **M29 landed the
  named successor** (the keyed-BLAKE2s derive-then-MAC, below; the retired
  `KEYED-NONCRYPTO` token is now guard-REJECTED, so the old tier cannot
  impersonate the new); `oracle=SIMULATED-ENROLLED-KEY` — a compiled-in
  test key, NOT a human or an enrolment; `kan_active=0` — an Accept is
  NECESSARY-NOT-SUFFICIENT (`KAN_ACTIVE` is const false; M24's statistical bar
  still gates). Replay scope, honestly: the verifier is pure + stateless —
  per-EPOCH staleness rejection (RejectStale for a different challenge epoch), NOT
  one-shot per-challenge nonce consumption (an identical valid wire re-verifies
  within the same epoch). A pre-merge adversarial review (4 independent skeptics +
  a merge-verdict synthesis) confirmed the core sound and forced two honesty fixes
  before merge (the `verify_decoded` extraction; the one-shot de-overclaim above).
  Named successors (tracked, not blockers; `mac=KEYED-CRYPTO` LANDED as M29): a
  real enrolment ceremony, one-shot nonce consumption (rotate-on-accept in the
  stateful seam), the pending-flag→M24 activation seam (the accepted command is
  today fully inert), and a trustworthy freshness clock.
  With M28 the loop the four pillars were built for is CLOSED — memory (M20–22) ·
  learning (M23–24 + the M26 producer) · communication (OUTBOUND M25 + INBOUND
  M28) · sovereignty (M27) — record (M23) → honestly-refuse (M24) →
  surface-to-human (M25) → record-workload (M26) → schedule (M27) →
  RECEIVE-HUMAN-COMMAND (M28).
- **The KEYED-CRYPTO MAC (the M28 §5 named successor) — M29.**
  `M29: khash-mac OK` (printed after M28; the cumulative tail until M30 landed): ONE new verified primitive
  leaf, `tb-encode::khash` — **BLAKE2s-256 (RFC 7693) in its native keyed mode**
  (width-exact: 32-byte key == `KEY_LEN`, 32-byte digest == `PROV_HASH_LEN`,
  spec-sanctioned 16-byte tag truncation == `MAC_LEN`; the keyed mode carries the
  Luykx–Mennink–Neves FSE 2016 PRF/MAC proof, so NO envelope and NO HMAC wrapper
  sit on top). `opframe_rx::compute_mac` became derive-then-MAC
  (`K_s = khash(key_a, "YUVA-OPCMD-KDF-V1" || key_b)`;
  `tag = khash(K_s, canon)[..16]` — the libsodium `crypto_kdf` precedent; the
  adversarially-chosen-component case rests on a dual-PRF-style assumption,
  Backendal et al. CRYPTO 2023, named not claimed-around) and `key_evolve` became
  `khash(key, "YUVA-KEY-EVOLVE-V1")` (Bellare–Yee forward-security shape,
  domain-separated from MAC use) — signatures UNCHANGED, so `seal` /
  `decode_and_verify` / the four hash-free M28 gate harnesses carry over
  verbatim. The prove/assume boundary is MACHINE-EMITTED on the `khash:` witness
  line — `prim=BLAKE2S-256 keylen=32 tag=128 kat=RFC7693-PASS
  sec=ASSUMED-FROM-LITERATURE sidechannel=NOT-CLAIMED`: Kani proves totality /
  determinism / official-KAT correctness / tamper-at-symbolic-flip-index on
  CONCRETE inputs (4 `kani_khash_*` harnesses, each mutation-tested; deliberately
  NO symbolic collision/preimage/PRF harness — the field proves implementations,
  never primitives: Appel TOPLAS 2015, HACL*, aws-lc, mlkem-native), while
  collision/preimage/PRF/forgery resistance is ASSUMED from the cryptanalysis
  literature (best published attacks ~6.75–7.5 of 10 rounds, pseudo settings
  only). `kat=RFC7693-PASS` is EARNED per boot — `khash::kat_ok()` recomputes the
  RFC 7693 Appendix B + BLAKE2 reference-KAT vectors through the REAL compression,
  fail-closed, before the kernel renders the token. The selftest also TESTS
  old-key erasure (snapshot → evolve → zeroize → assert; `oldkey-zeroized=1` —
  forward security is conditional on erasure, so the stateful seam demonstrates
  it; TESTED, not proven). khash is the named enabler for the #74
  provenance-hash cutover (`prov_hash` → `khash::uhash`) and #75 Merkle
  inclusion proofs; the #74 signed root is a separate signature primitive,
  explicitly out of khash scope.
- **The verified INFERENCE TRANSPORT (stages A+B) — M30, the cumulative
  tail until M31 landed.** `M30: infer-transport OK` (printed after M29): the sovereignty
  A-chain's channel to a host model peer (#87), promoting the M22 runner-up
  with the anti-hollow amendment that makes its in-kernel mock-loopback
  structurally impossible. ONE new verified codec leaf, `tb-encode::inferwire`
  (the 20th — the typed, fixed-header, length-prefixed, injective `InferFrame`,
  house magic `0x5958`; fail-closed `canon`/`decode`; the `FrameAccum`
  byte-stream re-framer with proven never-overflow scan-to-next-magic resync;
  the `resp_binds_req` correlation iff-theorem; and the host-keyed
  `echo_tag`/`verify_echo` — exactly ONE domain-separated khash call,
  `khash(K, "YUVA-M30-ECHO-V1" || peer_id || nonce || challenge || body)[..16]`,
  binding the challenge + host nonce + lane label INSIDE the MAC), carried by
  the kernel's FIRST TWO-queue virtio driver — a modern (Version==2 readback)
  virtio-console (DeviceID 3), VERSION_1-only (F_MULTIPORT/F_SIZE/F_EMERG_WRITE
  rejected, so the device is exactly receiveq(0)+transmitq(1) on port 0), the
  rx buffer posted BEFORE DRIVER_OK, poll-only (`mode=POLL`, guard-pinned
  against a silent IRQ migration until a #71 disposition) — to the
  `xport-harness` HOST peer over a QEMU virtconsole chardev unix socket on both
  TCG lanes (`transport=QEMU-CHARDEV-HARNESS`, `bus=SERIAL-FRAMED`). THE
  ANTI-HOLLOW DoD IS A TWO-LEG COMPOSITION: the host custodies a per-run OS-RNG
  key K + nonce N (never in the guest image/cmdline/config space), applies the
  khash echo and reveals K on the channel; the kernel recomputes + verifies and
  fires four in-boot negatives (badtag/wrongkey/partial/desync) — leg 1,
  `echo=HOST-KEYED-VERIFIED`, an explicitly KERNEL-SCOPE token; the run scripts
  then string-compare the kernel-witnessed challenge/tag against the harness's
  OWN printed line — leg 2, the loopback killer (a loopback can mint a
  self-consistent tag but cannot equal `khash(K, ..)` without guessing 32
  OS-RNG bytes) — plus skip/loopback-by-name rejects, the lane cross-pin, the
  `mode=IRQ` tripwire, a key-leak negative, and strip-then-reject overclaim
  guards. HONEST: `key=HOST-CUSTODIED-PER-RUN` claims custody, NOT
  confidentiality (K is cleartext on the channel — host *participation*, not
  exclusivity, until the M33 signature primitive); `backend=ECHO-ONLY` (no
  model, no inference semantics — the M31 adapter brings meaning); no
  network/TLS (a LOCAL host process, reject-enforced); desync recovery is
  decoder-level, not live-ring (named deferral). **Stage C — the tb-vmm
  virtio-console device backend (`transport=TB-VMM-HOST`, `bus=VIRTIO-MMIO`,
  tb-vmm's first `mmio_bus` device) — LANDED as its pre-authorized
  follow-up**: `tb-vmm/src/virtio_mmio.rs` (the modern Version=2 DeviceID-3
  register file + split-virtqueue walker at scan-slot 0, exactly the register
  set the kernel driver touches) fronts `tb-vmm/src/infer_host.rs`, the
  in-process host peer running the SAME `tb-encode` inferwire math as the
  chardev harness (the keyed echo + the M31 mock serve loop);
  `run-vmm-x86_64.sh` bumped from its M19 marker to the full cumulative M31
  tail with the §5 guard block ported (leg-2 cross-process equality against
  the `--xport-out` witness stream the guest cannot write, the key-leak
  negative, both lane cross-pins) — the whole M0..M31 chain is CI-required
  under tb-vmm/KVM whenever `/dev/kvm` is present. The chardev lanes remain
  the REQUIRED accel-independent both-arches DoD.
- **The verified INFERENCE ADAPTER, stages A+B (the mock lane) — M31, the NEW
  cumulative tail.** `M31: infer-e2e OK backend=MOCK-DETERMINISTIC` (printed
  after M30): the first MEANING on the M30 channel (#89). The `inferwire` leaf
  is EXTENDED — deliberately NOT a 21st leaf (same magic, same ver, the M30
  header codec byte-identical) — with the closed kinds
  `INFER_REQ`/`INFER_RESP`/`INFER_PENDING`, closed-enum `ERR` payload
  semantics (10 codes, the retryable flag BOUND to the code; raw provider
  text never rides the wire), the 24-byte IN-PAYLOAD chunk sub-header (seq +
  MORE + total_len + whole-body digest[16]) for stop-and-wait chunking under
  the UNTOUCHED 1024 payload cap, the compile-time shared
  `INFER_BODY_CAP=8192` (reject-never-truncate — both ends compile the SAME
  leaf, so compile-time agreement is the negotiation), the per-chunk MAC
  `khash(K, "YUVA-M31-INFER-V1" || peer || nonce || challenge || req_id ||
  kind || seq || sflags || total_len || body_digest || chunk)[..16]`
  (everything that adjudicates INSIDE the MAC — a reordered/spliced chunk
  fails VERIFICATION, not just assembly), the Kani-proven chunk-at-a-time
  fail-closed `InferAssembler` (completion requires digest-commitment
  equality; any reject poisons), and the SHARED deterministic `mock_infer`
  transform (1280 B — always chunks). The kernel retires the M16 u64 toy:
  the object-safe zero-alloc `infer_bytes` byte path + `M_MODEL_INVOKE_BYTES=32`
  at the SAME `INVOKE_MODEL` chokepoint (byte buffers ride the kernel facade,
  the M14.1/M15 precedent; the scalar path stays for M16 compatibility).
  EVERY BOOT, the mock-lane e2e: an in-kernel agent recalls M13 context
  through the chokepoint (stamping the unfiltered RECALL_TOUCH survival
  trace), serializes the scalars into the byte prompt
  (`context=M13-SCALAR-RECALL`), runs the ROUTES-registered
  MOCK-DETERMINISTIC backend, folds `req_id || op_hash(response)` into the
  M25 transcript BEFORE its closing GATE_VERDICT (the DIGEST, never the dump
  — the transcript is 5 frames since M31), then proves the WIRE legs against
  the keyless harness serve loop: a MAC'd `ERR code=NO-KEY` answer to the
  designated probe (`wire-err-handled=0x1` — the fail-closed path transits
  the boundary in-boot), EXACTLY ONE MAC'd `INFER_PENDING` heartbeat
  (liveness plumbing, never a completion), the deterministic response as 2
  MAC'd chunks reassembled + digest-verified + required BIT-EQUAL to the
  in-kernel expectation (the cross-process determinism check), and four
  in-boot negatives (badmac/digest-mismatch/oversize/err-taxonomy).
  INJECTION-PROOFING: all model-derived bytes cross serial ONLY
  lowercase-hex-encoded (`infer-dump:` lines — regex-inert, ESC-tripwired,
  grammar-pinned by the guards), with out-of-band `resp-len=` and the
  fixed-width `resp-digest=` commitment. HONEST: `backend=MOCK-DETERMINISTIC`
  (a transform, NOT a model — the e2e proves plumbing, never intelligence;
  the strip-then-reject guards ban the vocabulary), `key=CAPREF-HOST-CUSTODIED`
  (no secret exists anywhere on the mock lane), `host=RESIDUAL-TCB`,
  `ambient=ZERO-IN-GUEST` (scoped in-guest only). **Stage C — the
  ANTHROPIC-LIVE bridge (`ureq`+`rustls`+`serde_json`, host-bridge-only per
  the LANGUAGE-AND-STANDARDS §0/§6 [DECISION] rows), `real-infer.yml`
  (`workflow_dispatch`), the challenge-nonce liveness protocol, and
  `M31: real-infer OK backend=ANTHROPIC-LIVE` — is the OPERATOR'S lane:
  secret-gated, never a required check, never unattended, its marker banned
  from the cumulative chain by name.**
- **The kernel-integrated CONDUCTOR, stage B (TRINITY ADOPT-1) — M38, the NEW
  cumulative tail.** `M38: conductor OK turns=N organs=K verdict=ACCEPT` (printed
  after M31; #105): a tiny Kani-verified discrete scheduler that ORCHESTRATES the
  landed organs under a HAND-WRITTEN (not learned) policy. EVERY BOOT, the in-kernel
  selftest agent drives the Verifier-gated organ loop FROM THE GUEST through the cap
  chokepoint — `M_MEM_RECALL` (the M13/M20 BM25 lexical recall, the
  RetrievalOverMemory organ; `retrieval=LEXICAL-NOT-SEMANTIC`) -> the discrete Worker
  score over that context -> `M_MODEL_INVOKE_BYTES` (the MOCK organ through the
  landed `INVOKE_MODEL` possession gate, the LocalM32/ExternalMock organs;
  `local-organ=M38-AUTHORED-MOCK`, `external-organ=MOCK-IN-CI`) -> the
  `tb_encode::conductor` discrete Verifier verdict (`verifier=CI-DISCRETE-VERDICT`,
  the `bakeoff::gate_clears` shape, NEVER a learned classifier), looping
  select-organ->assign-role->until-ACCEPT, `MAX_TURNS=5` BOUNDED (no unbounded wait).
  The honest 2-hop task measures a >=2-organ sequence with a >=1 REVISE->ACCEPT
  cycle; each orchestration DECISION folds into a `conduct_head` via the M22 prov
  fold REUSED verbatim (under the new `prov::kind::CONDUCT_DECISION` tag), SEPARATE
  from every other fold head (M22/M23/M25/M26/M27 stay byte-identical — the conductor
  folds on its OWN lane). The guest emits the `conduct:` witness + per-step
  `conduct-step:` trace (hex-only, injection-proof) + the marker; the HOST feeds the
  guest's OWN emitted trace to `conductor-host --recompute-from-trace`, which
  INDEPENDENTLY re-folds the lineage via the SAME verified leaf in a SEPARATE process,
  and the run script string-equals the two heads — the cross-process anti-hollow leg
  (now guest->host; a forged summary or doctored trace diverges). HONEST: the policy
  is `policy=DISCRETE-HAND-WRITTEN-NOT-LEARNED`, `learning=DORMANT`, the M18.1
  human-approval gate is `m18-gate=ADMISSION-ONLY-INERT-IN-MOCK` (no high-impact organ
  -> its fail-closed branch is never reached), the cost record is the LOGICAL
  surrogate (`cost-metric=LOGICAL-SURROGATE-NOT-WALLCLOCK`), `novelty=VERIFIED-
  PROVENANCE-SOVEREIGN-WRAPPER` (not a new learning paradigm), `benchmark=NOT-CLAIMED`.
  The real M32 local engine as a conductor organ is the #90 follow-up; the live
  external organ in-loop is dispatch-only/operator-gated (the `conductor-live.yml`
  successor). M31 is demoted-not-deleted (asserted directly beneath the M38 tail).

**Verification posture.** Two complementary machine-checked seams guard the
silicon-adjacent value computation, both verifying the **exact same code the
kernel runs (zero model drift)**.

*M11 capability proof.* M11's rights-subset / no-confused-deputy invariant is
machine-proven by **Kani** over `crates/tb-caps-core` — the single source of truth
for the `Rights` algebra and the generation-checked `CapTable`, which `tb-hal`
re-exports verbatim and wraps as `CapTable<Rc<Object>>`: 12 `#[kani::proof]`
harnesses (`src/proofs.rs`) in three tiers — the `Rights` algebra over the full
2³² bit space, one proof per capability operation on the real `CapTable`, and an
inductive single-step no-widen preservation proof (plus a bounded-sequence
cross-check and a documented negative control). `scripts/verify-caps.sh` fails
closed unless every harness verifies and the count matches the pinned constant,
then emits `M11: caps-subset PROVEN`.

*The `tb-encode` VERIFIED-LEAF pattern.* This is now the **dominant** way value
computation ships. A pure leaf in `crates/tb-encode` (`#![no_std]`
`#![forbid(unsafe_code)]`, zero-dep, host-buildable, **no float**) computes WHAT a
bit pattern should be; `tb-hal` keeps the silicon-`unsafe` store next to the
just-computed value, so the hardware side is byte-identical while the value is
provably-safe. Each leaf carries Kani harnesses (concretized / bounded so they
stay tractable — the #49 symbolic-array state-explosion is the documented trap)
plus a negative control, and is also covered by the Miri UB gate. The 24 leaves:
`vmx` (control-MSR adjust legality + CR0/CR4 fixed-bit clamp + TSS-base decode),
`paging` (radix-512 page-table + EPT entry algebra), `ipc_frame` (the 16-byte IPC
wire codec + bounded ring), `route` (the M16 `model:` scheme grammar + longest-
prefix routing), `memscore` (the M13 fixed-point recall-ranking math + M17 forget
inputs + M18 frozen skill transform), `stage2` (L2.1 aarch64 stage-2 VMSAv8-64
descriptors + VTCR/VTTBR packers), `el2_trap` (L2.1/L2.3 ESR/HPFAR/FAR + sysreg/
MMIO ISS decoders + the aL2.5 GICH_LR vIRQ encoder), `smmuv3` (the aL2.6 SMMUv3
stage-2 STE + command-queue algebra, with the lemma that the SMMU stage-2 IS the
CPU stage-2 geometry), `blkfmt` (the **M20** durable-persistence codecs:
superblock, record frame, sector/extent math), `kancell` (the **M21** verified
fixed-point additive policy cell — spline totality, in-band score, structural
monotonicity, envelope-no-widening), `prov` (the **M22** provenance-ledger
math: injective `canon`, BLAKE2s-256 digest (khash since M29-C), order-sensitive fold, sound
inclusion), `exp` (the **M23** experience codec: fixed-width injective record +
ring + replay-determinism, reusing the M22 fold), `explore` + `bakeoff` (the
**M24** honest-gate math: shielded ε-greedy propensity, the 3-way censored survival
label, the partial-id lower bound, the one-shot HCPI gate), `opframe` (the
**M25** operator-transcript codec: injective length-prefixed frame, the held-out-
leakage guard, strict-monotone seq, intro-binding, and tail-truncation detection,
reusing the M22 fold), `exittel` (the **M26** EL2 exit-telemetry codec: the
reused L2.2 `classify_exit` + a no-float log2-bucket histogram + a fixed-width
injective record + the M22 fold reused, PRODUCER-only), `tpsched` (the **M27**
two-VMID time-partition scheduler math: the round-robin slot successor, frame
conservation, and the injective `SchedDecision` codec, the M22 fold reused), and
`opframe_rx` (the **M28** operator-command RX codec — the RX dual of `opframe`: a
fail-closed injective `CmdFrame` decode plus the pure `verify_decoded` conjunctive
verdict core, proven Accept-iff-all over stale-nonce / wrong-head / single-cred /
bad-MAC rejection, plus key forward-evolution — the MAC + evolution bodies since
M29 call the khash leaf), and `khash` (the **M29** keyed-hash primitive:
BLAKE2s-256 per RFC 7693 in its native keyed mode + the unkeyed form, the ONE
cryptographic primitive behind `mac=KEYED-CRYPTO` — official-KAT-pinned,
concrete-input Kani proofs only, primitive security
`sec=ASSUMED-FROM-LITERATURE` by design), and `inferwire` (the **M30**
inference-transport codec: the injective length-prefixed `InferFrame` +
fail-closed `canon`/`decode`, the `FrameAccum` byte-stream re-framer with
proven never-overflow resync, the correlation iff-theorem, and the host-keyed
`echo_tag`/`verify_echo` -- ONE domain-separated khash call binding
peer_id‖nonce‖challenge‖body inside the MAC; mutation-tested per the M30
proposal §6; EXTENDED at M31 with the closed inference kinds + closed-enum ERR
semantics, the 24-byte chunk sub-header, the compile-time `INFER_BODY_CAP=8192`,
the per-chunk `infer_tag`/`verify_infer_resp`/`verify_infer_req` MAC under the
NEW `"YUVA-M31-INFER-V1"` domain, the chunk-at-a-time fail-closed
`InferAssembler`, the closed `errcode` enum, and the shared deterministic
`mock_infer` transform -- +6 harnesses, the khash-bearing pair in the
PINNED-VECTOR one-khash-execution shape, mutation-tested per the M31 proposal
§8), plus the **M33** provenance-lineage leaves: `sha256` (the FIPS 180-4 / RFC
6234 second in-house verified hash — RFC 8554 pins SHA-256, so `conformance=
RFC8554`; streaming + one-shot, official-KAT-pinned), `lmsig` (the RFC 8554 LMS
`lms_verify` VERIFY-only leaf — LM-OTS Winternitz chains + the Merkle auth-path
fold, the `w=1` toy Kani instance + the pinned full-`W4`/`H10` KAT vectors
`PROV_KAT_*`; the private-key signer is cfg-gated OUT of the kernel), `attest`
(the DSSE-PAE-shaped fixed-width in-toto-Statement-subset attestation codec), and
`provhead` (the **M33 stage-B** multi-sector torn-write-safe persisted-signed-head
codec: a record-spanning FNV-64 catches a torn MIDDLE sector, a per-sector
`gen_tag` catches a mixed-gen torn commit, and the pure `pick_newer` two-phase-
`gen` recovery selector the `tb-hal` ping-pong reader delegates to — `+2`
harnesses `kani_persisted_record_decode`/`_recover`, mutation-tested per the M33
proposal §9). Since **#101** the CI lane is **sharded into two cost-balanced
parallel jobs** (`prove-encode-a`/`prove-encode-b` — the first post-M29-stage-C
pass measured 41m22s of the 45-min cap, past the pre-agreed ~38-min option-4
trigger); the shard lists, the per-shard pinned counts (the list lengths) and
the pinned total **`EXPECTED_HARNESSES_TOTAL=102`** live in ONE place,
`scripts/kani-shards.sh`, consumed by `scripts/verify-encode.sh`
(`SHARD=a|b|all`; `all` = the unchanged local single full pass). Every mode
first runs the fail-closed **completeness guard** (lists disjoint + exhaustive,
in lockstep with the `#[kani::proof]` count in `proofs.rs`), then fails closed
unless the shard's pinned count of harnesses verify and zero fail, then emits
`V1-shard-a: kani-encoders OK` / `V1-shard-b: kani-encoders OK` (the full pass
keeps `V1: kani-encoders OK`). Adding a harness is **one-touch**: the new name
goes into exactly ONE shard list plus the total in `kani-shards.sh`, so a
vacuous, deleted, renamed, or shard-unassigned harness fails the
gate. Kani is installed locally in WSL (`cargo-kani`), so a new/changed harness
should be measured with `cargo kani -p tb-encode --harness <name>` BEFORE pushing,
since the `prove-encode-*` lanes have hard timeouts.

*CI lanes.* Ten distinct CI jobs across eight workflow files guard the tree:
**ci** — the one required full-chain dual-arch gate, building on the runner and
booting both arches under pure QEMU-TCG to the final `M31: infer-e2e OK backend=MOCK-DETERMINISTIC`
marker (since M30 each lane also spawns the `xport-harness` host peer
against a QEMU virtconsole chardev socket and cross-process-compares the M30
challenge/tag between guest serial and harness stdout; since M31 the harness's
serve loop additionally answers the MAC'd chunked mock inference exchange the
M31 guards adjudicate)
(the aarch64 boot runs **inside a `debian:trixie-slim` qemu-10 container** because
the L2.6 SMMUv3 stage-2 rung needs qemu ≥ 9.0, which the runner's apt qemu 8.2.2
lacks); **vmm-boot** (`tb-vmm` boots the kernel via `tb-boot v0` on x86_64
`/dev/kvm`, asserting — since M30 stage C — the full cumulative M31 tail over
tb-vmm's own virtio-console backend with the M30/M31 guard blocks
(`transport=TB-VMM-HOST` cross-process equality + key-leak negative), plus the
QEMU+KVM boot-time benchmark);
**l2-nested-vmx** (informational — the real L2.0 VMX-root verdict under nested
KVM, checking the chain reached `M18: evolve OK`); **microvm-kvm** (required —
QEMU microvm + KVM `-cpu host`, the #36 LAPIC config, asserting the chain reaches
`M18: evolve OK`, plus a non-blocking `--release` boot-ready-cycles bench);
**kani** (three jobs: `prove-caps` over `tb-caps-core` = 12 harnesses, and the
#101 cost-balanced shard pair `prove-encode-a`/`prove-encode-b` over `tb-encode`
= 52 + 50 of the 102 harnesses, completeness-guarded); **miri** (the Tier-0 dynamic UB
gate over the forbid-unsafe leaf crates, `T0: miri OK`); **clippy** (static-lint
over the forbid-unsafe leaf crates, `S0: clippy OK`); and **bench** (non-blocking
`tb-vmm` vs Firecracker boot benchmark). `CARGO_INCREMENTAL=0` is the CI
discriminator (it changes `.bss` symbol ordering and has exposed layout-sensitive
bugs); every local boot-verify must set it on the `cargo kbuild` invocation to
match CI.

**Sovereignty-L2 (§1.2 host substrate).** The L2 track — Yuva as its own minimal
Type-1 microhypervisor, replacing `/dev/kvm` with `tb-core` — now runs an
**L2.0→L2.6 aarch64 sovereignty chain inside every boot** (`L2.0: el2 OK` EL2
nVHE world-switch → `L2.1: stage2 OK` stage-2 demand-translation → `L2.2:
el2-exits OK` exit-dispatch → `L2.3: el2-trap OK` trap-and-emulate → `L2.4:
el2-guest OK` a nested EL1 guest with its own stage-1 under our stage-2 → `L2.5:
vgic OK` vGIC vIRQ injection → `L2.6: smmu OK` SMMUv3 stage-2 STE programming,
proven on qemu ≥ 9.0 and a green skip below), with the silicon-unsafe asm confined
to `crates/tb-hal/src/arch/aarch64/` and the bit algebra in the proven `stage2` /
`el2_trap` / `smmuv3` `tb-encode` leaves. On x86_64, `L2.0: vmxroot OK` covers
VMXON + a minimal
VMCS + an EPT identity map + a world-switch + a 1-instruction nested guest whose
VM-exit is caught — all silicon-unsafe confined to
`crates/tb-hal/src/arch/x86_64/vmx/`; **but under QEMU-TCG (and most hosted CI) the
VMX CPUID bit is refused, so this is a graceful skip**
(`L2.0: vmxroot OK (vmx unavailable, skipped)`) — the real VMLAUNCH/world-switch
proof is gated on a nested-VMX substrate (the `l2-nested-vmx` lane) that hosted CI
lacks. On aarch64, `L2.0: el2 OK` is a **genuine, executing** nVHE EL2 world-switch
(HVC→ERET→EL1 guest stub→HVC→EL2 round-trip) that runs under pure TCG on a stock
runner. Each boot prints both lines; the off-arch one is a green `n/a`. The full
L2.0→L2.9 plan is [SOVEREIGNTY-L2-ROADMAP](SOVEREIGNTY-L2-ROADMAP.md).

**Still design-stage [PROPOSAL].** The richer scheduling algebra (§5 — Soar
preferences, impasse traps, ACT-R retrieval pricing, QoS admission control), the
context/token resource scheduler with local+remote driver families (§6), the
signed-manifest / human-approval / isolation-ladder mechanisms (§7.3–§7.5), and the
MCP/A2A/ACP/ANP bridge daemons (§9) are not yet built — they remain the design
targets this document sets.

---

## 1. Kernel Approach Comparison and Decision

### 1.1 Candidates (with verified data)

| Approach | Strength | Weakness | Source |
|---|---|---|---|
| **Capability microkernel** (seL4/Zircon class) | TCB ~10 kSLOC (1/1000th of Linux); 29% of critical vulnerabilities vanish, 55% drop below critical; everything is a capability including time/compute; auditing at a single object-lookup point | Inter-service IPC cost; you build the driver/service ecosystem yourself | seL4 whitepaper; Biggs'18; Capsicum |
| **Unikernel / library OS** (Unikraft/Mirage class) | ~1 MB image, <10 MB RAM, ~1 ms boot, 1.7–2.7× perf; only the needed component is compiled (the direct equivalent of the "no-bloat OS" principle); hypervisor = isolation | Single address space — internal protection falls to the language/compiler; no multi-tenant single image | arXiv:2104.12721; ASPLOS'13 |
| **Exokernel** | Protection ↔ management separation is proven (secure bindings, visible revocation, abort protocol); the kernel protects resources without understanding their semantics → LLM-agnosticity theorem | No production ecosystem in pure form; dependent on libOS quality | SOSP'95 |
| **MicroVM substrate** (Firecracker class) | Production-proven (AWS Lambda); tens of thousands of concurrent agent sandboxes at E2B; the VM-vs-container dilemma is a false dilemma | Not a kernel but a substrate — still needs a guest OS on top | NSDI'20; e2b.dev |

### 1.2 **[DECISION] Hybrid: "Capability core + unikernel body + exokernel spirit"**

Yuva layers the three approaches — they are not rivals but answers for different layers:

```
┌─────────────────────────────────────────────────────────────────┐
│  HOST: hypervisor (KVM / Firecracker-class VMM)                 │ ← production-proven substrate
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Yuva NODE IMAGE (single image booting as a unikernel)     │  │ ← Unikraft-style modular build
│  │  ┌──────────────────────────────────────────────────────┐ │  │
│  │  │ TB-CORE (frozen capability core, target ≤15kSLOC)    │ │  │ ← seL4/Zircon lessons
│  │  │  handle+rights · scheme dispatch · task machine ·     │ │  │
│  │  │  token-budget controller · event streams ·            │ │  │
│  │  │  checkpoint/persistence · held-out evaluator domain   │ │  │
│  │  └──────────────────────────────────────────────────────┘ │  │
│  │  TB-SERVICES (userspace daemons, scheme providers):        │  │ ← Redox lesson: userspace where possible
│  │   memory: · model: · tool: · agent: · trace: · discovery   │  │
│  │  AGENTS: WASM nanoprocess (tool/skill) +                   │  │ ← Bytecode Alliance
│  │   per-agent/per-tenant sub-microVM/unikernel as needed     │  │ ← Mirage model
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

- **The core is a microkernel** because our security claims (no ambient authority, measurer-measured separation, mutually-suspicious agents) require a small, auditable TCB — the numbers support this (three orders of magnitude, 29%/55%).
- **The body is a unikernel** because the "no-bloat OS" principle requires compile-time modularity and our agent spawn target (<50 ms) is achievable with ~1 ms boot images.
- **The spirit is exokernel** because the kernel does *not understand* the agent's memory/model semantics; it only establishes secure bindings, revokes them visibly (including stripping the context/tool quota from a runaway agent), and leaves policy to the agent's libOS (end-to-end argument).
- **The substrate is microVM** because hardware-backed isolation at the tenant boundary is the only trustworthy answer today (WASM side-channel admission; gVisor cost profile).

**[OPEN]** Whether the Phase-1 prototype will be user-mode on top of Linux or a direct Unikraft port ([OPEN-QUESTIONS](OPEN-QUESTIONS.md) §Architecture).

### 1.3 Implementation Language **[DECISION — detail: [LANGUAGE-AND-STANDARDS](LANGUAGE-AND-STANDARDS.md)]**

From the kernel to the protocol bridges, **Rust** (frozen kernel `no_std` + framekernel pattern: all `unsafe` in a small foundation crate, `#![forbid(unsafe_code)]` above it). The rationale is production-proven: Android memory-safety vulnerabilities 76%→24% (2019-2024), Rust in production in the Linux/Windows/AWS kernels, Asterinas's 15 kLOC framekernel TCB. C only in vendored llama.cpp behind a driver daemon; Python/TS only in external SDKs + network-bound inference engines (vLLM/SGLang). The substrate (Firecracker/crosvm) is already Rust. If certification-class kernel verification is needed, the path to building the node image on top of seL4 is open ([OPEN-QUESTIONS §I](OPEN-QUESTIONS.md)).

### 1.4 Kernel Foundation and Assembly **[DECISION — detail: [KERNEL-FOUNDATION-SPEC](KERNEL-FOUNDATION-SPEC.md)]**

The kernel boots as a Firecracker/KVM guest (not bare-metal) → large amounts of boot asm are eliminated. ALL `unsafe`+asm in a single `tb-hal` foundation crate (`#[unsafe(naked)]`+`naked_asm!`/`global_asm!`, Rust ≥1.88); `#![forbid(unsafe_code)]` above it. x86_64 **LinuxBoot** (enters 64-bit, no trampoline), aarch64 **PE-Image** (MMU cold, bring-up required). Single-vCPU (Mirage) → AP/SMP asm not in v1. Assembly work items split into 13 units (A1-A13), the build into 5 milestones (M0 boot → M1 trap → M2 context-switch → M3 MMU → M4 v2-user); each unit has an executable DoD (Firecracker+QEMU CI, both arches). Kernel-verification decision: pure-Rust + tiered-assurance (Miri+Kani mandatory, Verus selective). **Sovereignty:** Yuva inherits zero Linux code/design; canonical boot = our own `tb-boot`/`tb-vmm`, Firecracker is only the bootstrap loader (detail + the 'we don't carry old bugs' ledger: [SOVEREIGNTY](SOVEREIGNTY.md)).

## 2. Kernel Object Model **[PROPOSAL]**

The Zircon template, with agent semantics:

- **Objects** (refcounted, accessible only via handle): `Agent`, `Session`, `Task`, `MemTier`, `MemRecord`, `Block`, `Skill`, `ModelSession`, `ToolConn`, `Budget`, `Stream`, `Namespace`, `Evaluator`(held-out).
- **Handle = {object, rights, owner}**; duplication only by lowering rights (`tb_handle_dup` ⊆ rights); transfer only via channel (an auditable authority-flow graph — the self-improvement service learns least-authority manifests from this graph).
- **Agent-semantic rights** (parallel to READ/WRITE/TRANSFER/DUP): `INVOKE_MODEL`, `SPAWN_AGENT`, `WRITE_PROCEDURAL` (a separate right per CoALA risk asymmetry), `RECALL`, `CONSOLIDATE`, `EMIT_EXTERNAL` (writing to the outside world), `DELEGATE_BUDGET`.
- **Birth protocol [DECISION]**: a new agent starts with a **single bootstrap channel handle** (Zircon model); its manifest's prefix table is translated by the kernel into a handle set — *what is not in the table is unreachable*; the authority set is fully enumerable at spawn time.

## 3. Namespace and Resource Addressing **[PROPOSAL]**

A Plan 9 + Fuchsia + Redox synthesis:

- **No global root** (Fuchsia): each agent's namespace is the prefix→handle table in its manifest. `..` traversal does not exist at the protocol level → the path-traversal class of prompt-injection exploits is not representable.
- **Typed schemes** (Redox): `memory:`, `model:`, `tool:`, `agent:`, `task:`, `fs:`, `trace:`, `budget:`. `model:anthropic/opus` and `model:local/llama` are two provider daemons of the same contract — **LLM-agnosticity = who registered the scheme.**
- **Synthetic introspection tree** (Plan 9): a kernel-served `/agent/<id>/{status,ctl,context,goals,memory/{working,episodic,semantic,procedural},inbox,trace,budget}` for each agent; `status` is single-line fixed-format text, `ctl` accepts text verbs (`pause`, `checkpoint`, `compact-context`, `reflect`). Text = the LLM's natural ABI; `cat` is the universal introspection verb; the supervisor's `ps` is `cat` over a union. Interposition (the iostats pattern) = audit/budget/guardrail proxies splice in without touching the agent.
- **The deliberate limit of the file metaphor** (Plan 9's own lesson): spawn and KV/embedding sharing are not files — `tb_agent_spawn(manifest)` is a typed syscall + a local-only mmap primitive; `/agent/<id>/` is only *representation and control*.
- **Union directories**: the session-scratch memory tier is bound on top of the persistent tier; reads fall through in order — the ergonomics of tiered memory come for free.
- **Storage (`fs:`) [PROPOSAL]**: the file system is natively a *semantic + versioned* VFS — vector index and rollback are at the VFS layer, not bolted on (AIOS builds this in userspace with chromadb+Redis; the `sto_mount(collection)` mount metaphor and LSFS [ICLR'25] are precedents). The T5 archival memory tier and the file store **merge into a single storage manager** (the Letta finding: one manager can serve both file and memory-passage retrieval) — [OPEN: OPEN-QUESTIONS §C].

## 4. Syscall Surface (draft) **[PROPOSAL]**

The AIOS lesson: structural call + NL payload. The MCP lesson: errors return model-readable, suited to self-correction. The Capsicum lesson: all auditing at a single lookup point; denial `TB_ENOTCAPABLE` + leaves a trace (self-improvement feeds on these traces).

```
FAMILY      CALLS (summary)
──────────  ────────────────────────────────────────────────────────────
infer       tb_infer_submit(dag, qos, prefs) → future[]   # Parrot: DAG + target only the terminal output
            tb_infer_cancel(future)                        # MCP cancellation
mem         tb_mem_write(tier, record, policy) / tb_mem_read(query, pipeline)
            tb_mem_manage(op)                              # consolidate/demote/tombstone (see MEMORY-SPEC)
            tb_recall(cue, opts) · tb_reflect() · tb_learn(artifact)   # the CoALA triad
tool        tb_tool_call(conn, wit_typed_args) → typed_result|model_readable_error
agent       tb_agent_spawn(manifest) → handle · tb_agent_fork(h, hints) → handle   # shared-prefix hint (SGLang)
            tb_agent_send(h, msg) · tb_agent_watch(h) → stream
task        tb_task_create/get/cancel/subscribe            # A2A 9-state machine
session     tb_session_create() → h · tb_session_join/leave(h, agent) · tb_session_watch(h) → stream
cap         tb_handle_dup(h, rights_subset) · tb_handle_transfer(chan, h) · tb_handle_replace
budget      tb_budget_split(h, slice) · tb_budget_query    # delegable, hierarchical
consent     tb_consent_request(schema_restricted)          # MCP elicitation: accept/decline/cancel
stream      tb_stream_read(h, from_seq)                    # ordered, with replay (Last-Event-ID pattern)
```

- **`tb_infer_submit` takes a DAG** (not one prompt→one completion): typed dataflow edges, intermediate values flow over kernel channels (Parrot: client round-trips alone lose 2×+; up to 11.7× gain).
- The inference preference vector is the MCP sampling model: `{costPriority, speedPriority, intelligencePriority}` + advisory hint; the **kernel router** binds the concrete backend, not the caller.
- Re-entrancy: the inference path can re-enter tool dispatch (the MCP SEP-1577 direction).

## 5. Scheduling **[PROPOSAL]**

- **Quantum = decision cycle** (Soar): a parallel preparation phase (retrieval, tool results, rule match) → a single serialized commit; preemption and interrupt delivery only at the cycle boundary — the "no uninterruptible sequence ever" guarantee.
- **Impasse traps**: if arbitration produces a tie/conflict/constraint-failure/no-change, the kernel automatically opens a child reasoning context (page-fault analogy); the handler policy is userspace (escalate to a bigger model / ask another agent / return to memory), while detection + substate stack + automatic teardown (GDS) are in the kernel.
- **Arbitration algebra**: the default decision mechanism among competing proposed actions is Soar preference semantics (acceptable/reject/better/worse/require/prohibit); the proposal generators (LLM, rules) are userspace, the algebra is in the kernel.
- **Retrieval pricing**: the ACT-R latency equation `RT = F·e^(−f·A)` is the kernel's cost model — the scheduler can price a memory retrieval *before* dispatching it and decide wait/re-derive/escalate (F, f are per-backend calibration constants).
- **QoS classes (fixed in the ABI)**: `INTERACTIVE` (TTFT+TBT SLO; early rejection under overload — Mooncake), `PIPELINE` (DAG end-to-end target; inner nodes derived — Parrot), `BULK` (cost-optimal; the home of self-improvement; can be deferred indefinitely).
- **Cache-topology-aware dispatch**: runnable steps are nodes in a global prefix tree; within a class prefer DFS/longest-shared-prefix (SGLang Theorem 3.1, 96% of optimum) + **aging/fairness day-one** (the starvation admission).
- **Billing-aware preemption**: preempt freely on a local engine (swap/recompute); on a metered remote API lean toward run-to-completion — the token cost of text-resume is priced (the gap AIOS does not measure).
- **Admission control**: under token pressure, prediction-based early rejection/deferral; turn it away rather than thrash (Mooncake).

## 6. Context Scheduler — Token Resource Management **[PROPOSAL]**

A single neutral layer, two driver families (analogy to the block-layer/driver separation):

| | Local driver (vLLM/SGLang/llama.cpp class) | Remote driver (Anthropic/OpenAI class) |
|---|---|---|
| Unit cost | HBM byte, GPU-second | dollar, quota-token |
| Mechanism | KV block tables (PagedAttention: 96.3% utilization), radix prefix tree, all-or-nothing eviction, gang scheduling, swap-vs-**recompute** | **Lease objects** {prefix-hash, TTL, read=0.1×, write=1.25×/2×}; lease-renewal scheduler; breakpoint placement; affinity key management (~15 RPM/lane) |
| Quota | local pool arbitration (cache-vs-batch) | cgroup-style hierarchical token bucket (RPM/ITPM/OTPM/dollar 4 counters); preventive scheduling with header telemetry instead of 429 |
| Common abstraction | **Prefix object** (content-hash; residence: GPU/DRAM/SSD/lease/cold) · **Budget** (budget+period) · QoS · DAG | same |

- **Quota×cache joint optimization**: at Anthropic, cache reads do not count against ITPM → 80% hit = 5× effective quota; when quota is tight, the kernel's first move is not to throttle but to **re-arrange context placement**.
- **Checkpoint asymmetry**: persistent state is token text; the KV can be recomputed → migration carries KB, not GB.
- Backend drivers publish a **capability descriptor**: `{ttl_range, write_cost, read_cost, counts_against_quota, affinity_hint, min_cacheable_tokens}`.

## 7. Security Model **[DECISION — principles] / [PROPOSAL — mechanisms]**

1. **Zero ambient authority** [DECISION]: no default FS root, no default network, no inherited API key; secrets are capability references resolved at load-time (the correction of the Letta .af lesson).
2. **Single audit chokepoint**: a rights-mask at every handle dereference (the Capsicum fget pattern); denial = `TB_ENOTCAPABLE` + denial trace.
3. **Signed agent manifest** [DECISION]: the A2A Agent Card JWS model — verification at load time; an undeclared capability is mechanical EPERM. Tool manifests are also signed (the survey's tool-poisoning threat); capability grants are **task-scoped and time-limited** (the privilege-persistence threat); tool arguments are kernel-side schema-validated (command injection).
4. **Isolation ladder** [PROPOSAL]: intra-agent tool/skill = WASM nanoprocess (import-signature diff = consent event; static proof of "X has no path to Y" in the component graph); a different principal/tenant = a separate microVM/unikernel (a hardware boundary per the Spectre admission).
5. **Human-approval gate**: ANP humanAuthorization + MCP elicitation — `EMIT_EXTERNAL`-class labeled ops (payment, privacy, irreversible deletion) fall to human approval via a two-keyring model; kernel-enforced, not application courtesy.
6. **Measurer-measured separation**: evaluator/detector objects never appear in the agent's rights mask ([SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md)).
7. **Opaque execution** (A2A): the agent's working memory/plan is kernel-protected private memory; sharing only by explicit grant.

## 8. Persistence **[PROPOSAL]**

The KeyKOS orthogonal-persistence template: system-wide, tunable-interval checkpoint; on restart all agents return exactly at the register/VM level; a power outage = a "clock jump". The E2B cost asymmetry (4 s/GiB to save, ~1 s to return) validates hibernate-default. The agent image = `{manifest, context (token text), memory tier references, handle table, task states, FS delta}` — the kernel-completed form of the .af inventory ([AGENTS-SPEC §3](AGENTS-SPEC.md)). The revocation × restore interaction and external (non-transactional) resource handles are [OPEN].

## 9. IPC and Protocol Layering **[DECISION]**

The kernel speaks a **single canonical, schema-defined ABI** (the a2a.proto pattern); MCP/A2A/ACP/ANP are **userspace bridge daemons** — every protocol arriving from outside terminates at a bridge, and inside a single kernel IPC dialect flows. Kernel primitives: correlated request/response, notification, cancellation, capability-passing channel, ordered-replay stream (same order to N observers — the A2A rule), durable Task. Discovery, negotiation (ANP meta-protocol), transport bindings, and the marketplace are in userspace; the ANP negotiation cache binds to the memory tiers, and generated adapter code binds to the skill registry + sandbox pipeline.

## 10. Frozen Kernel Boundary

The kernel + evaluators + evolution engine (archive maintenance, parent selection) are **outside the scope of agents' self-modification** (the DGM precedent). The agent's default write authority is only its own config subtree; extension is an explicit capability grant. Detail: [SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md).

---

### The verification chain of the decisions in this document
All numeric bases are sourced and vote-verified in [RESEARCH-REPORT](RESEARCH-REPORT.md); the **[PROPOSAL]** items in this document are design inferences derived from that data (they are not themselves additionally verified "facts") and must be tested against prototype measurements.
