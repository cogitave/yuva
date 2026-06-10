# M20 — Durable Persistence: `VirtioBlkStore` behind the M13 `BackingStore` seam

**Status:** PROPOSED (build-ready) · **Marker:** `M20: persist OK` · **Size:** L (BACKLOG #22) · **Depends on:** M19 virtio-mmio transport (landed), M13 substrate (landed) · **Blocks unlocked:** agent hibernate/restore, persistent skill lineage (M18 follow-up), `.taf` checkpoint images

## 1. Motivation — the thesis-critical gap

TABOS is a *memory-centric* agent-native OS, and today every agent's memory dies with the power. M13's tiered substrate (T0 registers / T1 working graph / T2 episodic journal / T3 lexical store) is RAM behind the `BackingStore` trait (`crates/tb-hal/src/mem.rs:141`), with `RamStore` as the sole implementation and `flush()` a no-op. `docs/MILESTONES.md` §5 names durable persistence as the **only** deferred item phrased as a milestone, and BACKLOG #22's stated dependency — the virtio transport (#23) — landed as M19. The kernel just built the exact DMA/ring/handshake machinery persistence needs; M20 is the rung where, for the first time, *anything in TABOS outlives a boot*.

## 2. Prior art and what we take from each

- **KeyKOS / EROS** (Landau, *The Checkpoint Mechanism in KeyKOS*, IWOOOS 1992; Shapiro, Smith & Farber, *EROS: a fast capability system*, SOSP 1999) — the canonical capability-system single-level store. We take: persistence as **transactional snapshot**, not write-through; the `epoch()` seam becomes a **checkpoint generation** committed atomically. We reject (for now): whole-system checkpointing — M20 persists only the per-agent `MemSubstrate` regions behind the trait, never kernel ephemera.
- **Aurora** (Tsalapatis et al., *The Aurora Single Level Store Operating System*, SOSP 2021) — the closest shape to our situation: a single-level store over a **block device** (no NVM), log-structured. We take: append-only log per region; T2 is already append-only, so the journal maps 1:1 onto a log-structured block layout; `flush()` becomes a `VIRTIO_BLK_T_FLUSH` barrier defining the durability point.
- **TreeSLS** (Wu et al., SOSP 2023) — the capability tree as the natural checkpoint manifest. We take the *direction* (the superblock's region directory is the image's table of contents; restore re-derives indexes against restored objects) and reject the NVM cost model (we have virtio-blk, not Optane/CXL).
- **Twizzler** (Bittman et al., USENIX ATC 2020) — persistent data must be **position-independent**. `mem.rs` records are already id-addressed and pointer-free; M20 promotes that to a *stated invariant of the on-disk format* (a future `.taf` image is migratable, AGENTS-SPEC §3).
- **Firecracker / OSv** (Agache et al., NSDI 2020; Kivity et al., USENIX ATC 2014) — a minimal poll-mode virtio-blk driver plus a simple log is *sufficient* for a unikernel-class guest; tb-vmm can later grow the host-side device from the same rust-vmm lineage.

## 3. Design

### 3.1 Framekernel split

- **`tb-encode::blkfmt` (new module; pure, `#![forbid(unsafe_code)]`, zero deps, Kani-proven):** virtio-blk request-header codec (`{le32 type, le32 reserved, le64 sector}`; IN=0/OUT=1/FLUSH=4) and closed status decode; the 512-byte **superblock** codec (magic `TABOSMEM`, version, generation `gen`, per-region `used_bytes[3]`, FNV-1a-64 checksum) with total fail-closed decode; the 24-byte **record frame** codec (region tag, len, seq, payload checksum) and the 48-byte LE Episode body codec; **sector/extent math** (fixed partition: SB at LBA 0; Episodic 1..4096; Semantic 4096..6144; Working 6144..8192 over a ≥4 MiB image) with no-overflow/in-extent lemmas.
- **`tb-hal/arch/{x86_64,aarch64}/virtio.rs` (the only new `unsafe`):** the M19 slot scan generalized to probe by DeviceID; a virtio-blk (DeviceID 2) arm reusing M19's volatile accessors, barriers (`dmb ishst`/`dsb sy`/`dmb ishld` on aarch64; `compiler_fence` on TSO x86), one-DMA-frame layout, `POLL_CAP` fail-closed spin, and reset-before-free teardown. New surface only: the config-space capacity read and a 3-descriptor chain (header RO → 512-byte data → status byte WO), `Q_SIZE=4`. Every committed value is computed by `blkfmt`; per `assumptions.md` §4, each new unsafe block is lemma-covered or a named residual — anything else is a review failure.
- **`tb-hal` safe layer:** `VirtioBlkStore: BackingStore` — staged appends; `flush()` is a **two-phase commit**: dirty data sectors → FLUSH → superblock with `gen+1` (one-sector atomic commit point) → FLUSH. `mount()` validates the superblock fail-closed, formats fresh disks, and **replays** region logs up to the committed watermark, ignoring any torn tail (uncommitted appends never happened — the modest, honest crash story). `epoch() = (gen << 32) | appends_since_mount`, so T3 freshness is monotonic *across reboots*. `MemSubstrate::new_with_backing(..)` + replay rebuild T2 losslessly and **derive** the T3 index (Aurora: indexes are derived state).
- **Kernel:** branches on a new `PersistProof { Proven{gen, replayed, prior}, Absent, LegacyUnsupported, Failed{stage} }` — the `VirtioProof` pattern verbatim. Zero `unsafe` in the kernel crate, as always.

### 3.2 Self-test (the marker body)

probe → mount → *(if prior gen > 0: recall the previous boot's sentinel through the real M13 3-stage recall and report `prior=1`)* → append 3 known-token sentinel records → `flush()` → device reset + **drop the substrate** (all RAM state destroyed) → re-probe → re-mount → replay → recall the sentinel by token → assert value and generation continuity. Detail line `persist: gen=.. replayed=.. prior=..`, then the marker.

Renderings: `M20: persist OK` (Proven) · `M20: persist OK (no device, skipped)` (Absent — tb-vmm) · `M20: persist OK (legacy v1, skipped)` · `M20: persist FAIL stage=0x..` (no `persist OK` substring → red). M20 displaces M19 as the last cumulative marker; M0..M19 + L2.0..L2.4 still print before it (teardown-first, zero regression).

### 3.3 CI / scripts

`run-x86_64.sh` / `run-aarch64.sh`: `MARKER='M20: persist OK'`; explicit `M19: virtio OK` assert added (displaced-marker traceability); a fresh `mktemp` 4 MiB raw image per run; `-drive file=$IMG,if=none,format=raw,id=vblk0 -device virtio-blk-device,drive=vblk0` beside the existing rng device (`-global virtio-mmio.force-legacy=false` already covers it); **two sequential QEMU invocations against the same image**, each under its own existing timeout, boot 2 asserting `prior=1` — durability across a real reboot, proven under pure TCG in-lane. `vmm-boot` is untouched (no device → graceful skip, single boot). `microvm-kvm` gets the same disk + two-boot. `verify-encode.sh`: `EXPECTED_HARNESSES` 24 → 30. The wfi-park exit discipline is deliberately untouched.

## 4. Verification

Six new Kani harnesses in `tb-encode/src/proofs.rs` (pins bumped 24→30 in the same PR): req-header round-trip/well-formedness; superblock encode→decode identity over symbolic fields; superblock decode totality/fail-closure (header-region byte nondet + checksum-perturbation, **not** full 512-byte nondet — the documented assume-envelope, avoiding #49-style over-quantification); frame-header round-trip; frame decode totality with len-bound; sector-math no-overflow/in-extent. Host `#[cfg(test)]` round-trip and torn-tail-truncation tests run under the existing Miri lane (`-p tb-encode`). `prove-caps` stays pinned at 12. Clippy `-D warnings` on the verified leaves; both arches kbuild 0-warnings.

## 5. Definition of Done (fail-closed)

1. `M20: persist OK` prints on **both** arches every boot as the new last cumulative marker, with M0..M19 + L2.0..L2.4 all still printing before it; FAIL renderings contain no OK substring.
2. The single-boot proof **executes** (not skips) under pure QEMU-TCG on stock GitHub runners on both arches; the two-boot script pass proves a sentinel written in boot 1 is recalled in boot 2 (`prior=1`) on the same disk image.
3. tb-vmm / deviceless lanes stay green via the tagged `(no device, skipped)` line.
4. All six lanes green: ci, vmm-boot, l2-nested-vmx, microvm-kvm, kani (12/30), miri. Kernel crate has zero `unsafe`; all new unsafe sits in `arch/*/virtio.rs` with §4-compliant coverage.
5. No perf claims (TCG correctness only); flush latency unquoted until a KVM measurement with the same-boot counter base exists.
6. Landed via branch → PR → full CI → merge; CI-only failure ⇒ prompt revert with evidence (the a0b678d/#65 pattern); docs reconciled in the landing PR (MILESTONES marker list + table + §5, BENCHMARKS note, BACKLOG #22 → DONE, ROADMAP cross-refs).

## 6. Risks

See §10 of the proposal record: two-boot wall-clock budget (mitigated: per-invocation ceilings, `thread=single` determinism already in place), microvm top-down slot assignment with two devices (scan matches by DeviceID, not slot), Kani state-space blowup on 512-byte buffers (bounded envelopes), modest crash-consistency claims (clean-flush commit only — crash-at-any-point is a named non-claim), and the standing rule that this rung deliberately stays **poll-only**, far from the GIC/timer/EL2 interplay that produced the #65 flake family.

## 7. Rejected alternatives (deferred, not refused)

**Agent-ready state + second boot clock** — proves a state, not a capability; natural as M21 *on top of* durability. **virtio-net** — strictly larger than blk, proves less per LOC without an in-kernel consumer. **Completion-IRQ path** — lands exactly in the #65 flake zone; blocked on root-cause. **aL2.5 re-land / aL2.4b** — diagnostics-first discipline; sovereignty track resumes when the discriminating diagnostic exists. **x86 L2.x** — parked on #37 hardware.

## 8. Out of scope / follow-ups

Wiring every agent's born-with `MemoryHome` onto durable backing by policy (the hibernate/restore rung), checkpoint cadence (Aurora's 10 ms COW), tb-vmm host-side virtio-blk backend, multi-sector batched I/O, crash-injection torture lane, `.taf` export.

## References

Landau, IWOOOS 1992 · Shapiro/Smith/Farber, SOSP 1999 · Tsalapatis et al., SOSP 2021 · Wu et al., SOSP 2023 (TOCS 2025) · Bittman et al., ATC 2020 · Agache et al., NSDI 2020 · Kivity et al., ATC 2014 · virtio v1.2 §4.2/§2.7/§5.2.