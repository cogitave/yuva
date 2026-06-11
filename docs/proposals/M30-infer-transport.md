# M30 — the verified inference transport (`tb-encode::inferwire` leaf + the virtio-mmio seam + tb-vmm's first device backend)

**Status:** proposed (research-complete, build not started) · **Pillar:** communication (the sovereignty channel to a host model peer) + sovereignty (tb-vmm grows its first virtio device) · **Depends on:** M19 (virtio-rng over virtio-mmio), M20 (virtio-blk over virtio-mmio + durable head), M28 (`opframe_rx` MAC seam), **M29 (`tb-encode::khash` — the echo's MAC primitive; HARD sequencing dependency)** · **Tasks:** #87 / A1 infer-transport (sovereignty-plan §M30); promotes the M22 runner-up (`docs/proposals/M22-memory-provenance.md:23`); BACKLOG row 23 (the deferred tb-vmm backend lands) · **Marker:** `M30: infer-transport OK`

> **One-line:** a **verified bidirectional request/response inference channel** between the guest kernel and a host peer over modern virtio-mmio. The wire format is a Kani-proven `tb-encode::inferwire` leaf (magic + version + kind + correlation-id + length + a truncated `khash` tag); the kernel seam reuses every M19/M20 virtio primitive verbatim, adding only a two-queue virtio-console (DeviceID 3) driver shared by both lanes; and tb-vmm gains its **first** host-side virtio device backend. **Honest by construction — anti-hollow is the whole point:** the M22 design was demoted because its round-trip terminated at an in-kernel mock loopback; M30's DoD is a **host-applied khash-transformed echo** (host-held key + per-run nonce) verified TWO ways — the guest verifies the tag against the M29 leaf (leg 1), AND the run script string-compares the kernel's witnessed tag/challenge against the host peer's independently-printed line (leg 2). A loopback can mint a self-consistent tag but cannot equal the host's `khash(K, …)` without the host-custodied key — so it fails leg 2 for every variant. `backend=ECHO-ONLY`, `transport=` per lane, `sec=ASSUMED-FROM-LITERATURE` inherited from M29; the marker claims only what is proved.

Synthesis of [`docs/research/m30-infer-transport-literature.md`](../research/m30-infer-transport-literature.md) (device-class survey, the host-side backend, framing/correlation precedent, the verified-leaf fit, the aarch64-peer matrix). **Decision: virtio-console DeviceID 3, single-port, modern virtio-mmio (Version=2), poll-only, negotiating ONLY `VIRTIO_F_VERSION_1`; runner-up virtio-vsock (DeviceID 19)** — see research §3. **aarch64 host peer: option A, the stock-QEMU `virtconsole`+chardev harness; runner-up a custom QEMU device** — see research §8 and §9 below.

---

## 1. Why this milestone, and why these choices

The sovereignty roadmap's A-chain needs a channel to a host model before any inference can happen (A2/M31 = the real adapter). The M22 *runner-up* was exactly "verified inference-transport framing leaf + virtio-mmio seam" — demoted because its round-trip ended at an in-kernel `MockBackend` loopback (`M22: infer-transport OK`, hollow-pass exposure). M30 promotes that design and the sovereignty-plan amendments make the loopback **structurally impossible** (§4). Two load-bearing decisions, both decided in research:

**Device class = virtio-console (3), single-port, non-`F_MULTIPORT`.** It is the ONLY class with a stock-QEMU virtio-mmio peer on BOTH arches (`-device virtio-serial-device -device virtconsole,chardev=...`), so it gives the aarch64 lane a host peer with zero QEMU patching AND lets tb-vmm emulate the same DeviceID — **one kernel driver + one verified codec leaf serve both lanes**. Negotiating only `VIRTIO_F_VERSION_1` (rejecting `F_MULTIPORT`/`F_SIZE`/`F_EMERG_WRITE`) collapses the device to exactly receiveq(0)+transmitq(1): no control queue, no config space. The byte-stream nature is a *feature* — because the transport does not preserve message boundaries, the proven framing/resync/MAC leaf is genuinely load-bearing. Runner-up vsock (the roadmap's own B2 endgame) is deferred: stock QEMU cannot carry it on virtio-mmio without `vhost` entanglement that kills the zero-patch aarch64 lane (research §3). The frame format is designed to migrate onto a vsock stream unchanged — a length-prefixed frame rides `SOCK_STREAM`, whereas a custom-ID's descriptor-chain-implicit framing would not.

**The codec is the verified leaf; the transport is plumbing; the M29 khash leaf is reused, not re-implemented.** This is the M22..M29 reuse discipline (one new primitive, every consumer through it). `inferwire` is a sibling of `opframe`/`opframe_rx`; the echo's MAC is the M29 `khash` call. Nothing about virtio is verified — the spec's used-ring MUSTs are tested in-boot, not proved.

## 2. The leaf — `crates/tb-encode/src/inferwire.rs` (NEW)

`no_std`, `#![forbid(unsafe_code)]`, zero deps, no floats, integer/byte ops only. Style anchor: `opframe_rx.rs` (magic `0x5443`) and `opframe.rs` (`0x5442`); **next house magic = `0x5444`**. Canonical little-endian, length-prefixed payload, reserved-zero fail-closed — the `ipc_frame`/`opframe` discipline.

**Frame layout** (header then payload):

```text
magic:u16   = 0x5444
ver:u8      = 1
kind:u8     ∈ { ECHO_REQ=1, ECHO_RESP=2, ERR=3 }
flags:u8    reserved-zero (fail-closed)
req_id:u64  correlation id (in-flight window = 1, but on the wire from day one)
challenge:[u8;16]   kernel-chosen per boot (REQ); echoed verbatim into the MAC (RESP)
nonce:[u8;16]       HOST-chosen per run (zero in REQ canon; set in RESP)
peer_id:u8          0x01=TB-VMM-HOST, 0x02=QEMU-CHARDEV-HARNESS (zero in REQ canon)
tag:[u8;16]         truncated khash echo (RESP only; zero in REQ canon)
payload_len:u32
payload bytes...     (REQ body; RESP echoes body verbatim — body-bitexact)
```

**API (mirrors `opframe_rx` exactly):**

```rust
pub const INFER_MAGIC: u16   = 0x5444;
pub const INFER_PAYLOAD_CAP: usize = 1024;   // keeps Kani bounded
pub const INFER_TAG_LEN: usize = 16;          // truncation precedent: opframe_rx::MAC_LEN

pub fn canon_len(payload_len: usize) -> usize;
pub fn wire_len(f: &InferFrame) -> usize;
pub fn frame_is_encodable(payload_len: usize) -> bool;          // payload_len <= INFER_PAYLOAD_CAP
pub fn canon(f: &InferFrame, out: &mut [u8]) -> usize;          // canonical LE serialise
pub fn decode(buf: &[u8]) -> Option<InferFrame<'_>>;            // fail-closed total
pub fn resp_binds_req(resp: &InferFrame, req_id: u64) -> bool;  // iff-theorem

/// ONE khash call, domain-separated. label = "TABOS-M30-ECHO-V1".
/// T = khash(K, label ‖ peer_id ‖ nonce ‖ challenge ‖ body)[..INFER_TAG_LEN]
pub fn echo_tag(key: &[u8;32], peer_id: u8, nonce: &[u8;16],
                challenge: &[u8;16], body: &[u8]) -> [u8; INFER_TAG_LEN];
pub fn verify_echo(key: &[u8;32], resp: &InferFrame, req: &InferFrame) -> bool;
```

The challenge, nonce, and `peer_id` are bound INSIDE the MAC'd bytes (the M28/Terrapin bind-inside-the-MAC lesson) — so a host cannot be mislabeled, and the run script's cross-check on `transport=` is itself MAC-covered.

**Stream discipline — `FrameAccum`.** The chardev lane is a byte STREAM with no boundaries, so a fixed-capacity accumulator: `push_byte(b) -> Option<frame_len>` that emits a complete-frame length when one is buffered, and on garbage/oversize resyncs fail-closed by scanning to the next `INFER_MAGIC`. `ipc_frame.rs::BoundedRing` is the proven pattern; a length-delimited accumulator is the actual need. The tb-vmm lane delivers whole descriptor-chain buffers and can decode directly, but uses the SAME `decode` to stay one codec.

`pub mod inferwire;` joins the `lib.rs` module list. Domain separation lives in the leading `label` bytes inside the message — `khash` itself is unchanged.

## 3. The kernel seam + the tb-vmm backend (staged)

### 3a. Kernel driver — `crates/tb-hal/src/arch/{aarch64,x86_64}/virtio.rs`

Append an M30 section reusing every M19/M20 primitive verbatim (`reg_read`/`reg_write`, `ram_*`, the `dmb_ishst`/`dsb_sy`/`dmb_ishld` | `compiler_fence` barriers, `POLL_CAP=100M`, reset-before-frame-free, the slot scan — aarch64 `0x0A000000`×32 stride `0x200`, already Device-mapped; x86 `0xFEB00000` through the UC window at `VIRTIO_WINDOW_VA`). **NEW silicon surface: the first TWO-queue setup** — `QueueSel=0` rx with a device-WRITE buffer posted before `DRIVER_OK`, `QueueSel=1` tx; one 4 KiB frame holds both rings + both buffers; negotiate ONLY `VERSION_1` (rejecting `F_MULTIPORT` keeps port 0 bound to the chardev). Functions:

- `chan_probe() -> Option<u32>` (+ `chan_saw_legacy()` — a legacy slot is rejected, not silently used).
- `chan_send_recv(slot, req: &[u8], resp: &mut [u8]) -> Option<usize>` — tx-kick, poll tx-used, then poll rx-used under `POLL_CAP` (poll-only; **#71 watch applies the instant this grows a completion IRQ**).

### 3b. Kernel facade — `crates/tb-hal/src/lib.rs`

`InferChanProof { Proven{slot, req_id, resp_len}, Absent, LegacyUnsupported, Failed{stage} }` + a safe `infer_transport_selftest()` (the `VirtioProof`/`PersistProof` facade pattern, the M19/M20 idiom): canon an ECHO_REQ via `inferwire`, send, decode the ECHO_RESP, `verify_echo` against the compiled-in shared key (the M28 `oracle=SIMULATED-ENROLLED-KEY` custody precedent — the KEY is in both ends, but the per-run NONCE + the `peer_id`/lane token are HOST-held and ride inside the MAC'd payload, unknown to the guest image), plus the **in-boot negative controls** (§4): flip one response byte → `badtag`/`body` reject; perturb one key byte → `wrongkey` reject; feed a truncated frame to `decode` from a scratch buffer → `partial` reject; feed a bad-len/bad-seq frame → `desync` reject. Only if the REAL echo verifies AND all four negatives fire does the kernel print the witness + marker.

### 3c. Kernel marker — `kernel/src/main.rs`

M30 block appended after the M28/M29 blocks (the `main.rs:~4366` template — fail-closed `match`, a `FAIL` line with NO marker substring + `fail_exit()` per #65, then the witness line, then the marker). Witness + marker verbatim in §5. The transport token is the host-supplied lane string echoed from INSIDE the MAC'd payload — the kernel mechanically cannot mint `TB-VMM-HOST`/`QEMU-CHARDEV-HARNESS`, and a loopback cannot know the host nonce.

### 3d. tb-vmm — its FIRST virtio device backend (BACKLOG row 23 remainder)

tb-vmm today: x86_64/KVM/Linux-only, `mmio_bus = Bus::new()` empty (`vmm.rs:135`), exit loop already dispatching `MmioRead/MmioWrite` to it (`vmm.rs:~205`), guest RAM 256 MiB at GPA 0 so `0xFEB00000` is unmapped GPA → `KVM_EXIT_MMIO` arrives for free. The `Bus`/`BusDevice` trait (`device.rs:17`) was built "transport-agnostic so a virtio MMIO transport can be added later."

- **NEW `tb-vmm/src/virtio_mmio.rs`** — a minimal modern virtio-mmio register file as a `BusDevice`: Magic / Version=2 / DeviceID=3 / VendorID, DeviceFeatures(Sel) offering only the `VERSION_1` high word, DriverFeatures(Sel), QueueSel/QueueNumMax(≥1)/QueueNum/QueueReady, QueueNotify, Status, InterruptStatus/ACK inert (the guest is poll-only), Queue{Desc,Driver,Device}{Low,High} latched per queue. That is the full register set the kernel driver touches — nothing more (research §4).
- **NEW `tb-vmm/src/infer_host.rs`** — the device model behind QueueNotify: walk desc/avail/used in guest RAM (the device holds a clone of `GuestMemoryMmap` passed in at `Vmm::new` — the only `vmm.rs` plumbing change besides registration), pop the tx frame, **reuse `tb-encode` on the host** (add `tb-encode` as a path dependency of tb-vmm — it builds for the host triple by design) to `decode` + apply `echo_tag` with the host-held key + per-run nonce, write the ECHO_RESP into the posted rx buffer, then publish per §2.7.8.2 (bytes → `used.ring`→ `used.idx`). Lane token `transport=TB-VMM-HOST`; the device also prints its own host-stdout line (§5).
- **`tb-vmm/src/vmm.rs`** — register the transport at `0xFEB00000 + slot·0x200` on `mmio_bus`; bump `MAX_EXITS` (`vmm.rs:34`, the stale "M0–M4 boots" comment) — the full M0..M29 chain already boots under this lane and the virtio handshake adds only ~40 MMIO exits + 2 notifies, so a defensive bump to ~20M with a rewritten justification comment. **`tb-vmm/src/cli.rs`** — `--infer-nonce <hex>` + `--xport-key <hex>` (read from env/fd; auto-generate + print to stderr for the script cross-check). `main.rs`/`report.rs` untouched (BootReady PIO-side).
- **Harness for the QEMU lanes** — ONE small host binary (e.g. `tb-vmm/src/bin/xport-harness.rs` or a `tools/infer-harness/` sibling, workspace-internal) linking the SAME `tb-encode` `khash`+`inferwire` the kernel uses — **never a second codec implementation in shell/python**. It holds K+N, answers inferwire over the chardev UNIX socket, and prints the host-stdout line. Built by the run scripts the way run-vmm builds tb-vmm.

M16 stays untouched: `infer.rs`'s u64-scalar `InferRequest` and its "variable-length neutral core … DEFERRED" note remain — M30 is transport-only; M31 wires the byte-prompt `InferBackend` onto this channel.

## 4. The host-keyed echo — the anti-hollow protocol (NAMED section)

**The threat is not a wire attacker — the host is trusted ground. The adversary is hollow evidence:** a kernel (or a lazy future refactor, or a malicious M34-era candidate) that prints the M30 marker without ever crossing the guest/host boundary. The M22 proposal demoted this exact design because its round-trip terminated at an in-kernel mock loopback. Everything here exists to make a loopback **unable to produce the witness**.

**Key custody.** Per run, the HOST peer (tb-vmm for the vmm lane; the chardev harness for the QEMU lanes) samples from host OS RNG: `K:[u8;32]` (the echo key — lives ONLY in the host process, NEVER compiled into the kernel image, on the guest command line, in guest-visible config space, or printed by the guest) and `N:[u8;16]` (the host nonce, fresh per run). The kernel image carries the SAME K (the `oracle=SIMULATED-ENROLLED-KEY` custody precedent), but N and `peer_id` are host-held.

**Frame flow** (over the M30 channel under test — same codec both lanes):
1. **Kernel → Host `ECHO_REQ`**: `{ kind=ECHO_REQ, challenge=C, body }`, where `C:[u8;16]` is a per-boot fresh challenge (M19 virtio-rng bytes where present, else `uhash(boot_epoch ‖ cycle_counter)[..16]`; C's entropy quality is NOT the anti-hollow load-bearer — K is — so no extra token).
2. **Host → Kernel `ECHO_RESP`**: `{ kind=ECHO_RESP, peer_id, nonce=N, tag=T, body'=body }` with `T = khash(K, "TABOS-M30-ECHO-V1" ‖ peer_id ‖ N ‖ C ‖ body)[..16]`.
3. **Kernel verifies** via `tb_encode::khash` exactly: recompute `T'`, require `T'==T`, `body'==body`, and a fail-closed decode. Plus four in-boot negatives (§3b).
4. **Host peer prints its OWN line** to host stdout (a different process's stream than guest serial): `xport-harness: peer=<token> challenge=0x<C> tag=0x<T> key-custody=HOST` (tb-vmm prints the same shape with `key-custody=VMM`).
5. **The run script adjudicates the round-trip** by string-comparing two independently-produced outputs: the kernel-printed `challenge`/`tag` vs the host-printed `challenge`/`tag`. Equal ⇒ the bytes crossed the boundary both ways. No recompute tool — cross-process equality IS the proof.

**Why a loopback can never pass — the two-leg argument (verbatim in the caveats §9):**
- **The kernel-side verify ALONE cannot exclude a loopback.** A loopback can mint its own `K*`, `N*`, compute a self-consistent `T*` with the same khash leaf, and "verify" it. In-guest verification proves only khash-correctness of whatever arrived, plus that the response binds THIS boot's C. So `echo=HOST-KEYED-VERIFIED` is a **kernel-scope** token meaning "the kernel verified the tag against the key revealed on the channel" — NEVER "not a loopback."
- **Loopback exclusion lives in the guard's cross-process check.** K exists only in the host peer; the guest image, cmdline, and pre-contact memory never contain it. A loopback's self-minted `T*` cannot equal the harness's `T = khash(K, …)` without guessing K: `2⁻²⁵⁶` per attempt under the M29 PRF assumption (`sec=ASSUMED-FROM-LITERATURE`), and unconditionally "guess 32 OS-RNG bytes." So the script's `kernel-tag == harness-tag` equality fails for EVERY loopback variant, however elaborate.
- **Anti-hollow is a composition property:** (kernel verify) × (cross-process tag-equality with a host-custodied key). Both legs are mandatory; neither alone is the DoD.

## 5. DoD — witness lines, honesty tokens, guard blocks (verbatim)

**Guest witness** (house style — `xport:` fields, `0x1` flags, structured tokens, then the marker; chardev lanes print `bus=SERIAL-FRAMED transport=QEMU-CHARDEV-HARNESS`):

```
xport: bus=VIRTIO-MMIO qsz=0x4 tx=0x1 rx=0x1 challenge=0x<32hex> nonce=0x<32hex> tag=0x<32hex> req-id=0x<hex> echo-verified=0x1 body-bitexact=0x1 badtag-rejected=0x1 wrongkey-rejected=0x1 partial-rejected=0x1 desync-rejected=0x1 mode=POLL transport=TB-VMM-HOST echo=HOST-KEYED-VERIFIED key=HOST-CUSTODIED-PER-RUN backend=ECHO-ONLY sec=ASSUMED-FROM-LITERATURE
M30: infer-transport OK
```

**Host-peer witness** (host stdout, NOT guest serial):

```
xport-harness: peer=QEMU-CHARDEV-HARNESS challenge=0x<32hex> tag=0x<32hex> key-custody=HOST
```

(Marker deliberately avoids the substrings `virtio`/`network`/`crypto`/`infer` beyond the bare `infer-transport` phrase — all transport/crypto claims live ONLY in structured stripped tokens, the M29 bare-word discipline.)

**Run-script guard block per attached lane** (`run-x86_64.sh`/`run-aarch64.sh` new M30 block after M28/M29; `run-vmm-x86_64.sh` new block + the MARKER bump in §11). House order: skip-reject → positive-require → by-name rejects → lane-cross-pin → #71 tripwire → cross-process → key-leak → strip-then-reject.

1. **Skip-variant reject (by name, the M20 idiom):** an attached lane FAILS on `M30: infer-transport OK (no host peer, skipped)`.
2. **Positive-require** (one regex; all flags `=0x0*1`, all tokens literal): the `xport:` witness above with `bus=<LANE-BUS>` and `transport=<LANE-TOKEN>`, plus `M30: infer-transport OK`, plus the cumulative-displacement assert for M28/M29 ("no longer the top-level grep" idiom).
3. **Loopback variants rejected BY NAME** (case-insensitive, near `M30:|xport:`): `transport=IN-KERNEL-LOOPBACK`, `transport=MOCK-BACKEND`, `transport=GUEST-SELF`, `echo=SELF-KEYED`, `echo=GUEST-KEYED`, bare `loopback`, `self-echo`.
4. **Lane-token cross-pin:** chardev lanes FAIL on `transport=TB-VMM-HOST`; the vmm lane FAILS on `transport=QEMU-CHARDEV-HARNESS`. No lane borrows the other's evidence class.
5. **#71 tripwire:** FAIL on `mode=IRQ` (or any non-`POLL` mode token) — flipping this guard is the designated visible act that forces a #71 disposition first.
6. **Cross-process round-trip (the loopback killer):** extract `challenge=`/`tag=` from the guest `xport:` line AND from the host `xport-harness:` line (separate capture streams); assert both pairs string-equal; require `key-custody=HOST|VMM` on the host line.
7. **Key-leak negative:** FAIL if the K hex appears anywhere in guest serial OUTPUT or in the QEMU/tb-vmm command line echoed to the log.
8. **Strip-then-reject overclaims** (M28/M29 idiom — strip the declared tokens first: `HOST-KEYED-VERIFIED`, `HOST-CUSTODIED-PER-RUN`, `ASSUMED-FROM-LITERATURE`, `ECHO-ONLY`, `SERIAL-FRAMED`, `VIRTIO-MMIO`, `QEMU-CHARDEV-HARNESS`, `TB-VMM-HOST` — then case-insensitive reject near `M30:|xport:`): `network|internet|online|TLS|SSL|HTTPS|encrypt|confidential|secure[- ]channel|authenticated|cloud|remote[- ]model|real[- ]infer|model[- ](served|loaded)|validated|evaluated`. The M29 global rejects (`provably[- ]secure|unforgeable|collision[- ]resistant|…`) stay in force.

## 6. Kani obligations (each with a genuine negative control; the #49 strategy throughout)

**#49 strategy:** frame INPUTS concrete (or ≤2–3 symbolic bytes for totality), only flip-indexes/predicates/lengths symbolic; the `khash` body inside `echo_tag` runs on CONCRETE inputs (the M29 discipline); NEVER a symbolic collision/preimage/PRF harness (no tool in the field proves these — a vacuous one is overclaim-by-implication, banned). Mitigation ladder if any harness exceeds ~5 min locally: pin flip positions concrete → `kani::solver(kissat)` → shrink the payload-length set → split the FrameAccum harness out.

**New harnesses in `crates/tb-encode/src/proofs.rs` (+5–6, stage A):**

1. **`kani_inferwire_canon_roundtrip`** — concrete frame at boundary payload lengths {0, 1, 31, 1024}; `decode(canon(f)) == f` field-by-field; plus injectivity (two frames differing in one header byte canon to distinct bytes). *Neg:* assert `canon(req) != canon(resp)` for frames identical except `kind` — a kind-blind encoder fails it.
2. **`kani_inferwire_decode_total`** — symbolic short buffer (≤ a few bytes) + concrete truncations of a valid frame + a reserved-nonzero `flags` + an oversize `payload_len`; `decode` returns `None` on every one, panic-free. *Neg:* the exactly-valid frame MUST decode `Some` (proves the rejector is non-vacuous — it doesn't reject everything).
3. **`kani_inferwire_req_binding`** — `resp_binds_req(resp, id)` iff `resp.req_id == id` AND `resp.kind == ECHO_RESP`, symbolic `id` + a symbolic 1-byte perturbation of `resp.req_id`. *Neg:* flip-then-flip-back the perturbed byte restores binding (proves the harness mutates).
4. **`kani_inferwire_echo_sound`** — concrete K + concrete body (sized to force khash's two-block path); `verify_echo` accepts the genuine `(echo_tag, body)`; a symbolic flip index over ALL tag bytes AND all body bytes AND all key bytes makes it reject. *Neg:* flip-then-flip-back restores acceptance (a constant/length-only stand-in fails the inequality — the M29 §6.3 tamper idiom).
5. **`kani_inferwire_accum_resync`** — `FrameAccum` fed a symbolic prefix of garbage then a concrete valid frame emits exactly one frame at the right length and NEVER overflows its fixed capacity (the `BoundedRing` never-overflow proof shape). *Neg:* a stream of pure garbage (no magic) emits `None` forever and never overflows (proves resync doesn't false-positive).
6. **(conditional) `kani_inferwire_peer_label_bound`** — `echo_tag` with two distinct `peer_id`s on the same `(K,N,C,body)` yields distinct tags (proves `peer_id` is MAC-covered, so the run-script lane-cross-pin in §5.4 is real). *Neg:* an implementation that drops `peer_id` from the MAC input fails the inequality.

**Mutation-test requirement (the §6.4 anti-hollow discipline, extended):** before landing, run a mutation pass on `inferwire.rs` (flip a comparison operator in `decode`'s bounds checks; drop the `peer_id`/`challenge` byte from `echo_tag`'s input; off-by-one the `FrameAccum` capacity) and CONFIRM each mutant is killed by at least one harness above. A mutant that survives means a harness is vacuous — fix the harness, not the mutant. This is recorded in the proposal so the obligation is auditable, not implied.

**Anti-hollow in-boot:** the four §3b in-boot negatives (`badtag`/`wrongkey`/`partial`/`desync`) are the runtime mirror of harnesses 2 and 4 — the tokens are earned per boot, never compiled-in.

## 7. EXPECTED_HARNESSES bump plan

`EXPECTED_HARNESSES = 84` after M29 (the M30 starting point, per `scripts/verify-encode.sh`). M30 stage A adds the +5–6 `inferwire` harnesses above → **target 89–90, EXACT COUNT MEASURED LOCALLY pre-landing** (the M29 discipline — the count is the gate, not the estimate). `scripts/verify-encode.sh` count + doc block (stating the inferwire harnesses are CONCRETE-FRAME / SHORT-SYMBOLIC per the #49 discipline, with the mutation-test obligation noted) and the `.github/workflows/kani.yml` comment bump in **lockstep, fail-closed**.

## 8. CI lane plan

| Lane | Accel | Host peer | Tokens required | Status |
|---|---|---|---|---|
| `ci.yml` x86_64 (microvm, TCG) | TCG | chardev harness over a second `-serial`/chardev unix socket, run-script-launched | `bus=SERIAL-FRAMED transport=QEMU-CHARDEV-HARNESS` | REQUIRED, gates PRs |
| `ci.yml` aarch64 (`virt`, TCG single-thread) | TCG | same harness, `virtconsole`+chardev | same | REQUIRED, gates PRs |
| `vmm-boot.yml` (x86_64) | KVM | tb-vmm's new virtio-mmio backend (first `mmio_bus` device; exit loop grown past its M0–M4 sizing) | `bus=VIRTIO-MMIO transport=TB-VMM-HOST` | KVM-gated: hard gate when `/dev/kvm` present, whole-lane skip otherwise (existing semantics) |

The chardev lanes are **accel-independent** — the REQUIRED PR evidence (codec + framing + host-keyed echo, both arches) never depends on KVM. `transport=TB-VMM-HOST` evidence is best-effort on hosted runners and simply doesn't accrue when KVM is absent; it is asserted hard whenever the lane runs. This asymmetry is stated; no token pretends otherwise.

**`run-vmm-x86_64.sh`:** MARKER bumps `M19: virtio OK` → `M30: infer-transport OK`; the M19 Absent-skip comment block is rewritten — M19 still prints its `(no device, skipped)` variant on this lane unless an rng backend also lands (out of M30 scope — the infer device is a separate slot/DeviceID). The vmm lane's marker jump from mid-chain M19-skip to the full M30 tail makes the whole M0..M30 chain CI-required under tb-vmm for the first time (a named risk in §10).

## 9. The aarch64 lane decision + external-dependency log

**Chosen: option A — the stock-QEMU `virtconsole`+chardev harness; runner-up a custom QEMU device** (full matrix in research §8). tb-vmm has no aarch64 arch and no stock QEMU device carries this channel as a custom protocol, so the aarch64 peer is an explicit external-dependency choice. Option A is available ONLY because the device class is console (3) — the decisive coupling with §1. The external-dep to log: **option A makes QEMU's virtio-console device model part of the aarch64 (and QEMU-x86) trust path for this marker — status ACCEPTED-PERMANENT, alongside QEMU itself**, recorded in `assumptions.md`. Option D (a loud aarch64-only skip) is a fallback ONLY if A fails the empirical spike (`virtconsole` non-MULTIPORT port-0 behavior + Version=2 under `force-legacy=false` on qemu-6.2 vs 8.2.2), logged as an explicit concession — it violates the both-arches DoD, so it is a last resort, not a default.

## 10. Failure modes (each with its designed observable)

- **Host absent at discovery** (no device on the bus / no peer banner): LOUD skip `M30: infer-transport OK (no host peer, skipped)` — legitimate ONLY on lanes that attach no peer (bench, l2-nested); rejected by name on every attached lane (§5.1). Presence decided ONCE at discovery.
- **Peer present-then-silent** (harness died mid-run / poll budget exhausted AFTER first contact): hard `M30: FAIL xport-timeout` — never a skip. A dead harness cannot masquerade as legitimately-absent.
- **Partial frame / truncation:** the codec is fail-closed-total (Kani: every truncation rejects); the in-boot `partial-rejected=1` proves the comparator is non-vacuous.
- **Queue/stream desync** (bad seq/len): decoder-level rejection witnessed by `desync-rejected=1`. **HONESTY NOTE:** this negative exercises the DECODER's rejection from a scratch buffer, not live-ring recovery; device reset-and-reinit is a NAMED deferral, not claimed.
- **Wrong key / corrupted tag:** kernel `badtag`/`wrongkey` rejects fire (and fail the boot if the REAL echo fails verify); the script's cross-process equality independently distinguishes "host misconfigured" from "loopback."
- **#71 interaction:** poll-only today ⇒ zero exposure to the TCG ghost-IRQ flake (`Servicing hardware INT=0xffffffff`). If completion IRQs ever replace polling, the x86 TCG lanes inherit #71 risk on this exact path — the `mode=POLL` guard pin (§5.5) makes that migration impossible without a reviewed guard edit + a #71 disposition note in the PR.

## 11. Landing plan — staged, CI-green

- **(A)** `inferwire` leaf + host tests + the +5–6 Kani harnesses (§6) + the mutation pass, NO kernel/vmm consumer. **Measure every harness locally before landing.** `EXPECTED_HARNESSES` 84 → 89–90 (exact, measured) + `verify-encode.sh`/`kani.yml` lockstep. Hard sequencing: **A cannot land before M29 stage A** (`khash` must exist).
- **(B)** Kernel seam (§3a/§3b/§3c) + the chardev `xport-harness` binary + `run-x86_64.sh`/`run-aarch64.sh` M30 guard blocks + `ci.yml` (both QEMU invocations gain `virtio-serial-device`+`virtconsole`+chardev + harness spawn). After (B) the REQUIRED both-arches DoD is met on TCG.
- **(C)** tb-vmm backend (§3d: `virtio_mmio.rs` + `infer_host.rs` + `vmm.rs`/`cli.rs` + `tb-encode` dep + `MAX_EXITS` bump) + `run-vmm-x86_64.sh` MARKER bump + `vmm-boot.yml`. (C) is the risk concentration (first mmio_bus device; the whole M0..M30 chain becomes CI-required under tb-vmm). If (C) destabilizes, (A)+(B) alone already discharge the both-arches DoD; (C) splits to its own follow-up landing.

**Doc/honesty fan-out checklist:** `kernel/src/main.rs` (M30 block + token literals); `scripts/run-{x86_64,aarch64,vmm-x86_64}.sh`; `scripts/verify-encode.sh` (count + doc block); `.github/workflows/{ci,vmm-boot,kani}.yml`; `crates/tb-encode/{lib.rs,src/inferwire.rs module docs}`; `crates/tb-hal/src/lib.rs` + `arch/{aarch64,x86_64}/virtio.rs`; `docs/BACKLOG.md` row 23 (PARTIAL → backend LANDED); `docs/assumptions.md` (the aarch64 host-peer ACCEPTED-PERMANENT dep + the symmetric-shared-key residual); `docs/MILESTONES.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP-V2.md`, `docs/plans/INDEX.md`; the M22 runner-up paragraph (`docs/proposals/M22-memory-provenance.md:23`) gets a "promoted as M30, anti-hollow amended" note; `.claude/skills/tabos-milestone/SKILL.md`.

## 12. Honest caveats (conceded — encoded as witness tokens)

- **`echo=HOST-KEYED-VERIFIED` is kernel-scope, NOT a loopback-exclusion claim** — the load-bearing honesty point. In-guest khash verification proves only that whatever arrived is khash-correct against the channel-revealed key and binds this boot's challenge. Loopback exclusion is the **guard's** claim (the cross-process tag-equality with a host-custodied key, §5.6), not the kernel token's. The §4 two-leg split is the proposal's central caveat.
- **`key=HOST-CUSTODIED-PER-RUN` — no confidentiality, no forward authentication.** K is REVEALED in cleartext on the channel; the echo is a per-run liveness/integrity WITNESS against hollow evidence, NOT a secure channel and NOT authentication against an adversarial host (the host is trusted ground). Because K is symmetric and compiled into both ends, the echo proves host *participation* (via the host-held nonce + the script cross-check), not host *exclusivity* — a named, tokened limit until M33's signature primitive.
- **`backend=ECHO-ONLY` — no model, no inference semantics.** Meaning arrives in M31 (the mock/real adapter) and M32 (the local daemon). M30 is transport-only.
- **No network / internet / TLS** — the peer is a local host process; enforced by the §5.8 reject list.
- **`mode=POLL` — no IRQ path, no performance claims.** #71 watch; the guard pin (§5.5) blocks a silent migration.
- **`sec=ASSUMED-FROM-LITERATURE`** (inherited from M29) — the PRF strength of `khash` is assumed, never proven; no symbolic collision/preimage/PRF harness exists, deliberately.
- **No aarch64 host-parity with the chardev lane** (the recommended choice) — aarch64 proves the codec + framing + host-keyed echo over `bus=SERIAL-FRAMED`, NOT a virtio device backend. The parity successors (custom QEMU device / vhost-user / aarch64 tb-vmm) are logged in §9 and `assumptions.md`.
- **Queue desync recovery is decoder-level, not live-ring** (§10) — device reset-and-reinit is a named deferral.
- **vsock (the semantically-correct class and B2's endgame) is deferred** — the frame format is designed to migrate onto it unchanged; that migration is the named successor, not an M30 claim.

## 13. Roadmap context

M30 lands the sovereignty A-chain's transport (#87): a verified channel to a host model peer, with tb-vmm's first virtio device backend and a host-keyed echo whose anti-hollow guarantee is a *composition* the M22 mock-loopback could never satisfy. It promotes the M22 runner-up with the amendment that makes the loopback structurally impossible. Named successors: **M31** (the real Anthropic adapter / mock backend onto this channel, #89), **M32** (the local model daemon, #90), **B2** (the vsock-only `model:` API — the frame format already migrates onto it), **M33** (a signature primitive — upgrading the echo from host-participation to host-exclusivity), and the aarch64 virtio-device-parity options if the chardev lane's external-dep is ever to be retired.

---

### References
Full survey in [`docs/research/m30-infer-transport-literature.md`](../research/m30-infer-transport-literature.md). Key: OASIS Virtio 1.2/1.3 (§4.2 MMIO, §5.3 console, §5.10 vsock, §2.7.8.2 used-ring MUSTs) · Linux `virtio_ids.h` (ID space + gaps) · Firecracker vsock + internals (the VMM-internal device + host-socket peer architecture; `KVM_IOEVENTFD` vs the plain-MMIO-exit alternative) · rust-vmm `virtio-queue` (split-ring device-side reference) · Kata Containers / Nitro Enclaves (host-policy-peer RPC-over-virtio precedent) · COBS + 9p2000 tag (framing/correlation precedent) · Fedora/Harvey-OS/barebox (stock-QEMU `virtconsole`+chardev-over-virtio-mmio recipe) · the M29 `khash` leaf + the prove-vs-assume convention. In-repo: `crates/tb-encode/src/{opframe,opframe_rx,ipc_frame,khash}.rs`, `crates/tb-hal/src/arch/{aarch64,x86_64}/virtio.rs`, `tb-vmm/src/{vmm,device,memory,cli}.rs`, the sovereignty plan §M30 (`sovereignty-plan` branch), the M22 runner-up at `docs/proposals/M22-memory-provenance.md:23`.
</content>
</invoke>
