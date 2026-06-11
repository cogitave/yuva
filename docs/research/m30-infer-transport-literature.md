# M30 literature survey — the verified inference-transport channel (`tb-encode::inferwire` + the virtio-mmio seam)

Companion to [`docs/proposals/M30-infer-transport.md`](../proposals/M30-infer-transport.md). This survey discharges the research half of **#87 / A1 infer-transport** (sovereignty-plan branch, `docs/plans/sovereignty-plan.md` §M30): a verified bidirectional virtio-mmio request/response inference channel — a Kani-proven `tb-encode` frame-codec leaf plus the kernel virtio seam, with a **host-applied khash-transformed echo** (the M29 leaf) as the anti-hollow load-bearer. It promotes the M22 runner-up (`docs/proposals/M22-memory-provenance.md:23`) — the design demoted in M22 precisely because its round-trip terminated at an in-kernel mock loopback — and the sovereignty-plan amendments make that loopback structurally impossible. Where M30 goes beyond a source it is flagged **[BEYOND]**.

---

## 1. The decision frame (from the project's own constraints)

The channel has three hard fixtures the literature must be fitted to, not the other way round:

- **The kernel virtio layer is mature and poll-only.** M19 landed virtio-rng (DeviceID 4) and M20 virtio-blk (DeviceID 2) over virtio-mmio on BOTH arches: aarch64 modern-v2 slot scan at `0x0A000000` (32 slots, stride `0x200`, already Device-mapped — `crates/tb-hal/src/arch/aarch64/virtio.rs`), x86 microvm window at `0xFEB00000` (the 4-page UC region at `VIRTIO_WINDOW_VA`). The drivers spin on `used.idx` with `VIRTQ_AVAIL_F_NO_INTERRUPT` — **no interrupt path exists**, and #71 (the TCG ghost-IRQ flake) stays out of scope as long as that holds.
- **tb-vmm has NO host-side virtio backend today.** `tb-vmm/src/vmm.rs` constructs `mmio_bus = Bus::new()` EMPTY; only COM1 + a BootReady PIO live on the bus; the exit loop dispatches `VcpuExit::MmioRead/MmioWrite` to that empty bus and is sized (`MAX_EXITS`) with a stale "M0–M4 boots" comment. tb-vmm is x86_64/KVM/Linux-only — **no aarch64 arch**. BACKLOG row 23 records this deferred backend. M30 must build tb-vmm's **first** virtio device backend.
- **The frame codec must be a verified `tb-encode` leaf** in the M22..M29 mold (the `opframe`/`opframe_rx`/`ipc_frame` discipline: fixed-layout canonical LE frame, reserved-zero fail-closed, Kani-proven totality), so the request/response protocol — not the transport class — is where the verification lives.

Every candidate below passes the hard gates the kernel already enforces (modern virtio-mmio Version=2, the `0x200`-stride register window both drivers scan, poll-only completion). They differ on: **does a stock-QEMU device carry the class on virtio-mmio on BOTH arches** (the aarch64-lane decider), how much host-side device-model state the class costs, message-framing fit, and standardization/ledger debt (the device-ID question).

## 2. Device-class survey (Virtio 1.2/1.3, OASIS)

Canonical device-ID space confirmed against Linux `include/uapi/linux/virtio_ids.h` — the authoritative practice record, used because the spec-HTML extraction tooling returned garbled tables while the header is exact: **1**=net, **2**=blk (M20), **3**=console, **4**=entropy (M19), **9**=9P, **19**=vsock, **26**=fs, **45**=SPI (highest assigned). **Unassigned gaps: 14–15, 42–44, and everything >45.** New IDs formally require OASIS TC registration (spec Appendix "Creating New Device Types").

| Class | Queues / state | Message semantics | Stock-QEMU virtio-mmio peer, BOTH arches? | Host-side cost | Verdict |
|---|---|---|---|---|---|
| **virtio-console (3)**, single-port | receiveq(0) + transmitq(1) ONLY when `F_MULTIPORT` is NOT negotiated (§5.3.2); no control queue, no config space | byte STREAM, **no message boundaries** | **YES** — `-device virtio-serial-device -device virtconsole,chardev=<socket>` over virtio-mmio, modern-v2 via `-global virtio-mmio.force-legacy=false` (Fedora VirtioSerial, Harvey-OS wiki, barebox VirtIO docs all show this exact recipe) | 2-queue register file; trivial | **RECOMMENDED** |
| virtio-vsock (19) | rx + tx + event (§5.10.2); 44-byte `virtio_vsock_hdr`; connection state machine REQUEST/RESPONSE/RST/SHUTDOWN/RW/CREDIT_*; credit-based flow control (§5.10.6) | connection-oriented streams | **NO** stock — needs the host `vhost-vsock` kernel module or a `vhost-user-vsock` daemon (rust-vmm `vhost-device-vsock`); Firecracker deliberately *reimplemented* the device model to avoid vhost | large (≈ the size of tb-vmm's entire current device layer) | rejected for M30; named growth path (sovereignty plan B2 already pins a vsock-only `model:` API) |
| custom ID (14/15/42–44/>45) | 1 requestq, virtio-blk-style chains (response in device-writable buffers of the same chain; `used.id` correlates implicitly) | message-framed for free | **NO** — needs a custom QEMU C device, or vhost-user (no stock frontend for an unknown ID), or aarch64 tb-vmm | medium, but kills the aarch64 lane | rejected: an unregistered ID is exactly the silent nonstandard-ABI dependency the sovereignty ledger forbids (collision risk as IDs grow past 45) |
| 9P (9) / fs (26) / rpmsg (7) | full file/RPC protocols | — | yes (9P) | massive | over-scope; 9P's u16 `tag` is cited ONLY as a correlation-id precedent |

**Eliminations.** **vsock** is the *semantically* ideal class — it is literally "host↔guest RPC over virtio" and is the roadmap's own endgame (B2) — but stock QEMU cannot carry it on virtio-mmio without `vhost` entanglement, which has no stock frontend on the aarch64 `virt` lane and would force either a kernel-module dependency or a vendored vhost-user daemon: both are CI-host substrate M30 cannot assume. **Custom ID** buys implicit chain-correlation but at the cost of the entire aarch64 lane (no stock peer) and an out-of-spec device ID — a sovereignty-ledger debt by construction. **9P/fs** are whole protocols, orders of magnitude over a request/response echo.

## 3. The recommendation — virtio-console (DeviceID 3), single-port, modern-v2, poll-only; runner-up vsock

**Chosen: virtio-console, device ID 3, NON-`F_MULTIPORT` single port (so exactly receiveq+transmitq, zero control queue, zero config space), modern virtio-mmio (Version=2), poll-only, negotiating ONLY `VIRTIO_F_VERSION_1` — never `F_MULTIPORT`/`F_SIZE`/`F_EMERG_WRITE`.**

The decisive coupling: **option 3 is the ONLY class with a stock-QEMU virtio-mmio peer on BOTH arches**, which is what gives the aarch64 lane a host peer with zero QEMU patching (§5), AND tb-vmm can emulate DeviceID 3 with a 2-queue register file, so **ONE kernel driver and ONE verified codec leaf serve both lanes** (`transport=TB-VMM-HOST` on x86/KVM via tb-vmm's first `mmio_bus` device; `transport=QEMU-CHARDEV-HARNESS` on the stock-QEMU lanes). The byte-stream nature is turned into a feature: because the transport does NOT preserve message boundaries, the Kani-proven framing/resync/MAC-verification leaf is genuinely **load-bearing**, not decorative — the exact opposite of M22's hollow mock-loopback.

**Trade-offs accepted, recorded honestly:**

1. **Byte-stream, no message boundaries.** Compensated by an explicit length-prefixed magic+MAC frame with scan-to-next-magic resync — which a stream needs anyway, and which is *forward-compatible with the roadmap's own vsock endgame*: a length-prefixed stream frame rides a vsock `SOCK_STREAM` unchanged, whereas descriptor-chain-implicit framing (custom-ID's one advantage) would not survive the move. M30's wire format is therefore the migration-safe choice.
2. **We forgo implicit chain correlation** (custom-ID's advantage) — replaced by an explicit `req_id`/correlation field on the wire from day one (§5), so a future move to pipelining or to the #71-watched IRQ path never forces a frame-version bump.
3. **vsock rejected now** (3 queues + connection state machine + credit accounting + vhost entanglement absent from stock QEMU) but the codec is designed to migrate onto it.
4. **Custom ID rejected by name** — no aarch64 peer without vendored QEMU/C debt, and an unregistered ID is sovereignty-ledger debt.

**Runner-up: virtio-vsock (DeviceID 19).** The semantically-correct class and the roadmap's pinned destination (B2's vsock-only `model:` API). Why not now: stock QEMU on virtio-mmio cannot carry it without `vhost`, killing the zero-patch aarch64 lane; the device model is the heaviest in the table. The M30 frame leaf is explicitly designed so the *frame* migrates onto a vsock stream when B2 lands — the codec is the durable artifact, the class is replaceable.

## 4. Minimal host-side virtio-mmio backend — what tb-vmm must implement

From Virtio 1.2 §4.2 plus Firecracker / crosvm / cloud-hypervisor / rust-vmm practice. The kernel driver already fixes the exact register set, so the backend's surface is bounded:

- **Register window per slot** (fits the `0x200` stride both arch drivers scan): Magic `0x000`=`0x74726976`, Version `0x004`=2, DeviceID `0x008`=3, VendorID `0x00C`, Device/DriverFeatures(+Sel) `0x010`–`0x024` (must offer `VIRTIO_F_VERSION_1`, bit 32 — the high feature word), QueueSel/NumMax/Num/Ready `0x030`–`0x044`, QueueNotify `0x050`, InterruptStatus/ACK `0x060`/`0x064`, Status `0x070`, split queue address registers `0x080`–`0x0A4`. These offsets match the kernel's driver-side table in `crates/tb-hal/src/arch/aarch64/virtio.rs` verbatim.
- **Status state machine** (§2.1.2): device MUST NOT consume buffers before `DRIVER_OK`; a reset (Status=0 write) must zero state; reject unhonorable features at `FEATURES_OK`.
- **Used-ring ordering MUSTs** (§2.7.8.2): write response bytes → write `used.ring[i].{id,len}` → ONLY THEN bump `used.idx`. This is the mirror image of the kernel driver's `dmb ishst`-before-publish discipline (M19/M20).
- **Notification path — the simplifying decision.** Firecracker registers `KVM_IOEVENTFD` on the `0x050` notify offset per queue for async wakeup ([Hoffman, Firecracker internals]). The **plain alternative — no ioeventfd: a QueueNotify write takes a normal MMIO exit into `mmio_bus.write`, and the device processes the queue synchronously in the exit handler — is simpler, deterministic, and exactly fits tb-vmm's existing exit loop**, which already routes `MmioWrite` to the (currently empty) bus. Since the kernel is **poll-only** (`VIRTQ_AVAIL_F_NO_INTERRUPT`), **no irqfd / interrupt injection is needed at all**; the backend may still set InterruptStatus bit 0 for spec conformance, but the guest never reads it. **No #71 exposure** results.
- **Descriptor-chain walking.** rust-vmm's `virtio-queue` crate (split-ring only) is the canonical Rust device-side reference; M30 **mirrors its model** in a few hundred lines rather than importing it (importing would be a dependency-policy-ledger decision; the kernel's own M19/M20 ring code is the closer house precedent). The device holds a guest-memory handle — a clone of tb-vmm's `GuestMemoryMmap` (`vm-memory`, Arc-backed) passed in at construction.

## 5. Framing, correlation, backpressure — what the field uses

- **Framing.** COBS (Cheshire & Baker, SIGCOMM '97 / ToN '99) guarantees ≤1 byte overhead per 254 and **self-resynchronization** via the reserved `0x00` delimiter — its real advantage is desync recovery on dumb/lossy serial. Netstrings/length-prefix are cheaper but a corrupted length desyncs a stream forever with no resync anchor. **M30's channel is 8-bit-clean and reliable** (a virtqueue or a `SOCK_STREAM` chardev), so COBS's distinguishing benefit is weak. **Recommendation: a fixed-size little-endian header — magic word + version + kind + correlation-id + length + a khash tag (the M29 leaf) over `header‖payload` — with fail-closed reject + scan-to-next-magic resync.** This gives *stronger* resync than COBS (which can delimit but cannot detect corruption), and it is exactly the existing `ipc_frame.rs`/`opframe.rs` discipline (fixed `[u8; N]` frame, reserved-bits fail-closed, fixed-capacity ring — all already Kani-proven patterns in `crates/tb-encode/src/ipc_frame.rs`).
- **Correlation.** 9P precedent — a u16 `tag` unique among outstanding requests, NOTAG sentinel (9p2000 RFC); the JMS/EIP CorrelationID enterprise pattern. **Recommend a u64 correlation id with in-flight window = 1 initially** (poll-only ⇒ one outstanding request) but **on the wire from day one** so pipelining or the #71 IRQ migration never forces a frame-version bump.
- **Backpressure.** On the tb-vmm lane the bounded virtqueue IS the backpressure (the driver cannot post past `QueueNum` slots — virtio's native model); at protocol level the in-flight window bounds it; vsock's `buf_alloc`/`fwd_cnt` byte-credit scheme (§5.10.6) is the cited mechanism if byte-level credit is ever needed. In-kernel staging reuses the proven fixed-capacity ring in `ipc_frame.rs`.

## 6. Host↔guest RPC-over-virtio precedent (why the pattern is right even though vsock the class is deferred)

The architecture M30 builds — a VMM-internal (or host-process) device backend that holds the policy, with the guest as the requesting peer — is the mainstream pattern; only the *class* differs:

- **Firecracker hybrid vsock** ([docs/vsock.md]): a full virtio-vsock device model *inside the VMM*, host side mapped to AF_UNIX; the host-initiated handshake is literal text `"CONNECT <port>\n"` → `"OK <port>\n"`; a guest-initiated REQUEST maps to a `v.sock_PORT` UDS, RST if absent. Proof that a VMM-internal device + a host-socket peer is a sound, audited architecture — exactly M30's `TB-VMM-HOST` shape.
- **AWS Nitro Enclaves**: vsock is the *only* channel into an enclave; RPC layered on top (`vsock_proxy`).
- **Kata Containers**: the guest agent serves ttRPC (a low-memory gRPC reimplementation) over vsock/virtio-serial exposed to the host as a socket file. The **host-side-runtime / guest-agent split with the host holding policy is structurally identical to M30's anti-hollow shape** (host-held khash key/nonce, host applies the transform).

These validate "request/response RPC over a virtio channel with the host peer holding the policy/key" — the durable lesson, independent of whether the carrier is vsock or virtio-console.

## 7. The verified-leaf fit — why the codec, not the transport, is where verification lives

M30 inherits the M22..M29 reuse discipline: **the transport is unverified plumbing; the frame codec is the verified leaf, and the M29 `khash` leaf is reused, not re-implemented.** The new `tb-encode::inferwire` leaf is a sibling of `opframe`/`opframe_rx` (next house magic word `0x5444` after `0x5442`/`0x5443`): a fixed-layout canonical LE frame with reserved-zero fail-closed decode, a length-prefixed payload bounded for Kani, a `FrameAccum` byte-stream accumulator (the `ipc_frame.rs::BoundedRing` pattern, but length-delimited — the actual need on a stream lane), and an `echo_tag`/`verify_echo` pair that makes exactly ONE `khash` call with a domain-separated label. The field convention M29 already adopted carries over verbatim:

**PROVEN (Kani, concrete inputs / short-symbolic, the #49 discipline):** canon↔decode round-trip + injectivity; fail-closed totality on short/reserved/oversize frames; the request/response correlation-binding iff-theorem; `verify_echo` soundness + single-byte tamper rejection; `FrameAccum` never-overflow / resync; determinism.

**ASSUMED / NOT-PROVEN (tokened, never prose-claimed):** the cryptographic strength of `khash` (`sec=ASSUMED-FROM-LITERATURE`, inherited from M29); host EXCLUSIVITY (the key is symmetric and compiled into both ends — the echo proves host *participation* via the host-held nonce + the script's cross-process check, not host exclusivity, until the M33 signature primitive); message/inference *semantics* (`backend=ECHO-ONLY` — meaning arrives in M31).

**[BEYOND] the literature.** The synthesis — a **Kani-proven `no_std`/forbid-unsafe frame-codec leaf carrying a host-keyed liveness echo over a stock-class virtio channel, where the anti-hollow guarantee is a *composition* of in-guest khash verification AND a cross-process tag-equality check against a host-custodied per-run key, with the prove/assume boundary machine-emitted as witness tokens and enforced by anti-overclaim CI guards** — appears in no single source. Firecracker/Kata prove the host-policy-peer architecture is sound but token-encode nothing; the verified-codec literature (`ipc_frame`, opframe) does not carry a cross-process anti-loopback adjudication; the Virtio spec carries no notion of a hollow-evidence adversary. The transport is standard; the verification packaging and the anti-hollow composition are the novel part.

---

## 8. The aarch64 host-peer decision (the plan's explicit external-dependency item)

tb-vmm has no aarch64 arch, and **no stock QEMU device carries this channel as a custom protocol** — so the aarch64 host peer is an explicit external-dependency choice, ranked:

| Option | Mechanism | Cost | Verdict |
|---|---|---|---|
| **A. QEMU chardev-framed harness** | stock `-device virtio-serial-device -device virtconsole,chardev=<unix-socket>` on `virt` (+ `force-legacy=false` for Version=2, which the kernel driver hard-requires); a small host harness speaks inferwire+khash over the socket | one host harness binary (reuses `tb-encode`; ~S) + run-script wiring; must verify non-MULTIPORT port-0 fallback + Version=2 on BOTH qemu-6.2 (local) and 8.2.2 (CI `tabos-qemu8`) | **RECOMMENDED**; token `transport=QEMU-CHARDEV-HARNESS`; reusable on the x86 QEMU microvm lanes too |
| B. Custom QEMU device | fork/patch QEMU | breaks the stock-QEMU + prebuilt-CI-image story; XL | rejected |
| C. vhost-user | `x-vhost-user-device` is experimental, absent from qemu-6.2 | version-gated, fragile | rejected for M30; revisit at B2 |
| D. Skip-with-loud-token | `M30: infer-transport OK (no host peer, skipped)` on aarch64 only | violates the both-arches DoD; the amendments reject skip lanes | fallback ONLY if A fails empirically, logged as an explicit external-dep concession in `assumptions.md` |
| E. aarch64 tb-vmm | new arch in tb-vmm | XL | deferred ("aarch64-tb-vmm later" in the plan) |

**Option A is RECOMMENDED**, and it is available ONLY because the chosen class is console (3) — the decisive coupling with §3. The external-dep decision to log in the proposal: option A makes QEMU's virtio-console device model part of the aarch64 (and QEMU-x86) trust path for this marker — status **ACCEPTED-PERMANENT**, alongside QEMU itself. The harness MUST be ONE Rust host tool reusing `tb-encode` (never a second codec implementation in shell/python).

**Empirical spike required before the proposal freezes the device choice:** non-MULTIPORT port-0 behavior of `virtconsole` on qemu-6.2 vs 8.2.2, and Version=2 negotiation under `force-legacy=false`.

---

### Sources
- [OASIS Virtio 1.2 cs01 (spec HTML)](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html) — §4.2 MMIO transport, §5.3 console, §5.10 vsock, §2.1.2 status, §2.7.8.2 used-ring MUSTs · [Virtio 1.3 csd01](https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html)
- [Linux include/uapi/linux/virtio_ids.h](https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/virtio_ids.h) — exact ID assignments + gaps
- [Firecracker docs/vsock.md](https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md) — hybrid vsock, CONNECT/OK handshake · [Firecracker internals (Hoffman)](https://www.talhoffman.com/2021/07/18/firecracker-internals/) — `KVM_IOEVENTFD` on the 0x050 notify offset
- [rust-vmm vm-virtio / virtio-queue](https://github.com/rust-vmm/vm-virtio/blob/main/virtio-queue/README.md) — canonical split-queue device-side Rust · [rust-vmm vhost-device-vsock](https://github.com/rust-vmm/vhost-device/blob/main/vhost-device-vsock/README.md)
- [Garzarella, KVM Forum 2019: virtio-vsock in QEMU/Firecracker/Linux](https://stefano-garzarella.github.io/posts/2019-11-08-kvmforum-2019-vsock/)
- [Kata Containers architecture](https://github.com/kata-containers/kata-containers/blob/main/docs/design/architecture/README.md) + [VSocks.md](https://github.com/kata-containers/kata-containers/blob/main/docs/design/VSocks.md) — ttRPC-over-vsock host-runtime/guest-agent split
- [AWS Nitro Enclaves concepts](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html) + [vsock_proxy](https://github.com/aws/aws-nitro-enclaves-cli/blob/main/vsock_proxy/README.md)
- [Cheshire & Baker, COBS (SIGCOMM '97)](http://conferences.sigcomm.org/sigcomm/1997/papers/p062.pdf) / [ToN version](https://www.stuartcheshire.org/papers/COBSforToN.pdf) + [mbedded.ninja COBS analysis](https://blog.mbedded.ninja/programming/serialization-formats/consistent-overhead-byte-stuffing-cobs/)
- [9p2000 RFC (u16 tag correlation precedent)](https://ericvh.github.io/9p-rfc/rfc9p2000.html)
- Stock-QEMU virtio-console-over-virtio-mmio recipe: [Fedora VirtioSerial](https://fedoraproject.org/wiki/Features/VirtioSerial) · [Harvey-OS Using Virtio (QEMU)](https://github.com/Harvey-OS/harvey/wiki/Using-Virtio-(QEMU)) · [barebox VirtIO docs](https://www.barebox.org/doc/latest/user/virtio.html)
- In-repo precedent: `crates/tb-encode/src/{opframe,opframe_rx,ipc_frame,khash}.rs`, `crates/tb-hal/src/arch/{aarch64,x86_64}/virtio.rs`, `tb-vmm/src/{vmm,device,memory,cli}.rs`, [`docs/research/m29-crypto-mac-literature.md`](m29-crypto-mac-literature.md) (the prove-vs-assume convention + the khash leaf), the M22 runner-up at `docs/proposals/M22-memory-provenance.md:23`.
</content>
</invoke>
