# Yuva v2 Roadmap — the agent-native milestone chain (M5 → M18)

> Status: **the full v2 chain M5→M18 is COMPLETE and CI-green on both arches** (atop the v1 M0–M4 foundation + L1 sovereignty / tb-vmm). M18, the self-improving capstone, lands the frozen-kernel / evolving-userspace split — the capstone of the agent-native chain.
> Since then the chain has grown a tail of follow-on markers — **M14.1** (byte-payload IPC), **M14.2** (blocking-recv), **M15.1** (block unmap + frame reclamation), **M18.1** (mandatory human-approval gate), **M18.2** (rotating held-out evaluator), **M19** (a poll-based virtio-mmio virtio-rng round-trip — the kernel's FIRST real device I/O), the aarch64 sovereignty-L2 chain **L2.0→L2.6** (EL2 world-switch → stage-2 → exit-dispatch → trap-and-emulate → nested-EL1 guest → vGIC → SMMUv3), then **M20** (durable virtio-blk persistence), **M21** (a verified fixed-point additive-policy seam, SHIPS DORMANT), **M22** (a verified per-agent provenance hash-chain ledger), and then the **learning-loop arc** — **M23** (a verified experience codec + counterfactual shadow-recording), **M24** (the HONEST activation gate that correctly REFUSES on synthetic data, `M24: bakeoff OK (gate-not-met)`), **M25** (the verified OPERATOR TRANSCRIPT — a typed, tamper-evident channel surfacing the OS's decisions to a human exogenous oracle, anchored to the live M22 head, `M25: operator OK`), and **M26** (a verified EL2 EXIT-TELEMETRY producer — the already-Kani-proven `el2_trap` guest-exit classifier becomes a bounded no-float injective telemetry record folded into a separate `tel_head`; the OS records its own virtualization workload; PRODUCER-ONLY, `signal=OBSERVATIONAL-NONCAUSAL` — the marker `M26: exit-telemetry OK`, the cumulative TAIL until M28 landed), and **M27** (the sovereignty pillar's two-VMID time-partition SCHEDULER — the EL2 monitor alternates two guest VMIDs in a fixed major frame, folding each Kani-proven `SchedDecision` into a tamper-evident `sched_head`; landed as M27a (the cooperative green floor) then upgraded by **M27b** to REAL CNTHP timer-preemption — the FIRST asynchronous IRQ taken at EL2 (the 0x480 vector, IMO=1 only inside the armed window; pure store-spin guest stubs, so forward progress is only reachable via genuine preemption); `timing=TCG-NON-CYCLE-ACCURATE realtime=NOT-CLAIMED`, the retired cooperative token guard-REJECTED; `M27: sched OK`, in the L2-track position after L2.6, before M19), and **M28** (the operator INBOUND channel — `tb-encode::opframe_rx`, the RX dual of M25's `opframe` — the exogenous-oracle CAPSTONE that CLOSES the learning loop: a human holding TWO enrolled credentials answers the OS's freshness challenge and submits a dual-authorized `ACTIVATE_CMD` bound to the live M22 head. THE GATE IS MACHINE-PROVEN: the pure, buffer-free/hash-free conjunctive verdict core `opframe_rx::verify_decoded(frame, expected_nonce, live_head, mac_ok)` — `decode_and_verify` delegates its verdict to it verbatim — is Kani-driven fully symbolically: RejectStale iff echo≠challenge, RejectWrongHead iff the bound head differs from a fully-symbolic live head, RejectSingleCred iff `cred_a==cred_b`, RejectBadMac iff distinct-creds AND `!mac_ok`, Accept IFF every conjunct holds (the Accept-iff-all theorem), plus kind-dominance (NotActivate); the negative controls are MUTATION-TESTED (deleting each reject branch → VERIFICATION FAILED ×3), the `decode_and_verify` WRAPPER's buffer/MAC plumbing is host-tested across all 7 verdict arms (run under the Miri CI lane) + boot self-tested, and a pre-merge ADVERSARIAL VERIFICATION (4 independent skeptics: mac-honesty / gate-bypass / necessary-not-sufficient / harness-vacuity + a merge-verdict synthesis) confirmed the core sound — its two honesty findings (vacuous gate harnesses, a one-shot overclaim) FIXED before merge. HONEST SCOPE (machine-emitted tokens the run scripts enforce): `mac=KEYED-NONCRYPTO` — a NESTED keyed-FNV envelope genuinely keyed by two 256-bit creds but NOT cryptographic (FNV is not collision/preimage resistant); `oracle=SIMULATED-ENROLLED-KEY` — a compiled-in test key, NOT a human/enrolment; `kan_active=0` — an Accept is NECESSARY-NOT-SUFFICIENT (M24's statistical bar still gates); and the replay scope is honest: the verifier is pure + stateless, so staleness rejection is per-EPOCH, NOT one-shot/per-challenge nonce consumption (an identical valid wire re-verifies within the same epoch; rotate-on-accept in the stateful seam is a named successor). The cumulative TAIL marker until M29 landed: `M28: operator-cmd OK`, printed after M26), and **M29** (the M28 §5 named successor LANDS — `mac=KEYED-NONCRYPTO` retires for **`mac=KEYED-CRYPTO`**: ONE new verified primitive leaf `tb-encode::khash` (BLAKE2s-256, RFC 7693, native keyed mode — width-exact to `KEY_LEN`/`PROV_HASH_LEN`/`MAC_LEN`, the keyed mode carrying the Luykx–Mennink–Neves FSE 2016 PRF/MAC proof so NO envelope and NO HMAC wrapper) re-points the M28 MAC to derive-then-MAC (`K_s = khash(key_a, "YUVA-OPCMD-KDF-V1"‖key_b)`; `tag = khash(K_s, canon)[..16]`; `kdf=DERIVE-THEN-MAC-DOMSEP`) and `key_evolve` to `khash(key, "YUVA-KEY-EVOLVE-V1")` (`keyevolve=PRF-DOMSEP`; the selftest TESTS old-key erasure, `oldkey-zeroized=1`) with signatures UNCHANGED; the in-boot KAT recomputes the official RFC 7693 Appendix B + BLAKE2 reference-KAT vectors through the real compression fail-closed per boot (`kat=RFC7693-PASS` is EARNED, never compiled-in); the prove/assume boundary is machine-emitted — implementation totality/determinism/KAT-correctness/tamper-sensitivity PROVEN by 4 new `kani_khash_*` harnesses on CONCRETE inputs (the #49 discipline; each mutation-tested), primitive collision/preimage/PRF/forgery resistance **`sec=ASSUMED-FROM-LITERATURE`** (the Appel TOPLAS 2015 / HACL* / mlkem-native claim boundary — deliberately NO symbolic security harness); `sidechannel=NOT-CLAIMED`; `prim=BLAKE2S-256` names the informational-RFC trade; `oracle=SIMULATED-ENROLLED-KEY` + `kan_active=0` stay VERBATIM, and the retired `KEYED-NONCRYPTO` token is guard-REJECTED. The cumulative TAIL marker until M30 landed: `M29: khash-mac OK`), and **M30** (the verified INFERENCE TRANSPORT, stages A+B — the sovereignty A-chain channel (#87) promoting the M22 runner-up with its mock-loopback made structurally impossible: the Kani-proven `tb-encode::inferwire` codec leaf (house magic `0x5958`; fail-closed `canon`/`decode`, the `FrameAccum` byte-stream re-framer, the ONE-khash-call `echo_tag`/`verify_echo` binding peer_id‖nonce‖challenge‖body INSIDE the MAC) rides the kernel's FIRST TWO-queue virtio driver — a modern (Version==2) virtio-console, DeviceID 3, VERSION_1-only port 0, rx posted before DRIVER_OK, poll-only `mode=POLL` (#71 guard-pinned) — to the `xport-harness` HOST peer over a QEMU virtconsole chardev unix socket; the host CUSTODIES a per-run OS-RNG key K + nonce N (never in the guest image/cmdline), applies the khash echo, reveals K on the channel, and the DoD is the TWO-LEG anti-hollow composition: kernel-side `verify_echo` + four in-boot negatives (leg 1, `echo=HOST-KEYED-VERIFIED` — explicitly kernel-scope) AND the run scripts' CROSS-PROCESS challenge/tag string-equality against the harness's own printed line (leg 2 — the loopback killer), plus skip/loopback-by-name rejects, the lane cross-pin, the `mode=IRQ` tripwire, a key-leak negative and strip-then-reject overclaim guards; `key=HOST-CUSTODIED-PER-RUN` (custody, not confidentiality), `backend=ECHO-ONLY` (transport only — the M31 adapter brings semantics), `transport=QEMU-CHARDEV-HARNESS bus=SERIAL-FRAMED` on the TCG lanes; stage C (the tb-vmm `TB-VMM-HOST` device backend) split to its own follow-up landing; the cumulative TAIL marker until M31 landed: `M30: infer-transport OK`), and **M31** (the verified INFERENCE ADAPTER, stages A+B — the first MEANING on the M30 channel (#89): the `inferwire` leaf EXTENDED (not a 21st leaf) with the closed kinds INFER_REQ/INFER_RESP/INFER_PENDING + closed-enum ERR payload semantics, the 24-byte in-payload chunk sub-header for stop-and-wait chunking under the untouched 1024 payload cap, the compile-time shared `INFER_BODY_CAP=8192` (reject-never-truncate), the per-chunk `infer_tag` MAC under the NEW `"YUVA-M31-INFER-V1"` domain binding peer‖nonce‖challenge‖req_id‖kind‖seq‖sflags‖total_len‖body_digest‖chunk INSIDE the MAC, and the Kani-proven chunk-at-a-time `InferAssembler` whose completion requires digest-commitment equality; the kernel retires the u64 toy with the object-safe zero-alloc `infer_bytes` byte path + `M_MODEL_INVOKE_BYTES=32` at the same INVOKE_MODEL chokepoint; the every-boot MOCK-LANE e2e — M13 context recalled through the chokepoint → byte prompt → the ROUTES-registered MOCK-DETERMINISTIC backend (the SHARED `mock_infer` transform) → `req_id‖op_hash(response)` folded into the M25 transcript BEFORE its closing GATE_VERDICT → the WIRE legs against the keyless harness serve loop (a MAC'd `ERR code=NO-KEY` probe answer + EXACTLY ONE MAC'd PENDING heartbeat + the deterministic response as 2 MAC'd chunks reassembled, digest-verified, and required BIT-EQUAL to the in-kernel expectation) + four in-boot negatives; ALL model-derived bytes cross serial lowercase-hex-encoded (injection-proofing, ESC-tripwired, grammar-pinned); honesty tokens `backend=MOCK-DETERMINISTIC key=CAPREF-HOST-CUSTODIED host=RESIDUAL-TCB ambient=ZERO-IN-GUEST`; the LIVE ANTHROPIC half is stage C — operator-gated `workflow_dispatch` + a repo secret, never a required check, never unattended, its marker banned from the cumulative chain by name; the NEW cumulative TAIL marker `M31: infer-e2e OK backend=MOCK-DETERMINISTIC` is what both run scripts grep for; the boot chain is M0..M31 + L2.0..L2.6) — plus a **formally-verified core**: the M11 rights-subset invariant is Kani-proven (`crates/tb-caps-core`, `M11: caps-subset PROVEN`), the silicon-unsafe encoders/parsers + the memory/learning leaves are Kani-proven over the 21-leaf `crates/tb-encode` (102 harnesses, `V1: kani-encoders OK`), and a Miri Tier-0 UB gate runs over both (`T0: miri OK`). CI now has **9 gates across 8 workflow files** (ci, vmm-boot, l2-nested-vmx, microvm-kvm, kani [2 jobs], miri, clippy, bench). See §6.
> This document is the canonical, tracked plan for **v2**: turning the M0–M4
> hardware foundation into the agent-native OS the four pillars describe. Each
> milestone has an **executable Definition-of-Done** — an exact serial marker
> the kernel prints once the capability works — and the kernel runs milestones
> **cumulatively** (every boot regresses M0..latest under the QEMU + tb-vmm grep
> harness). Built by the same pipeline as M0–M4 (generate → adversarial review →
> apply → build → boot-and-assert → commit), one milestone per increment.
> Related: [MILESTONES](MILESTONES.md) · [VISION](VISION.md) ·
> [ARCHITECTURE](ARCHITECTURE.md) · [MEMORY-SPEC](MEMORY-SPEC.md) ·
> [AGENTS-SPEC](AGENTS-SPEC.md) · [SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md) ·
> [SOVEREIGNTY-ROADMAP](SOVEREIGNTY-ROADMAP.md) (the parallel L2 track).

This roadmap was produced by a four-lens architect panel (memory-first,
agent-runtime-first, ABI-first, risk/dependency-first) plus an adversarial
synthesis that resolved eight contested ordering decisions explicitly (see
§ Sequencing). It is a plan, not a contract: markers and DoDs are fixed once a
milestone lands; downstream milestones may be refined as earlier ones reveal
facts (the "actual build catches what review misses" rule that has held since M0).

---

## 1. The four pillars (why each milestone exists)

Every subsystem must answer **"what does this give an agent?"**

1. **Agent-native** — AI agents are first-class OS citizens; the syscall ABI is
   designed for agents (capability-based, non-POSIX: no fd/errno/ioctl/path/
   ambient-authority). Zero Linux heritage.
2. **LLM-agnostic** — API-based (Claude etc.) and local inference (vLLM/llama.cpp)
   are interchangeable behind one contract; GPU/CUDA is quarantined in a
   passthrough Linux driver VM reached only via a vsock inference API.
3. **Memory-central** — the OS gives every agent a **default** persistent,
   tiered, recallable memory substrate (MemGPT/MemOS/CoALA/HippoRAG lineage).
4. **Self-improving** — an agent improves itself on its own OS under a
   **frozen-kernel / evolving-userspace** split: evaluators and safety detectors
   live in a layer the agent provably cannot read or write (a visible metric
   gets Goodharted — the Darwin Gödel Machine lesson).

Plus the cross-cutting requirement: **single AND multiple agents in the same
session** (preemptive scheduling + capability-passing IPC).

---

## 2. The canonical chain

| # | Milestone | Pillar | DoD marker | Depends on |
|---|---|---|---|---|
| **M5** | Bootstrap kernel heap + `#[global_allocator]` (`alloc` online) | foundation | `M5: alloc OK` | M3 |
| **M6** | Physical frame allocator from the boot memory map | foundation | `M6: frame alloc OK` | M5, M3 |
| **M7** | Frame-backed growable kernel heap | foundation | `M7: heap OK` | M6, M5, M3 |
| **M8** | Async interrupt + monotonic timer tick (no switch) | foundation | `M8: timer OK` | M7, M1 |
| **M9** | Preemptive scheduler (involuntary full-context switch) | foundation | `M9: preempt OK` | M8, M2 |
| **M10** | Per-agent address spaces (memory isolation) | foundation | `M10: addrspace OK` | M9, M3 |
| **M11** | Capability handle table + kernel object model + agent-native syscall ABI | agent-native | `M11: caps OK` | M7, M4 |
| **M12** | Agent runtime — `AgentProcess` as a first-class scheduled, isolated entity | agent-native | `M12: agent OK` | M11, M10, M9 |
| **M13** | Default tiered memory substrate (T0/T1/T2 + lexical T3 + `tb_mem_*` ABI) | memory-central | `M13: memory OK` | M12, M11 |
| **M14** | Inter-agent IPC — capability-passing channels + ordered streams (+ M14.1 byte payload: `copy_to_user`/`copy_from_user` bounce buffer, `MAX_PAYLOAD=4096`, two new arch `uaccess.rs` unsafe modules; + M14.2 blocking-recv / runnable-on-send scheduler↔IPC integration) | multi-agent | `M14: ipc OK` → `M14.1: payload OK` → `M14.2: blocking-recv OK` | M12, M11, M9 |
| **M15** | Shared memory blocks + session blackboard (+ M15.1 owner-only `M_BLOCK_UNMAP` + frame reclamation, new `arch/*/mmu.rs` unmap unsafe) | memory-central | `M15: blocks OK` → `M15.1: unmap OK` | M14, M13, M10 |
| **M16** | LLM-agnostic inference bridge (the `model:` scheme) | LLM-agnostic | `M16: infer OK` | M14, M12, M8 |
| **M17** | Sleep-time consolidation / reflection / forgetting daemons | memory-central | `M17: consolidate OK` | M13, M16, M9 |
| **M18** | Frozen-kernel self-improvement harness + held-out evaluators + skill tier (+ M18.1 mandatory human-approval gate on `EMIT_EXTERNAL`/high-impact skills; + M18.2 rotating never-exposed held-out evaluator partition) | self-improving | `M18: evolve OK` → `M18.1: approval-gate OK` → `M18.2: held-out OK` | M11, M12, M13, M17 |
| **M19** | Poll-based virtio-mmio device I/O — a virtio-rng round-trip; the kernel's FIRST real device I/O (new `arch/*/virtio.rs` MMIO/DMA unsafe; completion-IRQ path deferred) | LLM-agnostic / device | `M19: virtio OK` | M16, M8 |

**Critical path:** `M5 → M6 → M7 → M8 → M9 → M10 → M11 → M12`, after which the
memory (M13/M15/M17), IPC (M14), inference (M16), and self-improvement (M18)
layers compose on the agent runtime.

**Framekernel dividend:** the *only* new `unsafe`/asm in the entire chain lives
in `tb-hal` — at M5–M12, then M14.1 (`uaccess.rs`), M15.1 (`arch/*/mmu.rs` unmap)
and M19 (`arch/*/virtio.rs`); M14/M16 themselves added **zero** new unsafe (the
cap moves by handle at M14; M16 ships a safe mock and deferred the virtio ring to
M19). The security-critical capability (M11), memory
(M13/M15/M17), and self-improvement (M18) layers add **zero new unsafe** — they
are entirely `#![forbid(unsafe_code)]` safe Rust, which is exactly where the
framekernel rule pays off (those are the Kani/Verus-targetable subsystems).

---

## 3. Milestones in detail

### M5 — Bootstrap kernel heap + `#[global_allocator]` · `M5: alloc OK`
Bring `extern crate alloc` online kernel-wide so `Box`/`Vec`/`BTreeMap`/`String`
work before any frame allocator exists. `tb-hal` holds a `KernelHeap` type with
`unsafe impl GlobalAlloc` over a fixed-size static `.bss` arena (free-list with
coalescing); the kernel declares `#[global_allocator] static HEAP: tb_hal::KernelHeap`
and stays `#![forbid(unsafe_code)]`. No boot-map parse, no new mapping (the arena
is already covered by M3's kernel mapping). **The allocator algebra written here
is reused unchanged by M7** — only the backing store changes later. Self-test:
`Box` a value; grow a `Vec` until it reallocates; build/iterate/drain a `BTreeMap`;
drop everything; re-alloc and assert the freed region is reused; a live-bytes
high-water counter returns to baseline (no leak); an over-arena request returns
null (handled, not UB). **Arch-neutral.**

### M6 — Physical frame allocator from the boot memory map · `M6: frame alloc OK`
Parse the active boot path's memory map into a real physical-frame allocator
handing out/reclaiming 4 KiB frames from usable RAM, never overlapping the kernel
image, boot structures, or device MMIO. `tb-hal` grows a `memory_map()` facade
reconciling three sources: x86_64 PVH `hvm_start_info.memmap`, x86_64 tb-vmm
`TbBootInfo` regions (bump tb-boot v0→v1 if needed), aarch64 FDT `/memory` minus
`/reserved-memory`/kernel/DTB/MMIO holes. Allocator = an **intrusive free-frame
stack** (each free frame stores the next free PA in its own first word) → O(1),
zero bitmap RAM. Self-test: alloc K frames, assert pairwise-disjoint + aligned +
in usable RAM + reserved-disjoint; LIFO reuse; total == map minus reservations;
exhaustion → fail-closed `None`; reject double-free. *Risk:* the aarch64 no_std
FDT parser must exclude device MMIO or it hands out device pages (fallback:
hard-code the QEMU `virt` map and defer full FDT parsing).

### M7 — Frame-backed growable kernel heap · `M7: heap OK`
Re-back the M5 allocator with a higher-half kernel-heap VA window that grows on
demand by pulling M6 frames and mapping them through the M3 typed-table layer —
lifting the heap off the fixed bootstrap arena so `alloc` scales with real RAM.
Same free-list/coalescing algebra as M5; only the backing changes. New tb-hal
primitive `map_heap_frames(window, n)`. Self-test: grow past one heap page
(forces realloc + fresh multi-frame map); alloc-free-alloc proves reuse **and**
the live physical-frame count returns to baseline (no frame leak).

### M8 — Async interrupt + monotonic timer tick (no switch) · `M8: timer OK`
Bring up the interrupt controller + a periodic timer, take the kernel's **first
asynchronous interrupt** (M0–M4 ran fully masked), and return to the exact
interrupted instruction with every register intact — the async-entry machinery
preemption stands on, proven **without** touching the scheduler. x86_64: mask the
8259 PIC, enable the LAPIC + LAPIC timer (microvm has no PIT) onto an M1 IDT
vector, EOI. aarch64: init the GIC (v2/v3 from FDT) + the EL1 physical generic
timer (PPI 30) into the M1 VBAR IRQ slot, ack via IAR/EOIR. The IRQ stub saves +
restores the **full** frame; a tight canary loop runs across many ticks asserting
zero corruption while an `AtomicU64` tick counter advances. *Riskiest milestone
in the chain* (first interrupt-enable; LAPIC-vs-PIT, GICv2-vs-v3); the M8/M9
split is the deliberate mitigation.

### M9 — Preemptive scheduler (involuntary full-context switch) · `M9: preempt OK`
On a timer tick the kernel involuntarily switches kernel tasks, so a task that
never voluntarily yields still loses the CPU. The M8 tick handler calls a **safe**
`schedule()` (round-robin to start, QoS hook INTERACTIVE/PIPELINE/BULK for later);
`tb-hal` performs a switch **from interrupt context** saving the entire interrupted
frame — a superset of M2's callee-saved-only cooperative switch (which is re-run
**unchanged** in the same boot to prove no regression). Self-test: two
no-`yield_to` spin tasks both advance and ≥K involuntary switches occur within a
wall-clock bound. DoD scoped to **kernel** tasks; user-mode involuntary preemption
is first exercised at M12.

### M10 — Per-agent address spaces (memory isolation) · `M10: addrspace OK`
Each schedulable entity runs in its own top-level page table — one cannot read or
write another's memory — while the kernel half stays mapped across every switch.
An `AddressSpace` object = a fresh top-level table (one M6 frame, M3 typed layer)
that COPIES the entire live kernel root into itself, so every existing kernel
mapping (identity RAM, serial, the M7 heap window, the M8 device window, the M3
test mapping) is shared by reference and the kernel half is identical in every
entity. Private pages (`map_in_space` → the new `tb-hal` `map_in_root` primitive)
land in a top-level slot the kernel root leaves vacant (x86_64 `PML4[4]`, aarch64
`L1[6]`), so they are visible only through that root. **Both arches are
symmetric** (no TTBR1/TTBR0 split): switch = `mov CR3` (x86_64, flushes
non-global TLB) / `msr TTBR0_EL1` + `isb; tlbi vmalle1is; dsb ish; isb` (aarch64,
no ASID yet). The swap folds into the M9 `yield_to` (a parallel `TASK_AS[]` of
per-task roots; it flips only when the next task's root differs). The textbook
`TTBR1`(kernel)/`TTBR0`(entity) split + ASIDs + PCID are a **deferred
refinement** (M11/M12); M10 ships the lower-risk copy-the-root design and so does
NOT touch `mmu_init` — `mmu_selftest` + `M3: mmu OK` print unchanged, and M10
actively **re-asserts M3** by reading the M3 test VA under each entity root.
Self-test: two tasks in two address spaces map the same VA to different private
frames, each writes/reads its own magic and sees only its own, a switch flips the
root, kernel/serial survive, and a cross-space access faults (observed by the
trap hook + a guarded resume).

### M11 — Capability handle table + kernel object model + agent-native syscall ABI · `M11: caps OK`
The non-POSIX ABI core: each kernel object is reached only through an unforgeable,
generation-checked, rights-masked **handle** in a per-principal table, and ring3/
EL0 code reaches the kernel through **one** numbered, capability-checked
dispatcher returning closed typed results — **zero ambient authority** (no
fd/errno/ioctl/path). Generalises the M4 user trap into a numbered dispatcher
(neutral `SyscallArgs` + a registered safe hook, mirroring M1's `set_trap_hook`).
Heap-backed per-principal table: `Handle = (generation:u32)<<32 | slot`, lookup
checks generation → `Stale` on mismatch (O(1) use-after-revoke). `Rights` bitset =
READ/WRITE/TRANSFER/DUP/REVOKE + agent-semantic INVOKE_MODEL/SPAWN_AGENT/
WRITE_PROCEDURAL/RECALL/CONSOLIDATE/EMIT_EXTERNAL/DELEGATE_BUDGET. `SysStatus` is a
**closed Rust enum** (Ok/BadCap/BadMethod/Denied/Stale/WouldBlock/NoMem/ObjFull),
not negative-errno. Meta-ops can only **narrow** rights (monotonic attenuation),
transfer (move), revoke (bump generation). **Only a few-line register-lift shim is
new unsafe; the entire handle table, rights algebra, object registry, and dispatch
are safe Rust** — deliberately the largest pure-safe subsystem so the chokepoint is
Kani/Verus-targetable. *This is a proof, not just a marker* (M18's frozen boundary
reduces to this rights-mask invariant). Decide the revocation model **here**:
v2 ships per-slot generation revoke; transitive/recursive revoke (seL4 CDT) is a
noted refinement.

*As shipped:* the revocation model is **per-slot generation revoke with
retire-on-overflow** — a slot whose `u32` generation would wrap is retired,
never reissued, closing the resurrected-stale-handle vector. The per-object
epoch ("kill the object in every table at once") and the seL4 CDT subtree revoke
are noted refinements the `u64` `Handle` layout stays forward-compatible with
(they land at M14 with no ABI break). The only new unsafe is the per-arch
register-lift shim: x86_64 routes the numbered cap syscall through a FRESH DPL=3
`int 0x81` gate into a SEPARATE `PT[2]` cap code page, and aarch64 maps a FRESH
EL0 window at the vacant `L1[5]` gated on a `CAPS_PROBE` flag — both leave the M4
`int 0x80` / EL0 `svc` path (and the aarch64 M7 heap window at `L1[4]`)
byte-for-byte intact, so `M4: user/ring OK` and the heap-backed cap table cannot
regress. The entire handle table, rights algebra, object registry and dispatch
live in `crates/tb-hal/src/caps.rs` under `#![forbid(unsafe_code)]`. M11 proves
the INBOUND boundary (a numbered, capability-checked syscall reaches `dispatch`
and yields a closed `SysStatus` kernel-side); returning that status into the
ring3/EL0 result register is the explicit M12 generalisation.

### M12 — Agent runtime: `AgentProcess` · `M12: agent OK`
Agents become first-class OS entities: `tb_agent_spawn(manifest)` mints an
`AgentProcess` in its **own** address space with **only** its manifest-declared
handles, scheduled preemptively in ring3/EL0, born with a private memory namespace
+ a memory-home handle + one bootstrap channel. Composes `AddressSpace`(M10) +
handle table(M11) + sched context(M9) + budget + identity. Generalises the M9
preemption path to its **user-frame** variant (CPL/EL change on the saved frame).
Self-test: root spawns **two** agents from static manifests; the timer round-robins
them (proving user-mode involuntary preemption); each makes a permitted
capability-checked syscall; a syscall for a non-manifest capability →
`TB_ENOTCAPABLE`; a child write to a parent-only VA faults; each finds its
memory-home handle present with **zero setup calls** (born-with-memory guarantee).

### M13 — Default tiered memory substrate · `M13: memory OK`
Every agent's reserved memory home becomes a real persistent, tiered, recallable
substrate: bounded **T0** context registers + **T1** working graph + an
append-only bi-temporal **T2** episodic journal with instant read-your-writes +
a lexical **T3** semantic store with activation-ranked recall — a kernel guarantee
via `tb_mem_write/read/manage` (+ `tb_recall`), with the embedding / "what matters"
policy left to userspace. Three-stage retrieval (candidate search → RRF/MMR rerank
→ templated context); additive default score = `w_a·BLA + w_r·relevance +
w_i·importance`; Finsts/`exclude_recent` bound the return-same-result loop;
copy-on-retrieve. Dispatched through the M11 chokepoint, gated by RECALL/CONSOLIDATE/
WRITE rights, namespaced `memory:private/<agent>`. **Zero new unsafe** — safe-Rust
heap data structures + indices; BM25/BLA math is host-cargo-test / Kani-verifiable.
RAM-backed behind a `BackingStore` trait (durable virtio-blk backing is future).

### M14 — Inter-agent IPC: capability-passing channels + ordered streams · `M14: ipc OK`
Two isolated, preemptively-scheduled agents exchange a message — **bytes plus a
transferred attenuated capability** — over one kernel IPC dialect (correlated
request/response + notification + cancellation + ordered-replay stream fan-out to
N observers + durable Task). `recv` on an empty channel **blocks** the agent (off
the M9 run queue); `send` makes it runnable (the IPC↔scheduler wake path). A
message can carry a `Handle`, which **moves** out of the sender's table into the
receiver's via the TRANSFER right with dup-attenuation — the auditable
authority-flow edge. **Only `copy_to_user`/`copy_from_user` are new unsafe**
(bounds- and mapping-checked cross-address-space copies). **M14.1 — byte payload
landed** (`M14.1: payload OK`): a message can carry a variable-length BYTE payload
via a kernel-heap **bounce buffer** (`ipc::MAX_PAYLOAD = 4096`, one page) — a
sender-side `copy_from_user` fills it, a receiver-side `copy_to_user` drains it
into the receiver's OWN address space. The two raw copy primitives (a software
page-table walk against an explicit root + a byte copy through the kernel
supervisor identity alias, SMAP/PAN-immune by construction) are confined to the
NEW per-arch `arch/{x86_64,aarch64}/uaccess.rs` unsafe modules; `ipc.rs`/`caps.rs`
and the kernel stay zero-unsafe, orchestrating through the safe tb-hal facade.
Fail-closed: oversize → `Denied`, copy-fault / too-small-buffer → `Fault` with no
message loss (peek-before-pop, push-front-restore). The **zero-copy** alternative
for bulk data is the M15 shared-memory block path. The recv-blocks-on-empty /
send-wakes-peer scheduler↔IPC integration remains the additive layer (reserved
`M14.2`). Self-test (the multi-agent north star): A sends B bytes + a derived-narrowed
capability; B, which had blocked on `recv` and is preemptively scheduled in its
own address space, wakes, receives the exact bytes + capability and uses it
(A no longer can), and replies; a third observer on a task stream sees identical
ordered events.

### M15 — Shared memory blocks + session blackboard · `M15: blocks OK`
Named, quota'd memory **blocks** map into N agents at once with record-level
CAS/versioned writes + watch-wakeups — a session blackboard with
update-once-visible-everywhere semantics (the last-write-wins library bug fixed in
the kernel); a single-agent session is just `|members| = 1`. A `Block` = a pinned,
quota'd shared segment whose frames are mapped into each member's address space
(reusing M10's map machinery); on conflict keep **both** versions bi-temporally
with a `supersedes` link. **Zero new unsafe** (reuses M10 map primitives).

### M16 — LLM-agnostic inference bridge (the `model:` scheme) · `M16: infer OK`
An agent submits a typed inference DAG with a `{cost,speed,intelligence}`
preference vector to a `model:` handle; the kernel **router** binds whichever
provider registered the scheme — `model:anthropic/opus` and `model:local/llama`
interchangeable behind one contract, the caller never naming a provider; the
INVOKE_MODEL right gates the call. Transport = a `tb-hal` **virtio** device —
**virtio-mmio on BOTH arches** (x86_64 QEMU `microvm` at `0xfeb00000`: `microvm`
has **no PCI bus by default**, its virtio transport is MMIO, *not* virtio-pci;
aarch64 `virt` at `0x0a000000`), a vsock-style channel; completion tokens stream
back over an ordered M14 stream. *(The in-kernel transport later landed at **M19**
as a **poll-based** virtio-mmio virtio-rng round-trip — the kernel's first real
device I/O; the completion-IRQ path is deferred, so M19 polls the used ring rather
than wiring the IRQ through M8.)* For a buildable CI DoD without GPU/network a deterministic
**mock provider** registers the scheme and returns canned embeddings/echo; the real
GPU/CUDA path stays a passthrough Linux driver VM reached **only** via this vsock
API (L2-sovereignty track, out of this DoD). Also fills `MemRecord.embedding`,
lighting up the T3 dense channel M13 left inert. New unsafe = only the virtio ring
(the virtio-mmio slot probe, volatile descriptor ring, doorbell, and — once the
IRQ path lands — the completion IRQ; M19's first cut polls the used ring instead);
the scheme registry/router/DAG executor/mock are safe. tb-vmm gains a host-side
device backend (still deferred — M19 boots green via a graceful Absent-skip when
no virtio-rng device is present).

### M17 — Sleep-time consolidation / reflection / forgetting daemons · `M17: consolidate OK`
Always-on background memory maintenance off the agent critical path on the M9
**BULK** lane: a consolidation daemon (kswapd analogy) that summarises/dedups/
merges/demotes, the importance-accumulator reflection trigger, and safe forgetting
(score-decay demotion T3→archival, tombstone-not-delete). Self-test: drive
importance past threshold → a BULK consolidation job runs **without blocking** the
foreground agent; two near-duplicates merge with a `supersedes`/`cites` link; a
low-score record is demoted (still addressable, not gone); p95 foreground retrieval
stays under budget during consolidation. **Zero new unsafe.**

### M18 — Frozen-kernel self-improvement harness · `M18: evolve OK`
An agent improves only its **own** config subtree through a kernel-owned
fork→modify→validate→merge pipeline whose **held-out** evaluators/detectors and
append-only lineage log live in a domain the agent **provably cannot read or write**
(measurer/measured separation) — self-improvement without Goodharting the metric.
Realised as **capability geometry** on the M11 rights layer: evaluator + evolution-
engine + lineage objects are created in a kernel domain and **never** inserted into
any agent's handle table (no cap to them is in any derivation closure), enforced by
the M11 rights mask **plus** an agent-unreadable address region. `tb_evolve_request`
forks the agent into a default-deny quota'd sandbox (M12 spawn), lets it modify only
its own subtree, then **ENDURE** (held-out safety suite) → **EXCEL** (held-out
regression suite) → **EVOLVE** (merge, human-approval hook on high-impact/
EMIT_EXTERNAL) — the three-laws ABI precedence; every step appends to an immutable
lineage log; rollback = snapshot restore. The **T4 procedural/skill tier** admits
skills only after verification-before-commit. **Zero new unsafe** — the entire
safety guarantee **reduces to the M11 rights-mask invariant** + M10/M12 isolation,
which is why M11's chokepoint must carry a Kani/Verus proof (M18 can pass its marker
and still be unsafe if a confused-deputy bug in M11 lets an agent reach an evaluator
— the DGM "node 114" lesson).

---

## 4. Sequencing — the eight decisions (resolved, not left open)

1. **Alloc-first, then frames.** The memory bedrock is split into three small
   rungs (M5 `.bss`-arena allocator → M6 real frame allocator → M7 frame-backed
   growable heap) to isolate three distinct failure modes into three markers:
   allocator-algebra (M5), boot-map-parsing (M6, the real unknown), and
   frame-into-heap mapping (M7). The M5 allocator body is reused unchanged at M7.
2. **Cap table is heap-backed** (M11, after M7), eliminating a static-array→heap
   swap that would otherwise threaten the handle ABI at the agent milestone.
3. **Foundation asm block (M8–M10) before the safe-Rust ABI spine (M11).** Caps
   depends only on M7+M4, so this is free; grouping all the scary asm contiguously
   surfaces the riskiest re-plan (preemption) early and keeps the cheap ABI spine
   right before the agent runtime that composes it.
4. **Timer split (M8 vs M9).** Separate "take an async interrupt and resume
   cleanly" from "switch context inside one" so controller-bring-up bugs
   (LAPIC-vs-PIT, GICv2-vs-v3) are isolated from context-switch-asm bugs.
5. **Address spaces (M10) kept separate** from the agent milestone because it
   touches the already-green M3 paging — a regression risk that earns its own
   marker and an M3 re-assertion. (As shipped, M10 is **symmetric** across both
   arches via the copy-the-live-root design — no TTBR1/TTBR0 split — leaving
   `mmu_init` untouched; the textbook split + ASIDs are a deferred M11/M12 refinement.)
6. **Memory substrate after agents (M13)** so it is genuinely the per-agent
   **default** (spawn creates `memory:private/<agent>` + a memory-home handle at
   birth; M13 implements the tiers behind that handle).
7. **Memory split into three** (M13 substrate, M15 shared blocks, M17 daemons) —
   three genuinely different capabilities, three small markers.
8. **Inference uses a mock provider** for the CI DoD; the real GPU/CUDA driver-VM
   over vsock is the L2-sovereignty track, out of this DoD. Self-improvement (M18)
   is last; its frozen boundary reduces to the M11 rights mask + M10/M12 isolation
   + the M17 GC machinery.

---

## 5. Risks (carried forward as build-time guards)

- **M8/M9 preemption is the riskiest:** first interrupt-enable (M0–M4 ran masked);
  a wrong frame/save path silently triple-faults and regresses the *entire*
  cumulative boot. The M8/M9 split is the baked-in mitigation; the likeliest
  re-plan beyond it is unifying M2's cooperative switch with the from-interrupt
  save path.
- **M10 on aarch64** touches the already-green M3 → the DoD re-asserts M3. As
  shipped it AVOIDS the TTBR1/TTBR0 split: both arches copy the live kernel root
  into each entity table (kernel half shared by reference) and swap a single root
  register (CR3 / TTBR0_EL1 + `tlbi vmalle1is`); `mmu_init` is untouched. The
  textbook TTBR1(kernel)/TTBR0(entity) split + ASIDs are a deferred M11/M12 refinement.
- **M6 boot-map divergence:** x86_64 must yield the *same* allocator from both PVH
  and TbBootInfo (may force a tb-boot v0→v1 bump); aarch64 hangs on a from-scratch
  FDT parser that must exclude device/reserved memory (fallback: hard-code the
  QEMU `virt` map).
- **M11 is a proof, not just a marker:** M18's frozen guarantee reduces to it;
  it must carry a Kani/Verus proof, and the revocation model is decided at M11.
- **The no-heap→heap transition (M5–M7) is one-way:** allocator math, BM25/BLA
  ranking (M13), eviction (M17), and the capability algebra (M11) must be covered
  by host `cargo test` / Kani — the on-target marker only proves *liveness*, not
  correctness.
- **Single-vCPU threads through all of v2:** "independently scheduled" means
  preemptive time-multiplex on one core (interrupt-masked critical sections, not
  real locks). SMP is the biggest latent debt and must not be conflated with the
  v2 north star.
- **Persistence scope:** the memory pillar says "persistent" but the chain has no
  block device; M13 is RAM-backed behind a `BackingStore` trait. Durable backing
  is a future virtio-blk milestone — decide durability scope before M13.

---

## 6. Status

| Phase | State |
|---|---|
| M0–M4 (v1 kernel foundation) | ✅ complete, CI-green both arches |
| L0→L1 sovereignty (tb-vmm + tb-boot v0) | ✅ complete, CI-green on `/dev/kvm` |
| **M5** (bootstrap heap / `alloc`) | ✅ **complete**, CI-green (x86_64 + aarch64 QEMU + tb-vmm/`/dev/kvm`) |
| **M6** (frame allocator from boot map) | ✅ **complete**, CI-green (PVH + tb-vmm/TbBootInfo + aarch64 QEMU-`virt` map) |
| **M7** (frame-backed growable heap) | ✅ **complete**, CI-green (kernel-heap window in PML4[2]/L1[4], M6 frames mapped via M3 tables; M5 algebra unchanged) |
| **M8** (async interrupt + timer tick) | ✅ **complete**, CI-green (x86_64 LAPIC + LAPIC timer on IDT vec 0x20 via a UC device window in PML4[3]; aarch64 GICv2 + EL1 physical timer PPI 30 through the `__vec_irq` slot; first `sti`/`daifclr`, register-integrity canary across many ticks, timer re-masked; in-guest `rdtsc`/`CNTPCT_EL0` cycle counter) |
| **M9** (preemptive scheduler) | ✅ **complete**, CI-green (timer-tick round-robin `schedule()` from IRQ context via the M8 `set_irq_hook` seam; M2 `ctx_switch` reused UNCHANGED — the IRQ entry already saved the full frame, so the cooperative switch swaps only the callee-saved continuation that returns into the IRQ epilogue's `iretq`/`eret`; EOI/EOIR moved BEFORE dispatch on both arches so the switched-in task is not starved of ticks; boot+C+D round-robin run queue in `lib.rs`, two no-yield spin tasks both advance under ≥100 involuntary switches; M2 cooperative ping-pong re-runs UNCHANGED → no regression) |
| **M10** (per-agent address spaces) | ✅ **complete**, CI-green (x86_64 + aarch64 QEMU + tb-vmm/`/dev/kvm`) — symmetric copy-the-live-root `AddressSpace` (no TTBR1/TTBR0 split): each entity gets a fresh top-level table copying the whole kernel root (kernel half shared by reference), private pages in a vacant slot (`PML4[4]` / `L1[6]`) via the new `map_in_root` primitive, the switch folds into `yield_to` (`TASK_AS[]`), two tasks in two spaces map the same VA to different private frames and see only their own, a cross-space access faults (trap hook + guarded resume), serial/kernel survive every switch, and `M3: mmu OK` re-asserts unchanged |
| **M11** (capability handle table + object model + syscall ABI) | ✅ **complete**, CI-green (x86_64 microvm + aarch64 virt + tb-vmm/`/dev/kvm`) — per-principal `HandleTable` with `Handle = (generation:u32)<<32 \| slot`, generation-checked O(1) resolve→`Stale`, the 12-bit `Rights` bitset whose only narrowing primitive is intersect (monotonic attenuation), the closed `SysStatus` enum, an `Rc`-counted object registry, and ONE numbered capability-checked `dispatch`er — all SAFE Rust in `caps.rs` (`#![forbid(unsafe_code)]`); the only new unsafe is a per-arch register-lift shim (x86_64 fresh DPL=3 `int 0x81` + a new `PT[2]` cap code page; aarch64 fresh EL0 window at the vacant `L1[5]` gated on `CAPS_PROBE`) — the M4 `int 0x80`/EL0 path and the aarch64 heap window (`L1[4]`) left byte-for-byte intact; per-slot generation revoke (retire-on-overflow), seL4 CDT noted for v3 |
| **M12** (agent runtime — `AgentProcess`) | ✅ **complete**, CI-green (x86_64 microvm + aarch64 virt) — `agent_spawn(manifest)` COMPOSES M10 `AddressSpace` + M11 `HandleTable` + M9 `Task` + the manifest into one owned `AgentProcess` (in the `TaskStack`-style `AGENTS` registry), born holding its memory-home/bootstrap/budget handles (minted by spawn, delivered in the user-entry register file — ZERO setup syscalls) and scheduled PREEMPTIVELY in ring3/EL0; user-mode preemption reuses the M9 IRQ path UNCHANGED via a per-task kernel stack programmed into `TSS.rsp0` from `yield_to`'s `switch_kernel_stack` fold-in (x86_64; `SP_EL1` auto-tracked on aarch64), a fabricated user-launch frame (`task_stack_init_user` → `agent_launch`, IF=1/`SPSR` I-clear so the agent is preemptible), and the aarch64 EL0-IRQ vector slot `0x480` re-pointed to `__vec_irq`; the agent cap syscall DISPATCHES against the running agent's table (`int 0x82` / shared EL0 `svc`) through the SAFE `agent_syscall_current` bridge and `iretq`/`eret`s back with the status; self-test proves born-with memory (kernel + user witnesses), the timer round-robins both ring3/EL0 agents (involuntary user-mode switches=0x3c), a permitted syscall→Ok + a non-manifest one→Denied, and a child read of a parent-only VA faults+recovers (M10 mechanism); kernel stays unsafe-free, all new unsafe/asm confined to `tb-hal/arch`, `caps.rs` still `#![forbid(unsafe_code)]`, M2–M11 markers all re-print |
| **M13** (default tiered memory substrate) | ✅ **complete**, CI-green (x86_64 microvm + aarch64 virt) — fills the body behind every agent's born-with `ObjKind::MemoryHome` handle with a real per-agent tiered substrate in a NEW safe module `tb-hal/src/mem.rs` (`#![forbid(unsafe_code)]`): T0 bounded context registers + T1 reachability-GC'd working graph + T2 append-only bi-temporal episodic journal (instant read-your-writes) + lexical (BM25+) T3 semantic store with a record-level inverted index, owned by `MemSubstrate{ t0,t1,t2,t3,finsts,clock,quota,backing: Box<dyn BackingStore> }` (RAM-backed `RamStore` now; durable virtio-blk deferred behind the `BackingStore` trait). Recall is the 3-stage pipeline (lexical candidate-gen → min-max-normalized additive score `w_a*BLA(d=0.5)+w_r*relevance+w_i*importance` → copy-on-retrieve) with Finsts/`exclude_recent` breaking the return-same-result loop — ALL math FIXED-POINT INTEGER (deterministic/replayable, no kernel FPU hazard, zero deps). ABI is purely additive method BODIES through the single M11 `dispatch` chokepoint: `M_MEM_WRITE=23` (WRITE) + `M_MEM_READ=24` (READ) added in the sparse band, reusing `M_MEM_RECALL=19` (RECALL) + `M_MEM_CONSOLIDATE=20` (CONSOLIDATE); `M_MEM_WRITE_PROC=18`/`WRITE_PROCEDURAL` kept reserved for the T4 procedural write (CoALA asymmetry, M18). `caps::Object` gains an interior-mutable `RefCell<MemSubstrate>` payload; `mint_memory_home` attaches a fresh substrate at spawn. **ZERO new unsafe** (`mem.rs` + `caps.rs` both `#![forbid(unsafe_code)]`); self-test proves write→instant RYW→activation-ranked recall→Finsts-advance→gated consolidate→rights-denied paths, both kernel-side (`caps::dispatch`) and through the actual born-with home of spawned agents (per-agent isolation); M2–M12 markers all re-print |
| **M14** (inter-agent IPC — capability-passing channels + ordered streams) | ✅ **complete**, CI-green (x86_64 microvm + aarch64 virt) — fills the `ObjKind::Channel` endpoint with a real body in a NEW safe module `tb-hal/src/ipc.rs` (`#![forbid(unsafe_code)]`): a kernel-owned `Channel` core both endpoints share via `Rc`, two per-direction ORDERED+BOUNDED `Ring`s (`VecDeque` `push_back`/`pop_front`, full→`WouldBlock`), `open[2]` peer-closed flags, and a `Message{ payload:u64, cap:Option<(Rc<Object>,Rights)> }`. A message MOVES a capability: the M11 `transfer_to` move DECOMPOSED ACROSS TIME into `HandleTable::detach` (SEND half = live+clone+`free_slot`, cap goes STALE in the sender) + `attach` (RECV half = `alloc` a fresh slot in the receiver), object identity + rights riding intact, attenuated cross-agent first via `M_HANDLE_NARROW`. ABI is purely additive method BODIES through the single M11 `dispatch` chokepoint: `M_CHAN_SEND=25` (WRITE, carried cap must hold TRANSFER, self-channel rejected), `M_CHAN_RECV=26` (READ), `M_CHAN_CLOSE=27` (none); `SysStatus::PeerClosed=8` added last. `caps::Object` gains an `Option<(Rc<ipc::Channel>,u8)>` endpoint payload + `mint_channel_endpoint`; kernel-side facades (`agent_channel_connect`/`agent_chan_send`/`agent_chan_recv_full`) drive the self-test. **ZERO new unsafe** (`ipc.rs` + `caps.rs` both `#![forbid(unsafe_code)]`); self-test proves FIFO order + capability-moved-and-attenuated-cross-agent (now STALE in the sender, USED by the receiver) + full-channel `WouldBlock` (atomic check-before-detach, no stranded cap) + denied/non-channel/bad-method paths + peer-closed→`PeerClosed`, reusing the two M13 agents as peers; M2–M13 markers all re-print. The variable-length BYTE payload via `copy_to_user`/`copy_from_user` (the ONLY M14 unsafe) and the recv-blocks-off-the-M9-runqueue / send-wakes-peer scheduler round-trip later LANDED as **M14.1** and **M14.2** (rows below) |
| **M14.1** (variable-length byte-payload IPC) | ✅ **complete**, CI-green (x86_64 microvm + aarch64 virt) — a message carries a variable-length BYTE payload via a kernel-heap **bounce buffer** (`ipc::MAX_PAYLOAD=4096`): a sender-side `copy_from_user` fills it, a receiver-side `copy_to_user` drains it into the receiver's OWN address space. The two raw copy primitives (software page-table walk vs explicit-root byte copy through the kernel supervisor identity alias, SMAP/PAN-immune) are the ONLY M14 unsafe, confined to NEW per-arch `arch/{x86_64,aarch64}/uaccess.rs`; `ipc.rs`/`caps.rs`/kernel stay zero-unsafe. Fail-closed: oversize→`Denied`, copy-fault/too-small→`Fault`, no message loss |
| **M14.2** (blocking-recv / runnable-on-send) | ✅ **complete**, CI-green (x86_64 microvm + aarch64 virt) — a receiver on an empty channel parks OFF the M9 run queue (`TASK_STATE` BLOCKED, `schedule()` skips it); a sender's push wakes it (runnable-on-send) from both `M_CHAN_SEND` and `chan_send_bytes`. Lost-wakeup-free via a single masked critical section (waiter registered before yield); proven with the timer ARMED (the real preemptive path), boot completes with no hang; `WouldBlock`/`PeerClosed` preserved |
| **M15** (shared memory blocks + session blackboard) | ✅ **complete**, CI-green (x86_64 microvm + aarch64 virt) — a shared-memory BLOCK is one or more pinned M6 frames owned by a new `ObjKind::Block` capability, mapped into MULTIPLE agents' M10 address spaces at once via the already-green `map_in_space` so every member sees the SAME physical bytes (vs M14, which COPIES). The Block core is a NEW safe module `tb-hal/src/blocks.rs` (`#![forbid(unsafe_code)]`): `Block{ frames: Vec<u64>, n_pages, members, seq: Cell<u64>, records: RefCell<Vec<Rec>> }` held behind `Rc<Block>` (the M14 `Rc<Channel>` rendezvous), `create(n_pages)` frame-allocs + ZEROES each frame (no tenant-byte leak, via the safe `addr_store_load` identity facade) and fails closed freeing partials on OOM, plus a RECORD-plane CAS/versioned bi-temporal store (`cas_write`/`read_latest`) for the blackboard. Permission is rights-derived at the M11 chokepoint: `writable = want && handle_rights.contains(WRITE)` (WRITE handle → RW page, READ-only handle → RO page). ABI is additive method numbers `M_BLOCK_MAP=28`/`M_BLOCK_UNMAP=29`/`M_BLOCK_WRITE=30`/`M_BLOCK_READ=31`; `M_BLOCK_WRITE`/`READ` ride the `dispatch` chokepoint, while the address-space-dependent `M_BLOCK_MAP` rides the kernel facade `agent_block_map` (re-enforcing the single-sourced READ gate + `min(request,rights)`). `caps::Object` gains an `Option<Rc<blocks::Block>>` payload + `mint_block`/`block_of`; the session blackboard is the well-known shared block all members attach. **ZERO new unsafe** (`blocks.rs` + `caps.rs` both `#![forbid(unsafe_code)]`; the map path reuses M10's existing `arch::map_in_root`); frames were initially PINNED for the kernel-session lifetime; the owner-only `M_BLOCK_UNMAP` + frame reclamation later LANDED as **M15.1** (row below), tearing down every member mapping with three UAF locks before any frame is reclaimed. Self-test proves true cross-agent sharing (A writes, B reads the SAME bytes under its own root), RO rejection (RO handle write → Denied + write-requesting map downgraded to RO), the RECORD-plane blackboard (C publishes a versioned record, D reads it — update-once-visible-everywhere), and non-block/READ-less/bad-method denial paths; M2–M14 markers all re-print |
| **M15.1** (block unmap + frame reclamation) | ✅ **complete**, CI-green (x86_64 microvm + aarch64 virt) — owner-only `M_BLOCK_UNMAP` (requires `Rights::REVOKE`) tears down EVERY recorded member mapping in EVERY root (clear leaf PTE + LOCAL TLB invalidate — x86 `invlpg` / aarch64 Break-Before-Make `tlbi`), poisons the shared `Rc<Block>` core (every outstanding handle → `Stale`, the channel peer-closed idiom), generation-bumps the caller's slot, then `frame_free`s the data frames — three UAF locks before any frame is reclaimed (frames are no longer pinned for the session lifetime). New unsafe (`unmap_in_root`/`va_to_pa_in_root`) confined to `arch/*/mmu.rs`; kernel zero-unsafe, `blocks.rs`/`caps.rs` forbid-unsafe. Self-test proves fail-closed (member-without-REVOKE→Denied, non-block→BadCap), reclamation (pmm free-count +1 and the allocator hands the block PA back out), and no-stale-access; M16..M18.1 + L2.0 stay green after |
| **M16** (LLM-agnostic inference bridge) | ✅ **complete**, CI-green (x86_64 microvm + aarch64 virt) — an agent invokes a model through a capability (`Rights::INVOKE_MODEL`, `M_MODEL_INVOKE=17`) naming the target via a `model:` scheme; a safe in-kernel ROUTER binds a REGISTERED backend behind ONE uniform contract (request→response), backend identity hidden from the agent. NEW safe module `tb-hal/src/infer.rs` (`#![forbid(unsafe_code)]`): the contract types (`InferRequest`/`InferResponse`/`StopReason`/`InferError`/`ModelId`), a panic-free `model:` scheme parser + longest-prefix `resolve` over an IMMUTABLE const `ROUTES` table, the object-safe `trait InferBackend: Sync`, an in-kernel deterministic stateless `MockBackend` registered under TWO `model:` names (`model:mock/echo`, `model:local/llama3`) binding ONE contract = the backend-agnostic proof, and a single-owner `ModelSession{ backend, model }` carried inline on the `ObjKind::ModelSession` Object. ABI is purely additive: NO new method number (`M_MODEL_INVOKE=17` + `required_right(17)==INVOKE_MODEL` + `ObjKind::ModelSession` already reserved at M11), the dispatch arm clones the `Rc<Object>` out and routes to the bound backend (non-session cap → `BadCap`), session-open is the kernel facade `agent_model_open` (resolve → `mint_model_session` WITH `INVOKE_MODEL\|READ`), freed by the existing meta-ops. **ZERO new unsafe** (`infer.rs` + `caps.rs` both `#![forbid(unsafe_code)]`; stateless mock + const route table need no `UnsafeCell`). Self-test proves parse (`model:…`→Some, `memory:x`→None), open+invoke deterministic, backend-agnostic (2nd scheme, identical agent code, identical response), narrow-to-drop-`INVOKE_MODEL`→Denied (the gate still bites), unknown scheme→clean `BadCap` (no panic), non-session→`BadCap`, unknown method→`BadMethod`; M2–M15 markers all re-print. Real Anthropic/OpenAI adapters + vsock-local GPU driver-VM deferred behind the SAME `InferBackend` trait |
| **M17** (sleep-time consolidation / reflection / forgetting daemons) | ✅ **complete**, CI-green (x86_64 microvm + aarch64 virt) — three sleep-time memory daemons (CONSOLIDATE / REFLECT / FORGET) realized as ONE bounded maintenance cycle over the M13 substrate, driven through the already-wired `M_MEM_CONSOLIDATE=20` method (`Rights::CONSOLIDATE=1<<9`), off the critical path. NO new ABI method numbers (the M11 closed set stays frozen; the M16 `method 33 == BadMethod` proof is untouched) — M17 only WIDENS the op-selector space INSIDE `consolidate(op,a,b,c)`: op=1 fills the supersedes/cites/relates LINK stub, op=3 runs one full cycle, op=4 reflect, op=5 forget-sweep, op=6 reflect-digest (read-only model-bridge seam), op=7 read imp_accum, op=8 link_count. Extends `tb-hal/src/mem.rs` (keeps line-1 `#![forbid(unsafe_code)]`) in pure SAFE Rust: new fields `MemRecord{ links:Vec<(u8,u64)>, tier:u8, provenance:u8 }` + `MemSubstrate{ imp_accum, last_consolidated_epoch, consol_cursor }`, a shared `push_record` helper, and the fixed-point methods `distill`/`reflect_inner`/`reflect_digest`/`forget_sweep`/`consolidation_cycle`. **CONSOLIDATE** (distill) is two-phase (immutable scan plans near-duplicate T3 clusters by shared token, picks a survivor by importance with a fixed tie-break; mutable apply tombstones ONLY the DERIVED T3 losers + appends supersedes/cites links to the survivor) — the T2 journal is NEVER touched. **REFLECT** folds the recent high-salience T3 slice into a NEW insight record (deterministic fixed-point digest, cites-back links, bounded depth, replay-strengthens its sources); the M16 `model:mock/echo` bridge is wired NOW at the daemon-task layer (op=6 digest → `M_MODEL_INVOKE` → op=4 token), keeping `mem.rs` free of any `infer.rs` dependency. **FORGET** is a fixed-point ACT-R BLA(d=0.5) decay sweep over a bounded wrapping `consol_cursor` that DEMOTES (tier 3→5: dropped from recall STAGE 1 but still `M_MEM_READ`-addressable) only records SIMULTANEOUSLY stale AND low-importance AND low-utility AND past a grace window — the append-only T2 floor is never popped/truncated/age-tombstoned. `lib.rs` adds the `agent_consolidate_cycle`/`agent_mem_accumulator` facades; `caps.rs` + `infer.rs` UNCHANGED. **ZERO new unsafe** (machine-enforced by `mem.rs`'s `#![forbid(unsafe_code)]`); self-test drives the cycle SYNCHRONOUSLY over a WITNESS-A home (timer disarmed) and proves distill→survivor-with-links, a cites-back reflection insight (deterministic AND model-bridged `digest ^ 0xA110_C0DE`), the stale record DEMOTED (gone from recall, still readable), the T2 floor intact, and CONSOLIDATE-gated denial both ways; M2–M16 markers all re-print. The armed-window concurrency witness + the M9-scheduled BULK daemon task are the documented deferred hooks |
| **M18** (frozen-kernel self-improvement harness + held-out evaluators + skill tier) | ✅ **complete**, CI-green (x86_64 microvm + aarch64 virt) — an agent extends its OWN T4 skill library under a FROZEN-KERNEL / EVOLVING-USERSPACE split where the held-out evaluator + test set live in a kernel domain the agent PROVABLY cannot read or write; the whole guarantee REDUCES TO the M11 rights-mask invariant — NO new mechanism, ZERO new unsafe, purely additive bodies + facades. Extends `tb-hal/src/mem.rs` (keeps line-1 `#![forbid(unsafe_code)]`) with the T4 PROCEDURAL/SKILL tier: `MemSubstrate{ t4: ProceduralStore }`, `SkillRecord{ id, body_tok, desc_tok, iface_tok, embedding, c_succ, c_use, util, lineage:Vec<u64>, tier:u8, provenance:u8 }`, the agent verb `write_proc(op,a,b,c)` with an OP-SELECTOR (op0 ADD_SKILL pushes a PROPOSED inert skill / op1 UPDATE_UTILITY / op2 READ_SKILL of the agent's OWN skill / op3 LINK_LINEAGE / op4 READ_TIER) reusing the `push_record` discipline + `TOKEN_QUOTA` fail-closed, the kernel-side harness-only methods `skill_get`/`skill_admit`(PROPOSED→ADMITTED + EvolveR util `U += (R−U)/5` + lineage)/`skill_count_admitted`/`skill_lineage_len`/`seed_heldout`, and the FROZEN held-out scorer `score_candidate(body)` over a fixed-point transform (the candidate never runs in the evaluator). NO new ABI method number (the M11 closed set stays frozen; the `method 33 == BadMethod` proof is untouched): skill writes FILL the EXISTING `M_MEM_WRITE_PROC=18` dispatch arm (which was wired into `required_right→WRITE_PROCEDURAL` but UNBODIED) with the EXACT clone-Rc-out / drop-slot-borrow-before-`borrow_mut` discipline of `M_MEM_WRITE`, op-selector inside (the M17 precedent). `caps.rs` gains a kernel-side harness surface (NOT method-numbered, so an agent literally cannot invoke it through `dispatch`): `eval_seed_heldout`/`harness_admit`/`skill_tier_of`/`skill_admitted_count`/`skill_lineage_len`; `lib.rs` adds the kernel-mediated facades `agent_skill_propose` (grants a SEPARATE `WRITE_PROCEDURAL` skill-home on first use — the `agent_model_open` INVOKE_MODEL-grant precedent — NEVER the born-with `READ\|WRITE\|RECALL` episodic home) and `agent_evolve_request` (builds a kernel-owned throwaway `eval_tbl`/`eval_home` NEVER minted into any agent table, scores, and admits only on STRICT improvement). **ZERO new unsafe** (`mem.rs` + `caps.rs` both `#![forbid(unsafe_code)]`; the facades are safe code over the existing blessed `AGENTS` registry). Self-test (kernel-side WITNESS A over `caps::dispatch` + WITNESS B through the spawned agent_c's M11 chokepoint) proves a GOOD skill proposed via `WRITE_PROCEDURAL` is ADMITTED by the frozen evaluator (PROPOSED→ADMITTED, lineage grew), a BAD/overfitting skill is REJECTED (stays PROPOSED/inert, admitted-count unchanged, rejection appended to lineage), the held-out set is UNREADABLE (a fabricated handle → BadCap/Stale; no facade exposes `eval_tbl`), the evaluator is UNWRITABLE (a home lacking `WRITE_PROCEDURAL` → Denied), the closed method set is intact (`0xDEAD` → BadMethod), and an ordinary born-with home proposing → Denied (the CoALA asymmetry); M2–M17 markers all re-print. The mandatory human-approval hook on high-impact/`EMIT_EXTERNAL` skills + the rotating never-exposed evaluator partition LANDED as **M18.1** / **M18.2** (rows below); the structural capability boundary (no handle to the evaluator/lineage) holds regardless. **THIS COMPLETES THE M5→M18 v2 chain** (extended since by M14.1/M14.2/M15.1/M18.1/M18.2 + M19 — see the rows above/below). |
| **M18.1** (mandatory human-approval gate) | ✅ **complete**, CI-green (x86_64 microvm + aarch64 virt) — new right `APPROVE_HIGH_IMPACT` (bit 12) in `tb-caps-core`; skills proposed via op `ADD_SKILL_EMIT_EXTERNAL` carry a `SKILL_PROV_EMIT_EXTERNAL` provenance bit; the merge step (`harness_merge`) is fail-closed for that class — absent / insufficient / forged approval capability → `Denied` (the skill stays PROPOSED), admitted only when a presented cap carries `APPROVE_HIGH_IMPACT`; ordinary skills merge unchanged. The guarantee REDUCES TO the Kani-proven M11 rights-mask invariant (SELF-IMPROVEMENT-SPEC §8) |
| **M18.2** (rotating held-out evaluator partition) | ✅ **complete**, CI-green (x86_64 microvm + aarch64 virt) — generalizes the single frozen evaluator to N=3 held-out SCORING partitions + 1 VISIBLE partition, all minted in the kernel-owned `eval_tbl` (never in any agent table → unnameable/unreadable/unwritable, reducing to the Kani-proven M11 rights-mask invariant). A kernel-side rotation counter the agent cannot observe or influence picks `idx = rotation % N`; the scoring set excludes the visible partition by construction. Anti-Goodhart: the visible metric and the hidden rotated scorer rank candidates oppositely, so a candidate tuned to the visible metric is REJECTED (stays PROPOSED) while the scorer-matched candidate is ADMITTED. No new Rights bit / no new unsafe; `tb-caps-core` untouched (12 Kani harnesses intact) |
| L2 (own Type-1 microhypervisor) | 🟡 **track STARTED** — **L2.0 (VMX-root / EL2 world-switch + 1-instruction nested guest + caught exit) IMPLEMENTED & boots green both arches**, emitting two lines after **M18.2** and BEFORE the new final marker `M19: virtio OK` ([SOVEREIGNTY-L2-ROADMAP §7/§8a](SOVEREIGNTY-L2-ROADMAP.md)). All new silicon-unsafe (x86 VMXON/VMCS/EPT/world-switch; aarch64 HCR_EL2/VTCR/stage-2) confined to `crates/tb-hal/src/arch/{x86_64/vmx/,aarch64/{el2,el2_vectors}.rs}`; the kernel + `caps/mem/ipc/blocks/infer` stay `#![forbid(unsafe_code)]`, driven by the SAFE `vmx_selftest()`/`el2_selftest()` facades. **x86_64 `L2.0: vmxroot OK` is an HONEST graceful-skip** on TCG/hosted CI (QEMU-TCG refuses the VMX CPUID bit → `Unavailable` → `(vmx unavailable, skipped)`); the REAL VMLAUNCH/world-switch/caught-exit (`Proven{exit_reason:10}`) fires ONLY on the dedicated `l2-nested-vmx` lane (`-cpu host,+vmx`, `kvm_intel nested=1`) — it is NOT a proof on the default lanes. **aarch64 `L2.0: el2 OK` is the opposite — a GENUINE executing nVHE EL2↔EL1 world-switch under pure TCG** on a stock runner (NOT a skip). L2.1 (aarch64 stage-2 demand-translation, `L2.1: stage2 OK`) has since LANDED on the aarch64 track (see the **L2 cross-reference** below); L2.2→L2.9 remain the tracked north-star ([SOVEREIGNTY-ROADMAP](SOVEREIGNTY-ROADMAP.md)). |
| **M19** (poll-based virtio-mmio device I/O — the FIRST real device I/O) | ✅ **complete**, CI-green (x86_64 microvm + aarch64 virt; printed AFTER the L2.0..L2.6 lines, BEFORE M20..M22) — a poll-based **virtio-mmio** virtio-rng round-trip in NEW `crates/tb-hal/src/arch/{x86_64,aarch64}/virtio.rs`: arch-neutral slot scan (MagicValue/DeviceID; x86 base `0xFEB00000` UC-mapped at `LAPIC_WINDOW_VA+0x1000`, aarch64 base `0x0A000000` already Device-mapped), modern (Version=2) handshake, one queue with desc/avail/used + buffer in ONE identity-mapped `frame_alloc` frame, submit→`QueueNotify`→**poll `used.idx`** under a fail-closed `POLL_CAP=100M` (never hangs), `NO_INTERRUPT` set. Safe `virtio_selftest()→VirtioProof{Absent\|LegacyUnsupported\|Proven\|Failed}` facade; kernel zero-unsafe; witness `virtio: rng round-trip slot=.. dev=.. len=..`. **Proven under TCG (`ci`) + KVM (`microvm-kvm`)** with `-device virtio-rng-device -global virtio-mmio.force-legacy=false`; **graceful Absent-skip under tb-vmm** (open-bus `0xFFFFFFFF`≠magic → `M19: virtio OK (no device, skipped)`, so `vmm-boot` stays green with no tb-vmm backend). DEFERRED: the completion-IRQ path (aarch64 GIC SPI 48 first, then an x86 IOAPIC driver), the M14-stream integration, and the tb-vmm host-side virtio backend |
| **M20** (durable persistence — virtio-blk + log-structured `BackingStore` + two-phase commit) | ✅ **complete**, CI-green (x86_64 microvm + aarch64 virt) — fills the M13 `Box<dyn BackingStore>` seam (RAM-backed at M13) with a REAL durable store over the M19 virtio-mmio transport: a poll-based **virtio-blk** block device (DeviceID 2) drives a **log-structured** `BackingStore` whose superblock + append-only record log survive a reboot via a **two-phase commit** (write records → fsync-class barrier → atomically bump the committed generation), replayed on next mount. All codecs are Kani-proven host-side in the NEW `tb-encode/blkfmt.rs` leaf (virtio-blk request header, 512-byte FNV-1a-64-checksummed superblock with fail-closed decode, 24-byte FNV-1a-32-CRC record frame with torn-tail rejection, 48-byte Episode body, fixed-partition sector/extent math); the silicon-unsafe virtio-blk MMIO/DMA is confined to `crates/tb-hal/src/arch/{x86_64,aarch64}/virtio.rs`, kernel + `mem.rs`/`caps.rs` stay `#![forbid(unsafe_code)]`. Witness `persist: gen=.. records=.. replayed=.. prior=..` (the run scripts POSITIVELY require it and REJECT the `(no disk, skipped)` skip variant). DEFERRED: the completion-IRQ path, multi-extent compaction/GC, and the durable T2 journal cutover |
| **M21** (verified fixed-point ADDITIVE-policy seam for M17 forget/demote — SHIPS DORMANT) | ✅ **complete**, CI-green (x86_64 microvm + aarch64 virt) — a Kani-proven fixed-point ADDITIVE policy cell for the M17 forget/demote sweep, landed behind a **fail-closed loader and shipped DORMANT (`active=0`)**: the verified leaf decides nothing yet — the M17 heuristic floor still owns the decision — pending a trace bake-off (the research-first proposal RESHAPED the naive "KAN" framing into a dormant gate-on-a-bake-off seam). The policy math lives in the NEW `tb-encode/kancell.rs` leaf (verified fixed-point ADDITIVE piecewise-linear integer GAM `kan_spline_eval`/`kan_score` + solver-free MonoKAN monotonicity + overflow-safe table validators, final-clamping into the M17 `DEMOTE_BAND`); 6 Kani harnesses + a negative control. **ZERO new unsafe** (`mem.rs`/`caps.rs` forbid-unsafe; the leaf is `#![forbid(unsafe_code)]` zero-dep no-float). Witness `kan: monotone=1 ovf-safe=1 q-err=.. bound=.. active=0` (the run scripts REQUIRE `active=0` + the monotone/ovf-safe proof bits and REJECT the `(no table, skipped)` variant; the `M21: kan-policy OK (heuristic floor, gate-not-met)` marker spelling is the legitimate dormant line). DEFERRED: activation pending the live trace bake-off |
| **M22** (verified memory PROVENANCE ledger — per-agent content-addressed hash-chain) | ✅ **complete**, CI-green (x86_64 microvm + aarch64 virt; **the cumulative-tail marker both run scripts grepped for until the chain grew past it — the tail is now `M31: infer-e2e OK backend=MOCK-DETERMINISTIC`**) — a per-agent content-addressed **hash-chain provenance ledger** over the M13 memory substrate: every write/derive/forget appends a canonical, length-prefixed `ProvEntry` folded into a 256-bit per-agent running digest (structural tamper-evidence at landing; **upgraded by M29 stage C to cryptographic khash/BLAKE2s-256**, `sec=ASSUMED-FROM-LITERATURE`), a **forget tombstones** the record in the chain, and an inclusion verifier proves a given entry is in an agent's history. All ledger math is Kani-proven host-side in the NEW `tb-encode/prov.rs` leaf (canonical injective `canon` encoder, 4-lane domain-separated `prov_hash`, per-agent `chain_mix` fold, `verify_inclusion`); 6 Kani harnesses + a negative control. **ZERO new unsafe** (`mem.rs`/`caps.rs` forbid-unsafe; the leaf is `#![forbid(unsafe_code)]` zero-dep no-float). Witness `prov: head=.. entries=.. tamper-caught=0x1 inclusion=0x1` (the run scripts POSITIVELY require it — `tamper-caught=1` + `inclusion=1` — and REJECT any `(no ledger, skipped)` variant, since a skip is never legitimate for the tail marker) |
| **Verification — Kani (M11 caps + encoders) + Miri Tier-0** | ✅ **landed**, three machine-checked gates: the M11 rights-subset / no-confused-deputy invariant is Kani-proven over `crates/tb-caps-core` (the single source of truth the kernel runs verbatim — zero model drift; **12 harnesses**, `M11: caps-subset PROVEN`, `kani.yml` `prove-caps` job); the silicon-unsafe encoders/parsers are Kani-proven over a NEW `crates/tb-encode` (a pure `#![no_std]` `#![forbid(unsafe_code)]` zero-external-dep no-float VERIFIED-LEAF crate — its one workspace-internal dep is the consts-only `brand` identity crate (PR-C) — now **20 leaves**: `vmx` (control-MSR adjust-legality gate, CR0/CR4 fixed-bit clamp, TSS-descriptor decode), `paging` (radix-512 PTE algebra + EPT encoders), `ipc_frame` (16-byte IPC frame round-trip + fail-closed decode + bounded no-alloc ring), `route` (M16 `model:` scheme grammar + longest-prefix routing), `memscore` (M13 fixed-point recall/BLA ranking math), `stage2` (aarch64 stage-2 descriptor + `VTCR_EL2`/`VTTBR_EL2` algebra), `smmuv3` (SMMUv3 stage-2 STE + the "SMMU stage-2 IS the CPU stage-2" lemma), `el2_trap` (`ESR_EL2`/`HPFAR_EL2`/`FAR_EL2` + sysreg/MMIO ISS + `GICH_LRn` encoders), plus the durable-memory + learning-loop leaves **`blkfmt`** (M20 virtio-blk/superblock/record codecs), **`kancell`** (M21 dormant additive-policy cell), **`prov`** (M22 provenance-ledger math), **`exp`** (M23 experience codec + ring + replay-determinism, reusing the M22 fold), **`explore`** + **`bakeoff`** (M24 honest-gate math: shielded ε-greedy propensity, the 3-way censored survival label, the partial-id lower bound, the one-shot HCPI gate), **`opframe`** (M25 operator-transcript codec: injective length-prefixed frame, the held-out-leakage guard, strict-monotone seq, intro-binding + tail-truncation detection, reusing the M22 fold), **`exittel`** (M26 EL2 exit-telemetry codec: the reused L2.2 `classify_exit` + a no-float log2-bucket histogram + a fixed-width injective record + the M22 fold reused, PRODUCER-only), **`tpsched`** (M27 two-VMID time-partition-scheduler math: the fixed two-slot major-frame slot function + frame conservation + VMID alternation + a fixed-width injective `SchedDecision` record + the M22 fold reused, `realtime=NOT-CLAIMED`), **`opframe_rx`** (M28 operator INBOUND command codec — the RX dual of `opframe`: injective canonical encoding + the pure conjunctive verdict core `verify_decoded` proven Accept-IFF-all (freshness echo · live-M22-head binding · dual custody · MAC) + kind-dominance + key evolution; the MAC since M29 is the khash-backed derive-then-MAC, `mac=KEYED-CRYPTO`), **`khash`** (M29 keyed-hash primitive — BLAKE2s-256, RFC 7693, native keyed mode: the verified REAL keyed hash behind the M28 MAC + key evolution, official-KAT-pinned, `sec=ASSUMED-FROM-LITERATURE` machine-tokened), and **`inferwire`** (M30 inference-transport codec — the injective length-prefixed `InferFrame` + fail-closed `canon`/`decode`, the `FrameAccum` byte-stream re-framer with proven never-overflow resync, the correlation iff-theorem, and the host-keyed `echo_tag`/`verify_echo` — ONE domain-separated khash call binding peer_id‖nonce‖challenge‖body inside the MAC; the kernel-scope leg-1 verifier of the M30 two-leg anti-hollow composition; EXTENDED at M31 -- deliberately not a 21st leaf -- with the closed inference kinds INFER_REQ/INFER_RESP/INFER_PENDING + closed-enum ERR semantics, the 24-byte chunk sub-header, the compile-time `INFER_BODY_CAP=8192`, the per-chunk `infer_tag`/`verify_infer_resp`/`verify_infer_req` MAC under the NEW `"YUVA-M31-INFER-V1"` domain, the chunk-at-a-time fail-closed `InferAssembler`, and the shared deterministic `mock_infer` transform), plus the aL2.4b carve/console leaves **`stage2::guest_carve_pa`** (the FIRST non-identity stage-2 map -- guest IPA->carve PA, injective + range-bounded) and **`guestlog`** (the injection-proof `guestlog:` hex-frame codec -- total + injective + the no-raw-leak safety property); **102 harnesses** (`scripts/verify-encode.sh` `EXPECTED_HARNESSES` — the 15 original + 5 L2.1 stage-2/`el2_trap` + 1 L2.2 exit-classifier + 2 L2.3 ISS + 1 L2.4 SCTLR + 1 L2.5 `GICH_LR` + 3 L2.6 SMMUv3 + 6 M20 `blkfmt` + 6 M21 `kancell` + 6 M22 `prov` + 6 M23 `exp` + 6 M24 `explore`/`bakeoff` + 6 M25 `opframe` + 5 M26 `exittel` + 5 M27 `tpsched` + 6 M28 `opframe_rx`: `kani_cmd_canon_injective`/`kani_cmd_stale_nonce`/`kani_cmd_head_binding`/`kani_cmd_dual_custody`/`kani_cmd_mac_tamper`/`kani_cmd_key_evolve` + 4 M29 `khash`: `kani_khash_total_deterministic`/`kani_khash_vectors`/`kani_khash_tamper`/`kani_khash_keyed_distinct` + 6 M30 `inferwire`: `kani_inferwire_canon_roundtrip`/`kani_inferwire_decode_total`/`kani_inferwire_req_binding`/`kani_inferwire_echo_sound`/`kani_inferwire_accum_resync`/`kani_inferwire_peer_label_bound` + 6 M31 `inferwire` adapter: `kani_inferwire_kind_ext`/`kani_infer_subhdr_total`/`kani_infer_assembler`/`kani_infer_resp_binding`/`kani_infer_domain_sep`/`kani_infer_err_closed` + 6 aL2.4b: `kani_guest_carve_range_bounded`/`kani_guest_carve_injective`/`kani_guestlog_bounded`/`kani_guestlog_roundtrip_total`/`kani_guestlog_injective`/`kani_guestlog_regex_inert` -- the khash-bearing pair in the PINNED-VECTOR one-khash-execution shape, the measured #49 budget), each TRACTABLE with a NEGATIVE CONTROL — `V1: kani-encoders OK`, `kani.yml` `prove-encode` job; the count is bumped in LOCKSTEP between `scripts/kani-shards.sh` (the one-touch list) and the `kani.yml` comment, which also pins 102); and a Miri Tier-0 UB gate runs `cargo miri test -p brand -p tb-caps-core -p tb-encode` over the EXACT host-runnable leaf code the kernel runs (`T0: miri OK`, `miri.yml`). `tb-hal` + `kernel` are excluded from Miri (asm + `os=none` triple) |
| **CI lanes (9 gates across 8 workflow files)** | ✅ green/allow-skip — `ci` (REQUIRED both-arch QEMU-TCG cumulative-marker boot, M0..M31, since M30 with the xport-harness host peer spawned per lane (since M31 its serve loop ALSO answers the MAC-chunked mock inference exchange) + the cross-process challenge/tag guard; the aarch64 leg boots INSIDE a `debian:trixie-slim` qemu-10 container via `matrix.boot_in_container` because SMMUv3 stage-2/L2.6 needs qemu≥9), `vmm-boot` (`tb-vmm`/KVM via the sovereign `tb-boot v0` contract, asserts M4 + the boot-time bench; allow-skip when KVM absent), `l2-nested-vmx` (INFORMATIONAL/continue-on-error — the REAL L2.0 VMX-root verdict under nested KVM `-cpu host`, checks `M18: evolve OK`), `microvm-kvm` (REQUIRED — QEMU-`microvm`+KVM `-cpu host` boot-assert to `M18: evolve OK` + the continue-on-error `--release` boot-ready-cycles bench feeding BENCHMARKS §3), `kani` (TWO jobs: `prove-caps` over `tb-caps-core` = 12 harnesses + `prove-encode` over `tb-encode` = 102 harnesses across two shard jobs; Kani runs in this lane and is also installed locally in WSL `cargo-kani` — measure a new/changed harness with `cargo kani -p tb-encode --harness <name>` BEFORE pushing, since the prove-encode lane has a hard timeout), `miri` (REQUIRED Tier-0 UB gate over the forbid-unsafe leaf crates), `clippy` (static-lint `-D warnings` over `tb-caps-core`/`tb-encode`/`tb-boot`), `bench` (NON-BLOCKING tb-vmm vs Firecracker Axis-A boot benchmark) |

### L2 cross-reference — the active sovereignty track is aarch64-first

The L2 microhypervisor lives in its own doc ([SOVEREIGNTY-L2-ROADMAP](SOVEREIGNTY-L2-ROADMAP.md) §5b · §7); this M5→M18 chain only **points** at it, the same way the status row above carries the L2.0 markers. Two pointers:

- **aarch64 leads, x86 is parked.** The aarch64-EL2 track runs REAL under pure QEMU TCG on a stock runner (no `/dev/kvm`, no nesting), so it is the PRIMARY CI-advancing L2 track; the x86 VMX chain (#41–46) is PARKED behind #37 (QEMU-TCG emulates no Intel VMX, and no stock runner exposes a second VMX level). The newest landed rung is **`L2.1: stage2 OK`** — stage-2 demand-translation, the ARM analog of x86 EPT-violation handling, built on L2.0's resident EL2 monitor: it arms stage-2 on `hvc #2`, catches the guest stage-2 abort, demand-maps the deliberate hole IPA `0x1_4000_0000` read from `HPFAR_EL2`, and the guest's `hvc #3` tears stage-2 down (`HCR_EL2.VM=0`) FIRST → `Stage2Proof::Proven { fault_ipa }`. New silicon-unsafe is confined to `crates/tb-hal/src/arch/aarch64/{stage2,el2}.rs`; the kernel stays `#![forbid(unsafe_code)]`. The `L2.1: stage2 OK` line prints after the L2.0 markers and before the final `M19: virtio OK`.
- **The isolation property is proven, not merely booted.** Following the pKVM/SeKVM precedent that a guest's stage-2 only ever maps frames it owns or was explicitly shared ([pKVM Security Model](https://source.android.com/docs/core/virtualization/security)), the new pure stage-2 descriptor algebra (`tb-encode/stage2.rs`) and `ESR_EL2`/`HPFAR_EL2` trap-syndrome decoders (`tb-encode/el2_trap.rs`) are Kani-proven host-side and reduce to the SAME M11 rights-subset / no-confused-deputy attenuation invariant this chain already machine-proves over `tb-caps-core` — stage-2 confidentiality is an instance of an existing proof, not a new mechanism. The `prove-encode` lane's pinned `EXPECTED_HARNESSES` grew to 46 (the 5 new L2.1 stage-2/`el2_trap` lemmas were the first increment, since extended across L2.2–L2.6 and the M20..M29 leaves), bumped in lockstep with `kani.yml`. See [MILESTONES](MILESTONES.md) for the cumulative marker chain.

### Next up — the tracked successors (not blockers)

With `M31: infer-e2e OK backend=MOCK-DETERMINISTIC` as the cumulative tail, each of the four pillars has a landed floor, the learning loop is CLOSED — record (M23) → honestly-refuse (M24) → surface-to-human (M25) → record-workload (M26) → schedule (M27) → receive-human-command (M28) — the loudest honesty concession on the board is discharged (the M28 MAC is a verified REAL keyed hash — M29, `mac=KEYED-CRYPTO`), and the sovereignty A-chain has its TRANSPORT (M30) AND its first MEANING: byte prompts assembled from real M13 substrate state ride a verified, MAC-chunked codec over that channel and come back as a digest-folded, injection-proofed response (M31 stages A+B, `backend=MOCK-DETERMINISTIC` — a deterministic transform, honestly NOT a model; the ANTHROPIC-LIVE half is the operator-gated stage C). The explicit next-up items:

- **M27b — real CNTHP timer-preemption (#84): ✅ LANDED.** The cooperative green floor was replaced by genuine EL2 physical-timer preemption — the FIRST asynchronous IRQ taken at EL2 (the 0x480 Lower-EL IRQ vector, IMO=1 only inside the armed window; pure store-spin guest stubs, so `both-progressed=1` is only reachable via real preemption; re-arm-before-EOI + IAR verify + ISTATUS read-back + a hard EOI cap; smoke-first landing — the dummy count-and-re-arm canary stays in every boot). `timing=TCG-NON-CYCLE-ACCURATE realtime=NOT-CLAIMED`; the retired cooperative token is guard-REJECTED.
- **M29 — `mac=KEYED-CRYPTO` (the M28 §5 named successor): ✅ LANDED.** The verified `tb-encode::khash` leaf (BLAKE2s-256, RFC 7693, native keyed mode) replaced the keyed-FNV envelope with derive-then-MAC + domain-separated key evolution; `kat=RFC7693-PASS` earned per boot; `sec=ASSUMED-FROM-LITERATURE` machine-tokened; the retired `KEYED-NONCRYPTO` token guard-REJECTED. The khash leaf is also the named enabler for the #74 provenance-hash cutover (`prov_hash` → `khash::uhash`) and the #75 Merkle successor.
- **M28/M29 successors (#85):** a real enrolment ceremony (today `oracle=SIMULATED-ENROLLED-KEY` is a compiled-in test key, not a human), one-shot nonce consumption (rotate-on-accept in the stateful seam — the pure stateless verifier rejects per-EPOCH only, so an identical valid wire re-verifies within the same epoch), the pending-flag→M24 activation seam (the accepted command is currently fully INERT), a trustworthy freshness clock, the #74 signed root (a signature primitive, explicitly out of khash scope), and #75 Merkle inclusion proofs.
- **M30 — verified INFERENCE TRANSPORT, stages A+B (#87): ✅ LANDED.** The `tb-encode::inferwire` codec leaf (the 20th) + the kernel's first TWO-queue virtio driver (modern virtio-console, DeviceID 3, poll-only) + the `xport-harness` host echo peer on both QEMU-TCG lanes; the DoD is the two-leg anti-hollow composition — kernel-side `verify_echo` against the channel-revealed per-run key (leg 1) AND the run scripts' cross-process challenge/tag equality against the harness's own line (leg 2, the loopback killer). `key=HOST-CUSTODIED-PER-RUN`, `echo=HOST-KEYED-VERIFIED` (kernel-scope), `backend=ECHO-ONLY`, `mode=POLL` (#71 guard-pinned), `sec=ASSUMED-FROM-LITERATURE`.
- **M30 stage C — the tb-vmm virtio-console device backend (`transport=TB-VMM-HOST`, `bus=VIRTIO-MMIO`):** the pre-authorized split follow-up (proposal §11C) — tb-vmm's FIRST `mmio_bus` device (`virtio_mmio.rs` register file + `infer_host.rs` device model reusing `tb-encode` host-side), the `run-vmm-x86_64.sh` MARKER bump M19 → the current tail, and the whole cumulative chain becoming CI-required under tb-vmm/KVM. The chardev lanes already discharge the REQUIRED both-arches DoD on TCG, accel-independent, so stage C adds the KVM-lane evidence class without gating PRs.
- **M31 — verified INFERENCE ADAPTER, stages A+B (#89): ✅ LANDED.** The first meaning on the M30 channel: the `inferwire` extension (chunked MAC'd byte bodies under `INFER_BODY_CAP=8192`, reject-never-truncate, the chunk-at-a-time Kani-proven `InferAssembler`), the `infer_bytes` byte path retiring the u64 toy (`M_MODEL_INVOKE_BYTES=32`, the same INVOKE_MODEL chokepoint), the every-boot mock-lane e2e (M13 recall → byte prompt → the shared deterministic `mock_infer` transform → the digest folded into the M25 transcript before its closing commit → the MAC-chunked wire exchange with the keyless harness incl. the `ERR code=NO-KEY` fail-closed check + ONE PENDING heartbeat + the bit-exact cross-process determinism equality), lowercase-hex injection-proofing of every model-derived serial byte, and the M31 guard blocks (skip/live-vocabulary rejects, the ESC tripwire + dump-grammar pin, strip-then-reject). `backend=MOCK-DETERMINISTIC key=CAPREF-HOST-CUSTODIED host=RESIDUAL-TCB ambient=ZERO-IN-GUEST`.
- **M31 stage C — the ANTHROPIC-LIVE bridge (the OPERATOR'S lane):** `ureq`+`rustls`+`serde_json` in the host harness only (the LANGUAGE-AND-STANDARDS §0/§6 [DECISION] rows are pre-landed), `real-infer.yml` on `workflow_dispatch` (never `pull_request_target`), the §5 challenge-nonce HEX-REVERSE liveness protocol, the dual marker `M31: real-infer OK backend=ANTHROPIC-LIVE` — requires the operator to provision `ANTHROPIC_API_KEY` and to trigger the run; NEVER a required check, NEVER unattended, NEVER in the cumulative chain (the mock lanes reject the live vocabulary by name). Named successors: **M32** (the local llama.cpp daemon serving `model:local/llama` over the SAME INFER_REQ/INFER_RESP framing, #90), **M33** (a signature primitive — host participation → host exclusivity; signed prov heads carry the inference digests), **B2** (the vsock-only `model:` API — the inferwire frame migrates onto a vsock stream unchanged), plus the named M31 deferrals: byte-payload M13 memory records and static registration of a channel-backed route.

Every milestone increment is shipped by the same pipeline — codified as the
[`tabos-milestone`](../.claude/skills/tabos-milestone/SKILL.md) project skill:
ultracode generate → 3-lens adversarial review → apply → both-arch `cargo kbuild`
→ QEMU + tb-vmm boot-assert → **boot-time benchmark** → doc/research/script/roadmap
updates → commit → CI-green. Boot time is measured on every change and compared,
with cited sources and matched metrics, in **[BENCHMARKS.md](BENCHMARKS.md)**
(Yuva is a kernel-only / "Bucket 1" system; its honest win is the firmware +
bootloader + decompress + Linux-init budget it never pays — orders of magnitude
below any full-Linux microVM).
