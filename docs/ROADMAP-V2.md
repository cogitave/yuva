# TABOS v2 Roadmap — the agent-native milestone chain (M5 → M18)

> Status: **v1 foundation (M0–M4) + L1 sovereignty (tb-vmm) complete and CI-green.**
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
| **M14** | Inter-agent IPC — capability-passing channels + ordered streams | multi-agent | `M14: ipc OK` | M12, M11, M9 |
| **M15** | Shared memory blocks + session blackboard | memory-central | `M15: blocks OK` | M14, M13, M10 |
| **M16** | LLM-agnostic inference bridge (the `model:` scheme) | LLM-agnostic | `M16: infer OK` | M14, M12, M8 |
| **M17** | Sleep-time consolidation / reflection / forgetting daemons | memory-central | `M17: consolidate OK` | M13, M16, M9 |
| **M18** | Frozen-kernel self-improvement harness + held-out evaluators + skill tier | self-improving | `M18: evolve OK` | M11, M12, M13, M17 |

**Critical path:** `M5 → M6 → M7 → M8 → M9 → M10 → M11 → M12`, after which the
memory (M13/M15/M17), IPC (M14), inference (M16), and self-improvement (M18)
layers compose on the agent runtime.

**Framekernel dividend:** the *only* new `unsafe`/asm in the entire chain lives
in `tb-hal` at M5–M12, M14, M16. The security-critical capability (M11), memory
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
An `AddressSpace` object = a fresh top-level table (M6 frames, M3 typed layer, M7
heap-tracked). x86_64: per-entity PML4 sharing the kernel higher-half; switch =
`mov CR3` + update `TSS.rsp0` (PCID deferred). aarch64: kernel to `TTBR1_EL1`,
each entity its own `TTBR0_EL1`; switch = write `TTBR0` + ASID + `tlbi`/`isb`.
The swap folds into the M9 switch. *Risk:* aarch64 **requires refactoring M3's
identity-only TTBR0 into a TTBR1/TTBR0 split** — touches an already-green
milestone, so the DoD must **re-assert M3**. Self-test: two tasks in two address
spaces map the same VA to different private frames, each writes/reads its own
magic, a switch flips the root, kernel/serial survive, a cross-space access faults.

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
(bounds- and mapping-checked cross-address-space copies; SMAP/PAN-aware later).
Self-test (the multi-agent north star): A sends B bytes + a derived-narrowed
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
INVOKE_MODEL right gates the call. Transport = a `tb-hal` **virtio** device
(virtio-pci on x86_64 microvm / virtio-mmio on aarch64 `virt`, a vsock-style
channel); completion tokens stream back over an ordered M14 stream; the completion
IRQ is wired through M8. For a buildable CI DoD without GPU/network a deterministic
**mock provider** registers the scheme and returns canned embeddings/echo; the real
GPU/CUDA path stays a passthrough Linux driver VM reached **only** via this vsock
API (L2-sovereignty track, out of this DoD). Also fills `MemRecord.embedding`,
lighting up the T3 dense channel M13 left inert. New unsafe = only the virtio ring
(MMIO/PCI probe, volatile descriptor ring, doorbell, completion IRQ); the scheme
registry/router/DAG executor/mock are safe. tb-vmm gains a host-side device backend.

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
5. **Address spaces (M10) kept separate** from the agent milestone because
   aarch64 must refactor M3's identity-only TTBR0 into a TTBR1/TTBR0 split — a
   regression risk that earns its own marker and an M3 re-assertion.
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
- **M10 on aarch64** touches the already-green M3 (TTBR split) → the DoD re-asserts
  M3. x86_64 stays a single CR3 swap.
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
| **M6** (frame allocator from boot map) | ⏳ **in progress** (next increment) |
| M7 – M18 | ⬜ planned (this document) |
| L2 (own Type-1 microhypervisor) | ⬜ parallel north-star track ([SOVEREIGNTY-ROADMAP](SOVEREIGNTY-ROADMAP.md)) |

Every milestone increment is shipped by the same pipeline — codified as the
[`tabos-milestone`](../.claude/skills/tabos-milestone/SKILL.md) project skill:
ultracode generate → 3-lens adversarial review → apply → both-arch `cargo kbuild`
→ QEMU + tb-vmm boot-assert → **boot-time benchmark** → doc/research/script/roadmap
updates → commit → CI-green. Boot time is measured on every change and compared,
with cited sources and matched metrics, in **[BENCHMARKS.md](BENCHMARKS.md)**
(TABOS is a kernel-only / "Bucket 1" system; its honest win is the firmware +
bootloader + decompress + Linux-init budget it never pays — orders of magnitude
below any full-Linux microVM).
