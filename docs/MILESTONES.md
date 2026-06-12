# Yuva Milestones & Development Pipeline

> Status: the agent-native milestone chain **M0 → M31 is complete and CI-green on
> both architectures** (x86_64 + aarch64), extended since the M18 capstone by a
> tail of follow-on markers — **M14.1** (byte-payload IPC), **M14.2**
> (blocking-recv), **M15.1** (block unmap + frame reclamation), **M18.1**
> (mandatory human-approval gate), **M18.2** (rotating held-out evaluator),
> **M19** (a poll-based virtio-mmio virtio-rng round-trip — the kernel's FIRST
> real device I/O), then **M20** (durable persistence: a virtio-blk-backed
> log-structured store behind the M13 `BackingStore` seam — the FIRST byte to
> outlive a boot), **M21** (a verified fixed-point additive-policy seam for the
> M17 forget/demote decision — SHIPS DORMANT, `active=0`), **M22** (a verified
> per-agent provenance hash-chain ledger), and then the **learning-loop arc**:
> **M23** (a verified experience codec + counterfactual shadow-recording — the
> Monitor/log layer, `M23: experience OK`), **M24** (the HONEST activation gate:
> shielded ε-greedy + a 3-way right-censored survival label + a partial-id
> lower-bound + a one-shot HCPI gate that correctly REFUSES on synthetic data —
> `M24: bakeoff OK (gate-not-met)`, the cell stays dormant), **M25** (the
> verified OPERATOR TRANSCRIPT — a typed, tamper-evident channel the OS emits over
> serial to SURFACE its decisions to a human exogenous oracle, anchored to the live
> M22 provenance head, `M25: operator OK`), and **M26** (a verified EL2 EXIT-TELEMETRY
> producer — the already-Kani-proven `el2_trap` guest-exit classifier becomes a
> bounded, no-float, injective telemetry record folded into a separate `tel_head`; the
> OS *records* its own virtualization workload; PRODUCER-ONLY, `signal=OBSERVATIONAL-
> NONCAUSAL`; `M26: exit-telemetry OK`) — plus
> the full aarch64 sovereignty-L2 chain, **L2.0**
> (x86_64 VMX-root graceful-skip + aarch64 EL2 world-switch) through **L2.6**
> (aarch64 stage-2 → exit-dispatch → trap-and-emulate → nested-EL1 guest → vGIC →
> SMMUv3) and then **M27** (the sovereignty pillar's two-VMID time-partition
> SCHEDULER — the EL2 monitor alternates two guest VMIDs in a fixed major frame,
> folding each Kani-proven scheduling decision into a tamper-evident `sched_head`;
> landed as M27a (the cooperative green floor) then upgraded by **M27b** to REAL
> CNTHP timer-preemption — the FIRST asynchronous IRQ taken at EL2 (the 0x480
> vector, IMO=1 only inside the armed window; the guest stubs are pure store-spins,
> so forward progress is only reachable via genuine preemption);
> `timing=TCG-NON-CYCLE-ACCURATE realtime=NOT-CLAIMED`, the retired cooperative
> token now guard-REJECTED; `M27: sched OK`), all printed before M19 — then **M28** (the operator
> **INBOUND** command channel, the RX dual of M25's transcript — the
> exogenous-oracle CAPSTONE that CLOSES the learning loop: a human holding TWO
> enrolled credentials answers the OS's freshness challenge and submits a
> dual-authorized `ACTIVATE_CMD` bound to the live M22 provenance head; honest
> by construction, `oracle=SIMULATED-ENROLLED-KEY` /
> `kan_active=0` (an Accept is necessary-not-sufficient); printed after M26,
> `M28: operator-cmd OK`) — and finally **M29** (the M28 named successor LANDS:
> the verified `tb-encode::khash` leaf — BLAKE2s-256, RFC 7693, native keyed
> mode — re-points the M28 MAC from the keyed-FNV envelope to a REAL keyed hash;
> `mac=KEYED-NONCRYPTO` retires (now guard-REJECTED) for `mac=KEYED-CRYPTO` +
> `kdf=DERIVE-THEN-MAC-DOMSEP` + `keyevolve=PRF-DOMSEP`, the in-boot KAT earns
> `kat=RFC7693-PASS` per boot through the real compression, and the prove/assume
> boundary is machine-emitted — `sec=ASSUMED-FROM-LITERATURE` (implementation
> PROVEN; primitive security assumed from the cryptanalysis literature, the
> Appel/HACL*/mlkem-native claim boundary); `M29: khash-mac OK`) — and finally
> **M30** (the verified INFERENCE TRANSPORT, stages A+B — the sovereignty
> A-chain's channel to a host model peer, promoting the M22 runner-up with the
> anti-hollow amendment that makes its mock-loopback structurally impossible:
> the Kani-proven `tb-encode::inferwire` frame codec (house magic `0x5958`,
> fail-closed `canon`/`decode`, the `FrameAccum` byte-stream re-framer, the
> ONE-khash-call `echo_tag`/`verify_echo`) rides a modern (Version==2)
> virtio-console (DeviceID 3, VERSION_1-only, port 0, poll-only `mode=POLL`)
> to a HOST peer that custodies a per-run OS-RNG key+nonce — the
> `xport-harness` binary on the QEMU chardev lanes (`transport=
> QEMU-CHARDEV-HARNESS`, `bus=SERIAL-FRAMED`) — and the DoD is a TWO-LEG
> composition: the kernel verifies the khash-transformed echo against the
> channel-revealed key (leg 1, `echo=HOST-KEYED-VERIFIED`, kernel-scope) AND
> the run script string-compares the kernel-witnessed challenge/tag against the
> host peer's OWN printed line (leg 2 — CROSS-PROCESS equality with a
> host-custodied key is the loopback killer); `key=HOST-CUSTODIED-PER-RUN`,
> `backend=ECHO-ONLY` (transport only — the adapter is M31), stage C (the
> tb-vmm `TB-VMM-HOST` device backend) split to its own follow-up landing; the
> NEW cumulative-tail marker `M30: infer-transport OK`) — every milestone
> verified by booting under QEMU
> (and, on x86_64, the project's own `tb-vmm`/KVM) on every change. A
> **formally-verified core** now backs the chain: M11's capability rights-subset
> invariant is **machine-proven by Kani** (`M11: caps-subset PROVEN`,
> `crates/tb-caps-core`), the silicon-unsafe encoders/parsers + the memory/learning
> leaves are **Kani-proven** over the 20-leaf `crates/tb-encode` (90 harnesses,
> `V1: kani-encoders OK`), and a
> **Miri Tier-0 UB gate** interprets both leaf crates (`T0: miri OK`); CI now runs
> **9 gates across 8 workflow files**. This
> document records what each milestone delivers, how it is proven, and how the
> codebase is built and run; the full sequenced, risk-analysed v2 plan with
> per-milestone detail is **[ROADMAP-V2](ROADMAP-V2.md)**.
> Related: [KERNEL-FOUNDATION-SPEC](KERNEL-FOUNDATION-SPEC.md) (the assembly plan
> the M0–M4 milestones implement) · [ROADMAP-V2](ROADMAP-V2.md) (the M5→M18
> detail) · [SOVEREIGNTY-L2-ROADMAP](SOVEREIGNTY-L2-ROADMAP.md) (the L2 track) ·
> [SOVEREIGNTY](SOVEREIGNTY.md) · [BUILD](../BUILD.md).

---

## 1. Architecture in one paragraph

Yuva is a from-scratch, `no_std` Rust kernel with **zero Linux code or design**
inherited (see [SOVEREIGNTY](SOVEREIGNTY.md)). It follows the *framekernel*
pattern: **all `unsafe` and all assembly live in one foundation crate,
`tb-hal`**; every layer above it is safe Rust. The pure leaves —
`crates/tb-caps-core` and `tb-hal`'s `caps`/`mem`/`ipc`/`blocks`/`infer`/`heap`/
`pmm` modules — are literally `#![forbid(unsafe_code)]`, and the `kernel` crate
itself carries **zero `unsafe {}` blocks** (it is not crate-level `forbid` only
because `#[unsafe(no_mangle)]` on `rust_main` is itself an unsafe *attribute*,
which the `unsafe_code` lint flags). The
kernel boots as a guest on a Firecracker/KVM-class virtual machine (for
development we boot it under QEMU). Two architectures are first-class:
**x86_64** (PVH boot) and **aarch64** (PE/Linux Image boot on QEMU `virt`).

```
kernel/                 entry shim + cumulative milestone self-tests; ZERO `unsafe {}`
                        blocks (not literally crate-level forbid only because
                        `#[unsafe(no_mangle)]` on `rust_main` is an unsafe attribute)
crates/tb-caps-core/    #![forbid(unsafe_code)] — the host-verifiable M11 capability
                        core (Rights + CapTable); the SAME code the kernel runs, Kani-proven
crates/tb-hal/          the ONLY crate where unsafe + asm is allowed
  src/mmu.rs            shared typed page-table layer (PageTable512)
  src/{caps,mem,ipc,blocks,infer,heap,pmm}.rs   safe-Rust leaves, each #![forbid(unsafe_code)]
  src/arch/x86_64/      boot, serial, gdt, idt, trap, sched, mmu, user, timer, uaccess, vmx/
  src/arch/aarch64/     boot, serial, vectors, trap, sched, mmu, user, timer, uaccess, el2
targets/*.json          custom no_std target specs (build-std)
kernel/linker/*.ld      per-arch linker scripts
scripts/run-*.sh        QEMU launch + serial-marker assertion (the executable DoD)
```

## 2. The milestone chain (M0 → M31, + L2.0 … L2.6)

Each milestone has an **executable Definition-of-Done (DoD)**: a marker string
the kernel prints over serial once that capability works. The kernel runs the
milestones cumulatively, so every boot is a full regression of M0 through the
latest. A green boot prints the M0–M4 foundation trace (below), then the M5–M18
agent-native markers (now including the M14.1/M14.2/M15.1/M18.1/M18.2 follow-ons),
then the aarch64 sovereignty-L2 chain `L2.0` … `L2.6` (two L2.0 lines, then
`L2.1: stage2 OK` through `L2.6: smmu OK`) and the `M27: sched OK` two-VMID
sovereign-scheduler marker (its own `sched: …` witness), then the `M19: virtio OK` device-I/O
marker, the `M20: persist OK` durable-persistence marker, the dormant
`M21: kan-policy OK` policy-seam marker, the `M22: provenance OK` provenance-ledger
marker, the learning-loop arc — `M23: experience OK` (the experience codec +
counterfactual shadow), `M24: bakeoff OK (gate-not-met)` (the honest activation gate,
correctly refusing on synthetic data), `M25: operator OK` (the operator transcript),
the `M26: exit-telemetry OK` exit-telemetry-producer marker, the
`M28: operator-cmd OK` operator-inbound marker (the RX dual of M25:
a dual-credential, freshness-challenged human command bound to the live M22 head),
the `M29: khash-mac OK` keyed-crypto-MAC marker
(the M28 MAC re-pointed at the verified BLAKE2s-256 `khash` leaf; its `khash: …`
witness line carries the machine-emitted prove/assume boundary), the
`M30: infer-transport OK` verified-inference-transport marker
(the host-keyed echo over the modern virtio-console channel; its `xport: …`
witness carries the two-leg anti-hollow tokens and the run scripts ALSO
string-compare its challenge/tag against the host peer's own `xport-harness: …`
line — cross-process equality with a host-custodied key), and finally the NEW
cumulative-tail `M31: infer-e2e OK backend=MOCK-DETERMINISTIC` inference-adapter
marker (the first MEANING on the M30 channel: M13-recalled context → a byte
prompt → the `infer_bytes` byte path → a MAC'd chunked wire exchange with the
host peer's deterministic mock serve loop → the response DIGEST folded into the
M25 transcript; its `infer: …` witness carries the custody/TCB honesty tokens,
its `infer-dump:` lines are lowercase-hex injection-proofed, and the LIVE
ANTHROPIC half is stage C — operator-gated, never in the cumulative chain)
(each preceded by its anti-hollow witness line: `prov: …`, `exp: …`, `bakeoff: …`,
`opframe: …`, `exittel: …`, `khash: …`, `opcmd: …`, `xport: …`, `infer: …`) — the
ordered sequence (detailed through M22) is listed further below.

| Milestone | Capability | x86_64 mechanism | aarch64 mechanism | DoD marker |
|---|---|---|---|---|
| **M0** | Boot + serial | PVH ELF note → 32→64 trampoline (`A0`) → `rust_main`; 16550 UART @ `0x3F8` | PE image, EL1h entry, `x0`=FDT; PL011 UART @ `0x0900_0000` | `hello from rust_main` |
| **M1** | Traps / exceptions + safe dispatch | permanent GDT+TSS(IST) + 256-entry IDT; `int3` → `__alltraps` → safe hook → `iretq` | `VBAR_EL1` 16×128B table; `brk #0` → ESR_EL1.EC=0x3C → `ELR_EL1+=4` → `eret` | `M1: traps OK` |
| **M2** | Cooperative context switch | naked `ctx_switch` saving SysV callee-saved set; fabricated initial frame | `stp/ldp` x19–x30 + SP; resume via `ret` to x30; entry trampoline + exit guard | `M2: context-switch OK` |
| **M3** | MMU + page tables | splice a 4 KiB mapping into the live boot tables; remap + `invlpg` | **cold MMU bring-up**: MAIR/TCR/TTBR0 → `SCTLR.M\|C\|I`; Break-Before-Make remap + TLBI | `M3: mmu OK` |
| **M4** | User/ring boundary | ring3 via `iretq`; user `int 0x80` through a DPL=3 gate; `TSS.rsp0`; user pages `U/S=1` | EL0 via `eret` (SPSR=EL0t); user `svc #0` → Lower-EL Sync handler; ESR.EC=0x15; pages AP=0b01/AF/UXN | `M4: user/ring OK` |

The M0–M4 foundation trace of a green boot (the M5–M18 agent-native markers and
the two L2.0 lines that follow are in the complete sequence further below):

```
hello from rust_main
trap-test: triggering breakpoint
trap: breakpoint, resuming
trap-test: resumed past breakpoint
M1: traps OK
ctx-test: starting ping-pong
M2: context-switch OK
mmu-test: init
mmu-test: enabled, serial alive
M3: mmu OK
user-test: entering unprivileged mode
syscall from user: arg=0x000000000000cafe
M4: user/ring OK
```

### What M4 means

The kernel can drop the CPU to its unprivileged mode (x86 ring 3 / aarch64
EL0), run code there on user-accessible pages, and that code can make a syscall
that traps cleanly back into the kernel — observed by a safe-Rust handler with
the user-supplied argument intact. This is the hardware foundation for running
agents and daemons at lower privilege than the kernel.

### MV — owned boot via `tb-vmm` (the L1 sovereignty rung)

M0–M4 above boot under QEMU using the bootstrap **PVH** ELF note (and, on x86_64,
the 32→64 `A0` trampoline). **MV** removes that external dependency from the boot
path: the project ships its own thin **userspace** VMM, [`tb-vmm`](../tb-vmm/),
built on the rust-vmm crates (`kvm-ioctls`, `kvm-bindings`, `vm-memory`), which
boots the *same* kernel through the project's own **`tb-boot v0`** contract —
entering the guest **directly in 64-bit long mode** with page tables, GDT, and a
`TbBootInfo` block that `tb-vmm` itself programs via `KVM_SET_SREGS`/`KVM_SET_REGS`.

To support both paths, the kernel now carries **two** ELF entry notes (see
`crates/tb-hal/src/arch/x86_64/boot.rs` and the [`tb-boot`](../crates/tb-boot/)
ABI crate):

| Note | Owner / type | Entry | Used by |
|---|---|---|---|
| Xen PVH | `Xen` / `0x12` (`XEN_ELFNOTE_PHYS32_ENTRY`) | `_start` (32-bit) | QEMU `-kernel`, Firecracker |
| Yuva tb-boot | `YUVA` / `0x59550001` (`TB_NOTE_TYPE_ENTRY64`) | `_tb_start` (64-bit) | `tb-vmm` *(both bytes derive from `crates/brand` — migrated in the brand PR)* |

`tb-vmm` resolves the **brand (YUVA) note only** — it refuses to fall back to `e_entry`
(which is the 32-bit PVH `_start`, and would triple-fault if entered in long
mode). The DoD is unchanged and shared: a `tb-vmm` boot must print the same
`M4: user/ring OK` marker, proving the entire M0–M4 stack runs **identically**
under the project's own VMM + boot contract. Because the host VMM needs
`/dev/kvm`, its CI job (`.github/workflows/vmm-boot.yml`) runs on the GitHub
Actions Linux runners; the WSL2 dev box has no nested virt, so locally `tb-vmm`
is exercised by its unit tests (ELF loader, boot-info serialisation, device bus)
plus the `tb-boot` ABI tests. Status: **implemented and green** (kernel boots
M0–M4 under both PVH/QEMU and tb-boot/tb-vmm). The next rung, **L2**, replaces
the host kernel's KVM with the project's own Type-1 microhypervisor —
see [SOVEREIGNTY-ROADMAP](SOVEREIGNTY-ROADMAP.md).

### The v2 agent-native chain (M5 → M18)

M0–M4 built the hardware foundation; the v2 chain turns it into the agent-native
OS the four pillars describe (agent-native · LLM-agnostic · memory-central ·
self-improving). Each milestone is one cumulative serial-marker DoD under the
same QEMU + `tb-vmm` harness, and — the **framekernel dividend** — the only new
`unsafe`/asm in the whole chain lives in `tb-hal`; the security-critical
capability (M11), memory (M13/M15/M17) and self-improvement (M18) layers add
**zero** new unsafe. Per-milestone design, risk analysis and self-test detail are
in **[ROADMAP-V2](ROADMAP-V2.md)**; the summary:

| Milestone | Capability | DoD marker | New `unsafe`/asm (all in `tb-hal`) |
|---|---|---|---|
| **M5** | Bootstrap kernel heap + `#[global_allocator]` (`alloc` online) | `M5: alloc OK` | `KernelHeap` `GlobalAlloc` over a `.bss` arena |
| **M6** | Physical frame allocator from the boot memory map | `M6: frame alloc OK` | boot-map parse + intrusive free-frame stack |
| **M7** | Frame-backed growable kernel heap | `M7: heap OK` | `map_heap_frames` (a higher-half heap VA window) |
| **M8** | Async interrupt + monotonic timer tick (no switch) | `M8: timer OK` | LAPIC / GICv2 + timer IRQ stub (first `sti`/`daifclr`) |
| **M9** | Preemptive scheduler (involuntary full-context switch) | `M9: preempt OK` | from-IRQ-context switch (M2 cooperative switch reused) |
| **M10** | Per-agent address spaces (memory isolation) | `M10: addrspace OK` | `map_in_root` + root swap (CR3 / TTBR0_EL1) |
| **M11** | Capability handle table + object model + agent-native syscall ABI | `M11: caps OK` | per-arch register-lift syscall shim **only** |
| **M12** | Agent runtime — `AgentProcess` as a scheduled, isolated entity | `M12: agent OK` | user-frame launch + preemption fold-in |
| **M13** | Default tiered memory substrate (T0–T3 + `tb_mem_*` ABI) | `M13: memory OK` | none (safe `mem.rs`) |
| **M14** | Inter-agent IPC — capability-passing channels + ordered streams | `M14: ipc OK` | none (safe `ipc.rs`; cap moved by handle) |
| **M14.1** | Variable-length byte payload (bounce buffer, `MAX_PAYLOAD = 4096`) | `M14.1: payload OK` | `copy_to_user`/`copy_from_user` in `arch/*/uaccess.rs` |
| **M14.2** | recv-blocks-on-empty / send-wakes-peer scheduler↔IPC round-trip | `M14.2: blocking-recv OK` | none |
| **M15** | Shared memory blocks + session blackboard | `M15: blocks OK` | none (reuses M10 map machinery) |
| **M15.1** | Owner-only block unmap + frame reclamation (`M_BLOCK_UNMAP`, `Rights::REVOKE`) | `M15.1: unmap OK` | `unmap_in_root`/`va_to_pa_in_root` in `arch/*/mmu.rs` |
| **M16** | LLM-agnostic inference bridge (the `model:` scheme) | `M16: infer OK` | none (safe mock backend; the virtio ring landed separately at M19) |
| **M17** | Sleep-time consolidation / reflection / forgetting daemons | `M17: consolidate OK` | none |
| **M18** | Frozen-kernel self-improvement harness + held-out evaluators + T4 skill tier | `M18: evolve OK` | none |
| **M18.1** | Mandatory human-approval gate on `EMIT_EXTERNAL`/high-impact skills | `M18.1: approval-gate OK` | none (new `APPROVE_HIGH_IMPACT` right; reduces to the M11 invariant) |
| **M18.2** | Rotating never-exposed held-out evaluator partition (anti-Goodhart) | `M18.2: held-out OK` | none |
| **M19** | Poll-based virtio-mmio device I/O — a virtio-rng round-trip (the FIRST real device I/O; prints AFTER the L2.0 lines; completion-IRQ deferred) | `M19: virtio OK` | virtio-mmio ring (MMIO/DMA) in `arch/{x86_64,aarch64}/virtio.rs` |
| **M20** | Durable persistence — a poll-only virtio-mmio **virtio-blk** (DeviceID 2) backing a log-structured store behind the M13 `BackingStore` seam; the FIRST byte to outlive a boot (write → two-phase flush → re-mount → replay; graceful `(no disk, skipped)` where no disk is attached) | `M20: persist OK` | virtio-blk MMIO/DMA ring in `arch/{x86_64,aarch64}/virtio.rs`; on-disk + request codecs in `tb-encode::blkfmt` (Kani-proven) |
| **M21** | Verified fixed-point **additive-policy seam** for the M17 forget/demote decision — a Kani-proven, total/bounded/monotone integer GAM (`tb-encode::kancell`) that may only **rank within** the unchanged M17 heuristic safety envelope; **shipped DORMANT** (`active=0`) behind a fail-closed loader until a held-out trace bake-off earns its activation | `M21: kan-policy OK` | none (pure value computation in `tb-encode::kancell`; `tb-hal` calls it next to the unchanged `THETA_DEMOTE` comparator, exactly as it already calls `bla_raw`/`minmax`) |
| **M22** | Verified memory **provenance ledger** — a per-agent, append-only, content-addressed **hash-chain** over the M13 substrate; every mutation appends a typed entry whose 256-bit digest (structural FNV at landing; **upgraded by M29 stage C to cryptographic khash/BLAKE2s-256**, `sec=ASSUMED-FROM-LITERATURE`) folds into a running `chain_head`; M17 forget becomes a verifiable **tombstone**; a deterministic tamper-injection boot self-test proves the head + inclusion proof catch any single-byte mutation | `M22: provenance OK` | none (canonical encoder / digest / fold / inclusion verifier in `tb-encode::prov`, Kani-proven; safe `ledger_append` seam in `mem.rs`) |
| **M23** | Verified **experience codec** + counterfactual shadow-recording — the learning loop's Monitor/log layer: each M17 forget/recall decision records a fixed-field injective `ExperienceRecord` (the features + the heuristic action + the COUNTERFACTUAL `kan_score` the dormant M21 cell WOULD produce + reserved-now propensity/outcome fields) into a fixed-capacity ring folded into a SEPARATE `xp_head` (reuses the M22 fold); a recorded row replays through the dormant `kan_score` BIT-IDENTICALLY; claims ONLY replay-determinism + tamper-evidence (cryptographic since M29-C), NOT validity (`oracle=DECLARED-PROXY-DEFERRED-M24`) | `M23: experience OK` | none (codec / ring / replay in `tb-encode::exp`, Kani-proven; the M17 demote stays byte-identical, `kan_active=0`) |
| **M24** | The **HONEST activation gate** — the honest resolution of the M21 ship-gate: shielded ε-greedy exploration restores statistical overlap (populating the M23-reserved propensity), a deterministic 3-way right-censored **survival label**, a partial-identification (Manski + Lipschitz-smoothness + empirical-Bernstein) **lower-bound** estimator, and a one-shot **HCPI** activation gate. On the necessarily-synthetic traces this milestone the gate does **NOT** clear — `gate-not-met` (the cell stays DORMANT) is the DESIGNED, CORRECT outcome (an honest gate that REFUSES is a success) | `M24: bakeoff OK (gate-not-met)` | none (estimators in `tb-encode::explore` + `tb-encode::bakeoff`, Kani-proven; `KAN_ACTIVE` stays `false`) |
| **M25** | Verified **operator transcript** (the exogenous-oracle channel) — the COMMUNICATION pillar's outbound half: a typed, fixed-header, length-prefixed, INJECTIVE, tamper-evident frame the OS emits over serial to SURFACE what it recorded (M23) and decided (M24) to a human, anchored to the live M22 provenance head ("which instance am I", RATS RFC 9334), with a strictly-monotone `seq` folded into the canonical bytes + a closing `GATE_VERDICT` so a reader detects mutation/reorder/drop/truncation; a held-out-leakage guard fail-closes `canon` on the sealed M24 partition (Seldonian no-snoop). TX-only + claims ONLY tamper-evidence (cryptographic-hash since M29-C, keyless) + instance binding (`keyed=0`), NOT crypto authenticity and NOT that a human replied (`oracle=HUMAN-DEFERRED-M26`) | `M25: operator OK` | none (canonical encoder / fold-reuse / seq / intro-binding / truncation verifier in `tb-encode::opframe`, Kani-proven; reuses the M22 `prov` fold verbatim) |
| **M26** | Verified **EL2 exit-telemetry producer** — the learning pillar's SECOND experience producer: the EL2 (nVHE) monitor's guest-exit demux (the already-Kani-proven L2.2 `el2_trap::classify_exit`) becomes a BOUNDED, no-float, injective telemetry record (exit-class + a saturating log2 cost-proxy histogram + logical time) folded into a per-instance `tel_head` via the M22 fold reused verbatim; the OS *records* its own virtualization workload. PRODUCER-ONLY (the telemetry is recorded + folded, NEVER fed to a policy whose decisions change the future exit distribution — the confounding loop the M24 adversary named is structurally avoided); the `tel_head` is SEPARATE from the M23 `xp_head` (zero regression). Claims injective bounded encoding + tamper-evidence, NOT a causal state-signal (`signal=OBSERVATIONAL-NONCAUSAL`); the last cumulative agent-native marker until the M28 tail landed (M28 now prints after it) | `M26: exit-telemetry OK` | none (classifier-reuse / log2-bucket histogram / fixed-width injective codec / fold-reuse in `tb-encode::exittel`, Kani-proven) |
| **M27** | **Two-VMID sovereign time-partition scheduler** — the sovereignty pillar's "Yuva owns time for two guests" rung: the EL2 (nVHE) monitor arms TWO distinct stage-2 roots (VMID 0 + 1) and alternates two trivial EL1 guest stubs in a fixed two-slot major frame, each bumping a DISTINCT per-VMID MMIO forward-progress cell (a guest can't fake a non-trapping store), folding each `SchedDecision` into a tamper-evident `sched_head` via the M22 fold; the verdict genuinely checks both-progressed + round-robin order + frame-conservation + fold-verified + tamper-caught. **Landed in two banked stages:** M27a, the cooperative HVC-yield green floor, then **M27b — REAL CNTHP timer-preemption, the first asynchronous IRQ ever taken at EL2** (the 0x480 Lower-EL IRQ vector; `HCR_EL2.IMO=1` only inside the armed window; the guest stubs are pure store-spins with NO voluntary yield, so `both-progressed=1` is only reachable via genuine timer preemption; re-arm-before-EOI + IAR==26 verify + ISTATUS read-back + a hard EOI cap turn any storm into a fast red; the retired `hvc #14` yield traps loud). `timing=TCG-NON-CYCLE-ACCURATE realtime=NOT-CLAIMED` — the guard REQUIRES the new token and REJECTS the cooperative one. Prints in the L2-track position (after L2.6, before M19) | `M27: sched OK` | the verified `tb-encode::tpsched` leaf (next_slot/frame-conservation/`SchedDecision` codec + 5 Kani harnesses) + the EL2 HAL (`tpsched_hal`/`el2`/`stage2`/`el2mmio`); kernel zero-unsafe, branches on `SchedProof` |
| **M28** | **Operator INBOUND command channel** — the COMMUNICATION pillar's inbound half, the RX dual of M25's `opframe`, and the exogenous-oracle CAPSTONE that CLOSES the learning loop (record M23 → honestly-refuse M24 → surface-to-human M25 → record-workload M26 → schedule M27 → **receive-human-command M28**): a human operator holding TWO enrolled credentials answers the OS's freshness challenge and submits a dual-authorized `ACTIVATE_CMD` bound to the live M22 provenance head. THE GATE IS MACHINE-PROVEN: the conjunctive verdict core is the pure, buffer-free/hash-free `opframe_rx::verify_decoded(frame, expected_nonce, live_head, mac_ok)` (`decode_and_verify` delegates its verdict to it verbatim) and Kani drives it fully symbolically — `RejectStale` iff echo ≠ challenge, `RejectWrongHead` iff the bound head ≠ a fully-symbolic live head, `RejectSingleCred` iff the two creds are equal, `RejectBadMac` iff distinct-creds AND `!mac_ok`, **Accept IFF every conjunct holds** (the Accept-iff-all theorem), plus kind-dominance (`NotActivate`); the reject branches are MUTATION-TESTED (deleting each → `VERIFICATION FAILED` ×3), and the `decode_and_verify` wrapper's buffer/MAC plumbing is host-tested (all 7 verdict arms, run under the Miri CI lane) + boot self-tested. Honest scope (machine-emitted tokens the run scripts enforce): at landing the MAC was `mac=KEYED-NONCRYPTO` — a NESTED keyed-FNV envelope, genuinely keyed by two 256-bit creds but NOT cryptographic — **upgraded by M29 to `mac=KEYED-CRYPTO`** (the named successor LANDED: a keyed BLAKE2s-256 derive-then-MAC; the retired `KEYED-NONCRYPTO` token is now guard-REJECTED); `oracle=SIMULATED-ENROLLED-KEY` — a compiled-in test key, NOT a human/enrolment ceremony; `kan_active=0` — an Accept is NECESSARY-NOT-SUFFICIENT (`KAN_ACTIVE` stays `false`, M24's statistical bar still gates, and the accepted command is currently fully inert). Replay scope is honest: the verifier is pure + stateless — per-EPOCH staleness rejection, NOT one-shot per-challenge nonce consumption (an identical valid wire re-verifies within the same epoch; rotate-on-accept in the stateful seam is a named successor). Witness (post-M29): `opcmd: challenge=<hex16> accepted=1 stale-rejected=1 wronghead-rejected=1 single-cred-rejected=1 badmac-rejected=1 oldkey-zeroized=1 kan_active=0 mac=KEYED-CRYPTO kdf=DERIVE-THEN-MAC-DOMSEP keyevolve=PRF-DOMSEP oracle=SIMULATED-ENROLLED-KEY`. Printed after M26 (M27 keeps its L2-track position) | `M28: operator-cmd OK` | none (challenge/echo + the canonical command codec + the keyed MAC + the pure `verify_decoded` verdict core in `tb-encode::opframe_rx`, Kani-proven — the 18th verified leaf, the six `kani_cmd_*` harnesses) |
| **M29** | **The KEYED-CRYPTO MAC** — the M28 §5 named successor LANDS: ONE new verified primitive leaf, `tb-encode::khash` — **BLAKE2s-256 (RFC 7693) in its native keyed mode** (key zero-padded into data block 0, §2.5/§2.10; width-exact: 32-byte key == `KEY_LEN`, 32-byte digest == `PROV_HASH_LEN`, spec-sanctioned 16-byte tag truncation == `MAC_LEN`) — consumed by the M28 MAC and key-evolution. `compute_mac` sheds the five-pass nested-FNV envelope for **derive-then-MAC** (`K_s = khash(key_a, "YUVA-OPCMD-KDF-V1" \|\| key_b)`; `tag = khash(K_s, canon)[..16]` — keyed-BLAKE2 PRF proof Luykx–Mennink–Neves FSE 2016; libsodium `crypto_kdf` precedent; the adversarially-chosen-component case rests on a dual-PRF-style assumption, Backendal et al. CRYPTO 2023, named not claimed-around) and `key_evolve` becomes `khash(key, "YUVA-KEY-EVOLVE-V1")` (Bellare–Yee forward-security shape, domain-separated from MAC use; the selftest TESTS old-key erasure — `oldkey-zeroized=1`); signatures UNCHANGED, so `seal`/`decode_and_verify`/the four hash-free Kani gate harnesses carry over verbatim. **Honest by construction:** Kani proves totality/determinism/official-KAT correctness/tamper-at-flip-index on CONCRETE inputs (the #49 discipline; 4 new `kani_khash_*` harnesses, each mutation-tested); collision/preimage/PRF/forgery resistance of the primitive is **`sec=ASSUMED-FROM-LITERATURE`** (the Appel TOPLAS 2015 / HACL* / mlkem-native claim boundary, machine-tokened — deliberately NO symbolic security harness); `kat=RFC7693-PASS` is EARNED per boot (the selftest recomputes RFC 7693 Appendix B + BLAKE2 reference-KAT vectors through the real compression, fail-closed); `sidechannel=NOT-CLAIMED` (constant-time-SHAPED only); `prim=BLAKE2S-256` names the informational-RFC trade. `oracle=SIMULATED-ENROLLED-KEY` + `kan_active=0` stay VERBATIM — a real hash makes the key neither a human nor an activation. Witness: `khash: prim=BLAKE2S-256 keylen=32 tag=128 kat=RFC7693-PASS sec=ASSUMED-FROM-LITERATURE sidechannel=NOT-CLAIMED`. The cumulative-tail marker until M30 landed | `M29: khash-mac OK` | none (the pure BLAKE2s-256 leaf in `tb-encode::khash`, Kani-proven — the 19th verified leaf, the four `kani_khash_*` harnesses; the kernel stays zero-unsafe and branches on `OpcmdProof` bools) |
| **M30** | **Verified INFERENCE TRANSPORT (stages A+B)** — the sovereignty A-chain's channel to a host model peer (#87), PROMOTING the M22 runner-up with the anti-hollow amendment that makes its in-kernel mock-loopback structurally impossible. Stage A: ONE new verified codec leaf, `tb-encode::inferwire` — the typed, fixed-header, LENGTH-PREFIXED, injective `InferFrame` (house magic `0x5958`; kind ECHO_REQ/ECHO_RESP/ERR, reserved-zero flags, a u64 correlation id on the wire from day one — 9p2000 tag precedent, challenge[16]/nonce[16]/peer_id/tag[16], payload cap 1024) with TOTAL fail-closed `canon`/`decode`, the `resp_binds_req` correlation iff-theorem, the `FrameAccum` byte-STREAM re-framer (the `BoundedRing` fixed-capacity pattern, length-delimited, scan-to-next-magic resync, proven never-overflow), and the host-keyed echo `echo_tag`/`verify_echo` — EXACTLY ONE domain-separated khash call, `khash(K, "YUVA-M30-ECHO-V1" ‖ peer_id ‖ nonce ‖ challenge ‖ body)[..16]`, binding the challenge + host nonce + lane label INSIDE the MAC (the M28/Terrapin lesson). Stage B: the kernel's FIRST TWO-queue virtio driver — a modern (Version==2 readback) virtio-console (DeviceID 3), VERSION_1-only (F_MULTIPORT/F_SIZE/F_EMERG_WRITE rejected → exactly receiveq(0)+transmitq(1) on port 0), rx buffer posted BEFORE DRIVER_OK, poll-only (`mode=POLL`, the #71 guard pin) — plus the `xport-harness` HOST peer on the QEMU chardev lanes (`-device virtio-serial-device -device virtconsole,chardev=<unix socket>`, the spike-verified config on qemu-6.2 + 8.2.2): the harness CUSTODIES a per-run OS-RNG key K + nonce N (NEVER in the guest image/cmdline/config space), applies the khash echo, reveals K on the CHANNEL for the kernel recompute, and prints its OWN `xport-harness:` witness. **THE ANTI-HOLLOW DoD IS A TWO-LEG COMPOSITION** (proposal §4): leg 1 — the kernel verifies the tag + challenge-echo + body-bitexact against the channel-revealed key (`echo=HOST-KEYED-VERIFIED`, an explicitly KERNEL-SCOPE token — it can never mean "not a loopback") and fires four in-boot negatives (badtag/wrongkey/partial/desync); leg 2 — the run script string-compares the kernel-witnessed challenge/tag against the harness's independently-printed line (CROSS-PROCESS equality with a host-custodied key — a loopback can mint a self-consistent tag but cannot equal `khash(K,…)` without guessing 32 OS-RNG bytes), plus skip/loopback-by-name rejects, the lane cross-pin, the `mode=IRQ` tripwire, a key-LEAK negative, and strip-then-reject overclaim guards. HONEST SCOPE (machine-emitted): `key=HOST-CUSTODIED-PER-RUN` claims custody, NOT confidentiality (K is cleartext on the channel — host *participation*, not exclusivity, until the M33 signature primitive); `backend=ECHO-ONLY` (no model, no inference semantics — the adapter is M31); no network/TLS (a LOCAL host process, §5.8-enforced); `sec=ASSUMED-FROM-LITERATURE` inherited from M29; desync recovery is decoder-level, not live-ring (named deferral). Witness: `xport: bus=SERIAL-FRAMED qsz=0x4 tx=0x1 rx=0x1 challenge=<hex32> nonce=<hex32> tag=<hex32> req-id=<hex16> echo-verified=0x1 body-bitexact=0x1 badtag-rejected=0x1 wrongkey-rejected=0x1 partial-rejected=0x1 desync-rejected=0x1 mode=POLL transport=QEMU-CHARDEV-HARNESS echo=HOST-KEYED-VERIFIED key=HOST-CUSTODIED-PER-RUN backend=ECHO-ONLY sec=ASSUMED-FROM-LITERATURE` + the host's `xport-harness: peer=QEMU-CHARDEV-HARNESS challenge=… tag=… key-custody=HOST`. **Stage C (the tb-vmm `TB-VMM-HOST` virtio-console device backend — `bus=VIRTIO-MMIO`) is SPLIT to its own follow-up landing** (the vmm-boot lane stays at its M19 marker); the chardev lanes already discharge the REQUIRED both-arches DoD on TCG, accel-independent. The cumulative-tail marker until M31 landed | `M30: infer-transport OK` | the two-queue virtio-console MMIO/DMA session in `arch::*::virtio::chan_*` (reusing every M19/M20 accessor/barrier primitive verbatim; the codec + MAC are the pure `tb-encode::inferwire` — the 20th verified leaf, the six `kani_inferwire_*` harnesses; the kernel stays zero-unsafe and matches on `InferChanProof`) |
| **M31** | **Verified INFERENCE ADAPTER, stages A+B (the mock lane)** — the first MEANING on the M30 channel (#89). Stage A EXTENDS the `inferwire` leaf (deliberately not a 21st leaf): closed kinds `INFER_REQ=4`/`INFER_RESP=5`/`INFER_PENDING=6` + closed-enum `ERR` payload semantics (10 codes, the retryable flag BOUND to the code — raw provider text never rides the wire), the 24-byte IN-PAYLOAD chunk sub-header (`seq:u16` + MORE flag + `total_len:u32` + whole-body `digest[16]`) for chunked stop-and-wait under the UNTOUCHED 1024 payload cap, the compile-time shared `INFER_BODY_CAP=8192` (reject-never-truncate, the 413 mirror — both ends compile the SAME leaf, so compile-time agreement is the negotiation), the per-chunk MAC `khash(K, "YUVA-M31-INFER-V1" ‖ peer ‖ nonce ‖ challenge ‖ req_id ‖ kind ‖ seq ‖ sflags ‖ total_len ‖ body_digest ‖ chunk)[..16]` (EVERYTHING that adjudicates rides INSIDE the MAC — a reordered/spliced/cross-sequence chunk fails VERIFICATION, not just assembly), the Kani-proven fail-closed `InferAssembler` (CHUNK-at-a-time by design — the M30 FrameAccum byte-push CBMC-floor lesson; completion REQUIRES the recomputed whole-body digest to equal the locked commitment; any reject POISONS), and the SHARED deterministic `mock_infer` transform (a 1280-byte uhash-keystream expansion — deliberately > the payload cap so the wire always chunks). Stage B retires the u64 toy: object-safe zero-alloc `infer_bytes(&self, ModelId, &[u8], &mut [u8]) -> Result<(usize, StopReason), InferError>` + `M_MODEL_INVOKE_BYTES=32` (the SAME `INVOKE_MODEL` right at the M11 chokepoint; byte buffers ride the kernel facade — the M14.1/M15 precedent; the M16 scalar path stays). THE MOCK-LANE E2E every boot: an in-kernel agent writes + recalls M13 context through the chokepoint (`M_MEM_RECALL` → `M_MEM_READ`/read_touch — context-gathering stamps the unfiltered RECALL_TOUCH survival trace), serializes the recalled scalars LE into the byte prompt (`context=M13-SCALAR-RECALL`; byte-payload records are a named deferral), runs the ROUTES-registered MOCK-DETERMINISTIC backend, folds `req_id ‖ op_hash(response)` into the M25 transcript BEFORE its closing GATE_VERDICT (the DIGEST, never the dump — the transcript grew to 5 frames, `tx_head` displaced by design, every other fold head byte-identical), then proves the WIRE legs: a MAC'd NOKEY probe answered by the keyless harness with a MAC'd closed-enum `ERR code=NO-KEY` (`wire-err-handled=0x1` — the fail-closed path transits the boundary in-boot) + the prompt as a MAC'd `INFER_REQ` answered with EXACTLY ONE MAC'd `INFER_PENDING` heartbeat (liveness plumbing, NEVER a completion) and the deterministic response as 2 MAC'd chunks the kernel reassembles, digest-verifies, and requires BIT-EQUAL to the in-kernel expectation (the cross-process determinism check), plus four in-boot negatives (badmac / digest-mismatch / oversize-reject / err-taxonomy). INJECTION-PROOFING (the guards are not line-anchored): ALL model-derived bytes cross serial ONLY lowercase-hex-encoded (`infer-dump:` lines — the regex-inert `[0-9a-f]` alphabet cannot forge an `M31:` marker/token or carry ESC; the run scripts pin the strict grammar + an ESC tripwire), with out-of-band `resp-len=` and the fixed-width `resp-digest=` commitment. HONEST SCOPE (machine-emitted): `backend=MOCK-DETERMINISTIC` (a transform, NOT a model — plumbing, never intelligence; the §7.8 strip-then-reject bans the vocabulary), `key=CAPREF-HOST-CUSTODIED` (no secret exists anywhere on the mock lane — the standing custody rule), `host=RESIDUAL-TCB`, `ambient=ZERO-IN-GUEST` (scoped in-guest ONLY), `sec=ASSUMED-FROM-LITERATURE`. **Stage C — the ANTHROPIC-LIVE bridge (`ureq`+`rustls`+`serde_json`, host-bridge-only), `real-infer.yml` (`workflow_dispatch`, never `pull_request_target`), the §5 challenge-nonce liveness protocol, `M31: real-infer OK backend=ANTHROPIC-LIVE` — is the OPERATOR'S lane: it needs the repo secret, is NEVER a required check, NEVER unattended, and its marker can never enter the cumulative chain (the mock lanes reject live/real vocabulary by name).** The NEW cumulative-tail marker | `M31: infer-e2e OK backend=MOCK-DETERMINISTIC` | none new (the wire legs reuse the M30 `arch::*::virtio::chan_*` session verbatim; ALL new value computation — the sub-header codec, per-chunk MAC, assembler, ERR enum, mock transform — is the pure `tb-encode::inferwire` extension, +6 `kani_infer*` harnesses → 96; the kernel stays zero-unsafe and matches on `InferWireProof`) |

Capability-passing IPC (M14) is the multi-agent north star and landed in three
serial steps: **M14** is the channel core — a `Handle` MOVES across address
spaces via the TRANSFER right with dup-attenuation (the auditable authority-flow
edge) over bounded ordered rings with peer-closed semantics, the cap carried by
handle, **zero** new unsafe; **M14.1** adds the variable-length byte payload
through a kernel-heap bounce buffer, where the mapping- and bounds-checked
`copy_to_user`/`copy_from_user` are the *only* M14 unsafe and are confined to the
new per-arch `arch/{x86_64,aarch64}/uaccess.rs` modules (`ipc.rs` stays
`#![forbid(unsafe_code)]`); **M14.2** closes the recv-blocks-off-the-run-queue /
send-wakes-the-peer scheduler↔IPC round-trip.

### M21 — a verified additive-policy seam for forget/demote, shipped *dormant*

M21 is the first milestone produced by the **research-first ultracode** workflow:
an honest, literature-grounded proposal
([`docs/proposals/M21-kan-policy.md`](proposals/M21-kan-policy.md), backed by
[`docs/research/kan-policy-literature.md`](research/kan-policy-literature.md))
that **reshaped** the naive plan before any code was written. The original
candidate — *"replace the M17 hand-tuned forget/demote constants with a learnable
in-kernel KAN"* — was deliberately rejected: the closest published analog (A-MAC)
won with a **linear** scorer, KANs beat MLPs only on symbolic regression (not
tabular scoring), and strong simple heuristics (SIEVE/TinyLFU) make the baseline
near-optimal. What survives is the part every research arm endorsed: the
*verifiable leaf* and the *safety seam*. So M21 ships a **Kani-proven,
total/bounded/monotone, fixed-point *additive* policy cell** (a piecewise-linear
integer GAM — a per-segment LUT + linear interpolation, no float, no "learning"
in-kernel), and the **"KAN/neural-net" framing is dropped**.

The cell lives in a new pure leaf, **`tb-encode::kancell`**
(`#![no_std] #![forbid(unsafe_code)]`, no float, zero-dep, host-buildable). It is
a **pure ranker strictly inside** the existing M17 heuristic safety envelope — the
**Black-Box Simplex / shielding** pattern. The envelope in `mem.rs` is
**unchanged and owns the decision**: `forget_sweep()` first applies the HARD
invariants (`MIN_AGE` grace, `IMP_PIN` flashbulb pin, `UTIL_PIN` utility pin, the
ordered Working→Semantic→Episodic→drop tier path) to compute the
eligible-and-safe candidate set, and **only then** calls `kancell::kan_score` to
produce the bounded score the **identical** `THETA_DEMOTE` comparator thresholds.
The consequence is the load-bearing safety property: the cell can only reorder /
threshold *within* the already-safe set — it can **never widen** the action set,
so even a signed-but-poisoned in-`i16` table is merely *suboptimal*, never
*unsafe*, and anti-starvation/liveness stay in the envelope's clock-hand counter,
never inferred from the cell. Monotonicity ("staler is never scored more
keepable") is enforced **by construction** on the integer knot table
(MonoKAN-style) and re-asserted at load with a solver-free sign check. The
**heuristic floor is always live**: if the table is absent, rejected by the
fail-closed loader, or its offline ship-gate margin was not met, the path falls
back to the tuned additive default with **zero behavioral change**. FRAMEKERNEL
is intact — `kancell` adds **zero** new `unsafe`/asm.

**M21 ships DORMANT (`active=0`).** Turning the spline *on* in the decision path
is a separate, evidence-bearing decision gated on a **pre-registered, falsifiable
bake-off**: the frozen GAM must beat a tuned linear/GDSF baseline on a held-out,
distribution-shifted eviction trace by a pre-registered margin. Yuva does not yet
have a real agent-memory eviction workload to replay, so **M21 builds and proves
the leaf + the fail-closed dormant seam** (the heuristic floor decides), and the
**activation is a tracked follow-up** (the trace-replay bake-off harness). This is
the honest division: the *verified machinery* is the milestone; the *activation*
waits for evidence.

The DoD is fail-closed and **anti-hollow-pass**. The boot self-test prints the
marker **only after** the in-kernel loader, on the *frozen integer table actually
shipped*, re-runs the monotonicity + overflow-safe validators **and** executes a
**real round-trip** proving the cell agrees with its shipped error bound — the
witness line

```
kan: monotone=1 ovf-safe=1 q-err=<delta> bound=<B> active=0
```

where `delta = max|float_score − kan_score|` is recomputed in-kernel over a fixed
probe vector baked next to the table, and the kan path is aborted (heuristic
restored, marker withheld) if `delta > B`. Because the dormant variant
`M21: kan-policy OK (heuristic floor, gate-not-met)` **contains** the
`M21: kan-policy OK` substring the run scripts grep, those scripts **reject** the
`(no table, skipped)` / skip variants and **positively require** the real `kan:`
witness with `active=0` — the same reject-skip + require-real-witness guard that
closed the M20 hollow-pass (and the guard itself is negative-tested to fire). The
six `kani_kan_*` harnesses (each with a documented **negative control**) land in
`tb-encode`; `scripts/verify-encode.sh` `EXPECTED_HARNESSES` and the `kani.yml`
count are bumped in **lockstep** so a vacuous or deleted harness reddens
`V1: kani-encoders OK` *before* M21 can claim its marker.

### M22 — a verified memory provenance ledger (mnemonic sovereignty)

M22, also a research-first proposal
([`docs/proposals/M22-memory-provenance.md`](proposals/M22-memory-provenance.md)),
makes the M13 memory store **tamper-evident**. It adds a per-agent, append-only,
**content-addressed hash-chain provenance ledger**: every memory mutation (write,
demote/tombstone, skill-admit) appends a typed `ProvEntry` whose **256-bit
digest** (structural FNV at landing; khash/BLAKE2s-256 since M29 stage C) folds
into a running per-agent `chain_head`. Crucially, **M17's
silent demote becomes a verifiable tombstone** (a `kind = forget` entry) — deletion
is *provable*, not silent — which the *Mnemonic Sovereignty* literature ranks as a
top-missing governance primitive for agent memory ("forgetting is the strongest
test of mnemonic sovereignty"). It composes existing milestones with almost no new
surface: `MemRecord` already carries typed DAG `links` + a `provenance` tag and
`SkillRecord` already carries `lineage`; the writer capability is M11's, the tiers
are M13's, the forget/tombstone is M17's.

The math is a new pure leaf, **`tb-encode::prov`** (`#![no_std]
#![forbid(unsafe_code)]`, no float, zero-dep): a **canonical, injective**
length-prefixed `ProvEntry` encoder (`canon`), the 256-bit digest (`prov_hash` —
at landing four domain-separated FNV-1a-64 lanes; **since M29 stage C the
Kani/KAT-verified `khash::uhash`, BLAKE2s-256 unkeyed**), the per-agent running
fold (`chain_mix`), and an inclusion verifier
(`verify_inclusion`). The kernel seam is **100% safe** (`ledger_append` in
`mem.rs`, invoked from the existing `write()` / `skill_add_class()` /
`forget_sweep()` mutation sites) — **zero** new `unsafe`/asm, FRAMEKERNEL intact.

**Honest scope (at landing):** M22 claimed **structural tamper-evidence only** — any single-byte
mutation to a committed entry invalidates the recomputed head and its inclusion
proof, *Kani-proved* over the fold. It explicitly did **NOT** claim cryptographic
collision / second-preimage resistance: the digest was fast/total/no-float FNV, not
a crypto hash, and an adversary who could *choose* inputs was out of scope.
**Since M29 stage C this concession is CLOSED:** `prov_hash` is the verified
`khash::uhash` (BLAKE2s-256 unkeyed) — cryptographic tamper-evidence,
assumption-conditional (collision/preimage resistance
`sec=ASSUMED-FROM-LITERATURE`, never prose-claimed). The head
is a **linear hash-chain fold, not a balanced Merkle tree**, and is held **in RAM
this milestone** — a crypto/keyed-hash + signed root, balanced-Merkle batch proofs,
and an M20-persisted reboot-surviving head are **tracked successors**. The boot
marker claims only what is proved.

The DoD is fail-closed and **anti-hollow-pass**. The self-test writes N ≥ 3 real
Region records, demotes one through the *actual* M17 `forget_sweep` (a tombstone
entry), asserts a genuine inclusion proof verifies `== true` on the clean ledger,
then **flips one byte of a *committed* entry** and asserts **both** head-mismatch
**and** inclusion-failure — exercising the real verifier path, not a constant
comparison. It prints the witness line then the marker:

```
prov: head=<hex> entries=<n> tamper-caught=1 inclusion=1
M22: provenance OK
```

A skip is **never** legitimate here (there is no device to be absent), so the run
scripts **reject** any `(no ledger, skipped)` variant and **positively require**
the `prov:` witness — and `M22: provenance OK` became **the cumulative-tail marker
both run scripts grep for** at its landing (replacing M20 as the final chain
marker; the tail has since moved along the chain and is `M31: infer-e2e OK backend=MOCK-DETERMINISTIC`
today). The six
`kani_prov_*` harnesses (each with a negative control; `canon`-injectivity is the
load-bearing proof, written before the kernel seam) land in `tb-encode`, bumping
`verify-encode.sh` `EXPECTED_HARNESSES` and the `kani.yml` count in lockstep.

### L2.0 — the first sovereignty-L2 rung (VMX-root / EL2 world-switch)

After M18 the kernel prints the first rung of the **L2 sovereignty track** —
Yuva as its own minimal Type-1 microhypervisor, replacing `/dev/kvm` with
`tb-core` (full plan: [SOVEREIGNTY-L2-ROADMAP](SOVEREIGNTY-L2-ROADMAP.md)). L2.0
emits **two** lines every boot, one per architecture; the off-arch line is a
green `n/a`:

- **x86_64 — `L2.0: vmxroot OK`.** The VMX-root path: `VMXON` → a minimal `VMCS`
  (host state from the live kernel context; a long-mode guest) → an EPT identity
  map → a `global_asm!` world-switch into a 1-instruction nested guest (`CPUID`)
  → catch its VM-exit via `VMREAD(exit-reason)` → `VMXOFF`. All silicon-unsafe is
  confined to the new `crates/tb-hal/src/arch/x86_64/vmx/` subtree, driven by the
  safe `tb_hal::vmx_selftest() -> VmxProof` facade. **Honest status: on the local
  and hosted-CI substrate this is a graceful skip.** QEMU-TCG (and the hosted
  GitHub runners) refuse the VMX CPUID bit, so the probe returns `Unavailable`
  and the marker prints as `L2.0: vmxroot OK (vmx unavailable, skipped)` — the
  same allow-skip discipline as `vmm-boot`. The **real** VMLAUNCH / world-switch
  / caught-exit proof is gated on a nested-VMX substrate (`-cpu host,+vmx` with
  L0 `kvm_intel nested=1`) that hosted CI lacks; that is the dedicated
  `l2-nested-vmx` lane, where the `Proven { exit_reason: 10 }` path fires and
  prints the bare `L2.0: vmxroot OK`. On aarch64 this line prints as
  `L2.0: vmxroot OK (x86-only, n/a on aarch64)`.
- **aarch64 — `L2.0: el2 OK`.** A **genuine, executing** nVHE EL2 world-switch.
  Yuva boots at **EL2** under QEMU `virt,virtualization=on,gic-version=2 -cpu
  cortex-a72`, installs a resident EL2 monitor (`VBAR_EL2` + `HCR_EL2.RW`), drops
  to EL1 so the entire M0..M18 chain runs at EL1 byte-for-byte, then issues a
  bootstrap `HVC #0` that the monitor `ERET`s into a tiny EL1 guest stub whose
  `HVC #1` traps back to EL2 and is caught and verified (magic `0xE12`) — a real
  EL1↔EL2 round-trip. The silicon-unsafe is confined to
  `crates/tb-hal/src/arch/aarch64/{boot,el2,el2_vectors}.rs` behind a safe
  `el2_selftest() -> El2Proof` facade. **This is the one L2 rung whose
  world-switch is NOT a CI skip** — it actually runs under pure TCG on a stock
  runner (`scripts/run-aarch64.sh` greps `el2 OK`). On x86_64 this line prints as
  `L2.0: el2 OK (aarch64-only, n/a on x86_64)`.

### The complete cumulative DoD-marker sequence

A green boot prints the M0–M4 foundation trace shown above, then the following
markers in order — every milestone runs cumulatively, so each boot is a full
regression of M0 through the cumulative tail `M31: infer-e2e OK backend=MOCK-DETERMINISTIC` (the listing
below is detailed through M22; after it the M23→M26 learning-loop arc, the M28
operator-inbound marker, the `M29: khash-mac OK` keyed-MAC marker, the `M30: infer-transport OK` transport marker and the NEW `M31: infer-e2e OK backend=MOCK-DETERMINISTIC` tail print in the §2 order
above, with `M27: sched OK` in its L2-track position between `L2.6` and M19):

```
tb-boot: contract v0 OK          # only on the tb-vmm / tb-boot v0 path
hello from rust_main             # M0
M1: traps OK
M2: context-switch OK
M3: mmu OK
M4: user/ring OK
M5: alloc OK
M6: frame alloc OK
M7: heap OK
M8: timer OK
M9: preempt OK
M10: addrspace OK
M11: caps OK
M12: agent OK
M13: memory OK
M14: ipc OK
M14.1: payload OK
M14.2: blocking-recv OK
M15: blocks OK
M15.1: unmap OK
M16: infer OK
M17: consolidate OK
M18: evolve OK
M18.1: approval-gate OK
M18.2: held-out OK
L2.0: vmxroot OK                 # x86_64: real proof on the nested-VMX lane, else "(vmx unavailable, skipped)"; aarch64 prints "(x86-only, n/a on aarch64)"
L2.0: el2 OK                     # aarch64: genuine EL2 world-switch under TCG; x86_64 prints "(aarch64-only, n/a on x86_64)"
L2.1: stage2 OK                  # aarch64: genuine stage-2 demand-translation round-trip under TCG; not-booted-at-EL2 prints "(no EL2, skipped)"; x86_64 prints "(aarch64-only, n/a on x86_64)"
L2.2: el2-exits OK               # aarch64: genuine ESR_EL2.EC exit-dispatch round-trip under TCG (WFx-resume + fail-closed inject-UNDEF default, classify_exit Kani-proven); not-booted-at-EL2 prints "(no EL2, skipped)"; x86_64 prints "(aarch64-only, n/a on x86_64)"
L2.3: el2-trap OK                # aarch64: genuine trap-and-EMULATE round-trip under TCG (HCR_EL2.TVM sysreg-write trap + HCR_EL2.VM MMIO device-IPA abort, SYS64/DABT ISS decoders Kani-proven, routed through the device_mmio SEAM, ELR_EL2 advanced +4 past each trapped insn); not-booted-at-EL2 prints "(no EL2, skipped)"; x86_64 prints "(aarch64-only, n/a on x86_64)"
L2.4: el2-guest OK               # aarch64: a REAL minimal Yuva guest at EL1 under our EL2 stage-2 with its OWN stage-1 MMU live -- a GENUINE two-stage walk (VA->guest-S1->IPA->our-S2->PA), the guest's own stage-1 walk itself S1PTW-re-translated; the guest BUILDS+ENABLES its stage-1 (reusing the proven make_entry/level_index + mmu.rs MAIR/TCR geometry; SCTLR_EL1.M via the Kani-proven sctlr_el1_guest_enable), stores+reads back a sentinel through a no-flat-meaning VA, AND takes its OWN EL1 brk trap (EL1->EL1, not an EL2 exit); magic 0x2E5 needs BOTH, with an independent EL2-side identity-alias readback the guest cannot fake; HVC#9 tears stage-2 down FIRST + the facade restores the kernel's TTBR0/TCR/MAIR/SCTLR/VBAR_EL1 (the new EL1-side teardown) so M19 resumes clean; the LITERAL full-kernel-as-guest is deferred to aL2.4b; not-booted-at-EL2 prints "(no EL2, skipped)"; x86_64 prints "(aarch64-only, n/a on x86_64)"
L2.5: vgic OK                    # aarch64: genuine vGIC virtual-interrupt injection + WFI scheduler-hook round-trip under TCG (GICH_LRn list-register vIRQ encode Kani-proven in tb-encode::el2_trap, the guest takes a virtual IRQ via our EL2 maintenance path); not-booted-at-EL2 prints "(no EL2, skipped)"; x86_64 prints "(aarch64-only, n/a on x86_64)"
L2.6: smmu OK                    # aarch64: genuine SMMUv3 stage-2 STE table-programming proof under qemu >= 9.0 (the SMMU stage-2 IS the CPU stage-2 geometry; STE + command-queue encoders Kani-proven in tb-encode::smmuv3); graceful "(no stage-2 SMMU, skipped)" on qemu < 9.0 where IDR0.S2P=0 (e.g. the 8.2.2 CI image); not-booted-at-EL2 prints "(no EL2, skipped)"; x86_64 prints "(aarch64-only, n/a on x86_64)"
M19: virtio OK                   # the kernel's FIRST real device I/O (poll-based virtio-mmio virtio-rng); Proven under TCG (ci) + KVM (microvm-kvm), graceful "(no device, skipped)" under tb-vmm
M20: persist OK                  # DURABLE PERSISTENCE -- a poll-only virtio-mmio virtio-blk (DeviceID 2) backs a log-structured store behind the M13 BackingStore seam; the selftest writes N sentinel records through a real Region, runs the TWO-PHASE flush (records -> VIRTIO_BLK_T_FLUSH -> superblock gen+1 -> FLUSH), DROPS the substrate (all RAM destroyed), RE-MOUNTS the same disk, replays the log, and asserts replayed==written + gen bumped by 1 -- a true durability round-trip (bytes left RAM, hit the device, came back on a fresh mount). All MMIO/DMA in arch/*/virtio.rs; the superblock/record-frame/req-header codecs are the Kani-proven tb-encode::blkfmt; the kernel branches on a pure-data PersistProof. Proven under TCG (ci) on both arches; graceful "(no disk, skipped)" where no -drive is attached (tb-vmm/vmm-boot stay green, unchanged)
M21: kan-policy OK               # VERIFIED FIXED-POINT ADDITIVE-POLICY SEAM for the M17 forget/demote decision -- a Kani-proven total/bounded/monotone integer GAM (tb-encode::kancell) that may only RANK WITHIN the unchanged M17 heuristic envelope; SHIPS DORMANT (active=0). Witness: "kan: monotone=1 ovf-safe=1 q-err=0x.. bound=0x.. active=0" (the in-kernel q-err<=bound round-trip on the frozen integer table). DORMANT variant "(heuristic floor, gate-not-met)" is allowed and CONTAINS the grepped substring -> the run scripts REJECT "(no table, skipped)" and POSITIVELY REQUIRE the kan: witness with active=0; the spline is gated on a held-out trace bake-off that is a tracked follow-up
M22: provenance OK               # VERIFIED MEMORY PROVENANCE LEDGER -- a per-agent content-addressed hash-chain over M13; every mutation appends a typed ProvEntry whose 256-bit digest (Kani-proven tb-encode::prov; since M29-C the khash::uhash BLAKE2s-256 — cryptographic, sec=ASSUMED-FROM-LITERATURE; two domain-separated FNV-1a-64 lanes at landing) folds into a running chain_head; M17 forget emits a TOMBSTONE entry (deletion is provable, not silent). The selftest writes N>=3 records, demotes one via the real forget_sweep, asserts a clean inclusion proof verifies, then flips one byte of a COMMITTED entry and asserts BOTH head-mismatch AND inclusion-fail. Witness: "prov: head=0x.. entries=0x.. tamper-caught=0x1 inclusion=0x1". Head is in-RAM this milestone (M20-persisted head is a tracked successor); a "(no ledger, skipped)" variant is NEVER legitimate and the run scripts reject it. The cumulative-tail marker from M22's landing until the M23 arc; the tail both run scripts grep for is now M28's
```

Each line is a hard `grep` target in the per-arch run script; a missing or
`FAIL` marker is always a non-zero exit (the run scripts bound the boot with a
wall-clock timeout, since the kernel halts after the last marker rather than
exiting).

### Verification posture

Two machine-checked guarantees back the chain:

- **M11 capability proof (Kani).** The rights-subset / no-confused-deputy
  invariant — *a capability meta-op can only ever narrow authority, and a forged
  handle resolves to no authority beyond its slot's* — is machine-proven by
  **Kani** over `crates/tb-caps-core`, the **single source of truth** for the
  `Rights` algebra and the generation-checked `CapTable`. `tb-hal` re-exports
  `Rights`/`Handle`/`SysStatus` verbatim and wraps `CapTable<Rc<Object>>`, so the
  kernel and the proofs verify the **exact same code — zero model drift**. The
  suite is **12 `#[kani::proof]` harnesses** (`crates/tb-caps-core/src/proofs.rs`)
  in three tiers: the `Rights` algebra over the full 2³² bit space (complete
  bit-vector proofs), one proof per capability operation on the real `CapTable`,
  and an inductive single-step no-widen preservation proof (plus a
  bounded-sequence cross-check and a documented negative control that fails if
  `intersect`'s `&` is swapped for `|`). The `.github/workflows/kani.yml` lane
  runs `cargo kani -p tb-caps-core` and `scripts/verify-caps.sh` **fails closed**
  unless every harness verifies *and* the success count equals the pinned
  constant, then emits `M11: caps-subset PROVEN`. This is what makes M18's
  frozen-kernel boundary a proof and not a hope: M18's self-improvement safety
  **reduces to** this M11 invariant (the held-out evaluators are simply objects
  no agent's handle table can ever name).
- **Encoder/parser proof (Kani).** The silicon-unsafe **value computation** that
  feeds `tb-hal`'s MMIO / VMCS / page-table writes — entangled bit-algebra that a
  wrong constant turns into a silent VM-entry failure — was extracted into a NEW
  pure `crates/tb-encode` (`no_std`, `#![forbid(unsafe_code)]`, host-buildable;
  `tb-hal` now CALLS it, the `vmwrite`/`read_volatile`/asm staying behind) and is
  machine-proven by **Kani**. The suite now totals **90 `#[kani::proof]`
  harnesses** across 20 leaves: the control-MSR adjust-legality gate (force all allowed-0 bits,
  clear all non-allowed-1 bits, under the Intel allowed0⊆allowed1 precondition),
  the CR0/CR4 fixed-bit clamp, the page-table / EPT entry encoders (address +
  flags preserved, level index < 512, EPTP well-formed), the 16-byte IPC frame
  round-trip + total fail-closed decode of untrusted bytes, a bounded no-alloc
  ring, the fixed-point memory-scoring lemmas — and, landed with **L2.1**, **five
  new aarch64 stage-2/el2_trap lemmas** in
  `crates/tb-encode/src/{stage2,el2_trap}.rs`: the stage-2 (VMSAv8-64) leaf and
  table/`VTTBR_EL2` descriptor round-trips with address + `S2AP`/attribute
  preservation (`kani_s2_leaf_wellformed`, `kani_s2_table_and_vttbr`), `VTCR_EL2`
  well-formedness catching the SL0/T0SZ off-by-one (`kani_vtcr_wellformed`), and
  the total `ESR_EL2` / `HPFAR_EL2` abort-syndrome decode the EL2 monitor imports
  verbatim — the `EC` class (`0x24` Data-Abort / `0x20` Instruction-Abort /
  `0x16` HVC64) and the faulting IPA (`kani_esr_decode_total`,
  `kani_hpfar_fault_ipa`). The `.github/workflows/kani.yml` `prove-encode` job
  runs `cargo kani -p tb-encode` and **fails closed** unless every harness
  verifies *and* the success count equals the pinned `EXPECTED_HARNESSES = 90`
  (`scripts/verify-encode.sh`, bumped from 15 in lockstep across the L2.1–L2.6
  rungs and the M20–M30 leaves: +5 stage-2/ESR, +1 exit-classifier, +2
  sysreg/DABT ISS, +1 SCTLR_EL1, +1 GICH_LR0 vIRQ, +3 SMMUv3 stage-2, +6 `blkfmt`
  durable-persistence codecs (M20), +6 `kancell` additive-policy (M21), +6 `prov`
  ledger (M22), +23 across the M23–M26 learning-loop / operator-transcript /
  exit-telemetry leaves (`exp`, `explore`, `bakeoff`, `opframe`, `exittel`), +5
  `tpsched` two-VMID scheduling (M27), +6 `opframe_rx` operator-inbound
  command-gate harnesses (M28, the `kani_cmd_*` suite), and +4 `khash`
  keyed-hash primitive harnesses (M29, the `kani_khash_*` suite — concrete
  official-vector/flip-index proofs ONLY; primitive security deliberately
  unproven, `sec=ASSUMED-FROM-LITERATURE`), and +6 `inferwire`
  inference-transport codec harnesses (M30, the `kani_inferwire_*` suite —
  concrete-frame / short-symbolic codec/accumulator proofs + the host-keyed
  echo at 2 compressions per khash call, each mutation-tested per the M30
  proposal §6)), then emits
  `V1: kani-encoders OK`. The twenty `tb-encode` leaves are now `vmx`,
  `paging`, `ipc_frame`, `route`, `memscore`, `stage2`, `smmuv3`, `el2_trap`,
  `blkfmt`, `kancell`, `prov`, `exp`, `explore`, `bakeoff`, `opframe`,
  `exittel`, `tpsched`, `opframe_rx`, `khash`, and `inferwire`. Each harness must be **tractable**
  (bounded symbolic / concretized-hash inputs — the `#49` symbolic-array
  state-explosion is the documented trap) and carries a **negative control**. (The `tb-caps-core` M11 proof is the independent
  `prove-caps` job in the same workflow; neither can break the other.)
- **Tier-0 UB gate (Miri).** `cargo miri test -p brand -p tb-caps-core -p tb-encode`
  interprets the EXACT pure host-runnable leaf crates the kernel runs (the same
  code Kani verifies — **zero model drift**) under the MIR interpreter, checking
  every path for undefined behaviour (OOB, use-after-free, uninit reads, invalid
  enum/bool, misalignment, integer overflow, strict-provenance) — especially the
  `tb-encode` `MessageFrame::decode` untrusted-byte parser and the `tb-caps-core`
  `CapTable` mint/dup/narrow/transfer/revoke sequences. `tb-hal` + the `kernel`
  are **excluded** (inline asm + the `os=none` target the MIR interpreter cannot
  execute; the gate is `-p`, never `--workspace`). Fail-closed: any UB or failing
  test makes the run exit non-zero before `T0: miri OK` echoes
  (`.github/workflows/miri.yml`).
- **Framekernel invariant.** All `unsafe` + asm is confined to `crates/tb-hal`.
  The `kernel` crate contains **zero `unsafe {}` blocks** (it is not crate-level
  `#![forbid(unsafe_code)]` only because `#[unsafe(no_mangle)]` on `rust_main` is
  itself an unsafe *attribute*, which the `unsafe_code` lint flags). The pure
  leaves — `tb-caps-core` and `tb-hal`'s `caps.rs`/`mem.rs`/`ipc.rs`/`blocks.rs`/
  `infer.rs` (plus `heap.rs`/`pmm.rs`) — are literally `#![forbid(unsafe_code)]`.

Nine CI gates across eight workflow files guard the tree:

| Gate | Workflow | What it proves |
|---|---|---|
| **ci** | `ci.yml` | build + boot both arches under pure QEMU-TCG; greps the cumulative serial marker (M0..M30; the aarch64 boot runs in a `debian:trixie-slim` qemu-10 container because the L2.6 SMMUv3 stage-2 rung needs qemu ≥ 9.0, with the virtio-blk disk attached + since M30 both lanes spawn the xport-harness host echo peer against a QEMU virtconsole chardev socket and CROSS-PROCESS-compare the M30 challenge/tag) |
| **vmm-boot** | `vmm-boot.yml` | `tb-vmm` boots the kernel via the sovereign `tb-boot v0` contract on x86_64 `/dev/kvm`, asserting M4 + the boot-time bench (allow-skip when KVM is absent) |
| **l2-nested-vmx** | `l2-nested-vmx.yml` | informational/continue-on-error — the **real** L2.0 VMX-root verdict under nested KVM (`-cpu host`), checking the chain reached `M18: evolve OK` |
| **microvm-kvm** | `microvm-kvm.yml` | boots the kernel under QEMU `-M microvm -accel kvm -cpu host` and asserts the cumulative chain reaches `M18: evolve OK` (the THIRD boot config beyond ci/TCG + vmm-boot; the #36 LAPIC/LVT regression guard); also captures the non-blocking `--release` `boot-ready-cycles` figure quoted in BENCHMARKS §3; allow-skip when `/dev/kvm` is absent |
| **kani** | `kani.yml` | three jobs — `prove-caps` (the M11 rights-subset proof over `tb-caps-core` → `M11: caps-subset PROVEN`, 12 harnesses) and the #101 cost-balanced shard pair `prove-encode-a`/`prove-encode-b` (the `tb-encode` encoder/parser proofs → `V1-shard-a: kani-encoders OK` / `V1-shard-b: kani-encoders OK`, 46 + 44 of the 90 harnesses; lists + pinned counts in ONE place, `scripts/kani-shards.sh`, with the fail-closed disjoint+exhaustive completeness guard run in BOTH jobs; local `SHARD=all` keeps the single 90-harness pass → `V1: kani-encoders OK`); Kani runs in this lane and is also installed locally in WSL (`cargo-kani`) — measure a new/changed harness with `cargo kani -p tb-encode --harness <name>` BEFORE pushing, since the prove-encode-* lanes have hard timeouts |
| **miri** | `miri.yml` | the Tier-0 UB gate → `T0: miri OK` (`cargo miri test -p brand -p tb-caps-core -p tb-encode`) |
| **clippy** | `clippy.yml` | static-lint `-D warnings` over the forbid-unsafe leaf crates (`tb-caps-core`/`tb-encode`/`tb-boot`) → `S0: clippy OK` |
| **bench** | `bench.yml` | non-blocking `tb-vmm` vs Firecracker boot benchmark (BENCHMARKS Axis-A) |

## 3. Development pipeline

Each milestone was built with the same loop, and the same loop applies going
forward:

1. **Generate** — a multi-agent workflow authors the milestone code against a
   fixed contract plus the verified hardware facts (3 generator agents:
   x86_64 / aarch64 / integration+test).
2. **Adversarially review** — 2 independent reviewer agents check
   privilege/boot/MMU correctness and build/regression, returning concrete
   blockers with fixes.
3. **Apply** — the generated files are written into the tree and reviewer
   findings are applied.
4. **Build** — both architectures are cross-compiled on a Linux host
   (see [BUILD](../BUILD.md)).
5. **Boot & assert** — each arch is booted under QEMU; the run script greps the
   serial output for the milestone marker and fails closed otherwise. This step
   is where real bugs surface (it has repeatedly caught issues a static review
   missed).
6. **Commit** — one conventional commit per milestone.

## 4. Build & run (quickstart)

Full instructions and toolchain bootstrap are in [BUILD.md](../BUILD.md). In
short, on a Linux host (or WSL2) with a Rust nightly that has `rust-src` +
`llvm-tools`, and `qemu-system-x86`/`qemu-system-arm` installed:

```sh
# Build (per arch)
cargo kbuild --target targets/x86_64-yuva-none.json
cargo kbuild --target targets/aarch64-yuva-none.json

# Boot under QEMU and assert the milestone marker (exit 0 = PASS)
bash scripts/run-x86_64.sh
bash scripts/run-aarch64.sh
```

CI runs exactly this matrix on every push — see
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

### The run scripts

- `scripts/run-x86_64.sh` — boots the PVH ELF under QEMU `microvm` (the machine
  type Firecracker is modelled on), wires the 16550 COM1 to stdio, and asserts
  the marker. Uses KVM only if `/dev/kvm` is usable; otherwise pure TCG, so it
  runs in any CI box without nested virtualization.
- `scripts/run-aarch64.sh` — boots under QEMU `virt` (`cortex-a72`), PL011
  serial on stdio, same marker assertion.

Both bound the run with a wall-clock timeout (the kernel halts after the last
milestone rather than exiting), so a missing marker is always a non-zero exit.

## 5. What's next

The v2 agent-native chain (M0–M18) and the **L1** sovereignty rung (`tb-vmm`) are
complete and CI-green; **L2.0** (the first **L2** rung) has landed. What remains
is the rest of the L2 track plus a set of named debts:

- **L2 — `tb-core`** (the **north-star**): Yuva as its own minimal Type-1
  microhypervisor (own VMX/SVM/EL2 + EPT/stage-2 + IOMMU + sovereign scheduling,
  <10K-LOC TCB), replacing `/dev/kvm` and quarantining the proprietary GPU/CUDA
  stack in a confined Linux driver VM — where **full sovereignty** lands. **L2.0 and L2.1 are done** (x86_64 `vmxroot`
  — a graceful skip pending a nested-VMX lane; aarch64 `el2` — a genuine
  executing EL2 world-switch under TCG; and aarch64 `L2.1: stage2 OK` — a genuine
  stage-2 demand-translation round-trip under TCG, the ARM analog of x86
  EPT-violation handling; see §2). The **active rung is the aarch64 L2 chain**,
  which advances **CI-green under pure TCG** on a stock runner with no hardware,
  no `/dev/kvm`, and no nesting; the x86 `L2.1`–`L2.6` chain (EPT-demand handling
  onward) is **gated on the #37 nested-VMX substrate** — a hardware-provisioning
  task for Arda, not a coding gap (QEMU-TCG emulates no Intel VMX, and stock CI
  runners expose no second VMX level). The
  ten-rung plan L2.0→L2.9 (EPT-demand handling, the full exit set, the
  device-model seam, the real-Yuva nested guest, sovereign scheduling, SMP, the
  bare-metal UEFI Type-1 launch, the IOMMU, and the full split-VMM) is tracked in
  **[SOVEREIGNTY-L2-ROADMAP](SOVEREIGNTY-L2-ROADMAP.md)** (ladder context:
  [SOVEREIGNTY-ROADMAP](SOVEREIGNTY-ROADMAP.md)).
- **aarch64 `tb-vmm` backend** — `tb-vmm` configures the x86_64 vCPU only; an
  aarch64 arch backend (`KVM_ARM_VCPU_INIT`) plus an aarch64 `tb-boot` producer +
  an `_tb_start`-equivalent EL1 entry are the prerequisites for an ARM L1/L2 boot
  path (today the aarch64 kernel `_start` consumes `x0`=FDT).
- **Durable persistence** — **DONE at M20.** M13's tiered substrate was RAM-backed
  behind a `BackingStore` trait; M20 lands `VirtioBlkStore: BackingStore` over a
  poll-only virtio-mmio virtio-blk device, log-structured with a two-phase-commit
  `flush()` and a mount/replay that rebuilds the journal across reboots
  (`M20: persist OK`). Crash-consistency is scoped to clean-flush durability (the
  commit point); crash-at-an-arbitrary-point is a named non-claim (a torn tail past
  the committed superblock is ignored on replay, not recovered).
- **SMP** — M0–M18 are single-vCPU (preemptive time-multiplex on one core); SMP
  is the biggest latent debt and is first designed at L2.6.
- **Real inference backends** — M16 ships a deterministic mock provider; the real
  Anthropic/OpenAI adapters and the vsock GPU/CUDA driver-VM sit behind the same
  `InferBackend` trait on the L2 track.
- **G0 spec-freeze** — closing the remaining P0 open questions
  ([OPEN-QUESTIONS](OPEN-QUESTIONS.md)) before freezing the v1 ABI.
