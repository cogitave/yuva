# M27 literature survey — two-VMID sovereign time-partition scheduling

Companion to [`docs/proposals/M27-sovereign-scheduler.md`](../proposals/M27-sovereign-scheduler.md). This is **Strand B** of the M26 research-first survey, promoted to its own milestone. It grounds the minimal first-increment that fits the autonomous-CI + verified-leaf + no-float + anti-hollow discipline. Where M27 goes beyond a source it is flagged **[BEYOND]**.

---

## The requirements anchor — time partitioning

- **ARINC 653 (APEX) specification.** The canonical two-level time-partition model: a **major frame** of fixed windows, with **temporal isolation** between partitions (one partition's overrun cannot steal another's window). A two-VMID time-partition is the minimal ARINC-653 major frame (two windows). M27 adopts the *structure* (fixed major frame, per-window budget) — **not** the *guarantee* (no WCET/schedulability proof; see the honest caveat).

## The closest architectural analog — and the design fork

- **Martins, Tavares, Pinto et al., "Bao: A Lightweight Static Partitioning Hypervisor," 2020** + **"Shedding Light on Static Partitioning Hypervisors for Arm-based MCS," arXiv:2303.11186.** Bao is the closest analog to the TABOS EL2 nVHE monitor: clean-slate, Armv8/RISC-V, thin, leverages ISA virtualization primitives — and notably **Bao has no scheduler** (pure static spatial partitioning, one vCPU pinned per core). **That is the design fork**: M27 adds the *minimal time-partition scheduler* Bao deliberately omits, to multiplex **two** VMIDs on one core. The Arm SPH survey gives the comparative landscape (Jailhouse, Xen Dom0-less, Bao, seL4 CAmkES VMM) and the real-time/latency framing.

## The architectural mechanism — the EL2 physical timer

- **ARM Generic Timer architecture — `CNTHP_CTL_EL2`, `CNTHP_TVAL_EL2`, `CNTHP_CVAL_EL2`, `CNTHCTL_EL2`** (Arm ARM DDI 0487 / DDI 0601 register pages; **Christoffer Dall, "Arm Timers and Fire," KVM Forum 2018**). The exact mechanism: the **EL2 physical timer** is the sovereign preemption tick. Writing `CNTHP_TVAL_EL2` snapshots `CNTPCT` + delta into `CNTHP_CVAL_EL2`; `CNTHP_CTL_EL2.ENABLE/IMASK/ISTATUS` arm it; firing routes a PPI to EL2. `CNTHCTL_EL2` controls the EL1/EL0 timer-register trapping. This is what lets the monitor preempt a guest off its OWN timer, not the guest's.
- **Intel SDM Vol. 3C — the VMX-preemption timer** (a 32-bit VMCS field counting down at a TSC-proportional rate, forcing a VM-exit at zero) is the x86 dual — same semantics, different ISA. **Deferred** (x86 L2 is hardware-gated, #37).

## The verified/sound scheduling grounding

- **Lyons, McLeod, Almatary, Heiser, "Scheduling-Context Capabilities: A Principled, Light-Weight OS Mechanism for Managing Time," EuroSys 2018**, and the **seL4 MCS line** (trustworthy.systems RTA project; Heiser et al. RTCSA 2020). The strongest *verified/sound* scheduling work: capability-authorized CPU time, budget+period enforcement, temporal integrity — with the MCS proofs (ARM_MCS/RISCV64_MCS) in progress. This is the formal-grounding citation and the model to *gesture at* without reimplementing (M27 has neither a capability-scheduled budget model nor a temporal-integrity proof — it has a fixed round-robin with a verified partition function).
- **Response-time analysis / time-partition schedulability** (classic RTA, Joseph & Pandya; the temporal-isolation assessment in arXiv:2208.14109 for virtualized partitioning). Grounds the claim that a fixed two-window major frame is *analyzable* for isolation — though M27 does not perform the analysis (no WCET inputs).

---

## The minimal first-increment (what M27 ships)
A **verified leaf** + a **HAL action**, matching the framekernel split:
- **Leaf `tb-encode::tpsched`** — the pure scheduling math: a fixed two-slot major frame (`next_slot` round-robin, `slot_deadline_delta` = the `CNTHP_TVAL_EL2` countdown, `frame_total` conservation), plus an injective `canon`/`decode` of each `SchedDecision` folded into the experience stream (the M22 fold reused — observational, NOT learned). Kani: `next_slot` totality + round-robin liveness, frame conservation (no slot starves / monopolizes), canon injectivity, fold tamper-sensitivity.
- **HAL action (`tb-hal/arch/aarch64`)** — arm `CNTHP_TVAL_EL2`/`CNTHP_CTL_EL2`, and on the timer PPI consult the leaf + switch `VTTBR_EL2`/VMID to the other guest (the L2.1–L2.6 world-switch machinery reused).
- **DoD under QEMU-TCG** — two trivial guests under two VMIDs; the marker asserts **both VMIDs made forward progress within one major frame** (a witnessable interleave — each guest bumps a distinct MMIO cell the monitor counts), driven entirely by the architectural timer with no host scheduler. TCG models the Generic Timer, so this is autonomously buildable.

## Honest caveats (encoded as marker tokens)
| Claim | M27? | Token |
|---|---|---|
| Deterministic two-VMID time-partition alternation under the EL2 timer | **YES** | `both-progressed=1 order-honored=1` |
| The partition function is total / no-panic / frame-conserving | **YES** (Kani) | `frame-conserved=1` |
| Each scheduling decision is recorded tamper-evidently | **YES** (M22 fold) | `fold-verified=1 tamper-caught=1` |
| Real-time / schedulability / WCET guarantee | **NO** (fixed round-robin, no WCET) | `realtime=NOT-CLAIMED` |
| Cycle-accurate timing | **NO** (TCG) | `timing=TCG-NON-CYCLE-ACCURATE` |
| A learned/adaptive schedule | **NO** (fixed; OBSERVATIONAL record only) | (implied — the M26 confounding firewall) |
| A Firecracker replacement | **NO** (demonstrator: two guests, no migration/devices/SMP) | (prose) |

## [BEYOND] the literature
- **A sovereign EL2 time-partition scheduler whose every decision is appended to a verified tamper-evident experience ledger** is not in the prior art: Bao has no scheduler; ARINC-653/seL4-MCS schedulers do not fold decisions into a content-addressed provenance chain. The fold (sovereignty → learning) is the novel bit; the time-partition mechanism is well-trodden — claim the novelty narrowly.
- **A Kani-proven no-float partition-function leaf** (totality + conservation + round-robin liveness) driving real EL2 silicon — the verified-leaf discipline applied to scheduling.

## Why M27 before M28
M27 (sovereignty) and M28 (the operator inbound capstone) both feed the same `xp_head`/experience stream. M27 is the natural next step: it reuses the L2 world-switch + the M22/M26 fold, advances the sovereignty pillar concretely, and its risk (a new EL2 runtime + a two-guest harness) is lower than M28's (a keyed construction whose `KEYED-NONCRYPTO`-vs-`KEYED-CRYPTO` honesty boundary is the biggest hollow-marker risk in the roadmap). M28 is the capstone — it delivers the activation command the entire learning loop was built to receive — so it lands last.
