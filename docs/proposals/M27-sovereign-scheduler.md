---
type: Design Decision
title: "M27 — Two-VMID Sovereign Time-Partition Scheduler"
description: "Proposes a two-slot major-frame scheduler multiplexing two guest VMIDs off the EL2 physical timer; observational, not real-time."
tags: ["m27", "scheduler", "sovereignty", "el2", "aarch64", "kani"]
timestamp: 2026-06-10T18:59:15+03:00
status: locked
diataxis: explanation
---

# M27 — Two-VMID sovereign time-partition scheduler (the sovereignty pillar advances)

**Status:** proposed (build) · **Pillar:** sovereignty ("replace Firecracker") + a bridge to learning · **Depends on:** L2.0–L2.6 (the EL2 nVHE world-switch + stage-2 + VMID machinery), M22/M23 (the experience fold), M26 (the exit-telemetry producer pattern) · **Marker:** `M27: sched OK`

> **One-line:** the aarch64 EL2 (nVHE) monitor already world-switches a guest by programming `VTTBR_EL2`/`VMID` + stage-2 (L2.1–L2.6). M27 adds the **minimal sovereign scheduler** that monitor deliberately lacks: a fixed **two-slot major frame** that time-partitions **two guest VMIDs** using the architectural **EL2 physical timer** (`CNTHP_*_EL2`), with each scheduling DECISION folded into the experience stream (observational, reusing the M22/M26 fold). The whole timing geometry — the slot function, the frame conservation, the VMID alternation — is a **Kani-proven `tb-encode::tpsched` leaf**; the silicon (timer arm + `VTTBR_EL2`/VMID switch on the timer PPI) stays in `tb-hal`. **Autonomously buildable** under QEMU-TCG (which models the Generic Timer): the DoD witnesses **both VMIDs making forward progress within one major frame**, driven by the timer alone with **no host scheduler**.

This is the output of the M26 research-first survey (Strand B — see [`docs/research/m27-sovereign-scheduler-literature.md`](../research/m27-sovereign-scheduler-literature.md)). Every mechanism is cited; the honest caveats (NOT real-time, NOT schedulability-proven, NOT a Firecracker replacement) are encoded as marker tokens.

---

## 1. Why this is M27 (and why it is the sovereignty step)

The L2 chain proved TABOS can **be the hypervisor** for a guest (world-switch, stage-2, exit-dispatch, trap-and-emulate, nested-EL1 guest, vGIC, SMMUv3). What it has never done is **own time** — schedule *more than one* guest, sovereignly, off its own timer. **Bao** (the closest architectural analog to our EL2 monitor) deliberately **has no scheduler** (pure static partitioning); ARINC-653 / seL4-MCS schedulers are not folding their decisions into a verified provenance chain. M27 is the minimal step across that line: two VMIDs, a fixed major frame, the EL2 timer — the demonstrator that TABOS can sovereignly multiplex guests. It also **bridges to learning**: each scheduling decision becomes an experience record (the sovereignty → learning edge the vision calls for), reusing M26's producer pattern.

M27 is **Strand B** of the M26 survey's three; **M28** (the operator INBOUND channel / `opframe` RX — the exogenous-oracle capstone) follows.

---

## 2. The design (cited, mechanism by mechanism)

### 2.1 The verified scheduling math — a new `tb-encode::tpsched` leaf
A new `tb-encode::tpsched` leaf (no_std, forbid-unsafe, no-float, zero-dep, Kani-proven). The pure timing geometry of a **fixed two-slot major frame**:
- A `FramePlan { slot_ticks: [u64; N_SLOTS], vmid: [u16; N_SLOTS] }` (`N_SLOTS = 2`): each slot grants its VMID a fixed tick budget; the frame is the sum.
- `next_slot(current_slot) -> usize` — the round-robin successor (a total `(current + 1) % N_SLOTS`).
- `slot_deadline_delta(plan, slot) -> u64` — the `CNTHP_TVAL_EL2` countdown value to arm for `slot` (the slot's `slot_ticks`, saturating).
- `frame_total(plan) -> u64` — the conserved major-frame length (saturating sum; no slot starves, budgets sum to the frame).
- A fixed-field injective `canon`/`decode` of a **`SchedDecision` { frame_seq, slot, vmid_from, vmid_to, t_logical }**, folded into the experience stream via the M22 fold reused verbatim (under a NEW `kind::SCHED_DECISION` tag) — the sovereignty → learning record. OBSERVATIONAL (it records which VMID ran when, it does not *learn* a schedule).

This is the ARINC-653 *two-window major frame* reduced to its decidable core (ARINC 653 APEX; the requirements anchor).

### 2.2 The architectural mechanism — the EL2 physical timer (`tb-hal`)
The silicon stays in `tb-hal/arch/aarch64`. The existing EL2 world-switch already programs `VTTBR_EL2`/`VMID`; M27 adds the **preemption tick**:
- Arm `CNTHP_TVAL_EL2` (write the slot's `slot_deadline_delta` — the architecture snapshots `CNTPCT` + delta into `CNTHP_CVAL_EL2`), enable via `CNTHP_CTL_EL2.ENABLE`, route the EL2 physical-timer PPI to the EL2 vector (`CNTHCTL_EL2`). (Arm ARM DDI 0487 / DDI 0601 timer register pages; Dall, "Arm Timers and Fire," KVM Forum 2018.)
- On the timer PPI at EL2: consult `tpsched::next_slot`, switch `VTTBR_EL2`/`VMID` to the next slot's guest (the L2.1–L2.6 machinery, reused), re-arm `CNTHP_TVAL_EL2` for the new slot, record the `SchedDecision`, `ERET` into the next guest. (The x86 dual is the Intel SDM Vol. 3C VMX-preemption timer — out of scope this milestone, x86 L2 is hardware-gated.)

### 2.3 The two guests + the forward-progress witness
Two trivial EL1 guests under two VMIDs (each a tiny stub in its own stage-2 view — reuse the L2.4 nested-EL1-guest machinery). Each guest, when running, bumps a **distinct MMIO cell** the EL2 monitor counts (a trap-and-emulate device, reusing the L2.3 MMIO seam). After K major frames the monitor asserts **both cells advanced** — i.e. both VMIDs were scheduled and made forward progress, driven by the timer alone.

---

## 3. DoD — `M27: sched OK` (the boot self-test)
The boot self-test (QEMU/TCG, no human/network/extra-hw) arms the two-VMID major frame, runs K frames under the EL2 physical timer, and verifies: (a) both VMIDs advanced their MMIO cell (forward progress — neither starved); (b) the observed VMID sequence matches the `tpsched` plan's round-robin (the schedule was honored); (c) the folded `SchedDecision` head matches a recompute + a genuine inclusion proof; (d) a single-byte tamper of a committed decision is caught; (e) the frame is conserved (`frame_total == sum of slot budgets`). It prints, fail-closed:
```
sched: head=<hex16> frames=<k> vmids=<2> both-progressed=1 order-honored=1 fold-verified=1 tamper-caught=1 frame-conserved=1 timing=TCG-NON-CYCLE-ACCURATE realtime=NOT-CLAIMED
M27: sched OK
```
The run-scripts positively **require** the `sched:` witness with `both-progressed=1 order-honored=1 fold-verified=1 tamper-caught=1 frame-conserved=1`, **require** the honesty tokens `timing=TCG-NON-CYCLE-ACCURATE` + `realtime=NOT-CLAIMED`, **reject** any `(no EL2, skipped)`/`(single guest)` degenerate variant, and **reject** any `validated`/`real-time`/`WCET`/`guaranteed` near the marker. `EXPECTED_HARNESSES` 69 → ~73.

> **The aarch64-only + skip honesty.** Like L2.0–L2.6, this is aarch64-real / x86-n/a. If a runner's QEMU lacks the EL2 physical timer (it does not — TCG models CNTHP), the lane degrades to a LOUD `::warning::` skip, never a silent pass.

---

## 4. Kani obligations (each with a negative control; measure locally first)
1. **next_slot totality + round-robin** — `next_slot` is total over `0..N_SLOTS` and strictly cycles (slot 0→1→0); no slot is unreachable. *Neg:* an `% (N_SLOTS-1)` typo makes slot 1 a fixed point (VMID 1 starves).
2. **frame conservation** — `frame_total == Σ slot_ticks` (saturating), and every slot's `slot_deadline_delta` is in `[1, frame_total]` (no zero-budget slot → no starvation; no over-budget slot → no monopoly). *Neg:* a slot budget of 0 lets its VMID never run; the conservation assert fires.
3. **canon injectivity + totality** — distinct `SchedDecision`s → distinct bytes; total + fail-closed. *Neg:* dropping `vmid_to` lets two decisions alias.
4. **fold tamper-sensitivity** — a single-byte flip of a committed decision changes the head (reuse the M22 fold proof). *Neg:* a constant fold accepts a tampered decision.

---

## 5. Honest caveats (conceded — encoded as witness tokens)
- **NOT real-time, NOT schedulability-proven (`realtime=NOT-CLAIMED`).** A fixed two-slot round-robin is deterministic alternation, NOT an ARINC-653 *guarantee* or an seL4-MCS *temporal-integrity proof* — there are no WCET bounds and no verified preemption-latency model. We claim only: deterministic time-partitioned alternation of two VMIDs under the architectural timer, the partition function verified total/no-panic, each decision recorded tamper-evidently.
- **TCG timing is not cycle-accurate (`timing=TCG-NON-CYCLE-ACCURATE`).** "Forward progress within a frame" is a liveness/interleave witness, NOT a timing measurement; the slot budgets are a relative shape under emulation. Do not quote latencies.
- **Two VMIDs is a sovereignty DEMONSTRATOR, not a Firecracker replacement.** The Firecracker/Cloud-Hypervisor vCPU-thread model we aim to replace has live migration, device models, rate-limiting, SMP — none of that is in scope. M27 proves TABOS can sovereignly multiplex *two* guests off its own timer; production multi-tenancy is far ahead.
- **The scheduler is OBSERVATIONAL, not LEARNED.** The `SchedDecision` records which VMID ran when; the schedule is a FIXED round-robin, not adapted from the telemetry (the M26 confounding firewall holds — a learned scheduler driven by exit/sched telemetry would close the confounded loop M24 refuses).
- **x86 deferred.** The VMX-preemption-timer dual needs the hardware-gated x86 L2 substrate (#37); aarch64-only this milestone.

---

## 6. Where M27 goes beyond the literature
- **A sovereign EL2 time-partition scheduler whose every decision is appended to a verified, tamper-evident experience ledger** is novel — Bao has no scheduler; ARINC-653 / seL4-MCS schedulers don't fold decisions into a content-addressed provenance chain. The *fold* (sovereignty → learning) is the new bit; the time-partition mechanism itself is well-trodden, so the novelty is claimed narrowly.
- **A Kani-proven, no-float partition-function leaf** (totality + frame-conservation + round-robin liveness) driving real EL2 silicon — the verified-leaf discipline applied to scheduling, not just encoding.

---

## 7. Roadmap context
M27 advances **sovereignty** (TABOS owns time for two guests) and **feeds learning** (scheduling decisions → experience). **M28** (the capstone) is the operator INBOUND channel: `opframe` RX + a freshness-bound, head-bound, **dual-authorized** enrolled-key `ACTIVATE_CMD` so a human can finally COMMAND the M24 gate — the exogenous-oracle closure the entire M23→M24→M25→M26 loop was built to receive.

---

### References
Full survey + citations in [`docs/research/m27-sovereign-scheduler-literature.md`](../research/m27-sovereign-scheduler-literature.md). Key: ARINC 653 (APEX) · Bao (Martins et al. 2020; arXiv:2303.11186) · ARM Generic Timer `CNTHP_*_EL2` (Arm ARM DDI 0487; Dall, KVM Forum 2018) · Intel SDM Vol. 3C (VMX-preemption timer) · Lyons et al. "Scheduling-Context Capabilities" (EuroSys 2018) + seL4 MCS (RTCSA 2020) · response-time analysis / temporal-isolation (arXiv:2208.14109).
