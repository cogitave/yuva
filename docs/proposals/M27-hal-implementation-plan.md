---
type: Design Decision
title: "M27 — HAL Implementation Plan (aarch64 EL2 Two-VMID CNTHP Sovereign Scheduler)"
description: "Build spec to wire M27's first async EL2 timer IRQ (0x480) preempting two EL1 guests; cooperative M27a floor, real preemptive M27b."
tags: ["m27", "hal", "aarch64", "el2", "scheduler", "interrupts"]
timestamp: 2026-06-10T22:23:48+03:00
status: locked
diataxis: explanation
---

# M27 HAL implementation plan — the aarch64 EL2 two-VMID CNTHP sovereign scheduler

**Status:** design-complete (build spec) · companion to [`M27-sovereign-scheduler.md`](M27-sovereign-scheduler.md) · derived from an ultracode design workflow (4 Explore studies of the world-switch / timer-IRQ-at-EL2 / two-guest-harness / boot-hang-history + synthesis). The **verified `tpsched` leaf + 5 Kani harnesses are already built** (branch `m27-sovereign-scheduler`); this plan is the **EL2 HAL runtime** that remains.

> **The headline finding.** The EL2 vector table is **synchronous-only** today — the Lower-EL IRQ slot (`el2_vectors.rs`, offset **`0x480`**) routes to `__el2_vec_other` (fatal). M27 must wire **the first-ever asynchronous IRQ taken at EL2** (the CNTHP physical-timer PPI, INTID 26). The guests run at **EL1**, so with `HCR_EL2.IMO=1` the PPI vectors to EL2's **Lower-EL-AArch64 IRQ** row = **`0x480`** (NOT `0x280`, which is Current-EL/EL2h and must stay fatal). This async-IRQ wiring is the entire risk of M27.

---

## Incremental landing (STRONGLY ADVISED) — M27a then M27b

- **M27a (cooperative, NO async IRQ — the green floor):** the two guests **`HVC`-yield** (`HVC #14`) instead of being timer-preempted. The existing `0x400` sync handler does the VTTBR/VMID switch + `tpsched::next_slot` consult + `SchedDecision` fold on each voluntary yield. This exercises **everything except the timer IRQ** — two VMIDs, two stage-2 roots, two MMIO forward-progress cells, round-robin order, the fold, the tamper check, both-progressed — and **cannot IRQ-storm** (no async IRQ at all). The marker emits `timing=COOPERATIVE-HVC-YIELD` so it can never impersonate the real thing.
- **M27b (real CNTHP preemption):** swap the cooperative yield for the `0x480` timer handler; flip the token to `timing=TCG-NON-CYCLE-ACCURATE`. Only Step 4 + the loop driver change; M27a already proved Steps 1–3, 5b/5d, 6.

If M27b's CNTHP IRQ proves runner-flaky under a given TCG, **M27a stays the shippable green floor.**

## Risk assessment
**Multi-iteration (3–5 boots), not one sitting.** The leaf + two-guest + fold are mechanical reuse (low risk); the `0x480` async IRQ (Step 4) is new silicon. Most likely first-boot failures, ranked:
1. **IRQ storm / silent hang** — the handler EOIs `GICC_EOIR` but forgets to clear the timer `ISTATUS` (by re-writing `CNTHP_TVAL_EL2`/masking) → PPI re-asserts → infinite re-entry → 240 s wedge (rc=124). **Mitigation: re-arm `CNTHP_TVAL_EL2` BEFORE `GICC_EOIR`, verify `GICC_IAR==26`, read back `ISTATUS`, and a hard `eoi_count` cap → `fail_exit()` (turns a storm into a fast red).**
2. **Wrong vector slot** — wiring `0x280` instead of `0x480` yields a clean red `el2: UNEXPECTED vector entry` (loud, not a hang) — use it as the diagnostic if Step 4 "does nothing".
3. **IMO steals the EL1 timer** — `HCR_EL2.IMO=1` is global; the M27 window must run with EL1 IRQs masked (`local_irq_save`) and short, restoring `HCR_EL2=RW` before unwind (the proven aL2.5 IMO-window discipline).
4. **Frame/stack drift** — `SAVE_CONTEXT_EL2` at `0x480` must produce the byte-identical `0x110` `Frame`; reuse the macro verbatim, never hand-roll.

---

## Reusable seams (verified — mirror these, do not invent)
- **`el2vgic.rs::arm_vgic_el2` / `disarm_vgic_el2`** — THE analog: the IMO + GIC + **teardown-first** window. M27's arm/disarm is this + CNTHP.
- **`stage2.rs::build_identity_stage2` / `compute_vtcr` / `compute_vttbr` / `arm_stage2_el2`** — VTTBR/VMID (generalize the fixed `const VMID: u64 = 1` → `build_identity_stage2_for_vmid(vmid)` + `compute_vttbr_vmid`).
- **`timer.rs::{gicd_write, gicc_read, gicc_write, GICD_ISENABLER0, GICC_IAR, GICC_EOIR}`** — GIC ack/EOI.
- **`el2.rs::{el2_return_to_kernel, el2_abort_retry, read_esr_el2, aarch64_el2_sync_handler}`** + the `HVC_*_ARM`/`_DONE` const+assert dispatch pattern (M27 takes **imm 12/13**, +14 for the M27a yield).
- **`el2vgic.rs::VgicCtx`** — the `align(64)` single-accessor `UnsafeCell` state-cell pattern (plain `read_volatile`/`write_volatile`, NOT atomics — EL2 MMU-off non-cacheable).
- **`stage2_guest_stub`** (`el2.rs`) — the `#[unsafe(naked)]` EL1 guest-stub model.

---

## Ordered build steps
- **Step 0 — leaf:** `tb-encode/src/tpsched.rs` + 5 Kani harnesses, `EXPECTED_HARNESSES` 69→74. **DONE on branch `m27-sovereign-scheduler`** (the design workflow read `main`, where it isn't merged yet).
- **Step 1 — state cell:** new `arch/aarch64/tpsched_hal.rs` — a `SchedCtx` (`align(64)` single-accessor) with `armed`, `current_slot`, `frames_done`, `eoi_count`, `vmid[2]`, `s2_root[2]`, `vttbr[2]`, `entry_pc[2]`, `frame_plan`, `sched_head`. Mirror `VgicCtx`.
- **Step 2 — two roots + two stubs:** `build_two_roots()` calls `build_identity_stage2_for_vmid()` twice (distinct roots, VMID 0 & 1); two `#[unsafe(naked)]` stubs each `str`-ing to a distinct device IPA (M27a: end each loop with `HVC #14`).
- **Step 3 — per-VMID MMIO witness:** extend `el2mmio.rs` with a two-cell `DeviceShadowPair` + `device_mmio_m27(ipa, …, vmid)`; route the M27 device IPAs through the existing `el2_mmio_emulate`, gated on the M27 window being armed (byte-identical L2.3 path when not armed). The monitor's count is the ground truth (a guest can't fake a non-trapping store).
- **Step 4 — ⚠️ async IRQ at EL2 (M27b only, LAST):** `el2_vectors.rs:0x480` → `__el2_vec_timer_irq` trampoline (`SAVE_CONTEXT_EL2` → `aarch64_el2_timer_handler`); `arm_cnthp_window_el2(delta)` (`GICD_ISENABLER0` PPI 26 → `CNTHP_TVAL_EL2`+`CNTHP_CTL_EL2.ENABLE` → `HCR_EL2 = RW|IMO|VM`); `disarm_cnthp_window_el2()` teardown-first (mask+disable timer → `HCR_EL2=RW` → drop VTTBR → `tlbi vmalls12e1is` → disable PPI). **Smoke "IRQ works" (a dummy handler that counts+re-arms K times) BEFORE wiring the VMID switch** — separate "IRQ fires" from "scheduler correct".
- **Step 5 — the loop:** new HVC imm 12/13(/14) consts+asserts; `HVC_SCHED_ARM` branch (populate `SchedCtx`, `VTTBR_EL2=vttbr[0]`, arm, `eret` into `entry_pc[0]`); `aarch64_el2_timer_handler` (M27b) / `HVC_SCHED_YIELD` branch (M27a): consult `tpsched::next_slot`, **re-arm CNTHP before EOI** (M27b), switch `VTTBR_EL2=vttbr[next]` + `tlbi vmalls12e1is`, fold `SchedDecision` into `sched_head` via the M22 `prov` fold verbatim, `note_eoi()`+cap, `el2_abort_retry(frame)` (frame UNCHANGED — resumes under the next guest's stage-2); `HVC_SCHED_DONE` branch (teardown-first → read both cells + order + `sched_head` → verdict → `el2_return_to_kernel`).
- **Step 6 — surface:** `SchedProof` enum + `sched_selftest()` facade in `lib.rs` (mirror `VgicProof`/`el2_vgic_selftest`; `Unavailable` if `BOOTED_AT_EL2 != 1`; `local_irq_save` around the `HVC #12`; bounded `K_MAX` major frames then `HVC #13`); kernel M27 block in `main.rs` between L2.6 and M19; `run-aarch64.sh` guards (require the `sched:` witness with all six `=1` flags + the honesty tokens, reject skip + `validated|real-time|WCET|guaranteed`, LOUD `::warning::` skip, append to the PASS summary).

## Mandatory defensive checklist (enforced inline)
Bounded frame count (`< K_MAX`, e.g. 10) · re-arm-before-EOI + `IAR==26` verify + `ISTATUS` read-back + `eoi_count` cap → `fail_exit()` · teardown-first on `HVC_SCHED_DONE` · fail-closed one-shot caps (no spin-waits) · `HCR.VM/IMO` only inside the `local_irq_save` window, restored before unwind (→ M0..M26 + L2.0..L2.6 byte-identical) · shallow handler (no deep calls/alloc; the EL2 stack is 32 KiB + guard + the #65 red-zone).

## DoD witness
`sched: head=<hex16> frames=<k> vmids=<2> both-progressed=1 order-honored=1 fold-verified=1 tamper-caught=1 frame-conserved=1 timing={COOPERATIVE-HVC-YIELD|TCG-NON-CYCLE-ACCURATE} realtime=NOT-CLAIMED` → `M27: sched OK`.

## Files touched
**New:** `tb-encode/src/tpsched.rs` (done), `tb-hal/arch/aarch64/tpsched_hal.rs`. **Modified:** `tb-encode/src/{lib.rs,proofs.rs}`, `tb-hal/arch/aarch64/{el2_vectors.rs, el2.rs, el2mmio.rs, stage2.rs, timer.rs, mod.rs}`, `tb-hal/src/lib.rs`, `kernel/src/main.rs`, `scripts/{run-aarch64.sh, verify-encode.sh}`.
