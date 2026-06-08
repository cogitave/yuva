//! aarch64 asynchronous interrupt + EL1 physical timer (M8): the kernel's FIRST
//! asynchronous interrupt path. ALL of M8's aarch64 `unsafe`/asm lives HERE
//! (plus the new `__vec_irq` slot in `vectors.rs` and the `source == 2` arm in
//! `trap.rs`); the kernel crate stays unsafe-free (KERNEL-FOUNDATION-SPEC §1).
//!
//! Design decisions (no open questions):
//!  * Controller = **GICv2**, hard-coded. QEMU `virt` with `-cpu cortex-a72`
//!    and no `gic-version` override exposes a GICv2: GICD (distributor) @
//!    0x0800_0000, GICC (CPU interface) @ 0x0801_0000. Both sit inside the
//!    `L1[0]` Device-nGnRnE identity gigabyte `mmu_init` already mapped, so NO
//!    new MMIO mapping is needed -- they are accessed at their physical address.
//!  * Timer = the **EL1 non-secure physical generic timer** (CNTP_*), PPI INTID
//!    30. TVAL mode is one-shot, so [`handle_irq`] reloads `CNTP_TVAL_EL0` each
//!    tick -- which also DE-ASSERTS the level-sensitive timer (clears
//!    `CNTP_CTL.ISTATUS`) before EOI -- making it periodic.
//!  * Period is uncalibrated by design (the DoD needs regular ticks, not a real
//!    Hz): `CNTFRQ_EL0 / 1000` (~1 ms at the `virt` 62.5 MHz CNTFRQ), floored
//!    against an implausibly-low CNTFRQ. The canary stops once it has seen
//!    [`CANARY_TICKS`] interrupts, then the timer is disabled again.
//!  * The `Current EL SPx IRQ` vector slot (offset 0x280) becomes the real
//!    `__vec_irq`, reusing the existing 0x110-byte `SAVE_CONTEXT` /
//!    `RESTORE_CONTEXT`/`eret`, so the interrupted context is restored
//!    byte-for-byte; the handler does NOT advance `ELR_EL1` (an async IRQ
//!    resumes AT the interrupted instruction, unlike the synchronous `brk`).
//!
//! Verified facts (Arm GICv2 IHI 0048 + Arm ARM DDI 0487):
//!  * GICD_CTLR @ 0x000 bit0 = EnableGrp0; GICD_ISENABLER0 @ 0x100 is
//!    write-1-to-set (bit n enables INTID n) -- bit 30 enables the timer PPI.
//!  * GICC_CTLR @ 0x000 bit0 = enable; GICC_PMR @ 0x004 = 0xFF allows every
//!    priority; GICC_IAR @ 0x00C (read = acknowledge, INTID in bits[9:0]);
//!    GICC_EOIR @ 0x010 (write the IAR value to end the interrupt). INTIDs
//!    1020..1023 are special/spurious and must NOT be EOIed.
//!  * EL1 physical timer: PPI INTID 30; `CNTP_CTL_EL0` bit0 = ENABLE, bit1 =
//!    IMASK; `CNTP_TVAL_EL0` programs compare = CNTPCT + TVAL; `CNTFRQ_EL0` is
//!    the counter frequency; `CNTPCT_EL0` is the monotonic physical counter.
//!  * IRQ unmask/mask = `msr daifclr, #2` / `msr daifset, #2` (PSTATE.I).

use core::arch::asm;
use core::hint::black_box;
use core::ptr::{read_volatile, write_volatile};

// ---------------------------------------------------------------------------
// GICv2 layout (QEMU `virt`) -- inside the L1[0] Device identity gigabyte.
// ---------------------------------------------------------------------------

const GICD_BASE: u64 = 0x0800_0000; // distributor
const GICC_BASE: u64 = 0x0801_0000; // CPU interface

const GICD_CTLR: u64 = 0x000;
const GICD_ISENABLER0: u64 = 0x100;

const GICC_CTLR: u64 = 0x000;
const GICC_PMR: u64 = 0x004;
const GICC_IAR: u64 = 0x00C;
const GICC_EOIR: u64 = 0x010;

const GICD_CTLR_ENABLE_GRP0: u32 = 1 << 0;
const GICC_CTLR_ENABLE_GRP0: u32 = 1 << 0;
const GICC_PMR_ALLOW_ALL: u32 = 0xFF;

/// PPI INTID of the EL1 non-secure physical generic timer (QEMU `virt` PPI 14).
const TIMER_PPI: u32 = 30;
/// IAR INTID field mask (GICv2: bits[9:0]); values >= 1020 are special/spurious.
const GIC_INTID_MASK: u32 = 0x3FF;
const GIC_SPURIOUS_MIN: u32 = 1020;

/// CNTP_CTL_EL0.ENABLE (bit 0); IMASK (bit 1) left clear = unmasked.
const CNTP_CTL_ENABLE: u64 = 1 << 0;
/// Floor for the timer period (counter ticks) if `CNTFRQ_EL0` reads implausible.
const PERIOD_FLOOR: u64 = 0x1000;

// ---------------------------------------------------------------------------
// Register-integrity canary (identical structure to the x86_64 arm + M2).
// ---------------------------------------------------------------------------

const CANARY_TICKS: u64 = 16;
const CANARY_CAP: u64 = 100_000_000;
const CANARY_SEED: u64 = 0x9E37_79B9_7F4A_7C15;
const CANARY_MULT: u64 = 0xD1B5_4A32_D192_ED03;

// ---------------------------------------------------------------------------
// GIC MMIO + system-register helpers (all the aarch64 M8 asm/unsafe).
// ---------------------------------------------------------------------------

fn gicd_write(offset: u64, value: u32) {
    // SAFETY: GICD sits in the L1[0] Device-nGnRnE identity gigabyte mapped by
    // `mmu_init`, so `GICD_BASE + offset` is a valid 32-bit MMIO address.
    unsafe { write_volatile((GICD_BASE + offset) as *mut u32, value) }
}

fn gicc_write(offset: u64, value: u32) {
    // SAFETY: as `gicd_write`, for the GICC CPU interface.
    unsafe { write_volatile((GICC_BASE + offset) as *mut u32, value) }
}

fn gicc_read(offset: u64) -> u32 {
    // SAFETY: as `gicd_write`; a side-effecting MMIO load (IAR ack on read).
    unsafe { read_volatile((GICC_BASE + offset) as *const u32) }
}

fn write_cntp_tval(v: u64) {
    // SAFETY: CNTP_TVAL_EL0 is EL1-accessible; the write sets compare = CNTPCT
    // + v. No memory/stack effect; NZCV preserved.
    unsafe {
        asm!("msr cntp_tval_el0, {v}", v = in(reg) v,
            options(nomem, nostack, preserves_flags));
    }
}

fn write_cntp_ctl(v: u64) {
    // SAFETY: CNTP_CTL_EL0 controls the EL1 physical timer enable/mask; legal at
    // EL1, no memory/stack effect, NZCV preserved.
    unsafe {
        asm!("msr cntp_ctl_el0, {v}", v = in(reg) v,
            options(nomem, nostack, preserves_flags));
    }
}

fn read_cntfrq() -> u64 {
    let v: u64;
    // SAFETY: CNTFRQ_EL0 is a read-only EL0/EL1 system register (the counter
    // frequency); side-effect-free, NZCV preserved.
    unsafe {
        asm!("mrs {v}, cntfrq_el0", v = out(reg) v,
            options(nomem, nostack, preserves_flags));
    }
    v
}

/// Clear PSTATE.I (`msr daifclr, #2`) -- the kernel's FIRST IRQ unmask.
fn irq_unmask() {
    // SAFETY: clears PSTATE.I so EL1 physical IRQs are taken; the GIC + CNTP
    // timer are the only wired source. No memory/stack effect, NZCV preserved.
    unsafe {
        asm!("msr daifclr, #2", options(nomem, nostack, preserves_flags));
    }
}

/// Set PSTATE.I (`msr daifset, #2`) -- re-mask EL1 physical IRQs.
fn irq_mask() {
    // SAFETY: sets PSTATE.I before the marker/halt; no memory/stack effect.
    unsafe {
        asm!("msr daifset, #2", options(nomem, nostack, preserves_flags));
    }
}

/// Read the physical generic counter (`CNTPCT_EL0`) -- the in-guest cycle clock.
/// `isb` first so the read is not speculated earlier (Arm ARM D11 guidance).
pub fn read_cycle_counter() -> u64 {
    let v: u64;
    // SAFETY: CNTPCT_EL0 is readable at EL1; monotonic, side-effect-free, NZCV
    // preserved.
    unsafe {
        asm!("isb", "mrs {v}, cntpct_el0", v = out(reg) v,
            options(nomem, nostack, preserves_flags));
    }
    v
}

// ---------------------------------------------------------------------------
// GIC + timer bring-up / teardown.
// ---------------------------------------------------------------------------

/// ~1 ms timer period (counter ticks); the floor guards an implausible CNTFRQ.
fn timer_period() -> u64 {
    (read_cntfrq() / 1000).max(PERIOD_FLOOR)
}

/// Minimal single-core GICv2 init: enable Group0 forwarding + the timer PPI in
/// the distributor, allow all priorities + enable the CPU interface, then a
/// `dsb sy; isb` so the programming is visible before the first unmask.
fn gic_init() {
    gicd_write(GICD_CTLR, GICD_CTLR_ENABLE_GRP0);
    gicd_write(GICD_ISENABLER0, 1 << TIMER_PPI);
    gicc_write(GICC_PMR, GICC_PMR_ALLOW_ALL);
    gicc_write(GICC_CTLR, GICC_CTLR_ENABLE_GRP0);
    // SAFETY: barriers only; order the GIC MMIO writes before interrupts flow.
    unsafe {
        asm!("dsb sy", "isb", options(nomem, nostack, preserves_flags));
    }
}

/// Arm the EL1 physical timer (still masked by PSTATE.I until [`irq_unmask`]).
fn timer_start() {
    write_cntp_tval(timer_period());
    write_cntp_ctl(CNTP_CTL_ENABLE);
    // SAFETY: barrier only; make the timer arming take effect promptly.
    unsafe {
        asm!("isb", options(nomem, nostack, preserves_flags));
    }
}

/// Disable the EL1 physical timer: no further timer interrupts.
fn timer_stop() {
    write_cntp_ctl(0);
    // SAFETY: barrier only.
    unsafe {
        asm!("isb", options(nomem, nostack, preserves_flags));
    }
}

// ---------------------------------------------------------------------------
// IRQ entry (called from `trap.rs::aarch64_trap_handler` for source == IRQ).
// ---------------------------------------------------------------------------

/// Handle one EL1 physical IRQ taken through the `__vec_irq` slot. Acknowledges
/// the GIC (read IAR); for the timer PPI it reloads `CNTP_TVAL_EL0` (re-arming
/// the one-shot timer AND de-asserting the level-sensitive condition so it does
/// not immediately re-fire -- this is what makes it periodic) and bumps the
/// monotonic tick (+ runs the M9 hook) via `crate::dispatch_irq`; then it EOIs.
/// A spurious INTID (>= 1020) gets neither a tick nor an EOI. Returns so
/// `RESTORE_CONTEXT`/`eret` resumes the exact interrupted instruction.
pub(super) fn handle_irq() {
    let iar = gicc_read(GICC_IAR);
    let intid = iar & GIC_INTID_MASK;
    if intid >= GIC_SPURIOUS_MIN {
        return; // spurious / no pending interrupt: no tick, no EOI
    }
    if intid == TIMER_PPI {
        write_cntp_tval(timer_period()); // re-arm + de-assert BEFORE EOI
        crate::dispatch_irq(intid as u64); // bump tick + M9 hook (centralized)
    }
    gicc_write(GICC_EOIR, iar); // EOI uses the full IAR value
}

// ---------------------------------------------------------------------------
// The register-integrity canary + the public self-test.
// ---------------------------------------------------------------------------

/// See the x86_64 arm: locals live across asynchronous IRQs must equal an
/// independent recomputation, proving the full-frame save/restore lost nothing.
fn run_canary() -> bool {
    let mut acc: u64 = CANARY_SEED;
    let mut i: u64 = 0;
    while crate::tick_count() < CANARY_TICKS && i < CANARY_CAP {
        acc = black_box(acc).wrapping_mul(CANARY_MULT).wrapping_add(i);
        i = i.wrapping_add(1);
    }
    let mut reference: u64 = CANARY_SEED;
    let mut j: u64 = 0;
    while j < i {
        reference = reference.wrapping_mul(CANARY_MULT).wrapping_add(j);
        j = j.wrapping_add(1);
    }
    black_box(acc) == black_box(reference)
}

/// Full M8 self-test: bring up GICv2 + the EL1 physical timer, take the kernel's
/// FIRST asynchronous IRQs across the register-integrity canary, then re-mask +
/// stop the timer. `true` iff at least [`CANARY_TICKS`] ticks were observed AND
/// the canary state survived every async entry uncorrupted. No new MMIO mapping
/// (the GIC + timer are identity-mapped Device / EL1 system registers). Touches
/// NO scheduler (that is M9).
pub fn timer_demo() -> bool {
    gic_init();
    timer_start();
    irq_unmask();
    let canary_ok = run_canary();
    irq_mask();
    timer_stop();
    canary_ok && crate::tick_count() >= CANARY_TICKS
}
