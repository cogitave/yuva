//! x86_64 asynchronous interrupt + LAPIC periodic timer (M8): the kernel's
//! FIRST asynchronous interrupt path. ALL of M8's x86_64 `unsafe`/asm lives
//! HERE (plus the one-line IRQ intercept in `trap.rs` and the `map_device_page`
//! primitive in `mmu.rs`); the kernel crate stays unsafe-free
//! (KERNEL-FOUNDATION-SPEC §1).
//!
//! Design decisions (no open questions), each pinned to a verified fact:
//!  * Controller = the **Local APIC**, hard-coded. QEMU `microvm` (the machine
//!    Firecracker models) has NO 8259 PIC, NO 8253/PIT, NO IOAPIC and RTC off,
//!    so the LAPIC is the only interrupt controller and the periodic source
//!    MUST be the LAPIC timer. Under `tb-vmm` the in-kernel KVM LAPIC
//!    (`KVM_CREATE_IRQCHIP`) provides the same model.
//!  * NO new IDT work. `idt::init` already installed all 256 gates as DPL0
//!    64-bit INTERRUPT gates pointing at the `trap.rs` thunks, so the timer
//!    vector (0x20) already vectors `__trap_thunk_32 -> __alltraps ->
//!    x86_trap_handler`, which saves + restores the FULL 15-GPR frame and
//!    `iretq`s. M8 only teaches `x86_trap_handler` to recognise 0x20/0xFF via
//!    [`try_handle_irq`]. The interrupt gate clears `IF` on entry, so a tick
//!    cannot nest inside its own handler.
//!  * LAPIC register access is via a dedicated UNCACHEABLE device window. The
//!    LAPIC MMIO page sits at PA `0xFEE0_0000`, which is in the FOURTH GiB --
//!    ABOVE the boot identity map `[0, 1 GiB)` (x86_64 boot.rs maps exactly
//!    512 x 2 MiB pages), so that PA is simply UNMAPPED. `mmu::map_device_page`
//!    maps a fresh 4 KiB page in the vacant `PML4[3]` device window to it with
//!    `P|RW|PWT|PCD|NX` (`PWT|PCD` = PAT entry 3 = strong UC under the power-up
//!    `IA32_PAT` default; NX because an MMIO register page is never executed).
//!    This fresh page is the SOLE mapping of the LAPIC -- there is NO WB alias
//!    to resolve, so no super-page split is needed.
//!  * Timer values are uncalibrated by design: the M8 DoD needs only REGULAR
//!    interrupts, not a real Hz. Divide-by-1 + initial count `0x10_0000` fires
//!    about every 1 ms under both KVM and TCG (well within the runner timeout);
//!    the canary stops the instant it has seen [`CANARY_TICKS`] interrupts,
//!    then the timer is masked again.
//!
//! Verified register facts (Intel SDM Vol.3A §11 "APIC", Table 11-1):
//!  * SVR @ 0x0F0 bit 8 = software enable; bits[7:0] = spurious vector.
//!  * LVT Timer @ 0x320: bits[7:0] vector, bit 16 = mask, bit 17 = periodic.
//!  * Divide Config @ 0x3E0 = 0b1011 -> divide-by-1; Initial Count @ 0x380;
//!    EOI @ 0x0B0 (write 0); TPR @ 0x080.
//!  * IA32_APIC_BASE = MSR 0x1B, bit 11 = global enable, base in bits[51:12]
//!    (§11.4.4); we OR in bit 11 only (base preserved) so a LAPIC left
//!    hardware-disabled by any boot path still delivers ticks.
//!  * A spurious interrupt (vector 0xFF) takes NO EOI (§11.9).
//!  * `rdtsc` returns EDX:EAX (SDM Vol.2B "RDTSC").

use core::arch::asm;
use core::hint::black_box;
use core::ptr::write_volatile;

// ---------------------------------------------------------------------------
// LAPIC device window + register map (verified -- see module header).
// ---------------------------------------------------------------------------

/// LAPIC MMIO physical base (Intel SDM Vol.3A §11.4.1; the BSP LAPIC is
/// hardware-enabled here at reset). In the 4th GiB, ABOVE the boot identity map.
const LAPIC_PHYS_BASE: u64 = 0xFEE0_0000;
/// VA the LAPIC register page is mapped UC at: `3 * 2^39` = `PML4[3]`, a vacant
/// top-level slot (boot `PML4[0]`, M4 user `PML4[1]`, M7 heap `PML4[2]`),
/// OUTSIDE the identity map, canonical (bits 63:48 sign-extend bit 47 = 0).
const LAPIC_WINDOW_VA: u64 = 0x0000_0180_0000_0000;

const LAPIC_TPR: u64 = 0x080; // Task Priority Register
const LAPIC_EOI: u64 = 0x0B0; // End-Of-Interrupt (write 0)
const LAPIC_SVR: u64 = 0x0F0; // Spurious Interrupt Vector Register
const LAPIC_LVT_TIMER: u64 = 0x320; // LVT Timer entry
const LAPIC_TIMER_INITIAL: u64 = 0x380; // Timer Initial Count
const LAPIC_TIMER_DIVIDE: u64 = 0x3E0; // Timer Divide Configuration

const SVR_APIC_ENABLE: u32 = 1 << 8; // SVR bit 8: APIC software enable
const LVT_TIMER_PERIODIC: u32 = 1 << 17; // LVT Timer bit 17: periodic mode
const LVT_MASKED: u32 = 1 << 16; // LVT bit 16: mask the interrupt

/// IDT vector the periodic LAPIC timer fires on -- 0x20, the first vector past
/// the 32 architecturally-reserved exception vectors.
const TIMER_VECTOR: u64 = 0x20;
/// LAPIC spurious-interrupt vector programmed into SVR; takes NO EOI.
const SPURIOUS_VECTOR: u32 = 0xFF;
/// Divide Config 0b1011 = divide-by-1 (SDM Figure 11-10).
const TIMER_DIVIDE_BY_1: u32 = 0b1011;
/// Initial count -- uncalibrated, picked for frequent (~1 ms) ticks.
const TIMER_INITIAL_COUNT: u32 = 0x0010_0000;

/// IA32_APIC_BASE MSR (Intel SDM Vol.3A §11.4.4).
const IA32_APIC_BASE: u32 = 0x1B;
/// IA32_APIC_BASE bit 11: LAPIC global (hardware) enable.
const APIC_BASE_ENABLE: u64 = 1 << 11;

// ---------------------------------------------------------------------------
// Register-integrity canary (multiply-mix + independent recompute).
// ---------------------------------------------------------------------------

/// Minimum asynchronous timer interrupts the canary must observe to pass.
const CANARY_TICKS: u64 = 16;
/// Fail-closed iteration bound: a DEAD timer bails here (and `timer_demo`
/// returns false) instead of spinning forever -- about tens of ms at native KVM
/// speed, well under the runner's wall-clock timeout.
const CANARY_CAP: u64 = 100_000_000;
/// Canary seed + odd multiplier (a bijective mix; the values are arbitrary).
const CANARY_SEED: u64 = 0x9E37_79B9_7F4A_7C15;
const CANARY_MULT: u64 = 0xD1B5_4A32_D192_ED03;

// ---------------------------------------------------------------------------
// LAPIC MMIO + privileged helpers (all the x86_64 M8 asm/unsafe).
// ---------------------------------------------------------------------------

/// Write a 32-bit LAPIC register at `offset` through the UC device window.
#[inline]
fn lapic_write(offset: u64, value: u32) {
    // SAFETY: `timer_demo` maps LAPIC_WINDOW_VA -> the LAPIC PA as a UC 4 KiB
    // device page BEFORE any LAPIC access; `offset` is one of the verified,
    // 16-byte-aligned register offsets within that one page, so the pointer is
    // valid + aligned and addresses the LAPIC. Volatile: an MMIO store.
    unsafe { write_volatile((LAPIC_WINDOW_VA + offset) as *mut u32, value) }
}

/// `rdmsr` -- read the 64-bit MSR `msr` (EDX:EAX).
#[inline]
fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: ring-0-only; `IA32_APIC_BASE` is implemented on every x86_64 CPU.
    // No memory/stack effect; condition flags untouched.
    unsafe {
        asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi,
            options(nomem, nostack, preserves_flags));
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// `wrmsr` -- write the 64-bit MSR `msr` (EDX:EAX).
#[inline]
fn wrmsr(msr: u32, val: u64) {
    // SAFETY: ring-0-only; we only OR `APIC_BASE_ENABLE` into the existing
    // IA32_APIC_BASE value, preserving the (legal) base-address field.
    unsafe {
        asm!("wrmsr", in("ecx") msr, in("eax") val as u32, in("edx") (val >> 32) as u32,
            options(nostack, preserves_flags));
    }
}

/// Set RFLAGS.IF -- the kernel's FIRST `sti` (M0..M7 ran fully masked).
#[inline]
fn irq_enable() {
    // SAFETY: `sti` only sets IF so the LAPIC timer (the only wired source on
    // QEMU `microvm`) can be taken; no memory/stack effect, and it leaves the
    // arithmetic condition flags (what `preserves_flags` covers) untouched.
    unsafe { asm!("sti", options(nomem, nostack, preserves_flags)) }
}

/// Clear RFLAGS.IF -- re-mask interrupts before the marker/halt.
#[inline]
fn irq_disable() {
    // SAFETY: as `irq_enable`; `cli` only clears IF.
    unsafe { asm!("cli", options(nomem, nostack, preserves_flags)) }
}

/// Read the time-stamp counter (`rdtsc`): EDX:EAX glued into one u64.
pub fn read_cycle_counter() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: `rdtsc` is ring-0-legal (CR4.TSD = 0 since boot), has no memory
    // or stack effect and leaves the condition flags untouched.
    unsafe {
        asm!("rdtsc", out("eax") lo, out("edx") hi,
            options(nomem, nostack, preserves_flags));
    }
    ((hi as u64) << 32) | (lo as u64)
}

// ---------------------------------------------------------------------------
// IRQ recognition (called from `trap.rs::x86_trap_handler`).
// ---------------------------------------------------------------------------

/// Recognise + service an external (async) interrupt; returns `true` iff it was
/// one of ours so the trap handler resumes WITHOUT consulting the synchronous
/// trap hook (whose kernel policy halts on a non-`#BP`). Narrow + fail-closed:
///  * `TIMER_VECTOR` (0x20): EOI the LAPIC FIRST, then bump the monotonic tick
///    (+ run the M9 hook) via the arch-neutral `crate::dispatch_irq` -- the M9
///    hook may ctx_switch away and not return on this stack, so the EOI must
///    precede it or the next task is starved of further timer interrupts.
///  * `SPURIOUS_VECTOR` (0xFF): just resume -- a spurious interrupt takes no EOI
///    (Intel SDM Vol.3A §11.9).
///  * anything else: `false` -> falls through to the fatal `Other` classifier.
///
/// Called with `IF` cleared (interrupt gate), so no nested timer IRQ races the
/// EOI; on `true`, `__alltraps` restores the full frame and `iretq`s back to the
/// exact interrupted instruction.
pub(super) fn try_handle_irq(vector: u64) -> bool {
    if vector == TIMER_VECTOR {
        // M9: EOI the LAPIC BEFORE dispatch. `dispatch_irq` runs the registered
        // hook -- M9's `schedule()` -- which may ctx_switch to another task and
        // NOT return on this stack for a while; sending EOI first lets the LAPIC
        // deliver the NEXT periodic tick to the switched-in task instead of
        // starving it (the in-service ISR bit would otherwise stay set,
        // blocking all further timer interrupts). `IF` stays clear (interrupt
        // gate) until that task does its own `iretq`, so no tick can nest
        // between this EOI and the switch.
        lapic_write(LAPIC_EOI, 0);
        crate::dispatch_irq(vector);
        true
    } else if vector == SPURIOUS_VECTOR as u64 {
        true
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// LAPIC + timer bring-up / teardown.
// ---------------------------------------------------------------------------

/// Hardware- + software-enable the LAPIC and accept all priorities. OR-ing only
/// `APIC_BASE_ENABLE` preserves the base, so the LAPIC stays at `0xFEE0_0000`.
fn lapic_enable() {
    let base = rdmsr(IA32_APIC_BASE);
    wrmsr(IA32_APIC_BASE, base | APIC_BASE_ENABLE); // belt-and-suspenders HW enable
    lapic_write(LAPIC_TPR, 0); // accept every interrupt priority
    lapic_write(LAPIC_SVR, SVR_APIC_ENABLE | SPURIOUS_VECTOR);
}

/// Arm the periodic LAPIC timer onto `TIMER_VECTOR`. The initial-count write
/// starts the count-down, but no interrupt is delivered until `irq_enable`.
fn lapic_timer_arm() {
    lapic_write(LAPIC_TIMER_DIVIDE, TIMER_DIVIDE_BY_1);
    lapic_write(LAPIC_LVT_TIMER, (TIMER_VECTOR as u32) | LVT_TIMER_PERIODIC);
    lapic_write(LAPIC_TIMER_INITIAL, TIMER_INITIAL_COUNT);
}

/// Mask the timer LVT and zero the initial count: no further timer interrupts.
fn lapic_timer_disarm() {
    lapic_write(LAPIC_LVT_TIMER, (TIMER_VECTOR as u32) | LVT_MASKED);
    lapic_write(LAPIC_TIMER_INITIAL, 0);
}

// ---------------------------------------------------------------------------
// M9 scheduler surface: re-arm / disarm the periodic timer + go preemptible.
// (The LAPIC device page mapped by M8's `timer_demo` -> `map_device_page`
// persists in PML4[3], so M9 re-arms WITHOUT re-mapping.)
// ---------------------------------------------------------------------------

/// M9: re-arm the periodic LAPIC timer and unmask interrupts so a tick drives
/// `schedule()` from interrupt context. M8's `timer_demo` left the LAPIC enabled
/// + its register page mapped but the timer LVT masked; this re-enables the
/// LAPIC (idempotent), re-arms the periodic timer, then `sti`. The kernel calls
/// it via `tb_hal::timer_rearm` AFTER registering the schedule hook.
pub fn timer_rearm() {
    lapic_enable();
    lapic_timer_arm();
    irq_enable();
}

/// M9: mask interrupts and disarm the periodic timer. The boot task calls this
/// via `tb_hal::timer_disarm` BEFORE printing the "M9: preempt OK" verdict so no
/// further involuntary switch races the final serial output.
pub fn timer_disarm() {
    irq_disable();
    lapic_timer_disarm();
}

/// M9: unmask interrupts on the CURRENT task without touching the timer. A task
/// first-activated through M2's `ctx_switch` `ret`s into its entry with
/// `RFLAGS.IF` still clear (it never passed through an `iretq` that would
/// restore `IF`), so a fresh preemptible kernel task calls this ONCE at entry to
/// become schedulable; thereafter the periodic timer can preempt it.
pub fn sched_irq_unmask() {
    irq_enable();
}

// ---------------------------------------------------------------------------
// The register-integrity canary + the public self-test.
// ---------------------------------------------------------------------------

/// Busy loop whose locals are live across asynchronous timer interrupts: each
/// taken interrupt saves + restores every GPR in `__alltraps`, so the running
/// `acc`/`i` must equal an INDEPENDENT recomputation afterwards (`black_box`
/// blocks constant-folding; the atomic-dependent trip count keeps either loop
/// from being precomputed). `true` = no corruption observed.
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

/// Full M8 self-test: map the LAPIC UC window, hardware/software-enable it, arm
/// the periodic timer, take the kernel's FIRST asynchronous interrupts across
/// the register-integrity canary, then re-mask interrupts + stop the timer.
/// `true` iff at least [`CANARY_TICKS`] ticks were observed AND the canary state
/// survived every async entry uncorrupted. Touches NO scheduler (that is M9).
pub fn timer_demo() -> bool {
    // 1. Map the LAPIC register page UC into the PML4[3] device window; fail
    //    closed if a page-table frame is unavailable.
    if !super::mmu::map_device_page(LAPIC_WINDOW_VA, LAPIC_PHYS_BASE) {
        return false;
    }
    // 2. Enable the LAPIC + arm the periodic timer (still masked by IF=0).
    lapic_enable();
    lapic_timer_arm();
    // 3. Take the kernel's FIRST asynchronous interrupts across the canary.
    irq_enable();
    let canary_ok = run_canary();
    irq_disable();
    // 4. Mask + stop the timer so no IRQ survives into the halt path.
    lapic_timer_disarm();
    canary_ok && crate::tick_count() >= CANARY_TICKS
}
