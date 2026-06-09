//! aarch64 **aL2.5 "vgic"**: the EL2 vGIC virtual-interrupt INJECTION glue +
//! the single-accessor armed/park-seen context cell.
//!
//! Where aL2.2 ([`super::exits`]) proves the EL2 *exit-dispatch table* (a trapped
//! `WFI` is resumed one instruction past), aL2.5 proves the EL2 *virtual-
//! interrupt injection* path: inside a short self-test window the monitor traps
//! the guest's `WFI` (the scheduler yield point), software-INJECTS a pending
//! virtual interrupt into `GICH_LR0` (using the Kani-proven
//! [`tb_encode::el2_trap::gich_lr_encode`]), resumes the guest past the `WFI`,
//! and -- because `GICH_HCR.En` is set + `HCR_EL2.IMO` routes the VIRQ to EL1 +
//! the guest's `GICV_CTLR.En` is set + `PSTATE.I` is clear -- the guest
//! immediately takes the vIRQ at its OWN EL1 IRQ vector, acks it via `GICV_IAR`,
//! and EOIs it via `GICV_EOIR`, retiring the LR. This module owns the silicon-
//! unsafe arming (`msr HCR_EL2` + the GICH/GICV MMIO) + the EL2-only armed/
//! park-seen cell; the handler/done/facade live in [`super::el2`] and the guest
//! EL1 vector table in [`super::el2_vgic_vectors`], so `tb-hal`'s
//! `#![forbid(unsafe_code)]` callers (the kernel) only ever branch on the
//! returned `VgicProof`.
//!
//! ## The four GICv2 MMIO frames (QEMU `virt` memmap, `hw/arm/virt.c`)
//!
//!  * GICD `0x0800_0000` (Distributor) -- NOT touched: the SW-injected vIRQ is
//!    purely a `GICH_LR0` list-register entry (HW=0), so the Distributor's
//!    physical SPI routing is never involved.
//!  * GICC `0x0801_0000` (physical CPU interface) -- NOT touched: the guest sees
//!    GICV instead. (The kernel's M8 timer drives GICC; aL2.5 leaves it alone.)
//!  * GICH `0x0803_0000` (Hypervisor control) -- the EL2-only injection surface:
//!    `GICH_HCR.En` enables the virtual CPU interface; `GICH_VTR` reports
//!    num_lrs-1; `GICH_LR0` is the list register the monitor writes the pending
//!    vIRQ into; `GICH_ELRSR0` reports per-LR empty status (the retire proof).
//!  * GICV `0x0804_0000` (Virtual CPU interface) -- the frame the GUEST touches
//!    thinking it is its GICC (`GICV_CTLR`/`GICV_PMR`/`GICV_IAR`/`GICV_EOIR`).
//!
//! All four sit inside the L1[0] Device-nGnRnE identity gigabyte (GIB0) the
//! kernel's `mmu_init` maps, so both the EL2 monitor (MMU off, flat) and the EL1
//! guest reach them with no new mapping (the GICH/GICV bases are NEW vs the M8
//! GICD/GICC; the gigabyte already covers them).
//!
//! ## Arming (HCR_EL2 -- absolute writes, mirroring `exits::arm_exits_el2`)
//!
//! The boot baseline is `HCR_EL2 = 1<<31` (RW only) for the whole M0..M19 +
//! L2.0..L2.4 run. [`arm_vgic_el2`] sets `HCR_EL2 = RW|IMO|TWI` (IMO so the VIRQ
//! line reaches EL1, TWI so the guest's `WFI` traps) and `GICH_HCR.En`;
//! [`disarm_vgic_el2`] restores `HCR_EL2 = RW` and clears `GICH_HCR.En` + zeroes
//! `GICH_LR0` (teardown-first, the L2.1 discipline) BEFORE the monitor unwinds.
//!
//! ## The armed/park-seen cell (EL2-only; the outcome leaves via the x0 register)
//!
//! [`set_armed`]/[`set_park_seen`] record the window state. They are written and
//! read ONLY at EL2 (the arm handler, the `WFx` inject arm, the done verdict),
//! never by EL1, so -- like `exits::ExitsCtx` -- it is a single-accessor
//! `align(64)` cell that shares no cache line with any EL1-written `.bss`. The
//! VERDICT derived from it is delivered to EL1 in the x0 register, never read by
//! EL1 from this cacheable static.

use core::arch::asm;
use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};

use tb_encode::el2_trap::{
    gich_lr_encode, lr_is_retired, vtr_list_regs, GICH_LR_STATE_PENDING,
};

// ===========================================================================
// HCR_EL2 arming bits (Linux `kvm_arm.h`; Arm ARM DDI 0487 D13).
// ===========================================================================

/// `HCR_EL2.RW` (bit31): the next lower EL (EL1) is AArch64 -- the boot baseline.
const HCR_RW: u64 = 1 << 31;
/// `HCR_EL2.IMO` (bit4): route physical IRQ to EL2 AND enable the virtual-IRQ
/// (VIRQ) line to EL1 (`kvm_arm.h HCR_IMO`). REQUIRED so the GIC virtual
/// interface's VIRQ is delivered to the guest -- WITHOUT it the injected vIRQ is
/// never taken and the guest re-parks forever (the #1 aL2.5 silent-hang trap).
const HCR_IMO: u64 = 1 << 4;
/// `HCR_EL2.TWI` (bit13): trap EL1 `WFI` to EL2 (`kvm_arm.h HCR_TWI`) -- the
/// scheduler-yield trap (park = WFI traps; wake = the monitor injects + resumes).
const HCR_TWI: u64 = 1 << 13;

// Tier-1 compile-time locks (a drift from the boot baseline is a build error).
const _: () = assert!(HCR_RW == 1 << 31);
const _: () = assert!(HCR_IMO == 0x10);
const _: () = assert!(HCR_TWI == 0x2000);

// ===========================================================================
// GICv2 virtualization MMIO frames (QEMU `virt` base_memmap[], hw/arm/virt.c --
// byte-identical v6.2.0 and v8.2.0).
// ===========================================================================

/// GICH (Hypervisor control interface) base -- `VIRT_GIC_HYP` (0x0803_0000).
const GICH_BASE: u64 = 0x0803_0000;
/// GICV (Virtual CPU interface) base -- `VIRT_GIC_VCPU` (0x0804_0000).
const GICV_BASE: u64 = 0x0804_0000;

// Tier-1 locks: a drift from the QEMU virt memmap silently mis-injects.
const _: () = assert!(GICH_BASE == 0x0803_0000);
const _: () = assert!(GICV_BASE == 0x0804_0000);

// GICH register offsets within GICH_BASE (IHI 0048B §4.4 == QEMU gic_internal.h).
/// `GICH_HCR` (0x000): En bit0, EOICount[31:27], UIE/LRENPIE/NPIE [3:1].
const GICH_HCR: u64 = 0x000;
/// `GICH_VTR` (0x004): read-only; ListRegs[5:0] = num_lrs - 1.
const GICH_VTR: u64 = 0x004;
/// `GICH_MISR` (0x010): maintenance-interrupt status (EOI bit0, U bit1).
#[allow(dead_code)]
const GICH_MISR: u64 = 0x010;
/// `GICH_ELRSR0` (0x030): per-LR empty-status bitmap; bit n == 1 iff LRn empty
/// (state INVALID). The cleanest independent retire proof.
const GICH_ELRSR0: u64 = 0x030;
/// `GICH_LR0` (0x100): list register 0 -- the heart of injection.
const GICH_LR0: u64 = 0x100;

/// `GICH_HCR.En` (bit0): enable the virtual CPU interface.
const GICH_HCR_EN: u32 = 1 << 0;
/// `GICH_HCR.EOICount` field (bits[31:27]): increments on each EOI-maintenance
/// LR retirement. The monitor reads it as a secondary completion signal (the
/// documented fallback if the ELRSR readback ever proves flaky under TCG --
/// aL2.5 uses ELRSR as the primary, so this stays defined but unexercised).
#[allow(dead_code)]
const GICH_HCR_EOICOUNT_SHIFT: u32 = 27;

// GICV register offsets within GICV_BASE (the guest's virtual CPU interface --
// touched by the guest stub + its IRQ vector, NOT by this EL2 module; named here
// only for the doc + the const-lock that keeps the stub/vectors in agreement).
/// `GICV_CTLR` (0x000): En bit0 (the guest enables its virtual CPU interface).
#[allow(dead_code)]
const GICV_CTLR: u64 = 0x000;
/// `GICV_PMR` (0x004): priority mask (the guest sets 0xFF = allow all).
#[allow(dead_code)]
const GICV_PMR: u64 = 0x004;
/// `GICV_IAR` (0x00C): read = acknowledge, returns the vINTID (the guest acks).
#[allow(dead_code)]
const GICV_IAR: u64 = 0x00C;
/// `GICV_EOIR` (0x010): write the IAR value to end the interrupt (the guest EOIs).
#[allow(dead_code)]
const GICV_EOIR: u64 = 0x010;

const _: () = assert!(GICH_LR0 == 0x100 && GICH_ELRSR0 == 0x030 && GICH_VTR == 0x004);
const _: () = assert!(GICV_IAR == 0x00C && GICV_EOIR == 0x010);

// ===========================================================================
// The EL2 armed/park-seen context cell (single-accessor; EL1 NEVER references it).
//
// `[0]` = armed flag (0/1), `[1]` = park-seen flag (set when the WFI trapped),
// `[2]` = park-count (capped: a second WFI-trap fails closed instead of looping).
// `align(64)` keeps the cells alone in one cache line -- the exact
// `exits::ExitsCtx` pattern. Accessed via plain volatile (NOT atomics): at EL2
// with `SCTLR_EL2.M=0` the memory is Normal non-cacheable, where exclusives are
// not guaranteed -- volatile is the coherent primitive.
// ===========================================================================

#[repr(C, align(64))]
struct VgicCtx(UnsafeCell<[u64; 3]>);

// SAFETY: single vCPU; the cells are touched ONLY from EL2 (the arm / WFx-inject
// / done handlers), never concurrently and never by EL1 -- like `exits::ExitsCtx`.
// No Rust reference to the interior is ever minted; access is volatile raw-pointer
// only.
unsafe impl Sync for VgicCtx {}

static VGIC_CTX: VgicCtx = VgicCtx(UnsafeCell::new([0; 3]));

fn ctx_ptr() -> *mut u64 {
    VGIC_CTX.0.get() as *mut u64
}

/// EL2: arm/disarm the vGIC injection window flag (the `WFx` inject arm gates on
/// it -- mutually exclusive with `exits::armed()` -- so a stray `WFx` OUTSIDE the
/// window fails closed, never injects). Also resets park-seen + park-count.
pub(super) fn set_armed(armed: bool) {
    // SAFETY: EL2, single accessor; `ctx_ptr()` is our static cell (64-B aligned,
    // EL1 never touches it). Aligned volatile stores of cells 0/1/2.
    unsafe {
        write_volatile(ctx_ptr().add(0), u64::from(armed));
        write_volatile(ctx_ptr().add(1), 0); // park-seen reset
        write_volatile(ctx_ptr().add(2), 0); // park-count reset
    }
}

/// EL2: is the vGIC injection window currently armed?
pub(super) fn armed() -> bool {
    // SAFETY: as `set_armed`; an aligned volatile load of cell 0.
    unsafe { read_volatile(ctx_ptr().add(0)) != 0 }
}

/// EL2: record that the guest's `WFI` trapped (the park was observed) and bump
/// the park-count. Returns the NEW park-count so the inject arm can cap it (a
/// second park == a mis-injection that would livelock -> fail closed).
pub(super) fn note_park() -> u64 {
    // SAFETY: as `set_armed`; single-accessor RMW of cells 1/2.
    unsafe {
        write_volatile(ctx_ptr().add(1), 1);
        let p = ctx_ptr().add(2);
        let n = read_volatile(p) + 1;
        write_volatile(p, n);
        n
    }
}

/// EL2: was a `WFI` park observed during the window? (Read by the done verdict;
/// a `Proven` requires the park actually happened.)
pub(super) fn park_seen() -> bool {
    // SAFETY: as `set_armed`; an aligned volatile load of cell 1.
    unsafe { read_volatile(ctx_ptr().add(1)) != 0 }
}

// ===========================================================================
// GICH MMIO accessors (EL2-physical, identity-mapped -- exactly `timer.rs`'s
// gicd/gicc pattern, for the GICH frame).
// ===========================================================================

fn gich_write(offset: u64, value: u32) {
    // SAFETY: GICH sits in the L1[0] Device-nGnRnE identity gigabyte mapped by
    // `mmu_init` (EL2: MMU off / flat Device), so `GICH_BASE + offset` is a valid
    // 32-bit MMIO address. A side-effecting MMIO store.
    unsafe { write_volatile((GICH_BASE + offset) as *mut u32, value) }
}

fn gich_read(offset: u64) -> u32 {
    // SAFETY: as `gich_write`; a side-effect-free MMIO load (GICH status regs).
    unsafe { read_volatile((GICH_BASE + offset) as *const u32) }
}

// ===========================================================================
// EL2-only: arm / inject / disarm the vGIC window (the msr HCR_EL2 + GICH glue).
// ===========================================================================

/// EL2: arm the window -- `HCR_EL2 = RW|IMO|TWI` (IMO routes the VIRQ to EL1, TWI
/// traps the guest's `WFI`) and `GICH_HCR.En = 1` (enable the virtual CPU
/// interface so list registers are presented as virtual interrupts). Zero
/// `GICH_LR0` to a clean slate first. Then `isb` + the stage-2 barrier dance so
/// the GICH config is in place before control returns to the guest.
pub(super) fn arm_vgic_el2() {
    // GICH side: clean LR0, then enable the virtual CPU interface.
    gich_write(GICH_LR0, 0);
    gich_write(GICH_HCR, GICH_HCR_EN);
    super::stage2::dsb_ish_pub();
    super::stage2::isb_pub();
    // SAFETY: EL2. Program HCR_EL2 = RW|IMO|TWI, then `isb` so the IRQ-routing +
    // WFI-trap config is in place before control returns to the guest. No
    // stack/flags effect; not `nomem` (it reconfigures trapping/routing).
    unsafe {
        asm!(
            "msr hcr_el2, {hcr}",
            "isb",
            hcr = in(reg) HCR_RW | HCR_IMO | HCR_TWI,
            options(nostack, preserves_flags),
        );
    }
}

/// EL2: INJECT a pending virtual interrupt -- ensure `GICH_HCR.En = 1`, then
/// write `GICH_LR0 = gich_lr_encode(vintid, pintid=0, state=PENDING, priority=0,
/// group0, hw=0, eoi=0)` (the Kani-proven encoder composes the u32). The
/// store lands NEXT to the just-computed value (the proof is on the leaf, the
/// glue stays outside the proof boundary). A `dsb ish` + `isb` so the GIC sees
/// the pending LR before the guest runs.
pub(super) fn inject_virq(vintid: u64) {
    // Re-assert En (belt-and-suspenders; arm_vgic_el2 already set it).
    gich_write(GICH_HCR, GICH_HCR_EN);
    let lr = gich_lr_encode(
        vintid,
        0,                     // pINTID -- unused for a SW-injected (HW=0) vIRQ
        GICH_LR_STATE_PENDING, // state = pending (the GIC HW signals the VIRQ)
        0,                     // priority 0 (highest -> passes any GICV_PMR)
        0,                     // group0
        0,                     // HW=0 -- software-injected, no physical de-activation
        0,                     // EOI=0 -- poll ELRSR for retirement, no maint IRQ
    );
    gich_write(GICH_LR0, lr);
    // The DSB/ISB so the GIC virtualization hardware observes the pending LR
    // before the guest resumes (the EL2 non-cacheable MMIO-ordering risk).
    super::stage2::dsb_ish_pub();
    super::stage2::isb_pub();
}

/// EL2: read `GICH_VTR.ListRegs` + 1 (the number of list registers the board
/// exposes). The monitor asserts this is `>= 1` so it never writes an LR the
/// board lacks (QEMU virt's num_lrs is small; aL2.5 uses only LR0).
pub(super) fn num_lrs() -> u64 {
    vtr_list_regs(gich_read(GICH_VTR))
}

/// EL2: did `GICH_LR0` RETIRE (go empty/invalid) after the guest's GICV_EOIR?
/// Read it two ways and require BOTH agree: (a) `GICH_ELRSR0` bit0 == 1 (the
/// per-LR empty-status bitmap), AND (b) the `GICH_LR0` readback decodes to State
/// == INVALID (via the Kani-proven `lr_is_retired`). A fact the guest cannot
/// fake by merely writing a magic.
pub(super) fn lr0_retired() -> bool {
    let elrsr = gich_read(GICH_ELRSR0);
    let lr0 = gich_read(GICH_LR0);
    (elrsr & 1) != 0 && lr_is_retired(lr0)
}

/// EL2: the `GICH_HCR.EOICount` field (bits[31:27]) -- increments per EOI-
/// maintenance LR retirement. A secondary completion signal (the documented
/// fallback if ELRSR readback ever proves flaky under TCG; aL2.5 uses ELRSR as
/// the primary, this as corroboration -- defined but not exercised in v1).
#[allow(dead_code)]
pub(super) fn eoi_count() -> u32 {
    gich_read(GICH_HCR) >> GICH_HCR_EOICOUNT_SHIFT
}

/// EL2: tear the window DOWN -- clear `GICH_HCR.En = 0`, zero `GICH_LR0` (no
/// stale virtual interrupt leaks into a later context), `dsb ish`/`isb`, then
/// restore `HCR_EL2 = RW` (the boot baseline) + `isb`. The MANDATORY zero-
/// regression step: leaving `HCR_EL2.TWI` armed would trap the kernel's own
/// later `wfi` (in `halt()`) to EL2 outside any window; leaving `GICH_HCR.En`
/// set could leak a stale virtual interface. Teardown is the FIRST action of the
/// done-HVC handler (the L2.1 discipline).
pub(super) fn disarm_vgic_el2() {
    // GICH side: disable the virtual CPU interface + zero the LR.
    gich_write(GICH_LR0, 0);
    gich_write(GICH_HCR, 0);
    super::stage2::dsb_ish_pub();
    super::stage2::isb_pub();
    // SAFETY: EL2. Restore the boot baseline (HCR_EL2 = RW only -- TWI/IMO clear),
    // then `isb` so the next EL1 access (incl. the kernel's halt `wfi`) is
    // untrapped + its IRQ routing is back to the kernel. No stack/flags effect.
    unsafe {
        asm!(
            "msr hcr_el2, {hcr}",
            "isb",
            hcr = in(reg) HCR_RW,
            options(nostack, preserves_flags),
        );
    }
}
