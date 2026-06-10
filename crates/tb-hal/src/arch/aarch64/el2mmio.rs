//! aarch64 **L2.3 "el2-trap"**: the trap-and-emulate ARMING glue + the MMIO
//! device-model callback SEAM + the single-accessor served-mask/context cell.
//!
//! Where L2.2 ([`super::exits`]) proves the EL2 exit-dispatch *table*, L2.3
//! proves trap-and-EMULATE: inside a short self-test window the monitor traps a
//! guest sysreg WRITE (`HCR_EL2.TVM`, EC 0x18 SYS64) and a guest MMIO LDR/STR to
//! an unmapped device IPA (`HCR_EL2.VM`, EC 0x24 DABT), DECODES each via the
//! pure [`tb_encode::el2_trap`] ISS decoders, EMULATES the access (records the
//! sysreg value; routes the MMIO access through the [`device_mmio`] seam), and
//! ADVANCES `ELR_EL2` past the trapped instruction -- the OPPOSITE of L2.1's
//! demand-retry. This module owns the silicon-unsafe arming (`msr HCR_EL2`) + the
//! EL2-only context cell + the stub device register; the handler/facade/guest
//! stub live in [`super::el2`], so `tb-hal`'s `#![forbid(unsafe_code)]` callers
//! (the kernel) only ever branch on the returned `TrapProof`.
//!
//! ## The device-model callback SEAM (the deliberate split-VMM upcall point)
//!
//! [`device_mmio`] is the aarch64 twin of the Track-A reason-30 PIO/MMIO
//! forward. TODAY it is a no_std re-host of tb-vmm's device.rs/serial.rs: ONE
//! shadow 64-bit "device register" in a single-accessor `align(64)` EL2 cell, a
//! write stores (size-masked) + returns 0, a read returns the shadow. In
//! aL2.9/the split-VMM this callback BECOMES an EXIT-UPCALL (`vcpu_run` returns
//! an MMIO exit reason {ipa,is_write,size,value}; the deprivileged tb-vmm device
//! VM services it over the hypercall/shared-ring ABI and returns the read value).
//! Keeping it a single function call NOW is what makes that later split a seam
//! and not a rewrite.
//!
//! ## Arming (HCR_EL2 -- absolute writes, mirroring `exits::arm_exits_el2`)
//!
//! The boot baseline is `HCR_EL2 = 1<<31` (RW only) for the WHOLE M0..M19 +
//! L2.0/L2.1/L2.2 run. [`arm_trap_el2`] sets `HCR_EL2 = RW | VM | TVM` for the
//! window: VM=1 so the device IPA stage-2-faults (the MMIO path), TVM=1 so EL1
//! sysreg-control WRITES trap to EL2 (the sysreg path). [`disarm_trap_el2`]
//! restores `HCR_EL2 = RW` (clears VM AND TVM) byte-for-byte (teardown-first, the
//! L2.1/L2.2 discipline) BEFORE the monitor unwinds to the kernel -- so the
//! kernel's own later sysreg writes / `wfi` are never trapped. Zero regression.
//!
//! ## The served-mask / context cell (EL2-only; the outcome leaves via x0)
//!
//! [`set_trap_served`] records which path fired (SYSREG / MMIO-write /
//! MMIO-read). [`record_sysreg_value`] captures the emulated sysreg write value.
//! All cells are written + read ONLY at EL2, never by EL1, so -- like
//! `exits::EXITS_CTX` -- it is a single-accessor `align(64)` cell that shares no
//! cache line with any EL1-written `.bss`. The VERDICT derived from it reaches
//! EL1 in the x0 register, never read by EL1 from this cacheable static.

use core::arch::asm;
use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};

// ===========================================================================
// HCR_EL2 arming bits (Linux `kvm_arm.h`; Arm ARM DDI 0487 D13).
// ===========================================================================

/// `HCR_EL2.RW` (bit31): the next lower EL (EL1) is AArch64 -- the boot baseline.
const HCR_RW: u64 = 1 << 31;
/// `HCR_EL2.VM` (bit0): enable stage-2 translation for EL1&0 (so the device IPA
/// stage-2-faults -> the MMIO emulate path). Same bit `stage2.rs` uses.
const HCR_VM: u64 = 1 << 0;
/// `HCR_EL2.TVM` (bit26): trap EL1 virtual-memory-control sysreg WRITES
/// (SCTLR/TTBR0/1/TCR/ESR/FAR/AFSR0/1/MAIR/AMAIR/CONTEXTIDR_EL1) to EL2 as EC
/// 0x18 SYS64 (`kvm_arm.h HCR_TVM`; KVM's `vcpu_reset_hcr |= HCR_TVM` non-FWB path).
const HCR_TVM: u64 = 1 << 26;

/// Served-mask bit: the SYSREG trap-and-emulate path fired (a trapped MSR to the
/// TVM trigger register was decoded + the value recorded + ELR advanced).
pub(super) const TRAP_SYSREG_BIT: u64 = 1 << 0;
/// Served-mask bit: the MMIO WRITE emulate path fired (a guest STR to the device
/// IPA was decoded + routed through `device_mmio(write)` + ELR advanced).
pub(super) const TRAP_MMIO_WR_BIT: u64 = 1 << 1;
/// Served-mask bit: the MMIO READ emulate path fired (a guest LDR from the device
/// IPA was decoded + routed through `device_mmio(read)` -> SRT + ELR advanced).
pub(super) const TRAP_MMIO_RD_BIT: u64 = 1 << 2;

// Tier-1 compile-time locks (a drift from the boot baseline is a build error).
const _: () = assert!(HCR_RW == 1 << 31);
const _: () = assert!(HCR_VM == 1);
const _: () = assert!(HCR_TVM == 0x0400_0000); // HCR_EL2.TVM == bit[26]
// The SYS64 EC the TVM trap raises is 0x18 (the proven decoder constant), kept in
// lockstep so the arming bit and the resulting exception class can never drift.
const _: () = assert!(tb_encode::el2_trap::EC_SYS64 == 0x18);

// ===========================================================================
// The MMIO device-model callback SEAM (the split-VMM upcall point).
//
// One shadow 64-bit "device register" in a single-accessor align(64) EL2 cell.
// In aL2.9 this whole body becomes an exit-upcall to the deprivileged tb-vmm
// device VM; today it is the no_std re-host of tb-vmm's device.rs/serial.rs.
// ===========================================================================

#[repr(C, align(64))]
struct DeviceCell(UnsafeCell<u64>);

// SAFETY: single vCPU; the shadow register is touched ONLY from EL2 (the MMIO
// emulate handler), never concurrently and never by EL1. No Rust reference to
// the interior is ever minted; access is volatile raw-pointer only.
unsafe impl Sync for DeviceCell {}

static DEVICE_SHADOW: DeviceCell = DeviceCell(UnsafeCell::new(0));

fn device_ptr() -> *mut u64 {
    DEVICE_SHADOW.0.get()
}

/// Size-mask for a `size`-byte access (1/2/4/8): the low `size*8` bits. `size==8`
/// yields the all-ones mask (the `1<<64` overflow is avoided by the special case).
const fn size_mask(size: u64) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    }
}

/// THE MMIO device-model SEAM. `is_write`: store `value & size_mask(size)` into
/// the shadow register, return 0. `!is_write`: return the shadow register. `ipa`
/// is accepted (the device decodes which register from it) but the stub has a
/// single register, so it is unused today -- in the split-VMM it routes to the
/// right device-VM. This is the ONLY behaviour-bearing function the aL2.9 upcall
/// will replace.
pub(super) fn device_mmio(_ipa: u64, is_write: bool, size: u64, value: u64) -> u64 {
    // SAFETY: EL2, single accessor; `device_ptr()` is our static cell (64-B
    // aligned, EL1 never touches it). One aligned volatile load or store.
    unsafe {
        if is_write {
            write_volatile(device_ptr(), value & size_mask(size));
            0
        } else {
            read_volatile(device_ptr())
        }
    }
}

/// EL2 (the done verdict): read the device shadow register (to verify the write
/// path captured the guest's stored magic).
pub(super) fn device_shadow() -> u64 {
    // SAFETY: as `device_mmio`; an aligned volatile load.
    unsafe { read_volatile(device_ptr()) }
}

// ===========================================================================
// M27a: the TWO-CELL per-VMID device shadow (the cooperative two-VMID scheduler's
// FORWARD-PROGRESS witness). Each guest, when running, STORES to a DISTINCT device
// IPA -> the M27 stage-2 faults -> the trap-and-emulate handler routes the access
// through `device_mmio_m27(.., vmid)`, INCREMENTING that VMID's cell. The monitor
// reads BOTH cells at done: both advanced == both VMIDs were scheduled + made
// forward progress (neither starved). A guest CANNOT fake a non-trapping store
// (the IPA is unmapped at stage-2), so the count is the GROUND TRUTH. A separate
// `align(64)` cell -- byte-identical to the single-VMID `DEVICE_SHADOW` when M27
// is NOT armed (the L2.3 path never touches this pair).
// ===========================================================================

#[repr(C, align(64))]
struct DeviceShadowPair(UnsafeCell<[u64; 2]>);

// SAFETY: single vCPU; the two cells are touched ONLY from EL2 (the M27 MMIO
// emulate handler increments; the done verdict reads), never concurrently and
// never by EL1. No Rust reference to the interior is ever minted; access is
// volatile raw-pointer only -- like `DeviceCell`.
unsafe impl Sync for DeviceShadowPair {}

static DEVICE_SHADOW_PAIR: DeviceShadowPair = DeviceShadowPair(UnsafeCell::new([0; 2]));

fn pair_ptr() -> *mut u64 {
    DEVICE_SHADOW_PAIR.0.get() as *mut u64
}

/// EL2: reset BOTH per-VMID forward-progress cells to 0 (called by the M27 arm
/// handler before `eret`-ing into slot 0 -- a clean slate, so a stale count from
/// a prior boot phase can never read as progress).
pub(super) fn reset_device_pair_m27() {
    // SAFETY: EL2, single accessor; two aligned volatile stores of cells 0/1.
    unsafe {
        write_volatile(pair_ptr().add(0), 0);
        write_volatile(pair_ptr().add(1), 0);
    }
}

/// THE M27a per-VMID MMIO device-model SEAM. On a WRITE (the guest's
/// forward-progress store), INCREMENT cell `vmid` (clamped to the two cells) and
/// return 0; on a READ, return the current count (the guest may read its own
/// progress back). `ipa`/`size`/`value` are accepted for parity with
/// [`device_mmio`] but the M27 device is a pure per-VMID COUNTER (the store's
/// VALUE is irrelevant -- the COUNT is the witness), so they are unused. A guest
/// cannot reach this without a trapping (unmapped-IPA) store, so the count cannot
/// be forged.
pub(super) fn device_mmio_m27(_ipa: u64, is_write: bool, _size: u64, _value: u64, vmid: u64) -> u64 {
    let cell = (vmid & 1) as usize; // two cells: VMID 0 -> [0], VMID 1 -> [1]
    // SAFETY: EL2, single accessor; `pair_ptr()` is our static cell (64-B aligned,
    // EL1 never touches it). `cell < 2`. One aligned volatile RMW (write) or load.
    unsafe {
        let p = pair_ptr().add(cell);
        if is_write {
            write_volatile(p, read_volatile(p).wrapping_add(1));
            0
        } else {
            read_volatile(p)
        }
    }
}

/// EL2 (the M27 done verdict): read VMID `vmid`'s forward-progress count.
pub(super) fn device_count_m27(vmid: u64) -> u64 {
    let cell = (vmid & 1) as usize;
    // SAFETY: as `device_mmio_m27`; an aligned volatile load of cell 0 or 1.
    unsafe { read_volatile(pair_ptr().add(cell)) }
}

// ===========================================================================
// The EL2 served-mask / context cell (single-accessor; EL1 NEVER references it).
//
// `[0]` = armed flag (0/1), `[1]` = served mask (SYSREG|MMIO_WR|MMIO_RD bits),
// `[2]` = device IPA (the expected MMIO fault IPA), `[3]` = the recorded
// sysreg-emulated write value (captured by the SYSREG path, checked at done).
// `align(64)` keeps the cells alone in one cache line so no EL1-written `.bss`
// can false-share + write back over an EL2 store -- the `exits::ExitsCtx` pattern.
// ===========================================================================

#[repr(C, align(64))]
struct TrapCtx(UnsafeCell<[u64; 4]>);

// SAFETY: single vCPU; the cells are touched ONLY from EL2 (the arm / sysreg /
// mmio / done handlers), never concurrently and never by EL1. No Rust reference
// to the interior is ever minted; access is volatile raw-pointer only.
unsafe impl Sync for TrapCtx {}

static TRAP_CTX: TrapCtx = TrapCtx(UnsafeCell::new([0; 4]));

fn ctx_ptr() -> *mut u64 {
    TRAP_CTX.0.get() as *mut u64
}

/// EL2: arm/disarm the trap-and-emulate window flag (the SYSREG/MMIO handler arms
/// gate on it so a stray exit OUTSIDE the window fails closed, never emulates).
pub(super) fn set_armed(armed: bool) {
    // SAFETY: EL2, single accessor; an aligned volatile store of cell 0.
    unsafe { write_volatile(ctx_ptr().add(0), u64::from(armed)) }
}

/// EL2: is the trap-and-emulate window currently armed?
pub(super) fn armed() -> bool {
    // SAFETY: as `set_armed`; an aligned volatile load of cell 0.
    unsafe { read_volatile(ctx_ptr().add(0)) != 0 }
}

/// EL2: record the device IPA + clear the served mask + recorded value (called
/// by the arm handler before `eret`-ing into the guest -- a clean slate).
pub(super) fn reset_context(device_ipa: u64) {
    // SAFETY: as `set_armed`; three aligned volatile stores (cells 1/2/3).
    unsafe {
        let p = ctx_ptr();
        write_volatile(p.add(1), 0); // served mask
        write_volatile(p.add(2), device_ipa); // expected MMIO fault IPA
        write_volatile(p.add(3), 0); // recorded sysreg value
    }
}

/// EL2: OR `bit` into the served mask (each emulate path records that it fired).
pub(super) fn set_trap_served(bit: u64) {
    // SAFETY: as `set_armed`; a single-accessor read-modify-write of cell 1.
    unsafe {
        let p = ctx_ptr().add(1);
        write_volatile(p, read_volatile(p) | bit);
    }
}

/// EL2: the accumulated served mask (read by the done handler to form the verdict).
pub(super) fn served() -> u64 {
    // SAFETY: as `set_armed`; an aligned volatile load of cell 1.
    unsafe { read_volatile(ctx_ptr().add(1)) }
}

/// EL2: the device IPA recorded at arm time (the expected MMIO fault IPA).
pub(super) fn device_ipa() -> u64 {
    // SAFETY: as `set_armed`; an aligned volatile load of cell 2.
    unsafe { read_volatile(ctx_ptr().add(2)) }
}

/// EL2: record the sysreg-emulated WRITE value (the SYSREG path captures the GPR
/// source so the done verdict can prove the trapped MSR was emulated).
pub(super) fn record_sysreg_value(v: u64) {
    // SAFETY: as `set_armed`; an aligned volatile store of cell 3.
    unsafe { write_volatile(ctx_ptr().add(3), v) }
}

/// EL2: the recorded sysreg-emulated WRITE value (read by the done verdict).
pub(super) fn recorded_sysreg_value() -> u64 {
    // SAFETY: as `set_armed`; an aligned volatile load of cell 3.
    unsafe { read_volatile(ctx_ptr().add(3)) }
}

// ===========================================================================
// EL2-only: arm / disarm the trap-and-emulate traps (the msr HCR_EL2 glue).
// ===========================================================================

/// EL2: arm the window -- `HCR_EL2 = RW | VM | TVM` (VM=1 so the device IPA
/// stage-2-faults; TVM=1 so EL1 VM-control sysreg writes trap), program the
/// stage-2 geometry (VTCR/VTTBR) + flush, then `isb`-synchronize so the next EL1
/// access sees the new config. Absolute writes off the boot baseline.
pub(super) fn arm_trap_el2(vtcr_val: u64, vttbr_val: u64) {
    // SAFETY: EL2. Program the stage-2 geometry + root, then HCR (RW|VM|TVM), and
    // `isb` so both the stage-2 regime AND the TVM sysreg trap are in place before
    // control returns to the guest. No stack/flags effect; not `nomem` (it
    // reconfigures translation + trapping behaviour).
    unsafe {
        asm!(
            "msr vtcr_el2,  {vtcr}",
            "msr vttbr_el2, {vttbr}",
            "isb",
            "msr hcr_el2,   {hcr}",
            "isb",
            vtcr  = in(reg) vtcr_val,
            vttbr = in(reg) vttbr_val,
            hcr   = in(reg) HCR_RW | HCR_VM | HCR_TVM,
            options(nostack, preserves_flags),
        );
    }
    // Flush any stale stage-1&2 for this VMID (parity; nothing is cached yet).
    super::stage2::tlbi_vmalls12e1is();
    super::stage2::dsb_ish_pub();
    super::stage2::isb_pub();
}

/// EL2: tear the window DOWN -- restore `HCR_EL2 = RW` only (clears VM AND TVM),
/// drop `VTTBR_EL2`, and `isb`. The MANDATORY zero-regression step: leaving TVM
/// armed would trap the kernel's own later VM-control sysreg writes, and leaving
/// VM=1 would instantly abort the kernel (its RAM is not stage-2-mapped).
/// Teardown is the FIRST action of the done-HVC handler (the L2.1/L2.2 discipline).
pub(super) fn disarm_trap_el2() {
    // SAFETY: EL2. Restore the boot baseline (HCR_EL2 = RW only -- VM=0, TVM=0),
    // drop the stage-2 root, then `isb` so the next EL1 access (incl. the kernel's
    // later sysreg writes + halt `wfi`) is untrapped + stage-1-only again. No
    // stack/flags effect; not `nomem`.
    unsafe {
        asm!(
            "msr hcr_el2,   {hcr}", // VM=0 + TVM=0 (RW=1 only) -- both traps OFF
            "msr vttbr_el2, xzr",   // drop the stage-2 root
            "isb",
            hcr = in(reg) HCR_RW,
            options(nostack, preserves_flags),
        );
    }
    super::stage2::tlbi_vmalls12e1is();
    super::stage2::dsb_ish_pub();
    super::stage2::isb_pub();
}
