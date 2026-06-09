//! aarch64 **L2.0 "el2 OK"**: the EL2 sovereignty primitive -- the aarch64
//! realization of the x86 VMX-root rung. A real EL1<->EL2 world-switch driven by
//! a SAFE [`el2_selftest`] facade (mirroring `vmx_selftest`/`VmxProof`), with
//! ALL silicon-unsafe asm confined here + in `el2_vectors.rs`/`boot.rs`; the
//! kernel crate stays `#![forbid(unsafe_code)]` and only branches on the enum.
//!
//! What runs (under PURE TCG on a stock runner -- this proof EXECUTES, it is not
//! a CI skip like the x86 vmxroot lane):
//!  1. `boot.rs::_start` booted at EL2 (QEMU `virt,virtualization=on`), installed
//!     this resident nVHE monitor (VBAR_EL2 + HCR_EL2.RW + ...), recorded
//!     [`BOOTED_AT_EL2`] `= 1`, then dropped to EL1 where M0..M18 ran unchanged.
//!  2. [`el2_selftest`] (end of boot, playing the live EL1 kernel) masks IRQs
//!     and issues the bootstrap **`HVC #0`**. It traps to EL2 through the
//!     Lower-EL-AArch64 Synchronous slot (0x400, `el2_vectors.rs`), which saves
//!     frame **B0** {x0..x30, ELR_EL2 (= the kernel's post-HVC PC), SPSR_EL2}
//!     on the dedicated monitor stack and calls [`aarch64_el2_sync_handler`].
//!  3. The handler sees `ESR_EL2.EC == HVC64` + `ISS imm == 0`, leaves B0
//!     resident, and `eret`s INTO the tiny EL1 [`guest_stub`] (its VA == PA,
//!     identity-mapped, EL1-executable kernel `.text`).
//!  4. The guest loads the magic `0xE12` into x0 and issues **`HVC #1`**, which
//!     traps back to EL2 (same 0x400 slot), saving frame **B1** one frame below
//!     B0 (B0 == B1 + 0x110, because B0 was never popped).
//!  5. The handler sees `ISS imm == 1`, reads the guest magic from `B1.gpr[0]`,
//!     overwrites `B0.gpr[0] = outcome` (0 == ok) and `B0.gpr[1] = magic`, then
//!     RESTORE_CONTEXT_EL2(B0) + `eret` -- returning to the kernel's post-HVC PC
//!     with **x0 = outcome** and every other kernel register transparent.
//!  6. [`el2_selftest`] maps x0 == 0 -> [`El2Proof::Proven`], nonzero ->
//!     [`El2Proof::RoundTripFailed`]; the kernel prints `L2.0: el2 OK`.
//!
//! Cache-coherency invariants (the EL2 handler runs with `SCTLR_EL2.M == 0`, so
//! its accesses are Device/non-cacheable, while EL1 maps the same RAM Normal-WB
//! cacheable -- an aliasing hazard if shared):
//!  * **Result via register, not a cacheable static.** The outcome reaches EL1
//!    in x0 (overwriting B0.gpr[0] before the restore), never read by EL1 from
//!    the EL2-mapped stack memory.
//!  * **Single-accessor EL2 stack.** `__el2_stack` (linker) is a region the EL1
//!    kernel NEVER references; B0/B1 and the handler frame live only there.
//!  * **`BOOTED_AT_EL2`** is the only cacheable static touched cross-EL: written
//!    once at boot with caches OFF (in `_start`, before `mmu_init`) and read
//!    here later via a cold fill -> coherent (the same caches-off-write /
//!    caches-on-read discipline every M0..M2 `.bss`/`.data` already relies on).
//!
//! Verified constants (Linux `el2_setup.h`/`esr.h`, Arm ARM DDI 0487; locked by
//! the `const _: () = assert!(...)` checks below):
//!  * `EC_HVC64 = 0x16`  -- ESR_ELx.EC for HVC in AArch64 state; EC = bits[31:26].
//!  * `SPSR = 0x3C5`     -- EL1h + DAIF masked (INIT_PSTATE_EL1) for both the
//!                          boot drop and the eret into the guest.
//!  * `SCTLR_EL2 = 0x30C50830`, `CNTHCTL_EL2 = 0x3` -- documented here, written
//!                          in `boot.rs`; the asserts keep the two in lockstep.
//!  * Frame size `0x110`; B0 == B1 + 0x110 (one frame, never popped).

use core::arch::{asm, naked_asm};
use core::sync::atomic::{AtomicU8, Ordering};

use tb_encode::el2_trap::{
    classify_exit, dabt_access_size_bytes, dabt_is_emulatable, dabt_iss_sf, dabt_iss_srt,
    dabt_iss_sse, esr_inject_undef, esr_is_translation_fault, esr_s1ptw, esr_wnr, hpfar_fault_ipa,
    sctlr_el1_guest_enable, sysreg_iss_is_read, sysreg_iss_rt, ExitClass, EC_DABT_LOW, EC_IABT_LOW,
    EL1_SYNC_SPX_OFFSET, SCTLR_EL1_GUEST_ENABLE_BITS, SYSREG_ISS_SYS_MASK, SYS_CONTEXTIDR_EL1,
};

use super::exits::{EXIT_UNDEF_BIT, EXIT_WFX_BIT};
use super::el2mmio::{TRAP_MMIO_RD_BIT, TRAP_MMIO_WR_BIT, TRAP_SYSREG_BIT};

// ===========================================================================
// Load-bearing constants (Tier-1: locked by const-asserts; mirror boot.rs).
// ===========================================================================

/// EC for `HVC` executed in AArch64 state (Linux `esr.h` ESR_ELx_EC_HVC64).
const EC_HVC64: u64 = 0x16;
/// `ESR_ELx.ISS` HVC immediate field (the 16-bit `#imm` of the HVC).
const HVC_IMM_MASK: u64 = 0xFFFF;

/// SPSR_EL2 for the drop / the eret into the guest: EL1h (M=0x5) + D|A|I|F
/// masked = 0x3C5 (INIT_PSTATE_EL1). Identical to `boot.rs`'s `SPSR_EL2`.
const SPSR_EL1H_DAIF: u64 = 0x3C5;

/// Documented EL2-setup values (WRITTEN in `boot.rs`; asserted here so the two
/// modules can never drift). See `boot.rs`'s module doc for the field rationale.
const SCTLR_EL2_VALUE: u64 = 0x30C5_0830;
const CNTHCTL_EL2_VALUE: u64 = 0x3;

/// The kernel's bootstrap HVC immediate (`hvc #0`) -- "drop into the guest".
const HVC_BOOTSTRAP: u64 = 0;
/// The guest's done HVC immediate (`hvc #1`) -- "round-trip complete".
const HVC_GUEST_DONE: u64 = 1;
/// The magic the EL1 guest stub passes in x0 (proves it ran the world-switched
/// guest). Captured at the `imm == 1` trap and echoed back to the kernel in x1.
const GUEST_MAGIC: u64 = 0xE12;

// Distinct nonzero FAIL codes (any nonzero -> `RoundTripFailed` -> red marker).
/// Guest ran but presented the wrong magic.
const FAIL_BAD_MAGIC: u64 = 0x0000_0E12_0000_0001;
/// HVC with an unexpected immediate (not #0/#1) at the Lower-EL sync slot.
const FAIL_BAD_IMM: u64 = 0x0000_0E12_0000_0002;
/// A lower-EL synchronous exception that was not an HVC64.
const FAIL_BAD_EC: u64 = 0x0000_0E12_0000_0003;
/// An exception through any non-(Lower-EL-sync) EL2 vector slot.
const FAIL_EL2_FAULT: u64 = 0x0000_0E12_0000_0004;

// Tier-1 compile-time locks on every load-bearing constant the world-switch
// depends on (plan §12). A drift here is a build error, not a boot bug.
const _: () = assert!(SPSR_EL1H_DAIF == 0x3C5);
const _: () = assert!(CNTHCTL_EL2_VALUE == 0x3);
const _: () = assert!(SCTLR_EL2_VALUE == 0x30C50830);
const _: () = assert!(EC_HVC64 == 0x16);
const _: () = assert!(HVC_BOOTSTRAP == 0 && HVC_GUEST_DONE == 1);
const _: () = assert!(core::mem::size_of::<Frame>() == 0x110);
const _: () = assert!(core::mem::offset_of!(Frame, gpr) == 0x00);
const _: () = assert!(core::mem::offset_of!(Frame, elr) == 0xF8);
const _: () = assert!(core::mem::offset_of!(Frame, spsr) == 0x100);

// ===========================================================================
// L2.1 stage-2 demand-translation constants (the second L2 rung; the abort
// path + the two new HVC immediates that bookend the stage-2 window).
// ===========================================================================

/// L2.1: the kernel's stage-2 bootstrap HVC immediate (`hvc #2`) -- "arm stage-2
/// (program VTCR/VTTBR + HCR.VM=1) and eret into the L2.1 guest stub".
const HVC_STAGE2_ARM: u64 = 2;
/// L2.1: the guest's stage-2 done HVC immediate (`hvc #3`) -- "round-trip
/// complete; tear stage-2 DOWN, then unwind to the kernel". The teardown is the
/// FIRST action on this branch (returning to EL1 with HCR.VM=1 instantly aborts
/// the kernel -- its RAM is not stage-2-mapped).
const HVC_STAGE2_DONE: u64 = 3;
/// L2.1: the magic the EL1 guest stub passes in x0 once its hole load succeeds
/// (proves the demand-translated guest actually ran). `0xACE` fits a single MOVZ.
const STAGE2_GUEST_MAGIC: u64 = 0xACE;

// L2.1 FAIL codes (distinct nonzero; any -> `Stage2Proof::Faulted` -> red marker,
// rendered WITHOUT a "stage2 OK" substring so the run-script grep stays fail-closed).
/// Could not build the stage-2 tables / demand frame at EL1 (physical-frame OOM).
const FAIL_S2_BUILD: u64 = 0x0000_0AC1_0000_0001;
/// The abort was on the guest's OWN stage-1 walk (`ESR_EL2.ISS` S1PTW=1): the
/// identity stage-2 failed to cover a live stage-1 table frame (wrong fault).
const FAIL_S2_S1PTW: u64 = 0x0000_0AC1_0000_0002;
/// The abort was NOT a translation fault (a permission/access-flag/external abort).
const FAIL_S2_NOT_XLAT: u64 = 0x0000_0AC1_0000_0003;
/// The faulting IPA was not the deliberate hole (an unexpected stage-2 fault).
const FAIL_S2_BAD_IPA: u64 = 0x0000_0AC1_0000_0004;
/// The demand map failed (a pre-built stage-2 table was unexpectedly missing --
/// a builder bug, never an allocation attempt at EL2).
const FAIL_S2_MAP: u64 = 0x0000_0AC1_0000_0005;
/// The guest presented the wrong magic at the done HVC.
const FAIL_S2_BAD_MAGIC: u64 = 0x0000_0AC1_0000_0006;
/// The guest reached done but no demand fault was served (the round-trip never
/// actually exercised the stage-2 demand path).
const FAIL_S2_NOT_SERVED: u64 = 0x0000_0AC1_0000_0007;

// Tier-1 compile-time locks on the L2.1 dispatch constants (a drift is a build
// error). The lower-EL abort EC values are imported from the proven decoder
// crate, so the kernel-side dispatch can never diverge from the Kani harnesses.
const _: () = assert!(HVC_STAGE2_ARM == 2 && HVC_STAGE2_DONE == 3);
const _: () = assert!(STAGE2_GUEST_MAGIC == 0xACE);
const _: () = assert!(EC_HVC64 == tb_encode::el2_trap::EC_HVC64);
const _: () = assert!(EC_DABT_LOW == 0x24 && EC_IABT_LOW == 0x20);

// ===========================================================================
// L2.2 exit-dispatch constants (the third L2 rung; the two new HVC immediates
// that bookend the exits window + the inject-UNDEF magic + the FAIL codes).
// ===========================================================================

/// L2.2: the kernel's exits bootstrap HVC immediate (`hvc #4`) -- "arm the
/// exit-dispatch window (HCR_EL2.TWI|TWE + CPTR_EL2.TFP) and eret into the L2.2
/// guest stub".
const HVC_EXITS_ARM: u64 = 4;
/// L2.2: the guest's exits done HVC immediate (`hvc #5`) -- "round-trip complete;
/// tear the window DOWN, then verify the served bits + magic and unwind". The
/// teardown is the FIRST action on this branch (leaving TWI|TWE|TFP armed would
/// trap the kernel's own later `wfi` -- the L2.1 teardown-first discipline).
const HVC_EXITS_DONE: u64 = 5;
/// L2.2: the magic the guest's EL1 UNDEF vector echoes once it CATCHES the
/// injected UNDEF (proves the software-synthesized exception was delivered to
/// EL1). `0xE22` fits a single MOVZ; MUST match `exits_vectors.rs`'s handler.
const UNDEF_GUEST_MAGIC: u64 = 0xE22;

// L2.2 FAIL codes (distinct nonzero; any -> `ExitsProof::Faulted` -> red marker,
// rendered WITHOUT an "el2-exits OK" substring so the run-script grep stays
// fail-closed).
/// The `WFx` arm never fired (the guest's `wfi` did not trap + resume).
const FAIL_EXITS_WFX_MISS: u64 = 0x0000_0E22_0000_0001;
/// The inject-UNDEF DEFAULT arm never fired (the FP/SIMD trap did not route to
/// `Undef` -> `el2_inject_undef`).
const FAIL_EXITS_UNDEF_MISS: u64 = 0x0000_0E22_0000_0002;
/// The guest's EL1 UNDEF vector echoed the WRONG magic (the injected exception
/// was not a genuine UNKNOWN, or a stray vector slot fired the fail trampoline).
const FAIL_EXITS_BAD_MAGIC: u64 = 0x0000_0E22_0000_0003;

// Tier-1 compile-time locks on the L2.2 dispatch constants (a drift is a build
// error). `EL1_SYNC_SPX_OFFSET` + the injected syndrome are imported from the
// proven decoder crate, so the inject vectoring can never diverge from the Kani
// harness (`kani_exit_classifier_total`).
const _: () = assert!(HVC_EXITS_ARM == 4 && HVC_EXITS_DONE == 5);
const _: () = assert!(UNDEF_GUEST_MAGIC == 0xE22);
const _: () = assert!(EL1_SYNC_SPX_OFFSET == 0x200);
const _: () = assert!(esr_inject_undef() == 0x0200_0000);
const _: () = assert!(EXIT_WFX_BIT == 1 && EXIT_UNDEF_BIT == 2);

// ===========================================================================
// L2.3 trap-and-emulate constants (the fourth L2 rung; the two new HVC
// immediates that bookend the trap window + the SYSREG/MMIO magics + FAIL codes).
// ===========================================================================

/// L2.3: the kernel's trap-and-emulate bootstrap HVC immediate (`hvc #6`) --
/// "arm the trap window (HCR_EL2 = RW|VM|TVM + program stage-2) and eret into the
/// L2.3 guest stub".
const HVC_TRAP_ARM: u64 = 6;
/// L2.3: the guest's trap-and-emulate done HVC immediate (`hvc #7`) -- "round-trip
/// complete; tear the window DOWN (HCR=RW only), then verify the served bits +
/// the recorded sysreg value + the device shadow + the guest magic and unwind".
/// Teardown is the FIRST action (leaving VM=1/TVM armed would abort/mis-trap the
/// kernel -- the L2.1/L2.2 teardown-first discipline).
const HVC_TRAP_DONE: u64 = 7;

/// L2.3: the magic the guest writes to `CONTEXTIDR_EL1` (the TVM trigger). The
/// SYSREG emulate path captures it from `frame.gpr[Rt]` and records it; the done
/// verdict checks the recorded value == this. `0x5103` fits a single MOVZ.
const SYSREG_EMU_VAL: u64 = 0x5103;
/// L2.3: the magic the guest STORES to the device IPA (the MMIO write trigger).
/// The MMIO write path routes it through `device_mmio(write)`; the done verdict
/// checks the device shadow == this AND that the guest's own LDR read it back.
/// `0x0D51` fits a single MOVZ.
const MMIO_VAL: u64 = 0x0D51;
/// L2.3: the guest's "good" outcome magic in x0 (set iff its `cmp x6,x5` proved
/// the MMIO read delivered the device value into the SRT register). `0xD23` fits
/// a single MOVZ; a `0xBAD` instead means the read path returned the wrong value.
const TRAP_GUEST_MAGIC: u64 = 0xD23;

// L2.3 FAIL codes (distinct nonzero; any -> `TrapProof::Faulted` -> red marker,
// rendered WITHOUT an "el2-trap OK" substring so the run-script grep stays
// fail-closed). The `0x0D23` tag echoes the guest magic family.
/// The SYSREG arm never fired (the trapped `msr contextidr_el1` was not emulated).
const FAIL_TRAP_SYSREG_MISS: u64 = 0x0000_0D23_0000_0001;
/// The MMIO WRITE arm never fired (the guest STR to the device IPA was not emulated).
const FAIL_TRAP_MMIO_WR_MISS: u64 = 0x0000_0D23_0000_0002;
/// The MMIO READ arm never fired (the guest LDR from the device IPA was not emulated).
const FAIL_TRAP_MMIO_RD_MISS: u64 = 0x0000_0D23_0000_0003;
/// The recorded sysreg-emulated value did not match `SYSREG_EMU_VAL` (the SYSREG
/// path captured the wrong GPR / decoded the wrong Rt).
const FAIL_TRAP_SYSREG_VAL: u64 = 0x0000_0D23_0000_0004;
/// The device shadow did not match `MMIO_VAL` (the MMIO write path stored the
/// wrong value / decoded the wrong SRT / size).
const FAIL_TRAP_MMIO_VAL: u64 = 0x0000_0D23_0000_0005;
/// The guest presented the wrong magic at done (its own `cmp x6,x5` failed -- the
/// MMIO read did not deliver the device value into the SRT register).
const FAIL_TRAP_BAD_MAGIC: u64 = 0x0000_0D23_0000_0006;
/// A trapped SYS64 that was NOT the expected CONTEXTIDR_EL1 write (TVM over-trap,
/// or a stray sysreg access while the window was armed -- fail-closed, never a
/// silent emulate).
const FAIL_TRAP_BAD_SYSREG: u64 = 0x0000_0D23_0000_0007;
/// A data abort that was NOT emulatable (ISV=0 / S1PTW=1 -- TABOS has no
/// instruction decoder, so it fails closed, the KVM `KVM_EXIT_ARM_NISV` analog).
const FAIL_TRAP_MMIO_NISV: u64 = 0x0000_0D23_0000_0008;
// 0x0000_0D23_0000_0009 (was FAIL_TRAP_BAD_IPA) is retired: a data abort at a
// NON-device IPA is no longer a failure -- `el2_mmio_emulate` now DEFERS it to
// the L2.1 stage-2 demand handler (IPA is the ground-truth window discriminator),
// so a bad/stale armed flag can never mis-route an L2.1 fault into a trap fail.
/// Could not build the device stage-2 tables at EL1 (physical-frame OOM).
const FAIL_TRAP_BUILD: u64 = 0x0000_0D23_0000_000A;

// Tier-1 compile-time locks on the L2.3 dispatch constants (a drift is a build
// error). The SYS64 trigger key + the magics are imported/locked from the proven
// decoder crate, so the kernel-side dispatch can never diverge from the harnesses.
const _: () = assert!(HVC_TRAP_ARM == 6 && HVC_TRAP_DONE == 7);
const _: () = assert!(SYS_CONTEXTIDR_EL1 == 0x32_3400);
const _: () = assert!(SYSREG_EMU_VAL == 0x5103 && MMIO_VAL == 0x0D51 && TRAP_GUEST_MAGIC == 0xD23);
const _: () = assert!(TRAP_SYSREG_BIT == 1 && TRAP_MMIO_WR_BIT == 2 && TRAP_MMIO_RD_BIT == 4);

// ===========================================================================
// aL2.4 NESTED-GUEST constants (the fifth L2 rung: a REAL minimal TABOS guest
// that runs at EL1 UNDER our EL2 stage-2 with its OWN stage-1 MMU live -- a
// GENUINE two-stage walk -- and takes its OWN EL1 exception, then HVCs done).
// ===========================================================================

/// aL2.4: the kernel's nested-guest bootstrap HVC immediate (`hvc #8`) -- "arm
/// the GiB0+GiB1 identity stage-2 (program VTCR/VTTBR + HCR.VM=1) and eret into
/// the aL2.4 guest stub". The guest then BUILDS its own stage-1 in the
/// frame_alloc'd frames handed across the frame (x4/x5/x6) and enables it.
const HVC_NESTED_GUEST_ARM: u64 = 8;
/// aL2.4: the guest's nested-guest done HVC immediate (`hvc #9`) -- "round-trip
/// complete; tear stage-2 DOWN, then verify the two-stage magic + the EL1 trap
/// + the EL2-side alias readback, and unwind". The stage-2 teardown is the FIRST
/// action on this branch (the L2.1/L2.2/L2.3 teardown-first discipline:
/// returning to EL1 with HCR.VM=1 still set instantly aborts the kernel).
const HVC_NESTED_GUEST_DONE: u64 = 9;

/// aL2.4: the magic the guest presents in x0 -- `0x2E5` ("2 stagES") -- set ONLY
/// when BOTH (1) its post-`SCTLR_EL1.M=1` load reads back the sentinel it stored
/// through the GENUINELY two-stage-translated VA AND (2) its own EL1 `brk` trap
/// was taken (x28 == NESTED_TRAP_TAKEN). A single MOVZ. The conjunction is the
/// two-stage proof: the readback cannot succeed unless the guest's stage-1 (that
/// it just built) AND our stage-2 both resolved the same physical cell.
const NESTED_GUEST_MAGIC: u64 = 0x2E5;
/// aL2.4: the "trap taken" sentinel the guest's OWN EL1 brk vector sets into x28
/// (must match `el2_nested_vectors.rs`). The guest checks `x28 == this` before
/// presenting `NESTED_GUEST_MAGIC`; equal to the magic by design (one MOVZ each).
const NESTED_TRAP_TAKEN: u64 = 0x2E5;

/// aL2.4: the guest's chosen first-stage target VA -- `0x2_0000_0000` (8 GiB,
/// stage-1 `L1[8]`). DELIBERATELY distinct from every identity-mapped region
/// (the kernel's stage-1 maps L1[0..7] only -- see stage2.rs), so this VA has NO
/// flat meaning: it is reachable ONLY through the stage-1 the guest itself
/// builds. Under T0SZ=25 (39-bit VA) `L1[8]` is a valid root index (< 512).
const NESTED_GUEST_VA: u64 = 0x2_0000_0000;
/// aL2.4: the sentinel the guest STORES through `NESTED_GUEST_VA` and reads back
/// (the load-bearing two-stage readback). The EL2 monitor independently reads it
/// through the identity IPA alias at done. `0xB22B` fits a single MOVZ.
const NESTED_SENTINEL: u64 = 0xB22B;

/// aL2.4: stage-1 descriptors the guest writes into its OWN frame_alloc'd tables
/// (mirrored BYTE-FOR-BYTE from `mmu.rs`'s M3 builder so the demonstration reuses
/// real kernel stage-1 primitives, not a toy encoding).
/// Table descriptor (L1/L2 -> next-level table): bits[1:0] = 0b11.
const NESTED_DESC_TABLE: u64 = 0b11;
/// 4 KiB Normal-WB page leaf at L3: page(0b11) | AF(1<<10) | SH inner(0b11<<8) |
/// AttrIndx1(Normal, 1<<2) == 0x707 (mmu.rs `PAGE_NORMAL`). EL1 RW (AP=0b00).
const NESTED_PAGE_NORMAL: u64 = 0b11 | (1 << 10) | (0b11 << 8) | (1 << 2);
/// 1 GiB Device block leaf at L1: block(0b01) | AF | SH | attr0 == 0x701
/// (mmu.rs `BLOCK_DEVICE`). The guest identity-maps GiB0 (incl. its own UART)
/// at `L1[0]` so its code/stack fetch survives `SCTLR_EL1.M=1`.
const NESTED_BLOCK_DEVICE: u64 = 0b01 | (1 << 10) | (0b11 << 8);
/// 1 GiB Normal-WB block leaf at L1: block(0b01) | AF | SH | attr1 == 0x705
/// (mmu.rs `BLOCK_NORMAL`). The guest identity-maps GiB1 (RAM: its `.text`,
/// stack, and its OWN frame_alloc'd stage-1 tables) at `L1[1]`.
const NESTED_BLOCK_NORMAL: u64 = 0b01 | (1 << 10) | (0b11 << 8) | (1 << 2);
/// aL2.4: the guest's MAIR_EL1 -- mirrored byte-for-byte from `mmu.rs` MAIR_VALUE
/// (attr0 = 0x00 Device-nGnRnE, attr1 = 0xFF Normal WB RA/WA).
const NESTED_MAIR_EL1: u64 = 0x00 | (0xFF << 8);
/// aL2.4: the guest's TCR_EL1 -- mirrored byte-for-byte from `mmu.rs` TCR_VALUE
/// (T0SZ=25 39-bit VA, 4 KiB granule, inner-WBWA cacheable walks, IPS 40-bit,
/// TTBR1 walks disabled). Computes to 0x2_0099_3519.
const NESTED_TCR_EL1: u64 = 25
    | (0b01 << 8)
    | (0b01 << 10)
    | (0b11 << 12)
    | (0b00 << 14)
    | (25 << 16)
    | (1 << 23)
    | (0b010 << 32);

// aL2.4 FAIL codes (distinct nonzero; any -> `NestedGuestProof::Faulted` -> red
// marker, rendered WITHOUT an "el2-guest OK" substring so the run grep is
// fail-closed). Family 0x02E5_....
/// Could not build the stage-2 / frame_alloc the guest stage-1 + scratch frames
/// at EL1 (physical-frame OOM).
const FAIL_NG_BUILD: u64 = 0x0000_02E5_0000_0001;
/// The guest's OWN stage-1 walk faulted stage-2 (`ESR_EL2.ISS` S1PTW=1): the
/// GiB0/GiB1 identity stage-2 failed to cover a live guest stage-1 table frame.
const FAIL_NG_S1PTW: u64 = 0x0000_02E5_0000_0002;
/// The EL2-side identity-alias readback of the sentinel was wrong -- the
/// two-stage walk did not land the store at PA==IPA (the check the guest cannot
/// fake; an independent EL2 corroboration of the guest's own readback).
const FAIL_NG_READBACK: u64 = 0x0000_02E5_0000_0003;
/// The guest presented the wrong x0 magic (its own post-SCTLR.M readback failed,
/// or its EL1 trap was not taken).
const FAIL_NG_BAD_MAGIC: u64 = 0x0000_02E5_0000_0004;
/// An unexpected stage-2 abort under the live guest stage-1 that was neither the
/// S1PTW case nor a translation fault at a covered IPA (fail-closed).
const FAIL_NG_BAD_IPA: u64 = 0x0000_02E5_0000_0005;

// Tier-1 compile-time locks on the aL2.4 dispatch constants (a drift is a build
// error). The MAIR/TCR geometry is mirrored byte-for-byte from mmu.rs and locked
// here; the SCTLR M|C|I enable bits are imported from the Kani-proven encoder
// (`sctlr_el1_guest_enable`), so the guest's S1-enable can never diverge from the
// harness (`kani_sctlr_el1_guest_enable`).
const _: () = assert!(HVC_NESTED_GUEST_ARM == 8 && HVC_NESTED_GUEST_DONE == 9);
const _: () = assert!(NESTED_GUEST_MAGIC == 0x2E5 && NESTED_TRAP_TAKEN == 0x2E5);
const _: () = assert!(NESTED_MAIR_EL1 == super::mmu::mmu_mair_value());
const _: () = assert!(NESTED_TCR_EL1 == super::mmu::mmu_tcr_value());
const _: () = assert!(NESTED_TCR_EL1 == 0x2_0099_3519);
const _: () = assert!(NESTED_PAGE_NORMAL == 0x707);
const _: () = assert!(SCTLR_EL1_GUEST_ENABLE_BITS == (1 << 0) | (1 << 2) | (1 << 12));
// Lock the guest's S1-enable mask to the Kani-proven `sctlr_el1_guest_enable`
// (proved in `kani_sctlr_el1_guest_enable`): the stub's `orr ...,#0x1005` mask
// IS `sctlr_el1_guest_enable(0)`, so the asm enable bits can never diverge from
// the harness. A compile-time evaluation pins the function into this build.
const _: () = assert!(sctlr_el1_guest_enable(0) == 0x1005);
const _: () = assert!(sctlr_el1_guest_enable(0) == SCTLR_EL1_GUEST_ENABLE_BITS);
const _: () = assert!((NESTED_GUEST_VA >> 30) & 0x1FF == 8); // stage-1 L1[8]
const _: () = assert!(NESTED_GUEST_VA & 0xFFF == 0); // page-aligned target
// Lock the descriptor immediates the guest stub materialises in asm to the named
// mmu.rs-mirrored constants (the stub writes 0x3/0x701/0x705/0x707 directly; a
// drift between those literals and these consts would silently mis-map the
// guest's stage-1, so pin them at compile time).
const _: () = assert!(NESTED_DESC_TABLE == 0x3);
const _: () = assert!(NESTED_BLOCK_DEVICE == 0x701);
const _: () = assert!(NESTED_BLOCK_NORMAL == 0x705);
const _: () = assert!(NESTED_PAGE_NORMAL == 0x707);
// The aL2.4 FAIL codes are distinct nonzero (a collision would mis-render the
// verdict). FAIL_NG_BAD_IPA is reserved for an unexpected stage-2 abort under the
// live guest stage-1 (v1 has full identity coverage so it is unreachable, but the
// code stays defined + distinct so a future demand sub-proof can route to it).
const _: () = assert!(FAIL_NG_BUILD != 0 && FAIL_NG_S1PTW != 0 && FAIL_NG_READBACK != 0);
const _: () = assert!(FAIL_NG_BAD_MAGIC != 0 && FAIL_NG_BAD_IPA != 0);
const _: () = assert!(FAIL_NG_BUILD != FAIL_NG_BAD_IPA && FAIL_NG_S1PTW != FAIL_NG_BAD_IPA);

// ===========================================================================
// aL2.5 vGIC constants (the sixth L2 rung: SOFTWARE-INJECT a virtual interrupt
// into a guest that PARKS on WFI, prove the guest takes + acks the vIRQ via its
// GICV virtual CPU interface and the GIC virtualization HW retires the injected
// list register).
// ===========================================================================

/// aL2.5: the kernel's vGIC bootstrap HVC immediate (`hvc #10`) -- "arm the vGIC
/// window (HCR_EL2 = RW|IMO|TWI + GICH_HCR.En) and eret into the aL2.5 guest
/// stub with PSTATE.I UNMASKED". The guest enables its GICV CPU interface, parks
/// on WFI (which traps -> the monitor injects the vIRQ + resumes), takes the
/// vIRQ at its EL1 IRQ vector, acks/EOIs, and HVCs done.
const HVC_VGIC_ARM: u64 = 10;
/// aL2.5: the guest's vGIC done HVC immediate (`hvc #11`) -- "round-trip
/// complete; TEAR the window DOWN (HCR_EL2 = RW, GICH_HCR.En=0, zero GICH_LR0)
/// FIRST, then verify the guest magic + the monitor-side LR-retired observation,
/// and unwind". Teardown-first (leaving TWI armed would trap the kernel's own
/// halt() WFI -- instant regression).
const HVC_VGIC_DONE: u64 = 11;

/// aL2.5: the vINTID the monitor injects + the guest acks (an SGI/PPI-style
/// software-injected ID; `0x2A` = 42 fits a single MOVZ and is below the GICV
/// 10-bit vINTID field). The guest's IRQ vector + the monitor's LR encode BOTH
/// use this; locked against `el2_vgic_vectors.rs`'s `movz x11, #0x2A` so a drift
/// silently breaks the ack-match.
const VGIC_VINTID: u64 = 0x2A;
/// aL2.5: the magic the guest presents in x0 -- `0x761` ("vIRQ") -- set ONLY when
/// its EL1 IRQ handler fired, read GICV_IAR == VGIC_VINTID, set x28 =
/// VGIC_IRQ_TAKEN, and wrote GICV_EOIR. A single MOVZ.
const VGIC_GUEST_MAGIC: u64 = 0x761;
/// aL2.5: the "vIRQ taken" sentinel the guest's OWN EL1 IRQ vector sets into x28
/// (must match `el2_vgic_vectors.rs`'s `movz x28, #0x5A5`). The guest checks
/// `x28 == this` before presenting `VGIC_GUEST_MAGIC`.
const VGIC_IRQ_TAKEN: u64 = 0x5A5;

/// aL2.5: the SPSR_EL2 for the eret into the vGIC guest -- EL1h (M=0x5) + D|A|F
/// masked but **I CLEAR** = `0x345` (= `0x3C5 & !(1<<7)`). DISTINCT from the
/// `SPSR_EL1H_DAIF` (0x3C5) every other rung uses, which MASKS I. The DAIF bits
/// live at SPSR[9:6] (D=9, A=8, I=7, F=6), so I is bit 7; `0x3C5` has it set,
/// `0x345` clears ONLY it (D/A/F + EL1h M field preserved). The injected VIRQ
/// only reaches the guest if PSTATE.I is UNMASKED -- a copy-paste of 0x3C5 would
/// silently never deliver the vIRQ and the guest would re-park forever (the #1
/// aL2.5 risk).
const SPSR_EL1H_VGIC: u64 = 0x345;

// aL2.5 FAIL codes (distinct nonzero; any -> `VgicProof::Faulted` -> red marker,
// rendered WITHOUT a "vgic OK" substring). Family 0x0761_....
/// The guest presented the wrong x0 magic (its EL1 IRQ handler did not fire, or
/// GICV_IAR != the injected vINTID, or the ack/EOI path did not complete).
const FAIL_VGIC_BAD_MAGIC: u64 = 0x0000_0761_0000_0001;
/// The WFI park was never observed (the guest did not reach its WFI, or TWI was
/// not armed) -- the scheduler-hook precondition failed.
const FAIL_VGIC_NO_PARK: u64 = 0x0000_0761_0000_0002;
/// The injected GICH_LR0 never retired (GICH_ELRSR0 bit0 still 0 + LR0 not
/// INVALID after the guest's EOIR) -- the GIC virtualization HW did not drive the
/// vIRQ through pending->active->invalid (a fact the guest cannot fake).
const FAIL_VGIC_NO_RETIRE: u64 = 0x0000_0761_0000_0003;
/// The board exposed zero list registers (GICH_VTR.ListRegs+1 == 0) -- LR0 is not
/// available, so injection is impossible. Fail closed (never write a missing LR).
const FAIL_VGIC_NO_LR: u64 = 0x0000_0761_0000_0004;
/// The guest's WFI trapped MORE THAN ONCE (a mis-injection livelock) -- the
/// park-count cap fired. Fail closed instead of looping to the 90s ceiling.
const FAIL_VGIC_RELOOP: u64 = 0x0000_0761_0000_0005;

// Tier-1 compile-time locks on the aL2.5 dispatch constants (a drift is a build
// error). The vINTID/sentinel/magic are mirrored into the asm guest stub +
// vector table; pin them here.
const _: () = assert!(HVC_VGIC_ARM == 10 && HVC_VGIC_DONE == 11);
const _: () = assert!(VGIC_VINTID == 0x2A && VGIC_VINTID < 1024); // fits the 10-bit field
const _: () = assert!(VGIC_GUEST_MAGIC == 0x761 && VGIC_IRQ_TAKEN == 0x5A5);
// The vGIC SPSR MUST have PSTATE.I (bit7) CLEAR so the injected VIRQ is taken;
// every other field matches the EL1h DAIF baseline except I. A const-assert pins
// it: an accidental 0x3C5 (I set) turns this build red, not a silent boot hang.
const _: () = assert!(SPSR_EL1H_VGIC & (1 << 7) == 0); // PSTATE.I UNMASKED
const _: () = assert!(SPSR_EL1H_VGIC == 0x345);
const _: () = assert!(SPSR_EL1H_VGIC == SPSR_EL1H_DAIF & !(1u64 << 7)); // == DAIF, ONLY I cleared
const _: () = assert!(SPSR_EL1H_DAIF & (1 << 7) != 0); // the other rungs MASK I
// The FAIL codes are distinct nonzero (a collision would mis-render the verdict).
const _: () = assert!(FAIL_VGIC_BAD_MAGIC != 0 && FAIL_VGIC_NO_PARK != 0);
const _: () = assert!(FAIL_VGIC_NO_RETIRE != 0 && FAIL_VGIC_NO_LR != 0 && FAIL_VGIC_RELOOP != 0);
const _: () = assert!(FAIL_VGIC_BAD_MAGIC != FAIL_VGIC_NO_PARK);
const _: () = assert!(FAIL_VGIC_NO_PARK != FAIL_VGIC_NO_RETIRE);
const _: () = assert!(FAIL_VGIC_NO_RETIRE != FAIL_VGIC_NO_LR && FAIL_VGIC_NO_LR != FAIL_VGIC_RELOOP);

// ===========================================================================
// The entry-EL flag (written ONCE by `_start`, caches off; read here).
// ===========================================================================

/// `1` iff `_start` booted at EL2 and armed the resident nVHE monitor; `0` if
/// the image entered at EL1 (no EL2). Written by `boot.rs::_start` via a raw
/// `strb` after `.bss`-zero (so it is not wiped); read by [`el2_selftest`] to
/// gate the bootstrap HVC. `#[no_mangle]` so the `_start` asm can name it.
#[no_mangle]
pub(super) static BOOTED_AT_EL2: AtomicU8 = AtomicU8::new(0);

// ===========================================================================
// The EL2 exception frame (must match `el2_vectors.rs` SAVE_CONTEXT_EL2): the
// SAME 0x110 layout as the EL1 TrapFrame but holding ELR_EL2 / SPSR_EL2.
// ===========================================================================

#[repr(C)]
pub(super) struct Frame {
    /// x0..x30 (x30 = LR), offsets 0x00..0xF0. `gpr[0]` carries the HVC's x0.
    gpr: [u64; 31],
    /// ELR_EL2 at the trap (the lower-EL return PC), offset 0xF8.
    elr: u64,
    /// SPSR_EL2 at the trap (the lower-EL PSTATE), offset 0x100.
    spsr: u64,
    /// Alignment pad; frame size is 0x110 (16-aligned).
    _pad: u64,
}

// ===========================================================================
// Privileged EL2 system-register helpers (asm confined here).
// ===========================================================================

/// Read `ESR_EL2` (the EL2 exception syndrome) -- EL2-readable, side-effect-free.
fn read_esr_el2() -> u64 {
    let v: u64;
    // SAFETY: ESR_EL2 is an EL2-readable system register; `mrs` has no memory or
    // stack effect and leaves NZCV unchanged. The handler runs at EL2.
    unsafe {
        asm!("mrs {v}, esr_el2", v = out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// Compute `__el2_stack_top` (the linker symbol) PC-relative -- no memory access,
/// so it is valid at EL2 with the MMU off. B0 (the kernel's bootstrap-HVC frame)
/// is always resident at `__el2_stack_top - 0x110` (the single-accessor stack).
fn el2_stack_top() -> u64 {
    let v: u64;
    // SAFETY: `adrp`/`add :lo12:` form the address of the linker-defined symbol
    // with no memory access; legal at EL2, MMU off. NZCV preserved.
    unsafe {
        asm!(
            "adrp {v}, __el2_stack_top",
            "add  {v}, {v}, :lo12:__el2_stack_top",
            v = out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    v
}

// ===========================================================================
// The EL1 guest stub: a position-independent EL1 payload the monitor erets into.
// ===========================================================================
// (a) PRE : reached only by the `imm == 0` handler's `eret`, executing at EL1h
//           (SPSR_EL2 = 0x3C5) under the kernel's live stage-1 MMU (HCR_EL2.VM=0,
//           no stage-2). Its VA == PA: it sits in identity-mapped, EL1-executable
//           kernel `.text` (the RAM gigabyte L1[1], PXN=0). POST: traps back to
//           EL2 via `hvc #1` with x0 = 0xE12; never runs past the `hvc` (the
//           monitor unwinds to the kernel and does not return here).
// (b) ABI : `#[unsafe(naked)]` -- EXACTLY these three instructions, all
//           PC-relative / immediate (no absolute relocation), so it is valid at
//           its identity VA. Uses NO stack (SP_EL1 untouched). `mov x0,#0xE12`
//           is a single MOVZ (0xE12 fits in 16 bits).
// (c) TEST: scripts/run-aarch64.sh -- the round-trip prints "L2.0: el2 OK".
/// The world-switched EL1 guest: pass the magic `0xE12` and `hvc #1`, then spin.
#[unsafe(naked)]
extern "C" fn guest_stub() -> ! {
    naked_asm!(
        "mov x0, #0xE12", // the guest magic in x0 (proves the guest ran at EL1)
        "hvc #1",         // trap back to the EL2 monitor (ESR_EL2.ISS imm = 1)
        "1: b 1b",        // unreachable: the monitor unwinds, never returns here
    )
}

// ===========================================================================
// The EL2 synchronous (HVC) handler -- the world-switch core. Never returns: it
// erets INTO the guest (bootstrap HVC) or BACK to the kernel (guest HVC / fail).
// ===========================================================================
// (a) PRE : entered at EL2h from the 0x400 vector after SAVE_CONTEXT_EL2; `frame`
//           = SP_EL2 = &B0 (bootstrap HVC) or &B1 (guest HVC). POST: never
//           returns -- see the per-branch `eret`s.
// (b) ABI : `extern "C"`, `#[no_mangle]` so `el2_vectors.rs` can `bl` it. `-> !`.
// (c) TEST: scripts/run-aarch64.sh -- "L2.0: el2 OK" iff the round-trip closes.
/// Dispatch one EL1->EL2 `HVC` on `ESR_EL2.EC == HVC64` + `ISS imm`.
#[no_mangle]
pub(super) extern "C" fn aarch64_el2_sync_handler(frame: *mut Frame) -> ! {
    let esr = read_esr_el2();
    // L2.2: route EVERY EL2 synchronous exit through the PURE, Kani-proven
    // ESR_EL2.EC dispatch table (`classify_exit`) -- the ARM analog of x86
    // `arm_exit_handlers[]`. Each non-HVC arm DIVERGES (handles the exit + erets);
    // the `Hvc` arm falls through to the unchanged HVC immediate dispatch below.
    // StageTwoAbort folds in the L2.1 abort path; Wfx/Undef/Smc/Sys64 are NEW and
    // only ACT inside the armed L2.2 window, else they fail closed EXACTLY as the
    // old `ec != EC_HVC64 -> FAIL_BAD_EC` path did (so M0..M19 + L2.0/L2.1 are
    // byte-for-byte unchanged: those runs only ever take HVC64 / DABT / IABT here).
    match classify_exit(esr) {
        // A stage-2 abort from a LOWER EL, routed through the SAME 0x400 vector
        // as an HVC. ONLY occurs while HCR_EL2.VM=1 (an L2.1 OR L2.3 window) --
        // VM=0 for the whole M0..M18 + L2.0/L2.2 run -- so it never collides. The
        // two windows are mutually-exclusive armed-flags: when the L2.3 trap
        // window is armed it is an MMIO device-IPA fault -> trap-and-EMULATE (the
        // device seam + ELR ADVANCE), routed BEFORE the L2.1 demand path so the
        // device IPA never reaches the demand-map (it stays unmapped per access).
        ExitClass::StageTwoAbort => {
            if super::el2mmio::armed() {
                el2_mmio_emulate(frame, esr);
            }
            aarch64_el2_stage2_abort(frame, esr)
        }
        // L2.2: a trapped WFI/WFE (only while HCR_EL2.TWI|TWE armed). RESUME the
        // guest one insn PAST the WFx (the `kvm_incr_pc` that closes
        // `kvm_handle_wfx`), recording the arm fired; outside the window it is
        // unexpected -> fail closed.
        ExitClass::Wfx => {
            // aL2.5: the vGIC injection branch (mutually exclusive with the L2.2
            // exits window -- the self-tests run sequentially so at most one is
            // armed; a debug-assert pins it). On the guest's trapped WFI (the
            // scheduler yield point), INJECT a pending vIRQ into GICH_LR0 and
            // resume past the WFI -- the now-pending VIRQ (HCR_EL2.IMO routes it,
            // PSTATE.I clear) fires immediately at the guest's EL1 IRQ vector.
            if super::el2vgic::armed() {
                debug_assert!(
                    !super::exits::armed(),
                    "aL2.5: the exits and vgic WFx windows must be mutually exclusive"
                );
                // Park-count cap: a SECOND WFI-trap means the inject/resume
                // mis-fired and the guest re-parked -> fail closed instead of
                // looping to the 90s ceiling (the WFI-as-park livelock risk).
                let parks = super::el2vgic::note_park();
                if parks > 1 {
                    el2_return_to_kernel(FAIL_VGIC_RELOOP, esr);
                }
                // Inject the pending vIRQ (GICH_HCR.En already set by the arm;
                // gich_lr_encode composes the LR0 word, the store lands next to
                // it inside el2vgic). Then advance ELR past the WFI + resume.
                super::el2vgic::inject_virq(VGIC_VINTID);
                // SAFETY: `frame` is the WFI trap frame on the single-accessor
                // monitor stack; `elr` (0xF8) is the WFI PC. Advance it by 4
                // (WFI is a 32-bit insn) so the restore-and-eret resumes PAST
                // the WFI (the guest's WFI "returns", woken by the pending vIRQ).
                unsafe { (*frame).elr += 4 };
                el2_abort_retry(frame);
            }
            // L2.2: a trapped WFI/WFE (only while HCR_EL2.TWI|TWE armed). RESUME
            // one insn PAST the WFx, recording the arm fired.
            if super::exits::armed() {
                super::exits::set_exit_served(EXIT_WFX_BIT);
                // SAFETY: `frame` is the WFx trap frame on the single-accessor
                // monitor stack; `elr` (offset 0xF8) is the faulting PC. Advance it
                // by 4 (WFx is a 32-bit insn) so the restore-and-eret resumes PAST
                // the WFx, then reuse the L2.1 restore/eret body (`el2_abort_retry`).
                unsafe { (*frame).elr += 4 };
                el2_abort_retry(frame);
            }
            el2_return_to_kernel(FAIL_BAD_EC, esr);
        }
        // L2.2: the FAIL-CLOSED DEFAULT (the FP/SIMD trap EC 0x07 via CPTR_EL2.TFP
        // -- NOT in the MUST set, exactly as `arm_exit_handlers[]`'s
        // kvm_handle_unknown_ec). Inside the window: software-inject an UNDEF into
        // the guest's own EL1 vector; outside: unexpected -> fail closed.
        ExitClass::Undef => {
            if super::exits::armed() {
                el2_inject_undef(frame);
            }
            el2_return_to_kernel(FAIL_BAD_EC, esr);
        }
        // L2.3: a trapped MSR/MRS (HCR_EL2.TVM, EC 0x18). Inside the trap window
        // it is the guest's `msr contextidr_el1` trigger -> trap-and-EMULATE
        // (record the source GPR + ELR ADVANCE); outside the window it is
        // unexpected -> fail closed (no general sysreg-emulation path exists).
        ExitClass::Sys64 => {
            if super::el2mmio::armed() {
                el2_sysreg_emulate(frame, esr);
            }
            el2_return_to_kernel(FAIL_BAD_EC, esr);
        }
        // No SMC emulation path exists in TABOS yet -- surface it honestly as a
        // fail rather than silently passing (the fail-closed table discipline).
        ExitClass::Smc => el2_return_to_kernel(FAIL_BAD_EC, esr),
        // An HVC64 -- fall through to the immediate dispatch below (UNCHANGED).
        ExitClass::Hvc => {}
    }
    match esr & HVC_IMM_MASK {
        HVC_BOOTSTRAP => {
            // imm == 0: the kernel's bootstrap HVC. Leave B0 (= frame) resident
            // and `eret` INTO the EL1 guest stub. We first reset SP_EL2 to &B0 so
            // the guest's later `hvc #1` saves B1 exactly one frame below B0
            // (B0 == B1 + 0x110), regardless of this handler's own frame usage.
            let guest = guest_stub as *const () as u64;
            // SAFETY: `frame` == &B0 on the single-accessor monitor stack. We set
            // SP_EL2 = &B0, program ELR_EL2/SPSR_EL2 for an EL1h entry at the
            // identity-mapped guest stub, and `eret`. `noreturn`: control leaves
            // EL2 for the guest and only re-enters via the guest's `hvc #1`.
            unsafe {
                asm!(
                    "mov sp, {b0}",
                    "msr elr_el2,  {guest}",
                    "msr spsr_el2, {spsr}",
                    "isb",
                    "eret",
                    b0    = in(reg) frame,
                    guest = in(reg) guest,
                    spsr  = in(reg) SPSR_EL1H_DAIF,
                    options(noreturn),
                );
            }
        }
        HVC_GUEST_DONE => {
            // imm == 1: the guest's done HVC. `frame` == &B1; read the magic the
            // guest placed in x0, then unwind back to the kernel through B0.
            // SAFETY: `frame` == &B1 on the monitor stack; `gpr[0]` is initialised
            // by SAVE_CONTEXT_EL2 and is the only field we read.
            let magic = unsafe { (*frame).gpr[0] };
            let outcome = if magic == GUEST_MAGIC { 0 } else { FAIL_BAD_MAGIC };
            el2_return_to_kernel(outcome, magic);
        }
        HVC_STAGE2_ARM => {
            // imm == 2: the kernel's L2.1 bootstrap. The demand context rides the
            // frame: x0 = stage-2 root PA, x1 = VTCR, x2 = VTTBR, x3 = stub entry,
            // x4 = demand-frame PA, x5 = expected hole IPA. Stash it for the abort
            // handler, arm stage-2, and `eret` INTO the L2.1 guest stub. Leave
            // this frame (B2.0) resident (SP_EL2 reset to it) so the guest's later
            // abort/`hvc #3` stack below it and the teardown unwinds through it.
            // SAFETY: `frame` == &B2.0 on the single-accessor monitor stack;
            // gpr[0..6] were framed by SAVE_CONTEXT_EL2 and carry the HVC #2 args.
            let (root, vtcr_v, vttbr_v, stub, demand, expect) = unsafe {
                (
                    (*frame).gpr[0],
                    (*frame).gpr[1],
                    (*frame).gpr[2],
                    (*frame).gpr[3],
                    (*frame).gpr[4],
                    (*frame).gpr[5],
                )
            };
            super::stage2::set_s2_context(root, demand, expect);
            super::stage2::arm_stage2_el2(vtcr_v, vttbr_v);
            // SAFETY: reset SP_EL2 = &B2.0, program ELR_EL2/SPSR_EL2 for an EL1h
            // entry at the identity-mapped L2.1 stub, `eret`. `noreturn`: control
            // leaves EL2 for the guest (now under stage-2) and re-enters only via
            // the stub's stage-2 abort or its `hvc #3`.
            unsafe {
                asm!(
                    "mov sp, {b0}",
                    "msr elr_el2,  {guest}",
                    "msr spsr_el2, {spsr}",
                    "isb",
                    "eret",
                    b0    = in(reg) frame,
                    guest = in(reg) stub,
                    spsr  = in(reg) SPSR_EL1H_DAIF,
                    options(noreturn),
                );
            }
        }
        HVC_STAGE2_DONE => {
            // imm == 3: the guest's L2.1 done HVC. TEARDOWN IS THE FIRST ACTION
            // (risk #1: returning to EL1 with HCR.VM=1 still set leaves the
            // kernel's RAM un-stage-2-mapped and instantly aborts it).
            super::stage2::disarm_stage2_el2();
            // `frame` == &B2.1; read the guest magic + the served IPA, then unwind
            // to the kernel through the resident B2.0 (== __el2_stack_top - 0x110).
            // SAFETY: `frame` == &B2.1 on the monitor stack; `gpr[0]` is the magic.
            let magic = unsafe { (*frame).gpr[0] };
            let served = super::stage2::s2_served();
            let expect = super::stage2::s2_expect_ipa();
            let outcome = if magic != STAGE2_GUEST_MAGIC {
                FAIL_S2_BAD_MAGIC
            } else if served != expect {
                // The guest reached done but the demand fault was never served at
                // the expected hole IPA -- the stage-2 demand path did not run.
                FAIL_S2_NOT_SERVED
            } else {
                0
            };
            el2_return_to_kernel(outcome, served);
        }
        HVC_EXITS_ARM => {
            // imm == 4: the kernel's L2.2 bootstrap. Arm the exit-dispatch window
            // (record armed + reset the served mask, then trap WFx via
            // HCR_EL2.TWI|TWE and FP/SIMD via CPTR_EL2.TFP) and `eret` INTO the
            // L2.2 guest stub. Leave this frame (B0 == __el2_stack_top - 0x110)
            // resident (SP_EL2 reset to it) so the guest's WFx/FP traps + the
            // inject + the `hvc #5` stack below it and the done unwind hits B0.
            super::exits::set_armed(true);
            super::exits::reset_served();
            super::exits::arm_exits_el2();
            let stub = exits_guest_stub as *const () as u64;
            // SAFETY: reset SP_EL2 = &B0 (= frame), program ELR_EL2/SPSR_EL2 for
            // an EL1h entry at the identity-mapped L2.2 stub, `eret`. `noreturn`:
            // control leaves EL2 for the guest (now with WFx/FP trapped) and
            // re-enters only via those traps or the guest's `hvc #5`.
            unsafe {
                asm!(
                    "mov sp, {b0}",
                    "msr elr_el2,  {guest}",
                    "msr spsr_el2, {spsr}",
                    "isb",
                    "eret",
                    b0    = in(reg) frame,
                    guest = in(reg) stub,
                    spsr  = in(reg) SPSR_EL1H_DAIF,
                    options(noreturn),
                );
            }
        }
        HVC_EXITS_DONE => {
            // imm == 5: the guest's L2.2 done HVC. TEARDOWN IS THE FIRST ACTION
            // (leaving HCR_EL2.TWI|TWE or CPTR_EL2.TFP armed would trap the
            // kernel's own later `wfi`/FP outside any window). Then verify BOTH
            // arms fired (the WFx resume AND the inject-UNDEF default) AND the
            // guest's EL1 vector echoed the right magic, and unwind to the kernel
            // through the resident B0 (== __el2_stack_top - 0x110).
            super::exits::disarm_exits_el2();
            super::exits::set_armed(false);
            // SAFETY: `frame` is the done-HVC frame on the monitor stack; `gpr[0]`
            // is the magic the guest's UNDEF vector placed in x0.
            let magic = unsafe { (*frame).gpr[0] };
            let served = super::exits::served();
            let outcome = if served & EXIT_WFX_BIT == 0 {
                FAIL_EXITS_WFX_MISS
            } else if served & EXIT_UNDEF_BIT == 0 {
                FAIL_EXITS_UNDEF_MISS
            } else if magic != UNDEF_GUEST_MAGIC {
                FAIL_EXITS_BAD_MAGIC
            } else {
                0
            };
            el2_return_to_kernel(outcome, served);
        }
        HVC_TRAP_ARM => {
            // imm == 6: the kernel's L2.3 bootstrap. The trap context rides the
            // frame: x0 = device stage-2 root PA, x1 = VTCR, x2 = VTTBR, x3 = stub
            // entry, x4 = device IPA. Record the device IPA + reset the served
            // mask, arm HCR_EL2 = RW|VM|TVM (so the device IPA stage-2-faults AND
            // EL1 VM-control sysreg writes trap), and `eret` INTO the L2.3 guest
            // stub. Leave this frame (B0 == __el2_stack_top - 0x110) resident
            // (SP_EL2 reset to it) so the guest's sysreg/MMIO traps + the `hvc #7`
            // stack below it and the done unwind hits B0.
            // SAFETY: `frame` == &B0 on the single-accessor monitor stack;
            // gpr[0..4] were framed by SAVE_CONTEXT_EL2 and carry the HVC #6 args.
            let (root, vtcr_v, vttbr_v, stub, dev_ipa) = unsafe {
                (
                    (*frame).gpr[0],
                    (*frame).gpr[1],
                    (*frame).gpr[2],
                    (*frame).gpr[3],
                    (*frame).gpr[4],
                )
            };
            let _ = root; // the root is already baked into vttbr_v (compute_vttbr)
            super::el2mmio::set_armed(true);
            super::el2mmio::reset_context(dev_ipa);
            super::el2mmio::arm_trap_el2(vtcr_v, vttbr_v);
            // SAFETY: reset SP_EL2 = &B0, program ELR_EL2/SPSR_EL2 for an EL1h
            // entry at the identity-mapped L2.3 stub, `eret`. `noreturn`: control
            // leaves EL2 for the guest (now with VM+TVM trapping) and re-enters
            // only via the sysreg/MMIO traps or the guest's `hvc #7`.
            unsafe {
                asm!(
                    "mov sp, {b0}",
                    "msr elr_el2,  {guest}",
                    "msr spsr_el2, {spsr}",
                    "isb",
                    "eret",
                    b0    = in(reg) frame,
                    guest = in(reg) stub,
                    spsr  = in(reg) SPSR_EL1H_DAIF,
                    options(noreturn),
                );
            }
        }
        HVC_TRAP_DONE => {
            // imm == 7: the guest's L2.3 done HVC. TEARDOWN IS THE FIRST ACTION
            // (leaving HCR_EL2.VM=1 would instantly abort the kernel; leaving TVM
            // armed would trap the kernel's own later VM-control sysreg writes).
            // Then verify ALL THREE arms fired (SYSREG emulate, MMIO write, MMIO
            // read) AND the recorded sysreg value == SYSREG_EMU_VAL AND the device
            // shadow == MMIO_VAL AND the guest magic == TRAP_GUEST_MAGIC, and unwind
            // to the kernel through the resident B0 (== __el2_stack_top - 0x110).
            super::el2mmio::disarm_trap_el2();
            super::el2mmio::set_armed(false);
            // SAFETY: `frame` is the done-HVC frame on the monitor stack; `gpr[0]`
            // is the guest magic (good iff its own `cmp x6,x5` matched).
            let magic = unsafe { (*frame).gpr[0] };
            let served = super::el2mmio::served();
            let sysreg_val = super::el2mmio::recorded_sysreg_value();
            let device_val = super::el2mmio::device_shadow();
            let outcome = if served & TRAP_SYSREG_BIT == 0 {
                FAIL_TRAP_SYSREG_MISS
            } else if served & TRAP_MMIO_WR_BIT == 0 {
                FAIL_TRAP_MMIO_WR_MISS
            } else if served & TRAP_MMIO_RD_BIT == 0 {
                FAIL_TRAP_MMIO_RD_MISS
            } else if sysreg_val != SYSREG_EMU_VAL {
                FAIL_TRAP_SYSREG_VAL
            } else if device_val != MMIO_VAL {
                FAIL_TRAP_MMIO_VAL
            } else if magic != TRAP_GUEST_MAGIC {
                FAIL_TRAP_BAD_MAGIC
            } else {
                0
            };
            el2_return_to_kernel(outcome, served);
        }
        HVC_NESTED_GUEST_ARM => {
            // imm == 8: the kernel's aL2.4 bootstrap. The nested-guest context
            // rides the frame: x0 = stage-2 root PA, x1 = VTCR, x2 = VTTBR,
            // x3 = stub entry, x4 = guest stage-1 L1 root PA, x5 = guest L2 PA,
            // x6 = guest L3 PA, x7 = scratch IPA (== PA, in GiB1). Stash {root,
            // scratch, scratch} for the done readback, arm the GiB0+GiB1 identity
            // stage-2 (HCR.VM=1) -- so EVERY EL1&0 access incl. the guest's OWN
            // stage-1 walk (S1PTW) is stage-2-translated -- and `eret` INTO the
            // aL2.4 guest stub WITH x4..x7 placed into the guest's registers (the
            // guest needs the runtime-allocated frame PAs it cannot materialise
            // as immediates). Leave this frame (B0 == __el2_stack_top - 0x110)
            // resident (SP_EL2 reset to it) so the guest's `hvc #9` stacks below
            // it and the done unwind hits B0.
            // SAFETY: `frame` == &B0 on the single-accessor monitor stack;
            // gpr[0..7] were framed by SAVE_CONTEXT_EL2 and carry the HVC #8 args.
            let (root, vtcr_v, vttbr_v, stub, gl1, gl2, gl3, scratch) = unsafe {
                (
                    (*frame).gpr[0],
                    (*frame).gpr[1],
                    (*frame).gpr[2],
                    (*frame).gpr[3],
                    (*frame).gpr[4],
                    (*frame).gpr[5],
                    (*frame).gpr[6],
                    (*frame).gpr[7],
                )
            };
            // Stash {root, scratch, scratch}: cell[1]=demand carries the scratch
            // PA the done handler reads back through the identity alias, cell[2]=
            // expect carries the scratch IPA (== scratch PA, the identity stage-2).
            super::stage2::set_s2_context(root, scratch, scratch);
            super::stage2::arm_stage2_el2(vtcr_v, vttbr_v);
            // SAFETY: reset SP_EL2 = &B0, place the four runtime PAs into x4..x7,
            // program ELR_EL2/SPSR_EL2 for an EL1h entry at the identity-mapped
            // aL2.4 stub, `eret`. `noreturn`: control leaves EL2 for the guest
            // (now under stage-2, S1 still OFF) and re-enters only via the guest's
            // own stage-2 abort (fail-closed) or its `hvc #9`.
            unsafe {
                asm!(
                    "mov sp, {b0}",
                    "msr elr_el2,  {guest}",
                    "msr spsr_el2, {spsr}",
                    "isb",
                    "eret",
                    b0    = in(reg) frame,
                    guest = in(reg) stub,
                    spsr  = in(reg) SPSR_EL1H_DAIF,
                    // Place the four runtime PAs DIRECTLY into the guest's x4..x7
                    // (explicit-register inputs -- no scratch `mov`, no output
                    // operand which `noreturn` forbids). The guest reads them on
                    // entry to build its OWN stage-1.
                    in("x4") gl1,
                    in("x5") gl2,
                    in("x6") gl3,
                    in("x7") scratch,
                    options(noreturn),
                );
            }
        }
        HVC_NESTED_GUEST_DONE => {
            // imm == 9: the guest's aL2.4 done HVC. TEARDOWN IS THE FIRST ACTION
            // (returning to EL1 with HCR.VM=1 still set instantly aborts the
            // kernel -- its RAM is not stage-2-mapped). The guest mutated its OWN
            // TTBR0_EL1/TCR_EL1/MAIR_EL1/SCTLR_EL1/VBAR_EL1; the FACADE restores
            // the kernel's saved values after this unwind (the EL1-side teardown).
            super::stage2::disarm_stage2_el2();
            // `frame` == &B1; read the guest magic (0x2E5 iff its two-stage
            // readback succeeded AND its EL1 brk trap was taken). Then independently
            // read the sentinel back from EL2 through the scratch IDENTITY alias
            // (PA == IPA under the identity stage-2) -- a check the guest cannot
            // fake, proving the store landed at the two-stage-resolved PA.
            // SAFETY: `frame` == &B1 on the monitor stack; `gpr[0]` is the magic.
            let magic = unsafe { (*frame).gpr[0] };
            let scratch = super::stage2::s2_demand();
            // SAFETY: EL2, MMU off (flat). `scratch` is the identity PA of the M6
            // frame the facade allocated in GiB1; an aligned volatile load reads
            // the cell the guest stored its sentinel into via the two-stage walk.
            let alias = unsafe { core::ptr::read_volatile(scratch as *const u64) };
            let outcome = if alias != NESTED_SENTINEL {
                FAIL_NG_READBACK
            } else if magic != NESTED_GUEST_MAGIC {
                FAIL_NG_BAD_MAGIC
            } else {
                0
            };
            el2_return_to_kernel(outcome, magic);
        }
        HVC_VGIC_ARM => {
            // imm == 10: the kernel's aL2.5 bootstrap. No frame context rides in
            // (the vGIC window is self-contained: the vINTID is a compile-time
            // const, the guest builds nothing). The monitor arms the window
            // (HCR_EL2 = RW|IMO|TWI + GICH_HCR.En), reads GICH_VTR to assert at
            // least one list register exists (fail closed if 0), records
            // el2vgic::set_armed(true), and `eret`s INTO the aL2.5 guest stub
            // with SPSR = SPSR_EL1H_VGIC (EL1h, PSTATE.I UNMASKED -- REQUIRED so
            // the injected VIRQ is taken). Leave this frame (B0 == __el2_stack_top
            // - 0x110) resident (SP_EL2 reset to it) so the guest's WFI-trap +
            // `hvc #11` stack below it and the done unwind hits B0.
            // SAFETY: `frame` == &B0 on the single-accessor monitor stack;
            // gpr[3] carries the stub entry framed by SAVE_CONTEXT_EL2 (HVC #10
            // args: x0..x2 unused/echoed, x3 = stub).
            let stub = unsafe { (*frame).gpr[3] };
            super::el2vgic::set_armed(true);
            super::el2vgic::arm_vgic_el2();
            // Risk: GICH_VTR.ListRegs small on the virt board -- assert >= 1 LR.
            if super::el2vgic::num_lrs() == 0 {
                super::el2vgic::disarm_vgic_el2();
                super::el2vgic::set_armed(false);
                el2_return_to_kernel(FAIL_VGIC_NO_LR, esr);
            }
            // SAFETY: reset SP_EL2 = &B0, program ELR_EL2 = stub + SPSR_EL2 =
            // SPSR_EL1H_VGIC (I-unmasked), `eret`. `noreturn`: control leaves EL2
            // for the guest (HCR_EL2.TWI armed, so its WFI re-enters EL2 via the
            // Wfx arm; the injected vIRQ then fires at the guest's EL1 vector).
            unsafe {
                asm!(
                    "mov sp, {b0}",
                    "msr elr_el2,  {guest}",
                    "msr spsr_el2, {spsr}",
                    "isb",
                    "eret",
                    b0    = in(reg) frame,
                    guest = in(reg) stub,
                    spsr  = in(reg) SPSR_EL1H_VGIC,
                    options(noreturn),
                );
            }
        }
        HVC_VGIC_DONE => {
            // imm == 11: the guest's aL2.5 done HVC (or a stray-exception fail
            // trampoline). TEARDOWN IS THE FIRST ACTION (leaving HCR_EL2.TWI armed
            // would trap the kernel's own halt() WFI -- instant regression; a
            // stale GICH_HCR.En / GICH_LR0 could leak a virtual interrupt). The
            // disarm clears HCR_EL2 to the boot baseline (RW only), GICH_HCR.En=0,
            // and zeroes GICH_LR0.
            // `frame` == &B1; read the guest magic (0x761 iff its EL1 IRQ handler
            // fired, GICV_IAR == vINTID, x28 == VGIC_IRQ_TAKEN, GICV_EOIR written).
            // SAFETY: `frame` == &B1 on the monitor stack; `gpr[0]` is the magic.
            let magic = unsafe { (*frame).gpr[0] };
            // Read the monitor-side completion proofs BEFORE teardown zeroes LR0:
            // (a) the WFI park was observed, (b) GICH_LR0 retired (ELRSR0 bit0 +
            // LR0 state INVALID -- a fact the guest cannot fake by writing a magic).
            let parked = super::el2vgic::park_seen();
            let retired = super::el2vgic::lr0_retired();
            // TEARDOWN FIRST (after reading the LR-retired proof, before unwinding).
            super::el2vgic::disarm_vgic_el2();
            super::el2vgic::set_armed(false);
            // The verdict requires the CONJUNCTION: the guest magic AND the WFI
            // park AND the monitor-side LR-retired observation. Any miss routes to
            // a distinct nonzero FAIL code (rendered WITHOUT a "vgic OK" substring).
            let outcome = if !parked {
                FAIL_VGIC_NO_PARK
            } else if magic != VGIC_GUEST_MAGIC {
                FAIL_VGIC_BAD_MAGIC
            } else if !retired {
                FAIL_VGIC_NO_RETIRE
            } else {
                0
            };
            el2_return_to_kernel(outcome, magic);
        }
        other => {
            // A valid HVC64 but an unexpected immediate -- fail, don't loop.
            el2_return_to_kernel(FAIL_BAD_IMM, other);
        }
    }
}

// ===========================================================================
// L2.3: trap-and-EMULATE a guest MSR/MRS (HCR_EL2.TVM, EC 0x18 SYS64). The
// SYSREG arm of the trap-and-emulate table. The KVM `kvm_handle_sys_reg` analog:
// decode WHICH sysreg from the ISS, EMULATE (here: record the source GPR value,
// the real CONTEXTIDR_EL1 is NEVER written), then ADVANCE ELR past the trapped
// MSR (+4, an AArch64 MSR is always 32-bit) and `eret`-resume -- exactly KVM's
// trailing `kvm_incr_pc`. Never returns: it reuses `el2_abort_retry` to resume.
// ===========================================================================
// (a) PRE : entered at EL2h from the `Sys64` arm with the trap window armed;
//           `frame` = the trap frame, `esr` = ESR_EL2 (EC 0x18, the SYS64 ISS).
//           POST: never returns -- resumes the guest PAST the MSR (it never
//           re-executes) or unwinds to the kernel on a fail. (b) ABI: plain fn.
// (c) TEST: scripts/run-aarch64.sh -- the round-trip prints "L2.3: el2-trap OK".
/// Decode + emulate one trapped MSR. Requires it be a WRITE to the expected TVM
/// trigger (CONTEXTIDR_EL1); records the source GPR value, advances ELR, resumes.
/// Any other trapped sysreg / a READ is FAIL (fail-closed, never a silent emulate).
fn el2_sysreg_emulate(frame: *mut Frame, esr: u64) -> ! {
    // The trap MUST be a WRITE (MSR) to the expected TVM trigger register. A READ
    // (MRS) or any other sysreg under TVM over-trap is fail-closed (risk #3).
    if (esr & SYSREG_ISS_SYS_MASK) != SYS_CONTEXTIDR_EL1 || sysreg_iss_is_read(esr) {
        super::el2mmio::disarm_trap_el2();
        el2_return_to_kernel(FAIL_TRAP_BAD_SYSREG, esr);
    }
    // The source GPR is ESR.ISS.Rt; read the value the guest moved to the sysreg.
    let rt = sysreg_iss_rt(esr) as usize;
    // SAFETY: `frame` is the SYS64 trap frame on the single-accessor monitor
    // stack; `gpr` (offset 0x00) was framed by SAVE_CONTEXT_EL2. `rt < 32` (a
    // 5-bit ISS field, proven by `kani_sysreg_iss_decode_total`), and `gpr` holds
    // x0..x30 (indices 0..=30); the ARMv8 GPR encoding 31 means XZR (reads 0),
    // which we map to a 0 source rather than an OOB index.
    let value = if rt < 31 {
        unsafe { (*frame).gpr[rt] }
    } else {
        0 // x31 == XZR: an MSR from the zero register writes 0
    };
    // EMULATE: record the value (the real CONTEXTIDR_EL1 is NEVER written -- we
    // advance past the MSR, so trap-and-emulate needs no save/restore), set the
    // served bit, advance ELR past the 32-bit MSR, and resume.
    super::el2mmio::record_sysreg_value(value);
    super::el2mmio::set_trap_served(TRAP_SYSREG_BIT);
    // SAFETY: `frame.elr` (offset 0xF8) is the faulting PC; +4 (the MSR is a
    // 32-bit insn, ESR.IL==1) so the restore-and-eret resumes PAST the MSR.
    unsafe { (*frame).elr += 4 };
    el2_abort_retry(frame);
}

// ===========================================================================
// L2.3: trap-and-EMULATE a guest MMIO LDR/STR to the unmapped device IPA
// (HCR_EL2.VM, EC 0x24 DABT). The MMIO arm of the trap-and-emulate table. The
// KVM `io_mem_abort` + `kvm_handle_mmio_return` analog: require ISV (else
// FAIL_MMIO_NISV, KVM's `!kvm_vcpu_dabt_isvalid` early-out), decode is_write /
// size / SRT from the DABT ISS, route the access through the `device_mmio` seam
// (write the SRT on a read, sf/sse-adjusted), then ADVANCE ELR past the trapped
// LDR/STR and `eret`-resume. Never returns: it reuses `el2_abort_retry`.
// ===========================================================================
// (a) PRE : entered at EL2h from the `StageTwoAbort` arm with the trap window
//           armed; `frame` = the abort frame, `esr` = ESR_EL2 (EC 0x24 DABT ISS).
//           POST: never returns -- resumes the guest PAST the LDR/STR or unwinds
//           on a fail. (b) ABI: plain fn, all asm via `el2_abort_retry`.
// (c) TEST: scripts/run-aarch64.sh -- the round-trip prints "L2.3: el2-trap OK".
/// Decode + emulate one MMIO data abort: gate on `dabt_is_emulatable` (ISV=1 &&
/// !S1PTW) and the expected device IPA, route through `device_mmio`, advance ELR.
fn el2_mmio_emulate(frame: *mut Frame, esr: u64) -> ! {
    // The fault IPA (HPFAR_EL2) must be EXACTLY the expected device IPA. An
    // unexpected stage-2 fault while armed is fail-closed.
    let hpfar = super::stage2::read_hpfar_el2();
    let fault_ipa = hpfar_fault_ipa(hpfar);
    let dev_ipa = super::el2mmio::device_ipa();
    if fault_ipa != dev_ipa {
        // The faulting IPA is NOT our emulated device window, so this is not an
        // MMIO access to handle here. The StageTwoAbort dispatch keys on the
        // el2mmio armed FLAG, but a flag is not a reliable window discriminator at
        // every guest-RAM init state: if it reads stale-nonzero (observed only on
        // some QEMU builds where the zero-init monitor static is not coherent at
        // L2.1 time -- TCG's no-cache model hides it on most), an L2.1 hole fault
        // can land here. The faulting IPA from HPFAR_EL2 is the GROUND TRUTH, so
        // DEFER a non-device fault to the L2.1 stage-2 demand-fault handler rather
        // than failing closed -- which makes L2.1 immune to a spuriously-armed
        // el2mmio flag. During the genuine L2.3 window the device stage-2
        // identity-maps all of GiB0+GiB1, so NO non-device fault is ever taken
        // here (the only fault is the device IPA == dev_ipa); this branch is the
        // L2.1-mis-route guard only.
        aarch64_el2_stage2_abort(frame, esr);
    }
    // The abort MUST be emulatable: ISV=1 (a single-GP LDR/STR TABOS can decode)
    // and S1PTW=0. Else fail closed (the KVM `KVM_EXIT_ARM_NISV` early-out --
    // TABOS has no instruction decoder, so it NEVER blind-decodes).
    if !dabt_is_emulatable(esr) {
        super::el2mmio::disarm_trap_el2();
        el2_return_to_kernel(FAIL_TRAP_MMIO_NISV, esr);
    }
    let is_write = esr_wnr(esr) == 1;
    let size = dabt_access_size_bytes(esr);
    let srt = dabt_iss_srt(esr) as usize;
    if is_write {
        // WRITE (STR): read the source value from gpr[SRT] and route it through
        // the device seam, then record the write arm fired.
        // SAFETY: `frame.gpr` (offset 0x00) holds x0..x30; `srt < 32` (a 5-bit
        // ISS field, proven by `kani_dabt_iss_decode_total`). srt==31 == XZR -> 0.
        let value = if srt < 31 {
            unsafe { (*frame).gpr[srt] }
        } else {
            0
        };
        super::el2mmio::device_mmio(dev_ipa, true, size, value);
        super::el2mmio::set_trap_served(TRAP_MMIO_WR_BIT);
    } else {
        // READ (LDR): get the value from the device seam, sf/sse-adjust it, and
        // write it into gpr[SRT] (the `kvm_handle_mmio_return` discipline), then
        // record the read arm fired. XZR (SRT==31) discards the result.
        let mut value = super::el2mmio::device_mmio(dev_ipa, false, size, 0);
        // 32-bit transfer (SF==0): mask the result to 32 bits.
        if dabt_iss_sf(esr) == 0 {
            value &= 0xFFFF_FFFF;
        }
        // Sign-extend a sub-register load when SSE==1 && size < 8 (the load was
        // narrower than the register width).
        if dabt_iss_sse(esr) == 1 && size < 8 {
            let bits = (size * 8) as u32;
            // Sign-extend `value` from `bits` to 64 (or to 32 then zero-extended
            // when SF==0 -- which the `& 0xFFFF_FFFF` above already applied).
            let shift = 64 - bits;
            value = (((value << shift) as i64) >> shift) as u64;
            if dabt_iss_sf(esr) == 0 {
                value &= 0xFFFF_FFFF;
            }
        }
        if srt < 31 {
            // SAFETY: as the write path; a single in-frame store of the SRT GPR.
            unsafe { (*frame).gpr[srt] = value };
        }
        super::el2mmio::set_trap_served(TRAP_MMIO_RD_BIT);
    }
    // ADVANCE ELR past the 32-bit LDR/STR (ESR.IL==1) and resume -- the guest
    // never re-executes the access (the OPPOSITE of the L2.1 demand-retry).
    // SAFETY: `frame.elr` (offset 0xF8) is the faulting PC; +4 resumes PAST it.
    unsafe { (*frame).elr += 4 };
    el2_abort_retry(frame);
}

// ===========================================================================
// L2.2: software-synthesize an Undefined-Instruction exception from EL2 into the
// EL1 guest -- a faithful inline of KVM `inject_undef64()` + `kvm_inject_sync()`
// followed by `enter_exception64(PSR_MODE_EL1h, except_type_sync)`. The
// fail-closed DEFAULT arm of the exit-dispatch table (`kvm_handle_unknown_ec`).
// Never returns: it erets into the guest's EL1 UNDEF vector.
// ===========================================================================
// (a) PRE : entered at EL2h from the `Undef` arm with the exits window armed;
//           `frame` = the FP-trap frame, `frame.elr` = the faulting guest PC,
//           `frame.spsr` = the guest PSTATE at the trap; VBAR_EL1 ==
//           __l2_guest_vectors (set by the facade). POST: never returns -- erets
//           to VBAR_EL1 + 0x200 at EL1h, where the guest's UNDEF vector echoes
//           its magic via `hvc #5`. (b) ABI: plain fn, all asm below.
// (c) TEST: scripts/run-aarch64.sh -- the inject round-trip prints
//           "L2.2: el2-exits OK".
/// Inject an UNKNOWN/UNDEF synchronous exception into the EL1 guest: program
/// `ESR_EL1`/`ELR_EL1`/`SPSR_EL1`, redirect `ELR_EL2` to `VBAR_EL1 + 0x200` (the
/// Current-EL-SPx Synchronous slot -- source EL == target EL == EL1h), set the
/// new EL1 PSTATE, and `eret`. There is NO hardware exception-delivery feature
/// involved -- the vectoring is software-synthesized exactly as
/// `enter_exception64` does in C, so it reduces to a plain EL2->EL1 `eret` to a
/// computed PC (the same primitive L2.0/L2.1 already run under TCG).
fn el2_inject_undef(frame: *mut Frame) -> ! {
    // Record that the inject-UNDEF DEFAULT arm fired (read by the done verdict).
    super::exits::set_exit_served(EXIT_UNDEF_BIT);
    // SAFETY: `frame` is the FP-trap frame on the single-accessor monitor stack;
    // `elr`/`spsr` (offsets 0xF8/0x100) were framed by SAVE_CONTEXT_EL2.
    let (elr, spsr) = unsafe { ((*frame).elr, (*frame).spsr) };
    let esr_el1 = esr_inject_undef(); // EC=0x00 (UNKNOWN) | IL == 0x0200_0000
    // Compute the EL1 vector entry in Rust (VBAR_EL1 + 0x200, the Current-EL-SPx
    // Synchronous slot -- NOT the Lower-EL +0x400 slot, since source EL == target
    // EL == EL1h). `read_vbar_el1()` is a side-effect-free `mrs` legal at EL2 too
    // (VBAR_EL1 is EL2-accessible); computing it here avoids a scratch *output*
    // register, which the `noreturn` asm below forbids.
    let vector = read_vbar_el1().wrapping_add(EL1_SYNC_SPX_OFFSET);
    // SAFETY: at EL2, ESR_EL1/ELR_EL1/SPSR_EL1 are EL2-accessible. We program the
    // guest's exception-return state (ESR/ELR/SPSR_EL1), redirect the EL2 eret to
    // the computed EL1 vector with the INIT_PSTATE_EL1 SPSR, and `eret`.
    // `noreturn`: control leaves EL2 for the guest's EL1 UNDEF vector and re-enters
    // only via that vector's `hvc #5`. All operands are INPUTS (noreturn forbids
    // outputs).
    unsafe {
        asm!(
            "msr esr_el1,  {esr}",   // inject_undef64: ESR_EL1 = UNKNOWN | IL
            "msr elr_el1,  {gelr}",  // enter_exception64: ELR_EL1 = faulting PC
            "msr spsr_el1, {gspsr}", // enter_exception64: SPSR_EL1 = old PSTATE
            "msr elr_el2,  {vec}",   // redirect the EL2 eret -> VBAR_EL1 + 0x200
            "msr spsr_el2, {npsr}",  // new EL1 PSTATE = EL1h + DAIF (INIT_PSTATE_EL1)
            "isb",
            "eret",
            esr   = in(reg) esr_el1,
            gelr  = in(reg) elr,
            gspsr = in(reg) spsr,
            vec   = in(reg) vector,
            npsr  = in(reg) SPSR_EL1H_DAIF,
            options(noreturn),
        );
    }
}

// ===========================================================================
// The EL2 stage-2 DEMAND-FAULT handler (L2.1) -- the ARM analog of the x86
// EPT-violation exit. Entered from the 0x400 vector when an EL1 access faults
// stage-2 translation (ESR_EL2.EC == DABT_LOW/IABT_LOW). Never returns: on the
// expected hole fault it demand-maps and ERET-RETRIES the faulting instruction
// WITHOUT advancing ELR_EL2 (the defining demand-fault behaviour); on any
// unexpected fault it tears stage-2 DOWN and unwinds to the kernel with a FAIL.
// ===========================================================================
// (a) PRE : entered at EL2h from 0x400 after SAVE_CONTEXT_EL2 with HCR_EL2.VM=1;
//           `frame` == SP_EL2 == &(the abort frame, one below the resident B2.0),
//           `esr` == ESR_EL2. POST: never returns (eret-retry into the guest, or
//           unwind to the kernel via B2.0). (b) ABI: plain fn, all asm below.
// (c) TEST: scripts/run-aarch64.sh -- the demand round-trip prints "L2.1: stage2 OK".
/// Service one stage-2 abort: read HPFAR/ESR, validate it is the deliberate
/// hole's translation fault (not S1PTW / not a permission fault / not the wrong
/// IPA), [`super::stage2::demand_map_ipa`] it, and ERET-retry the faulting load.
fn aarch64_el2_stage2_abort(frame: *mut Frame, esr: u64) -> ! {
    let hpfar = super::stage2::read_hpfar_el2();
    let fault_ipa = hpfar_fault_ipa(hpfar);
    let root = super::stage2::s2_root();
    let demand = super::stage2::s2_demand();
    let expect = super::stage2::s2_expect_ipa();

    // S1PTW: the fault was on the guest's OWN stage-1 walk -- the identity stage-2
    // should have covered the live stage-1 table frames. The wrong thing faulted;
    // tear stage-2 DOWN (before any unwind to EL1) and fail.
    if esr_s1ptw(esr) != 0 {
        super::stage2::disarm_stage2_el2();
        el2_return_to_kernel(FAIL_S2_S1PTW, fault_ipa);
    }
    // Must be a translation fault (the demand condition), not a permission /
    // access-flag / external abort.
    if !esr_is_translation_fault(esr) {
        super::stage2::disarm_stage2_el2();
        el2_return_to_kernel(FAIL_S2_NOT_XLAT, esr);
    }
    // The faulting IPA (from HPFAR_EL2) must be EXACTLY the deliberate hole, AND
    // the faulting VA's page (from FAR_EL2) must agree -- under the identity
    // stage-1 the guest VA == IPA, so a mismatch on either means the guest
    // touched something it should not have (an isolation breach), not the hole.
    let far_page = super::stage2::read_far_el2() & !0xFFF;
    if fault_ipa != expect || far_page != expect {
        super::stage2::disarm_stage2_el2();
        el2_return_to_kernel(FAIL_S2_BAD_IPA, fault_ipa);
    }
    // Splice the stage-2 leaf for the hole (NO allocation -- the table path was
    // pre-built at EL1). A failure here means a builder bug, not a guest fault.
    if !super::stage2::demand_map_ipa(root, fault_ipa, demand) {
        super::stage2::disarm_stage2_el2();
        el2_return_to_kernel(FAIL_S2_MAP, fault_ipa);
    }
    // Success: record the served IPA, then ERET-RETRY the faulting instruction
    // WITHOUT advancing ELR_EL2 -- the demand-fault path re-executes the load,
    // the exact OPPOSITE of the HVC arms (which set ELR explicitly). Stage-2
    // stays armed; the guest continues and closes the round-trip with `hvc #3`.
    super::stage2::set_s2_served(fault_ipa);
    el2_abort_retry(frame);
}

// ===========================================================================
// ERET-retry the faulting instruction (L2.1 abort success path). RESTORE the
// abort frame EXACTLY as saved -- crucially leaving ELR_EL2 UNCHANGED -- and
// `eret`, so the guest re-executes the (now stage-2-mapped) faulting load.
// ===========================================================================
/// Restore `frame` (the abort frame) and `eret` back into the guest WITHOUT
/// advancing ELR_EL2. The structural guarantee that the demand-fault path never
/// calls an ELR-advance helper: it re-runs the faulting load, never skips it.
fn el2_abort_retry(frame: *mut Frame) -> ! {
    // SAFETY: `frame` is the abort frame on the single-accessor monitor stack
    // (one frame below the resident B2.0). We RESTORE_CONTEXT_EL2 (pop x0..x30 +
    // ELR_EL2 + SPSR_EL2 EXACTLY as SAVE_CONTEXT_EL2 stored them -- ELR_EL2 is the
    // faulting PC, left UNCHANGED) and `eret`. The faulting load re-executes; its
    // IPA is now stage-2-mapped, so it succeeds. `noreturn`: control returns to
    // the guest and re-enters EL2 only via the guest's `hvc #3`.
    unsafe {
        asm!(
            "mov sp, {f}",
            "ldp x9,  x10, [sp, #0xF8]", // elr @ 0xF8 (faulting PC -- UNCHANGED), spsr @ 0x100
            "msr elr_el2,  x9",
            "msr spsr_el2, x10",
            "ldp x0,  x1,  [sp, #0x00]",
            "ldp x2,  x3,  [sp, #0x10]",
            "ldp x4,  x5,  [sp, #0x20]",
            "ldp x6,  x7,  [sp, #0x30]",
            "ldp x8,  x9,  [sp, #0x40]",
            "ldp x10, x11, [sp, #0x50]",
            "ldp x12, x13, [sp, #0x60]",
            "ldp x14, x15, [sp, #0x70]",
            "ldp x16, x17, [sp, #0x80]",
            "ldp x18, x19, [sp, #0x90]",
            "ldp x20, x21, [sp, #0xA0]",
            "ldp x22, x23, [sp, #0xB0]",
            "ldp x24, x25, [sp, #0xC0]",
            "ldp x26, x27, [sp, #0xD0]",
            "ldp x28, x29, [sp, #0xE0]",
            "ldr x30,      [sp, #0xF0]",
            "add sp, sp, #0x110",
            "eret",
            f = in(reg) frame,
            options(noreturn),
        );
    }
}

// ===========================================================================
// The EL2 fatal-vector handler: any non-(Lower-EL-sync) slot. Surfaces a FAIL by
// unwinding to the kernel (never a silent loop / hang).
// ===========================================================================
/// Handle an unexpected EL2 exception (e.g. the guest stub aborting instead of
/// HVC-ing): unwind to the kernel's resident B0 with a nonzero code carrying the
/// EL2 syndrome, so [`el2_selftest`] reports `RoundTripFailed` (red marker).
#[no_mangle]
pub(super) extern "C" fn aarch64_el2_fault_handler(_frame: *mut Frame) -> ! {
    let esr = read_esr_el2();
    el2_return_to_kernel(FAIL_EL2_FAULT, esr);
}

// ===========================================================================
// Unwind EL2 -> EL1 (kernel): write the result into the resident B0 and ERET.
// ===========================================================================
/// Deliver `code` (returned to the kernel in x0) and `x1val` (in x1) by
/// overwriting the resident bootstrap frame **B0** at `__el2_stack_top - 0x110`,
/// then RESTORE_CONTEXT_EL2(B0) + `eret` to the kernel's post-`HVC #0` PC. B0's
/// saved ELR_EL2/SPSR_EL2 carry the kernel's return PC and EL1h PSTATE, and its
/// x2..x30 are the kernel's pre-HVC values -- so the bootstrap HVC is fully
/// transparent except x0 = `code`, x1 = `x1val` (both caller-saved / clobbered).
fn el2_return_to_kernel(code: u64, x1val: u64) -> ! {
    let b0 = (el2_stack_top() - 0x110) as *mut Frame;
    // SAFETY: B0 lives in the single-accessor monitor stack (the EL1 kernel never
    // references it); it was fully initialised by the bootstrap HVC's
    // SAVE_CONTEXT_EL2. We overwrite only gpr[0]/gpr[1] (the result registers).
    unsafe {
        (*b0).gpr[0] = code;
        (*b0).gpr[1] = x1val;
    }
    // SAFETY: reset SP_EL2 to &B0 and RESTORE_CONTEXT_EL2 (pop x0..x30 + ELR_EL2 +
    // SPSR_EL2), then `eret` to EL1 at the kernel's post-HVC PC. The result
    // reaches EL1 in x0 (a register), never via the EL2-mapped (non-cacheable)
    // stack -- no EL2-MMU-off / EL1-cacheable aliasing hazard. `noreturn`:
    // control leaves EL2 for good and the abandoned frames below SP are inert.
    unsafe {
        asm!(
            "mov sp, {b0}",
            "ldp x9,  x10, [sp, #0xF8]", // elr @ 0xF8, spsr @ 0x100
            "msr elr_el2,  x9",
            "msr spsr_el2, x10",
            "ldp x0,  x1,  [sp, #0x00]", // x0 = code, x1 = x1val (just written)
            "ldp x2,  x3,  [sp, #0x10]",
            "ldp x4,  x5,  [sp, #0x20]",
            "ldp x6,  x7,  [sp, #0x30]",
            "ldp x8,  x9,  [sp, #0x40]",
            "ldp x10, x11, [sp, #0x50]",
            "ldp x12, x13, [sp, #0x60]",
            "ldp x14, x15, [sp, #0x70]",
            "ldp x16, x17, [sp, #0x80]",
            "ldp x18, x19, [sp, #0x90]",
            "ldp x20, x21, [sp, #0xA0]",
            "ldp x22, x23, [sp, #0xB0]",
            "ldp x24, x25, [sp, #0xC0]",
            "ldp x26, x27, [sp, #0xD0]",
            "ldp x28, x29, [sp, #0xE0]",
            "ldr x30,      [sp, #0xF0]",
            "add sp, sp, #0x110",
            "eret",
            b0 = in(reg) b0,
            options(noreturn),
        );
    }
}

// ===========================================================================
// The safe facade: el2_selftest() -> El2Proof (the only public surface).
// ===========================================================================
// (a) PRE : called once from the kernel at the L2.0 slot (end of boot), at EL1h
//           with the resident monitor armed (when BOOTED_AT_EL2 == 1). POST:
//           issued ONE bootstrap `HVC #0`, drove the ERET->guest->HVC->EL2
//           round-trip, and returns the outcome enum. Graceful skip (no HVC, no
//           fault) when not booted at EL2.
// (b) ABI : plain safe `fn`; all asm/unsafe confined above + in el2_vectors.rs /
//           boot.rs, so the `#![forbid(unsafe_code)]` kernel only branches on
//           the returned `El2Proof`.
// (c) TEST: scripts/run-aarch64.sh -- "L2.0: el2 OK" iff this returns `Proven`.
/// Drive the EL1->EL2->EL1-guest->EL2->EL1 world-switch and report the outcome.
/// `Unavailable` if we did not boot at EL2 (a green skip); `Proven` on a closed
/// round-trip; `RoundTripFailed{code}` if the monitor reported a fault.
pub fn el2_selftest() -> crate::El2Proof {
    use crate::El2Proof;

    // Graceful skip: no resident monitor -> issuing HVC would fault, so don't.
    // BOOTED_AT_EL2 was written caches-off at boot and is read here via a cold
    // fill (coherent), the same discipline M0..M2 `.bss` already relies on.
    if BOOTED_AT_EL2.load(Ordering::Acquire) != 1 {
        return El2Proof::Unavailable;
    }

    // Mask EL1 IRQs across the round-trip (belt-and-suspenders; mirrors
    // `vmx_selftest`'s `cli`). The guest also runs with DAIF masked (SPSR=0x3C5).
    let daif = super::timer::local_irq_save();

    let code: u64;
    // SAFETY: the resident EL2 monitor (armed in `_start`) catches `hvc #0`,
    // erets into the EL1 guest stub, catches the guest's `hvc #1`, and erets back
    // here with the outcome in x0 and every kernel register restored from B0
    // (x2..x30 transparent; x0/x1 are caller-saved, covered by clobber_abi("C")).
    // Nothing here touches the EL2 stack memory -- the result arrives in x0.
    unsafe {
        asm!("hvc #0", out("x0") code, clobber_abi("C"));
    }

    super::timer::local_irq_restore(daif);

    if code == 0 {
        El2Proof::Proven { hvc_imm: HVC_GUEST_DONE }
    } else {
        El2Proof::RoundTripFailed { code }
    }
}

// ===========================================================================
// L2.1: the EL1 guest stub that DELIBERATELY touches the stage-2 hole.
// ===========================================================================
// (a) PRE : reached only by the `HVC #2` handler's `eret`, executing at EL1h
//           (SPSR_EL2 = 0x3C5) under the kernel's live stage-1 MMU AND the armed
//           stage-2 (HCR_EL2.VM=1). Its VA == PA: identity-mapped, EL1-executable
//           kernel `.text` in the RAM gigabyte (GiB1, which stage-2 identity-maps,
//           so the fetch + stack never S1PTW-fault). POST: the `ldr` from the hole
//           VA faults to EL2 (stage-2 translation fault); the monitor demand-maps
//           and ERET-retries WITHOUT advancing ELR, so the SAME `ldr` re-executes
//           and succeeds; the stub then `hvc #3`s and the monitor unwinds (never
//           returns here).
// (b) ABI : `#[unsafe(naked)]` -- PC-relative / immediate only (valid at its
//           identity VA), no stack. The hole VA `0x1_4000_0000` (== stage2.rs
//           `HOLE_IPA`) is materialised with MOVZ+MOVK; `mov x0,#0xACE` is one MOVZ.
// (c) TEST: scripts/run-aarch64.sh -- the demand round-trip prints "L2.1: stage2 OK".
/// The L2.1 guest: load from the stage-2 hole VA (faults -> EL2 demand-maps ->
/// retry succeeds), present the magic `0xACE` in x0, and `hvc #3` to close.
#[unsafe(naked)]
extern "C" fn stage2_guest_stub() -> ! {
    naked_asm!(
        "movz x2, #0x4000, lsl #16", // x2 = 0x0000_0000_4000_0000
        "movk x2, #0x0001, lsl #32", // x2 = 0x0000_0001_4000_0000 == HOLE_IPA (the hole VA)
        "ldr  x1, [x2]",             // stage-2 demand fault -> EL2 maps -> retry OK
        "mov  x0, #0xACE",           // the L2.1 guest magic (proves the guest ran)
        "hvc  #3",                   // trap back to EL2 (done): teardown + unwind
        "1: b 1b",                   // unreachable: the monitor unwinds, never here
    )
}

// ===========================================================================
// L2.1: the safe facade: stage2_selftest() -> Stage2Proof.
// ===========================================================================
// (a) PRE : called once from the kernel at the L2.1 slot (right after L2.0), at
//           EL1h, with the resident monitor armed (BOOTED_AT_EL2 == 1). POST:
//           built the stage-2 tables + pre-allocated the demand frame AT EL1,
//           spliced the stage-1 hole block, issued ONE `HVC #2`, drove the
//           arm -> guest -> stage-2 abort -> demand-map -> retry -> guest `hvc #3`
//           -> TEARDOWN -> unwind round-trip, and returns the outcome enum. The
//           kernel resumes here at EL1 with stage-2 fully torn down (HCR.VM=0).
//           Graceful skip (no HVC, no fault) when not booted at EL2.
// (b) ABI : plain safe `fn`; all asm/unsafe confined here + in `stage2.rs` /
//           `el2_vectors.rs`, so the `#![forbid(unsafe_code)]` kernel only
//           branches on the returned `Stage2Proof`.
// (c) TEST: scripts/run-aarch64.sh -- "L2.1: stage2 OK" iff this returns `Proven`.
/// Drive the EL1->EL2(arm)->EL1-guest->EL2(demand)->EL1-guest->EL2(done+teardown)
/// ->EL1 stage-2 demand-translation round-trip and report the outcome.
/// `Unavailable` if we did not boot at EL2 (a green skip); `Proven{fault_ipa}` on
/// the closed demand round-trip; `Faulted{code}` on any monitor-reported fault.
pub fn stage2_selftest() -> crate::Stage2Proof {
    use crate::Stage2Proof;

    // Graceful skip: no resident monitor -> no stage-2 to arm, no HVC issued.
    if BOOTED_AT_EL2.load(Ordering::Acquire) != 1 {
        return Stage2Proof::Unavailable;
    }

    // Build the stage-2 regime + pre-allocate the demand frame AT EL1 (the EL2
    // abort handler does NO allocation -- risk #4). On physical-frame OOM, surface
    // a Faulted code honestly (a red marker, never a faked OK).
    let root = match super::stage2::build_identity_stage2() {
        Some(r) => r,
        None => return Stage2Proof::Faulted { code: FAIL_S2_BUILD },
    };
    let demand = match super::stage2::prep_demand_frame() {
        Some(d) => d,
        None => return Stage2Proof::Faulted { code: FAIL_S2_BUILD },
    };
    // Splice the stage-1 identity block at L1[5] so the guest VA HOLE_IPA produces
    // IPA HOLE_IPA (which stage-2 then faults). Its stage-1 walk touches only the
    // L1 root (in GiB1, stage-2-covered), so it never S1PTW-faults.
    super::stage2::install_stage1_hole_block();

    let vtcr_v = super::stage2::compute_vtcr();
    let vttbr_v = super::stage2::compute_vttbr(root);
    let stub = stage2_guest_stub as *const () as u64;
    let expect = super::stage2::HOLE_IPA;

    // Mask EL1 IRQs across the round-trip (the guest also runs DAIF-masked).
    let daif = super::timer::local_irq_save();

    let outcome: u64;
    let fault_ipa: u64;
    // SAFETY: the resident EL2 monitor catches `hvc #2`, programs VTCR/VTTBR and
    // sets HCR.VM=1, then erets into the EL1 guest stub (now under stage-2). The
    // stub's load faults the hole; the monitor demand-maps + eret-retries (ELR
    // unchanged); the stub's `hvc #3` TEARS stage-2 DOWN (HCR.VM=0) FIRST and
    // unwinds here with x0 = outcome, x1 = fault_ipa, every other kernel register
    // restored from B2.0. The result arrives in registers -- nothing here touches
    // the EL2 stack. x2..x5 carry the in-args; clobber_abi("C") covers the rest.
    unsafe {
        asm!(
            "hvc #2",
            inout("x0") root => outcome,
            inout("x1") vtcr_v => fault_ipa,
            in("x2") vttbr_v,
            in("x3") stub,
            in("x4") demand,
            in("x5") expect,
            clobber_abi("C"),
        );
    }

    super::timer::local_irq_restore(daif);

    if outcome == 0 {
        Stage2Proof::Proven { fault_ipa }
    } else {
        Stage2Proof::Faulted { code: outcome }
    }
}

// ===========================================================================
// L2.2: the EL1 guest stub that fires TWO distinct trapping exits.
// ===========================================================================
// (a) PRE : reached only by the `HVC #4` handler's `eret`, executing at EL1h
//           (SPSR_EL2 = 0x3C5) under the kernel's live stage-1 MMU (HCR_EL2.VM=0,
//           NO stage-2 -- the L2.0 simple world) with the exit window armed
//           (HCR_EL2.TWI|TWE + CPTR_EL2.TFP). Its VA == PA: identity-mapped,
//           EL1-executable kernel `.text` (GiB1). POST: the `wfi` traps to EL2
//           (EC 0x01 WFx) -> the Wfx arm resumes one insn PAST it; the FP `.inst`
//           then traps to EL2 (EC 0x07 FP_ASIMD via CPTR_EL2.TFP) -> the Undef
//           DEFAULT arm injects an UNDEF, so the SAME `.inst` never executes and
//           control redirects to the guest's EL1 UNDEF vector -- the stub never
//           reaches the `b 1b` (the monitor unwinds, never returns here).
// (b) ABI : `#[unsafe(naked)]` -- PC-relative / immediate only (valid at its
//           identity VA), NO stack (SP_EL1 untouched). The FP trigger is emitted
//           via `.inst 0x1e2703e0` (= `fmov s0, wzr`, an FP/SIMD access) so the
//           softfloat `-fp-armv8,-neon` assembler gate does NOT reject it.
// (c) TEST: scripts/run-aarch64.sh -- the exit round-trip prints "L2.2: el2-exits OK".
/// The L2.2 guest: execute a `wfi` (traps -> Wfx arm -> resume) then an FP/SIMD
/// access (traps -> Undef default -> inject UNDEF), proving TWO exit-table arms.
#[unsafe(naked)]
extern "C" fn exits_guest_stub() -> ! {
    naked_asm!(
        "wfi",              // 1st trap: WFx (EC 0x01) -> Wfx arm -> ELR+=4, resume
        ".inst 0x1e2703e0", // 2nd trap: fmov s0, wzr (FP/SIMD) -> CPTR.TFP (EC 0x07)
        "1: b 1b",          // unreachable: the monitor injects UNDEF + unwinds, never here
    )
}

// ===========================================================================
// L2.2: EL1 privileged-register helpers for the self-test facade (asm confined).
// ===========================================================================

/// `CPACR_EL1.FPEN = 0b11` (bits[21:20]) -- do NOT trap EL1&0 FP/SIMD to EL1, so
/// the L2.2 FP trigger reaches the `CPTR_EL2.TFP` EL2 trap (the fail-closed
/// default arm). The facade sets this for the window and restores the saved value.
const CPACR_FPEN_NOTRAP: u64 = 0b11 << 20;
const _: () = assert!(CPACR_FPEN_NOTRAP == 0x30_0000);

/// EL1: read `VBAR_EL1` (the current EL1 exception vector base). Side-effect-free.
fn read_vbar_el1() -> u64 {
    let v: u64;
    // SAFETY: VBAR_EL1 is EL1-readable; `mrs` has no memory/stack effect and
    // leaves NZCV unchanged.
    unsafe {
        asm!("mrs {v}, vbar_el1", v = out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// EL1: write `VBAR_EL1` + `isb` so the new vector base is architecturally visible.
fn write_vbar_el1(v: u64) {
    // SAFETY: writing VBAR_EL1 is legal at EL1; `isb` synchronizes the change so
    // the very next exception uses the new base.
    unsafe {
        asm!("msr vbar_el1, {v}", "isb", v = in(reg) v, options(nomem, nostack, preserves_flags));
    }
}

/// EL1: read `CPACR_EL1` (the FP/SIMD + copro access-control register).
fn read_cpacr_el1() -> u64 {
    let v: u64;
    // SAFETY: CPACR_EL1 is EL1-readable; side-effect-free.
    unsafe {
        asm!("mrs {v}, cpacr_el1", v = out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// EL1: write `CPACR_EL1` + `isb` so the new FP-trap policy is in effect.
fn write_cpacr_el1(v: u64) {
    // SAFETY: writing CPACR_EL1 is legal at EL1; `isb` synchronizes the FP-trap
    // policy change before the guest's FP trigger executes.
    unsafe {
        asm!("msr cpacr_el1, {v}", "isb", v = in(reg) v, options(nomem, nostack, preserves_flags));
    }
}

/// EL1: compute `&__l2_guest_vectors` (the L2.2 guest EL1 vector table in
/// `exits_vectors.rs`) PC-relative -- no memory access.
fn l2_guest_vectors_addr() -> u64 {
    let v: u64;
    // SAFETY: `adrp`/`add :lo12:` form the address of the linker-kept symbol with
    // no memory access; NZCV preserved.
    unsafe {
        asm!(
            "adrp {v}, __l2_guest_vectors",
            "add  {v}, {v}, :lo12:__l2_guest_vectors",
            v = out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    v
}

// ===========================================================================
// L2.2: the safe facade: el2_exits_selftest() -> ExitsProof.
// ===========================================================================
// (a) PRE : called once from the kernel at the L2.2 slot (right after L2.1,
//           before M19), at EL1h, with the resident monitor armed
//           (BOOTED_AT_EL2 == 1). POST: installed the L2.2 guest vectors +
//           opened CPACR_EL1.FPEN, masked IRQs, issued ONE `HVC #4`, drove the
//           arm -> WFx-trap+resume -> FP-trap -> inject-UNDEF -> guest-vector
//           -> `hvc #5` -> TEARDOWN -> unwind round-trip, restored CPACR_EL1 +
//           VBAR_EL1, and returns the outcome enum. The kernel resumes here at
//           EL1 with the exit window fully torn down (HCR/CPTR back to baseline).
//           Graceful skip (no HVC, no fault) when not booted at EL2.
// (b) ABI : plain safe `fn`; all asm/unsafe confined here + in `exits.rs` /
//           `exits_vectors.rs`, so the `#![forbid(unsafe_code)]` kernel only
//           branches on the returned `ExitsProof`.
// (c) TEST: scripts/run-aarch64.sh -- "L2.2: el2-exits OK" iff this is `Proven`.
/// Drive the EL1->EL2(arm)->EL1-guest->EL2(WFx resume)->EL1-guest->EL2(inject
/// UNDEF)->EL1-guest-vector->EL2(done+teardown)->EL1 exit-dispatch round-trip and
/// report the outcome. `Unavailable` if we did not boot at EL2 (a green skip);
/// `Proven{served}` on a closed round-trip that fired BOTH the WFx and inject-UNDEF
/// arms; `Faulted{code}` on any monitor-reported fault.
pub fn el2_exits_selftest() -> crate::ExitsProof {
    use crate::ExitsProof;

    // Graceful skip: no resident monitor -> issuing HVC would fault, so don't.
    if BOOTED_AT_EL2.load(Ordering::Acquire) != 1 {
        return ExitsProof::Unavailable;
    }

    // Save the kernel's VBAR_EL1 + CPACR_EL1, then install the L2.2 guest vector
    // table (so the injected UNDEF vectors into the guest's UNDEF handler) and
    // open CPACR_EL1.FPEN=0b11 (so the FP trigger is NOT trapped to EL1 by CPACR
    // -- the CPTR_EL2.TFP EL2 trap must win priority for the default arm).
    let saved_vbar = read_vbar_el1();
    let saved_cpacr = read_cpacr_el1();
    write_vbar_el1(l2_guest_vectors_addr());
    write_cpacr_el1(saved_cpacr | CPACR_FPEN_NOTRAP);

    // Mask EL1 IRQs across the whole window (the VBAR_EL1-hijack risk: while
    // VBAR_EL1 points at the guest table, a stray EL1 IRQ/abort would vector into
    // it -- masking + the guest fail-trampoline keep that fail-closed, never a
    // hang). The guest also runs DAIF-masked (SPSR=0x3C5).
    let daif = super::timer::local_irq_save();

    let code: u64;
    let served: u64;
    // SAFETY: the resident EL2 monitor catches `hvc #4`, arms the exit window
    // (HCR.TWI|TWE + CPTR.TFP) and erets into the EL1 exits stub. The stub's `wfi`
    // traps -> Wfx arm -> resume; its FP `.inst` traps -> Undef default -> inject
    // UNDEF -> the guest's EL1 vector echoes the magic via `hvc #5`; the done
    // handler tears the window DOWN, verifies the served bits + magic, and unwinds
    // here with x0 = outcome, x1 = served, every other kernel register restored
    // from B0. The result arrives in registers -- nothing here touches the EL2
    // stack. x0/x1 are caller-saved, covered by clobber_abi("C").
    unsafe {
        asm!(
            "hvc #4",
            out("x0") code,
            out("x1") served,
            clobber_abi("C"),
        );
    }

    super::timer::local_irq_restore(daif);

    // Restore the kernel's CPACR_EL1 + VBAR_EL1 (the EL1-side window teardown).
    write_cpacr_el1(saved_cpacr);
    write_vbar_el1(saved_vbar);

    if code == 0 {
        ExitsProof::Proven { served }
    } else {
        ExitsProof::Faulted { code }
    }
}

// ===========================================================================
// L2.3: the EL1 guest stub that exercises BOTH trap-and-emulate paths.
// ===========================================================================
// (a) PRE : reached only by the `HVC #6` handler's `eret`, executing at EL1h
//           (SPSR_EL2 = 0x3C5) under the kernel's live stage-1 MMU AND the armed
//           trap window (HCR_EL2.VM=1 + TVM=1). Its VA == PA: identity-mapped,
//           EL1-executable kernel `.text` in the RAM gigabyte (GiB1, which the
//           device stage-2 identity-maps, so the fetch + stack never S1PTW-fault).
//           POST: (A) `msr contextidr_el1` traps EC 0x18 SYS64 -> the SYSREG
//           emulate path records x3 + advances ELR past the MSR; (B) `str x5,[x4]`
//           to the device IPA stage-2-faults -> the MMIO write path stores x5 in
//           the device shadow + advances ELR; (C) `ldr x6,[x4]` faults -> the
//           MMIO read path returns the device value into x6 + advances ELR. The
//           stub's own `cmp x6,x5` proves the read delivered the device value;
//           then `hvc #7` closes (the monitor tears the window down + unwinds,
//           never returns here).
// (b) ABI : `#[unsafe(naked)]` -- PC-relative / immediate only (valid at its
//           identity VA), NO stack (SP_EL1 untouched). A SINGLE-GPR LDR/STR (no
//           LDP/STP, no writeback, no SIMD) so QEMU TCG sets ISV=1 (the decodable
//           form). The device VA `0x1_C000_0000` (== stage2.rs `DEVICE_IPA`) is
//           materialised MOVZ+MOVK; the magics fit single MOVZ.
// (c) TEST: scripts/run-aarch64.sh -- the round-trip prints "L2.3: el2-trap OK".
/// The L2.3 guest: write the SYSREG magic to CONTEXTIDR_EL1 (TVM trap -> emulate),
/// STORE the MMIO magic to the device IPA (DABT -> emulate write), LOAD it back
/// (DABT -> emulate read -> SRT), prove the read value, then `hvc #7` to close.
#[unsafe(naked)]
extern "C" fn el2_trap_guest_stub() -> ! {
    naked_asm!(
        // (A) SYSREG trap-and-emulate (HCR_EL2.TVM):
        "movz x3, #0x5103",            // SYSREG_EMU_VAL magic (single MOVZ)
        "msr  contextidr_el1, x3",     // EC 0x18 SYS64 trap -> emulate(record x3) -> ELR+=4
        // (B) MMIO emulate (stage-2 device IPA):
        "movz x4, #0xC000, lsl #16",   // x4 = 0x0000_0000_C000_0000
        "movk x4, #0x0001, lsl #32",   // x4 = 0x0000_0001_C000_0000 == DEVICE_IPA
        "movz x5, #0x0D51",            // MMIO_VAL magic
        "str  x5, [x4]",               // DABT ISV=1 WnR=1 -> device_mmio(write x5) -> ELR+=4
        "ldr  x6, [x4]",               // DABT ISV=1 WnR=0 -> device_mmio(read)->x6 -> ELR+=4
        // GUEST-side proof that the read-emulation wrote the DEVICE value into SRT:
        "mov  x0, #0xD23",             // L2.3 guest magic (good)
        "cmp  x6, x5",
        "b.eq 1f",
        "mov  x0, #0xBAD",             // x6 != written magic -> wrong magic -> FAIL
        "1:",
        "hvc  #7",                     // done: teardown + verify + unwind
        "2:",
        "b 2b",                        // unreachable: the monitor unwinds, never here
    )
}

// ===========================================================================
// L2.3: the safe facade: el2_trap_selftest() -> TrapProof.
// ===========================================================================
// (a) PRE : called once from the kernel at the L2.3 slot (right after L2.2,
//           before M19), at EL1h, with the resident monitor armed
//           (BOOTED_AT_EL2 == 1). POST: built the device stage-2 + spliced the
//           stage-1 device block AT EL1, issued ONE `HVC #6`, drove the
//           arm -> SYSREG-trap+emulate -> MMIO-write-emulate -> MMIO-read-emulate
//           -> `hvc #7` -> TEARDOWN -> unwind round-trip, and returns the outcome
//           enum. The kernel resumes here at EL1 with the trap window fully torn
//           down (HCR back to RW baseline). Graceful skip when not booted at EL2.
// (b) ABI : plain safe `fn`; all asm/unsafe confined here + in `el2mmio.rs` /
//           `stage2.rs`, so the `#![forbid(unsafe_code)]` kernel only branches on
//           the returned `TrapProof`.
// (c) TEST: scripts/run-aarch64.sh -- "L2.3: el2-trap OK" iff this returns `Proven`.
/// Drive the EL1->EL2(arm)->EL1-guest->EL2(SYSREG emulate)->EL1-guest->EL2(MMIO
/// write)->EL1-guest->EL2(MMIO read)->EL1-guest->EL2(done+teardown)->EL1
/// trap-and-emulate round-trip and report the outcome. `Unavailable` if we did
/// not boot at EL2 (a green skip); `Proven{served}` on a closed round-trip that
/// fired ALL THREE arms (SYSREG + MMIO write + MMIO read); `Faulted{code}` on any
/// monitor-reported fault.
pub fn el2_trap_selftest() -> crate::TrapProof {
    use crate::TrapProof;

    // Graceful skip: no resident monitor -> issuing HVC would fault, so don't.
    if BOOTED_AT_EL2.load(Ordering::Acquire) != 1 {
        return TrapProof::Unavailable;
    }

    // Build the device stage-2 regime AT EL1 (GiB0+GiB1 identity, the device IPA
    // L1[7] left UNMAPPED so it stage-2-faults). On physical-frame OOM, surface a
    // Faulted code honestly (a red marker, never a faked OK).
    let root = match super::stage2::build_device_stage2() {
        Some(r) => r,
        None => return TrapProof::Faulted { code: FAIL_TRAP_BUILD },
    };
    // Splice the stage-1 identity block at L1[7] so the guest VA DEVICE_IPA
    // produces IPA DEVICE_IPA (which the device stage-2 then faults). Its stage-1
    // walk touches only the L1 root (in GiB1, stage-2-covered), so it never
    // S1PTW-faults.
    super::stage2::install_stage1_device_block();

    let vtcr_v = super::stage2::compute_vtcr();
    let vttbr_v = super::stage2::compute_vttbr(root);
    let stub = el2_trap_guest_stub as *const () as u64;
    let dev_ipa = super::stage2::DEVICE_IPA;

    // Mask EL1 IRQs across the round-trip (the guest also runs DAIF-masked).
    let daif = super::timer::local_irq_save();

    let code: u64;
    let served: u64;
    // SAFETY: the resident EL2 monitor catches `hvc #6`, programs VTCR/VTTBR and
    // sets HCR.VM=1|TVM=1, then erets into the EL1 trap stub. The stub's `msr
    // contextidr_el1` traps -> SYSREG emulate (record + advance); its `str`/`ldr`
    // to the device IPA stage-2-fault -> MMIO write/read emulate (device seam +
    // advance); its `hvc #7` TEARS the window DOWN (HCR=RW) FIRST and unwinds here
    // with x0 = outcome, x1 = served, every other kernel register restored from
    // B0. The result arrives in registers -- nothing here touches the EL2 stack.
    // x0..x4 carry the in-args; clobber_abi("C") covers the rest.
    unsafe {
        asm!(
            "hvc #6",
            inout("x0") root => code,
            inout("x1") vtcr_v => served,
            in("x2") vttbr_v,
            in("x3") stub,
            in("x4") dev_ipa,
            clobber_abi("C"),
        );
    }

    super::timer::local_irq_restore(daif);

    if code == 0 {
        TrapProof::Proven { served }
    } else {
        TrapProof::Faulted { code }
    }
}

// ===========================================================================
// aL2.4: EL1 privileged-register helpers for the nested-guest facade (asm
// confined here). The facade SAVES the kernel's stage-1 sysregs BEFORE the
// round-trip (the guest mutates them) and RESTORES them AFTER (the EL1-side
// teardown -- the one genuinely-new teardown surface vs aL2.0..aL2.3).
// ===========================================================================

/// EL1: read `TTBR0_EL1` (the kernel's live stage-1 root). Side-effect-free.
fn read_ttbr0_el1() -> u64 {
    let v: u64;
    // SAFETY: TTBR0_EL1 is EL1-readable; `mrs` has no memory/stack effect.
    unsafe {
        asm!("mrs {v}, ttbr0_el1", v = out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// EL1: read `TCR_EL1`. Side-effect-free.
fn read_tcr_el1() -> u64 {
    let v: u64;
    // SAFETY: TCR_EL1 is EL1-readable; side-effect-free.
    unsafe {
        asm!("mrs {v}, tcr_el1", v = out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// EL1: read `MAIR_EL1`. Side-effect-free.
fn read_mair_el1() -> u64 {
    let v: u64;
    // SAFETY: MAIR_EL1 is EL1-readable; side-effect-free.
    unsafe {
        asm!("mrs {v}, mair_el1", v = out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// EL1: read `SCTLR_EL1`. Side-effect-free.
fn read_sctlr_el1() -> u64 {
    let v: u64;
    // SAFETY: SCTLR_EL1 is EL1-readable; side-effect-free.
    unsafe {
        asm!("mrs {v}, sctlr_el1", v = out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// EL1: RESTORE the kernel's stage-1 regime after the guest mutated it -- write
/// `MAIR_EL1`/`TCR_EL1`/`TTBR0_EL1`/`SCTLR_EL1`/`VBAR_EL1` back to the saved
/// values, then `isb` + a full local TLB/I-cache invalidate so the kernel
/// resumes on its OWN stage-1 with no stale guest translation surviving. This is
/// the aL2.4 EL1-side teardown (the guest never left EL1's sysregs as it found
/// them, unlike aL2.0..aL2.3). Mirrors `mmu.rs`'s cold-entry hygiene.
fn restore_kernel_stage1(mair: u64, tcr: u64, ttbr0: u64, sctlr: u64, vbar: u64) {
    // SAFETY: EL1. We write the kernel's OWN previously-saved stage-1 sysregs
    // (read moments earlier from these same registers), `isb`-synchronize, flush
    // the local EL1 TLB + I-cache (the guest's TTBR0/ASID-0 entries are now
    // stale), and `isb` so the very next kernel access translates under the
    // restored stage-1. No memory operands; not `nomem` (a translation-context
    // switch). The order (MAIR/TCR before TTBR0/SCTLR) mirrors `mmu_init`.
    unsafe {
        asm!(
            "msr mair_el1,  {mair}",
            "msr tcr_el1,   {tcr}",
            "msr ttbr0_el1, {ttbr0}",
            "msr vbar_el1,  {vbar}",
            "msr sctlr_el1, {sctlr}",
            "isb",
            "tlbi vmalle1",
            "dsb nsh",
            "ic iallu",
            "dsb nsh",
            "isb",
            mair  = in(reg) mair,
            tcr   = in(reg) tcr,
            ttbr0 = in(reg) ttbr0,
            vbar  = in(reg) vbar,
            sctlr = in(reg) sctlr,
            options(nostack, preserves_flags),
        );
    }
}

/// EL1: compute `&__l2_nested_guest_vectors` (the aL2.4 guest EL1 vector table in
/// `el2_nested_vectors.rs`) PC-relative -- no memory access.
fn l2_nested_guest_vectors_addr() -> u64 {
    let v: u64;
    // SAFETY: `adrp`/`add :lo12:` form the address of the linker-kept symbol with
    // no memory access; NZCV preserved.
    unsafe {
        asm!(
            "adrp {v}, __l2_nested_guest_vectors",
            "add  {v}, {v}, :lo12:__l2_nested_guest_vectors",
            v = out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    v
}

// ===========================================================================
// aL2.4: the EL1 nested guest -- a REAL minimal TABOS guest that, UNDER our EL2
// stage-2 (HCR_EL2.VM=1), BUILDS its OWN stage-1 in the frame_alloc'd frames
// handed in x4(L1)/x5(L2)/x6(L3)/x7(scratch IPA), ENABLES it (SCTLR_EL1.M=1),
// and stores+reads back a sentinel through a VA that has NO flat meaning -- a
// GENUINE two-stage walk (guest VA -> guest stage-1 -> IPA -> our stage-2 -> PA).
// Then it installs its OWN VBAR_EL1 and takes its OWN EL1 `brk` exception (an
// EL1->EL1 trap, NOT an EL2 exit), and HVCs done. The magic 0x2E5 is set ONLY on
// the path where BOTH the post-SCTLR.M readback matched AND the EL1 trap fired.
// ===========================================================================
// (a) PRE : reached only by the `HVC #8` arm's `eret`, executing at EL1h
//           (SPSR_EL2 = 0x3C5) under the kernel's stage-1 (HCR_EL2.VM=1 stage-2)
//           with SCTLR_EL1.M still 0 (the guest enables its OWN first stage). Its
//           VA == PA: identity-mapped, EL1-executable kernel `.text` in GiB1,
//           which the stage-2 identity covers (the fetch never S1PTW-faults).
//           x4=guest L1 PA, x5=guest L2 PA, x6=guest L3 PA, x7=scratch IPA.
//           POST: `hvc #9` (the monitor tears stage-2 down + verifies; never
//           returns here).
// (b) ABI : `#[unsafe(naked)]` -- a register-only sequence (writes the already-
//           allocated table frames, msr's its sysregs, store/load through the
//           translated VA, brk, hvc). Uses NO new stack frame (SP_EL1 is the
//           guest's own SP, untouched). Builds its stage-1 with the EXACT mmu.rs
//           descriptors (NESTED_* consts, locked against drift). It reuses the
//           Kani-proven M|C|I enable mask (SCTLR_EL1_GUEST_ENABLE_BITS).
// (c) TEST: scripts/run-aarch64.sh -- the two-stage round-trip prints
//           "L2.4: el2-guest OK".
/// The aL2.4 nested guest: build a 3-level stage-1 (identity GiB0+GiB1 so its own
/// fetch/stack/tables resolve, PLUS NESTED_GUEST_VA -> scratch), enable it, store
/// NESTED_SENTINEL through the translated VA + read it back, install its own
/// VBAR_EL1 + take a `brk` EL1 trap, then present 0x2E5 (iff both) and `hvc #9`.
#[unsafe(naked)]
extern "C" fn el2_nested_guest_stub() -> ! {
    naked_asm!(
        // -- (1) BUILD the guest's OWN stage-1 in x4(L1)/x5(L2)/x6(L3) ----------
        // L1[0] = GiB0 Device identity block (output PA 0): covers the UART so
        // the guest's serial-adjacent code + Device space resolve under S1.
        "movz x9, #0x701",             // NESTED_BLOCK_DEVICE
        "str  x9, [x4]",               // L1[0]
        // L1[1] = GiB1 Normal-WB identity block (output PA 0x4000_0000): covers
        // the guest's .text, stack, and its own L1/L2/L3 table frames.
        "movz x9, #0x4000, lsl #16",   // 0x4000_0000
        "movz x10, #0x705",            // NESTED_BLOCK_NORMAL
        "orr  x9, x9, x10",
        "str  x9, [x4, #8]",           // L1[1]
        // L1[8] -> L2 table (NESTED_GUEST_VA == 0x2_0000_0000 => L1 index 8).
        "orr  x9, x5, #0x3",           // x5 (L2 PA, 4K-aligned) | DESC_TABLE
        "str  x9, [x4, #64]",          // L1[8] (8 * 8 bytes)
        // L2[0] -> L3 table (VA L2 index 0).
        "orr  x9, x6, #0x3",           // x6 (L3 PA) | DESC_TABLE
        "str  x9, [x5]",               // L2[0]
        // L3[0] = scratch 4 KiB Normal-WB page leaf (VA L3 index 0).
        "movz x9, #0x707",             // NESTED_PAGE_NORMAL
        "orr  x9, x7, x9",             // x7 (scratch PA) | PAGE_NORMAL
        "str  x9, [x6]",               // L3[0]
        // Publish the whole stage-1 hierarchy to the (EL1 + stage-2) walker.
        "dsb  ishst",
        "isb",
        // -- (2) PROGRAM the guest's translation regime (MAIR/TTBR0/TCR) --------
        "movz x9, #0xFF00",            // NESTED_MAIR_EL1 = 0x00 | (0xFF<<8)
        "msr  mair_el1, x9",
        "msr  ttbr0_el1, x4",          // TTBR0_EL1 = the guest's OWN L1 root PA
        "movz x9, #0x3519",            // NESTED_TCR_EL1 = 0x2_0099_3519
        "movk x9, #0x0099, lsl #16",
        "movk x9, #0x0002, lsl #32",
        "msr  tcr_el1, x9",
        "dsb  ishst",
        "isb",
        // Cold-entry hygiene before the first translated access (mmu.rs parity):
        // TLB + I-cache contents are stale w.r.t. the new regime.
        "tlbi vmalle1",
        "dsb  nsh",
        "ic   iallu",
        "dsb  nsh",
        "isb",
        // -- (3) ENABLE the guest's FIRST STAGE (the "S1 after S2" step) --------
        // SCTLR_EL1 |= M|C|I (the Kani-proven sctlr_el1_guest_enable mask 0x1005),
        // read-modify-write preserving every other (RES1/EE/...) bit. From the
        // `isb` onward EVERY guest access is a FULL two-stage walk.
        "mrs  x9, sctlr_el1",
        "movz x10, #0x1005",           // SCTLR_EL1_GUEST_ENABLE_BITS (M|C|I)
        "orr  x9, x9, x10",
        "msr  sctlr_el1, x9",
        "isb",
        // -- (4) THE TWO-STAGE STORE+READBACK (the genuine-two-stage gate) ------
        // x10 = NESTED_GUEST_VA (0x2_0000_0000); x9 = NESTED_SENTINEL (0xB22B).
        // VA has NO flat meaning -- reachable ONLY via the stage-1 just built. The
        // store walks VA->(guest S1)->IPA->(our S2)->PA; the load reads it back.
        "movz x10, #0x0002, lsl #32",  // NESTED_GUEST_VA
        "movz x9,  #0xB22B",           // NESTED_SENTINEL
        "str  x9, [x10]",              // two-stage STORE through the translated VA
        "ldr  x11, [x10]",             // two-stage LOAD back
        "mov  x0, #0xBAD",             // assume FAIL until both gates pass
        "cmp  x11, x9",                // did the readback match the sentinel?
        "b.ne 1f",                     // no -> leave x0 = 0xBAD
        // -- (5) THE GUEST'S OWN EL1 EXCEPTION (the M1 analog, no EL2 exit) -----
        // Install the guest's OWN VBAR_EL1, clear the trap-taken sentinel, then
        // `brk #0`: it vectors to VBAR_EL1+0x200 (Current-EL-SPx Sync) INSIDE the
        // guest, whose handler sets x28 = NESTED_TRAP_TAKEN and returns.
        "adrp x12, __l2_nested_guest_vectors",
        "add  x12, x12, :lo12:__l2_nested_guest_vectors",
        "msr  vbar_el1, x12",
        "isb",
        "movz x28, #0",                // clear the trap-taken sentinel
        "brk  #0",                     // EL1->EL1 trap -> guest vector sets x28
        // -- (6) VERDICT: magic 0x2E5 iff readback matched AND the trap fired ---
        "movz x9, #0x2E5",             // NESTED_TRAP_TAKEN expected in x28
        "cmp  x28, x9",
        "b.ne 1f",                     // trap not taken -> leave x0 = 0xBAD
        "movz x0, #0x2E5",             // NESTED_GUEST_MAGIC -- BOTH gates passed
        "1:",
        "hvc  #9",                     // done: teardown + verify + unwind
        "2:",
        "b 2b",                        // unreachable: the monitor unwinds, never here
    )
}

// ===========================================================================
// aL2.4: the safe facade: el2_nested_guest_selftest() -> NestedGuestProof.
// ===========================================================================
// (a) PRE : called once from the kernel at the L2.4 slot (right after L2.3,
//           before M19), at EL1h, with the resident monitor armed
//           (BOOTED_AT_EL2 == 1). POST: built the GiB0+GiB1 identity stage-2 +
//           frame_alloc'd the guest's stage-1 L1/L2/L3 frames + a scratch frame
//           AT EL1, SAVED the kernel's MAIR/TCR/TTBR0/SCTLR/VBAR_EL1, issued ONE
//           `HVC #8`, drove the arm -> guest-builds-S1 -> SCTLR.M -> two-stage
//           store/load -> guest EL1 brk -> `hvc #9` -> TEARDOWN -> unwind
//           round-trip, RESTORED the kernel's stage-1 sysregs, and returns the
//           outcome enum. The kernel resumes here at EL1 with stage-2 torn down
//           AND its OWN stage-1 intact. Graceful skip when not booted at EL2.
// (b) ABI : plain safe `fn`; all asm/unsafe confined here + in `stage2.rs` /
//           `el2_nested_vectors.rs`, so the `#![forbid(unsafe_code)]` kernel only
//           branches on the returned `NestedGuestProof`.
// (c) TEST: scripts/run-aarch64.sh -- "L2.4: el2-guest OK" iff `Proven`.
/// Drive the EL1->EL2(arm)->EL1-guest(builds + enables its OWN stage-1 under our
/// stage-2, two-stage store/load, takes its OWN EL1 trap)->EL2(done+teardown)->
/// EL1 nested-guest round-trip and report the outcome. `Unavailable` if we did
/// not boot at EL2 (a green skip); `Proven{magic}` on a closed two-stage
/// round-trip; `Faulted{code}` on any monitor-reported fault.
pub fn el2_nested_guest_selftest() -> crate::NestedGuestProof {
    use crate::NestedGuestProof;

    // Graceful skip: no resident monitor -> issuing HVC would fault, so don't.
    if BOOTED_AT_EL2.load(Ordering::Acquire) != 1 {
        return NestedGuestProof::Unavailable;
    }

    // Build the GiB0+GiB1 identity stage-2 (reused verbatim from L2.1 -- it
    // covers the guest fetch/stack, its OWN stage-1 table frames so the S1PTW
    // never faults, AND the scratch IPA). On OOM, surface Faulted honestly.
    let root = match super::stage2::build_identity_stage2() {
        Some(r) => r,
        None => return NestedGuestProof::Faulted { code: FAIL_NG_BUILD },
    };
    // frame_alloc the guest's OWN stage-1 L1/L2/L3 frames + a scratch RAM frame,
    // all in GiB1 (so the stage-2 identity covers them -- no S1PTW self-fault).
    // The guest only WRITES these already-allocated frames (the no-EL2-allocation
    // rule, extended to the guest: it never calls frame_alloc at runtime).
    let gl1 = match super::stage2::prep_zeroed_frame() {
        Some(f) => f,
        None => return NestedGuestProof::Faulted { code: FAIL_NG_BUILD },
    };
    let gl2 = match super::stage2::prep_zeroed_frame() {
        Some(f) => f,
        None => return NestedGuestProof::Faulted { code: FAIL_NG_BUILD },
    };
    let gl3 = match super::stage2::prep_zeroed_frame() {
        Some(f) => f,
        None => return NestedGuestProof::Faulted { code: FAIL_NG_BUILD },
    };
    let scratch = match super::stage2::prep_zeroed_frame() {
        Some(f) => f,
        None => return NestedGuestProof::Faulted { code: FAIL_NG_BUILD },
    };
    // Risk #2: assert every guest stage-1 frame + the scratch is in GiB1
    // [0x4000_0000, 0x8000_0000), so the stage-2 identity covers it and the
    // guest's own stage-1 walk (S1PTW) can never fault. (frame_alloc only hands
    // out GiB1 RAM frames; this is a belt-and-suspenders fail-closed check.)
    for pa in [gl1, gl2, gl3, scratch] {
        if !(0x4000_0000..0x8000_0000).contains(&pa) {
            return NestedGuestProof::Faulted { code: FAIL_NG_S1PTW };
        }
    }

    let vtcr_v = super::stage2::compute_vtcr();
    let vttbr_v = super::stage2::compute_vttbr(root);
    let stub = el2_nested_guest_stub as *const () as u64;

    // PROVE the tb-boot guest-boot handoff block is well-formed (the documented
    // seam the deferred full-kernel-as-guest rung will consume): the EL1h /
    // PSTATE=0x3c5 + X0=info* register-file contract the EL2 monitor will splice.
    // The minimal guest does not consume TbBootInfo yet, so we only assert the
    // block is well-formed here (a host-testable invariant, no /dev/kvm).
    debug_assert_eq!(
        tb_boot::aarch64::AARCH64_PSTATE_EL1H_DAIF,
        SPSR_EL1H_DAIF,
        "tb-boot EL1h PSTATE must match the monitor's eret SPSR_EL2"
    );

    // SAVE the kernel's OWN stage-1 sysregs BEFORE the round-trip: the guest
    // mutates TTBR0_EL1/TCR_EL1/MAIR_EL1/SCTLR_EL1/VBAR_EL1, so the facade must
    // restore them after (the aL2.4 EL1-side teardown -- the new surface).
    let saved_ttbr0 = read_ttbr0_el1();
    let saved_tcr = read_tcr_el1();
    let saved_mair = read_mair_el1();
    let saved_sctlr = read_sctlr_el1();
    let saved_vbar = read_vbar_el1();
    let _ = l2_nested_guest_vectors_addr(); // keep the vector symbol referenced

    // Mask EL1 IRQs across the whole window (the guest runs DAIF-masked too).
    let daif = super::timer::local_irq_save();

    let outcome: u64;
    let magic: u64;
    // SAFETY: the resident EL2 monitor catches `hvc #8`, programs VTCR/VTTBR and
    // sets HCR.VM=1, then erets into the EL1 nested guest with x4..x7 carrying the
    // pre-allocated frame PAs. The guest builds + enables its OWN stage-1, does
    // the two-stage store/load, takes its OWN EL1 brk trap, and `hvc #9`s -- the
    // monitor TEARS stage-2 DOWN (HCR.VM=0) FIRST, reads the sentinel back through
    // the identity alias, and unwinds here with x0 = outcome, x1 = guest magic,
    // every other kernel register restored from B0. The result arrives in
    // registers -- nothing here touches the EL2 stack. x0..x7 carry the in-args;
    // clobber_abi("C") covers the rest.
    unsafe {
        asm!(
            "hvc #8",
            inout("x0") root => outcome,
            inout("x1") vtcr_v => magic,
            in("x2") vttbr_v,
            in("x3") stub,
            in("x4") gl1,
            in("x5") gl2,
            in("x6") gl3,
            in("x7") scratch,
            clobber_abi("C"),
        );
    }

    // EL1-side teardown: the guest left TTBR0_EL1/TCR_EL1/MAIR_EL1/SCTLR_EL1/
    // VBAR_EL1 pointing at its OWN regime; restore the kernel's saved values +
    // flush so M19 (and the rest of the kernel) resumes on its OWN stage-1. This
    // is the genuinely-new teardown step vs aL2.0..aL2.3 (where the guest never
    // touched EL1 sysregs). The marker discipline catches a miss: M19 must still
    // print AFTER L2.4.
    restore_kernel_stage1(saved_mair, saved_tcr, saved_ttbr0, saved_sctlr, saved_vbar);

    super::timer::local_irq_restore(daif);

    if outcome == 0 {
        NestedGuestProof::Proven { magic }
    } else {
        NestedGuestProof::Faulted { code: outcome }
    }
}

// ===========================================================================
// aL2.5: the EL1 vGIC guest -- a small position-independent EL1 payload that
// enables its OWN GICV virtual CPU interface, PARKS on WFI (which traps to EL2,
// where the monitor injects a pending vIRQ via GICH_LR0 and resumes it), takes
// the injected VIRTUAL interrupt at its OWN EL1 IRQ vector (GICV_IAR ack ->
// x28 = VGIC_IRQ_TAKEN -> GICV_EOIR), and presents the vGIC magic iff the vIRQ
// was taken+acked. Modeled on `guest_stub` / `el2_nested_guest_stub`. NO new
// stack frame (SP_EL1 is the guest's own, untouched); only x9..x12 scratch +
// the callee-saved x27/x28 handshake the IRQ vector agreed on.
// ===========================================================================
// (a) PRE : reached only by the `imm == 10` handler's `eret`, executing at EL1h
//           (SPSR = SPSR_EL1H_VGIC, PSTATE.I UNMASKED) under the kernel's live
//           stage-1 (HCR_EL2.VM=0). Its VA == PA: identity-mapped EL1-executable
//           kernel `.text` in GiB1; the GICV frame (0x0804_0000) is in the GiB0
//           Device identity block the kernel maps. POST: `hvc #11` (the monitor
//           tears the window down + verifies; never returns here).
// (b) ABI : `#[unsafe(naked)]` -- a register-only sequence (enable GICV, install
//           VBAR, WFI, check sentinel, hvc). Uses NO new stack frame. The
//           GICV_BASE / sentinels / vINTID are materialised as immediates; the
//           magic + sentinel are locked against the consts (and the vector
//           table) by const-asserts.
// (c) TEST: scripts/run-aarch64.sh -- the vGIC round-trip prints "L2.5: vgic OK".
/// The aL2.5 vGIC guest: enable GICV_CTLR.En + GICV_PMR=0xFF, install its OWN
/// VBAR_EL1 (whose 0x280 SPx-IRQ slot acks/EOIs the vIRQ), park on WFI, then
/// present `VGIC_GUEST_MAGIC` (0x761) iff x28 == VGIC_IRQ_TAKEN, and `hvc #11`.
#[unsafe(naked)]
extern "C" fn el2_vgic_guest_stub() -> ! {
    naked_asm!(
        // -- (1) ENABLE the guest's OWN GICV virtual CPU interface -------------
        // x9 = GICV_BASE (0x0804_0000): the frame the guest touches as its GICC.
        "movz x9, #0x0804, lsl #16",
        // GICV_PMR = 0xFF (allow all priorities -- the injected pri-0 vIRQ passes).
        "movz x10, #0xFF",
        "str  w10, [x9, #0x04]",       // GICV_PMR @ 0x004
        // GICV_CTLR.En = 1 (enable the virtual CPU interface).
        "movz x10, #1",
        "str  w10, [x9, #0x00]",       // GICV_CTLR @ 0x000
        "dsb  ish",
        "isb",
        // -- (2) INSTALL the guest's OWN VBAR_EL1 (the vIRQ vector) ------------
        "adrp x12, __l2_vgic_guest_vectors",
        "add  x12, x12, :lo12:__l2_vgic_guest_vectors",
        "msr  vbar_el1, x12",
        "isb",
        // -- (3) PARK on WFI (PSTATE.I left UNMASKED; do NOT msr DAIFSet) -------
        // The WFI traps to EL2 (HCR_EL2.TWI=1); the monitor injects a pending
        // vIRQ into GICH_LR0 and resumes past the WFI. On resume the now-pending
        // VIRQ (IMO routes it, I clear) fires immediately at VBAR_EL1+0x280,
        // whose handler reads GICV_IAR, sets x28 = VGIC_IRQ_TAKEN (iff the IAR
        // matched the injected vINTID), writes GICV_EOIR, and erets back here.
        "movz x28, #0",                // clear the vIRQ-taken sentinel
        "wfi",                         // park -> trap -> inject -> resume -> vIRQ
        // -- (4) VERDICT: magic 0x761 iff the vIRQ was taken + acked -----------
        "mov  x0, #0xBAD",             // assume FAIL until the sentinel matches
        "movz x9, #0x5A5",             // VGIC_IRQ_TAKEN expected in x28
        "cmp  x28, x9",
        "b.ne 1f",                     // vIRQ not taken/acked -> leave x0 = 0xBAD
        "movz x0, #0x761",             // VGIC_GUEST_MAGIC -- the vIRQ round-trip closed
        "1:",
        "hvc  #11",                    // done: teardown + verify + unwind
        "2:",
        "b 2b",                        // unreachable: the monitor unwinds, never here
    )
}

// ===========================================================================
// aL2.5: the safe facade: el2_vgic_selftest() -> VgicProof.
// ===========================================================================
// (a) PRE : called once from the kernel at the L2.5 slot (right after aL2.4,
//           before M19), at EL1h, with the resident monitor armed
//           (BOOTED_AT_EL2 == 1). POST: SAVED the kernel's VBAR_EL1 (the guest
//           installs its OWN), masked IRQs, issued ONE `HVC #10`, drove the
//           arm -> guest-enables-GICV -> WFI-park -> WFI-trap-to-EL2 -> monitor
//           injects vIRQ via GICH_LR0 -> resume -> guest takes the vIRQ at EL1
//           -> ack(GICV_IAR)/EOI(GICV_EOIR) -> `hvc #11` -> TEARDOWN (HCR_EL2
//           back to baseline, GICH_HCR.En=0, GICH_LR0 zeroed) -> unwind
//           round-trip, RESTORED VBAR_EL1, and returns the outcome enum. The
//           kernel resumes here at EL1 with the vGIC window fully torn down.
//           Graceful skip when not booted at EL2.
// (b) ABI : plain safe `fn`; all asm/unsafe confined here + in `el2vgic.rs` /
//           `el2_vgic_vectors.rs`, so the `#![forbid(unsafe_code)]` kernel only
//           branches on the returned `VgicProof`.
// (c) TEST: scripts/run-aarch64.sh -- "L2.5: vgic OK" iff this is `Proven`.
/// Drive the EL1->EL2(arm)->EL1-guest(enable GICV + park on WFI)->EL2(WFI-trap:
/// inject vIRQ + resume)->EL1-guest(take + ack the vIRQ)->EL2(done+teardown)->EL1
/// vGIC injection round-trip and report the outcome. `Unavailable` if we did not
/// boot at EL2 (a green skip); `Proven{vintid}` on a closed round-trip that fired
/// the WFI park, delivered the vIRQ, AND retired the injected LR; `Faulted{code}`
/// on any monitor-reported fault.
pub fn el2_vgic_selftest() -> crate::VgicProof {
    use crate::VgicProof;

    // Graceful skip: no resident monitor -> issuing HVC would fault, so don't.
    if BOOTED_AT_EL2.load(Ordering::Acquire) != 1 {
        return VgicProof::Unavailable;
    }

    let stub = el2_vgic_guest_stub as *const () as u64;
    let _ = l2_vgic_guest_vectors_addr(); // keep the vector symbol referenced

    // SAVE the kernel's VBAR_EL1 BEFORE the round-trip: the guest installs its
    // OWN vGIC vectors, so the facade must restore the kernel's after (the
    // EL1-side teardown -- mirrors the aL2.4 VBAR save/restore).
    let saved_vbar = read_vbar_el1();

    // Mask EL1 IRQs across the whole window (the guest runs with PSTATE.I clear
    // so it CAN take the injected vIRQ, but the KERNEL side stays masked so no
    // stray physical IRQ disturbs the round-trip).
    let daif = super::timer::local_irq_save();

    let outcome: u64;
    // SAFETY: the resident EL2 monitor catches `hvc #10`, arms the vGIC window
    // (HCR_EL2 = RW|IMO|TWI + GICH_HCR.En), and erets into the EL1 vGIC guest
    // with PSTATE.I unmasked. The guest enables its GICV interface, parks on WFI
    // (which traps to EL2 -- the monitor injects a pending vIRQ via GICH_LR0 and
    // resumes past the WFI), takes the vIRQ at its EL1 vector, acks + EOIs it,
    // and `hvc #11`s -- the monitor TEARS the window DOWN (HCR_EL2 baseline,
    // GICH_HCR.En=0, GICH_LR0 zeroed) FIRST, reads the LR-retired proof, and
    // unwinds here with x0 = outcome, x1 = guest magic (unused by the verdict,
    // which reports the injected vINTID), every other kernel register restored
    // from B0. The result arrives in registers -- nothing here touches the EL2
    // stack. x3 carries the stub entry; clobber_abi("C") covers the rest.
    unsafe {
        asm!(
            "hvc #10",
            inout("x0") 0u64 => outcome,
            out("x1") _, // x1 = guest magic (consumed at EL2 in the done verdict)
            in("x3") stub,
            clobber_abi("C"),
        );
    }

    // EL1-side teardown: restore the kernel's VBAR_EL1 (the guest pointed it at
    // its OWN vGIC vectors) + isb so the next kernel exception uses the kernel
    // table. The marker discipline catches a miss: M19 must still print after.
    write_vbar_el1(saved_vbar);

    super::timer::local_irq_restore(daif);

    if outcome == 0 {
        VgicProof::Proven {
            vintid: VGIC_VINTID,
        }
    } else {
        VgicProof::Faulted { code: outcome }
    }
}

/// EL1: compute `&__l2_vgic_guest_vectors` (the aL2.5 guest EL1 vector table in
/// `el2_vgic_vectors.rs`) PC-relative -- no memory access.
fn l2_vgic_guest_vectors_addr() -> u64 {
    let v: u64;
    // SAFETY: `adrp`/`add :lo12:` form the address of the linker-kept symbol with
    // no memory access; NZCV preserved.
    unsafe {
        asm!(
            "adrp {v}, __l2_vgic_guest_vectors",
            "add  {v}, {v}, :lo12:__l2_vgic_guest_vectors",
            v = out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    v
}
