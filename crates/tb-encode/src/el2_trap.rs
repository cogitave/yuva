//! Pure aarch64 **EL2 trap-syndrome** decoders -- `ESR_EL2` / `HPFAR_EL2` /
//! `FAR_EL2` bit extraction for the L2.1 stage-2 demand-fault handler.
//!
//! When a guest EL1&0 access faults stage-2 translation (`HCR_EL2.VM == 1`), the
//! abort is taken to EL2 and the resident monitor must decide WHAT happened from
//! three raw system registers: `ESR_EL2` (the exception class + data-fault status
//! code), `HPFAR_EL2` (the faulting Intermediate Physical Address -- the
//! EPT-`PHYSICAL_ADDRESS`-of-the-violation analog), and `FAR_EL2` (the faulting
//! virtual address, for the in-page offset). Those decisions are pure bit
//! transforms, so they live here (Kani-proven total over all 64-bit inputs,
//! Miri-gated), exactly as the stage-2 descriptor algebra lives in
//! [`crate::stage2`]: `tb-hal`'s `arch/aarch64/el2.rs` reads the raw registers
//! with `mrs` and CALLS these to classify the fault. Nothing here is `unsafe` or
//! touches hardware.
//!
//! Verified bit facts (Arm ARM DDI 0487, ESR_ELx / HPFAR_EL2 / FAR_ELx;
//! cross-checked against Linux v6.6 `arch/arm64/include/asm/esr.h` +
//! `kvm_emulate.h`):
//!   * `ESR_ELx.EC` -- exception class, bits `[31:26]` (`esr.h ESR_ELx_EC_SHIFT
//!     26`, `ESR_ELx_EC_MASK GENMASK(31,26)`). Lower-EL HVC64 = `0x16`, an
//!     instruction abort from a lower EL = `0x20`, a data abort from a lower EL
//!     = `0x24`.
//!   * `ESR_ELx.ISS.DFSC` -- data/instruction fault status code, bits `[5:0]`
//!     (`esr.h ESR_ELx_FSC GENMASK(5,0)`). A **translation fault** is `0b0001LL`
//!     = `0x04..=0x07` where `LL` is the walk level (`ESR_ELx_FSC_FAULT 0x04`).
//!   * `ESR_ELx.ISS.WnR` -- write-not-read, bit `[6]` (`ESR_ELx_WNR (1<<6)`).
//!   * `ESR_ELx.ISS.S1PTW` -- stage-1-page-table-walk, bit `[7]`
//!     (`ESR_ELx_S1PTW (1<<7)`): set iff the fault occurred on the stage-1 walk
//!     itself (the access that faulted was the hardware reading a stage-1
//!     descriptor through stage-2). For the L2.1 smoke this MUST be 0 -- the
//!     identity stage-2 covers the guest's live stage-1 table frames, so an
//!     S1PTW=1 means the wrong thing faulted and the handler fails closed.
//!   * `HPFAR_EL2.FIPA` -- faulting IPA bits, stored in `HPFAR_EL2[43:4]` =
//!     IPA`[51:12]` (`kvm_emulate.h`: `(hpfar & HPFAR_MASK) << 8`, `HPFAR_MASK
//!     GENMASK(39,4)` on ARMv8.0). So the page-aligned faulting IPA is
//!     `(hpfar & !0xF) << 8`.
//!   * `FAR_ELx` -- faulting VA; the in-page offset is `FAR & 0xFFF`.

#![allow(dead_code)]

// ===========================================================================
// ESR_EL2.EC exception-class constants (the EL2 sync-handler dispatch keys).
// ===========================================================================

/// `EC` for an UNKNOWN reason (`esr.h ESR_ELx_EC_UNKNOWN`) -- the value the
/// monitor SYNTHESIZES into `ESR_EL1` when injecting an Undefined-Instruction
/// exception into the guest (`esr_inject_undef`), and the table-wide default's
/// conceptual home (every un-named EC routes to [`ExitClass::Undef`]).
pub const EC_UNKNOWN: u64 = 0x00;
/// `EC` for a trapped `WFI`/`WFE`/`WFIT`/`WFET` (`esr.h ESR_ELx_EC_WFx`) -- taken
/// to EL2 only while `HCR_EL2.TWI`/`TWE` are set (the L2.2 exits window).
pub const EC_WFX: u64 = 0x01;
/// `EC` for `HVC` executed in AArch64 state (the bootstrap / done hypercalls).
pub const EC_HVC64: u64 = 0x16;
/// `EC` for `SMC` executed in AArch64 state (`esr.h ESR_ELx_EC_SMC64`).
pub const EC_SMC64: u64 = 0x17;
/// `EC` for a trapped AArch64 MSR/MRS/system instruction (`esr.h
/// ESR_ELx_EC_SYS64`).
pub const EC_SYS64: u64 = 0x18;
/// `EC` for an Instruction Abort taken from a LOWER EL (a stage-2 fetch fault).
pub const EC_IABT_LOW: u64 = 0x20;
/// `EC` for a Data Abort taken from a LOWER EL (the expected stage-2 demand fault).
pub const EC_DABT_LOW: u64 = 0x24;

/// `ESR_ELx.ISS.DFSC` value for a translation fault at walk level 0 (`0b000100`).
pub const DFSC_TRANSLATION_L0: u64 = 0x04;
/// `ESR_ELx.ISS.DFSC` value for a translation fault at walk level 3 (`0b000111`).
pub const DFSC_TRANSLATION_L3: u64 = 0x07;

// ===========================================================================
// ESR_EL2 field decoders (total over all 64-bit inputs -- never panic).
// ===========================================================================

/// `ESR_ELx.EC` -- the exception class, bits `[31:26]`. Always `< 64`.
#[inline]
pub const fn esr_ec(esr: u64) -> u64 {
    (esr >> 26) & 0x3F
}

/// `ESR_ELx.ISS.DFSC` -- the (data/instruction) fault status code, bits `[5:0]`.
/// Always `< 64`. The FULL 6-bit field: masking with `0x1F` instead would
/// mis-classify some faults (the negative control in `kani_esr_decode_total`).
#[inline]
pub const fn esr_dfsc(esr: u64) -> u64 {
    esr & 0x3F
}

/// Whether the syndrome's DFSC encodes a **translation fault** (`0x04..=0x07`,
/// i.e. `0b0001xx`, any walk level) -- the stage-2 demand-fault classifier. An
/// access-flag fault (`0b0010xx`), permission fault (`0b0011xx`), or any fault
/// with DFSC bit[5] set is deliberately NOT a translation fault.
#[inline]
pub const fn esr_is_translation_fault(esr: u64) -> bool {
    let dfsc = esr_dfsc(esr);
    dfsc >= DFSC_TRANSLATION_L0 && dfsc <= DFSC_TRANSLATION_L3
}

/// `ESR_ELx.ISS.WnR` -- write-not-read, bit `[6]` (`1` = the faulting access was
/// a write). Always `0` or `1`.
#[inline]
pub const fn esr_wnr(esr: u64) -> u64 {
    (esr >> 6) & 1
}

/// `ESR_ELx.ISS.S1PTW` -- stage-1-page-table-walk, bit `[7]` (`1` = the fault was
/// on the stage-1 walk, NOT the final access). Always `0` or `1`. For L2.1 a `1`
/// means the identity stage-2 failed to cover a live stage-1 table frame, so the
/// handler treats it as a fail (the wrong thing faulted).
#[inline]
pub const fn esr_s1ptw(esr: u64) -> u64 {
    (esr >> 7) & 1
}

// ===========================================================================
// HPFAR_EL2 / FAR_EL2 decoders.
// ===========================================================================

/// The page-aligned faulting Intermediate Physical Address from `HPFAR_EL2`:
/// `(hpfar & !0xF) << 8` (FIPA in `HPFAR[43:4]` = IPA`[51:12]`). The result is
/// ALWAYS page-aligned (low 12 bits 0) for every input -- proven in
/// `kani_hpfar_fault_ipa`. The `<< 8` (not `<< 4`) is load-bearing: a `<< 4`
/// would leave bits in `[11:8]` and mislocate the IPA (the negative control).
#[inline]
pub const fn hpfar_fault_ipa(hpfar: u64) -> u64 {
    (hpfar & !0xF) << 8
}

/// The in-page offset of the faulting VA from `FAR_ELx`: `far & 0xFFF`. Combined
/// with [`hpfar_fault_ipa`] it gives the exact faulting IPA, but the L2.1
/// demand-map operates at page granularity so only the page-aligned IPA is used.
#[inline]
pub const fn far_page_offset(far: u64) -> u64 {
    far & 0xFFF
}

// ===========================================================================
// L2.2: the ESR_EL2.EC exit-dispatch table (the ARM analog of x86
// `arm_exit_handlers[]`). PURE + TOTAL -- the ONLY new classification logic.
//
// Cloned in spirit from KVM's `arm_exit_handlers[]` (handle_exit.c), where
// `[0 ... ESR_ELx_EC_MAX] = kvm_handle_unknown_ec` is the table-wide default and
// `kvm_handle_unknown_ec()` calls `kvm_inject_undefined()`. Here the six MUST
// ECs map to named arms and EVERY other EC maps to `Undef` (the fail-closed
// inject-UNDEF default).
// ===========================================================================

/// `ESR_EL2.EC` -> the named EL2 exit arm (the MUST-handle dispatch table). TOTAL:
/// the six MUST ECs map to named arms; EVERY other EC maps to [`ExitClass::Undef`]
/// (the fail-closed inject-UNDEF default), exactly the `arm_exit_handlers[]`
/// `[0..EC_MAX]=kvm_handle_unknown_ec` discipline.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExitClass {
    /// EC `0x24` DABT_LOW | `0x20` IABT_LOW -> the stage-2 demand-fault path
    /// (`kvm_handle_guest_abort`, L2.1).
    StageTwoAbort,
    /// EC `0x16` HVC64 -> the hypercall dispatch (`handle_hvc`, L2.0/L2.1/L2.2).
    Hvc,
    /// EC `0x17` SMC64 -> the secure-monitor-call path (`handle_smc`).
    Smc,
    /// EC `0x18` SYS64 -> a trapped MSR/MRS/system instruction
    /// (`kvm_handle_sys_reg`).
    Sys64,
    /// EC `0x01` WFx (WFI/WFE/WFIT/WFET) -> the wait-for-event path
    /// (`kvm_handle_wfx`, L2.2).
    Wfx,
    /// DEFAULT: every OTHER EC -> `kvm_handle_unknown_ec` -> inject UNDEF. The
    /// structural fail-closed property: anything un-named lands here.
    Undef,
}

/// Classify ONE EL2 synchronous exit from its raw `ESR_EL2`. TOTAL over every
/// 64-bit ESR: [`esr_ec`] masks to the 6-bit EC (`0..=63`), the six MUST ECs hit
/// their named arms, and the `_` arm catches ALL 58 remaining ECs as the
/// fail-closed [`ExitClass::Undef`] default. No panic, no `unreachable`, no
/// index -> it cannot trap on any input (Kani-proven `kani_exit_classifier_total`).
#[inline]
pub const fn classify_exit(esr: u64) -> ExitClass {
    match esr_ec(esr) {
        EC_DABT_LOW | EC_IABT_LOW => ExitClass::StageTwoAbort,
        EC_HVC64 => ExitClass::Hvc,
        EC_SMC64 => ExitClass::Smc,
        EC_SYS64 => ExitClass::Sys64,
        EC_WFX => ExitClass::Wfx,
        _ => ExitClass::Undef,
    }
}

/// `ESR_ELx.IL` -- the instruction-length bit `[25]` (`1` = a 32-bit trapped
/// instruction). Set in the injected UNKNOWN syndrome because WFx/MSR/FP traps
/// are all 32-bit instructions. (Mixed-case to mirror the Arm ARM / Linux
/// `esr.h` field name `ESR_ELx_IL`.)
#[allow(non_upper_case_globals)]
pub const ESR_ELx_IL: u64 = 1 << 25;

/// The `VBAR_ELx` vector offset for a **Current-EL-with-SPx, Synchronous**
/// exception (`0x200`). The injected UNDEF targets the guest's OWN EL1 (source
/// EL == target EL, both EL1h using SP_ELx), so it vectors to `VBAR_EL1 + 0x200`
/// -- NOT the Lower-EL `+0x400` slot (the #1 inject-vectoring trap). Authority:
/// `enter_exception64`'s `mode == target_mode -> CURRENT_EL_SP_ELx_VECTOR`.
pub const EL1_SYNC_SPX_OFFSET: u64 = 0x200;

/// `ESR_EL1` for an injected UNKNOWN/UNDEF synchronous exception: `EC = 0x00`
/// (UNKNOWN) `| ESR_ELx_IL` == `0x0200_0000`. A faithful encode of KVM
/// `inject_undef64()` (`esr = ESR_ELx_EC_UNKNOWN<<26; if il32 esr |= ESR_ELx_IL`).
/// The monitor writes this into `ESR_EL1` before redirecting the guest's EL1
/// vector, so the guest's UNDEF handler reads `ESR_EL1.EC == 0x00`.
#[inline]
pub const fn esr_inject_undef() -> u64 {
    (EC_UNKNOWN << 26) | ESR_ELx_IL
}

// ===========================================================================
// aL2.4: the guest's SCTLR_EL1 first-stage ENABLE word -- the load-bearing
// "S1 after S2" step (KVM nvhe/switch.c: "S2 is configured and enabled. We can
// now restore the guest's S1 configuration: SCTLR, and only then TCR"). The
// aL2.4 guest runs at EL1 UNDER our EL2 stage-2 with its OWN stage-1; the single
// instant it turns its first stage ON is `msr sctlr_el1, <baseline | M|C|I>`.
// This pins THAT word -- exactly bits {0,2,12} OR-set, every other baseline bit
// (RES1 / EE / SA / WXN ...) preserved -- to a machine-checked invariant rather
// than a hand-written constant, so a typo in the stub's enable mask is a proof
// failure, not a silent boot hang.
// ===========================================================================

/// `SCTLR_EL1.M`, bit 0: stage-1 MMU enable for EL1&0 (Arm ARM D19.2 SCTLR_EL1).
pub const SCTLR_EL1_M: u64 = 1 << 0;
/// `SCTLR_EL1.C`, bit 2: data / unified cache enable.
pub const SCTLR_EL1_C: u64 = 1 << 2;
/// `SCTLR_EL1.I`, bit 12: instruction cache enable.
pub const SCTLR_EL1_I: u64 = 1 << 12;
/// The exact bitmask the guest OR-sets to bring its first stage up: M|C|I.
pub const SCTLR_EL1_GUEST_ENABLE_BITS: u64 = SCTLR_EL1_M | SCTLR_EL1_C | SCTLR_EL1_I;

/// Compose the guest's first-stage ENABLE word from its current `SCTLR_EL1`
/// baseline: OR-set `M|C|I` (bits 0, 2, 12) and touch nothing else. A pure
/// projection -- the guest reads its baseline `SCTLR_EL1` (carrying the RES1 /
/// EE / SA / WXN bits the reset/drop established), passes it here, and `msr`s the
/// result to flip its stage-1 ON. Mirrors `tb-hal::mmu`'s `sctlr_el1_set_bits`,
/// which RMW-ORs the SAME bits for the kernel's own M3 bring-up.
#[inline]
pub const fn sctlr_el1_guest_enable(baseline: u64) -> u64 {
    baseline | SCTLR_EL1_GUEST_ENABLE_BITS
}

// ===========================================================================
// L2.3: TRAP-and-EMULATE ISS decoders (SYS64 sysreg + Data-Abort MMIO).
//
// Two new syndrome families, both PURE + TOTAL (const, never panic) bit
// extraction over `ESR_EL2.ISS[24:0]`, exactly the family of the existing
// `esr_ec`/`esr_wnr`/`esr_s1ptw` decoders. They underpin the aL2.3 trap-and-
// emulate handler: when a guest MSR/MRS traps (EC 0x18 SYS64) or a guest LDR/STR
// to an unmapped device IPA aborts (EC 0x24 DABT_LOW), the monitor decodes which
// sysreg / which transfer register from the raw syndrome here, emulates the
// access, then ADVANCES ELR_EL2 past the trapped instruction (the OPPOSITE of
// the L2.1 demand-retry).
//
// Bit layouts are IDENTICAL in Linux `esr.h` (ESR_ELx_SYS64_ISS_* / the DABT
// fields) and QEMU `syndrome.h` (FIELD(SYSREG_ISS,...) / FIELD(DABORT_ISS,...)),
// cross-checked against KVM `kvm_emulate.h`. All sit inside ISS[24:0], disjoint
// from EC[31:26]/IL[25], so (like `esr_ec`) the decoders take the raw 64-bit ESR.
// ===========================================================================

// -- SYS64 (MSR/MRS/SYS) trap ISS ------------------------------------------------
// ISS layout for an AArch64 MSR/MRS/SYS trap (EC 0x18), bits within [24:0]:
//   [21:20] Op0, [19:17] Op2, [16:14] Op1, [13:10] CRn, [9:5] Rt,
//   [4:1] CRm, [0] Direction (1 = READ/MRS, 0 = WRITE/MSR); [24:22] RES0.

/// `ESR.ISS.Op0` of a trapped MSR/MRS -- bits `[21:20]`. Always `< 4`.
#[inline]
pub const fn sysreg_iss_op0(esr: u64) -> u64 {
    (esr >> 20) & 0x3
}
/// `ESR.ISS.Op2` of a trapped MSR/MRS -- bits `[19:17]`. Always `< 8`.
#[inline]
pub const fn sysreg_iss_op2(esr: u64) -> u64 {
    (esr >> 17) & 0x7
}
/// `ESR.ISS.Op1` of a trapped MSR/MRS -- bits `[16:14]`. Always `< 8`.
#[inline]
pub const fn sysreg_iss_op1(esr: u64) -> u64 {
    (esr >> 14) & 0x7
}
/// `ESR.ISS.CRn` of a trapped MSR/MRS -- bits `[13:10]`. Always `< 16`.
#[inline]
pub const fn sysreg_iss_crn(esr: u64) -> u64 {
    (esr >> 10) & 0xF
}
/// `ESR.ISS.Rt` of a trapped MSR/MRS -- bits `[9:5]`, the GPR moved to/from the
/// sysreg (the value source for a WRITE, the destination for a READ). `< 32`.
#[inline]
pub const fn sysreg_iss_rt(esr: u64) -> u64 {
    (esr >> 5) & 0x1F
}
/// `ESR.ISS.CRm` of a trapped MSR/MRS -- bits `[4:1]`. Always `< 16`.
#[inline]
pub const fn sysreg_iss_crm(esr: u64) -> u64 {
    (esr >> 1) & 0xF
}
/// `ESR.ISS.Direction` of a trapped MSR/MRS -- bit `[0]`: `true` == a READ (MRS),
/// `false` == a WRITE (MSR). The L2.3 TVM trigger is a WRITE (so this is `false`).
#[inline]
pub const fn sysreg_iss_is_read(esr: u64) -> bool {
    (esr & 1) != 0
}

/// Pack the Rt/Direction-INDEPENDENT sysreg KEY (op0/op1/op2/crn/crm only) into
/// the same `[21:1]` layout the ISS uses -- a faithful clone of `esr.h`
/// `ESR_ELx_SYS64_ISS_SYS_VAL`. The handler compares `(esr & SYSREG_ISS_SYS_MASK)`
/// against this to identify WHICH sysreg was trapped, ignoring the GPR + direction.
#[inline]
pub const fn sysreg_iss_sys_val(op0: u64, op1: u64, op2: u64, crn: u64, crm: u64) -> u64 {
    (op0 << 20) | (op2 << 17) | (op1 << 14) | (crn << 10) | (crm << 1)
}

/// The mask selecting the op0/op1/op2/crn/crm KEY bits of the ISS (everything
/// `sysreg_iss_sys_val` populates -- NOT Rt and NOT the direction bit). AND an
/// ISS with this to get the register identity independent of the GPR/direction.
pub const SYSREG_ISS_SYS_MASK: u64 =
    (0x3 << 20) | (0x7 << 17) | (0x7 << 14) | (0xF << 10) | (0xF << 1);

/// The TVM-trapped trigger register `CONTEXTIDR_EL1` (op0=3, op1=0, CRn=13,
/// CRm=0, op2=1) as a `sysreg_iss_sys_val` key == `0x32_3400`. The canonical KVM
/// `HCR_EL2.TVM` example: side-effect-free under a flat identity stage-1, and
/// trap-and-emulate means the real register is NEVER written.
pub const SYS_CONTEXTIDR_EL1: u64 = sysreg_iss_sys_val(3, 0, 1, 13, 0);

// -- Data-Abort (MMIO) ISS -------------------------------------------------------
// ISS layout for a Data Abort with a valid syndrome (EC 0x24), bits in [24:0]:
//   [24] ISV (syndrome valid), [23:22] SAS (access size), [21] SSE (sign-extend),
//   [20:16] SRT (transfer GPR), [15] SF (64-bit transfer), [14] AR (acq/rel),
//   [7] S1PTW (via `esr_s1ptw`), [6] WnR (via `esr_wnr`), [5:0] DFSC.

/// `ESR.ISS.ISV` -- syndrome-valid, bit `[24]` (`1` => SAS/SSE/SRT/SF/AR are
/// meaningful). `0` for complex/SIMD/pair/writeback accesses Yuva cannot decode.
#[inline]
pub const fn dabt_iss_isv(esr: u64) -> u64 {
    (esr >> 24) & 1
}
/// `ESR.ISS.SAS` -- access size, bits `[23:22]` (`00`=byte, `01`=half, `10`=word,
/// `11`=dword). Always `< 4`.
#[inline]
pub const fn dabt_iss_sas(esr: u64) -> u64 {
    (esr >> 22) & 0x3
}
/// `ESR.ISS.SSE` -- sign-extend, bit `[21]` (`1` => a load narrower than the reg
/// width is sign-extended). Always `0` or `1`.
#[inline]
pub const fn dabt_iss_sse(esr: u64) -> u64 {
    (esr >> 21) & 1
}
/// `ESR.ISS.SRT` -- the transfer GPR (Rt), bits `[20:16]`: the write source / the
/// load destination. Always `< 32` (the FULL 5-bit field -- masking `0xF` would
/// drop x16..x31, the negative control).
#[inline]
pub const fn dabt_iss_srt(esr: u64) -> u64 {
    (esr >> 16) & 0x1F
}
/// `ESR.ISS.SF` -- bit `[15]` (`1` => a 64-bit register transfer, `0` => 32-bit).
/// Always `0` or `1`. On a read the handler masks the result to 32 bits when 0.
#[inline]
pub const fn dabt_iss_sf(esr: u64) -> u64 {
    (esr >> 15) & 1
}
/// `ESR.ISS.AR` -- acquire/release, bit `[14]`. Always `0` or `1`.
#[inline]
pub const fn dabt_iss_ar(esr: u64) -> u64 {
    (esr >> 14) & 1
}

/// The access size in BYTES == `1 << SAS` (KVM `kvm_vcpu_dabt_get_as`): one of
/// `1`/`2`/`4`/`8`. Total (the `1u64 << SAS` shift can never overflow: SAS < 4).
#[inline]
pub const fn dabt_access_size_bytes(esr: u64) -> u64 {
    1u64 << dabt_iss_sas(esr)
}

/// Whether a Data Abort is EMULATABLE by the MMIO seam: `ISV == 1` (a single-GP
/// load/store Yuva can decode) AND `S1PTW == 0` (the access itself faulted, not
/// the stage-1 walk). Fail-closed otherwise -- mirrors KVM `io_mem_abort`'s
/// `!kvm_vcpu_dabt_isvalid -> KVM_EXIT_ARM_NISV` early-out (Yuva has no
/// instruction decoder, so an ISV=0 abort must FAIL, never blind-decode).
#[inline]
pub const fn dabt_is_emulatable(esr: u64) -> bool {
    dabt_iss_isv(esr) != 0 && esr_s1ptw(esr) == 0
}

// ===========================================================================
// aL2.5: the GICv2 **GICH_LRn list-register** encoder/decoder -- the pure value
// computation for a software-injected VIRTUAL INTERRUPT. The EL2 monitor's
// `el2vgic.rs` CALLS `gich_lr_encode(...)` and `write_volatile`s the result into
// GICH_LR0 to inject; it CALLS `lr_is_retired(...)` on the GICH_LRn readback to
// confirm the injected interrupt retired after the guest's EOIR. Nothing here
// touches hardware -- it is the same `forbid(unsafe_code)` leaf the stage-2/vtcr
// encoders live in, Kani-proven (`kani_gich_lr_encode_roundtrip`), Miri-gated.
//
// Field layout (Arm GICv2 Architecture Spec IHI 0048B chapter 5 "GIC
// virtualization" / §4.4 GICH_LRn, cross-checked against QEMU `hw/intc/
// gic_internal.h` `REG32(GICH_LR0, 0x100)` + the `FIELD(GICH_LR0, ...)` defs,
// byte-identical between v6.2.0 and v8.2.0):
//   VirtualID  [9:0]    -- the vINTID presented to the guest at GICV_IAR.
//   PhysicalID [19:10]  -- the physical INTID (used only when HW=1 for HW
//                          de-activation; aL2.5 uses HW=0 so this is 0).
//   EOI        bit19    -- request a maintenance interrupt on EOI (QEMU's
//                          GICH_LR_EOI; aL2.5 leaves it 0, polls ELRSR instead).
//   Priority   [27:23]  -- the LR stores priority[7:3] (the 5 MSBs); aL2.5
//                          injects priority 0 (highest), so this field is 0.
//   State      [29:28]  -- 00 invalid, 01 pending, 10 active, 11 active+pending.
//   Grp1       bit30    -- 0 = Group0, 1 = Group1 (aL2.5 injects Group0).
//   HW         bit31    -- 0 = software-injected (no physical de-activation),
//                          1 = hardware interrupt (PhysicalID drives the
//                          de-activation). aL2.5 is purely SW-injected (HW=0).

/// `GICH_LRn.State` value for an INVALID (empty) list register (`0b00`). The
/// monitor's done-side retire check reads back GICH_LR0 and asserts the state
/// returned to this after the guest's EOIR (the cleanest proof of completion).
pub const GICH_LR_STATE_INVALID: u64 = 0b00;
/// `GICH_LRn.State` value for a PENDING virtual interrupt (`0b01`) -- the state
/// the monitor injects so the GIC virtualization HW signals the VIRQ.
pub const GICH_LR_STATE_PENDING: u64 = 0b01;
/// `GICH_LRn.State` value for an ACTIVE virtual interrupt (`0b10`) -- the state
/// after the guest reads GICV_IAR (pending -> active) but before it EOIRs.
pub const GICH_LR_STATE_ACTIVE: u64 = 0b10;
/// `GICH_LRn.State` value for ACTIVE+PENDING (`0b11`).
pub const GICH_LR_STATE_ACTIVE_PENDING: u64 = 0b11;

/// Shift of the `VirtualID` field in `GICH_LRn` (bit 0).
pub const LR_VIRTID_SHIFT: u64 = 0;
/// Shift of the `PhysicalID` field in `GICH_LRn` (bit 10).
pub const LR_PHYSID_SHIFT: u64 = 10;
/// The `EOI` (maintenance-on-EOI) bit of `GICH_LRn` (bit 19).
pub const LR_EOI_BIT: u64 = 1 << 19;
/// Shift of the `Priority` field in `GICH_LRn` (bit 23; stores priority[7:3]).
pub const LR_PRIO_SHIFT: u64 = 23;
/// Shift of the 2-bit `State` field in `GICH_LRn` (bit 28).
pub const LR_STATE_SHIFT: u64 = 28;
/// The `Grp1` bit of `GICH_LRn` (bit 30): 0 = Group0, 1 = Group1.
pub const LR_GRP1_BIT: u64 = 1 << 30;
/// The `HW` bit of `GICH_LRn` (bit 31): 0 = software-injected, 1 = hardware.
pub const LR_HW_BIT: u64 = 1 << 31;

/// The documented union mask of EVERY `GICH_LRn` field (== QEMU `GICH_LR_MASK`
/// when projected to the GICv2 fields). VirtualID[9:0] | PhysicalID[19:10] |
/// EOI(19) | Priority[27:23] | State[29:28] | Grp1(30) | HW(31). A composed LR
/// must have NO bit set outside this mask (the no-field-bleed property).
pub const GICH_LR_MASK: u32 = 0x3FF             // VirtualID[9:0]
    | (0x3FF << 10)                                // PhysicalID[19:10]
    | (1 << 19)                                    // EOI bit19
    | (0x1F << 23)                                 // Priority[27:23]
    | (0x3 << 28)                                  // State[29:28]
    | (1 << 30)                                    // Grp1 bit30
    | (1 << 31); // HW bit31

/// Compose a 32-bit `GICH_LRn` list-register value from the GICv2 virtual-
/// interrupt fields, EACH masked to its real width and shifted into place so no
/// field bleeds into a neighbour (the field-bleed-prevention discipline the
/// `vtcr`/`s2_leaf` encoders use). `vintid`/`pintid` are 10-bit, `priority` is
/// 5-bit (the stored priority[7:3]), `state` is 2-bit; `group`/`hw`/`eoi` are
/// single bits. Authority: IHI 0048B §4.4 GICH_LRn / QEMU `gic_internal.h`.
///
/// The result fits a `u32` (the LR is a 32-bit register); the monitor stores it
/// with one `write_volatile((GICH_BASE + GICH_LR0) as *mut u32, ...)`.
#[inline]
pub const fn gich_lr_encode(
    vintid: u64,
    pintid: u64,
    state: u64,
    priority: u64,
    group: u64,
    hw: u64,
    eoi: u64,
) -> u32 {
    let v = ((vintid & 0x3FF) << LR_VIRTID_SHIFT)
        | ((pintid & 0x3FF) << LR_PHYSID_SHIFT)
        | (if eoi & 1 != 0 { LR_EOI_BIT } else { 0 })
        | ((priority & 0x1F) << LR_PRIO_SHIFT)
        | ((state & 0x3) << LR_STATE_SHIFT)
        | (if group & 1 != 0 { LR_GRP1_BIT } else { 0 })
        | (if hw & 1 != 0 { LR_HW_BIT } else { 0 });
    v as u32
}

/// Decode the 2-bit `State` field of a `GICH_LRn` value -- bits `[29:28]`.
/// Always `< 4`. The monitor reads it back to observe the pending->active->
/// invalid lifecycle of the injected vIRQ.
#[inline]
pub const fn lr_state(lr: u32) -> u64 {
    ((lr as u64) >> LR_STATE_SHIFT) & 0x3
}

/// Decode the 10-bit `VirtualID` field of a `GICH_LRn` value -- bits `[9:0]`.
/// Always `< 1024`. Equals the vINTID the guest reads from GICV_IAR.
#[inline]
pub const fn lr_virtid(lr: u32) -> u64 {
    ((lr as u64) >> LR_VIRTID_SHIFT) & 0x3FF
}

/// Whether a `GICH_LRn` value is RETIRED (its `State` is INVALID, i.e. the LR
/// went empty after the guest's GICV_EOIR). The monitor's done-side completion
/// proof: an injected LR that retired is one the GIC virtualization HW actually
/// drove through pending->active->invalid -- a fact the guest cannot fake by
/// merely writing a magic.
#[inline]
pub const fn lr_is_retired(lr: u32) -> bool {
    lr_state(lr) == GICH_LR_STATE_INVALID
}

/// `GICH_HCR.En` (bit 0): enable the virtual CPU interface so the list registers
/// are presented to the guest as virtual interrupts. A thin one-bit packer
/// mirroring the `vtcr`/`vttbr` style; the monitor OR-sets this to arm injection.
#[inline]
pub const fn gich_hcr(en: bool) -> u32 {
    if en {
        1
    } else {
        0
    }
}

/// Decode `GICH_VTR.ListRegs` (bits `[5:0]`) into the NUMBER of list registers:
/// `(vtr & 0x3F) + 1` (the field stores num_lrs - 1). The monitor reads GICH_VTR
/// and asserts the result `>= 1` so it never writes an LR index the board lacks.
/// Always `>= 1` and `<= 64` (the 6-bit field maxes at 63 -> 64 LRs).
#[inline]
pub const fn vtr_list_regs(vtr: u32) -> u64 {
    ((vtr as u64) & 0x3F) + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_esr(ec: u64, dfsc: u64, wnr: u64, s1ptw: u64) -> u64 {
        (ec << 26) | (s1ptw << 7) | (wnr << 6) | (dfsc & 0x3F)
    }

    fn make_sysreg_iss(op0: u64, op1: u64, op2: u64, crn: u64, crm: u64, rt: u64, dir: u64) -> u64 {
        (EC_SYS64 << 26)
            | (op0 << 20)
            | (op2 << 17)
            | (op1 << 14)
            | (crn << 10)
            | (rt << 5)
            | (crm << 1)
            | dir
    }

    #[test]
    fn sysreg_iss_fields_decode_and_round_trip() {
        // CONTEXTIDR_EL1 write (op0=3,op1=0,op2=1,CRn=13,CRm=0), Rt=x3, dir=write.
        let iss = make_sysreg_iss(3, 0, 1, 13, 0, 3, 0);
        assert_eq!(sysreg_iss_op0(iss), 3);
        assert_eq!(sysreg_iss_op1(iss), 0);
        assert_eq!(sysreg_iss_op2(iss), 1);
        assert_eq!(sysreg_iss_crn(iss), 13);
        assert_eq!(sysreg_iss_crm(iss), 0);
        assert_eq!(sysreg_iss_rt(iss), 3);
        assert!(!sysreg_iss_is_read(iss)); // a WRITE (MSR)
        assert_eq!(iss & SYSREG_ISS_SYS_MASK, SYS_CONTEXTIDR_EL1);
        assert_eq!(SYS_CONTEXTIDR_EL1, 0x32_3400);
    }

    #[test]
    fn sysreg_iss_sys_mask_excludes_rt_and_direction() {
        // Two ISS for the SAME register but different Rt/direction match the key.
        let a = make_sysreg_iss(3, 0, 1, 13, 0, 3, 0);
        let b = make_sysreg_iss(3, 0, 1, 13, 0, 30, 1);
        assert_eq!(a & SYSREG_ISS_SYS_MASK, b & SYSREG_ISS_SYS_MASK);
        assert!(sysreg_iss_is_read(b)); // a READ (MRS)
    }

    #[test]
    fn dabt_iss_fields_and_size() {
        // ISV=1, SAS=11 (dword), SSE=0, SRT=6, SF=1, AR=0, WnR=0 (read).
        let iss = (EC_DABT_LOW << 26)
            | (1 << 24)
            | (0b11 << 22)
            | (6 << 16)
            | (1 << 15)
            | DFSC_TRANSLATION_L0;
        assert_eq!(dabt_iss_isv(iss), 1);
        assert_eq!(dabt_iss_sas(iss), 0b11);
        assert_eq!(dabt_iss_sse(iss), 0);
        assert_eq!(dabt_iss_srt(iss), 6);
        assert_eq!(dabt_iss_sf(iss), 1);
        assert_eq!(dabt_access_size_bytes(iss), 8);
        assert_eq!(esr_wnr(iss), 0);
        assert!(dabt_is_emulatable(iss));
    }

    #[test]
    fn dabt_access_sizes_cover_all_four() {
        for (sas, bytes) in [(0u64, 1u64), (1, 2), (2, 4), (3, 8)] {
            let iss = (1 << 24) | (sas << 22);
            assert_eq!(dabt_access_size_bytes(iss), bytes);
        }
    }

    #[test]
    fn dabt_isv0_or_s1ptw_is_not_emulatable() {
        // ISV=0 (bit24 clear) -> not emulatable (no decoder); SAS=word is ignored.
        assert!(!dabt_is_emulatable(0b10 << 22));
        // ISV=1 but S1PTW=1 -> not emulatable (the wrong thing faulted).
        assert!(!dabt_is_emulatable((1 << 24) | (1 << 7)));
        // The full 5-bit SRT recovers x31 (the 0xF-mask negative control).
        let iss = (1 << 24) | (0x1F << 16);
        assert_eq!(dabt_iss_srt(iss), 0x1F);
    }

    #[test]
    fn ec_decodes_the_three_dispatch_classes() {
        assert_eq!(esr_ec(make_esr(EC_HVC64, 0, 0, 0)), EC_HVC64);
        assert_eq!(esr_ec(make_esr(EC_DABT_LOW, 0, 0, 0)), EC_DABT_LOW);
        assert_eq!(esr_ec(make_esr(EC_IABT_LOW, 0, 0, 0)), EC_IABT_LOW);
    }

    #[test]
    fn translation_fault_classification_is_exact() {
        // The four translation-fault levels are classified true.
        for dfsc in DFSC_TRANSLATION_L0..=DFSC_TRANSLATION_L3 {
            assert!(esr_is_translation_fault(make_esr(EC_DABT_LOW, dfsc, 0, 0)));
        }
        // An access-flag fault (0b001000) and permission fault (0b001100) are NOT.
        assert!(!esr_is_translation_fault(make_esr(EC_DABT_LOW, 0x08, 0, 0)));
        assert!(!esr_is_translation_fault(make_esr(EC_DABT_LOW, 0x0C, 0, 0)));
        // A DFSC with bit[5] set but low bits 0b0111 (= 0x27) must NOT be a
        // translation fault (the 0x1F-vs-0x3F masking negative control).
        assert!(!esr_is_translation_fault(make_esr(EC_DABT_LOW, 0x27, 0, 0)));
    }

    #[test]
    fn wnr_and_s1ptw_are_single_bits() {
        let esr = make_esr(EC_DABT_LOW, 0x07, 1, 1);
        assert_eq!(esr_wnr(esr), 1);
        assert_eq!(esr_s1ptw(esr), 1);
        let esr0 = make_esr(EC_DABT_LOW, 0x07, 0, 0);
        assert_eq!(esr_wnr(esr0), 0);
        assert_eq!(esr_s1ptw(esr0), 0);
    }

    #[test]
    fn hpfar_fault_ipa_is_page_aligned_and_correct() {
        // HPFAR for IPA 0x1_4000_0000: FIPA = IPA[51:12] in HPFAR[43:4], i.e.
        // hpfar = (ipa >> 12) << 4 = (0x1_4000_0000 >> 8).
        let ipa = 0x1_4000_0000u64;
        let hpfar = (ipa >> 12) << 4;
        assert_eq!(hpfar_fault_ipa(hpfar), ipa);
        assert_eq!(hpfar_fault_ipa(hpfar) & 0xFFF, 0); // page aligned
    }

    #[test]
    fn far_page_offset_is_low_12_bits() {
        assert_eq!(far_page_offset(0x1_4000_0ABC), 0xABC);
    }

    #[test]
    fn classify_exit_maps_each_must_ec_to_its_named_arm() {
        // The six MUST ECs hit their named arms (the abort pair folds together).
        assert_eq!(classify_exit(EC_DABT_LOW << 26), ExitClass::StageTwoAbort);
        assert_eq!(classify_exit(EC_IABT_LOW << 26), ExitClass::StageTwoAbort);
        assert_eq!(classify_exit(EC_HVC64 << 26), ExitClass::Hvc);
        assert_eq!(classify_exit(EC_SMC64 << 26), ExitClass::Smc);
        assert_eq!(classify_exit(EC_SYS64 << 26), ExitClass::Sys64);
        assert_eq!(classify_exit(EC_WFX << 26), ExitClass::Wfx);
    }

    #[test]
    fn classify_exit_defaults_every_other_ec_to_undef() {
        // The self-test's default trigger (FP_ASIMD 0x07) and UNKNOWN 0x00 are
        // NOT in the MUST set -> the fail-closed default.
        assert_eq!(classify_exit(0x07 << 26), ExitClass::Undef); // FP_ASIMD
        assert_eq!(classify_exit(EC_UNKNOWN << 26), ExitClass::Undef); // UNKNOWN
        // A spot-check across the whole EC space: every EC not in the MUST set
        // classifies Undef, and every MUST EC does not.
        let must = [
            EC_DABT_LOW,
            EC_IABT_LOW,
            EC_HVC64,
            EC_SMC64,
            EC_SYS64,
            EC_WFX,
        ];
        for ec in 0u64..64 {
            let class = classify_exit(ec << 26);
            if must.contains(&ec) {
                assert_ne!(class, ExitClass::Undef);
            } else {
                assert_eq!(class, ExitClass::Undef);
            }
        }
    }

    #[test]
    fn esr_inject_undef_round_trips_to_unknown_ec_with_il() {
        let esr = esr_inject_undef();
        assert_eq!(esr, 0x0200_0000); // EC=0x00 (UNKNOWN) | IL bit25
        assert_eq!(esr_ec(esr), EC_UNKNOWN); // decodes back to EC 0x00
        assert_eq!(esr & ESR_ELx_IL, ESR_ELx_IL); // IL set (32-bit trapped insn)
        assert_eq!(EL1_SYNC_SPX_OFFSET, 0x200); // Current-EL SPx Sync vector slot
    }

    #[test]
    fn sctlr_el1_guest_enable_sets_mci_and_preserves_baseline() {
        // The three enable bits are exactly {0, 2, 12}.
        assert_eq!(SCTLR_EL1_GUEST_ENABLE_BITS, (1 << 0) | (1 << 2) | (1 << 12));
        assert_eq!(SCTLR_EL1_GUEST_ENABLE_BITS, 0x1005);
        // From a zero baseline the result IS the enable mask.
        assert_eq!(sctlr_el1_guest_enable(0), SCTLR_EL1_GUEST_ENABLE_BITS);
        // A representative SCTLR_EL1 reset/drop baseline (RES1 bits 11/20/22/23/28/29
        // set, SA1 bit 4, plus a stray EE bit 25) is preserved bit-for-bit while M|C|I
        // are forced on.
        let baseline = (1u64 << 4) | (1 << 11) | (1 << 20) | (1 << 22) | (1 << 23)
            | (1 << 25) | (1 << 28) | (1 << 29);
        let enabled = sctlr_el1_guest_enable(baseline);
        assert_eq!(enabled & SCTLR_EL1_M, SCTLR_EL1_M);
        assert_eq!(enabled & SCTLR_EL1_C, SCTLR_EL1_C);
        assert_eq!(enabled & SCTLR_EL1_I, SCTLR_EL1_I);
        // Every baseline bit survives, and ONLY the enable bits were added.
        assert_eq!(enabled & baseline, baseline);
        assert_eq!(
            enabled & !SCTLR_EL1_GUEST_ENABLE_BITS,
            baseline & !SCTLR_EL1_GUEST_ENABLE_BITS
        );
        // Idempotent: enabling an already-enabled word is a no-op.
        assert_eq!(sctlr_el1_guest_enable(enabled), enabled);
    }

    #[test]
    fn gich_lr_encode_fields_round_trip() {
        // A representative SW-injected PENDING vIRQ: vINTID=0x2A (42), pINTID=0,
        // state=pending, priority=0, group0, HW=0, EOI=0 -- the exact aL2.5 LR0.
        let lr = gich_lr_encode(0x2A, 0, GICH_LR_STATE_PENDING, 0, 0, 0, 0);
        assert_eq!(lr_virtid(lr), 0x2A);
        assert_eq!(lr_state(lr), GICH_LR_STATE_PENDING);
        assert!(!lr_is_retired(lr));
        // No bit set outside the documented union mask.
        assert_eq!(lr & !GICH_LR_MASK, 0);
        // The HW + Grp1 bits are clear (SW-injected, Group0).
        assert_eq!(lr as u64 & LR_HW_BIT, 0);
        assert_eq!(lr as u64 & LR_GRP1_BIT, 0);
    }

    #[test]
    fn gich_lr_encode_all_fields_pack_disjoint() {
        // Pack every field at its max so any bleed shows. vINTID=0x3FF, pINTID=
        // 0x3FF, state=active+pending, priority=0x1F, group1, HW=1, EOI=1.
        let lr = gich_lr_encode(0x3FF, 0x3FF, GICH_LR_STATE_ACTIVE_PENDING, 0x1F, 1, 1, 1);
        let v = lr as u64;
        assert_eq!(v & 0x3FF, 0x3FF); // VirtualID [9:0]
        assert_eq!((v >> 10) & 0x3FF, 0x3FF); // PhysicalID [19:10]
        assert_eq!((v >> 19) & 1, 1); // EOI bit19
        assert_eq!((v >> 23) & 0x1F, 0x1F); // Priority [27:23]
        assert_eq!((v >> 28) & 0x3, 0x3); // State [29:28]
        assert_eq!((v >> 30) & 1, 1); // Grp1 bit30
        assert_eq!((v >> 31) & 1, 1); // HW bit31
        // The fully-packed value == the union mask (every documented bit set).
        assert_eq!(lr, GICH_LR_MASK);
    }

    #[test]
    fn lr_is_retired_iff_state_invalid() {
        for (state, retired) in [
            (GICH_LR_STATE_INVALID, true),
            (GICH_LR_STATE_PENDING, false),
            (GICH_LR_STATE_ACTIVE, false),
            (GICH_LR_STATE_ACTIVE_PENDING, false),
        ] {
            let lr = gich_lr_encode(0x10, 0, state, 0, 0, 0, 0);
            assert_eq!(lr_is_retired(lr), retired);
        }
    }

    #[test]
    fn gich_hcr_and_vtr_list_regs() {
        assert_eq!(gich_hcr(true), 1);
        assert_eq!(gich_hcr(false), 0);
        // GICH_VTR.ListRegs stores num_lrs-1: 0 -> 1 LR, 3 -> 4 LRs, 0x3F -> 64.
        assert_eq!(vtr_list_regs(0), 1);
        assert_eq!(vtr_list_regs(3), 4);
        assert_eq!(vtr_list_regs(0x3F), 64);
        // High bits of VTR (ID/PRIbits/PREbits) are ignored -- only [5:0] count.
        assert_eq!(vtr_list_regs(0xFFFF_FF03), 4);
    }
}
