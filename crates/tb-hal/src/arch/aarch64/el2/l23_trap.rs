//! L2.3 "el2-trap" rung (the trap-and-emulate proof), extracted from
//! `el2/mod.rs` for readability. The dispatch-called emulate helpers
//! (`el2_sysreg_emulate` / `el2_mmio_emulate`) STAY in `mod.rs` next to the
//! central `aarch64_el2_sync_handler` match; this child carries the rung's
//! naked guest stub + the safe facade. As a CHILD of `el2`, it sees every
//! `super`-private monitor item via `use super::*`, so this is a 100%
//! BEHAVIOUR-PRESERVING code move: the kernel still calls
//! `el2::el2_trap_selftest()` through the `pub use` re-export in `mod.rs`.
#![allow(unused_imports)]
use super::*;

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
