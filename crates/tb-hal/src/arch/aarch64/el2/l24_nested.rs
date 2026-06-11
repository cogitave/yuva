//! aL2.4 "el2-guest" rung (the nested-guest two-stage proof), extracted from
//! `el2/mod.rs` for readability. As a CHILD of `el2`, this module sees every
//! `super`-private monitor item (the shared consts, the `Frame`/`BOOTED_AT_EL2`
//! core, the EL1 vbar helpers) via `use super::*`, so this is a 100%
//! BEHAVIOUR-PRESERVING code move: the kernel still calls
//! `el2::el2_nested_guest_selftest()` through the `pub use` re-export in
//! `mod.rs`.
#![allow(unused_imports)]
use super::*;

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
