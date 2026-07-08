//! The verified-leaf SELF-TEST FACADE seam: the L2.0..L2.6 sovereignty-track proofs
//! (VmxProof/El2Proof/Stage2Proof/ExitsProof/TrapProof/GuestProof/VgicProof/SmmuProof)
//! and the M19..M26 device-I/O + memory + learning-loop proofs (VirtioProof/
//! PersistProof/KanProof/ProvProof/ExpProof/BakeoffProof/OpframeProof/
//! ExitTelemetryProof) plus their `*_selftest()` facade fns. Each facade is a SAFE
//! entry point the `#![forbid(unsafe_code)]` kernel calls to drive a verified-leaf
//! round-trip (the silicon-unsafe / pure-value work lives in `arch/`, `mem`, or the
//! `tb-encode` leaves); the kernel only branches on the returned pure-data verdict to
//! render a milestone marker. Extracted VERBATIM from the lib.rs root for readability;
//! the crate-root `pub use verified_leaf::*;` re-export preserves every `tb_hal::*Proof`
//! / `tb_hal::*_selftest` (kernel) and `crate::*Proof` (internal) path -- a 100%
//! behaviour-preserving move with ZERO coupling to the task/agent/scheduler core.
#![allow(unused_imports)]
use super::*;

// ===========================================================================
// L2.0: VMX-root self-test facade (the L2 sovereignty track).
//
// The first rung of `tb-core`, the from-scratch Type-1 microhypervisor: a SAFE
// entry point the `#![forbid(unsafe_code)]` kernel calls to drive the silicon-
// unsafe VMX bring-up confined to `arch/x86_64/vmx/`. On x86_64 it does the full
// VMXON -> minimal VMCS -> EPT identity map -> 1-`CPUID` long-mode nested guest
// -> world-switch -> caught VM-exit -> VMXOFF proof (or skips gracefully when VMX
// is not exposed, the TCG `qemu64` case). On aarch64 (no VMX) it is N/A: the EL2
// world-switch is a LATER L2 sub-milestone. Mirrors the `mmu_selftest`/`user_demo`
// pattern — all unsafe stays in tb-hal/arch, the kernel only branches on a value.
// ===========================================================================

/// L2.0 VMX-root self-test outcome (returned to the kernel for marker rendering).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmxProof {
    /// This arch has no VMX (aarch64): the EL2 path is a later sub-milestone.
    NotApplicable,
    /// VMX is not exposed or the BIOS locked VT-x off — graceful skip (no VMX
    /// instruction was executed). The TCG `qemu64` case; mirrors the `vmm-boot`
    /// `KVM_OK` allow-skip.
    Unavailable,
    /// VMXON itself failed (VMfail) — VMX advertised but the substrate could not
    /// enter VMX operation (e.g. incomplete emulation under `-cpu max` TCG).
    VmxonFailed,
    /// VMXON succeeded but VM-entry failed; `vm_error` is the VMCS
    /// VM-instruction-error (0 if even VMPTRLD failed before launch).
    EntryFailed {
        /// The VMCS VM-instruction-error code (Intel SDM Vol 3C §30.4).
        vm_error: u64,
    },
    /// THE PROOF: the world switch ran and the nested guest's VM-exit was caught;
    /// `exit_reason` is the basic exit reason (10 = CPUID, the expected value).
    Proven {
        /// The basic VM-exit reason (VMCS field 0x4402, bits 15:0).
        exit_reason: u32,
    },
}

/// L2.0: run the VMX-root + nested-guest + caught-VM-exit self-test (x86_64), or
/// report [`VmxProof::NotApplicable`] on aarch64. See [`VmxProof`].
#[cfg(target_arch = "x86_64")]
pub fn vmx_selftest() -> VmxProof {
    arch::vmx_selftest()
}

/// L2.0: aarch64 has no VMX — the EL2 world-switch is the aarch64 realization of
/// this rung (see [`el2_selftest`]), so this reports [`VmxProof::NotApplicable`]
/// (the kernel prints the n/a marker).
#[cfg(target_arch = "aarch64")]
pub fn vmx_selftest() -> VmxProof {
    VmxProof::NotApplicable
}

// ===========================================================================
// L2.0: EL2 (nVHE) world-switch self-test facade (the aarch64 L2 sovereignty
// track — the ARM realization of the x86 VMX-root rung).
//
// The aarch64 proof that Yuva *is* the hypervisor: booted at EL2 (QEMU
// `virt,virtualization=on`), installed a resident nVHE EL2 monitor, dropped to
// EL1 to run M0..M18 unchanged, then at this slot does a real EL1<->EL2
// world-switch — a bootstrap `HVC #0` from the running EL1 kernel ERETs into a
// tiny EL1 guest stub, whose `HVC #1` traps back to EL2 and is caught. ALL the
// silicon-unsafe/asm is confined to tb-hal's `arch/aarch64/{boot,el2,el2_vectors}.rs`,
// so the framekernel invariant SURVIVES: this crate stays unsafe-free and the
// kernel only branches on the returned `El2Proof`. Unlike L2.0 vmxroot (which
// only SKIPS under TCG), this proof actually EXECUTES under pure TCG. On x86_64
// (no EL2) it is N/A — exactly mirroring the `VmxProof`/`vmx_selftest` block.
// ===========================================================================

/// L2.0 EL2 world-switch self-test outcome (returned to the kernel for marker
/// rendering). Mirrors [`VmxProof`] one EL up: the proof is a closed
/// ERET->guest->HVC->EL2 round-trip rather than a VMLAUNCH/VM-exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum El2Proof {
    /// This arch has no EL2 hypervisor level (x86_64): VMX-root is its rung.
    NotApplicable,
    /// We did NOT boot at EL2 (plain QEMU `virt`, no `virtualization=on`): no
    /// resident monitor exists, so no HVC is issued — a graceful green skip
    /// (mirrors [`VmxProof::Unavailable`], no privileged instruction executed).
    Unavailable,
    /// We booted at EL2 and issued the bootstrap HVC, but the monitor reported a
    /// fault instead of a clean round-trip; `code` is the nonzero diagnostic
    /// (booted-EL2 but failed — surfaced honestly as a red marker).
    RoundTripFailed {
        /// The nonzero failure code the EL2 monitor returned in x0.
        code: u64,
    },
    /// THE PROOF: the EL1->EL2->EL1-guest->EL2->EL1 world-switch ran and the
    /// guest's HVC was caught with its magic verified; `hvc_imm` is the guest's
    /// trap-back immediate (1, the expected value).
    Proven {
        /// The guest HVC immediate that closed the round-trip (1 == `hvc #1`).
        hvc_imm: u64,
    },
}

/// L2.0: run the EL2 (nVHE) world-switch self-test (aarch64), or report
/// [`El2Proof::NotApplicable`] on x86_64. See [`El2Proof`].
#[cfg(target_arch = "aarch64")]
pub fn el2_selftest() -> El2Proof {
    arch::el2_selftest()
}

/// L2.0: x86_64 has no EL2 — the VMX-root world-switch (see [`vmx_selftest`]) is
/// this arch's realization of the rung, so this reports
/// [`El2Proof::NotApplicable`] (the kernel prints the n/a marker).
#[cfg(target_arch = "x86_64")]
pub fn el2_selftest() -> El2Proof {
    El2Proof::NotApplicable
}

// ===========================================================================
// L2.1: stage-2 demand-translation self-test facade (the aarch64 analog of x86
// EPT-violation handling — the SECOND L2 sovereignty rung, one EL down from the
// stage-1 MMU and built ON TOP of L2.0's resident EL2 monitor).
//
// Where L2.0 proved Yuva *is* the hypervisor (a real EL1<->EL2 world-switch),
// L2.1 proves the R/W second-stage leaf is THE isolation primitive: inside a
// short self-test window the EL2 monitor arms stage-2 (HCR_EL2.VM=1) over a
// table that identity-maps everything the guest needs to RUN but leaves ONE IPA
// gigabyte a deliberate HOLE; the EL1 guest stub touches it, faults to EL2 as a
// stage-2 translation fault, the monitor reads HPFAR_EL2, demand-maps a leaf,
// and ERETs WITHOUT advancing ELR so the guest re-executes the load and closes
// the round-trip — the citable ARM equivalent of the x86 `touch-unmapped-GPA ->
// reason-48 -> map -> INVEPT -> resume` loop. ALL the silicon-unsafe/asm is
// confined to `arch/aarch64/{stage2,el2,el2_vectors}.rs` (stage-2 is OFF for the
// whole M0..M18 + L2.0 run and torn down before this returns — zero regression),
// so this crate stays unsafe-free and the kernel only branches on a closed enum.
// On x86_64 (no EL2/stage-2) it is N/A — mirroring the `El2Proof` block one rung
// up, with the stage-2 demand path standing in for VMX's nested-guest exit.
// ===========================================================================

/// L2.1 stage-2 demand-translation self-test outcome (returned to the kernel for
/// marker rendering). A SIBLING of [`El2Proof`] (not an overload): the proof is a
/// closed demand-fault round-trip (`fault -> demand-map -> ERET-retry`) rather
/// than a trap-and-emulate HVC exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage2Proof {
    /// This arch has no EL2/stage-2 (x86_64): VMX-root + EPT is its analog.
    NotApplicable,
    /// We did NOT boot at EL2 (plain QEMU `virt`): no resident monitor, so
    /// stage-2 is never armed — a graceful green skip (mirrors
    /// [`El2Proof::Unavailable`]; no privileged instruction executed).
    Unavailable,
    /// We booted at EL2 and ran the round-trip, but the monitor reported a fault
    /// instead of a clean demand-translation (build OOM, S1PTW, the wrong fault
    /// IPA, a non-translation abort, a missing pre-built table, a bad magic, or
    /// an unserved fault); `code` is the nonzero diagnostic (surfaced honestly as
    /// a red marker WITHOUT a "stage2 OK" substring).
    Faulted {
        /// The nonzero failure code the EL2 monitor returned in x0.
        code: u64,
    },
    /// THE PROOF: the EL1-guest stage-2 abort was caught, demand-mapped, and the
    /// retried load succeeded — the demand-translation round-trip closed.
    /// `fault_ipa` is the faulting Intermediate Physical Address the monitor read
    /// from `HPFAR_EL2` (the deliberate hole, `0x1_4000_0000`).
    Proven {
        /// The demand-faulted IPA the stage-2 leaf was spliced for.
        fault_ipa: u64,
    },
}

/// L2.1: run the stage-2 demand-translation self-test (aarch64), or report
/// [`Stage2Proof::NotApplicable`] on x86_64. See [`Stage2Proof`].
#[cfg(target_arch = "aarch64")]
pub fn stage2_selftest() -> Stage2Proof {
    arch::stage2_selftest()
}

/// L2.1: x86_64 has no EL2/stage-2 — the VMX-root + EPT path (see
/// [`vmx_selftest`]) is this arch's realization of the rung, so this reports
/// [`Stage2Proof::NotApplicable`] (the kernel prints the n/a marker).
#[cfg(target_arch = "x86_64")]
pub fn stage2_selftest() -> Stage2Proof {
    Stage2Proof::NotApplicable
}

// ===========================================================================
// L2.2: EL2 exit-dispatch self-test facade (the aarch64 analog of the x86
// `arm_exit_handlers[]` table — the THIRD L2 sovereignty rung, built ON TOP of
// L2.0's resident EL2 monitor and SIBLING to L2.1's stage-2 demand path).
//
// Where L2.0 proved Yuva *is* the hypervisor and L2.1 proved the stage-2 leaf
// is the isolation primitive, L2.2 proves the EL2 *exit-dispatch table* itself:
// inside a short self-test window the monitor routes EVERY guest exit through
// the PURE, Kani-proven `tb_encode::el2_trap::classify_exit` (the ARM analog of
// x86 `arm_exit_handlers[]`), then fires TWO distinct arms — a trapped `WFx`
// (HCR_EL2.TWI|TWE) it RESUMES one instruction past, and an FP/SIMD access
// (CPTR_EL2.TFP, EC 0x07, NOT in the MUST set) that hits the fail-closed
// inject-UNDEF DEFAULT (the `[0..EC_MAX]=kvm_handle_unknown_ec` discipline,
// software-synthesized exactly as KVM's `enter_exception64`). The injected UNDEF
// is caught by the guest's OWN EL1 vector, which echoes a magic; the verdict
// requires BOTH arms to have fired AND the magic to round-trip. ALL the
// silicon-unsafe/asm is confined to `arch/aarch64/{exits,exits_vectors,el2,
// el2_vectors}.rs` (the window is OFF for the whole M0..M19 + L2.0/L2.1 run and
// torn down before this returns — zero regression), so this crate stays
// unsafe-free and the kernel only branches on a closed enum. On x86_64 (no EL2)
// it is N/A — mirroring the `El2Proof`/`Stage2Proof` blocks above.
// ===========================================================================

/// L2.2 EL2 exit-dispatch self-test outcome (returned to the kernel for marker
/// rendering). A SIBLING of [`El2Proof`]/[`Stage2Proof`]: the proof is a closed
/// round-trip that fires TWO exit-table arms (the `WFx` resume AND the
/// fail-closed inject-UNDEF default), rather than a single trap-and-emulate exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitsProof {
    /// This arch has no EL2 exit-dispatch table (x86_64): the VMX
    /// `arm_exit_handlers[]` analog is its rung.
    NotApplicable,
    /// We did NOT boot at EL2 (plain QEMU `virt`): no resident monitor, so the
    /// exit window is never armed — a graceful green skip (mirrors
    /// [`El2Proof::Unavailable`]; no privileged instruction executed).
    Unavailable,
    /// We booted at EL2 and ran the round-trip, but the monitor reported a fault
    /// instead of a clean exit dispatch (the `WFx` arm missed, the inject-UNDEF
    /// default missed, or the guest echoed the wrong magic); `code` is the
    /// nonzero diagnostic (surfaced honestly as a red marker WITHOUT an
    /// "el2-exits OK" substring).
    Faulted {
        /// The nonzero failure code the EL2 monitor returned in x0.
        code: u64,
    },
    /// THE PROOF: the exit-dispatch round-trip closed — the `WFx` trap was
    /// resumed AND the FP/SIMD trap hit the fail-closed inject-UNDEF default,
    /// whose injected exception the guest's EL1 vector caught and echoed.
    /// `served` is the EL2 served mask (`WFX|UNDEF` bits, == `0b11`).
    Proven {
        /// The served-arm bitmask the monitor accumulated (`WFX(1) | UNDEF(2)`).
        served: u64,
    },
}

/// L2.2: run the EL2 exit-dispatch self-test (aarch64), or report
/// [`ExitsProof::NotApplicable`] on x86_64. See [`ExitsProof`].
#[cfg(target_arch = "aarch64")]
pub fn el2_exits_selftest() -> ExitsProof {
    arch::el2_exits_selftest()
}

/// L2.2: x86_64 has no EL2 exit-dispatch table — the VMX `arm_exit_handlers[]`
/// analog (see [`vmx_selftest`]) is this arch's realization of the rung, so this
/// reports [`ExitsProof::NotApplicable`] (the kernel prints the n/a marker).
#[cfg(target_arch = "x86_64")]
pub fn el2_exits_selftest() -> ExitsProof {
    ExitsProof::NotApplicable
}

// ===========================================================================
// L2.3: EL2 trap-and-emulate self-test facade — the aarch64 trap-and-EMULATE
// rung (the SYSREG + MMIO-abort emulate primitive), the FOURTH L2 rung built ON
// TOP of L2.0's resident EL2 monitor.
//
// Inside a short self-test window the monitor traps a guest sysreg WRITE
// (HCR_EL2.TVM, the `msr contextidr_el1` trigger) and a guest MMIO LDR/STR to an
// unmapped device IPA (HCR_EL2.VM), DECODES each via the pure Kani-proven
// `el2_trap` ISS decoders, EMULATES it (records the sysreg value; routes the
// MMIO access through the `device_mmio` callback SEAM — the split-VMM upcall
// point), and ADVANCES ELR_EL2 past the trapped instruction (the OPPOSITE of
// L2.1's demand-retry, exactly KVM's `kvm_incr_pc`). The verdict requires ALL
// THREE arms (SYSREG emulate + MMIO write + MMIO read) AND the recorded values
// to round-trip. ALL the silicon-unsafe/asm is confined to
// `arch/aarch64/{el2mmio,el2,stage2}.rs` (the window is OFF for the whole
// M0..M19 + L2.0/L2.1/L2.2 run and torn down before this returns — zero
// regression), so this crate stays unsafe-free and the kernel only branches on a
// closed enum. On x86_64 (no EL2) it is N/A — mirroring the `ExitsProof` block.
// ===========================================================================

/// L2.3 EL2 trap-and-emulate self-test outcome (returned to the kernel for marker
/// rendering). A SIBLING of [`El2Proof`]/[`Stage2Proof`]/[`ExitsProof`]: the proof
/// is a closed round-trip that trap-and-EMULATES THREE accesses (a sysreg WRITE,
/// an MMIO WRITE, an MMIO READ), advancing ELR past each rather than re-executing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrapProof {
    /// This arch has no EL2 trap-and-emulate seam (x86_64): the VMX
    /// trap-and-emulate path is its rung.
    NotApplicable,
    /// We did NOT boot at EL2 (plain QEMU `virt`): no resident monitor, so the
    /// trap window is never armed — a graceful green skip (mirrors
    /// [`El2Proof::Unavailable`]; no privileged instruction executed).
    Unavailable,
    /// We booted at EL2 and ran the round-trip, but the monitor reported a fault
    /// instead of a clean trap-and-emulate (an arm missed, a decoded value was
    /// wrong, the SYS64 was not the expected trigger, or the MMIO abort was
    /// non-decodable ISV=0); `code` is the nonzero diagnostic (surfaced honestly
    /// as a red marker WITHOUT an "el2-trap OK" substring).
    Faulted {
        /// The nonzero failure code the EL2 monitor returned in x0.
        code: u64,
    },
    /// THE PROOF: the trap-and-emulate round-trip closed — the SYS64 sysreg WRITE
    /// was decoded + emulated, the MMIO WRITE was routed through the device seam,
    /// and the MMIO READ returned the device value into the transfer register
    /// (the guest's own compare confirmed it). `served` is the EL2 served mask
    /// (`SYSREG|MMIO_WR|MMIO_RD` bits, == `0b111`).
    Proven {
        /// The served-arm bitmask the monitor accumulated (`SYSREG(1) |
        /// MMIO_WR(2) | MMIO_RD(4)`).
        served: u64,
    },
}

/// L2.3: run the EL2 trap-and-emulate self-test (aarch64), or report
/// [`TrapProof::NotApplicable`] on x86_64. See [`TrapProof`].
#[cfg(target_arch = "aarch64")]
pub fn el2_trap_selftest() -> TrapProof {
    arch::el2_trap_selftest()
}

/// L2.3: x86_64 has no EL2 trap-and-emulate seam — the VMX trap-and-emulate path
/// is this arch's realization of the rung, so this reports
/// [`TrapProof::NotApplicable`] (the kernel prints the n/a marker).
#[cfg(target_arch = "x86_64")]
pub fn el2_trap_selftest() -> TrapProof {
    TrapProof::NotApplicable
}

// ===========================================================================
// aL2.4: EL2 nested-guest (GENUINE two-stage) self-test facade — a REAL minimal
// Yuva guest that runs at EL1 UNDER our EL2 stage-2 with its OWN stage-1 MMU
// live, the FIFTH L2 rung built ON TOP of L2.0's resident EL2 monitor.
//
// The monitor arms the GiB0+GiB1 identity stage-2 (HCR_EL2.VM=1) and erets into a
// minimal guest that BUILDS its own 3-level stage-1 (reusing the REAL kernel M3
// `tb_encode::paging` encoders + the mmu.rs MAIR/TCR geometry), ENABLES it
// (SCTLR_EL1.M=1 — the Kani-proven `sctlr_el1_guest_enable` "S1 after S2" step),
// and stores+reads back a sentinel through a VA that has NO flat meaning — a
// GENUINE VA->(guest stage-1)->IPA->(our stage-2)->PA two-stage walk, the
// guest's own stage-1 walk itself re-translated by our stage-2 (S1PTW). It then
// installs its OWN VBAR_EL1 and takes its OWN EL1 `brk` exception (an EL1->EL1
// trap, NOT an EL2 exit — proof the guest's exception delivery works under
// stage-2), and HVCs done. The verdict requires BOTH the guest's two-stage
// readback AND its EL1 trap to have fired, with an INDEPENDENT EL2-side identity-
// alias readback of the sentinel as corroboration the guest cannot fake. The
// stage-2 is torn down (HCR.VM=0) BEFORE the monitor unwinds, and the facade
// restores the kernel's saved TTBR0_EL1/TCR_EL1/MAIR_EL1/SCTLR_EL1/VBAR_EL1 (the
// EL1-side teardown — a new surface the guest mutated, vs L2.0..L2.3) so the
// kernel resumes on its OWN stage-1 (zero regression — M19 still prints after).
// ALL the new asm/unsafe is confined to tb-hal's arch/aarch64/{el2,
// el2_nested_vectors,stage2}.rs, so this crate stays unsafe-free and the kernel
// only branches on a closed enum. On x86_64 (no EL2) it is N/A — mirroring the
// `TrapProof` block above.
// ===========================================================================

/// aL2.4 EL2 nested-guest self-test outcome (returned to the kernel for marker
/// rendering). A SIBLING of [`El2Proof`]/[`Stage2Proof`]/[`ExitsProof`]/
/// [`TrapProof`]: the proof is a closed round-trip in which a REAL minimal guest
/// runs at EL1 UNDER our stage-2 with its OWN stage-1 live — a GENUINE two-stage
/// walk — and takes its OWN EL1 exception, rather than the single-stage rungs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NestedGuestProof {
    /// This arch has no EL2 / two-stage translation (x86_64): the nested-VMX
    /// path would be its rung.
    NotApplicable,
    /// We did NOT boot at EL2 (plain QEMU `virt`): no resident monitor, so the
    /// stage-2 is never armed — a graceful green skip (mirrors
    /// [`El2Proof::Unavailable`]; no privileged instruction executed).
    Unavailable,
    /// We booted at EL2 and ran the round-trip, but the monitor reported a fault
    /// instead of a clean two-stage proof (the guest's S1 walk faulted stage-2,
    /// the EL2-side alias readback was wrong, the guest's readback failed, or its
    /// EL1 trap was not taken); `code` is the nonzero diagnostic (surfaced
    /// honestly as a red marker WITHOUT an "el2-guest OK" substring).
    Faulted {
        /// The nonzero failure code the EL2 monitor returned in x0.
        code: u64,
    },
    /// THE PROOF: the nested-guest round-trip closed — the guest built + enabled
    /// its OWN stage-1 under our stage-2, the GENUINE two-stage store/load
    /// resolved (corroborated by the EL2-side identity-alias readback), AND the
    /// guest took its OWN EL1 exception. `magic` is `0x2E5` ("2 stages").
    Proven {
        /// The guest's two-stage magic (`0x2E5` iff both gates passed).
        magic: u64,
    },
}

/// aL2.4: run the EL2 nested-guest (two-stage) self-test (aarch64), or report
/// [`NestedGuestProof::NotApplicable`] on x86_64. See [`NestedGuestProof`].
#[cfg(target_arch = "aarch64")]
pub fn el2_nested_guest_selftest() -> NestedGuestProof {
    arch::el2_nested_guest_selftest()
}

/// aL2.4: x86_64 has no EL2 / two-stage translation — the (deferred) nested-VMX
/// path would be this arch's realization of the rung, so this reports
/// [`NestedGuestProof::NotApplicable`] (the kernel prints the n/a marker).
#[cfg(target_arch = "x86_64")]
pub fn el2_nested_guest_selftest() -> NestedGuestProof {
    NestedGuestProof::NotApplicable
}

// ===========================================================================
// aL2.5: EL2 vGIC virtual-interrupt injection + WFI scheduler-hook self-test
// facade — the SIXTH L2 rung, built ON TOP of L2.0's resident EL2 monitor.
//
// The proof is a closed round-trip in which the monitor SOFTWARE-INJECTS a
// virtual interrupt into a guest that PARKS on WFI: the guest enables its OWN
// GICV virtual CPU interface, parks on WFI (the canonical scheduler yield
// point); the WFI traps to EL2 (HCR_EL2.TWI) where the monitor writes a PENDING
// vIRQ into GICH_LR0 (via the Kani-proven `tb_encode::el2_trap::gich_lr_encode`)
// and resumes the guest past the WFI; with HCR_EL2.IMO routing the VIRQ to EL1 +
// the guest's GICV_CTLR.En + PSTATE.I clear, the guest immediately takes the
// vIRQ at its OWN EL1 IRQ vector, reads GICV_IAR == the injected vINTID, sets a
// sentinel, and writes GICV_EOIR. The verdict requires the CONJUNCTION of the
// guest-side magic AND the monitor-side independent confirmation (the WFI park
// was observed AND GICH_ELRSR0 shows LR0 retired — a fact the guest cannot fake
// by merely writing a magic). The window is torn down (HCR_EL2 baseline,
// GICH_HCR.En=0, GICH_LR0 zeroed) BEFORE the monitor unwinds, and the facade
// restores the kernel's VBAR_EL1 (the EL1-side teardown — the guest installed
// its OWN vGIC vectors) so the kernel resumes on its OWN exception table (zero
// regression — M19 still prints after). ALL the new asm/unsafe is confined to
// tb-hal's arch/aarch64/{el2,el2vgic,el2_vgic_vectors}.rs (the GICH_LR encoder
// in tb-encode is `forbid(unsafe_code)` + Kani-proven), so this crate stays
// unsafe-free and the kernel only branches on a closed enum. On x86_64 (no EL2)
// it is N/A — mirroring the `NestedGuestProof` block above.
// ===========================================================================

/// aL2.5 EL2 vGIC virtual-interrupt-injection self-test outcome (returned to the
/// kernel for marker rendering). A SIBLING of [`NestedGuestProof`]/[`ExitsProof`]:
/// the proof is a closed round-trip in which the monitor SOFTWARE-INJECTS a
/// virtual interrupt into a guest that PARKS on WFI and the guest takes + acks
/// the vIRQ via its GICV virtual CPU interface, rather than the two-stage /
/// trap-and-emulate rungs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VgicProof {
    /// This arch has no EL2 / GIC virtualization (x86_64): the (deferred) APIC
    /// virtualization / posted-interrupt path would be its rung.
    NotApplicable,
    /// We did NOT boot at EL2 (plain QEMU `virt`): no resident monitor, so the
    /// vGIC window is never armed — a graceful green skip (mirrors
    /// [`NestedGuestProof::Unavailable`]; no privileged instruction executed).
    Unavailable,
    /// We booted at EL2 and ran the round-trip, but the monitor reported a fault
    /// instead of a clean vGIC injection proof (the WFI park was not observed,
    /// the guest presented the wrong magic, the injected list register never
    /// retired, the board exposed no list registers, or the WFI re-looped);
    /// `code` is the nonzero diagnostic (surfaced honestly as a red marker
    /// WITHOUT a "vgic OK" substring).
    Faulted {
        /// The nonzero failure code the EL2 monitor returned in x0.
        code: u64,
    },
    /// THE PROOF: the vGIC injection round-trip closed — the guest parked on WFI,
    /// the monitor injected a pending vIRQ via GICH_LR0 and resumed it, the guest
    /// took the vIRQ at its OWN EL1 IRQ vector and acked + EOIed it via GICV, AND
    /// the monitor independently confirmed the injected list register retired
    /// (GICH_ELRSR0 — a fact the guest cannot fake). `vintid` is the injected +
    /// acknowledged virtual interrupt ID.
    Proven {
        /// The injected + acknowledged virtual interrupt ID (vINTID).
        vintid: u64,
    },
}

/// aL2.5: run the EL2 vGIC virtual-interrupt-injection self-test (aarch64), or
/// report [`VgicProof::NotApplicable`] on x86_64. See [`VgicProof`].
#[cfg(target_arch = "aarch64")]
pub fn el2_vgic_selftest() -> VgicProof {
    arch::el2_vgic_selftest()
}

/// aL2.5: x86_64 has no EL2 / GIC virtualization — the (deferred) APIC-
/// virtualization / posted-interrupt path would be this arch's realization of
/// the rung, so this reports [`VgicProof::NotApplicable`] (the kernel prints the
/// n/a marker).
#[cfg(target_arch = "x86_64")]
pub fn el2_vgic_selftest() -> VgicProof {
    VgicProof::NotApplicable
}

// ===========================================================================
// aL2.6: SMMUv3 stage-2 DMA-isolation table-programming self-test facade — the
// SEVENTH L2 rung, the IOMMU twin of the L2.1 CPU stage-2 demand-translation.
//
// Unlike L2.0..L2.5 (which world-switch through the resident EL2 monitor), this
// rung runs ENTIRELY at EL1: the SMMUv3 is a memory-mapped platform device
// (QEMU `virt` MMIO base 0x0905_0000, already inside the GiB0 Device-nGnRnE
// identity gigabyte `mmu_init` covers), programmed directly. The kernel probes
// SMMU_IDR0.S2P==1 (stage-2 supported), builds a 1-entry LINEAR stream table +
// ONE stage-2-only STE (Config==0b110) whose S2TTB == the SAME stage-2 L1 root
// `build_identity_stage2()` produced, S2VMID == the CPU's VMID, and STE.VTCR ==
// the projection of the CPU's `compute_vtcr()` (via the Kani-proven
// `tb_encode::smmuv3::ste_vtcr_from_vtcr_el2` LEMMA), programs STRTAB_BASE/_CFG +
// CMDQ_BASE + EVENTQ_BASE + CR0 (SMMUEN|CMDQEN|EVTQEN), pushes CMD_CFGI_STE +
// CMD_TLBI_S12_VMALL + CMD_SYNC, and observes the SYNC drain (CMDQ_CONS catches
// CMDQ_PROD) with GERROR clean (no CMDQ_ERR, no C_BAD_STE in the event queue) —
// i.e. the SMMU ACCEPTED the STE. This EXECUTES for real under TCG (QEMU walks +
// accepts the STE) on a QEMU that advertises IDR0.S2P — the IOMMU twin of
// "stage2 OK", NOT a skip. NOTE: stage-2 SMMUv3 support (the Mostafa series)
// landed in QEMU 9.0 (2024), NOT 8.1 — QEMU 8.2.2 (the current CI image)
// advertises S1P=1 but S2P=0, so on it (and on local qemu-6.2) the IDR0.S2P gate
// takes the honest GREEN skip until the CI QEMU is bumped to >= 9.0, at which
// point the Proven path runs for real.
//
// THE HONEST CLAIM: the marker asserts ONLY "tables programmed + SMMU accepted
// them (CMD_CFGI_STE synced, no GERROR/C_BAD_STE)". The ACTUAL DMA-isolation
// GUARANTEE — that a rogue physical device is BLOCKED from memory outside its
// grant — needs REAL SILICON (declared in assumptions.md, the L2.8/VT-d twin):
// QEMU emulation cannot prove isolation against silicon errata, ATS/PRI corners,
// peer-to-peer DMA bypass, or a non-ACS-clean topology. So this proves the
// PROGRAMMING is well-formed and ACCEPTED, never that silicon enforces it.
//
// ALL the SMMU MMIO/asm unsafe is confined to tb-hal's arch/aarch64/smmu.rs (the
// STE/command-queue value computation in tb-encode::smmuv3 is forbid(unsafe) +
// Kani-proven), so this crate stays unsafe-free and the kernel only branches on a
// closed enum. On x86_64 the VT-d/L2.8 path is x86's IOMMU rung, so this reports
// NotApplicable — mirroring the `VgicProof` block above. The SMMU is left
// DISABLED (CR0.SMMUEN=0, STE.V cleared) before M19 (teardown-clean), so M19's
// virtio-mmio path (NOT behind the SMMU) is untouched.
// ===========================================================================

/// aL2.6 SMMUv3 stage-2 DMA-isolation table-programming self-test outcome
/// (returned to the kernel for marker rendering). A SIBLING of [`VgicProof`]:
/// the proof is the SMMU ACCEPTING a well-formed stage-2-only STE that points at
/// the SAME stage-2 root the CPU uses, rather than a CPU-side world-switch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmmuProof {
    /// This arch has no Arm SMMUv3 (x86_64): the (deferred) Intel VT-d / L2.8
    /// path would be its IOMMU rung.
    NotApplicable,
    /// No stage-2 SMMUv3: SMMU_IDR0 reads open-bus `0xFFFF_FFFF` (booted WITHOUT
    /// `iommu=smmuv3` — the plain-`virt`/`tb-vmm` lanes) OR the SMMU does NOT
    /// advertise stage-2 (`IDR0.S2P == 0` — an S1-only SMMU). The latter is the
    /// case for QEMU older than 9.0: stage-2 SMMUv3 support (the Mostafa series)
    /// landed in QEMU 9.0 (2024), so QEMU 8.2.2 advertises `S1P=1` but `S2P=0`. A
    /// GRACEFUL GREEN skip — NO privileged stage-2 STE write is attempted (an
    /// S1-only SMMU would reject it), so non-stage-2-SMMU boot lanes stay green
    /// (the IDR0.S2P gate, the IOMMU analog of the `BOOTED_AT_EL2` gate).
    Unavailable,
    /// We probed S2P==1 and ran the table-programming round-trip, but it faulted
    /// instead of a clean acceptance (a frame OOM, CR0ACK never reflected enable,
    /// the CMD_SYNC never drained before the bounded cap, a GERROR fired, or a
    /// C_BAD_STE event was recorded); `code` is the nonzero diagnostic (surfaced
    /// honestly as a red marker WITHOUT a "smmu OK" substring).
    Faulted {
        /// The nonzero failure code the SMMU self-test returned.
        code: u64,
    },
    /// THE PROOF: the kernel built + wrote a stage-2-only STE whose geometry IS
    /// the CPU stage-2 geometry, programmed the SMMU registers, pushed
    /// CMD_CFGI_STE + CMD_SYNC, observed the SYNC drain with GERROR clean and no
    /// C_BAD_STE event — i.e. the SMMU ACCEPTED the STE. `stream_id` is the
    /// programmed StreamID (0 for the single-entry linear stream table).
    Proven {
        /// The StreamID the accepted stage-2-only STE was programmed for.
        stream_id: u32,
    },
}

/// aL2.6: run the SMMUv3 stage-2 DMA-isolation table-programming self-test
/// (aarch64), or report [`SmmuProof::NotApplicable`] on x86_64. See [`SmmuProof`].
#[cfg(target_arch = "aarch64")]
pub fn smmu_selftest() -> SmmuProof {
    arch::smmu_selftest()
}

/// aL2.6: x86_64 has no Arm SMMUv3 — the (deferred) Intel VT-d / L2.8 path would
/// be this arch's realization of the IOMMU rung, so this reports
/// [`SmmuProof::NotApplicable`] (the kernel prints the n/a marker).
#[cfg(target_arch = "x86_64")]
pub fn smmu_selftest() -> SmmuProof {
    SmmuProof::NotApplicable
}

// ===========================================================================
// M27 (M27b): the CNTHP TIMER-PREEMPTED two-VMID sovereign time-partition
// scheduler self-test facade — the sovereignty pillar's "Yuva owns time for two
// guests" rung, built ON TOP of L2.1's stage-2 + L2.3's trap-and-emulate seam +
// M22's fold. M27b upgraded the M27a cooperative green floor to REAL preemption:
// two trivial EL1 guest stubs run under TWO distinct VMIDs (two stage-2 roots);
// each is a PURE store-spin bumping a DISTINCT per-VMID MMIO cell — NO voluntary
// yield (the retired `hvc #14` now traps loud), so the ONLY control transfer is
// the CNTHP physical-timer PPI taken at EL2's 0x480 Lower-EL IRQ vector (the
// first async IRQ at EL2; HCR_EL2.IMO=1 only inside the armed window). On each
// preemption the monitor consults the Kani-proven `tb_encode::tpsched::next_slot`,
// re-arms CNTHP BEFORE EOI (IAR==26 verified, ISTATUS read back, a hard EOI cap
// turns a storm into a fast red), switches `VTTBR_EL2` to the next VMID's root,
// folds a `tb_encode::tpsched::SchedDecision` into a running `sched_head` (the M22
// `prov` fold reused VERBATIM), and resumes the next guest. After K bounded major
// frames the monitor tears the window down (teardown-FIRST) and verifies the five
// DoD properties. The marker emits `timing=TCG-NON-CYCLE-ACCURATE` (TCG timing is
// not cycle-accurate) + `realtime=NOT-CLAIMED`; the run-script guard REJECTS the
// retired `timing=COOPERATIVE-HVC-YIELD` token so M27a cannot impersonate M27b.
//
// ALL the asm/unsafe is confined to tb-hal's arch/aarch64/{el2,tpsched_hal,stage2,
// el2mmio}.rs (the tpsched leaf + the prov fold in tb-encode are forbid(unsafe) +
// Kani-proven); this crate stays unsafe-free and the kernel only branches on a
// closed enum. On x86_64 there is no EL2 — the (deferred) VMX-preemption-timer
// path would be this arch's rung, so this reports NotApplicable (mirroring the
// `VgicProof` block above).
// ===========================================================================

/// M27a COOPERATIVE two-VMID time-partition scheduler self-test outcome (returned
/// to the kernel for marker rendering). A SIBLING of [`VgicProof`]: the proof is a
/// closed round-trip in which TWO guest VMIDs are time-partitioned under TWO
/// stage-2 roots, each yielding voluntarily (`hvc #14`), with every scheduling
/// DECISION folded into a running provenance head — rather than a single-guest
/// world-switch or a real-timer preemption (M27b, deferred).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedProof {
    /// This arch has no EL2 (x86_64): the (deferred) VMX-preemption-timer path
    /// would be its realization of the sovereign-scheduler rung.
    NotApplicable,
    /// We did NOT boot at EL2 (plain QEMU `virt`): no resident monitor, so the
    /// scheduler window is never armed — a graceful green skip (mirrors
    /// [`VgicProof::Unavailable`]; no privileged instruction executed).
    Unavailable,
    /// We booted at EL2 and ran the round-trip, but the monitor reported a fault
    /// instead of a clean schedule proof (a stage-2 build OOM, a starved VMID, an
    /// out-of-order schedule, a fold mismatch, a tamper that was NOT caught, a
    /// non-conserved frame, or too few major frames); `code` is the nonzero
    /// diagnostic (surfaced honestly as a red marker WITHOUT a "sched OK"
    /// substring).
    Faulted {
        /// The nonzero failure code the EL2 monitor returned in x0.
        code: u64,
    },
    /// THE PROOF: the timer-preempted two-VMID round-trip closed — both VMIDs advanced
    /// their DISTINCT MMIO cell (both-progressed, neither starved), the observed
    /// VMID run-order was the tpsched round-robin (order-honored), the recomputed
    /// `sched_head` matched the committed fold (fold-verified) AND a single-byte
    /// tamper flipped it (tamper-caught), and the major frame was conserved
    /// (`frame_total == Σ slot budgets`). `head` is the `head_witness` of the
    /// committed fold; `frames` is the bounded major-frame count K.
    Proven {
        /// The `tb_encode::tpsched::sched_head_witness` of the committed fold head.
        head: u64,
        /// The bounded number of major frames the scheduler ran (K).
        frames: u64,
    },
}

/// M27 (M27b): run the CNTHP timer-preempted two-VMID time-partition scheduler
/// self-test (aarch64), or report [`SchedProof::NotApplicable`] on x86_64. See
/// [`SchedProof`].
#[cfg(target_arch = "aarch64")]
pub fn sched_selftest() -> SchedProof {
    arch::sched_selftest()
}

/// M27a: x86_64 has no EL2 — the (deferred) VMX-preemption-timer path would be
/// this arch's realization of the sovereign-scheduler rung, so this reports
/// [`SchedProof::NotApplicable`] (the kernel prints the n/a marker).
#[cfg(target_arch = "x86_64")]
pub fn sched_selftest() -> SchedProof {
    SchedProof::NotApplicable
}

// ===========================================================================
// aL2.4b: the FULL-KERNEL EL1 guest self-test facade — the literal M0..M31
// kernel image booted as a stage-2-CONFINED EL1 guest under the resident EL2
// monitor (the M34 champion/challenger prerequisite).
//
// Unlike aL2.4's ~80-instruction in-image stub, the guest here is a SECOND
// copy of this very kernel (staged by the run-script `-device loader` at the
// reserved top-32 MiB carve), handed the frozen `tb_boot::aarch64`
// `build_handoff` block (X0=TbBootInfo*, PC=_tb_start, SPSR=0x3C5) with the
// IN-GUEST flag, running its OWN stage-1 MMU under the FIRST NON-IDENTITY
// stage-2 in the codebase (guest IPA 0x4000_0000+off -> carve PA — link
// address == IPA, no relocation; NOTHING outside the carve + the GIC
// pass-through block is mapped). Its PL011 is trapped-and-emulated: every
// guest serial byte is re-emitted as an injection-proof `guestlog:` hex frame
// (the Kani-proven `tb_encode::guestlog` leaf). Completion is judged from
// MONITOR-WITNESSED, non-text evidence ONLY: the doorbell MMIO store-count at
// a watched unmapped IPA carrying the per-boot nonce, the `HVC #17` done
// hypercall, and the final WFI trapped under HCR_EL2.TWI. Guest text is
// corroborating evidence (it is OUR trusted image, pre-M34) checked by the
// run-script's GUEST-stream profile, never by this facade.
//
// ALL the asm/unsafe is confined to tb-hal's arch/aarch64/{el2/l24b_guest,
// stage2, inguest}.rs; this crate stays unsafe-free and the kernel only
// branches on the closed enum. On x86_64 the realization is hardware-gated
// (#37, parked) — the kernel prints the loud aarch64-only skip token.
// ===========================================================================

/// aL2.4b full-kernel EL1 guest self-test outcome (returned to the kernel for
/// marker rendering). A SIBLING of [`SchedProof`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelGuestProof {
    /// x86_64: the Track-A `L2.4: tabos-guest` realization is hardware-gated
    /// (#37); the kernel prints the loud aarch64-only skip token.
    NotApplicable,
    /// We did NOT boot at EL2 (plain QEMU `virt`, or we ARE the confined
    /// guest ourselves — one level of nesting is the claim): no resident
    /// monitor, so no launch is attempted — a graceful green skip in the
    /// required `(no EL2, skipped)` form.
    Unavailable,
    /// No guest image is staged at the carve (`-device loader` absent — the
    /// demo/bench lanes): a graceful green skip in the `(no guest image,
    /// skipped)` form. The boot lane attaches the loader and REJECTS this
    /// variant by name (the M20 no-disk anti-hollow idiom).
    NoImage,
    /// The launch ran but the monitor (or the facade's post-flight checks)
    /// reported a fault: a stage-2 build OOM, a guest-reported chain failure,
    /// an early park (the guest died before `HVC #17`), a trap storm, an
    /// unexpected stage-2 fault outside every emulated window, an ISV=0 abort
    /// on an emulated IPA, a doorbell/nonce mismatch, a missed confinement
    /// probe, or a wrong in-guest discriminator readback. `code` is the
    /// nonzero diagnostic; `info` carries the fault detail (e.g. the last
    /// trapped IPA for the storm/unexpected classes).
    Faulted {
        /// The nonzero failure code (monitor x0, or a facade post-flight code).
        code: u64,
        /// Fault detail (monitor x1: last-trap IPA/ESR, status, ...).
        info: u64,
    },
    /// THE PROOF (monitor-witnessed, non-text): the full-kernel guest booted
    /// confined, echoed the per-boot nonce through the doorbell MMIO window
    /// (count above threshold), signalled done (`HVC #17` status 0 — reachable
    /// only from the guest's single armed clean-exit site, so the chain
    /// completed), parked in its final WFI (trapped under TWI), performed
    /// EXACTLY ONE confinement-probe store to a host-RAM IPA that FAULTED and
    /// did NOT land, and read back the in-guest discriminator
    /// (`BOOT_ENTRY_EL == 0xFF`, `BOOTED_AT_EL2 == 0`) from guest memory.
    Proven {
        /// The monitor-chosen per-boot nonce the guest echoed.
        nonce: u64,
        /// Doorbell MMIO store-count witnessed at the watched unmapped IPA.
        doorbell: u64,
        /// Confinement-probe fault count (exactly 1: faulted, never landed).
        probe: u64,
        /// Total guest traps the monitor serviced (diagnostic; storm-capped).
        traps: u64,
    },
}

/// aL2.4b: launch the full-kernel EL1 guest under the monitor's stage-2 and
/// judge it from monitor-witnessed evidence (aarch64). See [`KernelGuestProof`].
#[cfg(target_arch = "aarch64")]
pub fn el2_kernel_guest_selftest() -> KernelGuestProof {
    arch::el2_kernel_guest_selftest()
}

/// aL2.4b: x86_64's realization (Track A `L2.4: tabos-guest`) is hardware-gated
/// on #37, so this reports [`KernelGuestProof::NotApplicable`] (the kernel
/// prints the loud aarch64-only skip token — never a silent pass).
#[cfg(target_arch = "x86_64")]
pub fn el2_kernel_guest_selftest() -> KernelGuestProof {
    KernelGuestProof::NotApplicable
}

// ===========================================================================
// M19: poll-based virtio-mmio virtio-rng self-test facade — the kernel's FIRST
// real device I/O.
//
// A single, NON-cfg-gated facade ([`virtio_selftest`]) over an `arch` arm that
// exists on BOTH architectures (mirroring `mmu_selftest`/`timer_demo`, NOT the
// cfg-split `vmx_selftest`/`el2_selftest` pair — virtio-mmio is identical on
// x86_64 `microvm` and aarch64 `virt`). Each arm drives a MODERN (Version=2)
// virtio-rng (DeviceID 4) over ONE virtqueue: a hard-coded slot scan, the
// reset->ACK->DRIVER->features->FEATURES_OK->queue->DRIVER_OK handshake, one
// WRITE-ONLY descriptor pointing at an entropy buffer in a single identity-
// mapped DMA frame, a poll-only (`VIRTQ_AVAIL_F_NO_INTERRUPT`) used-ring
// completion, and a fail-closed iteration cap so a dead device bails to
// [`VirtioProof::Failed`] instead of hanging. ALL the MMIO/DMA/asm unsafe is
// confined to `arch/{x86_64,aarch64}/virtio.rs` (the UC device-window map +
// `dmb`/`dsb` barriers live there too); this crate stays unsafe-free and the
// `#![forbid(unsafe_code)]` kernel only branches on the returned `VirtioProof`.
// Absent (no DeviceID==4 in any slot) is a GRACEFUL GREEN skip — so a runner
// with no virtio-rng backend (e.g. `tb-vmm` with no `-device`, where the scan
// reads open-bus `0xFFFF_FFFF` != magic) stays green with no backend added.
// ===========================================================================

/// M19 virtio-rng self-test outcome (returned to the kernel for marker
/// rendering). A closed, pure-data verdict the `#![forbid(unsafe_code)]` kernel
/// matches on — mirroring [`VmxProof`]/[`El2Proof`] but arch-neutral.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioProof {
    /// No virtio-rng (DeviceID 4) in any scanned slot — a GRACEFUL GREEN skip.
    /// The `tb-vmm`-with-no-`-device` case (open-bus read != magic) and any
    /// QEMU run that omits `-device virtio-rng-device`.
    Absent,
    /// A virtio-rng was found but it is LEGACY (`Version` != 2) — an honest skip
    /// (this driver speaks only the modern transport); still GREEN.
    LegacyUnsupported,
    /// THE PROOF: the full modern handshake + one write-only descriptor + a
    /// polled used-ring completion ran, and the entropy buffer came back
    /// non-trivially filled. `slot` is the bus slot index, `device_id` == 4,
    /// `len` is the device-reported `used.ring[0].len` (bytes written).
    Proven {
        /// The virtio-mmio slot index the entropy device was found at.
        slot: u32,
        /// The probed DeviceID (4 == entropy/rng; the expected value).
        device_id: u32,
        /// The device-reported number of entropy bytes written (`> 0`).
        len: u32,
    },
    /// Found + driven, but the round-trip failed fail-closed (handshake
    /// rejected, FEATURES_OK cleared, queue unready, or `used.idx` never
    /// advanced before the cap). `stage` localises the failure; the kernel
    /// renders it WITHOUT a "virtio OK" substring, so the run-script grep is red.
    Failed {
        /// The pipeline stage that failed (1 map .. 6 completion-validate).
        stage: u32,
    },
}

/// M19: run the poll-based virtio-rng round-trip self-test (both arches) and
/// report the outcome. See [`VirtioProof`]. Brings up no interrupt controller
/// (poll-only) and touches NO scheduler; all raw work is in `arch::*::virtio`.
pub fn virtio_selftest() -> VirtioProof {
    arch::virtio_selftest()
}

// ===========================================================================
// M20: durable persistence self-test facade -- the first time ANYTHING in Yuva
// outlives a boot. Mirrors the `VirtioProof` pattern verbatim: a pure-data
// verdict the `#![forbid(unsafe_code)]` kernel matches on. ALL silicon-unsafe
// (the virtio-blk MMIO/DMA ring) is in `arch::*::virtio`; the on-disk codecs are
// the Kani-proven `tb_encode::blkfmt`; the orchestration (mount/replay/two-phase
// commit) is 100% safe in `mem::VirtioBlkStore`. Absent (no DeviceID==2 in any
// slot -- e.g. a lane with no `-drive`) is a GRACEFUL GREEN skip.
// ===========================================================================

/// M20 durable-persistence self-test outcome (returned to the kernel for marker
/// rendering). A closed, pure-data verdict -- mirroring [`VirtioProof`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistProof {
    /// No virtio-blk (DeviceID 2) in any scanned slot -- a GRACEFUL GREEN skip
    /// (a lane with no `-drive`; the open-bus read != magic case). The kernel
    /// renders `M20: persist OK (no disk, skipped)`.
    Absent,
    /// A virtio-blk was found but it is LEGACY (`Version` != 2) -- an honest skip
    /// (this driver speaks only the modern transport); still GREEN.
    LegacyUnsupported,
    /// THE PROOF: N sentinel records were written through a real Region behind
    /// the [`VirtioBlkStore`], the two-phase flush committed (data sectors ->
    /// FLUSH -> superblock at gen+1 -> FLUSH), the store was RE-MOUNTED (super-
    /// block re-read + Region logs replayed into a freshly-rebuilt journal), and
    /// the replayed records == the read-after-flush values AND `gen` bumped by 1.
    Proven {
        /// The committed checkpoint generation after the round-trip's flush.
        gen: u64,
        /// The number of sentinel records replayed back on the re-mount.
        replayed: u64,
        /// The prior generation observed on the FIRST mount (`0` on a fresh disk,
        /// `> 0` if a previous boot left a committed checkpoint -- the two-boot
        /// durability witness).
        prior: u64,
    },
    /// Found + driven, but the durability round-trip failed fail-closed. `stage`
    /// localises the failure (0x1 probe/feature, 0x2 DMA-frame OOM, 0x3 mount/
    /// superblock-decode, 0x4 write/flush, 0x5 re-mount/replay, 0x6 equality-or-
    /// generation mismatch). The kernel renders it WITHOUT a "persist OK"
    /// substring, so the run-script grep is red.
    Failed {
        /// The pipeline stage that failed (see the variant doc).
        stage: u32,
    },
}

/// M20: run the durable-persistence round-trip self-test (both arches) and
/// report the outcome. See [`PersistProof`]. Poll-only (no completion IRQ),
/// touches NO scheduler; all raw device work is in `arch::*::virtio`, the on-disk
/// codecs are the Kani-proven `tb_encode::blkfmt`, the orchestration is safe
/// `mem::VirtioBlkStore`. Absent (no `-drive`) is a GRACEFUL GREEN skip.
pub fn persist_selftest() -> PersistProof {
    mem::persist_selftest()
}

// ===========================================================================
// M21: verified fixed-point ADDITIVE-policy leaf self-test facade. The
// fail-closed loader + real round-trip the kernel runs at boot over the FROZEN
// `tb_encode::kancell` integer artifact, returned as a pure-data verdict the
// `#![forbid(unsafe_code)]` kernel matches on (mirroring [`PersistProof`]). SHIPS
// DORMANT: `active == false` this milestone -- the heuristic floor in
// `mem::forget_sweep` owns every demote decision; the spline is WIRED + validated
// at load but never on the decision path (turning it on is gated on an offline
// trace bake-off, proposal §7). The math is the Kani-proven `tb-encode::kancell`;
// the validators/round-trip are pure value computation -- no device, no `unsafe`.
// ===========================================================================

/// M21 policy-leaf load-time self-test outcome (returned to the kernel for marker
/// rendering). A closed, pure-data verdict -- mirroring [`PersistProof`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KanProof {
    /// The shipped table passed the solver-free MonoKAN sign check
    /// (`kan_table_is_monotone`): every sign-constrained feature is monotone by
    /// construction (staler never scored more keepable). The kernel requires this.
    pub monotone: bool,
    /// The shipped table passed the headroom check (`kan_table_overflow_safe`):
    /// every knot is within `KAN_KNOT_MAX`, so `kan_score` cannot overflow. The
    /// kernel requires this.
    pub ovf_safe: bool,
    /// The recomputed round-trip deviation `delta = max|expected - kan_score(probe)|`
    /// over the baked probe vector. The kernel requires `q_err <= bound`.
    pub q_err: i64,
    /// The shipped checked error bound `B`. `q_err > bound` fails closed (the kan
    /// path is aborted, the marker withheld -- so an over-error table can never
    /// reach the comparator).
    pub bound: i64,
    /// Whether the spline is on the decision path. `false` this milestone (DORMANT,
    /// gate-not-met): the heuristic floor decides. The run-scripts require
    /// `active=0` for this lane (and would reject a future `(no table, skipped)`).
    pub active: bool,
}

/// M21: run the verified-policy-leaf load-time self-test (both arches) over the
/// frozen integer table and report the outcome. See [`KanProof`]. Pure value
/// computation -- re-runs the `tb_encode::kancell` MonoKAN + headroom validators
/// and the `kan_score` round-trip over the baked probe vector; touches NO device
/// and NO scheduler. SHIPS DORMANT (`active == false`).
pub fn kan_selftest() -> KanProof {
    mem::kan_selftest()
}

// ===========================================================================
// M22: verified memory-PROVENANCE-LEDGER self-test facade. A per-agent, append-
// only, content-addressed HASH-CHAIN ledger over the M13 substrate: every memory
// mutation (write / forget-tombstone / skill-admit) appends a typed entry whose
// 256-bit BLAKE2s-256 digest (khash/uhash since M29 stage C) folds into a running
// `chain_head`. The boot self-test
// writes N>=3 real records, demotes one through the REAL M17 forget_sweep (a
// provable tombstone), builds a genuine inclusion proof, then flips ONE byte of a
// COMMITTED entry's canonical bytes and proves the head + inclusion proof BOTH
// catch it. The math is the Kani-proven `tb_encode::prov`; the verdict is a pure-
// data struct the `#![forbid(unsafe_code)]` kernel matches on (mirroring
// [`KanProof`]). Tamper-evidence is CRYPTOGRAPHIC since M29-C (khash/BLAKE2s-256,
// `sec=ASSUMED-FROM-LITERATURE`): a SIGNED root (authenticity) remains the tracked
// successor. The head is kept IN-RAM
// this milestone (it does NOT ride the M20 superblock), so the M20 two-phase
// commit + persist_selftest gen-continuity stay byte-identical (zero M20/M21
// regression).
// ===========================================================================

/// M22 provenance-ledger self-test outcome (returned to the kernel for marker
/// rendering). A closed, pure-data verdict -- mirroring [`KanProof`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvProof {
    /// The CLEAN ledger verified: the independently re-folded committed entry ids
    /// equal the running `chain_head` AND the tamper-leg's committed entry was
    /// faithfully reconstructed (`prov_hash(canon) == committed id`). The kernel
    /// requires this (a false here withholds the marker).
    pub clean_ok: bool,
    /// A single-byte tamper of a COMMITTED entry's canonical bytes was caught on
    /// BOTH legs: the recomputed head MISMATCHED the committed head AND the
    /// tampered entry's inclusion proof FAILED. The kernel requires this -- it is
    /// the load-bearing tamper-evidence claim.
    pub tamper_caught: bool,
    /// A genuine inclusion proof for a known committed entry verified `== true`
    /// against the clean head. The kernel requires this.
    pub inclusion_ok: bool,
    /// A u64 WITNESS folded from the 32-byte committed head (every head byte
    /// contributes), rendered as `head=<hex16>` in the boot witness line.
    pub head: u64,
    /// The number of committed ledger entries after the round-trip (the N writes
    /// plus any tombstone), rendered as `entries=<n>`.
    pub entries: u64,
}

/// M22: run the provenance-ledger round-trip self-test (both arches) and report
/// the outcome. See [`ProvProof`]. Pure value computation over the Kani-proven
/// `tb_encode::prov` leaf and the real `mem::MemSubstrate` mutation path -- writes
/// N>=3 real records, demotes one via the real M17 forget_sweep (a tombstone),
/// builds a genuine inclusion proof, and injects a single-byte tamper into a
/// committed entry's canonical bytes; touches NO device and NO scheduler.
pub fn prov_selftest() -> ProvProof {
    mem::prov_selftest()
}

// ===========================================================================
// M23: verified EXPERIENCE-CODEC self-test facade. A SEPARATE per-agent, fixed-
// capacity, tamper-evident EXPERIENCE LOG over the M17 forget/recall decisions:
// at each decision the OS records an injective ExperienceRecord (the features it
// ALREADY computes + the heuristic action + the COUNTERFACTUAL kan_score the
// DORMANT cell would produce + RESERVED-but-unset propensity/outcome fields) into a
// fixed-capacity drop-oldest ring folded into a SEPARATE per-agent `xp_head`
// (REUSING the M22 fold -- the M22 `chain_head` is UNTOUCHED, so M22's persist/prov
// witnesses stay byte-identical). The learned cell stays DORMANT (`KAN_ACTIVE ==
// false`): the shadow is logged ONLY, never changing a demote, so the live
// forget/demote decision is BYTE-IDENTICAL to M22's. The boot self-test seeds a
// memory-pressure scenario that forces >=3 forget-decisions + >=1 recall-touch,
// then proves replay-determinism (a recorded feats row replays through kan_score to
// the logged shadow BIT-IDENTICALLY) + tamper-evidence (cryptographic since
// M29-C) + heuristic
// faithfulness. M23 claims ONLY replay-determinism + tamper-evidence --
// NOT policy validity (deterministic logging -> degenerate propensity; validity is
// M24's burden, the exogenous human-operator oracle is M25's). The math is the
// Kani-proven `tb_encode::exp`; the verdict is a pure-data struct the
// `#![forbid(unsafe_code)]` kernel matches on (mirroring [`ProvProof`]).
// ===========================================================================

/// M23 experience-codec self-test outcome (returned to the kernel for marker
/// rendering). A closed, pure-data verdict -- mirroring [`ProvProof`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpProof {
    /// The CLEAN experience log verified: the independently re-folded committed
    /// record ids equal the running `xp_head`. The kernel requires this.
    pub clean_ok: bool,
    /// A genuine inclusion proof for a known committed record verified `== true`
    /// against the clean `xp_head`. The kernel requires this.
    pub inclusion_ok: bool,
    /// REPLAY-DETERMINISM (the headline): a recorded `feats` row replayed through the
    /// dormant `kan_score` reproduced the logged `kan_score_shadow` BIT-IDENTICALLY.
    /// The kernel requires this (rendered `replay-bitexact=0x1`).
    pub replay_bitexact: bool,
    /// HEURISTIC FAITHFULNESS: a recorded `FORGET_DECISION`'s `action_taken` /
    /// `envelope_verdict` re-derive from the live record's heuristic envelope. The
    /// kernel requires this (the log faithfully recorded the action actually served).
    pub heuristic_faithful: bool,
    /// A single-byte tamper of a COMMITTED record's canonical bytes was caught on
    /// BOTH legs (head-mismatch AND inclusion-fail). The kernel requires this -- the
    /// load-bearing tamper-evidence claim (cryptographic since M29-C; rendered
    /// `tamper-caught=0x1`).
    pub tamper_caught: bool,
    /// Whether the learned cell is on the decision path. `false` this milestone (the
    /// shadow is logged only, never changing a demote -- the live decision is
    /// byte-identical to M22's). The run-scripts REQUIRE `kan_active=0` for this lane.
    pub kan_active: bool,
    /// A u64 WITNESS folded from the 32-byte committed `xp_head` (every head byte
    /// contributes), rendered as `head=<hex16>` in the boot witness line.
    pub head: u64,
    /// The number of committed experience records (the >=3 forget-decisions plus any
    /// recall-touch), rendered as `records=<n>`.
    pub records: u64,
}

/// M23: run the experience-codec round-trip self-test (both arches) and report the
/// outcome. See [`ExpProof`]. Pure value computation over the Kani-proven
/// `tb_encode::exp` leaf and the real `mem::MemSubstrate` forget/recall path --
/// seeds a memory-pressure scenario that forces >=3 forget-decisions + >=1
/// recall-touch into a SEPARATE per-agent `xp_head` (the M22 head untouched),
/// replays a recorded feats row through the dormant `kan_score` to prove bit-exact
/// determinism, and injects a single-byte tamper into a committed record's canonical
/// bytes; touches NO device and NO scheduler. `KAN_ACTIVE` stays `false` (the shadow
/// changes zero demotes).
pub fn exp_selftest() -> ExpProof {
    mem::exp_selftest()
}

// ===========================================================================
// M39: the verified EXPERIENCE-CORPUS self-test facade (the in-kernel seam). A
// SEPARATE per-agent, GROWING, tamper-evident EXPERIENCE CORPUS over the M17
// CONSOLIDATION outcomes: at each `distill()` survivor + `reflect_inner()` insight
// the OS CURATES the outcome via a DECLARED (not learned) predicate and folds an
// injective `corpus::CorpusRecord` -- a PROVENANCE SKELETON in interned tokens, not
// text -- into a SEPARATE per-agent `corpus_head` (REUSING the M22 fold verbatim, so
// the M22 `chain_head` / M23 `xp_head` witnesses stay byte-identical). The math is
// the Kani-proven `tb_encode::corpus`; the verdict is a pure-data struct the
// `#![forbid(unsafe_code)]` kernel matches on (mirroring [`ExpProof`]). HONEST: the
// corpus is a Phase-1 data-engineering PREREQUISITE -- it does NOT touch `KAN_ACTIVE`,
// does NOT flip the Learning pillar out of dormancy, and TRAINS NOTHING (Phase-2
// gated). `token=corpus=PROVENANCE-SKELETON`, `token=curation=PREDICATE-DECLARED-NOT-
// LEARNED`, `token=training=NONE-PHASE2-GATED`.
// ===========================================================================

/// M39 experience-corpus self-test outcome (returned to the kernel for marker
/// rendering). A closed, pure-data verdict -- mirroring [`ExpProof`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorpusProof {
    /// The CLEAN corpus verified: the independently re-folded committed record ids
    /// equal the running `corpus_head` AND the FIRST committed record's canonical
    /// bytes were FAITHFULLY reconstructed (`corpus_hash(canon) == committed id`, so
    /// the tamper leg hits a REAL committed record). The kernel requires this.
    pub clean_ok: bool,
    /// A genuine inclusion proof for a known committed record verified `== true`
    /// against the clean `corpus_head`. The kernel requires this.
    pub inclusion_ok: bool,
    /// A single-byte tamper of a COMMITTED record's canonical bytes was caught on
    /// BOTH legs (head-mismatch AND inclusion-fail). The kernel requires this -- the
    /// load-bearing tamper-evidence claim (inherited from the proven `prov` fold;
    /// rendered `tamper-caught=0x1`).
    pub tamper_caught: bool,
    /// The DECLARED curation predicate is genuinely TWO-SIDED on real consolidation
    /// outcomes this boot (`>=1 ACCEPT` AND `>=1 REJECT`) -- proof it is not a constant
    /// (rendered `predicate-two-sided=0x1`). The kernel requires this.
    pub predicate_two_sided: bool,
    /// The number of curated records that genuinely FLOWED into the corpus (the
    /// anti-hollow evidence -- rendered `records=<n>`, MUST be `> 0`). The kernel
    /// requires this.
    pub records: u64,
    /// The DECLARED-predicate ACCEPT count this boot (rendered `accepted=<n>`).
    pub accepted: u64,
    /// The DECLARED-predicate REJECT count this boot -- RECORDED, not dropped
    /// (rendered `rejected=<n>`).
    pub rejected: u64,
    /// A u64 WITNESS folded from the 32-byte committed `corpus_head` (every head byte
    /// contributes), rendered as `head=<hex16>` in the boot witness line.
    pub head: u64,
    /// Whether the learned cell is on the decision path. `false` this milestone (the
    /// corpus does NOT touch `KAN_ACTIVE` and trains nothing). The run-scripts REQUIRE
    /// `kan_active=0` for this lane.
    pub kan_active: bool,
}

/// M39: run the experience-corpus round-trip self-test (both arches) and report the
/// outcome. See [`CorpusProof`]. Pure value computation over the Kani-proven
/// `tb_encode::corpus` leaf and the REAL `mem::MemSubstrate` M17 CONSOLIDATION path
/// -- seeds two near-duplicate clusters and runs the ACTUAL `consolidation_cycle`, so
/// `distill()`/`reflect_inner()` CURATE genuine outcomes into a SEPARATE per-agent
/// `corpus_head` (the M22/M23 heads untouched), then re-folds + tamper-checks the
/// committed records; touches NO device and NO scheduler. `KAN_ACTIVE` stays `false`
/// (the corpus trains nothing).
pub fn corpus_selftest() -> CorpusProof {
    mem::corpus_selftest()
}

/// M39 (increment-3) DURABLE-corpus persist outcome (returned to the kernel for the
/// `corpus:` witness). A closed, pure-data verdict -- mirroring the M33 persist result
/// for the corpus lane. Every field is EARNED by the real read-back / re-fold / write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorpusPersistProof {
    /// A modern virtio-blk device with room for both corpus slots was present. `false`
    /// is a GRACEFUL skip (no disk / too small) -- the marker still prints, but an
    /// ATTACHED lane (the run-scripts) REQUIRES `present` + `persisted`.
    pub present: bool,
    /// The accumulated corpus was written + FLUSHED to disk this boot (`gen+1` into the
    /// staler ping-pong slot). The run-scripts require this on the attached lane.
    pub persisted: bool,
    /// A prior boot's persisted corpus was read back, EVERY packed record fail-closed-
    /// decoded, AND the re-folded `corpus_head` string-equalled the stored head (the
    /// corpus SURVIVED a genuine reboot with integrity). `false` on a FRESH disk (the
    /// anti-hollow "no false survival on a fresh region" negative control -- boot 1).
    pub survived: bool,
    /// The read-back corpus re-folded to the SAME stored `corpus_head` (integrity). Set
    /// with (and equal to) `survived`; rendered `corpus-head-matches=0x1`.
    pub head_matches: bool,
    /// A u64 WITNESS of the corpus head (via `corpus_head_witness`): on SURVIVAL the head
    /// read FROM DISK (the cross-boot evidence), else the head just persisted this boot.
    /// Boot 1's persisted-head witness string-equals boot 2's read-back witness.
    pub head_disk: u64,
    /// The number of records READ BACK off disk from a prior boot (`0` on a fresh disk;
    /// `>= 1` once a prior corpus survived -- the anti-hollow read-back evidence).
    pub records_disk: u64,
    /// The number of records now persisted (the ACCUMULATED total: prior ++ this boot,
    /// ring-bounded). GROWS across boots -- the dataset-moat evidence (`records-total`).
    pub records_total: u64,
}

/// M39 (increment-3): run the DURABLE-corpus persist round-trip (both arches) and report
/// the outcome. See [`CorpusPersistProof`]. REUSES the M33 `provhead` torn-write-safe
/// codec VERBATIM over a SEPARATE disk region; touches NO scheduler and NEITHER the M22
/// nor the M23 head. HONEST: no LMS signature (the head's tamper-evidence is the M22
/// fold, reused verbatim); the FNV checksums are torn-write detection ONLY; it persists
/// PROVENANCE SKELETONS and trains nothing.
pub fn corpus_persist() -> CorpusPersistProof {
    mem::corpus_persist()
}

// ===========================================================================
// M24: the verified HONEST ACTIVATION GATE self-test facade. The honest
// resolution of the M21 activation gate (#72): shielded epsilon-greedy
// exploration (restores statistical overlap, populating the M23-reserved
// propensity field) + a deterministic 3-way right-censored survival label + a
// partial-identification (Manski + Lipschitz-smoothness) lower-bound estimator +
// an empirical-Bernstein HCPI lower-bound activation gate. `KAN_ACTIVE` flips
// `false -> true` ONLY if the conjunctive one-shot gate clears (`V_lower(kancell)
// - V_upper(heuristic) >= MARGIN` over a distribution-shifted held-out split AND
// the re-asserted envelope-no-widening proof). On the (necessarily SYNTHETIC)
// traces this milestone the gate WILL NOT clear -- `gate-not-met` (the cell stays
// DORMANT) is the DESIGNED, CORRECT outcome (the M21 idiom -- an honest gate that
// REFUSES is a success, not a failure). The math is the Kani-proven
// `tb_encode::explore` + `tb_encode::bakeoff`; the verdict is a pure-data enum the
// `#![forbid(unsafe_code)]` kernel matches on (mirroring [`ExpProof`]). The
// experience stays IN-RAM this milestone (durable spill deferred -- see the M24
// proposal §3 / the self-test note): the gate self-test runs on the in-RAM
// accumulated experience, so M20's two-phase commit + persist_selftest stay
// byte-identical.
// ===========================================================================

/// M24 honest-gate bake-off self-test outcome (returned to the kernel for marker
/// rendering). A closed, pure-data verdict -- mirroring [`ExpProof`]. The witness
/// fields (`vlo_kan`/`vhi_heur`/`margin`/...) are POSITIVELY required on the boot
/// witness line so the marker mechanically cannot claim an activation the lower
/// bound does not support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BakeoffProof {
    /// THE (counterfactual this milestone) ACTIVATION: the conjunctive one-shot gate
    /// CLEARED -- the cell's worst-case value `vlo_kan` beat the heuristic's best-case
    /// value `vhi_heur` by at least `margin` over a sufficiently-supported, overlap-
    /// restored held-out split, AND the envelope-no-widening proof re-asserted. NOT
    /// reached on synthetic traces (the cell would flip ACTIVE -- a real activation
    /// awaits M25's human oracle).
    Cleared {
        /// The integer lower bound on the kancell policy's value (`V_lower`).
        vlo_kan: i64,
        /// The integer upper bound on the heuristic floor's value (`V_upper`).
        vhi_heur: i64,
        /// The cleared margin (`vlo_kan - vhi_heur`).
        margin: i64,
    },
    /// THE DESIGNED, CORRECT OUTCOME this milestone: the machinery executed (label +
    /// estimator + gate + the in-RAM replay) and the gate was EVALUABLE but the margin
    /// was NOT met on the (synthetic) traces -- the cell stays DORMANT. The honest M21
    /// `(heuristic floor, gate-not-met)` idiom. Carries the witness so the boot line
    /// proves the gate actually RAN (anti-hollow-pass).
    NotMet {
        /// The integer lower bound on the kancell policy's value (`V_lower`).
        vlo_kan: i64,
        /// The integer upper bound on the heuristic floor's value (`V_upper`).
        vhi_heur: i64,
        /// The (negative or sub-margin) gap (`vlo_kan - vhi_heur`).
        margin: i64,
        /// The count of RESOLVED (non-censored) labeled pairs the gate evaluated over.
        resolved: u64,
        /// The count of CENSORED (open-window, excluded) labeled pairs.
        censored: u64,
        /// The summed soft-greedy exploration mass (overlap-restored, SCALE==1000).
        overlap_mass: u64,
        /// The Manski no-overlap mass fraction (decisions epsilon could not explore).
        no_overlap: u64,
    },
    /// Too few RESOLVED non-censored pairs / near-zero overlap mass: the gate is not
    /// EVALUABLE (the eligibility pre-gate failed -- distinct from a genuine refusal).
    NotEvaluable {
        /// The count of RESOLVED labeled pairs (below the eligibility floor).
        resolved: u64,
        /// The summed soft-greedy exploration mass (below the eligibility floor).
        overlap_mass: u64,
    },
    /// The self-test did NOT execute a required stage (seed/label/replay/gate). `stage`
    /// localises the failure. The kernel renders this WITHOUT a "bakeoff OK" substring
    /// (fail-closed: the marker is withheld), so the run-script grep is red.
    Failed {
        /// The pipeline stage that failed (0x1 seed, 0x2 replay/label, 0x3 envelope
        /// re-assertion, 0x4 estimator/gate, 0x5 dormant-invariant violated).
        stage: u32,
    },
}

/// M24: run the honest-gate bake-off self-test (both arches) over the in-RAM
/// accumulated experience and report the outcome. See [`BakeoffProof`]. Pure value
/// computation over the Kani-proven `tb_encode::explore` + `tb_encode::bakeoff`
/// leaves and the real `mem::MemSubstrate` forget/read-touch path -- seeds a
/// shielded-epsilon-greedy labeled stream (stamping the M23-reserved propensity
/// field), drives unfiltered `read_touch` to attach the deterministic 3-way survival
/// label, replays the in-RAM stream through the frozen-heuristic AND dormant
/// `kan_score` over an M18.2-style shifted split, computes `V_lower(kancell)` /
/// `V_upper(heuristic)`, evaluates the conjunctive one-shot gate, and re-asserts the
/// envelope-no-widening proof; touches NO device and NO scheduler. On synthetic
/// traces the gate does NOT clear -> [`BakeoffProof::NotMet`] (the cell stays DORMANT)
/// -- the designed, correct outcome. `KAN_ACTIVE` stays `false`.
pub fn bakeoff_selftest() -> BakeoffProof {
    mem::bakeoff_selftest()
}

// ===========================================================================
// M25: the verified OPERATOR-TRANSCRIPT self-test facade. The COMMUNICATION
// pillar's outbound half + the exogenous-oracle channel: a typed, tamper-
// evident transcript the OS EMITS over serial to SURFACE what it recorded
// (M23) and decided (M24) to a human, anchored to the live M22 provenance head
// ("which instance am I"). TX-only this milestone (the inbound RX + an enrolled
// operator credential by which a human could COMMAND the M24 gate is M26 -- it
// fails the no-human CI gate today). The math is the Kani-proven
// `tb_encode::opframe` (which REUSES the M22 `tb_encode::prov` fold verbatim);
// the verdict is a pure-data struct the `#![forbid(unsafe_code)]` kernel matches
// on (mirroring [`ExpProof`]). HONEST: the fold is keyless (tamper-EVIDENCE --
// a cryptographic hash since M29-C but unkeyed, not authenticity -- `keyed=0`)
// and the boot self-test's verifier is
// the OS's own plumbing, NOT a human (`oracle=HUMAN-DEFERRED-M26`).
// ===========================================================================

/// M25 operator-transcript self-test outcome (returned to the kernel for marker
/// rendering). A closed, pure-data verdict -- mirroring [`ExpProof`]. The witness
/// fields are POSITIVELY required on the boot witness line so the marker mechanically
/// cannot claim a transcript property it did not verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpframeProof {
    /// The CLEAN transcript verified: independently re-folding the committed frame ids
    /// equals the running `op_head`. The kernel requires this.
    pub clean_ok: bool,
    /// A genuine inclusion proof for the genesis frame verified `== true` against the
    /// clean `op_head`. The kernel requires this.
    pub inclusion_ok: bool,
    /// The `seq` is strictly `seqs[i] == i` (no gap / reorder / duplicate / non-zero
    /// start) -- the strict-monotone reader check. The kernel requires this (rendered
    /// `seq_monotone=1`).
    pub seq_monotone: bool,
    /// The genesis `INTRO` frame's `prev_head` binds the transcript to the LIVE M22
    /// provenance head ("which instance am I" attestation). The kernel requires this
    /// (rendered `intro_bound=1`).
    pub intro_bound: bool,
    /// The closing `GATE_VERDICT` commits the final `seq`, AND a reader expecting a
    /// longer transcript (a truncated tail) is REJECTED -- the Ma-Tsudik FssAgg tail-
    /// truncation guard. The kernel requires this (folded into `tamper-caught=1`).
    pub truncation_caught: bool,
    /// A single-byte tamper of a committed frame's canonical bytes was caught on BOTH
    /// legs (head-mismatch AND inclusion-fail) -- the load-bearing tamper-evidence
    /// claim (cryptographic since M29-C). The kernel requires this (rendered
    /// `tamper-caught=1`).
    pub tamper_caught: bool,
    /// A u64 WITNESS folded from the 32-byte committed `op_head` (every head byte
    /// contributes), rendered as `tx_head=<hex16>` in the boot witness line.
    pub head: u64,
    /// The number of emitted + committed transcript frames (5 since M31:
    /// intro / marker / experience-digest / the M31 inference-digest marker /
    /// gate-verdict), rendered as `frames=<n>`.
    pub frames: u64,
}

/// M25: emit a short operator transcript and play the simulated operator-verifier on
/// it (both arches), reporting the outcome. See [`OpframeProof`]. Pure value
/// computation over the Kani-proven `tb_encode::opframe` leaf (which REUSES the M22
/// `tb_encode::prov` fold) and the real `mem::MemSubstrate` M22-head + M23-experience
/// state -- seeds the M23 memory-pressure scenario for a LIVE M22 head + forget-
/// decisions, emits INTRO(binds the live head)/MARKER/EXPERIENCE_DIGEST(the most-
/// borderline M23 record)/the M31 INFERENCE-DIGEST MARKER(`infer_fold_payload` =
/// `req_id (u64 LE) || op_hash(response-bytes)` from the channel-free
/// MOCK-DETERMINISTIC e2e -- the DIGEST, never raw model bytes, folded BEFORE the
/// closing commit so the committed final seq covers it)/GATE_VERDICT(commits the
/// final seq + the honest M24 verdict),
/// and verifies the clean fold + a genuine inclusion proof + strict-monotone seq +
/// the INTRO binding + the tail-truncation commit + a single-byte tamper rejection;
/// touches NO device beyond the serial the kernel renders over, and NO scheduler. The
/// fold is keyless (tamper-EVIDENCE, not authenticity) and the verifier is the OS's
/// own plumbing, not a human (the marker's `keyed=0` / `oracle=HUMAN-DEFERRED-M26`
/// honesty tokens).
pub fn opframe_selftest(infer_fold_payload: &[u8]) -> OpframeProof {
    mem::opframe_selftest(infer_fold_payload)
}

// ===========================================================================
// M26: the verified EL2 EXIT-TELEMETRY producer self-test facade. The learning
// pillar's SECOND experience producer: the EL2 (nVHE) monitor's guest-exit demux
// (the already-Kani-proven L2.2 `el2_trap::classify_exit`) becomes a bounded,
// no-float, injective TELEMETRY record folded into a per-instance `tel_head` via
// the M22 fold reused verbatim -- the OS *records* its own virtualization
// workload. The math is the Kani-proven `tb_encode::exittel`; the verdict is a
// pure-data struct the `#![forbid(unsafe_code)]` kernel matches on. PRODUCER-ONLY:
// the telemetry is recorded + folded, NEVER fed to a policy whose decisions change
// the future exit distribution (the confounding loop the M24 adversary named is
// structurally avoided), and the `tel_head` is SEPARATE from the M23 `xp_head`
// (zero regression). The marker emits `signal=OBSERVATIONAL-NONCAUSAL` so it
// cannot claim a causal state-signal.
// ===========================================================================

/// M26 exit-telemetry self-test outcome (returned to the kernel for marker rendering).
/// A closed, pure-data verdict -- mirroring [`ExpProof`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitTelemetryProof {
    /// CLASS-TOTALITY: every synthetic ESR mapped to an in-range class tag AND the six
    /// synthetic exits hit six DISTINCT classes (the reused classifier distinguished
    /// them). The kernel requires this (rendered `class-total=1`).
    pub class_total: bool,
    /// BUCKETS-EXACT: each recorded bucket equals an independent `bucket_index` of the
    /// cost-proxy delta AND the per-`(class, bucket)` cell count is exact. The kernel
    /// requires this (rendered `buckets-exact=1`).
    pub buckets_exact: bool,
    /// CLEAN: independently re-folding the committed record ids equals the running
    /// `tel_head`. The kernel requires this.
    pub clean_ok: bool,
    /// A genuine inclusion proof for the first committed record verified against the
    /// clean `tel_head`. The kernel requires this (folded into `fold-verified=1`).
    pub inclusion_ok: bool,
    /// A single-byte tamper of a committed record's canonical bytes was caught on BOTH
    /// legs (head-mismatch AND inclusion-fail). The kernel requires this (rendered
    /// `tamper-caught=1`) -- the tamper-evidence claim (cryptographic since M29-C).
    pub tamper_caught: bool,
    /// The number of DISTINCT exit classes observed (6 on the synthetic vector),
    /// rendered as `classes=<m>`.
    pub classes: u64,
    /// A u64 WITNESS folded from the 32-byte committed `tel_head`, rendered as
    /// `head=<hex16>`.
    pub head: u64,
    /// The number of committed telemetry records (6), rendered as `records=<n>`.
    pub records: u64,
}

/// M26: feed a fixed synthetic ESR_EL2 vector through the reused L2.2 exit classifier,
/// count each exit into a bounded no-float histogram, fold each as an injective
/// telemetry record into a per-instance `tel_head` (the M22 fold reused), and verify
/// class-totality + bucket-exactness + the clean fold + a genuine inclusion proof + a
/// single-byte tamper rejection. See [`ExitTelemetryProof`]. Pure value computation
/// over the Kani-proven `tb_encode::exittel` leaf; touches NO device, NO scheduler.
/// PRODUCER-ONLY (the telemetry is recorded + folded, not fed to any policy) and the
/// `tel_head` is SEPARATE from the M23 `xp_head` (zero regression).
pub fn exittel_selftest() -> ExitTelemetryProof {
    mem::exittel_selftest()
}

// ===========================================================================
// M38 (stage B): the verified CONDUCTOR self-test facade -- TRINITY ADOPT-1
// wired into the kernel boot. The in-kernel selftest agent drives the verified
// `tb_encode::conductor` policy over a multi-organ loop (select-organ ->
// assign-role -> the discrete Verifier verdict, loop until ACCEPT, MAX_TURNS=5);
// the kernel-side organ EXECUTION (the real M_MEM_RECALL context + the
// M_MODEL_INVOKE_BYTES mock through the INVOKE_MODEL gate) supplies the per-turn
// Worker scores, and THIS facade runs the verified policy + folds each
// `ConductDecision` into a `conduct_head` via the M22 prov fold REUSED verbatim,
// then independently re-folds the trace + injects a single-byte tamper. The
// verdict is a closed pure-data struct the `#![forbid(unsafe_code)]` kernel
// matches on. The boundary is the proposal §2.2 one: the DISCRETE policy + the
// discrete Verifier verdict + the provenance fold are IN `tb_encode`; the
// organ EXECUTION (the cap-chokepoint recall/invoke) is the kernel block.
//
// HONEST (proposal §1/§10): the policy is HAND-WRITTEN, NOT learned
// (`policy=DISCRETE-HAND-WRITTEN-NOT-LEARNED`); the Verifier that bites is the
// discrete `gate_clears`-shaped verdict (`verifier=CI-DISCRETE-VERDICT`), NOT a
// learned classifier (`learning=DORMANT`); the M18.1 human-approval gate is
// admission-only + provably inert in the all-mock chain
// (`m18-gate=ADMISSION-ONLY-INERT-IN-MOCK`); the LocalM32 organ is an
// M38-AUTHORED-MOCK in CI (`local-organ=M38-AUTHORED-MOCK`); the cost record is
// the LOGICAL surrogate (`cost-metric=LOGICAL-SURROGATE-NOT-WALLCLOCK`).
// ===========================================================================

/// The number of registered organs the conductor selects over (mirrors
/// [`tb_encode::conductor::N_ORGANS`]), used to size the kernel-side trace cap.
pub const CONDUCTOR_MAX_STEPS: usize = 8;

/// One captured conductor loop STEP -- the SEPARATE trace stream the kernel emits
/// (hex-framed) so the HOST can INDEPENDENTLY re-fold the lineage from the
/// guest's OWN emitted trace (the cross-process anti-hollow leg, proposal §8.6).
/// Each field is the per-turn canonical `ConductDecision` field; the host rebuilds
/// the SAME record + folds it, and the recomputed head must string-equal the
/// guest-emitted head. A forged guest summary cannot match an independent fold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ConductorTraceStep {
    /// The turn number (`0..=MAX_TURNS`) of this step.
    pub turn: u8,
    /// The role assigned this turn (`Role::tag`): 0 Thinker / 1 Worker / 2 Verifier.
    pub role: u8,
    /// The organ selected this turn (`Organ::tag`): 0 Retrieval / 1 LocalM32 / 2 External.
    pub organ: u8,
    /// The Verifier verdict at this turn (`Verdict::tag`): 0 Accept / 1 Revise / 2 HaltBudget.
    pub verdict: u8,
    /// The accumulated organ-call count at this step (the ADOPT-4 cost token).
    pub organ_calls: u16,
    /// The logical (boot/session-relative) clock at this step.
    pub t_logical: u64,
}

/// M38 conductor self-test outcome (returned to the kernel for marker rendering).
/// A closed, pure-data verdict -- mirroring [`ExitTelemetryProof`]. The witness
/// fields are POSITIVELY required on the boot witness line so the marker
/// mechanically cannot overclaim. The `steps` array carries the SEPARATE trace the
/// kernel emits hex-framed for the host's INDEPENDENT cross-process recompute.
#[derive(Clone, Copy, Debug)]
pub struct ConductorProof {
    /// CLEAN: independently re-folding the committed `ConductDecision` ids equals
    /// the running `conduct_head`. The kernel requires this (folded into
    /// `fold-verified=1`).
    pub clean_ok: bool,
    /// A genuine inclusion proof for the first committed decision verified against
    /// the clean `conduct_head`. The kernel requires this (folded into
    /// `fold-verified=1`).
    pub inclusion_ok: bool,
    /// A single-byte tamper of a committed decision's canonical bytes was caught on
    /// BOTH legs (head-mismatch AND inclusion-fail) -- the tamper-evidence claim
    /// (cryptographic since M29-C). The kernel requires this (rendered
    /// `tamper-caught=1`).
    pub tamper_caught: bool,
    /// The loop reached a real Verifier-ACCEPT terminal (not HaltBudget). The
    /// kernel requires this (rendered `verdict=ACCEPT`).
    pub accepted: bool,
    /// The number of DISTINCT organs in the measured sequence (the anti-hollow
    /// `organs>=2` requirement -- a single-organ stub has 1). Rendered `organs=<m>`.
    pub organs: u64,
    /// The number of Verifier REVISE steps in the measured trace (the anti-hollow
    /// `revise-cycles>=1` requirement -- an always-accept stub has 0). Rendered
    /// `revise-cycles=<m>`.
    pub revise_cycles: u64,
    /// The turn count (the last turn + 1; `<=MAX_TURNS+1`). Rendered `turns=<n>`.
    pub turns: u64,
    /// The turn at which the Verifier ACCEPTed. Rendered `accept-at=<k>`.
    pub accept_at: u64,
    /// The accumulated organ-call count (the ADOPT-4 cost token). Rendered
    /// `organ-calls=<c>`.
    pub organ_calls: u64,
    /// A u64 WITNESS folded from the 32-byte committed `conduct_head` (every head
    /// byte contributes), rendered `head=<hex16>`.
    pub head: u64,
    /// The number of committed conductor decisions (== the captured trace length).
    pub records: u64,
    /// The SEPARATE captured trace (the kernel emits each step hex-framed for the
    /// host's INDEPENDENT cross-process re-fold). Valid entries are `0..records`.
    pub steps: [ConductorTraceStep; CONDUCTOR_MAX_STEPS],
}

/// M38 (stage B): run the verified `tb_encode::conductor` policy over the kernel-
/// supplied per-turn Worker scores (the REAL organ-execution results: the
/// M_MEM_RECALL context strength + the M_MODEL_INVOKE_BYTES mock-response refinement
/// the kernel block computes through the cap chokepoint), fold each
/// `ConductDecision` into a `conduct_head` via the M22 prov fold REUSED verbatim,
/// independently re-fold the trace, inject a single-byte tamper, and report the
/// outcome as a pure-data [`ConductorProof`]. See proposal §8 (stage B). Pure value
/// computation over the Kani-proven `tb_encode::conductor` leaf; touches NO device,
/// NO scheduler -- the kernel block does the cap-chokepoint organ execution and
/// passes the scores in. The `conduct_head` is SEPARATE from every other fold head
/// (M22/M23/M25/M26/...) so the cumulative chain stays byte-identical (the
/// conductor folds on its OWN lane).
///
/// `worker_scores[round]` is the Worker organ's output score on retry `round` (the
/// kernel derives it from the real recall context + the mock invoke); a round-0
/// below-margin score forces a Verifier REVISE, a later round clears -- so the
/// honest run measures a >=2-organ sequence with a >=1 REVISE->ACCEPT cycle. The
/// loop is bounded by `MAX_TURNS` (no unbounded wait -- the #1 boot-hang risk is
/// structurally excluded).
pub fn conductor_selftest(worker_scores: &[i64]) -> ConductorProof {
    mem::conductor_selftest(worker_scores)
}

// ===========================================================================
// M28: the verified OPERATOR-INBOUND command self-test facade -- the CAPSTONE
// that closes the M23->M24->M25->M26->M27 learning loop. The RX dual of the M25
// transcript: a SIMULATED enrolled verifier (a compiled-in test key, two creds)
// answers the OS's freshness CHALLENGE (a fresh per-boot nonce) and submits a
// well-formed, fresh, head-bound, DUAL-AUTHORIZED `ACTIVATE_CMD`; the RX path
// ACCEPTS the valid command AND REJECTS (a) a stale-nonce replay, (b) a wrong-head
// command, (c) a single-credential command, (d) a flipped-MAC command. The math is
// the Kani-proven `tb_encode::opframe_rx` (whose keyed MAC + key-evolution, since
// M29, call the verified `tb_encode::khash` BLAKE2s-256 leaf -- RFC 7693, native
// keyed mode); the verdict is a pure-data struct the `#![forbid(unsafe_code)]`
// kernel matches on (mirroring [`OpframeProof`]).
//
// CRITICAL HONESTY: the accepted command is NECESSARY-NOT-SUFFICIENT -- `KAN_ACTIVE`
// stays `false` (a `const false`; the command does NOT flip it). The architectural
// "pending flag -> M24 reads it" seam is described in the proposal, but for THIS
// self-test the assertion is simply that an accepted command leaves `KAN_ACTIVE ==
// false` because M24's statistical bar is unmet on synthetic data. The witness MUST
// carry `kan_active=0`. The MAC is `mac=KEYED-CRYPTO` (M29: a keyed BLAKE2s-256
// derive-then-MAC -- implementation VERIFIED, primitive security
// `sec=ASSUMED-FROM-LITERATURE`, never "proven secure") and the oracle is
// `oracle=SIMULATED-ENROLLED-KEY` (a test key, not a human + not a real enrolment
// ceremony) -- the marker proves the auth PLUMBING, never that a human commanded.
// The self-test also recomputes the OFFICIAL RFC 7693 vectors through the real
// compression (`khash::kat_ok`, fail-closed -- `kat=RFC7693-PASS` is EARNED per
// boot) and TESTS old-key erasure (snapshot-evolve-zeroize-assert,
// `oldkey-zeroized=1` -- the Bellare-Yee forward-security erasure condition,
// TESTED not proven). The honesty tokens are machine-emitted so the run-scripts
// reject any overclaim. DoD: "M28: operator-cmd OK" + "M29: khash-mac OK".
// ===========================================================================

/// M28 operator-inbound command self-test outcome (returned to the kernel for marker
/// rendering). A closed, pure-data verdict -- mirroring [`OpframeProof`]. The witness
/// fields are POSITIVELY required on the boot witness line so the marker mechanically
/// cannot claim an authentication property it did not verify, nor an activation the
/// M24 bar does not support (`kan_active` is REQUIRED false).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpcmdProof {
    /// THE ACCEPT: the SIMULATED enrolled verifier's well-formed, fresh, head-bound,
    /// dual-authorized `ACTIVATE_CMD` was ACCEPTED by the RX path (decode + kind +
    /// nonce + head-binding + dual-custody + keyed MAC all held). The kernel requires
    /// this (rendered `accepted=1`).
    pub accepted: bool,
    /// A stale-nonce replay (a command echoing a prior challenge nonce) was REJECTED
    /// (`RejectStale`) -- the freshness check (RATS RFC 9334 §10). The kernel requires
    /// this (rendered `stale-rejected=1`).
    pub stale_rejected: bool,
    /// A wrong-head command (binding an `op_head` != the live head) was REJECTED
    /// (`RejectWrongHead`) -- the Terrapin head-binding lesson. The kernel requires this
    /// (rendered `wronghead-rejected=1`).
    pub wronghead_rejected: bool,
    /// A single-credential command (`cred_a_id == cred_b_id`) was REJECTED
    /// (`RejectSingleCred`) -- the dual-custody / two-person rule. The kernel requires
    /// this (rendered `single-cred-rejected=1`).
    pub single_cred_rejected: bool,
    /// A flipped-MAC command (a single tampered MAC byte) was REJECTED (`RejectBadMac`)
    /// -- the keyed-MAC tamper-sensitivity. The kernel requires this (rendered
    /// `badmac-rejected=1`).
    pub badmac_rejected: bool,
    /// M29: the in-boot KAT verdict -- `tb_encode::khash::kat_ok()` RECOMPUTED the
    /// official RFC 7693 Appendix B + BLAKE2 reference-KAT vectors through the real
    /// compression and they all matched. The kernel requires this BEFORE rendering
    /// `kat=RFC7693-PASS` on the `khash:` witness line (the token is EARNED per
    /// boot, never compiled-in -- fail-closed).
    pub kat_ok: bool,
    /// M29: the old-key ERASURE seam check -- the self-test snapshotted an epoch
    /// key, evolved it forward via [`tb_encode::opframe_rx::key_evolve`], ZEROIZED
    /// the old epoch's bytes and asserted the erasure took (rendered
    /// `oldkey-zeroized=1`). Forward security (Bellare-Yee) is CONDITIONAL on
    /// erasure -- a stateful-seam property the pure leaf cannot claim, so it is
    /// TESTED here, not proven.
    pub oldkey_zeroized: bool,
    /// The learned cell's activation state AFTER the accepted command. REQUIRED `false`
    /// this milestone (necessary-not-sufficient: the command un-blocks the M24 gate's
    /// oracle input, but M24's statistical bar is unmet on synthetic data, so the cell
    /// stays DORMANT). The run-scripts REQUIRE `kan_active=0`.
    pub kan_active: bool,
    /// The per-boot challenge NONCE the OS issued + the verifier echoed, rendered as
    /// `challenge=<hex16>` in the boot witness line (the freshness anchor).
    pub challenge: u64,
}

/// M28: play the SIMULATED enrolled operator-verifier over the Kani-proven
/// `tb_encode::opframe_rx` RX path (both arches) and report the outcome. See
/// [`OpcmdProof`]. Pure value computation -- a compiled-in test key (two creds)
/// answers the OS's per-boot freshness CHALLENGE with a well-formed, fresh, head-
/// bound, DUAL-AUTHORIZED `ACTIVATE_CMD`; the RX path ACCEPTS the valid command and
/// REJECTS (a) stale-nonce, (b) wrong-head, (c) single-credential, (d) flipped-MAC --
/// and (M29) RECOMPUTES the official RFC 7693 KAT vectors fail-closed (`kat_ok`) +
/// TESTS old-key erasure (`oldkey_zeroized`). Touches NO device beyond the serial the
/// kernel renders over, and NO scheduler. The accepted command is
/// NECESSARY-NOT-SUFFICIENT: `KAN_ACTIVE` stays `false` (M24's bar is unmet on
/// synthetic data). HONEST: the MAC is `mac=KEYED-CRYPTO` (M29: a keyed BLAKE2s-256
/// derive-then-MAC -- implementation verified; primitive security
/// `sec=ASSUMED-FROM-LITERATURE`) and the oracle is `oracle=SIMULATED-ENROLLED-KEY`
/// (a test key, not a human) -- the marker proves the auth PLUMBING, never that a
/// human commanded.
pub fn opcmd_selftest() -> OpcmdProof {
    mem::opcmd_selftest()
}

/// Boot-Profiles stage A (§3.3): the STANDALONE M29 khash KAT, hoisted out of
/// [`opcmd_selftest`] for the SUBSTRATE arm only. The khash primitive is a
/// substrate INTEGRITY feature (a keyed BLAKE2s-256 MAC), NOT an agent organ, so
/// it stays live in the substrate profile. On the AGENT profile the KAT still
/// runs INSIDE `opcmd_selftest` (`OpcmdProof::kat_ok`) exactly as before and the
/// `khash:`/`M29:` lines emit from that path, BYTE-IDENTICAL — this function is
/// reached ONLY from the gated M28 block's substrate `else` arm, so there is
/// EXACTLY one KAT emission per boot on either profile (no duplicate line on the
/// agent stream). Recomputes the official RFC 7693 vectors through the REAL
/// compression, fail-closed; `true` earns the `kat=RFC7693-PASS` token.
pub fn khash_kat_selftest() -> bool {
    tb_encode::khash::kat_ok()
}

// ===========================================================================
// M30: the verified INFERENCE-TRANSPORT self-test facade -- the sovereignty
// A-chain's channel to a host model peer (transport ONLY; the adapter is M31).
// Mirrors the `VirtioProof`/`PersistProof` device-facade pattern: a closed,
// pure-data verdict the `#![forbid(unsafe_code)]` kernel matches on. ALL
// silicon-unsafe (the virtio-console two-queue MMIO/DMA session) is in
// `arch::*::virtio::chan_*`; ALL value computation (frame codec, stream
// re-framing, the host-keyed echo MAC) is the Kani-proven
// `tb_encode::inferwire` (+ the M29 `tb_encode::khash` it calls); the
// orchestration is the safe `mem::xport_selftest`.
//
// THE ANTI-HOLLOW SHAPE (proposal §4 -- the M22 mock-loopback lesson): the
// host peer custodies a per-run OS-RNG key K + nonce N; the kernel emits an
// ECHO_REQ with a per-boot challenge; the host answers with a khash echo tag
// binding peer_id||N||challenge||body INSIDE the MAC and reveals K on the
// channel; the kernel recomputes + verifies (LEG 1, this facade) and the run
// script string-compares the kernel-witnessed challenge/tag against the host
// peer's OWN printed line (LEG 2, the loopback killer -- a loopback can mint a
// self-consistent tag but cannot equal the host's khash(K,..) without the
// host-custodied K). `echo=HOST-KEYED-VERIFIED` is therefore KERNEL-SCOPE;
// `key=HOST-CUSTODIED-PER-RUN` claims custody, never confidentiality (K rides
// the channel in cleartext); `backend=ECHO-ONLY` (no model, no semantics);
// `mode=POLL` (no IRQ path -- the #71 guard pin); `sec=ASSUMED-FROM-
// LITERATURE` is inherited from M29. DoD: "M30: infer-transport OK".
// ===========================================================================

/// M30 inference-transport self-test outcome (returned to the kernel for
/// marker rendering). A closed, pure-data verdict -- mirroring
/// [`VirtioProof`]/[`PersistProof`] (proposal §3b).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InferChanProof {
    /// No virtio-console (DeviceID 3) in any scanned slot -- a GRACEFUL skip
    /// rendered LOUDLY as `M30: infer-transport OK (no host peer, skipped)`.
    /// Legitimate ONLY on lanes that attach no peer (bench, l2-nested,
    /// vmm-boot until stage C); every peer-attached lane REJECTS it by name.
    Absent,
    /// A virtio-console was found but it is LEGACY (`Version` != 2) -- an
    /// honest skip (this driver speaks only the modern transport; a legacy
    /// slot is rejected, never silently driven).
    LegacyUnsupported,
    /// THE PROOF (leg 1 of the §4 composition): the full modern two-queue
    /// handshake + ONE host-keyed echo round-trip ran; the response was
    /// stream-re-framed through the proven `FrameAccum`, decoded fail-closed,
    /// and `verify_echo` ACCEPTED it against the channel-revealed per-run key
    /// (kind + correlation binding + challenge echo + body-bitexact + tag
    /// recompute); AND all four in-boot negatives (badtag / wrongkey /
    /// partial / desync) REJECTED. Constructed ONLY when every leg held --
    /// the witness flags the kernel renders as `=0x1` are earned per boot,
    /// fail-closed, never compiled-in defaults.
    Proven {
        /// The virtio-mmio slot index the console channel was found at.
        slot: u32,
        /// The correlation id of the echo round-trip (witness `req-id=`).
        req_id: u64,
        /// The decoded response FRAME length in bytes (the channel additionally
        /// carried the [`tb_encode::inferwire::INFER_KEY_REVEAL_LEN`] trailer).
        resp_len: u64,
        /// The per-boot challenge the response provably echoed + MAC-bound
        /// (witness `challenge=`; leg 2 string-compares it cross-process).
        challenge: [u8; 16],
        /// The HOST-chosen per-run nonce, MAC-covered (witness `nonce=`).
        nonce: [u8; 16],
        /// The verified truncated khash echo tag (witness `tag=`; leg 2
        /// string-compares it against the host peer's own printed line).
        tag: [u8; 16],
        /// The MAC-covered host peer identity byte (0x01 = TB-VMM-HOST, 0x02 =
        /// QEMU-CHARDEV-HARNESS) -- the kernel maps it to the `bus=`/
        /// `transport=` lane tokens, so the lane label is bound INSIDE the tag
        /// it just verified (the kernel mechanically cannot mint it).
        peer_id: u8,
        /// M31: the CHANNEL-REVEALED per-run host key K (the M30 reveal
        /// convention -- custody, never confidentiality). Carried forward so
        /// the M31 inference-adapter wire legs can MAC their `INFER_REQ`
        /// chunks and verify the host's `INFER_RESP`/`INFER_PENDING`/`ERR`
        /// tags under the NEW `infer_tag` domain without a second reveal.
        key: [u8; 32],
    },
    /// Found + driven, but the round-trip failed fail-closed. `stage`
    /// localises the failure (0x2 req-canon, 0x3 channel session/poll-cap --
    /// the present-then-silent peer, 0x4 stream-reframe/decode, 0x5 unknown
    /// peer label, 0x6 echo-verify, 0x7 a negative control did not fire). The
    /// kernel renders it WITHOUT an 'infer-transport OK' substring -- red.
    Failed {
        /// The pipeline stage that failed (see the variant doc).
        stage: u32,
    },
}

/// M30: run the host-keyed echo round-trip over the virtio-console channel
/// (both arches) and report the outcome. See [`InferChanProof`]. Poll-only
/// (no completion IRQ -- `mode=POLL`, the #71 guard pin), touches NO
/// scheduler; all raw device work is in `arch::*::virtio::chan_*`, all value
/// computation is the Kani-proven `tb_encode::inferwire` + `tb_encode::khash`,
/// the orchestration is safe `mem::xport_selftest`. Absent (no DeviceID 3) is
/// a graceful LOUD skip; a present-then-silent peer is a hard `Failed`, never
/// a skip (proposal §10).
pub fn xport_selftest() -> InferChanProof {
    mem::xport_selftest()
}

// ===========================================================================
// M31: the verified INFERENCE-ADAPTER wire self-test facade -- the first
// MEANING on the M30 channel (still MOCK-DETERMINISTIC: a deterministic
// transform, never a model, never a network). Mirrors the InferChanProof
// device-facade pattern: a closed, pure-data verdict the
// `#![forbid(unsafe_code)]` kernel matches on. ALL value computation (the
// chunk sub-header codec, the per-chunk infer_tag MAC under the NEW
// "YUVA-M31-INFER-V1" domain, the fail-closed InferAssembler, the closed ERR
// enum, the shared mock_infer transform) is the Kani-proven
// `tb_encode::inferwire` M31 extension; the channel session is the SAME
// `arch::*::virtio::chan_*` silicon path M30 proved; the orchestration is
// the safe `mem::infer_wire_selftest`.
// ===========================================================================

/// M31 inference-adapter WIRE self-test outcome (returned to the kernel for
/// witness rendering). A closed, pure-data verdict -- the `Proven` variant is
/// constructed ONLY when the keyless wire-ERR check verified, the chunked
/// mock exchange MAC-verified + reassembled + matched the in-kernel
/// expectation bit-exactly, AND all four in-boot negatives fired (badmac /
/// digest-mismatch / oversize / err-taxonomy) -- the witness flags are earned
/// per boot, fail-closed, never compiled-in defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InferWireProof {
    /// The full wire proof held. See the gate list in the enum doc.
    Proven {
        /// Verified `INFER_PENDING` heartbeats received (the deterministic
        /// stage-B protocol sends EXACTLY one; pendings are budget-resets,
        /// NEVER completions -- a pendings-only run is a hard fail).
        pending: u64,
        /// MAC-verified `INFER_RESP` chunks reassembled (the 1280-byte mock
        /// body forces 2 -- the assembler does real wire work every boot).
        chunks: u64,
        /// The reassembled response body length in bytes.
        resp_len: u64,
    },
    /// A wire leg failed fail-closed. `stage` localises it (0x1x = the
    /// keyless ERR probe legs, 0x2x = the chunked mock-exchange legs, 0x27 =
    /// a negative control did not fire). The kernel renders it WITHOUT an
    /// 'infer-e2e OK' substring -- red.
    Failed {
        /// The pipeline stage that failed (see the variant doc).
        stage: u32,
    },
}

/// M31: the fixed MOCK-DETERMINISTIC response length (re-exported so the
/// `#![forbid(unsafe_code)]` kernel -- which has no tb-encode dependency --
/// can size its response buffer; deliberately > the 1024 payload cap, so the
/// wire exchange always chunks).
pub const INFER_MOCK_RESP_LEN: usize = tb_encode::inferwire::INFER_MOCK_RESP_LEN;

/// M32 (stage B): the LOCAL-ORGAN request sentinel prefix (re-exported so the
/// `#![forbid(unsafe_code)]`, tb-encode-free kernel can build the M32 prompt
/// that routes a host peer to the local-organ leg -- see
/// [`infer_local_wire_selftest`]).
pub const INFER_LOCAL_PROBE: &[u8] = tb_encode::inferwire::INFER_LOCAL_PROBE;

/// M31: the deterministic correlation id for a byte prompt: the leading 8
/// bytes (LE) of `op_hash(prompt)` -- deterministic so the SAME id appears in
/// the M25 transcript fold (computed before M25 prints) and on the wire
/// exchange (after M30), and the witness/transcript/wire evidence all
/// correlate. No security claim rides on the id; freshness is the per-boot
/// challenge inside the MAC.
pub fn infer_req_id_for(prompt: &[u8]) -> u64 {
    let h = tb_encode::opframe::op_hash(prompt);
    u64::from_le_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]])
}

/// M31: the full 32-byte response digest (`op_hash` -- the ONE M29-C digest
/// discipline; its leading 16 bytes equal the on-wire `body_digest`
/// commitment, so the witness `resp-digest=` and the wire commitment can
/// never drift).
pub fn infer_resp_digest(resp: &[u8]) -> [u8; 32] {
    tb_encode::opframe::op_hash(resp)
}

/// M31: the M25 transcript fold payload -- `req_id (u64 LE) || op_hash
/// (response-bytes)` (proposal §3d: the DIGEST, never the dump -- fixed-width,
/// injection-inert). The kernel passes this into [`opframe_selftest`] so the
/// committed transcript covers the inference evidence BEFORE the closing
/// GATE_VERDICT.
pub fn infer_fold_payload(req_id: u64, resp_digest: &[u8; 32]) -> [u8; 40] {
    let mut out = [0u8; 40];
    out[..8].copy_from_slice(&req_id.to_le_bytes());
    out[8..].copy_from_slice(resp_digest);
    out
}

/// M31: run the inference-adapter WIRE legs (the keyless `ERR NO-KEY` check +
/// the chunked PENDING-then-RESP mock exchange + the four in-boot negatives)
/// over the M30-proven channel at `slot`, MAC'ing every frame with the
/// channel-revealed per-run key under the NEW M31 domain separator. See
/// [`InferWireProof`]. `prompt` is the agent-assembled M13-scalar context;
/// `expected_resp` is the in-kernel MOCK-DETERMINISTIC `infer_bytes` output
/// the wire body must equal bit-exactly (the cross-process determinism
/// check). Poll-only, no scheduler; a present-then-silent peer is a hard
/// `Failed`, never a skip.
pub fn infer_wire_selftest(
    slot: u32,
    key: &[u8; 32],
    m30_nonce: &[u8; 16],
    req_id: u64,
    prompt: &[u8],
    expected_resp: &[u8],
) -> InferWireProof {
    mem::infer_wire_selftest(slot, key, m30_nonce, req_id, prompt, expected_resp)
}

/// M32 (stage B): run the LOCAL-ORGAN receive path -- a PARALLEL exchange beside
/// the untouched M31 mock leg. Sends ONE MAC'd `INFER_REQ` whose body opens with
/// [`tb_encode::inferwire::INFER_LOCAL_PROBE`] on the SAME proven channel and
/// receives PENDING + `INFER_RESP` chunks stamped `peer_id = INFER_DAEMON
/// (0x03)`; every frame is MAC-verified, the local peer id is asserted (so a
/// mock `0x02` frame can never wear the local identity), and the reassembled
/// body must equal the in-kernel DETERMINISTIC STAND-IN `expected_resp`
/// bit-exact. This receive is what feeds the M38 conductor a REAL, over-the-wire
/// local organ. See [`InferWireProof`] (the `0x3x` fail band is disjoint from
/// M31's). NO vendored C engine runs here -- the honest render is
/// `local-organ=DETERMINISTIC-STANDIN`, never live inference.
pub fn infer_local_wire_selftest(
    slot: u32,
    key: &[u8; 32],
    m30_nonce: &[u8; 16],
    req_id: u64,
    prompt: &[u8],
    expected_resp: &[u8],
) -> InferWireProof {
    mem::infer_local_wire_selftest(slot, key, m30_nonce, req_id, prompt, expected_resp)
}

// ===========================================================================
// M33: the provenance-lineage crypto-verify self-test facade (stage A). PURE
// value computation over the Kani-proven tb_encode leaves (sha256 / lmsig /
// attest) -- NO device, NO scheduler, NO secret, microseconds at boot. The
// kernel matches on the returned proof bools and renders the honesty-tokened
// witness. VERIFY ONLY: the private signing key + the never-reuse leaf-index
// state live host-side (tools/prov-signer), NEVER in this kernel TCB.
// ===========================================================================

/// M33 stage-A proof: the in-boot KATs + the small-parameter LMS roundtrip +
/// the two regional tamper controls + the attestation codec roundtrip. See
/// [`m33_prov_selftest`].
pub struct M33ProvProof {
    /// The SHA-256 in-boot KAT recomputed the official FIPS 180-4 vectors
    /// through the real compression (earns `sha256-kat=FIPS180-4-PASS`).
    pub sha256_kat_ok: bool,
    /// The pinned small-parameter (`w=1`) LMS toy signature VERIFIED against the
    /// pinned public root through real SHA-256 compressions (earns
    /// `kat=RFC8554-PASS`, `sig-verified=1`).
    pub lms_verified: bool,
    /// A one-byte flip in the LM-OTS-signature region was REJECTED (a Merkle-
    /// only half-verifier is caught; `tamper-rejected-ots=1`).
    pub tamper_ots_rejected: bool,
    /// A one-byte flip in the Merkle-auth-path region was REJECTED (an OTS-only
    /// half-verifier is caught; `tamper-rejected-merkle=1`).
    pub tamper_merkle_rejected: bool,
    /// The DSSE-PAE attestation codec round-tripped (canon -> decode identity)
    /// AND the DSSE PAE encoded non-empty (`attest-decoded=1`).
    pub attest_ok: bool,
    /// A u64 witness fold of the 32-byte public root (rendered `root=<hex16>`).
    pub root_witness: u64,
    /// A u64 witness fold of the attestation subject digest (rendered
    /// `attest-digest=<hex16>`).
    pub attest_digest: u64,
    // ---- stage B (the persisted signed head; proposal §6/§8) ----
    /// The compiled-in FULL-parameter `W4`/`H10` signature verified this boot (the
    /// every-boot full-parameter verify KAT, stronger than the toy-only KAT).
    pub full_sig_verified: bool,
    /// The signed head was written + FLUSHED to disk this boot (`head-persisted`).
    pub head_persisted: bool,
    /// A signed head from a PRIOR boot was read back + its signature verified
    /// (`head-reboot-survived` -- the two-boot cross-boot DoD).
    pub head_reboot_survived: bool,
    /// A u32 witness fold of the 16-byte LMS identifier `I` (rendered `i-id=<hex8>`).
    pub i_id_witness: u32,
    /// A u64 witness fold of the signed head (rendered `head=<hex16>`) -- read
    /// FROM DISK on survival (the anti-hollow cross-boot evidence).
    pub head_witness: u64,
    /// The LMS leaf index of the witnessed head (rendered `leaf-idx=<hex>`).
    pub leaf_idx: u32,
}

/// Fold the first 8 bytes of a 32-byte value into a u64 witness (LE). Pure.
fn fold8(b: &[u8; 32]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Fold the first 4 bytes of the 16-byte LMS identifier into a u32 witness (LE).
fn fold4(b: &[u8; 16]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// M33 stage-A self-test (both arches): recompute the SHA-256 FIPS 180-4 KAT +
/// the LMS small-parameter roundtrip KAT (with the two regional tamper
/// controls) through REAL compressions, and round-trip the DSSE-PAE attestation
/// codec. All value computation is the host-verifiable, Kani-proven
/// `tb_encode::{sha256,lmsig,attest}` (VERIFY-only in the kernel). HONEST: a
/// signature proves `exclusivity=OFF-PLATFORM-ONLY` and NOTHING against the
/// host holding the key; `key=SIMULATED-ENROLLED-CI-CUSTODIED`;
/// `state=SIMULATED-REUSE-OK-NO-SECURITY`; `sec=ASSUMED-FROM-LITERATURE`.
pub fn m33_prov_selftest() -> M33ProvProof {
    let sha256_kat_ok = tb_encode::sha256::kat_ok();
    let k = tb_encode::lmsig::kat();

    // Exercise the DSSE-PAE attestation codec (self-reported subject digest --
    // selfmeasure=UNATTESTED-LOADER): build a statement, canon it, decode it
    // back, and PAE-wrap it under the M33 attestation domain separator.
    let subject_digest = tb_encode::sha256::sha256(b"YUVA-M33-selfmeasure");
    let toolchain_hash = tb_encode::sha256::sha256(b"YUVA-M33-toolchain");
    let materials: [[u8; 32]; 1] = [tb_encode::sha256::sha256(b"YUVA-M33-material-0")];
    let ledger = [tb_encode::attest::LedgerEntry {
        dep_tok: 0x594D_3333, // "YM33"
        status: tb_encode::attest::ledger_status::ACCEPTED_PERMANENT,
    }];
    let st = tb_encode::attest::AttestStatement {
        subject_digest,
        builder_id: [0x59u8; tb_encode::attest::BUILDER_ID_LEN],
        build_type: tb_encode::attest::build_type::KERNEL_IMAGE,
        toolchain_hash,
        materials: &materials,
        ledger: &ledger,
    };
    let mut cbuf = [0u8; 256];
    let cn = tb_encode::attest::canon(&st, &mut cbuf);
    let roundtrip_ok = cn > 0
        && match tb_encode::attest::decode(&cbuf[..cn]) {
            Some(d) => {
                d.subject_digest == subject_digest
                    && d.toolchain_hash == toolchain_hash
                    && d.build_type == tb_encode::attest::build_type::KERNEL_IMAGE
                    && d.n_materials == 1
                    && d.n_ledger == 1
            }
            None => false,
        };
    let mut pbuf = [0u8; 384];
    let pn = tb_encode::attest::pae(
        tb_encode::attest::ATTEST_PAYLOAD_TYPE,
        &cbuf[..cn],
        &mut pbuf,
    );
    let attest_ok = roundtrip_ok && pn > 0;

    // Stage B: the persisted signed-head two-boot round-trip (proposal §6/§8).
    let p = mem::m33_persist_head();

    M33ProvProof {
        sha256_kat_ok,
        lms_verified: k.verified,
        tamper_ots_rejected: k.tamper_ots_rejected,
        tamper_merkle_rejected: k.tamper_merkle_rejected,
        attest_ok,
        // The `root=` witness is now the OPERATIONAL W4/H10 public root the
        // persisted signature verifies against (not the toy root).
        root_witness: fold8(&tb_encode::lmsig::PROV_KAT_ROOT),
        attest_digest: fold8(&subject_digest),
        full_sig_verified: p.full_sig_verified,
        head_persisted: p.persisted,
        head_reboot_survived: p.survived,
        i_id_witness: fold4(&tb_encode::lmsig::TOY_I),
        head_witness: fold8(&p.head),
        leaf_idx: p.leaf_idx,
    }
}
