//! L2.0 — the control-MSR ADJUST algorithm (the VM-entry legality gate).
//!
//! Every VMX control field (pin-based, primary/secondary processor-based, exit,
//! entry) has a capability MSR whose low 32 bits are "allowed-0" (bits that MUST
//! be 1) and whose high 32 bits are "allowed-1" (bits that MAY be 1). A legal
//! control value is therefore:
//!
//! ```text
//!     final = (desired | allowed0) & allowed1
//! ```
//!
//! SKIPPING this is the #1 cause of silent VM-entry failure (the design's
//! explicit warning). When IA32_VMX_BASIC bit 55 is set, the TRUE_* capability
//! MSRs report the real allowed-0 (fewer forced bits) and MUST be used for the
//! pin/primary/exit/entry classes; the secondary class has no TRUE variant.
//!
//! Field/bit values: Intel SDM Vol 3C §24.6 + Appendix A.3/A.4.

use super::vmxon::rdmsr;
// Task #49: the pure `(desired|allowed0)&allowed1` gate now lives in the
// host-verifiable, Kani-proven `tb-encode` crate. We CALL it here; only the
// `rdmsr` of the capability MSR (the silicon-unsafe read) stays in tb-hal. The
// emitted control words are byte-identical to the former inline implementation.
use tb_encode::vmx::adjust;
use super::{
    IA32_VMX_BASIC, IA32_VMX_ENTRY_CTLS, IA32_VMX_EXIT_CTLS, IA32_VMX_PINBASED_CTLS,
    IA32_VMX_PROCBASED_CTLS, IA32_VMX_PROCBASED_CTLS2, IA32_VMX_TRUE_ENTRY_CTLS,
    IA32_VMX_TRUE_EXIT_CTLS, IA32_VMX_TRUE_PINBASED_CTLS, IA32_VMX_TRUE_PROCBASED_CTLS,
};

// ---- Desired control bits (pre-adjust) ------------------------------------

/// Primary processor-based control: "activate secondary controls" (bit 31).
pub(super) const PROCBASED_ACTIVATE_SECONDARY: u32 = 1 << 31;

/// Secondary processor-based control: "enable EPT" (bit 1).
pub(super) const PROCBASED2_ENABLE_EPT: u32 = 1 << 1;

/// VM-exit control: "host address-space size" (bit 9) — host returns to 64-bit.
pub(super) const EXIT_HOST_ADDRSPACE_SIZE: u32 = 1 << 9;
/// VM-exit control: "save IA32_EFER" (bit 20).
pub(super) const EXIT_SAVE_EFER: u32 = 1 << 20;
/// VM-exit control: "load IA32_EFER" (bit 21).
pub(super) const EXIT_LOAD_EFER: u32 = 1 << 21;

/// VM-entry control: "IA-32e mode guest" (bit 9) — the guest enters 64-bit mode.
pub(super) const ENTRY_IA32E_MODE_GUEST: u32 = 1 << 9;
/// VM-entry control: "load IA32_EFER" (bit 15).
pub(super) const ENTRY_LOAD_EFER: u32 = 1 << 15;

/// The five adjusted control words ready to VMWRITE.
pub(super) struct Controls {
    /// Pin-based VM-execution controls.
    pub(super) pinbased: u32,
    /// Primary processor-based VM-execution controls.
    pub(super) procbased: u32,
    /// Secondary processor-based VM-execution controls.
    pub(super) procbased2: u32,
    /// VM-exit controls.
    pub(super) exit: u32,
    /// VM-entry controls.
    pub(super) entry: u32,
}

/// Run the adjust algorithm for the minimal L2.0 control set and return the five
/// legal control words. Picks the TRUE_* capability MSRs when available
/// (IA32_VMX_BASIC bit 55).
///
/// # Safety
/// Ring 0; reads architectural VMX capability MSRs only.
pub(super) unsafe fn adjusted() -> Controls {
    unsafe {
        let basic = rdmsr(IA32_VMX_BASIC);
        let use_true = (basic & (1 << 55)) != 0;

        let pin_msr = if use_true { IA32_VMX_TRUE_PINBASED_CTLS } else { IA32_VMX_PINBASED_CTLS };
        let proc_msr = if use_true { IA32_VMX_TRUE_PROCBASED_CTLS } else { IA32_VMX_PROCBASED_CTLS };
        let exit_msr = if use_true { IA32_VMX_TRUE_EXIT_CTLS } else { IA32_VMX_EXIT_CTLS };
        let entry_msr = if use_true { IA32_VMX_TRUE_ENTRY_CTLS } else { IA32_VMX_ENTRY_CTLS };

        Controls {
            pinbased: adjust(0, rdmsr(pin_msr)),
            procbased: adjust(PROCBASED_ACTIVATE_SECONDARY, rdmsr(proc_msr)),
            // Secondary class: no TRUE variant.
            procbased2: adjust(PROCBASED2_ENABLE_EPT, rdmsr(IA32_VMX_PROCBASED_CTLS2)),
            exit: adjust(EXIT_HOST_ADDRSPACE_SIZE | EXIT_SAVE_EFER | EXIT_LOAD_EFER, rdmsr(exit_msr)),
            entry: adjust(ENTRY_IA32E_MODE_GUEST | ENTRY_LOAD_EFER, rdmsr(entry_msr)),
        }
    }
}
