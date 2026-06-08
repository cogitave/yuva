//! L2.0 — raw VM-exit readout (thin VMREAD wrappers).
//!
//! After the world switch returns, the VMCS is still current, so the exit
//! information is read here in (otherwise-)plain Rust. L2.0 only needs the exit
//! reason (to assert CPUID = 10) and, on a VM-entry failure, the VM-instruction
//! error. The qualification / instruction-length / guest-physical readers are
//! the scaffolding the L2.1+ exit demultiplexer will use.
//!
//! Read-only field encodings — Intel SDM Vol 3C Appendix B.2/B.3:
//!  VM-instruction error 0x4400, exit reason 0x4402, exit instruction length
//!  0x440C, exit qualification 0x6400, guest-physical address 0x2400.

use super::vmcs::vmread;

/// EXIT_REASON field encoding.
const VM_EXIT_REASON: u64 = 0x4402;
/// VM_INSTRUCTION_ERROR field encoding.
const VM_INSTRUCTION_ERROR: u64 = 0x4400;
/// VM_EXIT_INSTRUCTION_LEN field encoding.
const VM_EXIT_INSTRUCTION_LEN: u64 = 0x440C;
/// EXIT_QUALIFICATION field encoding.
const EXIT_QUALIFICATION: u64 = 0x6400;
/// GUEST_PHYSICAL_ADDRESS field encoding.
const GUEST_PHYSICAL_ADDRESS: u64 = 0x2400;

/// VM-exit reason: the basic exit reason is bits 15:0 (e.g. 10 = CPUID,
/// 18 = VMCALL, 48 = EPT violation).
///
/// # Safety
/// Ring 0, VMX-root, a current VMCS that has taken a VM-exit.
pub(super) unsafe fn exit_reason() -> u32 {
    (unsafe { vmread(VM_EXIT_REASON) } & 0xFFFF) as u32
}

/// The VM-instruction error number (valid after a VMfailValid).
///
/// # Safety
/// Ring 0, VMX-root, a current VMCS.
pub(super) unsafe fn vm_instruction_error() -> u64 {
    unsafe { vmread(VM_INSTRUCTION_ERROR) }
}

/// Length in bytes of the instruction that caused the exit (used by the
/// L2.1+ RIP-advance discipline).
///
/// # Safety
/// Ring 0, VMX-root, a current VMCS that has taken a VM-exit.
#[allow(dead_code)] // consumed by the L2.2 exit demultiplexer
pub(super) unsafe fn exit_instruction_len() -> u64 {
    unsafe { vmread(VM_EXIT_INSTRUCTION_LEN) }
}

/// The exit qualification (exit-reason-specific detail).
///
/// # Safety
/// Ring 0, VMX-root, a current VMCS that has taken a VM-exit.
#[allow(dead_code)] // consumed by the L2.1 EPT-violation handler
pub(super) unsafe fn exit_qualification() -> u64 {
    unsafe { vmread(EXIT_QUALIFICATION) }
}

/// The faulting guest-physical address (valid on EPT-violation/misconfig exits).
///
/// # Safety
/// Ring 0, VMX-root, a current VMCS that has taken a VM-exit.
#[allow(dead_code)] // consumed by the L2.1 EPT-violation handler
pub(super) unsafe fn guest_physical_address() -> u64 {
    unsafe { vmread(GUEST_PHYSICAL_ADDRESS) }
}
