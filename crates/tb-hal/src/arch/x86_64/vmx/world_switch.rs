//! L2.0 — the host<->guest world switch (`global_asm!`).
//!
//! The CPU does NOT save/restore the general-purpose registers (RAX..R15)
//! across a VM entry/exit — only RSP/RIP/RFLAGS/segments/control-regs come from
//! the VMCS host area. So the launching routine must itself preserve the host
//! GPRs it cares about (the callee-saved set, per the System V ABI) around the
//! switch, because the guest will clobber them.
//!
//! The single-shot launch trick: write HOST_RSP = the current RSP and HOST_RIP
//! = a label immediately past `vmlaunch`, then execute `vmlaunch`. Control
//! reaches that label by EITHER of two paths, which share an identical stack:
//!
//!   * `vmlaunch` FAILED  -> falls through to the label with CF or ZF set
//!     (VMfailInvalid / VMfailValid).
//!   * `vmlaunch` SUCCEEDED, the guest ran one instruction and VM-exited -> the
//!     CPU reloads HOST_RIP (= the label) and HOST_RSP and resumes there with
//!     RFLAGS cleared (CF = ZF = 0).
//!
//! Capturing RFLAGS at the label distinguishes the two. The function returns
//! 0 = "a VM-exit was caught" (the world switch worked) or 1 = "vmlaunch
//! failed" (read VM-instruction-error to learn why). After it returns the VMCS
//! is still current, so the caller VMREADs the exit reason in safe-ish Rust.
//!
//! HOST_RSP encoding = 0x6C14, HOST_RIP = 0x6C16 (Intel SDM Vol 3C App B.4.4).

use core::arch::global_asm;

global_asm!(
    ".text",
    ".globl __yuva_vmx_launch",
    "__yuva_vmx_launch:",
    // Preserve the host callee-saved registers (the guest will trash GPRs).
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    // HOST_RSP = current RSP (so the VM-exit returns onto this very stack).
    "mov rax, 0x6C14",
    "vmwrite rax, rsp",
    // HOST_RIP = the resume label just past vmlaunch.
    "lea rax, [rip + 2f]",
    "mov rdx, 0x6C16",
    "vmwrite rdx, rax",
    "vmlaunch",
    // Reached on BOTH the vmlaunch-failure fall-through AND the VM-exit return.
    "2:",
    "pushfq",
    "pop rax", // rax = RFLAGS (CF|ZF set => failure; both clear => clean exit)
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    "and rax, 0x41", // CF (bit0) | ZF (bit6)
    "setnz al",      // al = 1 iff vmlaunch failed
    "movzx rax, al", // return 0 (exit caught) or 1 (launch failed)
    "ret",
);

extern "C" {
    fn __yuva_vmx_launch() -> u64;
}

/// Execute the world switch: launch the guest, catch its (single) VM-exit, and
/// return to the caller. Returns `true` iff a VM-exit was caught (the world
/// switch worked); `false` iff `vmlaunch` itself failed.
///
/// # Safety
/// Ring 0, VMX-root, the current VMCS fully programmed (host + guest + controls
/// + EPTP). The guest's one instruction must be an unconditional-exit
/// instruction (CPUID) so exactly one exit occurs.
pub(super) unsafe fn launch() -> bool {
    unsafe { __yuva_vmx_launch() == 0 }
}
