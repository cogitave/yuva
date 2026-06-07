//! Architecture seam.
//!
//! tb-vmm targets **x86_64** today with a clean arch boundary so **aarch64 is a
//! documented follow-up** (it would add `arch/aarch64/boot.rs` implementing the
//! `KVM_ARM_VCPU_INIT` + `KVM_SET_ONE_REG` path described in
//! docs/SOVEREIGNTY-ROADMAP.md §7, and register itself in [`setup`]).
//!
//! Everything arch-specific about turning a loaded kernel into a runnable vCPU
//! (page tables, GDT, the boot-info block, and the long-mode `KVM_SET_SREGS`/
//! `KVM_SET_REGS`) lives behind the single [`setup`] entry point.

use kvm_ioctls::{Kvm, VcpuFd, VmFd};
use vm_memory::GuestMemoryMmap;

use crate::error::VmmError;
use crate::memory::MemRegion;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

/// Arch-neutral inputs the boot configurator needs.
pub struct BootParams<'a> {
    /// Guest physical address to begin executing at (the kernel's tb-boot entry).
    pub entry_point: u64,
    /// The guest's logical memory map, reported to the kernel via tb-boot.
    pub mem_regions: &'a [MemRegion],
    /// The kernel command line.
    pub cmdline: &'a str,
}

/// Configure the VM + vCPU for a direct boot of `params.entry_point`.
///
/// Writes the arch boot structures into guest RAM and programs the vCPU's
/// special + general registers. After this returns the vCPU is ready for its
/// first `KVM_RUN`.
pub fn setup(
    kvm: &Kvm,
    vm: &VmFd,
    vcpu: &VcpuFd,
    mem: &GuestMemoryMmap,
    params: &BootParams,
) -> Result<(), VmmError> {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::boot::setup(kvm, vm, vcpu, mem, params)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (kvm, vm, vcpu, mem, params);
        Err(VmmError::Unsupported(
            "tb-vmm host arch: only x86_64 is implemented (aarch64 is a documented follow-up)",
        ))
    }
}
