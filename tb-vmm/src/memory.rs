//! Guest RAM management: a `vm-memory` [`GuestMemoryMmap`] (anonymous mmap in
//! the VMM's address space) registered with KVM via `KVM_SET_USER_MEMORY_REGION`.
//!
//! This module owns tb-vmm's single intentional `unsafe` block — the FFI
//! handoff of the host mapping to the kernel. It is isolated and commented per
//! the SOVEREIGNTY-ROADMAP §3 rule that tb-vmm's `unsafe` stays small + audited.
//!
//! Sources:
//! * `KVM_SET_USER_MEMORY_REGION` / `kvm_userspace_memory_region`:
//!   <https://docs.kernel.org/virt/kvm/api.html>
//! * `VmFd::set_user_memory_region` (unsafe; "no guarantee userspace_addr points
//!   to a valid memory region, nor the memory region lives as long as the kernel
//!   needs it to"): docs.rs/kvm-ioctls `VmFd`.
//! * `GuestMemoryMmap::from_ranges`: docs.rs/vm-memory.

use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::VmFd;
use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

use crate::error::VmmError;

/// Logical kind of a guest physical memory region, as reported to the guest in
/// the tb-boot [`tb_boot::TbMemRegion`] array (`kind`: Ram=1, Reserved=2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum MemKind {
    /// Usable RAM.
    Ram = 1,
    /// Reserved (not usable by the guest allocator). Not emitted yet — the M0-M4
    /// boot hands the guest a single Ram region — but the tb-boot ABI defines it,
    /// so the value is fixed here for when tb-vmm carves out reserved windows
    /// (framebuffer, MMIO holes, ACPI-equivalent tables).
    #[allow(dead_code)]
    Reserved = 2,
}

/// One contiguous guest physical memory region in the logical map handed to the
/// guest. (Distinct from the KVM memslot list, though for a single-region VM
/// they coincide.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemRegion {
    /// Guest physical base address.
    pub base: u64,
    /// Length in bytes.
    pub len: u64,
    /// Region kind reported to the guest.
    pub kind: MemKind,
}

/// Guest RAM: the backing `GuestMemoryMmap` plus the logical region map.
pub struct GuestRam {
    inner: GuestMemoryMmap,
    regions: Vec<MemRegion>,
}

impl GuestRam {
    /// Allocate `size_bytes` of guest RAM as one contiguous region based at
    /// guest physical 0. The mapping is anonymous and zero-initialised, which
    /// satisfies the kernel's assumption that `.bss` / page-table frames start
    /// zeroed.
    pub fn new(size_bytes: u64) -> Result<Self, VmmError> {
        let size = usize::try_from(size_bytes)
            .map_err(|_| VmmError::Config("memory size too large for this host".into()))?;
        let inner = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), size)])
            .map_err(|e| VmmError::GuestMemoryCreate(e.to_string()))?;
        let regions = vec![MemRegion {
            base: 0,
            len: size_bytes,
            kind: MemKind::Ram,
        }];
        Ok(Self { inner, regions })
    }

    /// The backing guest memory (for the loader + boot-structure writes).
    pub fn inner(&self) -> &GuestMemoryMmap {
        &self.inner
    }

    /// The logical region map reported to the guest via tb-boot.
    pub fn regions(&self) -> &[MemRegion] {
        &self.regions
    }

    /// Register every backing region with KVM as a userspace memory slot.
    ///
    /// Must be called once, after `create_vm` and before the first `KVM_RUN`.
    /// `self` must outlive the [`VmFd`]: the mappings stay valid only while this
    /// `GuestRam` is alive (enforced by [`crate::vmm::Vmm`] owning both).
    pub fn register_with_kvm(&self, vm: &VmFd) -> Result<(), VmmError> {
        for (slot, region) in self.inner.iter().enumerate() {
            let guest_phys_addr = region.start_addr().raw_value();
            let memory_size = region.len();
            // Host address of the region's base byte. For a `GuestMemoryMmap`
            // this is the mmap base, which is what KVM needs as userspace_addr.
            let host_addr = self.inner.get_host_address(region.start_addr())?;

            let mem_region = kvm_userspace_memory_region {
                slot: slot as u32,
                flags: 0,
                guest_phys_addr,
                memory_size,
                userspace_addr: host_addr as u64,
            };

            // SAFETY: `host_addr` is the base of a live anonymous mmap owned by
            // `self.inner`, of exactly `memory_size` bytes (vm-memory invariant).
            // `self` (and therefore the mapping) outlives `vm` because
            // `crate::vmm::Vmm` holds both and drops the VM fd first. The regions
            // come from a single non-overlapping `from_ranges` allocation, so the
            // "regions are not overlapping" precondition holds. This is the one
            // audited FFI handoff that places tb-vmm outside forbid(unsafe).
            unsafe {
                vm.set_user_memory_region(mem_region)?;
            }
        }
        Ok(())
    }
}
