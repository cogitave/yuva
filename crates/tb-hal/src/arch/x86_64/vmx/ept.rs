//! L2.0 — the second-stage (EPT) identity map + the guest's own CR3 hierarchy.
//!
//! Two 4-level identity maps over `[0, 1 GiB)` with 2 MiB leaves, each three
//! frames (PML4 + PDPT + one PD of 512 large leaves):
//!
//!  * EPT (`build_ept_identity_1gib`): translates guest-physical -> host-physical
//!    identity for all of low RAM, so every frame this self-test allocates (the
//!    guest code page AND the guest's own page-table frames, which the CPU walks
//!    as guest-physical addresses) resolves to itself. Leaves are R|W|X with EPT
//!    memory-type WB. EPTP = PML4 | WB(6) | (walk-length-1 = 3).
//!  * Guest paging (`build_guest_pml4_identity_1gib`): the guest's CR3 hierarchy,
//!    translating guest-linear -> guest-physical identity over the same span, so
//!    a guest RIP placed at a host frame's address fetches that frame. Standard
//!    4-level paging entries (P|RW, PS at the 2 MiB leaf).
//!
//! Because the kernel boot map makes PA == VA for low RAM, a frame's `frame_alloc`
//! PA is also its writable VA, so the tables are filled through that identity VA.
//!
//! EPT entry bits — Intel SDM Vol 3C §28.2.2, Table 28-1/28-3:
//!  bit0 R, bit1 W, bit2 X, bits5:3 = EPT memory type, bit7 = "maps a page"
//!  (large leaf). Non-leaf entries carry only R|W|X + the child address.

use core::ptr::write_volatile;

use super::vmxon::rdmsr;
use super::IA32_VMX_EPT_VPID_CAP;

/// EPT read|write|execute (non-leaf and leaf permission bits).
const EPT_RWX: u64 = 0b111;
/// EPT 2 MiB leaf: R|W|X | memory-type WB(6)<<3 | "maps page"(bit7).
const EPT_LEAF_2MB: u64 = EPT_RWX | (6 << 3) | (1 << 7);

/// Standard paging entry: Present|R/W.
const PTE_P_RW: u64 = 0b11;
/// Standard paging 2 MiB leaf: Present|R/W|PS(bit7).
const PDE_LEAF_2MB: u64 = PTE_P_RW | (1 << 7);

/// A built EPT identity map: the EPTP to VMWRITE plus the three table frames
/// (kept so the caller can free them on teardown).
pub(super) struct EptMap {
    /// The EPT pointer (PML4 base | WB | walk-length-1=3) for VMCS field EPTP.
    pub(super) eptp: u64,
    /// EPT PML4 frame PA.
    pub(super) pml4: u64,
    /// EPT PDPT frame PA.
    pub(super) pdpt: u64,
    /// EPT PD frame PA.
    pub(super) pd: u64,
}

/// A built guest CR3 hierarchy: the value for GUEST_CR3 plus its three frames.
pub(super) struct GuestPaging {
    /// Guest CR3 value (the guest PML4 base PA).
    pub(super) cr3: u64,
    /// Guest PML4 frame PA.
    pub(super) pml4: u64,
    /// Guest PDPT frame PA.
    pub(super) pdpt: u64,
    /// Guest PD frame PA.
    pub(super) pd: u64,
}

/// Zero a freshly-allocated 4 KiB table frame through its identity VA.
///
/// # Safety
/// `pa` is a 4 KiB-aligned, identity-mapped frame this code exclusively owns.
unsafe fn zero_frame(pa: u64) {
    let p = pa as *mut u64;
    let mut i = 0usize;
    while i < 512 {
        unsafe { write_volatile(p.add(i), 0) };
        i += 1;
    }
}

/// Write entry `idx` of the table at frame `pa`.
///
/// # Safety
/// `pa` is an owned identity-mapped table frame; `idx < 512`.
unsafe fn put(pa: u64, idx: usize, val: u64) {
    unsafe { write_volatile((pa as *mut u64).add(idx), val) };
}

/// Build the EPT identity map over `[0, 1 GiB)`. `None` on frame OOM (with any
/// partial frames left allocated — the self-test treats OOM as a hard skip).
///
/// # Safety
/// Ring 0; pulls three M6 frames and fills them through their identity VAs.
pub(super) unsafe fn build_ept_identity_1gib() -> Option<EptMap> {
    let pml4 = crate::frame_alloc()?;
    let pdpt = crate::frame_alloc()?;
    let pd = crate::frame_alloc()?;
    unsafe {
        zero_frame(pml4);
        zero_frame(pdpt);
        zero_frame(pd);
        put(pml4, 0, pdpt | EPT_RWX);
        put(pdpt, 0, pd | EPT_RWX);
        let mut i = 0u64;
        while i < 512 {
            put(pd, i as usize, (i << 21) | EPT_LEAF_2MB);
            i += 1;
        }
    }
    // EPTP: PML4 base | memory-type WB(6) | (page-walk-length - 1 = 3) << 3.
    let eptp = pml4 | 6 | (3 << 3);
    Some(EptMap { eptp, pml4, pdpt, pd })
}

/// Build the guest's own CR3 hierarchy: an identity map of guest-linear ->
/// guest-physical over `[0, 1 GiB)`. `None` on frame OOM.
///
/// # Safety
/// Ring 0; pulls three M6 frames and fills them through their identity VAs.
pub(super) unsafe fn build_guest_pml4_identity_1gib() -> Option<GuestPaging> {
    let pml4 = crate::frame_alloc()?;
    let pdpt = crate::frame_alloc()?;
    let pd = crate::frame_alloc()?;
    unsafe {
        zero_frame(pml4);
        zero_frame(pdpt);
        zero_frame(pd);
        put(pml4, 0, pdpt | PTE_P_RW);
        put(pdpt, 0, pd | PTE_P_RW);
        let mut i = 0u64;
        while i < 512 {
            put(pd, i as usize, (i << 21) | PDE_LEAF_2MB);
            i += 1;
        }
    }
    Some(GuestPaging { cr3: pml4, pml4, pdpt, pd })
}

/// Best-effort `INVEPT(single-context, eptp)` after building the tables. A
/// freshly-built EPTP that has never been launched has nothing cached, so this
/// is belt-and-suspenders; it is GATED on IA32_VMX_EPT_VPID_CAP advertising
/// INVEPT + single-context support so it can never #UD on a CPU/emulator that
/// lacks it.
///
/// # Safety
/// Ring 0, VMX-root.
pub(super) unsafe fn invept_single_context(eptp: u64) {
    let cap = unsafe { rdmsr(IA32_VMX_EPT_VPID_CAP) };
    // bit 20 = INVEPT supported, bit 25 = single-context INVEPT supported.
    if cap & (1 << 20) == 0 || cap & (1 << 25) == 0 {
        return;
    }
    #[repr(C)]
    struct Desc {
        eptp: u64,
        rsvd: u64,
    }
    let d = Desc { eptp, rsvd: 0 };
    let typ: u64 = 1; // single-context
    unsafe {
        core::arch::asm!(
            "invept {t}, [{d}]",
            t = in(reg) typ,
            d = in(reg) &d,
            options(nostack),
        );
    }
}
