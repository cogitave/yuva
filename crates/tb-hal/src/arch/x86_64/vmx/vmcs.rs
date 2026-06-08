//! L2.0 — VMCS region management + typed VMREAD / VMWRITE wrappers.
//!
//! A VMCS is a per-vCPU 4 KiB region whose dword0 holds the VMCS revision id.
//! `VMCLEAR(phys)` initialises it and marks it not-current; `VMPTRLD(phys)`
//! makes it the *current* VMCS, after which `VMREAD`/`VMWRITE` (which take no
//! address — they implicitly target the current VMCS) read/write its fields by
//! their architectural encodings (Intel SDM Vol 3C Appendix B).
//!
//! All four instructions set CF (VMfailInvalid) or ZF (VMfailValid) on failure
//! and leave both clear on success; the wrappers report that via `seta`.

use core::arch::asm;
use core::ptr::write_volatile;

/// Initialise `vmcs_pa` (stamp the revision id), `VMCLEAR` it, then `VMPTRLD`
/// it so it becomes the current VMCS. Returns `true` iff both VMX instructions
/// succeeded.
///
/// # Safety
/// Ring 0, in VMX-root operation; `vmcs_pa` is a 4 KiB-aligned identity-mapped
/// frame this code owns.
pub(super) unsafe fn clear_and_load(vmcs_pa: u64, rev_id: u32) -> bool {
    unsafe {
        // VMCS revision id in dword0 (bit 31 = 0: this is not a shadow VMCS).
        write_volatile(vmcs_pa as *mut u32, rev_id & 0x7FFF_FFFF);
        vmclear(vmcs_pa) && vmptrld(vmcs_pa)
    }
}

/// `VMCLEAR(phys)` — ensure `vmcs_pa` is inactive/clear and not current.
///
/// # Safety
/// Ring 0, VMX-root; `vmcs_pa` is an owned 4 KiB-aligned frame.
unsafe fn vmclear(vmcs_pa: u64) -> bool {
    let p = vmcs_pa;
    let ok: u8;
    unsafe {
        asm!(
            "vmclear [{ptr}]",
            "seta {ok}",
            ptr = in(reg) &p,
            ok = out(reg_byte) ok,
            options(nostack),
        );
    }
    ok != 0
}

/// `VMPTRLD(phys)` — load `vmcs_pa` as the current VMCS.
///
/// # Safety
/// Ring 0, VMX-root; `vmcs_pa` was just VMCLEAR'd.
unsafe fn vmptrld(vmcs_pa: u64) -> bool {
    let p = vmcs_pa;
    let ok: u8;
    unsafe {
        asm!(
            "vmptrld [{ptr}]",
            "seta {ok}",
            ptr = in(reg) &p,
            ok = out(reg_byte) ok,
            options(nostack),
        );
    }
    ok != 0
}

/// `VMWRITE field, value` into the current VMCS. Returns `true` on success.
///
/// # Safety
/// Ring 0, VMX-root, a current VMCS is loaded; `field` is a real encoding.
pub(super) unsafe fn vmwrite(field: u64, value: u64) -> bool {
    let ok: u8;
    unsafe {
        asm!(
            "vmwrite {f}, {v}",
            "seta {ok}",
            f = in(reg) field,
            v = in(reg) value,
            ok = out(reg_byte) ok,
            options(nostack, nomem),
        );
    }
    ok != 0
}

/// `VMREAD field` from the current VMCS. Reads of valid fields on a current
/// VMCS do not fail, so this returns the raw value directly.
///
/// # Safety
/// Ring 0, VMX-root, a current VMCS is loaded; `field` is a real encoding.
pub(super) unsafe fn vmread(field: u64) -> u64 {
    let v: u64;
    unsafe {
        asm!(
            "vmread {v}, {f}",
            v = out(reg) v,
            f = in(reg) field,
            options(nostack, nomem),
        );
    }
    v
}
