//! L2.0 — VMX feature-enable + VMXON region (the "enter VMX-root" step).
//!
//! This module owns the privileged register/MSR primitives the rest of the
//! `vmx/` subtree builds on (CPUID, RDMSR/WRMSR, CRn read/write, segment and
//! descriptor-table readers) plus the actual VMX bring-up: probe VMX, configure
//! IA32_FEATURE_CONTROL, set CR4.VMXE, clamp CR0/CR4 to the VMX fixed MSRs, and
//! execute VMXON / VMXOFF. ALL of it is silicon-`unsafe`, confined here per the
//! framekernel rule (KERNEL-FOUNDATION-SPEC §1); the `kernel` crate stays
//! `#![forbid(unsafe_code)]` and reaches this only through the safe
//! `tb_hal::vmx_selftest()` facade.
//!
//! Verified facts (Intel SDM Vol 3C §24-26, Vol 4 Table 2-2):
//!  * CPUID.1:ECX.VMX = bit 5 advertises VMX.
//!  * IA32_FEATURE_CONTROL (MSR 0x3A): bit 0 = lock, bit 2 = "enable VMX outside
//!    SMX". If locked with bit 2 clear, the BIOS disabled VT-x and VMXON #GPs —
//!    so we SKIP. If unlocked, we set bit 0|bit 2 ourselves.
//!  * CR4.VMXE = bit 13 must be 1 to execute VMXON.
//!  * IA32_VMX_CR0_FIXED0/1 (0x486/0x487) and CR4_FIXED0/1 (0x488/0x489) give
//!    the bits that must be 1 / may be 1 in CR0/CR4 during VMX operation.
//!  * The VMXON region's first dword = IA32_VMX_BASIC[30:0] (the VMCS revision
//!    id), bit 31 = 0.

use core::arch::asm;
use core::arch::x86_64::__cpuid;
use core::ptr::write_volatile;

use super::{IA32_FEATURE_CONTROL, IA32_VMX_CR0_FIXED0, IA32_VMX_CR0_FIXED1};
use super::{IA32_VMX_CR4_FIXED0, IA32_VMX_CR4_FIXED1};

/// CR4.VMXE — bit 13 (Intel SDM Vol 3A §2.5; required for VMXON).
const CR4_VMXE: u64 = 1 << 13;

/// IA32_FEATURE_CONTROL bit 0 — lock bit (writes #GP once set).
const FC_LOCK: u64 = 1 << 0;

/// IA32_FEATURE_CONTROL bit 2 — "enable VMX outside SMX operation".
const FC_VMXON_OUTSIDE_SMX: u64 = 1 << 2;

// ---------------------------------------------------------------------------
// Low-level privileged primitives (shared by the whole vmx/ subtree).
// ---------------------------------------------------------------------------

/// CPUID leaf 1, ECX: returns the feature flags. `VMX = bit 5`. `__cpuid` is a
/// safe intrinsic for baseline x86_64 (CPUID is unprivileged + side-effect-free).
pub(super) fn cpuid1_ecx() -> u32 {
    __cpuid(1).ecx
}

/// `rdmsr` — read the 64-bit MSR selected by `msr` (EDX:EAX glued).
///
/// # Safety
/// Ring 0; `msr` must be implemented by the CPU (else #GP). Callers pass only
/// architectural VMX/EFER/segment-base MSRs.
pub(super) unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// `wrmsr` — write `val` to the 64-bit MSR selected by `msr` (EDX:EAX split).
///
/// # Safety
/// Ring 0; `msr`/`val` must be legal for the CPU (else #GP).
pub(super) unsafe fn wrmsr(msr: u32, val: u64) {
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") val as u32,
            in("edx") (val >> 32) as u32,
            options(nostack, preserves_flags),
        );
    }
}

/// Read CR0.
///
/// # Safety
/// Ring 0 control-register read; no side effects.
pub(super) unsafe fn read_cr0() -> u64 {
    let v: u64;
    unsafe { asm!("mov {}, cr0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Read CR3 (the live PML4 base + control bits).
///
/// # Safety
/// Ring 0 control-register read; no side effects.
pub(super) unsafe fn read_cr3() -> u64 {
    let v: u64;
    unsafe { asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Read CR4.
///
/// # Safety
/// Ring 0 control-register read; no side effects.
pub(super) unsafe fn read_cr4() -> u64 {
    let v: u64;
    unsafe { asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Write CR0.
///
/// # Safety
/// Ring 0; `val` must be a legal CR0 for the current mode (clearing PE/PG would
/// fault). Callers only ever OR-in VMX-fixed bits, never clear PE/PG.
pub(super) unsafe fn write_cr0(val: u64) {
    unsafe { asm!("mov cr0, {}", in(reg) val, options(nostack, preserves_flags)) };
}

/// Write CR4.
///
/// # Safety
/// Ring 0; `val` must be a legal CR4 (PAE etc. preserved). Callers only ever
/// OR-in VMXE/fixed bits or clear VMXE on teardown.
pub(super) unsafe fn write_cr4(val: u64) {
    unsafe { asm!("mov cr4, {}", in(reg) val, options(nostack, preserves_flags)) };
}

/// A descriptor-table register image (`sgdt`/`sidt` operand): 16-bit limit then
/// 64-bit linear base (Intel SDM Vol 3A §2.4; the m16&64 form).
#[repr(C, packed)]
pub(super) struct Dtr {
    /// Table byte-limit (size - 1).
    pub(super) limit: u16,
    /// Linear base address of the table.
    pub(super) base: u64,
}

/// Read the current code-segment selector (`mov reg, cs`).
///
/// # Safety
/// Ring 0; reads a segment register.
pub(super) unsafe fn read_cs() -> u16 {
    let s: u16;
    unsafe { asm!("mov {0:x}, cs", out(reg) s, options(nomem, nostack, preserves_flags)) };
    s
}

/// Read the current stack-segment selector.
///
/// # Safety
/// Ring 0.
pub(super) unsafe fn read_ss() -> u16 {
    let s: u16;
    unsafe { asm!("mov {0:x}, ss", out(reg) s, options(nomem, nostack, preserves_flags)) };
    s
}

/// Read the current data-segment (DS) selector.
///
/// # Safety
/// Ring 0.
pub(super) unsafe fn read_ds() -> u16 {
    let s: u16;
    unsafe { asm!("mov {0:x}, ds", out(reg) s, options(nomem, nostack, preserves_flags)) };
    s
}

/// Read the current ES selector.
///
/// # Safety
/// Ring 0.
pub(super) unsafe fn read_es() -> u16 {
    let s: u16;
    unsafe { asm!("mov {0:x}, es", out(reg) s, options(nomem, nostack, preserves_flags)) };
    s
}

/// Read the current FS selector.
///
/// # Safety
/// Ring 0.
pub(super) unsafe fn read_fs() -> u16 {
    let s: u16;
    unsafe { asm!("mov {0:x}, fs", out(reg) s, options(nomem, nostack, preserves_flags)) };
    s
}

/// Read the current GS selector.
///
/// # Safety
/// Ring 0.
pub(super) unsafe fn read_gs() -> u16 {
    let s: u16;
    unsafe { asm!("mov {0:x}, gs", out(reg) s, options(nomem, nostack, preserves_flags)) };
    s
}

/// Read the current task-register selector (`str`).
///
/// # Safety
/// Ring 0.
pub(super) unsafe fn read_tr() -> u16 {
    let s: u16;
    unsafe { asm!("str {0:x}", out(reg) s, options(nomem, nostack, preserves_flags)) };
    s
}

/// Read the live GDTR (base + limit) via `sgdt`.
///
/// # Safety
/// Ring 0.
pub(super) unsafe fn sgdt() -> Dtr {
    let mut d = Dtr { limit: 0, base: 0 };
    unsafe { asm!("sgdt [{}]", in(reg) &mut d, options(nostack, preserves_flags)) };
    d
}

/// Read the live IDTR (base + limit) via `sidt`.
///
/// # Safety
/// Ring 0.
pub(super) unsafe fn sidt() -> Dtr {
    let mut d = Dtr { limit: 0, base: 0 };
    unsafe { asm!("sidt [{}]", in(reg) &mut d, options(nostack, preserves_flags)) };
    d
}

// ---------------------------------------------------------------------------
// VMX bring-up.
// ---------------------------------------------------------------------------

/// Step 0a: is VMX advertised by CPUID? (CPUID.1:ECX.VMX, bit 5.)
pub(super) fn vmx_supported() -> bool {
    (cpuid1_ecx() & (1 << 5)) != 0
}

/// Step 0b: bring IA32_FEATURE_CONTROL into a state where VMXON is legal.
/// Returns `false` when the BIOS locked VT-x OFF (skip-gracefully case).
///
/// # Safety
/// Ring 0; only ever called after [`vmx_supported`] returned true.
pub(super) unsafe fn configure_feature_control() -> bool {
    let fc = unsafe { rdmsr(IA32_FEATURE_CONTROL) };
    if fc & FC_LOCK != 0 {
        // Locked: VMXON is only legal if "VMX outside SMX" was already enabled.
        return fc & FC_VMXON_OUTSIDE_SMX != 0;
    }
    // Unlocked: enable VMX-outside-SMX and take the lock.
    unsafe { wrmsr(IA32_FEATURE_CONTROL, fc | FC_LOCK | FC_VMXON_OUTSIDE_SMX) };
    true
}

/// Step 1+2: set CR4.VMXE, clamp CR0/CR4 to the VMX fixed MSRs, stamp the VMCS
/// revision id into `region_pa`'s dword0, and execute VMXON(region_pa). Returns
/// `true` on success (CF=ZF=0).
///
/// # Safety
/// Ring 0; `region_pa` is a 4 KiB-aligned, identity-mapped frame this code owns.
pub(super) unsafe fn enable_and_vmxon(region_pa: u64, rev_id: u32) -> bool {
    unsafe {
        // Clamp CR0 to its VMX-legal value (forces e.g. CR0.NE; never clears
        // PE/PG since they are in FIXED1's "may be 1" set and already set).
        let cr0 = read_cr0();
        let cr0_f0 = rdmsr(IA32_VMX_CR0_FIXED0);
        let cr0_f1 = rdmsr(IA32_VMX_CR0_FIXED1);
        write_cr0((cr0 | cr0_f0) & cr0_f1);

        // Set CR4.VMXE and clamp CR4 to its VMX-legal value.
        let cr4 = read_cr4() | CR4_VMXE;
        let cr4_f0 = rdmsr(IA32_VMX_CR4_FIXED0);
        let cr4_f1 = rdmsr(IA32_VMX_CR4_FIXED1);
        write_cr4((cr4 | cr4_f0) & cr4_f1);

        // Stamp the revision id (bit 31 = 0) into the VMXON region.
        write_volatile(region_pa as *mut u32, rev_id & 0x7FFF_FFFF);

        // VMXON with the region's PHYSICAL address (== VA in the identity map).
        let p = region_pa;
        let ok: u8;
        asm!(
            "vmxon [{ptr}]",
            "seta {ok}",
            ptr = in(reg) &p,
            ok = out(reg_byte) ok,
            options(nostack),
        );
        ok != 0
    }
}

/// Leave VMX operation (`vmxoff`).
///
/// # Safety
/// Ring 0; in VMX-root operation (a prior VMXON succeeded).
pub(super) unsafe fn vmxoff() {
    unsafe { asm!("vmxoff", options(nostack)) };
}

/// Teardown: restore CR4 to `original_cr4` (clearing the VMXE bit we set).
///
/// # Safety
/// Ring 0; after VMXOFF.
pub(super) unsafe fn restore_cr4(original_cr4: u64) {
    unsafe { write_cr4(original_cr4 & !CR4_VMXE) };
}
