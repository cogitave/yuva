//! L2.0 — VMX-root + 1-instruction nested guest + caught VM-exit.
//!
//! The first rung of the L2 sovereignty track (`tb-core`, the from-scratch
//! Type-1 microhypervisor): the smallest step that proves TABOS *is* the
//! hypervisor. Running inside the already-booted TABOS guest, this subtree does
//! the full Intel VMX-root bring-up — VMXON, a minimal VMCS, an EPT identity
//! map, a one-instruction (`CPUID`) long-mode guest, the host<->guest world
//! switch, catching the guest's VM-exit, and VMXOFF — then reports the outcome
//! to the `#![forbid(unsafe_code)]` kernel through the safe
//! [`crate::vmx_selftest`] facade.
//!
//! ALL the new silicon-`unsafe` lives in this `arch/x86_64/vmx/` subtree
//! (KERNEL-FOUNDATION-SPEC §1 / SOVEREIGNTY-L2-ROADMAP §10), mirroring how the
//! existing `arch/x86_64/{boot,mmu,trap,user,timer}.rs` confine the kernel's
//! other unsafe. Submodules: [`vmxon`] (feature-enable + register primitives +
//! VMXON), [`vmcs`] (region + VMREAD/VMWRITE), [`controls`] (the control-MSR
//! adjust algorithm), [`ept`] (stage-2 + guest CR3 identity maps),
//! [`world_switch`] (the `global_asm!` launch), [`exit`] (raw exit readout).
//!
//! GRACEFUL SKIP: if CPUID does not advertise VMX, or the BIOS locked VT-x off,
//! NO VMX instruction is executed and the self-test returns
//! [`crate::VmxProof::Unavailable`] — the TCG (`qemu64`) case, mirroring the
//! `vmm-boot` `KVM_OK` allow-skip discipline. The real world-switch proof is
//! exercised wherever VMX is exposed (a KVM + nested-VMX lane).
//!
//! The key enabler that makes this implementable with ZERO new platform code:
//! the kernel boot map identity-maps `[0, 1 GiB)` with PA == VA, so every M6
//! `frame_alloc` PA is directly writable AND directly usable as the physical
//! address VMX/EPT instructions demand. All field encodings below are quoted
//! from Intel SDM Vol 3C Appendix B.

use core::arch::asm;
use core::ptr::{read_volatile, write_volatile};

pub mod controls;
pub mod ept;
pub mod exit;
pub mod vmcs;
pub mod vmxon;
pub mod world_switch;

// ---------------------------------------------------------------------------
// MSR addresses (Intel SDM Vol 4 Table 2-2 + Vol 3D Appendix A).
// ---------------------------------------------------------------------------

/// IA32_FEATURE_CONTROL — VMX enable/lock.
pub(super) const IA32_FEATURE_CONTROL: u32 = 0x3A;
/// IA32_VMX_BASIC — VMCS revision id (bits 30:0) + TRUE-controls flag (bit 55).
pub(super) const IA32_VMX_BASIC: u32 = 0x480;
/// IA32_VMX_PINBASED_CTLS.
pub(super) const IA32_VMX_PINBASED_CTLS: u32 = 0x481;
/// IA32_VMX_PROCBASED_CTLS (primary).
pub(super) const IA32_VMX_PROCBASED_CTLS: u32 = 0x482;
/// IA32_VMX_EXIT_CTLS.
pub(super) const IA32_VMX_EXIT_CTLS: u32 = 0x483;
/// IA32_VMX_ENTRY_CTLS.
pub(super) const IA32_VMX_ENTRY_CTLS: u32 = 0x484;
/// IA32_VMX_CR0_FIXED0 — CR0 bits that MUST be 1 in VMX operation.
pub(super) const IA32_VMX_CR0_FIXED0: u32 = 0x486;
/// IA32_VMX_CR0_FIXED1 — CR0 bits that MAY be 1 in VMX operation.
pub(super) const IA32_VMX_CR0_FIXED1: u32 = 0x487;
/// IA32_VMX_CR4_FIXED0 — CR4 bits that MUST be 1 (incl. VMXE).
pub(super) const IA32_VMX_CR4_FIXED0: u32 = 0x488;
/// IA32_VMX_CR4_FIXED1 — CR4 bits that MAY be 1.
pub(super) const IA32_VMX_CR4_FIXED1: u32 = 0x489;
/// IA32_VMX_PROCBASED_CTLS2 (secondary).
pub(super) const IA32_VMX_PROCBASED_CTLS2: u32 = 0x48B;
/// IA32_VMX_EPT_VPID_CAP — EPT/VPID capability bits (INVEPT support etc.).
pub(super) const IA32_VMX_EPT_VPID_CAP: u32 = 0x48C;
/// IA32_VMX_TRUE_PINBASED_CTLS.
pub(super) const IA32_VMX_TRUE_PINBASED_CTLS: u32 = 0x48D;
/// IA32_VMX_TRUE_PROCBASED_CTLS.
pub(super) const IA32_VMX_TRUE_PROCBASED_CTLS: u32 = 0x48E;
/// IA32_VMX_TRUE_EXIT_CTLS.
pub(super) const IA32_VMX_TRUE_EXIT_CTLS: u32 = 0x48F;
/// IA32_VMX_TRUE_ENTRY_CTLS.
pub(super) const IA32_VMX_TRUE_ENTRY_CTLS: u32 = 0x490;
/// IA32_EFER.
const IA32_EFER: u32 = 0xC000_0080;
/// IA32_FS_BASE.
const IA32_FS_BASE: u32 = 0xC000_0100;
/// IA32_GS_BASE.
const IA32_GS_BASE: u32 = 0xC000_0101;
/// IA32_SYSENTER_CS.
const IA32_SYSENTER_CS: u32 = 0x174;
/// IA32_SYSENTER_ESP.
const IA32_SYSENTER_ESP: u32 = 0x175;
/// IA32_SYSENTER_EIP.
const IA32_SYSENTER_EIP: u32 = 0x176;

// ---------------------------------------------------------------------------
// VMCS field encodings (Intel SDM Vol 3C Appendix B).
// ---------------------------------------------------------------------------

// 16-bit guest-state selectors.
const GUEST_ES_SELECTOR: u64 = 0x0800;
const GUEST_CS_SELECTOR: u64 = 0x0802;
const GUEST_SS_SELECTOR: u64 = 0x0804;
const GUEST_DS_SELECTOR: u64 = 0x0806;
const GUEST_FS_SELECTOR: u64 = 0x0808;
const GUEST_GS_SELECTOR: u64 = 0x080A;
const GUEST_LDTR_SELECTOR: u64 = 0x080C;
const GUEST_TR_SELECTOR: u64 = 0x080E;

// 16-bit host-state selectors.
const HOST_ES_SELECTOR: u64 = 0x0C00;
const HOST_CS_SELECTOR: u64 = 0x0C02;
const HOST_SS_SELECTOR: u64 = 0x0C04;
const HOST_DS_SELECTOR: u64 = 0x0C06;
const HOST_FS_SELECTOR: u64 = 0x0C08;
const HOST_GS_SELECTOR: u64 = 0x0C0A;
const HOST_TR_SELECTOR: u64 = 0x0C0C;

// 64-bit control fields.
const VMCS_LINK_POINTER: u64 = 0x2800;
const EPT_POINTER: u64 = 0x201A;
const GUEST_IA32_DEBUGCTL: u64 = 0x2802;
const GUEST_IA32_EFER: u64 = 0x2806;
const HOST_IA32_EFER: u64 = 0x2C02;

// 32-bit control fields.
const PIN_BASED_VM_EXEC_CONTROL: u64 = 0x4000;
const PRIMARY_PROC_BASED_VM_EXEC_CONTROL: u64 = 0x4002;
const EXCEPTION_BITMAP: u64 = 0x4004;
const PAGE_FAULT_ERROR_CODE_MASK: u64 = 0x4006;
const PAGE_FAULT_ERROR_CODE_MATCH: u64 = 0x4008;
const CR3_TARGET_COUNT: u64 = 0x400A;
const VM_EXIT_CONTROLS: u64 = 0x400C;
const VM_EXIT_MSR_STORE_COUNT: u64 = 0x400E;
const VM_EXIT_MSR_LOAD_COUNT: u64 = 0x4010;
const VM_ENTRY_CONTROLS: u64 = 0x4012;
const VM_ENTRY_MSR_LOAD_COUNT: u64 = 0x4014;
const VM_ENTRY_INTR_INFO_FIELD: u64 = 0x4016;
const SECONDARY_PROC_BASED_VM_EXEC_CONTROL: u64 = 0x401E;

// 32-bit guest-state fields.
const GUEST_ES_LIMIT: u64 = 0x4800;
const GUEST_CS_LIMIT: u64 = 0x4802;
const GUEST_SS_LIMIT: u64 = 0x4804;
const GUEST_DS_LIMIT: u64 = 0x4806;
const GUEST_FS_LIMIT: u64 = 0x4808;
const GUEST_GS_LIMIT: u64 = 0x480A;
const GUEST_LDTR_LIMIT: u64 = 0x480C;
const GUEST_TR_LIMIT: u64 = 0x480E;
const GUEST_GDTR_LIMIT: u64 = 0x4810;
const GUEST_IDTR_LIMIT: u64 = 0x4812;
const GUEST_ES_ACCESS_RIGHTS: u64 = 0x4814;
const GUEST_CS_ACCESS_RIGHTS: u64 = 0x4816;
const GUEST_SS_ACCESS_RIGHTS: u64 = 0x4818;
const GUEST_DS_ACCESS_RIGHTS: u64 = 0x481A;
const GUEST_FS_ACCESS_RIGHTS: u64 = 0x481C;
const GUEST_GS_ACCESS_RIGHTS: u64 = 0x481E;
const GUEST_LDTR_ACCESS_RIGHTS: u64 = 0x4820;
const GUEST_TR_ACCESS_RIGHTS: u64 = 0x4822;
const GUEST_INTERRUPTIBILITY_STATE: u64 = 0x4824;
const GUEST_ACTIVITY_STATE: u64 = 0x4826;
const GUEST_SYSENTER_CS: u64 = 0x482A;

// 32-bit host-state field.
const HOST_IA32_SYSENTER_CS: u64 = 0x4C00;

// Natural-width control fields.
const CR0_GUEST_HOST_MASK: u64 = 0x6000;
const CR4_GUEST_HOST_MASK: u64 = 0x6002;
const CR0_READ_SHADOW: u64 = 0x6004;
const CR4_READ_SHADOW: u64 = 0x6006;

// Natural-width guest-state fields.
const GUEST_CR0: u64 = 0x6800;
const GUEST_CR3: u64 = 0x6802;
const GUEST_CR4: u64 = 0x6804;
const GUEST_ES_BASE: u64 = 0x6806;
const GUEST_CS_BASE: u64 = 0x6808;
const GUEST_SS_BASE: u64 = 0x680A;
const GUEST_DS_BASE: u64 = 0x680C;
const GUEST_FS_BASE: u64 = 0x680E;
const GUEST_GS_BASE: u64 = 0x6810;
const GUEST_LDTR_BASE: u64 = 0x6812;
const GUEST_TR_BASE: u64 = 0x6814;
const GUEST_GDTR_BASE: u64 = 0x6816;
const GUEST_IDTR_BASE: u64 = 0x6818;
const GUEST_DR7: u64 = 0x681A;
const GUEST_RSP: u64 = 0x681C;
const GUEST_RIP: u64 = 0x681E;
const GUEST_RFLAGS: u64 = 0x6820;
const GUEST_PENDING_DBG_EXCEPTIONS: u64 = 0x6822;
const GUEST_SYSENTER_ESP: u64 = 0x6824;
const GUEST_SYSENTER_EIP: u64 = 0x6826;

// Natural-width host-state fields.
const HOST_CR0: u64 = 0x6C00;
const HOST_CR3: u64 = 0x6C02;
const HOST_CR4: u64 = 0x6C04;
const HOST_FS_BASE: u64 = 0x6C06;
const HOST_GS_BASE: u64 = 0x6C08;
const HOST_TR_BASE: u64 = 0x6C0A;
const HOST_GDTR_BASE: u64 = 0x6C0C;
const HOST_IDTR_BASE: u64 = 0x6C0E;
const HOST_IA32_SYSENTER_ESP: u64 = 0x6C10;
const HOST_IA32_SYSENTER_EIP: u64 = 0x6C12;

// ---------------------------------------------------------------------------
// Guest segment access-rights constants (Intel SDM Vol 3C Table 24-2 format:
// type[3:0] | S[4] | DPL[6:5] | P[7] | AVL[12] | L[13] | D/B[14] | G[15] |
// Unusable[16]).
// ---------------------------------------------------------------------------

/// 64-bit code segment: type=0xB (exec/read, accessed), S=1, P=1, L=1, G=1.
const AR_CODE64: u64 = 0xA09B;
/// Data segment: type=0x3 (read/write, accessed), S=1, P=1, D/B=1, G=1.
const AR_DATA: u64 = 0xC093;
/// 64-bit busy TSS: type=0xB, S=0, P=1.
const AR_TSS64: u64 = 0x008B;
/// Unusable segment marker (bit 16).
const AR_UNUSABLE: u64 = 0x1_0000;

// ---------------------------------------------------------------------------
// Self-test driver.
// ---------------------------------------------------------------------------

/// L2.0 self-test: VMXON -> minimal VMCS -> EPT -> 1-`CPUID` long-mode guest ->
/// VMLAUNCH -> catch the VM-exit -> VMXOFF. Returns the proof outcome for the
/// kernel to render. Skips gracefully (no VMX instruction executed) when VMX is
/// absent or BIOS-locked.
pub fn vmx_selftest() -> crate::VmxProof {
    use crate::VmxProof;

    // Step 0a: probe. No VMX instruction is touched on the skip path.
    if !vmxon::vmx_supported() {
        return VmxProof::Unavailable;
    }

    // SAFETY: from here on this is the silicon-unsafe VMX bring-up. The whole
    // sequence runs in ring 0 with interrupts masked (a timer IRQ must not race
    // the VMX critical section or the world switch); the M6 frames are owned,
    // identity-mapped (PA == VA) and freed on teardown; VMXOFF + CR4 restore
    // always run before returning on the in-VMX paths.
    unsafe {
        asm!("cli", options(nomem, nostack));

        // Step 0b: configure IA32_FEATURE_CONTROL; false == BIOS locked off.
        if !vmxon::configure_feature_control() {
            return VmxProof::Unavailable;
        }

        // Allocate every frame BEFORE entering VMX operation, so an (effectively
        // impossible, 256 MiB RAM / 9 frames) OOM unwinds with nothing to undo.
        let vmxon_pa = match crate::frame_alloc() {
            Some(p) => p,
            None => return VmxProof::Unavailable,
        };
        let vmcs_pa = match crate::frame_alloc() {
            Some(p) => p,
            None => {
                crate::frame_free(vmxon_pa);
                return VmxProof::Unavailable;
            }
        };
        let code_pa = match crate::frame_alloc() {
            Some(p) => p,
            None => {
                crate::frame_free(vmxon_pa);
                crate::frame_free(vmcs_pa);
                return VmxProof::Unavailable;
            }
        };
        let ept = match ept::build_ept_identity_1gib() {
            Some(e) => e,
            None => {
                crate::frame_free(vmxon_pa);
                crate::frame_free(vmcs_pa);
                crate::frame_free(code_pa);
                return VmxProof::Unavailable;
            }
        };
        let gp = match ept::build_guest_pml4_identity_1gib() {
            Some(g) => g,
            None => {
                crate::frame_free(vmxon_pa);
                crate::frame_free(vmcs_pa);
                crate::frame_free(code_pa);
                crate::frame_free(ept.pml4);
                crate::frame_free(ept.pdpt);
                crate::frame_free(ept.pd);
                return VmxProof::Unavailable;
            }
        };

        let basic = vmxon::rdmsr(IA32_VMX_BASIC);
        let rev_id = (basic & 0x7FFF_FFFF) as u32;
        let saved_cr4 = vmxon::read_cr4();

        // Steps 1+2: enable VMX + VMXON.
        let outcome = if !vmxon::enable_and_vmxon(vmxon_pa, rev_id) {
            vmxon::restore_cr4(saved_cr4);
            VmxProof::VmxonFailed
        } else {
            // Step 3: VMCLEAR + VMPTRLD the VMCS.
            let result = if !vmcs::clear_and_load(vmcs_pa, rev_id) {
                VmxProof::EntryFailed { vm_error: 0 }
            } else {
                // Place the guest's single instruction (CPUID, then a HLT pad).
                write_guest_code(code_pa);
                // Step 4: program controls + host-state + guest-state.
                let ctrls = controls::adjusted();
                program_vmcs(&ctrls, &ept, &gp, code_pa);
                // Step 5: invalidate any (empty) EPT TLB for this EPTP.
                ept::invept_single_context(ept.eptp);
                // Step 6+7: world switch + catch.
                if world_switch::launch() {
                    VmxProof::Proven {
                        exit_reason: exit::exit_reason(),
                    }
                } else {
                    VmxProof::EntryFailed {
                        vm_error: exit::vm_instruction_error(),
                    }
                }
            };
            // Step 8: leave VMX operation + restore CR4.VMXE.
            vmxon::vmxoff();
            vmxon::restore_cr4(saved_cr4);
            result
        };

        // Return every frame to M6.
        crate::frame_free(vmxon_pa);
        crate::frame_free(vmcs_pa);
        crate::frame_free(code_pa);
        crate::frame_free(ept.pml4);
        crate::frame_free(ept.pdpt);
        crate::frame_free(ept.pd);
        crate::frame_free(gp.pml4);
        crate::frame_free(gp.pdpt);
        crate::frame_free(gp.pd);

        outcome
    }
}

/// Write the guest's one instruction — `CPUID` (0F A2), which causes an
/// UNCONDITIONAL VM-exit (Intel SDM §25.1.2), then a `HLT` pad that is never
/// reached — into the guest code page through its identity VA.
///
/// # Safety
/// `code_pa` is an owned, identity-mapped 4 KiB frame.
unsafe fn write_guest_code(code_pa: u64) {
    let p = code_pa as *mut u8;
    unsafe {
        write_volatile(p.add(0), 0x0F);
        write_volatile(p.add(1), 0xA2);
        write_volatile(p.add(2), 0xF4);
    }
}

/// Parse a 64-bit TSS descriptor's base out of the GDT (the host TR base for
/// the VMCS host area). 16-byte system descriptor: base[15:0] @ +2,
/// base[23:16] @ +4, base[31:24] @ +7, base[63:32] in the high qword.
///
/// # Safety
/// `gdt_base` is the live GDTR base (identity-mapped low RAM); `tr_sel` is the
/// current TR selector.
unsafe fn host_tr_base(gdt_base: u64, tr_sel: u16) -> u64 {
    let off = (tr_sel & 0xFFF8) as u64;
    let desc = (gdt_base + off) as *const u64;
    let lo = unsafe { read_volatile(desc) };
    let hi = unsafe { read_volatile(desc.add(1)) };
    // Task #49: the pure base reassembly lives in the Kani-proven `tb-encode`
    // crate; only the two `read_volatile`s of the GDT descriptor stay here. The
    // returned base is byte-identical to the former inline shuffle.
    tb_encode::vmx::decode_tss_base(lo, hi)
}

/// Step 4: write the full minimal VMCS — controls, host-state (from the LIVE
/// kernel context), and a long-mode guest whose RIP is the `CPUID` page.
///
/// # Safety
/// Ring 0, VMX-root, a current VMCS is loaded; `ept`/`gp`/`code_pa` are the
/// just-built identity maps and code frame.
unsafe fn program_vmcs(
    ctrls: &controls::Controls,
    ept: &ept::EptMap,
    gp: &ept::GuestPaging,
    code_pa: u64,
) {
    unsafe {
        let w = vmcs::vmwrite;

        // ---- Execution / exit / entry controls (already adjusted) ----------
        w(PIN_BASED_VM_EXEC_CONTROL, ctrls.pinbased as u64);
        w(PRIMARY_PROC_BASED_VM_EXEC_CONTROL, ctrls.procbased as u64);
        w(SECONDARY_PROC_BASED_VM_EXEC_CONTROL, ctrls.procbased2 as u64);
        w(VM_EXIT_CONTROLS, ctrls.exit as u64);
        w(VM_ENTRY_CONTROLS, ctrls.entry as u64);
        w(EXCEPTION_BITMAP, 0);
        w(PAGE_FAULT_ERROR_CODE_MASK, 0);
        w(PAGE_FAULT_ERROR_CODE_MATCH, 0);
        w(CR3_TARGET_COUNT, 0);
        w(VM_EXIT_MSR_STORE_COUNT, 0);
        w(VM_EXIT_MSR_LOAD_COUNT, 0);
        w(VM_ENTRY_MSR_LOAD_COUNT, 0);
        w(VM_ENTRY_INTR_INFO_FIELD, 0);
        w(EPT_POINTER, ept.eptp);
        w(VMCS_LINK_POINTER, 0xFFFF_FFFF_FFFF_FFFF);

        // ---- Host state (the LIVE kernel context) --------------------------
        w(HOST_CR0, vmxon::read_cr0());
        w(HOST_CR3, vmxon::read_cr3());
        w(HOST_CR4, vmxon::read_cr4());
        let gdtr = vmxon::sgdt();
        let idtr = vmxon::sidt();
        let tr_sel = vmxon::read_tr();
        w(HOST_CS_SELECTOR, (vmxon::read_cs() & 0xFFF8) as u64);
        w(HOST_SS_SELECTOR, (vmxon::read_ss() & 0xFFF8) as u64);
        w(HOST_DS_SELECTOR, (vmxon::read_ds() & 0xFFF8) as u64);
        w(HOST_ES_SELECTOR, (vmxon::read_es() & 0xFFF8) as u64);
        w(HOST_FS_SELECTOR, (vmxon::read_fs() & 0xFFF8) as u64);
        w(HOST_GS_SELECTOR, (vmxon::read_gs() & 0xFFF8) as u64);
        w(HOST_TR_SELECTOR, (tr_sel & 0xFFF8) as u64);
        w(HOST_FS_BASE, vmxon::rdmsr(IA32_FS_BASE));
        w(HOST_GS_BASE, vmxon::rdmsr(IA32_GS_BASE));
        w(HOST_TR_BASE, host_tr_base(gdtr.base, tr_sel));
        w(HOST_GDTR_BASE, gdtr.base);
        w(HOST_IDTR_BASE, idtr.base);
        w(HOST_IA32_SYSENTER_CS, vmxon::rdmsr(IA32_SYSENTER_CS));
        w(HOST_IA32_SYSENTER_ESP, vmxon::rdmsr(IA32_SYSENTER_ESP));
        w(HOST_IA32_SYSENTER_EIP, vmxon::rdmsr(IA32_SYSENTER_EIP));
        w(HOST_IA32_EFER, vmxon::rdmsr(IA32_EFER));
        // HOST_RSP / HOST_RIP are written by the world-switch asm.

        // ---- Guest control registers (clamped to the VMX fixed MSRs) -------
        // Task #49: the `(fixed0 | desired) & fixed1` clamp is the Kani-proven
        // `tb_encode::vmx::clamp_fixed`; only the `rdmsr`s of the fixed MSRs (the
        // silicon-unsafe reads) stay here. The clamped CRs are byte-identical.
        let pe_ne_pg: u64 = (1 << 0) | (1 << 5) | (1 << 31);
        let guest_cr0 = tb_encode::vmx::clamp_fixed(
            pe_ne_pg,
            vmxon::rdmsr(IA32_VMX_CR0_FIXED0),
            vmxon::rdmsr(IA32_VMX_CR0_FIXED1),
        );
        let pae: u64 = 1 << 5;
        let guest_cr4 = tb_encode::vmx::clamp_fixed(
            pae,
            vmxon::rdmsr(IA32_VMX_CR4_FIXED0),
            vmxon::rdmsr(IA32_VMX_CR4_FIXED1),
        );
        w(GUEST_CR0, guest_cr0);
        w(GUEST_CR3, gp.cr3);
        w(GUEST_CR4, guest_cr4);
        w(CR0_GUEST_HOST_MASK, 0);
        w(CR4_GUEST_HOST_MASK, 0);
        w(CR0_READ_SHADOW, guest_cr0);
        w(CR4_READ_SHADOW, guest_cr4);

        // ---- Guest segments: flat long-mode (CS L=1; data; usable TSS) -----
        // CS.
        w(GUEST_CS_SELECTOR, 0x08);
        w(GUEST_CS_BASE, 0);
        w(GUEST_CS_LIMIT, 0xFFFF_FFFF);
        w(GUEST_CS_ACCESS_RIGHTS, AR_CODE64);
        // SS.
        w(GUEST_SS_SELECTOR, 0x10);
        w(GUEST_SS_BASE, 0);
        w(GUEST_SS_LIMIT, 0xFFFF_FFFF);
        w(GUEST_SS_ACCESS_RIGHTS, AR_DATA);
        // DS / ES / FS / GS.
        for &(sel, base, limit, ar) in &[
            (GUEST_DS_SELECTOR, GUEST_DS_BASE, GUEST_DS_LIMIT, GUEST_DS_ACCESS_RIGHTS),
            (GUEST_ES_SELECTOR, GUEST_ES_BASE, GUEST_ES_LIMIT, GUEST_ES_ACCESS_RIGHTS),
            (GUEST_FS_SELECTOR, GUEST_FS_BASE, GUEST_FS_LIMIT, GUEST_FS_ACCESS_RIGHTS),
            (GUEST_GS_SELECTOR, GUEST_GS_BASE, GUEST_GS_LIMIT, GUEST_GS_ACCESS_RIGHTS),
        ] {
            w(sel, 0x10);
            w(base, 0);
            w(limit, 0xFFFF_FFFF);
            w(ar, AR_DATA);
        }
        // LDTR: unusable.
        w(GUEST_LDTR_SELECTOR, 0);
        w(GUEST_LDTR_BASE, 0);
        w(GUEST_LDTR_LIMIT, 0);
        w(GUEST_LDTR_ACCESS_RIGHTS, AR_UNUSABLE);
        // TR: a usable 64-bit busy TSS (required usable for IA-32e entry).
        w(GUEST_TR_SELECTOR, 0x18);
        w(GUEST_TR_BASE, 0);
        w(GUEST_TR_LIMIT, 0x67);
        w(GUEST_TR_ACCESS_RIGHTS, AR_TSS64);

        // ---- Guest descriptor tables (not accessed by a CPUID-only guest) --
        w(GUEST_GDTR_BASE, 0);
        w(GUEST_GDTR_LIMIT, 0xFFFF);
        w(GUEST_IDTR_BASE, 0);
        w(GUEST_IDTR_LIMIT, 0xFFFF);

        // ---- Guest misc + control state ------------------------------------
        w(GUEST_DR7, 0x400);
        w(GUEST_RFLAGS, 0x2); // reserved bit 1 set, IF=0
        w(GUEST_RIP, code_pa); // the CPUID instruction
        w(GUEST_RSP, code_pa + 0xFF0); // a mapped, canonical stack slot
        w(GUEST_IA32_EFER, (1 << 8) | (1 << 10)); // LME | LMA (64-bit guest)
        w(GUEST_IA32_DEBUGCTL, 0);
        w(GUEST_SYSENTER_CS, 0);
        w(GUEST_SYSENTER_ESP, 0);
        w(GUEST_SYSENTER_EIP, 0);
        w(GUEST_ACTIVITY_STATE, 0); // active
        w(GUEST_INTERRUPTIBILITY_STATE, 0);
        w(GUEST_PENDING_DBG_EXCEPTIONS, 0);
    }
}
