//! x86_64 `tb-boot v0` guest setup — **enter the guest directly in 64-bit long
//! mode**, deleting the PVH note + the A0 32->64 trampoline from the boot path.
//!
//! Every constant here is taken VERBATIM from Firecracker's verified sources and
//! cited inline; do not invent KVM struct fields or descriptor bits.
//!  * GDT encoding (`gdt_entry`, `kvm_segment_from_gdt`):
//!    Firecracker `src/vmm/src/arch/x86_64/gdt.rs`.
//!  * Long-mode GDT table, `KVM_SET_SREGS` cr0/cr3/cr4/efer, identity page
//!    tables, and `KVM_SET_REGS` rflags/rip: Firecracker
//!    `src/vmm/src/arch/x86_64/regs.rs` (the `BootProtocol::LinuxBoot` arm).
//!  * `kvm_sregs`/`kvm_regs`/`kvm_segment` layout, `KVM_SET_USER_MEMORY_REGION`:
//!    <https://docs.kernel.org/virt/kvm/api.html>.
//!
//! Low-memory map (all below 1 MiB; identity-mapped by the page tables below):
//! ```text
//!   0x0500  boot GDT (4 x u64)             [Firecracker BOOT_GDT_OFFSET]
//!   0x0520  boot IDT (zeroed)             [Firecracker BOOT_IDT_OFFSET]
//!   0x6000  TbBootInfo (56 bytes)          [tb-boot v0]
//!   0x6040  TbMemRegion array             [tb-boot v0]
//!   0x6800  cmdline (NUL-terminated)       [tb-boot v0]
//!   0x9000  PML4                          [Firecracker PML4_START]
//!   0xa000  PDPTE                         [Firecracker PDPTE_START]
//!   0xb000  PDE (512 x 2 MiB, [0,1 GiB))   [Firecracker PDE_START]
//! ```

use kvm_bindings::{kvm_regs, kvm_segment, kvm_sregs, KVM_MAX_CPUID_ENTRIES};
use kvm_ioctls::{Kvm, VcpuFd, VmFd};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use crate::arch::BootParams;
use crate::error::VmmError;
use crate::memory::MemRegion;

// --- Firecracker low-memory offsets (regs.rs) ------------------------------
const BOOT_GDT_OFFSET: u64 = 0x500;
const BOOT_IDT_OFFSET: u64 = 0x520;
const PML4_START: u64 = 0x9000;
const PDPTE_START: u64 = 0xa000;
const PDE_START: u64 = 0xb000;
const BOOT_GDT_MAX: usize = 4;

// --- tb-boot v0 structure placement ---------------------------------------
const TB_BOOT_INFO_ADDR: u64 = 0x6000;
const TB_MEM_REGIONS_ADDR: u64 = 0x6040;
const TB_CMDLINE_ADDR: u64 = 0x6800;
/// Boot structures must stay below the page tables.
const TB_LOWMEM_LIMIT: u64 = PML4_START;

/// Serialized size of [`tb_boot::TbBootInfo`] (repr(C)).
const TB_BOOT_INFO_SIZE: usize = 56;
/// Serialized size of [`tb_boot::TbMemRegion`] (repr(C)).
const TB_MEM_REGION_SIZE: usize = 24;

// Compile-time ABI guards: if tb-boot ever changes its struct layout, this
// breaks the build instead of silently writing a mismatched boot block.
const _: () = assert!(std::mem::size_of::<tb_boot::TbBootInfo>() == TB_BOOT_INFO_SIZE);
const _: () = assert!(std::mem::size_of::<tb_boot::TbMemRegion>() == TB_MEM_REGION_SIZE);

// --- Control-register bits (regs.rs) ---------------------------------------
const X86_CR0_PE: u64 = 0x1;
const X86_CR0_PG: u64 = 0x8000_0000;
const X86_CR4_PAE: u64 = 0x20;
const EFER_LME: u64 = 0x100;
const EFER_LMA: u64 = 0x400;

/// KVM's internal real-mode TSS region (Firecracker arch/x86_64/mod.rs).
const KVM_TSS_ADDRESS: usize = 0xfffb_d000;

// ===========================================================================
// GDT encoding — verbatim from Firecracker gdt.rs (cited).
// ===========================================================================

/// Constructor for a conventional segment GDT entry (Linux `segment.h`).
/// Verbatim from Firecracker `gdt.rs::gdt_entry`.
pub(crate) fn gdt_entry(flags: u16, base: u32, limit: u32) -> u64 {
    ((u64::from(base) & 0xff00_0000u64) << (56 - 24))
        | ((u64::from(flags) & 0x0000_f0ffu64) << 40)
        | ((u64::from(limit) & 0x000f_0000u64) << (48 - 16))
        | ((u64::from(base) & 0x00ff_ffffu64) << 16)
        | (u64::from(limit) & 0x0000_ffffu64)
}

fn get_base(entry: u64) -> u64 {
    (((entry) & 0xFF00_0000_0000_0000) >> 32)
        | (((entry) & 0x0000_00FF_0000_0000) >> 16)
        | (((entry) & 0x0000_0000_FFFF_0000) >> 16)
}

fn get_limit(entry: u64) -> u32 {
    let limit: u32 =
        ((((entry) & 0x000F_0000_0000_0000) >> 32) | ((entry) & 0x0000_0000_0000_FFFF)) as u32;
    match get_g(entry) {
        0 => limit,
        _ => (limit << 12) | 0xFFF,
    }
}

fn get_g(entry: u64) -> u8 {
    ((entry & 0x0080_0000_0000_0000) >> 55) as u8
}
fn get_db(entry: u64) -> u8 {
    ((entry & 0x0040_0000_0000_0000) >> 54) as u8
}
fn get_l(entry: u64) -> u8 {
    ((entry & 0x0020_0000_0000_0000) >> 53) as u8
}
fn get_avl(entry: u64) -> u8 {
    ((entry & 0x0010_0000_0000_0000) >> 52) as u8
}
fn get_p(entry: u64) -> u8 {
    ((entry & 0x0000_8000_0000_0000) >> 47) as u8
}
fn get_dpl(entry: u64) -> u8 {
    ((entry & 0x0000_6000_0000_0000) >> 45) as u8
}
fn get_s(entry: u64) -> u8 {
    ((entry & 0x0000_1000_0000_0000) >> 44) as u8
}
fn get_type(entry: u64) -> u8 {
    ((entry & 0x0000_0F00_0000_0000) >> 40) as u8
}

/// Build a `kvm_segment` from a GDT entry + its table index.
/// Verbatim from Firecracker `gdt.rs::kvm_segment_from_gdt`.
pub(crate) fn kvm_segment_from_gdt(entry: u64, table_index: u8) -> kvm_segment {
    kvm_segment {
        base: get_base(entry),
        limit: get_limit(entry),
        selector: u16::from(table_index * 8),
        type_: get_type(entry),
        present: get_p(entry),
        dpl: get_dpl(entry),
        db: get_db(entry),
        s: get_s(entry),
        l: get_l(entry),
        g: get_g(entry),
        avl: get_avl(entry),
        padding: 0,
        unusable: match get_p(entry) {
            0 => 1,
            _ => 0,
        },
    }
}

/// The flat 64-bit boot GDT (Firecracker `BootProtocol::LinuxBoot`): NULL, a
/// 64-bit code segment (L=1), a flat data segment, and a TSS descriptor.
fn gdt_table() -> [u64; BOOT_GDT_MAX] {
    [
        gdt_entry(0, 0, 0),            // NULL
        gdt_entry(0xa09b, 0, 0xfffff), // CODE: present, ring0, exec/read, L=1, G=1
        gdt_entry(0xc093, 0, 0xfffff), // DATA: present, ring0, read/write, DB=1, G=1
        gdt_entry(0x808b, 0, 0xfffff), // TSS
    ]
}

// ===========================================================================
// Guest-RAM boot structures.
// ===========================================================================

fn write_gdt(mem: &GuestMemoryMmap) -> Result<(), VmmError> {
    for (i, entry) in gdt_table().iter().enumerate() {
        mem.write_obj(*entry, GuestAddress(BOOT_GDT_OFFSET + (i as u64) * 8))?;
    }
    Ok(())
}

fn write_idt(mem: &GuestMemoryMmap) -> Result<(), VmmError> {
    mem.write_obj(0u64, GuestAddress(BOOT_IDT_OFFSET))?;
    Ok(())
}

/// Identity page tables covering VA [0, 1 GiB) with 2 MiB pages.
/// Verbatim structure from Firecracker `regs.rs::setup_page_tables`.
fn setup_page_tables(mem: &GuestMemoryMmap) -> Result<(), VmmError> {
    mem.write_obj(PDPTE_START | 0x03u64, GuestAddress(PML4_START))?; // PML4[0] -> PDPTE
    mem.write_obj(PDE_START | 0x03u64, GuestAddress(PDPTE_START))?; // PDPTE[0] -> PDE
    for i in 0..512u64 {
        // PDE[i] = (i*2MiB) | PRESENT|WRITE|PS
        mem.write_obj((i << 21) | 0x83u64, GuestAddress(PDE_START + i * 8))?;
    }
    Ok(())
}

/// Serialize a [`tb_boot::TbMemRegion`] (repr(C): base,len,kind,_pad).
pub(crate) fn serialize_mem_region(base: u64, len: u64, kind: u32) -> [u8; TB_MEM_REGION_SIZE] {
    let mut b = [0u8; TB_MEM_REGION_SIZE];
    b[0..8].copy_from_slice(&base.to_le_bytes());
    b[8..16].copy_from_slice(&len.to_le_bytes());
    b[16..20].copy_from_slice(&kind.to_le_bytes());
    // b[20..24] = _pad (0)
    b
}

/// Serialize a [`tb_boot::TbBootInfo`] (repr(C)).
#[allow(clippy::too_many_arguments)]
pub(crate) fn serialize_boot_info(
    magic: u64,
    version: u32,
    flags: u32,
    mem_regions_ptr: u64,
    mem_regions_len: u64,
    cmdline_ptr: u64,
    cmdline_len: u64,
    kernel_entry: u64,
) -> [u8; TB_BOOT_INFO_SIZE] {
    let mut b = [0u8; TB_BOOT_INFO_SIZE];
    b[0..8].copy_from_slice(&magic.to_le_bytes());
    b[8..12].copy_from_slice(&version.to_le_bytes());
    b[12..16].copy_from_slice(&flags.to_le_bytes());
    b[16..24].copy_from_slice(&mem_regions_ptr.to_le_bytes());
    b[24..32].copy_from_slice(&mem_regions_len.to_le_bytes());
    b[32..40].copy_from_slice(&cmdline_ptr.to_le_bytes());
    b[40..48].copy_from_slice(&cmdline_len.to_le_bytes());
    b[48..56].copy_from_slice(&kernel_entry.to_le_bytes());
    b
}

/// Write GDT, IDT, page tables, the TbMemRegion array, the cmdline, and the
/// TbBootInfo block into guest RAM. Returns the guest-physical TbBootInfo addr.
fn write_system_memory(mem: &GuestMemoryMmap, params: &BootParams) -> Result<u64, VmmError> {
    let n = params.mem_regions.len();
    let regions_end = TB_MEM_REGIONS_ADDR + (n as u64) * (TB_MEM_REGION_SIZE as u64);
    if regions_end > TB_CMDLINE_ADDR {
        return Err(VmmError::Config(
            "too many memory regions for the tb-boot low-memory window".into(),
        ));
    }
    let cmd = params.cmdline.as_bytes();
    if TB_CMDLINE_ADDR + cmd.len() as u64 + 1 > TB_LOWMEM_LIMIT {
        return Err(VmmError::Config("kernel cmdline too long for the boot window".into()));
    }

    write_gdt(mem)?;
    write_idt(mem)?;
    setup_page_tables(mem)?;

    for (i, r) in params.mem_regions.iter().enumerate() {
        let bytes = serialize_mem_region(r.base, r.len, r.kind as u32);
        mem.write_slice(
            &bytes,
            GuestAddress(TB_MEM_REGIONS_ADDR + (i as u64) * (TB_MEM_REGION_SIZE as u64)),
        )?;
    }

    mem.write_slice(cmd, GuestAddress(TB_CMDLINE_ADDR))?;
    mem.write_obj(0u8, GuestAddress(TB_CMDLINE_ADDR + cmd.len() as u64))?; // NUL

    let info = serialize_boot_info(
        tb_boot::TB_BOOT_MAGIC,
        tb_boot::TB_BOOT_VERSION,
        0, // flags
        TB_MEM_REGIONS_ADDR,
        n as u64,
        TB_CMDLINE_ADDR,
        cmd.len() as u64,
        params.entry_point,
    );
    mem.write_slice(&info, GuestAddress(TB_BOOT_INFO_ADDR))?;

    Ok(TB_BOOT_INFO_ADDR)
}

// ===========================================================================
// vCPU programming.
// ===========================================================================

/// `KVM_SET_SREGS`: long-mode segments + control registers.
/// Mirrors Firecracker `regs.rs` `configure_segments_and_sregs` +
/// `setup_page_tables` for `BootProtocol::LinuxBoot`.
fn setup_sregs(vcpu: &VcpuFd) -> Result<(), VmmError> {
    let mut sregs: kvm_sregs = vcpu.get_sregs()?;
    let gdt = gdt_table();

    let code_seg = kvm_segment_from_gdt(gdt[1], 1);
    let data_seg = kvm_segment_from_gdt(gdt[2], 2);
    let tss_seg = kvm_segment_from_gdt(gdt[3], 3);

    sregs.cs = code_seg;
    sregs.ds = data_seg;
    sregs.es = data_seg;
    sregs.fs = data_seg;
    sregs.gs = data_seg;
    sregs.ss = data_seg;
    sregs.tr = tss_seg;

    sregs.gdt.base = BOOT_GDT_OFFSET;
    sregs.gdt.limit = (std::mem::size_of::<u64>() * BOOT_GDT_MAX - 1) as u16; // 31
    sregs.idt.base = BOOT_IDT_OFFSET;
    sregs.idt.limit = (std::mem::size_of::<u64>() - 1) as u16; // 7

    // 64-bit protected mode (Firecracker LinuxBoot): PE from segments, then
    // PG + cr3 + PAE + EFER.LME|LMA from the page-table setup.
    sregs.cr0 |= X86_CR0_PE | X86_CR0_PG;
    sregs.cr3 = PML4_START;
    sregs.cr4 |= X86_CR4_PAE;
    sregs.efer |= EFER_LME | EFER_LMA;

    vcpu.set_sregs(&sregs)?;
    Ok(())
}

/// `KVM_SET_REGS`: enter at `entry` with the tb-boot ABI — `rdi` = guest-phys
/// TbBootInfo (SysV arg0), `rsi` = 0, `rflags` = 0x2.
///
/// (Firecracker's LinuxBoot also sets rsp/rbp/rsi for the Linux zero-page ABI;
/// the TABOS kernel's `_tb_start` instead sets its own RSP and reads `rdi`, so
/// we leave rsp/rbp at 0 and place our info pointer in rdi.)
fn setup_regs(vcpu: &VcpuFd, entry: u64, boot_info_addr: u64) -> Result<(), VmmError> {
    let regs = kvm_regs {
        rflags: 0x0000_0000_0000_0002u64,
        rip: entry,
        rdi: boot_info_addr,
        rsi: 0,
        ..Default::default()
    };
    vcpu.set_regs(&regs)?;
    Ok(())
}

/// Present the host's supported CPUID to the guest (`KVM_SET_CPUID2`). The
/// soft-float TABOS kernel does not enable advertised SIMD features, but this
/// keeps any `cpuid` the guest issues well-defined rather than all-zero.
fn configure_cpuid(kvm: &Kvm, vcpu: &VcpuFd) -> Result<(), VmmError> {
    let cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES as usize)?;
    vcpu.set_cpuid2(&cpuid)?;
    Ok(())
}

/// VM-level x86 setup: reserve KVM's real-mode TSS region (Firecracker always
/// calls `set_tss_address(0xfffbd000)`), unless guest RAM extends over it.
fn configure_vm(vm: &VmFd, mem: &GuestMemoryMmap) -> Result<(), VmmError> {
    if (mem.last_addr().raw_value() as usize) < KVM_TSS_ADDRESS {
        vm.set_tss_address(KVM_TSS_ADDRESS)?;
    }
    Ok(())
}

/// Full x86_64 boot configuration: VM TSS region, CPUID, boot structures in
/// guest RAM, then the long-mode sregs/regs. After this the vCPU is ready to run.
pub fn setup(
    kvm: &Kvm,
    vm: &VmFd,
    vcpu: &VcpuFd,
    mem: &GuestMemoryMmap,
    params: &BootParams,
) -> Result<(), VmmError> {
    let _: &[MemRegion] = params.mem_regions; // documents the seam input type
    configure_vm(vm, mem)?;
    configure_cpuid(kvm, vcpu)?;
    let boot_info_addr = write_system_memory(mem, params)?;
    setup_sregs(vcpu)?;
    setup_regs(vcpu, params.entry_point, boot_info_addr)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemKind;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    fn mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20_0000)]).unwrap()
    }

    // The exact qwords are asserted by Firecracker's own gdt.rs/regs.rs tests.
    #[test]
    fn gdt_entries_match_firecracker() {
        let g = gdt_table();
        assert_eq!(g[0], 0x0);
        assert_eq!(g[1], 0x00af_9b00_0000_ffff); // CODE
        assert_eq!(g[2], 0x00cf_9300_0000_ffff); // DATA
        assert_eq!(g[3], 0x008f_8b00_0000_ffff); // TSS
    }

    #[test]
    fn code_segment_decodes_to_long_mode() {
        let seg = kvm_segment_from_gdt(gdt_table()[1], 1);
        assert_eq!(seg.selector, 0x08);
        assert_eq!(seg.l, 1, "code segment must be 64-bit (L=1)");
        assert_eq!(seg.present, 1);
        assert_eq!(seg.dpl, 0);
        assert_eq!(seg.g, 1);
        assert_eq!(seg.limit, 0xffff_ffff);
        assert_eq!(seg.unusable, 0);
    }

    #[test]
    fn page_tables_identity_map_first_gib() {
        let gm = mem();
        setup_page_tables(&gm).unwrap();
        assert_eq!(gm.read_obj::<u64>(GuestAddress(PML4_START)).unwrap(), 0xa003);
        assert_eq!(gm.read_obj::<u64>(GuestAddress(PDPTE_START)).unwrap(), 0xb003);
        for i in 0..512u64 {
            let pde: u64 = gm.read_obj(GuestAddress(PDE_START + i * 8)).unwrap();
            assert_eq!(pde, (i << 21) | 0x83);
        }
    }

    #[test]
    fn gdt_written_to_guest_low_memory() {
        let gm = mem();
        write_gdt(&gm).unwrap();
        write_idt(&gm).unwrap();
        assert_eq!(gm.read_obj::<u64>(GuestAddress(BOOT_GDT_OFFSET)).unwrap(), 0x0);
        assert_eq!(
            gm.read_obj::<u64>(GuestAddress(BOOT_GDT_OFFSET + 8)).unwrap(),
            0x00af_9b00_0000_ffff
        );
        assert_eq!(gm.read_obj::<u64>(GuestAddress(BOOT_IDT_OFFSET)).unwrap(), 0x0);
    }

    #[test]
    fn boot_info_serialization_layout() {
        let b = serialize_boot_info(
            tb_boot::TB_BOOT_MAGIC,
            tb_boot::TB_BOOT_VERSION,
            0,
            TB_MEM_REGIONS_ADDR,
            2,
            TB_CMDLINE_ADDR,
            5,
            0x0010_0000,
        );
        assert_eq!(u64::from_le_bytes(b[0..8].try_into().unwrap()), tb_boot::TB_BOOT_MAGIC);
        assert_eq!(u32::from_le_bytes(b[8..12].try_into().unwrap()), tb_boot::TB_BOOT_VERSION);
        assert_eq!(u32::from_le_bytes(b[12..16].try_into().unwrap()), 0);
        assert_eq!(u64::from_le_bytes(b[16..24].try_into().unwrap()), TB_MEM_REGIONS_ADDR);
        assert_eq!(u64::from_le_bytes(b[24..32].try_into().unwrap()), 2);
        assert_eq!(u64::from_le_bytes(b[32..40].try_into().unwrap()), TB_CMDLINE_ADDR);
        assert_eq!(u64::from_le_bytes(b[40..48].try_into().unwrap()), 5);
        assert_eq!(u64::from_le_bytes(b[48..56].try_into().unwrap()), 0x0010_0000);
    }

    #[test]
    fn mem_region_serialization_layout() {
        let b = serialize_mem_region(0x1000, 0x4000, MemKind::Ram as u32);
        assert_eq!(u64::from_le_bytes(b[0..8].try_into().unwrap()), 0x1000);
        assert_eq!(u64::from_le_bytes(b[8..16].try_into().unwrap()), 0x4000);
        assert_eq!(u32::from_le_bytes(b[16..20].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(b[20..24].try_into().unwrap()), 0);
    }

    #[test]
    fn writes_boot_block_and_validates_cmdline_bound() {
        let gm = mem();
        let regions = [MemRegion { base: 0, len: 0x20_0000, kind: MemKind::Ram }];
        let params = BootParams { entry_point: 0x0010_0000, mem_regions: &regions, cmdline: "ro" };
        let addr = write_system_memory(&gm, &params).unwrap();
        assert_eq!(addr, TB_BOOT_INFO_ADDR);
        // magic landed
        assert_eq!(gm.read_obj::<u64>(GuestAddress(TB_BOOT_INFO_ADDR)).unwrap(), tb_boot::TB_BOOT_MAGIC);
        // region landed
        assert_eq!(gm.read_obj::<u64>(GuestAddress(TB_MEM_REGIONS_ADDR)).unwrap(), 0);
        assert_eq!(gm.read_obj::<u64>(GuestAddress(TB_MEM_REGIONS_ADDR + 8)).unwrap(), 0x20_0000);

        // Over-long cmdline is rejected.
        let huge = "x".repeat((TB_LOWMEM_LIMIT - TB_CMDLINE_ADDR) as usize + 1);
        let bad = BootParams { entry_point: 0, mem_regions: &regions, cmdline: &huge };
        assert!(matches!(write_system_memory(&gm, &bad), Err(VmmError::Config(_))));
    }
}
