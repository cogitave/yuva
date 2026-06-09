//! Host-side **aarch64** `tb-boot v0` producer + register-file handoff.
//!
//! This is the aarch64 mirror of the x86_64 producer that lives in
//! `tb-vmm/src/arch/x86_64/boot.rs`. On x86_64 the producer's *pure* parts
//! (serialize the boot block, decide where it lands, derive the entry register
//! values) are interleaved with the Linux-only KVM ioctls (`KVM_SET_SREGS` /
//! `KVM_SET_REGS`). aarch64's KVM glue (`KVM_ARM_VCPU_INIT` + `KVM_SET_ONE_REG`,
//! the in-kernel vGIC, and the PL011 MMIO console) is a deliberately-**deferred**
//! `tb-vmm` backend — there is no aarch64 `/dev/kvm` in CI and no aarch64
//! `tb-vmm` backend yet — so the *host-testable* half of the aarch64 producer
//! is extracted here, in the `forbid(unsafe_code)`, host-on-every-arch
//! `tb-boot` crate, where `cargo test` proves it green without `/dev/kvm`.
//!
//! What this module produces, given a guest-RAM buffer + a memory map + a
//! cmdline + the kernel entry:
//!  1. the serialized **boot block** — a [`crate::TbBootInfo`], its packed
//!     [`crate::TbMemRegion`] array, and the cmdline — written into guest RAM at
//!     the frozen aarch64 placement (all inside the 512 KiB sub-image window
//!     `[0x4000_0000, 0x4008_0000)` that the kernel's pmm already treats as DTB
//!     staging, so the kernel's `.bss`-clear never touches it and it is readable
//!     both MMU-off and MMU-on);
//!  2. the **register-file handoff descriptor** ([`Aarch64Handoff`]) — the exact
//!     `(KVM core-register ID, value)` writes a future `tb-vmm` aarch64 backend
//!     feeds to `KVM_SET_ONE_REG` to land the vCPU on `_tb_start`: `X0` = the
//!     guest-physical `TbBootInfo*`, `X1=X2=X3=0`, `PC` = the entry, and
//!     `PSTATE = 0x3c5` (EL1h + DAIF masked). MMU/caches stay at the KVM reset
//!     (off); the kernel's `mmu_init` brings translation up cold, so the
//!     producer programs ZERO page tables (unlike x86, where it must pre-build
//!     CR3 + identity tables).
//!
//! ## The aarch64 boot contract this mirrors (frozen, cited)
//!  * arm64 Linux boot protocol primary-CPU state (the contract `tb-boot`
//!    overrides only in the *semantics* of `x0`): `x0` = physical address of a
//!    blob in RAM, `x1=x2=x3=0`, all of PSTATE.DAIF masked, EL1 (or EL2), MMU
//!    OFF. `tb-boot` puts the `TbBootInfo*` in `x0` instead of Linux's dtb,
//!    exactly as the x86 producer puts the pointer in `rdi` rather than Linux's
//!    `rsi` zero-page. Source: kernel.org `Documentation/arch/arm64/booting.rst`.
//!  * KVM ARM64 core-register `ONE_REG` encoding: base
//!    `0x6030_0000_0010_0000` (`KVM_REG_ARM64 | KVM_REG_SIZE_U64 |
//!    KVM_REG_ARM_CORE`); index = `offsetof(kvm_regs)/4`: `X0=…0000`,
//!    `X1=…0002`, `X2=…0004`, `X3=…0006`, `PC=…0040`, `PSTATE=…0042`. Source:
//!    docs.kernel.org/virt/kvm/api.html (the arm64 `ONE_REG` table).
//!  * `PSTATE = 0x3c5 = PSR_MODE_EL1h(0x5) | D(0x200) | A(0x100) | I(0x80) |
//!    F(0x40)`. Cross-confirmed by `booting.rst` ("all DAIF masked") and the
//!    in-repo `arch/aarch64/boot.rs` `SPSR_EL2 = 0x3c5` EL2->EL1 drop.
//!
//! This module is `no_std` (it only borrows `&[u8]`/`&mut [u8]` and copies via
//! `to_le_bytes`/`copy_from_slice`), so it compiles into the kernel build too;
//! the kernel never calls it (the consumer side lives in `tb-hal`), but keeping
//! the producer in the shared ABI crate makes the contract testable on every
//! host arch — including x86_64 CI and WSL2 — with no `/dev/kvm`.

use crate::{TbBootInfo, TbMemRegion};

// ===========================================================================
// Guest-physical placement (frozen aarch64 tb-boot v0 layout)
// ===========================================================================

/// Guest RAM base on aarch64: the QEMU `virt` DRAM base, the kernel's link
/// gigabyte, and the M3 identity-mapped RAM block. The boot block is addressed
/// relative to this base (vs `0` on x86_64).
pub const AARCH64_GUEST_RAM_BASE: u64 = 0x4000_0000;

/// Kernel image load address (the classic arm64 `Image` `TEXT_OFFSET`). The
/// whole boot block must stay strictly below this so the kernel's `.bss`-clear
/// and image never overlap it.
pub const AARCH64_IMAGE_LMA: u64 = 0x4008_0000;

/// Guest-physical address of the [`TbBootInfo`] (8-byte aligned; `X0` points
/// here). 56 bytes end at `0x4000_1038`, below [`AARCH64_MEM_REGIONS_ADDR`].
pub const AARCH64_BOOT_INFO_ADDR: u64 = 0x4000_1000;

/// Guest-physical address of the packed [`TbMemRegion`] array (8-byte aligned).
pub const AARCH64_MEM_REGIONS_ADDR: u64 = 0x4000_1040;

/// Guest-physical address of the cmdline byte buffer (NUL-terminated on write).
pub const AARCH64_CMDLINE_ADDR: u64 = 0x4000_1800;

// ===========================================================================
// KVM core-register IDs + the PSTATE handoff value
// ===========================================================================

/// `KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE` — the base a core
/// general/PC/PSTATE register ID is OR-ed with its `offsetof(kvm_regs)/4` index.
pub const KVM_REG_ARM_CORE_BASE: u64 = 0x6030_0000_0010_0000;

/// PSTATE handoff value: `EL1h (0x5) | D(0x200) | A(0x100) | I(0x80) | F(0x40)`
/// = EL1h with all of DAIF masked (Linux `INIT_PSTATE_EL1`).
pub const AARCH64_PSTATE_EL1H_DAIF: u64 = 0x3c5;

/// Build a core-register `ONE_REG` ID from its `offsetof(kvm_regs)/4` index.
const fn core_reg_id(index: u64) -> u64 {
    KVM_REG_ARM_CORE_BASE | index
}

/// `ONE_REG` ID for `X0` (index `0x0000`) — receives the `TbBootInfo*`.
pub const AARCH64_REG_X0: u64 = core_reg_id(0x0000);
/// `ONE_REG` ID for `X1` (index `0x0002`) — reserved-zero per the arm64 contract.
pub const AARCH64_REG_X1: u64 = core_reg_id(0x0002);
/// `ONE_REG` ID for `X2` (index `0x0004`) — reserved-zero per the arm64 contract.
pub const AARCH64_REG_X2: u64 = core_reg_id(0x0004);
/// `ONE_REG` ID for `X3` (index `0x0006`) — reserved-zero per the arm64 contract.
pub const AARCH64_REG_X3: u64 = core_reg_id(0x0006);
/// `ONE_REG` ID for `PC` (index `0x0040`) — receives the kernel entry address.
pub const AARCH64_REG_PC: u64 = core_reg_id(0x0040);
/// `ONE_REG` ID for `PSTATE` (index `0x0042`) — receives [`AARCH64_PSTATE_EL1H_DAIF`].
pub const AARCH64_REG_PSTATE: u64 = core_reg_id(0x0042);

/// The number of vCPU registers the [`Aarch64Handoff`] programs: `X0..X3`, `PC`,
/// `PSTATE`.
pub const AARCH64_HANDOFF_REG_COUNT: usize = 6;

// ===========================================================================
// Handoff descriptor
// ===========================================================================

/// One `KVM_SET_ONE_REG` write: a core-register ID and the 64-bit value to set.
///
/// A future `tb-vmm` aarch64 backend turns each of these into
/// `vcpu.set_one_reg(reg.id, &reg.value.to_le_bytes())`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegWrite {
    /// The KVM core-register ID (`KVM_REG_ARM64 | SIZE_U64 | ARM_CORE | index`).
    pub id: u64,
    /// The 64-bit value to write into that register (little-endian on the wire).
    pub value: u64,
}

/// The result of the aarch64 producer: the boot block has been written into the
/// caller's guest-RAM buffer, and this descriptor carries everything the KVM
/// glue still needs — the `TbBootInfo*` and the exact register-file writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aarch64Handoff {
    /// Guest-physical address of the [`TbBootInfo`] written into guest RAM
    /// (equals [`AARCH64_BOOT_INFO_ADDR`]; also the `X0` value).
    pub boot_info_addr: u64,
    /// The [`TbBootInfo`] that was serialized (handy for assertions/logging).
    pub info: TbBootInfo,
    /// The `KVM_SET_ONE_REG` writes that land the vCPU on `_tb_start`:
    /// `X0, X1, X2, X3, PC, PSTATE` in that order.
    pub regs: [RegWrite; AARCH64_HANDOFF_REG_COUNT],
}

/// Why [`build_handoff`] refused to produce the boot block. Fail-closed: the
/// producer never silently writes a truncated or out-of-window block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Aarch64HandoffError {
    /// The packed [`TbMemRegion`] array would overflow into the cmdline window
    /// (`AARCH64_MEM_REGIONS_ADDR + n*24 > AARCH64_CMDLINE_ADDR`).
    TooManyRegions,
    /// The cmdline (plus its NUL terminator) would overflow past the kernel
    /// image base (`AARCH64_CMDLINE_ADDR + len + 1 > AARCH64_IMAGE_LMA`).
    CmdlineTooLong,
    /// The provided guest-RAM slice (interpreted as starting at
    /// [`AARCH64_GUEST_RAM_BASE`]) is too small to hold the boot block.
    RamTooSmall,
}

impl core::fmt::Display for Aarch64HandoffError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Aarch64HandoffError::TooManyRegions => {
                write!(f, "tb-boot/aarch64: too many memory regions for the boot window")
            }
            Aarch64HandoffError::CmdlineTooLong => {
                write!(f, "tb-boot/aarch64: cmdline too long for the boot window")
            }
            Aarch64HandoffError::RamTooSmall => {
                write!(f, "tb-boot/aarch64: guest RAM slice too small for the boot block")
            }
        }
    }
}

/// Copy `bytes` into the guest-RAM slice at guest-physical address `gpa`,
/// where `ram[0]` corresponds to [`AARCH64_GUEST_RAM_BASE`]. Bounds-checked.
fn write_at(ram: &mut [u8], gpa: u64, bytes: &[u8]) -> Result<(), Aarch64HandoffError> {
    let off = gpa
        .checked_sub(AARCH64_GUEST_RAM_BASE)
        .ok_or(Aarch64HandoffError::RamTooSmall)? as usize;
    let end = off
        .checked_add(bytes.len())
        .ok_or(Aarch64HandoffError::RamTooSmall)?;
    if end > ram.len() {
        return Err(Aarch64HandoffError::RamTooSmall);
    }
    ram[off..end].copy_from_slice(bytes);
    Ok(())
}

/// Build the aarch64 `tb-boot v0` boot block + register-file handoff.
///
/// Writes the [`TbBootInfo`], its packed [`TbMemRegion`] array, and the
/// (NUL-terminated) cmdline into `ram` at the frozen guest-physical placement,
/// then returns the [`Aarch64Handoff`] descriptor (the `TbBootInfo*` + the six
/// `KVM_SET_ONE_REG` writes). `ram[0]` is interpreted as
/// [`AARCH64_GUEST_RAM_BASE`]; it must be large enough to span the boot block
/// (a few KiB is plenty — the whole block lives below `0x4000_1800 + cmdline`).
///
/// The boot block is bounds-checked against the cmdline window and the kernel
/// image base, mirroring the x86 producer's `write_system_memory` guards.
pub fn build_handoff(
    ram: &mut [u8],
    mem_regions: &[TbMemRegion],
    cmdline: &[u8],
    entry_point: u64,
) -> Result<Aarch64Handoff, Aarch64HandoffError> {
    let n = mem_regions.len() as u64;
    let regions_end = AARCH64_MEM_REGIONS_ADDR + n * (TbMemRegion::SIZE as u64);
    if regions_end > AARCH64_CMDLINE_ADDR {
        return Err(Aarch64HandoffError::TooManyRegions);
    }
    if AARCH64_CMDLINE_ADDR + cmdline.len() as u64 + 1 > AARCH64_IMAGE_LMA {
        return Err(Aarch64HandoffError::CmdlineTooLong);
    }

    // (1) Memory map: packed TbMemRegion[] at AARCH64_MEM_REGIONS_ADDR.
    for (i, r) in mem_regions.iter().enumerate() {
        let gpa = AARCH64_MEM_REGIONS_ADDR + (i as u64) * (TbMemRegion::SIZE as u64);
        write_at(ram, gpa, &r.to_bytes())?;
    }

    // (2) cmdline + a trailing NUL (mirrors the x86 producer).
    write_at(ram, AARCH64_CMDLINE_ADDR, cmdline)?;
    write_at(ram, AARCH64_CMDLINE_ADDR + cmdline.len() as u64, &[0u8])?;

    // (3) The root TbBootInfo (magic/version pre-filled by `new`).
    let info = TbBootInfo::new(
        0, // flags
        AARCH64_MEM_REGIONS_ADDR,
        n,
        AARCH64_CMDLINE_ADDR,
        cmdline.len() as u64,
        entry_point,
    );
    write_at(ram, AARCH64_BOOT_INFO_ADDR, &info.to_bytes())?;

    // (4) The register-file handoff: X0=info*, X1..X3=0, PC=entry, PSTATE=EL1h.
    let regs = [
        RegWrite { id: AARCH64_REG_X0, value: AARCH64_BOOT_INFO_ADDR },
        RegWrite { id: AARCH64_REG_X1, value: 0 },
        RegWrite { id: AARCH64_REG_X2, value: 0 },
        RegWrite { id: AARCH64_REG_X3, value: 0 },
        RegWrite { id: AARCH64_REG_PC, value: entry_point },
        RegWrite { id: AARCH64_REG_PSTATE, value: AARCH64_PSTATE_EL1H_DAIF },
    ];

    Ok(Aarch64Handoff { boot_info_addr: AARCH64_BOOT_INFO_ADDR, info, regs })
}

// ===========================================================================
// Compile-time guards (break the build if the frozen layout ever drifts)
// ===========================================================================

const _: () = assert!(AARCH64_BOOT_INFO_ADDR + TbBootInfo::SIZE as u64 <= AARCH64_MEM_REGIONS_ADDR);
const _: () = assert!(AARCH64_MEM_REGIONS_ADDR < AARCH64_CMDLINE_ADDR);
const _: () = assert!(AARCH64_CMDLINE_ADDR < AARCH64_IMAGE_LMA);
const _: () = assert!(KVM_REG_ARM_CORE_BASE == 0x6030_0000_0010_0000);
const _: () = assert!(AARCH64_REG_PC == 0x6030_0000_0010_0040);
const _: () = assert!(AARCH64_REG_PSTATE == 0x6030_0000_0010_0042);

// ===========================================================================
// Tests (std harness; the crate is no_std in non-test builds)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{regions_from_bytes, MemKind, TB_BOOT_MAGIC, TB_BOOT_VERSION};

    /// A guest-RAM buffer big enough for the boot block: covers
    /// `[0x4000_0000, 0x4002_0000)` (128 KiB), which contains the whole block.
    fn ram() -> Vec<u8> {
        vec![0u8; 0x2_0000]
    }

    /// THE contract round-trip: producer -> serialize -> parse recovers the
    /// SAME `TbBootInfo` (magic/version validated) and the SAME region array.
    #[test]
    fn producer_serialize_parse_roundtrip() {
        let mut ram = ram();
        let regions = [
            TbMemRegion::new(0x4000_0000, 0x0800_0000, MemKind::Ram),
            TbMemRegion::new(0x4800_0000, 0x0001_0000, MemKind::Reserved),
        ];
        let cmdline = b"console=ttyAMA0 ro";
        let entry = 0x4008_0000u64;

        let h = build_handoff(&mut ram, &regions, cmdline, entry).unwrap();

        // Parse the TbBootInfo back out of guest RAM at the X0 address.
        let off = (h.boot_info_addr - AARCH64_GUEST_RAM_BASE) as usize;
        let back = TbBootInfo::read_validated(&ram[off..]).unwrap();
        assert_eq!(back, h.info, "round-trip must recover the produced TbBootInfo");
        assert_eq!(back.magic, TB_BOOT_MAGIC);
        assert_eq!(back.version, TB_BOOT_VERSION);
        assert_eq!(back.kernel_entry, entry);
        assert_eq!(back.mem_regions_ptr, AARCH64_MEM_REGIONS_ADDR);
        assert_eq!(back.mem_regions_len, regions.len() as u64);
        assert_eq!(back.cmdline_ptr, AARCH64_CMDLINE_ADDR);
        assert_eq!(back.cmdline_len, cmdline.len() as u64);

        // Parse the region array back out and compare element-for-element.
        let roff = (back.mem_regions_ptr - AARCH64_GUEST_RAM_BASE) as usize;
        let got: Vec<_> = regions_from_bytes(&ram[roff..], back.mem_regions_len).collect();
        assert_eq!(got.as_slice(), &regions[..]);

        // The cmdline (+ NUL) round-trips byte-for-byte.
        let coff = (back.cmdline_ptr - AARCH64_GUEST_RAM_BASE) as usize;
        assert_eq!(&ram[coff..coff + cmdline.len()], cmdline);
        assert_eq!(ram[coff + cmdline.len()], 0, "cmdline must be NUL-terminated");
    }

    #[test]
    fn handoff_register_file_is_the_frozen_contract() {
        let mut ram = ram();
        let regions = [TbMemRegion::new(0x4000_0000, 0x0800_0000, MemKind::Ram)];
        let entry = 0x4008_0000u64;
        let h = build_handoff(&mut ram, &regions, b"", entry).unwrap();

        // Exact IDs (KVM ONE_REG encoding) + values (the arm64 tb-boot contract).
        assert_eq!(h.regs[0], RegWrite { id: 0x6030_0000_0010_0000, value: AARCH64_BOOT_INFO_ADDR });
        assert_eq!(h.regs[1], RegWrite { id: 0x6030_0000_0010_0002, value: 0 });
        assert_eq!(h.regs[2], RegWrite { id: 0x6030_0000_0010_0004, value: 0 });
        assert_eq!(h.regs[3], RegWrite { id: 0x6030_0000_0010_0006, value: 0 });
        assert_eq!(h.regs[4], RegWrite { id: 0x6030_0000_0010_0040, value: entry });
        assert_eq!(h.regs[5], RegWrite { id: 0x6030_0000_0010_0042, value: 0x3c5 });
        assert_eq!(h.boot_info_addr, AARCH64_BOOT_INFO_ADDR);
        assert_eq!(AARCH64_PSTATE_EL1H_DAIF, 0x3c5);
    }

    #[test]
    fn reg_id_constants_match_kvm_arm64_one_reg_table() {
        assert_eq!(KVM_REG_ARM_CORE_BASE, 0x6030_0000_0010_0000);
        assert_eq!(AARCH64_REG_X0, 0x6030_0000_0010_0000);
        assert_eq!(AARCH64_REG_X1, 0x6030_0000_0010_0002);
        assert_eq!(AARCH64_REG_X2, 0x6030_0000_0010_0004);
        assert_eq!(AARCH64_REG_X3, 0x6030_0000_0010_0006);
        assert_eq!(AARCH64_REG_PC, 0x6030_0000_0010_0040);
        assert_eq!(AARCH64_REG_PSTATE, 0x6030_0000_0010_0042);
    }

    #[test]
    fn boot_block_stays_below_the_image_base() {
        let mut ram = ram();
        let regions = [TbMemRegion::new(0x4000_0000, 0x0800_0000, MemKind::Ram)];
        let cmdline = b"ro";
        let h = build_handoff(&mut ram, &regions, cmdline, 0x4008_0000).unwrap();
        // Every produced address (info, regions, cmdline+NUL) < the image LMA.
        assert!(h.boot_info_addr + TbBootInfo::SIZE as u64 <= AARCH64_IMAGE_LMA);
        let regions_end = AARCH64_MEM_REGIONS_ADDR + regions.len() as u64 * TbMemRegion::SIZE as u64;
        assert!(regions_end <= AARCH64_CMDLINE_ADDR);
        assert!(AARCH64_CMDLINE_ADDR + (cmdline.len() as u64) < AARCH64_IMAGE_LMA);
    }

    #[test]
    fn rejects_too_many_regions() {
        let mut ram = ram();
        // The window [MEM_REGIONS_ADDR, CMDLINE_ADDR) is 0x7C0 bytes = 50 regions.
        let max = ((AARCH64_CMDLINE_ADDR - AARCH64_MEM_REGIONS_ADDR) / TbMemRegion::SIZE as u64) as usize;
        let many = vec![TbMemRegion::new(0, 0x1000, MemKind::Ram); max + 1];
        assert_eq!(
            build_handoff(&mut ram, &many, b"", 0x4008_0000),
            Err(Aarch64HandoffError::TooManyRegions)
        );
    }

    #[test]
    fn rejects_overlong_cmdline() {
        let mut ram = ram();
        let regions = [TbMemRegion::new(0x4000_0000, 0x0800_0000, MemKind::Ram)];
        let huge = vec![b'x'; (AARCH64_IMAGE_LMA - AARCH64_CMDLINE_ADDR) as usize + 1];
        assert_eq!(
            build_handoff(&mut ram, &regions, &huge, 0x4008_0000),
            Err(Aarch64HandoffError::CmdlineTooLong)
        );
    }

    #[test]
    fn rejects_ram_slice_too_small() {
        // RAM that ends before the cmdline window: the region write itself is
        // fine, but the cmdline write runs off the end -> RamTooSmall.
        let mut tiny = vec![0u8; 0x1500]; // covers up to 0x4000_1500 only
        let regions = [TbMemRegion::new(0x4000_0000, 0x0800_0000, MemKind::Ram)];
        assert_eq!(
            build_handoff(&mut tiny, &regions, b"ro", 0x4008_0000),
            Err(Aarch64HandoffError::RamTooSmall)
        );
    }

    #[test]
    fn error_display_is_nonempty() {
        for e in [
            Aarch64HandoffError::TooManyRegions,
            Aarch64HandoffError::CmdlineTooLong,
            Aarch64HandoffError::RamTooSmall,
        ] {
            assert!(!format!("{e}").is_empty());
        }
    }
}
