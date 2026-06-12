//! aarch64 boot memory-map source for M6 (QEMU `virt`) — extended at aL2.4b
//! with the **`TbBootInfo.mem_regions` branch** (x86 parity) and the
//! **guest-RAM carve reservation**.
//!
//! Two boot paths feed the SAME frame allocator (the x86_64 `pmm.rs` shape):
//!  * **FDT / `_start`** (QEMU `virt`, the host): the HARD-CODED `virt` RAM
//!    map — RAM = `[0x4000_0000, +128 MiB)` clamped to the M3 identity RAM
//!    gigabyte — plus the precise DTB reservation, PLUS (aL2.4b) the
//!    **top-32 MiB guest-RAM carve `[0x4600_0000, 0x4800_0000)` reserved** so
//!    the host never hands out a frame the EL1 guest's stage-2 owns.
//!  * **tb-boot v0 / `_tb_start`** (tb-vmm, or the aL2.4b in-guest boot):
//!    `boot_info` = the address of a validated `tb_boot::TbBootInfo`; its
//!    `TbMemRegion[]` IS the memory map (Ram → usable, everything else →
//!    reserved). This is the port the aL2.4b survey names MISSING #3: an
//!    unported guest would believe it owns 128 MiB and `frame_alloc` straight
//!    into unmapped stage-2 → spurious aborts. The boot block + region array +
//!    cmdline are reserved via the conventional sub-image staging window.
//!
//! The two are told apart exactly as `crate::read_boot_magic` does: the 8-byte
//! word at offset 0 equals `tb_boot::TB_BOOT_MAGIC` for tb-boot; the FDT
//! header's big-endian `0xD00DFEED` never matches, so the host path falls to
//! the FDT branch. Every read is GUARDED to the identity RAM gigabyte
//! `[0x4000_0000, 0x8000_0000)`, byte-wise volatile, with `saturating_add`
//! pointer math — a garbage block fail-closes (no usable frames) instead of
//! faulting, mirroring `x86_64/pmm.rs`.
//!
//! Verified facts:
//!  * QEMU `virt` DRAM base `0x4000_0000`; the kernel links at `+512 KiB`
//!    (`0x4008_0000`, see `kernel/linker/aarch64.ld`); device MMIO is all below
//!    DRAM (QEMU `hw/arm/virt.c` memmap).
//!  * FDT header layout (Devicetree Specification v0.4 §5.2): big-endian
//!    `magic` then `totalsize` as the first two 32-bit words.
//!  * The carve geometry is the Kani-locked `tb_encode::stage2` leaf
//!    (`GUEST_CARVE_PA`/`GUEST_CARVE_SIZE`) — one source of truth.

use crate::pmm::RegionSink;
use tb_boot::{TbBootInfo, TbMemRegion, TB_BOOT_MAGIC};
use tb_encode::stage2::{GUEST_CARVE_PA, GUEST_CARVE_SIZE};

/// QEMU `virt` DRAM base.
const DRAM_BASE: u64 = 0x4000_0000;

/// QEMU `virt` runner RAM size (`-m 128M`).
const DRAM_SIZE: u64 = 128 * 1024 * 1024;

/// Upper bound of the M3 identity-mapped RAM gigabyte (L1[1] Normal-WB block):
/// `[0x4000_0000, 0x8000_0000)`. Usable RAM is clamped here because the
/// intrusive free-frame links are written through identity addresses, and only
/// this gigabyte of RAM is identity-mapped.
const ID_RAM_HI: u64 = 0x8000_0000;

/// Kernel image link base (`KERNEL_LMA` in `kernel/linker/aarch64.ld`). The
/// 512 KiB of DRAM below it is where QEMU stages the DTB / boot params, so it is
/// reserved wholesale as a conservative DTB margin.
const IMAGE_LMA: u64 = 0x4008_0000;

/// FDT header magic, as a big-endian 32-bit word (Devicetree Spec §5.2).
const FDT_MAGIC: u32 = 0xD00D_FEED;

/// Guarded big-endian `u32` read inside the identity-mapped RAM gigabyte. The
/// QEMU `virt` DTB lives in DRAM, so the FDT header is reachable here; an
/// out-of-window pointer simply yields `None` (no DTB reservation, never a
/// fault).
fn read_be32(pa: u64) -> Option<u32> {
    if pa < DRAM_BASE {
        return None;
    }
    match pa.checked_add(4) {
        Some(end) if end <= ID_RAM_HI => {}
        _ => return None,
    }
    let mut b = [0u8; 4];
    let mut i = 0u64;
    while i < 4 {
        // SAFETY: `[pa, pa + 4)` is inside the identity-mapped Normal-WB RAM
        // gigabyte; a `u8` load imposes no alignment, and `read_volatile` keeps
        // the optimiser from reordering/eliding the foreign boot-blob read.
        b[i as usize] = unsafe { ((pa + i) as *const u8).read_volatile() };
        i += 1;
    }
    Some(u32::from_be_bytes(b))
}

/// FDT `totalsize` if `boot_info` points at a valid FDT header (magic matches
/// and the size is sane), else `None`.
fn fdt_totalsize(fdt: u64) -> Option<u32> {
    if read_be32(fdt)? != FDT_MAGIC {
        return None;
    }
    let total = read_be32(fdt + 4)?;
    // A QEMU `virt` DTB is well under 2 MiB; reject anything implausible so a
    // garbage read can never produce a giant reservation.
    if total == 0 || total > 0x20_0000 {
        return None;
    }
    Some(total)
}

// ---------------------------------------------------------------------------
// aL2.4b: the tb-boot `TbBootInfo.mem_regions` reader (x86 `collect_tb_boot`
// parity). Guarded byte-wise volatile reads inside the identity RAM gigabyte;
// every data-derived pointer uses `saturating_*` so a garbage block can never
// overflow-panic — it fail-closes (the walk stops, no usable frames pushed).
// ---------------------------------------------------------------------------

/// Read `buf.len()` bytes starting at physical `pa`, guarded to
/// `[DRAM_BASE, ID_RAM_HI)`. `false` if the span does not fit the window.
fn read_bytes(pa: u64, buf: &mut [u8]) -> bool {
    let n = buf.len() as u64;
    if pa < DRAM_BASE {
        return false;
    }
    match pa.checked_add(n) {
        Some(end) if end <= ID_RAM_HI => {}
        _ => return false,
    }
    let mut i = 0u64;
    while i < n {
        // SAFETY: `[pa, pa + n)` is inside the identity-mapped (or, pre-MMU,
        // flat) Normal-WB RAM gigabyte; a `u8` load imposes no alignment, and
        // `read_volatile` keeps the optimiser from reordering/eliding the
        // foreign boot-blob read — exactly `read_be32`'s contract.
        buf[i as usize] = unsafe { ((pa + i) as *const u8).read_volatile() };
        i += 1;
    }
    true
}

/// Parse a tb-boot `TbBootInfo` (validated via the crate) into usable +
/// reserved spans. Returns `false` when `bi` does not carry a valid tb-boot
/// block (the caller then falls to the FDT branch). The aarch64 mirror of
/// `x86_64/pmm.rs::collect_tb_boot`, clamped to the identity RAM gigabyte.
fn collect_tb_boot(bi: u64, sink: &mut RegionSink) -> bool {
    let mut head = [0u8; TbBootInfo::SIZE];
    if !read_bytes(bi, &mut head) {
        return false;
    }
    let info = match TbBootInfo::read_validated(&head) {
        Ok(i) => i,
        Err(_) => return false,
    };

    // Reserve the boot structures themselves (the aL2.4b/aarch64 producer
    // places them in the sub-image staging window, but reserve them explicitly
    // so the policy is source-independent — the x86 discipline).
    sink.push_reserved(bi, TbBootInfo::SIZE as u64);
    let regions_ptr = info.mem_regions_ptr;
    let count = info.mem_regions_len;
    sink.push_reserved(regions_ptr, count.saturating_mul(TbMemRegion::SIZE as u64));
    if info.cmdline_ptr != 0 && info.cmdline_len != 0 {
        sink.push_reserved(info.cmdline_ptr, info.cmdline_len);
    }
    // The conventional staging window below the image stays reserved on this
    // path too (the boot block lives inside it; the image reservation is added
    // by the shared pmm layer).
    sink.push_reserved(DRAM_BASE, IMAGE_LMA - DRAM_BASE);

    let mut i = 0u64;
    while i < count {
        let rpa = regions_ptr.saturating_add(i.saturating_mul(TbMemRegion::SIZE as u64));
        let mut rb = [0u8; TbMemRegion::SIZE];
        if !read_bytes(rpa, &mut rb) {
            break;
        }
        if let Ok(r) = TbMemRegion::read_from_prefix(&rb) {
            // Clamp usable RAM to the identity gigabyte (the intrusive
            // free-frame links are written through identity addresses).
            if r.is_ram() {
                let base = r.base.max(DRAM_BASE);
                let end = r.base.saturating_add(r.len).min(ID_RAM_HI);
                if end > base {
                    sink.push_usable(base, end - base);
                }
            } else {
                sink.push_reserved(r.base, r.len);
            }
        }
        i += 1;
    }
    true
}

/// Collect usable-RAM ranges + reservations for aarch64 (QEMU `virt`).
///
/// Dispatches on the boot-info magic (the `read_boot_magic` discipline):
///  * a validated `TbBootInfo` → its `mem_regions` ARE the map (the
///    `_tb_start` paths: tb-vmm, the aL2.4b confined guest);
///  * anything else (the QEMU `virt` FDT pointer) → the hard-coded `virt`
///    map clamped to the identity gigabyte, the DTB staging-window + exact
///    DTB-span reservations, AND the aL2.4b guest-RAM carve reservation
///    (`[GUEST_CARVE_PA, +GUEST_CARVE_SIZE)`) so the host pmm can never hand
///    out a frame inside the EL1 guest's stage-2 window.
///
/// The shared `pmm` layer adds the kernel-image reservation on top.
pub fn pmm_collect_regions(boot_info: usize, sink: &mut RegionSink) {
    let bi = boot_info as u64;

    // tb-boot v0 branch (x86 parity, aL2.4b MISSING-#3 port): an 8-byte magic
    // probe via the same guarded reader, then the full validated parse.
    let mut magic = [0u8; 8];
    if read_bytes(bi, &mut magic) && u64::from_le_bytes(magic) == TB_BOOT_MAGIC {
        if collect_tb_boot(bi, sink) {
            return;
        }
    }

    let fdt = bi;

    // (1) Usable RAM: the QEMU `virt` map, clamped to the identity gigabyte.
    let end = (DRAM_BASE + DRAM_SIZE).min(ID_RAM_HI);
    if end > DRAM_BASE {
        sink.push_usable(DRAM_BASE, end - DRAM_BASE);
    }

    // (2) Reserve the low-RAM window below the kernel image (DTB / boot params).
    sink.push_reserved(DRAM_BASE, IMAGE_LMA - DRAM_BASE);

    // (3) Reserve the exact DTB span wherever QEMU placed it (best-effort).
    if let Some(total) = fdt_totalsize(fdt) {
        sink.push_reserved(fdt, total as u64);
    }

    // (4) aL2.4b: reserve the guest-RAM carve — the top 32 MiB the EL1
    // guest's stage-2 maps as ITS RAM. The host never allocates a frame here;
    // the run-script `-device loader` stages the guest image inside it. The
    // geometry comes from the Kani-locked tb-encode leaf (one source of truth).
    sink.push_reserved(GUEST_CARVE_PA, GUEST_CARVE_SIZE);
}
