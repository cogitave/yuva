//! aarch64 boot memory-map source for M6 (QEMU `virt`).
//!
//! FALLBACK CHOSEN (per the ROADMAP-V2 M6 risk note): rather than a full
//! from-scratch no_std FDT *node* walker, this uses the HARD-CODED QEMU `virt`
//! RAM map — RAM = `[0x4000_0000, 0x4000_0000 + 128 MiB)` (the runner uses
//! `-m 128M`) — as the usable-RAM source, clamped to the M3 identity-mapped RAM
//! gigabyte `[0x4000_0000, 0x8000_0000)`. Because usable RAM is RANGE-restricted
//! to DRAM, every device MMIO window is excluded NATURALLY: the PL011 UART
//! (`0x0900_0000`), the GIC, and the virtio-mmio transports all sit BELOW
//! `0x4000_0000` and can never be handed out.
//!
//! The DTB is still reserved PRECISELY: the FDT header is big-endian, with
//! `magic@0 = 0xD00DFEED` and `totalsize@4`. We read those two words (guarded)
//! straight from the `boot_info` pointer QEMU left in `x0`, and reserve exactly
//! `[fdt, fdt + totalsize)` wherever QEMU placed the blob — plus the
//! conventional low-RAM staging window below the kernel image. A full
//! `/memory` + `/reserved-memory` FDT parse is the post-M6 upgrade; until then
//! the hard-coded map is the correct, bounded answer for the `virt` runner.
//!
//! Verified facts:
//!  * QEMU `virt` DRAM base `0x4000_0000`; the kernel links at `+512 KiB`
//!    (`0x4008_0000`, see `kernel/linker/aarch64.ld`); device MMIO is all below
//!    DRAM (QEMU `hw/arm/virt.c` memmap).
//!  * FDT header layout (Devicetree Specification v0.4 §5.2): big-endian
//!    `magic` then `totalsize` as the first two 32-bit words.

use crate::pmm::RegionSink;

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

/// Collect usable-RAM ranges + reservations for aarch64 (QEMU `virt`).
///
/// Usable RAM is the hard-coded `virt` map clamped to the identity gigabyte;
/// reservations are the low-RAM DTB staging window below the image plus the
/// exact DTB span (read from the FDT header). The shared `pmm` layer adds the
/// kernel-image reservation on top.
pub fn pmm_collect_regions(boot_info: usize, sink: &mut RegionSink) {
    let fdt = boot_info as u64;

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
}
