//! M14.1 -- the aarch64 cross-address-space user-buffer copy primitive
//! (`copy_to_user` / `copy_from_user`). The ONE deliberately-deferred M14
//! `unsafe`, lifted here -- the symmetric twin of the x86_64 `uaccess`.
//!
//! MECHANISM: a SOFTWARE 3-level (L1 -> L2 -> L3) translation-table walk against
//! an EXPLICIT TTBR0 root PA (NOT the live TTBR0_EL1), reaching the translated
//! frame through the kernel EL1 identity alias (the M3 tables identity-map the
//! RAM gigabyte [1 GiB, 2 GiB), so a frame PA in that window == its EL1 VA). It
//! therefore works when NEITHER agent root is live, needs zero TTBR0/TLB churn
//! on this single core, and sidesteps PAN (PSTATE.PAN, the SMAP analog) by
//! construction: every access is through the EL1 identity alias, never the EL0
//! VA.
//!
//! FAIL-CLOSED (Arm ARM VMSAv8-64, transcribed in `mmu.rs`): every interior
//! descriptor (L1/L2) must be a VALID TABLE (low bits 0b11) -- a block
//! descriptor (0b01) in the user range is rejected as `NotPresent` (TABOS maps
//! only 4 KiB user leaves); the L3 leaf must be a valid PAGE (0b11) with the
//! Access Flag (`AF`, bit 10) set and EL0 access enabled (`AP[1]` = bit 6) else
//! `NotUser`, and for a write `AP[2]` (bit 7, read-only) must be CLEAR else
//! `NotWritable`. The translated frame is asserted inside the identity-mapped
//! RAM gigabyte BEFORE any access -- each failure is a typed [`CopyFault`].
//!
//! BYTE-GRANULAR + PAGE-BY-PAGE: the copy walks one page at a time and copies
//! bytes, so an arbitrary EL0 VA never triggers an unaligned access.
//!
//! ALL the aarch64 `unsafe` of this milestone lives here; the kernel
//! orchestrates it only through the safe `tb-hal` facade.

use core::ptr::{copy_nonoverlapping, read_volatile};

use crate::arch::CopyFault;
use crate::mmu::{entry_addr, level_index, ENTRY_ADDR_MASK, PAGE_SIZE, SHIFT_1G, SHIFT_2M, SHIFT_4K};

/// Descriptor low-bits type field (VMSAv8-64).
const DESC_TYPE_MASK: u64 = 0b11;
/// Valid TABLE descriptor (L0..L2): low bits 0b11 (Linux `PUD_TYPE_TABLE`).
const DESC_TABLE: u64 = 0b11;
/// Valid PAGE descriptor (L3 leaf): low bits 0b11 (Linux `PTE_TYPE_PAGE`).
const DESC_PAGE: u64 = 0b11;
/// Access Flag, bit[10] (Linux `PTE_AF`): MANDATORY on every live leaf (tb-hal
/// installs no AF-fault handler, so a cleared AF would abort on first access).
const DESC_AF: u64 = 1 << 10;
/// AP[1] = bit[6] (Linux `PTE_USER`): set => EL0 may access the leaf.
const AP_EL0: u64 = 1 << 6;
/// AP[2] = bit[7] (Linux `PTE_RDONLY`): set => read-only at the granted EL(s).
const AP_RDONLY: u64 = 1 << 7;

/// Identity-mapped RAM gigabyte base: QEMU `virt` RAM starts at 1 GiB, and the
/// M3 tables identity-map [1 GiB, 2 GiB) Normal-WB, so a frame PA in this window
/// equals its EL1 VA and is safe to access through that alias.
const RAM_BASE: u64 = 0x4000_0000;
/// Identity-mapped RAM gigabyte limit (2 GiB). A leaf at/outside [RAM_BASE,
/// RAM_LIMIT) faults [`CopyFault::NotInPhysmap`] before any byte moves.
const RAM_LIMIT: u64 = 0x8000_0000;

/// Low 12 bits = the in-page offset of a 4 KiB page.
const PAGE_OFF_MASK: u64 = (PAGE_SIZE as u64) - 1;

/// PURE leaf-permission classifier (no memory access): the statically
/// verifiable core the boot self-test then exercises against real frames.
/// Requires a valid PAGE leaf with `AF`, EL0-accessible (`AP[1]`); a write
/// additionally requires `AP[2]` (read-only) CLEAR. One [`CopyFault`] per
/// failure, fail-closed.
fn classify_leaf(desc: u64, write: bool) -> Result<(), CopyFault> {
    if desc & DESC_TYPE_MASK != DESC_PAGE || desc & DESC_AF == 0 {
        return Err(CopyFault::NotPresent);
    }
    if desc & AP_EL0 == 0 {
        return Err(CopyFault::NotUser);
    }
    if write && desc & AP_RDONLY != 0 {
        return Err(CopyFault::NotWritable);
    }
    Ok(())
}

/// PURE page-splitting helper: iterate `(buf_offset, page_va, in_page_len)`
/// chunks that split a `len`-byte access starting at `uva` on 4 KiB page
/// boundaries. The cumulative `in_page_len`s sum EXACTLY to `len`, each chunk
/// lies within ONE page (`page_off + in_page_len <= 4096`) and never exceeds the
/// remaining `len` -- the bounds the copy loop relies on. Allocation-free.
fn span_pages(uva: u64, len: usize) -> impl Iterator<Item = (usize, u64, usize)> {
    let mut done = 0usize;
    core::iter::from_fn(move || {
        if done >= len {
            return None;
        }
        let cur = uva.wrapping_add(done as u64);
        let off = (cur & PAGE_OFF_MASK) as usize;
        let in_page = core::cmp::min(PAGE_SIZE - off, len - done);
        let start = done;
        done += in_page;
        Some((start, cur, in_page))
    })
}

/// Software-walk the 3-level table rooted at `root_pa` for `uva`, returning the
/// leaf PHYSICAL address (`leaf_pa | page_offset`). Requires a VALID TABLE
/// descriptor at L1 AND L2; the L3 leaf is classified by [`classify_leaf`].
fn walk_user(root_pa: u64, uva: u64, write: bool) -> Result<u64, CopyFault> {
    // The two interior levels (L1, L2); the L3 page leaf is handled below.
    const INTERIOR: [u32; 2] = [SHIFT_1G, SHIFT_2M];
    let mut table = root_pa & ENTRY_ADDR_MASK;
    let mut lvl = 0;
    while lvl < INTERIOR.len() {
        let idx = level_index(uva, INTERIOR[lvl]);
        // SAFETY: `table` is an identity-mapped translation-table frame (PA == VA
        // in the RAM gigabyte), 4 KiB-aligned; `idx < 512` keeps the 8-byte read
        // inside that frame. `read_volatile` stops the optimiser caching a stale
        // descriptor. The root is explicit (possibly not-live), so this never
        // depends on / disturbs TTBR0_EL1.
        let entry = unsafe { read_volatile((table as *const u64).add(idx)) };
        // A valid TABLE descriptor (0b11) is required; a block leaf (0b01) or an
        // invalid entry in the user range is rejected fail-closed.
        if entry & DESC_TYPE_MASK != DESC_TABLE {
            return Err(CopyFault::NotPresent);
        }
        table = entry_addr(entry);
        lvl += 1;
    }
    let idx = level_index(uva, SHIFT_4K);
    // SAFETY: as above -- `table` is the identity-mapped L3 frame, `idx < 512`.
    let leaf = unsafe { read_volatile((table as *const u64).add(idx)) };
    classify_leaf(leaf, write)?;
    Ok(entry_addr(leaf) | (uva & PAGE_OFF_MASK))
}

/// Copy `len` bytes between the kernel buffer `kbuf` and the user buffer at
/// `uva` in the space rooted at `root_pa`, PAGE BY PAGE. `to_user == true`
/// WRITES the user buffer (`copy_to_user`; `kbuf` is read-only, the leaf must
/// permit EL0 write); `false` READS it (`copy_from_user`; `kbuf` is written).
/// Every page is walked, its leaf PA asserted inside the identity-mapped RAM
/// gigabyte, and the in-page slice byte-copied through that PA's EL1 alias.
///
/// # Safety
/// `kbuf` must be valid for `len` bytes -- for reads (`!to_user`) writable, for
/// writes (`to_user`) at least readable. The caller derives `kbuf`/`len` from a
/// real kernel slice, so the per-chunk `kbuf.add(start)` with `start + in_page
/// <= len` stays in-bounds. The user side is bounds- and permission-checked per
/// page by [`walk_user`] + the RAM-window assert before any access.
unsafe fn copy_span(
    root_pa: u64,
    uva: u64,
    kbuf: *mut u8,
    len: usize,
    to_user: bool,
) -> Result<(), CopyFault> {
    for (start, page_va, in_page) in span_pages(uva, len) {
        let pa = walk_user(root_pa, page_va, to_user)?;
        // Fail-closed: the whole in-page slice MUST sit inside the identity RAM
        // gigabyte, or the EL1 alias would be a wild deref.
        if pa < RAM_BASE || pa + (in_page as u64) > RAM_LIMIT {
            return Err(CopyFault::NotInPhysmap);
        }
        // SAFETY: `pa` is a 4 KiB-granule leaf PA proven inside [1 GiB, 2 GiB),
        // so its identity alias is a valid EL1 mapping (writable for a `to_user`
        // write -- the leaf was AP[2]-checked; readable for a `from_user` read).
        // `in_page` stays within this page AND within `kbuf` (`start + in_page <=
        // len`). Byte-granular copy -> never an unaligned access; the kernel heap
        // and identity RAM never overlap, so `copy_nonoverlapping` is sound.
        unsafe {
            let phys = pa as *mut u8;
            let kp = kbuf.add(start);
            if to_user {
                copy_nonoverlapping(kp as *const u8, phys, in_page);
            } else {
                copy_nonoverlapping(phys as *const u8, kp, in_page);
            }
        }
    }
    Ok(())
}

/// M14.1 `copy_from_user`: read `dst.len()` bytes from `src_uva` in the space
/// whose top-level root PA is `root_pa` into the kernel slice `dst`. Read access
/// (no AP[2] requirement). Fail-closed [`CopyFault`] on any not-present /
/// not-user / not-in-physmap leaf.
pub fn copy_from_user(root_pa: u64, src_uva: u64, dst: &mut [u8]) -> Result<(), CopyFault> {
    // SAFETY: `dst` is a valid kernel slice; `copy_span` writes exactly
    // `dst.len()` bytes into it (from_user => to_user=false), in-bounds by the
    // per-chunk `start + in_page <= len` invariant.
    unsafe { copy_span(root_pa, src_uva, dst.as_mut_ptr(), dst.len(), false) }
}

/// M14.1 `copy_to_user`: write the kernel slice `src` into `dst_uva` in the
/// space whose top-level root PA is `root_pa`. Write access (the destination
/// leaf must be EL0-writable, AP[2] clear). Fail-closed [`CopyFault`] on any
/// not-present / not-user / not-writable / not-in-physmap leaf BEFORE any byte
/// is written through it.
pub fn copy_to_user(root_pa: u64, dst_uva: u64, src: &[u8]) -> Result<(), CopyFault> {
    // SAFETY: `src` is a valid kernel slice; `copy_span` only READS `src.len()`
    // bytes from it (to_user => to_user=true) -- the `*mut` is never written
    // through -- so casting away const is sound here.
    unsafe { copy_span(root_pa, dst_uva, src.as_ptr() as *mut u8, src.len(), true) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_leaf_rejects_every_bad_combination() {
        let base = DESC_PAGE | DESC_AF; // a valid present page leaf
        // Invalid type / cleared AF -> NotPresent.
        assert_eq!(classify_leaf(0, false), Err(CopyFault::NotPresent));
        assert_eq!(classify_leaf(DESC_PAGE | AP_EL0, false), Err(CopyFault::NotPresent)); // AF clear
        assert_eq!(classify_leaf(0b01 | DESC_AF | AP_EL0, false), Err(CopyFault::NotPresent)); // block
        // Present page but EL0 not enabled -> NotUser.
        assert_eq!(classify_leaf(base, false), Err(CopyFault::NotUser));
        // Present + EL0 + read-only, write requested -> NotWritable.
        assert_eq!(classify_leaf(base | AP_EL0 | AP_RDONLY, true), Err(CopyFault::NotWritable));
        // Present + EL0 is enough for a READ (even when read-only).
        assert_eq!(classify_leaf(base | AP_EL0 | AP_RDONLY, false), Ok(()));
        // Present + EL0 + writable is enough for a WRITE.
        assert_eq!(classify_leaf(base | AP_EL0, true), Ok(()));
    }

    #[test]
    fn span_pages_never_escapes_a_page_and_sums_to_len() {
        for &(uva, len) in &[
            (0x4000_0000u64, 0usize),
            (0x4000_0000, 4096),
            (0x4000_0FF8, 1),
            (0x4000_0FF8, 16),   // straddles a page boundary
            (0x4000_0123, 9000), // > 2 pages from an unaligned base
        ] {
            let mut total = 0usize;
            let mut last_end = 0usize;
            for (start, page_va, in_page) in span_pages(uva, len) {
                let off = (page_va & PAGE_OFF_MASK) as usize;
                assert!(in_page >= 1);
                assert!(off + in_page <= PAGE_SIZE, "chunk escaped its page");
                assert_eq!(start, last_end, "chunks must be contiguous");
                assert!(start + in_page <= len, "chunk exceeded len");
                last_end = start + in_page;
                total += in_page;
            }
            assert_eq!(total, len, "chunks must cover exactly len");
        }
    }
}
