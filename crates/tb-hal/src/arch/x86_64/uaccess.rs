//! M14.1 -- the x86_64 cross-address-space user-buffer copy primitive
//! (`copy_to_user` / `copy_from_user`). The ONE deliberately-deferred M14
//! `unsafe`, lifted here.
//!
//! MECHANISM: a SOFTWARE 4-level page-table walk against an EXPLICIT top-level
//! root PA (NOT the live CR3), reaching the translated frame through the kernel
//! SUPERVISOR identity alias (the boot tables identity-map [0, 1 GiB), so a
//! frame PA in that window == its supervisor VA). It therefore works when
//! NEITHER agent root is live (the disarmed-timer self-test runs in the boot
//! root), needs zero CR3/TLB churn on this single core, and is SMAP-immune by
//! construction: every access is through a U/S=0 supervisor mapping, never the
//! user VA, so CR4.SMAP (a supervisor explicit access to a U/S=1 page) can never
//! fire (Intel SDM Vol.3A; the M4 `user.rs` note that an identity-address write
//! is SMAP-immune).
//!
//! FAIL-CLOSED: the walk requires `P` AND `U/S` at EVERY level (SDM Vol.3A 4.6:
//! a user access needs U/S=1 in every controlling entry), rejects any `PS` huge
//! leaf in the user range (TABOS maps only 4 KiB user leaves), enforces `R/W` on
//! the leaf for a write, and asserts the translated frame lies inside the boot
//! identity window BEFORE any access -- each failure is a typed [`CopyFault`],
//! never a wild deref.
//!
//! BYTE-GRANULAR + PAGE-BY-PAGE: the copy walks one page at a time (an unaligned
//! UVA spans >= 2 pages, mirroring rust-vmm's fragmented `get_slices`) and
//! copies bytes (`*const u8`/`*mut u8`), so an arbitrary user VA never triggers
//! an unaligned u64 access (the Linux unaligned-memory-access guidance).
//!
//! ALL the x86_64 `unsafe` of this milestone lives here; the kernel orchestrates
//! it only through the safe `tb-hal` facade.

use core::ptr::{copy_nonoverlapping, read_volatile};

use crate::arch::CopyFault;
use crate::mmu::{
    entry_addr, level_index, ENTRY_ADDR_MASK, PAGE_SIZE, SHIFT_1G, SHIFT_2M, SHIFT_4K, SHIFT_512G,
};

/// Paging-entry Present bit (SDM Vol.3A Table 4-15; Linux `_PAGE_BIT_PRESENT 0`).
const PTE_P: u64 = 1 << 0;
/// Paging-entry Read/Write bit (Linux `_PAGE_BIT_RW 1`).
const PTE_RW: u64 = 1 << 1;
/// Paging-entry User/Supervisor bit (Linux `_PAGE_BIT_USER 2`). U/S=1 is
/// required at EVERY level of a user translation (SDM Vol.3A 4.6).
const PTE_US: u64 = 1 << 2;
/// Page-Size bit (SDM Table 4-15; Linux `_PAGE_BIT_PSE 7`): a huge leaf
/// (2 MiB at PD / 1 GiB at PDPT). TABOS maps user memory only with 4 KiB leaves,
/// so a `PS` entry anywhere in the user walk is rejected fail-closed.
const PTE_PS: u64 = 1 << 7;

/// The boot identity window upper bound: boot.rs identity-maps [0, 1 GiB) with
/// 2 MiB pages, so a frame PA below this equals its kernel supervisor VA and is
/// safe to access through that alias. A translated leaf at/above it faults
/// [`CopyFault::NotInPhysmap`] before any byte moves.
const IDENTITY_LIMIT: u64 = 0x4000_0000;

/// Low 12 bits = the in-page offset of a 4 KiB page.
const PAGE_OFF_MASK: u64 = (PAGE_SIZE as u64) - 1;

/// PURE leaf-permission classifier (no memory access): the statically
/// verifiable core the boot self-test then exercises against real frames.
/// Requires the leaf `Present` AND user-reachable (`U/S`); a write additionally
/// requires `R/W`. One [`CopyFault`] variant per real failure, fail-closed.
fn classify_leaf(flags: u64, write: bool) -> Result<(), CopyFault> {
    if flags & PTE_P == 0 {
        return Err(CopyFault::NotPresent);
    }
    if flags & PTE_US == 0 {
        return Err(CopyFault::NotUser);
    }
    if write && flags & PTE_RW == 0 {
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

/// Software-walk the 4-level table rooted at `root_pa` for `uva`, returning the
/// leaf PHYSICAL address (`leaf_pa | page_offset`). Requires `PTE_P` AND
/// `PTE_US` at PML4/PDPT/PD AND the PT leaf; rejects any `PTE_PS` huge entry as
/// `NotPresent`; enforces `PTE_RW` on the leaf when `write`.
fn walk_user(root_pa: u64, uva: u64, write: bool) -> Result<u64, CopyFault> {
    // The three interior levels (PML4, PDPT, PD); the PT leaf is handled below.
    const INTERIOR: [u32; 3] = [SHIFT_512G, SHIFT_1G, SHIFT_2M];
    let mut table = root_pa & ENTRY_ADDR_MASK;
    let mut lvl = 0;
    while lvl < INTERIOR.len() {
        let idx = level_index(uva, INTERIOR[lvl]);
        // SAFETY: `table` is an identity-mapped page-table frame (PA == VA in the
        // boot identity window), 4 KiB-aligned; `idx < 512` keeps the 8-byte
        // read inside that frame. `read_volatile` stops the optimiser caching a
        // stale entry. The root is explicit (possibly not-live), so this never
        // depends on / disturbs CR3.
        let entry = unsafe { read_volatile((table as *const u64).add(idx)) };
        if entry & PTE_P == 0 {
            return Err(CopyFault::NotPresent);
        }
        if entry & PTE_US == 0 {
            return Err(CopyFault::NotUser);
        }
        // A huge page in the user range is never expected (4 KiB leaves only).
        if entry & PTE_PS != 0 {
            return Err(CopyFault::NotPresent);
        }
        table = entry_addr(entry);
        lvl += 1;
    }
    let idx = level_index(uva, SHIFT_4K);
    // SAFETY: as above -- `table` is the identity-mapped PT frame, `idx < 512`.
    let leaf = unsafe { read_volatile((table as *const u64).add(idx)) };
    classify_leaf(leaf, write)?;
    Ok(entry_addr(leaf) | (uva & PAGE_OFF_MASK))
}

/// Copy `len` bytes between the kernel buffer `kbuf` and the user buffer at
/// `uva` in the space rooted at `root_pa`, PAGE BY PAGE. `to_user == true`
/// WRITES the user buffer (`copy_to_user`; `kbuf` is read-only, the leaf must be
/// `R/W`); `false` READS the user buffer (`copy_from_user`; `kbuf` is written).
/// Every page is walked, its leaf PA asserted inside the boot identity window,
/// and the in-page slice byte-copied through that PA's supervisor identity alias.
///
/// # Safety
/// `kbuf` must be valid for `len` bytes -- for reads (`!to_user`) writable, for
/// writes (`to_user`) at least readable. The caller derives `kbuf`/`len` from a
/// real kernel slice, so the per-chunk `kbuf.add(start)` with `start + in_page
/// <= len` stays in-bounds. The user side is bounds- and permission-checked per
/// page by [`walk_user`] + the identity-window assert before any access.
unsafe fn copy_span(
    root_pa: u64,
    uva: u64,
    kbuf: *mut u8,
    len: usize,
    to_user: bool,
) -> Result<(), CopyFault> {
    for (start, page_va, in_page) in span_pages(uva, len) {
        let pa = walk_user(root_pa, page_va, to_user)?;
        // Fail-closed: the whole in-page slice MUST be inside the boot identity
        // window, or the supervisor alias would be a wild deref. (A 4 KiB leaf PA
        // < 1 GiB plus an in-page length <= 4096 can only reach up to the window
        // bound, but the explicit upper check keeps the contract local.)
        if pa >= IDENTITY_LIMIT || pa + (in_page as u64) > IDENTITY_LIMIT {
            return Err(CopyFault::NotInPhysmap);
        }
        // SAFETY: `pa` is a 4 KiB-granule leaf PA proven < 1 GiB, so its identity
        // alias is a valid supervisor mapping (RW for a `to_user` write -- the
        // leaf was `R/W`-checked; readable for a `from_user` read). `in_page`
        // stays within this page AND within `kbuf` (`start + in_page <= len`).
        // Byte-granular copy -> never an unaligned access; the kernel heap and
        // identity RAM never overlap, so `copy_nonoverlapping` is sound.
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
/// (no `R/W` requirement). Fail-closed [`CopyFault`] on any not-present /
/// not-user / not-in-physmap leaf; nothing is partially trusted by the caller
/// (the IPC layer treats ANY error as "nothing enqueued").
pub fn copy_from_user(root_pa: u64, src_uva: u64, dst: &mut [u8]) -> Result<(), CopyFault> {
    // SAFETY: `dst` is a valid kernel slice; `copy_span` writes exactly
    // `dst.len()` bytes into it (from_user => to_user=false), in-bounds by the
    // per-chunk `start + in_page <= len` invariant.
    unsafe { copy_span(root_pa, src_uva, dst.as_mut_ptr(), dst.len(), false) }
}

/// M14.1 `copy_to_user`: write the kernel slice `src` into `dst_uva` in the
/// space whose top-level root PA is `root_pa`. Write access (the destination
/// leaf must be `R/W`). Fail-closed [`CopyFault`] on any not-present / not-user /
/// not-writable / not-in-physmap leaf BEFORE any byte is written through it.
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
        // Not present -> NotPresent, regardless of the other bits / direction.
        assert_eq!(classify_leaf(0, false), Err(CopyFault::NotPresent));
        assert_eq!(classify_leaf(PTE_US | PTE_RW, false), Err(CopyFault::NotPresent));
        // Present but supervisor-only -> NotUser.
        assert_eq!(classify_leaf(PTE_P, false), Err(CopyFault::NotUser));
        assert_eq!(classify_leaf(PTE_P | PTE_RW, true), Err(CopyFault::NotUser));
        // Present + user + read-only, write requested -> NotWritable.
        assert_eq!(classify_leaf(PTE_P | PTE_US, true), Err(CopyFault::NotWritable));
        // Present + user is enough for a READ.
        assert_eq!(classify_leaf(PTE_P | PTE_US, false), Ok(()));
        // Present + user + writable is enough for a WRITE.
        assert_eq!(classify_leaf(PTE_P | PTE_US | PTE_RW, true), Ok(()));
    }

    #[test]
    fn span_pages_never_escapes_a_page_and_sums_to_len() {
        // An unaligned start spanning three pages, plus zero-length + aligned.
        for &(uva, len) in &[
            (0x2000_0000u64, 0usize),
            (0x2000_0000, 4096),
            (0x2000_0FF8, 1),
            (0x2000_0FF8, 16),   // straddles a page boundary
            (0x2000_0123, 9000), // > 2 pages from an unaligned base
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
