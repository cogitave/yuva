//! x86_64 boot memory-map reader for M6 — the ONE place the boot-info pointer
//! is dereferenced on x86_64.
//!
//! Two boot paths feed the SAME frame allocator, and are DESIGNED TO CONVERGE
//! on the same usable set for the same guest (both reduce to
//! `[__image_end, top_of_RAM)` once the shared sub-1 MiB + kernel-image +
//! boot-structure reservations are applied; QEMU may additionally carve a few
//! E820-reserved holes, so the two sets COINCIDE in practice rather than being
//! guaranteed bit-identical — and the M6 marker test does not assert cross-path
//! equality):
//!  * **PVH** (QEMU `microvm` / Firecracker): `boot_info` = phys addr of a Xen
//!    `struct hvm_start_info`; its `memmap` is an E820-style array of
//!    `hvm_memmap_table_entry`. `type == 1` is usable RAM; everything else is
//!    reserved.
//!  * **tb-boot v0** (the project's `tb-vmm`): `boot_info` = phys addr of a
//!    `tb_boot::TbBootInfo`; we parse its `TbMemRegion` array with the crate's
//!    OWN typed `#[repr(C)]` readers + constants (no hand-coded offsets).
//!
//! The two are told apart exactly as `crate::read_boot_magic` does: the 8-byte
//! word at offset 0 equals `tb_boot::TB_BOOT_MAGIC` for tb-boot, or the PVH
//! magic `0x336E_C578` ("xEn3") for PVH.
//!
//! Every read is GUARDED to the identity-mapped low window `[0x1000, 1 GiB)`
//! that BOTH x86_64 boot paths establish (PVH `_start`'s `__boot_pd`; tb-vmm's
//! Firecracker-shaped 2 MiB-page identity tables), so a stray/foreign pointer
//! can never fault the boot path — it just yields `None` and the allocator
//! fail-closes to "no usable frames". Reads are byte-wise volatile, so no
//! alignment assumption is imposed on the foreign boot block, and every
//! data-derived pointer arithmetic uses `saturating_add`, so even a block that
//! happens to carry the PVH magic plus garbage pointers fail-closes rather than
//! panicking. This also bakes in the assumption that `hvm_start_info` AND its
//! `memmap` array sit below 1 GiB: the PVH ABI only mandates they live below
//! 4 GiB, but QEMU microvm / Firecracker stage them in low memory; anything
//! above 1 GiB simply fail-closes (no usable frames) instead of being misread.
//!
//! Verified layouts (cross-checked against the in-repo PVH note emitter
//! `arch/x86_64/boot.rs`, `crates/tb-boot`, and the Xen ABI):
//!  * `hvm_start_info` (xen/include/public/arch-x86/hvm/start_info.h):
//!    `magic@0(u32)=0x336EC578`, `version@4(u32)`, `flags@8`, `nr_modules@12`,
//!    `modlist_paddr@16(u64)`, `cmdline_paddr@24(u64)`, `rsdp_paddr@32(u64)`,
//!    `memmap_paddr@40(u64)`, `memmap_entries@48(u32)`, `reserved@52(u32)`
//!    (56 bytes total for v1). `memmap_paddr`/`memmap_entries` exist only for
//!    version >= 1, so the reader gates the memmap walk on the version.
//!  * `hvm_memmap_table_entry`: `addr@0(u64)`, `size@8(u64)`, `type@16(u32)`,
//!    `reserved@20(u32)` (24 bytes); `type == 1` = `XEN_HVM_MEMMAP_TYPE_RAM`.
//!  * `hvm_modlist_entry`: `paddr@0(u64)`, `size@8(u64)`,
//!    `cmdline_paddr@16(u64)`, `reserved@24(u64)` (32 bytes); each module's
//!    `[paddr, size)` is reserved so initrd-class RAM is never handed out.

use crate::pmm::RegionSink;
use tb_boot::{TbBootInfo, TbMemRegion, TB_BOOT_MAGIC};

/// Bytes per frame.
const FRAME: u64 = 4096;

/// Lowest physical address the guarded readers will touch (rejects the null
/// page). Mirrors `crate::read_boot_magic`'s `WINDOW_LO`.
const ID_LO: u64 = 0x1000;

/// First address PAST the identity-mapped low window: 1 GiB. Both x86_64 boot
/// paths identity-map `[0, 1 GiB)` with 2 MiB pages, so any read below this is
/// present, and any usable RAM above this is NOT reachable by the intrusive
/// link writes — hence the clamp in [`push_usable_clamped`].
const ID_HI: u64 = 0x4000_0000;

/// The PVH `hvm_start_info` magic ("xEn3").
const PVH_MAGIC: u32 = 0x336E_C578;

/// E820 / PVH memmap entry type for usable RAM.
const MEMMAP_TYPE_RAM: u32 = 1;

// ---------------------------------------------------------------------------
// Guarded volatile readers (the BootMemMap generalisation of read_boot_magic).
// ---------------------------------------------------------------------------

/// Read `buf.len()` bytes starting at physical `pa`, guarded to
/// `[ID_LO, ID_HI)`. `false` (leaving `buf` partially written but unused) if the
/// whole span does not fit inside the identity window.
fn read_bytes(pa: u64, buf: &mut [u8]) -> bool {
    let n = buf.len() as u64;
    if pa < ID_LO {
        return false;
    }
    match pa.checked_add(n) {
        Some(end) if end <= ID_HI => {}
        _ => return false,
    }
    let mut i = 0u64;
    while i < n {
        // SAFETY: `[pa, pa + n)` is inside `[ID_LO, ID_HI)`, which both x86_64
        // boot paths identity-map present; a `u8` read imposes no alignment and
        // `read_volatile` keeps the optimiser from reordering/eliding these
        // foreign, single-producer boot reads.
        buf[i as usize] = unsafe { ((pa + i) as *const u8).read_volatile() };
        i += 1;
    }
    true
}

/// Guarded little-endian `u32` read, or `None` if out of window.
fn read_u32(pa: u64) -> Option<u32> {
    let mut b = [0u8; 4];
    if read_bytes(pa, &mut b) {
        Some(u32::from_le_bytes(b))
    } else {
        None
    }
}

/// Guarded little-endian `u64` read, or `None` if out of window.
fn read_u64(pa: u64) -> Option<u64> {
    let mut b = [0u8; 8];
    if read_bytes(pa, &mut b) {
        Some(u64::from_le_bytes(b))
    } else {
        None
    }
}

/// M6 boot diagnostic: print `label=0x<value>\n` over the early serial console.
/// TEMPORARY — surfaces what the active QEMU/Firecracker actually puts in the
/// PVH/tb-boot block so a CI-only "no usable frames" can be diagnosed from the
/// serial log without a local repro. (Removed once M6 is CI-green.)
fn dbg(label: &str, value: u64) {
    crate::serial_write_str(label);
    crate::serial_write_str("=0x");
    let mut shift: i32 = 60;
    while shift >= 0 {
        let nib = ((value >> shift) & 0xf) as u8;
        let c = if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) };
        crate::serial_write_byte(c);
        shift -= 4;
    }
    crate::serial_write_byte(b'\n');
}

// ---------------------------------------------------------------------------
// Range helpers (clamp everything to the identity window).
// ---------------------------------------------------------------------------

/// Push a usable RAM span, clamped to `[0, 1 GiB)`. The intrusive free-frame
/// links are written through identity addresses, which exist only inside the M3
/// identity map, so RAM above 1 GiB is deliberately dropped.
fn push_usable_clamped(sink: &mut RegionSink, base: u64, len: u64) {
    let end = base.saturating_add(len).min(ID_HI);
    if end > base {
        sink.push_usable(base, end - base);
    }
}

/// Reserve a span, clamped to `[0, 1 GiB)` so reservation bounds stay finite.
fn reserve_span(sink: &mut RegionSink, base: u64, len: u64) {
    if len == 0 {
        return;
    }
    let end = base.saturating_add(len).min(ID_HI);
    if end > base {
        sink.push_reserved(base, end - base);
    }
}

// ---------------------------------------------------------------------------
// The two boot-map readers.
// ---------------------------------------------------------------------------

/// Parse a tb-boot `TbBootInfo` (validated via the crate) into usable + reserved
/// spans. The boot block + region array + cmdline are all reserved.
fn collect_tb_boot(bi: u64, sink: &mut RegionSink) {
    let mut head = [0u8; TbBootInfo::SIZE];
    if !read_bytes(bi, &mut head) {
        return;
    }
    let info = match TbBootInfo::read_validated(&head) {
        Ok(i) => i,
        Err(_) => return,
    };

    // Reserve the boot structures themselves (tb-vmm places them below 1 MiB,
    // but reserve them explicitly so the policy is source-independent).
    reserve_span(sink, bi, TbBootInfo::SIZE as u64);
    let regions_ptr = info.mem_regions_ptr;
    let count = info.mem_regions_len;
    reserve_span(
        sink,
        regions_ptr,
        count.saturating_mul(TbMemRegion::SIZE as u64),
    );
    if info.cmdline_ptr != 0 && info.cmdline_len != 0 {
        reserve_span(sink, info.cmdline_ptr, info.cmdline_len);
    }

    let mut i = 0u64;
    while i < count {
        // `saturating_add`/`saturating_mul`: `regions_ptr` is unvalidated guest
        // data, so a garbage value must not overflow-panic — `read_bytes` then
        // guards the (possibly saturated) address and stops the walk.
        let rpa = regions_ptr.saturating_add(i.saturating_mul(TbMemRegion::SIZE as u64));
        let mut rb = [0u8; TbMemRegion::SIZE];
        if !read_bytes(rpa, &mut rb) {
            break;
        }
        if let Ok(r) = TbMemRegion::read_from_prefix(&rb) {
            if r.is_ram() {
                push_usable_clamped(sink, r.base, r.len);
            } else {
                reserve_span(sink, r.base, r.len);
            }
        }
        i += 1;
    }
}

/// Parse a PVH `hvm_start_info` memmap into usable + reserved spans.
fn collect_pvh(bi: u64, sink: &mut RegionSink) {
    match read_u32(bi) {
        Some(m) if m == PVH_MAGIC => {}
        _ => return, // not a PVH block either -> fail-closed (no usable frames)
    }

    // `memmap_paddr`@40 / `memmap_entries`@48 are version>=1 fields; a v0
    // start_info is only 40 bytes, so reading them would walk off the struct.
    // Gate the memmap walk on the version below (QEMU microvm + Firecracker
    // both emit version 1). The reservations just below use only v0 fields.
    let version = read_u32(bi + 4).unwrap_or(0);
    dbg("pmm-dbg pvh-ver", version as u64);

    // Reserve the start_info block (v1 is 56 bytes) and the cmdline
    // (NUL-terminated; reserve one conservative page).
    reserve_span(sink, bi, 56);
    if let Some(cmdline) = read_u64(bi + 24) {
        if cmdline != 0 {
            reserve_span(sink, cmdline, FRAME);
        }
    }
    // Reserve any boot modules (initrd-class): both the `hvm_modlist_entry`
    // array itself AND each module's `[paddr, size)` payload, because the
    // hypervisor marks module RAM as memmap type==1 and it would otherwise be
    // seeded as usable. `hvm_modlist_entry` = { paddr@0, size@8, cmdline@16,
    // reserved@24 } (32 bytes); the walk is bounded against a corrupt count and
    // uses `saturating_add` on the data-derived `modlist` pointer.
    if let Some(nr_modules) = read_u32(bi + 12) {
        if nr_modules != 0 {
            if let Some(modlist) = read_u64(bi + 16) {
                reserve_span(sink, modlist, (nr_modules as u64).saturating_mul(32));
                let nmods = if nr_modules > 64 { 64 } else { nr_modules };
                let mut m = 0u64;
                while m < nmods as u64 {
                    let ment = modlist.saturating_add(m.saturating_mul(32));
                    if let (Some(mpaddr), Some(msize)) =
                        (read_u64(ment), read_u64(ment.saturating_add(8)))
                    {
                        reserve_span(sink, mpaddr, msize);
                    }
                    m += 1;
                }
            }
        }
    }

    // start_info v0 carries no memmap table -> fail-closed (no usable frames).
    if version < 1 {
        return;
    }

    let memmap = match read_u64(bi + 40) {
        Some(m) => m,
        None => return,
    };
    let entries = match read_u32(bi + 48) {
        Some(e) => e,
        None => return,
    };
    dbg("pmm-dbg memmap", memmap);
    dbg("pmm-dbg entries", entries as u64);
    if memmap == 0 || entries == 0 {
        return;
    }
    reserve_span(sink, memmap, (entries as u64).saturating_mul(24));

    // Bound the walk so a corrupt `entries` can never run away.
    let n = if entries > 128 { 128 } else { entries };
    let mut i = 0u64;
    while i < n as u64 {
        // `saturating_add`/`saturating_mul`: `memmap` is unvalidated guest data,
        // so a garbage value must not overflow-panic — `read_u64` then guards
        // the (possibly saturated) address and stops the walk.
        let e = memmap.saturating_add(i.saturating_mul(24));
        let addr = match read_u64(e) {
            Some(a) => a,
            None => break,
        };
        let size = match read_u64(e + 8) {
            Some(s) => s,
            None => break,
        };
        let etype = match read_u32(e + 16) {
            Some(t) => t,
            None => break,
        };
        if etype == MEMMAP_TYPE_RAM {
            push_usable_clamped(sink, addr, size);
        } else {
            reserve_span(sink, addr, size);
        }
        i += 1;
    }
}

// ---------------------------------------------------------------------------
// The arch contract entry point.
// ---------------------------------------------------------------------------

/// Collect usable-RAM ranges + reservations for the active x86_64 boot path.
///
/// Always reserves the sub-1 MiB region (legacy/BIOS/boot scratch on x86_64),
/// then dispatches on the boot-info magic to the tb-boot or PVH reader. The
/// shared `pmm` layer adds the kernel-image reservation on top.
pub fn pmm_collect_regions(boot_info: usize, sink: &mut RegionSink) {
    // Sub-1 MiB is never handed out on x86_64 (real-mode IVT/BDA, EBDA, VGA,
    // option ROMs, and where tb-vmm stages its boot structures). Reserving it
    // here is what makes the PVH and tb-boot sources converge on one usable set.
    sink.push_reserved(0, 0x10_0000);

    let bi = boot_info as u64;
    dbg("pmm-dbg bootinfo", bi);
    dbg("pmm-dbg magic", read_u64(bi).unwrap_or(0xffff_ffff_ffff_ffff));
    if let Some(magic) = read_u64(bi) {
        if magic == TB_BOOT_MAGIC {
            collect_tb_boot(bi, sink);
            return;
        }
    }
    collect_pvh(bi, sink);
}
