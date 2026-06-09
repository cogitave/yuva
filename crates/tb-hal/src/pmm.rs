//! `pmm` — M6: the physical FRAME allocator over the active boot memory map.
//!
//! Hands out / reclaims 4 KiB physical frames from USABLE RAM only — never the
//! kernel image (which now INCLUDES M5's 2 MiB `.bss` heap arena, so reserving
//! the image span covers it), the boot structures, sub-1 MiB on x86_64, or
//! device MMIO. Built on M3 (the identity map is live) and M5 (`alloc` is
//! online), so the cumulative boot M0..M5 is untouched.
//!
//! Framekernel rule (KERNEL-FOUNDATION-SPEC.md §1): every raw memory access
//! lives here in tb-hal. THIS module owns the intrusive free-frame stack, the
//! identity-mapped link writes, and the kernel-image linker-symbol read; the
//! per-arch boot-map READERS (PVH `hvm_start_info` / tb-boot `TbBootInfo` /
//! aarch64 QEMU-`virt` map) live in `arch/<arch>/pmm.rs` behind one
//! [`pmm_collect_regions`](crate::arch::pmm_collect_regions) contract. The
//! `kernel` crate stays `#![forbid(unsafe_code)]`: it only calls the safe
//! facade ([`crate::pmm_init`], [`crate::frame_alloc`], [`crate::frame_free`],
//! the stats and [`crate::pmm_selftest`]) and compares the returned `u64`
//! physical addresses — it can never dereference a frame.
//!
//! ALGORITHM — an INTRUSIVE FREE-FRAME STACK (ROADMAP-V2 M6). Each free 4 KiB
//! frame stores the physical address of the next free frame in its OWN first 8
//! bytes, written through the frame's identity-mapped address (PA == VA inside
//! the M3 identity region: `[0, 1 GiB)` on x86_64, `[0x4000_0000, 0x8000_0000)`
//! on aarch64). [`PmmState::head`] is the top of the stack; `0` is the empty
//! sentinel (frame PA 0 is never usable — x86_64 reserves sub-1 MiB, aarch64
//! RAM starts at 0x4000_0000). Allocation is an O(1) pop; free is an O(1) push;
//! there is NO per-frame bitmap. Exhaustion fail-closes to `None`.
//!
//! DOUBLE-FREE — with no per-frame ownership bit the stack can only reject the
//! O(1)-detectable misuse: a misaligned / out-of-range PA, a PA inside a
//! reservation, a free when nothing is allocated, or a free of the current
//! stack top. A well-formed double-free of a frame buried MID-stack is not
//! detectable in O(1) and is accepted — the documented cost of a bitmap-less
//! O(1) allocator (a debug allocated-set is a post-M6 option). No kernel path
//! frees a frame it does not currently hold, so this cannot manifest in M6.
//!
//! SEEDING — at [`PmmState::init`] every 4 KiB frame fully inside a parsed
//! usable range AND disjoint from every reservation is pushed onto the stack,
//! once. `total_frames` is that count (`sum(usable ranges) − reservations`, the
//! stat the self-test asserts on); `free_count` tracks the live free total. If
//! the reservation table ever overflows (see [`RegionSink`]) the seed fails
//! CLOSED — `total_frames` stays 0 — rather than risk handing out a reservation.
//!
//! SINGLE-CORE ASSUMPTION — identical to `heap.rs`: an [`UnsafeCell`] of the
//! state guarded by an [`AtomicBool`]. M0..M6 run single-threaded with
//! interrupts masked (M8 adds the first IRQ); the allocator never re-enters, so
//! the guard is always uncontended. When M8 lands preemption this critical
//! section must additionally mask interrupts — the same one-line change noted
//! in `heap.rs`.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

/// Bytes per physical frame (4 KiB granule, both architectures).
const FRAME: u64 = 4096;

/// Maximum number of distinct usable-RAM ranges the parser may report. PVH
/// E820 maps split RAM into a handful of entries; tb-boot/aarch64 use one.
const MAX_RANGES: usize = 16;

/// Maximum number of reservation spans (sub-1 MiB, the kernel image, every boot
/// structure, and any non-RAM hole inside a RAM range). Generously sized so a
/// rich E820 map never overflows it.
const MAX_RESV: usize = 64;

// ===========================================================================
// Physical ranges + the arch->pmm collection sink
// ===========================================================================

/// A half-open physical span `[base, base + len)`.
#[derive(Clone, Copy)]
struct PhysRange {
    /// Physical base address.
    base: u64,
    /// Length in bytes.
    len: u64,
}

impl PhysRange {
    /// The empty range, for `const` array initialisers.
    const ZERO: PhysRange = PhysRange { base: 0, len: 0 };

    /// One-past-the-end physical address (saturating, so a pathological `len`
    /// can never wrap into a false-negative overlap test).
    fn end(&self) -> u64 {
        self.base.saturating_add(self.len)
    }
}

/// The collection target the per-arch [`pmm_collect_regions`] fills.
///
/// The arch reader pushes USABLE RAM ranges (already clamped to its identity
/// window) and RESERVED spans (boot structures, sub-1 MiB on x86_64, the DTB on
/// aarch64, any non-RAM hole). [`PmmState::init`] then adds the kernel-image
/// reservation and seeds the free-frame stack from the difference. A dropped
/// USABLE range only under-seeds (fail-safe); a dropped RESERVATION could
/// expose reserved memory, so an overflow of the reservation table sets
/// [`RegionSink::overflow`] and makes `init` fail closed.
pub(crate) struct RegionSink {
    usable: [PhysRange; MAX_RANGES],
    usable_len: usize,
    reserved: [PhysRange; MAX_RESV],
    reserved_len: usize,
    /// Set when a reservation could not be recorded because the table filled.
    /// `PmmState::init` refuses to seed (fail-closed) when this is set, so a
    /// silently-dropped reservation can never be handed out as a free frame.
    overflow: bool,
}

impl RegionSink {
    /// A new, empty sink.
    fn new() -> Self {
        RegionSink {
            usable: [PhysRange::ZERO; MAX_RANGES],
            usable_len: 0,
            reserved: [PhysRange::ZERO; MAX_RESV],
            reserved_len: 0,
            overflow: false,
        }
    }

    /// Record a usable-RAM span `[base, base + len)`. Zero-length spans are
    /// ignored; a table overflow silently drops the span (fail-SAFE: dropping a
    /// usable range only under-seeds, never exposes memory). The arch reader is
    /// responsible for clamping to its identity-mapped window.
    pub(crate) fn push_usable(&mut self, base: u64, len: u64) {
        if len == 0 {
            return;
        }
        if self.usable_len < MAX_RANGES {
            self.usable[self.usable_len] = PhysRange { base, len };
            self.usable_len += 1;
        }
    }

    /// Record a reserved span `[base, base + len)` that must be carved out of
    /// usable RAM. Zero-length spans are ignored; a table overflow sets
    /// [`RegionSink::overflow`] (fail-CLOSED) instead of silently dropping the
    /// span, because a dropped reservation could otherwise be seeded as a free
    /// frame.
    pub(crate) fn push_reserved(&mut self, base: u64, len: u64) {
        if len == 0 {
            return;
        }
        if self.reserved_len < MAX_RESV {
            self.reserved[self.reserved_len] = PhysRange { base, len };
            self.reserved_len += 1;
        } else {
            self.overflow = true;
        }
    }
}

// ===========================================================================
// Pure arithmetic helpers
// ===========================================================================

/// Round `x` up to the next multiple of `a` (a power of two).
fn align_up(x: u64, a: u64) -> u64 {
    (x.saturating_add(a - 1)) & !(a - 1)
}

/// Round `x` down to the previous multiple of `a` (a power of two).
fn align_down(x: u64, a: u64) -> u64 {
    x & !(a - 1)
}

// ===========================================================================
// Seed-diagnostic serial helpers (fix_plan §A.2)
// ===========================================================================
//
// Pure-safe, allocation-free, `core::fmt`-free writers over the tb-hal serial
// facade. Used ONLY by `PmmState::seed` to make a future CI stall-at-M6
// diagnosable (it would print the last range / total it reached). They perform
// no `unsafe` — they fan out to `crate::serial_write_str` / `serial_write_byte`,
// which are themselves pure-safe loops over the per-arch byte writer.

/// Write a `u64` as a fixed-width `0x…` 16-hex-digit string over serial.
fn write_hex_u64(value: u64) {
    crate::serial_write_str("0x");
    let mut shift: i32 = 60;
    while shift >= 0 {
        let nibble = ((value >> shift) & 0xf) as u8;
        let c = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
        crate::serial_write_byte(c);
        shift -= 4;
    }
}

/// Write a `usize` as a base-10 string over serial (no leading zeros; `0`
/// prints as `"0"`). Buffer is 20 bytes — wide enough for `u64::MAX`.
fn write_dec_usize(value: usize) {
    if value == 0 {
        crate::serial_write_byte(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut n = value;
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    let mut j = i;
    while j < buf.len() {
        crate::serial_write_byte(buf[j]);
        j += 1;
    }
}

// ===========================================================================
// Kernel-image span (linker symbols)
// ===========================================================================

/// The whole-kernel-image span `[__image_start, __image_end)`, exported by both
/// linker scripts (`kernel/linker/{x86_64,aarch64}.ld`). It covers `.text`,
/// `.rodata`, `.data`, and `.bss` — and `.bss` holds M5's 2 MiB heap arena, the
/// x86_64 boot page tables/stacks and every tb-hal `.bss` static — so reserving
/// this single span keeps the frame allocator off ALL of them.
fn kernel_image_span() -> (u64, u64) {
    extern "C" {
        static __image_start: u8;
        static __image_end: u8;
    }
    // `addr_of!` forms a raw pointer to each linker-defined absolute symbol
    // WITHOUT reading it (no load occurs), so taking their addresses needs no
    // `unsafe`; we only compare the resulting integers.
    let start = core::ptr::addr_of!(__image_start) as u64;
    let end = core::ptr::addr_of!(__image_end) as u64;
    (start, end)
}

// ===========================================================================
// Intrusive free-frame link accessors (the only frame derefs)
// ===========================================================================

/// Write the next-free-PA link into a free frame's first 8 bytes, THROUGH its
/// identity-mapped address.
///
/// # Safety
/// `frame_pa` must be a 4 KiB-aligned physical frame inside the live M3
/// identity-mapped RAM window (so `PA == VA` and the first 8 bytes are mapped
/// read/write) and currently owned by the allocator (on, or being pushed onto,
/// the free stack), so this write cannot race or clobber live data.
unsafe fn write_link(frame_pa: u64, next: u64) {
    (frame_pa as *mut u64).write_volatile(next);
}

/// Read the next-free-PA link out of a free frame's first 8 bytes, through its
/// identity-mapped address.
///
/// # Safety
/// As [`write_link`]: `frame_pa` is an aligned, identity-mapped frame the
/// allocator owns (it is the current free-stack top).
unsafe fn read_link(frame_pa: u64) -> u64 {
    (frame_pa as *const u64).read_volatile()
}

// ===========================================================================
// Allocator state
// ===========================================================================

/// The mutable frame-allocator state. Only ever reached through [`PmmCell`]'s
/// guarded `&mut` borrow, so its intrusive `head` link is never aliased.
struct PmmState {
    /// Top of the intrusive free-frame stack (a physical frame address), or `0`
    /// when no free frame remains.
    head: u64,
    /// Parsed usable-RAM ranges (clamped to the identity window by the arch
    /// reader); the membership oracle for `frame_alloc`/`frame_free` validation.
    usable: [PhysRange; MAX_RANGES],
    /// Number of live entries in `usable`.
    usable_len: usize,
    /// Reservation spans carved out of usable RAM (boot structures, sub-1 MiB,
    /// the kernel image, device/non-RAM holes).
    reserved: [PhysRange; MAX_RESV],
    /// Number of live entries in `reserved`.
    reserved_len: usize,
    /// Frames seeded at init: `sum(usable ranges) − reservations`, the invariant
    /// the self-test checks. Constant after [`PmmState::init`].
    total_frames: usize,
    /// Frames currently on the free stack. `total_frames − (live allocations)`.
    free_count: usize,
    /// Whether [`PmmState::init`] has already parsed the map and seeded.
    initialized: bool,
}

impl PmmState {
    /// A zeroed, uninitialised state for a `const` static.
    const fn new() -> Self {
        PmmState {
            head: 0,
            usable: [PhysRange::ZERO; MAX_RANGES],
            usable_len: 0,
            reserved: [PhysRange::ZERO; MAX_RESV],
            reserved_len: 0,
            total_frames: 0,
            free_count: 0,
            initialized: false,
        }
    }

    /// Parse the active boot path's memory map and seed the free-frame stack.
    /// Idempotent (a second call is a no-op), so [`crate::pmm_init`] is safe to
    /// call once per boot without a double-seed hazard.
    fn init(&mut self, boot_info: usize) {
        if self.initialized {
            return;
        }

        let mut sink = RegionSink::new();
        // Per-arch reader: usable RAM (clamped to the identity window) + the
        // boot-structure / sub-1 MiB / DTB / device-hole reservations.
        crate::arch::pmm_collect_regions(boot_info, &mut sink);

        // Shared reservation: the whole kernel image — code/rodata/data/bss,
        // which INCLUDES M5's 2 MiB heap arena and the boot page tables/stacks.
        let (img_start, img_end) = kernel_image_span();
        if img_end > img_start {
            sink.push_reserved(img_start, img_end - img_start);
        }

        // Fail CLOSED on reservation-table overflow: a silently-dropped
        // reservation could otherwise be seeded as a usable frame. Leave the
        // allocator empty (`total_frames` == 0) so the kernel's M6 self-test
        // reports "no usable frames" instead of risking a bad handout. The three
        // real boot maps stay far under MAX_RESV, so this never trips in
        // practice; it is a hard backstop on the trusted reservation set.
        if sink.overflow {
            self.initialized = true;
            return;
        }

        self.usable_len = sink.usable_len;
        self.usable[..sink.usable_len].copy_from_slice(&sink.usable[..sink.usable_len]);
        self.reserved_len = sink.reserved_len;
        self.reserved[..sink.reserved_len].copy_from_slice(&sink.reserved[..sink.reserved_len]);

        self.seed();
        self.initialized = true;
    }

    /// Push every usable, non-reserved 4 KiB frame onto the intrusive stack.
    ///
    /// DIAGNOSTIC PRINT (per fix_plan §A.2): before iterating each usable range
    /// this emits `seed: range[i] [START,END) ...` and, after the loop, the
    /// final `seed: total_frames=N` — all via the pure-safe `serial_write_str`
    /// facade (no extra `unsafe`). The print is byte-cheap (~1 line per range,
    /// the `virt` map has ONE usable range) and lands between the kernel's
    /// `frame-test: parsing boot memory map` and `M6: frame alloc OK` markers —
    /// exactly the gap where the CI-only aarch64 stall was last observed. It
    /// turns a future silent stall-at-M6 into a diagnosable one: the last
    /// `seed:` line flushed pins the range + frame the seed was touching when
    /// it died, instead of leaving only the upstream `parsing` line.
    fn seed(&mut self) {
        self.head = 0;
        self.total_frames = 0;
        let mut i = 0;
        while i < self.usable_len {
            let r = self.usable[i];
            let mut f = align_up(r.base, FRAME);
            let end = align_down(r.end(), FRAME);
            // Defensive diagnostic: the computed frame-aligned [start, end) the
            // seed loop is about to walk for this usable range.
            crate::serial_write_str("seed: range[");
            write_dec_usize(i);
            crate::serial_write_str("] [");
            write_hex_u64(f);
            crate::serial_write_str(", ");
            write_hex_u64(end);
            crate::serial_write_str(")\n");
            while f < end {
                if f != 0 && !self.is_reserved_frame(f) {
                    // SAFETY: `f` is a 4 KiB-aligned frame fully inside a parsed
                    // usable range (so identity-mapped RAM) and disjoint from
                    // every reservation; linking it touches only its own first
                    // 8 bytes, which nothing else references at seed time.
                    unsafe {
                        write_link(f, self.head);
                    }
                    self.head = f;
                    self.total_frames += 1;
                }
                f += FRAME;
            }
            i += 1;
        }
        self.free_count = self.total_frames;
        // Defensive diagnostic: the seeded free-frame total (== the M6 stat the
        // kernel self-test asserts on). A future stall that never prints this
        // line localises the hang to the seed loop above, not the parser.
        crate::serial_write_str("seed: total_frames=");
        write_dec_usize(self.total_frames);
        crate::serial_write_str("\n");
    }

    /// `true` iff the frame `[f, f + FRAME)` intersects any reservation.
    fn is_reserved_frame(&self, f: u64) -> bool {
        // `saturating_add` so a top-of-space `f` can never panic on overflow;
        // it saturates to u64::MAX and the `f < r.end()` half of the overlap
        // test (every reservation end is finite, far below u64::MAX) is false,
        // so no false positive results.
        let fe = f.saturating_add(FRAME);
        let mut i = 0;
        while i < self.reserved_len {
            let r = self.reserved[i];
            if f < r.end() && r.base < fe {
                return true;
            }
            i += 1;
        }
        false
    }

    /// `true` iff `pa` lies inside some parsed usable-RAM range.
    fn addr_in_usable(&self, pa: u64) -> bool {
        let mut i = 0;
        while i < self.usable_len {
            let r = self.usable[i];
            if pa >= r.base && pa < r.end() {
                return true;
            }
            i += 1;
        }
        false
    }

    /// `true` iff `pa` lies inside some reservation span.
    fn addr_reserved(&self, pa: u64) -> bool {
        let mut i = 0;
        while i < self.reserved_len {
            let r = self.reserved[i];
            if pa >= r.base && pa < r.end() {
                return true;
            }
            i += 1;
        }
        false
    }

    /// `true` iff the whole frame `[pa, pa + FRAME)` fits inside one usable range.
    fn frame_in_usable(&self, pa: u64) -> bool {
        // `checked_add` so a 4 KiB-aligned `pa` near `u64::MAX` is rejected
        // fail-closed instead of overflowing — a debug-build panic, or a release
        // wrap that could spuriously satisfy the `pe <= r.end()` range test and
        // let `frame_free` write a link word through an unmapped VA. The
        // framekernel boundary promises `frame_free` rejects out-of-range PAs;
        // this is where that promise is kept.
        let pe = match pa.checked_add(FRAME) {
            Some(v) => v,
            None => return false,
        };
        let mut i = 0;
        while i < self.usable_len {
            let r = self.usable[i];
            if pa >= r.base && pe <= r.end() {
                return true;
            }
            i += 1;
        }
        false
    }

    /// Pop the top free frame (O(1)). `None` when exhausted (fail-closed).
    fn alloc(&mut self) -> Option<u64> {
        if self.head == 0 {
            return None;
        }
        let pa = self.head;
        // SAFETY: `pa` is the current free-stack top — a frame the allocator
        // owns; reading its link word yields the next free PA (or `0`).
        let next = unsafe { read_link(pa) };
        self.head = next;
        self.free_count -= 1;
        Some(pa)
    }

    /// Push a frame back (O(1)). Returns `false` — fail-closed, no state change —
    /// for a misaligned/null PA, a PA not fully inside a usable range (incl. an
    /// out-of-range PA near `u64::MAX`, rejected via `frame_in_usable`'s
    /// checked add), a PA that intersects a reservation, a free of the current
    /// top (the cheap O(1) double-free guard), or a free when nothing is
    /// allocated.
    fn free(&mut self, pa: u64) -> bool {
        if pa == 0 || pa % FRAME != 0 {
            return false;
        }
        if !self.frame_in_usable(pa) {
            return false;
        }
        if self.is_reserved_frame(pa) {
            return false;
        }
        if self.free_count >= self.total_frames {
            return false; // nothing is allocated -> this must be a double-free
        }
        if self.head == pa {
            return false; // freeing the current top is an immediate double-free
        }
        // SAFETY: `pa` is a 4 KiB-aligned usable RAM frame previously handed out
        // by `alloc`; pushing it writes only its own link word.
        unsafe {
            write_link(pa, self.head);
        }
        self.head = pa;
        self.free_count += 1;
        true
    }
}

// ===========================================================================
// Guarded interior-mutable cell (the heap.rs `HeapCell` pattern)
// ===========================================================================

/// Interior-mutable, `Sync` wrapper around [`PmmState`].
struct PmmCell {
    state: UnsafeCell<PmmState>,
    lock: AtomicBool,
}

// SAFETY: the inner `PmmState` is reached only through `with`, which takes the
// `lock` before minting a `&mut`; on this single, non-preemptible core that
// guard hands out exclusive access, so the `UnsafeCell` is never aliased. (M8's
// first IRQ will require masking interrupts inside `with`; see the module doc.)
unsafe impl Sync for PmmCell {}

impl PmmCell {
    /// A new, unlocked, uninitialised cell for a `const` static.
    const fn new() -> Self {
        PmmCell {
            state: UnsafeCell::new(PmmState::new()),
            lock: AtomicBool::new(false),
        }
    }

    /// Run `f` with exclusive access to the [`PmmState`], under the guard.
    /// Single-core, non-reentrant: the CAS only ever succeeds uncontended.
    fn with<R>(&self, f: impl FnOnce(&mut PmmState) -> R) -> R {
        while self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // SAFETY: the CAS gives this core exclusive ownership of the cell for
        // the duration of `f`; nothing else can hold a `&mut` to the state.
        let state = unsafe { &mut *self.state.get() };
        let result = f(state);
        self.lock.store(false, Ordering::Release);
        result
    }
}

/// The single, crate-internal frame allocator.
static GLOBAL_PMM: PmmCell = PmmCell::new();

// ===========================================================================
// Crate-internal facade (lib.rs re-exports these as the safe public surface)
// ===========================================================================

/// Parse the active boot path's memory map and seed the allocator. Idempotent.
pub(crate) fn init(boot_info: usize) {
    GLOBAL_PMM.with(|s| s.init(boot_info));
}

/// Pop one 4 KiB physical frame, or `None` on exhaustion.
pub(crate) fn frame_alloc() -> Option<u64> {
    GLOBAL_PMM.with(|s| s.alloc())
}

/// Return a previously-allocated frame; `true` = accepted, `false` = rejected.
pub(crate) fn frame_free(pa: u64) -> bool {
    GLOBAL_PMM.with(|s| s.free(pa))
}

/// Total seeded frames (`sum(usable ranges) − reservations`).
pub(crate) fn total_frames() -> usize {
    GLOBAL_PMM.with(|s| s.total_frames)
}

/// Frames currently on the free stack.
pub(crate) fn free_frames() -> usize {
    GLOBAL_PMM.with(|s| s.free_count)
}

/// `true` iff `pa` lies inside a parsed usable-RAM range.
pub(crate) fn addr_in_usable_ram(pa: u64) -> bool {
    GLOBAL_PMM.with(|s| s.addr_in_usable(pa))
}

/// `true` iff `pa` lies inside any reservation span.
pub(crate) fn addr_reserved(pa: u64) -> bool {
    GLOBAL_PMM.with(|s| s.addr_reserved(pa))
}

/// Low-level frame self-test the `forbid(unsafe_code)` kernel cannot do itself:
/// allocate a frame, write a magic THROUGH its identity address (first word and
/// a word deep in the page), read both back, free it, and end at the entry
/// free-count (no leak). Returns `true` on pass.
pub(crate) fn selftest() -> bool {
    const MAGIC: u64 = 0x4D36_4672_616D_6531; // b"M6Frame1"

    let base_free = free_frames();
    let pa = match frame_alloc() {
        Some(p) => p,
        None => return false,
    };
    // A freshly handed-out frame must be 4 KiB-aligned and the free count must
    // have dropped by exactly one.
    if pa % FRAME != 0 || free_frames() != base_free - 1 {
        let _ = frame_free(pa);
        return false;
    }

    // SAFETY: `pa` is a 4 KiB-aligned, identity-mapped RAM frame this allocator
    // just handed out and still owns; both offsets stay inside its 4 KiB page.
    let read_ok = unsafe {
        write_link(pa, MAGIC); // first word (the link slot)
        let deep = (pa + FRAME - 8) as *mut u64;
        deep.write_volatile(!MAGIC); // last word of the page
        let first = read_link(pa);
        let last = (deep as *const u64).read_volatile();
        first == MAGIC && last == !MAGIC
    };

    let freed = frame_free(pa);
    read_ok && freed && free_frames() == base_free
}
