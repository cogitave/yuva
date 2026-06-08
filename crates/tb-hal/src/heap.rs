//! `heap` — M5: the kernel-wide `alloc` backing store.
//!
//! Brings `alloc` (Box / Vec / BTreeMap / String) online BEFORE any physical
//! frame allocator exists, by serving every allocation out of a fixed,
//! `.bss`-resident static arena. The framekernel rule (KERNEL-FOUNDATION-SPEC.md
//! §1) keeps ALL of this here: the static arena, its `unsafe impl Sync`, the
//! `unsafe impl GlobalAlloc`, and every raw pointer/free-list manipulation. The
//! `kernel` crate only declares `#[global_allocator] static HEAP: tb_hal::Heap`
//! and calls the safe facade ([`crate::heap_init`], [`crate::heap_used_bytes`],
//! [`crate::heap_high_water`], [`crate::heap_selftest`]).
//!
//! ALGORITHM — intrusive, address-ordered FREE-LIST with two-sided coalescing
//! (NOT a bump allocator; a bump allocator cannot reuse freed memory and would
//! fail the DoD). Each free region begins with an in-place [`FreeBlock`] header
//! `{ size, next }`; the list is kept sorted by ascending address so that, on
//! free, a region can be merged with an immediately-adjacent free neighbour on
//! either side. Allocation is first-fit with front/back splitting: any padding
//! needed to satisfy an over-aligned request, and any tail left over after the
//! payload, is returned to the free list as its own block — so the region handed
//! out is EXACTLY `[ptr, ptr + size)` and [`HeapState::dealloc`] can reconstruct
//! it from `ptr` + `Layout` alone, with no per-allocation boundary tag.
//!
//! This allocator algebra is REUSED UNCHANGED by M7: M7 keeps every line of the
//! free-list / coalescing / splitting math above and only adds a SECOND backing
//! store — a frame-backed, kernel-only VA window that [`HeapState::grow`] maps
//! on demand (pulling M6 frames through the per-arch
//! [`crate::arch::map_heap_frames`] splice) and donates to this same free list
//! via [`HeapState::insert_free_region`]. The fixed `.bss` [`ARENA`] stays as
//! the bootstrap store; the window lifts the heap off its 2 MiB cap so `alloc`
//! scales with real RAM. Still store-agnostic — `grow` is the only new hook,
//! and it disappears entirely while the window is disabled (the pure M5 path).
//!
//! SINGLE-CORE ASSUMPTION — the global allocator static must be `Sync`, yet
//! `GlobalAlloc::alloc` only takes `&self`. We mirror the M2 `TaskStack`
//! pattern: an [`UnsafeCell`] of the mutable state guarded by an [`AtomicBool`].
//! At M5 there is no heap before this point and NO interrupts yet (M8 adds the
//! first timer IRQ), so execution is single-threaded and non-preemptible: the
//! guard only ever sees an UNCONTENDED acquire, and the allocator itself
//! performs no nested allocation, so it can never re-enter. When M8 lands
//! preemption, this critical section MUST additionally mask interrupts (an IRQ
//! that allocates mid-update would otherwise deadlock on the guard). That is the
//! one and only change M8 needs here.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

/// Total size of the fixed kernel heap arena, in bytes (2 MiB).
///
/// `.bss` is NOBITS, so this does not bloat the kernel image; guest RAM is
/// 256 MiB with the kernel at 1 MiB, so 2 MiB of zero-init heap fits with vast
/// headroom inside the identity-mapped low window both boot paths establish.
const ARENA_BYTES: usize = 2 * 1024 * 1024;

/// Bytes per page/frame (4 KiB granule, both arches) — the unit the M7 window
/// maps in. The free-list algebra is page-size-agnostic; only the window grow
/// path below deals in whole pages.
const PAGE: usize = 4096;

/// Pages mapped per on-demand grow when a request is smaller than one chunk —
/// amortises the page-table splice + TLB work over many future allocations
/// (256 pages = 1 MiB). A request LARGER than a chunk maps exactly what it needs.
const GROW_CHUNK_PAGES: usize = 256;

/// In-place header at the start of every FREE region. The payload bytes of an
/// allocated region never carry this; only free regions do (intrusive list).
#[repr(C)]
struct FreeBlock {
    /// Total size of this free region in bytes, INCLUDING this header.
    size: usize,
    /// Next free region by ascending address, or null at the tail.
    next: *mut FreeBlock,
}

/// Smallest region the allocator will ever create or hand back: a region must
/// always be large enough to host a [`FreeBlock`] header once it is freed.
const MIN_BLOCK: usize = core::mem::size_of::<FreeBlock>();

/// Alignment every free-region address and every region size is a multiple of.
/// Equals `align_of::<FreeBlock>()`, so an in-place header is always aligned.
const HEADER_ALIGN: usize = core::mem::align_of::<FreeBlock>();

/// Round `addr` up to the next multiple of `align` (a power of two), or `None`
/// on overflow — so a pathological [`Layout`] can never wrap into a false fit.
fn align_up_checked(addr: usize, align: usize) -> Option<usize> {
    Some(addr.checked_add(align - 1)? & !(align - 1))
}

/// Normalise a [`Layout`] into the `(size, align)` this allocator actually
/// services: at least [`MIN_BLOCK`] bytes (so the region can be re-headered when
/// freed), rounded up to [`HEADER_ALIGN`] (so every resulting boundary stays
/// header-aligned), and at least [`HEADER_ALIGN`] alignment. `None` on overflow.
///
/// `alloc` and `dealloc` both call this with the SAME `Layout`, so they always
/// agree on a region's exact size — that is what lets `dealloc` work from
/// `ptr` + `Layout` without a stored boundary tag. Also collapses `size == 0` /
/// ZST requests onto a real [`MIN_BLOCK`] region (symmetric alloc/dealloc), so
/// the `GlobalAlloc` size-0 corner is handled without a dangling special case.
fn required(layout: Layout) -> Option<(usize, usize)> {
    let align = if layout.align() > HEADER_ALIGN {
        layout.align()
    } else {
        HEADER_ALIGN
    };
    let raw = if layout.size() > MIN_BLOCK {
        layout.size()
    } else {
        MIN_BLOCK
    };
    let size = align_up_checked(raw, HEADER_ALIGN)?;
    Some((size, align))
}

/// Try to place an allocation of `size` bytes at `align` inside the free region
/// `[block_start, block_start + block_size)`. On success returns
/// `(alloc_start, front_pad)` where `front_pad = alloc_start - block_start`.
///
/// Both the FRONT gap (alignment slack before the payload) and the BACK gap
/// (tail after it) must each be either 0 or at least [`MIN_BLOCK`], so whatever
/// is left over can itself become a valid free block. If the natural aligned
/// start would leave a too-small front gap, the start is pushed up by one
/// alignment step so the gap grows to host a header. All arithmetic is checked,
/// so overflow simply means "does not fit" (returns `None`), never UB.
fn fit(block_start: usize, block_size: usize, size: usize, align: usize) -> Option<(usize, usize)> {
    let mut alloc_start = align_up_checked(block_start, align)?;
    let mut front = alloc_start - block_start;
    if front != 0 && front < MIN_BLOCK {
        // Too small to be its own free block; advance one alignment step so the
        // front gap grows to at least MIN_BLOCK (size is a HEADER_ALIGN multiple
        // and align >= HEADER_ALIGN, so the new gap is header-aligned too).
        alloc_start = align_up_checked(block_start.checked_add(MIN_BLOCK)?, align)?;
        front = alloc_start - block_start;
    }
    let alloc_end = alloc_start.checked_add(size)?;
    let block_end = block_start + block_size;
    if alloc_end > block_end {
        return None;
    }
    let back = block_end - alloc_end;
    if back != 0 && back < MIN_BLOCK {
        return None;
    }
    Some((alloc_start, front))
}

/// The mutable allocator state: the free-list head plus arena bounds and
/// accounting. Only ever touched through [`HeapCell`]'s guarded `&mut` borrow,
/// so its raw `head` pointer is never aliased.
struct HeapState {
    /// Head of the address-ordered free list, or null when fully allocated.
    head: *mut FreeBlock,
    /// Aligned base of the usable arena (set by [`HeapState::init`]).
    arena_start: usize,
    /// Usable arena length in bytes (header-aligned-down).
    arena_size: usize,
    /// Whether [`HeapState::init`] has already laid the initial free block.
    initialized: bool,
    /// Bytes currently handed out (sum of the normalised `size` of live
    /// allocations). Returns to its post-init baseline when all are freed; this
    /// is the no-leak metric the self-test asserts on.
    used: usize,
    /// Maximum `used` ever observed — the heap high-water mark.
    high_water: usize,
    /// Whether the M7 frame-backed window has been enabled (via
    /// [`crate::heap_window_init`]). While `false` the allocator is the pure M5
    /// `.bss`-arena allocator — [`HeapState::grow`] is a no-op.
    window_enabled: bool,
    /// Base VA of the kernel-heap window (set by [`HeapState::window_init`];
    /// retained for symmetry with `arena_start` and for M10's per-agent address
    /// spaces, which re-use this window base).
    window_base: u64,
    /// Next unmapped VA in the window — the cursor [`HeapState::grow`] advances
    /// contiguously, so successive grows produce VA-adjacent (coalescing) slices.
    window_next: u64,
    /// One-past-the-end VA of the window (its hard VA cap).
    window_end: u64,
    /// DATA-page bytes currently mapped into the window (the M7 stat;
    /// monotonically rises as the heap grows — the window never unmaps). Does
    /// NOT include the intermediate page-table frames `grow` also pulls.
    window_bytes: usize,
}

impl HeapState {
    /// A zeroed, uninitialised state, usable in a `const` static.
    const fn new() -> Self {
        HeapState {
            head: core::ptr::null_mut(),
            arena_start: 0,
            arena_size: 0,
            initialized: false,
            used: 0,
            high_water: 0,
            window_enabled: false,
            window_base: 0,
            window_next: 0,
            window_end: 0,
            window_bytes: 0,
        }
    }

    /// Lay the initial single free block over `[start, start + size)`. Idempotent
    /// (a second call is a no-op), so [`crate::heap_init`] is safe to call once
    /// per boot without a double-init hazard.
    fn init(&mut self, start: usize, size: usize) {
        if self.initialized {
            return;
        }
        let aligned = match align_up_checked(start, HEADER_ALIGN) {
            Some(a) => a,
            None => return,
        };
        let lost = aligned - start;
        let usable = (size - lost) & !(HEADER_ALIGN - 1);
        self.head = core::ptr::null_mut();
        self.arena_start = aligned;
        self.arena_size = usable;
        self.used = 0;
        self.high_water = 0;
        self.initialized = true;
        if usable >= MIN_BLOCK {
            self.insert_free_region(aligned, usable);
        }
    }

    /// Insert the region `[addr, addr + size)` into the address-ordered free
    /// list, coalescing it with an immediately-adjacent free neighbour on either
    /// side. `addr` is [`HEADER_ALIGN`]-aligned and `size >= MIN_BLOCK`.
    fn insert_free_region(&mut self, addr: usize, size: usize) {
        // Find `prev`: the last free block whose address is below `addr`.
        let mut prev: *mut FreeBlock = core::ptr::null_mut();
        let mut cur = self.head;
        // SAFETY: every non-null link is a FreeBlock header this allocator wrote
        // at a header-aligned arena address; the list is well-formed by
        // construction, so walking `next` only dereferences valid headers.
        while !cur.is_null() && (cur as usize) < addr {
            prev = cur;
            cur = unsafe { (*cur).next };
        }

        // Write the new header in place, linking it ahead of `cur`.
        let node = addr as *mut FreeBlock;
        // SAFETY: `addr` is a header-aligned arena address and the region is at
        // least MIN_BLOCK bytes, so it can hold a FreeBlock; writing the whole
        // struct initialises it without reading any prior contents.
        unsafe {
            node.write(FreeBlock { size, next: cur });
        }
        if prev.is_null() {
            self.head = node;
        } else {
            // SAFETY: `prev` is a valid header located before `addr`.
            unsafe {
                (*prev).next = node;
            }
        }

        // Coalesce forward: node + cur if they abut.
        if !cur.is_null() && addr + size == cur as usize {
            // SAFETY: both `node` and `cur` are valid, adjacent headers.
            unsafe {
                (*node).size += (*cur).size;
                (*node).next = (*cur).next;
            }
        }
        // Coalesce backward: prev + node if they abut.
        if !prev.is_null() {
            // SAFETY: `prev` and `node` are valid headers; `prev` precedes node.
            unsafe {
                if (prev as usize) + (*prev).size == addr {
                    (*prev).size += (*node).size;
                    (*prev).next = (*node).next;
                }
            }
        }
    }

    /// First-fit allocation with front/back splitting, then GROW-AND-RETRY.
    ///
    /// Runs one first-fit pass ([`Self::try_fit`]); on no-fit it asks the
    /// frame-backed window to [`Self::grow`] and retries, looping until either
    /// the request is satisfied or growth makes no progress (window disabled,
    /// window VA exhausted, or true physical-frame OOM) — at which point it
    /// returns null. Never panics (the `GlobalAlloc` contract requires `alloc`
    /// to signal failure with null). The M5 first-fit/split/coalesce algebra in
    /// [`Self::try_fit`] is BYTE-IDENTICAL to the M5 allocator; only this
    /// grow-on-miss wrapper is new, and it is inert until the window is enabled.
    fn alloc(&mut self, layout: Layout) -> *mut u8 {
        let (size, align) = match required(layout) {
            Some(v) => v,
            None => return core::ptr::null_mut(),
        };
        loop {
            if let Some(ptr) = self.try_fit(size, align) {
                return ptr;
            }
            // No region fits. Grow the frame-backed window by at least enough to
            // cover this request, then retry the SAME first-fit pass. `grow`
            // returns false only when no further progress is possible (window
            // disabled / VA exhausted / physical-frame OOM) → signal OOM.
            if !self.grow(size) {
                return core::ptr::null_mut();
            }
        }
    }

    /// One first-fit pass over the current free list — the UNCHANGED M5 algebra:
    /// first fit, unlink, return the front/back split remainders to the list,
    /// account the bytes. `Some(ptr)` on a fit, `None` if no region fits.
    fn try_fit(&mut self, size: usize, align: usize) -> Option<*mut u8> {
        let mut prev: *mut FreeBlock = core::ptr::null_mut();
        let mut cur = self.head;
        while !cur.is_null() {
            let block_start = cur as usize;
            // SAFETY: `cur` is a valid free-list header.
            let block_size = unsafe { (*cur).size };
            // SAFETY: `cur` is a valid free-list header.
            let next = unsafe { (*cur).next };

            if let Some((alloc_start, front)) = fit(block_start, block_size, size, align) {
                // Unlink `cur` from the list.
                if prev.is_null() {
                    self.head = next;
                } else {
                    // SAFETY: `prev` is a valid header.
                    unsafe {
                        (*prev).next = next;
                    }
                }

                let block_end = block_start + block_size;
                let alloc_end = alloc_start + size;
                // Return the alignment-slack front gap to the free list.
                if front != 0 {
                    self.insert_free_region(block_start, front);
                }
                // Return the leftover tail to the free list.
                let back = block_end - alloc_end;
                if back != 0 {
                    self.insert_free_region(alloc_end, back);
                }

                self.used += size;
                if self.used > self.high_water {
                    self.high_water = self.used;
                }
                return Some(alloc_start as *mut u8);
            }

            prev = cur;
            cur = next;
        }
        // No region fit in this pass.
        None
    }

    /// Enable the M7 frame-backed growable window over `[base, base + size)` — a
    /// kernel-only, RW + NX VA range OUTSIDE the identity map. Idempotent. No
    /// frames are mapped here; [`Self::grow`] maps them lazily on first miss.
    /// Until this is called the allocator is the pure M5 `.bss`-arena allocator.
    fn window_init(&mut self, base: u64, size: u64) {
        if self.window_enabled {
            return;
        }
        self.window_base = base;
        self.window_next = base;
        self.window_end = base.saturating_add(size);
        self.window_bytes = 0;
        self.window_enabled = true;
    }

    /// Grow the heap by mapping fresh physical frames into the next contiguous
    /// slice of the kernel-heap VA window and donating that slice to the free
    /// list. `false` (no progress) when the window is disabled, its VA range is
    /// exhausted, or no physical frame could be mapped (true OOM).
    ///
    /// The slice is VA-ADJACENT to the previous one, so [`Self::insert_free_region`]
    /// coalesces successive grows into one large CONTIGUOUS free region — which
    /// is exactly what lets a single >4 KiB allocation (a `Vec` outgrowing one
    /// page) be served even though the backing physical frames are SCATTERED:
    /// the window supplies contiguous virtual addresses over non-contiguous RAM.
    fn grow(&mut self, min_bytes: usize) -> bool {
        if !self.window_enabled {
            return false;
        }
        let remaining = self.window_end.saturating_sub(self.window_next);
        if remaining < PAGE as u64 {
            return false; // window VA exhausted
        }
        // Map at least enough whole pages for the request, at least one grow
        // chunk (amortise), clamped to the window's remaining VA.
        let need_pages = (min_bytes + PAGE - 1) / PAGE;
        let want_pages = if need_pages > GROW_CHUNK_PAGES {
            need_pages
        } else {
            GROW_CHUNK_PAGES
        };
        let room_pages = (remaining / PAGE as u64) as usize;
        let req_pages = if want_pages > room_pages {
            room_pages
        } else {
            want_pages
        };
        if req_pages == 0 {
            return false;
        }
        // tb-hal's per-arch primitive: pull `req_pages` 4 KiB frames from M6 (+
        // any intermediate page-table frames it needs, ALSO from M6), splice
        // them through the M3 typed page-table layer so `[window_next,
        // window_next + mapped*PAGE)` maps to them RW+NX kernel-only, and report
        // how many pages it actually mapped (`< req_pages` only on frame OOM).
        let mapped = crate::arch::map_heap_frames(self.window_next, req_pages);
        if mapped == 0 {
            return false; // out of physical frames
        }
        let bytes = mapped * PAGE;
        let region = self.window_next;
        self.window_next += bytes as u64;
        self.window_bytes += bytes;
        // Donate the freshly mapped, contiguous slice to the SAME M5 free list.
        self.insert_free_region(region as usize, bytes);
        true
    }

    /// Return a region previously handed out by [`HeapState::alloc`] with the
    /// SAME `layout`. Re-inserts `[ptr, ptr + size)` into the free list, merging
    /// with any adjacent free neighbours. A null `ptr` is a no-op.
    fn dealloc(&mut self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let (size, _align) = match required(layout) {
            Some(v) => v,
            None => return,
        };
        self.insert_free_region(ptr as usize, size);
        self.used = self.used.saturating_sub(size);
    }
}

/// Interior-mutable, `Sync` wrapper around [`HeapState`] — the M2 `TaskStack`
/// pattern (an [`UnsafeCell`] guarded by an [`AtomicBool`]).
struct HeapCell {
    state: UnsafeCell<HeapState>,
    lock: AtomicBool,
}

// SAFETY: the inner `HeapState` is only ever reached through `with`, which takes
// the `lock` before minting a `&mut` to it; on this single, non-preemptible core
// that guard hands out exclusive access, so the `UnsafeCell` is never aliased.
// (M8's first IRQ will require masking interrupts inside `with`; see module doc.)
unsafe impl Sync for HeapCell {}

impl HeapCell {
    /// A new, unlocked, uninitialised heap cell for a `const` static.
    const fn new() -> Self {
        HeapCell {
            state: UnsafeCell::new(HeapState::new()),
            lock: AtomicBool::new(false),
        }
    }

    /// Run `f` with exclusive access to the [`HeapState`], under the guard.
    ///
    /// Single-core, non-reentrant: the allocator never allocates while inside
    /// here, so the CAS only ever succeeds uncontended; a contended acquire
    /// would mean reentrancy (a bug) rather than true contention. M8 must add
    /// interrupt-masking around this section (module doc).
    fn with<R>(&self, f: impl FnOnce(&mut HeapState) -> R) -> R {
        while self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // SAFETY: the CAS above gives this core exclusive ownership of the cell
        // for the duration of `f`; nothing else can hold a `&mut` to the state.
        let state = unsafe { &mut *self.state.get() };
        let result = f(state);
        self.lock.store(false, Ordering::Release);
        result
    }
}

/// The single, crate-internal heap instance. The kernel's `#[global_allocator]`
/// ([`Heap`]) forwards here; the safe facade ([`init`], [`used_bytes`],
/// [`high_water`], [`selftest`]) drives it. M7 swaps only the backing store fed
/// to [`init`]; this state and its algebra are unchanged.
static GLOBAL_HEAP: HeapCell = HeapCell::new();

/// The fixed `.bss` heap arena. Zero-initialised (NOBITS), `align(16)` so its
/// base is comfortably [`HEADER_ALIGN`]-aligned. The same `UnsafeCell` +
/// `unsafe impl Sync` shape as `TaskStack`, since it is shared mutable storage.
#[repr(align(16))]
struct Arena {
    mem: UnsafeCell<[u8; ARENA_BYTES]>,
}

// SAFETY: the arena's bytes are only ever reached as raw memory through the
// guarded `GLOBAL_HEAP`; `Arena` itself hands out nothing but its base address,
// so the `UnsafeCell` is never turned into an aliasing reference.
unsafe impl Sync for Arena {}

impl Arena {
    /// A new zeroed arena for a `const` static.
    const fn new() -> Self {
        Arena {
            mem: UnsafeCell::new([0u8; ARENA_BYTES]),
        }
    }

    /// The base address of the arena's bytes.
    fn base(&self) -> usize {
        self.mem.get() as *mut u8 as usize
    }
}

/// The fixed static heap arena (`.bss`). Replaced by a frame-backed store in M7.
static ARENA: Arena = Arena::new();

/// The kernel-facing `#[global_allocator]` handle.
///
/// A zero-sized forwarding type: it carries no state itself (the heap lives in
/// the crate-internal [`GLOBAL_HEAP`]), so the kernel can declare
/// `#[global_allocator] static HEAP: tb_hal::Heap = tb_hal::Heap::new();`
/// without any `unsafe`. The `unsafe impl GlobalAlloc` below — the sole route a
/// `Layout` turns into a raw pointer — lives here in tb-hal, per the framekernel
/// rule.
pub struct Heap;

impl Heap {
    /// Construct the global-allocator handle. `const`, for a `static`.
    pub const fn new() -> Heap {
        Heap
    }
}

// SAFETY: `alloc`/`dealloc` forward to the guarded `GLOBAL_HEAP`, which upholds
// the GlobalAlloc contract — `alloc` returns a `layout`-fit pointer or null
// (never panicking on OOM), and `dealloc` is only ever called by `alloc`'s
// callers with a pointer+layout this allocator previously returned.
unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        GLOBAL_HEAP.with(|s| s.alloc(layout))
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        GLOBAL_HEAP.with(|s| s.dealloc(ptr, layout));
    }
}

/// Lay the heap down over the static [`ARENA`]. Idempotent; call once early.
pub(crate) fn init() {
    GLOBAL_HEAP.with(|s| s.init(ARENA.base(), ARENA_BYTES));
}

/// Enable the M7 frame-backed growable window (see [`HeapState::window_init`]).
/// The window VA range is the per-arch [`crate::arch::heap_window`] constant.
/// Idempotent; call once after M6 (`pmm_init`) so a grow can pull real frames.
pub(crate) fn window_init() {
    let (base, size) = crate::arch::heap_window();
    GLOBAL_HEAP.with(|s| s.window_init(base, size));
}

/// DATA-page bytes currently mapped into the growable window (excludes the
/// intermediate page-table frames a grow also pulls). `0` before the first
/// grow; rises monotonically as the heap scales past the arena.
pub(crate) fn window_bytes() -> usize {
    GLOBAL_HEAP.with(|s| s.window_bytes)
}

/// Bytes currently handed out (the no-leak baseline metric).
pub(crate) fn used_bytes() -> usize {
    GLOBAL_HEAP.with(|s| s.used)
}

/// Maximum bytes ever simultaneously handed out (heap high-water mark).
pub(crate) fn high_water() -> usize {
    GLOBAL_HEAP.with(|s| s.high_water)
}

/// Low-level allocator self-test that the `forbid(unsafe_code)`-class kernel
/// cannot perform itself (it touches raw pointers). Returns `true` on success.
///
/// Exercises, all ending back at the entry baseline so it leaks nothing:
///   1. an OVER-ARENA request is HANDLED — `alloc` returns null (no panic, no
///      UB) and no bytes are accounted;
///   2. an over-aligned `alloc` honours the alignment, is writable across its
///      whole length, and after `dealloc` the SAME address is handed back on a
///      re-`alloc` of the same layout (real dealloc + reuse, not a bump);
///   3. two adjacent blocks freed and then re-served as ONE larger block, which
///      can only fit if the neighbours COALESCED.
pub(crate) fn selftest() -> bool {
    let baseline = used_bytes();
    let arena = GLOBAL_HEAP.with(|s| s.arena_size);

    // 0. size == 0 / ZST request: `required` collapses it onto a real MIN_BLOCK
    //    region, so alloc returns a NON-null, dealloc-symmetric pointer (never a
    //    dangling sentinel), and freeing it lands back at baseline.
    if let Ok(zst) = Layout::from_size_align(0, 1) {
        let z = GLOBAL_HEAP.with(|s| s.alloc(zst));
        if z.is_null() {
            return false;
        }
        GLOBAL_HEAP.with(|s| s.dealloc(z, zst));
        if used_bytes() != baseline {
            return false;
        }
    }

    // 1. Over-arena request is handled with null, not UB; accounting untouched.
    if let Ok(huge) = Layout::from_size_align(arena + 4096, 8) {
        let p = GLOBAL_HEAP.with(|s| s.alloc(huge));
        if !p.is_null() {
            return false;
        }
    }
    if used_bytes() != baseline {
        return false;
    }

    // 2. Over-aligned alloc / write / dealloc / re-alloc reuse round-trip.
    let layout = match Layout::from_size_align(96, 64) {
        Ok(l) => l,
        Err(_) => return false,
    };
    let p1 = GLOBAL_HEAP.with(|s| s.alloc(layout));
    if p1.is_null() || (p1 as usize) % 64 != 0 || used_bytes() == baseline {
        return false;
    }
    // SAFETY: `p1` is a live 96-byte region; fill then read back one byte.
    unsafe {
        core::ptr::write_bytes(p1, 0xA5, 96);
    }
    // SAFETY: `p1` still owns that region; the byte was just written.
    if unsafe { *p1 } != 0xA5 {
        return false;
    }
    GLOBAL_HEAP.with(|s| s.dealloc(p1, layout));
    if used_bytes() != baseline {
        return false;
    }
    let p2 = GLOBAL_HEAP.with(|s| s.alloc(layout));
    if p2 != p1 {
        return false; // freed block must be reused at the same address
    }
    GLOBAL_HEAP.with(|s| s.dealloc(p2, layout));

    // 3. Coalescing: two adjacent blocks, freed, must re-serve as one big block.
    let small = match Layout::from_size_align(64, 8) {
        Ok(l) => l,
        Err(_) => return false,
    };
    let a = GLOBAL_HEAP.with(|s| s.alloc(small));
    let b = GLOBAL_HEAP.with(|s| s.alloc(small));
    if a.is_null() || b.is_null() {
        return false;
    }
    GLOBAL_HEAP.with(|s| s.dealloc(a, small));
    GLOBAL_HEAP.with(|s| s.dealloc(b, small));
    let big = match Layout::from_size_align(128, 8) {
        Ok(l) => l,
        Err(_) => return false,
    };
    let c = GLOBAL_HEAP.with(|s| s.alloc(big));
    if c.is_null() || (c as usize) != (a as usize) {
        return false; // 128 B only fits where the two 64 B blocks merged
    }
    GLOBAL_HEAP.with(|s| s.dealloc(c, big));

    used_bytes() == baseline
}