//! `tb-hal` — TABOS Hardware Abstraction Layer (M0 serial + M1 traps + M2
//! tasks + M3 MMU + M4 user/ring boundary).
//!
//! Single crate where `unsafe`/asm is allowed (framekernel rule,
//! KERNEL-FOUNDATION-SPEC.md §1). Raw pokes live in `arch/`; THIS file is the
//! thin, mostly-safe facade the `kernel` crate is allowed to call:
//!
//! M0: [`serial_init`], [`serial_write_byte`], [`serial_write_str`], [`halt`].
//! M1: [`install_traps`], [`breakpoint`], [`set_trap_hook`], [`TrapInfo`] /
//!     [`TrapKind`] / [`TrapAction`] (the safe trap-dispatch ABI).
//! M2: [`Task`], [`task_create`], [`yield_to`], [`TaskStack`], [`current_task`]
//!     (cooperative context switch; the saved SP is the whole per-task handle).
//! M3: [`mmu_init`], [`mmu_selftest`] (MMU bring-up + map/remap self-test; the
//!     shared typed table layer is `mmu.rs`).
//! M4 (this milestone): [`user_demo`] — drop the CPU to unprivileged mode
//!     (x86_64 ring 3 / aarch64 EL0) at a tiny user stub, have it issue ONE
//!     syscall (`int 0x80` / `svc #0`) that traps back into the kernel,
//!     observe it (and its magic argument) from the safe handler, and return
//!     the CPU to the kernel. The whole round-trip + all new unsafe/asm lives
//!     in `arch::user`; the kernel crate only branches on the returned bool.
//!
//! POLICY lives in safe Rust: tb-hal's per-arch asm marshals a raw
//! `TrapFrame`, an `extern \"C\"` handler (the ONLY raw-frame deref) builds a
//! safe [`TrapInfo`] and calls the registered hook via [`dispatch_trap`]; the
//! default hook returns [`TrapAction::Halt`].

#![no_std]
#![deny(missing_docs)]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

mod arch;
mod heap; // M5: free-list global allocator over a fixed .bss arena.
mod mmu; // M3: shared typed page-table layer (PageTable512/Frame4K + entry math).
mod pmm; // M6: intrusive free-frame physical allocator over the boot memory map.

/// Initialise the early serial console for the current architecture.
///
/// * x86_64: legacy 16550 UART, COM1 @ I/O port `0x3F8`.
/// * aarch64: PL011 UART0 @ MMIO `0x0900_0000` (QEMU `virt` first-light).
///
/// Must be called once before any [`serial_write_byte`] / [`serial_write_str`].
pub fn serial_init() {
    arch::serial_init();
}

/// Write a single byte to the early serial console, blocking until the UART can
/// accept it.
pub fn serial_write_byte(b: u8) {
    arch::serial_write_byte(b);
}

/// Write a string to the early serial console, byte by byte (blocking).
///
/// Pure safe Rust: a loop over [`serial_write_byte`]; performs no `unsafe`.
pub fn serial_write_str(s: &str) {
    for &b in s.as_bytes() {
        arch::serial_write_byte(b);
    }
}

/// Halt the (single) vCPU forever. Never returns.
///
/// * x86_64: masked `cli; hlt` spin.
/// * aarch64: `wfi` spin with interrupts masked.
pub fn halt() -> ! {
    arch::halt()
}

// ===========================================================================
// M1: trap installation + safe dispatch ABI
// ===========================================================================

/// Install real CPU exception/interrupt handling for the current architecture.
///
/// * x86_64: load a PERMANENT flat 64-bit GDT (null, ring0 code, ring0 data,
///   64-bit TSS, ring3 user code/data), reload `CS`/data segments, `ltr` the
///   TSS, then load a 256-entry IDT of 64-bit interrupt gates. `#DF`/NMI/`#MC`
///   route through TSS IST stacks.
/// * aarch64: point `VBAR_EL1` at the 2 KiB-aligned, 16×128-byte vector table.
///
/// Idempotent. Call once early from `rust_main`, before [`breakpoint`].
pub fn install_traps() {
    arch::install_traps();
}

/// Execute a software breakpoint trap on the current architecture.
///
/// * x86_64: `int3` (`#BP`, vector 3) — a TRAP whose CPU-saved `RIP` already
///   points PAST the instruction, so it resumes automatically on
///   [`TrapAction::Resume`].
/// * aarch64: `brk #0` — a SYNCHRONOUS exception (`ESR_EL1.EC = 0x3C`) whose
///   `ELR_EL1` points AT the instruction; the trap entry advances `ELR_EL1` by
///   4 on [`TrapAction::Resume`].
pub fn breakpoint() {
    arch::breakpoint();
}

/// The architecture-neutral classification of a trap, derived in the per-arch
/// `extern \"C\"` handler from the raw cause (vector + error code on x86_64,
/// `ESR_EL1.EC` on aarch64).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrapKind {
    /// Software breakpoint: x86 `#BP` (vector 3) / aarch64 `brk` (EC `0x3C`).
    Breakpoint,
    /// Page / data fault: x86 `#PF` (vector 14) / aarch64 data abort
    /// (EC `0x24`/`0x25`). [`TrapInfo::fault_addr`] holds the faulting address.
    PageFault,
    /// Undefined / invalid instruction: x86 `#UD` (vector 6) / aarch64 Unknown
    /// (EC `0x00`).
    Undefined,
    /// Any other trap not specially classified above.
    Other,
}

/// What the dispatch hook asks tb-hal to do after a trap is handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrapAction {
    /// Return from the trap entry so execution continues past the trapping
    /// instruction (x86: `iretq`; aarch64: `eret`, advancing `ELR_EL1` by 4 for
    /// the at-instruction synchronous breakpoint).
    Resume,
    /// Do not return; park the vCPU forever. Used for fatal faults and as the
    /// default policy when no hook is registered.
    Halt,
}

/// A safe, fully-owned description of a trap, handed to the dispatch hook.
///
/// Built inside tb-hal's per-arch handler from the raw `TrapFrame`; it borrows
/// nothing from the raw frame, so the hook (in the otherwise-`forbid(unsafe)`
/// kernel crate) can read it freely.
#[derive(Clone, Copy, Debug)]
pub struct TrapInfo {
    /// The architecture-neutral kind of this trap.
    pub kind: TrapKind,
    /// Raw cause word. x86_64: `(vector << 32) | (error_code & 0xFFFF_FFFF)`.
    /// aarch64: the full `ESR_EL1` value (EC = bits `[31:26]`).
    pub cause: u64,
    /// Faulting address for memory faults (x86 `CR2` for `#PF`; aarch64
    /// `FAR_EL1` for a data abort), otherwise `0`.
    pub fault_addr: u64,
    /// The trapping instruction pointer (x86 saved `RIP`; aarch64 `ELR_EL1`).
    pub pc: u64,
}

/// Storage for the registered trap hook: a `fn(&TrapInfo) -> TrapAction`
/// reinterpreted as `usize`. `0` means \"no hook registered → default halt\".
static TRAP_HOOK: AtomicUsize = AtomicUsize::new(0);

/// The default policy when no hook has been registered: always halt.
fn default_trap_hook(_info: &TrapInfo) -> TrapAction {
    TrapAction::Halt
}

/// Register the safe trap-dispatch policy hook.
///
/// A plain `fn(&TrapInfo) -> TrapAction`; it lives in safe Rust (e.g. the
/// kernel crate under `#![forbid(unsafe_code)]`) and decides per-trap whether
/// to [`TrapAction::Resume`] or [`TrapAction::Halt`].
pub fn set_trap_hook(hook: fn(&TrapInfo) -> TrapAction) {
    TRAP_HOOK.store(hook as usize, Ordering::Release);
}

/// Dispatch a trap to the registered hook (or the default halt policy).
///
/// Called by each per-arch `extern \"C\"` handler with a [`TrapInfo`] it built
/// from the raw frame: the safe boundary between the raw-frame deref
/// (per-arch, `unsafe`) and the policy hook (safe).
pub(crate) fn dispatch_trap(info: &TrapInfo) -> TrapAction {
    let raw = TRAP_HOOK.load(Ordering::Acquire);
    if raw == 0 {
        return default_trap_hook(info);
    }
    // SAFETY: `raw` is non-zero, so it was produced by `set_trap_hook` from a
    // valid `fn(&TrapInfo) -> TrapAction` via `hook as usize`. A function
    // pointer and `usize` are pointer-sized; this is the exact inverse cast.
    let hook: fn(&TrapInfo) -> TrapAction =
        unsafe { core::mem::transmute::<usize, fn(&TrapInfo) -> TrapAction>(raw) };
    hook(info)
}

// ===========================================================================
// M2: cooperative tasks + context switch
// ===========================================================================
//
// Saved-context model (callee-saved-on-stack): `yield_to` saves ONLY the
// callee-saved registers of the outgoing task on its own stack and records the
// resulting SP in that task's slot; resuming is \"load saved SP, pop the
// callee-saved set, return\". A single `usize` (the saved SP) is the whole
// per-task context. Caller-saved regs are dead across the call, so unsaved.
//
// Verified ABI facts (do NOT change register sets / frame layouts without
// re-reading): x86-64 SysV psABI §3.2.1 callee-saved = {rbx, rbp, r12..r15}
// (+rsp); §3.2.2 \"(%rsp + 8) is a multiple of 16\" at entry. AAPCS64 §6.1.1
// callee-saved = r19..r29 + SP (r29=FP, r30=LR carries the resume address);
// §6.4.5.1 \"SP mod 16 = 0\". Initial-frame fabrication (OSDev \"Brendan's
// Multi-tasking Tutorial\"): a fake callee-saved frame whose return address /
// LR is the entry, so the FIRST switch \"returns\" into `entry`. No FP/SIMD
// state is switched (both targets are soft-float).

/// Number of task slots tb-hal tracks, INCLUDING slot 0 (the bootstrap context
/// `rust_main` runs on). Eight leaves headroom without a heap.
const MAX_TASKS: usize = 8;

/// Per-slot saved stack pointer — the WHOLE saved context of a suspended task.
/// `0` means \"no saved context\". `AtomicUsize` for safe interior mutability
/// (single-core cooperative, not racing).
static TASK_SP: [AtomicUsize; MAX_TASKS] = [const { AtomicUsize::new(0) }; MAX_TASKS];

/// Slot index of the task currently executing on this (single) core.
static CURRENT_TASK: AtomicUsize = AtomicUsize::new(0);

/// Next free slot in [`TASK_SP`]; slot 0 is the bootstrap context.
static NEXT_TASK_SLOT: AtomicUsize = AtomicUsize::new(1);

/// Smallest stack [`task_create`] accepts, in `usize` words.
const MIN_STACK_WORDS: usize = 64;

/// An opaque handle to a cooperative kernel task: the slot index into tb-hal's
/// internal saved-SP table. `Copy`; convertible to/from a raw `usize` (see
/// [`Task::raw`]) so the `forbid(unsafe_code)` kernel can stash handles in
/// `AtomicUsize` statics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Task(usize);

impl Task {
    /// The raw slot index of this handle, for stashing in an `AtomicUsize`.
    pub fn raw(self) -> usize {
        self.0
    }

    /// Rebuild a handle from a value previously obtained via [`Task::raw`].
    ///
    /// Safe: an invalid index cannot cause memory unsafety — it is rejected
    /// fail-closed by [`yield_to`] (bounds + saved-context check).
    pub fn from_raw(raw: usize) -> Self {
        Task(raw)
    }
}

/// Handle of the task currently executing (slot 0 — the bootstrap context —
/// until the first [`yield_to`] after [`task_create`]).
pub fn current_task() -> Task {
    Task(CURRENT_TASK.load(Ordering::Relaxed))
}

/// Fail-closed termination for misuse of the M2 task API: report over serial
/// (best-effort) and park the core. Never returns.
fn task_api_fatal(msg: &str) -> ! {
    serial_write_str("tb-hal: task: ");
    serial_write_str(msg);
    serial_write_byte(b'\n');
    halt()
}

/// Create a cooperative task that starts executing `entry` the first time
/// somebody [`yield_to`]s it.
///
/// `stack` is caller-provided `'static` memory (see [`TaskStack`]; tb-hal does
/// NOT allocate). The arch backend fabricates the INITIAL context frame at the
/// 16-byte-aligned-down top of `stack` so the first switch \"returns\" into
/// `entry` with an ABI-conformant stack.
///
/// `entry` must never return. Fatal (reports + halts) if the stack is too
/// small or all task slots are used.
pub fn task_create(stack: &'static mut [usize], entry: fn()) -> Task {
    if stack.len() < MIN_STACK_WORDS {
        task_api_fatal("task_create: stack too small");
    }
    let slot = NEXT_TASK_SLOT.fetch_add(1, Ordering::Relaxed);
    if slot >= MAX_TASKS {
        task_api_fatal("task_create: too many tasks");
    }
    let sp = arch::task_stack_init(stack, entry);
    TASK_SP[slot].store(sp, Ordering::Release);
    Task(slot)
}

/// Cooperatively switch from the current context to `next`.
///
/// Saves the callee-saved registers + SP of the CURRENT task (on its own
/// stack), records the resulting SP, then loads `next`'s saved SP, restores
/// its callee-saved registers and returns into it. Yielding to the current
/// task is a no-op; an invalid handle is fatal (report + halt).
pub fn yield_to(next: Task) {
    if next.0 >= MAX_TASKS {
        task_api_fatal("yield_to: invalid task handle");
    }
    let prev = CURRENT_TASK.load(Ordering::Relaxed);
    if prev == next.0 {
        return; // self-yield: nothing to switch
    }
    let next_sp = TASK_SP[next.0].load(Ordering::Acquire);
    if next_sp == 0 {
        task_api_fatal("yield_to: target has no saved context");
    }
    CURRENT_TASK.store(next.0, Ordering::Relaxed);
    // SAFETY: `next_sp` was produced by `arch::task_stack_init` (fabricated
    // frame) or a previous `ctx_switch` save; both leave a well-formed
    // callee-saved frame at that SP. `TASK_SP[prev].as_ptr()` is a valid
    // 'static atomic for the single word `ctx_switch` stores. Single core +
    // cooperative: no other context can touch either slot mid-switch.
    unsafe { arch::ctx_switch(TASK_SP[prev].as_ptr(), next_sp) }
}

/// A statically-allocatable, 16-byte-aligned kernel task stack of `WORDS`
/// `usize` words, takeable exactly once as `&'static mut [usize]`.
///
/// Lets the `#![forbid(unsafe_code)]` kernel OWN its static stack arrays and
/// still mint the unique `&'static mut` [`task_create`] requires. The atomic
/// one-shot gate makes aliased handouts impossible; a second [`TaskStack::take`]
/// is fatal.
#[repr(C, align(16))]
pub struct TaskStack<const WORDS: usize> {
    mem: UnsafeCell<[usize; WORDS]>,
    taken: AtomicBool,
}

// SAFETY: the ONLY route to the inner array is `take()`, whose swap-once gate
// hands out at most one `&'static mut` ever, so shared references to the cell
// never alias the interior data.
unsafe impl<const WORDS: usize> Sync for TaskStack<WORDS> {}

impl<const WORDS: usize> TaskStack<WORDS> {
    /// A new zeroed stack; `const`, so it can initialise a kernel `static`.
    pub const fn new() -> Self {
        TaskStack {
            mem: UnsafeCell::new([0; WORDS]),
            taken: AtomicBool::new(false),
        }
    }

    /// Hand out the stack as `&'static mut [usize]` — exactly once. A second
    /// call on the same static is fatal (fail-closed).
    pub fn take(&'static self) -> &'static mut [usize] {
        if self.taken.swap(true, Ordering::AcqRel) {
            task_api_fatal("TaskStack::take: taken twice");
        }
        // SAFETY: the swap guarantees this runs at most once per static, so the
        // `&mut` minted here is unique for `'static`; `UnsafeCell` makes
        // mutating the interior of an immutable `static` well-defined.
        let array: &'static mut [usize; WORDS] = unsafe { &mut *self.mem.get() };
        &mut array[..]
    }
}

// ===========================================================================
// M3: MMU bring-up + map/remap self-test
// ===========================================================================
//
// The typed table layer both backends share is `mmu.rs` (pure safe Rust); ALL
// new unsafe + asm (CR3/EFER/invlpg, MAIR/TCR/TTBR0/SCTLR, dsb/isb/tlbi, the
// mapped-VA derefs) lives in `arch/`. The kernel only sees the two safe fns.

/// Bring the MMU to the M3 baseline. Call ONCE from `rust_main`, AFTER
/// [`install_traps`] (a broken mapping then reports via the trap path instead
/// of an opaque hang / triple fault).
///
/// * x86_64: paging is already LIVE; this programs `EFER.NXE` so PTE bit 63
///   (NX) is honoured. `IA32_PAT` keeps its power-on default.
/// * aarch64: brings the MMU up from cold — identity tables (L1[0] Device for
///   the PL011 gigabyte, L1[1] Normal-WB for RAM, AF on every leaf), then
///   `MAIR_EL1`/`TCR_EL1`/`TTBR0_EL1` → `isb` → `SCTLR_EL1.{M,C,I}` → `isb`.
pub fn mmu_init() {
    arch::mmu_init();
}

/// Run the in-HAL MMU map/remap self-test; `true` = pass.
///
/// Maps `TEST_VA` (x86_64 `0x4000_0000` / aarch64 `0x8000_0000`, both OUTSIDE
/// the identity region) to frame A, writes a magic through `TEST_VA`, verifies
/// via frame A's identity address, remaps to frame B (x86: PTE rewrite +
/// `invlpg`; aarch64: full Break-Before-Make + `tlbi`), and verifies the read
/// through `TEST_VA` now sees frame B. Tables/frames are static, 4096-aligned,
/// `.bss`-resident; every raw deref stays in tb-hal's arch backends.
pub fn mmu_selftest() -> bool {
    arch::mmu_selftest()
}

// ===========================================================================
// M4: user/ring boundary (this milestone)
// ===========================================================================
//
// The privileged/unprivileged split end-to-end: tb-hal drops the CPU to ring 3
// (x86_64) / EL0 (aarch64), runs a tiny user stub, the stub issues ONE syscall
// that traps back into the kernel, the safe handler records it, and the CPU
// returns to the kernel. ALL new unsafe/asm lives in `arch::user`; this facade
// just forwards. The kernel crate stays `#![forbid(unsafe_code)]`.

/// M4 user/ring round-trip; `true` = the syscall was observed from user mode
/// with the expected magic argument (`0xCAFE`).
///
/// tb-hal sets up a user-accessible code page + user stack page (via the M3
/// `mmu` machinery, with USER permission bits at every level of the walk),
/// drops the CPU to unprivileged mode at the stub, the stub issues the syscall
/// (x86_64 `int 0x80` with `rax = 0xCAFE`; aarch64 `svc #0` with
/// `x0 = 0xCAFE`), the kernel-side handler records the argument and switches
/// the CPU back into a kernel continuation, and `user_demo` reads the recorded
/// flag/argument. The whole round-trip — USER mappings, the privileged drop
/// (`iretq` / `eret`), the user stub, the syscall entry and the kernel return
/// — lives in `arch::user`; all the new unsafe + assembly is confined there.
pub fn user_demo() -> bool {
    arch::user_demo()
}

// ===========================================================================
// MV: tb-boot v0 — recognise a `tb-vmm` boot (the L1 sovereignty rung)
// ===========================================================================
//
// On the tb-boot path the kernel's `rust_main(boot_info: usize)` is entered
// (via `arch::x86_64::boot::_tb_start`) with `boot_info` = the guest-physical
// address of an identity-mapped `tb_boot::TbBootInfo`. On the PVH path the same
// argument is an `hvm_start_info` pointer instead. The kernel crate is
// `#![forbid(unsafe_code)]`, so it cannot dereference the raw address itself;
// THIS is the single, guarded raw read that lets it tell the two boot paths
// apart by magic — the one place the boundary is crossed, confined to tb-hal.

/// Read the 8-byte `tb-boot` magic at the boot-info pointer, if that pointer is
/// safe to dereference; `None` otherwise (so the caller fail-closed-ignores it).
///
/// `boot_info` is the raw `usize` `rust_main` was entered with. The magic is the
/// first field (offset 0) of `#[repr(C)] tb_boot::TbBootInfo`, so this reads it
/// WITHOUT importing the struct layout. The caller — the `forbid(unsafe_code)`
/// kernel — compares the result against `tb_boot::TB_BOOT_MAGIC`: a match means
/// `tb-vmm` booted us via tb-boot v0; a mismatch (e.g. a PVH `hvm_start_info`
/// pointer, whose magic is `0x336e_c578`) is simply ignored, never misread.
///
/// The read is guarded to the architecture's identity-mapped low window
/// (`[0x1000, 1 GiB)` on x86_64 — the PVH `_start` / tb-vmm 2 MiB-page identity
/// region, which is present and readable) and to 8-byte alignment, so a stray
/// or out-of-window pointer can never fault the boot path; it just yields
/// `None`. aarch64 is an MV follow-up: there the FDT pointer (QEMU `virt` places
/// it at `0x4000_0000`) falls outside this window and is correctly ignored.
pub fn read_boot_magic(boot_info: usize) -> Option<u64> {
    // Lowest address we will touch (reject the null page) and the first address
    // past the identity-mapped window. Both x86_64 boot paths map [0, 1 GiB)
    // with 2 MiB pages: PVH `_start` builds __boot_pd; tb-vmm builds the same
    // shape (Firecracker `regs.rs::setup_page_tables`). Anything in range is
    // present, so an 8-byte read there cannot page-fault.
    const WINDOW_LO: usize = 0x1000;
    const WINDOW_HI: usize = 0x4000_0000; // 1 GiB, exclusive upper bound

    if boot_info < WINDOW_LO {
        return None;
    }
    // Ensure the whole 8-byte read stays inside the window.
    if boot_info > WINDOW_HI - core::mem::size_of::<u64>() {
        return None;
    }
    // A `u64` read must be 8-byte aligned (TbBootInfo is `#[repr(C)]` with
    // `magic: u64` first, so the struct — and thus its magic — is 8-aligned).
    if boot_info % core::mem::align_of::<u64>() != 0 {
        return None;
    }

    // SAFETY: `boot_info` is in [0x1000, 1 GiB - 8] and 8-byte aligned (checked
    // above), so it lies inside the present, identity-mapped 2 MiB-page region
    // the active boot path established (PVH `_start` or tb-vmm), making this
    // 8-byte read both mapped and aligned. `u64` has no invalid bit patterns,
    // so whatever bytes are there form a valid value (we never act on it unless
    // it equals `TB_BOOT_MAGIC`). `read_volatile` stops the optimiser from
    // making assumptions about this foreign, single-producer boot word. The
    // pointee is boot RAM that outlives this call.
    let magic = unsafe { (boot_info as *const u64).read_volatile() };
    Some(magic)
}

// ===========================================================================
// M5: bring `alloc` online (this milestone)
// ===========================================================================
//
// A from-scratch, intrusive free-list global allocator served from a fixed
// `.bss` static arena, so Box/Vec/BTreeMap/String work kernel-wide BEFORE any
// physical frame allocator exists. ALL the unsafe — the static arena, its
// `unsafe impl Sync`, the `unsafe impl GlobalAlloc`, and every raw pointer /
// free-list manipulation — lives in `heap.rs`; this file exposes only the safe
// facade and re-exports the global-allocator type. The kernel declares
// `#[global_allocator] static HEAP: tb_hal::Heap = tb_hal::Heap::new();`, calls
// `heap_init()` once, then uses `alloc` types and the stats/self-test fns below.
// The allocator algebra is reused UNCHANGED by M7 (only the backing store, the
// arena, changes there).

pub use heap::Heap;

/// Lay the kernel heap down over its fixed `.bss` arena. Idempotent; call once
/// early (e.g. from `rust_main`, after M4) before using any `alloc` type.
///
/// Installs a single free block spanning the arena; subsequent allocations are
/// served first-fit with splitting and coalescing. All raw work is in `heap.rs`.
pub fn heap_init() {
    heap::init();
}

/// Bytes currently handed out by the global allocator (sum of live allocations'
/// normalised sizes). Returns to its post-[`heap_init`] baseline once every
/// allocation is freed — the metric a no-leak assertion checks.
pub fn heap_used_bytes() -> usize {
    heap::used_bytes()
}

/// The maximum [`heap_used_bytes`] ever observed — the heap high-water mark.
pub fn heap_high_water() -> usize {
    heap::high_water()
}

/// Run tb-hal's low-level allocator self-test; `true` = pass.
///
/// Performs the raw-pointer checks the `forbid(unsafe_code)`-class kernel cannot
/// do itself: an over-arena request returns null (handled, not UB); an
/// over-aligned alloc/dealloc/re-alloc round-trip reuses the freed block at the
/// same address; and two freed adjacent blocks re-serve as one larger block
/// (proving coalescing). It leaks nothing — used-bytes ends at the entry value.
pub fn heap_selftest() -> bool {
    heap::selftest()
}

// ===========================================================================
// M7: frame-backed GROWABLE kernel heap (this milestone)
// ===========================================================================
//
// Re-back the M5 free-list allocator with a kernel-only VA window (RW + NX,
// OUTSIDE the identity map) that GROWS ON DEMAND: when no existing free region
// fits a request, the allocator pulls 4 KiB frames from the M6 physical frame
// allocator (plus any intermediate page-table frames it needs, ALSO from M6),
// splices them through the M3 typed page-table layer (`PageTable512`) so the
// next CONTIGUOUS chunk of the window maps to those possibly-scattered frames,
// and donates that chunk to the SAME M5 free list. The allocator ALGEBRA
// (first-fit + coalescing + alignment) is byte-for-byte the M5 code; only the
// backing store + the grow hook are new. ALL the page-table writes, the M6
// frame pulls, and the writes THROUGH the mapped window VAs live in tb-hal
// (`heap.rs` + the per-arch `map_heap_frames`); the `#![forbid(unsafe_code)]`
// kernel only calls the safe facade below and uses `alloc` types. DoD marker:
// "M7: heap OK".

/// Enable the M7 frame-backed growable kernel heap.
///
/// Installs the kernel-heap VA window (the per-arch range, OUTSIDE the identity
/// map) and arms the allocator's grow-on-miss path. After this, an allocation
/// that no existing free region can satisfy triggers an on-demand map of fresh
/// M6 frames into the window, then a retry; only if that map fails (true OOM)
/// does `alloc` return null. Idempotent; call once after [`pmm_init`] (M6).
///
/// Before this is called the heap is exactly the M5 fixed `.bss`-arena
/// allocator (the grow hook is inert), so M0-M6 behaviour is unchanged.
pub fn heap_window_init() {
    heap::window_init();
}

/// DATA-page bytes currently mapped into the growable heap window — `0` until
/// the first grow, then climbing as the heap scales past the fixed 2 MiB `.bss`
/// arena. Counts only the data pages donated to the free list, NOT the
/// intermediate page-table frames the grow also pulls from M6 (so it slightly
/// under-counts total frames consumed). The M7 self-test reads it only to
/// confirm real frames backed the growth (it rises as [`pmm_free_frames`] drops).
pub fn heap_window_mapped_bytes() -> usize {
    heap::window_bytes()
}

// ===========================================================================
// M6: physical frame allocator over the active boot memory map (this milestone)
// ===========================================================================
//
// A from-scratch INTRUSIVE FREE-FRAME STACK that hands out / reclaims 4 KiB
// PHYSICAL frames from usable RAM only — never the kernel image (which now
// INCLUDES M5's 2 MiB .bss heap arena), the boot structures, sub-1 MiB on
// x86_64, or device MMIO. The per-arch boot-map READERS (PVH `hvm_start_info` /
// tb-boot `TbBootInfo` / aarch64 QEMU-`virt` map) and ALL the raw memory access
// — the guarded boot-map reads, the kernel-image linker-symbol read, and the
// next-free-PA links written THROUGH each free frame's identity address — live
// in `pmm.rs` + `arch::pmm`. The kernel crate stays `#![forbid(unsafe_code)]`:
// `frame_alloc` returns a PHYSICAL address it cannot dereference, so the
// "write a magic through the frame then verify" check lives in `pmm_selftest`
// (mirroring M5's `heap_selftest`). DoD marker: "M6: frame alloc OK".

/// Parse the ACTIVE boot path's memory map and seed the physical frame
/// allocator. Idempotent; call once early (after [`heap_init`], i.e. after M5),
/// passing the same `boot_info` `rust_main` was entered with.
///
/// tb-hal reads the boot map for the live path — x86_64 PVH
/// `hvm_start_info.memmap`, x86_64 tb-boot `tb_boot::TbBootInfo` regions, or the
/// aarch64 QEMU `virt` map — clamps usable RAM to the M3 identity region, carves
/// out the kernel image (incl. the M5 heap arena), the boot structures, sub-1
/// MiB (x86_64) and the DTB (aarch64), and pushes every remaining 4 KiB frame
/// onto an intrusive free stack. All raw work is in `pmm.rs`/`arch::pmm`.
pub fn pmm_init(boot_info: usize) {
    pmm::init(boot_info);
}

/// Allocate one 4 KiB physical frame, returning its PHYSICAL address, or `None`
/// when usable RAM is exhausted (fail-closed). O(1) pop of the free stack.
///
/// The returned address is 4 KiB-aligned, inside a parsed usable-RAM range, and
/// disjoint from every reservation. The `#![forbid(unsafe_code)]` kernel may
/// compare it but cannot dereference it (see [`pmm_selftest`]).
pub fn frame_alloc() -> Option<u64> {
    pmm::frame_alloc()
}

/// Return a frame previously obtained from [`frame_alloc`] to the free stack;
/// `true` = accepted, `false` = rejected (fail-closed) for a misaligned/null
/// address, an address outside usable RAM, an address inside a reservation, a
/// free when nothing is allocated, or a double-free of the current stack top.
/// O(1) push.
pub fn frame_free(pa: u64) -> bool {
    pmm::frame_free(pa)
}

/// Total frames the allocator seeded at [`pmm_init`]:
/// `sum(usable RAM ranges) − reservations`. Constant after init; the invariant
/// the M6 self-test checks the free count against.
pub fn pmm_total_frames() -> usize {
    pmm::total_frames()
}

/// Frames currently available on the free stack (`pmm_total_frames` minus the
/// number of live allocations).
pub fn pmm_free_frames() -> usize {
    pmm::free_frames()
}

/// `true` iff `pa` lies inside a parsed usable-RAM range. Lets the
/// `#![forbid(unsafe_code)]` kernel assert an allocated frame is real RAM.
pub fn pmm_addr_in_usable_ram(pa: u64) -> bool {
    pmm::addr_in_usable_ram(pa)
}

/// `true` iff `pa` lies inside any reservation (kernel image incl. the heap
/// arena, boot structures, sub-1 MiB, DTB, or a device/non-RAM hole). Lets the
/// kernel assert an allocated frame never overlaps a reservation.
pub fn pmm_addr_reserved(pa: u64) -> bool {
    pmm::addr_reserved(pa)
}

/// Run tb-hal's low-level frame self-test; `true` = pass.
///
/// Performs the raw-memory check the `forbid(unsafe_code)`-class kernel cannot:
/// allocate a frame, write a magic THROUGH its identity-mapped address (first
/// word and a word deep in the page), read both back, free it, and end at the
/// entry free-count (no leak). Mirrors M5's [`heap_selftest`].
pub fn pmm_selftest() -> bool {
    pmm::selftest()
}

// ===========================================================================
// M8: asynchronous interrupt + monotonic timer tick (this milestone)
// ===========================================================================
//
// The kernel's FIRST asynchronous-interrupt machinery: a periodic hardware
// timer (x86_64 LAPIC timer / aarch64 EL1 physical timer via GICv2) fires while
// interrupts are briefly unmasked, the per-arch IRQ entry path saves + restores
// the FULL register frame, and control returns to the exact interrupted
// instruction. The monotonic tick counter and the (M9-facing) IRQ hook are
// arch-neutral SAFE state HERE -- a single source of truth -- while every
// register poke (LAPIC/GIC MMIO, the timer system registers, `sti`/`cli` and
// `daifclr`/`daifset`, the cycle counter) lives in `arch::*::timer`. NO
// scheduler is touched -- M9 will register an IRQ hook that calls `schedule()`.

/// Monotonic count of timer ticks taken since boot. Bumped by [`dispatch_irq`]
/// from each arch IRQ handler (the single place a tick is counted); read by the
/// M8 self-test and, later, the scheduler. `AtomicU64`: written from interrupt
/// context, read from the foreground on one core (no contention, just
/// visibility).
static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);

/// Registered async-IRQ hook (`fn(irq_id)`) reinterpreted as `usize`; `0` means
/// "no hook -> only the tick is counted". M9 registers `schedule()` here so a
/// tick drives an involuntary switch. SEPARATE from the synchronous
/// [`TRAP_HOOK`]: a timer IRQ carries none of [`TrapInfo`]'s fault semantics
/// (`fault_addr` / `cause` / Resume-vs-Halt), and the kernel's trap policy halts
/// on anything but `#BP`, so preemption must never thread through it.
static IRQ_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Total timer ticks observed since boot. The M8 self-test asserts this
/// advanced across the canary window; M9 reads it for scheduling quanta.
pub fn tick_count() -> u64 {
    TIMER_TICKS.load(Ordering::Relaxed)
}

/// Register the safe per-tick async-IRQ hook (`fn(irq_id)`), invoked from
/// [`dispatch_irq`] AFTER the tick counter is bumped. A plain `fn(u64)` so it
/// lives in the `#![forbid(unsafe_code)]` kernel; M9 points it at `schedule()`.
/// Replaces any previous hook.
pub fn set_irq_hook(hook: fn(u64)) {
    IRQ_HOOK.store(hook as usize, Ordering::Release);
}

/// Dispatch one asynchronous interrupt: bump the monotonic tick, then run the
/// registered IRQ hook (if any). Called by each per-arch timer handler with the
/// platform interrupt id (x86_64 IDT vector / aarch64 GIC INTID) once it has
/// acked the controller -- the single safe boundary between the raw IRQ entry
/// asm (per-arch, `unsafe`) and policy (safe; M9's `schedule()`).
pub(crate) fn dispatch_irq(irq_id: u64) {
    TIMER_TICKS.fetch_add(1, Ordering::Relaxed);
    let raw = IRQ_HOOK.load(Ordering::Acquire);
    if raw != 0 {
        // SAFETY: `raw` is non-zero, so `set_irq_hook` produced it from a valid
        // `fn(u64)` via `hook as usize`; a function pointer and `usize` are
        // pointer-sized and this is the exact inverse cast.
        let hook: fn(u64) = unsafe { core::mem::transmute::<usize, fn(u64)>(raw) };
        hook(irq_id);
    }
}

/// Run the in-HAL async-interrupt + timer self-test; `true` = pass.
///
/// Brings up the interrupt controller + a periodic timer (x86_64: map the LAPIC
/// UC, enable it + the LAPIC timer on IDT vector `0x20`; aarch64: init GICv2 +
/// the EL1 physical timer on PPI 30), unmasks interrupts for the FIRST time in
/// the whole kernel, spins a register-integrity canary across many ticks, then
/// re-masks the timer + interrupts. Returns `true` iff at least the required
/// number of ticks were observed AND the canary's recomputation matched across
/// every async interrupt (proving the full frame was saved/restored). Touches
/// NO scheduler.
pub fn timer_demo() -> bool {
    arch::timer_demo()
}

/// Read the in-guest cycle counter for honest boot benchmarking: x86_64 `rdtsc`
/// (TSC), aarch64 `CNTPCT_EL0` (physical counter). A monotonic, VMM-independent
/// clock the kernel samples at entry and after the M8 marker to print a
/// guest-only `boot-cycles` figure (see docs/BENCHMARKS.md §2/§5).
pub fn read_cycle_counter() -> u64 {
    arch::read_cycle_counter()
}
