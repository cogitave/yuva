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
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};

// M11: the capability subsystem (`caps`) needs heap-backed collections
// (`Vec`/`Rc`). `alloc` is brought online crate-wide by the kernel's
// `#[global_allocator]` (tb-hal's `heap.rs`); this single line lets tb-hal name
// it too. No allocator is defined here -- only the final kernel binary does, and
// `cargo kbuild` recompiles `alloc` via `-Zbuild-std=core,compiler_builtins,alloc`.
extern crate alloc;

mod arch;
pub mod caps; // M11: SAFE capability handle table + object model + dispatcher.
mod mem; // M13: SAFE tiered per-agent memory substrate (T0..T3 + recall).
mod ipc; // M14: SAFE inter-agent IPC channel core (bounded ordered FIFO + cap move).
mod blocks; // M15: SAFE shared-memory block core (pinned M6 frames + RECORD CAS).
pub mod infer; // M16: SAFE LLM-agnostic inference bridge core (model: scheme + backend registry).
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
/// `rust_main` runs on). Raised to 12 at M12: the cumulative boot now creates
/// boot(0) + M2 A/B(1,2) + M9 C/D(3,4) + M10 G/H(5,6) + M12 two agents(7,8),
/// so the prior `8` would fatal on the second agent. 12 leaves headroom.
const MAX_TASKS: usize = 12;

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
    // M10: fold the address-space switch into the cooperative/preemptive switch.
    // BEFORE the register switch, flip the top-level page-table root to `next`'s
    // space (when it differs from `prev`'s), so `ctx_switch` reads/writes the
    // next task's stack under the correct translation. Every entity root shares
    // the kernel half, so this code, the stacks and serial stay mapped across
    // the flip. A no-op when both tasks use the same root -- the M2/M9 case,
    // where every task is the default boot space -- so pre-M10 boots are
    // byte-for-byte unchanged (no control-register touch, even while the
    // aarch64 MMU is still OFF during M2).
    switch_address_space(prev, next.0);
    // M12: fold the per-task KERNEL-stack switch in beside the address-space
    // switch. When the incoming task is a USER (ring3/EL0) agent, program the
    // CPU's privilege-change stack pointer (x86 TSS.rsp0; aarch64 SP_EL1 is
    // tracked automatically, so a no-op) to THAT agent's own kernel stack, so a
    // timer IRQ taken while the agent runs unprivileged pushes its frame on the
    // agent's stack. Kernel tasks keep `0` and leave the register untouched.
    switch_kernel_stack(next.0);
    // SAFETY: `next_sp` was produced by `arch::task_stack_init` (fabricated
    // frame) or a previous `ctx_switch` save; both leave a well-formed
    // callee-saved frame at that SP. `TASK_SP[prev].as_ptr()` is a valid
    // 'static atomic for the single word `ctx_switch` stores. Single core, and
    // the switch is atomic w.r.t. interrupts: M2 calls this cooperatively while
    // M9 calls it from IRQ context with RFLAGS.IF / PSTATE.I masked from
    // exception entry until the switched-in task's own `iretq`/`eret`, so no
    // timer tick can re-enter `yield_to` and touch either slot mid-switch.
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

// ===========================================================================
// M9: preemptive round-robin scheduler (involuntary full-context switch)
// ===========================================================================
//
// On a timer tick the kernel INVOLUNTARILY switches kernel tasks: a task that
// never voluntarily `yield_to`s still loses the CPU. The design REUSES the M2
// cooperative `ctx_switch` UNCHANGED. Justification: the per-arch IRQ entry
// (`__alltraps` on x86_64 / `__vec_irq`'s `SAVE_CONTEXT` on aarch64) already
// saved the FULL interrupted register frame on the CURRENT task's own kernel
// stack BEFORE any Rust ran, and the call chain down to `schedule()` is
// [full IRQ frame] -> trap_handler -> try_handle_irq/handle_irq ->
// `dispatch_irq` -> `schedule` -> `ctx_switch`. So when `ctx_switch` saves the
// callee-saved continuation + SP and switches to the next task, that task --
// whether it was preempted earlier (its full frame + its own suspended handler
// chain sit on ITS stack) or is brand-new (a fabricated entry frame) -- resumes
// by unwinding back through ITS handler chain and the IRQ epilogue's
// `iretq`/`eret`, which restores ITS full frame at ITS interrupted instruction.
// A separate "full-frame switch primitive" is therefore NOT needed: the full
// frame is already on the stack; `ctx_switch` only has to swap the callee-saved
// continuation that returns INTO that epilogue.
//
// No per-task `TSS.rsp0` / `SP_EL1` juggling is needed for M9: every task runs
// at ring0 / EL1 on its OWN kernel stack, so the CPU builds each IRQ frame on
// the current task's stack automatically. (User-task involuntary preemption --
// a CPL/EL change on the saved frame, which DOES need a per-task rsp0/SP_EL1 --
// is first exercised at M12; see ROADMAP-V2 §3.)
//
// The run queue + the involuntary-switch counter live HERE (safe atomics), so
// the kernel crate stays `#![forbid(unsafe_code)]`: it only drives the scheduler
// facade. `schedule(irq_id)` is a `fn(u64)`, so it slots straight into the M8
// `set_irq_hook` seam. Round-robin to start; a QoS lane (INTERACTIVE / PIPELINE
// / BULK) is the deferred M9+ hook. The seam is forward-compatible: M10 swaps
// the address-space root inside the same switch, M12 adds the user-frame variant.

/// Run queue: task slot indices scheduled round-robin. `usize::MAX` marks an
/// empty entry. Populated by [`scheduler_init`] (the bootstrap task) and
/// [`scheduler_spawn`]; read by [`schedule`] from interrupt context.
static RUNQUEUE: [AtomicUsize; MAX_TASKS] = [const { AtomicUsize::new(usize::MAX) }; MAX_TASKS];

/// Number of live entries at the front of [`RUNQUEUE`].
static RUNQUEUE_LEN: AtomicUsize = AtomicUsize::new(0);

/// Count of INVOLUNTARY context switches [`schedule`] has performed since boot.
/// Written from interrupt context, read from the foreground; the M9 self-test
/// asserts it crosses a threshold (proving a no-yield task really lost the CPU).
static INVOLUNTARY_SWITCHES: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// M14.2: blocking-recv run-state -- a receiver on an EMPTY channel parks OFF the
// run queue (RUNNABLE -> BLOCKED) and a sender's delivery makes it RUNNABLE
// again (runnable-on-send). A PARALLEL `TASK_STATE[]` array that `schedule()`
// SKIPS when BLOCKED -- NOT run-queue compaction: skipping is O(1) per entry,
// keeps slot indices stable, and is byte-identical M9 round-robin when nothing
// is blocked (so M2/M9/M10/M12 stay green). The block/wake POLICY lives HERE
// (the scheduler-owning layer); caps.rs/ipc.rs stay mechanism-only + forbid(unsafe).
// ---------------------------------------------------------------------------

/// M14.2: a task that is on the scheduler's round-robin (the default).
const TASK_RUNNABLE: u8 = 0;
/// M14.2: a task parked OFF the run queue (descheduled by
/// [`block_current_and_yield`], re-made RUNNABLE by [`sched_wake_task`]).
const TASK_BLOCKED: u8 = 1;

/// M14.2: per-task run state (RUNNABLE/BLOCKED), indexed by task slot. Safe
/// atomics: written from the foreground (a blocking receiver) AND from the send
/// path (the wake), read by [`schedule`] from interrupt context, all single-core.
static TASK_STATE: [AtomicU8; MAX_TASKS] = [const { AtomicU8::new(TASK_RUNNABLE) }; MAX_TASKS];

/// M14.2: `true` iff task `t` is parked BLOCKED off the run queue (descheduled on
/// an empty-channel receive, awaiting a sender's wake). The self-test's SENDER
/// polls this to prove the receiver is demonstrably OFF the run queue BEFORE it
/// delivers -- the direct "parked off the run queue" witness.
pub fn task_is_blocked(t: Task) -> bool {
    let slot = t.raw();
    slot < MAX_TASKS && TASK_STATE[slot].load(Ordering::Acquire) == TASK_BLOCKED
}

/// M14.2: mark task `slot` RUNNABLE -- the runnable-on-send wake. Called from the
/// `M_CHAN_SEND` dispatch arm (crate-internal) AFTER a message is enqueued and
/// the ring borrow is dropped, so EVERY send path wakes a blocked receiver. A
/// pure atomic store touching no table/ring, so it never re-borrows the `RefCell`
/// the send just released (the caps.rs `forbid(unsafe)` discipline is preserved).
pub(crate) fn sched_wake_task(slot: u32) {
    let s = slot as usize;
    if s < MAX_TASKS {
        TASK_STATE[s].store(TASK_RUNNABLE, Ordering::Release);
    }
}

/// M14.2: deschedule the CURRENT task (mark it BLOCKED) and hand the CPU to a
/// RUNNABLE peer. Round-robins the run queue from this task's position for a
/// RUNNABLE task != self and [`yield_to`]s it. If NONE exists it is a genuine
/// single-core deadlock (TABOS has no idle task yet), reported fail-closed --
/// the minimal idle-task/WFI path is the documented forward item.
///
/// Called ONLY from [`agent_chan_recv_blocking`] with interrupts MASKED, so the
/// whole {empty-recheck -> register waiter -> mark BLOCKED -> yield} sequence is
/// one indivisible critical section: on a single core a sender cannot run until
/// this task yields, and the waiter was registered BEFORE the yield, so no send
/// can be lost (the seL4 "kernel runs with interrupts disabled" guarantee).
pub(crate) fn block_current_and_yield() {
    let current = CURRENT_TASK.load(Ordering::Relaxed);
    if current < MAX_TASKS {
        TASK_STATE[current].store(TASK_BLOCKED, Ordering::Release);
    }
    let len = RUNQUEUE_LEN.load(Ordering::Acquire);
    // Find this task's position in the queue (head fallback, as M9 schedule()).
    let mut pos = 0;
    let mut i = 0;
    while i < len {
        if RUNQUEUE[i].load(Ordering::Relaxed) == current {
            pos = i;
            break;
        }
        i += 1;
    }
    // Scan the successors for the first RUNNABLE peer and switch to it.
    let mut step = 1;
    while step <= len {
        let cand = RUNQUEUE[(pos + step) % len].load(Ordering::Relaxed);
        if cand != usize::MAX
            && cand != current
            && cand < MAX_TASKS
            && TASK_STATE[cand].load(Ordering::Acquire) == TASK_RUNNABLE
        {
            yield_to(Task(cand));
            return;
        }
        step += 1;
    }
    task_api_fatal("deadlock: all tasks blocked on IPC");
}

/// Initialise the M9 round-robin scheduler: register the CURRENT context (the
/// bootstrap task `rust_main` runs on) as the first runnable entry. Call ONCE,
/// before [`scheduler_spawn`] and before re-arming the timer; pair with
/// [`set_irq_hook`]`(`[`schedule`]`)` so a tick drives the switch.
pub fn scheduler_init() {
    let current = CURRENT_TASK.load(Ordering::Relaxed);
    RUNQUEUE[0].store(current, Ordering::Relaxed);
    RUNQUEUE_LEN.store(1, Ordering::Release);
}

/// Create a preemptible kernel task on `stack` starting at `entry` and append
/// it to the run queue. Reuses the M2 [`task_create`] machinery UNCHANGED (so
/// the fabricated entry frame, the minimum-stack check and the return guard all
/// apply), then enqueues the new slot for round-robin scheduling.
///
/// `entry` must never voluntarily yield AND must unmask interrupts once at the
/// top (see [`irq_unmask`]): a freshly-activated task is entered through
/// `ctx_switch`'s plain return with interrupts still masked from the switching
/// IRQ, so it re-enables them itself to become preemptible. Fatal (report +
/// halt) if more than `MAX_TASKS` slots are queued.
pub fn scheduler_spawn(stack: &'static mut [usize], entry: fn()) -> Task {
    let task = task_create(stack, entry);
    let len = RUNQUEUE_LEN.load(Ordering::Relaxed);
    if len >= MAX_TASKS {
        task_api_fatal("scheduler_spawn: run queue full");
    }
    RUNQUEUE[len].store(task.0, Ordering::Relaxed);
    RUNQUEUE_LEN.store(len + 1, Ordering::Release);
    task
}

/// The M9 tick policy: pick the next runnable task round-robin and perform an
/// INVOLUNTARY switch to it. Registered as the [`set_irq_hook`] callback, so it
/// runs from interrupt context on every timer tick (after [`tick_count`] was
/// bumped by `dispatch_irq`). Reuses the M2 cooperative [`yield_to`] (hence the
/// arch `ctx_switch`) UNCHANGED -- see the module note for why the already-saved
/// IRQ frame makes that sufficient. A no-op when fewer than two tasks are
/// runnable (it simply resumes the interrupted task).
pub fn schedule(_irq_id: u64) {
    let len = RUNQUEUE_LEN.load(Ordering::Acquire);
    if len < 2 {
        return; // nothing else runnable -> resume the interrupted task
    }
    let current = CURRENT_TASK.load(Ordering::Relaxed);
    // Find `current`'s position in the queue (the head is the fallback if it is
    // somehow not enqueued, which it never is in M9/M12).
    let mut pos = 0;
    let mut i = 0;
    while i < len {
        if RUNQUEUE[i].load(Ordering::Relaxed) == current {
            pos = i;
            break;
        }
        i += 1;
    }
    // M14.2: pick the next RUNNABLE successor (mod len), SKIPPING any BLOCKED
    // entry (a receiver parked off the run queue). With nothing blocked this is
    // byte-identical M9 round-robin -- the immediate successor -- so M2/M9/M10/M12
    // stay green; the skip only ever fires once a blocking receiver exists.
    let mut next = current;
    let mut step = 1;
    while step <= len {
        let cand = RUNQUEUE[(pos + step) % len].load(Ordering::Relaxed);
        if cand != usize::MAX
            && cand < MAX_TASKS
            && TASK_STATE[cand].load(Ordering::Acquire) == TASK_RUNNABLE
        {
            next = cand;
            break;
        }
        step += 1;
    }
    if next == current {
        return; // only one runnable task (others blocked/absent) -> no switch
    }
    INVOLUNTARY_SWITCHES.fetch_add(1, Ordering::Relaxed);
    // Reuse the M2 cooperative switch: it saves the callee-saved continuation
    // (which returns INTO this task's IRQ epilogue) + SP and restores the next
    // task's, so the next task resumes through its OWN epilogue + iret/eret.
    yield_to(Task(next));
}

/// Total INVOLUNTARY context switches [`schedule`] has performed since boot. The
/// M9 self-test asserts this crossed its threshold within the run window.
pub fn involuntary_switch_count() -> u64 {
    INVOLUNTARY_SWITCHES.load(Ordering::Relaxed)
}

/// M9: re-arm the periodic timer and unmask interrupts so a tick drives
/// [`schedule`] from interrupt context. M8's [`timer_demo`] left the controller
/// up but the timer masked; this is the "GO" the kernel calls AFTER
/// [`scheduler_init`] + [`set_irq_hook`]. All the controller pokes + the first
/// re-`sti` / `daifclr` live in `arch::*::timer`.
pub fn timer_rearm() {
    arch::timer_rearm();
}

/// M9: mask interrupts and disarm the periodic timer -- the "STOP" the boot task
/// calls BEFORE printing the marker so the verdict renders with no further
/// involuntary switch in flight.
pub fn timer_disarm() {
    arch::timer_disarm();
}

/// M9: unmask asynchronous interrupts on the CURRENT task WITHOUT touching the
/// timer. A preemptible kernel task spawned via [`scheduler_spawn`] calls this
/// ONCE at the top of its body to become schedulable: it is first entered
/// through `ctx_switch`'s plain return (not an `iretq`/`eret`), so interrupts
/// are still masked from the IRQ that switched into it and it must re-enable
/// them itself. It must NOT later re-mask them (that would stop its own
/// preemption).
pub fn irq_unmask() {
    arch::sched_irq_unmask();
}

/// M14.2: save the interrupt-enable state and MASK interrupts, returning an
/// opaque guard for [`local_irq_restore`]. The lost-wakeup-free critical-section
/// primitive: the unsafe arch asm (x86_64 `pushfq;cli` / aarch64 `mrs daif; msr
/// daifset,#2`) is confined to `arch::*::timer`; this is the SAFE facade the
/// kernel calls (e.g. to wrap an `AGENTS`-touching send a timer must not preempt
/// while a blocked receiver it just woke could be scheduled in). Nestable:
/// [`local_irq_restore`] re-enables interrupts ONLY if they were enabled before.
pub fn local_irq_save() -> u64 {
    arch::local_irq_save()
}

/// M14.2: restore the interrupt-enable state saved by [`local_irq_save`] --
/// re-enabling interrupts iff they were enabled before the matching save.
pub fn local_irq_restore(guard: u64) {
    arch::local_irq_restore(guard);
}

// ===========================================================================
// M10: per-entity address spaces (memory isolation)
// ===========================================================================
//
// Each schedulable entity runs in its OWN top-level page table, so one entity
// cannot read/write another's private memory, while the KERNEL half stays
// mapped across every switch. The mechanism is deliberately SYMMETRIC across
// both arches (no TTBR1/TTBR0 split -- that textbook refinement, with ASIDs and
// PCID, is deferred to M11/M12): `arch::address_space_new` frame-allocates a
// fresh top-level table and COPIES the entire live kernel root into it, so every
// existing kernel mapping (identity RAM, serial, the M7 heap window, the M8
// device window, the M3 test mapping) is shared BY REFERENCE -- the kernel half
// is byte-identical in every entity root, which is why the kernel stack, code
// and serial keep working through any switch. Private pages go into a top-level
// slot the kernel root leaves vacant (x86_64 `PML4[4]`, aarch64 `L1[6]`) via the
// new `arch::map_in_root` primitive, so writing one never affects the kernel
// root or another entity. The switch FOLDS INTO `yield_to` through a parallel
// `TASK_AS[]` of per-task roots, flipping the live root only when the next
// task's root differs from the previous task's.
//
// CAVEAT (defended against): because each entity root is a COPY taken at create
// time, a NEW top-level KERNEL entry created AFTER an `AddressSpace` exists would
// NOT propagate into already-created spaces. None happens during M10's self-test
// (every kernel top-level slot the test relies on -- identity, heap, device,
// LAPIC, the M3 subtree -- predates the first `address_space_new`), and the
// private test VA is the only top-level entry M10 adds, into entity roots only.
// M11/M12 will either pre-reserve the kernel top-level slots or move to the
// TTBR1/higher-half split so kernel growth propagates automatically.

/// Per-task top-level page-table root PA (installed in CR3 / TTBR0_EL1), indexed
/// by task slot. `0` is the sentinel "the default boot space" (every task before
/// M10 keeps it). Written by [`task_set_address_space`], read by the [`yield_to`]
/// address-space fold-in.
static TASK_AS: [AtomicU64; MAX_TASKS] = [const { AtomicU64::new(0) }; MAX_TASKS];

/// M12: per-task KERNEL-stack TOP (the privilege-change landing stack), indexed
/// by task slot. `0` = a kernel (ring0/EL1) task -- never takes a privilege
/// change on a timer IRQ, so its stale value is never consulted. A USER agent
/// stores its own kernel-stack top here at [`agent_spawn`]; [`switch_kernel_stack`]
/// (folded into [`yield_to`]) programs the CPU's privilege-change stack pointer
/// (x86 `TSS.rsp0`) to it on every switch INTO that agent. On aarch64 `SP_EL1`
/// tracks the running task's kernel stack via `ctx_switch` automatically, so the
/// arch hook is a documented no-op there.
static TASK_KSTACK_TOP: [AtomicU64; MAX_TASKS] = [const { AtomicU64::new(0) }; MAX_TASKS];

/// The default boot top-level root PA, captured the first time an
/// [`AddressSpace`] is created (when the live root still IS the boot root every
/// space is copied from). `0` until captured. [`yield_to`] resolves the sentinel
/// `0` in [`TASK_AS`] to this when switching back to a default-space task.
static BOOT_ROOT: AtomicU64 = AtomicU64::new(0);

/// An opaque handle to one address space: the physical address of its private
/// top-level page table (x86_64 PML4 / aarch64 L1). Created by
/// [`address_space_new`] as a COPY of the live kernel root, so the kernel half
/// is shared by reference; private pages added with [`map_in_space`] are visible
/// ONLY through this root. `Copy`, with a raw-PA accessor, so the
/// `#![forbid(unsafe_code)]` kernel can stash it (e.g. for the cross-space
/// fault-recovery hook) and the M11/M12 agent runtime can extend it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressSpace {
    root: u64,
}

impl AddressSpace {
    /// The physical address of this space's top-level page table -- the value
    /// installed in CR3 / TTBR0_EL1 to make it the live address space.
    pub fn root_pa(self) -> u64 {
        self.root
    }
}

/// Create a fresh address space: allocate a top-level page table (one M6 frame)
/// and copy the ENTIRE live kernel root into it, so the kernel half is shared by
/// reference and every entity sees identical kernel mappings. Returns `None` on
/// physical-frame OOM (fail-closed). Captures the default boot root on first use.
pub fn address_space_new() -> Option<AddressSpace> {
    let root = arch::address_space_new()?;
    // Capture the boot root once: at first-create the live root the copy was
    // taken from IS the boot root (no space has been switched to yet).
    let _ = BOOT_ROOT.compare_exchange(
        0,
        arch::current_root(),
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    Some(AddressSpace { root })
}

/// Map one private 4 KiB page `va` -> physical `pa` into `space`'s OWN root (NOT
/// the live root), building intermediate tables from M6 frames as needed. `va`
/// MUST sit in a top-level slot the kernel does not use, so writing it never
/// touches the shared kernel half or another space. `true` on success, `false`
/// on physical-frame OOM.
pub fn map_in_space(space: AddressSpace, va: u64, pa: u64, writable: bool) -> bool {
    arch::map_in_root(space.root, va, pa, writable)
}

/// Make `space` the live address space (install its root in CR3 / TTBR0_EL1 with
/// the arch TLB + barrier ceremony). The shared kernel half keeps the caller's
/// stack, code and serial valid across the flip.
pub fn address_space_switch(space: AddressSpace) {
    arch::switch_root(space.root);
}

/// Re-install the default boot root as the live address space (a no-op if no
/// space has been created yet, i.e. the boot root was never captured).
pub fn address_space_switch_default() {
    let r = BOOT_ROOT.load(Ordering::Acquire);
    if r != 0 {
        arch::switch_root(r);
    }
}

/// Make the space whose top-level root PA is `root_pa` the live address space --
/// the raw-PA twin of [`address_space_switch`], used by the M10 cross-space
/// fault-recovery trap hook (which stashes the home root in an `AtomicU64`).
/// Every root shares the kernel half, so the faulting handler's own stack, code
/// and serial survive the flip.
pub fn address_space_switch_root(root_pa: u64) {
    arch::switch_root(root_pa);
}

/// Assign `space` to `task`, so the next [`yield_to`] into `task` folds in a
/// switch to `space`'s root (and back to the default root when yielding to a
/// task with no space). Fatal on an invalid handle.
pub fn task_set_address_space(task: Task, space: AddressSpace) {
    if task.raw() >= MAX_TASKS {
        task_api_fatal("task_set_address_space: invalid task handle");
    }
    TASK_AS[task.raw()].store(space.root, Ordering::Release);
}

/// The [`yield_to`] address-space fold-in: flip the live top-level page-table
/// root from `prev`'s space to `next`'s space when they differ, resolving the
/// sentinel `0` (no space assigned) to the captured default boot root. A
/// complete no-op -- touching NO control register -- when both tasks share a
/// root (the M2/M9 case, where every task is the default space), so cooperative
/// and preemptive switches are byte-for-byte unchanged for pre-M10 milestones
/// (including while the aarch64 MMU is still OFF during M2).
fn switch_address_space(prev: usize, next: usize) {
    let prev_as = TASK_AS[prev].load(Ordering::Relaxed);
    let next_as = TASK_AS[next].load(Ordering::Relaxed);
    if prev_as == next_as {
        return; // same root (incl. both == 0, the default): nothing to flip
    }
    // Resolve the sentinel 0 (default space) to the real boot-root PA.
    let target = if next_as == 0 {
        BOOT_ROOT.load(Ordering::Acquire)
    } else {
        next_as
    };
    if target == 0 {
        return; // boot root not captured yet (no AddressSpace created): no-op
    }
    arch::switch_root(target);
}

/// M12 [`yield_to`] kernel-stack fold-in: when the incoming task is a USER
/// agent (`TASK_KSTACK_TOP[next] != 0`), program the CPU's privilege-change
/// stack pointer to that agent's own kernel stack so a timer IRQ taken while the
/// agent runs ring3/EL0 builds its frame there. A no-op for kernel tasks
/// (top `0`), so M2/M9/M10 switches touch no extra state. On aarch64
/// `arch::set_kernel_stack` is itself a no-op (SP_EL1 already tracks it).
fn switch_kernel_stack(next: usize) {
    let top = TASK_KSTACK_TOP[next].load(Ordering::Acquire);
    if top != 0 {
        arch::set_kernel_stack(top);
    }
}

/// M10 self-test primitive: write `val` THROUGH virtual address `va`, then read
/// it back and return what was observed. Confined to tb-hal because the
/// `#![forbid(unsafe_code)]` kernel cannot deref a raw VA; a task uses it under
/// its OWN space's root to write+verify its private magic at the shared test VA.
pub fn addr_store_load(va: u64, val: u64) -> u64 {
    // SAFETY: `va` is a self-test address the caller has mapped RW into the LIVE
    // address space (its own space's private page). A single aligned volatile
    // u64 store + load; `read_volatile` stops the optimiser eliding the
    // round-trip. The kernel half (this code/stack) is mapped in every space.
    unsafe {
        let p = va as *mut u64;
        core::ptr::write_volatile(p, val);
        core::ptr::read_volatile(p)
    }
}

/// M10 self-test primitive: read the u64 at virtual address `va`. Confined to
/// tb-hal (raw deref). The kernel uses it to read a space's private magic under
/// that space's root (isolation cross-check) and to PROVOKE the cross-space
/// fault -- reading a VA mapped only in another space, under a root where it is
/// vacant, takes a page fault into the registered trap hook, which records it
/// and (guarded resume) flips to a space where the VA IS mapped before the
/// faulting instruction is re-executed.
pub fn addr_load(va: u64) -> u64 {
    // SAFETY: a single aligned volatile u64 load. When `va` is unmapped in the
    // live space this is the access that intentionally faults; the trap hook
    // recovers the translation before the instruction is restarted.
    unsafe { core::ptr::read_volatile(va as *const u64) }
}

/// M10: re-assert M3 across address-space switches. `true` iff the M3 self-test
/// VA still reads its post-remap magic under the LIVE root -- proving the M3
/// mapping (part of the shared kernel half copied into every space) survives
/// every address-space switch. tb-hal owns the raw read + the expected magic.
pub fn m3_test_va_intact() -> bool {
    arch::m3_test_va_intact()
}

// ===========================================================================
// M11: capability handle table + object model + numbered dispatcher
// ===========================================================================
//
// The cap MACHINERY -- [`caps::Handle`]/[`caps::Rights`]/[`caps::SysStatus`],
// the per-principal [`caps::HandleTable`], the object registry and the numbered
// [`caps::dispatch`] -- is 100% SAFE Rust in the `caps` module (it carries
// `#![forbid(unsafe_code)]`). The ONLY new unsafe M11 adds is the per-arch
// register-lift shim that reads a numbered syscall's args out of the ring3/EL0
// trap frame and hands them to the safe dispatcher; it lives in
// `arch::{x86_64,aarch64}::user`, next to the M4 round trip it generalises
// (mirroring how M1's `set_trap_hook`/`dispatch_trap` split the raw-frame deref
// from the safe policy). The per-arch capture atomics live next to each shim;
// this facade is thin, exactly like [`user_demo`].

/// Drive ONE numbered, capability-checked syscall from ring3/EL0 through the
/// per-arch register-lift shim and return the neutral [`caps::SyscallArgs`] the
/// shim lifted out of the trap frame (`None` if the trap never arrived). The
/// kernel M11 self-test feeds the result to [`caps::dispatch`] to prove the
/// unprivileged boundary is numbered + capability-checked end-to-end.
///
/// `root_handle` is the raw value of the bootstrap capability the unprivileged
/// stub presents. The deterministic first-minted root is `(generation 1, slot
/// 0)`, which the position-independent stub carries as an immediate, so a
/// mismatched expectation returns `None` fail-closed. Mirrors [`user_demo`]:
/// all the new unsafe/asm is confined to tb-hal.
pub fn caps_user_probe(root_handle: u64) -> Option<caps::SyscallArgs> {
    arch::caps_user_probe(root_handle)
}

// ===========================================================================
// M12: the agent runtime -- AgentProcess as a first-class OS entity
// ===========================================================================
//
// `agent_spawn(manifest)` COMPOSES the four already-green substrates into one
// owned Rust value: M10 [`AddressSpace`] (its own root) + M11 [`caps::HandleTable`]
// (its only authority) + an M9 [`Task`] (its run-queue slot) + the manifest
// (its declared, least-privilege authority). The agent is born already holding
// its memory-home + bootstrap + budget handles (minted by spawn, delivered in
// the user-entry register file -- ZERO setup syscalls) and is scheduled
// PREEMPTIVELY in ring3/EL0. The user-mode preemption mechanism (per-task kernel
// stack + TSS.rsp0 / SP_EL1, the fabricated user-launch frame, the EL0-IRQ
// vector) lives in `arch::*`; the cap-syscall bridge [`agent_syscall_current`]
// stays SAFE (it runs `caps::dispatch` on the CURRENT agent's table). All spawn
// LOGIC is safe; the only `unsafe` here is the blessed `UnsafeCell` +
// `unsafe impl Sync` registry cell (the exact `TaskStack` precedent).

/// One declared capability grant in an [`AgentManifest`]: an object KIND the
/// agent is born holding, with the exact RIGHTS minted into its handle. Authority
/// the manifest omits simply never exists for the agent (least privilege by
/// construction).
#[derive(Clone, Copy)]
pub struct CapGrant {
    /// The kind of object minted into the agent's table.
    pub kind: caps::ObjKind,
    /// The rights attached to the minted handle (only ever narrowed thereafter).
    pub rights: caps::Rights,
}

/// The MINIMAL static declaration [`agent_spawn`] consumes -- the TABOS analogue
/// of seL4's initial-thread CNode contents / Zircon's processargs: the exhaustive
/// list of authority an agent is born holding, nothing ambient. `const`-
/// constructible, so the kernel declares `static MANIFEST: AgentManifest = ...`
/// with zero heap/unsafe.
pub struct AgentManifest {
    /// Identity label for audit / serial.
    pub name: &'static str,
    /// The EXACT declared authority: one object minted per grant (least privilege).
    pub caps: &'static [CapGrant],
    /// Request the born-with memory home (true at M12).
    pub wants_memory_home: bool,
}

/// An [`AgentProcess`] -- the first-class OS entity composing the four substrates.
/// One owned Rust value (the M18 checkpoint/fork/migrate unit), held in [`AGENTS`].
#[allow(dead_code)] // several fields are identity/forward-compat (M13/M14/M18)
struct AgentProcess {
    /// The signed-in-spirit authority declaration this agent was minted from.
    manifest: &'static AgentManifest,
    /// M10: the agent's OWN top-level root (own CR3 / TTBR0).
    space: AddressSpace,
    /// M11: the per-principal authority -- THE table `caps::dispatch` resolves against.
    table: caps::HandleTable,
    /// M9: the scheduler / run-queue slot handle.
    task: Task,
    /// The per-agent ring0/EL1 stack top (TSS.rsp0 / SP_EL1 landing on preemption).
    kstack_top: u64,
    /// Born-with `ObjKind::MemoryHome` (M13 fills the body).
    memory_home: caps::Handle,
    /// Born-with `ObjKind::Channel` bootstrap (M14 fills the body).
    bootstrap: caps::Handle,
    /// Born-with `ObjKind::Budget` (split from the caller at M12+).
    budget: caps::Handle,
    /// Identity = the task slot / agent id.
    principal: u32,
    /// M18: the SEPARATE `WRITE_PROCEDURAL` T4 skill-home, minted KERNEL-MEDIATED
    /// by [`agent_skill_propose`] on first use (the `agent_model_open` INVOKE_MODEL
    /// grant precedent) -- NEVER the born-with episodic home (which stays
    /// `READ|WRITE|RECALL`, so an ordinary skill write is `Denied`). `Handle::NULL`
    /// until the self-improver first proposes.
    skill_home: caps::Handle,
}

/// The agent registry: `[Option<AgentProcess>; MAX_TASKS]` indexed by task slot,
/// behind the `TaskStack`-style `UnsafeCell` + `unsafe impl Sync` cell. Mutated
/// only single-core with interrupts masked (spawn in the disarmed boot window;
/// the cap-syscall bridge inside the syscall gate), so the transient `&mut` it
/// hands out never aliases -- the same soundness argument `ctx_switch` relies on.
struct AgentTable {
    agents: UnsafeCell<[Option<AgentProcess>; MAX_TASKS]>,
}

// SAFETY: single-core; the only mutation paths are `agent_spawn` (boot window,
// timer disarmed) and `agent_syscall_current` (inside the ring3/EL0 syscall gate
// with IF / PSTATE.I clear), so no two accesses to a slot's `&mut` overlap.
unsafe impl Sync for AgentTable {}

impl AgentTable {
    /// A transient `&mut` to slot `i`. Caller must be single-core with interrupts
    /// masked (the registry's discipline), so the borrow never aliases.
    #[allow(clippy::mut_from_ref)]
    fn slot(&self, i: usize) -> &mut Option<AgentProcess> {
        // SAFETY: see the type-level `unsafe impl Sync` note; `i < MAX_TASKS` is
        // checked by every caller, keeping the index in bounds.
        unsafe { &mut (*self.agents.get())[i] }
    }
}

static AGENTS: AgentTable = AgentTable {
    agents: UnsafeCell::new([const { None }; MAX_TASKS]),
};

/// Per-agent observation: set when the agent's PERMITTED capability-checked
/// syscall (`M_OBJECT_INSPECT` on its born-with memory home) returned `Ok` from
/// the cap bridge -- witness #2 of the born-with-memory guarantee, observed from
/// the user side.
static AGENT_PERMITTED_OK: [AtomicBool; MAX_TASKS] = [const { AtomicBool::new(false) }; MAX_TASKS];

/// Per-agent observation: set when the agent's NON-MANIFEST capability syscall
/// (`M_EMIT_EXTERNAL`, a right its manifest never granted) returned `Denied` --
/// least privilege holding end-to-end through the user boundary.
static AGENT_DENIED_OK: [AtomicBool; MAX_TASKS] = [const { AtomicBool::new(false) }; MAX_TASKS];

/// Mint one capability per [`CapGrant`] into `table` (after the born-with set).
fn mint_manifest_caps(table: &mut caps::HandleTable, manifest: &AgentManifest) {
    let mut i = 0;
    while i < manifest.caps.len() {
        let g = manifest.caps[i];
        if table.mint(g.kind, g.rights).is_none() {
            task_api_fatal("agent_spawn: handle table full minting manifest caps");
        }
        i += 1;
    }
}

/// M12: spawn an [`AgentProcess`] from a static `manifest` on a caller-provided
/// `kstack`, scheduled preemptively in ring3/EL0. Mints the agent's OWN address
/// space, its per-principal handle table (born-with memory-home + bootstrap +
/// budget, then one handle per manifest grant), fabricates the user-launch frame
/// on `kstack`, maps the agent's user code + stack into its private root, and
/// enqueues it for the round-robin timer. Returns the agent's [`Task`] handle.
/// Fatal (report + halt) on frame OOM or slot exhaustion. Call in the disarmed
/// boot window (timer off), AFTER [`scheduler_init`].
pub fn agent_spawn(manifest: &'static AgentManifest, kstack: &'static mut [usize]) -> Task {
    // 1. The agent's own address space (a copy of the live kernel half).
    let space = match address_space_new() {
        Some(s) => s,
        None => task_api_fatal("agent_spawn: out of frames for the address space"),
    };

    // 2. The per-principal table + the born-with handle set, minted DETERMINISTICALLY
    //    (memory_home FIRST -> generation 1, slot 0) so the agent can name them.
    // Capacity 32: a single agent (agent_c) is reused as the principal across the
    // cumulative M13/M14/M15/M16 self-tests, each minting handles into this SAME
    // table (never closed), so the born-with set + M14 endpoints + M15 blocks +
    // M16 sessions must all coexist. (The M11/M12 ObjFull algebra tests use their
    // OWN explicitly-sized tables, so this bound is independent of them.)
    let mut table = caps::HandleTable::with_capacity(48);
    let mh_rights = caps::Rights::READ
        .union(caps::Rights::WRITE)
        .union(caps::Rights::RECALL);
    let bs_rights = caps::Rights::READ
        .union(caps::Rights::WRITE)
        .union(caps::Rights::TRANSFER);
    // M13: the born-with home now carries a REAL per-agent tiered substrate
    // (mint_memory_home attaches a fresh MemSubstrate) -- the memory:private/<agent>
    // namespace reachable ONLY through this handle via the M11 dispatch chokepoint.
    let memory_home = match table.mint_memory_home(mh_rights) {
        Some(h) => h,
        None => task_api_fatal("agent_spawn: could not mint the memory home"),
    };
    let bootstrap = match table.mint(caps::ObjKind::Channel, bs_rights) {
        Some(h) => h,
        None => task_api_fatal("agent_spawn: could not mint the bootstrap channel"),
    };
    let budget = match table.mint(caps::ObjKind::Budget, caps::Rights::READ) {
        Some(h) => h,
        None => task_api_fatal("agent_spawn: could not mint the budget"),
    };
    mint_manifest_caps(&mut table, manifest);

    // 3. Map the agent's user code (shared stub) + private stack into its OWN root.
    let (entry_va, user_sp) = match arch::agent_map_space(space.root_pa()) {
        Some(x) => x,
        None => task_api_fatal("agent_spawn: out of frames mapping the user window"),
    };

    // 4. Fabricate the resume-symmetric user-launch frame on the kernel stack;
    //    the birth registers carry the memory-home + bootstrap handles.
    let top = ((kstack.as_ptr() as usize + kstack.len() * core::mem::size_of::<usize>()) & !0xF)
        as u64;
    let sp = arch::task_stack_init_user(kstack, entry_va, user_sp, memory_home.raw(), bootstrap.raw());

    // 5. Allocate a scheduler slot and wire the per-task state.
    let slot = NEXT_TASK_SLOT.fetch_add(1, Ordering::Relaxed);
    if slot >= MAX_TASKS {
        task_api_fatal("agent_spawn: too many tasks");
    }
    TASK_SP[slot].store(sp, Ordering::Release);
    TASK_KSTACK_TOP[slot].store(top, Ordering::Release);
    TASK_AS[slot].store(space.root_pa(), Ordering::Release);
    AGENT_PERMITTED_OK[slot].store(false, Ordering::Release);
    AGENT_DENIED_OK[slot].store(false, Ordering::Release);

    let task = Task(slot);
    *AGENTS.slot(slot) = Some(AgentProcess {
        manifest,
        space,
        table,
        task,
        kstack_top: top,
        memory_home,
        bootstrap,
        budget,
        principal: slot as u32,
        skill_home: caps::Handle::NULL,
    });

    // 6. Enqueue for the round-robin timer (append after the current queue).
    let len = RUNQUEUE_LEN.load(Ordering::Relaxed);
    if len >= MAX_TASKS {
        task_api_fatal("agent_spawn: run queue full");
    }
    RUNQUEUE[len].store(slot, Ordering::Relaxed);
    RUNQUEUE_LEN.store(len + 1, Ordering::Release);

    task
}

/// M12: install the per-arch agent cap-syscall door (x86 the `int 0x82` DPL3
/// gate; a no-op on aarch64, whose EL0 `svc` slot is already wired). Idempotent;
/// call once before arming the timer for the agents.
pub fn agent_traps_init() {
    arch::agent_traps_init();
}

/// M12: the SAFE cap-syscall bridge the per-arch ring3/EL0 register-lift shim
/// calls. Resolves the CURRENT task to its [`AgentProcess`], runs the numbered,
/// capability-checked [`caps::dispatch`] against ITS table, records the
/// permitted/denied observations, and returns `(status, value)` for the shim to
/// place in the agent's result registers. `None` when the current task is not an
/// agent (so the legacy M4/M11 EL0 paths fall through unchanged).
pub fn agent_syscall_current(method: u64, handle: u64, a0: u64, a1: u64) -> Option<(u32, u64)> {
    let slot = CURRENT_TASK.load(Ordering::Relaxed);
    if slot >= MAX_TASKS {
        return None;
    }
    let ap = AGENTS.slot(slot).as_mut()?;
    let args = caps::SyscallArgs {
        method: method as u32,
        handle: caps::Handle::from_raw(handle),
        args: [a0, a1, 0, 0],
    };
    let ret = caps::dispatch(&mut ap.table, &args);
    if args.method == caps::M_OBJECT_INSPECT && ret.status == caps::SysStatus::Ok {
        AGENT_PERMITTED_OK[slot].store(true, Ordering::Release);
    }
    if args.method == caps::M_EMIT_EXTERNAL && ret.status == caps::SysStatus::Denied {
        AGENT_DENIED_OK[slot].store(true, Ordering::Release);
    }
    Some((ret.status as u32, ret.value))
}

/// M13: kernel-side facade driving a numbered, capability-checked memory method
/// against `task`'s OWN born-with memory home (the per-agent substrate; `AGENTS`
/// is private). Runs the full [`caps::dispatch`] against the agent's table with
/// ALL four inline args plumbed, returning `(status, value)` -- or `None` if
/// `task` is not a live agent. This is the through-the-born-with-home witness:
/// it proves the substrate is a real per-agent guarantee reached only through
/// the M11 chokepoint, not a local toy.
pub fn agent_mem_dispatch(
    task: Task,
    method: u32,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
) -> Option<(u32, u64)> {
    let slot = task.raw();
    if slot >= MAX_TASKS {
        return None;
    }
    let ap = AGENTS.slot(slot).as_mut()?;
    let args = caps::SyscallArgs {
        method,
        handle: ap.memory_home,
        args: [a0, a1, a2, a3],
    };
    let ret = caps::dispatch(&mut ap.table, &args);
    Some((ret.status as u32, ret.value))
}

/// M17: the sleep-time CONSOLIDATE daemon facade -- drive ONE bounded maintenance
/// cycle (distill + reflect + forget_sweep) through `task`'s born-with memory home
/// at the M11 chokepoint (`M_MEM_CONSOLIDATE` op=3, `Rights::CONSOLIDATE`-gated).
/// Returns `(status, affected_count)`; `None` if `task` is not a live agent. A
/// normal agent born WITHOUT `CONSOLIDATE` (`mh_rights = READ|WRITE|RECALL`) is
/// correctly `Denied` -- the daemon proper mints its own CONSOLIDATE-righted home.
pub fn agent_consolidate_cycle(task: Task) -> Option<(u32, u64)> {
    agent_mem_dispatch(task, caps::M_MEM_CONSOLIDATE, 3, 0, 0, 0)
}

/// M17: READ-ONLY observability facade -- read `task`'s GA importance accumulator
/// (`M_MEM_CONSOLIDATE` op=7) so the >=150 consolidation trigger is witnessable.
/// `Denied` for an agent lacking `CONSOLIDATE`, mirroring [`agent_consolidate_cycle`].
#[allow(dead_code)]
pub fn agent_mem_accumulator(task: Task) -> Option<(u32, u64)> {
    agent_mem_dispatch(task, caps::M_MEM_CONSOLIDATE, 7, 0, 0, 0)
}

/// M14: open ONE ordered, bounded, bidirectional IPC channel between agents `a`
/// and `b`, minting a fresh [`caps::ObjKind::Channel`] ENDPOINT into EACH agent's
/// own table (side 0 in `a`, side 1 in `b`) over a shared `Rc<ipc::Channel>`
/// core. Returns `(ep_a, ep_b)`, or `None` if either task is not a live agent or
/// they are the same task. The two `AGENTS.slot()` borrows are taken in SEPARATE
/// scopes (the `Rc` cloned across) so no two `&mut AgentProcess` ever overlap --
/// the single-`&mut`-at-a-time discipline the registry relies on.
pub fn agent_channel_connect(
    a: Task,
    b: Task,
    bound: usize,
) -> Option<(caps::Handle, caps::Handle)> {
    let sa = a.raw();
    let sb = b.raw();
    if sa >= MAX_TASKS || sb >= MAX_TASKS || sa == sb {
        return None;
    }
    let ch = ipc::create(bound);
    let ep_rights = caps::Rights::READ
        .union(caps::Rights::WRITE)
        .union(caps::Rights::TRANSFER);
    let ha = {
        let ap_a = AGENTS.slot(sa).as_mut()?;
        ap_a.table.mint_channel_endpoint(ep_rights, ch.clone(), 0)?
    };
    let hb = {
        let ap_b = AGENTS.slot(sb).as_mut()?;
        ap_b.table.mint_channel_endpoint(ep_rights, ch, 1)?
    };
    Some((ha, hb))
}

/// M14: drive `M_CHAN_SEND` against `t`'s OWN table through the M11 dispatch
/// chokepoint -- `payload` in `args[0]`, the raw handle of an optional cap to
/// MOVE in `args[1]` (`0` = bytes-only). Returns `(status, value)`, or `None` if
/// `t` is not an agent.
pub fn agent_chan_send(t: Task, ep: caps::Handle, payload: u64, cap_h: u64) -> Option<(u32, u64)> {
    let slot = t.raw();
    if slot >= MAX_TASKS {
        return None;
    }
    let ap = AGENTS.slot(slot).as_mut()?;
    let args = caps::SyscallArgs {
        method: caps::M_CHAN_SEND,
        handle: ep,
        args: [payload, cap_h, 0, 0],
    };
    let ret = caps::dispatch(&mut ap.table, &args);
    Some((ret.status as u32, ret.value))
}

/// M14: the richer kernel-side RECV facade -- runs the READ-gated channel recv
/// against `t`'s OWN table and returns `(status, inline payload, moved-handle)`.
/// The single-scalar [`caps::SysReturn`] dispatch path can only return the moved
/// handle; this tuple surfaces the inline payload too (the user ABI will deliver
/// it via the deferred `copy_to_user`). `None` if `t` is not an agent.
pub fn agent_chan_recv_full(t: Task, ep: caps::Handle) -> Option<(u32, u64, u64)> {
    let slot = t.raw();
    if slot >= MAX_TASKS {
        return None;
    }
    let ap = AGENTS.slot(slot).as_mut()?;
    let (st, payload, moved) = ap.table.chan_recv(ep);
    Some((st as u32, payload, moved))
}

/// M14.2: the SCHEDULER-AWARE blocking receive -- the deferred M14 Step-2. Runs
/// the READ-gated non-blocking recv against `t`'s table; on an EMPTY-but-open
/// inbox (`WouldBlock`) it registers the CURRENT task as the channel's waiter and
/// DESCHEDULES it OFF the M9 run queue ([`block_current_and_yield`]), to be made
/// RUNNABLE again by a sender's [`sched_wake_task`] (fired from the `M_CHAN_SEND`
/// arm). Returns `(status, inline payload, moved-handle)` once a message arrives
/// (or a non-`WouldBlock` terminal status like `PeerClosed`/`BadCap`); `None` if
/// `t` is not an agent or `ep` is not a channel endpoint.
///
/// LOST-WAKEUP-FREE protocol (the seL4 single-core argument): the ENTIRE wait
/// loop runs under [`arch::local_irq_save`]-masked interrupts, so {empty-recheck
/// -> register waiter -> mark BLOCKED -> yield} is ONE indivisible critical
/// section. On a single core a sender cannot run until THIS task yields, and the
/// waiter is registered BEFORE the yield, so no send can interleave between the
/// empty-check and the block -> no wakeup is ever lost. The `while`-loop
/// re-checks the inbox after every wake, so a spurious wakeup just re-parks.
/// Preserves M14 semantics for non-blocking callers: this is an ADDITIVE mode,
/// not a replacement for [`agent_chan_recv_full`]'s synchronous `WouldBlock`.
pub fn agent_chan_recv_blocking(t: Task, ep: caps::Handle) -> Option<(u32, u64, u64)> {
    let slot = t.raw();
    if slot >= MAX_TASKS {
        return None;
    }
    // Resolve the channel ONCE up front (the endpoint identity is stable for the
    // whole session). `None` if `ep` is not a live channel endpoint -> BadCap to
    // the caller WITHOUT ever masking interrupts.
    let (chan, side) = {
        let ap = AGENTS.slot(slot).as_mut()?;
        ap.table.chan_of(ep)?
    };
    // The wait loop is one masked critical section (lost-wakeup-free).
    let guard = arch::local_irq_save();
    let result = loop {
        // Non-blocking recv against `t`'s OWN table. The AGENTS borrow is dropped
        // at the end of THIS block, so no table/ring borrow is held across the
        // yield below (the registry's single-`&mut`-at-a-time discipline).
        let r = {
            match AGENTS.slot(slot).as_mut() {
                Some(ap) => ap.table.chan_recv(ep),
                None => break (caps::SysStatus::BadCap, 0u64, 0u64),
            }
        };
        if r.0 != caps::SysStatus::WouldBlock {
            break r;
        }
        // EMPTY inbox: register THIS task as the waiter on its inbox ring
        // (`1 - side`) and deschedule. The sender on the peer side pushes that
        // SAME physical ring and wakes `waiter[1 - side]`, so they rendezvous.
        // Both steps run under the same interrupt mask (no send can interleave).
        chan.set_waiter((1 - side) as usize, current_task().raw() as u32);
        block_current_and_yield();
        // ... resumes HERE once a sender has made us RUNNABLE and the armed M9
        // timer switched back to us; the loop re-checks the inbox under the mask.
    };
    arch::local_irq_restore(guard);
    Some((result.0 as u32, result.1, result.2))
}

/// M14: run an arbitrary numbered, capability-checked [`caps::dispatch`] against
/// `t`'s OWN table with an explicit `handle` + two inline args -- the kernel-side
/// door the self-test uses to NARROW / INSPECT a cap inside an agent's table (the
/// same chokepoint user code reaches). Returns `(status, value)`.
pub fn agent_cap_dispatch(
    t: Task,
    method: u32,
    handle: caps::Handle,
    a0: u64,
    a1: u64,
) -> Option<(u32, u64)> {
    let slot = t.raw();
    if slot >= MAX_TASKS {
        return None;
    }
    let ap = AGENTS.slot(slot).as_mut()?;
    let args = caps::SyscallArgs {
        method,
        handle,
        args: [a0, a1, 0, 0],
    };
    let ret = caps::dispatch(&mut ap.table, &args);
    Some((ret.status as u32, ret.value))
}

/// M14 test helper: mint a fresh identity-only [`caps::ObjKind::Generic`] cap
/// with `rights` into `t`'s own table; returns its handle (`None` if `t` is not
/// an agent or its table is full). Lets the self-test fabricate a transferable
/// carried capability without a manifest grant.
pub fn agent_mint_generic(t: Task, rights: caps::Rights) -> Option<caps::Handle> {
    let slot = t.raw();
    if slot >= MAX_TASKS {
        return None;
    }
    let ap = AGENTS.slot(slot).as_mut()?;
    ap.table.mint(caps::ObjKind::Generic, rights)
}

/// M14 test helper: the raw rights bits attached to `handle` in `t`'s table, or
/// `None` if it does not resolve -- lets the self-test assert cross-agent
/// attenuation (a moved cap arrives with rights that are a SUBSET of the source).
pub fn agent_rights_of(t: Task, handle: caps::Handle) -> Option<u32> {
    let slot = t.raw();
    if slot >= MAX_TASKS {
        return None;
    }
    let ap = AGENTS.slot(slot).as_mut()?;
    ap.table.rights_of(handle).map(|r| r.bits())
}

/// M12 witness #1 (kernel-side, BEFORE the agent has run): `true` iff `task`'s
/// table resolves its born-with memory home (`Ok`, `ObjKind::MemoryHome`) AND
/// bootstrap channel (`Ok`, `ObjKind::Channel`) -- proving the agent is born
/// already holding them with ZERO setup syscalls.
pub fn agent_born_ok(task: Task) -> bool {
    let slot = task.raw();
    if slot >= MAX_TASKS {
        return false;
    }
    let ap = match AGENTS.slot(slot).as_mut() {
        Some(a) => a,
        None => return false,
    };
    let mh_h = ap.memory_home;
    let bs_h = ap.bootstrap;
    let mh = caps::dispatch(&mut ap.table, &caps::SyscallArgs::call(caps::M_OBJECT_INSPECT, mh_h));
    let bs = caps::dispatch(&mut ap.table, &caps::SyscallArgs::call(caps::M_OBJECT_INSPECT, bs_h));
    mh.status == caps::SysStatus::Ok
        && mh.value == caps::ObjKind::MemoryHome as u64
        && bs.status == caps::SysStatus::Ok
        && bs.value == caps::ObjKind::Channel as u64
}

/// M12 witness #2 (user-side): `true` iff `task`'s PERMITTED cap-checked syscall
/// returned `Ok` through the user boundary.
pub fn agent_permitted_ok(task: Task) -> bool {
    let slot = task.raw();
    slot < MAX_TASKS && AGENT_PERMITTED_OK[slot].load(Ordering::Acquire)
}

/// M12: `true` iff `task`'s NON-MANIFEST capability syscall returned `Denied`
/// (least privilege held through the user boundary).
pub fn agent_denied_ok(task: Task) -> bool {
    let slot = task.raw();
    slot < MAX_TASKS && AGENT_DENIED_OK[slot].load(Ordering::Acquire)
}

/// M12: the top-level page-table root PA of `task`'s address space (`0` if it is
/// not an agent). The kernel uses it to drive the parent-only-VA fault probe
/// under the agent's own root.
pub fn agent_root_pa(task: Task) -> u64 {
    let slot = task.raw();
    if slot >= MAX_TASKS {
        return 0;
    }
    AGENTS
        .slot(slot)
        .as_ref()
        .map(|a| a.space.root_pa())
        .unwrap_or(0)
}

// ===========================================================================
// M14.1: byte-payload IPC -- copy_to_user / copy_from_user bounce buffer
// ===========================================================================
//
// A message can carry a variable-length BYTE payload copied across two agents'
// isolated address spaces. The payload travels as a kernel-heap `Box<[u8]>`
// parked in the `ipc::Message` (one copy IN at send via `copy_from_user`, one
// copy OUT at recv via `copy_to_user`), reached ONLY through the kernel facades
// below (the M15 `agent_block_map` precedent -- an address-space-dependent op
// must ride the facade because `caps::dispatch` holds only `&mut HandleTable`,
// not the agent root). The two raw copy primitives' unsafe is confined to the
// per-arch `arch::*::uaccess` modules; these facades + `caps.rs` stay safe.

/// The dedicated, VACANT top-level window an agent maps its M14.1 byte-payload
/// scratch buffer into, clear of the agent's own code/stack (`AGENT_CODE_VA`,
/// `PML4[4]`) and shared blocks (`BLOCK_WINDOW_VA`, `PML4[5]`). x86_64 =
/// `PML4[6]`; a layout-lock const-assert pins the slot.
#[cfg(target_arch = "x86_64")]
pub const AGENT_BUF_VA: u64 = 0x0000_0300_0000_0000;
#[cfg(target_arch = "x86_64")]
const _: () = assert!((AGENT_BUF_VA >> 39) & 0x1FF == 6);

/// aarch64 = `L1[8]` (sibling of agent code `L1[6]` and block window `L1[7]`).
#[cfg(target_arch = "aarch64")]
pub const AGENT_BUF_VA: u64 = 0x0000_0002_0000_0000;
#[cfg(target_arch = "aarch64")]
const _: () = assert!((AGENT_BUF_VA >> 30) & 0x1FF == 8);

/// M14.1: map ONE fresh, writable 4 KiB USER scratch page into `t`'s OWN address
/// space at [`AGENT_BUF_VA`] (a vacant top-level slot), with `U/S`/`AP[1]` at
/// every level so the `copy_to_user`/`copy_from_user` walk reaches it. Returns
/// `(AGENT_BUF_VA, frame_pa)` -- the VA the copy primitives translate AND the
/// physical frame, so a kernel-side self-test can seed/verify the bytes through
/// the frame's identity alias and assert two agents' buffers have DISTINCT PAs.
/// `None` if `t` is not a live agent or on physical-frame OOM (the frame is
/// returned first, so a failed map leaks nothing).
pub fn agent_map_user_buffer(t: Task) -> Option<(u64, u64)> {
    let slot = t.raw();
    if slot >= MAX_TASKS {
        return None;
    }
    let root = {
        let ap = AGENTS.slot(slot).as_ref()?;
        ap.space.root_pa()
    };
    let pa = frame_alloc()?;
    if !arch::map_user_in_root(root, AGENT_BUF_VA, pa, true, false) {
        // Mapping OOM (intermediate-table frame): return the data frame so no
        // frame is leaked, then fail closed.
        let _ = frame_free(pa);
        return None;
    }
    Some((AGENT_BUF_VA, pa))
}

/// M14.1: drive a BYTE-PAYLOAD send against `t`'s OWN table -- resolve `t`'s
/// address-space root (the sender side of `copy_from_user`) and run
/// [`caps::HandleTable::chan_send_bytes`] (WRITE-gated, atomic, fail-closed).
/// `payload` is the inline scalar, `cap_h` the raw handle of an optional cap to
/// MOVE (`0` = none), `(src_uva, len)` the sender-space byte buffer. Returns
/// `(status, 0)` (a send has no scalar return), or `None` if `t` is not a live
/// agent.
pub fn agent_chan_send_bytes(
    t: Task,
    ep: caps::Handle,
    payload: u64,
    cap_h: u64,
    src_uva: u64,
    len: usize,
) -> Option<(u32, u64)> {
    let slot = t.raw();
    if slot >= MAX_TASKS {
        return None;
    }
    let ap = AGENTS.slot(slot).as_mut()?;
    let root = ap.space.root_pa();
    let st = ap.table.chan_send_bytes(ep, payload, cap_h, root, src_uva, len);
    Some((st as u32, 0))
}

/// M14.1: drive a BYTE-PAYLOAD recv against `t`'s OWN table -- resolve `t`'s
/// address-space root (the receiver side of `copy_to_user`) and run
/// [`caps::HandleTable::chan_recv_bytes`] (READ-gated, peek-before-pop,
/// push-front-restore on a copy fault). `(dst_uva, dst_cap)` is the
/// receiver-space destination buffer + its capacity. Returns `(status, inline
/// payload, moved-handle-raw, byte-len)`, or `None` if `t` is not a live agent.
pub fn agent_chan_recv_bytes(
    t: Task,
    ep: caps::Handle,
    dst_uva: u64,
    dst_cap: usize,
) -> Option<(u32, u64, u64, usize)> {
    let slot = t.raw();
    if slot >= MAX_TASKS {
        return None;
    }
    let ap = AGENTS.slot(slot).as_mut()?;
    let root = ap.space.root_pa();
    let (st, payload, moved, blen) = ap.table.chan_recv_bytes(ep, root, dst_uva, dst_cap);
    Some((st as u32, payload, moved, blen))
}

// ===========================================================================
// M15: shared memory blocks + session blackboard
// ===========================================================================
//
// A `blocks::Block` owns one or more pinned M6 frames and is reached as an
// `ObjKind::Block` capability through the M11 chokepoint. Sharing = mint an `Rc`
// clone Block handle into EACH member's table (`agent_block_create`) and map the
// SAME frames into each member's own root (`agent_block_map`) at `BLOCK_WINDOW_VA`
// -- so every member translates that VA to the SAME physical frame (true
// sharing). Permission is rights-derived at the chokepoint: `writable = want &&
// rights.contains(WRITE)`. The RECORD-plane CAS/read (the session blackboard's
// update-once-visible-everywhere) rides the M11 `dispatch` arms via
// `agent_block_dispatch`. The map path reuses M10 `map_in_space` -> ZERO new
// unsafe.
//
// M15.1 -- UNMAP + frame reclamation (`agent_block_unmap`): the OWNER (the cap
// granted REVOKE at create) tears down EVERY member's mapping (clear the leaf
// PTEs + a LOCAL TLB invalidate via the new arch `unmap_in_root`), POISONS the
// shared `blocks::Block` core (so every outstanding handle, in any agent's table,
// goes `Stale`), and only THEN returns the backing frames to the M6 allocator --
// so the frames become re-allocatable WITHOUT a stale PTE / use-after-free. The
// new arch unsafe (the leaf teardown + TLB invalidate, the read-only walk probe)
// lives ONLY in `arch::{x86_64,aarch64}::mmu` with a SAFETY comment; this facade
// and `caps.rs`/`blocks.rs` stay safe.

/// The dedicated, VACANT top-level window each agent maps its shared blocks into,
/// clear of the agent's own code/stack (`AGENT_CODE_VA`). x86_64 = `PML4[5]`
/// (sibling of the agent code slot `PML4[4]`); a layout-lock const-assert pins
/// the slot so a future change cannot silently collide with code/stack.
#[cfg(target_arch = "x86_64")]
pub const BLOCK_WINDOW_VA: u64 = 0x0000_0280_0000_0000;
#[cfg(target_arch = "x86_64")]
const _: () = assert!((BLOCK_WINDOW_VA >> 39) & 0x1FF == 5);

/// aarch64 = `L1[7]` (sibling of the agent code slot `L1[6]`).
#[cfg(target_arch = "aarch64")]
pub const BLOCK_WINDOW_VA: u64 = 0x0000_0001_C000_0000;
#[cfg(target_arch = "aarch64")]
const _: () = assert!((BLOCK_WINDOW_VA >> 30) & 0x1FF == 7);

/// M15: create ONE shared block of `n_pages` pinned M6 frames and mint an `Rc`
/// clone Block handle into EACH of agents `a` and `b` (the `agent_channel_connect`
/// precedent -- two SEPARATE `AGENTS.slot()` scopes so no two `&mut AgentProcess`
/// overlap). `a` is the OWNER: it gets READ|WRITE|TRANSFER|DUP plus REVOKE (the
/// M15.1 owner-only UNMAP/destroy authority -- see [`agent_block_unmap`]); `b` a
/// plain member (READ|WRITE, NO REVOKE, so it cannot unmap). Observers are
/// produced by NARROWing to drop WRITE. `None` on frame OOM (the block frees its
/// partial allocation first), a bad task, or a full table.
pub fn agent_block_create(a: Task, b: Task, n_pages: usize) -> Option<(caps::Handle, caps::Handle)> {
    let sa = a.raw();
    let sb = b.raw();
    if sa >= MAX_TASKS || sb >= MAX_TASKS || sa == sb {
        return None;
    }
    let blk = blocks::Block::create(n_pages)?;
    let full = caps::Rights::READ
        .union(caps::Rights::WRITE)
        .union(caps::Rights::TRANSFER)
        .union(caps::Rights::DUP)
        .union(caps::Rights::REVOKE);
    let member = caps::Rights::READ.union(caps::Rights::WRITE);
    let ha = {
        let ap_a = AGENTS.slot(sa).as_mut()?;
        ap_a.table.mint_block(full, blk.clone())?
    };
    let hb = {
        let ap_b = AGENTS.slot(sb).as_mut()?;
        ap_b.table.mint_block(member, blk)?
    };
    Some((ha, hb))
}

/// M15: ATTACH the block named by `h` into `t`'s OWN address space at `base_va`,
/// one [`map_in_space`] per frame. Re-enforces the SINGLE-SOURCED chokepoint
/// algebra (the dispatch path holds only `&mut HandleTable`, not the
/// `AddressSpace`, so the body must ride here -- the `agent_chan_recv_full`
/// precedent): the `required_right(M_BLOCK_MAP)==READ` gate, then `writable =
/// want_writable && rights.contains(WRITE)` (a READ-only handle requesting write
/// is downgraded to an RO mapping -- the literal `min(request, rights)`).
/// Returns `(status, base_va)`: `Ok` + `base_va`, or `BadCap`/`Stale` (resolve),
/// `Denied` (READ-less handle), `NoMem` (intermediate-table frame OOM). `None`
/// only if `t` is not an agent.
pub fn agent_block_map(
    t: Task,
    h: caps::Handle,
    want_writable: bool,
    base_va: u64,
) -> Option<(u32, u64)> {
    let slot = t.raw();
    if slot >= MAX_TASKS {
        return None;
    }
    let ap = AGENTS.slot(slot).as_mut()?;
    let (rights, blk) = match ap.table.block_of(h) {
        Ok(x) => x,
        Err(e) => return Some((e as u32, 0)),
    };
    if !rights.contains(caps::Rights::READ) {
        return Some((caps::SysStatus::Denied as u32, 0));
    }
    let writable = want_writable && rights.contains(caps::Rights::WRITE);
    let space = ap.space;
    let mut i = 0;
    while i < blk.n_pages() {
        let va = base_va + (i as u64) * 0x1000;
        if !map_in_space(space, va, blk.frames()[i], writable) {
            return Some((caps::SysStatus::NoMem as u32, 0));
        }
        i += 1;
    }
    blk.record_member(space.root_pa(), base_va, writable);
    Some((caps::SysStatus::Ok as u32, base_va))
}

/// M15: drive a numbered, capability-checked [`caps::dispatch`] against `t`'s OWN
/// table with an explicit `handle` + three inline args -- the RECORD-plane door
/// the self-test uses for `M_BLOCK_WRITE`/`M_BLOCK_READ` and the block-handle
/// NARROW (the `agent_cap_dispatch` precedent, widened to a third arg for the CAS
/// expected-version). Returns `(status, value)`.
pub fn agent_block_dispatch(
    t: Task,
    method: u32,
    handle: caps::Handle,
    a0: u64,
    a1: u64,
    a2: u64,
) -> Option<(u32, u64)> {
    let slot = t.raw();
    if slot >= MAX_TASKS {
        return None;
    }
    let ap = AGENTS.slot(slot).as_mut()?;
    let args = caps::SyscallArgs {
        method,
        handle,
        args: [a0, a1, a2, 0],
    };
    let ret = caps::dispatch(&mut ap.table, &args);
    Some((ret.status as u32, ret.value))
}

/// M15 test cross-check: the recorded `writable` flag of `t`'s most recent
/// mapping of block `h` at `base_va`, or `None` if it does not resolve. Lets the
/// self-test OBSERVE that a READ-only handle's write-requesting map was
/// downgraded to RO (`min(request, rights)` dropped WRITE) -- the PORTABLE
/// cross-check, since CR0.WP=0 makes the hardware RO-write-fault unobservable
/// kernel-side on x86_64.
pub fn agent_block_member_writable(t: Task, h: caps::Handle, base_va: u64) -> Option<bool> {
    let slot = t.raw();
    if slot >= MAX_TASKS {
        return None;
    }
    let ap = AGENTS.slot(slot).as_mut()?;
    let root_pa = ap.space.root_pa();
    let (_rights, blk) = ap.table.block_of(h).ok()?;
    blk.member_writable(root_pa, base_va)
}

/// M15.1: OWNER-only UNMAP of block `h` + frame reclamation -- the inverse of
/// [`agent_block_map`], the proof that block frames are no longer pinned for the
/// kernel-session lifetime. ADDRESS-SPACE-dependent, so (like map) it rides this
/// facade, not `dispatch`. Fail-closed and ATOMIC (single-core, interrupts
/// masked):
///   1. Resolve `h` (`BadCap`/`Stale`; `Stale` if the block was already unmapped).
///   2. Authorize: the handle must hold REVOKE (the owner/destroy authority); a
///      plain member or RO observer is `Denied`.
///   3. Tear down EVERY recorded member mapping in EVERY member root (clear each
///      leaf PTE via `arch::unmap_in_root` + a LOCAL TLB invalidate) -- after
///      this NO live VA translation reaches the frames.
///   4. POISON the shared core ([`blocks::Block::kill`]) -- after this every
///      outstanding handle in EVERY table resolves `Stale`, so NO live handle can
///      re-map or reach the frames (the cross-table revoke).
///   5. Reclaim the data frames to the M6 allocator (safe NOW: no live mapping or
///      handle remains).
///   6. Revoke the caller's OWN handle (per-slot generation bump) so it goes
///      `Stale` immediately (the M11 idiom; also blocks a double-unmap).
/// Returns `(status, n_pages_reclaimed)`; `None` only if `t` is not an agent.
pub fn agent_block_unmap(t: Task, h: caps::Handle) -> Option<(u32, u64)> {
    let slot = t.raw();
    if slot >= MAX_TASKS {
        return None;
    }
    let ap = AGENTS.slot(slot).as_mut()?;
    // (1) Resolve (fail-closed; a poisoned/dead core resolves `Stale`).
    let (rights, blk) = match ap.table.block_of(h) {
        Ok(x) => x,
        Err(e) => return Some((e as u32, 0)),
    };
    // (2) Owner gate: REVOKE is the destroy authority (only the create-time owner
    //     holds it; a plain member or RO observer -> Denied, fail-closed).
    if !rights.contains(caps::Rights::REVOKE) {
        return Some((caps::SysStatus::Denied as u32, 0));
    }
    let n = blk.n_pages();
    let members = blk.members_snapshot();
    // (3) Tear down every member mapping (all roots) + LOCAL TLB invalidate.
    let mut m = 0;
    while m < members.len() {
        let (root_pa, base_va, _w) = members[m];
        let mut i = 0;
        while i < n {
            let _ = arch::unmap_in_root(root_pa, base_va + (i as u64) * 0x1000);
            i += 1;
        }
        m += 1;
    }
    // (4) Poison the shared core: every outstanding handle now fails closed.
    blk.kill();
    // (5) Reclaim the data frames (only now -- nothing live can still reach them).
    let frames_len = blk.frames().len();
    let mut f = 0;
    while f < frames_len {
        let _ = frame_free(blk.frames()[f]);
        f += 1;
    }
    // (6) Revoke the caller's own handle (per-slot generation bump -> Stale).
    let _ = ap.table.revoke(h);
    Some((caps::SysStatus::Ok as u32, n as u64))
}

/// M15.1 test helper: the PHYSICAL address of data-frame `idx` of block `h` in
/// `t`'s table, or `None` if `h` does not resolve (incl. a reclaimed block) or
/// `idx` is out of range. Lets the self-test NAME the exact frame it expects the
/// M6 allocator to hand back out after the block is unmapped.
pub fn agent_block_frame_pa(t: Task, h: caps::Handle, idx: usize) -> Option<u64> {
    let slot = t.raw();
    if slot >= MAX_TASKS {
        return None;
    }
    let ap = AGENTS.slot(slot).as_ref()?;
    let (_rights, blk) = ap.table.block_of(h).ok()?;
    blk.frames().get(idx).copied()
}

/// M15.1 test helper: the PHYSICAL frame that `va` maps to in `t`'s OWN root, or
/// `None` if `va` is unmapped there. A PURE software page-table walk (it never
/// dereferences `va`), so the self-test can PROVE that an unmapped block VA no
/// longer resolves to the reclaimed frame WITHOUT taking a page fault.
pub fn agent_block_va_maps(t: Task, va: u64) -> Option<u64> {
    let slot = t.raw();
    if slot >= MAX_TASKS {
        return None;
    }
    let root = AGENTS.slot(slot).as_ref()?.space.root_pa();
    arch::va_to_pa_in_root(root, va)
}

/// M16: OPEN a model inference session -- kernel-mediated (NOT a dispatch method:
/// it needs the [`infer`] router, which `dispatch` can't reach holding only `&mut
/// HandleTable`; the `agent_channel_connect`/`agent_block_create` precedent).
/// Resolves the `model:` scheme, then mints an [`caps::ObjKind::ModelSession`]
/// bound to the registered backend WITH `INVOKE_MODEL | READ` into `t`'s OWN
/// table. An unknown / non-`model:` scheme resolves to no backend -> a clean
/// [`caps::SysStatus::BadCap`] (NEVER a panic). Returns `(status, session_raw)`;
/// `None` only if `t` is not an agent.
///
/// Least-privilege NOTE: the manifest does not grant `INVOKE_MODEL`; the right
/// is granted HERE by the facade (the kernel-mediated grant), so the gate is
/// proven still to bite by NARROWing the session to drop it (-> `Denied`).
pub fn agent_model_open(t: Task, scheme: &str) -> Option<(u32, u64)> {
    let slot = t.raw();
    if slot >= MAX_TASKS {
        return None;
    }
    let (model, backend) = match infer::resolve(scheme) {
        Some(x) => x,
        None => return Some((caps::SysStatus::BadCap as u32, 0)),
    };
    let rights = caps::Rights::INVOKE_MODEL.union(caps::Rights::READ);
    let ap = AGENTS.slot(slot).as_mut()?;
    match ap
        .table
        .mint_model_session(rights, infer::ModelSession { backend, model })
    {
        Some(h) => Some((caps::SysStatus::Ok as u32, h.raw())),
        None => Some((caps::SysStatus::ObjFull as u32, 0)),
    }
}

/// M16: drive a numbered, capability-checked [`caps::dispatch`] against `t`'s OWN
/// table (the `agent_block_dispatch` clone) -- the self-test door for
/// `M_MODEL_INVOKE` plus the session-handle NARROW. Every call routes the M11
/// chokepoint (the `INVOKE_MODEL` gate, the closed method set). Returns
/// `(status, value)`; `None` only if `t` is not an agent.
pub fn agent_model_dispatch(
    t: Task,
    method: u32,
    handle: caps::Handle,
    a0: u64,
) -> Option<(u32, u64)> {
    let slot = t.raw();
    if slot >= MAX_TASKS {
        return None;
    }
    let ap = AGENTS.slot(slot).as_mut()?;
    let args = caps::SyscallArgs {
        method,
        handle,
        args: [a0, 0, 0, 0],
    };
    let ret = caps::dispatch(&mut ap.table, &args);
    Some((ret.status as u32, ret.value))
}

// ===========================================================================
// M18: frozen-kernel self-improvement harness (held-out evaluator + skill tier)
// ===========================================================================
//
// An agent extends its OWN T4 skill library under a FROZEN-KERNEL /
// EVOLVING-USERSPACE split. The held-out evaluator + test set live in a
// kernel-owned `eval_tbl`/`eval_home` NEVER minted into any agent's table, so the
// improving agent provably cannot READ the held-out set nor WRITE the evaluator:
// the whole guarantee REDUCES TO the M11 rights-mask invariant. ZERO new unsafe
// (these facades are safe code over the existing blessed `AGENTS` registry); NO
// new ABI method (skill writes ride the existing `M_MEM_WRITE_PROC=18` arm; the
// harness is a kernel facade, not method-numbered, so an agent cannot invoke it).

/// M18: the GOOD candidate body == the held-out evaluator's SECRET target, so it
/// generalizes and scores a perfect held-out result. (The self-test, being
/// kernel-side, hands the improver this matching body to witness admission; a
/// real searching agent does not know it.)
pub const HARNESS_GOOD_BODY: u64 = 0x0000_600D_5C11_0001;
/// M18: an OVERFITTING candidate body that games a visible slice but MISSES the
/// held-out set -- it never strictly improves the held-out score, so it is
/// rejected (the Goodhart-stop).
pub const HARNESS_BAD_BODY: u64 = 0x0000_BAD0_5C11_0002;
/// M18: deterministic base offset for the harness's held-out inputs.
const EVAL_BASE: u64 = 0x0000_0000_00E5_7000;
/// M18: held-out test-set size (the EXCEL-rung regression suite cardinality).
const EVAL_N: u64 = 6;

/// M18: PROPOSE a candidate skill into `task`'s OWN T4 procedural store through
/// the M11 chokepoint (`M_MEM_WRITE_PROC=18`, `WRITE_PROCEDURAL`-gated). The
/// `WRITE_PROCEDURAL` skill-home is a SEPARATE object minted KERNEL-MEDIATED on
/// first use (the `agent_model_open` INVOKE_MODEL-grant precedent) -- NEVER the
/// born-with episodic home (which stays `READ|WRITE|RECALL`, so an ordinary skill
/// write is `Denied`). `op` rides the `write_proc` op-selector (0=ADD_SKILL ...).
/// Returns `(status, value)`; `None` if `task` is not a live agent.
pub fn agent_skill_propose(task: Task, op: u64, a: u64, b: u64, c: u64) -> Option<(u32, u64)> {
    let slot = task.raw();
    if slot >= MAX_TASKS {
        return None;
    }
    let ap = AGENTS.slot(slot).as_mut()?;
    if ap.skill_home == caps::Handle::NULL {
        // Kernel-mediated grant: a DISTINCT skill-home carrying WRITE_PROCEDURAL
        // (the manifest never declares it -- the agent_model_open precedent).
        let wp = caps::Rights::READ
            .union(caps::Rights::WRITE)
            .union(caps::Rights::RECALL)
            .union(caps::Rights::WRITE_PROCEDURAL);
        match ap.table.mint_memory_home(wp) {
            Some(h) => ap.skill_home = h,
            None => return Some((caps::SysStatus::ObjFull as u32, 0)),
        }
    }
    let args = caps::SyscallArgs {
        method: caps::M_MEM_WRITE_PROC,
        handle: ap.skill_home,
        args: [op, a, b, c],
    };
    let ret = caps::dispatch(&mut ap.table, &args);
    Some((ret.status as u32, ret.value))
}

/// M18: the kernel-owned EVOLVE harness for `task`'s PROPOSED skill `skill_id`
/// (NOT a dispatch method -- it builds the kernel-owned FROZEN evaluator the agent
/// holds no handle to; the `agent_model_open` kernel-mediated precedent). Builds a
/// throwaway `eval_tbl`/`eval_home`, seeds the held-out set from the secret target
/// ([`HARNESS_GOOD_BODY`]), scores the candidate via the frozen evaluator, and
/// admits PROPOSED->ADMITTED ONLY on strict improvement (the EXCEL rung). The
/// `eval_home` handle is NEVER returned or accepted, so the frozen boundary ==
/// the M11 rights-mask invariant. Returns `(status, admitted)`; `None` if `task`
/// is not a live agent.
pub fn agent_evolve_request(task: Task, skill_id: u64) -> Option<(u32, bool)> {
    let slot = task.raw();
    if slot >= MAX_TASKS {
        return None;
    }
    // The FROZEN evaluator domain: kernel-owned, never minted into ANY agent table.
    let mut eval_tbl = caps::HandleTable::with_capacity(4);
    let eval_home = eval_tbl.mint_memory_home(
        caps::Rights::READ
            .union(caps::Rights::WRITE)
            .union(caps::Rights::RECALL),
    )?;
    eval_tbl.eval_seed_heldout(eval_home, HARNESS_GOOD_BODY, EVAL_BASE, EVAL_N);
    let ap = AGENTS.slot(slot).as_mut()?;
    if ap.skill_home == caps::Handle::NULL {
        return Some((caps::SysStatus::BadCap as u32, false));
    }
    let (admitted, _score) = ap
        .table
        .harness_admit(ap.skill_home, skill_id, &eval_tbl, eval_home);
    // eval_tbl / eval_home drop HERE -- the frozen domain never leaves the kernel.
    Some((caps::SysStatus::Ok as u32, admitted))
}

// ===========================================================================
// L2.0: VMX-root self-test facade (the L2 sovereignty track).
//
// The first rung of `tb-core`, the from-scratch Type-1 microhypervisor: a SAFE
// entry point the `#![forbid(unsafe_code)]` kernel calls to drive the silicon-
// unsafe VMX bring-up confined to `arch/x86_64/vmx/`. On x86_64 it does the full
// VMXON -> minimal VMCS -> EPT identity map -> 1-`CPUID` long-mode nested guest
// -> world-switch -> caught VM-exit -> VMXOFF proof (or skips gracefully when VMX
// is not exposed, the TCG `qemu64` case). On aarch64 (no VMX) it is N/A: the EL2
// world-switch is a LATER L2 sub-milestone. Mirrors the `mmu_selftest`/`user_demo`
// pattern — all unsafe stays in tb-hal/arch, the kernel only branches on a value.
// ===========================================================================

/// L2.0 VMX-root self-test outcome (returned to the kernel for marker rendering).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmxProof {
    /// This arch has no VMX (aarch64): the EL2 path is a later sub-milestone.
    NotApplicable,
    /// VMX is not exposed or the BIOS locked VT-x off — graceful skip (no VMX
    /// instruction was executed). The TCG `qemu64` case; mirrors the `vmm-boot`
    /// `KVM_OK` allow-skip.
    Unavailable,
    /// VMXON itself failed (VMfail) — VMX advertised but the substrate could not
    /// enter VMX operation (e.g. incomplete emulation under `-cpu max` TCG).
    VmxonFailed,
    /// VMXON succeeded but VM-entry failed; `vm_error` is the VMCS
    /// VM-instruction-error (0 if even VMPTRLD failed before launch).
    EntryFailed {
        /// The VMCS VM-instruction-error code (Intel SDM Vol 3C §30.4).
        vm_error: u64,
    },
    /// THE PROOF: the world switch ran and the nested guest's VM-exit was caught;
    /// `exit_reason` is the basic exit reason (10 = CPUID, the expected value).
    Proven {
        /// The basic VM-exit reason (VMCS field 0x4402, bits 15:0).
        exit_reason: u32,
    },
}

/// L2.0: run the VMX-root + nested-guest + caught-VM-exit self-test (x86_64), or
/// report [`VmxProof::NotApplicable`] on aarch64. See [`VmxProof`].
#[cfg(target_arch = "x86_64")]
pub fn vmx_selftest() -> VmxProof {
    arch::vmx_selftest()
}

/// L2.0: aarch64 has no VMX — the EL2 world-switch is the aarch64 realization of
/// this rung (see [`el2_selftest`]), so this reports [`VmxProof::NotApplicable`]
/// (the kernel prints the n/a marker).
#[cfg(target_arch = "aarch64")]
pub fn vmx_selftest() -> VmxProof {
    VmxProof::NotApplicable
}

// ===========================================================================
// L2.0: EL2 (nVHE) world-switch self-test facade (the aarch64 L2 sovereignty
// track — the ARM realization of the x86 VMX-root rung).
//
// The aarch64 proof that TABOS *is* the hypervisor: booted at EL2 (QEMU
// `virt,virtualization=on`), installed a resident nVHE EL2 monitor, dropped to
// EL1 to run M0..M18 unchanged, then at this slot does a real EL1<->EL2
// world-switch — a bootstrap `HVC #0` from the running EL1 kernel ERETs into a
// tiny EL1 guest stub, whose `HVC #1` traps back to EL2 and is caught. ALL the
// silicon-unsafe/asm is confined to tb-hal's `arch/aarch64/{boot,el2,el2_vectors}.rs`,
// so the framekernel invariant SURVIVES: this crate stays unsafe-free and the
// kernel only branches on the returned `El2Proof`. Unlike L2.0 vmxroot (which
// only SKIPS under TCG), this proof actually EXECUTES under pure TCG. On x86_64
// (no EL2) it is N/A — exactly mirroring the `VmxProof`/`vmx_selftest` block.
// ===========================================================================

/// L2.0 EL2 world-switch self-test outcome (returned to the kernel for marker
/// rendering). Mirrors [`VmxProof`] one EL up: the proof is a closed
/// ERET->guest->HVC->EL2 round-trip rather than a VMLAUNCH/VM-exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum El2Proof {
    /// This arch has no EL2 hypervisor level (x86_64): VMX-root is its rung.
    NotApplicable,
    /// We did NOT boot at EL2 (plain QEMU `virt`, no `virtualization=on`): no
    /// resident monitor exists, so no HVC is issued — a graceful green skip
    /// (mirrors [`VmxProof::Unavailable`], no privileged instruction executed).
    Unavailable,
    /// We booted at EL2 and issued the bootstrap HVC, but the monitor reported a
    /// fault instead of a clean round-trip; `code` is the nonzero diagnostic
    /// (booted-EL2 but failed — surfaced honestly as a red marker).
    RoundTripFailed {
        /// The nonzero failure code the EL2 monitor returned in x0.
        code: u64,
    },
    /// THE PROOF: the EL1->EL2->EL1-guest->EL2->EL1 world-switch ran and the
    /// guest's HVC was caught with its magic verified; `hvc_imm` is the guest's
    /// trap-back immediate (1, the expected value).
    Proven {
        /// The guest HVC immediate that closed the round-trip (1 == `hvc #1`).
        hvc_imm: u64,
    },
}

/// L2.0: run the EL2 (nVHE) world-switch self-test (aarch64), or report
/// [`El2Proof::NotApplicable`] on x86_64. See [`El2Proof`].
#[cfg(target_arch = "aarch64")]
pub fn el2_selftest() -> El2Proof {
    arch::el2_selftest()
}

/// L2.0: x86_64 has no EL2 — the VMX-root world-switch (see [`vmx_selftest`]) is
/// this arch's realization of the rung, so this reports
/// [`El2Proof::NotApplicable`] (the kernel prints the n/a marker).
#[cfg(target_arch = "x86_64")]
pub fn el2_selftest() -> El2Proof {
    El2Proof::NotApplicable
}

// ===========================================================================
// M19: poll-based virtio-mmio virtio-rng self-test facade — the kernel's FIRST
// real device I/O.
//
// A single, NON-cfg-gated facade ([`virtio_selftest`]) over an `arch` arm that
// exists on BOTH architectures (mirroring `mmu_selftest`/`timer_demo`, NOT the
// cfg-split `vmx_selftest`/`el2_selftest` pair — virtio-mmio is identical on
// x86_64 `microvm` and aarch64 `virt`). Each arm drives a MODERN (Version=2)
// virtio-rng (DeviceID 4) over ONE virtqueue: a hard-coded slot scan, the
// reset->ACK->DRIVER->features->FEATURES_OK->queue->DRIVER_OK handshake, one
// WRITE-ONLY descriptor pointing at an entropy buffer in a single identity-
// mapped DMA frame, a poll-only (`VIRTQ_AVAIL_F_NO_INTERRUPT`) used-ring
// completion, and a fail-closed iteration cap so a dead device bails to
// [`VirtioProof::Failed`] instead of hanging. ALL the MMIO/DMA/asm unsafe is
// confined to `arch/{x86_64,aarch64}/virtio.rs` (the UC device-window map +
// `dmb`/`dsb` barriers live there too); this crate stays unsafe-free and the
// `#![forbid(unsafe_code)]` kernel only branches on the returned `VirtioProof`.
// Absent (no DeviceID==4 in any slot) is a GRACEFUL GREEN skip — so a runner
// with no virtio-rng backend (e.g. `tb-vmm` with no `-device`, where the scan
// reads open-bus `0xFFFF_FFFF` != magic) stays green with no backend added.
// ===========================================================================

/// M19 virtio-rng self-test outcome (returned to the kernel for marker
/// rendering). A closed, pure-data verdict the `#![forbid(unsafe_code)]` kernel
/// matches on — mirroring [`VmxProof`]/[`El2Proof`] but arch-neutral.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioProof {
    /// No virtio-rng (DeviceID 4) in any scanned slot — a GRACEFUL GREEN skip.
    /// The `tb-vmm`-with-no-`-device` case (open-bus read != magic) and any
    /// QEMU run that omits `-device virtio-rng-device`.
    Absent,
    /// A virtio-rng was found but it is LEGACY (`Version` != 2) — an honest skip
    /// (this driver speaks only the modern transport); still GREEN.
    LegacyUnsupported,
    /// THE PROOF: the full modern handshake + one write-only descriptor + a
    /// polled used-ring completion ran, and the entropy buffer came back
    /// non-trivially filled. `slot` is the bus slot index, `device_id` == 4,
    /// `len` is the device-reported `used.ring[0].len` (bytes written).
    Proven {
        /// The virtio-mmio slot index the entropy device was found at.
        slot: u32,
        /// The probed DeviceID (4 == entropy/rng; the expected value).
        device_id: u32,
        /// The device-reported number of entropy bytes written (`> 0`).
        len: u32,
    },
    /// Found + driven, but the round-trip failed fail-closed (handshake
    /// rejected, FEATURES_OK cleared, queue unready, or `used.idx` never
    /// advanced before the cap). `stage` localises the failure; the kernel
    /// renders it WITHOUT a "virtio OK" substring, so the run-script grep is red.
    Failed {
        /// The pipeline stage that failed (1 map .. 6 completion-validate).
        stage: u32,
    },
}

/// M19: run the poll-based virtio-rng round-trip self-test (both arches) and
/// report the outcome. See [`VirtioProof`]. Brings up no interrupt controller
/// (poll-only) and touches NO scheduler; all raw work is in `arch::*::virtio`.
pub fn virtio_selftest() -> VirtioProof {
    arch::virtio_selftest()
}
