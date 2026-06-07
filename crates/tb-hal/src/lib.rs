//! `tb-hal` — TABOS Hardware Abstraction Layer (M0 serial + M1 traps + M2
//! tasks + M3 MMU).
//!
//! This crate is the single place where `unsafe` and assembly are allowed in
//! TABOS (framekernel rule, KERNEL-FOUNDATION-SPEC.md §1). The raw pokes live in
//! the per-arch submodules under `arch/`; THIS file is a thin, mostly-safe
//! facade exposing the symbols the `kernel` crate is allowed to call:
//!
//! M0 serial + park:
//!   * [`serial_init`], [`serial_write_byte`], [`serial_write_str`], [`halt`]
//!
//! M1 traps:
//!   * [`install_traps`]  — load the permanent GDT+TSS+IDT (x86_64) / set
//!     `VBAR_EL1` (aarch64). Idempotent, called once from `rust_main`.
//!   * [`breakpoint`]     — execute a software breakpoint (`int3` / `brk #0`).
//!   * [`set_trap_hook`]  — register the safe dispatch policy hook.
//!   * [`TrapInfo`] / [`TrapKind`] / [`TrapAction`] — the safe trap-dispatch ABI.
//!
//! M2 cooperative tasks:
//!   * [`Task`], [`task_create`], [`yield_to`] — voluntary (cooperative)
//!     context switch between kernel tasks. Only the ABI callee-saved
//!     registers plus the stack pointer are switched; the saved SP is the
//!     ENTIRE per-task context handle (verified ABI facts in the M2 section
//!     below).
//!   * [`TaskStack`] — one-shot-takeable static stack cell, so the
//!     `#![forbid(unsafe_code)]` kernel crate can OWN its static stack arrays
//!     (tb-hal allocates nothing) and still mint the unique `&'static mut`
//!     that [`task_create`] requires.
//!   * [`current_task`] — handle of the task executing right now (slot 0 is
//!     the bootstrap context that entered `rust_main`).
//!
//! M3 MMU (this milestone):
//!   * [`mmu_init`]     — x86_64: program `EFER.NXE` over the already-live A0
//!     boot paging; aarch64: bring the MMU up FROM COLD — identity translation
//!     tables + `MAIR_EL1`/`TCR_EL1`/`TTBR0_EL1`, `isb`, then
//!     `SCTLR_EL1.{M,C,I}`, `isb`. Called once from `rust_main`, AFTER
//!     [`install_traps`].
//!   * [`mmu_selftest`] — the whole 4 KiB map → write → verify → remap →
//!     re-verify test lives INSIDE tb-hal (x86: PTE rewrite + `invlpg`;
//!     aarch64: full Break-Before-Make + `tlbi`); the kernel crate only sees
//!     the returned `bool`. The typed table layer both backends share is
//!     `mmu.rs` (`PageTable512` + entry/index math); raw derefs stay per-arch.
//!
//! POLICY lives in safe Rust: tb-hal's per-arch assembly marshals a raw
//! `TrapFrame`, an `extern "C"` handler in tb-hal (the ONLY place that derefs
//! the raw frame, `unsafe`) builds a safe [`TrapInfo`] and calls the registered
//! hook via [`dispatch_trap`]. The default hook returns [`TrapAction::Halt`].

#![no_std]
#![deny(missing_docs)]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

mod arch;
mod mmu; // M3: shared typed page-table layer (PageTable512/Frame4K + entry math).

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
/// Pure safe Rust: this is just a loop over [`serial_write_byte`]; it performs
/// no `unsafe` itself.
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
/// * x86_64: build and load a PERMANENT flat 64-bit GDT (null, ring0 code,
///   ring0 data, 64-bit TSS), reload `CS`/data segments, `ltr` the TSS, then
///   load a 256-entry IDT of 64-bit interrupt gates. `#DF`/NMI/`#MC` are routed
///   through TSS IST stacks.
/// * aarch64: point `VBAR_EL1` at the 2 KiB-aligned, 16×128-byte vector table.
///
/// Idempotent: safe to call more than once (each call rebuilds the descriptor
/// tables from scratch). Call once early from `rust_main`, before [`breakpoint`].
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
/// `extern "C"` handler from the raw cause (vector + error code on x86_64,
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
/// reinterpreted as `usize`. `0` means "no hook registered → use the default
/// halt policy". `AtomicUsize` because tb-hal is `no_std` with no locks; the
/// pointer is written once at boot and read on every trap.
static TRAP_HOOK: AtomicUsize = AtomicUsize::new(0);

/// The default policy when no hook has been registered: always halt.
fn default_trap_hook(_info: &TrapInfo) -> TrapAction {
    TrapAction::Halt
}

/// Register the safe trap-dispatch policy hook.
///
/// The hook is a plain function pointer `fn(&TrapInfo) -> TrapAction`; it lives
/// in safe Rust (e.g. the kernel crate under `#![forbid(unsafe_code)]`) and
/// decides per-trap whether to [`TrapAction::Resume`] or [`TrapAction::Halt`].
pub fn set_trap_hook(hook: fn(&TrapInfo) -> TrapAction) {
    TRAP_HOOK.store(hook as usize, Ordering::Release);
}

/// Dispatch a trap to the registered hook (or the default halt policy).
///
/// Called by each per-arch `extern "C"` handler with a [`TrapInfo`] it built
/// from the raw frame. This is the safe boundary between the raw-frame deref
/// (per-arch, `unsafe`) and the policy hook (safe).
pub(crate) fn dispatch_trap(info: &TrapInfo) -> TrapAction {
    let raw = TRAP_HOOK.load(Ordering::Acquire);
    if raw == 0 {
        return default_trap_hook(info);
    }
    // SAFETY: `raw` is non-zero here, so it was produced by `set_trap_hook`
    // from a valid `fn(&TrapInfo) -> TrapAction` via `hook as usize`. A function
    // pointer and `usize` are both pointer-sized; this transmute is the exact
    // inverse of that cast.
    let hook: fn(&TrapInfo) -> TrapAction =
        unsafe { core::mem::transmute::<usize, fn(&TrapInfo) -> TrapAction>(raw) };
    hook(info)
}

// ===========================================================================
// M2: cooperative tasks + context switch
// ===========================================================================
//
// Saved-context model (callee-saved-on-stack, the classic cooperative switch):
// `yield_to` saves ONLY the callee-saved registers of the outgoing task onto
// the outgoing task's own stack and records the resulting stack pointer in
// that task's slot; resuming a task is "load its saved SP, pop the
// callee-saved set, return". A single `usize` (the saved SP) is therefore the
// whole per-task context. Caller-saved registers need no saving: `yield_to`
// is an ordinary function call, so the compiler already treats them as dead
// across it.
//
// Verified ABI facts (sources re-checked for M2 — do NOT change the register
// sets or frame layouts without re-reading them):
//  * x86-64 System V psABI (AMD64 ABI 1.0 draft, 2025-03-12, §3.2.1 + Fig 3.4
//    "Register Usage"): "Registers %rbp, %rbx and %r12 through %r15 'belong'
//    to the calling function and the called function is required to preserve
//    their values" → callee-saved GPRs = {rbx, rbp, r12, r13, r14, r15}
//    (+ rsp itself). §3.2.2 "The Stack Frame": at function entry "the value of
//    (%rsp + 8) is a multiple of 16", i.e. RSP % 16 == 8 right after `call`.
//  * AAPCS64 (ARM-software/abi-aa, aapcs64.rst, 2025Q4, §6.1.1 "General-purpose
//    registers"): "r19…r28 | Callee-saved registers" and "Registers r19-r29
//    and SP are Callee-saved"; r29 = FP, r30 = LR (the resume address rides in
//    LR; `ret` branches to it). §6.4.5.1 "Universal stack constraints":
//    "SP mod 16 = 0. The stack must be quad-word aligned."
//  * Initial-frame fabrication technique: OSDev wiki, "Brendan's Multi-tasking
//    Tutorial" (Step 1/2): "put values on the new kernel stack to match the
//    values that your switch_to_task(task) function expects to pop off the
//    stack after switching to the task" — i.e. a fake callee-saved frame whose
//    return address / LR is the task's entry, so the FIRST switch into the
//    task "returns" into `entry`.
//
// No FP/SIMD state is switched: both TABOS targets are soft-float target
// specs, so v8-v15 (AAPCS64) and the SSE/x87 state (psABI) cannot hold live
// values across the switch.

/// Number of task slots tb-hal tracks, INCLUDING slot 0, which is permanently
/// reserved for the bootstrap context (the stack `_start` set up and
/// `rust_main` runs on). M2 needs three (bootstrap + the two ping-pong tasks);
/// eight leaves headroom without needing a heap.
const MAX_TASKS: usize = 8;

/// Per-slot saved stack pointer — the WHOLE saved context of a suspended task
/// under the callee-saved-on-stack model. `0` means "no saved context" (slot
/// never created, or its task is currently running so its slot is stale).
/// `AtomicUsize` because tb-hal is `no_std` with no locks; M2 is single-core
/// cooperative, so the atomics are for safe interior mutability, not racing.
static TASK_SP: [AtomicUsize; MAX_TASKS] = [const { AtomicUsize::new(0) }; MAX_TASKS];

/// Slot index of the task currently executing on this (single) core.
/// `yield_to` updates it right before the raw switch, so a task that is
/// resumed always observes itself as current.
static CURRENT_TASK: AtomicUsize = AtomicUsize::new(0);

/// Next free slot in [`TASK_SP`]; slot 0 is the bootstrap context.
static NEXT_TASK_SLOT: AtomicUsize = AtomicUsize::new(1);

/// Smallest stack [`task_create`] accepts, in `usize` words. The fabricated
/// initial frame needs at most 13 words (aarch64: 12-register stp/ldp frame +
/// 16-byte re-alignment of the top); 64 words also gives the entry a little
/// room before it overflows. Real guard pages arrive with the MMU milestone.
const MIN_STACK_WORDS: usize = 64;

/// An opaque handle to a cooperative kernel task: the slot index into
/// tb-hal's internal saved-SP table. `Copy` so it can be passed around freely;
/// convertible to/from a raw `usize` (see [`Task::raw`]) so the
/// `forbid(unsafe_code)` kernel can stash handles in `AtomicUsize` statics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Task(usize);

impl Task {
    /// The raw slot index of this handle, for stashing in an `AtomicUsize`
    /// (cross-task handle passing in safe kernel code goes through statics).
    pub fn raw(self) -> usize {
        self.0
    }

    /// Rebuild a handle from a value previously obtained via [`Task::raw`].
    ///
    /// Safe: a fabricated/invalid index cannot cause memory unsafety — it is
    /// rejected fail-closed by [`yield_to`] (bounds check + "has this slot a
    /// saved context" check), which reports over serial and halts.
    pub fn from_raw(raw: usize) -> Self {
        Task(raw)
    }
}

/// Handle of the task currently executing (slot 0 — the bootstrap context —
/// until the first [`yield_to`] after [`task_create`]).
pub fn current_task() -> Task {
    Task(CURRENT_TASK.load(Ordering::Relaxed))
}

/// Fail-closed termination for misuse of the M2 task API: report the reason
/// over serial (best-effort) and park the core. Never returns.
fn task_api_fatal(msg: &str) -> ! {
    serial_write_str("tb-hal: task: ");
    serial_write_str(msg);
    serial_write_byte(b'\n');
    halt()
}

/// Create a cooperative task that will start executing `entry` the first time
/// somebody [`yield_to`]s it.
///
/// `stack` is caller-provided `'static` memory (the kernel owns its static
/// stack arrays — see [`TaskStack`]; tb-hal does NOT allocate). The arch
/// backend fabricates the INITIAL context frame at the 16-byte-aligned-down
/// top of `stack` — a fake callee-saved frame whose return address (x86_64) /
/// LR slot (aarch64) is `entry` and whose other slots are zero — so the first
/// switch into the task "returns" into `entry` with an ABI-conformant stack
/// (x86_64: RSP % 16 == 8 as after `call`, psABI §3.2.2; aarch64:
/// SP % 16 == 0, AAPCS64 §6.4.5.1).
///
/// `entry` must never return: there is no caller frame beneath it. End it in
/// `halt()` or park it by never yielding back. Fatal (reports + halts) if the
/// stack is too small or all task slots are used.
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
/// stack), records the resulting SP in the current task's slot, then loads
/// `next`'s saved SP, restores its callee-saved registers and returns into it.
/// When somebody later yields back, this function simply returns to its
/// caller, all callee-saved state intact (psABI §3.2.1 / AAPCS64 §6.1.1).
///
/// M2 keeps scheduling explicit/manual: there is no run queue; the caller says
/// exactly which task runs next. Yielding to the current task is a no-op.
/// An invalid handle (out of range, or a slot with no saved context) is fatal:
/// reported over serial, then halt — never a wild jump.
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
    // SAFETY: `next_sp` was produced either by `arch::task_stack_init` over a
    // caller-provided exclusive `&'static mut` stack (fabricated initial
    // frame) or by a previous `ctx_switch` save of a then-live task; both
    // leave a well-formed callee-saved frame at that SP. `TASK_SP[prev]
    // .as_ptr()` points into a `'static` atomic, valid for the single word
    // `ctx_switch` stores. Single core + cooperative switching: no other
    // context can touch either slot while the switch runs.
    unsafe { arch::ctx_switch(TASK_SP[prev].as_ptr(), next_sp) }
}

/// A statically-allocatable, 16-byte-aligned kernel task stack of `WORDS`
/// `usize` words, takeable exactly once as `&'static mut [usize]`.
///
/// Exists so the `#![forbid(unsafe_code)]` kernel crate can OWN its static
/// stack arrays (tb-hal allocates nothing) and still produce the unique
/// `&'static mut` that [`task_create`] requires — safe code cannot otherwise
/// mint a mutable reference into a `static`. The atomic one-shot gate makes
/// aliased handouts impossible; a second [`TaskStack::take`] is fatal
/// (reported over serial, then halt).
#[repr(C, align(16))]
pub struct TaskStack<const WORDS: usize> {
    // First field at offset 0 inherits the struct's 16-byte alignment — both
    // ABIs demand a 16-aligned stack (psABI §3.2.2; AAPCS64 §6.4.5.1
    // "SP mod 16 = 0"), and the arch frame builders keep it that way.
    mem: UnsafeCell<[usize; WORDS]>,
    // One-shot gate, flipped by the first `take()`.
    taken: AtomicBool,
}

// SAFETY: the ONLY route to the inner array is `take()`, whose atomic
// swap-once gate hands out at most one `&'static mut` ever (a racing second
// caller loses the swap and halts), so shared references to the cell are never
// used to alias the interior data.
unsafe impl<const WORDS: usize> Sync for TaskStack<WORDS> {}

impl<const WORDS: usize> TaskStack<WORDS> {
    /// A new zeroed stack; `const`, so it can initialise a kernel `static`.
    pub const fn new() -> Self {
        TaskStack {
            mem: UnsafeCell::new([0; WORDS]),
            taken: AtomicBool::new(false),
        }
    }

    /// Hand out the stack as `&'static mut [usize]` — exactly once.
    ///
    /// A second call on the same static is a fatal API misuse: it reports over
    /// serial and halts (fail-closed; it can never mint a second aliasing
    /// `&mut`).
    pub fn take(&'static self) -> &'static mut [usize] {
        if self.taken.swap(true, Ordering::AcqRel) {
            task_api_fatal("TaskStack::take: taken twice");
        }
        // SAFETY: the swap above guarantees this body runs at most once per
        // static instance, so the `&mut` minted here is unique for `'static`;
        // `UnsafeCell` makes mutating the interior of an immutable `static`
        // well-defined.
        let array: &'static mut [usize; WORDS] = unsafe { &mut *self.mem.get() };
        &mut array[..]
    }
}

// ===========================================================================
// M3: MMU bring-up + map/remap self-test
// ===========================================================================
//
// Division of labour (framekernel rule upheld): the typed table layer the two
// backends share is `mmu.rs` (`PageTable512`, `Frame4K`, entry/index math —
// pure safe Rust); ALL new `unsafe` + `asm!` (CR3/EFER/invlpg wrappers,
// MAIR/TCR/TTBR0/SCTLR writes, dsb/isb/tlbi, the mapped-VA derefs of the
// self-test) lives in `arch/x86_64/` and `arch/aarch64/`. The kernel crate
// only ever sees the two safe functions below.
//
// Verified facts (sources re-checked for M3 — do NOT change bit positions
// without re-reading them):
//  * Intel SDM Vol 3A §4.5 Table 4-15 paging-entry formats: P = bit 0,
//    R/W = bit 1, PS = bit 7 (2 MiB at PD level), XD/NX = bit 63 (honoured
//    only when EFER.NXE = 1). Cross-checked against Linux v6.6
//    arch/x86/include/asm/pgtable_types.h: `_PAGE_BIT_PRESENT 0`,
//    `_PAGE_BIT_RW 1`, `_PAGE_BIT_PSE 7`, `_PAGE_BIT_NX 63`.
//  * IA32_EFER = MSR 0xC000_0080, NXE = bit 11; IA32_PAT = MSR 0x277
//    (left at its power-on default for M3); CR4.PGE = bit 7 (Linux v6.6
//    msr-index.h: `MSR_EFER 0xc0000080`, `_EFER_NX 11`,
//    `MSR_IA32_CR_PAT 0x00000277`; processor-flags.h: `X86_CR4_PGE_BIT 7`).
//  * `invlpg m` (Intel SDM Vol 2 / felixcloutier): "Invalidates any TLB
//    entries specified with the source operand … flushes all TLB entries for
//    that page", privileged (CPL 0), "also invalidates any global TLB entries
//    for the specified page". Required after changing a LIVE PTE; adding a
//    brand-new (previously non-present) translation needs no flush
//    (SDM Vol 3A §4.10.4.3 delayed-invalidation allowance).
//  * SCTLR_EL1: M = bit 0, C = bit 2, I = bit 12 (Arm ARM DDI 0487; Linux
//    v6.6 sysreg.h `SCTLR_ELx_M BIT(0)`, `SCTLR_ELx_C BIT(2)`,
//    `SCTLR_ELx_I BIT(12)`). MAIR attr encodings: Device-nGnRnE = 0x00,
//    Normal WB RA/WA = 0xFF (sysreg.h `MAIR_ATTR_DEVICE_nGnRnE 0x00`,
//    `MAIR_ATTR_NORMAL 0xff`), one attribute byte per index
//    (`MAIR_ATTRIDX(attr, idx) = attr << (idx * 8)`).
//  * VMSAv8-64 descriptors (Arm ARM; Linux v6.6 pgtable-hwdef.h): block at
//    L1/L2 = 0b01 (`PMD_TYPE_SECT 1<<0`), table = 0b11 (`PMD_TYPE_TABLE
//    3<<0`), page at L3 = 0b11 (`PTE_TYPE_PAGE 3<<0`); AF = bit 10
//    (`PTE_AF 1<<10`) MUST be set on every leaf (no AF-fault handling);
//    SH[9:8] = 0b11 inner shareable (`PTE_SHARED 3<<8`); AP[7:6] = 0b00 =
//    EL1 RW (AP[1]=bit6 `PTE_USER`, AP[2]=bit7 `PTE_RDONLY` — both clear);
//    AttrIndx at bits [4:2] (`PTE_ATTRINDX(t) t<<2`).
//  * TLBI VA-operand format: VA >> 12 in bits [43:0] (ASID in [63:48], 0 for
//    vaaE1IS "all ASIDs" forms) — Linux v6.6 tlbflush.h `__TLBI_VADDR`:
//    `__ta = addr >> 12; __ta &= GENMASK_ULL(43, 0)`.

/// Bring the MMU for the current architecture to the M3 baseline. Call ONCE
/// from `rust_main`, AFTER [`install_traps`] — a broken mapping then reports
/// through the trap path (`TrapKind::PageFault`) instead of an opaque hang or
/// triple fault.
///
/// * x86_64: paging is already LIVE (the A0 boot trampoline built the
///   identity 2 MiB tables and loaded CR3 before `rust_main`); this programs
///   `EFER.NXE` (MSR `0xC000_0080`, bit 11) so PTE bit 63 (NX) is honoured
///   from M3 on. `IA32_PAT` (MSR `0x277`) keeps its power-on default.
/// * aarch64: the MMU is OFF until here. Builds the identity translation
///   tables while still off (L1[0] = Device-nGnRnE block covering the PL011
///   UART gigabyte, L1[1] = Normal-WB block covering RAM, AF set on every
///   leaf), then `dsb ishst` → `MAIR_EL1`/`TCR_EL1` (T0SZ=25, TG0=4K,
///   IRGN0/ORGN0=WBWA, SH0=inner, IPS=40-bit, EPD1=1) / `TTBR0_EL1` → `isb`
///   → set `SCTLR_EL1.{M,C,I}` preserving all other bits → `isb`. Serial
///   keeps working across the enable — that is the device-mapping proof the
///   kernel prints right after calling this.
pub fn mmu_init() {
    arch::mmu_init();
}

/// Run the in-HAL MMU map/remap self-test; `true` = pass.
///
/// The WHOLE test lives inside tb-hal: map `TEST_VA` (x86_64: `0x4000_0000`,
/// the 1 GiB line — OUTSIDE the boot identity map, PDPT index 1 is empty;
/// aarch64: `0x8000_0000`, the 2 GiB line — outside the RAM gigabyte, L1
/// index 2 is empty) to 4 KiB frame A, write a magic value through `TEST_VA`,
/// verify it through frame A's identity-mapped address; then remap `TEST_VA`
/// to frame B — x86: rewrite the PTE + `invlpg [TEST_VA]`; aarch64: full
/// Break-Before-Make (invalid descriptor → `dsb ishst` → `tlbi vaae1is,
/// VA>>12` → `dsb ish` → `isb` → new descriptor → `dsb ishst` → `isb`) — and
/// verify a read through `TEST_VA` now observes frame B's value.
///
/// Frames and tables are static, 4096-aligned, `.bss`-resident
/// (`mmu::Frame4K` / `mmu::PageTable512`); every raw pointer deref stays
/// inside tb-hal's arch backends. The `#![forbid(unsafe_code)]` kernel crate
/// only branches on the returned `bool`.
pub fn mmu_selftest() -> bool {
    arch::mmu_selftest()
}
