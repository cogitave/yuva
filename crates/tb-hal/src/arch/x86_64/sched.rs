//! x86_64 cooperative context switch (M2): the naked `ctx_switch` primitive
//! plus the initial-stack fabricator that tb-hal's shared task layer
//! (`Task` / `task_create` / `yield_to` in `lib.rs`) builds on. ALL of M2's
//! x86_64 `unsafe`/asm lives HERE; the kernel crate stays
//! `#![forbid(unsafe_code)]` (KERNEL-FOUNDATION-SPEC §1).
//!
//! Verified facts QUOTED from primary sources, not invented:
//!   * Callee-saved set. System V AMD64 psABI §3.2.1, Figure 3.4 "Register
//!     Usage" (gitlab.com/x86-psABIs/x86-64-ABI, low-level-sys-info.tex):
//!     "Registers %rbp, %rbx and %r12 through %r15 ``belong'' to the calling
//!     function and the called function is required to preserve their
//!     values." A cooperative switch is call-shaped (`yield_to` is an
//!     ordinary `extern "C"` call), so it must preserve exactly
//!     {rbx, rbp, r12, r13, r14, r15} + rsp; every other GPR is
//!     caller-saved and already dead at the call site.
//!   * Stack alignment. psABI §3.2.2 "The Stack Frame": "The end of the
//!     input argument area shall be aligned on a 16 ... byte boundary", i.e.
//!     the stack is "16 ... byte aligned immediately before the call
//!     instruction is executed. Once control has been transferred to the
//!     function entry point, i.e. immediately after the return address has
//!     been pushed, %rsp points to the return address, and the value of
//!     (%rsp + 8) is a multiple of 16." The fabricated frame reproduces
//!     exactly that shape when the first switch `ret`s into the entry fn.
//!   * Switch model + initial-frame fabrication. xv6 (mit-pdos/xv6-public)
//!     swtch.S: "Save the current registers on the stack, creating a struct
//!     context, and save its address in *old. Switch stacks to new and pop
//!     previously-saved registers." proc.c `allocproc`: "Set up new context
//!     to start executing at forkret, which returns to trapret" — fabricate
//!     the new task's stack so the FIRST switch's `ret` lands in the entry
//!     function. Same callee-saved-on-stack technique as OSDev wiki
//!     "Context Switching" (Brendan) and phil-opp's kernel-threads material.
//!
//! No FP/SIMD state is saved or restored: the target is soft-float
//! (targets/x86_64-yuva-none.json: `"features": "-mmx,-sse,+soft-float"`),
//! so the compiler can never hold live state in x87/MMX/SSE registers.

use core::arch::naked_asm;
use core::mem::size_of;

/// Stack slot granularity: one machine word (8 bytes on x86_64).
const WORD: usize = size_of::<usize>();

/// How many callee-saved GPRs `ctx_switch` saves/restores: rbx, rbp,
/// r12, r13, r14, r15 (psABI Figure 3.4; rsp is handled separately as the
/// saved-context handle itself).
const CALLEE_SAVED: usize = 6;

/// Slots a fabricated initial frame occupies below the aligned stack top:
/// 6 callee-saved registers + the entry "return address" + the exit guard.
const INITIAL_FRAME_SLOTS: usize = CALLEE_SAVED + 2;

/// Refuse to fabricate a frame on a stack with fewer than this many `usize`
/// slots: the initial frame itself needs 9 (8 + worst-case alignment pad),
/// and anything close to that leaves no room for the entry fn's own frames.
/// (M2's kernel stacks are `[usize; 4096]` — 32 KiB — far above this floor.)
const MIN_STACK_SLOTS: usize = 32;

// ===========================================================================
// ctx_switch: the ONLY context-switch asm on x86_64.
// (a) PRE: called like a normal extern "C" fn from task A (rdi = where to
//     store A's SP, rsi = B's saved SP, a value previously produced by this
//     function or by `task_stack_init`). POST: callee-saved regs of A
//     {rbx,rbp,r12-r15} + A's resume RIP are parked on A's stack and
//     *prev_sp_save = A's SP; B's regs are reloaded from B's stack and `ret`
//     resumes B exactly where it called ctx_switch (or at its entry fn, on
//     B's first run). A resumes here, later, when someone switches back.
// (b) ABI: SysV extern "C" (args rdi/rsi); Intel syntax (Rust default). Saves
//     EXACTLY the psABI Fig. 3.4 callee-saved GPR set — "Registers %rbp,
//     %rbx and %r12 through %r15 belong to the calling function and the
//     called function is required to preserve their values" — everything
//     else is caller-saved, i.e. dead across this call. 6 pushes = 48 bytes
//     keeps rsp ≡ 8 (mod 16) throughout, matching psABI §3.2.2 "(%rsp + 8)
//     is a multiple of 16" at fn entry. Model: xv6 swtch.S ("Save the
//     current registers on the stack ... save its address in *old. Switch
//     stacks to new and pop previously-saved registers.").
// (c) Tested by: kernel M2 ping-pong — >=1000 strict A/B alternations with
//     live locals in callee-saved regs; scripts/run-x86_64.sh asserts the
//     "M2: context-switch OK" marker.
// ===========================================================================
/// Switch register context from the calling task to `next_sp`.
///
/// Saves the current task's callee-saved registers + return address on ITS
/// OWN stack, stores the resulting stack pointer to `*prev_sp_save` (the
/// caller's saved-context handle), installs `next_sp` as the stack pointer
/// and pops the next task's context, `ret`ing into its resume point.
///
/// # Safety
///
/// * `prev_sp_save` must be valid for an 8-byte write and not alias the
///   active region of either stack.
/// * `next_sp` must be a context handle produced by a previous `ctx_switch`
///   save or by [`task_stack_init`], on a stack that is still alive
///   and not currently executing on any CPU.
/// * Single-core use, with interrupts masked across the switch. M2 calls this
///   cooperatively; M9 ALSO invokes it from interrupt context (the timer
///   tick's `schedule()` -> `yield_to()` runs inside the handler). That is
///   sound: vector 0x20 has IST=0, so the CPU builds the IRQ frame on the
///   CURRENT ring0 stack and the `__alltraps` TrapFrame + suspended handler
///   chain sit on that task's OWN stack; this switch swaps only the
///   callee-saved set + SP, and resume unwinds back through that chain to the
///   IRQ epilogue's `iretq`, which restores the full frame (including
///   RFLAGS.IF) at the interrupted instruction. IF stays clear from the
///   interrupt gate until that `iretq`, so no second tick can re-enter the
///   switch on either task's stack.
#[unsafe(naked)]
pub unsafe extern "C" fn ctx_switch(prev_sp_save: *mut usize, next_sp: usize) {
    naked_asm!(
        // Save current task's callee-saved context on its own stack.
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        // Publish the old task's saved-SP handle, then switch stacks.
        "mov [rdi], rsp", // *prev_sp_save = current SP
        "mov rsp, rsi",   // SP = next task's saved SP
        // Restore the next task's callee-saved context (reverse order).
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        // Return into the next task: pops its saved RIP — either where it
        // last called ctx_switch, or the fabricated entry slot (first run).
        "ret",
    )
}

/// Fabricate the initial saved context for a NEW task on `stack`, so that
/// the first [`ctx_switch`] INTO it pops six zeroed callee-saved registers
/// and `ret`s into `entry` (xv6 `allocproc` / OSDev-Brendan technique).
///
/// Frame layout built at the 16-byte-aligned logical top of `stack`
/// (addresses descend; `top` is aligned DOWN from the slice end):
///
/// ```text
///   top      ─ 16-byte aligned ─ (0..1 pad slot may exist above, unused)
///   top -  8: task_exit_guard   ← entry's caller, if entry ever returns
///   top - 16: entry             ← popped by ctx_switch's final `ret`
///   top - 24: 0 (rbx)   ┐
///   top - 32: 0 (rbp)   │ popped rbx-last by ctx_switch
///   top - 40: 0 (r12)   │ (push order rbx..r15 ⇒ r15 at the
///   top - 48: 0 (r13)   │  lowest address, rbx at the highest)
///   top - 56: 0 (r14)   │
///   top - 64: 0 (r15)   ┘ ← returned initial SP (saved-context handle)
/// ```
///
/// At entry to `entry`, rsp = top - 8, so (rsp + 8) = top ≡ 0 (mod 16) —
/// exactly the psABI §3.2.2 post-`call` shape the compiler assumes. The
/// returned handle (top - 64) also stays 16-aligned, since the 6 register
/// slots + 2 address slots total 64 bytes.
///
/// Pure safe Rust: only slice indexing + integer math; the resulting handle
/// is consumed by `ctx_switch`'s asm. Panics if `stack` has fewer than
/// [`MIN_STACK_SLOTS`] slots.
pub fn task_stack_init(stack: &mut [usize], entry: fn()) -> usize {
    assert!(
        stack.len() >= MIN_STACK_SLOTS,
        "task stack too small to fabricate an initial context"
    );

    let base = stack.as_mut_ptr() as usize;
    let limit = base + stack.len() * WORD;
    // Logical stack top: slice end aligned DOWN to 16 bytes (`[usize]` only
    // guarantees 8-byte alignment, so up to one slot above `top` is unused).
    let top = limit & !0xF;

    // Address -> index into `stack`; in-bounds because top - 64 >= base for
    // any slice of >= 9 slots (and MIN_STACK_SLOTS is far above that).
    let slot = |addr: usize| (addr - base) / WORD;

    // (fn-item -> raw-ptr -> usize: the two-step cast rustc requires.)
    stack[slot(top - WORD)] = task_exit_guard as *const () as usize; // guard
    stack[slot(top - 2 * WORD)] = entry as usize; // `ret` target, first switch
    for i in 0..CALLEE_SAVED {
        stack[slot(top - (3 + i) * WORD)] = 0; // rbx, rbp, r12, r13, r14, r15
    }

    top - INITIAL_FRAME_SLOTS * WORD // the initial saved-SP handle
}

/// M12: fabricate the initial saved context for a NEW *user* agent task on its
/// KERNEL `stack`, so the FIRST [`ctx_switch`] into it pops six fabricated
/// callee-saved registers and `ret`s into `super::user::agent_launch`, which
/// then `iretq`s to ring3 at `entry_va` with `RSP = user_sp`, the birth
/// registers `rdi = arg0` / `rsi = arg1`, and `RFLAGS.IF = 1` (preemptible).
///
/// The six callee-saved slots carry the launch arguments, since the trampoline
/// runs immediately after `ctx_switch`'s `pop`s: `rbx = entry_va`,
/// `rbp = user_sp`, `r12 = user_cs|3`, `r13 = user_ss|3`, `r14 = arg0`,
/// `r15 = arg1`. `ctx_switch` pops r15 FIRST (lowest address), so the returned
/// SP names the r15 slot. Pure safe Rust (slice writes + the trampoline
/// address). Panics if `stack` is smaller than [`MIN_STACK_SLOTS`].
pub fn task_stack_init_user(
    stack: &mut [usize],
    entry_va: u64,
    user_sp: u64,
    arg0: u64,
    arg1: u64,
) -> usize {
    assert!(
        stack.len() >= MIN_STACK_SLOTS,
        "agent kernel stack too small to fabricate a user-launch context"
    );

    let base = stack.as_mut_ptr() as usize;
    let limit = base + stack.len() * WORD;
    let top = limit & !0xF;
    let slot = |addr: usize| (addr - base) / WORD;

    let user_cs = (super::gdt::USER_CODE_SEL | 3) as usize;
    let user_ss = (super::gdt::USER_DATA_SEL | 3) as usize;

    // Top-down: the `ret` target, then rbx,rbp,r12,r13,r14,r15 below it. The pop
    // order in `ctx_switch` is r15,r14,r13,r12,rbp,rbx, so r15 sits LOWEST and
    // the returned SP names it.
    stack[slot(top - WORD)] = super::user::agent_launch as *const () as usize; // ret -> launch
    stack[slot(top - 2 * WORD)] = entry_va as usize; // rbx -> user RIP
    stack[slot(top - 3 * WORD)] = user_sp as usize; // rbp -> user RSP
    stack[slot(top - 4 * WORD)] = user_cs; // r12 -> user CS|3
    stack[slot(top - 5 * WORD)] = user_ss; // r13 -> user SS|3
    stack[slot(top - 6 * WORD)] = arg0 as usize; // r14 -> birth rdi
    stack[slot(top - 7 * WORD)] = arg1 as usize; // r15 -> birth rsi

    top - 7 * WORD // the initial saved-SP handle (the r15 slot)
}

// ===========================================================================
// task_exit_guard: landing pad if a task's entry fn ever returns.
// (a) PRE: a task's entry fn executed `ret` with rsp back at its fabricated
//     entry shape (rsp = top - 8), popping this guard's address; rsp = top,
//     which is 16-aligned — NOT the (%rsp + 8) % 16 == 0 shape a normal Rust
//     fn entered via `call` may assume. POST: never returns; realigns, then
//     calls the diverging Rust reporter, which halts the core.
// (b) ABI: naked, so no prologue assumes anything about the stack. `and
//     rsp, -16` forces 16-alignment, and the `call` then pushes 8 so
//     `task_exit_fail` gets the exact psABI §3.2.2 "(%rsp + 8) is a multiple
//     of 16" entry shape. Intel syntax (Rust default).
// (c) Tested by: construction only — M2's ping-pong tasks loop forever and
//     never return; this guard turns the "task returned" bug class into a
//     deterministic serial message + halt instead of a wild jump.
// ===========================================================================
/// Diverging landing pad placed above each fabricated entry frame; reached
/// only if a task's entry function returns (which M2 tasks never do).
#[unsafe(naked)]
extern "C" fn task_exit_guard() -> ! {
    naked_asm!(
        "and rsp, -16",  // restore the alignment invariant for the call below
        "call {fail}",   // diverges (prints + halts); never comes back
        "2: jmp 2b",     // belt-and-braces: park if it somehow did
        fail = sym task_exit_fail,
    )
}

/// Report a returned task entry fn over serial, then park the core forever.
/// Called only from `task_exit_guard`, after it has realigned the stack.
extern "C" fn task_exit_fail() -> ! {
    crate::serial_write_str("M2: FAIL task entry fn returned\n");
    super::halt()
}
