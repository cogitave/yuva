//! aarch64 cooperative context switch (M2): `ctx_switch` + the initial frame.
//!
//! This is the aarch64 half of milestone **M2** ("cooperative context
//! switch"). It provides the two arch primitives the safe `tb-hal` task API
//! in `lib.rs` (`Task` / `task_create` / `yield_to`) delegates to:
//!
//!  * [`ctx_switch`] — the raw switch (`global_asm!` below): push the current
//!    task's callee-saved registers onto its own stack, publish the resulting
//!    SP through `prev_sp_save`, adopt `next_sp`, pop the next task's
//!    callee-saved registers, and `ret` into it.
//!  * [`task_stack_init`] — fabricate the INITIAL context frame on a
//!    brand-new task's stack so the very first switch into it "returns" into
//!    `entry`. Fabrication is pure safe Rust (slice writes); only the switch
//!    itself is assembly.
//!
//! Saved-context model ("callee-saved-on-stack"): `ctx_switch` is an ordinary
//! `extern "C"` call, so at every call site the compiler has already spilled
//! or given up every caller-saved value; only the callee-saved set survives a
//! call in registers, so that set — and nothing else — is what the switch
//! must carry from one task to the other. The saved SP doubles as the whole
//! context handle (same model as the x86_64 side in `arch/x86_64/sched.rs`).
//!
//! Verified facts (obey exactly):
//!  * AAPCS64 callee-saved set: **r19-r29 and SP**, with r29 = FP and
//!    r30 = LR holding the return address. Procedure Call Standard for the
//!    Arm 64-bit Architecture (github.com/ARM-software/abi-aa,
//!    `aapcs64/aapcs64.rst`), §6.1.1 "General-purpose registers": "r19…r28 —
//!    Callee-saved registers", and: "r19-r29 and SP are Callee-saved. All 64
//!    bits of each value stored in r19-r29 are Callee-saved." The resume
//!    address rides in x30/LR, so the frame stores **x19..x28 + x29(FP) +
//!    x30(LR)** = 12 registers; SP is the handle, not a slot.
//!  * Stack alignment, AAPCS64 "Universal stack constraints" (§6.4.5): "SP
//!    mod 16 = 0. The stack must be quad-word aligned." The 0x60-byte frame
//!    is a multiple of 16 and the fabricated initial SP is aligned down to
//!    16, so SP is quad-word aligned at every instruction of the switch and
//!    at task entry.
//!  * Frame-record chain termination (AAPCS64 §6.4.6 "The Frame Pointer"):
//!    "The end of the frame record chain is indicated by the address zero in
//!    the address for the previous frame." — why the fabricated x29 slot is 0.
//!  * Cross-check, Linux v6.6 `arch/arm64/kernel/entry.S` `cpu_switch_to`
//!    (lines 822-847): stp/ldp of exactly `x19..x28`, `x29 + sp`, `lr`
//!    ("store callee-saved registers"), then `ret` — same register set, same
//!    LR-carries-the-resume-address model (Linux parks the frame in
//!    `task_struct.thread.cpu_context`; we park it on the task stack).
//!  * Initial-frame fabrication technique: OSDev Wiki, "Brendan's
//!    Multi-tasking Tutorial": "put values on the new kernel stack to match
//!    the values that your 'switch_to_task(task)' function expects to pop off
//!    the stack after switching to the task ... the values on the new kernel
//!    stack will include a 'return EIP' (the address that the
//!    'switch_to_task(task)' function will return to)". Same technique in
//!    Linux v6.6 `arch/arm64/kernel/process.c` `copy_thread`:
//!    `p->thread.cpu_context.pc = (unsigned long)ret_from_fork;` — a new
//!    task's first switch "returns" into a fabricated entry point.
//!  * No FP/SIMD state is saved: `targets/aarch64-tabos-none.json` is
//!    `abi: softfloat` with `-fp-armv8,-neon`, so the V registers carry no
//!    live values (same reasoning as the M1 `TrapFrame` in `vectors.rs`).
//!
//! Saved-context frame layout (byte offsets from the saved SP; 0x60 = 96 B,
//! shared verbatim between the assembly and [`task_stack_init`]):
//!
//! ```text
//! [sp+0x00] x19   [sp+0x08] x20   [sp+0x10] x21   [sp+0x18] x22
//! [sp+0x20] x23   [sp+0x28] x24   [sp+0x30] x25   [sp+0x38] x26
//! [sp+0x40] x27   [sp+0x48] x28   [sp+0x50] x29   [sp+0x58] x30 <- resume PC
//! ```

use core::arch::{global_asm, naked_asm};
use core::mem::size_of;

/// `usize` slots in one saved-context frame: x19..x28 (10) + x29/FP + x30/LR.
const CTX_FRAME_SLOTS: usize = 12;

/// Frame size in bytes (0x60). A multiple of 16, so pushing/popping a frame
/// preserves the AAPCS64 "SP mod 16 = 0" universal stack constraint.
const CTX_FRAME_BYTES: usize = CTX_FRAME_SLOTS * size_of::<usize>();

/// Frame slot index of x30/LR — the address `ctx_switch` `ret`s to. For a
/// fabricated frame this slot holds `entry`; offset 0x58, matching the asm.
const CTX_SLOT_LR: usize = CTX_FRAME_SLOTS - 1;

/// Smallest stack (in `usize` slots) [`task_stack_init`] accepts: one frame
/// (12) + worst-case 16-byte top alignment loss (1) + a little headroom. The
/// kernel's real M2 stacks are 4096 slots; this only rejects absurd inputs.
const MIN_STACK_SLOTS: usize = 32;

// Compile-time locks on the layout the assembly below assumes.
const _: () = assert!(CTX_FRAME_BYTES == 0x60 && CTX_FRAME_BYTES % 16 == 0);
const _: () = assert!(CTX_SLOT_LR * size_of::<usize>() == 0x58);

// -- ctx_switch ---------------------------------------------------------------
// (a) PRE : extern "C" call with x0 = prev_sp_save (*mut usize save slot for
//           the CURRENT task) and x1 = next_sp (a handle from task_stack_init
//           or from a previous save through *prev_sp_save); SP 16-aligned
//           (AAPCS64 invariant holds on every call). POST: the current task's
//           x19..x30 sit in a 0x60-byte frame on its own stack with
//           *prev_sp_save = that frame's SP; execution continues in the next
//           task at its saved x30 with x19..x29 + SP restored.
// (b) ABI : AAPCS64. Beyond the callee-saved set it deliberately reloads, it
//           clobbers only x2 (caller-saved); memory touched: [sp-0x60, sp) of
//           the old stack, [x1, x1+0x60) of the new one, the 8-byte store to
//           *x0. SP stays 16-aligned at every step (0x60 % 16 == 0; AAPCS64
//           "SP mod 16 = 0"). Register set per AAPCS64 §6.1.1 / Linux v6.6
//           cpu_switch_to (see module note).
// (c) TEST: scripts/run-aarch64.sh — the M2 ping-pong (>=1000 strict A/B
//           round trips with callee-saved canaries) prints
//           "M2: context-switch OK".
global_asm!(
    r#"
    .section .text._sched, "ax"
    .balign 4
    .globl ctx_switch
ctx_switch:
    // Push the AAPCS64 callee-saved set onto the CURRENT task's stack.
    sub  sp, sp, #0x60            // 12 slots; 0x60 % 16 == 0 keeps SP aligned
    stp  x19, x20, [sp, #0x00]
    stp  x21, x22, [sp, #0x10]
    stp  x23, x24, [sp, #0x20]
    stp  x25, x26, [sp, #0x30]
    stp  x27, x28, [sp, #0x40]
    stp  x29, x30, [sp, #0x50]    // FP + LR; LR is this task's resume address

    // Publish the frame: the saved SP itself is the whole context handle.
    mov  x2, sp
    str  x2, [x0]                 // *prev_sp_save = SP

    // Adopt the next task's saved SP and pop ITS callee-saved set.
    mov  sp, x1
    ldp  x19, x20, [sp, #0x00]
    ldp  x21, x22, [sp, #0x10]
    ldp  x23, x24, [sp, #0x20]
    ldp  x25, x26, [sp, #0x30]
    ldp  x27, x28, [sp, #0x40]
    ldp  x29, x30, [sp, #0x50]    // x30 = resume PC (or the fabricated entry)
    add  sp, sp, #0x60
    ret                           // branch to x30: continue the next task
"#
);

extern "C" {
    /// Cooperative context switch — the raw M2 primitive (assembly above).
    ///
    /// Saves the current task's AAPCS64 callee-saved registers (x19..x28,
    /// x29/FP, x30/LR) in a 0x60-byte frame on its own stack, stores the
    /// resulting SP to `*prev_sp_save`, switches SP to `next_sp`, restores the
    /// next task's frame, and returns into it (at its saved x30). For a frame
    /// fabricated by [`task_stack_init`] that "return" is the first entry into
    /// the task's `entry` function.
    ///
    /// # Safety
    ///
    /// * `prev_sp_save` must be valid, 8-aligned, and writable; it receives
    ///   the only handle through which the current task can ever be resumed.
    /// * `next_sp` must be a live context handle: the value produced by
    ///   [`task_stack_init`], or one stored through `prev_sp_save` by an
    ///   earlier `ctx_switch`, whose backing stack is still alive ('static in
    ///   M2) and which has not already been consumed by a switch.
    /// * Cooperative single-core use only — never call from a trap handler.
    pub fn ctx_switch(prev_sp_save: *mut usize, next_sp: usize);
}

// -- task_stack_init ----------------------------------------------------------
// (a) PRE : `stack` is the new task's (caller-owned, in M2 'static) stack
//           array, >= MIN_STACK_SLOTS slots; `entry` is the task body. POST:
//           the top of `stack` (aligned down to 16) holds one fabricated
//           0x60-byte frame — x19..x28 = 0, x29 = 0 (frame-record chain
//           terminator), x30 = entry — and the returned value is the frame's
//           SP, ready to be passed to `ctx_switch` as `next_sp` exactly once.
// (b) ABI : pure safe Rust; no asm, no unsafe — plain slice writes. The frame
//           bytes/offsets mirror the `ctx_switch` assembly via the shared
//           CTX_* constants. Returned SP is 16-aligned; after the first
//           switch pops the frame, `entry` starts with SP = aligned stack
//           top (AAPCS64 "SP mod 16 = 0" holds) and FP = 0.
// (c) TEST: scripts/run-aarch64.sh — task B of the M2 ping-pong enters
//           through exactly this fabricated frame.
/// Fabricate the initial saved context for a new task on `stack`.
///
/// Builds, at the (16-byte aligned-down) top of `stack`, the exact 0x60-byte
/// frame [`ctx_switch`] expects to pop: x19..x28 zeroed, x29/FP zeroed (the
/// AAPCS64 frame-record chain ends at address zero), and x30/LR = `entry`, so
/// the first switch into the returned handle pops zeros and `ret`s straight
/// into `entry` (OSDev "Brendan's Multi-tasking Tutorial" technique; Linux
/// `copy_thread` does the same with `cpu_context.pc = ret_from_fork`).
///
/// Returns the fabricated SP — the context handle to pass to [`ctx_switch`]
/// (via the safe `yield_to`) as `next_sp` for the task's FIRST activation.
///
/// `entry` must never return: there is no caller frame beneath it. In M2 every
/// task either yields forever or ends in `halt()`.
///
/// # Panics
///
/// Panics if `stack` has fewer than `MIN_STACK_SLOTS` (32) slots.
pub fn task_stack_init(stack: &mut [usize], entry: fn()) -> usize {
    assert!(
        stack.len() >= MIN_STACK_SLOTS,
        "task stack too small for an initial context frame"
    );

    // Align the stack TOP down to 16 bytes (AAPCS64 universal stack
    // constraint: "SP mod 16 = 0"). A `[usize]` is only guaranteed 8-aligned,
    // so at most one 8-byte slot is sacrificed.
    let base = stack.as_ptr() as usize;
    let top = (base + stack.len() * size_of::<usize>()) & !0xF;
    let frame_sp = top - CTX_FRAME_BYTES;

    // Both `frame_sp` and `base` are 8-aligned, so the slot index is exact;
    // `frame_sp + 0x60 == top <= base + len*8` keeps the range in bounds.
    let first = (frame_sp - base) / size_of::<usize>();

    // x19..x28 = 0 and x29/FP = 0 (frame-record chain terminator) ...
    for slot in &mut stack[first..first + CTX_FRAME_SLOTS] {
        *slot = 0;
    }
    // x19 = entry (consumed by the trampoline) and x30/LR = the trampoline:
    // the first `ctx_switch` `ret`s into `task_entry_trampoline`, which arms
    // LR with `task_exit_guard` and branches to `entry` — so an entry fn that
    // RETURNS lands on a loud deterministic failure instead of silently
    // re-entering itself (mirrors the x86_64 exit-guard).
    stack[first] = entry as usize; // x19 slot (sp+0x00)
    stack[first + CTX_SLOT_LR] = task_entry_trampoline as *const () as usize;

    frame_sp
}

// ===========================================================================
// task_entry_trampoline / task_exit_guard: first-activation shim + landing
// pad (mirrors arch/x86_64/sched.rs task_exit_guard).
// (a) PRE: reached by ctx_switch's `ret` on a task's FIRST activation, with
//     x19 = entry fn address (fabricated by task_stack_init) and SP at the
//     16-aligned stack top. POST: never returns to the switch path; arms
//     LR = task_exit_guard, then branches into `entry`.
// (b) ABI: naked. Clobbers only LR before entering `entry`; x19 is
//     callee-saved and its fabricated value is dead after the `br`.
//     adrp/add :lo12: materializes the guard address (relocation-model:
//     static keeps it in range).
// (c) Tested by: construction — M2 tasks never return; the guard converts the
//     "task returned" bug class into "M2: FAIL task entry fn returned" + halt.
// ===========================================================================
/// First-activation shim: arms the exit guard in LR, then enters the task.
#[unsafe(naked)]
extern "C" fn task_entry_trampoline() -> ! {
    naked_asm!(
        "adrp lr, {guard}",
        "add  lr, lr, :lo12:{guard}",
        "br   x19",
        guard = sym task_exit_guard,
    )
}

/// Diverging landing pad reached only if a task's entry function returns.
#[unsafe(naked)]
extern "C" fn task_exit_guard() -> ! {
    naked_asm!(
        "mov x29, xzr", // terminate any frame-record chain
        "bl  {fail}",   // diverges (prints + halts); never comes back
        "1: b 1b",      // belt-and-braces park
        fail = sym task_exit_fail,
    )
}

extern "C" fn task_exit_fail() -> ! {
    crate::serial_write_str("M2: FAIL task entry fn returned\n");
    super::halt()
}
