//! x86_64 trap entry: per-vector thunks + `__alltraps` + the extern "C"
//! `x86_trap_handler` that marshals a raw `TrapFrame` into a SAFE
//! [`crate::TrapInfo`] and hands policy to the registered hook
//! ([`crate::dispatch_trap`]). All `unsafe`/asm stays in `tb-hal`; the kernel
//! crate is `#![forbid(unsafe_code)]` (KERNEL-FOUNDATION-SPEC §1).
//!
//! Verified facts QUOTED from primary sources, not invented:
//!   * Error-code vectors. The CPU pushes a 32-bit error code only for #DF(8),
//!     #TS(10), #NP(11), #SS(12), #GP(13), #PF(14), #AC(17), #CP(21), #SX(30);
//!     every other vector gets a dummy 0 from the thunk so the frame is uniform:
//!     Intel SDM Vol.3A §6.13 + Table 6-1 "Protected-Mode Exceptions and
//!     Interrupts"; OSDev "Exceptions".
//!   * #BP (vector 3, INT3) is a TRAP: the CPU-saved RIP points to the
//!     instruction FOLLOWING int3, so `iretq` resumes with no RIP fix-up —
//!     Intel SDM Vol.3A §6.15 "#BP ... Saved Instruction Pointer points to the
//!     instruction following the INT3" (contrast aarch64 `brk`, whose ELR is AT
//!     the instruction and must be advanced by 4). #PF(14) fault address = CR2
//!     (Intel SDM Vol.3A §6.15 "#PF").
//!   * 64-bit interrupt entry aligns the stack to 16 bytes before pushing the
//!     iret frame (Intel SDM Vol.3A §6.14.2 "Stack Usage ... aligned to a
//!     16-byte boundary"); the 15 GPR pushes preserve that, so SysV's 16-byte
//!     alignment holds at the `call`.

use core::arch::{asm, global_asm};
use core::ptr::addr_of;

// ===========================================================================
// Trap entry asm: 256 per-vector thunks -> __alltraps -> x86_trap_handler.
// (a) PRE: a CPU exception/interrupt vectored to thunk N. For the 9 error-code
//     vectors the CPU already pushed a 32-bit error code; the rest push a
//     dummy 0. POST: a full TrapFrame (15 GPRs + vector + errcode + iret frame)
//     is on the stack, its address is in rdi, and x86_trap_handler is called;
//     on its return (Resume only) the frame is popped and `iretq` resumes.
// (b) ABI: extern "C"/SysV; RSP is 16-byte aligned at the `call` (CPU aligns
//     the iret frame to 16, +120 bytes of GPRs keeps it aligned). Intel syntax
//     (Rust default). Sources: Intel SDM Vol.3A §6 (esp. §6.13/§6.14, Table
//     6-1); OSDev "Interrupt Descriptor Table" / "Exceptions".
// (c) Tested by: kernel M1 sequence (int3 -> hook -> resume; "M1: traps OK").
// ===========================================================================
global_asm!(
    r#"
.section .text.trap, "ax", @progbits

// ---- 256 per-vector entry thunks ------------------------------------------
.macro TRAP_THUNK vec
__trap_thunk_\vec:
    .if (\vec == 8) || (\vec == 10) || (\vec == 11) || (\vec == 12) || (\vec == 13) || (\vec == 14) || (\vec == 17) || (\vec == 21) || (\vec == 30)
        // This vector carries a CPU-pushed 32-bit error code; do not add one.
    .else
        push 0          // dummy error code -> every TrapFrame is identical
    .endif
    push \vec           // vector number
    jmp  __alltraps
.endm

.altmacro
.set vecidx, 0
.rept 256
    TRAP_THUNK %vecidx
    .set vecidx, vecidx + 1
.endr
.noaltmacro

// ---- common entry: save GPRs, call Rust, restore, iretq -------------------
.global __alltraps
__alltraps:
    // Stack on entry (low->high): vector, errcode, rip, cs, rflags, rsp, ss.
    // Push the 15 GPRs so rax lands lowest -> matches `struct TrapFrame`.
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rbp
    push rdi
    push rsi
    push rdx
    push rcx
    push rbx
    push rax

    mov  rdi, rsp           // arg0 = *mut TrapFrame
    call x86_trap_handler   // returns ONLY on TrapAction::Resume

    // Resume path: restore the GPRs, drop vector+errcode, return from interrupt.
    pop  rax
    pop  rbx
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    pop  rbp
    pop  r8
    pop  r9
    pop  r10
    pop  r11
    pop  r12
    pop  r13
    pop  r14
    pop  r15
    add  rsp, 16            // discard the pushed vector + error code
    iretq

// ---- table of thunk addresses, consumed by idt::init ----------------------
.section .rodata, "a", @progbits
.balign 8
.global __trap_thunks
__trap_thunks:
.macro TRAP_ADDR vec
    .quad __trap_thunk_\vec
.endm
.altmacro
.set vecidx, 0
.rept 256
    TRAP_ADDR %vecidx
    .set vecidx, vecidx + 1
.endr
.noaltmacro
"#
);

/// 64-bit trap frame, in MEMORY order (lowest address first). The 15 GPRs are
/// pushed by `__alltraps` (rax lowest), then the thunk-pushed vector + error
/// code, then the CPU-pushed interrupt frame.
#[repr(C)]
#[allow(dead_code)] // most fields exist only to lay out the frame correctly
pub(super) struct TrapFrame {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    vector: u64,
    error_code: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}

/// Trap demux. The ONE place in `tb-hal/x86_64` that dereferences the raw
/// frame: it builds a safe [`crate::TrapInfo`], lets the registered safe hook
/// decide policy via [`crate::dispatch_trap`], then either returns (Resume —
/// `__alltraps` restores + `iretq`s) or parks the core (Halt — never returns).
#[no_mangle]
pub(super) extern "C" fn x86_trap_handler(frame: *mut TrapFrame) {
    // SAFETY: `__alltraps` passes rsp pointing at a fully-populated TrapFrame.
    let f = unsafe { &*frame };
    let vector = f.vector;

    // M8: external (asynchronous) LAPIC interrupts arrive on vectors >= 32. The
    // timer vector (0x20) bumps the monotonic tick + EOIs the LAPIC; the
    // spurious vector (0xFF) just resumes (Intel SDM Vol.3A §11.9: no EOI). Any
    // OTHER vector returns false and falls through to the synchronous-fault
    // classification below (correctly fatal). A recognised IRQ never consults
    // the SYNCHRONOUS trap hook (whose kernel policy halts on anything but #BP),
    // and on return `__alltraps` restores the FULL frame and `iretq`s back to
    // the exact interrupted instruction. (M4's `int 0x80` bypasses this handler
    // via its dedicated DPL3 gate, so it is unaffected.)
    if super::timer::try_handle_irq(vector) {
        return;
    }

    let error_code = f.error_code & 0xFFFF_FFFF; // CPU error code is 32-bit

    let kind = match vector {
        3 => crate::TrapKind::Breakpoint, // #BP (int3)
        6 => crate::TrapKind::Undefined,  // #UD invalid opcode
        14 => crate::TrapKind::PageFault, // #PF
        _ => crate::TrapKind::Other,
    };
    let fault_addr = if vector == 14 {
        // SAFETY: reading CR2 is a side-effect-free MSR-like read; valid on #PF.
        unsafe { read_cr2() }
    } else {
        0
    };

    let info = crate::TrapInfo {
        kind,
        // cause = (vector number, 32-bit CPU error code), packed hi:lo.
        cause: (vector << 32) | error_code,
        fault_addr,
        pc: f.rip,
    };

    match crate::dispatch_trap(&info) {
        crate::TrapAction::Resume => {
            // #BP's saved RIP already points past int3 (see module header), so
            // `iretq` in __alltraps resumes the next instruction. Just return.
        }
        crate::TrapAction::Halt => super::halt(),
    }
}

/// Read CR2 (the linear address of the last page-fault). Intel SDM Vol.3A
/// §2.5 / §6.15 (#PF).
#[inline]
unsafe fn read_cr2() -> u64 {
    let cr2: u64;
    asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags));
    cr2
}

/// Entry address of the per-vector thunk for `vector` (0..256), read from the
/// `__trap_thunks` table emitted by the `global_asm!` above. Used by
/// `idt::init` to populate the gate descriptors.
pub(super) fn thunk(vector: usize) -> u64 {
    extern "C" {
        static __trap_thunks: [usize; 256];
    }
    // SAFETY: __trap_thunks is the 256-entry `.quad` table below; idt::init
    // only ever passes `vector` in 0..256, so the index is in bounds.
    unsafe { *(addr_of!(__trap_thunks) as *const usize).add(vector) as u64 }
}

/// Raise a breakpoint exception (`int3`, #BP, vector 3) from safe code.
///
/// Proves the take-trap -> Rust-dispatch -> resume path: the registered hook
/// prints and returns `TrapAction::Resume`, and because the CPU-saved RIP
/// already points past `int3`, execution continues at the next instruction.
/// Requires `super::install_traps()` to have run first.
pub fn breakpoint() {
    // (a) PRE: traps installed. POST: #BP taken, dispatched, (M1 policy) resumed.
    // (b) ABI: `int3` (0xCC). The handler runs on the current stack and may
    //     touch memory/serial, so NO nomem/nostack; flags survive via `iretq`.
    // (c) Tested by: kernel M1 sequence ("trap: breakpoint, resuming").
    unsafe { asm!("int3") }
}
