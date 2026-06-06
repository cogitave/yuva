//! TABOS kernel entry shim (M1: traps).
//!
//! Framekernel rule: the kernel crate is otherwise safe Rust. THIS file is the
//! single permitted exception. It contains no `unsafe {}` blocks; the only
//! reason crate-level `forbid(unsafe_code)` is not applied here is that
//! `#[unsafe(no_mangle)]` is itself an *unsafe attribute* (it tells the linker
//! to expose `rust_main` un-mangled for tb-hal's `_start` to `call`/`b` into),
//! and the `unsafe_code` lint flags it. All real unsafe + assembly is confined
//! to tb-hal (KERNEL-FOUNDATION-SPEC.md §1).
//!
//! M1 proves the trap path: install CPU exception handling, register a SAFE
//! dispatch policy hook (defined below, in this `forbid`-class crate), take a
//! synchronous breakpoint, dispatch into Rust, and RESUME past it — then emit
//! the DoD marker `"M1: traps OK"`.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use tb_hal::{TrapAction, TrapInfo, TrapKind};

/// Boot entry. tb-hal's per-arch `_start` jumps here after it has set up a
/// stack, zeroed `.bss`, and placed the boot-info pointer in arg0 (SysV `rdi`
/// on x86_64 = `hvm_start_info` phys addr; AAPCS64 `x0` on aarch64 = FDT blob).
#[unsafe(no_mangle)]
pub extern "C" fn rust_main(boot_info: usize) -> ! {
    // M0/M1 ignore boot_info; M2+ will parse hvm_start_info / the FDT.
    let _ = boot_info;

    // --- M0 proof (kept verbatim): serial first-light ----------------------
    tb_hal::serial_init();
    tb_hal::serial_write_str("hello from rust_main\n");

    // --- M1: install traps and register the safe dispatch policy -----------
    // Order per spec: install the CPU vectors first, THEN publish the hook.
    tb_hal::install_traps();
    tb_hal::set_trap_hook(trap_hook);

    // --- M1 test sequence: take a breakpoint and resume past it ------------
    tb_hal::serial_write_str("trap-test: triggering breakpoint\n");
    tb_hal::breakpoint(); // int3 (x86_64) / brk #0 (aarch64); hook -> Resume
    tb_hal::serial_write_str("trap-test: resumed past breakpoint\n");

    // Reaching here proves take-trap -> Rust-dispatch -> resume works.
    tb_hal::serial_write_str("M1: traps OK\n"); // <-- the M1 DoD marker
    tb_hal::halt()
}

/// Safe trap-dispatch policy hook (the demonstration of M1: policy lives in
/// this `forbid(unsafe_code)`-class crate, not in tb-hal's raw entry asm).
///
/// tb-hal's per-arch `extern "C"` handler builds this [`TrapInfo`] from the raw
/// `TrapFrame` and calls us. A [`TrapKind::Breakpoint`] is resumed (prove the
/// round-trip); any other trap is reported and the core is halted.
fn trap_hook(info: &TrapInfo) -> TrapAction {
    match info.kind {
        TrapKind::Breakpoint => {
            tb_hal::serial_write_str("trap: breakpoint, resuming\n");
            TrapAction::Resume
        }
        _ => {
            // Fatal fault: report the cause/faulting-address/pc, then halt.
            tb_hal::serial_write_str("trap: fatal fault, halting\n");
            tb_hal::serial_write_str("  cause=");
            write_hex_u64(info.cause);
            tb_hal::serial_write_str(" fault_addr=");
            write_hex_u64(info.fault_addr);
            tb_hal::serial_write_str(" pc=");
            write_hex_u64(info.pc);
            tb_hal::serial_write_byte(b'\n');
            TrapAction::Halt
        }
    }
}

/// Write a `u64` as a fixed-width 16-digit `0x…` hex string over serial.
///
/// Pure safe Rust (no `core::fmt`, no allocation): just shifts nibbles out of
/// the value and emits ASCII via the tb-hal byte writer.
fn write_hex_u64(value: u64) {
    tb_hal::serial_write_str("0x");
    let mut shift: i32 = 60;
    while shift >= 0 {
        let nibble = ((value >> shift) & 0xf) as u8;
        let c = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
        tb_hal::serial_write_byte(c);
        shift -= 4;
    }
}

/// Panic handler: best-effort marker over serial, then halt forever.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    tb_hal::serial_write_str("panic\n");
    tb_hal::halt()
}
