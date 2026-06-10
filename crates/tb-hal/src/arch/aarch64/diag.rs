//! aarch64 boot-path corruption diagnostics (case #65: the aL2.5 CI-only
//! per-binary-layout failure triage).
//!
//! Three deterministic failure modes appeared ONLY on `CARGO_INCREMENTAL=0`
//! builds of the aL2.5 chain (a layout-sensitive memory corruption expressed
//! around the M9 preemption-arming window). This module provides the probes
//! that DISCRIMINATE the candidate mechanisms without changing the healthy
//! path's behaviour:
//!
//!  * **Stack red-zones (probe P2)**: a small `0xA5A5_5A5A_DEAD_5AA5` pattern
//!    painted at the BOTTOM of the 16 KiB boot stack and the 16 KiB resident
//!    EL2-monitor stack (linker symbols `__boot_stack_bottom` /
//!    `__el2_stack_bottom`, `kernel/linker/aarch64.ld`). A breach means the
//!    stack grew down to within 64 bytes of its bound -- the overflow-victim
//!    chain (`ID_L1` page tables, the EL2 context cells, `BOOTED_AT_EL2`)
//!    starts right below. Checked on every timer tick (`dispatch_irq`) and at
//!    each milestone; the report is ONE-TIME latched so an IRQ storm cannot
//!    flood the serial log.
//!  * **`read_word`**: the single raw-load primitive `lib.rs`'s task-stack
//!    red-zone scan uses (the task stacks are painted in safe code -- they are
//!    `&mut [usize]` slices -- but the scan runs while another task owns them).
//!
//! All `unsafe` is confined here (framekernel rule); the public surface is
//! safe and is re-exported crate-internally via `arch/mod.rs`.

use core::arch::asm;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, Ordering};

/// The red-zone fill pattern: recognisable in any later corruption dump.
/// (`arch` is a private module of the crate, so nothing here leaks publicly.)
pub const REDZONE_PATTERN: usize = 0xA5A5_5A5A_DEAD_5AA5;
/// Red-zone size in `usize` words (64 bytes -- small enough never to trip on a
/// healthy run, large enough that a descending stack cannot step over it with
/// ordinary frame sizes).
pub const REDZONE_WORDS: usize = 8;

/// One-time latch: the boot-stack red-zone breach was already reported.
static BOOT_RZ_REPORTED: AtomicBool = AtomicBool::new(false);
/// One-time latch: the EL2-stack red-zone breach was already reported.
static EL2_RZ_REPORTED: AtomicBool = AtomicBool::new(false);

/// PC-relative address of `__boot_stack_bottom` (no memory access; valid with
/// the MMU off or on -- the kernel runs identity-mapped either way).
fn boot_stack_bottom() -> usize {
    let v: usize;
    // SAFETY: `adrp`/`add :lo12:` form the linker-symbol address with no memory
    // access; NZCV preserved.
    unsafe {
        asm!(
            "adrp {v}, __boot_stack_bottom",
            "add  {v}, {v}, :lo12:__boot_stack_bottom",
            v = out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    v
}

/// PC-relative address of `__el2_stack_bottom` (see [`boot_stack_bottom`]).
fn el2_stack_bottom() -> usize {
    let v: usize;
    // SAFETY: as `boot_stack_bottom`.
    unsafe {
        asm!(
            "adrp {v}, __el2_stack_bottom",
            "add  {v}, {v}, :lo12:__el2_stack_bottom",
            v = out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    v
}

/// Read one `usize` at `addr` (volatile, so the optimiser cannot elide or
/// reorder the diagnostic load). Crate-internal: `lib.rs` uses it ONLY against
/// addresses it derived from live `&'static mut [usize]` task stacks.
pub fn read_word(addr: usize) -> usize {
    // SAFETY: callers pass addresses inside statically-allocated, 'static
    // kernel stack arrays (painted by `task_create`) or the linker-placed
    // boot/EL2 stacks -- always mapped, aligned `usize` words.
    unsafe { read_volatile(addr as *const usize) }
}

/// Paint the boot-stack and EL2-stack red-zones. Called ONCE from `rust_main`
/// (via the `tb_hal::stack_redzone_init` facade) before the first timer tick.
pub fn redzone_init() {
    let boot = boot_stack_bottom();
    let el2 = el2_stack_bottom();
    let mut i = 0;
    while i < REDZONE_WORDS {
        // SAFETY: both zones are the lowest 64 bytes of linker-reserved 16 KiB
        // stack regions inside .bss; the boot SP is near the TOP of its stack
        // here and the EL2 stack's resident frames also live at its top, so
        // painting the bottoms touches no live data.
        unsafe {
            write_volatile((boot + i * core::mem::size_of::<usize>()) as *mut usize, REDZONE_PATTERN);
            write_volatile((el2 + i * core::mem::size_of::<usize>()) as *mut usize, REDZONE_PATTERN);
        }
        i += 1;
    }
}

/// Check the boot/EL2 stack red-zones; on the FIRST breach of each, print one
/// loud line with the zone name and the observed word, then never again (the
/// latch keeps an IRQ-storm from flooding the log). Cheap (16 loads) -- runs on
/// every timer tick from `dispatch_irq` and at each milestone checkpoint.
pub fn redzone_check_report() {
    check_zone(boot_stack_bottom(), "boot", &BOOT_RZ_REPORTED);
    check_zone(el2_stack_bottom(), "el2", &EL2_RZ_REPORTED);
}

/// DIAG (#65): scan a stack region upward from `bottom` and return the address
/// of the LOWEST word that is neither 0 (never touched -- .bss-zeroed) nor the
/// red-zone pattern: the deepest "dirty" word. A descending-stack high-water
/// leaves nonzero residue, so `result - bottom` approximates the stack's
/// remaining headroom in bytes; a ZEROED red-zone with a CLEAN (all-zero) gap
/// above it instead fingerprints a zero-writer running UP from below the
/// stack (e.g. an adjacent page-table zeroing overrun) -- the two candidate
/// writers the M8 breach must be discriminated between.
fn lowest_dirty_word(bottom: usize, top: usize) -> usize {
    let mut a = bottom;
    while a < top {
        let w = read_word(a);
        if w != 0 && w != REDZONE_PATTERN {
            return a;
        }
        a += core::mem::size_of::<usize>();
    }
    top
}

/// Bytes between the boot stack's bottom and its deepest dirty word -- the
/// measured remaining headroom (approximate: an all-zero frame is invisible).
pub fn boot_stack_headroom() -> u64 {
    let bottom = boot_stack_bottom();
    (lowest_dirty_word(bottom, bottom + 0x4000) - bottom) as u64
}

/// As [`boot_stack_headroom`], for the resident EL2-monitor stack.
pub fn el2_stack_headroom() -> u64 {
    let bottom = el2_stack_bottom();
    (lowest_dirty_word(bottom, bottom + 0x4000) - bottom) as u64
}

fn check_zone(base: usize, name: &str, latch: &AtomicBool) {
    if latch.load(Ordering::Relaxed) {
        return;
    }
    let mut i = 0;
    while i < REDZONE_WORDS {
        let w = read_word(base + i * core::mem::size_of::<usize>());
        if w != REDZONE_PATTERN {
            if !latch.swap(true, Ordering::AcqRel) {
                crate::serial_write_str("diag: stack red-zone breached: ");
                crate::serial_write_str(name);
                crate::serial_write_str(" word=");
                crate::diag_write_hex(w as u64);
                crate::serial_write_str(" off=");
                crate::diag_write_hex(i as u64);
                crate::serial_write_byte(b'\n');
            }
            return;
        }
        i += 1;
    }
}
