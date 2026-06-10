//! aarch64 boot-path corruption diagnostics (case #65: the aL2.5 CI-only
//! per-binary-layout failure triage).
//!
//! Three deterministic failure modes appeared ONLY on `CARGO_INCREMENTAL=0`
//! builds of the aL2.5 chain (a layout-sensitive memory corruption expressed
//! around the M9 preemption-arming window). This module provides the probes
//! that DISCRIMINATE the candidate mechanisms without changing the healthy
//! path's behaviour:
//!
//!  * **Stack red-zones (probe P2, now a PERMANENT check)**: a small
//!    `0xA5A5_5A5A_DEAD_5AA5` pattern painted at the BOTTOM of the 64 KiB boot
//!    stack and the 32 KiB resident EL2-monitor stack (linker symbols
//!    `__boot_stack_bottom` / `__el2_stack_bottom`,
//!    `kernel/linker/aarch64.ld`). A breach means the stack grew down to
//!    within 64 bytes of its bound. Checked on every timer tick
//!    (`dispatch_irq`) and at each milestone; the report is ONE-TIME latched
//!    so an IRQ storm cannot flood the serial log.
//!  * **Sacrificial stack guards (#65 fix, H1b)**: the linker now reserves a
//!    4 KiB canary-painted guard region BELOW each stack
//!    (`__boot_stack_guard_bottom` / `__el2_stack_guard_bottom`), so an
//!    overflow that crosses a stack's bottom lands in dead memory instead of
//!    live `.bss` statics (the confirmed root cause of the three CI-only
//!    aL2.5 failure modes: the `CARGO_INCREMENTAL=0` symbol order parked live
//!    statics right below `__boot_stack_bottom` and the -O0 M5 heap call
//!    chain ran SP up to ~0x280 bytes below it). The guards are scanned with
//!    the same one-time-latched, silent-when-healthy discipline; the
//!    run-aarch64.sh harness turns any breach line into a RED verdict.
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
/// One-time latch: the boot-stack GUARD breach was already reported.
static BOOT_GUARD_REPORTED: AtomicBool = AtomicBool::new(false);
/// One-time latch: the EL2-stack GUARD breach was already reported.
static EL2_GUARD_REPORTED: AtomicBool = AtomicBool::new(false);

/// PC-relative address of a linker symbol (no memory access; valid with the
/// MMU off or on -- the kernel runs identity-mapped either way).
macro_rules! linker_symbol_fn {
    ($(#[$doc:meta])* $name:ident, $sym:literal) => {
        $(#[$doc])*
        fn $name() -> usize {
            let v: usize;
            // SAFETY: `adrp`/`add :lo12:` form the linker-symbol address with
            // no memory access; NZCV preserved.
            unsafe {
                asm!(
                    concat!("adrp {v}, ", $sym),
                    concat!("add  {v}, {v}, :lo12:", $sym),
                    v = out(reg) v,
                    options(nomem, nostack, preserves_flags),
                );
            }
            v
        }
    };
}

linker_symbol_fn!(
    /// Top of the boot stack (the initial SP_EL1).
    boot_stack_top,
    "__boot_stack_top"
);
linker_symbol_fn!(
    /// Top of the resident EL2-monitor stack (SP_EL2).
    el2_stack_top,
    "__el2_stack_top"
);
linker_symbol_fn!(
    /// Bottom of the 4 KiB sacrificial guard BELOW the boot stack (#65 fix);
    /// its top is `__boot_stack_bottom`.
    boot_stack_guard_bottom,
    "__boot_stack_guard_bottom"
);
linker_symbol_fn!(
    /// Bottom of the 4 KiB sacrificial guard BELOW the EL2 stack (#65 fix);
    /// its top is `__el2_stack_bottom`.
    el2_stack_guard_bottom,
    "__el2_stack_guard_bottom"
);

linker_symbol_fn!(
    /// Bottom of the boot stack (also the TOP of its sacrificial guard).
    boot_stack_bottom,
    "__boot_stack_bottom"
);
linker_symbol_fn!(
    /// Bottom of the EL2-monitor stack (also the TOP of its guard).
    el2_stack_bottom,
    "__el2_stack_bottom"
);

/// Read one `usize` at `addr` (volatile, so the optimiser cannot elide or
/// reorder the diagnostic load). Crate-internal: `lib.rs` uses it ONLY against
/// addresses it derived from live `&'static mut [usize]` task stacks.
pub fn read_word(addr: usize) -> usize {
    // SAFETY: callers pass addresses inside statically-allocated, 'static
    // kernel stack arrays (painted by `task_create`) or the linker-placed
    // boot/EL2 stacks -- always mapped, aligned `usize` words.
    unsafe { read_volatile(addr as *const usize) }
}

/// Paint `[bottom, top)` with the red-zone pattern, one `usize` word at a time.
///
/// # Safety
/// `bottom..top` must be a linker-reserved, identity-mapped region holding no
/// live data (a stack's unused bottom words or a sacrificial guard region).
unsafe fn paint_range(bottom: usize, top: usize) {
    let mut a = bottom;
    while a < top {
        // SAFETY: per the function contract, `a` is inside a linker-reserved
        // .bss region with no live data; aligned `usize` stores cannot fault.
        unsafe { write_volatile(a as *mut usize, REDZONE_PATTERN) };
        a += core::mem::size_of::<usize>();
    }
}

/// Paint the boot-stack and EL2-stack red-zones AND the two 4 KiB sacrificial
/// guard regions below them (#65 fix). Called ONCE from `rust_main` (via the
/// `tb_hal::stack_redzone_init` facade) before the first timer tick.
pub fn redzone_init() {
    let boot = boot_stack_bottom();
    let el2 = el2_stack_bottom();
    let word = core::mem::size_of::<usize>();
    // SAFETY: the red-zones are the lowest 64 bytes of the linker-reserved
    // 64 KiB / 32 KiB stack regions inside .bss; the boot SP is near the TOP
    // of its stack here and the EL2 stack's resident frames also live at its
    // top, so painting the bottoms touches no live data. The guard regions
    // ([__*_stack_guard_bottom, __*_stack_bottom)) are linker-reserved dead
    // memory nothing legitimate ever addresses.
    unsafe {
        paint_range(boot, boot + REDZONE_WORDS * word);
        paint_range(el2, el2 + REDZONE_WORDS * word);
        paint_range(boot_stack_guard_bottom(), boot);
        paint_range(el2_stack_guard_bottom(), el2);
    }
}

/// Check the boot/EL2 stack red-zones AND the sacrificial guard regions below
/// them; on the FIRST breach of each, print one loud line with the zone name
/// and the observed word, then never again (the latch keeps an IRQ-storm from
/// flooding the log). Runs on every timer tick from `dispatch_irq` and at each
/// milestone checkpoint: 16 loads for the red-zones plus a 1024-word sweep
/// over the two 4 KiB guards -- trivially cheap against a ~1 ms tick, and the
/// permanent price of never again letting a stack overflow stomp .bss
/// silently (#65).
pub fn redzone_check_report() {
    check_zone(boot_stack_bottom(), "boot", &BOOT_RZ_REPORTED);
    check_zone(el2_stack_bottom(), "el2", &EL2_RZ_REPORTED);
    check_guard(
        boot_stack_guard_bottom(),
        boot_stack_bottom(),
        "boot",
        &BOOT_GUARD_REPORTED,
    );
    check_guard(
        el2_stack_guard_bottom(),
        el2_stack_bottom(),
        "el2",
        &EL2_GUARD_REPORTED,
    );
}

/// Scan a full sacrificial guard region `[bottom, top)` for any word that no
/// longer holds the canary pattern; report the FIRST breach once, with the
/// observed word and its depth in bytes BELOW the stack bottom (= `top`).
fn check_guard(bottom: usize, top: usize, name: &str, latch: &AtomicBool) {
    if latch.load(Ordering::Relaxed) {
        return;
    }
    // Scan downward from the stack bottom so the reported word is the breach
    // CLOSEST to the stack -- the deepest legitimate-looking frame word.
    let mut a = top;
    while a > bottom {
        a -= core::mem::size_of::<usize>();
        let w = read_word(a);
        if w != REDZONE_PATTERN {
            if !latch.swap(true, Ordering::AcqRel) {
                crate::serial_write_str("diag: stack guard breached: ");
                crate::serial_write_str(name);
                crate::serial_write_str(" word=");
                crate::diag_write_hex(w as u64);
                crate::serial_write_str(" depth=");
                crate::diag_write_hex((top - a) as u64);
                crate::serial_write_byte(b'\n');
            }
            return;
        }
    }
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
/// Bounds come from the linker symbols, so the figure tracks the real stack
/// size (64 KiB since the #65 fix).
pub fn boot_stack_headroom() -> u64 {
    let bottom = boot_stack_bottom();
    (lowest_dirty_word(bottom, boot_stack_top()) - bottom) as u64
}

/// As [`boot_stack_headroom`], for the resident EL2-monitor stack (32 KiB).
pub fn el2_stack_headroom() -> u64 {
    let bottom = el2_stack_bottom();
    (lowest_dirty_word(bottom, el2_stack_top()) - bottom) as u64
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
