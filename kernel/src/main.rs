//! TABOS kernel entry shim (M0).
//!
//! Framekernel rule: the kernel crate is otherwise safe Rust
//! (`#![forbid(unsafe_code)]` on every non-shim module added later). THIS file is
//! the single permitted exception. It contains no `unsafe {}` blocks; the only
//! reason crate-level `forbid(unsafe_code)` is not applied here is that
//! `#[unsafe(no_mangle)]` is itself an *unsafe attribute* (it tells the linker to
//! expose `rust_main` un-mangled for tb-hal's `_start` to `call`/`b` into), and
//! the `unsafe_code` lint flags it. All real unsafe + assembly is confined to
//! tb-hal (KERNEL-FOUNDATION-SPEC.md §1).

#![no_std]
#![no_main]

use core::panic::PanicInfo;

/// Boot entry. tb-hal's per-arch `_start` jumps here after it has set up a
/// stack, zeroed `.bss`, and placed the boot-info pointer in arg0 (SysV `rdi`
/// on x86_64 = `hvm_start_info` phys addr; AAPCS64 `x0` on aarch64 = FDT blob).
#[unsafe(no_mangle)]
pub extern "C" fn rust_main(boot_info: usize) -> ! {
    // M0 ignores boot_info; M1+ will parse hvm_start_info / the FDT.
    let _ = boot_info;
    tb_hal::serial_init();
    tb_hal::serial_write_str("hello from rust_main\n");
    tb_hal::halt()
}

/// Panic handler: best-effort marker over serial, then halt forever.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    tb_hal::serial_write_str("panic\n");
    tb_hal::halt()
}
