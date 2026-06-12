//! Axis-A nano-guest — the trivial dual-note PVH + tb-boot "signal-and-halt"
//! guest. See `bench/nano-guest/README.md` and `docs/BENCHMARKS.md` (axis A).
//!
//! This crate is a thin Rust shell around the single-source-of-truth assembly
//! in `bench/nano-guest/nano-guest.S`: it embeds that file verbatim via
//! `global_asm!(include_str!())` so the nightly build (`cargo nbuild --release`,
//! -Zbuild-std against ../../targets/x86_64-yuva-none.json) and the canonical
//! `clang`/`ld.lld` build (`build.sh`) produce the SAME machine code. The two
//! ELF entries (`pvh_start`, `tb_start`) and the two boot notes live entirely
//! in the assembly; the linker script `nano-guest.ld` lays them out at 1 MiB.
//!
//! The CI bench lane builds via `build.sh` (clang + ld.lld), which is immune to
//! the repo-root .cargo/config.toml linker-script inheritance that double-links
//! `kernel/linker/x86_64.ld` under `cargo nbuild` from this subdir. This crate
//! is kept as the equivalent nightly path + a compile check of the assembly.
//!
//! Framekernel note: this is NOT the `kernel`/`tb-hal` crate. It is a standalone
//! bench artifact in its own excluded workspace, so its hand assembly is allowed
//! and the "kernel crate has zero real `unsafe{}`" invariant is untouched. The
//! only Rust here is the freestanding shell (no `unsafe` blocks at all in this
//! file — the panic handler is safe, and `global_asm!` is a macro, not unsafe).

#![no_std]
#![no_main]
// The assembly opens with `.intel_syntax noprefix` so the SAME file also
// assembles under clang (`build.sh`), whose integrated assembler defaults to
// AT&T. Rust's `global_asm!` is already Intel, so it (harmlessly) flags the
// redundant directive via `bad_asm_style`; silence it so a `-D warnings` CI is
// happy without forking the source.
#![allow(bad_asm_style)]

use core::arch::global_asm;
use core::panic::PanicInfo;

// The nano-guest machine code: dual boot notes (.note.Xen PHYS32_ENTRY type 18
// + the .note.kboot brand note, name "YUVA" type 0x59550001 -- MIRRORS
// crates/brand, see the loud note in the .S) and the two entry stubs (`pvh_start` 32-bit
// PVH / `tb_start` 64-bit tb-boot). Each stub emits one COM1 (0x3f8) sentinel
// byte then parks; `tb_start` additionally latches tb-vmm's 0x510 BootReady
// clock. Byte-identical to the file `build.sh` assembles with clang.
global_asm!(include_str!("../nano-guest.S"));

/// A freestanding binary needs a panic handler, but the nano-guest never panics
/// (it executes only the hand-asm stubs, which never reach Rust code). If the
/// linker somehow routed here, park the CPU. No `unsafe`, no allocation.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
