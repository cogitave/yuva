//! Architecture dispatch for `tb-hal`.
//!
//! `lib.rs` calls `arch::serial_init()`, `arch::serial_write_byte(b)` and
//! `arch::halt()`. Those three symbols are re-exported here from whichever
//! per-arch submodule matches the build target. The submodules
//! (`arch/x86_64/{mod,boot,serial}.rs`, `arch/aarch64/{mod,boot,serial}.rs`)
//! contain ALL of the crate's `unsafe` + assembly and are emitted separately;
//! THIS file only wires them up.
//!
//! INTERNAL CONTRACT each `arch/<arch>/mod.rs` must satisfy (see BUILD.md):
//!   * `pub fn serial_init();`
//!   * `pub fn serial_write_byte(b: u8);`
//!   * `pub fn halt() -> !;`
//!   * plus the boot entry (`_start`, via `global_asm!`) and the
//!     XEN_ELFNOTE_PHYS32_ENTRY note (x86_64 only), which the linker keeps.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use self::x86_64::{halt, serial_init, serial_write_byte};

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use self::aarch64::{halt, serial_init, serial_write_byte};

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!(
    "tb-hal supports only x86_64 and aarch64 (the two Firecracker-class arches); \
     build with --target targets/x86_64-tabos-none.json or \
     targets/aarch64-tabos-none.json"
);
