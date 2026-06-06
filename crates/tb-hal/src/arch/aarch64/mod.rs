//! aarch64 backend for the `tb-hal` foundation crate.
//!
//! One of the two `#[cfg(target_arch)]` arms re-exported by `arch/mod.rs`. It
//! exposes exactly the three primitives the safe `tb-hal` public API
//! (`lib.rs`) delegates to on aarch64: [`serial_init`], [`serial_write_byte`]
//! and [`halt`]. (`serial_write_str` is composed in `lib.rs` from
//! `serial_write_byte`, so it is arch-independent.)
//!
//! Boot contract for the M0 QEMU `virt` first-light path (verified facts,
//! KERNEL-FOUNDATION-SPEC §2): the vCPU enters `_start` at **EL1h, MMU OFF,
//! DAIF masked**, with **x0 = FDT/DTB pointer** (AAPCS64 arg0 already).
//! `boot.rs` owns that entry; `serial.rs` owns the PL011 UART.

mod boot; // _start + EL1 vector table; pure side-effect (`global_asm!`) module.
mod serial; // PL011 @ 0x0900_0000 (QEMU `virt` UART0).

pub use serial::{serial_init, serial_write_byte};

// -- halt() -----------------------------------------------------------------
// (a) PRE : any state; called on the M0 happy path after the marker is flushed
//           and from the kernel #[panic_handler]. POST: never returns -- the
//           vCPU is parked in a low-power wait, re-parking on any wake event.
// (b) ABI : `wfi` clobbers nothing, touches no memory/stack, preserves NZCV.
// (c) TEST: scripts/run-aarch64.sh -- the kernel reaches here after printing
//           "hello from rust_main"; the runner times out and asserts the marker.
/// Halt the current vCPU forever (low-power wait loop).
pub fn halt() -> ! {
    loop {
        // SAFETY: `wfi` is an unprivileged hint with no memory or stack
        // effects; it is always legal at EL1 and merely suspends the core
        // until a wake event, after which we loop and re-park.
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack, preserves_flags));
        }
    }
}
