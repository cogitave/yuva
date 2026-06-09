#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! `tb-encode` -- the host-verifiable PURE bit-level encoders/validators of TABOS.
//!
//! This crate is the SINGLE SOURCE OF TRUTH for the *value computation* that
//! sits one millimetre in front of the kernel's silicon-`unsafe`: the bit
//! algebra that decides WHAT a VMX control word, an EPT/page-table entry, a TSS
//! descriptor base, or an IPC wire frame should be. The actual `unsafe`
//! `vmwrite`/`write_volatile`/asm that COMMITS that value to hardware stays in
//! [`tb-hal`](../tb_hal/index.html); `tb-hal` calls the functions here and keeps
//! the store next to the just-computed value, so the silicon side is
//! byte-identical to before this crate existed -- only now the value is computed
//! by provably-safe code.
//!
//! ## Why a separate crate (mirrors `tb-boot` / `tb-caps-core`)
//!
//! `#![no_std]` + `#![forbid(unsafe_code)]` + ZERO deps + ZERO asm, so it builds
//! for the HOST triple under plain `cargo` (the repo deliberately keeps
//! `-Zbuild-std` out of the global `.cargo/config.toml`). That is what lets
//! `cargo kani -p tb-encode` model-check the EXACT SAME encoders the kernel
//! runs, with NO model drift and WITHOUT dragging `tb-hal`'s `target_arch`
//! inline asm into CBMC.
//!
//! ## Modules
//!
//!  * [`vmx`] -- the control-MSR ADJUST gate (the #1 cause of silent VM-entry
//!    failure), the CR0/CR4 fixed-bit clamp, and the TSS-descriptor base decode.
//!  * [`paging`] -- the shared radix-512 page-table entry algebra
//!    (`make_entry`/`entry_addr`/`level_index`/`entry_is_valid` + the level
//!    shifts and the `[47:12]` address mask) plus the EPT and standard-paging
//!    leaf/non-leaf/EPTP entry encoders.
//!  * [`ipc_frame`] -- the mature 16-byte on-wire IPC [`MessageFrame`] codec
//!    (`encode`/`decode`, fail-closed on malformed input) and a fixed-capacity
//!    [`ipc_frame::BoundedRing`] with FIFO + capacity invariants.
//!  * [`route`] -- the M16 `model:`-scheme routing helpers lifted out of
//!    `tb-hal::infer`: the panic-free `model:<provider>/<path>` grammar parser
//!    (`route::parse_scheme`) and the longest-prefix-match routing decision
//!    (`route::longest_prefix_index`) over the in-kernel route-key literals.
//!
//! ## Verification
//!
//! The Kani harnesses live in `src/proofs.rs`, gated `#[cfg(kani)]` so a normal
//! `cargo build` / `cargo kbuild` never compiles them. They prove the
//! control-MSR adjust legality gate over ALL inputs, encode/decode round-trip
//! identity, total/fail-closed decoding, and the page-table/EPT entry bit
//! invariants. See `scripts/verify-encode.sh` (DoD marker `V1: kani-encoders OK`).

pub mod ipc_frame;
pub mod paging;
pub mod route;
pub mod vmx;

// The Kani proof harnesses. Gated on `cfg(kani)` (set ONLY under `cargo kani`)
// so a normal `cargo build` / `cargo kbuild` never compiles them; they run only
// in the CI Kani lane (`scripts/verify-encode.sh`).
#[cfg(kani)]
mod proofs;
