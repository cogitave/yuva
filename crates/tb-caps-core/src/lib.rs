#![no_std]
#![forbid(unsafe_code)]
//! `tb-caps-core` -- the host-verifiable capability CORE of TABOS M11.
//!
//! This crate is the SINGLE SOURCE OF TRUTH for the two pieces of the M11
//! capability machinery whose correctness M18's frozen boundary reduces to:
//!
//!   * [`Rights`] -- a 32-bit rights bitset whose ONLY rights-changing primitive
//!     is bitwise-AND ([`Rights::intersect`]) -> monotone attenuation BY
//!     CONSTRUCTION (no API can ever OR a right into an existing capability), and
//!   * [`CapTable`] -- a generation-checked, free-list-backed authority table of
//!     [`SlotCore`] slots, generic over the object payload `O`. Authority lives
//!     in the SLOT (not the [`Handle`]), so a forged integer cannot manufacture
//!     rights; the only meta-ops are NARROW (attenuate), MOVE (transfer) and
//!     REVOKE (bump the slot generation).
//!
//! `tb-hal` re-exports `Rights`/`Handle`/`SysStatus` verbatim and wraps
//! `CapTable<Rc<Object>>`, so the kernel and the Kani harnesses in
//! [`proofs`](crate) verify the EXACT SAME code -- ZERO model drift. The crate is
//! `#![no_std]` + `#![forbid(unsafe_code)]`; it pulls in `alloc` only for `Vec`.

// `alloc` is brought online by the final kernel binary's `#[global_allocator]`;
// this crate only names `Vec` from it. For the HOST build (`cargo build`/`cargo
// kani`) the platform `alloc` is linked normally.
extern crate alloc;

mod rights;
mod table;

pub use rights::Rights;
pub use table::{CapTable, Handle, SlotCore, SysStatus};

// The Kani proof harnesses (Tier-1 Rights algebra over the full u32 space,
// Tier-2 per-operation, Tier-3 inductive single-step no-widen + a bounded
// sequence cross-check). Gated on `cfg(kani)` so a normal `cargo build` /
// `cargo kbuild` never compiles them; they run only under `cargo kani` in CI.
#[cfg(kani)]
mod proofs;
