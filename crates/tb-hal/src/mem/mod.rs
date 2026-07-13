#![forbid(unsafe_code)]
//! `mem` -- the per-agent memory subsystem, factored into a substrate ENGINE and
//! an agent ORGAN along the seam `docs/proposals/boot-profiles.md` §3.4 draws
//! (Yuva-memory = the substrate-side retrieval/durability STORE; the tiers +
//! recall + learning above it = composable agent capabilities).
//!
//!   * [`engine`] -- the SUBSTRATE half: the tier-tagged durability seam, the
//!     RAM default, the M20 durable virtio-blk store, AND the M20
//!     `persist_selftest` that drives it directly. Depends on nothing in the
//!     organ; a substrate-profile boot exercises exactly this (M20 persist).
//!   * [`organ`] -- the AGENT half: the M13 [`MemSubstrate`] (T0..T4 tiers +
//!     recall/consolidation/learning) and the M22..M40 organ boot self-tests
//!     (its `selftests` child; the substrate M20 `persist_selftest` is NOT among
//!     them -- it lives on the engine). This is what boot-profiles stage B
//!     compiles out.
//!
//! This module is a THIN COORDINATOR: it wires the two halves and re-exports the
//! crate-facing surface (`crate::mem::{MemSubstrate, VirtioBlkStore, *_selftest}`
//! consumed by `caps.rs` + `verified_leaf.rs`) so those paths are byte-identical
//! across the split. `#![forbid(unsafe_code)]` here covers the whole subtree.
//!
//! The split is PURE CODE MOTION -- no organ/engine logic changed -- so it moves
//! zero marker bytes and cannot shift the M38 conduct head (SP#4). It only
//! establishes the boundary that lets stage B's `#[cfg(feature = "agent-organs")]`
//! sit on the `organ` module line below.

mod engine;
// stage-B seam: docs/proposals/boot-profiles.md §11 will prefix the next `mod`
// with `#[cfg(feature = "agent-organs")]` so a substrate-profile build compiles
// out the organ (and its `selftests` child) while the engine above stays linked.
// (No cfg here yet -- this landing is the factorization only.)
mod organ;

// --- crate-facing re-export surface (paths preserved byte-for-byte) -----------
// The ONLY external real-code consumers are `crate::caps` (MemSubstrate) and
// `crate::verified_leaf` (MemSubstrate + the self-tests); re-exported here so
// every existing `crate::mem::X` path resolves unchanged. `VirtioBlkStore` is
// deliberately NOT re-exported: its sole caller is now in-module in `engine` (the
// engine's M20 `persist_selftest`), so a `crate::mem::VirtioBlkStore` re-export
// would be dead. It stays `pub(crate)` in `engine`, reachable within the subsystem.
// The organ self-tests come up through `organ`; the substrate M20
// `persist_selftest` comes straight off `engine` (both resolve as `crate::mem::X`).
// M24: `mount_durable` (the durable-backing constructor) is re-exported so the
// durable-memory witness can attach a mounted virtio-blk store; the concrete
// `VirtioBlkStore` + the `BackingStore` trait stay in `engine` (the organ names
// only the trait via `super::engine`).
pub(crate) use engine::{mount_durable, persist_selftest};
pub(crate) use organ::{
    bakeoff_selftest, conductor_selftest, corpus_labeled_outcome_selftest,
    corpus_operator_turn_selftest, corpus_persist, corpus_selftest, exittel_selftest,
    exp_selftest, infer_local_wire_selftest, infer_wire_selftest, kan_selftest,
    m24_durable_mem_selftest, m33_persist_head,
    opcmd_selftest, opframe_selftest, prov_selftest, recall_selftest,
    xport_selftest, MemSubstrate,
};
