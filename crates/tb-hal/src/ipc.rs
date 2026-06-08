#![forbid(unsafe_code)]
//! M14 -- the inter-agent IPC channel core (100% SAFE Rust; the body behind every
//! agent's born-with [`crate::caps::ObjKind::Channel`] endpoint).
//!
//! Structural model = a Zircon channel: two single-owner ENDPOINTS share one
//! kernel-owned [`Channel`] core; each direction is its own ORDERED, BOUNDED FIFO
//! [`Ring`] (`push_back`/`pop_front`), so A->B and B->A never interleave ("one
//! stream breaking does not affect another"). A message MOVES a capability:
//! handles are consumed on write (parked into the ring as an `Rc<Object>` + the
//! `Rights` riding intact) and re-slotted on read -- the M11 `transfer_to` move
//! DECOMPOSED ACROSS TIME via the shared `Rc<Channel>`. Peer-closed is
//! fire-and-forget (Zircon): closing an endpoint flips its `open` flag but leaves
//! the peer's queued backlog intact -- the peer drains, THEN sees `PeerClosed`.
//!
//! ZERO unsafe: `VecDeque` + `RefCell` + `Cell` + `Rc` are all safe heap -- the
//! identical soundness argument the green M13 `mem.rs` already discharges (a
//! payload reached through a shared `Rc<Object>`, sound because `dispatch` runs
//! single-core with interrupts masked, so no reentrant borrow). No atomics, no
//! lock, no `&'static mut` (single-core buys nothing from a crossbeam ring).
//!
//! The variable-length BYTE payload (via `copy_to_user`/`copy_from_user` across
//! the two address spaces) is the ONLY part of the ROADMAP M14 surface that adds
//! `unsafe`; it is DELIBERATELY DEFERRED. The marker self-test rides the inline-
//! scalar payload (`Message::payload`) with the capability moved by handle, at
//! zero new unsafe.

use alloc::collections::VecDeque;
use alloc::rc::Rc;
use core::cell::{Cell, RefCell};

use crate::caps::{Object, Rights};

/// One in-transit message: an inline scalar `payload` (the "bytes" at the M14
/// inline-ABI) plus an OPTIONAL parked capability -- the moved cap's object
/// identity (`Rc<Object>`) and its `Rights`, riding from sender to receiver while
/// NO table holds a handle to it (the `Rc` alone keeps the object alive).
pub struct Message {
    /// The inline scalar payload.
    pub payload: u64,
    /// The 0-or-1 parked, in-transit capability (`None` for a bytes-only message).
    pub cap: Option<(Rc<Object>, Rights)>,
}

/// A single per-direction FIFO bounded at `cap` (the backpressure depth). A
/// `push_back` into a full ring is rejected fail-closed by the caller
/// (`SysStatus::WouldBlock`) -- never unbounded buffering.
pub struct Ring {
    /// The ordered queue (`push_back` to send, `pop_front` to receive).
    pub q: VecDeque<Message>,
    /// The capacity bound (backpressure threshold).
    pub cap: usize,
}

/// The kernel-owned channel core both endpoints share through an `Rc` clone.
/// `dir[s]` is side `s`'s OUTBOX (= side `1-s`'s inbox); `open[s]` is `true`
/// while endpoint `s` still has a live handle (the peer-closed flag).
pub struct Channel {
    dir: [RefCell<Ring>; 2],
    open: [Cell<bool>; 2],
}

/// Create a fresh channel core with two empty rings, each bounded at `bound`.
/// Both endpoints start open; the two minted endpoint objects hold an `Rc` clone
/// of the returned core (so the two per-principal tables rendezvous on it).
pub fn create(bound: usize) -> Rc<Channel> {
    Rc::new(Channel {
        dir: [
            RefCell::new(Ring {
                q: VecDeque::with_capacity(bound),
                cap: bound,
            }),
            RefCell::new(Ring {
                q: VecDeque::with_capacity(bound),
                cap: bound,
            }),
        ],
        open: [Cell::new(true), Cell::new(true)],
    })
}

impl Channel {
    /// The OUTBOX of side `side` (`dir[side]`): a send pushes here.
    pub fn outbox(&self, side: u8) -> &RefCell<Ring> {
        &self.dir[side as usize]
    }

    /// The INBOX of side `side` (`dir[1-side]`): a receive pops here.
    pub fn inbox(&self, side: u8) -> &RefCell<Ring> {
        &self.dir[1 - side as usize]
    }

    /// `true` iff the PEER of side `side` still holds a live endpoint handle.
    pub fn peer_open(&self, side: u8) -> bool {
        self.open[1 - side as usize].get()
    }

    /// Flip side `side`'s endpoint to closed (fire-and-forget; the peer's queued
    /// backlog is left intact for it to drain before it observes `PeerClosed`).
    pub fn close_side(&self, side: u8) {
        self.open[side as usize].set(false);
    }
}
