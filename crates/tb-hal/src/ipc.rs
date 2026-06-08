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
//! M14.1: a message may ALSO carry a variable-length BYTE payload -- a
//! kernel-heap [`alloc::boxed::Box<[u8]>`] bounce buffer (`Message::bytes`,
//! capped at [`MAX_PAYLOAD`]) filled by a sender-side `copy_from_user` and
//! drained by a receiver-side `copy_to_user`. THIS module stays
//! `#![forbid(unsafe_code)]`: the `Box<[u8]>` is safe heap (the same soundness
//! argument the `Rc`/`RefCell` rings already discharge); the ONLY new `unsafe`
//! -- the cross-address-space page-table walk + physical copy -- is confined to
//! the per-arch `crate::arch::{x86_64,aarch64}::uaccess` modules, reached here
//! only through the kernel facade (`crate::caps::HandleTable::chan_send_bytes` /
//! `chan_recv_bytes`). `None` bytes = the existing inline-scalar-only path.

use alloc::collections::VecDeque;
use alloc::rc::Rc;
use core::cell::{Cell, RefCell};

use alloc::boxed::Box;

use crate::caps::{Object, Rights};

/// M14.1: the maximum BYTE-payload length one message may carry -- one page.
/// A send over this bound is rejected `SysStatus::Denied` (anything larger is
/// explicitly the M15 shared-block path); the bound caps worst-case kernel-heap
/// pressure at `MAX_PAYLOAD * ring_depth` and matches seL4's one-page IPC buffer.
pub const MAX_PAYLOAD: usize = 4096;

/// One in-transit message: an inline scalar `payload` (the "bytes" at the M14
/// inline-ABI), an OPTIONAL variable-length BYTE payload (M14.1, the kernel-heap
/// bounce buffer), plus an OPTIONAL parked capability -- the moved cap's object
/// identity (`Rc<Object>`) and its `Rights`, riding from sender to receiver while
/// NO table holds a handle to it (the `Rc` alone keeps the object alive).
pub struct Message {
    /// The inline scalar payload.
    pub payload: u64,
    /// M14.1: the optional kernel-owned BYTE-payload bounce buffer (safe heap;
    /// `<= MAX_PAYLOAD` bytes), filled by the sender's `copy_from_user` and
    /// drained by the receiver's `copy_to_user`. `None` = no byte payload (the
    /// existing inline-scalar-only message).
    pub bytes: Option<Box<[u8]>>,
    /// The 0-or-1 parked, in-transit capability (`None` for a bytes-only message).
    pub cap: Option<(Rc<Object>, Rights)>,
}

impl Message {
    /// The length of the carried BYTE payload (`0` when there is none). Used by
    /// the receiver to peek the head's size BEFORE popping, so a too-small
    /// destination buffer can fail-closed without discarding the message
    /// (Zircon `zx_channel_read` BUFFER_TOO_SMALL-without-discard semantics).
    pub fn byte_len(&self) -> usize {
        match &self.bytes {
            Some(b) => b.len(),
            None => 0,
        }
    }
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
