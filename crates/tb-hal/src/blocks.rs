#![forbid(unsafe_code)]
//! M15 -- the shared-memory BLOCK core (100% SAFE Rust; the body behind every
//! [`crate::caps::ObjKind::Block`] capability).
//!
//! Structural model = a seL4 frame / Zircon VMO: a [`Block`] OWNS one or more M6
//! physical frames (PAs from [`crate::frame_alloc`]) and is held behind an
//! `Rc<Block>` so EVERY member agent's [`crate::caps::HandleTable`] holds an
//! `Rc` clone of the SAME core -- the EXACT [`crate::ipc::Channel`] rendezvous
//! pattern. Unlike an M14 channel (which COPIES/MOVES a payload), a Block is
//! MAPPED into MULTIPLE agent roots at once via the already-green M10
//! [`crate::map_in_space`], so every member sees the SAME physical bytes.
//!
//! TWO SHARING PLANES:
//!   * FRAME plane -- the ordered `frames` PAs mapped into N roots: the literal
//!     true-sharing demonstration (a write by one member is physically visible
//!     to all others under their own roots).
//!   * RECORD plane -- a kernel-mediated CAS/versioned append-only store
//!     ([`Block::cas_write`]/[`Block::read_latest`]): the session blackboard's
//!     "update-once-visible-everywhere" with bi-temporal supersedes links. It is
//!     trivially atomic w.r.t. preemption because dispatch runs single-core with
//!     interrupts masked (the same RefCell soundness argument the green M13
//!     `mem.rs` / M14 `ipc.rs` already discharge); SMP CAS + watch-wakeups are
//!     the additive Step-2 layer.
//!
//! ZERO unsafe: `Vec` + `Rc` + `RefCell` + `Cell` are all safe heap, and the
//! frame zeroing reuses the already-audited safe [`crate::addr_store_load`]
//! identity facade. The VA->PA mapping reuses M10's existing
//! [`crate::map_in_space`], whose unsafe is untouched -- so M15 adds NO new
//! unsafe.
//!
//! M15.1 -- UNMAP + frame reclamation. A block is no longer pinned for the whole
//! kernel session: the OWNER-only [`crate::agent_block_unmap`] facade tears down
//! every live mapping (clearing the leaf PTEs + a LOCAL TLB invalidate in each
//! member root), POISONS this shared core ([`Block::kill`] sets [`Block::is_dead`]),
//! and only THEN returns the backing frames to [`crate::frame_free`]. Because the
//! core is shared by `Rc` across every member table, the poison flag is the
//! cross-table revoke: once dead, EVERY outstanding handle's block op fails closed
//! ([`crate::caps::SysStatus::Stale`]) -- the exact `Rc<Channel>` peer-closed
//! idiom M14 already uses. A frame is reclaimed ONLY after no live mapping (all
//! leaves cleared) and no live handle (core poisoned) can still reach it, so a
//! freed-then-reused frame can never sit behind a stale PTE = no cross-agent
//! use-after-free.

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};

/// One RECORD-plane blackboard version (append-only, bi-temporal). A losing CAS
/// keeps BOTH the old and the new `Rec` linked by `supersedes` -- the M13
/// bi-temporal pattern reused at record granularity.
pub struct Rec {
    /// The record slot offset/key this version writes.
    pub off: u64,
    /// The value published at this version.
    pub val: u64,
    /// The monotonic version number stamped by [`Block::cas_write`].
    pub version: u64,
    /// The version this one superseded (`0` = first write to the slot).
    #[allow(dead_code)] // bi-temporal back-link, surfaced by the M17 consolidator
    pub supersedes: u64,
}

/// A pinned, kernel-owned shared segment. Held behind `Rc<Block>` so every
/// member's table holds an `Rc` clone of the SAME core (the `ipc::Channel`
/// pattern). All bookkeeping is interior-mutable SAFE heap.
pub struct Block {
    /// FRAME plane: the ordered M6 frame PAs == the shared bytes.
    frames: Vec<u64>,
    /// `== frames.len()`; the segment is `n_pages * 4096` bytes.
    n_pages: usize,
    /// Live mappings `(root_pa, base_va, writable)` -- the refcount/detach
    /// bookkeeping (a re-map of the same root+va appends; the most recent wins).
    members: RefCell<Vec<(u64, u64, bool)>>,
    /// The monotonic version word for the whole block (the seqlock/CAS counter).
    seq: Cell<u64>,
    /// RECORD plane: the append-only, bi-temporal versioned slots.
    records: RefCell<Vec<Rec>>,
    /// M15.1 POISON flag. `false` while live; set ONCE by [`Block::kill`] when the
    /// owner unmaps + reclaims the backing frames. Because every member table
    /// holds an `Rc` clone of THIS one core, flipping it makes EVERY outstanding
    /// handle's block op fail closed (the cross-table revoke), so no stale handle
    /// can reach a reclaimed frame. Monotonic (never cleared) -- a reclaimed block
    /// stays dead, so a late access can never resurrect freed frames.
    dead: Cell<bool>,
}

impl Block {
    /// Allocate `n_pages` M6 frames, ZERO each (no tenant-byte leak -- the
    /// seL4/Zircon zero-on-handout discipline, done through the safe
    /// [`crate::addr_store_load`] identity facade), and record their PAs. Held
    /// behind `Rc<Block>`. Fail-closed -> `None` on physical-frame OOM, freeing
    /// any partial allocation first so no frame is leaked.
    pub fn create(n_pages: usize) -> Option<Rc<Block>> {
        let mut frames: Vec<u64> = Vec::new();
        let mut i = 0;
        while i < n_pages {
            match crate::frame_alloc() {
                Some(pa) => {
                    // Zero the whole 4 KiB frame through its identity-mapped
                    // kernel address (every M6 frame is inside the M3 identity
                    // region, RW in the live kernel half). No raw deref here --
                    // the existing audited facade owns the only unsafe.
                    let mut off = 0u64;
                    while off < 4096 {
                        let _ = crate::addr_store_load(pa + off, 0);
                        off += 8;
                    }
                    frames.push(pa);
                }
                None => {
                    // OOM: return every frame already taken, then fail closed.
                    let mut k = 0;
                    while k < frames.len() {
                        let _ = crate::frame_free(frames[k]);
                        k += 1;
                    }
                    return None;
                }
            }
            i += 1;
        }
        Some(Rc::new(Block {
            frames,
            n_pages,
            members: RefCell::new(Vec::new()),
            seq: Cell::new(0),
            records: RefCell::new(Vec::new()),
            dead: Cell::new(false),
        }))
    }

    /// The ordered shared frame PAs (the map facade maps each into a member root).
    pub fn frames(&self) -> &[u64] {
        &self.frames
    }

    /// The page count (`frames.len()`).
    pub fn n_pages(&self) -> usize {
        self.n_pages
    }

    /// Record a live mapping for refcount/detach bookkeeping (safe `RefCell`).
    /// A no-op on a dead block (defence-in-depth: the map facade already gates on
    /// [`Block::is_dead`] via `block_of`, so this is never reached for one).
    pub fn record_member(&self, root_pa: u64, base_va: u64, writable: bool) {
        if self.dead.get() {
            return;
        }
        self.members.borrow_mut().push((root_pa, base_va, writable));
    }

    /// M15.1: `true` once this block has been unmapped + reclaimed by its owner.
    /// Every member table holds an `Rc` clone of THIS core, so a `true` here makes
    /// every outstanding handle's block op fail closed -- the cross-table revoke.
    pub fn is_dead(&self) -> bool {
        self.dead.get()
    }

    /// M15.1: a SNAPSHOT (clone) of the recorded live mappings `(root_pa, base_va,
    /// writable)`, so the unmap facade can tear down each member root's leaf PTEs
    /// WITHOUT holding the `members` borrow across the arch page-table walk.
    pub fn members_snapshot(&self) -> Vec<(u64, u64, bool)> {
        self.members.borrow().clone()
    }

    /// M15.1: POISON this shared core (set [`Block::is_dead`]) and drop the member
    /// list. Called by the owner-unmap facade AFTER every leaf PTE is torn down
    /// and BEFORE the backing frames are returned to the allocator, so no live
    /// handle can reach a frame that is about to be reclaimed. Idempotent.
    pub fn kill(&self) {
        self.dead.set(true);
        self.members.borrow_mut().clear();
    }

    /// The `writable` flag of the most recent mapping at `(root_pa, base_va)`, or
    /// `None` if no such mapping was recorded -- lets the self-test OBSERVE that
    /// a READ-only handle's write-requesting map was downgraded to RO (the
    /// portable `min(request, rights)` cross-check, since CR0.WP=0 makes the
    /// hardware RO-write-fault unobservable kernel-side on x86_64).
    pub fn member_writable(&self, root_pa: u64, base_va: u64) -> Option<bool> {
        let members = self.members.borrow();
        let mut idx = members.len();
        while idx > 0 {
            idx -= 1;
            let (r, v, w) = members[idx];
            if r == root_pa && v == base_va {
                return Some(w);
            }
        }
        None
    }

    /// The latest version stamped for slot `off` (`0` = never written).
    fn latest_version(&self, off: u64) -> u64 {
        let records = self.records.borrow();
        let mut ver = 0u64;
        let mut i = 0;
        while i < records.len() {
            if records[i].off == off && records[i].version > ver {
                ver = records[i].version;
            }
            i += 1;
        }
        ver
    }

    /// RECORD-plane compare-and-swap: if the latest version of slot `off` equals
    /// `expected`, APPEND a superseding [`Rec`] (keeping both versions
    /// bi-temporally), bump the block `seq`, and return `Some(new_version)`;
    /// otherwise `None` (the CAS lost -> the caller surfaces `WouldBlock`).
    /// Atomic w.r.t. preemption (single-core, interrupts masked).
    pub fn cas_write(&self, off: u64, val: u64, expected: u64) -> Option<u64> {
        if self.dead.get() {
            return None; // reclaimed block: fail closed (dispatch maps it to Stale)
        }
        let cur = self.latest_version(off);
        if cur != expected {
            return None;
        }
        let new_ver = self.seq.get() + 1;
        self.seq.set(new_ver);
        self.records.borrow_mut().push(Rec {
            off,
            val,
            version: new_ver,
            supersedes: cur,
        });
        Some(new_ver)
    }

    /// RECORD-plane read: the value of the latest version of slot `off`, or
    /// `None` if the slot has never been written.
    pub fn read_latest(&self, off: u64) -> Option<u64> {
        if self.dead.get() {
            return None; // reclaimed block: fail closed (dispatch maps it to Stale)
        }
        let records = self.records.borrow();
        let mut ver = 0u64;
        let mut out: Option<u64> = None;
        let mut i = 0;
        while i < records.len() {
            if records[i].off == off && records[i].version >= ver {
                ver = records[i].version;
                out = Some(records[i].val);
            }
            i += 1;
        }
        out
    }
}
