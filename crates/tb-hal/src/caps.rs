#![forbid(unsafe_code)]
//! M11 -- the agent-native, non-POSIX capability ABI core (100% SAFE Rust).
//!
//! Every kernel object is reached ONLY through an unforgeable, generation-
//! checked, rights-masked [`Handle`] in a per-principal [`HandleTable`];
//! unprivileged (ring3/EL0) code reaches the kernel through ONE numbered,
//! capability-checked [`dispatch`]er returning a CLOSED [`SysStatus`] -- zero
//! ambient authority (no fd / errno / ioctl / path). This is deliberately the
//! largest pure-safe subsystem: the ENTIRE handle table, rights algebra, object
//! registry and dispatch logic live here under `#![forbid(unsafe_code)]`. The
//! ONLY new `unsafe` M11 adds is the per-arch register-lift shim that reads a
//! numbered syscall's args out of the trap frame (in `arch::*::user`).
//!
//! DESIGN (validated against seL4 CDT, Zircon handles, generational arenas):
//!   * `Handle = (generation:u32) << 32 | slot:u32`, one opaque `u64`. The slot
//!     indexes the table; the generation is matched against the slot's live
//!     generation on every resolve -> O(1) use-after-revoke. Authority lives in
//!     the SLOT, not the handle, so a forged integer cannot manufacture rights
//!     (it hits the wrong generation -> `Stale`, or an empty/vacant slot ->
//!     `BadCap`/`Stale`). `Handle(0)` is the reserved invalid NULL.
//!   * [`Rights`] is a 32-bit bitset; the ONLY rights-changing primitive is
//!     bitwise-AND ([`Rights::intersect`]) -> monotonic attenuation BY
//!     CONSTRUCTION (no API can ever OR a right into an existing capability).
//!   * Meta-ops only NARROW (attenuate), MOVE (transfer) or REVOKE (bump the
//!     slot generation). v2 ships PER-SLOT generation revoke (sound + O(1));
//!     transitive/recursive revoke (the seL4 Capability Derivation Tree) and an
//!     O(1) per-object epoch are noted refinements -- the `Handle` layout is
//!     forward-compatible with both, so they land at M14 with no ABI break.
//!
//! THE INVARIANT this module is a PROOF of (M18's frozen boundary reduces to it):
//! across every sequence of {mint, dup, narrow, transfer, revoke}, the rights of
//! any handle a principal can resolve are a SUBSET of the rights of the
//! capability it was derived from (no operation ascends the (Rights, subset)
//! order), AND [`dispatch`]/resolve returns `Ok` ONLY for a handle whose
//! generation equals the live, OCCUPIED slot's generation.

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

/// An unforgeable, generation-tagged reference into a per-principal
/// [`HandleTable`]: `(generation:u32) << 32 | slot:u32`, one opaque `u64`.
/// Process-local and meaningless in any other principal's table (Zircon model).
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Handle(u64);

impl Handle {
    /// Bit width of the slot field (the low half of the handle).
    const SLOT_BITS: u32 = 32;

    /// The reserved invalid handle. Generation 0 is never issued, so a zeroed
    /// argument register can never resolve to a live capability.
    pub const NULL: Handle = Handle(0);

    /// Construct a handle from a `generation` and `slot` index.
    #[inline]
    pub const fn new(generation: u32, slot: u32) -> Self {
        Handle(((generation as u64) << Self::SLOT_BITS) | slot as u64)
    }

    /// Rebuild a handle from a raw `u64` (e.g. one lifted out of a trap frame).
    /// The value is UNTRUSTED -- it is re-validated field-by-field on every
    /// [`HandleTable::live`]-backed resolve.
    #[inline]
    pub const fn from_raw(value: u64) -> Self {
        Handle(value)
    }

    /// The raw `u64` encoding, for stashing in a register or atomic.
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// The generation field (high 32 bits).
    #[inline]
    pub const fn generation(self) -> u32 {
        (self.0 >> Self::SLOT_BITS) as u32
    }

    /// The slot index (low 32 bits).
    #[inline]
    pub const fn slot(self) -> u32 {
        self.0 as u32
    }
}

/// A 32-bit rights bitset: structural rights plus the agent-semantic rights the
/// later milestones gate on. The ONLY narrowing primitive is [`Rights::intersect`]
/// (bitwise AND), so rights can only ever be DROPPED -- never amplified.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Rights(u32);

impl Rights {
    /// The empty rights set (authorises nothing; satisfies a no-right method).
    pub const NONE: Rights = Rights(0);
    /// Read / inspect the object.
    pub const READ: Rights = Rights(1 << 0);
    /// Mutate the object.
    pub const WRITE: Rights = Rights(1 << 1);
    /// Move this capability into another principal's table.
    pub const TRANSFER: Rights = Rights(1 << 2);
    /// Duplicate this capability (mint a sibling handle to the same object).
    pub const DUP: Rights = Rights(1 << 3);
    /// Revoke this capability (bump the slot generation).
    pub const REVOKE: Rights = Rights(1 << 4);
    /// Invoke a model inference session (M16).
    pub const INVOKE_MODEL: Rights = Rights(1 << 5);
    /// Spawn an agent (M12).
    pub const SPAWN_AGENT: Rights = Rights(1 << 6);
    /// Write procedural memory (M13).
    pub const WRITE_PROCEDURAL: Rights = Rights(1 << 7);
    /// Recall from memory (M13).
    pub const RECALL: Rights = Rights(1 << 8);
    /// Consolidate memory (M17).
    pub const CONSOLIDATE: Rights = Rights(1 << 9);
    /// Emit an externally-visible effect (gated by human authorization).
    pub const EMIT_EXTERNAL: Rights = Rights(1 << 10);
    /// Delegate a slice of a budget to a child (M12).
    pub const DELEGATE_BUDGET: Rights = Rights(1 << 11);

    /// The raw bits of this rights set.
    #[inline]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Build a rights set from raw bits (used to interpret a NARROW mask; the
    /// mask can only ever DROP bits via [`Rights::intersect`], never amplify).
    #[inline]
    pub const fn from_bits(bits: u32) -> Rights {
        Rights(bits)
    }

    /// The union of two rights sets. Used only to BUILD an authority a principal
    /// already holds -- never to widen an existing capability.
    #[inline]
    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }

    /// Monotonic attenuation: the intersection of two rights sets. The result is
    /// ALWAYS a subset of both operands (`(a & m)` is a subset of `a`) -- this
    /// is the one rights-changing primitive, so narrowing can never amplify.
    #[inline]
    pub const fn intersect(self, mask: Rights) -> Rights {
        Rights(self.0 & mask.0)
    }

    /// `true` iff `self` carries every right in `need` (the dispatch gate).
    #[inline]
    pub const fn contains(self, need: Rights) -> bool {
        (self.0 & need.0) == need.0
    }

    /// `true` iff every right in `self` is also in `sup` -- the attenuation
    /// invariant predicate the proof discharges.
    #[inline]
    pub const fn is_subset_of(self, sup: Rights) -> bool {
        (self.0 & sup.0) == self.0
    }
}

/// The CLOSED result status of every capability operation -- a total Rust enum,
/// NOT a negative errno. An unrepresentable error is a compile error.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum SysStatus {
    /// The operation succeeded.
    Ok = 0,
    /// The handle does not name a slot in this table (out of range / never
    /// allocated) -- not even a stale one.
    BadCap = 1,
    /// The method number is not part of the closed method set.
    BadMethod = 2,
    /// The capability is live but lacks the right the method requires.
    Denied = 3,
    /// The handle's generation does not match the live slot, or the slot is
    /// vacant (use-after-revoke / use-after-transfer) -- O(1) detection.
    Stale = 4,
    /// The operation would block (reserved for M14 channels).
    WouldBlock = 5,
    /// Out of memory while performing the operation.
    NoMem = 6,
    /// The table (or object registry) is at capacity.
    ObjFull = 7,
    /// M14: the channel's peer endpoint has been closed -- a `send` to a closed
    /// peer, or a `recv` on an inbox that is empty AND whose peer has closed (the
    /// backlog is drained first, THEN this surfaces). Kept LAST so the closed
    /// status surface stays total.
    PeerClosed = 8,
}

/// The closed set of kernel object kinds. Identity-only at M11; per-subsystem
/// payload is attached by the milestone that introduces each kind.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ObjKind {
    /// An agent process (M12).
    Agent,
    /// A model inference session (M16).
    ModelSession,
    /// A memory home / namespace root (M13).
    MemoryHome,
    /// A single memory record (M13).
    MemoryRecord,
    /// A compute / token budget (M12).
    Budget,
    /// An IPC channel endpoint (M14).
    Channel,
    /// A procedural skill (M15).
    Skill,
    /// A capability namespace (M14).
    Namespace,
    /// An untyped / test object with no subsystem payload yet.
    Generic,
    /// M15: a shared-memory block -- one or more pinned M6 frames mapped into
    /// MULTIPLE agent roots at once (the session blackboard's backing object).
    /// APPENDED after `Generic` so every prior `#[repr(u32)]` discriminant (which
    /// `M_OBJECT_INSPECT` returns raw) stays stable. Distinct from `Skill` (the
    /// T4 procedural-memory kind), which is NOT a shared-memory object.
    Block,
}

/// A kernel object: identity (its [`ObjKind`]) plus, in later milestones, its
/// per-subsystem payload. Held behind an [`Rc`] so the object lives while any
/// handle references it and is freed when the last handle is closed / revoked /
/// transferred out (Zircon refcount semantics).
pub struct Object {
    /// The kind tag of this object.
    pub kind: ObjKind,
    /// M13: the optional per-agent tiered memory substrate. Present ONLY on a
    /// born-with [`ObjKind::MemoryHome`] (one substrate per home = the
    /// `memory:private/<agent>` namespace); `None` for identity-only objects.
    /// Interior-mutable (safe `RefCell`) so [`dispatch`] reaches `&mut` through a
    /// shared `Rc<Object>`; sound because M13 dispatch runs single-core with
    /// interrupts masked (no reentrant borrow).
    mem: Option<RefCell<crate::mem::MemSubstrate>>,
    /// M13: an inline scalar payload. A copy-on-retrieve [`ObjKind::MemoryRecord`]
    /// carries the recalled record id here; `0` for objects without one.
    scalar: u64,
    /// M14: the optional IPC endpoint body. Present ONLY on an
    /// [`ObjKind::Channel`] endpoint minted by [`HandleTable::mint_channel_endpoint`]:
    /// an `Rc` clone of the shared [`crate::ipc::Channel`] core plus this
    /// endpoint's side (`0` or `1`); `None` for identity-only objects (including
    /// the M12 bootstrap-channel stub). The two endpoint objects of one channel
    /// hold an `Rc` clone of the SAME core, so the two per-principal tables stay
    /// disjoint yet rendezvous on it.
    chan: Option<(Rc<crate::ipc::Channel>, u8)>,
    /// M15: the optional SHARED-MEMORY block body. Present ONLY on an
    /// [`ObjKind::Block`] minted by [`HandleTable::mint_block`]: an `Rc` clone of
    /// the shared [`crate::blocks::Block`] core (its pinned M6 frames + the
    /// RECORD-plane CAS store); `None` for identity-only objects. EVERY member's
    /// table holds an `Rc` clone of the SAME core, so mapping it into N roots
    /// makes the SAME physical bytes appear in N address spaces (true sharing).
    block: Option<Rc<crate::blocks::Block>>,
    /// M16: the optional bound INFERENCE session body. Present ONLY on an
    /// [`ObjKind::ModelSession`] minted by [`HandleTable::mint_model_session`]:
    /// the router-resolved backend + the pinned [`crate::infer::ModelId`];
    /// `None` for identity-only objects. OWNED INLINE (single-owner, the M13
    /// `mem` ownership precedent -- a session is not shared across two tables,
    /// so no `Rc`). `dispatch` reaches it by cloning the shared `Rc<Object>`,
    /// reading the bound backend, and invoking it -- the backend identity stays
    /// hidden from the agent (the LLM-agnostic contract).
    session: Option<crate::infer::ModelSession>,
}

/// The neutral, fully-owned syscall descriptor the per-arch register-lift shim
/// builds from the trap frame: a method selector, the target capability, and up
/// to four inline scalar args. Pointer-free at M11 (buffers arrive with M14
/// channels), so the dispatch surface is trivially analysable.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SyscallArgs {
    /// The numbered method selector.
    pub method: u32,
    /// The target capability handle (resolved against the CALLER's table).
    pub handle: Handle,
    /// Inline scalar arguments.
    pub args: [u64; 4],
}

impl SyscallArgs {
    /// Build a descriptor for `method` on `handle` with all inline args zero.
    pub fn call(method: u32, handle: Handle) -> Self {
        SyscallArgs {
            method,
            handle,
            args: [0; 4],
        }
    }
}

/// The closed, typed result a [`dispatch`] returns: a [`SysStatus`] plus one
/// scalar (e.g. a freshly-minted handle's raw value, or an object-kind tag).
/// Never an fd, never a path, never an errno.
#[derive(Clone, Copy)]
pub struct SysReturn {
    /// The closed status.
    pub status: SysStatus,
    /// The single scalar return value (meaningful only when `status == Ok`).
    pub value: u64,
}

impl SysReturn {
    /// A success result carrying `value`.
    pub fn ok(value: u64) -> Self {
        SysReturn {
            status: SysStatus::Ok,
            value,
        }
    }

    /// A failure result with `status` and a zero value.
    pub fn err(status: SysStatus) -> Self {
        SysReturn { status, value: 0 }
    }

    /// A result carrying `status` with a zero value (for status-only ops).
    pub fn status(status: SysStatus) -> Self {
        SysReturn { status, value: 0 }
    }
}

// ---------------------------------------------------------------------------
// The closed numbered method set. Meta-ops (the capability algebra itself) sit
// in [0, 16); agent-semantic verbs (rights-checked stubs at M11, real bodies in
// M12+) sit at [16, ..). The space is deliberately sparse so M12/M13/M14 add
// method BODIES, not new ABI.
// ---------------------------------------------------------------------------

/// Inspect an object's kind (needs READ).
pub const M_OBJECT_INSPECT: u32 = 0;
/// Duplicate a capability (needs DUP).
pub const M_HANDLE_DUP: u32 = 1;
/// Narrow (attenuate) a capability's rights (needs no right -- weakening your
/// own authority is always permitted). The mask is `args[0]`.
pub const M_HANDLE_NARROW: u32 = 2;
/// Move a capability into another principal's table (needs TRANSFER).
pub const M_HANDLE_TRANSFER: u32 = 3;
/// Revoke a capability, bumping the slot generation (needs REVOKE).
pub const M_HANDLE_REVOKE: u32 = 4;
/// Close one handle (needs no right -- closing your own handle is allowed).
pub const M_HANDLE_CLOSE: u32 = 5;
/// Spawn an agent (needs SPAWN_AGENT; body lands M12).
pub const M_AGENT_SPAWN: u32 = 16;
/// Invoke a model session (needs INVOKE_MODEL; body lands M16).
pub const M_MODEL_INVOKE: u32 = 17;
/// Write procedural memory (needs WRITE_PROCEDURAL; body lands M13).
pub const M_MEM_WRITE_PROC: u32 = 18;
/// Recall from memory (needs RECALL; body lands M13).
pub const M_MEM_RECALL: u32 = 19;
/// Consolidate memory (needs CONSOLIDATE; body lands M17).
pub const M_MEM_CONSOLIDATE: u32 = 20;
/// Emit an external effect (needs EMIT_EXTERNAL; body lands with the keyring).
pub const M_EMIT_EXTERNAL: u32 = 21;
/// Delegate a budget slice (needs DELEGATE_BUDGET; body lands M12).
pub const M_BUDGET_DELEGATE: u32 = 22;
/// M13: write episodic/semantic memory (needs WRITE; body lands M13). KEPT
/// distinct from [`M_MEM_WRITE_PROC`] (=18, WRITE_PROCEDURAL) so the privileged
/// T4 procedural write preserves the CoALA risk asymmetry (lands M18).
pub const M_MEM_WRITE: u32 = 23;
/// M13: read a memory record by id -- instant read-your-writes (needs READ).
pub const M_MEM_READ: u32 = 24;
/// M14: send a message on a channel endpoint (needs WRITE on the endpoint).
/// `args[0]` = inline scalar payload; `args[1]` = raw handle of an optional
/// capability to MOVE (0 / [`Handle::NULL`] = bytes-only). The carried cap must
/// hold [`Rights::TRANSFER`]; `args[2..3]` reserved for the deferred user buffer.
pub const M_CHAN_SEND: u32 = 25;
/// M14: receive a message on a channel endpoint (needs READ on the endpoint).
/// Returns the raw handle freshly installed for any MOVED capability (`0` if the
/// message carried none); the inline payload is surfaced kernel-side via a richer
/// facade tuple (and, later, `copy_to_user`).
pub const M_CHAN_RECV: u32 = 26;
/// M14: close this channel endpoint (needs no right -- closing your own endpoint
/// is always allowed). Flips the peer-closed flag; the peer drains its backlog
/// first, then observes [`SysStatus::PeerClosed`].
pub const M_CHAN_CLOSE: u32 = 27;
/// M15: MAP a shared block into the CALLER's address space (needs READ; the
/// page WRITE bit is granted only if the handle ALSO holds WRITE, i.e.
/// `writable = want && rights.contains(WRITE)`). ADDRESS-SPACE-dependent, so the
/// BODY rides the kernel facade [`crate::agent_block_map`] (dispatch holds only
/// `&mut HandleTable`, not the `AddressSpace`); the number stays registered for
/// the future EL0 syscall gate that DOES know the current agent's space.
pub const M_BLOCK_MAP: u32 = 28;
/// M15: voluntary member detach (needs no right). DEFERRED -- no unmap primitive
/// exists yet (blocks are pinned for the kernel-session lifetime); the number is
/// reserved so the closed method space stays stable.
pub const M_BLOCK_UNMAP: u32 = 29;
/// M15: RECORD-plane CAS/versioned write on the blackboard (needs WRITE).
/// `args[0]`=slot off, `args[1]`=value, `args[2]`=expected version.
pub const M_BLOCK_WRITE: u32 = 30;
/// M15: RECORD-plane read-latest on the blackboard (needs READ). `args[0]`=off.
pub const M_BLOCK_READ: u32 = 31;

/// Map a method number to the single right it requires, or `None` for an
/// unknown method (-> [`SysStatus::BadMethod`]). This closes the method space.
fn required_right(method: u32) -> Option<Rights> {
    Some(match method {
        M_OBJECT_INSPECT => Rights::READ,
        M_HANDLE_DUP => Rights::DUP,
        M_HANDLE_NARROW => Rights::NONE,
        M_HANDLE_TRANSFER => Rights::TRANSFER,
        M_HANDLE_REVOKE => Rights::REVOKE,
        M_HANDLE_CLOSE => Rights::NONE,
        M_AGENT_SPAWN => Rights::SPAWN_AGENT,
        M_MODEL_INVOKE => Rights::INVOKE_MODEL,
        M_MEM_WRITE_PROC => Rights::WRITE_PROCEDURAL,
        M_MEM_RECALL => Rights::RECALL,
        M_MEM_CONSOLIDATE => Rights::CONSOLIDATE,
        M_MEM_WRITE => Rights::WRITE,
        M_MEM_READ => Rights::READ,
        M_CHAN_SEND => Rights::WRITE,
        M_CHAN_RECV => Rights::READ,
        M_CHAN_CLOSE => Rights::NONE,
        M_BLOCK_MAP => Rights::READ,
        M_BLOCK_UNMAP => Rights::NONE,
        M_BLOCK_WRITE => Rights::WRITE,
        M_BLOCK_READ => Rights::READ,
        M_EMIT_EXTERNAL => Rights::EMIT_EXTERNAL,
        M_BUDGET_DELEGATE => Rights::DELEGATE_BUDGET,
        _ => return None,
    })
}

/// One table slot: a generation, the rights mask, and the object. An OCCUPIED
/// slot has `object.is_some()`; a vacant/revoked slot has `object == None`, and
/// any handle to it resolves [`SysStatus::Stale`].
struct Slot {
    generation: u32,
    rights: Rights,
    object: Option<Rc<Object>>,
}

/// The per-principal handle table -- the unit of authority. Heap-backed; a LIFO
/// free list reuses revoked slots (their generation already bumped, so prior
/// handles stay `Stale`). `cap` bounds the table fail-closed (`ObjFull`).
pub struct HandleTable {
    slots: Vec<Slot>,
    free: Vec<u32>,
    cap: usize,
}

impl HandleTable {
    /// A new empty table that will hold at most `cap` live capabilities.
    pub fn with_capacity(cap: usize) -> Self {
        HandleTable {
            slots: Vec::new(),
            free: Vec::new(),
            cap,
        }
    }

    /// Resolve `h` to its live slot index, fail-closed. `BadCap` if the slot is
    /// out of range; `Stale` if the slot is vacant (use-after-revoke) or its
    /// generation does not match. The occupancy check is INDEPENDENT of the
    /// generation match, so a forged handle whose generation happens to equal a
    /// vacant slot's can never resolve `Ok`.
    fn live(&self, h: Handle) -> Result<usize, SysStatus> {
        let i = h.slot() as usize;
        let s = self.slots.get(i).ok_or(SysStatus::BadCap)?;
        if s.object.is_none() {
            return Err(SysStatus::Stale);
        }
        if s.generation != h.generation() {
            return Err(SysStatus::Stale);
        }
        Ok(i)
    }

    /// Place `object` with `rights` into a free or fresh slot, returning its
    /// handle, or `None` when the table is at `cap` (`ObjFull`).
    fn alloc(&mut self, rights: Rights, object: Rc<Object>) -> Option<Handle> {
        if let Some(idx) = self.free.pop() {
            let s = &mut self.slots[idx as usize];
            // The generation was already bumped when this slot was freed.
            s.rights = rights;
            s.object = Some(object);
            return Some(Handle::new(s.generation, idx));
        }
        if self.slots.len() >= self.cap {
            return None;
        }
        let idx = self.slots.len() as u32;
        self.slots.push(Slot {
            generation: 1,
            rights,
            object: Some(object),
        });
        Some(Handle::new(1, idx))
    }

    /// Vacate slot `i`: drop the object and bump the generation so every extant
    /// handle resolves `Stale`. On generation overflow the slot is RETIRED (not
    /// returned to the free list), so a security generation is never silently
    /// wrapped.
    fn free_slot(&mut self, i: usize) {
        let s = &mut self.slots[i];
        s.object = None;
        match s.generation.checked_add(1) {
            Some(g) => {
                s.generation = g;
                self.free.push(i as u32);
            }
            None => { /* retire: overflowed generation, never reuse this slot */ }
        }
    }

    /// Mint a brand-new object of `kind` and its first handle with `rights`.
    /// `None` when the table is full (`ObjFull`).
    pub fn mint(&mut self, kind: ObjKind, rights: Rights) -> Option<Handle> {
        self.alloc(
            rights,
            Rc::new(Object {
                kind,
                mem: None,
                scalar: 0,
                chan: None,
                block: None,
                session: None,
            }),
        )
    }

    /// M13: mint a born-with [`ObjKind::MemoryHome`] whose body is a fresh, empty
    /// per-agent [`crate::mem::MemSubstrate`] (the `memory:private/<agent>`
    /// namespace -- one substrate per home). `None` when the table is at `cap`
    /// (`ObjFull`). The substrate is the M11-chokepoint-only door to memory:
    /// dispatch reaches it ONLY by resolving this handle.
    pub fn mint_memory_home(&mut self, rights: Rights) -> Option<Handle> {
        self.alloc(
            rights,
            Rc::new(Object {
                kind: ObjKind::MemoryHome,
                mem: Some(RefCell::new(crate::mem::MemSubstrate::new())),
                scalar: 0,
                chan: None,
                block: None,
                session: None,
            }),
        )
    }

    /// M13: mint a copy-on-retrieve [`ObjKind::MemoryRecord`] working copy
    /// carrying `scalar` (the recalled record id) with READ rights. `None` on
    /// `ObjFull` (the caller maps it to a closed status; never a panic).
    fn mint_record(&mut self, scalar: u64) -> Option<Handle> {
        self.alloc(
            Rights::READ,
            Rc::new(Object {
                kind: ObjKind::MemoryRecord,
                mem: None,
                scalar,
                chan: None,
                block: None,
                session: None,
            }),
        )
    }

    /// M14: mint an [`ObjKind::Channel`] ENDPOINT carrying a real IPC body -- an
    /// `Rc` clone of the shared [`crate::ipc::Channel`] core plus this endpoint's
    /// `side` (`0` or `1`) -- with `rights`. The peer endpoint (the other side,
    /// over the same core) is minted into the OTHER principal's table; the two
    /// rendezvous on the `Rc`. `None` on `ObjFull`.
    pub(crate) fn mint_channel_endpoint(
        &mut self,
        rights: Rights,
        chan: Rc<crate::ipc::Channel>,
        side: u8,
    ) -> Option<Handle> {
        self.alloc(
            rights,
            Rc::new(Object {
                kind: ObjKind::Channel,
                mem: None,
                scalar: 0,
                chan: Some((chan, side)),
                block: None,
                session: None,
            }),
        )
    }

    /// M15: mint an [`ObjKind::Block`] capability carrying a real shared-memory
    /// body -- an `Rc` clone of the shared [`crate::blocks::Block`] core -- with
    /// `rights`. Each member agent gets its OWN handle (over the same core) into
    /// THEIR table; all members rendezvous on the `Rc`, so the one segment's
    /// frames map into each member root separately (true sharing). `None` on
    /// `ObjFull`.
    pub(crate) fn mint_block(
        &mut self,
        rights: Rights,
        blk: Rc<crate::blocks::Block>,
    ) -> Option<Handle> {
        self.alloc(
            rights,
            Rc::new(Object {
                kind: ObjKind::Block,
                mem: None,
                scalar: 0,
                chan: None,
                block: Some(blk),
                session: None,
            }),
        )
    }

    /// M16: mint an [`ObjKind::ModelSession`] carrying its router-bound inference
    /// body (single-owner, OWNED inline like the M13 `MemSubstrate` -- no `Rc`).
    /// The session is minted by the kernel facade `agent_model_open` (the
    /// `mint_channel_endpoint`/`mint_block` precedent), reached thereafter ONLY
    /// through its capability at the M11 chokepoint (`M_MODEL_INVOKE`). `None` on
    /// `ObjFull`.
    pub(crate) fn mint_model_session(
        &mut self,
        rights: Rights,
        sess: crate::infer::ModelSession,
    ) -> Option<Handle> {
        self.alloc(
            rights,
            Rc::new(Object {
                kind: ObjKind::ModelSession,
                mem: None,
                scalar: 0,
                chan: None,
                block: None,
                session: Some(sess),
            }),
        )
    }

    /// M15: resolve `h` to its block body for the map facade. `BadCap`/`Stale`
    /// from the fail-closed [`HandleTable::live`] resolve; `BadCap` when the live
    /// object carries no block payload (a non-block cap presented to a block
    /// method). Returns the slot's `Rights` (so the facade re-enforces the
    /// single-sourced `required_right(M_BLOCK_MAP)==READ` gate + `min(request,
    /// rights)`) plus an `Rc` clone of the shared core.
    pub(crate) fn block_of(
        &self,
        h: Handle,
    ) -> Result<(Rights, Rc<crate::blocks::Block>), SysStatus> {
        let i = self.live(h)?;
        let o = self.slots[i].object.clone().ok_or(SysStatus::Stale)?;
        match &o.block {
            Some(b) => Ok((self.slots[i].rights, b.clone())),
            None => Err(SysStatus::BadCap),
        }
    }

    /// The rights currently attached to `h`, or `None` if it does not resolve.
    pub fn rights_of(&self, h: Handle) -> Option<Rights> {
        self.live(h).ok().map(|i| self.slots[i].rights)
    }

    /// Duplicate `h`: a sibling handle to the SAME object with the SAME rights.
    /// `None` if `h` does not resolve or the table is full.
    pub fn dup(&mut self, h: Handle) -> Option<Handle> {
        let i = self.live(h).ok()?;
        let rights = self.slots[i].rights;
        let object = self.slots[i].object.clone()?;
        self.alloc(rights, object)
    }

    /// Narrow (attenuate) `h`: a new handle to the same object whose rights are
    /// `old & mask` -- ALWAYS a subset of `old`, by construction. `None` if `h`
    /// does not resolve or the table is full.
    pub fn narrow(&mut self, h: Handle, mask: Rights) -> Option<Handle> {
        let i = self.live(h).ok()?;
        let rights = self.slots[i].rights.intersect(mask);
        let object = self.slots[i].object.clone()?;
        self.alloc(rights, object)
    }

    /// Per-slot generation revoke of `h`: `Ok` and the slot is vacated (every
    /// extant handle to it now resolves `Stale`, O(1)); otherwise the resolve
    /// error. NOTE: this is the privileged MECHANISM; the REVOKE-right gate is
    /// enforced for unprivileged callers by [`dispatch`].
    pub fn revoke(&mut self, h: Handle) -> SysStatus {
        match self.live(h) {
            Ok(i) => {
                self.free_slot(i);
                SysStatus::Ok
            }
            Err(e) => e,
        }
    }

    /// Close one handle. At M11 (per-slot revoke) this is identical to
    /// [`HandleTable::revoke`]; it needs no right (closing your own handle is
    /// always allowed).
    pub fn close(&mut self, h: Handle) -> SysStatus {
        self.revoke(h)
    }

    /// Transfer (MOVE) `h` into `dst`: mint a fresh handle to the same object,
    /// with the same rights, in `dst`, then vacate the source slot. `None`
    /// (leaving the source intact) if `h` does not resolve or `dst` is full --
    /// the object is never lost. The raw handle value is NEVER reused across
    /// tables; the receiver gets a new slot + generation.
    pub fn transfer_to(&mut self, h: Handle, dst: &mut HandleTable) -> Option<Handle> {
        let i = self.live(h).ok()?;
        let rights = self.slots[i].rights;
        let object = self.slots[i].object.clone()?;
        // ATOMIC: attach into `dst` FIRST; only vacate the source AFTER it lands,
        // so a full `dst` never strands the object (M11 all-or-nothing preserved).
        let moved = dst.attach((object, rights))?;
        self.free_slot(i);
        Some(moved)
    }

    /// M14 -- the SEND half of [`HandleTable::transfer_to`], split across an IPC
    /// ring: resolve `h` (fail-closed `BadCap`/`Stale`), clone its object +
    /// rights OUT, then `free_slot` so the capability goes STALE in THIS table
    /// (Zircon "handles are consumed on write"). The returned `(Rc<Object>,
    /// Rights)` is parked in the message; while parked NO table holds a handle --
    /// the `Rc` alone keeps the object alive. The caller MUST confirm the outbox
    /// has space BEFORE calling this, so a `WouldBlock` send never detaches.
    pub(crate) fn detach(&mut self, h: Handle) -> Result<(Rc<Object>, Rights), SysStatus> {
        let i = self.live(h)?;
        let rights = self.slots[i].rights;
        let object = self.slots[i].object.clone().ok_or(SysStatus::Stale)?;
        self.free_slot(i);
        Ok((object, rights))
    }

    /// M14 -- the RECV half of [`HandleTable::transfer_to`]: install a parked,
    /// in-transit capability into THIS table, yielding a fresh slot + generation
    /// (the raw handle value is never reused across tables). Object identity (the
    /// `Rc`) and `rights` ride intact. `None` on `ObjFull`.
    pub(crate) fn attach(&mut self, parked: (Rc<Object>, Rights)) -> Option<Handle> {
        self.alloc(parked.1, parked.0)
    }

    /// M14 -- the RECV body shared by [`dispatch`] and the kernel-side facade:
    /// pop one message from `ep`'s INBOX (drop the ring borrow before touching
    /// the table) and `attach` any carried capability. Returns `(status, inline
    /// payload, moved-handle-raw)` -- `WouldBlock` on an empty-but-open inbox,
    /// `PeerClosed` on empty-and-peer-closed. The endpoint `Rc<Channel>` is
    /// cloned OUT of the slot first so the table `&mut` never aliases the ring
    /// borrow (single-core, interrupts masked -> no reentrant borrow).
    pub(crate) fn chan_recv_body(&mut self, ep: Handle) -> (SysStatus, u64, u64) {
        let i = match self.live(ep) {
            Ok(i) => i,
            Err(e) => return (e, 0, 0),
        };
        let ep_obj = match self.slots[i].object.clone() {
            Some(o) => o,
            None => return (SysStatus::Stale, 0, 0),
        };
        let (chan, side) = match &ep_obj.chan {
            Some((c, s)) => (c.clone(), *s),
            None => return (SysStatus::BadCap, 0, 0),
        };
        let msg = chan.inbox(side).borrow_mut().q.pop_front();
        match msg {
            None => {
                if chan.peer_open(side) {
                    (SysStatus::WouldBlock, 0, 0)
                } else {
                    (SysStatus::PeerClosed, 0, 0)
                }
            }
            Some(m) => {
                let payload = m.payload;
                match m.cap {
                    None => (SysStatus::Ok, payload, 0),
                    Some(parked) => match self.attach(parked) {
                        Some(h) => (SysStatus::Ok, payload, h.raw()),
                        // Receiver table full: the cap cannot be re-slotted. The
                        // self-test never hits this (table cap 16, few handles).
                        None => (SysStatus::ObjFull, payload, 0),
                    },
                }
            }
        }
    }

    /// M14 -- the kernel-side RECV entry: apply the same READ gate [`dispatch`]
    /// applies, then run [`HandleTable::chan_recv_body`]. Lets a facade surface
    /// BOTH the inline payload AND the moved handle (the single-scalar
    /// [`SysReturn`] dispatch path can only carry the handle).
    pub(crate) fn chan_recv(&mut self, ep: Handle) -> (SysStatus, u64, u64) {
        let i = match self.live(ep) {
            Ok(i) => i,
            Err(e) => return (e, 0, 0),
        };
        if !self.slots[i].rights.contains(Rights::READ) {
            return (SysStatus::Denied, 0, 0);
        }
        self.chan_recv_body(ep)
    }
}

/// THE one numbered, capability-checked dispatcher (pure, safe). Resolves
/// `args.handle` against the CALLER's `table`, checks the right the method
/// requires, runs the method, and returns a CLOSED [`SysReturn`]. This is the
/// single audit chokepoint unprivileged code reaches the kernel through; it
/// acts ONLY on the presented capability's rights -- never ambient authority
/// (the confused-deputy stop).
pub fn dispatch(table: &mut HandleTable, args: &SyscallArgs) -> SysReturn {
    let need = match required_right(args.method) {
        Some(r) => r,
        None => return SysReturn::err(SysStatus::BadMethod),
    };
    let i = match table.live(args.handle) {
        Ok(i) => i,
        Err(e) => return SysReturn::err(e),
    };
    if !table.slots[i].rights.contains(need) {
        return SysReturn::err(SysStatus::Denied);
    }
    match args.method {
        M_OBJECT_INSPECT => {
            let kind = match &table.slots[i].object {
                Some(o) => o.kind as u64,
                None => 0,
            };
            SysReturn::ok(kind)
        }
        M_HANDLE_DUP => match table.dup(args.handle) {
            Some(h) => SysReturn::ok(h.raw()),
            None => SysReturn::err(SysStatus::ObjFull),
        },
        M_HANDLE_NARROW => match table.narrow(args.handle, Rights::from_bits(args.args[0] as u32)) {
            Some(h) => SysReturn::ok(h.raw()),
            None => SysReturn::err(SysStatus::ObjFull),
        },
        M_HANDLE_REVOKE => SysReturn::status(table.revoke(args.handle)),
        M_HANDLE_CLOSE => SysReturn::status(table.close(args.handle)),
        // M13: the rights-gated memory verbs route to the caller's OWN substrate
        // behind this MemoryHome handle (the chokepoint-only door). Clone the
        // `Rc<Object>` out and drop the slot/RefCell borrow BEFORE minting the
        // copy-on-retrieve MemoryRecord, so the table `&mut` never aliases the
        // in-flight substrate borrow (single-core, interrupts masked -> no
        // reentrant borrow_mut).
        M_MEM_WRITE => {
            let obj = match table.slots[i].object.clone() {
                Some(o) => o,
                None => return SysReturn::err(SysStatus::Stale),
            };
            match &obj.mem {
                Some(cell) => {
                    match cell.borrow_mut().write(
                        args.args[0],
                        args.args[1],
                        args.args[2],
                        args.args[3],
                    ) {
                        Some(id) => SysReturn::ok(id),
                        None => SysReturn::err(SysStatus::NoMem),
                    }
                }
                None => SysReturn::err(SysStatus::BadCap),
            }
        }
        M_MEM_READ => {
            let obj = match table.slots[i].object.clone() {
                Some(o) => o,
                None => return SysReturn::err(SysStatus::Stale),
            };
            match obj.kind {
                ObjKind::MemoryHome => match &obj.mem {
                    Some(cell) => match cell.borrow().read(args.args[0]) {
                        Some(v) => SysReturn::ok(v),
                        None => SysReturn::err(SysStatus::BadCap),
                    },
                    None => SysReturn::err(SysStatus::BadCap),
                },
                // A copy-on-retrieve record hands back its inline scalar (id).
                ObjKind::MemoryRecord => SysReturn::ok(obj.scalar),
                _ => SysReturn::err(SysStatus::BadCap),
            }
        }
        M_MEM_RECALL => {
            let obj = match table.slots[i].object.clone() {
                Some(o) => o,
                None => return SysReturn::err(SysStatus::Stale),
            };
            let rec = match &obj.mem {
                Some(cell) => cell.borrow_mut().recall(
                    args.args[0],
                    args.args[1],
                    args.args[2],
                    args.args[3],
                ),
                None => return SysReturn::err(SysStatus::BadCap),
            };
            // The substrate borrow is dropped above; now mint the working copy.
            match rec {
                Some(id) => match table.mint_record(id) {
                    Some(h) => SysReturn::ok(h.raw()),
                    None => SysReturn::err(SysStatus::ObjFull),
                },
                None => SysReturn::err(SysStatus::BadCap),
            }
        }
        M_MEM_CONSOLIDATE => {
            let obj = match table.slots[i].object.clone() {
                Some(o) => o,
                None => return SysReturn::err(SysStatus::Stale),
            };
            match &obj.mem {
                Some(cell) => {
                    let n = cell.borrow_mut().consolidate(
                        args.args[0],
                        args.args[1],
                        args.args[2],
                        args.args[3],
                    );
                    SysReturn::ok(n)
                }
                None => SysReturn::err(SysStatus::BadCap),
            }
        }
        // M14: SEND a message on the endpoint behind `args.handle` (WRITE gated
        // above). Clone the endpoint `Rc<Object>` OUT and read `(chan, side)`
        // BEFORE touching the ring / detaching, so the table `&mut` never aliases
        // the in-flight RefCell borrow (the M_MEM_* discipline). ATOMICITY: the
        // outbox space check happens BEFORE any `detach`, so a WouldBlock send
        // never strands a detached-and-lost capability.
        M_CHAN_SEND => {
            let ep_obj = match table.slots[i].object.clone() {
                Some(o) => o,
                None => return SysReturn::err(SysStatus::Stale),
            };
            let (chan, side) = match &ep_obj.chan {
                Some((c, s)) => (c.clone(), *s),
                None => return SysReturn::err(SysStatus::BadCap),
            };
            if !chan.peer_open(side) {
                return SysReturn::err(SysStatus::PeerClosed);
            }
            // Backpressure: confirm space BEFORE detaching anything (atomic).
            {
                let ring = chan.outbox(side).borrow();
                if ring.q.len() >= ring.cap {
                    return SysReturn::err(SysStatus::WouldBlock);
                }
            }
            let cap_raw = args.args[1];
            let parked = if cap_raw != 0 {
                let cap_h = Handle::from_raw(cap_raw);
                let ci = match table.live(cap_h) {
                    Ok(ci) => ci,
                    Err(e) => return SysReturn::err(e),
                };
                // The carried cap must hold TRANSFER (the M_HANDLE_TRANSFER gate).
                if !table.slots[ci].rights.contains(Rights::TRANSFER) {
                    return SysReturn::err(SysStatus::Denied);
                }
                // Reject sending an endpoint into its OWN channel (Zircon
                // NOT_SUPPORTED): the carried object IS this channel's core.
                if let Some(carried) = table.slots[ci].object.clone() {
                    if let Some((carried_chan, _)) = &carried.chan {
                        if Rc::ptr_eq(carried_chan, &chan) {
                            return SysReturn::err(SysStatus::Denied);
                        }
                    }
                }
                match table.detach(cap_h) {
                    Ok(p) => Some(p),
                    Err(e) => return SysReturn::err(e),
                }
            } else {
                None
            };
            chan.outbox(side).borrow_mut().q.push_back(crate::ipc::Message {
                payload: args.args[0],
                cap: parked,
            });
            SysReturn::status(SysStatus::Ok)
        }
        // M14: RECV a message (READ gated above). The single-scalar SysReturn
        // carries the moved handle in `value`; the inline payload is surfaced
        // kernel-side via the facade tuple (and, later, copy_to_user).
        M_CHAN_RECV => {
            let (st, _payload, moved) = table.chan_recv_body(args.handle);
            match st {
                SysStatus::Ok => SysReturn::ok(moved),
                e => SysReturn::err(e),
            }
        }
        // M14: CLOSE this endpoint (no right required). Flips the peer-closed flag;
        // the peer drains its backlog, then observes PeerClosed.
        M_CHAN_CLOSE => {
            let ep_obj = match table.slots[i].object.clone() {
                Some(o) => o,
                None => return SysReturn::err(SysStatus::Stale),
            };
            match &ep_obj.chan {
                Some((c, s)) => {
                    c.close_side(*s);
                    SysReturn::status(SysStatus::Ok)
                }
                None => SysReturn::err(SysStatus::BadCap),
            }
        }
        // M15: RECORD-plane CAS write on the shared block behind `args.handle`
        // (WRITE gated above). Clone the `Rc<Object>` OUT and drop the slot
        // borrow BEFORE touching `block.records` (the M_MEM_*/M_CHAN_* single-
        // &mut-at-a-time discipline -> no reentrant borrow_mut). A losing CAS
        // surfaces WouldBlock; a non-block object -> BadCap.
        M_BLOCK_WRITE => {
            let obj = match table.slots[i].object.clone() {
                Some(o) => o,
                None => return SysReturn::err(SysStatus::Stale),
            };
            match &obj.block {
                Some(b) => match b.cas_write(args.args[0], args.args[1], args.args[2]) {
                    Some(v) => SysReturn::ok(v),
                    None => SysReturn::err(SysStatus::WouldBlock),
                },
                None => SysReturn::err(SysStatus::BadCap),
            }
        }
        // M15: RECORD-plane read-latest (READ gated above). Same clone-out
        // discipline; an unwritten slot or a non-block object -> BadCap.
        M_BLOCK_READ => {
            let obj = match table.slots[i].object.clone() {
                Some(o) => o,
                None => return SysReturn::err(SysStatus::Stale),
            };
            match &obj.block {
                Some(b) => match b.read_latest(args.args[0]) {
                    Some(v) => SysReturn::ok(v),
                    None => SysReturn::err(SysStatus::BadCap),
                },
                None => SysReturn::err(SysStatus::BadCap),
            }
        }
        // M_BLOCK_MAP / M_BLOCK_UNMAP are ADDRESS-SPACE-dependent; their bodies
        // ride the kernel facade `agent_block_map` (dispatch holds no
        // AddressSpace). Reached here only via the future EL0 gate, they fall
        // through to the rights-checked stub below.
        // M_HANDLE_TRANSFER is kernel-mediated (it needs a destination table);
        // its TRANSFER right is verified above. Remaining agent-semantic methods
        // are rights-checked stubs at M11 (bodies land in later milestones).
        //
        // M16: INVOKE the model session behind `args.handle` (INVOKE_MODEL gated
        // above). Clone the `Rc<Object>` OUT and drop the slot borrow BEFORE
        // calling the backend -- the single-&mut-at-a-time discipline (the
        // M_MEM_*/M_CHAN_*/M_BLOCK_* precedent). The router was consulted ONCE at
        // open time, never here, so dispatch keeps holding only `&mut
        // HandleTable`. A non-session cap presented to a model method -> BadCap
        // (the M_BLOCK_WRITE wrong-payload branch).
        M_MODEL_INVOKE => {
            let obj = match table.slots[i].object.clone() {
                Some(o) => o,
                None => return SysReturn::err(SysStatus::Stale),
            };
            match &obj.session {
                Some(sess) => SysReturn::ok(sess.invoke(args.args[0]).token),
                None => SysReturn::err(SysStatus::BadCap),
            }
        }
        _ => SysReturn::ok(0),
    }
}
