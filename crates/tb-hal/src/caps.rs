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
use core::cell::RefCell;

use tb_caps_core::CapTable;

// M11 -- the capability rights algebra ([`Rights`]), the unforgeable
// generation-tagged [`Handle`], and the closed [`SysStatus`] now live in the
// host-verifiable `tb-caps-core` crate, so the kernel and the Kani proof
// harnesses verify the EXACT SAME bit/slot/generation logic (zero model drift).
// They are re-exported VERBATIM here so `tb_hal::caps::{Rights, Handle,
// SysStatus}` stays byte-identical for the kernel and the M11..M18 witnesses.
pub use tb_caps_core::{Handle, Rights, SysStatus};

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

/// The per-principal handle table -- the unit of authority. A thin `tb-hal`
/// wrapper over the host-verifiable [`CapTable`]`<Rc<Object>>`: the generic core
/// owns ALL slot/generation/free-list/rights logic (and is exactly what the Kani
/// harnesses prove); this wrapper adds only the `Rc<Object>` payload helpers
/// (`mint_*`) and the object-aware dispatch surface.
pub struct HandleTable {
    core: CapTable<Rc<Object>>,
}

impl HandleTable {
    /// A new empty table that will hold at most `cap` live capabilities.
    pub fn with_capacity(cap: usize) -> Self {
        HandleTable {
            core: CapTable::with_capacity(cap),
        }
    }

    /// Resolve `h` to its live slot index, fail-closed (delegates to the proven
    /// [`CapTable::live`]): `BadCap` if the slot is out of range; `Stale` if it is
    /// vacant (use-after-revoke) or its generation does not match.
    fn live(&self, h: Handle) -> Result<usize, SysStatus> {
        self.core.live(h)
    }

    /// Place `object` with `rights` into a free or fresh slot (delegates to the
    /// proven [`CapTable::alloc`]), or `None` when the table is at `cap`.
    fn alloc(&mut self, rights: Rights, object: Rc<Object>) -> Option<Handle> {
        self.core.alloc(rights, object)
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
        let o = self.core.object_at(i).clone().ok_or(SysStatus::Stale)?;
        match &o.block {
            Some(b) => Ok((self.core.rights_at(i), b.clone())),
            None => Err(SysStatus::BadCap),
        }
    }

    /// The rights currently attached to `h`, or `None` if it does not resolve.
    /// Delegates to the proven [`CapTable::rights_of`].
    pub fn rights_of(&self, h: Handle) -> Option<Rights> {
        self.core.rights_of(h)
    }

    /// Duplicate `h`: a sibling handle to the SAME object with the SAME rights.
    /// `None` if `h` does not resolve or the table is full. Delegates to the
    /// proven [`CapTable::dup`].
    pub fn dup(&mut self, h: Handle) -> Option<Handle> {
        self.core.dup(h)
    }

    /// Narrow (attenuate) `h`: a new handle to the same object whose rights are
    /// `old & mask` -- ALWAYS a subset of `old`, by construction. `None` if `h`
    /// does not resolve or the table is full. Delegates to the proven
    /// [`CapTable::narrow`].
    pub fn narrow(&mut self, h: Handle, mask: Rights) -> Option<Handle> {
        self.core.narrow(h, mask)
    }

    /// Per-slot generation revoke of `h`: `Ok` and the slot is vacated (every
    /// extant handle to it now resolves `Stale`, O(1)); otherwise the resolve
    /// error. NOTE: this is the privileged MECHANISM; the REVOKE-right gate is
    /// enforced for unprivileged callers by [`dispatch`]. Delegates to the proven
    /// [`CapTable::revoke`].
    pub fn revoke(&mut self, h: Handle) -> SysStatus {
        self.core.revoke(h)
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
    /// tables; the receiver gets a new slot + generation. Delegates to the proven
    /// [`CapTable::transfer_to`].
    pub fn transfer_to(&mut self, h: Handle, dst: &mut HandleTable) -> Option<Handle> {
        self.core.transfer_to(h, &mut dst.core)
    }

    /// M14 -- the SEND half of [`HandleTable::transfer_to`], split across an IPC
    /// ring: resolve `h` (fail-closed `BadCap`/`Stale`), clone its object +
    /// rights OUT, then `free_slot` so the capability goes STALE in THIS table
    /// (Zircon "handles are consumed on write"). The returned `(Rc<Object>,
    /// Rights)` is parked in the message; while parked NO table holds a handle --
    /// the `Rc` alone keeps the object alive. The caller MUST confirm the outbox
    /// has space BEFORE calling this, so a `WouldBlock` send never detaches.
    /// Delegates to the proven [`CapTable::detach`].
    pub(crate) fn detach(&mut self, h: Handle) -> Result<(Rc<Object>, Rights), SysStatus> {
        self.core.detach(h)
    }

    /// M14 -- the RECV half of [`HandleTable::transfer_to`]: install a parked,
    /// in-transit capability into THIS table, yielding a fresh slot + generation
    /// (the raw handle value is never reused across tables). Object identity (the
    /// `Rc`) and `rights` ride intact. `None` on `ObjFull`. Delegates to the
    /// proven [`CapTable::attach`].
    pub(crate) fn attach(&mut self, parked: (Rc<Object>, Rights)) -> Option<Handle> {
        self.core.attach(parked)
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
        let ep_obj = match self.core.object_at(i).clone() {
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
        if !self.core.rights_at(i).contains(Rights::READ) {
            return (SysStatus::Denied, 0, 0);
        }
        self.chan_recv_body(ep)
    }

    /// M14.1 -- the BYTE-PAYLOAD send body the kernel facade
    /// [`crate::agent_chan_send_bytes`] calls. Mirrors the scalar `M_CHAN_SEND`
    /// dispatch arm exactly, plus a kernel-heap bounce buffer filled from the
    /// sender's address space (`src_root` = the sender agent's top-level table
    /// PA) via `copy_from_user`. ATOMICITY (the M11 all-or-nothing invariant):
    /// peer-open + outbox-space + size are checked, then `copy_from_user` runs
    /// BEFORE any carried-cap `detach`, so a copy fault or oversize send can
    /// never strand a detached-and-lost capability or enqueue a partial message.
    /// Applies the same WRITE gate `required_right(M_CHAN_SEND)` does (the facade
    /// path does not pass through `dispatch`'s top-level gate). Returns the
    /// CLOSED [`SysStatus`]: `Denied` (WRITE-less endpoint / oversize / TRANSFER-
    /// less or self-channel carried cap), `WouldBlock` (full outbox), `PeerClosed`
    /// (peer gone), `Fault` (`copy_from_user` failed -- NOTHING enqueued),
    /// `BadCap`/`Stale` (resolve).
    pub(crate) fn chan_send_bytes(
        &mut self,
        ep: Handle,
        payload: u64,
        cap_raw: u64,
        src_root: u64,
        src_uva: u64,
        len: usize,
    ) -> SysStatus {
        // Resolve + WRITE gate (single-sourced `required_right(M_CHAN_SEND)`).
        let i = match self.live(ep) {
            Ok(i) => i,
            Err(e) => return e,
        };
        if !self.core.rights_at(i).contains(Rights::WRITE) {
            return SysStatus::Denied;
        }
        // Clone the endpoint object OUT and read `(chan, side)` BEFORE touching
        // the ring / detaching (the dispatch M_CHAN_SEND discipline -- the table
        // `&mut` never aliases the in-flight RefCell borrow).
        let ep_obj = match self.core.object_at(i).clone() {
            Some(o) => o,
            None => return SysStatus::Stale,
        };
        let (chan, side) = match &ep_obj.chan {
            Some((c, s)) => (c.clone(), *s),
            None => return SysStatus::BadCap,
        };
        if !chan.peer_open(side) {
            return SysStatus::PeerClosed;
        }
        // Backpressure FIRST (atomic): confirm space BEFORE any copy / detach.
        {
            let ring = chan.outbox(side).borrow();
            if ring.q.len() >= ring.cap {
                return SysStatus::WouldBlock;
            }
        }
        // Size bound (one page); an oversize send is Denied (the M15 path).
        if len > crate::ipc::MAX_PAYLOAD {
            return SysStatus::Denied;
        }
        // Copy the sender's bytes into a kernel bounce buffer BEFORE detaching
        // any carried cap, so a copy fault leaves the sender's table + the ring
        // untouched. A `Box<[u8]>` is safe heap (this module stays
        // `#![forbid(unsafe_code)]`); the ONLY unsafe is inside the arch facade.
        let mut buf = {
            let mut v = alloc::vec::Vec::with_capacity(len);
            v.resize(len, 0u8);
            v.into_boxed_slice()
        };
        if len > 0 && crate::arch::copy_from_user(src_root, src_uva, &mut buf).is_err() {
            return SysStatus::Fault;
        }
        // ONLY now detach the optional carried cap (TRANSFER-gated, self-channel-
        // rejected -- exactly as the scalar M_CHAN_SEND arm).
        let parked = if cap_raw != 0 {
            let cap_h = Handle::from_raw(cap_raw);
            let ci = match self.live(cap_h) {
                Ok(ci) => ci,
                Err(e) => return e,
            };
            if !self.core.rights_at(ci).contains(Rights::TRANSFER) {
                return SysStatus::Denied;
            }
            if let Some(carried) = self.core.object_at(ci).clone() {
                if let Some((carried_chan, _)) = &carried.chan {
                    if Rc::ptr_eq(carried_chan, &chan) {
                        return SysStatus::Denied;
                    }
                }
            }
            match self.detach(cap_h) {
                Ok(p) => Some(p),
                Err(e) => return e,
            }
        } else {
            None
        };
        chan.outbox(side).borrow_mut().q.push_back(crate::ipc::Message {
            payload,
            bytes: Some(buf),
            cap: parked,
        });
        SysStatus::Ok
    }

    /// M14.1 -- the BYTE-PAYLOAD recv body the kernel facade
    /// [`crate::agent_chan_recv_bytes`] calls. Applies the same READ gate as
    /// [`HandleTable::chan_recv`], then drains any carried byte payload into the
    /// receiver's address space (`dst_root` = the receiver agent's top-level
    /// table PA) via `copy_to_user`. Returns `(status, inline payload,
    /// moved-handle-raw, byte-len)`.
    ///
    /// FAIL-CLOSED, NO-LOSS ordering (Zircon `zx_channel_read` semantics): PEEK
    /// the head's `byte_len` FIRST; a `dst_cap` smaller than it returns `Fault`
    /// WITHOUT popping (the message survives for a retry with a bigger buffer).
    /// Otherwise pop; if it carries bytes, attempt `copy_to_user`; on a copy
    /// fault `push_front` the WHOLE message back (restoring FIFO order + the
    /// parked cap + the bytes) and return `Fault` -- an in-flight message is
    /// never silently dropped. On success, attach any carried cap (as `chan_recv`
    /// does). `WouldBlock` (empty-but-open) / `PeerClosed` (empty-and-closed) as
    /// usual.
    pub(crate) fn chan_recv_bytes(
        &mut self,
        ep: Handle,
        dst_root: u64,
        dst_uva: u64,
        dst_cap: usize,
    ) -> (SysStatus, u64, u64, usize) {
        let i = match self.live(ep) {
            Ok(i) => i,
            Err(e) => return (e, 0, 0, 0),
        };
        if !self.core.rights_at(i).contains(Rights::READ) {
            return (SysStatus::Denied, 0, 0, 0);
        }
        let ep_obj = match self.core.object_at(i).clone() {
            Some(o) => o,
            None => return (SysStatus::Stale, 0, 0, 0),
        };
        let (chan, side) = match &ep_obj.chan {
            Some((c, s)) => (c.clone(), *s),
            None => return (SysStatus::BadCap, 0, 0, 0),
        };
        // PEEK the head's byte length WITHOUT popping: a too-small dst buffer
        // fails closed and leaves the message in place (no discard). Drop the
        // ring borrow before any pop (single-core, interrupts masked).
        {
            let inbox = chan.inbox(side).borrow();
            match inbox.q.front() {
                None => {
                    return if chan.peer_open(side) {
                        (SysStatus::WouldBlock, 0, 0, 0)
                    } else {
                        (SysStatus::PeerClosed, 0, 0, 0)
                    };
                }
                Some(head) => {
                    if head.byte_len() > dst_cap {
                        return (SysStatus::Fault, 0, 0, 0);
                    }
                }
            }
        }
        // Big enough: pop it (the borrow above is dropped).
        let msg = match chan.inbox(side).borrow_mut().q.pop_front() {
            Some(m) => m,
            // Single-core + interrupts masked: nothing could have drained the
            // head between the peek and here, but stay fail-closed regardless.
            None => return (SysStatus::WouldBlock, 0, 0, 0),
        };
        let blen = msg.byte_len();
        // Drain any byte payload into the receiver's space. The `copy_to_user`
        // body's unsafe is confined to the arch facade; on a fault, restore the
        // WHOLE message (FIFO + parked cap + bytes) and report Fault.
        let copy_ok = match msg.bytes.as_ref() {
            Some(bytes) if !bytes.is_empty() => {
                crate::arch::copy_to_user(dst_root, dst_uva, bytes).is_ok()
            }
            _ => true,
        };
        if !copy_ok {
            chan.inbox(side).borrow_mut().q.push_front(msg);
            return (SysStatus::Fault, 0, 0, 0);
        }
        let payload = msg.payload;
        match msg.cap {
            None => (SysStatus::Ok, payload, 0, blen),
            Some(parked) => match self.attach(parked) {
                Some(h) => (SysStatus::Ok, payload, h.raw(), blen),
                // Receiver table full: the cap cannot be re-slotted.
                None => (SysStatus::ObjFull, payload, 0, blen),
            },
        }
    }
}

/// M18 -- the FROZEN-evaluator harness surface (kernel-side, NOT method-numbered).
///
/// These helpers reach a [`MemSubstrate`] behind a [`ObjKind::MemoryHome`] handle
/// for the kernel-owned self-improvement harness. They are DELIBERATELY NOT wired
/// into [`dispatch`] (the closed numbered method set stays frozen at M11), so an
/// agent literally cannot invoke them -- the evaluator scores from a kernel domain
/// the agent has no handle/right to. The whole guarantee REDUCES TO the M11
/// rights-mask invariant: a handle resolves ONLY against the table it is presented
/// to, so an agent can never name the kernel-owned `eval_tbl`/`eval_home`.
impl HandleTable {
    /// Reach the substrate behind `h` and read `(body_tok, tier)` of skill `id`
    /// (harness/self-test witness). `None` if `h` does not resolve, carries no
    /// substrate, or has no such skill.
    fn skill_get_of(&self, h: Handle, id: u64) -> Option<(u64, u8)> {
        let i = self.live(h).ok()?;
        let o = self.core.object_at(i).as_ref()?;
        o.mem.as_ref()?.borrow().skill_get(id)
    }

    /// Score `body` against the FROZEN held-out set in the substrate behind `h`
    /// (the evaluator domain). `None` if `h` does not resolve or carries no
    /// substrate. Single short-lived immutable borrow (no reentrancy).
    fn score_of(&self, h: Handle, body: u64) -> Option<u32> {
        let i = self.live(h).ok()?;
        let o = self.core.object_at(i).as_ref()?;
        Some(o.mem.as_ref()?.borrow().score_candidate(body))
    }

    /// Flip skill `id` PROPOSED->ADMITTED in the substrate behind `h` iff `score`
    /// strictly improves. Clones the `Rc<Object>` out and drops the slot borrow
    /// BEFORE `borrow_mut` (the M_MEM_WRITE discipline). `false` on any miss.
    fn skill_admit_of(&mut self, h: Handle, id: u64, score: u32) -> bool {
        let i = match self.live(h) {
            Ok(i) => i,
            Err(_) => return false,
        };
        let o = match self.core.object_at(i).clone() {
            Some(o) => o,
            None => return false,
        };
        match &o.mem {
            Some(cell) => cell.borrow_mut().skill_admit(id, score),
            None => false,
        }
    }

    /// M18 kernel-side: seed the held-out `(input -> expected)` test set into the
    /// FROZEN evaluator substrate behind `eval_home`, deriving each expected from
    /// the secret `target`. `eval_home` lives only in a kernel-owned table never
    /// minted into any agent's table. Returns `false` if it does not resolve.
    pub fn eval_seed_heldout(&mut self, eval_home: Handle, target: u64, base: u64, n: u64) -> bool {
        let i = match self.live(eval_home) {
            Ok(i) => i,
            Err(_) => return false,
        };
        let o = match self.core.object_at(i).clone() {
            Some(o) => o,
            None => return false,
        };
        match &o.mem {
            Some(cell) => {
                cell.borrow_mut().seed_heldout(target, base, n);
                true
            }
            None => false,
        }
    }

    /// M18 ADMISSION (kernel-side; the EXCEL rung): read the PROPOSED skill
    /// `skill_id` from the substrate behind `skill_home` in THIS table, score its
    /// body_tok against the held-out set behind `eval_home` in the kernel-owned
    /// `eval_tbl`, and flip it PROPOSED->ADMITTED ONLY on strict improvement (no
    /// regression). Returns `(admitted, score)`. The improving agent holds NO
    /// handle to `eval_tbl`/`eval_home`, so the held-out set is unreadable and the
    /// verdict unforgeable -- the frozen boundary == the M11 rights-mask invariant.
    pub fn harness_admit(
        &mut self,
        skill_home: Handle,
        skill_id: u64,
        eval_tbl: &HandleTable,
        eval_home: Handle,
    ) -> (bool, u32) {
        let body = match self.skill_get_of(skill_home, skill_id) {
            Some((b, _t)) => b,
            None => return (false, 0),
        };
        let score = match eval_tbl.score_of(eval_home, body) {
            Some(s) => s,
            None => return (false, 0),
        };
        let admitted = self.skill_admit_of(skill_home, skill_id, score);
        (admitted, score)
    }

    /// M18 self-test witness: the PROPOSED/ADMITTED tier of skill `id` behind `h`.
    pub fn skill_tier_of(&self, h: Handle, id: u64) -> Option<u8> {
        self.skill_get_of(h, id).map(|(_b, t)| t)
    }

    /// M18 self-test witness: count of ADMITTED skills behind `h` (trust promotion).
    pub fn skill_admitted_count(&self, h: Handle) -> Option<u64> {
        let i = self.live(h).ok()?;
        let o = self.core.object_at(i).as_ref()?;
        Some(o.mem.as_ref()?.borrow().skill_count_admitted())
    }

    /// M18 self-test witness: lineage length of skill `id` behind `h` (admitted
    /// AND rejected proposals both grow the immutable, agent-unwritable log).
    pub fn skill_lineage_len(&self, h: Handle, id: u64) -> Option<u64> {
        let i = self.live(h).ok()?;
        let o = self.core.object_at(i).as_ref()?;
        Some(o.mem.as_ref()?.borrow().skill_lineage_len(id))
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
    if !table.core.rights_at(i).contains(need) {
        return SysReturn::err(SysStatus::Denied);
    }
    match args.method {
        M_OBJECT_INSPECT => {
            let kind = match table.core.object_at(i) {
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
            let obj = match table.core.object_at(i).clone() {
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
        // M18: the privileged T4 PROCEDURAL write (WRITE_PROCEDURAL gated above).
        // Route to the caller's OWN substrate via the SAME clone-Rc-out / drop-
        // slot-borrow-before-borrow_mut discipline as the M_MEM_WRITE arm (single-
        // core, interrupts masked -> no reentrant borrow_mut). The procedural verbs
        // (ADD_SKILL / UPDATE_UTILITY / READ_SKILL / LINK_LINEAGE / READ_TIER) ride
        // an OP-SELECTOR in args[0] -- the M17 pattern, so NO new ABI method number.
        M_MEM_WRITE_PROC => {
            let obj = match table.core.object_at(i).clone() {
                Some(o) => o,
                None => return SysReturn::err(SysStatus::Stale),
            };
            match &obj.mem {
                Some(cell) => {
                    match cell.borrow_mut().write_proc(
                        args.args[0],
                        args.args[1],
                        args.args[2],
                        args.args[3],
                    ) {
                        Some(v) => SysReturn::ok(v),
                        None => SysReturn::err(SysStatus::NoMem),
                    }
                }
                None => SysReturn::err(SysStatus::BadCap),
            }
        }
        M_MEM_READ => {
            let obj = match table.core.object_at(i).clone() {
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
            let obj = match table.core.object_at(i).clone() {
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
            let obj = match table.core.object_at(i).clone() {
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
            let ep_obj = match table.core.object_at(i).clone() {
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
                if !table.core.rights_at(ci).contains(Rights::TRANSFER) {
                    return SysReturn::err(SysStatus::Denied);
                }
                // Reject sending an endpoint into its OWN channel (Zircon
                // NOT_SUPPORTED): the carried object IS this channel's core.
                if let Some(carried) = table.core.object_at(ci).clone() {
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
                // The scalar dispatch path carries no byte payload; the M14.1
                // byte-payload send rides the kernel facade `chan_send_bytes`
                // (it needs the sender's address-space root, which `dispatch`
                // cannot resolve holding only `&mut HandleTable`).
                bytes: None,
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
            let ep_obj = match table.core.object_at(i).clone() {
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
            let obj = match table.core.object_at(i).clone() {
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
            let obj = match table.core.object_at(i).clone() {
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
            let obj = match table.core.object_at(i).clone() {
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
