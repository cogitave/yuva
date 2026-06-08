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
            }),
        )
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
        let moved = dst.alloc(rights, object)?;
        self.free_slot(i);
        Some(moved)
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
        // M_HANDLE_TRANSFER is kernel-mediated (it needs a destination table);
        // its TRANSFER right is verified above. Remaining agent-semantic methods
        // are rights-checked stubs at M11 (bodies land in later milestones).
        _ => SysReturn::ok(0),
    }
}
