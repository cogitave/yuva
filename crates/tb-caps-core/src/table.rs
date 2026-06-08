//! The payload-agnostic authority CORE: the unforgeable [`Handle`], the closed
//! [`SysStatus`], the per-slot [`SlotCore`], and the generic generation-checked
//! [`CapTable`]. Factored out of `tb-hal/src/caps.rs` with byte-identical method
//! bodies (only the object payload `Rc<Object>` parameterised out to `O`) so the
//! kernel and the Kani harnesses exercise the SAME slot/generation/free-list/
//! rights logic -- zero model drift.

use crate::rights::Rights;
use alloc::vec::Vec;

/// An unforgeable, generation-tagged reference into a per-principal
/// [`CapTable`]: `(generation:u32) << 32 | slot:u32`, one opaque `u64`.
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
    /// [`CapTable::live`]-backed resolve.
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
    /// backlog is drained first, THEN this surfaces).
    PeerClosed = 8,
    /// M14.1: a user-buffer copy fault or precondition miss on a BYTE-payload
    /// send/recv -- the per-page `copy_to_user`/`copy_from_user` walk hit a
    /// not-present / not-user / not-writable / not-in-physmap leaf, OR the
    /// receive buffer was too small for the queued payload. Fail-closed: NOTHING
    /// was enqueued (send) or dequeued (recv) when this surfaces. Appended AFTER
    /// `PeerClosed = 8` so every prior discriminant stays stable; kept LAST so
    /// the closed status surface stays total.
    Fault = 9,
}

/// One table slot: a generation, the rights mask, and the object payload. An
/// OCCUPIED slot has `object.is_some()`; a vacant/revoked slot has
/// `object == None`, and any handle to it resolves [`SysStatus::Stale`].
pub struct SlotCore<O> {
    /// The slot's live generation, matched against a handle's generation on
    /// every resolve. Starts at 1 and is bumped on every free (revoke/move).
    pub generation: u32,
    /// The rights mask currently attached to whatever occupies this slot.
    pub rights: Rights,
    /// The object payload, or `None` for a vacant/revoked slot.
    pub object: Option<O>,
}

/// The per-principal authority table -- the unit of authority, generic over the
/// object payload `O`. Heap-backed; a LIFO free list reuses revoked slots (their
/// generation already bumped, so prior handles stay `Stale`). `cap` bounds the
/// table fail-closed (the caller maps a full table to `ObjFull`).
pub struct CapTable<O> {
    slots: Vec<SlotCore<O>>,
    free: Vec<u32>,
    cap: usize,
}

impl<O> CapTable<O> {
    /// A new empty table that will hold at most `cap` live capabilities.
    pub fn with_capacity(cap: usize) -> Self {
        CapTable {
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
    pub fn live(&self, h: Handle) -> Result<usize, SysStatus> {
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
    pub fn alloc(&mut self, rights: Rights, object: O) -> Option<Handle> {
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
        self.slots.push(SlotCore {
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
    pub fn free_slot(&mut self, i: usize) {
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

    /// The rights currently attached to `h`, or `None` if it does not resolve.
    pub fn rights_of(&self, h: Handle) -> Option<Rights> {
        self.live(h).ok().map(|i| self.slots[i].rights)
    }

    /// Install a parked `(object, rights)` pair (RECV / move target): a fresh
    /// slot + generation (the raw handle value is never reused across tables).
    /// `None` on a full table.
    pub fn attach(&mut self, parked: (O, Rights)) -> Option<Handle> {
        self.alloc(parked.1, parked.0)
    }

    /// Per-slot generation revoke of `h`: `Ok` and the slot is vacated (every
    /// extant handle to it now resolves `Stale`, O(1)); otherwise the resolve
    /// error. This is the privileged MECHANISM; the REVOKE-right gate is enforced
    /// for unprivileged callers above this layer.
    pub fn revoke(&mut self, h: Handle) -> SysStatus {
        match self.live(h) {
            Ok(i) => {
                self.free_slot(i);
                SysStatus::Ok
            }
            Err(e) => e,
        }
    }

    /// The rights of the (already-resolved) slot `i`. The caller MUST have
    /// obtained `i` from [`CapTable::live`]; used by the `tb-hal` wrapper /
    /// dispatcher after a fail-closed resolve.
    pub fn rights_at(&self, i: usize) -> Rights {
        self.slots[i].rights
    }

    /// The object payload of the (already-resolved) slot `i`, as borrowed from a
    /// [`CapTable::live`] index. Used by the `tb-hal` wrapper / dispatcher to
    /// reach the payload after a fail-closed resolve.
    pub fn object_at(&self, i: usize) -> &Option<O> {
        &self.slots[i].object
    }
}

impl<O: Clone> CapTable<O> {
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

    /// Transfer (MOVE) `h` into `dst`: mint a fresh handle to the same object,
    /// with the same rights, in `dst`, then vacate the source slot. `None`
    /// (leaving the source intact) if `h` does not resolve or `dst` is full --
    /// the object is never lost. The raw handle value is NEVER reused across
    /// tables; the receiver gets a new slot + generation.
    pub fn transfer_to(&mut self, h: Handle, dst: &mut CapTable<O>) -> Option<Handle> {
        let i = self.live(h).ok()?;
        let rights = self.slots[i].rights;
        let object = self.slots[i].object.clone()?;
        // ATOMIC: attach into `dst` FIRST; only vacate the source AFTER it lands,
        // so a full `dst` never strands the object (all-or-nothing preserved).
        let moved = dst.attach((object, rights))?;
        self.free_slot(i);
        Some(moved)
    }

    /// The SEND half of [`CapTable::transfer_to`], split across an IPC ring:
    /// resolve `h` (fail-closed `BadCap`/`Stale`), clone its object + rights OUT,
    /// then `free_slot` so the capability goes STALE in THIS table (Zircon
    /// "handles are consumed on write"). The returned `(O, Rights)` is parked in
    /// the message; while parked NO table holds a handle.
    pub fn detach(&mut self, h: Handle) -> Result<(O, Rights), SysStatus> {
        let i = self.live(h)?;
        let rights = self.slots[i].rights;
        let object = self.slots[i].object.clone().ok_or(SysStatus::Stale)?;
        self.free_slot(i);
        Ok((object, rights))
    }
}

// ---------------------------------------------------------------------------
// Harness-only hooks: let a `#[cfg(test)]`/`#[cfg(kani)]` build construct an
// arbitrary table state directly and read a slot's rights/occupancy/generation
// back. Absent from a normal `cargo build`/`cargo kbuild`, so the kernel never
// sees them.
// ---------------------------------------------------------------------------
#[cfg(any(test, kani))]
impl<O> CapTable<O> {
    /// Push a slot in an arbitrary `(generation, rights, object)` state so a
    /// harness can build a nondeterministic table that respects the invariant by
    /// construction.
    pub fn seed_slot(&mut self, generation: u32, rights: Rights, object: Option<O>) {
        self.slots.push(SlotCore {
            generation,
            rights,
            object,
        });
    }

    /// The rights stored in slot `slot` (no resolve; harness inspection only).
    pub fn peek_rights(&self, slot: usize) -> Rights {
        self.slots[slot].rights
    }

    /// The live generation of slot `slot` (harness inspection only).
    pub fn peek_generation(&self, slot: usize) -> u32 {
        self.slots[slot].generation
    }

    /// `true` iff slot `slot` is currently occupied (harness inspection only).
    pub fn is_occupied(&self, slot: usize) -> bool {
        self.slots[slot].object.is_some()
    }

    /// The number of slots the table currently holds (harness inspection only).
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }
}

// ---------------------------------------------------------------------------
// Host `#[cfg(test)]` suite -- real execution for the Tier-0 Miri UB gate
// (.github/workflows/miri.yml). These drive the generation + slot + free-list +
// rights logic on the REAL `CapTable<O>` over concrete inputs, so Miri can check
// every path for OOB / use-after-free / uninitialized reads / overflow. They are
// the dynamic complement to the `#[cfg(kani)]` symbolic proofs in `proofs.rs`.
// Deterministic, no `#[should_panic]`. `Rights`/`Handle` derive no `Debug`, so
// assertions compare `.bits()` / `.slot()` / `.generation()`.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rights::Rights;

    /// A common read|write rights set used across the table tests.
    fn rw() -> Rights {
        Rights::READ.union(Rights::WRITE)
    }

    #[test]
    fn alloc_assigns_fresh_slots_at_generation_one() {
        let mut t: CapTable<u32> = CapTable::with_capacity(4);
        let a = t.alloc(Rights::READ, 100).unwrap();
        let b = t.alloc(Rights::WRITE, 200).unwrap();
        assert_eq!(a.generation(), 1);
        assert_eq!(b.generation(), 1);
        assert_ne!(a.slot(), b.slot());
        assert_eq!(t.live(a).unwrap(), a.slot() as usize);
        assert_eq!(t.rights_of(a).unwrap().bits(), Rights::READ.bits());
        assert_eq!(t.rights_of(b).unwrap().bits(), Rights::WRITE.bits());
    }

    #[test]
    fn alloc_is_capacity_bounded_failclosed() {
        let mut t: CapTable<u32> = CapTable::with_capacity(2);
        assert!(t.alloc(Rights::READ, 1).is_some());
        assert!(t.alloc(Rights::READ, 2).is_some());
        // At cap -> None (the caller maps this to SysStatus::ObjFull); no panic.
        assert!(t.alloc(Rights::READ, 3).is_none());
    }

    #[test]
    fn live_rejects_out_of_range_wrong_generation_and_null() {
        let mut t: CapTable<u32> = CapTable::with_capacity(4);
        let h = t.alloc(Rights::READ, 7).unwrap();
        // Slot index past the end of the table -> BadCap.
        assert_eq!(t.live(Handle::new(1, 999)), Err(SysStatus::BadCap));
        // Correct slot, stale generation -> Stale.
        assert_eq!(
            t.live(Handle::new(h.generation() + 1, h.slot())),
            Err(SysStatus::Stale)
        );
        // The reserved NULL handle (generation 0) never resolves.
        assert!(t.live(Handle::NULL).is_err());
        // The valid handle still resolves Ok.
        assert!(t.live(h).is_ok());
    }

    #[test]
    fn dup_mints_sibling_with_identical_rights_and_object() {
        let mut t: CapTable<u32> = CapTable::with_capacity(4);
        let h = t.alloc(rw(), 42).unwrap();
        let s = t.dup(h).unwrap();
        assert_ne!(s.slot(), h.slot());
        assert_eq!(t.rights_of(s).unwrap().bits(), rw().bits());
        // Both handles resolve to the SAME (cloned) object payload.
        let i = t.live(h).unwrap();
        let j = t.live(s).unwrap();
        assert_eq!(t.object_at(i), &Some(42));
        assert_eq!(t.object_at(j), &Some(42));
    }

    #[test]
    fn narrow_only_ever_attenuates() {
        let mut t: CapTable<u32> = CapTable::with_capacity(4);
        let full = Rights::READ.union(Rights::WRITE).union(Rights::TRANSFER);
        let h = t.alloc(full, 1).unwrap();
        // Narrowing drops TRANSFER.
        let n = t.narrow(h, rw()).unwrap();
        let nr = t.rights_of(n).unwrap();
        assert!(nr.is_subset_of(full));
        assert_eq!(nr.bits(), rw().bits());
        // A mask with EVERY bit set can never amplify beyond the parent rights.
        let n2 = t.narrow(h, Rights::from_bits(u32::MAX)).unwrap();
        let n2r = t.rights_of(n2).unwrap();
        assert!(n2r.is_subset_of(full));
        assert_eq!(n2r.bits(), full.bits());
    }

    #[test]
    fn transfer_moves_object_and_drains_source() {
        let mut src: CapTable<u32> = CapTable::with_capacity(4);
        let mut dst: CapTable<u32> = CapTable::with_capacity(4);
        let h = src.alloc(rw(), 0xABCD).unwrap();
        let moved = src.transfer_to(h, &mut dst).unwrap();
        // Source slot drained -> the old handle is now Stale.
        assert_eq!(src.live(h), Err(SysStatus::Stale));
        // Destination carries the same rights and object.
        assert_eq!(dst.rights_of(moved).unwrap().bits(), rw().bits());
        let j = dst.live(moved).unwrap();
        assert_eq!(dst.object_at(j), &Some(0xABCD));
    }

    #[test]
    fn transfer_into_full_dst_strands_nothing() {
        let mut src: CapTable<u32> = CapTable::with_capacity(4);
        let mut dst: CapTable<u32> = CapTable::with_capacity(1);
        let _fill = dst.alloc(Rights::READ, 1).unwrap();
        let h = src.alloc(rw(), 9).unwrap();
        // dst is full -> None, and the source is left intact (all-or-nothing).
        assert!(src.transfer_to(h, &mut dst).is_none());
        assert!(src.live(h).is_ok());
        assert_eq!(src.rights_of(h).unwrap().bits(), rw().bits());
    }

    #[test]
    fn revoke_makes_stale_then_reuse_bumps_generation() {
        let mut t: CapTable<u32> = CapTable::with_capacity(2);
        let h = t.alloc(Rights::READ, 1).unwrap();
        let slot = h.slot();
        let g0 = h.generation();
        assert_eq!(t.revoke(h), SysStatus::Ok);
        assert_eq!(t.live(h), Err(SysStatus::Stale));
        // Revoking an already-dead handle is fail-closed (returns the resolve
        // error), never a double-free panic.
        assert_eq!(t.revoke(h), SysStatus::Stale);
        // The freed slot is reused with a BUMPED generation, so the old handle
        // can never resolve Ok again.
        let h2 = t.alloc(Rights::WRITE, 2).unwrap();
        assert_eq!(h2.slot(), slot);
        assert_ne!(h2.generation(), g0);
        assert!(t.live(h).is_err());
        assert!(t.live(h2).is_ok());
    }

    #[test]
    fn detach_returns_payload_and_drains_source() {
        let mut t: CapTable<u32> = CapTable::with_capacity(4);
        let h = t.alloc(rw(), 0x1234).unwrap();
        let (obj, rights) = t.detach(h).unwrap();
        assert_eq!(obj, 0x1234);
        assert_eq!(rights.bits(), rw().bits());
        assert_eq!(t.live(h), Err(SysStatus::Stale));
        // A second detach of the dead handle is fail-closed.
        assert!(matches!(t.detach(h), Err(SysStatus::Stale)));
    }

    #[test]
    fn free_list_reuse_holds_capacity_across_many_ops() {
        // A long alloc/revoke/realloc sequence so Miri exercises the Vec growth,
        // the LIFO free-list push/pop, and the generation bump on every path.
        let mut t: CapTable<u32> = CapTable::with_capacity(8);
        let mut handles = [Handle::NULL; 8];
        for k in 0..8u32 {
            handles[k as usize] = t.alloc(Rights::READ, k).unwrap();
        }
        assert!(t.alloc(Rights::READ, 99).is_none()); // at capacity
        // Revoke every other capability.
        let mut k = 0;
        while k < 8 {
            assert_eq!(t.revoke(handles[k]), SysStatus::Ok);
            k += 2;
        }
        // Re-alloc into the freed slots; the table never exceeds its capacity.
        for v in 0..4u32 {
            let h = t.alloc(Rights::WRITE, 1000 + v).unwrap();
            assert!(t.live(h).is_ok());
        }
        assert!(t.alloc(Rights::READ, 0).is_none()); // full again
        // Every revoked original handle stays permanently dead.
        let mut k = 0;
        while k < 8 {
            assert!(t.live(handles[k]).is_err());
            k += 2;
        }
    }

    #[test]
    fn generation_overflow_retires_slot_instead_of_wrapping() {
        // A slot whose generation is already at u32::MAX must be RETIRED on free
        // (NOT returned to the free list), so a security generation never wraps
        // to a value some stale handle could match. Built via the test-only
        // `seed_slot` hook so we can place the slot at the overflow boundary.
        let mut t: CapTable<u32> = CapTable::with_capacity(4);
        t.seed_slot(u32::MAX, Rights::READ, Some(7));
        assert_eq!(t.slot_count(), 1);
        t.free_slot(0);
        // Retired: generation left unchanged (no wrap) and the slot is vacant.
        assert_eq!(t.peek_generation(0), u32::MAX);
        assert!(!t.is_occupied(0));
        // A fresh alloc must NOT reuse the retired slot 0 -- a new slot appears.
        let h = t.alloc(Rights::WRITE, 8).unwrap();
        assert_ne!(h.slot(), 0);
        assert_eq!(t.slot_count(), 2);
    }
}
