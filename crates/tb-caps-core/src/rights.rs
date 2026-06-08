//! The capability rights algebra -- moved VERBATIM out of `tb-hal/src/caps.rs`
//! so the kernel and the Kani harnesses verify the exact same bit operations.

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
