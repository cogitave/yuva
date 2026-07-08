//! The Yuva↔agent ABI registry -- the FROZEN-LITERAL, machine-readable snapshot
//! of the versioned, agent-agnostic contract a conformant agent speaks to Yuva.
//!
//! See `docs/spec/yuva-abi-v1.md` (the normative spec) and
//! `docs/proposals/yuva-abi.md` (the proposal). This is Yuva-ABI **stage A**: the
//! contract is FORMALIZED from the existing seams, not invented -- every value
//! below is a DELIBERATE INDEPENDENT COPY of a landed seam constant, committed as
//! a literal here so a cross-check test FAILS on a renumber / relabel / relaxed
//! right rather than silently tracking the drift. `abi=IN-REPO-SPEC-AT-STAGE-A`.
//!
//! ## Why a frozen INDEPENDENT copy, not a re-export
//!
//! An earlier design said this leaf should "single-source BY REFERENCE, never a
//! copy". That is a TAUTOLOGY: if the registry merely re-exported the live
//! `caps.rs`/`brand`/`conductor` constants, then `registry == referenced` is
//! `X == X`, which fails on NOTHING. To actually catch a renumber, a relabel, or
//! a RELAXED `required_right()`, the registry MUST be a second, hand-committed
//! literal copy that a test cross-checks against the LIVE seam constants. The
//! "never a copy" rule is retracted; the copy IS the mechanism.
//!   `registry=CROSSCHECKED-VS-LIVE-INCLUDING-REQUIRED-RIGHT`.
//!
//! ## The two enforcement sites (split by the crate boundary)
//!
//! `tb-encode` is upstream of `tb-hal`, so this leaf CANNOT see `tb-hal::caps`.
//! The cross-check is therefore split, and BOTH halves are genuine drift
//! detectors -- neither is a self-comparison:
//!
//! * **Wire magics + domain labels + organ tags** -- the frozen literals here are
//!   cross-checked against the LIVE `brand` / `conductor` constants by the
//!   `#[cfg(test)]` module at the bottom of THIS file (it runs under
//!   `cargo test -p tb-encode` / `cargo miri test -p tb-encode`, the CI host-test
//!   lane). A renumbered magic, a relabelled domain separator, or a renumbered
//!   organ tag FAILS here. As of Yuva-ABI stage B all FOUR frame magics are
//!   single-sourced in `brand` (the standalone `attest.rs` `ATTEST_MAGIC` literal
//!   was unified into `brand::MAGIC_ATTEST` and is now a re-export), so the
//!   cross-check reads all four from `brand`.
//! * **Method numbers + `required_right()` mapping + `Rights` bits** -- these live
//!   in `tb-hal::caps` (a downstream crate) and its `required_right()` is private,
//!   so they cannot be cross-checked from a `tb-encode` host test. They are
//!   cross-checked by `caps::abi_registry_selfcheck()` (which consumes
//!   [`FROZEN_METHODS`] + [`FROZEN_RIGHTS`] from here) as an IN-KERNEL BOOT
//!   self-test on BOTH arches -- a renumber or a relaxed right reddens every boot.
//!   See the spec §3.2 and the DoD-2 reconciliation.
//!
//! ## Scope honesty (stage A)
//!
//! The version token below is a discoverable LABEL, not a GATE -- nothing at
//! stage A consumes it to reject a mismatched agent (`version-token=
//! DISCOVERY-ONLY-LABEL-NOT-A-GATE`). This registry is keyless / tamper-evident
//! (a committed literal + a cross-check), not signed (`abi-attestation=
//! UNSIGNED-KEYLESS`, `sec=ASSUMED-FROM-LITERATURE`). It catches signature breaks
//! (renumber, relaxed right, addition-past-ceiling), NOT every semantic change
//! under a stable signature (`freeze=CROSSCHECK-CATCHES-SIGNATURE-BREAKS-NOT-ALL-SEMANTICS`).

// ===========================================================================
// The two-axis version token (Firecracker's independent-version discipline)
// ===========================================================================

/// The two INDEPENDENT ABI version axes. The cap-plane (the M11 capability
/// dispatch surface -- method numbers, `Rights`, `required_right()`) carries a
/// SEMVER `(major, minor)`; the wire-plane (the M25/M28/M30/M33 frame family --
/// magics + per-frame `ver` bytes + domain labels) carries a `u8`. They move
/// independently: adding a method bumps `cap_minor` only; a new frame `ver`
/// bumps `wire` only. MINOR/`wire`+1 is backward-compatible (append-only, the
/// Linux-syscall rule); a cap-plane MAJOR bump is forced ONLY by a breaking
/// change (a renumber, a removed method, or a RELAXED right -- each of which the
/// frozen cross-check catches, so the bump can never be silent).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbiVersion {
    /// Cap-plane SEMVER major -- bumps on a BREAKING Plane-1 change.
    pub cap_major: u16,
    /// Cap-plane SEMVER minor -- bumps on an append-only Plane-1 addition.
    pub cap_minor: u16,
    /// Wire-plane `u8` -- the ceiling over the Plane-2 frame family `ver` bytes.
    pub wire: u8,
}

/// The single source of truth for the Yuva-ABI version token (`abi-version=
/// YUVA-ABI-V1`). Today's snapshot: cap-plane `(1, 0)` (methods `0..=32`),
/// wire-plane `1` (`INFER_VER=1`, `ATTEST_VERSION=1`, `OPFRAME_VER`).
pub const YUVA_ABI_VERSION: AbiVersion = AbiVersion { cap_major: 1, cap_minor: 0, wire: 1 };

/// The number of ABI planes a conformant agent binds across: Plane 1 (in-process
/// capability dispatch, M11) + Plane 2 (cross-process wire, M25/M28/M30/M33).
pub const PLANES: u8 = 2;

// ===========================================================================
// Plane 1 -- the FROZEN capability-dispatch registry (a literal copy of
// crates/tb-hal/src/caps.rs :189-298; cross-checked by caps::abi_registry_selfcheck)
// ===========================================================================

/// The frozen `(method_id, name, required_right_bits)` snapshot of the M11
/// numbered method surface. Each `required_right_bits` value is the literal
/// `Rights::bits()` of the right `caps::required_right()` maps the method to --
/// the single most safety-critical part of the surface, frozen so a RELAXED
/// right FAILS the boot self-test. Append-only: a new method is a NEW row with a
/// NEW id (never a renumber), and the ceiling [`METHOD_CEILING`] must move in
/// lockstep. This is a DELIBERATE independent copy -- see the module header.
pub const FROZEN_METHODS: &[(u32, &str, u32)] = &[
    // Meta-ops -- the capability algebra itself, [0, 16).
    (0, "M_OBJECT_INSPECT", 1),      // Rights::READ
    (1, "M_HANDLE_DUP", 8),          // Rights::DUP
    (2, "M_HANDLE_NARROW", 0),       // Rights::NONE (weakening own authority)
    (3, "M_HANDLE_TRANSFER", 4),     // Rights::TRANSFER
    (4, "M_HANDLE_REVOKE", 16),      // Rights::REVOKE
    (5, "M_HANDLE_CLOSE", 0),        // Rights::NONE (closing own handle)
    // Agent-semantic verbs, [16, ..).
    (16, "M_AGENT_SPAWN", 64),       // Rights::SPAWN_AGENT
    (17, "M_MODEL_INVOKE", 32),      // Rights::INVOKE_MODEL
    (18, "M_MEM_WRITE_PROC", 128),   // Rights::WRITE_PROCEDURAL
    (19, "M_MEM_RECALL", 256),       // Rights::RECALL
    (20, "M_MEM_CONSOLIDATE", 512),  // Rights::CONSOLIDATE
    (21, "M_EMIT_EXTERNAL", 1024),   // Rights::EMIT_EXTERNAL (the high-impact seam)
    (22, "M_BUDGET_DELEGATE", 2048), // Rights::DELEGATE_BUDGET
    (23, "M_MEM_WRITE", 2),          // Rights::WRITE
    (24, "M_MEM_READ", 1),           // Rights::READ
    (25, "M_CHAN_SEND", 2),          // Rights::WRITE
    (26, "M_CHAN_RECV", 1),          // Rights::READ
    (27, "M_CHAN_CLOSE", 0),         // Rights::NONE (closing own endpoint)
    (28, "M_BLOCK_MAP", 1),          // Rights::READ
    (29, "M_BLOCK_UNMAP", 16),       // Rights::REVOKE (owner-only destroy)
    (30, "M_BLOCK_WRITE", 2),        // Rights::WRITE
    (31, "M_BLOCK_READ", 1),         // Rights::READ
    (32, "M_MODEL_INVOKE_BYTES", 32), // Rights::INVOKE_MODEL
];

/// The highest registered method number (the append-only ceiling). A method
/// ADDED past this without a version bump is caught by the self-test asserting
/// `max(FROZEN_METHODS.id) == METHOD_CEILING`. `M_MODEL_INVOKE_BYTES=32` is the
/// highest since M31; `33+` is still `SysStatus::BadMethod`.
pub const METHOD_CEILING: u32 = 32;

/// The frozen `(bits, name)` snapshot of the `Rights` bitset
/// (`tb-caps-core::rights`). A single-bit set per named right, `NONE=0`.
/// Cross-checked against the live `Rights::*` constants by
/// `caps::abi_registry_selfcheck` (`tb-encode` cannot see `tb-caps-core`).
pub const FROZEN_RIGHTS: &[(u32, &str)] = &[
    (0, "NONE"),
    (1, "READ"),               // 1 << 0
    (2, "WRITE"),              // 1 << 1
    (4, "TRANSFER"),           // 1 << 2
    (8, "DUP"),                // 1 << 3
    (16, "REVOKE"),            // 1 << 4
    (32, "INVOKE_MODEL"),      // 1 << 5
    (64, "SPAWN_AGENT"),       // 1 << 6
    (128, "WRITE_PROCEDURAL"), // 1 << 7
    (256, "RECALL"),           // 1 << 8
    (512, "CONSOLIDATE"),      // 1 << 9
    (1024, "EMIT_EXTERNAL"),   // 1 << 10
    (2048, "DELEGATE_BUDGET"), // 1 << 11
    (4096, "APPROVE_HIGH_IMPACT"), // 1 << 12
];

// ===========================================================================
// Plane 2 -- the FROZEN wire namespace (all four u16 frame magics enumerated
// together under an enforced disjointness check; as of Yuva-ABI stage B all four
// are single-sourced in `brand`)
// ===========================================================================

/// The frozen `(magic, name)` snapshot of the FULL u16 frame-magic namespace,
/// as ONE unit. As of Yuva-ABI stage B all four -- `MAGIC_OPFRAME/RX/INFERWIRE`
/// and `MAGIC_ATTEST` (the former standalone `attest::ATTEST_MAGIC`) -- are
/// single-sourced in `brand`. This registry still adds value as the enumerated
/// union with its own four-way disjointness const-assert. Cross-checked against
/// the live `brand::MAGIC_*` below.
pub const FROZEN_WIRE_MAGICS: &[(u16, &str)] = &[
    (0x5956, "MAGIC_OPFRAME"),    // M25 operator-transcript frame
    (0x5957, "MAGIC_OPFRAME_RX"), // M28 operator-inbound command frame
    (0x5958, "MAGIC_INFERWIRE"),  // M30 inference-transport frame
    (0x5959, "MAGIC_ATTEST"),     // M33 attestation-statement codec (brand::MAGIC_ATTEST)
];

/// The frozen domain-separator label snapshot (the M28/M29/M30/M31/M33
/// keyed-use labels). ALREADY `YUVA-*` on the live tree -- the "TABOS-*" leak is
/// CLOSED (`wire-labels=ALREADY-YUVA`). Cross-checked against the live
/// `brand::DOMSEP_*` byte constants below.
pub const FROZEN_DOMSEP: &[&str] = &[
    "YUVA-OPCMD-KDF-V1",  // brand::DOMSEP_OPCMD_KDF
    "YUVA-KEY-EVOLVE-V1", // brand::DOMSEP_KEY_EVOLVE
    "YUVA-M30-ECHO-V1",   // brand::DOMSEP_M30_ECHO
    "YUVA-M31-INFER-V1",  // brand::DOMSEP_M31_INFER
    "YUVA-M33-ATTEST-V1", // brand::DOMSEP_M33_ATTEST
];

// ===========================================================================
// The spine -- the FROZEN append-only organ registry (M38 conductor)
// ===========================================================================

/// The frozen `(tag, name)` snapshot of the M38 `conductor::Organ` enum -- the
/// enumerated agent-organ contract the whole loop is built on. Organ ids are
/// append-only exactly like syscall numbers: a new organ is a NEW tag, never a
/// renumber. Cross-checked against the live `conductor::Organ` tags below.
pub const FROZEN_ORGANS: &[(u8, &str)] = &[
    (0x00, "RetrievalOverMemory"),
    (0x01, "LocalM32"),
    (0x02, "ExternalMock"),
];

// ===========================================================================
// The FROZEN conformance-vector skeleton (docs/spec/yuva-abi-v1.md §6)
//
// The POSITIVE agent-agnostic demonstration: a mini/mock conformant agent
// (in-kernel, sharing no code with the resident agent's M12/M38 runtime) binds
// through the two planes and passes these FROZEN literal vectors. Committed
// literals, NOT recomputed at test time. The Plane-1 family is the load-bearing
// one -- it runs against the REAL `caps::dispatch` gate, so a RELAXED admission
// (a negative vector returning Ok instead of Denied) FAILS the conformance lane.
// ===========================================================================

/// Expected outcome tag for a [`CONFORMANCE_CAP_VECTORS`] row: dispatch returns
/// `SysStatus::Ok`.
pub const EXPECT_OK: u8 = 0;
/// Expected outcome: dispatch returns `SysStatus::Denied` (the rights gate
/// fail-closed BEFORE any method body -- a NEGATIVE vector).
pub const EXPECT_DENIED: u8 = 1;
/// Expected outcome: dispatch returns `SysStatus::BadMethod` (the method space
/// is closed; an unknown number is rejected).
pub const EXPECT_BADMETHOD: u8 = 2;

/// Frozen Plane-1 capability-dispatch conformance vectors:
/// `(method, granted_rights_bits, expected_outcome)`. Run IN-KERNEL against the
/// real `caps::dispatch` gate by minting a handle carrying `granted_rights_bits`
/// and invoking `method`. The NEGATIVE (`EXPECT_DENIED`) rows are the runtime
/// complement to the registry cross-check: a relaxed admission that returns `Ok`
/// where `Denied` is frozen FAILS. The gate fail-closes before any method body,
/// so the negative + `BadMethod` rows are body-independent (safe at any boot
/// stage); the one positive uses `M_OBJECT_INSPECT` (proven `Ok` at M11).
pub const CONFORMANCE_CAP_VECTORS: &[(u32, u32, u8)] = &[
    (0, 1, EXPECT_OK),        // M_OBJECT_INSPECT, granted READ            -> Ok
    (21, 1, EXPECT_DENIED),   // M_EMIT_EXTERNAL, granted READ (no EMIT)   -> Denied
    (18, 1, EXPECT_DENIED),   // M_MEM_WRITE_PROC, granted READ (no WPROC) -> Denied
    (16, 1, EXPECT_DENIED),   // M_AGENT_SPAWN, granted READ (no SPAWN)    -> Denied
    (0xDEAD, 0x1FFF, EXPECT_BADMETHOD), // unknown method, all rights      -> BadMethod
];

// ===========================================================================
// Frozen-internal consistency (compile-time; NOT a cross-check -- these pin the
// literals' self-consistency so a typo in THIS file is a compile error)
// ===========================================================================

const _: () = {
    // The four frame magics are pairwise disjoint AS LITERALS (extends the
    // brand three-magic assert to all four -- the enforced union the module
    // header promises).
    let m = FROZEN_WIRE_MAGICS;
    assert!(m.len() == 4);
    let mut i = 0;
    while i < m.len() {
        let mut j = i + 1;
        while j < m.len() {
            assert!(m[i].0 != m[j].0, "abi: frame magic collision");
            j += 1;
        }
        i += 1;
    }
};

const _: () = {
    // The method ceiling equals the highest frozen id, and ids are strictly
    // increasing (no dup / no out-of-order -- append-only).
    let t = FROZEN_METHODS;
    assert!(t[0].0 == 0);
    let mut i = 1;
    let mut max = t[0].0;
    while i < t.len() {
        assert!(t[i].0 > t[i - 1].0, "abi: method ids not strictly increasing");
        if t[i].0 > max {
            max = t[i].0;
        }
        i += 1;
    }
    assert!(max == METHOD_CEILING, "abi: METHOD_CEILING != max frozen id");
};

// ===========================================================================
// The cross-check test -- the tb-encode-visible half (wire magics, domain
// labels, organ tags) against the LIVE brand / attest / conductor constants.
// A genuine drift detector: a renumbered magic / relabelled domain / renumbered
// organ FAILS here. (The caps-side method/rights half runs in-kernel; see the
// module header.) Runs under `cargo test -p tb-encode` / `cargo miri test`.
// ===========================================================================
#[cfg(test)]
mod abi_snapshot {
    use super::*;
    use crate::attest;
    use crate::conductor::{self, Organ, N_ORGANS};

    /// Each frozen frame magic equals its LIVE source constant. As of Yuva-ABI
    /// stage B all four are single-sourced in `brand` (`ATTEST_MAGIC` is now a
    /// re-export of `brand::MAGIC_ATTEST`). A renumber of any live magic FAILS.
    #[test]
    fn frozen_wire_magics_match_live() {
        for &(magic, name) in FROZEN_WIRE_MAGICS {
            let live = match name {
                "MAGIC_OPFRAME" => brand::MAGIC_OPFRAME,
                "MAGIC_OPFRAME_RX" => brand::MAGIC_OPFRAME_RX,
                "MAGIC_INFERWIRE" => brand::MAGIC_INFERWIRE,
                "MAGIC_ATTEST" => brand::MAGIC_ATTEST,
                other => panic!("abi: FROZEN_WIRE_MAGICS has an unmapped name {other:?}"),
            };
            assert_eq!(
                live, magic,
                "abi: live wire magic {name} = {live:#06x} != frozen {magic:#06x} (renumber)"
            );
        }
        // The `attest::ATTEST_MAGIC` re-export resolves to the same brand source
        // (guards a future divergence of the codec-local alias from its home).
        assert_eq!(attest::ATTEST_MAGIC, brand::MAGIC_ATTEST);
    }

    /// All four LIVE frame magics are pairwise disjoint (via the frozen==live
    /// bridge above + the frozen-literal disjointness const-assert). This is the
    /// enforced union; `brand`'s own KAT covers the same four.
    #[test]
    fn all_four_live_magics_disjoint() {
        let live = [
            brand::MAGIC_OPFRAME,
            brand::MAGIC_OPFRAME_RX,
            brand::MAGIC_INFERWIRE,
            brand::MAGIC_ATTEST,
        ];
        for i in 0..live.len() {
            for j in (i + 1)..live.len() {
                assert_ne!(live[i], live[j], "abi: live frame magic collision");
            }
        }
    }

    /// Each frozen domain separator equals its LIVE `brand::DOMSEP_*` byte string.
    /// A relabel (e.g. a reverted "TABOS-*") FAILS.
    #[test]
    fn frozen_domsep_match_live() {
        for &label in FROZEN_DOMSEP {
            let live: &[u8] = match label {
                "YUVA-OPCMD-KDF-V1" => brand::DOMSEP_OPCMD_KDF,
                "YUVA-KEY-EVOLVE-V1" => brand::DOMSEP_KEY_EVOLVE,
                "YUVA-M30-ECHO-V1" => brand::DOMSEP_M30_ECHO,
                "YUVA-M31-INFER-V1" => brand::DOMSEP_M31_INFER,
                "YUVA-M33-ATTEST-V1" => brand::DOMSEP_M33_ATTEST,
                other => panic!("abi: FROZEN_DOMSEP has an unmapped label {other:?}"),
            };
            assert_eq!(
                live,
                label.as_bytes(),
                "abi: live domain separator != frozen {label:?} (relabel)"
            );
        }
    }

    /// Each frozen organ `(tag, name)` equals the LIVE `conductor::Organ`
    /// tag/decode, and the count matches `N_ORGANS`. A renumbered organ tag FAILS.
    #[test]
    fn frozen_organs_match_live() {
        assert_eq!(
            FROZEN_ORGANS.len(),
            N_ORGANS,
            "abi: frozen organ count != conductor::N_ORGANS (organ added/removed)"
        );
        for (i, &(tag, name)) in FROZEN_ORGANS.iter().enumerate() {
            let organ = Organ::at(i).expect("abi: frozen organ index past N_ORGANS");
            assert_eq!(organ.tag(), tag, "abi: live organ tag != frozen for {name}");
            assert_eq!(
                Organ::from_tag(tag),
                Some(organ),
                "abi: organ tag {tag:#04x} does not round-trip"
            );
            // The frozen NAME matches the enum variant it stands for (guards a
            // silent variant swap that kept the tag).
            let expect = match name {
                "RetrievalOverMemory" => Organ::RetrievalOverMemory,
                "LocalM32" => Organ::LocalM32,
                "ExternalMock" => Organ::ExternalMock,
                other => panic!("abi: FROZEN_ORGANS has an unmapped name {other:?}"),
            };
            assert_eq!(organ, expect, "abi: frozen organ name {name} maps to the wrong variant");
        }
        // The registry above the ceiling is empty (append-only: no tag 3 yet).
        assert!(conductor::Organ::at(N_ORGANS).is_none());
    }

    /// The version token is the single, self-consistent two-axis snapshot.
    #[test]
    fn version_token_is_v1() {
        assert_eq!(YUVA_ABI_VERSION.cap_major, 1);
        assert_eq!(YUVA_ABI_VERSION.cap_minor, 0);
        assert_eq!(YUVA_ABI_VERSION.wire, 1);
        assert_eq!(PLANES, 2);
        // The wire-plane ceiling covers the landed per-frame ver bytes.
        assert_eq!(attest::ATTEST_VERSION, 1);
    }

    /// FROZEN_METHODS is internally well-formed at the value level (the live
    /// cross-check is `caps::abi_registry_selfcheck`, in-kernel). Guards a
    /// hand-edit typo in the frozen table: unique ids, unique names, and every
    /// `required_right_bits` value is a member of FROZEN_RIGHTS.
    #[test]
    fn frozen_methods_wellformed() {
        assert_eq!(FROZEN_METHODS.len(), 23);
        for (a, &(id, name, bits)) in FROZEN_METHODS.iter().enumerate() {
            assert!(
                FROZEN_RIGHTS.iter().any(|&(b, _)| b == bits),
                "abi: method {name} maps to right bits {bits:#x} not in FROZEN_RIGHTS"
            );
            for &(id2, name2, _) in &FROZEN_METHODS[a + 1..] {
                assert_ne!(id, id2, "abi: duplicate method id {id}");
                assert_ne!(name, name2, "abi: duplicate method name {name}");
            }
        }
    }
}
