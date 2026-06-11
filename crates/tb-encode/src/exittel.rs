//! The M26 verified EL2 EXIT-TELEMETRY codec math -- the pure, verified value-
//! computation leaf that turns the aarch64 EL2 (nVHE) monitor's guest-exit demux
//! into a BOUNDED, fixed-point, injective, tamper-evident TELEMETRY RECORD, lifted
//! into `tb-encode` exactly as the M23 experience codec ([`crate::exp`]) was. The EL2
//! monitor ALREADY classifies every guest exit by `ESR_EL2.EC` via the already-Kani-
//! proven [`crate::el2_trap::classify_exit`] (L2.2); M26 COUNTS those exits into a
//! bounded no-float histogram and records each as a fixed-field [`ExitTelemetryRecord`]
//! folded into a per-instance `tel_head` via the M22 [`crate::prov`] fold REUSED
//! verbatim (M26 writes NO new fold math, exactly as M23). So the OS *records* its own
//! virtualization workload -- a SECOND experience producer next to the M17 forget/
//! recall decisions.
//!
//! ## Honest scope (proposal §5 -- the marker claims ONLY what is proved)
//!
//! * **PRODUCER-ONLY (`signal=OBSERVATIONAL-NONCAUSAL`).** The telemetry is recorded
//!   and folded; it is NOT this milestone fed to any policy whose decisions change the
//!   future exit distribution. Learning from one's own logs is confounded and the OPE
//!   bias is non-identifiable (the M24 adversary's exogeneity problem, restated for an
//!   exit stream); M26 does not close any exit->policy->exit loop. The honesty token is
//!   machine-emitted so the marker mechanically cannot claim a causal state-signal.
//! * **CLAIMS injective bounded encoding + replay-determinism + tamper-evidence
//!   (cryptographic since M29-C)** (the M23 claim set): a single-byte mutation of a
//!   committed record provably invalidates the recomputed `tel_head` AND its
//!   inclusion proof -- the M22 fold reused verbatim (khash/BLAKE2s-256 since M29
//!   stage C; `sec=ASSUMED-FROM-LITERATURE`). Per-class counts are EXACT (a direct-
//!   mapped per-class histogram over the small CLOSED `ExitClass` set -- no sketch
//!   collisions to bound); the cost-proxy bucket is a RELATIVE shape, not a validated
//!   cost model, and under QEMU TCG is not cycle-accurate.
//! * **The `tel_head` is SEPARATE from the M23 `xp_head`** (a deliberate zero-
//!   regression refinement of proposal §2.3): the M23/M22 heads stay byte-identical;
//!   the exit stream is its own verified chain over the SAME reused M22 fold.
//!
//! ## Numeric format (no float, ever -- mirrors `exp`/`prov`)
//!
//! Pure integer/byte arithmetic, zero alloc, zero deps. [`canon`] is a FIXED-WIDTH,
//! fixed-field-order LE byte layout into a caller buffer (total + fail-closed: returns
//! `0` if the buffer is too small, never panics). [`decode`] is the inverse over a
//! large-enough buffer (fail-closed to `None`). The bucket index is an integer `log2`
//! (`leading_zeros`-based -- the OpenTelemetry exponential-histogram idea WITHOUT the
//! float mapping). The fold REUSES the proven [`crate::prov`] leaf -- NO new fold math.

// The fold is the M22 provenance leaf, REUSED verbatim (no new fold math), exactly as
// M23. We import the proven digest / fold / verify / witness functions.
pub use crate::prov::{
    append as tel_append, chain_mix as tel_chain_mix, head_witness as tel_head_witness,
    prov_hash as tel_hash, recompute as tel_recompute, verify_inclusion as tel_verify_inclusion,
    PROV_HASH_LEN,
};

// The exit classifier is the already-Kani-proven L2.2 leaf, REUSED verbatim. M26
// counts its output; it does NOT re-decode ESR.
pub use crate::el2_trap::{classify_exit, ExitClass};

/// The telemetry-record kind tag (proposal §2.3). A NEW tag so an exit-telemetry
/// record can never masquerade as an M23 forget-decision/recall-touch even if the two
/// streams are ever merged into one head (the tag is folded into the digest -> the
/// byte differs -> the head differs). The closed set the exit producer emits.
pub mod kind {
    /// An EL2 guest-exit telemetry observation.
    pub const EXIT_TELEMETRY: u8 = 1;
}

/// The number of distinct exit CLASSES (the [`ExitClass`] variants): the histogram has
/// one direct-mapped bucket row per class, so per-class counts are EXACT (no sketch
/// collisions over this small closed set -- the safer first increment vs Count-Min).
pub const N_CLASSES: usize = 6;

/// The number of log2 cost-proxy BUCKETS per class. A cost delta is bucketed by its
/// high-bit index (`0..=N_BUCKETS-1`), saturating into the top bucket -- the OTel
/// exponential-histogram base-2 idea, integer-only. 16 buckets cover deltas up to
/// `2^15` cycles before saturating (a wide dynamic range for an exit-handling cost).
pub const N_BUCKETS: usize = 16;

/// The stable `u8` tag for an [`ExitClass`] (the canonical-record class byte). A total,
/// injective mapping onto `0..N_CLASSES` -- load-bearing for [`canon`] injectivity (two
/// records that differ only in class must differ at the class byte). The inverse is
/// [`class_from_tag`]; together they are a bijection on the 6 classes (the
/// `kani_exittel_class_total` harness proves it).
#[inline]
#[must_use]
pub fn class_tag(c: ExitClass) -> u8 {
    match c {
        ExitClass::StageTwoAbort => 0,
        ExitClass::Hvc => 1,
        ExitClass::Smc => 2,
        ExitClass::Sys64 => 3,
        ExitClass::Wfx => 4,
        ExitClass::Undef => 5,
    }
}

/// Reconstruct an [`ExitClass`] from its [`class_tag`] byte, or `None` for an unknown
/// tag (the [`decode`] inverse -- fail-closed, total, no panic).
#[inline]
#[must_use]
pub fn class_from_tag(tag: u8) -> Option<ExitClass> {
    match tag {
        0 => Some(ExitClass::StageTwoAbort),
        1 => Some(ExitClass::Hvc),
        2 => Some(ExitClass::Smc),
        3 => Some(ExitClass::Sys64),
        4 => Some(ExitClass::Wfx),
        5 => Some(ExitClass::Undef),
        _ => None,
    }
}

/// The bounded log2 BUCKET index for a cost-proxy `delta` (the exit-handling cycle/tick
/// delta the monitor already has): the index of the high set bit (`63 -
/// leading_zeros`), SATURATING into the top bucket `N_BUCKETS-1`. `delta == 0` -> bucket
/// `0`. TOTAL, no float, no panic, no overflow over ALL `u64` (the
/// `kani_exittel_histogram_saturates` harness proves the result is always in
/// `0..N_BUCKETS`). This is the OTel exponential-histogram base-2 idea without the float
/// mapping.
#[inline]
#[must_use]
pub fn bucket_index(delta: u64) -> usize {
    if delta == 0 {
        return 0;
    }
    let hi = 63 - (delta.leading_zeros() as usize); // 0..=63, the high set-bit index
    if hi >= N_BUCKETS {
        N_BUCKETS - 1
    } else {
        hi
    }
}

/// A fixed, canonical EL2 exit-telemetry record (proposal §2.3). EVERY field is FIXED-
/// WIDTH, so [`canon`] is injective by construction (no variable-length tail). It
/// captures ONE exit observation: its class, the cost-proxy bucket, the saturating
/// count in that `(class, bucket)` cell at record time, the logical clock, and the
/// guest VMID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitTelemetryRecord {
    /// The record kind (see [`kind`]): always [`kind::EXIT_TELEMETRY`] this milestone.
    pub kind: u8,
    /// The [`class_tag`] of the exit's [`ExitClass`] (`0..N_CLASSES`).
    pub exit_class: u8,
    /// The log2 cost-proxy bucket (`0..N_BUCKETS`) from [`bucket_index`].
    pub bucket: u8,
    /// The guest VMID the exit came from (the producer of this experience).
    pub vmid: u16,
    /// The SATURATING count in the `(exit_class, bucket)` histogram cell at record time
    /// (monotone non-decreasing; never wraps -- the saturating-add invariant).
    pub count_in_bucket: u64,
    /// The logical (boot-relative) clock at the exit.
    pub logical_time: u64,
}

/// The fixed canonical byte length of EVERY [`ExitTelemetryRecord`] (fully fixed-width).
/// Layout (fixed field order, all LE):
///
/// ```text
///   [0]      kind            u8
///   [1]      exit_class      u8
///   [2]      bucket          u8
///   [3..5]   vmid            u16 LE
///   [5..13]  count_in_bucket u64 LE
///   [13..21] logical_time    u64 LE
/// ```
pub const EXITTEL_CANON_LEN: usize = 1 + 1 + 1 + 2 + 8 + 8;

const OFF_KIND: usize = 0;
const OFF_CLASS: usize = 1;
const OFF_BUCKET: usize = 2;
const OFF_VMID: usize = 3;
const OFF_COUNT: usize = 5;
const OFF_TIME: usize = 13;

/// The exact canonical byte length of `rec` -- a tautological [`EXITTEL_CANON_LEN`]
/// (fixed-width), kept as a function to mirror [`crate::exp::canon_len`] so the seam
/// sizes its scratch identically.
#[inline]
#[must_use]
pub fn canon_len(_rec: &ExitTelemetryRecord) -> usize {
    EXITTEL_CANON_LEN
}

/// Canonical, UNAMBIGUOUS, total fixed-width LE encoding of `rec` into `out`. Returns
/// the bytes written ([`EXITTEL_CANON_LEN`]), or `0` if `out` is too small (TOTAL +
/// fail-closed: never panics, never partial-writes -- mirrors [`crate::exp::canon`]).
/// INJECTIVE: every field at a fixed offset, no variable-length tail.
#[must_use]
pub fn canon(rec: &ExitTelemetryRecord, out: &mut [u8]) -> usize {
    if out.len() < EXITTEL_CANON_LEN {
        return 0;
    }
    out[OFF_KIND] = rec.kind;
    out[OFF_CLASS] = rec.exit_class;
    out[OFF_BUCKET] = rec.bucket;
    let vm = rec.vmid.to_le_bytes();
    out[OFF_VMID] = vm[0];
    out[OFF_VMID + 1] = vm[1];
    let c = rec.count_in_bucket.to_le_bytes();
    let t = rec.logical_time.to_le_bytes();
    let mut i = 0usize;
    while i < 8 {
        out[OFF_COUNT + i] = c[i];
        out[OFF_TIME + i] = t[i];
        i += 1;
    }
    EXITTEL_CANON_LEN
}

/// The exact inverse of [`canon`]: decode `buf` into an [`ExitTelemetryRecord`], or
/// `None` if `buf` is too small OR carries an unknown class tag (TOTAL + fail-closed,
/// never panics). A successful decode round-trips back to identical canonical bytes
/// (the `kani_exittel_canon_roundtrip` harness).
#[must_use]
pub fn decode(buf: &[u8]) -> Option<ExitTelemetryRecord> {
    if buf.len() < EXITTEL_CANON_LEN {
        return None;
    }
    let exit_class = buf[OFF_CLASS];
    // Fail-closed on an unknown class tag (so decode + canon agree on the class set).
    class_from_tag(exit_class)?;
    let vmid = u16::from_le_bytes([buf[OFF_VMID], buf[OFF_VMID + 1]]);
    let count_in_bucket = u64::from_le_bytes([
        buf[OFF_COUNT],
        buf[OFF_COUNT + 1],
        buf[OFF_COUNT + 2],
        buf[OFF_COUNT + 3],
        buf[OFF_COUNT + 4],
        buf[OFF_COUNT + 5],
        buf[OFF_COUNT + 6],
        buf[OFF_COUNT + 7],
    ]);
    let logical_time = u64::from_le_bytes([
        buf[OFF_TIME],
        buf[OFF_TIME + 1],
        buf[OFF_TIME + 2],
        buf[OFF_TIME + 3],
        buf[OFF_TIME + 4],
        buf[OFF_TIME + 5],
        buf[OFF_TIME + 6],
        buf[OFF_TIME + 7],
    ]);
    Some(ExitTelemetryRecord {
        kind: buf[OFF_KIND],
        exit_class,
        bucket: buf[OFF_BUCKET],
        vmid,
        count_in_bucket,
        logical_time,
    })
}

/// A bounded, direct-mapped, SATURATING per-class exit histogram (proposal §2.2): one
/// `[u64; N_BUCKETS]` counter row per [`ExitClass`]. NO alloc, NO float. [`record`] is
/// TOTAL: a saturating add can never overflow/panic, and the count is monotone non-
/// decreasing per cell (the `kani_exittel_histogram_saturates` invariant). Direct-
/// mapped over the small CLOSED class set -> per-class counts are EXACT (no sketch
/// collisions).
#[derive(Clone, Copy, Debug)]
pub struct ExitHistogram {
    cells: [[u64; N_BUCKETS]; N_CLASSES],
}

impl Default for ExitHistogram {
    fn default() -> Self {
        Self::new()
    }
}

impl ExitHistogram {
    /// A fresh, all-zero histogram. No alloc.
    #[must_use]
    pub const fn new() -> Self {
        ExitHistogram {
            cells: [[0u64; N_BUCKETS]; N_CLASSES],
        }
    }

    /// Record ONE exit of class `c` with cost-proxy `delta`: bucket it via
    /// [`bucket_index`], SATURATING-increment the `(class, bucket)` cell, and return
    /// `(bucket, new_count)`. TOTAL -- never overflows (saturating), never panics
    /// (every index is in range by construction). The returned `new_count` is the
    /// value the matching [`ExitTelemetryRecord::count_in_bucket`] carries.
    pub fn record(&mut self, c: ExitClass, delta: u64) -> (u8, u64) {
        let bucket = bucket_index(delta);
        let class = class_tag(c) as usize;
        // Both indices are in range by construction (class_tag < N_CLASSES,
        // bucket_index < N_BUCKETS), so this never panics.
        let cell = &mut self.cells[class][bucket];
        *cell = cell.saturating_add(1);
        (bucket as u8, *cell)
    }

    /// Read the exact count in the `(class, bucket)` cell (`0` if out of range -- total,
    /// no panic). The boot self-test asserts the recorded counts are bucket-exact.
    #[inline]
    #[must_use]
    pub fn count(&self, c: ExitClass, bucket: usize) -> u64 {
        let class = class_tag(c) as usize;
        if class >= N_CLASSES || bucket >= N_BUCKETS {
            return 0;
        }
        self.cells[class][bucket]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::el2_trap::{EC_DABT_LOW, EC_HVC64, EC_SMC64, EC_SYS64, EC_WFX};

    fn sample() -> ExitTelemetryRecord {
        ExitTelemetryRecord {
            kind: kind::EXIT_TELEMETRY,
            exit_class: class_tag(ExitClass::Sys64),
            bucket: 5,
            vmid: 0x1234,
            count_in_bucket: 42,
            logical_time: 0xCAFE,
        }
    }

    #[test]
    fn canon_len_is_fixed_width() {
        assert_eq!(EXITTEL_CANON_LEN, 21);
        let e = sample();
        assert_eq!(canon_len(&e), EXITTEL_CANON_LEN);
        let mut buf = [0u8; 32];
        assert_eq!(canon(&e, &mut buf), EXITTEL_CANON_LEN);
    }

    #[test]
    fn canon_fail_closed_on_small_buffer() {
        let e = sample();
        let mut small = [0u8; EXITTEL_CANON_LEN - 1];
        assert_eq!(canon(&e, &mut small), 0);
        assert!(small.iter().all(|&b| b == 0));
    }

    #[test]
    fn canon_decode_roundtrip() {
        let e = sample();
        let mut buf = [0u8; EXITTEL_CANON_LEN];
        assert_eq!(canon(&e, &mut buf), EXITTEL_CANON_LEN);
        assert_eq!(decode(&buf), Some(e));
    }

    #[test]
    fn decode_fail_closed_short_and_bad_class() {
        let e = sample();
        let mut buf = [0u8; EXITTEL_CANON_LEN];
        assert_eq!(canon(&e, &mut buf), EXITTEL_CANON_LEN);
        assert_eq!(decode(&buf[..EXITTEL_CANON_LEN - 1]), None);
        buf[OFF_CLASS] = 0xFF; // unknown class tag
        assert_eq!(decode(&buf), None);
    }

    fn enc(e: &ExitTelemetryRecord) -> [u8; EXITTEL_CANON_LEN] {
        let mut b = [0u8; EXITTEL_CANON_LEN];
        assert_eq!(canon(e, &mut b), EXITTEL_CANON_LEN);
        b
    }

    #[test]
    fn canon_injective_each_field() {
        let base = sample();
        let b = enc(&base);
        let mut c = base;
        c.exit_class = class_tag(ExitClass::Wfx);
        assert_ne!(enc(&c), b);
        let mut k = base;
        k.bucket ^= 1;
        assert_ne!(enc(&k), b);
        let mut v = base;
        v.vmid ^= 1;
        assert_ne!(enc(&v), b);
        let mut n = base;
        n.count_in_bucket ^= 1;
        assert_ne!(enc(&n), b);
        let mut t = base;
        t.logical_time ^= 1;
        assert_ne!(enc(&t), b);
    }

    #[test]
    fn class_tag_bijection() {
        for c in [
            ExitClass::StageTwoAbort,
            ExitClass::Hvc,
            ExitClass::Smc,
            ExitClass::Sys64,
            ExitClass::Wfx,
            ExitClass::Undef,
        ] {
            assert_eq!(class_from_tag(class_tag(c)), Some(c));
            assert!((class_tag(c) as usize) < N_CLASSES);
        }
        assert_eq!(class_from_tag(6), None);
    }

    #[test]
    fn bucket_index_is_bounded_and_log2() {
        assert_eq!(bucket_index(0), 0);
        assert_eq!(bucket_index(1), 0); // bit 0
        assert_eq!(bucket_index(2), 1);
        assert_eq!(bucket_index(3), 1);
        assert_eq!(bucket_index(4), 2);
        assert_eq!(bucket_index(1 << 15), N_BUCKETS - 1);
        assert_eq!(bucket_index(u64::MAX), N_BUCKETS - 1); // saturates
        for d in [0u64, 1, 7, 255, 1 << 20, u64::MAX] {
            assert!(bucket_index(d) < N_BUCKETS);
        }
    }

    #[test]
    fn histogram_saturating_and_exact() {
        let mut h = ExitHistogram::new();
        // Distinct classes land in distinct rows; counts are exact.
        let (b0, c0) = h.record(ExitClass::Wfx, 1);
        assert_eq!((b0, c0), (0, 1));
        let (b1, c1) = h.record(ExitClass::Wfx, 1);
        assert_eq!((b1, c1), (0, 2));
        assert_eq!(h.count(ExitClass::Wfx, 0), 2);
        assert_eq!(h.count(ExitClass::Hvc, 0), 0); // a different class is untouched
        // A larger delta lands in a higher bucket.
        let (b2, _) = h.record(ExitClass::Wfx, 1 << 10);
        assert_eq!(b2, 10);
        assert_eq!(h.count(ExitClass::Wfx, 10), 1);
    }

    #[test]
    fn classify_then_record_via_reused_classifier() {
        // The reused L2.2 classifier maps a synthetic ESR to its class; we record it.
        let mut h = ExitHistogram::new();
        let esrs = [
            (EC_DABT_LOW << 26, ExitClass::StageTwoAbort),
            (EC_HVC64 << 26, ExitClass::Hvc),
            (EC_SMC64 << 26, ExitClass::Smc),
            (EC_SYS64 << 26, ExitClass::Sys64),
            (EC_WFX << 26, ExitClass::Wfx),
            (0x07u64 << 26, ExitClass::Undef),
        ];
        for (esr, want) in esrs {
            let c = classify_exit(esr);
            assert_eq!(c, want);
            let (_b, n) = h.record(c, 8);
            assert_eq!(n, 1);
        }
    }

    #[test]
    fn fold_is_tamper_sensitive_via_prov() {
        let e0 = sample();
        let mut e1 = sample();
        e1.logical_time = 999;
        let mut scratch = [0u8; EXITTEL_CANON_LEN + 8];
        let n0 = canon(&e0, &mut scratch);
        let id0 = tel_hash(&scratch[..n0]);
        let n1 = canon(&e1, &mut scratch);
        let id1 = tel_hash(&scratch[..n1]);
        let head = tel_recompute(id0, &[id1]);
        assert!(tel_verify_inclusion(id0, &[id1], head));
        let mut tampered = [0u8; EXITTEL_CANON_LEN];
        assert_eq!(canon(&e0, &mut tampered), EXITTEL_CANON_LEN);
        tampered[OFF_COUNT] ^= 0x01;
        let bad = tel_hash(&tampered);
        assert!(!tel_verify_inclusion(bad, &[id1], head));
    }
}
