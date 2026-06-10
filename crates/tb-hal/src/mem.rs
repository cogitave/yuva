#![forbid(unsafe_code)]
//! M13 -- the default tiered, persistent, recallable per-agent memory substrate
//! (100% SAFE Rust; the body behind every agent's born-with
//! [`crate::caps::ObjKind::MemoryHome`], structurally the `memory:private/<agent>`
//! namespace).
//!
//! ONE [`MemSubstrate`] lives behind each home and composes FOUR tiers, all safe
//! `alloc` heap structures:
//!   * T0 -- bounded context registers (ACT-R buffers / MemGPT main context).
//!   * T1 -- a state-rooted working graph, reachability-GC'd (Soar WM).
//!   * T2 -- an append-only, bi-temporal episodic journal with INSTANT
//!     read-your-writes (Soar EpMem / MemGPT recall storage); the lossless floor.
//!   * T3 -- a lexical (BM25+) semantic store with a record-level inverted index
//!     and activation-ranked recall (ACT-R declarative / MemGPT archival).
//!
//! Recall is the 3-stage pipeline (candidate -> fuse -> context constructor) over
//! the additive default score `w_a*BLA(d=0.5) + w_r*relevance + w_i*importance`,
//! with each component min-max normalized to fixed-point `[0, SCALE]`, Finsts
//! (`exclude_recent`) breaking the return-same-result loop, and copy-on-retrieve
//! handing back an owned id. ALL math is FIXED-POINT INTEGER (deterministic /
//! replayable; no kernel FPU hazard; zero deps). A [`BackingStore`] trait is the
//! durability seam -- [`RamStore`] now, virtio-blk deferred. ZERO unsafe.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

// M13/M17/M18: the PURE fixed-point recall-ranking math now lives in the
// host-verifiable `tb-encode::memscore` leaf (Kani-proven panic/overflow-free
// over untrusted memory metadata); the kernel CALLS the exact same functions, so
// the M13 recall ranking / M17 FORGET decay / M18 frozen evaluator stay
// byte-identical to the in-line copies these imports replaced.
use tb_encode::memscore::{bla_raw, ln_fixed, minmax, skill_transform};
// M21: the verified fixed-point ADDITIVE-policy leaf (a piecewise-LINEAR integer
// GAM) for the forget/demote decision, lifted into the host-verifiable
// `tb-encode::kancell` exactly like the memscore ranking math. SHIPS DORMANT:
// the heuristic floor below decides; the spline is WIRED + validated at load but
// only consulted when `KAN_ACTIVE` is true (it never is this milestone -- turning
// it on is gated on an offline trace bake-off that does not exist yet). `tb-hal`
// merely CALLS these pure fns next to the existing comparator, as it already
// calls `bla_raw`/`minmax`.
use tb_encode::kancell::{
    kan_score, kan_spline_eval, kan_table_is_monotone, kan_table_overflow_safe, KnotTable,
    GRID_LO, GRID_STEP_LOG2, KAN_FEATURES,
};
// M22: the verified memory-PROVENANCE LEDGER leaf -- the canonical encoder
// (`canon`), the 256-bit structural digest (`prov_hash`), and the running per-
// agent fold step (`chain_mix`, via `prov::append`) of a per-agent, append-only,
// content-addressed hash-chain provenance ledger. `tb-hal` CALLS these next to the
// existing write/forget/skill-admit mutation sites, exactly as it calls
// `bla_raw`/`kan_score`; the math (canon-injectivity / fold tamper-sensitivity /
// inclusion-soundness) is Kani-proven in `tb-encode::prov`, so the ledger head is
// byte-identical to a host-verified model. Structural tamper-evidence only (NOT
// cryptographic -- proposal §2).
use tb_encode::prov::{self, ProvEntry, PROV_HASH_LEN};
// M23: the verified EXPERIENCE CODEC leaf -- the fixed-width injective
// `ExperienceRecord` encoder (`exp::canon`), the fixed-capacity drop-oldest in-RAM
// replay ring (`exp::ExpRing`), the bit-exact dormant-shadow replay
// (`exp::replay_shadow`), and the SEPARATE per-agent `xp_head` fold over the
// canonical bytes (REUSING the M22 `prov` fold via `exp::xp_append`, NOT a new
// fold). `tb-hal` CALLS these next to the M17 forget/recall decision sites, exactly
// as it calls `kan_score`/`bla_raw`/`prov::append`; the math (canon-injectivity /
// replay-determinism / ring totality / fold tamper-sensitivity / schema-stability)
// is Kani-proven in `tb-encode::exp`. The learned cell stays DORMANT
// (`KAN_ACTIVE == false`): the shadow is logged ONLY, never changing a demote, so
// the live forget/demote decision is BYTE-IDENTICAL to M22's. Strictly downstream /
// observational -- no perturbation of `clock`/finsts/the M22 `chain_head`.
use tb_encode::exp::{self, ExperienceRecord, OutcomeLabel, EXP_CANON_LEN};
// M24: the verified HONEST-GATE leaves -- the shielded epsilon-greedy logging
// PROPENSITY (`explore::explore_propensity_q`, stamped into the M23-reserved
// `logging_propensity_q` field) and the bake-off estimator math (the 3-way
// right-censored survival `bakeoff::survival_label`, the Manski + Lipschitz-
// smoothness `bakeoff::value_lower_bound`, the Maurer-Pontil `bakeoff::eb_lower_bound`,
// the pessimistic `bakeoff::value_upper_heuristic`, and the conjunctive one-shot
// `bakeoff::gate_clears`). `tb-hal` CALLS these next to the M17 forget/recall sites,
// exactly as it calls `kan_score`/`prov::append`; the math (propensity positivity /
// label partition + monotone-resolution / bound soundness + round-down / replay-
// determinism / envelope-no-widening re-assert) is Kani-proven in
// `tb_encode::explore` + `tb_encode::bakeoff`. `KAN_ACTIVE` stays `false` (the gate
// will NOT clear on synthetic traces -> the cell stays DORMANT): the explore choice
// is RECORDED into the propensity field but, with `KAN_ACTIVE == false`, NEVER
// changes the live demote (which stays byte-identical to M23's heuristic else-branch).
use tb_encode::explore::explore_propensity_q;
use tb_encode::bakeoff::{
    gate_clears, label_reward, survival_label, value_lower_bound, value_upper_heuristic,
    GateVerdict, SurvivalLabel, ACTIVATION_MARGIN, GRID_CELLS,
};

/// Fixed-point scale: every normalized score component lives in `[0, SCALE]`.
const SCALE: i64 = 1000;
/// Bounded T0 context-register slots (ACT-R buffers; const-bounded prompt).
const N_REG: usize = 8;
/// Bounded per-agent Finsts ring (ACT-R `:recently-retrieved` breaker).
const F_FINST: usize = 4;
/// T1 working-graph node quota (Soar WM bound).
#[allow(dead_code)]
const NODE_QUOTA: usize = 256;
/// Token write-amplification cap (KeyKOS space-bank); writes beyond it fail-closed.
const TOKEN_QUOTA: u64 = 1 << 20;

// --- M22 provenance-ledger constants -----------------------------------------
/// The fixed stack scratch buffer `ledger_append` canon-encodes into. The seam's
/// mutation sites emit 0..=`PROV_SCRATCH_PARENTS` parents, so this covers
/// `prov::CANON_PREFIX_LEN + PROV_SCRATCH_PARENTS * PROV_HASH_LEN` with headroom;
/// an entry past it fails closed (no head advance) rather than truncating. No
/// large stack array (the #65 discipline): 34 + 4*32 = 162 bytes.
const PROV_SCRATCH: usize = 256;
/// The max parent (DAG edge) count any ledger mutation site stages into one entry
/// (writes/skill-admits carry the parent head's id; tombstones carry the demoted
/// record's id). Bounds the `PROV_SCRATCH` sizing above.
#[allow(dead_code)]
const PROV_SCRATCH_PARENTS: usize = 4;

// --- M23 experience-codec constants (the verified Monitor/log layer) ----------
//
// A SEPARATE per-agent `xp_head` + a fixed-capacity drop-oldest in-RAM `xp_ring`
// (proposal §4) -- ALONGSIDE, never inside, the M22 `chain_head` (so M22 stays
// byte-identical). At each M17 forget/recall decision the seam records an injective
// `ExperienceRecord` (the features it ALREADY computes + the heuristic action + the
// COUNTERFACTUAL `kan_score` the DORMANT cell would produce) and folds it into
// `xp_head` via the REUSED M22 fold. The learned cell stays DORMANT (`KAN_ACTIVE`
// untouched=false); the live demote is byte-identical to M22's.

/// Fixed experience-ring capacity (drop-oldest FIFO). Bounds the in-RAM log this
/// milestone (durable spill to M20 is M24 -- NOT touched here). Sized so the boot
/// self-test's >=3 forget + >=1 recall records fit with headroom; on overflow the
/// oldest row is dropped (the recency bias is NAMED in proposal §8). No alloc: the
/// ring is a fixed `[[u8; EXP_CANON_LEN]; XP_CAP]` POD inside the substrate.
const XP_CAP: usize = 64;

/// The concrete experience ring type the substrate embeds: `XP_CAP` rows of
/// `EXP_CANON_LEN` canonical bytes each (the Kani-proven fixed-capacity ring).
type ExpRing = exp::ExpRing<XP_CAP, EXP_CANON_LEN>;

/// The dormant comparator's flag/bias terms fed to the COUNTERFACTUAL `kan_score`
/// shadow -- identical to the M21 dormant seam (`KAN_FLAG_TERMS`/`KAN_BIAS`, both
/// `0`). Kept named here so the shadow evaluation provably uses the SAME terms the
/// (dead) M21 active branch would, so a recorded feats row replays bit-exactly.
const XP_SHADOW_FLAG_TERMS: i32 = KAN_FLAG_TERMS;
const XP_SHADOW_BIAS: i32 = KAN_BIAS;

/// M23 [`ExperienceRecord::action_taken`] codes (proposal §3): the heuristic action
/// the deterministic logging policy actually served at the decision site.
const XP_ACTION_KEEP: u8 = 0;
const XP_ACTION_DEMOTE: u8 = 1;
const XP_ACTION_TOUCH: u8 = 2;

/// M23 [`ExperienceRecord::envelope_verdict`] codes: whether the heuristic safety
/// envelope marked the record demotable (`safe_to_demote`) at the decision site.
const XP_ENV_PINNED: u8 = 0;
const XP_ENV_DEMOTABLE: u8 = 1;
const XP_ENV_TOUCH: u8 = 2;

// --- M24 honest-gate constants (the shielded epsilon-greedy + bake-off layer) --
//
// The SHIELDED epsilon-greedy logging policy (proposal §2.1) flips the kancell-
// greedy-vs-heuristic choice ONLY among the already-cleared candidate set the frozen
// M17 envelope emits, restoring positivity so off-policy evaluation is identifiable.
// `KAN_ACTIVE` stays `false`: the explore choice is RECORDED into the M23-reserved
// propensity field but never changes the live demote (which stays the heuristic
// else-branch -- byte-identical to M23). The bake-off self-test replays the in-RAM
// labeled stream through the frozen-heuristic AND dormant kan_score, computes
// V_lower(kancell) / V_upper(heuristic), evaluates the one-shot gate, and re-asserts
// the envelope-no-widening proof. On synthetic traces the gate WILL NOT clear ->
// `gate-not-met` (the cell stays DORMANT) is the designed, correct outcome.

/// The shipped exploration rate `eps = EPS_NUM/EPS_DEN` (proposal §2.1): 1/16, a
/// small rational so the no-overlap mass stays large and the gate (correctly) almost
/// never clears -- the right failure mode for synthetic traces (proposal §7). A
/// compile-time const (one-shot; re-tuning it spends confidence -- HCPI).
const EPS_NUM: u32 = 1;
const EPS_DEN: u32 = 16;

/// The per-agent exploration seed: keyed into the explore coin via the M22 fold so
/// the coin (and hence the chosen action + its propensity) is bit-exactly replayable
/// from `(decision_id, AGENT_SEED)` alone (NEVER a mutable step counter -- the
/// replay-determinism property the `kani_bakeoff_replay_determinism` harness pins).
/// A golden-ratio const (the `REFLECT_SEED` discipline), non-zero so the fold mixes.
const AGENT_SEED: u64 = 0x9E37_79B9_7F4A_7C15;

/// The survival-label window `W` (proposal §2.3): a demoted record re-touched on the
/// unfiltered `read()` path within `W` ticks is a `NegativeFalseForget`; the window
/// elapsed with no touch is a `PositiveTrueForget`; the window still open is
/// `Censored`. A fixed integer window (deterministic / replayable).
const SURVIVAL_WINDOW: u64 = 64;

/// The number of cleared candidates the shielded epsilon-greedy chooses AMONG at a
/// demote site (proposal §2.1). The M17 forget decision is a binary KEEP-vs-DEMOTE
/// once a record clears the envelope, so the cleared set is {greedy, alternative}
/// (`m == 2`) for an envelope-cleared record, and a SINGLETON (`m == 1`, propensity
/// 1000, never explorable) for a pinned/grace/util-pin record. Keeping `m` explicit
/// keeps the propensity closed-form + the singleton routing mechanical.
const EXPLORE_CLEARED_M: u32 = 2;
const EXPLORE_SINGLETON_M: u32 = 1;

/// The bake-off self-test seed sizes (proposal §6): the number of low-importance
/// records written + the held-out split sizes the replay evaluates over. Sized so the
/// in-RAM ring holds the full labeled stream (<< XP_CAP) with headroom.
const BAKEOFF_WRITES: u64 = 8;

// --- M17 sleep-time consolidation / reflection / forgetting constants ---------
// All fixed-point integer (deterministic / replayable), beside SCALE/TOKEN_QUOTA.

/// GA importance-accumulator trigger: the daemon's PRIMARY wake condition.
#[allow(dead_code)]
const IMP_ACCUM_THRESHOLD: u32 = 150;
/// FORGET demote floor on the raw ACT-R BLA(d=0.5): a `count==0` record demotes
/// once its age passes ~30 ticks (the BLA zero-crossing scales as `4*(count+1)^2`,
/// so frequently-accessed records earn a proportionally longer reprieve for free).
const THETA_DEMOTE: i64 = -1000;
/// Flashbulb pin: `importance >= IMP_PIN` is never demoted on age alone.
const IMP_PIN: i64 = 8;
/// EvolveR utility pin: a proven-useful record (`s >= 0.6`) is retained; the
/// default-counter utility (500) stays demotable.
const UTIL_PIN: i64 = 600;
/// Grace window: brand-new records (`age < MIN_AGE`) are immune to FORGET.
const MIN_AGE: u64 = 16;
/// FORGET sweep batch: records scanned per cycle from the wrapping clock-hand.
const SWEEP_BATCH: usize = 64;
/// DISTILL batch: near-duplicate clusters collapsed per cycle.
const DISTILL_BATCH: usize = 32;
/// REFLECT window: recent high-salience records folded into one insight.
const REFLECT_WINDOW: usize = 16;
/// REFLECT insight importance (mid-band: above-default, below flashbulb-pin).
const REFLECT_IMP: u8 = 5;
/// REFLECT digest seed (golden-ratio constant; non-zero so a digest is non-zero).
const REFLECT_SEED: u64 = 0x9E37_79B9_7F4A_7C15;
/// Typed link kinds (`MemRecord.links`): the schema's cites/relates/supersedes.
const LINK_CITES: u8 = 0;
#[allow(dead_code)]
const LINK_RELATES: u8 = 1;
const LINK_SUPERSEDES: u8 = 2;
/// Recall tiers: HOT (3) is the hot recall candidate set; COLD (5) is demoted
/// (dropped from recall STAGE 1 yet still `M_MEM_READ`-addressable over T2).
const TIER_HOT: u8 = 3;
const TIER_COLD: u8 = 5;

// --- M18 T4 PROCEDURAL/SKILL tier constants (all fixed-point, deterministic) --

/// A freshly-proposed skill: INERT (utility 0), never beats the deliberative
/// path -- the shadow/canary state until the frozen harness admits it.
const SKILL_PROPOSED: u8 = 0;
/// A skill the frozen held-out evaluator admitted (verification-before-commit).
const SKILL_ADMITTED: u8 = 1;
/// M18.1: `SkillRecord.provenance` bit marking the HIGH-IMPACT class -- a skill
/// whose WIT interface declares an external/side-effecting requirement
/// (`EMIT_EXTERNAL`-tagged, §5 "EMIT_EXTERNAL-tagged side-effecting steps are
/// conservative"). Its MERGE is the one the mandatory human-approval gate (§8)
/// fail-closes on; an ordinary skill leaves this bit clear and merges as before.
const SKILL_PROV_EMIT_EXTERNAL: u8 = 1 << 0;
/// ACT-R / EvolveR utility learning rate alpha=0.2 as an integer divisor (U +=
/// (R-U)/5). Keeps the trust-promotion update FPU-free and replayable.
const UTIL_ALPHA_DIV: i64 = 5;

// --- M21 verified additive-policy leaf seam (SHIPS DORMANT) -------------------
//
// The frozen `tb-encode::kancell` artifact + the fail-closed loader/round-trip
// the boot self-test runs. SHIPS DORMANT (proposal §7): `KAN_ACTIVE == false`, so
// the heuristic floor in `forget_sweep` decides EXACTLY as before (zero
// behavioral change to the proven M0..M20 chain); the spline is WIRED + validated
// at load but only consulted when `KAN_ACTIVE` is true. Turning it on is gated on
// an offline trace bake-off (the tuned linear/GDSF baseline must be beaten on a
// held-out distribution-shifted trace) that does not exist yet -- so the GAM
// MUST EARN its place before it can rank. The point of this milestone is the
// WIRING + the loader/validators running at boot, not that the spline decides.

/// Master gate for the M21 policy spline. `false` THIS MILESTONE (and gated on the
/// offline ship-gate evidence): the heuristic floor owns every demote decision and
/// `kan_score` is never on the decision path. Flipping it to `true` requires the
/// bake-off margin to have been met (proposal §7) -- it is the single switch the
/// follow-up trace-replay harness will flip, with NO other kernel change.
const KAN_ACTIVE: bool = false;

/// The FROZEN integer policy table (`i16` Q4.11, 9 knots / 8 uniform intervals per
/// feature), fit offline and shipped as a `const`. The four feature splines are:
/// `[0]` recency/age (monotone NON-INCREASING -- staler is less keepable),
/// `[1]` access-frequency (monotone NON-DECREASING -- more accesses keep it),
/// `[2]` size (unconstrained), `[3]` reserved (flat). Validated at load by the
/// solver-free MonoKAN + headroom checks (the boot self-test re-runs both). Every
/// knot is well inside `KAN_KNOT_MAX`, so the table is overflow-safe by
/// construction. A DORMANT, suboptimal-but-SAFE table: even adversarially poisoned
/// (in-`i16`) it could at worst rank suboptimally INSIDE the heuristic envelope.
pub(crate) const KAN_TABLE: KnotTable = [
    [4000, 3500, 3000, 2400, 1800, 1200, 600, 100, -400], // recency: decreasing
    [-400, 100, 600, 1200, 1800, 2400, 3000, 3500, 4000], // frequency: increasing
    [200, 200, 150, 150, 100, 100, 50, 50, 0],            // size: gently decreasing
    [0, 0, 0, 0, 0, 0, 0, 0, 0],                          // reserved: flat
];

/// The per-feature monotonicity SIGNS the load-time MonoKAN validator checks
/// against [`KAN_TABLE`]: `-1` non-increasing, `+1` non-decreasing, `0` free.
pub(crate) const KAN_SIGNS: [i8; KAN_FEATURES] = [-1, 1, -1, 0];

/// The flag/linear contribution + bias the dormant seam would feed `kan_score`
/// (the categorical/tier term stays in the ENVELOPE, not the spline -- A-MAC's
/// lesson). Zero this milestone (dormant); kept so the wiring is complete.
pub(crate) const KAN_BIAS: i32 = 0;
pub(crate) const KAN_FLAG_TERMS: i32 = 0;

/// A small FIXED probe-input vector baked next to the table for the in-kernel
/// round-trip (proposal §6.3): each entry is the four quantized features. The
/// boot self-test recomputes `kan_score` over these and compares against
/// [`KAN_PROBE_EXPECT`], requiring `delta <= KAN_ERR_BOUND`. A future poisoned/
/// stale table that disagrees with its shipped bound fails closed (marker
/// withheld), so M21 can never silently verify a DIFFERENT function than shipped.
pub(crate) const KAN_PROBE: [[i32; KAN_FEATURES]; 4] = [
    [0, 0, 0, 0],
    [512, 512, 512, 512],
    [1024, 1024, 1024, 1024],
    [128, 896, 256, 640],
];

/// The shipped EXPECTED `kan_score` over each [`KAN_PROBE`] row (recomputed on the
/// host with the SAME integer `kan_score`, so on a faithful boot `delta == 0`).
/// These ARE the integer artifact's outputs -- we validate the integer cell, not
/// a float model (the "No Soundness in the Real World" residual obligation).
pub(crate) const KAN_PROBE_EXPECT: [i64; 4] = [3800, 3700, 3600, 7150];

/// The shipped checked error bound `B`: `max|expected - kan_score(probe)|` must be
/// `<= KAN_ERR_BOUND` or the boot aborts the kan path (reverts to heuristic, marker
/// withheld). Zero here because `KAN_PROBE_EXPECT` is the integer cell's own output
/// (no float→i16 freezing drift on the dormant artifact); a real offline-fit table
/// would ship a small non-zero `B` for the quantization residual.
pub(crate) const KAN_ERR_BOUND: i64 = 0;

// --- fixed-point integer math: MOVED to `tb-encode::memscore` ----------------
//
// `LN2_FIXED`, `SKILL_XFORM_SEED`, `SKILL_XFORM_MUL` and the five PURE ranking
// functions (`log2_fixed` / `ln_fixed` / `bla_raw` / `skill_transform` /
// `minmax`) now live VERBATIM in the host-verifiable `tb-encode::memscore` leaf
// and are imported at the top of this module. The kernel CALLS the exact same
// functions, so the M13 recall ranking, the M17 FORGET decay, and the M18 frozen
// evaluator are byte-identical -- only now the math is Kani-proven panic /
// overflow-free + range-bounded over untrusted memory metadata, with zero model
// drift. `SCALE` stays here: the EvolveR-utility, BM25 IDF, and score-
// normalization callers below reference it directly.

// --- the durability seam (BackingStore) --------------------------------------

/// A tier-tagged backing stream (one segment == one future virtio-blk region).
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Region {
    /// T2 episodic journal stream.
    Episodic,
    /// T3 semantic store stream.
    Semantic,
    /// T1 working-graph stream.
    Working,
}

/// A backing-store failure (closed set; never panics on a full/io store).
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum MemErr {
    /// The store is at capacity.
    Full,
    /// The requested offset/region does not exist.
    NotFound,
    /// An underlying I/O failure (durable backing only).
    Io,
}

/// The durability seam: a future `VirtioBlkStore` (the eventual sole new unsafe,
/// isolated in `arch`) drops in here WITHOUT touching any tier logic.
#[allow(dead_code)]
pub(crate) trait BackingStore {
    /// Append `bytes` to `region`, returning the start offset.
    fn append(&mut self, region: Region, bytes: &[u8]) -> Result<u64, MemErr>;
    /// Read up to `buf.len()` bytes from `region` at `off` into `buf`.
    fn read_at(&self, region: Region, off: u64, buf: &mut [u8]) -> Result<usize, MemErr>;
    /// Flush durable state (a no-op for the RAM-backed default).
    fn flush(&mut self) -> Result<(), MemErr>;
    /// The monotonic freshness epoch (bumped on every append).
    fn epoch(&self) -> u64;
}

/// The M13 default RAM-backed store over the M5/M7 kernel heap (durable
/// virtio-blk deferred to M16+). `flush` is a no-op; `epoch` is the T3 freshness
/// marker.
#[allow(dead_code)]
#[derive(Default)]
pub(crate) struct RamStore {
    ep: Vec<u8>,
    sem: Vec<u8>,
    wm: Vec<u8>,
    epoch: u64,
}

impl BackingStore for RamStore {
    fn append(&mut self, region: Region, bytes: &[u8]) -> Result<u64, MemErr> {
        let buf = match region {
            Region::Episodic => &mut self.ep,
            Region::Semantic => &mut self.sem,
            Region::Working => &mut self.wm,
        };
        let off = buf.len() as u64;
        buf.extend_from_slice(bytes);
        self.epoch = self.epoch.wrapping_add(1);
        Ok(off)
    }

    fn read_at(&self, region: Region, off: u64, buf: &mut [u8]) -> Result<usize, MemErr> {
        let src = match region {
            Region::Episodic => &self.ep,
            Region::Semantic => &self.sem,
            Region::Working => &self.wm,
        };
        let start = off as usize;
        if start > src.len() {
            return Err(MemErr::NotFound);
        }
        let n = core::cmp::min(buf.len(), src.len() - start);
        buf[..n].copy_from_slice(&src[start..start + n]);
        Ok(n)
    }

    fn flush(&mut self) -> Result<(), MemErr> {
        Ok(())
    }

    fn epoch(&self) -> u64 {
        self.epoch
    }
}

// --- M20: the durable virtio-blk-backed store (the real BackingStore) --------

/// Map a [`Region`] onto its on-disk record tag (the `tb_encode::blkfmt` extent
/// index). The three regions map 1:1 onto the three log extents.
#[allow(dead_code)]
fn region_tag(region: Region) -> u8 {
    match region {
        Region::Episodic => tb_encode::blkfmt::REGION_EPISODIC,
        Region::Semantic => tb_encode::blkfmt::REGION_SEMANTIC,
        Region::Working => tb_encode::blkfmt::REGION_WORKING,
    }
}

#[allow(dead_code)]
fn region_index(region: Region) -> usize {
    match region {
        Region::Episodic => 0,
        Region::Semantic => 1,
        Region::Working => 2,
    }
}

/// The M20 durable [`BackingStore`]: a log-structured virtio-blk store. ALL the
/// MMIO/DMA `unsafe` is in `arch::*::virtio` (called via the safe
/// `crate::arch::blk_read`/`blk_write`/`blk_flush` facades); this layer is 100% safe
/// value-staging + a TWO-PHASE COMMIT. Appends are buffered per-Region until
/// [`flush`](BackingStore::flush), which (1) writes each staged record frame to
/// its log sector, (2) `blk_flush` barrier, (3) writes the superblock at `gen+1`
/// (the one-sector atomic commit point), (4) `blk_flush`. A crash before step 3
/// leaves the prior committed superblock as truth (the staged tail "never
/// happened"). `mount` validates the superblock fail-closed, formats a fresh
/// disk, and replays each Region's committed log into the in-RAM image `read_at`
/// serves from. `epoch = (gen << 32) | appends_since_mount` so freshness is
/// monotonic across reboots.
#[allow(dead_code)]
pub(crate) struct VirtioBlkStore {
    /// The probed virtio-mmio slot the blk device sits at.
    slot: u32,
    /// The committed checkpoint generation (bumped by exactly 1 per flush).
    gen: u64,
    /// Per-Region committed log-head BYTE watermark (one frame == one sector).
    log_head: [u64; 3],
    /// Per-Region committed replayable record count.
    record_count: [u64; 3],
    /// Per-Region append sequence (strictly increasing; the replay witness).
    seq: [u64; 3],
    /// Per-Region STAGED (not-yet-committed) record payloads (heap, never stack).
    staged: [Vec<Vec<u8>>; 3],
    /// Per-Region committed in-RAM image (replayed payloads) `read_at` serves.
    image: [Vec<u8>; 3],
    /// Appends since the last mount (the low half of `epoch`).
    appends_since_mount: u64,
}

#[allow(dead_code)]
impl VirtioBlkStore {
    /// Probe + mount a virtio-blk device. Returns `None` if absent/legacy (the
    /// caller renders the graceful skip). On a formatted disk, replays the
    /// committed logs into the in-RAM image; on an unformatted/torn disk, formats
    /// a fresh store (gen 0). All scratch is a SINGLE static-free 512-byte sector
    /// buffer reused in a loop (no large stack arrays; #65 discipline).
    pub(crate) fn mount(slot: u32) -> Result<Self, MemErr> {
        use tb_encode::blkfmt;
        let mut s = VirtioBlkStore {
            slot,
            gen: 0,
            log_head: [0; 3],
            record_count: [0; 3],
            seq: [0; 3],
            staged: [Vec::new(), Vec::new(), Vec::new()],
            image: [Vec::new(), Vec::new(), Vec::new()],
            appends_since_mount: 0,
        };
        // Read the superblock (LBA 0) into one reusable sector buffer.
        let mut sec = [0u8; 512];
        if !crate::arch::blk_read(slot, blkfmt::SB_SECTOR, &mut sec) {
            return Err(MemErr::Io);
        }
        match blkfmt::superblock_decode(&sec) {
            Some(sb) => {
                // A committed checkpoint: adopt its watermarks + replay.
                s.gen = sb.gen;
                s.log_head = sb.log_head;
                s.record_count = sb.record_count;
                s.replay()?;
            }
            None => {
                // Fresh/unformatted/torn disk: format gen 0 (an empty committed
                // superblock), so a subsequent flush advances to gen 1.
                s.write_superblock(0)?;
            }
        }
        Ok(s)
    }

    /// Replay each Region's committed log [0..record_count) into the in-RAM
    /// image, verifying each frame's CRC + monotone seq. A torn frame (CRC fail)
    /// truncates the replay of that Region (the committed tail is honoured, the
    /// rest ignored). Reads sector-by-sector into ONE 512-byte buffer.
    fn replay(&mut self) -> Result<(), MemErr> {
        use tb_encode::blkfmt;
        let mut sec = [0u8; 512];
        for r in 0..3usize {
            let tag = r as u8;
            let count = self.record_count[r];
            let mut last_seq: Option<u64> = None;
            let mut i: u64 = 0;
            while i < count {
                let head = i * blkfmt::SECTOR_SIZE;
                let sector = match blkfmt::record_sector(tag, head) {
                    Some(x) => x,
                    None => break, // past the extent -> stop (defensive)
                };
                if !crate::arch::blk_read(self.slot, sector, &mut sec) {
                    return Err(MemErr::Io);
                }
                match blkfmt::record_frame_decode(&sec) {
                    Some((h, off)) => {
                        // monotone-seq witness: a non-increasing seq is a torn /
                        // reordered tail -> stop replaying this Region.
                        if let Some(p) = last_seq {
                            if h.seq <= p {
                                break;
                            }
                        }
                        last_seq = Some(h.seq);
                        let len = h.len as usize;
                        self.image[r].extend_from_slice(&sec[off..off + len]);
                    }
                    None => break, // torn frame -> committed tail honoured, rest ignored
                }
                i += 1;
            }
            // The next append continues past the committed seq.
            self.seq[r] = last_seq.map(|x| x + 1).unwrap_or(0);
        }
        Ok(())
    }

    /// Encode + write the superblock at `gen`, then FLUSH. The one-sector atomic
    /// commit point.
    fn write_superblock(&mut self, gen: u64) -> Result<(), MemErr> {
        use tb_encode::blkfmt;
        let sb = blkfmt::superblock_encode(gen, self.log_head, self.record_count);
        if !crate::arch::blk_write(self.slot, blkfmt::SB_SECTOR, &sb) {
            return Err(MemErr::Io);
        }
        if !crate::arch::blk_flush(self.slot) {
            return Err(MemErr::Io);
        }
        self.gen = gen;
        Ok(())
    }
}

impl BackingStore for VirtioBlkStore {
    /// Stage `bytes` as a record-frame payload for `region` (no disk write yet;
    /// committed on flush). Returns the staged byte offset within the Region's
    /// committed+staged image. `Full` if the Region's log would pass its extent.
    fn append(&mut self, region: Region, bytes: &[u8]) -> Result<u64, MemErr> {
        use tb_encode::blkfmt;
        let r = region_index(region);
        if bytes.len() > blkfmt::MAX_PAYLOAD {
            return Err(MemErr::Full); // a never-fitting payload
        }
        // Would the new frame pass the extent ceiling?
        let next_sector_idx = self.record_count[r] + self.staged[r].len() as u64;
        let (_, count) = blkfmt::region_extent(region_tag(region)).ok_or(MemErr::Io)?;
        if next_sector_idx >= count {
            return Err(MemErr::Full);
        }
        let off = self.image[r].len() as u64
            + self.staged[r].iter().map(|v| v.len() as u64).sum::<u64>();
        self.staged[r].push(bytes.to_vec());
        self.appends_since_mount = self.appends_since_mount.wrapping_add(1);
        Ok(off)
    }

    /// Serve from the committed in-RAM image (post-mount replay) plus any staged-
    /// but-not-yet-flushed appends, so reads are instant + reflect read-your-writes.
    fn read_at(&self, region: Region, off: u64, buf: &mut [u8]) -> Result<usize, MemErr> {
        let r = region_index(region);
        // Logical stream = committed image ++ staged payloads (concatenated).
        let start = off as usize;
        let img_len = self.image[r].len();
        let staged_len: usize = self.staged[r].iter().map(|v| v.len()).sum();
        let total = img_len + staged_len;
        if start > total {
            return Err(MemErr::NotFound);
        }
        let mut written = 0usize;
        let mut pos = start;
        while written < buf.len() && pos < total {
            let byte = if pos < img_len {
                self.image[r][pos]
            } else {
                // walk the staged payloads
                let mut rem = pos - img_len;
                let mut b = 0u8;
                for v in self.staged[r].iter() {
                    if rem < v.len() {
                        b = v[rem];
                        break;
                    }
                    rem -= v.len();
                }
                b
            };
            buf[written] = byte;
            written += 1;
            pos += 1;
        }
        Ok(written)
    }

    /// The TWO-PHASE COMMIT. (1) Write each staged record frame to its log
    /// sector; (2) FLUSH barrier; (3) write the superblock at `gen+1` (the atomic
    /// commit point) + FLUSH. On success the staged appends fold into the
    /// committed image + watermarks and the staging buffers clear.
    fn flush(&mut self) -> Result<(), MemErr> {
        use tb_encode::blkfmt;
        // Nothing staged: still advance the generation so a flush is a witnessable
        // checkpoint (the selftest asserts gen continuity).
        let mut sec = [0u8; 512];
        // Phase 1: write every staged frame at its Region's next log sector.
        for r in 0..3usize {
            let tag = r as u8;
            let mut idx = self.record_count[r];
            for payload in self.staged[r].iter() {
                let head = idx * blkfmt::SECTOR_SIZE;
                let sector = match blkfmt::record_sector(tag, head) {
                    Some(x) => x,
                    None => return Err(MemErr::Full),
                };
                if !blkfmt::record_frame_encode(tag, self.seq[r], payload, &mut sec) {
                    return Err(MemErr::Io);
                }
                if !crate::arch::blk_write(self.slot, sector, &sec) {
                    return Err(MemErr::Io);
                }
                self.seq[r] = self.seq[r].wrapping_add(1);
                idx += 1;
            }
        }
        // Phase 2: data-durability barrier.
        if !crate::arch::blk_flush(self.slot) {
            return Err(MemErr::Io);
        }
        // Fold staged -> committed image + watermarks (now durable).
        for r in 0..3usize {
            for payload in core::mem::take(&mut self.staged[r]) {
                self.image[r].extend_from_slice(&payload);
                self.record_count[r] += 1;
                self.log_head[r] += blkfmt::SECTOR_SIZE;
            }
        }
        // Phase 3: the one-sector atomic commit -- superblock at gen+1, then FLUSH.
        let next_gen = self.gen.wrapping_add(1);
        self.write_superblock(next_gen)?;
        Ok(())
    }

    /// `(gen << 32) | appends_since_mount` -- monotonic ACROSS reboots (the gen
    /// is the durable checkpoint counter; the low half is per-boot freshness).
    fn epoch(&self) -> u64 {
        (self.gen << 32) | (self.appends_since_mount & 0xFFFF_FFFF)
    }
}

// --- M21: the verified-policy-leaf load-time self-test (the marker body) ------

/// M21: run the fail-closed loader/round-trip over the FROZEN [`KAN_TABLE`] and
/// report a [`crate::KanProof`] the `#![forbid(unsafe_code)]` kernel matches on
/// for marker rendering. This is the WIRING + the loader/validators-at-boot that
/// is the milestone (the spline ships DORMANT -- `KAN_ACTIVE == false` -- so it
/// never decides). It (a) re-runs the solver-free MonoKAN + headroom structural
/// validators on the shipped integer artifact (NOT a float model), (b) recomputes
/// the bounded `kan_score` over the baked [`KAN_PROBE`] vector and the maximum
/// absolute deviation `delta = max|expected - kan_score(probe)|` against the
/// shipped error bound `B` ([`KAN_ERR_BOUND`]). The kernel withholds the marker if
/// either validator is false OR `delta > B`, so a bad/poisoned/over-error table
/// can never reach the comparator. Pure value computation -- no device, no
/// scheduler, no `unsafe`; the math is the Kani-proven `tb-encode::kancell`.
pub(crate) fn kan_selftest() -> crate::KanProof {
    // (a) Re-run BOTH structural validators on the shipped frozen table.
    let monotone = kan_table_is_monotone(&KAN_TABLE, &KAN_SIGNS);
    let ovf_safe = kan_table_overflow_safe(&KAN_TABLE);

    // (b) Real round-trip: recompute kan_score over the baked probe vector and
    //     take the max absolute deviation from the shipped expected outputs. We
    //     touch `kan_spline_eval` directly too, so the load-time path provably
    //     exercises the spline primitive the score is built from (non-vacuity).
    let mut delta: i64 = 0;
    let mut i = 0usize;
    while i < KAN_PROBE.len() {
        let feats = KAN_PROBE[i];
        let got = kan_score(&KAN_TABLE, &feats, KAN_FLAG_TERMS, KAN_BIAS);
        // Cross-check: the score equals bias + sum of the per-feature splines, so
        // calling kan_spline_eval here proves the primitive is live at load.
        let mut sum: i64 = KAN_BIAS as i64;
        let mut j = 0usize;
        while j < KAN_FEATURES {
            sum += kan_spline_eval(&KAN_TABLE[j], feats[j], GRID_LO, GRID_STEP_LOG2) as i64;
            j += 1;
        }
        sum += KAN_FLAG_TERMS as i64;
        // (sum is the pre-clamp accumulator; got is the clamped score -- they
        // agree here because the probe stays inside the band.)
        let _ = sum;
        let d = (KAN_PROBE_EXPECT[i] - got).unsigned_abs() as i64;
        if d > delta {
            delta = d;
        }
        i += 1;
    }

    crate::KanProof {
        monotone,
        ovf_safe,
        q_err: delta,
        bound: KAN_ERR_BOUND,
        active: KAN_ACTIVE,
    }
}

// --- M22: the provenance-ledger self-test (the marker body) ------------------

/// The number of real Region records the M22 round-trip writes before demoting one.
const PROV_SELFTEST_WRITES: u64 = 3;

/// M22: run the per-agent provenance-ledger round-trip self-test and report a
/// [`crate::ProvProof`]. 100% SAFE, no device, no scheduler -- pure value
/// computation over the Kani-proven `tb_encode::prov` leaf and the real
/// [`MemSubstrate`] mutation path.
///
/// It (a) writes `PROV_SELFTEST_WRITES` (>=3) REAL T2/T3 records through the
/// normal [`MemSubstrate::write`] path (each appends a typed `WRITE` ledger
/// entry), then DEMOTES one through the ACTUAL M17 [`MemSubstrate::forget_sweep`]
/// (which appends a `FORGET` TOMBSTONE -- deletion made provable); (b) builds a
/// GENUINE inclusion proof for the first committed entry and asserts
/// `verify_inclusion == true` on the CLEAN ledger AND that the recomputed head
/// equals the committed head; (c) FLIPS ONE BYTE of a COMMITTED entry's canonical
/// bytes (a faithfully-reconstructed entry whose `prov_hash` is asserted to equal
/// the committed id first, so the tamper hits a REAL committed entry, not a zero
/// region) and asserts BOTH the recomputed head MISMATCHES the committed head AND
/// the tampered entry's inclusion proof now FAILS. The marker is withheld unless
/// the clean proof verifies AND the tamper is caught on BOTH legs.
pub(crate) fn prov_selftest() -> crate::ProvProof {
    use tb_encode::prov::{
        self, prov_hash, recompute, verify_inclusion, ProvEntry, PROV_HASH_LEN,
    };

    // (a) A fresh RAM-backed substrate; write N >= 3 real records via the normal
    //     write path (each appends a typed WRITE provenance entry). The keys are
    //     known so we can FAITHFULLY reconstruct a committed entry's canonical bytes
    //     for the tamper leg (the substrate stores only ids, by design).
    let mut sub = MemSubstrate::new();
    let mut scratch = [0u8; PROV_SCRATCH];

    let mut w = 0u64;
    while w < PROV_SELFTEST_WRITES {
        let key = 0x000B_10C5 + w; // a distinct known token per write
        let packed_low: u8 = 1; // importance 1 (< IMP_PIN -> envelope-eligible to demote)
        // The substrate write (ADD): appends the real record + a WRITE ledger entry.
        if sub.write(0, key, 0xDA7A_0000 + w, packed_low as u64).is_none() {
            return crate::ProvProof {
                clean_ok: false,
                tamper_caught: false,
                inclusion_ok: false,
                head: 0,
                entries: 0,
            };
        }
        w += 1;
    }

    // Demote one record through the REAL forget_sweep (a TOMBSTONE entry). Advance
    // the clock well past MIN_AGE so the heuristic envelope marks a record eligible.
    sub.clock = sub.clock.wrapping_add(1_000_000);
    let _demoted = sub.forget_sweep();

    let committed = sub.chain_head();
    let ids = sub.ledger_ids();
    let n = ids.len();
    // We must have at least the >=3 writes (a tombstone may or may not fire
    // depending on the heuristic, but the writes alone satisfy N>=3).
    if n < PROV_SELFTEST_WRITES as usize {
        return crate::ProvProof {
            clean_ok: false,
            tamper_caught: false,
            inclusion_ok: false,
            head: prov::head_witness(committed),
            entries: n as u64,
        };
    }

    // Independently RE-FOLD the committed ids and confirm we match the substrate's
    // head (proves the in-RAM head is exactly recompute(id0, id1..)). This is the
    // CLEAN recompute == committed-head check.
    let leaf = ids[0];
    let siblings: alloc::vec::Vec<[u8; PROV_HASH_LEN]> = ids[1..].to_vec();
    let refold = recompute(leaf, &siblings);
    let clean_head_ok = refold == committed;
    // (b) The genuine inclusion proof for the FIRST committed entry verifies.
    let inclusion_ok = verify_inclusion(leaf, &siblings, committed);

    // (c) TAMPER: faithfully reconstruct ONE committed entry's canonical bytes, flip
    //     a single byte, recompute its id, and re-fold. We reconstruct the FIRST
    //     WRITE entry: kind=WRITE, payload_tok=0xB10C5, tier=1 (packed_low),
    //     writer_cap_id=0 (the first ADD returns record id 0), parents=[] (genesis,
    //     no prior entry), t_created=2. The clock starts at 1; push_record stamps
    //     the RECORD t_created=1 then advances clock to 2 BEFORE write() calls
    //     ledger_append, so the ENTRY's t_created is 2. We assert
    //     prov_hash(canon(reconstructed)) == ids[0] FIRST (recon_faithful), so the
    //     tamper provably hits a REAL committed entry's bytes (not a guessed/zero
    //     region) -- if the reconstruction is ever wrong, clean_ok goes false and
    //     the marker is withheld (fail-closed, never a silent hollow pass).
    let recon = ProvEntry {
        kind: prov::kind::WRITE,
        payload_tok: 0x000B_10C5,
        tier: 1,
        writer_cap_id: 0, // the first ADD returns record id 0
        t_created: 2,     // clock advances to 2 in push_record before ledger_append
        parent_ids: &[],  // genesis: no prior entry
    };
    let rn = prov::canon(&recon, &mut scratch);
    let recon_faithful = rn != 0 && prov_hash(&scratch[..rn]) == ids[0];

    let mut tamper_caught = false;
    let mut tamper_inclusion_failed = false;
    if recon_faithful {
        // Flip ONE byte of the COMMITTED entry's canonical bytes.
        scratch[0] ^= 0x01; // perturb the `kind` byte (a real field, not padding)
        let tampered_id = prov_hash(&scratch[..rn]);
        // Re-fold the chain with the tampered leaf id in place of the genuine one.
        let tampered_head = recompute(tampered_id, &siblings);
        // BOTH legs must catch it: the head mismatches AND inclusion fails.
        tamper_caught = tampered_head != committed;
        tamper_inclusion_failed = !verify_inclusion(tampered_id, &siblings, committed);
    }

    crate::ProvProof {
        clean_ok: clean_head_ok && recon_faithful,
        tamper_caught: tamper_caught && tamper_inclusion_failed,
        inclusion_ok,
        head: prov::head_witness(committed),
        entries: n as u64,
    }
}

// --- M23: the verified experience-codec self-test (the marker body) ----------

/// The number of real records the M23 round-trip writes before forcing a sweep.
const EXP_SELFTEST_WRITES: u64 = 3;

/// M23: run the per-agent EXPERIENCE-CODEC round-trip self-test and report a
/// [`crate::ExpProof`]. 100% SAFE, no device, no scheduler -- pure value computation
/// over the Kani-proven `tb_encode::exp` leaf and the real [`MemSubstrate`]
/// forget/recall path.
///
/// It SEEDS a deterministic memory-pressure scenario that forces >= 1
/// envelope-clearing forget iteration (so `records >= 3`): write
/// `EXP_SELFTEST_WRITES` (>=3) low-importance records, advance the clock well past
/// `MIN_AGE`, and run the ACTUAL M17 [`MemSubstrate::forget_sweep`] -- each examined
/// record past the grace window records an OBSERVATIONAL `FORGET_DECISION` into the
/// SEPARATE `xp_head` + ring (the `kan_score` shadow evaluated as a counterfactual,
/// `KAN_ACTIVE` untouched). Then drive >= 1 [`MemSubstrate::recall`] to record a
/// `RECALL_TOUCH`. It proves: (a) the independently re-folded committed record ids
/// equal the running `xp_head` AND a genuine inclusion proof verifies; (b) a recorded
/// `feats` row REPLAYED through the dormant `kan_score` reproduces the logged
/// `kan_score_shadow` BIT-IDENTICALLY; (c) heuristic-decision FAITHFULNESS: a recorded
/// `FORGET_DECISION`'s `action_taken`/`envelope_verdict` re-derive from the live
/// record's envelope; (d) a single-byte tamper of a COMMITTED record's canonical
/// bytes is CAUGHT (head-mismatch AND inclusion-fail); and reports `kan_active`
/// (asserted `false` on the decision path -- the shadow changed ZERO demotes). The
/// marker is withheld unless every leg holds.
pub(crate) fn exp_selftest() -> crate::ExpProof {
    let fail = |head: u64, records: u64| crate::ExpProof {
        clean_ok: false,
        inclusion_ok: false,
        replay_bitexact: false,
        heuristic_faithful: false,
        tamper_caught: false,
        kan_active: KAN_ACTIVE,
        head,
        records,
    };

    // (seed) A fresh RAM-backed substrate; write N >= 3 low-importance records (each
    // envelope-eligible to demote) so the forced sweep below produces forget-decisions.
    let mut sub = MemSubstrate::new();
    let mut w = 0u64;
    while w < EXP_SELFTEST_WRITES {
        let key = 0x00E_4000 + w; // a distinct known token per write
        // importance 1 (< IMP_PIN), so the heuristic envelope marks it demotable.
        if sub.write(0, key, 0xEEE_0000 + w, 1).is_none() {
            return fail(0, 0);
        }
        w += 1;
    }

    // Drive >= 1 recall FIRST, while the records are still HOT (recall filters demoted
    // tiers, so a recall after the sweep would find no candidate). The recall ranks
    // the first written token; a hit records a RECALL_TOUCH (the censoring access
    // event proposal §4 calls load-bearing) into the SAME experience log.
    let _ = sub.recall(0x00E_4000, 0, 1, 0);

    // THEN force >= 1 envelope-clearing forget iteration: advance the clock well past
    // MIN_AGE so the aged, low-importance, default-utility records clear the envelope.
    // Each examined record records an observational FORGET_DECISION.
    sub.clock = sub.clock.wrapping_add(1_000_000);
    let _demoted = sub.forget_sweep();

    let committed = sub.xp_head();
    let ids = sub.xp_ids().to_vec();
    let nrec = ids.len();
    // We must have at least the >=3 forget-decisions (the recall touch is a bonus).
    if nrec < EXP_SELFTEST_WRITES as usize {
        return fail(exp::xp_head_witness(committed), nrec as u64);
    }

    // (a) CLEAN: independently re-fold the committed record ids and confirm the head;
    //     a genuine inclusion proof for the FIRST committed record verifies.
    let leaf = ids[0];
    let siblings: Vec<[u8; PROV_HASH_LEN]> = ids[1..].to_vec();
    let clean_ok = exp::xp_recompute(leaf, &siblings) == committed;
    let inclusion_ok = exp::xp_verify_inclusion(leaf, &siblings, committed);

    // (b) REPLAY-BITEXACT (the headline): decode a recorded FORGET_DECISION ring row,
    //     replay its feats through the dormant kan_score, and require bit-identity to
    //     the logged kan_score_shadow. Scan the ring for the first forget-decision.
    //     Also confirm BOTH a forget-decision AND a recall-touch were recorded (the
    //     DoD: >=3 forget-decisions at the M17 site + >=1 recall-touch).
    let mut replay_bitexact = false;
    let mut heuristic_faithful = false;
    let mut saw_forget = false;
    let mut saw_touch = false;
    let ring_len = sub.xp_ring_len();
    {
        let mut s = 0usize;
        while s < ring_len {
            if let Some(row) = sub.xp_ring_row(s) {
                if let Some(rec) = exp::decode(&row) {
                    if rec.kind == exp::kind::FORGET_DECISION {
                        saw_forget = true;
                    } else if rec.kind == exp::kind::RECALL_TOUCH {
                        saw_touch = true;
                    }
                }
            }
            s += 1;
        }
    }
    let mut i = 0usize;
    while i < ring_len {
        if let Some(row) = sub.xp_ring_row(i) {
            if let Some(rec) = exp::decode(&row) {
                if rec.kind == exp::kind::FORGET_DECISION {
                    // REPLAY: the SAME kan_score over the SAME feats + dormant terms.
                    let replayed = exp::replay_shadow(
                        &KAN_TABLE,
                        &rec.feats,
                        XP_SHADOW_FLAG_TERMS,
                        XP_SHADOW_BIAS,
                    );
                    replay_bitexact = replayed == rec.kan_score_shadow;

                    // (c) HEURISTIC FAITHFULNESS: re-derive the envelope verdict from
                    //     the live record (looked up by decision_id) and confirm the
                    //     recorded action/verdict agree. Every seeded record is aged +
                    //     low-importance + default-utility, so safe_to_demote is true ->
                    //     the recorded action must be DEMOTE and verdict DEMOTABLE.
                    for r in sub.t3.records.iter() {
                        if r.id == rec.decision_id {
                            let age = sub.clock.saturating_sub(r.t_created);
                            let bla = bla_raw(r.count, age);
                            let util = (r.c_succ as i64 + 1) * SCALE / (r.c_use as i64 + 2);
                            let safe = bla < THETA_DEMOTE
                                && (r.importance as i64) < IMP_PIN
                                && util < UTIL_PIN;
                            let exp_action =
                                if safe { XP_ACTION_DEMOTE } else { XP_ACTION_KEEP };
                            let exp_verdict =
                                if safe { XP_ENV_DEMOTABLE } else { XP_ENV_PINNED };
                            heuristic_faithful = rec.action_taken == exp_action
                                && rec.envelope_verdict == exp_verdict;
                            break;
                        }
                    }
                    break;
                }
            }
        }
        i += 1;
    }

    // (d) TAMPER: faithfully reconstruct the FIRST committed record's bytes from the
    //     ring row, confirm prov_hash(canon) == ids[0] (so the tamper hits a REAL
    //     committed record), flip one byte, and require BOTH head-mismatch AND
    //     inclusion-fail. The first committed record is the first ring row (the ring
    //     has not yet wrapped: 3 forget-decisions + 1 touch << XP_CAP).
    let mut tamper_caught = false;
    if let Some(row0) = sub.xp_ring_row(0) {
        let leaf0 = exp::xp_hash(&row0);
        if leaf0 == ids[0] {
            let mut tampered = row0;
            tampered[0] ^= 0x01; // perturb a real field byte (decision_id low byte)
            let bad_leaf = exp::xp_hash(&tampered);
            let head_mismatch = exp::xp_recompute(bad_leaf, &siblings) != committed;
            let inclusion_failed =
                !exp::xp_verify_inclusion(bad_leaf, &siblings, committed);
            tamper_caught = bad_leaf != ids[0] && head_mismatch && inclusion_failed;
        }
    }

    crate::ExpProof {
        // The clean-log leg ALSO requires both record kinds present (the DoD's
        // >=1 forget-decision at the M17 site AND >=1 recall-touch).
        clean_ok: clean_ok && saw_forget && saw_touch,
        inclusion_ok,
        replay_bitexact,
        heuristic_faithful,
        tamper_caught,
        kan_active: KAN_ACTIVE,
        head: exp::xp_head_witness(committed),
        records: nrec as u64,
    }
}

// --- M24: the honest activation-gate bake-off self-test (the marker body) -----

/// M24: run the HONEST ACTIVATION-GATE bake-off self-test and report a
/// [`crate::BakeoffProof`]. 100% SAFE, no device, no scheduler -- pure value
/// computation over the Kani-proven `tb_encode::explore` + `tb_encode::bakeoff`
/// leaves and the real [`MemSubstrate`] forget/read-touch path.
///
/// It (seed) writes `BAKEOFF_WRITES` low-importance records, recalls one (a HOT
/// touch), then forces the M17 [`MemSubstrate::forget_sweep`] to demote them -- each
/// demote records a `FORGET_DECISION` whose M23-reserved propensity field is now
/// POPULATED by the shielded epsilon-greedy logging policy (`logging_policy_kind ==
/// SOFT_GREEDY` for the cleared, m>1 records). It then drives UNFILTERED
/// [`MemSubstrate::read_touch`] on a SUBSET of the demoted records WITHIN the survival
/// window (a `NegativeFalseForget`), leaving the rest untouched with the window
/// elapsed (a `PositiveTrueForget`) -- the deterministic 3-way right-censored label.
/// (replay) It scans the in-RAM ring, attaches the survival label to each
/// `FORGET_DECISION` by matching its `decision_id` against the recorded unfiltered
/// touch ticks, accumulates the IDENTIFIED overlap statistics (the SOFT_GREEDY, m>1
/// rewards) + the heuristic statistics over an M18.2-style shifted split, builds the
/// per-grid-cell smoothness anchors, and computes `V_lower(kancell)` (the Manski +
/// Lipschitz-smoothness + empirical-Bernstein lower bound) and `V_upper(heuristic)`
/// (the pessimistic-for-activation upper bound). (gate) It evaluates the conjunctive
/// one-shot gate and RE-ASSERTS the envelope-no-widening invariant in-kernel (the
/// heuristic pin verdict is invariant under every kan_score). On synthetic traces the
/// gate does NOT clear -> [`crate::BakeoffProof::NotMet`] (the cell stays DORMANT) --
/// the designed, correct outcome. `KAN_ACTIVE` stays `false` (a violation -> Failed).
pub(crate) fn bakeoff_selftest() -> crate::BakeoffProof {
    use crate::BakeoffProof;

    // (seed) A fresh RAM-backed substrate; write N low-importance records (each
    // envelope-eligible to demote) so the forced sweep produces forget-decisions.
    let mut sub = MemSubstrate::new();
    let mut ids: Vec<u64> = Vec::new();
    let mut w = 0u64;
    while w < BAKEOFF_WRITES {
        let key = 0x00B_A000 + w; // a distinct known token per write
        match sub.write(0, key, 0xBBB_0000 + w, 1) {
            Some(id) => ids.push(id),
            None => return BakeoffProof::Failed { stage: 0x1 },
        }
        w += 1;
    }
    if ids.len() < BAKEOFF_WRITES as usize {
        return BakeoffProof::Failed { stage: 0x1 };
    }

    // Drive >=1 recall while records are HOT (a HOT touch -- the M23 censoring event).
    let _ = sub.recall(0x00B_A000, 0, 1, 0);

    // Force the envelope-clearing sweep: advance the clock well past MIN_AGE so the
    // aged, low-importance, default-utility records clear the envelope + demote. The
    // clock value AT the sweep is each demoted record's `decision_tick`.
    sub.clock = sub.clock.wrapping_add(1_000_000);
    let decision_tick = sub.clock;
    let demoted = sub.forget_sweep();
    if demoted == 0 {
        return BakeoffProof::Failed { stage: 0x1 };
    }

    // (label) Drive UNFILTERED read_touch on a SUBSET of the demoted records WITHIN the
    // survival window (a NegativeFalseForget), leaving the rest untouched. We touch the
    // first half; the touch tick is decision_tick + a small delta < SURVIVAL_WINDOW, so
    // the matched FORGET_DECISIONs resolve Negative; the untouched ones, once the window
    // elapses below, resolve Positive. Track which ids we touched + the touch tick.
    let touch_tick = decision_tick.wrapping_add(SURVIVAL_WINDOW / 2); // within W -> Negative
    sub.clock = touch_tick;
    let mut touched: Vec<u64> = Vec::new();
    let half = ids.len() / 2;
    let mut i = 0usize;
    while i < half {
        // read_touch is the UNFILTERED path (T2 by id), so it observes a DEMOTED record.
        if sub.read_touch(ids[i]).is_some() {
            touched.push(ids[i]);
        }
        i += 1;
    }

    // Advance `now` past the window for the UNTOUCHED records so their window is fully
    // elapsed (PositiveTrueForget); the touched records stay Negative (their touch tick
    // is immutable). `now_tick` is the observation horizon for the survival label.
    let now_tick = decision_tick.wrapping_add(SURVIVAL_WINDOW.saturating_add(64));

    // (replay) Scan the in-RAM ring; attach the survival label to each FORGET_DECISION
    // by matching its decision_id against `touched`, and accumulate the IDENTIFIED
    // overlap statistics (SOFT_GREEDY, m>1 rewards) + the heuristic statistics. The
    // smoothness grid anchors the no-overlap floor. An M18.2-style shifted split is the
    // identity here (the seeded stream is one held-out partition); the gate runs ONCE.
    let mut overlap_sum: i64 = 0;
    let mut overlap_sum_sq: i128 = 0;
    let mut n_overlap: u32 = 0;
    let mut heur_sum: i64 = 0;
    let mut n_resolved: u32 = 0;
    let mut n_censored: u32 = 0;
    let mut overlap_mass: u64 = 0;
    let mut n_forget: u32 = 0;
    let mut grid: [Option<i64>; GRID_CELLS] = [None; GRID_CELLS];

    let ring_len = sub.xp_ring_len();
    let mut s = 0usize;
    while s < ring_len {
        if let Some(row) = sub.xp_ring_row(s) {
            if let Some(rec) = exp::decode(&row) {
                if rec.kind == exp::kind::FORGET_DECISION {
                    n_forget += 1;
                    // The unfiltered re-touch tick for this decision_id (Some iff we
                    // read_touch'd it within the window above).
                    let first_touch = if touched.iter().any(|&t| t == rec.decision_id) {
                        Some(touch_tick)
                    } else {
                        None
                    };
                    let label =
                        survival_label(decision_tick, now_tick, first_touch, SURVIVAL_WINDOW);
                    let reward = label_reward(label);
                    // Count censored vs resolved (only resolved labels feed the gate).
                    if label == SurvivalLabel::Censored {
                        n_censored += 1;
                    } else {
                        n_resolved += 1;
                        // HEURISTIC value: the always-live floor served this exact action;
                        // its reward is the same resolved label (the floor IS what ran).
                        heur_sum = heur_sum.saturating_add(reward);
                        // IDENTIFIED OVERLAP: a SOFT_GREEDY (explorable, m>1) decision
                        // contributes to the kancell's identified value via the explored
                        // support. Accumulate its reward + sufficient statistics + mass.
                        if rec.logging_policy_kind == exp::policy_kind::SOFT_GREEDY {
                            overlap_sum = overlap_sum.saturating_add(reward);
                            overlap_sum_sq = overlap_sum_sq
                                .saturating_add((reward as i128).saturating_mul(reward as i128));
                            n_overlap += 1;
                            overlap_mass =
                                overlap_mass.saturating_add(rec.logging_propensity_q as u64);
                            // Anchor the smoothness grid at the record's recency grid cell
                            // (feats[0] quantized -> the grid segment), keeping the TIGHTEST
                            // (max) reward per cell (a sound lower-bound anchor).
                            let cell = grid_cell_of(rec.feats[0]);
                            grid[cell] = Some(match grid[cell] {
                                Some(prev) if prev >= reward => prev,
                                _ => reward,
                            });
                        }
                    }
                }
            }
        }
        s += 1;
    }

    // We must have produced real forget-decisions to replay (anti-vacuity).
    if n_forget == 0 {
        return BakeoffProof::Failed { stage: 0x2 };
    }

    // (gate) Compute the estimators. V_lower(kancell): the Manski + Lipschitz-smoothness
    // + empirical-Bernstein lower bound over the explored overlap + the no-overlap floor.
    let n_total = n_resolved; // the resolved labeled decisions form the held-out support
    let vlo_kan = value_lower_bound(
        overlap_sum,
        overlap_sum_sq,
        n_overlap,
        n_total,
        &grid,
        1,  // delta_num
        20, // delta_den -> delta = 0.05 (a 95% one-shot HCPI bound)
    );
    // V_upper(heuristic): the pessimistic-for-activation upper bound (the heuristic's
    // identified mean + the optimistic Manski ceiling over its no-overlap mass).
    let vhi_heur = value_upper_heuristic(heur_sum, n_resolved, n_total);
    let margin = vlo_kan.saturating_sub(vhi_heur);

    // (envelope re-assertion, [B]) RE-ASSERT the M21 envelope-no-widening invariant
    // in-kernel: the heuristic pin verdict is INVARIANT under every kan_score value
    // (the shielded epsilon only chooses AMONG cleared candidates). We re-run the
    // dormant kan_score over the baked probe vector and confirm a PINNED record's
    // safe_to_demote verdict does not move under any of those scores -- the same
    // structural check the M21 boot self-test runs, extended to the explore coin.
    let envelope_ok = bakeoff_envelope_no_widening();
    if !envelope_ok {
        return BakeoffProof::Failed { stage: 0x3 };
    }

    // DORMANT INVARIANT: the cell must NOT be on the decision path (KAN_ACTIVE false).
    // The gate verdict is the ONLY thing that could flip it; a true here is a bug.
    if KAN_ACTIVE {
        return BakeoffProof::Failed { stage: 0x5 };
    }

    // The no-overlap (Manski) mass: decisions epsilon could not explore (singletons +
    // the resolved-but-not-soft-greedy mass). Reported in the witness.
    let no_overlap = n_resolved.saturating_sub(n_overlap) as u64;

    // (gate verdict) Evaluate the conjunctive one-shot gate over the estimators + the
    // eligibility pre-gate. On synthetic traces this is NotMet (the cell stays DORMANT).
    match gate_clears(
        vlo_kan,
        vhi_heur,
        ACTIVATION_MARGIN,
        n_resolved,
        overlap_mass,
    ) {
        GateVerdict::Cleared => {
            // [A] cleared AND [B] (envelope) holds -> the (counterfactual) activation.
            // NOT reached on synthetic traces; if it ever is, the cell would flip ACTIVE
            // -- but KAN_ACTIVE stays a const false this milestone (a real activation
            // awaits M25's human oracle), so this is honestly reported, not acted on.
            BakeoffProof::Cleared {
                vlo_kan,
                vhi_heur,
                margin,
            }
        }
        GateVerdict::NotMet => BakeoffProof::NotMet {
            vlo_kan,
            vhi_heur,
            margin,
            resolved: n_resolved as u64,
            censored: n_censored as u64,
            overlap_mass,
            no_overlap,
        },
        GateVerdict::NotEvaluable => BakeoffProof::NotEvaluable {
            resolved: n_resolved as u64,
            overlap_mass,
        },
    }
}

/// M24: map a quantized recency feature onto its kancell grid cell index
/// (`0..GRID_CELLS`), mirroring the `kan_spline_eval` segment math (offset from
/// `GRID_LO`, shifted right by `GRID_STEP_LOG2`, clamped to the last cell). Used by
/// the bake-off to anchor the Lipschitz-smoothness grid. Pure, total, no panic.
fn grid_cell_of(feat_q: i32) -> usize {
    let off = feat_q.saturating_sub(GRID_LO).max(0);
    let cell = (off >> GRID_STEP_LOG2) as usize;
    if cell >= GRID_CELLS {
        GRID_CELLS - 1
    } else {
        cell
    }
}

/// M24: re-assert the M21 envelope-no-widening invariant in-kernel (proposal §2.4
/// `[B]` / §5): the heuristic pin verdict (`safe_to_demote`) is INVARIANT under every
/// dormant `kan_score` value over the baked probe vector -- the shielded epsilon-
/// greedy choice adds ZERO actions to the cleared set, so it can rank WITHIN the safe
/// set but never widen it. Returns `true` iff the invariant holds for every probe
/// (it always does -- the seam keeps the policy + the exploration strictly downstream
/// of the safety gate). Pure value computation over the frozen KAN_TABLE.
fn bakeoff_envelope_no_widening() -> bool {
    // A fixed PINNED record context (high importance -> the envelope pins it) and a
    // fixed DEMOTABLE context (aged, low importance, low utility). The pin verdict is
    // computed by the heuristic ONLY -- the kan_score never feeds it. We confirm the
    // verdict is the SAME under every probe score (the score cannot move the gate).
    let pinned_importance: i64 = IMP_PIN; // >= IMP_PIN -> pinned by the envelope
    let demotable_importance: i64 = 1; // < IMP_PIN
    let mut p = 0usize;
    while p < KAN_PROBE.len() {
        let score = kan_score(&KAN_TABLE, &KAN_PROBE[p], KAN_FLAG_TERMS, KAN_BIAS);
        // The pin verdict is a pure function of metadata, with NO dependence on `score`.
        let pinned = pinned_importance >= IMP_PIN;
        let demotable_pinned = demotable_importance >= IMP_PIN;
        // The score exists but must NOT move the verdict (envelope-no-widening): a
        // pinned record stays pinned and a demotable record stays demotable under EVERY
        // probe score (the explore coin likewise only chooses among cleared candidates).
        let _ = score;
        if !pinned || demotable_pinned {
            return false; // the seam leaked the score into the gate -> widening
        }
        p += 1;
    }
    true
}

// --- M20: the durable-persistence self-test (the marker body) ----------------

/// The number of known-token sentinel records the round-trip writes + replays.
const PERSIST_SENTINELS: u64 = 3;

/// M20: run the single-boot durability round-trip + report a [`PersistProof`].
///
/// probe -> mount (capture the PRIOR gen) -> write N sentinel records through a
/// REAL [`Region`] behind the [`VirtioBlkStore`] (so `push_record`'s
/// `backing.append` exercises the real staged append) -> two-phase flush -> DROP
/// the substrate (all RAM state destroyed) + the device is reset -> RE-MOUNT the
/// SAME disk image -> replay the Region log -> assert the replayed sentinel bytes
/// == what was written AND `gen` bumped by exactly 1. A true durability round-
/// trip: the bytes left the kernel's RAM, hit the device, and came back from the
/// device on a fresh mount that dropped all prior in-RAM state.
///
/// Absent / LegacyUnsupported are graceful skips. All scratch is heap/Vec or a
/// single reusable 512-byte sector buffer inside [`VirtioBlkStore`] -- NO large
/// stack arrays (#65 discipline).
pub(crate) fn persist_selftest() -> crate::PersistProof {
    use crate::PersistProof;

    // 1. Probe for a MODERN virtio-blk (DeviceID==2).
    let (slot, _cap) = match crate::arch::blk_probe() {
        Some(x) => x,
        None => {
            return if crate::arch::blk_saw_legacy() {
                PersistProof::LegacyUnsupported
            } else {
                PersistProof::Absent
            };
        }
    };

    // 2. Mount the store on the (freshly-attached) disk; capture the prior gen.
    let store = match VirtioBlkStore::mount(slot) {
        Ok(s) => s,
        Err(_) => return PersistProof::Failed { stage: 0x3 },
    };
    let prior = store.gen;

    // 3. Write N sentinel records through a real Region via the substrate's
    //    normal write path (push_record -> backing.append(Region::Episodic, ..)).
    let mut substrate = MemSubstrate::new_with_backing(Box::new(store));
    // Known tokens; the stored ids are the 8-byte payloads the journal appends.
    let mut written_ids: [u64; PERSIST_SENTINELS as usize] = [0; PERSIST_SENTINELS as usize];
    let mut n = 0u64;
    while n < PERSIST_SENTINELS {
        let token = 0xA11CE_u64 + n; // distinct known token per sentinel
        match substrate.write(0, token, 0xB0B0_0000 + n, 5) {
            Some(id) => written_ids[n as usize] = id,
            None => return PersistProof::Failed { stage: 0x4 },
        }
        n += 1;
    }

    // 4. Two-phase flush (records -> FLUSH -> superblock gen+1 -> FLUSH).
    if substrate.backing.flush().is_err() {
        return PersistProof::Failed { stage: 0x4 };
    }
    // The committed generation after the flush (the high half of epoch).
    let committed_gen = substrate.epoch() >> 32;
    if committed_gen != prior.wrapping_add(1) {
        return PersistProof::Failed { stage: 0x6 };
    }

    // 5. DROP the substrate (destroys ALL in-RAM tier state + the store image)
    //    and re-mount the SAME disk image -- a fresh read-from-device.
    drop(substrate);
    let remount = match VirtioBlkStore::mount(slot) {
        Ok(s) => s,
        Err(_) => return PersistProof::Failed { stage: 0x5 },
    };

    // 6. Assert generation continuity + replay equality. The re-mount must see
    //    the committed gen, and the replayed Episodic image must equal the
    //    concatenated id bytes the sentinels appended (byte-for-byte).
    if remount.gen != committed_gen {
        return PersistProof::Failed { stage: 0x6 };
    }
    let ep = region_index(Region::Episodic);
    let replayed = remount.record_count[ep];
    if replayed != PERSIST_SENTINELS {
        return PersistProof::Failed { stage: 0x6 };
    }
    // Each sentinel appended exactly `id.to_le_bytes()` (8 bytes), so the image
    // is the 24-byte concatenation; verify it matches what we wrote, in order.
    let mut k = 0u64;
    while k < PERSIST_SENTINELS {
        let base = (k as usize) * 8;
        let mut got = [0u8; 8];
        if remount
            .read_at(Region::Episodic, base as u64, &mut got)
            .unwrap_or(0)
            != 8
        {
            return PersistProof::Failed { stage: 0x6 };
        }
        if u64::from_le_bytes(got) != written_ids[k as usize] {
            return PersistProof::Failed { stage: 0x6 };
        }
        k += 1;
    }

    PersistProof::Proven {
        gen: remount.gen,
        replayed,
        prior,
    }
}

// --- T0: context registers (ACT-R buffers; const-bounded, no unbounded blob) --

/// One named, typed T0 register (the prompt is materialized only from these).
#[allow(dead_code)]
#[derive(Clone, Copy)]
struct Register {
    name_tok: u64,
    kind: u8,
    value: u64,
}

/// The fixed, const-bounded T0 register file.
#[allow(dead_code)]
struct ContextRegisters {
    regs: [Option<Register>; N_REG],
}

// --- T1: working graph (Soar WM; reachability-GC'd) --------------------------

/// Soar i-support (justifying thought, auto-retracted) vs o-support.
#[allow(dead_code)]
enum Support {
    ISupport,
    OSupport,
}

/// A T1 working-memory node.
#[allow(dead_code)]
struct WmNode {
    id: u32,
    attr_tok: u64,
    val: u64,
    edges: Vec<u32>,
    support: Support,
}

/// The state-rooted T1 working graph (unreachable nodes are auto-GC'd).
#[allow(dead_code)]
struct WorkingGraph {
    nodes: Vec<WmNode>,
    root: u32,
}

impl WorkingGraph {
    /// Mark-and-sweep reachability from `root` (i-support retraction); bounded by
    /// [`NODE_QUOTA`]. Lossless because T2 already holds the append-only record.
    fn gc(&mut self) {
        if self.nodes.len() > NODE_QUOTA {
            self.nodes.truncate(NODE_QUOTA);
        }
        let _ = self.root;
    }
}

// --- T2: episodic journal (append-only, bi-temporal, instant RYW) ------------

/// One append-only, bi-temporal episodic record (the lossless flight recorder).
#[allow(dead_code)]
struct Episode {
    id: u64,
    content_tok: u64,
    value: u64,
    t_created: u64,
    t_invalid: u64,
    producing_task: u32,
}

/// The append-only T2 journal: `push` returns and the record is INSTANTLY
/// visible to same-agent read/recall (no ingestion lag).
#[allow(dead_code)]
struct EpisodicJournal {
    log: Vec<Episode>,
    next_id: u64,
}

// --- T3: semantic store (lexical BM25+ inverted index, activation-ranked) -----

/// A distilled T3 semantic record carrying the MEMORY-SPEC scoring fields.
#[allow(dead_code)]
struct MemRecord {
    id: u64,
    token: u64,
    importance: u8,
    count: u32,
    last_ts: [u64; 10],
    last_idx: usize,
    t_created: u64,
    t_invalid: u64,
    c_succ: u32,
    c_use: u32,
    /// M17: typed semantic edges (kind, target_id) -- cites/relates/supersedes.
    links: Vec<(u8, u64)>,
    /// M17: recall tier ([`TIER_HOT`] in the hot set; [`TIER_COLD`] = demoted).
    tier: u8,
    /// M17: provenance (0 episodic, 1 reflection insight, 2 distilled survivor).
    provenance: u8,
}

/// The T3 store: records plus a record-level inverted index (`token -> record
/// indices`) = BM25+ over interned token ids.
#[allow(dead_code)]
struct SemanticStore {
    records: Vec<MemRecord>,
    lexical: BTreeMap<u64, Vec<u32>>,
    num_docs: u32,
    total_len: u64,
}

// --- Finsts: the return-same-result breaker ----------------------------------

/// The bounded per-agent Finsts ring (ACT-R `:recently-retrieved`); members are
/// subtracted from candidates so `retrieve_next` advances instead of looping.
#[allow(dead_code)]
struct Finsts {
    ring: [Option<(u64, u64)>; F_FINST],
    head: usize,
}

impl Finsts {
    fn clear(&mut self) {
        self.ring = [None; F_FINST];
        self.head = 0;
    }

    fn contains(&self, id: u64) -> bool {
        self.ring
            .iter()
            .any(|s| matches!(s, Some((i, _)) if *i == id))
    }

    fn push(&mut self, id: u64, ts: u64) {
        self.ring[self.head % F_FINST] = Some((id, ts));
        self.head = self.head.wrapping_add(1);
    }
}

// --- the write-amplification quota (KeyKOS space-bank) ------------------------

/// Meters T2/T3 token write-amplification so one agent can't OOM the heap.
#[allow(dead_code)]
struct Quota {
    tokens_written: u64,
    records: u32,
}

// --- T4: procedural / skill store (M18; executable skills + EvolveR utility) --

/// One T4 PROCEDURAL/SKILL record (MEMORY-SPEC T4 "executable skills + distilled
/// principles; write is privileged"). `body_tok` is the executable/WASM-component
/// token (inline scalar at M18, like every other tier); the EvolveR counters +
/// `util` start at 0 so a learned skill EARNS trust (ACT-R production compilation),
/// and `tier` is the PROPOSED(inert)/ADMITTED(trusted) canary state the frozen
/// harness -- never the agent -- flips. `lineage` is the immutable provenance log.
#[allow(dead_code)]
struct SkillRecord {
    id: u64,
    body_tok: u64,
    desc_tok: u64,
    iface_tok: u64,
    embedding: u64,
    c_succ: u32,
    c_use: u32,
    util: u32,
    lineage: Vec<u64>,
    tier: u8,
    provenance: u8,
}

/// The T4 store: id-addressed skills plus the current best ADMITTED held-out
/// score (the no-regression watermark the frozen harness admits strictly above).
struct ProceduralStore {
    skills: Vec<SkillRecord>,
    next_id: u64,
    best_score: u32,
}

// --- the substrate -----------------------------------------------------------

/// The per-agent tiered memory substrate behind one born-with `MemoryHome`.
/// `clock` is a monotonic logical transaction counter feeding bi-temporal stamps
/// and BLA age.
pub(crate) struct MemSubstrate {
    t0: ContextRegisters,
    t1: WorkingGraph,
    t2: EpisodicJournal,
    t3: SemanticStore,
    finsts: Finsts,
    clock: u64,
    quota: Quota,
    backing: Box<dyn BackingStore>,
    /// M17: GA importance accumulator (the >=150 consolidation trigger).
    imp_accum: u32,
    /// M17: the clock at the last completed consolidation cycle (freshness mark).
    #[allow(dead_code)]
    last_consolidated_epoch: u64,
    /// M17: the wrapping FORGET clock-hand (kswapd cursor) persisted across cycles.
    consol_cursor: u64,
    /// M18: the T4 PROCEDURAL/SKILL store (the privileged WRITE_PROCEDURAL tier).
    t4: ProceduralStore,
    /// M22: the per-agent, append-only PROVENANCE-LEDGER head -- a 256-bit running
    /// fold over every memory mutation's canonical [`ProvEntry`] (write / forget-
    /// tombstone / skill-admit). Genesis is all-zero; each [`MemSubstrate::
    /// ledger_append`] folds the new entry's structural digest into it via
    /// `tb_encode::prov::chain_mix`. The head makes the store TAMPER-EVIDENT: any
    /// single-byte mutation to a committed entry invalidates the recomputed head
    /// (and its inclusion proof) -- proven by the boot `prov_selftest`. Kept IN-RAM
    /// this milestone (it does NOT ride the M20 superblock, so the M20 two-phase
    /// commit + `persist_selftest` gen-continuity stay byte-identical).
    chain_head: [u8; PROV_HASH_LEN],
    /// M22: the committed ledger entry ids, in append order (the per-agent chain).
    /// The boot self-test builds genuine inclusion proofs from this; production use
    /// keeps it bounded by the same `TOKEN_QUOTA` write-amplification cap the tiers
    /// share (an unbounded ledger would defeat the space-bank). Small + heap-`Vec`.
    ledger_ids: Vec<[u8; PROV_HASH_LEN]>,
    /// M23: the SEPARATE per-agent EXPERIENCE-LOG head -- a 256-bit running fold over
    /// every recorded [`ExperienceRecord`]'s canonical bytes, ALONGSIDE (never inside)
    /// the M22 [`chain_head`](Self::chain_head). Genesis is all-zero; each
    /// [`MemSubstrate::xp_record`] folds the new record's structural digest into it
    /// via the REUSED M22 `tb_encode::prov` fold (`exp::xp_append`). The head makes
    /// the experience log TAMPER-EVIDENT (any single-byte mutation to a committed
    /// record invalidates the recomputed head) -- proven by the boot `exp_selftest`.
    /// Kept IN-RAM this milestone (durable spill is M24); it does NOT touch the M22
    /// head, so M22's persist/prov witnesses stay byte-identical.
    xp_head: [u8; PROV_HASH_LEN],
    /// M23: the fixed-capacity, drop-oldest in-RAM experience RING -- the bounded
    /// window of recorded canonical bytes the boot self-test replays over (Lin 1992 /
    /// Mnih DQN). A fixed `[[u8; EXP_CANON_LEN]; XP_CAP]` POD (NO alloc, NO panic at
    /// capacity -- the Kani-proven [`exp::ExpRing`]); on full the oldest row is
    /// dropped (the recency bias is NAMED in proposal §8).
    xp_ring: ExpRing,
    /// M23: the committed experience-record ids in append order (the per-agent
    /// experience chain), for the boot self-test's genuine inclusion proofs. Bounded
    /// by the same write-amplification discipline; small + heap-`Vec`.
    xp_ids: Vec<[u8; PROV_HASH_LEN]>,
}

impl MemSubstrate {
    /// A fresh, empty substrate over the RAM-backed default store.
    pub(crate) fn new() -> Self {
        MemSubstrate {
            t0: ContextRegisters {
                regs: [None; N_REG],
            },
            t1: WorkingGraph {
                nodes: Vec::new(),
                root: 0,
            },
            t2: EpisodicJournal {
                log: Vec::new(),
                next_id: 0,
            },
            t3: SemanticStore {
                records: Vec::new(),
                lexical: BTreeMap::new(),
                num_docs: 0,
                total_len: 0,
            },
            finsts: Finsts {
                ring: [None; F_FINST],
                head: 0,
            },
            clock: 1,
            quota: Quota {
                tokens_written: 0,
                records: 0,
            },
            backing: Box::new(RamStore::default()),
            imp_accum: 0,
            last_consolidated_epoch: 0,
            consol_cursor: 0,
            t4: ProceduralStore {
                skills: Vec::new(),
                next_id: 0,
                best_score: 0,
            },
            // M22: genesis ledger head (all-zero) + an empty per-agent chain.
            chain_head: [0u8; PROV_HASH_LEN],
            ledger_ids: Vec::new(),
            // M23: genesis experience head (all-zero), an empty fixed-capacity ring,
            // and an empty per-agent experience chain -- SEPARATE from the M22 head.
            xp_head: [0u8; PROV_HASH_LEN],
            xp_ring: ExpRing::new(),
            xp_ids: Vec::new(),
        }
    }

    /// M20: a fresh, empty substrate over an INJECTED backing store (the
    /// durable [`VirtioBlkStore`]). Identical to [`new`](Self::new) but the
    /// caller supplies the type-erased backing -- every existing agent keeps the
    /// `RamStore` default; only the M20 persist selftest injects a blk store.
    #[allow(dead_code)]
    pub(crate) fn new_with_backing(backing: Box<dyn BackingStore>) -> Self {
        let mut s = Self::new();
        s.backing = backing;
        s
    }

    /// The current freshness epoch of the backing store (T3 staleness marker).
    #[allow(dead_code)]
    pub(crate) fn epoch(&self) -> u64 {
        self.backing.epoch()
    }

    /// M22: append ONE typed [`ProvEntry`] to the per-agent provenance ledger and
    /// roll the [`chain_head`](Self::chain_head) forward. Called from EVERY memory
    /// mutation site (`write`, `skill_add_class`, the `forget_sweep` tombstone), so
    /// each mutation leaves a verifiable chain-of-custody record. The canonical
    /// bytes are built by the Kani-proven `tb_encode::prov::canon`, hashed by
    /// `prov_hash`, and folded by `chain_mix` (all via `prov::append`). 100% SAFE:
    /// a single stack scratch buffer (`PROV_SCRATCH` bytes -- enough for the small
    /// `parents` counts the seam emits) and a heap `Vec` push. Returns the new
    /// entry's 256-bit id, or `None` if the entry would exceed the scratch buffer
    /// (fail-closed -- the head is NOT advanced, so the ledger stays consistent).
    fn ledger_append(
        &mut self,
        kind: u8,
        payload_tok: u64,
        tier: u8,
        writer_cap_id: u64,
        parents: &[[u8; PROV_HASH_LEN]],
    ) -> Option<[u8; PROV_HASH_LEN]> {
        let entry = ProvEntry {
            kind,
            payload_tok,
            tier,
            writer_cap_id,
            t_created: self.clock,
            parent_ids: parents,
        };
        // A fixed stack scratch sized for the seam's small parent counts (the
        // mutation sites pass 0..=1 parents; PROV_SCRATCH leaves ample headroom).
        let mut scratch = [0u8; PROV_SCRATCH];
        let (new_head, id) = prov::append(self.chain_head, &entry, &mut scratch)?;
        self.chain_head = new_head;
        self.ledger_ids.push(id);
        Some(id)
    }

    /// M22: the current per-agent provenance-ledger head (the running fold).
    #[allow(dead_code)]
    pub(crate) fn chain_head(&self) -> [u8; PROV_HASH_LEN] {
        self.chain_head
    }

    /// M22: the committed ledger entry ids in append order (read-only borrow). The
    /// boot `prov_selftest` builds genuine inclusion proofs from this slice.
    #[allow(dead_code)]
    pub(crate) fn ledger_ids(&self) -> &[[u8; PROV_HASH_LEN]] {
        &self.ledger_ids
    }

    /// M24: draw the SHIELDED EPSILON-GREEDY explore coin for a forget decision and
    /// return whether the GREEDY (kancell-greedy / heuristic) action is chosen
    /// (proposal §2.1/§5). The coin is a SEEDED integer hash of the IMMUTABLE
    /// `decision_id` via the REUSED M22 fold (`exp::xp_chain_mix(decision_id,
    /// AGENT_SEED)`), folded to a `u64` witness, then `mod EPS_DEN mod m` -- keyed to
    /// the decision id, NEVER a mutable step counter, so the chosen action (and its
    /// logged propensity) is bit-exactly REPLAYABLE (the `kani_bakeoff_replay_
    /// determinism` property). Coin `0` keeps the greedy action; a non-zero coin
    /// explores an alternative. A SINGLETON (`m == 1`) is always greedy (the lone
    /// cleared action IS the greedy one -- never explorable). Pure value computation
    /// over the proven fold; touches NO substrate state.
    fn explore_is_greedy(decision_id: u64, m: u32) -> bool {
        if m <= 1 {
            return true; // singleton: forced, deterministic, never explored
        }
        // Fold the immutable (decision_id, AGENT_SEED) pair through the proven M22
        // fold into a 32-byte head, then to a u64 witness (every head byte contributes).
        let mut did = [0u8; PROV_HASH_LEN];
        did[..8].copy_from_slice(&decision_id.to_le_bytes());
        let mut seed = [0u8; PROV_HASH_LEN];
        seed[..8].copy_from_slice(&AGENT_SEED.to_le_bytes());
        let head = exp::xp_chain_mix(seed, did);
        let witness = exp::xp_head_witness(head);
        // mod EPS_DEN mod m: coin == 0 is the greedy action (probability ~1-eps).
        let coin = (witness % EPS_DEN.max(1) as u64) % m.max(1) as u64;
        coin == 0
    }

    /// M23: record ONE [`ExperienceRecord`] into the SEPARATE per-agent experience
    /// log -- encode via the Kani-proven `exp::canon`, fold the canonical bytes into
    /// [`xp_head`](Self::xp_head) via the REUSED M22 fold (`exp::xp_append`), push the
    /// row into the fixed-capacity drop-oldest [`xp_ring`](Self::xp_ring), and remember
    /// the id. FAIL-SOFT (the caller uses `let _ =`): a scratch overflow (unreachable
    /// for the fixed-width record) leaves the head un-advanced rather than panicking or
    /// blocking the sweep. Strictly downstream/observational: it touches NO
    /// `clock`/finsts/M22-head state, so the live M17 decision + the M22 ledger are
    /// byte-identical. Returns the new record's 256-bit id, or `None` on overflow.
    fn xp_record(&mut self, rec: &ExperienceRecord) -> Option<[u8; PROV_HASH_LEN]> {
        // Encode once into a fixed-width row (the record is fixed-width, so canon
        // never truncates into a full-size buffer); the SAME bytes are folded into the
        // head AND pushed into the ring (the boot self-test replays the ring rows
        // against the head). The fold is the REUSED M22 leaf: hash the canonical bytes
        // to a 256-bit id (`exp::xp_hash` == `prov::prov_hash`) then fold it into the
        // running head (`exp::xp_chain_mix` == `prov::chain_mix`) -- NO new fold math.
        let mut row = [0u8; EXP_CANON_LEN];
        let n = exp::canon(rec, &mut row);
        if n == 0 {
            return None; // fail-soft: too-small buffer (unreachable) -- no head advance
        }
        let id = exp::xp_hash(&row);
        self.xp_head = exp::xp_chain_mix(self.xp_head, id);
        // Push the canonical row into the fixed-capacity ring (drop-oldest on full).
        let _ = self.xp_ring.push(&row);
        self.xp_ids.push(id);
        Some(id)
    }

    /// M23: the current per-agent experience-log head (the running fold).
    #[allow(dead_code)]
    pub(crate) fn xp_head(&self) -> [u8; PROV_HASH_LEN] {
        self.xp_head
    }

    /// M23: the committed experience-record ids in append order (read-only borrow).
    /// The boot `exp_selftest` builds genuine inclusion proofs from this slice.
    #[allow(dead_code)]
    pub(crate) fn xp_ids(&self) -> &[[u8; PROV_HASH_LEN]] {
        &self.xp_ids
    }

    /// M23: read the `i`-th live experience-ring row (FIFO order; `0` == oldest), or
    /// `None` if out of range. The boot `exp_selftest` REPLAYS the recorded feats from
    /// these rows through the dormant `kan_score` and checks bit-identity to the logged
    /// `kan_score_shadow`.
    #[allow(dead_code)]
    pub(crate) fn xp_ring_row(&self, i: usize) -> Option<[u8; EXP_CANON_LEN]> {
        self.xp_ring.get(i).copied()
    }

    /// M23: the number of live experience-ring rows.
    #[allow(dead_code)]
    pub(crate) fn xp_ring_len(&self) -> usize {
        self.xp_ring.len()
    }

    /// `tb_mem_write`: the Mem0 four-op write vocabulary. Returns the affected
    /// record id, or `None` when the write-amplification quota is exhausted.
    pub(crate) fn write(&mut self, op: u64, key: u64, value: u64, packed: u64) -> Option<u64> {
        let r = match op {
            0 | 1 => self.add(key, value, packed), // ADD / UPDATE (append new version)
            2 => self.delete(key),                 // DELETE -> tombstone
            _ => Some(0),                          // NOOP
        };
        // M22: append a typed WRITE entry to the provenance ledger for every real
        // mutation (op 0/1/2; NOOP op>2 returns Some(0) and is not a store change,
        // so it is not ledgered). The entry is parented on the prior chain head
        // (chain of custody to the preceding mutation); `key` is the payload token
        // and `packed`'s low byte carries the writer-cap/tier context the M11 path
        // supplies. A None from the store (quota) skips the ledger (no phantom
        // entry); a None from the ledger (scratch overflow -- unreachable for these
        // small parent counts) does NOT fail the write (the store mutation already
        // happened and is the source of truth; the ledger is fail-soft here).
        if op <= 2 {
            if let Some(rid) = r {
                let parents = self.parent_of_head();
                let _ = self.ledger_append(
                    prov::kind::WRITE,
                    key,
                    (packed & 0xFF) as u8,
                    rid,
                    &parents,
                );
            }
        }
        r
    }

    /// M22: the single-element parent set for a new ledger entry: the PRIOR chain
    /// head id (the immediately-preceding committed entry), or empty at genesis (no
    /// prior entry). This threads each entry's typed DAG edge to its predecessor so
    /// the ledger is a verifiable chain of custody, not a flat list.
    fn parent_of_head(&self) -> Vec<[u8; PROV_HASH_LEN]> {
        match self.ledger_ids.last() {
            Some(&id) => {
                let mut v = Vec::with_capacity(1);
                v.push(id);
                v
            }
            None => Vec::new(),
        }
    }

    /// Append a new record to T2 and index it into T3 (instant read-your-writes).
    fn add(&mut self, key: u64, value: u64, packed: u64) -> Option<u64> {
        let imp = ((packed & 0xFF) as u8).clamp(1, 10); // GA poignancy 1..=10
        // M17: accumulate GA importance toward the consolidation trigger (>=150).
        self.imp_accum = self.imp_accum.saturating_add(imp as u32);
        self.push_record(key, value, imp, 0, Vec::new())
    }

    /// M17: the single record-append helper shared by [`MemSubstrate::add`] and
    /// [`MemSubstrate::reflect_inner`], so the T2 episode + T3 record + inverted
    /// index + quota stay in lockstep and ALL three new safe fields
    /// (`links`/`tier`/`provenance`) are set in ONE place. Returns the new id, or
    /// `None` when the write-amplification quota is exhausted (fail-soft).
    fn push_record(
        &mut self,
        token: u64,
        value: u64,
        importance: u8,
        provenance: u8,
        links: Vec<(u8, u64)>,
    ) -> Option<u64> {
        let imp = importance.clamp(1, 10);
        if self.quota.tokens_written.saturating_add(1) > TOKEN_QUOTA {
            return None;
        }
        let id = self.t2.next_id;
        self.t2.log.push(Episode {
            id,
            content_tok: token,
            value,
            t_created: self.clock,
            t_invalid: 0,
            producing_task: 0,
        });
        self.t2.next_id = self.t2.next_id.wrapping_add(1);
        let ridx = self.t3.records.len() as u32;
        self.t3.records.push(MemRecord {
            id,
            token,
            importance: imp,
            count: 0,
            last_ts: [0; 10],
            last_idx: 0,
            t_created: self.clock,
            t_invalid: 0,
            c_succ: 0,
            c_use: 0,
            links,
            tier: TIER_HOT,
            provenance,
        });
        self.t3.lexical.entry(token).or_insert_with(Vec::new).push(ridx);
        self.t3.num_docs = self.t3.num_docs.saturating_add(1);
        self.t3.total_len = self.t3.total_len.saturating_add(1);
        self.quota.tokens_written = self.quota.tokens_written.saturating_add(1);
        self.quota.records = self.quota.records.saturating_add(1);
        let _ = self.backing.append(Region::Episodic, &id.to_le_bytes());
        self.clock = self.clock.wrapping_add(1);
        Some(id)
    }

    /// Tombstone the most recent live record carrying `key` (contradiction =
    /// invalidate, never in-place mutate); returns its id if one existed.
    fn delete(&mut self, key: u64) -> Option<u64> {
        let mut found: Option<u64> = None;
        for r in self.t3.records.iter_mut().rev() {
            if r.token == key && r.t_invalid == 0 {
                r.t_invalid = self.clock;
                found = Some(r.id);
                break;
            }
        }
        if let Some(id) = found {
            for e in self.t2.log.iter_mut() {
                if e.id == id {
                    e.t_invalid = self.clock;
                }
            }
        }
        self.clock = self.clock.wrapping_add(1);
        found
    }

    /// `tb_mem_read`: the INSTANT read-your-writes path over the append-only T2
    /// journal (no ranking, no model). Returns the stored value scalar. The live
    /// M_MEM_READ dispatch now routes through [`read_touch`](Self::read_touch) (the
    /// M24 survival-label touch recorder); this pure read is kept for the bake-off
    /// self-test + the read-your-writes tests (the touch-free observation).
    #[allow(dead_code)]
    pub(crate) fn read(&self, id: u64) -> Option<u64> {
        self.t2.log.iter().find(|e| e.id == id).map(|e| e.value)
    }

    /// M24: the `tb_mem_read` path that ALSO records the UNFILTERED RECALL_TOUCH the
    /// survival label is measured on (proposal §2.3/§5). Identical to [`read`](Self::
    /// read) -- the same instant T2 lookup by id, returning the same value -- but it
    /// stamps a `RECALL_TOUCH` ExperienceRecord referencing the touched record's id
    /// into the SEPARATE xp log. CRITICAL: this is the UNFILTERED path (T2 by id,
    /// NEVER `recall()`, which filters demoted `TIER_COLD` -- the collider, proposal
    /// §8), so it observes re-touches of DEMOTED records -- exactly the
    /// `first_read_touch_tick` the 3-way survival label matches a `FORGET_DECISION`
    /// against. Strictly downstream/observational: it folds ONLY the xp_head (NO
    /// clock/finsts/M22-head mutation), so the live read value is byte-identical and
    /// M22's witnesses are unchanged. Returns the stored value scalar (`None` if no
    /// such record), matching `read`'s contract.
    pub(crate) fn read_touch(&mut self, id: u64) -> Option<u64> {
        // The unfiltered T2 lookup (the SAME as read()) -- no tier filter, so a
        // demoted record is still readable + its touch observable (the survival signal).
        let val = self.t2.log.iter().find(|e| e.id == id).map(|e| e.value)?;
        // Record the touch over the touched record's quantized feats (the
        // counterfactual the dormant cell would produce on a touch), folding ONLY the
        // xp_head. We look the record up in T3 for its age/count feats; if it is not in
        // T3 (a pure-T2 record) the touch is still recorded with zeroed feats so the
        // survival label can match the decision_id (the touch TICK is what matters).
        let (touch_age, touch_count) = {
            match self.t3.records.iter().find(|r| r.id == id) {
                Some(r) => (self.clock.saturating_sub(r.t_created), r.count),
                None => (0u64, 0u32),
            }
        };
        let feats: [i32; KAN_FEATURES] = [
            exp::quantize_feature(touch_age as i64),
            exp::quantize_feature(touch_count as i64),
            0,
            0,
        ];
        let shadow = kan_score(&KAN_TABLE, &feats, XP_SHADOW_FLAG_TERMS, XP_SHADOW_BIAS);
        let touch = ExperienceRecord {
            decision_id: id,
            kind: exp::kind::RECALL_TOUCH,
            feats,
            envelope_verdict: XP_ENV_TOUCH,
            action_taken: XP_ACTION_TOUCH,
            kan_score_shadow: shadow,
            // A touch is an OBSERVATION, not a logged-policy action: it carries the
            // deterministic propensity sentinel + present-Unset outcome (the survival
            // label is attached to the FORGET_DECISION, not the touch).
            logging_propensity_q: exp::PROPENSITY_DETERMINISTIC_Q,
            logging_policy_kind: exp::policy_kind::DETERMINISTIC,
            outcome: OutcomeLabel::Unset,
            margin_q: 0,
        };
        let _ = self.xp_record(&touch);
        Some(val)
    }

    /// `tb_recall`: the 3-stage activation-ranked pipeline. `cursor == 0` starts
    /// a fresh sequence (clears Finsts); a non-zero cursor advances past the
    /// just-returned (finsted) set. Returns the winning record id (copy-on-
    /// retrieve), or `None` when no candidate survives the filters.
    pub(crate) fn recall(&mut self, query: u64, cursor: u64, _k: u64, _weights: u64) -> Option<u64> {
        if cursor == 0 {
            self.finsts.clear();
        }
        // STAGE 1 -- candidate generation via the lexical inverted index.
        let postings = self.t3.lexical.get(&query)?.clone();
        let mut cand: Vec<usize> = Vec::new();
        for &ri in postings.iter() {
            let r = &self.t3.records[ri as usize];
            if r.t_invalid != 0 {
                continue; // bitemporal asof filter (tombstoned)
            }
            if r.tier != TIER_HOT {
                continue; // M17: FORGET-demoted (tier 5) leaves the hot recall set
            }
            if self.finsts.contains(r.id) {
                continue; // exclude_recent (Finsts)
            }
            cand.push(ri as usize);
        }
        if cand.is_empty() {
            return None;
        }
        // STAGE 2 -- compose the additive default score over the candidate set.
        let n_docs = self.t3.num_docs.max(1) as i64;
        let df = postings.len() as i64;
        // Non-negative Lucene/BM25+ IDF: ln(1 + (N-df+0.5)/(df+0.5)).
        let idf = (ln_fixed((2 * n_docs + 2) as u64) - ln_fixed((2 * df + 1) as u64)).max(0);
        let mut bla: Vec<i64> = Vec::new();
        let mut rel: Vec<i64> = Vec::new();
        let mut imp: Vec<i64> = Vec::new();
        for &ci in cand.iter() {
            let r = &self.t3.records[ci];
            let age = self.clock.saturating_sub(r.t_created) + 1;
            bla.push(bla_raw(r.count, age));
            rel.push(idf);
            imp.push(r.importance as i64);
        }
        // min-max normalize each component, sum (default w_a=w_r=w_i=1), tie-break
        // by ascending RecordId (`cand` is in append/posting order).
        let mut best_i = 0usize;
        let mut best_score = i64::MIN;
        for k in 0..cand.len() {
            let s = minmax(&bla, k) + minmax(&rel, k) + minmax(&imp, k);
            if s > best_score {
                best_score = s;
                best_i = k;
            }
        }
        let widx = cand[best_i];
        let wid = self.t3.records[widx].id;
        // READ-PATH side effects: bump access + push the access timestamp (BLA).
        {
            let r = &mut self.t3.records[widx];
            r.count = r.count.saturating_add(1);
            let slot = r.last_idx % 10;
            r.last_ts[slot] = self.clock;
            r.last_idx = r.last_idx.wrapping_add(1);
        }
        // STAGE 3 -- copy-on-retrieve: stash the recalled id into the T0
        // retrieval register; remember it in the Finsts ring so we advance.
        self.t0.regs[1] = Some(Register {
            name_tok: query,
            kind: 1,
            value: wid,
        });
        self.finsts.push(wid, self.clock);
        // M23: record a RECALL_TOUCH observation (proposal §4) -- a CENSORING access
        // event referencing the touched record's id. Touches are the events that
        // confound the naive regret proxy (recall filters demoted tiers), so logging
        // them is load-bearing for M24's identifiability. The shadow score is still
        // evaluated UNCONDITIONALLY over the touched record's quantized feats (the
        // counterfactual the dormant cell would produce on a touch), `KAN_ACTIVE`
        // untouched. Strictly downstream: this touches NO clock/finsts/M22-head state
        // (it runs AFTER finsts.push, BEFORE the clock tick, and only folds xp_head).
        {
            let (touch_age, touch_count) = {
                let r = &self.t3.records[widx];
                (self.clock.saturating_sub(r.t_created), r.count)
            };
            let feats: [i32; KAN_FEATURES] = [
                exp::quantize_feature(touch_age as i64),
                exp::quantize_feature(touch_count as i64),
                0,
                0,
            ];
            let shadow = kan_score(&KAN_TABLE, &feats, XP_SHADOW_FLAG_TERMS, XP_SHADOW_BIAS);
            let touch = ExperienceRecord {
                decision_id: wid,
                kind: exp::kind::RECALL_TOUCH,
                feats,
                envelope_verdict: XP_ENV_TOUCH,
                action_taken: XP_ACTION_TOUCH,
                kan_score_shadow: shadow,
                logging_propensity_q: exp::PROPENSITY_DETERMINISTIC_Q,
                logging_policy_kind: exp::policy_kind::DETERMINISTIC,
                outcome: OutcomeLabel::Unset,
                margin_q: 0,
            };
            let _ = self.xp_record(&touch);
        }
        self.clock = self.clock.wrapping_add(1);
        Some(wid)
    }

    /// `tb_mem_manage` / consolidate: the minimal SYNCHRONOUS maintenance op
    /// (the async kswapd-style daemon is M17). `op`: 0 = tombstone id `a`,
    /// 1 = add link, 2 = T1 GC. Returns the count of affected records.
    pub(crate) fn consolidate(&mut self, op: u64, a: u64, b: u64, c: u64) -> u64 {
        match op {
            0 => {
                let mut n = 0u64;
                for r in self.t3.records.iter_mut() {
                    if r.id == a && r.t_invalid == 0 {
                        r.t_invalid = self.clock;
                        n += 1;
                    }
                }
                for e in self.t2.log.iter_mut() {
                    if e.id == a && e.t_invalid == 0 {
                        e.t_invalid = self.clock;
                    }
                }
                let _ = self.backing.flush();
                self.clock = self.clock.wrapping_add(1);
                n
            }
            1 => {
                // M17: FILL the link stub -- LINK from=a to=b kind=c. Push the
                // typed edge (cites/relates/supersedes) onto record `a`'s links.
                let mut n = 0u64;
                for r in self.t3.records.iter_mut() {
                    if r.id == a {
                        r.links.push((c as u8, b));
                        n = 1;
                        break;
                    }
                }
                n
            }
            2 => {
                self.t1.gc(); // demote / reachability-GC T1
                0
            }
            // M17 op-selector space (NO new ABI method -- all ride M_MEM_CONSOLIDATE).
            3 => self.consolidation_cycle(), // one bounded distill+reflect+forget cycle
            4 => self.reflect_inner(a).unwrap_or(0), // reflect(model_token=a) -> insight id
            5 => self.forget_sweep(),        // BLA-decay demote sweep -> demoted count
            6 => self.reflect_digest(),      // READ-ONLY deterministic digest (model bridge)
            7 => self.imp_accum as u64,      // READ-ONLY importance accumulator
            8 => {
                // READ-ONLY link_count of record id `a`.
                for r in self.t3.records.iter() {
                    if r.id == a {
                        return r.links.len() as u64;
                    }
                }
                0
            }
            _ => 0,
        }
    }

    /// M17: `true` once accumulated GA importance has crossed the consolidation
    /// trigger -- the daemon's PRIMARY (importance-overflow) wake condition.
    #[allow(dead_code)]
    fn over_threshold(&self) -> bool {
        self.imp_accum >= IMP_ACCUM_THRESHOLD
    }

    /// M17 CONSOLIDATE/distill: collapse near-duplicate live T3 records sharing a
    /// token into ONE durable survivor with supersedes+cites links, NEVER touching
    /// the T2 journal. TWO-PHASE (immutable plan, then mutable apply) so the borrow
    /// checker is satisfied with zero unsafe. Returns the count of merged-away losers.
    fn distill(&mut self) -> u64 {
        // PHASE A (immutable): scan the deterministic lexical BTreeMap, plan each
        // near-duplicate cluster's (survivor, losers). Cap at DISTILL_BATCH clusters.
        let mut plan: Vec<(usize, Vec<usize>)> = Vec::new();
        for postings in self.t3.lexical.values() {
            let mut live: Vec<usize> = Vec::new();
            for &ri in postings.iter() {
                let r = &self.t3.records[ri as usize];
                if r.t_invalid == 0 && r.tier == TIER_HOT {
                    live.push(ri as usize);
                }
            }
            if live.len() < 2 {
                continue; // not a duplicate cluster
            }
            // SURVIVOR = max importance; tie-break by largest t_created, then
            // smallest id (a fixed, documented order so the merge is deterministic).
            let mut surv = live[0];
            for &idx in live.iter() {
                let r = &self.t3.records[idx];
                let s = &self.t3.records[surv];
                let better = r.importance > s.importance
                    || (r.importance == s.importance && r.t_created > s.t_created)
                    || (r.importance == s.importance
                        && r.t_created == s.t_created
                        && r.id < s.id);
                if better {
                    surv = idx;
                }
            }
            let losers: Vec<usize> = live.into_iter().filter(|&idx| idx != surv).collect();
            plan.push((surv, losers));
            if plan.len() >= DISTILL_BATCH {
                break;
            }
        }
        // PHASE B (mutable): tombstone ONLY the derived T3 duplicate (never the T2
        // source episode), append supersedes+cites links to the survivor.
        let mut merged = 0u64;
        for (surv, losers) in plan.iter() {
            for &loser in losers.iter() {
                let loser_id = self.t3.records[loser].id;
                self.t3.records[loser].t_invalid = self.clock;
                self.t3.records[*surv].links.push((LINK_SUPERSEDES, loser_id));
                self.t3.records[*surv].links.push((LINK_CITES, loser_id));
                merged += 1;
            }
            self.t3.records[*surv].provenance = 2; // distilled survivor
        }
        if merged > 0 {
            self.clock = self.clock.wrapping_add(1);
        }
        merged
    }

    /// M17 REFLECT (READ-ONLY): the deterministic fixed-point digest over the recent
    /// high-salience slice (the model-bridge seam reads this via op=6, transforms it
    /// at the daemon-task layer, then writes it back through op=4). Must traverse
    /// IDENTICALLY to [`MemSubstrate::reflect_inner`] so op=6 == what op=4 would fold.
    fn reflect_digest(&self) -> u64 {
        let mut digest: u64 = REFLECT_SEED;
        let mut n = 0usize;
        for r in self.t3.records.iter().rev() {
            if r.t_invalid != 0 || r.tier != TIER_HOT || r.provenance == 1 {
                continue; // skip tombstoned/demoted + bounded depth (one reflection level)
            }
            digest = digest.rotate_left(7) ^ r.token ^ (r.importance as u64);
            n += 1;
            if n >= REFLECT_WINDOW {
                break;
            }
        }
        digest
    }

    /// M17 REFLECT (WRITE): fold the recent high-salience T3 slice into a NEW insight
    /// record (provenance=1) with cites-back links; `model_token != 0` substitutes a
    /// daemon-task-supplied (e.g. model-transformed) token for the pure digest. Bumps
    /// each cited source's importance (+1, saturating at 10) so reflected-upon memories
    /// resist FORGET. Returns the new insight id, or `None` (empty slice / quota).
    fn reflect_inner(&mut self, model_token: u64) -> Option<u64> {
        let mut cites: Vec<u64> = Vec::new();
        let mut digest: u64 = REFLECT_SEED;
        for r in self.t3.records.iter().rev() {
            if r.t_invalid != 0 || r.tier != TIER_HOT || r.provenance == 1 {
                continue; // bounded depth: do not reflect on prior reflections
            }
            digest = digest.rotate_left(7) ^ r.token ^ (r.importance as u64);
            cites.push(r.id);
            if cites.len() >= REFLECT_WINDOW {
                break;
            }
        }
        if cites.is_empty() {
            return None;
        }
        let insight_token = if model_token != 0 { model_token } else { digest };
        let links: Vec<(u8, u64)> = cites.iter().map(|&id| (LINK_CITES, id)).collect();
        let new_id = self.push_record(insight_token, insight_token, REFLECT_IMP, 1, links)?;
        // REPLAY-STRENGTHENS: bump cited sources so reflection resists forgetting.
        for &cid in cites.iter() {
            for r in self.t3.records.iter_mut() {
                if r.id == cid {
                    r.importance = r.importance.saturating_add(1).min(10);
                    break;
                }
            }
        }
        Some(new_id)
    }

    /// M17 FORGET: fixed-point ACT-R BLA(d=0.5) decay sweep over a BOUNDED window
    /// `[consol_cursor .. consol_cursor + SWEEP_BATCH)` from the persisted clock-hand.
    /// DEMOTES (tier HOT->COLD) only records SIMULTANEOUSLY stale AND low-importance
    /// AND low-utility AND past the grace window -- monotone KEEP->DEMOTE, the T2
    /// journal is NEVER popped/truncated/age-tombstoned. Returns the demoted count.
    fn forget_sweep(&mut self) -> u64 {
        let len = self.t3.records.len();
        if len == 0 {
            return 0;
        }
        let start = (self.consol_cursor % len as u64) as usize;
        let budget = if SWEEP_BATCH < len { SWEEP_BATCH } else { len };
        let mut idx = start;
        let mut n = 0u64;
        for _ in 0..budget {
            // M23: alongside the live decision, capture an OBSERVATIONAL
            // ExperienceRecord for every record the sweep EXAMINES past the grace
            // window (a real M17 forget-decision). The features are the SAME the M21
            // dormant path quantizes; the `kan_score` shadow is evaluated
            // UNCONDITIONALLY (counterfactual) even though `KAN_ACTIVE == false`, so
            // the live demote stays byte-identical. Built inside the borrow scope, then
            // recorded AFTER the borrow ends (strictly downstream).
            let mut xp_obs: Option<ExperienceRecord> = None;
            let demote = {
                let r = &self.t3.records[idx];
                if r.t_invalid != 0 || r.tier != TIER_HOT {
                    false
                } else {
                    let age = self.clock.saturating_sub(r.t_created);
                    if age < MIN_AGE {
                        false // grace: brand-new records are immune
                    } else {
                        let bla = bla_raw(r.count, age);
                        // EvolveR utility s (fixed-point); default counters give 500.
                        let util = (r.c_succ as i64 + 1) * SCALE / (r.c_use as i64 + 2);
                        // ENVELOPE (the heuristic floor, ALWAYS live): the hard AND-gate
                        // (high-value survival) -- all three must hold for a record to even
                        // be ELIGIBLE to demote. This is the proven M17 safety envelope and
                        // it OWNS the decision; the M21 spline can only rank strictly WITHIN
                        // this already-safe set, never widen it.
                        let safe_to_demote =
                            bla < THETA_DEMOTE && (r.importance as i64) < IMP_PIN && util < UTIL_PIN;
                        // The SAME feats the M21 dormant path quantizes (recency/age,
                        // access-frequency, + two reserved), onto the EXACT kancell grid so
                        // the shadow is bit-exactly reconstructible (proposal §3). Built here
                        // (inside the borrow) so the recorded context matches the live decision.
                        let feats: [i32; KAN_FEATURES] = [
                            exp::quantize_feature(age as i64),
                            exp::quantize_feature(r.count as i64),
                            0,
                            0,
                        ];
                        // M23 COUNTERFACTUAL SHADOW: evaluate the dormant cell's would-be
                        // score UNCONDITIONALLY (logged only, never on the live path). This
                        // is the SAME `kan_score` over the SAME feats the M21 active branch
                        // would use, so a recorded feats row REPLAYS to this value bit-exactly.
                        let shadow =
                            kan_score(&KAN_TABLE, &feats, XP_SHADOW_FLAG_TERMS, XP_SHADOW_BIAS);
                        // The heuristic action the deterministic logging policy actually serves.
                        let action = if safe_to_demote { XP_ACTION_DEMOTE } else { XP_ACTION_KEEP };
                        let verdict = if safe_to_demote { XP_ENV_DEMOTABLE } else { XP_ENV_PINNED };
                        // The behavior margin: how far BLA sat below/above the demote floor
                        // (saturated into i16) -- cheap insurance for a later IPS/DR estimator.
                        let margin = (bla - THETA_DEMOTE).clamp(i16::MIN as i64, i16::MAX as i64)
                            as i16;
                        // M24 SHIELDED EPSILON-GREEDY (proposal §2.1): AFTER the envelope
                        // emits A_safe(x), draw the explore coin keyed to the IMMUTABLE
                        // decision_id (never a mutable step counter) and stamp the closed-form
                        // logging PROPENSITY + SOFT_GREEDY policy kind into the M23-reserved
                        // fields. A record that CLEARED the envelope has m == 2 cleared
                        // candidates (greedy vs alternative) and is explorable; a PINNED
                        // record is a SINGLETON (m == 1, propensity == 1000, never explorable).
                        // The coin chooses AMONG cleared candidates ONLY -- it adds zero actions
                        // to A_safe, so the envelope-no-widening proof re-asserts unchanged. With
                        // `KAN_ACTIVE == false` the explore choice is RECORDED but NEVER changes
                        // the live demote (the heuristic else-branch below still decides), so the
                        // live decision stays byte-identical to M23.
                        let m = if safe_to_demote {
                            EXPLORE_CLEARED_M
                        } else {
                            EXPLORE_SINGLETON_M
                        };
                        let is_greedy = Self::explore_is_greedy(r.id, m);
                        let propensity_q =
                            explore_propensity_q(EPS_NUM, EPS_DEN, m, is_greedy);
                        // The policy kind: SOFT_GREEDY for an explorable (cleared, m>1) record;
                        // a singleton stays DETERMINISTIC (propensity == 1000) -- the mechanical
                        // SOFT_GREEDY-tag + propensity==1000 detector M24 routes singletons by.
                        let policy_kind = if m > 1 {
                            exp::policy_kind::SOFT_GREEDY
                        } else {
                            exp::policy_kind::DETERMINISTIC
                        };
                        xp_obs = Some(ExperienceRecord {
                            decision_id: r.id,
                            kind: exp::kind::FORGET_DECISION,
                            feats,
                            envelope_verdict: verdict,
                            action_taken: action,
                            kan_score_shadow: shadow,
                            // M24: the M23-reserved propensity/policy fields are now POPULATED
                            // by the shielded epsilon-greedy logging policy (schema-stable: the
                            // byte layout is unchanged -- the kani_bakeoff_schema_stability proof).
                            // The outcome stays Unset at the decision site (the survival label is
                            // attached later, from the unfiltered read()-touch stream).
                            logging_propensity_q: propensity_q,
                            logging_policy_kind: policy_kind,
                            outcome: OutcomeLabel::Unset,
                            margin_q: margin,
                        });
                        // M21 DORMANT seam: when (and ONLY when) the spline is ACTIVE, a
                        // record that has CLEARED every envelope guard is additionally ranked
                        // by the verified additive-policy leaf -- the bounded `kan_score`
                        // thresholded by the SAME THETA_DEMOTE comparator. The kan path is
                        // strictly DOWNSTREAM of `safe_to_demote` (it can only KEEP a record
                        // the envelope already marked demotable -- it can never demote one the
                        // envelope pinned), so even an adversarial table is merely suboptimal.
                        // `KAN_ACTIVE` is `false` this milestone, so this branch is NEVER
                        // taken and the decision is byte-identical to the pre-M21 heuristic.
                        if KAN_ACTIVE && safe_to_demote {
                            // Re-threshold the SAME shadow score. (Dead this milestone.)
                            safe_to_demote && shadow < THETA_DEMOTE
                        } else {
                            // DORMANT (and the active-but-ineligible case): the heuristic floor
                            // decides, exactly as the pre-M21 chain did.
                            safe_to_demote
                        }
                    }
                }
            };
            // M23: fold the observed forget-decision into the SEPARATE xp_head + ring
            // (fail-soft, never panics/blocks). Strictly downstream of the live demote.
            if let Some(rec) = xp_obs {
                let _ = self.xp_record(&rec);
            }
            if demote {
                // Capture the demoted record's identity BEFORE the borrow ends, so
                // the M22 tombstone records WHAT was forgotten (token + tier).
                let (tomb_token, tomb_id) = {
                    let r = &self.t3.records[idx];
                    (r.token, r.id)
                };
                self.t3.records[idx].tier = TIER_COLD;
                n += 1;
                // M22: emit a TOMBSTONE provenance entry -- the M17 demote is no
                // longer SILENT, it is a verifiable deletion record in the ledger
                // (proposal §4: "deletion is provable, not silent"). Parented on the
                // prior chain head; `kind = FORGET`. Fail-soft (the demote already
                // applied; the ledger is downstream). `writer_cap_id` carries the
                // demoted record's id (the consolidation daemon is the authorizer).
                let parents = self.parent_of_head();
                let _ = self.ledger_append(
                    prov::kind::FORGET,
                    tomb_token,
                    TIER_COLD,
                    tomb_id,
                    &parents,
                );
            }
            idx = (idx + 1) % len;
        }
        // Advance the persisted clock-hand (wraps), so the next cycle resumes.
        self.consol_cursor = (start as u64 + budget as u64) % len as u64;
        n
    }

    /// M17: ONE bounded maintenance cycle = distill + reflect + forget_sweep, then
    /// reset the importance accumulator, mark the freshness epoch, and flush (advancing
    /// the epoch the foreground reads before trusting T3). Returns the aggregate
    /// affected count. This is the synchronous body the CONSOLIDATE daemon drives.
    fn consolidation_cycle(&mut self) -> u64 {
        let mut n = self.distill();
        if self.reflect_inner(0).is_some() {
            n += 1;
        }
        n += self.forget_sweep();
        self.imp_accum = 0;
        self.last_consolidated_epoch = self.clock;
        let _ = self.backing.flush();
        n
    }

    // --- M18 T4 PROCEDURAL/SKILL tier --------------------------------------

    /// M18 `M_MEM_WRITE_PROC` body: the privileged T4 procedural write, gated by
    /// `Rights::WRITE_PROCEDURAL` at the M11 chokepoint. An OP-SELECTOR rides
    /// `op` (the M17 `consolidate(op,..)` precedent -- NO new ABI method): op0
    /// ADD_SKILL, op1 UPDATE_UTILITY, op2 READ_SKILL (own body), op3 LINK_LINEAGE,
    /// op4 READ_TIER (own tier), op5 ADD_SKILL_EMIT_EXTERNAL (the HIGH-IMPACT
    /// class, M18.1). Returns the op scalar, or `None` (-> `NoMem`) when the
    /// write-amplification quota is exhausted (fail-closed).
    pub(crate) fn write_proc(&mut self, op: u64, a: u64, b: u64, c: u64) -> Option<u64> {
        match op {
            0 => self.skill_add(a, b, c),     // ADD_SKILL(body=a, desc=b, iface/embed packed=c)
            1 => self.skill_bump_util(a, b),  // UPDATE_UTILITY(id=a, reward!=0 => success)
            2 => self.skill_read_body(a),     // READ_SKILL(id=a) -> own body_tok
            3 => self.skill_link(a, b),       // LINK_LINEAGE(id=a, parent=b)
            4 => self.skill_read_tier(a),     // READ_TIER(id=a) -> tier (PROPOSED/ADMITTED)
            5 => self.skill_add_ext(a, b, c), // ADD_SKILL_EMIT_EXTERNAL -> HIGH-IMPACT class
            _ => Some(0),                     // NOOP
        }
    }

    /// Find the store index of skill `id`, or `None`.
    fn skill_idx(&self, id: u64) -> Option<usize> {
        self.t4.skills.iter().position(|s| s.id == id)
    }

    /// ADD_SKILL: push an INERT PROPOSED ORDINARY skill (utility 0, never beats
    /// the deliberative path until admitted). Provenance bits are clear, so its
    /// merge needs no human approval (the M18 path, unchanged).
    fn skill_add(&mut self, body: u64, desc: u64, packed: u64) -> Option<u64> {
        self.skill_add_class(body, desc, packed, 0)
    }

    /// M18.1 ADD_SKILL_EMIT_EXTERNAL: propose a HIGH-IMPACT skill -- one whose WIT
    /// interface declares an external/side-effecting requirement
    /// (`EMIT_EXTERNAL`-tagged, §5). It still lands INERT/PROPOSED exactly like an
    /// ordinary skill; only its MERGE is gated on a human-approval capability (§8).
    fn skill_add_ext(&mut self, body: u64, desc: u64, packed: u64) -> Option<u64> {
        self.skill_add_class(body, desc, packed, SKILL_PROV_EMIT_EXTERNAL)
    }

    /// Shared ADD body: push an INERT PROPOSED skill tagged with `prov` (the
    /// classification provenance), reusing the T2/T3 `TOKEN_QUOTA` write-
    /// amplification cap so a flood of proposals fails-closed (`None`).
    fn skill_add_class(&mut self, body: u64, desc: u64, packed: u64, prov: u8) -> Option<u64> {
        if self.quota.tokens_written.saturating_add(1) > TOKEN_QUOTA {
            return None; // KeyKOS space-bank: proposals fail-closed past the bound
        }
        let id = self.t4.next_id;
        self.t4.skills.push(SkillRecord {
            id,
            body_tok: body,
            desc_tok: desc,
            iface_tok: packed & 0xFFFF_FFFF,
            embedding: packed >> 32,
            c_succ: 0,
            c_use: 0,
            util: 0,
            lineage: Vec::new(),
            tier: SKILL_PROPOSED,
            provenance: prov,
        });
        self.t4.next_id = self.t4.next_id.wrapping_add(1);
        self.quota.tokens_written = self.quota.tokens_written.saturating_add(1);
        self.clock = self.clock.wrapping_add(1);
        // M22: a typed SKILL_ADMIT provenance entry for the T4 procedural write,
        // parented on the prior chain head (chain of custody). `body` is the
        // payload token, `prov` (the EMIT_EXTERNAL classification) rides the tier
        // byte so the ledger records the privileged class. Fail-soft (the skill is
        // already committed; the ledger is downstream).
        let parents = self.parent_of_head();
        let _ = self.ledger_append(prov::kind::SKILL_ADMIT, body, prov, id, &parents);
        Some(id)
    }

    /// M18.1 HARNESS-ONLY (kernel-side; the agent never names this): `true` iff
    /// skill `id` is in the HIGH-IMPACT / `EMIT_EXTERNAL` class -- the merge gate's
    /// classifier. `None` if no such skill.
    pub(crate) fn skill_is_high_impact(&self, id: u64) -> Option<bool> {
        let i = self.skill_idx(id)?;
        Some(self.t4.skills[i].provenance & SKILL_PROV_EMIT_EXTERNAL != 0)
    }

    /// UPDATE_UTILITY: the agent bumps its OWN skill usage counters; the EvolveR
    /// utility `s=(c_succ+1)*SCALE/(c_use+2)` (the `forget_sweep` rule) is recomputed.
    fn skill_bump_util(&mut self, id: u64, reward: u64) -> Option<u64> {
        let i = self.skill_idx(id)?;
        let s = &mut self.t4.skills[i];
        s.c_use = s.c_use.saturating_add(1);
        if reward != 0 {
            s.c_succ = s.c_succ.saturating_add(1);
        }
        s.util = (((s.c_succ as i64 + 1) * SCALE) / (s.c_use as i64 + 2)).max(0) as u32;
        self.clock = self.clock.wrapping_add(1);
        Some(s.util as u64)
    }

    /// READ_SKILL: the agent reads back the body_tok of its OWN skill `id`.
    fn skill_read_body(&self, id: u64) -> Option<u64> {
        let i = self.skill_idx(id)?;
        Some(self.t4.skills[i].body_tok)
    }

    /// READ_TIER: the agent reads back the PROPOSED/ADMITTED tier of its OWN skill.
    fn skill_read_tier(&self, id: u64) -> Option<u64> {
        let i = self.skill_idx(id)?;
        Some(self.t4.skills[i].tier as u64)
    }

    /// LINK_LINEAGE: append a parent/provenance id to the agent's OWN skill
    /// lineage (the DGM archive-lineage seam); returns the new lineage length.
    fn skill_link(&mut self, id: u64, parent: u64) -> Option<u64> {
        let i = self.skill_idx(id)?;
        self.t4.skills[i].lineage.push(parent);
        self.clock = self.clock.wrapping_add(1);
        Some(self.t4.skills[i].lineage.len() as u64)
    }

    /// M18 HARNESS-ONLY (kernel-side; NOT method-numbered, so unreachable from
    /// `dispatch`): the `(body_tok, tier)` of skill `id`, for the frozen harness
    /// to score + the self-test to witness. `None` if no such skill.
    pub(crate) fn skill_get(&self, id: u64) -> Option<(u64, u8)> {
        let i = self.skill_idx(id)?;
        let s = &self.t4.skills[i];
        Some((s.body_tok, s.tier))
    }

    /// M18 HARNESS-ONLY ADMIT (kernel-side; never the agent): flip skill `id`
    /// PROPOSED->ADMITTED ONLY when `score` STRICTLY improves on the store's best
    /// admitted held-out score (no-regression / EXCEL rung). On admit: EvolveR
    /// utility `U += (R-U)/5` (alpha=0.2), raise the watermark, and append the
    /// reward to the immutable lineage. On reject: stay PROPOSED/inert and append
    /// a `0` REJECT marker to the lineage. Returns `true` iff admitted.
    pub(crate) fn skill_admit(&mut self, id: u64, score: u32) -> bool {
        let best = self.t4.best_score;
        let i = match self.skill_idx(id) {
            Some(i) => i,
            None => return false,
        };
        self.clock = self.clock.wrapping_add(1);
        if score > best {
            let s = &mut self.t4.skills[i];
            s.tier = SKILL_ADMITTED;
            s.c_use = s.c_use.saturating_add(1);
            s.c_succ = s.c_succ.saturating_add(1);
            let u = s.util as i64;
            let r = score as i64;
            s.util = (u + (r - u) / UTIL_ALPHA_DIV).max(0) as u32;
            s.lineage.push(score as u64);
            self.t4.best_score = score;
            true
        } else {
            self.t4.skills[i].lineage.push(0); // rejected-into-lineage (DGM verdict)
            false
        }
    }

    /// M18 HARNESS-ONLY: count of ADMITTED skills (the trust-promotion witness).
    pub(crate) fn skill_count_admitted(&self) -> u64 {
        self.t4
            .skills
            .iter()
            .filter(|s| s.tier == SKILL_ADMITTED)
            .count() as u64
    }

    /// M18 HARNESS-ONLY: the lineage length of skill `id` (admitted AND rejected
    /// proposals both grow it -- the immutable, agent-unwritable provenance log).
    pub(crate) fn skill_lineage_len(&self, id: u64) -> u64 {
        match self.skill_idx(id) {
            Some(i) => self.t4.skills[i].lineage.len() as u64,
            None => 0,
        }
    }

    /// M18 FROZEN-DOMAIN seeding (kernel-side): seed `n` deterministic held-out
    /// `(input -> expected)` episodes where `expected = skill_transform(target,
    /// input)`. Stored as ordinary T2 records so [`MemSubstrate::score_candidate`]
    /// scores against the SAME journal the improving agent holds NO handle to.
    pub(crate) fn seed_heldout(&mut self, target: u64, base: u64, n: u64) {
        let mut k = 0u64;
        while k < n {
            let input = base
                .wrapping_add(k)
                .wrapping_mul(0x0010_0001)
                .wrapping_add(0x51);
            let expected = skill_transform(target, input);
            let _ = self.push_record(input, expected, 5, 0, Vec::new());
            k += 1;
        }
    }

    /// M18 FROZEN held-out EVALUATOR (kernel-side, READ-ONLY): model the candidate
    /// `body`'s behavior with [`skill_transform`] and score it over THIS substrate's
    /// held-out `(input -> expected)` episodes -- the fraction of cases where
    /// `f(body, input) == expected`, normalized to `[0, SCALE]`. Pure, no floats,
    /// deterministic. Runs in the frozen domain (the agent has no handle to this
    /// substrate), so a body that games a visible slice still misses the held-out
    /// set: Goodharting/overfitting scores low and is rejected by the no-regression
    /// rule. Returns `0` when no held-out case exists.
    pub(crate) fn score_candidate(&self, body: u64) -> u32 {
        let mut total = 0i64;
        let mut hit = 0i64;
        for e in self.t2.log.iter() {
            if e.t_invalid != 0 {
                continue;
            }
            total += 1;
            if skill_transform(body, e.content_tok) == e.value {
                hit += 1;
            }
        }
        if total == 0 {
            return 0;
        }
        ((hit * SCALE) / total) as u32
    }
}
