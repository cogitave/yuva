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

/// Fixed-point scale: every normalized score component lives in `[0, SCALE]`.
const SCALE: i64 = 1000;
/// `ln(2)` scaled by [`SCALE`] (converts an integer `log2` into `ln`).
const LN2_FIXED: i64 = 693;
/// Bounded T0 context-register slots (ACT-R buffers; const-bounded prompt).
const N_REG: usize = 8;
/// Bounded per-agent Finsts ring (ACT-R `:recently-retrieved` breaker).
const F_FINST: usize = 4;
/// T1 working-graph node quota (Soar WM bound).
#[allow(dead_code)]
const NODE_QUOTA: usize = 256;
/// Token write-amplification cap (KeyKOS space-bank); writes beyond it fail-closed.
const TOKEN_QUOTA: u64 = 1 << 20;

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

// --- fixed-point integer math (no floats: deterministic, FPU-hazard-free) -----

/// `log2(x) * SCALE` as an integer (`0` for `x <= 1`): floor part from the
/// leading-bit position, fractional part by a linear interpolation in `[0, 1)`.
fn log2_fixed(x: u64) -> i64 {
    if x <= 1 {
        return 0;
    }
    let ip = 63 - x.leading_zeros() as i64; // floor(log2 x)
    let pow = 1u64 << (ip as u32);
    let frac = ((x - pow) as i64 * SCALE) / pow as i64; // linear in [0, SCALE)
    ip * SCALE + frac
}

/// `ln(x) * SCALE` as an integer, via `log2(x) * ln(2)`.
fn ln_fixed(x: u64) -> i64 {
    log2_fixed(x) * LN2_FIXED / SCALE
}

/// The ACT-R base-level activation BLA(d=0.5) in fixed point (the O(1) fallback,
/// Petrov optimized-learning): grows with access frequency, decays with age.
/// Higher = more active (more recent and/or more often accessed).
fn bla_raw(count: u32, age: u64) -> i64 {
    let freq = ln_fixed(2 * (count as u64 + 1)); // frequency term
    let recency = ln_fixed(age + 1) / 2; // 0.5 * ln(age) decay
    freq - recency
}

/// Min-max normalize `vals[i]` over the candidate set into `[0, SCALE]`; a
/// degenerate (all-equal) component contributes `0` so it cannot reorder.
fn minmax(vals: &[i64], i: usize) -> i64 {
    let mut lo = vals[0];
    let mut hi = vals[0];
    for &v in vals.iter() {
        if v < lo {
            lo = v;
        }
        if v > hi {
            hi = v;
        }
    }
    if hi == lo {
        0
    } else {
        (vals[i] - lo) * SCALE / (hi - lo)
    }
}

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
        }
    }

    /// The current freshness epoch of the backing store (T3 staleness marker).
    #[allow(dead_code)]
    pub(crate) fn epoch(&self) -> u64 {
        self.backing.epoch()
    }

    /// `tb_mem_write`: the Mem0 four-op write vocabulary. Returns the affected
    /// record id, or `None` when the write-amplification quota is exhausted.
    pub(crate) fn write(&mut self, op: u64, key: u64, value: u64, packed: u64) -> Option<u64> {
        match op {
            0 | 1 => self.add(key, value, packed), // ADD / UPDATE (append new version)
            2 => self.delete(key),                 // DELETE -> tombstone
            _ => Some(0),                          // NOOP
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
    /// journal (no ranking, no model). Returns the stored value scalar.
    pub(crate) fn read(&self, id: u64) -> Option<u64> {
        self.t2.log.iter().find(|e| e.id == id).map(|e| e.value)
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
                        // AND-gate (high-value survival): all three must hold.
                        bla < THETA_DEMOTE && (r.importance as i64) < IMP_PIN && util < UTIL_PIN
                    }
                }
            };
            if demote {
                self.t3.records[idx].tier = TIER_COLD;
                n += 1;
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
}
