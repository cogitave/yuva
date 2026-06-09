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
