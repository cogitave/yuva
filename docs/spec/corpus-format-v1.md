# Corpus Format v1 — the FROZEN `CorpusRecord` schema (M39 stage A)

**Status:** **FROZEN.** This is the normative, byte-level contract for the Phase-1
EXPERIENCE CORPUS record. It is the source of truth for `crates/tb-encode/src/corpus.rs`
and, later, for the in-kernel `corpus_head` seam and the host `tools/corpus-export/`
join. **The schema is frozen BEFORE the codec by design** (the tabos-milestone
discipline): a `CorpusRecord` is fixed-width, canon-encoded, and folded into a
hash-chain `corpus_head`, so adding or reordering a field after the freeze would
change the canonical bytes and break BOTH replay-determinism and every already-
committed `corpus_head` — the exact schema-stability obligation `exp.rs:32-40`
pre-reserved fields for. Forward evolution happens through the RESERVED fields and
the `schema_version` byte, never by shifting a live offset.

> **What this is, honestly.** A corpus record is a **PROVENANCE SKELETON**, not text.
> Memory content in Yuva is stored as u64 INTERNED TOKENS, not strings
> (`crates/tb-hal/src/mem/mod.rs:766,787,862` — `content_tok`/`token`/`body_tok`); the
> text dictionary is agent-side/userspace by MEMORY-SPEC design. So a `CorpusRecord`
> carries **token ids + a lineage head + a timestamp + a curation verdict**, and the
> host exporter joins the tokens back to text through the agent-supplied dictionary.
> `token=corpus=PROVENANCE-SKELETON-TEXT-IS-AGENT-DICT-JOIN`.
>
> **What this is NOT.** It is NOT a model, NOT training, and NOT an activation of the
> Learning pillar. Building the corpus is the Phase-1 **data-engineering PREREQUISITE**
> that stocks the dataset a Phase-2 (operator-gated) fine-tune would consume; it does
> not touch `KAN_ACTIVE` and does not flip the pillar out of dormancy.
> `token=phase1=LEARNING-PREREQUISITE-NOT-CAPABILITY-ADVANCE`,
> `token=training=NONE-PHASE2-GATED`.
>
> **The curation verdict is DECLARED, not learned.** The `curation_verdict` byte
> records the outcome of a deterministic curation predicate (a later in-kernel
> increment); nothing in this format learns or grades. `token=curation=PREDICATE-DECLARED-NOT-LEARNED`.

---

## 1. Scope of v1

v1 fixes the on-wire and in-fold byte layout of ONE curated experience row. It does
NOT specify the in-kernel emit path, the durable region, or the export JSONL — those
are later M39 increments that CONSUME this frozen format. v1 specifies exactly:

- the fixed field set, order, widths, and offsets (§2);
- the closed enum vocabularies and their fail-closed decode (§3);
- the RESERVED fields and the schema-stability guarantee (§4);
- the fold binding — how a record joins the `corpus_head` by REUSING the M22 `prov`
  fold verbatim, with no new fold math (§5);
- the frozen invariants the codec and its Kani harnesses discharge (§6).

## 2. The `CorpusRecord` byte layout (fixed-width, LE, 71 bytes)

Every record is FULLY FIXED-WIDTH — there is no variable-length tail — so `canon` is
injective by construction (each field owns a fixed offset) and `canon_len` is a single
`const`, `CORPUS_CANON_LEN = 71`. All multi-byte scalars are little-endian.

```text
  offset  width  field               type       meaning
  ------  -----  ------------------  ---------  ---------------------------------------
  [0]       1    schema_version      u8         = CORPUS_SCHEMA_V1 (1). A bump is
                                                replay-detectable; decode fail-closes
                                                on any other value (this is the v1 codec).
  [1]       1    example_kind        u8         closed set §3.1: which curated channel
                                                this row is (episodic-consolidation /
                                                operator-turn / labeled-outcome).
  [2]       1    source_stream       u8         closed set §3.2: which substrate stream
                                                the row was curated FROM (M13 mem / M17
                                                reflect / M25 operator / M31 infer).
  [3]       1    curation_verdict    u8         closed set §3.3: the DECLARED curation-
                                                predicate outcome (rejected / accepted).
  [4..12]   8    content_tok         u64 LE     the interned CONTENT token id — the
                                                agent-dictionary text-join handle
                                                (PROVENANCE SKELETON, not text).
  [12..20]  8    aux_tok             u64 LE     a secondary interned token id (the
                                                reflect cite-back / operator response /
                                                inference prompt handle), 0 when unused.
  [20..28]  8    t_created           u64 LE     the substrate logical clock at curation.
  [28..60] 32    source_head        [u8;32]     the M22 fold-position: the lineage
                                                `chain_head`/`xp_head` this row was
                                                curated at, linking it back to its
                                                source provenance (all-zero = genesis).
  [60]      1    outcome.tag         u8          the labeled-outcome channel TAG (§3.4).
                                                PRESENT-Unset this milestone (RESERVED).
  [61..69]  8    outcome.payload     i64 LE      the labeled-outcome PAYLOAD. Present-
                                                but-zero for Unset. Fixed 8-byte slot
                                                REGARDLESS of variant (schema-stable).
  [69..71]  2    curation_score_q    i16 LE      RESERVED graded-curation sentinel
                                                (present; 0 this milestone).
```

`CORPUS_CANON_LEN = 1+1+1+1 + 8+8+8 + 32 + 1+8 + 2 = 71`.

## 3. Closed enum vocabularies (fail-closed decode)

Decode is TOTAL and fail-closed: it returns `None` (never panics, never partial-reads)
on a too-short buffer OR any out-of-vocabulary tag in a closed-set field. `canon` is
defined over the whole `u8` domain of each field (injectivity is a property of the
ENCODER and does not depend on validity); the closed-set VALIDATION lives in `decode`,
so a v1 decoder rejects a byte pattern it does not recognise rather than silently
mis-interpreting it. This is stronger than the M23 exp decoder (which validated only
the outcome tag), and is the frozen fail-closed posture v1 commits to.

### 3.1 `example_kind` — the curated channel

| value | name | meaning |
|---|---|---|
| 1 | `EPISODIC_CONSOLIDATION` | an M17 consolidation outcome — a `distill()` survivor or a `reflect_inner()` insight promoted to a curated example. |
| 2 | `OPERATOR_TURN` | an M25/M28 operator-approved turn (a human-in-the-loop transcript row). |
| 3 | `LABELED_OUTCOME` | a row carrying a resolved outcome label from the survival stream. |

### 3.2 `source_stream` — the provenance stream

| value | name | meaning |
|---|---|---|
| 1 | `M13_MEM` | an M13 `MemRecord` (`content_tok` is the record's content token). |
| 2 | `M17_REFLECT` | an M17 reflection insight (`aux_tok` is the cited-back token). |
| 3 | `M25_OPERATOR` | an M25/M28 approved operator turn. |
| 4 | `M31_INFER` | an M31/M32 inference digest. |

### 3.3 `curation_verdict` — the DECLARED predicate outcome

| value | name | meaning |
|---|---|---|
| 0 | `REJECTED` | the curation predicate declined the row (recorded, not silently dropped). |
| 1 | `ACCEPTED` | the curation predicate admitted the row into the corpus. |

`token=curation=PREDICATE-DECLARED-NOT-LEARNED` — the byte records a verdict; the
predicate is a deterministic later increment, and nothing here learns.

### 3.4 `outcome.tag` / `outcome.payload` — the labeled-outcome channel (RESERVED)

A present-but-Unset tagged variant, mirroring the PROVEN M23 `exp::OutcomeLabel` idiom
so populating it later is bit-stable (§4):

| tag | variant | payload |
|---|---|---|
| 0 | `Unset` | present-but-zero (this milestone) |
| 1 | `Positive(i64)` | a positive training label (e.g. an operator-approval id) |
| 2 | `Negative(i64)` | a negative training label (e.g. a corrected/rejected id) |

Any other tag → `decode` fails closed to `None`.

## 4. RESERVED fields and the schema-stability guarantee

Three fields are RESERVED — present in the v1 layout NOW, at fixed offsets, so a later
milestone can POPULATE them WITHOUT shifting any live offset or changing the canonical
length (hence without breaking any already-committed `corpus_head`):

- `outcome` (`[60..69]`) — present-Unset now; a later increment sets `Positive`/`Negative`
  for the labeled-outcome channel. The 8-byte payload slot is present regardless of
  variant, so an `Unset` row and a populated row have IDENTICAL length and offsets.
- `curation_score_q` (`[69..71]`) — 0 now; reserved for a future graded curation score.
- `aux_tok` (`[12..20]`) — 0 when unused now; reserved per `example_kind` for the
  cite-back / response / prompt secondary handle.

The **schema-stability lemma** (discharged by `kani_corpus_schema_stability`): a record
with `outcome = Unset` and an otherwise-identical record with a POPULATED outcome encode
to the SAME length, are byte-identical in `[0..60)` (every field before the outcome tag)
and byte-identical in `[69..71)` (the trailing `curation_score_q`); only the fixed
`[60..69)` outcome window differs, at an offset that never moves. This is the exact
`exp.rs` reserve-now discipline, and it is what lets the format be FROZEN today while
still admitting the labeled-outcome channel later.

`schema_version` is the coarse escape hatch: a genuinely incompatible v2 changes the
byte at `[0]`, which a v1 decoder rejects (fail-closed) — a version bump is loud and
replay-detectable, never a silent reinterpretation.

## 5. Fold binding — REUSE the M22 `prov` fold verbatim (no new fold math)

A record joins the growing corpus by folding its canonical bytes into a per-agent
`corpus_head`, REUSING the proven M22 provenance leaf verbatim — exactly as the M23 exp
log and the M38 conductor reuse it, writing NO new fold math:

1. `canon(rec, &mut scratch)` → the 71 canonical bytes (fail-closed to `0`);
2. `prov::prov_hash(&scratch[..71])` → the 32-byte leaf id (BLAKE2s-256, khash);
3. `prov::chain_mix(corpus_head, leaf_id)` → the advanced `corpus_head`.

`corpus.rs` re-exports `prov::{append, chain_mix, recompute, verify_inclusion,
head_witness, prov_hash}` as `corpus_*` aliases and calls them; the fold's determinism,
tamper-sensitivity, and inclusion-soundness are ALREADY proven by the `prov` Kani suite
(`kani_prov_chain_mix_tamper`, `kani_prov_head_deterministic`, `kani_prov_inclusion_sound`)
and are inherited unchanged. The `corpus_head` is a SEPARATE accumulator from `chain_head`
/ `xp_head` / `conduct_head`; separation is by distinct head + the distinct canonical
record bytes, the same house discipline the sibling folds use.

Cryptographic scope is inherited verbatim from `prov`/`khash`: implementation totality /
determinism / tamper-sensitivity are PROVEN; the BLAKE2s-256 primitive's collision /
preimage resistance is `sec=ASSUMED-FROM-LITERATURE`, never prose-claimed.

## 6. Frozen invariants (the codec + harness obligations)

1. **Fixed width / totality.** `canon` writes EXACTLY `CORPUS_CANON_LEN` into a large-
   enough buffer and `0` (no partial write) into a too-small one; it never panics.
2. **Injectivity.** Two records differing in ANY field — including the RESERVED
   `outcome` tag, `curation_score_q`, and `aux_tok` — encode to different bytes.
3. **Round-trip.** `decode(canon(rec)) == Some(rec)` for every record over the valid
   vocabularies; re-encoding a decoded record reproduces identical bytes.
4. **Fail-closed decode.** A too-short buffer, an unknown `schema_version`, or any out-
   of-vocabulary closed-set tag (`example_kind`, `source_stream`, `curation_verdict`,
   `outcome.tag`) decodes to `None` — never a panic, never a silent mis-decode.
5. **Schema stability.** An `Unset` record and a populated-outcome record have identical
   length and identical offsets outside the fixed `[60..69)` outcome window (§4).
6. **Fold determinism + inheritance.** Folding a record via the reused `prov` leaf is
   deterministic, and a single-byte tamper of a committed record's canonical bytes
   changes the recomputed `corpus_head` and fails its inclusion proof (inherited from
   the proven `prov` fold).

---

*Frozen against `origin/main` `49fd035`. Consumers: `crates/tb-encode/src/corpus.rs`
(this increment); the in-kernel `corpus_head` seam, the durable corpus region, and
`tools/corpus-export/` (later M39 increments). Any change to §2/§3/§5 is a v2, gated on
a new `schema_version` and a fresh spec file — never an in-place edit of this one.*
