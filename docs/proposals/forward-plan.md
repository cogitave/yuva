---
type: Roadmap
title: "Yuva/Cogi Forward Plan — the phased road to a learning, model-bearing agent-OS"
description: "Research-first roadmap sequencing eight parallel tracks toward a two-phase model endgame; flagship is a no-live-model experience corpus."
tags: ["roadmap", "corpus", "fine-tune", "m39", "parallel-tracks", "sovereignty"]
timestamp: 2026-07-08T11:21:29+03:00
status: active
diataxis: explanation
---

# Yuva/Cogi FORWARD PLAN — the phased road from a mature sovereign substrate to a learning, model-bearing agent-OS, with the parallel-track schedule the operator drives

**Status:** **PLAN (research-first; nothing landed by this document). The convergent forward map that sequences the three landed sibling milestones (boot-profiles stage A, Yuva-ABI stage A, agent-terminology) and the mature M0..M38 substrate toward the four-pillar vision, honoring the 2026-07-08 operator decisions (tinygrad DEFERRED, Namzu DEFERRED, the model endgame is TWO PHASES with the CORPUS as the real prerequisite, and the three GATES stay operator-owned).** · **Pillars & their honest state:** sovereignty (**STRONG** — kernel + M11/M18 caps + M22/M33 provenance-EXCLUSIVITY, zero-unsafe kernel, Kani-verified leaves), memory (**STRONG for storage/recall** — M13-M20 tiered, LEXICAL/BM25 recall NOT embeddings, durable, reboot-surviving), continuous-learning (**DORMANT** — KAN_ACTIVE=false, the M24 Seldonian gate correctly gate-not-met AND the no-gradient substrate structurally cannot weight-learn; the biggest OPEN pillar — and it STAYS dormant through Phase 1, since a dataset build is a prerequisite, not a capability advance), operator-communication (**GOOD** — M25/M28, industrial-boot, the hello). · **Discipline:** every witness carries honesty tokens; a mock is a mock, dormant is standby, a stand-in is a stand-in, a provenance skeleton is not text. · **Terminology:** agent-agnostic throughout (Yuva = the OS; Cogi = the future resident agent's identity, home = `cogitave/cogi`; no assumption of any specific model provider or agent framework as the occupant). · **The load-bearing deliverable is §3, the parallel-track table.** `token=plan=RESEARCH-FIRST-NOTHING-LANDED`, `token=pillars=SOV-STRONG/MEM-STRONG/LEARN-DORMANT-THROUGH-PHASE1/COMMS-GOOD`.

> **One-line:** The substrate is mature and sovereign; the two open frontiers are LEARNING (dormant) and the MODEL (no live occupant). The flagship ungated move is neither — it is the **Phase-1 experience corpus**: turn Yuva's already-signed, reboot-surviving memory into a GROWING, CURATED, tamper-evident EXPERIENCE CORPUS (the dataset moat) with NO live model, by reusing three landed primitives (the M22 prov fold, the M23 experience-codec pattern, the M33 durable signed-head persistence) verbatim. The corpus is the real PREREQUISITE for Cogi's own model — data-engineering that stocks the dataset the Phase-2 fine-tune consumes; it is NOT itself an activation of the Learning pillar (that stays dormant until a Phase-2 fine-tune or KAN activation). Compute/tokens are cheap. Everything model-training and everything bare-metal-x86 stays behind an operator gate.

---

## 1. Where we are — the mature substrate, honestly

**In-repo state:** `origin/main` `49fd035`, all CI-green, pinned nightly-2026-07-06. The sovereign substrate is MATURE. What is genuinely built and boot-witnessed today:

| Layer | What is landed | Honesty token |
|---|---|---|
| **Kernel / caps** | M0-M11 kernel, zero-unsafe kernel body, M11 capability dispatch + M18/M18.1 admission gate (organs as opt-in capabilities) | `sovereignty=STRONG` |
| **Memory** | M13-M20 tiered store, LEXICAL/BM25 recall (NOT embeddings), durable M20 (YUVAMEM0), M17 consolidation (distill + reflect) | `memory=STORAGE-RECALL-STRONG`, `recall=LEXICAL-NOT-SEMANTIC` |
| **Provenance** | M22 tamper-evident BLAKE2s-256 fold + M33 LMS-signed lineage surviving reboot = **EXCLUSIVITY** (torn-write-safe, per-sector gen-tag, ping-pong recovery) | `provenance=EXCLUSIVITY-REBOOT-SURVIVING` |
| **Orchestration** | M38 Conductor — verified discrete orchestrator over MOCK/stand-in organs; conduct head `0x066855300c57557b` is the deterministic regression baseline | `conductor=VERIFIED-OVER-MOCK-ORGANS` |
| **Inference transport** | M30/M31 wire (MOCK backend, NO live model); M32-B local-organ receive seam (deterministic stand-in, honest) | `backend=MOCK-NO-LIVE-MODEL`, `m32b=DETERMINISTIC-STAND-IN` |
| **ABI** | Yuva-ABI v1 (`docs/spec/yuva-abi-v1.md` + `crates/tb-encode/src/abi.rs` frozen-literal registry + `caps::abi_registry_selfcheck` in-kernel boot self-check, FAIL-CLOSES on drift) | `abi=IN-REPO-SPEC-AT-STAGE-A` |
| **Boot profiles** | Stage A: `yuva.profile=substrate\|agent` (default agent), a real execution GATE — substrate omits the organs, negative-census proven | `separability=EXECUTION-ADMISSION-LEVEL-AT-STAGE-A` |
| **Terminology** | agent-neutral in code (`View::Agent`, generic principals; last `Cogi` in one host fixture) | `terminology=AGENT-NEUTRAL-PER-DIRECTIVE` |
| **CI** | run-x86_64/aarch64/vmm scripts grep 100+ cumulative markers M0..M38; kani.yml 3 encoder shards (123 harnesses, swap-headroom) | `ci=100+-MARKER-CUMULATIVE-CHAIN` |

**The two structural facts that shape everything downstream (stated sharply, so nothing overclaims):**

1. **Memory content is stored as u64 INTERNED TOKENS, not text** (`crates/tb-hal/src/mem/mod.rs:766,787,862` — `content_tok`/`token`/`body_tok`). The text dictionary is agent-side/userspace by MEMORY-SPEC design. So any kernel-side corpus is a **provenance skeleton in tokens**; text is joined host-side. `token=corpus=PROVENANCE-SKELETON-TEXT-IS-AGENT-DICT-JOIN`.
2. **KAN is not learning.** The M21 kancell is a FROZEN integer additive-policy GAM (a per-segment spline LUT, `KAN_TABLE` const at `mem/mod.rs:284`) that ranks memory FORGET/retention decisions inside the heuristic safety envelope. It is NOT neural learning and NOT model-training (`M21-kan-policy.md:21,61`: "Nothing is learnable in-kernel"; offline-fit float knots quantized to a frozen i16 const). `KAN_ACTIVE=false` (`mem/mod.rs:273`) is DORMANT for **two simultaneously-true reasons** (`cogi-cognitive-architecture.md §2.2`): (a) **principled** — the M24 Seldonian gate correctly refuses to self-grade on synthetic traces (gate-not-met by design), and (b) **structural** — the no-gradient/no-float substrate CANNOT do weight-locus learning at all. `token=kan=FROZEN-INTEGER-POLICY-NOT-LEARNING`, `token=dormancy=PRINCIPLED-AND-STRUCTURAL`.

**The pivotal in-tree blocker that gates multiple future tracks:** `crates/tb-hal/src/mem/{mod.rs,selftests.rs}` welds the M20 storage ENGINE (`BackingStore`/`VirtioBlkStore`) to the M13 memory ORGAN (`MemSubstrate`/`recall`/KAN) in one unfactored file (recall at `mod.rs:1339`, `KAN_ACTIVE` at `:273`). This `mem/` factorization is the shared enabler of boot-profiles stage B (compile-out), the extraction resident cut, and it overlaps the corpus/recall work. `token=mem-factorization=PIVOTAL-SHARED-BLOCKER`.

---

## 2. The phased roadmap toward the vision — with each phase's DoD

The vision is a **sovereign + memory + LEARNING + operator-comms agent-OS**, whose endgame is *Cogi's own model* reached via **Phase-1-corpus → Phase-2-finetune**. The roadmap sequences that honestly.

### 2.1 Phase 0 — the mature substrate (DONE)

Everything in §1. Sovereignty and memory-storage are strong; operator-comms is good. **DoD (met):** M0..M38 cumulative chain CI-green on both arches; provenance survives reboot; the ABI fail-closes on drift; the substrate profile boots with organs provably not run.

### 2.2 Phase 1 — the DATASET MOAT (the ungated flagship, NOW-buildable)

**Goal:** turn Yuva's provenance-signed, reboot-surviving memory into a **GROWING, CURATED, tamper-evident EXPERIENCE CORPUS** that is training-ready — with **NO live model** — by reusing landed primitives, so you know EXACTLY what Cogi will have learned from. This is the **Phase-1 PREREQUISITE for the Learning pillar — data-engineering, NOT a capability advance of the pillar.** It does **not** activate learning, does **not** touch KAN (activating KAN is orthogonal, §2.4), and the Learning pillar remains DORMANT throughout Phase 1; the corpus simply builds the dataset the Phase-2 fine-tune consumes. `token=phase1=LEARNING-PREREQUISITE-NOT-CAPABILITY-ADVANCE`, `token=learn-pillar=STAYS-DORMANT-THROUGH-PHASE1`.

**What already exists to build on:** M17 consolidation ALREADY manufactures the curated high-value examples — distilled survivors (provenance=2, `distill()`, `mem/mod.rs:1560`) and reflection insights (provenance=1 with cites-back links, `reflect_inner()`, `:1611`) — but only in-RAM. M23 already logs (features→decision→outcome) tuples into a tamper-evident `xp_head`+ring, but the ring is IN-RAM, drop-oldest, cap-64 (`mem/mod.rs:930,935`) — a sliding WINDOW, not a growing corpus (durable spill is the **M24-named-but-unbuilt** gap). The missing piece = a corpus EXPORT FORMAT + consolidation-into-corpus emit + durable growth + host export tool, all provenance-preserved.

**Honest correction carried into the design:** the "experience corpus" the operator means (a NL/reasoning dataset moat) is a curation over M13 MemRecords + M25/M28 operator transcript + M31/M32 inference digests — each row carrying its M22 fold-position / M33 signature. It is **NOT** the M23 `ExperienceRecord` scheduling tuples (those feed the dormant kancell). The corpus REUSES the M22/M23/M33 tamper-evidence machinery but its rows are language/reasoning examples, not scheduling triplets. `token=corpus=NL-CURATION-OVER-M13/M25/M31-NOT-M23-TUPLES`.

**DoD:**
1. A FROZEN corpus-format spec (`docs/spec/corpus-format-v1.md`) — `CorpusRecord` schema frozen before any codec (it is folded into a hash chain; adding a field later breaks replay-determinism, the exact schema-stability lemma `exp.rs:32-40` pre-reserved fields for).
2. A verified corpus codec leaf (`crates/tb-encode/src/corpus.rs`) — injective + TOTAL + fail-closed, folded into a `corpus_head` via the REUSED M22 prov fold (`prov::{append,chain_mix,verify_inclusion,head_witness,prov_hash}`, **no new fold math**), with Kani harnesses (canon-injective, roundtrip, fold-tamper-sensitivity, inclusion-soundness).
3. An in-kernel corpus seam — `corpus_head` + `corpus_ids` alongside (never inside) `chain_head`/`xp_head`, a deterministic curation predicate, emit wired into `consolidation_cycle` (`mem/mod.rs:1794`), a `CorpusProof` boot self-test, a new cumulative marker.
4. Durable GROWING corpus — reuse the M33 `provhead.rs` persistence to spill records + persist a SIGNED `corpus_head` to a new durable M20 region, with a two-boot cross-reboot witness (boot1 writes/consolidates → boot2 verifies the signed head survived + records decode + lineage intact).
5. A host export tool (`tools/corpus-export/`) — verifies the signed head (LMS path), joins the agent-supplied token→text dictionary, emits training-ready JSONL where every example carries a provenance envelope (lineage hash, source M22/M23 ids, consolidation_class, outcome label, honesty tokens); a CPU-only, zero-secret, zero-network CI lane asserting round-trip (kernel `corpus_head` == host-recomputed head over the exported rows).
6. Labeled-outcome + operator-turn channels populated (M23 `OutcomeLabel` from the survival stream; M25/M28 approved turns as `example_kind=operator-turn`).

**Conduct-head re-verification (mandatory for this track):** because §1's recall feeds the M38 conductor input, landing the corpus emit into `consolidation_cycle` requires re-confirming the byte-identical conduct head after this track merges (see §3, SP#4).

`token=phase1=UNGATED-FLAGSHIP`, `token=corpus=GROWING-CURATED-TAMPER-EVIDENT`, `token=reuse=M22-FOLD+M23-CODEC-PATTERN+M33-DURABLE-HEAD`.

### 2.3 Phase 2 — Cogi's own model (GATED — BRAIN gate)

**Goal:** distill/fine-tune an OPEN base model on the accumulated corpus → a sovereign Cogi model that gives its own answers. This is a **Phase-2, operator-gated, OPEN capability** — the base model, framework, and fine-tune method are decisions the operator makes at the gate, not commitments this plan bakes in. **Pragmatic path (operator-decided default):** llama.cpp/GGUF for inference (the `tools/infer-daemon` + `llama-engine-sys` plumbing ALREADY exists — M32-B is its receive seam) + a host-side QLoRA fine-tune (PyTorch + Unsloth-or-axolotl). tinygrad is a possible LATER sovereign-compute stack, NOT now.

**The load PLUMBING is already built — but serving a new model still requires a golden-measure run.** `tools/infer-daemon/` is a working key-holding safe-Rust daemon + keyless sandboxed worker that links vendored llama.cpp, loads a SHA256-pinned GGUF, and runs greedy completion end-to-end over the M30/M31 wire; it serves `models/stories260K.gguf` today. Serving a future sovereign Cogi model is therefore a KNOWN, low-risk sequence, but NOT literally three lines: (1) produce a GGUF, (2) **run the produced model to MEASURE its goldens** (the daemon pins and adjudicates against goldens — you cannot pin goldens you have not measured), (3) append one `ModelPin{name,path,sha256,goldens}` const (`pins.rs:22-40`), (4) the daemon serves it. So Phase 2 after "produce GGUF" is a KNOWN, CHEAP path whose only non-trivial step is the measure-run. `token=phase2-load=PLUMBING-BUILT-BUT-REQUIRES-GOLDEN-MEASURE-RUN`.

**DoD (gated — needs the operator's go + a corpus + spend/hardware):**
1. Corpus reaches fine-tune-sufficient curated size (Phase-1 accumulation over real operation time + curation review).
2. Open base model selected (≥7B — must clear the ~7B competence floor; `cogi-cognitive-architecture.md §1.2b`: sub-7B GGUF reproduces the scaling-cliff / BrowseComp-zero failure).
3. QLoRA fine-tune run (PyTorch + Unsloth/axolotl, ~weeks, ~$100-2000), adapters merged, converted to GGUF (`convert_hf_to_gguf` + quantize Q4_K_M/Q8_0).
4. Produced model's goldens MEASURED (measure-run) and pinned into `pins.rs`; its adjudication lane stood up.

**Honest capability ceiling:** an open QLoRA fine-tune on a ≥7B base gives a SOVEREIGN, provider-independent, persona/memory-grounded model **AT the ~7B competence floor** — NOT frontier reasoning. The M31 escalation bridge stays the path to a stronger external reasoner (`cogi-cognitive-architecture.md §2.3/§1.2b`). Yuva secured the SLOT (M32), not the occupant's competence. `token=phase2=OPEN-MODEL-CAPABILITY-NOT-FRONTIER`, `token=sovereignty-of-WEIGHTS≠sovereignty-of-ENGINE` (the B3 pure-Rust engine debt is orthogonal and unchanged by a fine-tune).

### 2.4 The LEARNING pillar — corpus now (prerequisite), KAN activation later, adaptation still deferred

The Learning pillar has **two distinct, orthogonal future advances**, and the plan keeps them razor-sharp. Note that Phase 1 delivers NEITHER — it delivers the DATASET the first of them will eventually consume:

- **The corpus arc (Phase 1, NOW, ungated)** — builds the dataset moat. Does NOT touch `KAN_ACTIVE`, does NOT flip the pillar out of dormancy. It is the data-engineering PREREQUISITE that makes a later "adaptation" advance possible; the pillar itself remains "memory now" until Phase-2 fine-tune (host-side weight-learning) or KAN activation actually flips it. `token=corpus=PREREQUISITE-NOT-PILLAR-ADVANCE`, `token=corpus≠kan-activation`.
- **KAN activation (GATED)** — flipping `KAN_ACTIVE=false→true` swaps the in-kernel memory-retention ranker from heuristic to the frozen spline. Gated on the M24 Seldonian bake-off clearing `V_lower(kan) − V_upper(heuristic) >= ACTIVATION_MARGIN=250` against a REAL exogenous operator oracle (M25/M28) over REAL (non-synthetic) traces. Correctly refuses today (gate-not-met by design). Separate from and NOT a substitute for the model fine-tune. `token=kan-flip=GATED-ON-M24-MARGIN-250-REAL-ORACLE`.

Neither is model weight-adaptation on-substrate — that stays structurally out of scope (no-gradient/no-float discipline). The sovereign model's actual weight-learning happens Phase-2 host-side (PyTorch), not in-kernel. `token=in-kernel-weight-learning=STRUCTURALLY-EXCLUDED`.

---

## 3. The explicit parallel-track table (the load-bearing deliverable)

Eight candidate tracks. **Four serialization points dominate** and every row states its collisions against them:

- **SP#1 — `kernel/src/main.rs` (the boot chain).** A/A′ add memory-region marker blocks (~:1732); B adds a version witness at `abi_registry_selfcheck` (~:1389) + `M_OBJECT_INSPECT` wiring; C rewrites ALL ~18 `if profile::agent_organs_enabled()` gate blocks (:1732–:5442). **C is the whole-file collider → C is LAST on main.rs.** A/A′ vs B are region-disjoint (memory ~:1732 vs selfcheck ~:1389, ~343 lines apart, textually mergeable) — but NOT independent: whichever of A′/B merges second must REBASE and re-run CI. Treat A′∥B as "concurrently authorable, serialized at merge with a mandatory rebase," not conflict-free.
- **SP#2 — `scripts/kani-shards.sh` + `crates/tb-encode/src/proofs.rs`.** `EXPECTED_HARNESSES_TOTAL` (=123 in-code, consistent with `proofs.rs`) + 3 shard lists + fail-closed count guard (lines ~303-311) counts the `#[kani::proof]` occurrences in `proofs.rs` too — so ANY track that adds even one harness collides here on BOTH files. A/A′ (+N harnesses) and E (+N) collide. B collides here ONLY IF B adds a harness; its `abi_snapshot` cross-check is a plain unit test, so B CAN avoid SP#2 — **this is a CONDITION B must honor (add zero Kani harnesses), not a property B inherently has.**
- **SP#3 — `crates/tb-hal/src/mem/{mod.rs,selftests.rs}` (the unfactored engine↔organ).** A edits recall/scoring, A′ adds the corpus seam, C's compile-out REQUIRES the factorization first, and the extraction resident-cut is blocked on the same seam.
- **SP#4 — the M38 conduct head `0x066855300c57557b` (`kernel` conductor input).** The head's byte-value is a real regression BASELINE (anchored `boot-profiles.md:3`, `M32-local-infer.md:268`), enforced by the CI **empty-byte-diff baseline comparison** (a changed-but-self-consistent head must NOT drift the baseline). The `run-x86_64.sh:769-807` cross-process guard is a FORMAT-regex + host-recompute==guest **stub-resistance** check — it does NOT fire on a self-consistent value change, so it is NOT the head-value pin. Because the guarded `conduct:` line (`run-x86_64.sh:765`) carries `m31_recalls` and `retrieval=LEXICAL-NOT-SEMANTIC`, **recall output IS conductor input**: A (rewrites recall scoring, `mem/mod.rs:1339`) and A′ (wires curation/emit into `consolidation_cycle`, `:1794`) can each shift the head. This is a **MUST-VERIFY gate for A and A′, not an asserted invariant** — each MUST re-confirm the byte-identical head against the baseline as a landing step. `token=m38-head=MUST-REVERIFY-AFTER-A/A′-NOT-ASSERTED-INVARIANT`.

- **SP#5 — `docs/ROADMAP-V2.md` (single 452-line file).** A three-way textual collision if A′, D, and F all edit it. **Resolved by single-ownership: F OWNS `ROADMAP-V2.md`.** D writes ONLY its new proposal file (its roadmap entry is handed to F, not appended by D). A′ does NOT touch `ROADMAP-V2.md` — its M39 milestone row is folded into F's reconciliation (or a follow-up). The old "{D,F} parallel-safe, separate doc files" verdict was FALSE for this file and is corrected here. `token=roadmap-v2=SINGLE-OWNER-F`.

| # | Track | What | Ungated? | Effort | Files it touches | PARALLEL-SAFE with | Must SERIALIZE with |
|---|---|---|---|---|---|---|---|
| **A′** | **Phase-1 EXPERIENCE CORPUS (flagship)** | New `corpus.rs` verified codec (reuse M22 fold) + in-kernel `corpus_head`/`corpus_append` + curation predicate wired into `consolidation_cycle` + durable signed corpus region (reuse M33 `provhead.rs`) + two-boot witness + host `tools/corpus-export/` + labeled-outcome/operator-turn channels + honest-status doc pass + **SP#4 conduct-head re-verify** | **UNGATED** | XL (spread over A′-codec L / A′-durable XL / A′-export M) | `tb-encode/src/corpus.rs` (NEW), `tb-encode/src/lib.rs`, `tb-encode/src/proofs.rs` (SP#2), `tb-encode/src/provhead.rs`, `mem/mod.rs` + `mem/selftests.rs` (SP#3), `tb-hal/src/lib.rs` (`CorpusProof`), `main.rs` (SP#1, ~:1732 marker; SP#4 head re-verify), `kani-shards.sh` (SP#2), `run-{x86_64,aarch64,vmm}.sh`, `tools/corpus-export/` (NEW), docs (M39 proposal + corpus-spec + cog-arch §2.2 — **NOT ROADMAP-V2.md**, whose M39 row is handed to F) | **D, F** (docs, now that A′ does not touch ROADMAP-V2.md); **B** (ONLY if B honors zero-Kani AND with the SP#1 merge-rebase note) | **E** (SP#2 lockstep — fold E into A′'s PR or run E after); **mem-factorization** (coordinate the `mem/` edits, SP#3); **C** (C serializes after); **SP#4** (re-verify head as a landing step) |
| **B** | **Yuva-ABI stage B slice** | version-DISCOVERY hardening + offer/accept negotiation SPEC on the landed `abi.rs` frozen registry; brand wire-magic unification (incl. standalone `ATTEST_MAGIC=0x5959`); `caps.rs` required_right pins; an `abi:` witness line + `M_OBJECT_INSPECT=0` version report in main.rs OUTSIDE the cumulative grep | **UNGATED** (the runtime version GATE itself is deferred — needs the offer/accept/reject mechanism) | L | `tb-encode/src/abi.rs`, `crates/brand/src/lib.rs`, `caps.rs`, `main.rs` (SP#1, ~:1389 selfcheck + witness), `tb-encode/src/lib.rs`, `scripts/run-abi-conformance.sh` (own lane) | **A′** (region-disjoint main.rs, **with mandatory second-merger rebase**), **D, F** | **CONDITION: B MUST add zero Kani harnesses** — else it hard-collides with A′/A/E on `kani-shards.sh` + `proofs.rs` (SP#2). Trivial `tb-encode/lib.rs` mod-list vs A′; shares the `mem/` blocker only for the deferred resident bind |
| **D** | **Model-pipeline DESIGN doc** (Phase-2) | `docs/proposals/model-path-phase2.md` (corpus→QLoRA→merge→GGUF-convert/quantize→goldens-measure→pin→daemon) + capability-ceiling + B3-distinction section; respects tinygrad-DEFERRED, Namzu-DEFERRED | **UNGATED** (design only; the fine-tune EXECUTION is BRAIN-gated) | M | `docs/proposals/model-path-phase2.md` (NEW) **only** — its ROADMAP entry is handed to F, D does NOT edit `ROADMAP-V2.md` | **EVERYTHING** (single new doc file) | **ROADMAP-V2.md is F's** — do NOT append |
| **F** | **Docs reconciliation (owns ROADMAP-V2.md)** | update `ROADMAP-V2.md` §6 / MILESTONES / BACKLOG for landed boot-profiles-A, Yuva-ABI-A, agent-terminology, extraction plan; ingest A′'s M39 row + D's model-path row; fix the 122-vs-123 **prose-doc lag** (see note) | **UNGATED** | S | `docs/**` incl. **sole owner of `ROADMAP-V2.md`** (SP#5), MILESTONES, BACKLOG — different files than D's proposal | **EVERYTHING** (docs; sole ROADMAP-V2.md owner removes the three-way collision) | none |
| **A** | **Research-skill LEXICAL recall leaf** | a tb-encode pure/no-float/Kani-proven LEXICAL (BM25+ IDF) recall-scoring leaf + tb-hal `mem/` seam + a new gated boot self-test marker (`M3x: retrieve OK`), following the M21/M22 leaf+seam+deterministic-marker pattern; explicitly lexical-only (semantic/embedding needs a no-float fixed-point encoder that does not exist — out of scope); **SP#4 conduct-head re-verify** | **UNGATED** | L | `tb-encode` leaf (NEW) + `lib.rs` + `proofs.rs` (SP#2), `mem/mod.rs` (SP#3, recall/scoring), `main.rs` (SP#1, gated block ~:1732; SP#4 head re-verify), `kani-shards.sh` (SP#2), `run-{x86_64,aarch64}.sh` | **D, F**; **B** (region-partition main.rs + B zero-Kani) | **E** + **A′** (SP#2 + SP#3 — coordinate/merge the `mem/` and shard edits); **C** after; **SP#4** (re-verify head — recall scoring IS conductor input) |
| **E** | **Hardening / verification** | author Kani harnesses for A/A′'s new leaves + coverage gaps; update `kani-shards.sh` (`EXPECTED_HARNESSES_TOTAL` + one shard list) + `proofs.rs` in lockstep | **UNGATED** | M | `kani-shards.sh` (SP#2, line 75 + shard arrays), `proofs.rs` (SP#2) | **D, F** | **HARD-SERIALIZES with A and A′** on SP#2 (`kani-shards.sh` + `proofs.rs`) — RECOMMEND folding E into A/A′'s PR, or run E strictly AFTER they merge. Never two concurrent PRs bumping the pin |
| **mem-fx** | **`mem/` engine↔organ FACTORIZATION** | split `mem/mod.rs` (2k+) + `selftests.rs` (2.3k) into the M20 storage ENGINE (`BackingStore`/`VirtioBlkStore`/`RamStore`) vs the M13 memory ORGAN (`MemSubstrate`/recall/tiers/KAN); record the M20-round-trip-does-not-exercise-organ audit finding | **UNGATED** | L | `mem/mod.rs` + `mem/selftests.rs` (SP#3, the whole file) | **D, F** | **THE pivotal shared blocker** — sequence AFTER A/A′ land their recall/corpus work OR merge with them to avoid a three-way `mem/` conflict; hard prerequisite of **C** and of the extraction resident cut |
| **C** | **boot-profiles stage B (compile-out)** | convert the ~18 `if profile::agent_organs_enabled()` runtime branches (:1732–:5442) into `#[cfg(feature="agent-organs")]`; Cargo feature wiring; build the substrate `--no-default-features` image; add image-size + symbol-absence check to `run-substrate-x86_64.sh` (the only rung that earns "not present"/tcb-delta=MEASURED-BYTES) | **GATED** (blocked by **mem-fx** — cannot `#[cfg]`-out an organ welded to the kept engine) | XL | `main.rs` (SP#1, the WHOLE post-core body → C is LAST), Cargo feature wiring, `run-substrate-x86_64.sh` + `gen-witness-census.sh` + `witness-census.txt` (own lane, disjoint) | its own `run-substrate` lane is disjoint from A/B/D/E/F | **LAST on main.rs** (after A/A′/B); **after mem-fx** |

**Parallel-safe partition (the verdict, corrected):**
- `{D, F}` are parallel-safe with everything and each other **only because F is now the single owner of `ROADMAP-V2.md` and D restricts itself to its new proposal file** — the prior blanket "separate doc files" claim was false and is retracted.
- `A′ ∥ B` is **concurrently authorable, serialized at merge**: safe IF (i) B honors the zero-Kani CONDITION, (ii) they partition `main.rs` (:1389 vs :1732), and (iii) the second PR to land REBASES and re-runs CI; the trivial `tb-encode/lib.rs` mod-list + `proofs.rs` append conflicts resolve on that rebase.
- `A` and `A′` both touch `mem/` (SP#3) and SP#2 — **merge or serialize them.**
- `E` folds into A/A′ (SP#2).
- `mem-fx` is the dedicated serialized pivot.
- `C` and `mem-fx` serialize after the corpus/recall work; `C` is LAST on main.rs.
- **SP#4:** A and A′ each re-verify the M38 conduct head against the byte-diff baseline as a landing step — not assumed.

`token=partition=DOCS-PARALLEL-IFF-F-OWNS-ROADMAP/A′∥B-CONCURRENT-BUT-MERGE-SERIALIZED/MEM-SERIALIZED/C-LAST/HEAD-REVERIFIED`.

**Note on 122-vs-123:** the in-code pins are already CONSISTENT (`proofs.rs` count == `EXPECTED_HARNESSES_TOTAL=123`). Only PROSE docs lag at "122." This is a **doc-only reconciliation (F), NOT a code pin-drift**, and it touches no parallelism surface. `token=122-vs-123=PROSE-DOC-LAG-NOT-CODE-DRIFT`.

---

## 4. The gates — operator decision points, NOT autonomously built

Three gates need the operator. The house discipline is **anti-hollow**: do NOT autonomously build unexercised/unvalidatable code. Each gate is surfaced here as a decision the operator makes, with what unblocks it.

### 4.1 HARDWARE gate — the x86 L2.x bare-metal Type-1 sovereignty track

The x86 L2.x bare-metal Type-1 track (L2.3+ / UEFI Type-1 / IOMMU / split-VMM) needs a **self-hosted `kvm_intel` nested=1 runner + real hardware**. The aarch64 L2.0-L2.6 already landed under TCG. **Building unvalidatable x86 L2 code is anti-hollow and is DECLINED.** `token=hardware-gate=NEEDS-OPERATOR-NESTED-VMX-RUNNER`, `token=x86-L2=DECLINED-UNTIL-VALIDATABLE`.

### 4.2 BRAIN gate — the actual model fine-tune / deep-learning execution

Needs the operator's **go + a corpus**. The gated items: the QLoRA fine-tune run (~weeks, ~$100-2000, GPU/spend); open ≥7B base-model selection + acquisition (license/storage; must clear the ~7B competence floor); GGUF conversion + quantization of the FINE-TUNED weights; the **golden-measure run** + pinning of the produced model; corpus reaching fine-tune-sufficient size; corpus→preference-pairs/DPO from sustained REAL operator-transcript volume (not synthetic). **No model training happens now.** The Phase-1 corpus build (§2.2) is the prerequisite this gate waits on. `token=brain-gate=NEEDS-OPERATOR-GO+CORPUS+SPEND`.

Note that **KAN activation** (§2.4) is a *separate* gated decision on the M24 margin — it is not the brain gate and not a substitute for the fine-tune.

### 4.3 EXTRACTION gate — the cross-repo move to `cogitave/cogi`

The physical `git filter-repo` move of the agent's portable host-side core (`tools/conductor-host`, `infer-daemon`, `xport-core`, `xport-harness`) to `cogitave/cogi` is the **operator's cross-repo action** (plan #67 / `extraction-plan.md` exists but is PLAN-NOT-EXECUTED). The resident in-kernel agent stays (blocked by the EL0 trap gate UNBUILT + the `mem/` factorization); the host export tool `tools/corpus-export/` is a candidate to dual-home then cut. `token=extraction-gate=OPERATORS-CROSS-REPO-ACTION`, `token=resident-agent=STAYS`.

---

## 5. The immediate next tasks — what to launch NOW, in parallel

Start these **today**, in parallel — all ungated, all mutually parallel-safe under the corrected §3 partition (F owns `ROADMAP-V2.md`; D writes only its new file; A′ hands its M39 row to F; the conduct head is re-verified on land).

**Launch (2-3 tracks, one optional):**

1. **A′ — Phase-1 experience corpus (the flagship).**
   - *Scope (first increment):* (i) the research-first proposal `docs/proposals/M39-experience-corpus.md` + the FROZEN `docs/spec/corpus-format-v1.md` (adversarial review per the tabos-milestone discipline — the schema MUST freeze before any codec); then (ii) the verified `crates/tb-encode/src/corpus.rs` codec leaf reusing the M22 prov fold verbatim + its Kani harnesses.
   - *Files:* `docs/proposals/M39-experience-corpus.md` (NEW), `docs/spec/corpus-format-v1.md` (NEW), `crates/tb-encode/src/corpus.rs` (NEW), `tb-encode/src/lib.rs`, `tb-encode/src/proofs.rs`, `kani-shards.sh`. **Does NOT touch `ROADMAP-V2.md`** (M39 row → F). **Fold its Kani harnesses (Track E) into this same PR** (SP#2 lockstep). Re-verify the M38 head only once the emit reaches `consolidation_cycle` (later increment).
   - *Effort:* M (proposal) → L (codec).

2. **D — the Phase-2 model-pipeline design doc.**
   - *Scope:* `docs/proposals/model-path-phase2.md` — corpus→QLoRA→merge→GGUF-convert/quantize→**goldens-measure-run**→pin→daemon; honest capability-ceiling + B3-distinction; a NEW-MODEL DROP-IN RUNBOOK that exercises the `pins.rs` measure-mode path on a real non-toy small GGUF to PROVE the load path is cheap/known (and that the measure-run is the one real step).
   - *Files:* `docs/proposals/model-path-phase2.md` (NEW) **only** — its roadmap row is handed to F, D does NOT edit `ROADMAP-V2.md`.
   - *Effort:* M.

3. **F — docs reconciliation (sole `ROADMAP-V2.md` owner).**
   - *Scope:* fix the 122-vs-123 **prose-doc lag**; update `ROADMAP-V2.md` §6 / MILESTONES / BACKLOG for the three landed stage-A milestones; ingest A′'s M39 row and D's model-path row.
   - *Files:* `docs/ROADMAP-V2.md` (SOLE owner), MILESTONES, BACKLOG — separate files from D's proposal.
   - *Effort:* S.

**Optional 4th (only with a second code stream):**

4. **B — Yuva-ABI stage B slice**, taking the **zero-Kani CONDITION** (the `abi_snapshot` cross-check is a unit test, so B adds NO harness and stays off SP#2) and living at the `main.rs` ~:1389 selfcheck region, region-disjoint from A′'s ~:1732 block. Start concurrently ONLY IF you can guarantee (a) B adds zero Kani harnesses, (b) the main.rs partition holds, and (c) whichever of A′/B merges second REBASES + re-runs CI. Effort L.

**Deliberately NOT launched now:** Track A (lexical recall leaf) collides with A′ on both `mem/` (SP#3) and the shards (SP#2) — sequence it after or merge into A′'s `mem/` work. **mem-fx** is the dedicated serialized pivot — after A′ lands its corpus seam (or merge). **C** is LAST on main.rs and gated on mem-fx. `token=launch-now=A′+D+F(+B-if-second-stream-AND-zero-Kani)`.

---

## 6. Honest scope — the named deferrals and the non-overclaims

Stated with the razor the architecture doc demands (`cogi-cognitive-architecture.md §2.2` — never conflate "built a dataset moat" with "activated continual learning" or "trained a model"):

- **Cogi's own model is Phase-2-OPEN-capability, not Phase-1, and is at the competence floor, NOT frontier.** Phase 1 (now, ungated) builds the CORPUS — a prerequisite. Phase 2 (later, BRAIN-gated) fine-tunes an open ≥7B base — sovereign, provider-independent, persona/memory-grounded, at the ~7B competence floor; the base/framework/method are open operator choices at the gate. The M31 bridge stays the escalation path. Yuva built the SLOT and the GATE, not the occupant's competence. `token=model=PHASE-2-OPEN-CAPABILITY-NOT-FRONTIER`.
- **Learning is dormant: memory now, adaptation later — and Phase 1 does not change that.** The corpus is the Phase-1 PREREQUISITE (data-engineering), ORTHOGONAL to KAN, and does NOT flip the pillar out of dormancy. KAN is a frozen integer retention POLICY (not neural learning, not model-training); its dormancy is both principled (M24 gate-not-met) and structural (no-gradient substrate). The corpus does not touch `KAN_ACTIVE`. `token=learning=MEMORY-NOW/ADAPTATION-LATER/CORPUS-IS-PREREQUISITE`.
- **tinygrad DEFERRED** — the model path is pragmatic (llama.cpp/GGUF inference — plumbing already built, golden-measure-run still required — + PyTorch/Unsloth-or-axolotl QLoRA). tinygrad is a possible LATER sovereign-compute stack, not now. `token=tinygrad=DEFERRED`.
- **Namzu DEFERRED** — Cogi's future ACTION/skills layer (Cogi = Namzu persona/skills + Yuva behind Namzu's MemoryStore interface, no bridge). A FUTURE composition step; the substrate does not need Namzu yet. `token=namzu=DEFERRED`.
- **Semantic/embedding retrieval on-substrate + live web egress** — structurally excluded (no-float discipline; zero-network CI posture). The research-skill recall is LEXICAL-only. `token=semantic-retrieval=STRUCTURALLY-EXCLUDED`.
- **Sovereignty-of-the-WEIGHTS (Phase 2) ≠ sovereignty-of-the-ENGINE (B3 pure-Rust).** A fine-tune gives weight-sovereignty; it does NOT retire the vendored-C-llama.cpp engine debt. `token=B3-engine-debt=UNCHANGED-BY-FINETUNE`.
- **The M38 conduct head is a re-verified baseline, not an assumed invariant.** Its byte-value is pinned by the CI empty-byte-diff baseline; the `run-x86_64.sh:769-807` guard is stub-resistance (host==guest recompute), NOT the value pin. Memory-touching tracks (A, A′) MUST re-confirm it on land because recall output feeds conductor input. `token=m38-head=BASELINE-REVERIFIED-NOT-ASSUMED`.
- **Serving a new model needs a golden-measure run.** The load plumbing exists, but a produced model must be RUN to measure its goldens before the daemon can pin+serve it — not a literal three-line drop-in. `token=phase2-load=PLUMBING-BUILT-BUT-REQUIRES-GOLDEN-MEASURE-RUN`.
- **Every witness carries honesty tokens.** A mock is a mock (M30/M31 backend), dormant is standby (KAN, M32-B stand-in), a stand-in is a stand-in, a provenance skeleton is not text (the kernel corpus is u64 tokens; text is agent-dict-join-host-side). Never overclaim. `token=honesty=NEVER-OVERCLAIM`.

---

## 7. Adversarial review

This section records the two-reviewer adversarial pass and how each item was resolved in this document. Both reviews returned **SOUND-WITH-AMENDMENTS**; every `must_fix` is applied and every `overclaim` neutralized with an honest token.

**Applied must-fixes:**

1. **`ROADMAP-V2.md` three-way collision (was falsely called disjoint).** A′, D, and F all edited the same 452-line file while being launched concurrently. **Resolved:** F is now the SOLE owner of `ROADMAP-V2.md` (new SP#5). D writes only its new proposal file; A′'s M39 row is handed to F; the blanket "{D,F} separate doc files, parallel-safe" verdict is retracted and re-derived conditionally. Reflected in §3 (SP#5, table rows A′/D/F, partition verdict) and §5.
2. **M38 conduct head downgraded from asserted invariant to a MUST-VERIFY gate.** Because recall output (`retrieval=LEXICAL-NOT-SEMANTIC`, `m31_recalls`) feeds the conductor input, A (recall scoring, `mem/mod.rs:1339`) and A′ (emit into `consolidation_cycle`, `:1794`) can each shift the head. **Resolved:** new SP#4; A/A′ carry an explicit "re-confirm byte-identical head" landing step; token changed to `MUST-REVERIFY-...-NOT-ASSERTED-INVARIANT`.
3. **Fixed the conduct-head ENFORCEMENT citation.** The value is NOT pinned by the `run-x86_64.sh:769-807` cross-process guard (that is a FORMAT-regex + host-recompute==guest STUB-RESISTANCE check that would not fire on a self-consistent value change); it is pinned by the CI **empty-byte-diff baseline comparison**. Corrected in SP#4, §1 (M38 row now says "regression baseline"), and §6.
4. **Reframed the corpus as a Learning-pillar PREREQUISITE, not an advance.** §2.2 no longer calls the corpus "the REAL Learning-pillar advance"; it is data-engineering that stocks the Phase-2 dataset, and the pillar STAYS DORMANT through Phase 1. Reflected in the header pillar line, the one-liner, §2.2, §2.4, and §6.

**Neutralized overclaims (each now carries an honest token):**

- **B's "zero-Kani path avoids SP#2" is a CONDITION, not a property.** The `kani-shards.sh` guard counts `proofs.rs` `#[kani::proof]` occurrences, so one harness from B hard-collides on both files. Marked as an explicit CONDITION B must honor in SP#2 and the B row. `token=B-zero-kani=CONDITION-NOT-PROPERTY`.
- **"A′ ∥ B region-disjoint main.rs" is textually mergeable but not independent.** The second PR to land must REBASE and re-run CI; A′∥B is now "concurrently authorable, serialized at merge." Noted in SP#1, the A′/B rows, §5.
- **The "three-line drop-in" model-load headline was internally inconsistent** with the plan's own DoD-4 golden-measure step. Corrected to a golden-measure-run requirement in §2.3, §4.2, §5, §6.
- **The 122-vs-123 "pin-drift" is doc-only, not a code drift.** In-code pins are consistent (`proofs.rs` == `EXPECTED_HARNESSES_TOTAL=123`); only prose docs lag. Reclassified as an F-owned prose reconciliation touching no parallelism surface. `token=122-vs-123=PROSE-DOC-LAG-NOT-CODE-DRIFT`.

`token=adversarial-review=BOTH-SOUND-WITH-AMENDMENTS/ALL-MUST-FIX-APPLIED/ALL-OVERCLAIMS-TOKENIZED`.

---

## 8. References

**Code (in-repo, `origin/main` `49fd035`):**

- `crates/tb-hal/src/mem/mod.rs:766,787,862` — memory content is u64 INTERNED TOKENS (`content_tok`/`token`/`body_tok`), NOT text — the load-bearing honest constraint (corpus = provenance skeleton; text is agent-side).
- `crates/tb-hal/src/mem/mod.rs:273,284` — `KAN_ACTIVE=false` dormant master gate + `KAN_TABLE` frozen integer additive-policy spline LUT (a const, not trainable weights).
- `crates/tb-hal/src/mem/mod.rs:920-939,930,935,1094` — the M23 SEPARATE-head + fixed-cap drop-oldest ring (`XP_CAP`=64, IN-RAM sliding window, NOT a growing corpus) + `xp_record` template; "durable spill is M24" = the unbuilt gap.
- `crates/tb-hal/src/mem/mod.rs:1339` (recall), `:368/:463/:583` (`BackingStore`/`VirtioBlkStore` engine), `:887` (`MemSubstrate` organ) — engine↔organ cohabit one unfactored file = the pivotal shared blocker; recall output feeds the M38 conductor input (SP#4).
- `crates/tb-hal/src/mem/mod.rs:1513,1560,1593,1611,1768,1794` — M17 consolidation manufactures the curated examples: `distill()` survivors (provenance=2), `reflect_inner()` insights (provenance=1, cites-linked), forget tombstones, `consolidation_cycle` — the corpus emit points (and the SP#4 head-shift risk site).
- `crates/tb-encode/src/prov.rs:46,99-113` — the M22 BLAKE2s-256 fold + `ProvEntry` canonical hash-chain, reused verbatim by `corpus_head` (no new fold math).
- `crates/tb-encode/src/exp.rs:1-40,32-40,66-70,116,232` — M23 `ExperienceRecord` is (features→decision→outcome) SCHEDULING tuples for the dormant kancell (NOT a language corpus); the schema-stability lemma; the prov-fold re-import discipline; the reserved `OutcomeLabel`; `EXP_CANON_LEN`.
- `crates/tb-encode/src/blkfmt.rs:246,278` — `superblock_encode/decode` + episode codec over the YUVAMEM0 durable image — the host-readable leaf a corpus exporter reuses (no new codec).
- `crates/tb-hal/src/mem/selftests.rs:2360,2424,2452-2489` — the M33 durable persistence seam (`M33_BASE=8192`, `m33_persist_head`, torn-write-safe ping-pong slab I/O, `survived` flag) — the reboot-surviving-signed-head machinery the growing-corpus track reuses.
- `tools/infer-daemon/llama-engine-sys/src/lib.rs:89-120` + `build.rs:22-29,44-67` — the GGUF→tokens inference path EXISTS end-to-end (vendored llama.cpp b9756, deterministic single-thread CPU envelope, SHA256-verified, static-linked).
- `tools/infer-daemon/src/pins.rs:7-40` + `engine.rs:45-58,210,290` + `models/stories260K.gguf` — `ModelPin` registry; `verify_artifact`/`measure_model`/the `@@` measure-mode branch = the Phase-2 drop-in path — including the golden-MEASURE-run that a new model requires before pinning; a real in-repo GGUF served today.
- `kernel/src/profile.rs:38` (`agent_organs_enabled`) + `main.rs` gate hits `:1732,:2644,…,:5442` — the ~18 runtime gate blocks Track C must convert; proves C touches the whole post-core body.
- `scripts/kani-shards.sh:75` (`EXPECTED_HARNESSES_TOTAL=123`) + `:285` `shards_assert_complete` + `~:303-311` fail-closed count guard over `proofs.rs` `#[kani::proof]` — the one-touch lockstep (SP#2); the 123-vs-122 lag is PROSE-DOC only, code is consistent.
- `scripts/run-x86_64.sh:37,765,769-807` — the M38 cumulative tail + the `conduct:` line carrying recall-derived input + the cross-process host==guest STUB-RESISTANCE guard (NOT the head-value pin; the byte-value is pinned by the CI empty-byte-diff baseline).

**Docs:**

- `docs/proposals/boot-profiles.md` §2.3/§3.4/§8.4 + `:3` (conduct-head anchor) — boot-profiles stage A LANDED; stage B = compile-out gated on the `mem/` factorization; stage A added zero harnesses. (House style reference.)
- `docs/proposals/extraction-plan.md` §2.1/§2.3/§3.9/§5-R2/§9 — the movable surface, the resident-cut blockers (EL0 gate UNBUILT, `mem/` UNFACTORED), the DoD-5 boot-against-pinned-image lane. (House style reference.)
- `docs/proposals/yuva-abi.md` §3.2/§7.3/§2.5 — `abi.rs` frozen-literal registry + `abi_snapshot` UNIT test (Track B's zero-Kani CONDITION) + the shared `mem/` blocker.
- `docs/spec/yuva-abi-v1.md` — the normative frozen ABI contract, source of truth for `YUVA_ABI_VERSION`.
- `docs/proposals/M32-local-infer.md:3,25,34,41,268` — M32 stage A daemon lane LANDED; stage B kernel receive seam (#90); the tools/infer-daemon + CPU-only zero-secret adjudicated-lane pattern the corpus-export tool copies; confirms the pragmatic llama.cpp/GGUF path (no tinygrad); `:268` = the "M38 fold head UNCHANGED" baseline anchor.
- `docs/proposals/M33-prov-lineage.md` — the durable signed-head reboot-surviving machinery the growing-corpus track reuses.
- `docs/proposals/M21-kan-policy.md:21,61` — "Nothing is learnable in-kernel"; knots fit offline in float, quantized to a frozen i16 y-table — direct evidence KAN is NOT neural learning / model-training.
- `docs/research/cogi-cognitive-architecture.md:39,47,82-90,94-96` (§1.2b/§1.3/§2.2/§2.3/§3.1/§3.2) — the ~7B competence floor; "Yuva built the SLOT and the GATE, not the occupant's competence"; the two-true-descriptions of KAN dormancy (principled + structural); the BUILDABLE-NOW lexical research-skill scope; M32=default organ / M31=escalation; the never-conflate-moat-with-learning razor.
- `docs/ROADMAP-V2.md` (F's SOLE ownership), `docs/BACKLOG.md`, MILESTONES — the milestone/backlog reconciliation targets (Track F).

*— END FORWARD PLAN —*