# M29 stage C — the `prov_hash` → `khash::uhash` cutover: landing plan (#99)

**Status:** plan (ready to build after M30 A+B lands). **Pillar:** memory (the #74 provenance-hash first half). **Depends on:** M29 stages A+B (LANDED — `tb-encode::khash` leaf + the M28 MAC cutover), M22 fold, the M30 inferwire harness additions (in flight in PARALLEL — see §6 lockstep). **Closes:** the #74 hash half + the M22 `NOT cryptographic` structural-digest concession. **Companion docs:** [`docs/proposals/M29-crypto-mac.md`](../proposals/M29-crypto-mac.md) §4/§5(C)/§6.3 (the protocol + the split-out decision), [`m29-stage-c-kani-budget-plan.md`](m29-stage-c-kani-budget-plan.md) (study 2 — the option analysis this plan adopts).

> **One-line:** the cutover itself is ONE function body — `prov.rs` `lane()`+`prov_hash` (~176–222) becomes `khash::uhash`; `chain_mix`/`recompute`/`verify_inclusion`/`append`/`head_witness`/`canon` stay byte-for-byte and every consumer (M23 exp, M25 opframe, M26 exittel, M27 tpsched, M28 `cmd_hash`) inherits through the existing re-export aliases with ZERO per-consumer edits. What does NOT fit as-is is the PROOF BILL: the PR #27 scratch swap MEASURED the naive cutover at ≈ +35 min on the prove-encode lane (45-min cap), so this plan lands the swap TOGETHER with six fold-harness body restructurings (budget-plan option 1) — same harness NAMES, same pinned count, every negative control kept or strengthened, ONE explicitly documented concession (§3.6).

---

## 1. Scope — what changes, what is frozen

- **Changes:** the `prov_hash` body (4-lane FNV-1a-64 → `khash::uhash`, BLAKE2s-256 unkeyed) + the `lane()` helper it orphans; six harness bodies in `proofs.rs` (§3); honesty text (the `prov.rs` "NOT cryptographic" block + the mirrored notes in `exp.rs`/`exittel.rs`/`tpsched.rs`, the `verify-encode.sh` doc block, the `kani.yml` comment — M29 §5 stage C fan-out list).
- **Frozen:** every signature, every wire format/offset, `PROV_HASH_LEN=32`, the `MIX_DOMAIN`-prefixed 65-byte `chain_mix` buffer (prov.rs:236), all re-export seams, the boot fold call sites, and the `EXPECTED_HARNESSES` pin (stage C adds/removes ZERO harnesses — §6).
- **Out of scope (named successors):** the #74 signed root (a signature primitive, not a hash), #75 Merkle inclusion proofs (khash is the enabler, not the delivery), M33 (sequenced AFTER this lands).
- The `fnv1a64` leaf itself is NOT deleted blind — it has non-prov consumers; the landing checklist audits before removing anything (§7).

## 2. The proof bill — per-harness compression table (the measured cost model)

One CONCRETE BLAKE2s compression ≈ **9 s** under CBMC. `uhash`: ≤64 B = 1 compression, 65 B = 2; `chain_mix` = `uhash` over 65 B = **2 compressions per fold step**; `recompute(leaf,[sib])` = 4. The model reproduces all three PR #27 measurements (36 s exact; 185 s vs 162 model, +14% symbolic-index overhead; 267 s vs 252, +6%) — projections below carry a **±15% overhead band**.

| # | harness | property / NEG control | comps (naive) | FNV-era | naive khash | restructured comps | restructured proj. |
|---|---|---|---:|---:|---:|---:|---:|
| 1 | `kani_prov_hash_total` | totality + determinism + 32 B width / checked-mul panics | 4 | 4 s (meas) | **36 s (meas)** | 4 (keep) | 36 s |
| 2 | `kani_prov_chain_mix_tamper` | fold non-degenerate at EVERY of 64 head/entry byte positions / identity-constant fold | 132 (66 calls, 2×32 concrete unroll) | 106 s (meas) | **~1 190 s ≈ 19.8 min (proj)** | **10** (§3.1) | **~90–180 s** |
| 3 | `kani_prov_inclusion_sound` | verify ⇔ recompute==head iff + leaf/sib/head tamper reject / sibling-ignoring verifier | 28 | 18 s (meas) | **267 s (meas)** | **16** (§3.2) | **~145–165 s** |
| 4 | `kani_prov_head_deterministic` | same-sequence determinism + 2-entry order-sensitivity / commutative XOR fold | 12 | ~7 s (est) | ~108–120 s (proj) | **8** (§3.3) | **~72–85 s** |
| 5 | `kani_exp_fold_tamper` (M23) | symbolic-flip over 49 canon bytes → leaf + head + inclusion all change / constant hash | 18 | 29 s (meas) | **185 s (meas)** | 18 (**KEEP FULL**, §3.4) | 185 s |
| 6 | `kani_opframe_fold_truncation` (M25) | flip over 61 canon bytes changes op_head; `gate_commits_final_seq` (hash-free) / constant hash, length-ignoring gate | 18 | ~25 s (est) | ~162–190 s (proj) | **2–3** (§3.5) | **~25–40 s** |
| 7 | `kani_exittel_fold_tamper` (M26) | flip over 21 canon bytes changes tel_head / constant hash | 18 | ~25 s (est) | ~162–190 s (proj) | **2–3** (§3.5) | **~25–40 s** |
| 8 | `kani_tpsched_fold_tamper` (M27) | flip over 21 canon bytes changes sched_head / constant hash | 18 | ~25 s (est) | ~162–190 s (proj) | **2–3** (§3.5) | **~25–40 s** |
| 9 | `kani_bakeoff_replay_determinism` (M24) | explore-coin keyed to immutable decision_id replays bit-exact / mutable-step-counter coin | 4 (2 `chain_mix`, proofs.rs:2441) | ~5 s (est) | ~36–41 s (proj) | 4 (keep) | ~36–41 s |
| | **affected-set totals** | | 254 | **~4.2 min** | **~39–41 min** | | **~11–14 min** |

Stage-C-IMMUNE (zero hash executions, untouched): `kani_prov_canon_injective`/`_roundtrip` (canon-only), `kani_opframe_intro_binding` (pure field compares), `kani_opframe_partition_leak` (fail-closes before the hash), the four hash-free cmd harnesses (placeholder MAC, hash-free `verify_decoded` by design). Already-khash stage A/B harnesses (`kani_khash_*` ×4, `kani_cmd_mac_tamper`, `kani_cmd_key_evolve`) are IN the current baseline and unchanged.

## 3. The restructurings (budget-plan option 1 — adopted; same names, same count)

1. **`kani_prov_chain_mix_tamper` — concrete unroll → symbolic flip index.** The 66-call 2×32 unroll was an FNV-era workaround (the #49 symbolic-65-byte-FNV blow-up, see the in-harness TRACTABILITY comment at proofs.rs:1709/1727). Under khash the precedent INVERTS: `kani_khash_tamper` already proves a one-bit flip at a SYMBOLIC index over all 65 message + 32 key bytes through the 2-block keyed hash, inside the current baseline. Rewrite khash-style over concrete head/entry: base (2) + determinism (2) + ONE symbolic-index entry-id flip (2) + ONE symbolic-index head flip (2) + **flip-back NEG (2)** = 10 compressions. Coverage IDENTICAL — all 64 positions, now by symbolic index; the flip-back negative control (flip-then-flip-back restores the base digest, proving the mutation reaches the hash) is a strict ADDITION. The identity/constant-fold NEG carries over unchanged. **Conceded: nothing.**
2. **`kani_prov_inclusion_sound` — drop the redundant recompute.** Today the iff re-evaluates `recompute(leaf,&sibs)` on both sides (proofs.rs:1780 + 1786). Compute `head = recompute(leaf,&sibs)` ONCE; assert `verify_inclusion(leaf,&sibs,any_head) == (head == any_head)` over the symbolic `any_head` — sound because `recompute` determinism is separately proven, and the symbolic `any_head` SUBSUMES both the genuine-accept (1790) and bad-head-reject (1807) legs, which are then dropped as redundant. Keep `bad_leaf` + `bad_sib` rejections verbatim (the sibling-ignoring-verifier NEG stays live). 28 → 16 compressions. **Conceded: nothing — the iff IS the property.**
3. **`kani_prov_head_deterministic` — trim the duplicate determinism recompute** (3 recomputes → 2 + one equality on the stored digest): 12 → 8 compressions. The 2-entry order-swap (the commutative-XOR-fold NEG) stays verbatim. If local measurement shows the trim is not needed, keep as-is at 12 (~108 s) — decide on the §7 measurement, not on the model. **Conceded: nothing.**
4. **`kani_exp_fold_tamper` — KEEP FULL (185 s, measured).** The ONE representative end-to-end witness: symbolic-flip canon byte → leaf re-hash → head mismatch → inclusion failure, through the REAL khash fold at full depth. This harness is what LICENSES §3.5's thinning — it is named in every thinned doc-comment.
5. **`kani_opframe_fold_truncation` / `kani_exittel_fold_tamper` / `kani_tpsched_fold_tamper` — thin to leaf-sensitivity.** Each keeps its symbolic-flip-index leg as `prov_hash(canon) != prov_hash(tampered)` (61/21/21 B buffers = 1 compression per call) and keeps its hash-free half (`gate_commits_final_seq` tail-truncation etc.) VERBATIM. The constant-hash NEG carries over (a constant hash makes the `!=` fail); add the flip-back NEG where cheap. ~18 → 2–3 compressions each. **This is the plan's one real concession — see §3.6.**
6. **The concession, explicitly tokened.** Post-thinning, each per-milestone harness machine-proves "a flipped canonical byte changes the LEAF id"; the chain-level rejection (head mismatch + inclusion failure) becomes a documented COMPOSITION of three separately machine-proven conjuncts — (leaf ≠ leaf′ [this harness]) ∧ (`chain_mix` tamper-sensitive at every byte [`kani_prov_chain_mix_tamper`]) ∧ (inclusion iff [`kani_prov_inclusion_sound`]) — demonstrated end-to-end by the kept `kani_exp_fold_tamper`. Each thinned doc-comment + the `verify-encode.sh` doc block carries the literal marker **`fold-claim=LEAF-SENSITIVITY+COMPOSED(chain_mix_tamper, inclusion_sound; e2e=exp_fold_tamper)`** so the narrowed per-harness claim is greppable and can never silently widen back in prose. No boot witness token changes — the composition is a proof-surface fact, not a runtime claim.
7. **`kani_prov_hash_total`, `kani_bakeoff_replay_determinism` — leave as-is** (36 s + ~40 s; the bakeoff's 2 `chain_mix` coin calls are load-bearing for replay determinism and not worth a special case).

Rejected alternatives (full analysis in the budget plan §3): concretized flip indexes (dominated — under khash, concretization IS the blow-up, and the surrendered positions are exactly the block-boundary/padding/t-counter bug class), a weekly deep-chain lane (zero `on: schedule` precedent in all 8 workflows; non-blocking; detects up to 7 days late; NO property needs chain depth >2), and the algebraic stub split (Kani has no uninterpreted-function surface; `-Z stubbing` is unstable and the witness mix has no machine link to khash — collapses into §3.6's composition with extra trusted surface).

## 4. Projected lane time (target ≤ ~42 of the 45-min cap)

**Restructured stage C delta ≈ +7–10 min** (affected set ~4.2 → ~11–14 min, §2 table) over the **21–29 min measured baseline**, plus the in-flight M30 inferwire additions (~5–6 concrete-input harnesses, unmeasured — assumed +1–3 min). **Projection: ~31–42 min**, against 56–70 min for the naive cutover. Assumptions, stated:

- **Single pass:** one `cargo kani -p tb-encode --output-format=terse` invocation (verify-encode.sh:238), harnesses solved serially, no retry loops; the projection is per-pass wall-clock.
- **Cache:** the lane is codegen-fronted and the #77 Kani build cache only covers unchanged-crate pushes — the band above assumes a **COLD cache** (the 21–29 min baseline spread already spans cold-vs-warm); a warm-cache pass lands at the low end.
- **Smoke legs excluded:** host `cargo test` KATs, Miri, clippy, and the both-arch boot smokes run in OTHER lanes and do not count against the 45-min prove-encode cap.
- **Calibration:** the 9 s/compression constant is local-WSL-calibrated and reproduced all three CI-measured stage-A/B/scratch numbers within the ±15% symbolic-overhead band; every rewritten harness is re-measured locally pre-push (§7) so the model never substitutes for a measurement.

**Pre-agreed escape hatch (budget plan option 4):** if a measured full pass exceeds **~38 min**, prepare the 2-way shard — two matrix jobs over a pinned harness split, per-shard `EXPECTED_HARNESSES_A/_B`, PLUS the mandatory fail-closed completeness guard `grep -c '#\[kani::proof\]' == A + B` (the M29 execution-enforced count-gate lesson: a harness assigned to neither shard must fail the gate, not silently skip). Do NOT shard pre-emptively — it duplicates codegen and doubles the lockstep surface.

## 5. Head migration — values change, nothing breaks (re-verify at landing)

Every fold head, leaf id, and derived challenge CHANGES VALUE at the cutover — and that is FREE, per the M29 §4 verification: heads/MACs/challenges are per-boot, in-RAM, recomputed on producer and verifier sides within one run; **M20 persists memory records, NOT prov heads**; CI builds fresh images; the run-script gates pin FORMAT only (`head=0x[0-9a-fA-F]+`, `challenge=0x[0-9a-fA-F]+`); host tests assert determinism/inequality, never digest literals. There is NO byte-identity baseline to preserve. **The claim was verified at proposal time and MUST be re-verified at landing** (M30 lands in between): re-grep both run scripts + the host test suite for any hex digest literal that could have crept in, before the first push. The `M2x:` markers and all witness-line SHAPES are untouched; only honesty prose changes (the `prov.rs` "NOT cryptographic" / "STRUCTURAL tamper-evidence" block and its mirrors become the stage-A claim boundary: `prim=BLAKE2S-256`, collision/preimage resistance ASSUMED-FROM-LITERATURE, never prose-claimed — the §9 overclaim rejects already enforce this).

## 6. Harness-count lockstep — coordinating with the parallel M30 bump

`EXPECTED_HARNESSES` (verify-encode.sh:232) is the execution-enforced pin; the M30 inferwire agent is bumping it **in parallel, right now** (84 → ~+5–6). Convention for this plan: **`N_base` = the live pinned value at branch time — always read the script, never this doc.** Rules:

1. **Stage C adds/removes ZERO harnesses** (six body rewrites under the SAME names) → this PR does **not** touch the pin. The count gate must pass at `N_base` unchanged before AND after the cutover commit — that invariance is itself a hollow-pass check (a rewrite that accidentally deleted or duplicated a `#[kani::proof]` fails the gate).
2. This plan branches **after M30 A+B lands** (the Status gate) and rebases over any further M30 bump; on a doc-block merge conflict, take M30's COUNT and stage C's TEXT (the two PRs edit disjoint claims in the same header comment).
3. All lane projections in §4 are expressed at the M30-inflated `N_base` — re-measure the baseline once post-rebase before trusting the §4 band.

## 7. Landing checklist (one CI-green PR; every box blocks merge)

1. **Rebase gate:** M30 A+B landed and green; record the live `N_base` and a fresh baseline lane measurement.
2. **The swap:** `prov.rs` `lane()`+`prov_hash` body → `khash::uhash`; audit `fnv1a64`'s remaining consumers before deleting `lane()` (keep the proven `fnv1a64` leaf if anything else uses it); `chain_mix`/`recompute`/`verify_inclusion` byte-identical.
3. **Six harness bodies** per §3, doc-comments rewritten with the preserved NEG controls + the §3.6 `fold-claim=` marker in the three thinned harnesses.
4. **Measure EVERY affected harness locally (WSL)** — `cargo kani -p tb-encode --harness <name>` — before push; record the numbers in the PR description. Mitigation ladder for any outlier (the M29 §6 discipline): pin a flip position concrete → `kani::solver(kissat)` → shrink → re-split the harness out.
5. **Mutation re-tests (anti-hollow-pass):** temporarily re-introduce each documented NEG-control bug — constant hash, identity/constant fold, sibling-ignoring verifier, length-ignoring gate, dropped flip-back — and confirm the owning harness FAILS, then revert. Every §2-table NEG must be demonstrated live against the NEW bodies, not inherited on faith.
6. **Doc/honesty fan-out** (M29 §5 stage C list): `prov.rs` honesty block + mirrors in `exp.rs`/`exittel.rs`/`tpsched.rs`/`opframe.rs`, `verify-encode.sh` doc block (text only — count untouched), `kani.yml` comment, `docs/ARCHITECTURE.md`, `docs/MILESTONES.md`, `docs/ROADMAP-V2.md`, M29 proposal status line (stage C → LANDED), this plan's Status flip, `docs/plans/INDEX.md`.
7. **Head-migration re-verification** per §5 (grep for digest literals in run scripts + host tests).
8. **Both-arch boots:** `CARGO_INCREMENTAL=0`, x86_64 + aarch64 run scripts green — all M22-family witness lines re-emitted with NEW head values under the SAME format-pinned guards.
9. **2× CI green:** the full pipeline twice (budget variance + flakiness); record both prove-encode wall-clocks. If either pass > ~38 min → open the option-4 shard follow-up before merging anything further into the lane.
10. **Count gate:** `SUCCEEDED == N_base` on both runs.

## 8. What this closes — and what stays open

**Closes:** the **#74 hash half** — the provenance chain's digest is now a real (assumed-secure, RFC 7693) cryptographic hash end to end, leaf and fold; and the **M22 structural-digest concession** — the "NOT cryptographic / STRUCTURAL tamper-evidence only" honesty block that M23/M25/M26/M27 all mirror retires, replaced by the M29 claim boundary (`prim=BLAKE2S-256`, `sec=ASSUMED-FROM-LITERATURE`). With stages A+B this completes the M29 three-stage plan.

**Stays open (named, not implied):** the **#74 signed-root half** (a signature primitive — a separate proposal); **#75 Merkle inclusion proofs** — OPTIONAL synergy, khash is ready as the node hash but nothing here delivers tree-shaped proofs; **M33 is sequenced AFTER this lands** (this plan is its predecessor in the lane-budget chain); and the standing M29 §9 concessions verbatim — collision/preimage/PRF resistance ASSUMED never proven, `sidechannel=NOT-CLAIMED`, `oracle=SIMULATED-ENROLLED-KEY`, `kan_active=0`, rotate-on-accept and real enrolment as successors.
