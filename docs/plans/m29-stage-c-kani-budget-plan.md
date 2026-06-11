# M29 Stage C (#99) — prove-encode budget plan for the `prov_hash` → `khash::uhash` cutover

**Status:** PLAN (study 2 — budget options). **Scope:** restructure the fold-harness
family so the one-function-body stage C swap (prov.rs `lane()`+`prov_hash` →
`khash::uhash`; `chain_mix`/`recompute`/`verify_inclusion`/`append`/`canon`
byte-identical; all consumers inherit via re-exports with zero edits) fits the
45-min prove-encode lane. **This doc changes no code.**

Symbolic count convention: `N_base` = the pinned `EXPECTED_HARNESSES` in
`scripts/verify-encode.sh` at branch time (84 at writing, ~90 once the parallel
M30 inferwire harnesses land — always read the live pinned value, never this
doc). Stage C adds ZERO harnesses (a body swap), so the count gate stays
`N_base`; only doc blocks and harness bodies change.

---

## 1. The cost model (measured, PR #27 scratch swap)

One CONCRETE BLAKE2s compression ≈ **9 s** under CBMC. `uhash`: ≤64 B input =
1 compression, 65 B = 2; `khash` adds +1 key block. `chain_mix` = `uhash` over
the 65-byte `MIX_DOMAIN|head|entry_id` buffer = **2 compressions per fold
step**; `recompute(leaf,[sib])` = 2 steps = 4 compressions.

Measured/projected deltas at the naive cutover (compression counts audited
against `proofs.rs` bodies — the model reproduces every measured number):

| harness | shape | comps | FNV-era | khash-era | delta |
|---|---|---:|---:|---:|---:|
| `kani_prov_hash_total` | 4 hashes | 4 | 4 s | **36 s (measured)** | +0.5 min |
| `kani_exp_fold_tamper` | 2 hashes + 4 recompute/verify | 18 | 29 s | **185 s (measured)** | +2.6 min |
| `kani_prov_inclusion_sound` | 7 recompute/verify | 28 | 18 s | **267 s (measured)** | +4.2 min |
| `kani_prov_chain_mix_tamper` | 66 concrete-unrolled `chain_mix` | 132 | 106 s | **~1190 s (projected)** | +18 min |
| `kani_prov_head_deterministic` | 3 recomputes | 12 | ~s | ~108 s | +1.7 min |
| `kani_opframe_fold_truncation` | 2 hashes (61 B) + 4 rec/verify | 18 | ~25 s | ~170 s | +2.4 min |
| `kani_exittel_fold_tamper` | 2 hashes (21 B) + 4 rec/verify | 18 | ~25 s | ~170 s | +2.4 min |
| `kani_tpsched_fold_tamper` | 2 hashes (21 B) + 4 rec/verify | 18 | ~25 s | ~170 s | +2.4 min |
| `kani_bakeoff_replay_determinism` | 2 `chain_mix` | 4 | ~s | ~36 s | +0.5 min |

**Naive cutover delta ≈ +35 min** on a ~21–29 min baseline → **56–64 min ≫ 45-min
cap.** Restructuring is mandatory, not optional. (`kani_opframe_intro_binding`
and `kani_prov_canon_roundtrip` contain no hash calls — unaffected.)

---

## 2. Minimal-chain analysis (what each property actually needs)

* **Tamper-at-symbolic-flip-index** (the exp/opframe/exittel/tpsched fold
  harnesses): the flipped byte must traverse **ONE `prov_hash`** —
  `prov_hash(bytes) != prov_hash(tampered)`. The downstream
  `recompute(bad)!=head` + `!verify_inclusion` lines are CORROBORATION whose
  truth already follows from (leaf≠leaf′) ∧ (`chain_mix` tamper-sensitive,
  proven separately) ∧ (inclusion iff, proven separately). Minimal chain
  length: **0 siblings** for the sensitivity claim itself.
* **Inclusion soundness**: needs **leaf + ≥1 sibling** so "siblings are
  load-bearing" is non-vacuous (a verifier ignoring siblings must fail).
  1 sibling = already the minimum; the current harness's cost is redundant
  recomputation, not chain depth.
* **Order-sensitivity**: needs exactly **2 entries swapped** — already the
  current shape.
* **One-step fold non-degeneracy** (`chain_mix_tamper`): needs **one fold
  step** with the flip reaching every one of the 64 head/entry byte positions.
  Depth >1 adds nothing to any stated property. **No harness needs a chain
  deeper than 2 — depth is corroborative only.** That fact drives every
  option's evaluation below.

---

## 3. The options

### Option 1 — SHRINK the fold harnesses (minimal chains + symbolic index over one-block buffers) — **ADOPT**

Six body rewrites, same harness NAMES, same count `N_base`, every negative
control kept or strengthened:

1. **`kani_prov_chain_mix_tamper`** — the 66-call concrete unroll exists
   because a symbolic flip index over a symbolic-data **FNV** fold was the #49
   blow-up. Under khash the precedent inverts: `kani_khash_tamper` ALREADY
   proves a one-bit flip at a SYMBOLIC index over 65+32 positions through a
   2-block keyed hash (12 compressions) inside the current baseline. Rewrite
   khash-style: concrete head/entry, base (2) + determinism (2) + ONE
   symbolic-index entry-flip eval (2) + ONE symbolic-index head-flip eval (2)
   + flip-back NEG (2) ≈ **10 compressions ≈ 1.5–3 min** (vs ~20 min).
   Coverage: IDENTICAL — all 64 positions, now by symbolic index; the
   flip-back negative control is a strict addition. Conceded: nothing.
2. **`kani_prov_inclusion_sound`** — compute `head = recompute(leaf,&sibs)`
   ONCE; assert the iff as `verify_inclusion(leaf,&sibs,any_head) == (head ==
   any_head)` (sound because `recompute` determinism is proven; the symbolic
   `any_head` SUBSUMES both the genuine-accept and the tampered-head cases);
   keep `bad_leaf` + `bad_sib` verify rejections. 28 → **16 compressions ≈
   ~2.5 min**. Conceded: nothing — the iff IS the property.
3. **`kani_prov_head_deterministic`** — keep as-is (12 compressions ≈ 1.8 min,
   affordable) or drop the duplicate determinism recompute to 8. Order-swap
   (2-entry) stays verbatim.
4. **`kani_exp_fold_tamper`** — **KEEP FULL** (185 s measured) as the ONE
   representative deep harness: leaf re-hash → head mismatch → inclusion
   failure end-to-end through the real khash fold. This is what licenses the
   thinning of the other three.
5. **`kani_opframe_fold_truncation` / `kani_exittel_fold_tamper` /
   `kani_tpsched_fold_tamper`** — thin to leaf-sensitivity:
   `prov_hash(bytes) != prov_hash(tampered)` at a symbolic index (buffers are
   21–61 B = 1 compression each), keeping each harness's non-fold half
   (`gate_commits_final_seq` truncation etc.) verbatim. ~18 → **2–3
   compressions ≈ ~30 s each**. Conceded (the only real concession in this
   plan): each per-milestone harness claims "a flipped canonical byte changes
   the leaf id"; the head/inclusion rejection becomes a documented
   COMPOSITION of three separately machine-proven conjuncts (leaf≠leaf′ ∧
   chain_mix tamper-sensitivity ∧ inclusion-iff), demonstrated end-to-end by
   the kept `kani_exp_fold_tamper`. The composition note goes in each thinned
   doc-comment + the verify-encode.sh block — no marker text overclaims.
6. **`kani_prov_hash_total`, `kani_bakeoff_replay_determinism`** — leave
   (36 s + ~36 s).

**Projected stage C delta ≈ +9–11 min → lane ≈ 31–42 min** at the
M30-inflated `N_base`. Implementation cost: 6 harness bodies + doc-comments,
verify-encode.sh doc block, kani.yml comment, prov.rs honesty block ("NOT
cryptographic" → the stage C wording), per-harness local WSL measurement
before push (the §8 gate; ladder: kissat → shrink → re-split).

### Option 2 — CONCRETIZE the flip-index in the worst harnesses — **REJECT (dominated)**

The worst harness (`chain_mix_tamper`) is already concrete-indexed — under
khash, concretization IS the blow-up (every unrolled position pays full
compressions: 64 positions × 2 comps ≈ 19 min; k-position subsets cost
k×~18 s AND surrender all-positions coverage). What is lost: the uncovered
positions are exactly where the real bug class lives — last-partial-block /
padding / t-counter drops at block boundaries (63/64/65) and field offsets,
the precise NEG-control targets of `kani_khash_total_deterministic`. A
symbolic index over a SHORTER (≤1-block) buffer — i.e. option 1 — keeps
all-positions coverage at lower cost everywhere. Concretization is dominated
at every point of the trade space.

### Option 3 — ONE deep-chain harness in a weekly scheduled lane — **REJECT as primary; optional later**

Precedent: **none** — grep over all 8 workflows (`bench, ci, clippy, kani,
l2-nested-vmx, microvm-kvm, miri, vmm-boot`) finds zero `on: schedule`
triggers; this would be a new lane class. GitHub `schedule` runs on the
default branch only, is best-effort under load, auto-disables after 60 days
of repo inactivity, and blocks no PR — a deep-chain regression would surface
up to a week late with no natural owner, against the M24 honest-gate
philosophy and the M29 lesson that the count gate is execution-enforced
per-PR. Honesty mechanics if ever adopted: a separate pinned count + a
DISTINCT marker token (e.g. `V1-deep: kani-fold-deep OK`), and the per-PR
marker/doc must say shallow-chains-per-PR / deep-weekly. Decisive against:
§2 shows NO property needs depth >2 — a deep chain is pure corroboration, so
a whole new workflow + double lockstep surface buys proof-theater, not proof.
Revisit only if a future milestone introduces a genuinely depth-dependent
property.

### Option 4 — SHARD prove-encode into 2 parallel jobs — **PREPARE as the escape hatch, do not land now**

Mechanics: two matrix jobs each running `cargo kani -p tb-encode --harness
<name> --exact ...` over a pinned half of the list; `verify-encode.sh` takes a
shard id and asserts per-shard `EXPECTED_HARNESSES_A/_B`. Lockstep cost is
real: TWO pinned numbers plus a pinned harness LIST — and a harness assigned
to NEITHER shard would be silently unproven, the exact hollow-pass failure
the M29 count-gate lesson exists to prevent. Mandatory mitigation: a third,
free, fail-closed completeness check — `grep -c '#\[kani::proof\]'
crates/tb-encode/src/proofs.rs` must equal `A + B` (execution-enforced, same
discipline as today's single count). Budget honesty: the lane is
codegen-dominated and codegen is DUPLICATED per shard (the #77 cache covers
unchanged-crate pushes only); sharding splits solving time alone — so it
cannot rescue the naive cutover (one shard would carry codegen + the 20-min
`chain_mix_tamper` monolith ≈ cap again). After option 1 it cleanly halves a
~15-min solving load: per-shard ≈ 20–30 min. Verdict: the right tool for the
NEXT capacity crisis (harness count growth), not for this one. Pre-agree the
trigger: **shard when a measured full pass exceeds ~38 min.**

### Option 5 — algebraic split (one-step khash proof + abstracted-mix chain proof) — **REJECT (not expressible without weakening)**

Seam audit: the harnesses import CONCRETE free fns (`proofs.rs:56-59`:
`use crate::prov::{canon, chain_mix, prov_hash, recompute, verify_inclusion, ...}`);
`prov.rs` has no trait/generic seam and `recompute` hard-calls `chain_mix` —
**no seam exists today.** Kani's two abstraction mechanisms both fall short:
(a) `#[kani::stub(prov::chain_mix, cheap_mix)]` lives harness-side
(production code untouched) but requires the unstable `-Z stubbing` flag
(absent from Cargo.toml/lane args today) and the replacement must be a
CONCRETE function — Kani exposes **no uninterpreted-function surface**, so
"uninterpreted-but-injective" is not expressible; the chain theorem would be
proven for one witness mix with NO machine-checked link to khash. (b)
Function contracts (`#[kani::ensures]` + `stub_verified`) would annotate
`prov.rs` itself (cfg(kani)-erased, code path unchanged, but new trusted
surface) — and the property needed (tamper-sensitivity/injectivity) is
RELATIONAL across two calls, which a single-call `ensures` cannot state.
Net: option 5 collapses into option 1's informal composition argument plus
an unstable flag, a stand-in mix in the trusted base, and an anti-hollow-pass
vacuity hazard (a green stubbed harness asserts nothing about production).
Option 1 already delivers the honest kernel of this idea — "one step is
tamper-sensitive (real khash, once: `chain_mix_tamper`) + the chain composes
(2-entry real-khash chains: `inclusion_sound`, `head_deterministic`)" —
with zero new machinery.

---

## 4. Recommended composition

1. **Land stage C with Option 1** (six bodies; projected lane 31–42 min;
   the only concession is three thinned per-milestone fold harnesses whose
   chain-level claim becomes a documented three-conjunct composition, each
   conjunct machine-proven, with `kani_exp_fold_tamper` kept as the full
   end-to-end witness).
2. **Measure every rewritten harness locally in WSL pre-push** (`cargo kani
   -p tb-encode --harness <name>`); apply the M29 §8 ladder (concrete pin →
   kissat → shrink) to any outlier; record numbers in the landing PR.
3. **Keep Option 4 drafted with a written trigger** (full pass measured
   > ~38 min, or the next milestone's harness additions project past it):
   2-way shard + per-shard pinned counts + the `#[kani::proof]`-count
   completeness guard.
4. **Do not adopt** options 2 (dominated, loses boundary-position coverage),
   3 (no precedent, non-blocking, detects late, nothing needs depth >2),
   5 (inexpressible without unstable stubbing; no stronger than option 1's
   composition; vacuity hazard).
5. Count gate unchanged: `EXPECTED_HARNESSES` stays `N_base` (stage C adds no
   harness); only the doc blocks in verify-encode.sh / kani.yml / prov.rs and
   the six harness bodies change — bump nothing.
