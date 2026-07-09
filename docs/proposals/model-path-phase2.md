---
type: Design Decision
title: "Model-path Phase 2 — Cogi's own model (corpus→QLoRA→GGUF, DESIGN ONLY)"
description: "Design-only, BRAIN-gated pipeline to fine-tune an open ≥7B model on Cogi's corpus (QLoRA→GGUF→golden-measure→pin); nothing trained yet."
tags: ["model-path", "fine-tuning", "qlora", "gguf", "brain-gated", "sovereignty"]
timestamp: 2026-07-08T11:29:25+03:00
status: draft
diataxis: explanation
---

# Model-path Phase 2 — Cogi's own model: corpus → QLoRA → merge → GGUF → the golden-measure run → the pinned local organ (BRAIN-gated; DESIGN ONLY)

**Status:** **DESIGN ONLY — nothing is trained, acquired, or spent by this document.** The execution is **BRAIN-gated** (`forward-plan.md §4.2`): it waits on the operator's **go + a fine-tune-sufficient corpus + spend/hardware**. This doc is the Track-D deliverable of the forward plan (`docs/proposals/forward-plan.md §2.3` + §3 row D + §4.2); that plan IS the binding scope and this file adds no new commitment beyond it. It writes DOWN the Phase-2 pipeline so that when the gate opens the path is a known sequence and not a research scramble, and it proves — with a runnable-TODAY runbook (§5) — that the one non-trivial post-training step (the golden-measure run into the landed M32 load seam) is cheap and already exercisable. · **Pillar:** the MODEL frontier (no live sovereign occupant yet) + honesty (the capability ceiling and the two distinct sovereignties are stated sharply, never conflated). · **Depends on (for EXECUTION, not for this doc):** Phase-1 corpus (`forward-plan.md §2.2` / the M39 track — the real prerequisite), the landed M32-B receive seam + `tools/infer-daemon/` load plumbing (`M32-local-infer.md`), the B3 debt note (`docs/research/b3-pure-rust-engine.md`), and the competence-floor finding (`docs/research/cogi-cognitive-architecture.md §1.2b`). · **Operator decisions honored:** tinygrad **DEFERRED**, Namzu **DEFERRED**, the pragmatic path is llama.cpp/GGUF inference (plumbing built) + a host-side PyTorch/Unsloth-or-axolotl QLoRA fine-tune. · **Does NOT touch `docs/ROADMAP-V2.md`** — the roadmap row is handed to Track F (§9). `token=doc=DESIGN-ONLY-BRAIN-GATED`, `token=scope=ONE-NEW-FILE-ROADMAP-ROW-TO-F`.

> **One-line:** Phase 1 stocks the dataset moat; Phase 2 — later, operator-gated — turns it into **Cogi's own weights**: fine-tune an **open ≥7B** base on the corpus (host-side QLoRA), merge, convert + quantize to GGUF, then run the **one real step** — the golden-measure run that pins the produced model into `tools/infer-daemon/src/pins.rs` — and the already-built daemon serves it over the landed M30/M31/M32-B wire. The ceiling is honest: an open QLoRA fine-tune gives a **sovereign, provider-independent, persona/memory-grounded** model **at the ~7B competence floor — NOT frontier**; the M31 bridge stays the escalation path for hard reasoning. Yuva already built the SLOT and the GATE; Phase 2 fills the slot with weights whose PROVENANCE is yours. `token=phase2=OPEN-MODEL-CAPABILITY-NOT-FRONTIER`, `token=one-real-step=GOLDEN-MEASURE-RUN`.

---

## 1. Why this document, and what it is NOT

M31 put real model traffic on the M30 channel — but the model is Anthropic's. M32 built the daemon that runs a model **the machine holds** — but the model it serves today (`stories260K.gguf`) is a 260K-param toy, and the weights came from `ggml-org/models`, not from Cogi. Phase 2 is the milestone where the occupant of the M32 slot is **a model Cogi trained from Cogi's own corpus**. Three things make this a *design* doc and not a build:

1. **No training happens now.** The QLoRA run needs GPU/spend, and — more bindingly — a **corpus that does not yet exist at fine-tune-sufficient size** (`forward-plan.md §2.2` / §4.2). The corpus is Phase 1, ungated, in flight on the M39 track; the fine-tune is Phase 2, gated on Phase 1 maturing. Building the fine-tune harness before the corpus exists would be anti-hollow (unexercisable code). `token=no-train-now=CORPUS-IS-THE-PREREQUISITE`.
2. **The base/framework/method are operator choices at the gate,** not commitments this plan bakes in. This doc names the *pragmatic default* the operator already decided (open ≥7B + QLoRA via PyTorch/Unsloth-or-axolotl + llama.cpp/GGUF serving) and the honest ranges around it; the actual base model, quant level, and hyper-parameters are the operator's call when the gate opens. `token=choices=OPERATOR-OWNED-AT-GATE`.
3. **The load path is already built and this doc PROVES it (§5).** The only novel, non-constant Phase-2 step after "produce a GGUF" is the **golden-measure run**; §5 is a runbook the operator can execute TODAY on a real small open GGUF to demonstrate that step is cheap and known, without any training. `token=load-path=BUILT-PROVEN-BY-§5-RUNBOOK`.

**What this doc is NOT:** it is not a training run, not a model acquisition, not a spend authorization, not a KAN-activation (that is a separate gated decision on the M24 margin — `forward-plan.md §2.4`), and not a claim that a fine-tune retires the B3 pure-Rust-engine debt (§4). It edits exactly one new file and hands its roadmap row to Track F.

---

## 2. The pipeline — eight steps, each with inputs, outputs, cost, and failure mode

The end-to-end path from Yuva's corpus to a served sovereign organ. Steps 1–2 are Phase-1/curation, 3–6 are the host-side training half (BRAIN-gated), 7 is the one real load step, 8 is serving. Every step names what goes wrong, so the gate opens onto a checklist, not a fog.

### Step 1 — Corpus export (the Phase-1 handoff)

- **Inputs:** the durable, LMS-signed `corpus_head` + records the M39 track builds (`forward-plan.md §2.2` DoD-4/5); the agent-side token→text dictionary (the kernel stores u64 interned tokens, NOT text — `forward-plan.md §1` fact 1, `mem/mod.rs:766`).
- **Outputs:** training-ready **JSONL**, one example per row, each carrying its provenance envelope (lineage hash, source M22/M23 ids, `consolidation_class`, outcome label, honesty tokens) — produced by the M39 host tool `tools/corpus-export/`.
- **Cost:** CPU-only, seconds-to-minutes; zero spend. This is the boundary Phase 1 already delivers.
- **What can go wrong:** the exported head must round-trip (kernel `corpus_head` == host-recompute over the exported rows — M39 DoD-5); a dictionary-join gap yields rows with dangling tokens. Both are Phase-1 (M39) failures caught before Phase 2 begins — Phase 2 CONSUMES a verified export, it does not re-verify provenance. `token=corpus-in=VERIFIED-JSONL-WITH-PROVENANCE-ENVELOPE`.

### Step 2 — Training-pairs curation

- **Inputs:** the JSONL corpus.
- **Outputs:** two distinct sets — (a) **SFT/instruction pairs** (prompt→response), the LIMA-style small-high-quality set (§6); (b) **preference/DPO pairs** (prompt, chosen, rejected), OPTIONAL and honestly harder.
- **Cost:** human curation review time — the dominant *quality* cost, not a compute cost.
- **What can go wrong — stated bluntly:** **preference/DPO pairs need sustained REAL operator-transcript volume, not synthetic self-labels.** Synthetic preference data can *decrease* quality when it is small/domain-narrow (§6 evidence); a sovereign, cheap, trustworthy preference oracle is itself an open problem (the same M24 exogenous-oracle problem — `cogi-cognitive-architecture.md §1.2b/§2.3`). So Phase 2's **first** fine-tune is SFT-only (LIMA-style curation over the M25/M28 approved operator turns + M17 distilled/reflected survivors); DPO is a **later** step that waits on real operator-transcript accumulation, and this plan does NOT pretend a synthetic-DPO shortcut exists. `token=dpo=NEEDS-REAL-OPERATOR-TRANSCRIPT-VOLUME-NOT-SYNTHETIC`, `token=first-finetune=SFT-ONLY`.

### Step 3 — Base-model selection

- **Inputs:** operator choice at the gate.
- **Outputs:** a pinned open base, **≥7B**, permissive license (Apache-2.0 / Llama-community / Qwen / Mistral class — the license governs redistribution of the produced weights and must be read at the gate).
- **Cost:** download + storage (tens of GB); zero training spend.
- **What can go wrong:** **sub-7B does not clear the competence floor** — below ~7B, retrieved context frequently *hurts* (the scaling-cliff, `arXiv:2603.11513`) and hard multi-hop research benchmarks collapse toward zero (BrowseComp, `cogi-cognitive-architecture.md §1.2b`). "Small" here means small-relative-to-frontier, never small-in-absolute-terms. A license that forbids derivative redistribution silently poisons the "sovereign weights" claim — read it at the gate. `token=base=OPEN-≥7B-LICENSE-READ-AT-GATE`.

### Step 4 — QLoRA fine-tune

- **Inputs:** the SFT pairs (Step 2a) + the base (Step 3).
- **Outputs:** **LoRA adapter weights** (the 4-bit base is frozen; only the low-rank adapters train).
- **Cost:** ~2–8 GPU-hours on a single 16–24 GB GPU for a 7–8B QLoRA at 2–3 epochs (§6); ~$3–$100 of rented GPU for a single run, budget ~$100–$2000 across iteration/failed runs (§6). Tooling: **Unsloth** (fastest, single-GPU) or **axolotl** (multi-GPU/production) over PyTorch + PEFT/bitsandbytes.
- **What can go wrong:** overfitting a small curated set (LIMA trains few epochs deliberately — §6); catastrophic forgetting of base competence if the mix is wrong (naïve continual fine-tune forgetting *intensifies* 1B→7B — `cogi-cognitive-architecture.md §1.3`, `arXiv:2308.08747`); a botched chat-template/tokenizer config produces a model that formats but does not answer. `token=finetune=QLORA-ADAPTERS-SFT-FEW-EPOCHS`.

### Step 5 — Merge

- **Inputs:** the base + the LoRA adapters.
- **Outputs:** a **full-weight** merged HF model (F16/BF16). `convert_hf_to_gguf.py` does NOT accept PEFT adapters — the merge is mandatory before conversion (§6 evidence).
- **Cost:** ~2–5 min on CPU, ~16 GB RAM for an 8B model; zero spend.
- **What can go wrong:** merging into a *quantized* base loses precision — merge into the F16/BF16 base, not the 4-bit one. `token=merge=INTO-FP16-BASE-BEFORE-GGUF`.

### Step 6 — GGUF convert + quantize

- **Inputs:** the merged HF model.
- **Outputs:** a high-precision GGUF (`convert_hf_to_gguf.py` → F16/BF16), then a **quantized** GGUF (`llama-quantize` → **Q4_K_M** default for a 7–8B, or Q8_0 for headroom). Optionally an **imatrix** (importance-matrix) pass improves aggressive quants at ~30–60 min extra (§6).
- **Cost:** minutes (convert) + minutes-to-an-hour (quantize/imatrix), CPU-only; zero spend.
- **What can go wrong:** jumping straight to Q4_K_M inside the converter (the quantizer expects an F32/BF16 GGUF input — a two-stage pipeline, §6); a `_S` vs `_M` variant that over-degrades sensitive layers. The quant level is a **witness-pinned** field downstream (`isa`/`sampler`/`batch` are pinned; the model bytes are `gguf=SHA256:` in the M32 witness — `M32-local-infer.md §8`) so a re-quant is a reviewed re-pin, never a silent swap. `token=gguf=CONVERT-THEN-QUANTIZE-Q4KM-DEFAULT`.

### Step 7 — The GOLDEN-MEASURE run (the one real step)

- **Inputs:** the produced quantized GGUF; its SHA256.
- **Outputs:** the model's **measured goldens** — the `body_digest` of the greedy completion of the two frozen prompts (`PRIMARY_PROMPT` + `NEG_PROMPT`) inside the pinned determinism envelope — pasted into a `ModelPin` const in `pins.rs`.
- **Cost:** a handful of CPU-only worker spawns (the §4 four-leg compare: 2× primary + neg + 2× nonce), seconds-to-minutes; zero spend. **This is the ONLY non-constant post-training step** and §5 is its runbook.
- **What can go wrong — and why this step is REAL, not a formality:** *you cannot pin goldens you have not measured* (`forward-plan.md §2.3` / `M32-local-infer.md §4` leg 1). The daemon adjudicates the produced model against **repo-pinned** golden digests; a hash-stub or broken engine cannot forge them. If the produced model's greedy output is not bit-stable under the pinned envelope (single-slot, no prompt cache, threads=1, baseline ISA — `pins.rs:42-55`), the measure REFUSES rather than pinning a flaky golden. `token=step7=MEASURE-THEN-PIN-CANNOT-PIN-UNMEASURED`.

### Step 8 — Serve

- **Inputs:** the pinned `ModelPin` + the produced GGUF on disk.
- **Outputs:** the daemon (`tools/infer-daemon/`) serves the model over the SAME landed M30/M31 framing (`YUVA-M31-INFER-V1` MAC domain, host-custodied key), with the M32-B kernel receive seam delivering real engine bytes to the guest (`M32-local-infer.md §3` stage B).
- **Cost:** zero incremental — the plumbing is built (the vendored-llama.cpp `-sys` worker, the keyless sandbox, the witness). The debt tokens (`engine=VENDORED-C-LLAMACPP debt=SOVEREIGNTY-OPEN-B3 ...`) ride every witness line UNCHANGED — a fine-tune changes the WEIGHTS, not the ENGINE (§4).
- **What can go wrong:** the model is larger than the toy — the M32-B `QEMU_TIMEOUT` budget for in-boot engine latency under TCG (`M32-local-infer.md §3` stage B) must be re-measured for a real ≥7B GGUF; model-load + decode of a 7B under TCG in-boot may exceed the boot wall-clock and force the host-adjudicated (stage-A) shape for the large model, with the guest-visible path reserved for a small enough quant. This is a **measure-before-pin** boot-budget question named here, not discovered mid-landing. `token=step8=SERVE-OVER-BUILT-SEAM-REBUDGET-TCG-TIMEOUT`.

`token=pipeline=CORPUS→CURATE→QLORA→MERGE→GGUF→GOLDEN-MEASURE→PIN→SERVE`.

---

## 3. The capability ceiling — honest

An open ≥7B QLoRA fine-tune on Cogi's corpus produces a model that is **sovereign, provider-independent, and grounded in Cogi's persona/memory/experience** — and that is **at the ~7B competence floor, NOT frontier reasoning.** Both halves are true and neither may be dropped:

- **What it GAINS:** provider independence (no Anthropic/OpenAI dependency for the default path), persona and experience grounding (it answers *as Cogi*, from Cogi's curated corpus), and weight-provenance sovereignty (§4). This is the "small sovereign REASONING ORGAN — the default operation organ" the cognitive-architecture doc describes (`cogi-cognitive-architecture.md §3.1`).
- **What it does NOT gain:** frontier reasoning. The base is open ≥7B; QLoRA adapts *style/persona/procedure over the corpus*, it does not manufacture capability the base lacks (RLVR/fine-tune *elicits* latent reasoning, it does not *teach* new reasoning from nothing — `cogi-cognitive-architecture.md §1.2b`, `arXiv:2504.13837`). Small-model test-time wins additionally lean on a large (7B–72B) external verifier (`arXiv:2502.06703`) — the same M24 oracle problem.
- **The hybrid, as an operator choice:** the honest architecture is **own-model default + provider for hard cases**. M32 (the local sovereign organ) is the default operation organ; **M31 (the Anthropic live bridge) stays the escalation path** for open-ended/hard reasoning (`cogi-cognitive-architecture.md §3.1`, the NVIDIA heterogeneous-SLM-agent shape `arXiv:2506.02153`). Phase 2 does not remove M31; it makes the *default* sovereign. Whether to route a given query to the local organ or escalate is an operator/agent policy, not baked here.

**Yuva secured the SLOT and the GATE, not the occupant's competence** (`cogi-cognitive-architecture.md §1.3`): swappability and a small-relative-to-frontier slot are guaranteed by M32; whether the dropped-in model clears the floor is a property of the *chosen base + corpus*, not of Yuva. `token=ceiling=OPEN-MODEL-FLOOR-NOT-FRONTIER`, `token=hybrid=OWN-DEFAULT+PROVIDER-ESCALATION-M31-STAYS`, `token=slot-secured-not-competence`.

---

## 4. The B3-distinction — weight-sovereignty vs engine-sovereignty (two different debts)

Phase 2 changes **whose weights** Cogi runs. It changes **nothing** about **whose engine** runs them. Conflating the two would be the exact overclaim the M32 debt tokens exist to prevent.

- **The sovereignty Phase 2 DELIVERS — provenance of the WEIGHTS.** Today the M32 slot serves a GGUF from `ggml-org/models` — a model the *host provided*, `weights=UNTRUSTED-INPUT-NAMED` (`M32-local-infer.md §7`). A Phase-2 model is trained **from Cogi's own corpus** — you know exactly what it learned from, because Phase 1 made the corpus tamper-evident and signed (`forward-plan.md §2.2`). That is the sovereignty difference: **a model the host hands you vs a model you grew from your own provenance-signed experience.** The `weights=UNTRUSTED-INPUT-NAMED` token still rides (a fine-tune does not make weights *safe* to parse — the GGUF is still untrusted C-parser input), but the *provenance* is now yours, tied to `debt=SOVEREIGNTY-OPEN-B3` in the M32 witness as the standing marker of what is and is not sovereign. `token=weight-sovereignty=OWN-CORPUS-PROVENANCE-NOT-HOST-PROVIDED`.
- **The sovereignty Phase 2 does NOT deliver — the ENGINE.** The daemon still links **vendored C llama.cpp** (`engine=VENDORED-C-LLAMACPP debt=SOVEREIGNTY-OPEN-B3 memsafety=UNSAFE-C-PROCESS-CONFINED`). Retiring THAT debt is the orthogonal **B3 pure-Rust-engine** track (`docs/research/b3-pure-rust-engine.md` — five closure gates, the grep-enforced `engine=VENDORED-C-LLAMACPP → engine=PURE-RUST` flip, `#95`), and a fine-tune touches none of its gates. **Sovereignty-of-the-WEIGHTS ≠ sovereignty-of-the-ENGINE.** The witness token grammar was deliberately built so these move independently: `engine=` names the engine STATE, `weights=`/`gguf=` name the weights — a Phase-2 model bump changes `gguf=SHA256:` + `model=` and nothing about `engine=`/`debt=`; a B3 cutover changes `engine=`/`debt=`/`memsafety=` and nothing about the weights (`M32-local-infer.md §7`). `token=engine-debt=B3-UNCHANGED-BY-FINETUNE`, `token=two-sovereignties=WEIGHTS≠ENGINE-MOVE-INDEPENDENTLY`.

---

## 5. The NEW-MODEL DROP-IN RUNBOOK — proving the load path is cheap TODAY

**Purpose:** prove — with a runnable-NOW sequence, **no training required** — that the golden-measure path (Step 7) is the *only* real step for serving a new model, and that it is cheap and known. This is the **one thing an operator can run before Phase 2 exists**, on a real small **non-toy** open GGUF (e.g. a Qwen2-0.5B / TinyLlama-1.1B-class GGUF, or any small open GGUF the operator already has). **OPTIONAL-NOW, NEEDED-BEFORE-PHASE2.** `token=runbook=OPTIONAL-NOW-NEEDED-BEFORE-PHASE2`.

**The measure-mode mechanism (the code that makes this cheap).** `measure_model` (`tools/infer-daemon/src/engine.rs:210-327`) runs the full §4 four-leg determinism evidence and prints the **measured** `resp-digest`/`neg-digest` on the witness line. When a `ModelPin`'s `golden_primary` is a `@@`-prefixed placeholder, the daemon SKIPS its own golden self-check (`engine.rs:290`: `if !pin.golden_primary.starts_with("@@")`) and simply emits the measured digests — that is **measure mode**. You read the measured digests off the witness, paste them into the pin, and re-run; now the daemon self-checks AND the workflow (`scripts/m32-adjudicate.sh`) string-compares the pin against the daemon stdout — the independent-stream golden (`M32-local-infer.md §4` leg 1). *(Note: the `pins.rs:14-18` doc-comment still says "empty string = measure mode"; the CODE authority is the `@@`-prefix check at `engine.rs:290` — a one-line comment-lag worth a Track-F/cleanup pass.)*

**The steps (reusing the optional Q8 slot — the fewest-changes exercise):**

1. **Obtain a real small non-toy open GGUF** (already quantized, or produce one via Step 6 on any small open model). Compute its hash: `sha256sum <model>.gguf`.
2. **Point the daemon at it + measure-mode the pin.** Set the Q8 slot's path via env (`M32_Q8_PATH=<abs path to the gguf>`), and in `tools/infer-daemon/src/pins.rs` edit `STORIES15M_Q8`: set `sha256` to the real hash and set `golden_primary`/`golden_neg` to a placeholder like `"@@MEASURE@@"`. (For a genuinely NEW slot rather than reusing Q8, add a third `ModelPin` const + one entry to the `run_local_once` loop at `main.rs:236` — a few lines; the Q8-slot reuse needs zero loop code.)
3. **Run the measure step** (the double gate + the standalone measure branch, `main.rs:--local-measure`):
   ```
   cd tools/infer-daemon
   XPORT_LOCAL_LLAMA=1 M32_Q8_PATH=/abs/model.gguf \
     cargo run --features engine -- --local-measure > /tmp/witness.log
   ```
   The daemon verifies the SHA256, installs the seccomp+Landlock sandbox BEFORE parsing the GGUF, runs the four-leg compare, and prints the `infer-daemon: backend=LOCAL-ENGINE ... resp-digest=0x<32hex> ... neg-digest=0x<32hex> ...` line with the **measured** digests. *(The sandbox rows need a Linux runner / WSL with Landlock ABI — the §4/§5 substrate; on the operator's Windows host this runs under WSL, matching the CI lane's `ubuntu-24.04`.)*
4. **Pin the measured goldens.** Copy the `resp-digest`/`neg-digest` hex (drop the `0x`) into `golden_primary`/`golden_neg` in `pins.rs`. This is the "reviewed re-pin" commit — the model bytes + hash + goldens land together in one ledger edit.
5. **Re-run + adjudicate for green.** Re-run step 3, then `scripts/m32-adjudicate.sh /tmp/witness.log <nonce-hex>`: the independent-stream compare now matches (`>> ... golden MATCHED (independent stream), neg distinct, 2-run + nonce-2run equal`). The load path is green on a real non-toy model — with **zero training**.

**What this demonstrates:** the entire post-training Phase-2 tail (Steps 7–8) reduces to *measure the two frozen prompts, paste two hex digests, commit.* Everything else about serving is a constant edit. The operator can therefore de-risk the load path NOW and know that when Phase 2's GGUF exists, dropping it in is exactly this runbook with the produced model in the slot. `token=drop-in=MEASURE-PASTE-COMMIT-PROVEN-ON-REAL-GGUF`.

---

## 6. Cost, time, and corpus-size thresholds — honest ranges with basis

**Fine-tune cost/time (single 7–8B QLoRA run, 2–3 epochs):** ~**2–8 GPU-hours** on a single 16–24 GB GPU (≈2–4 h on an A100, ≈6–8 h on an RTX 4090); a single run rents for roughly **$3–$100** depending on GPU/duration. The **~$100–$2000** forward-plan figure is the honest *budget across iteration* — failed runs, hyper-parameter sweeps, data-mix experiments, and the occasional larger base — not the cost of one successful run (a clean 7B QLoRA is famously cheap: sub-$5 reported on budget providers). The contrast that matters: full fine-tune of a 7B needs ~100–120 GB VRAM (~$50K-class hardware); **QLoRA is what makes this a $100s-not-$50Ks decision.** Tooling: **Unsloth** for single-GPU speed/simplicity, **axolotl** for 4+-GPU/production. `token=cost=~$100-2000-BUDGET-INCL-ITERATION`, `token=time=~2-8-GPU-HOURS-PER-RUN`.

**Corpus-size threshold (how much is "enough"):** the evidence says **quality over quantity, and small can be enough** — LIMA fine-tuned a base on **1,000 carefully curated** prompt/response pairs (no RL, no preference modeling) and matched or beat far-larger-data alignment in a controlled study, supporting the *superficial alignment hypothesis*: almost all capability is learned in pretraining, and instruction tuning mainly teaches *format/behavior* (`arXiv:2305.11206`). Corroborating small-high-quality results: SPIN matching 50k-sample performance with ~1.8k curated examples; ORPO effective at scale with ~7k samples (§8 sources). **Consequence for Cogi:** the first SFT fine-tune does NOT need a giant corpus — it needs a **curated ~1k–10k high-quality examples** drawn from the M17 distilled/reflected survivors + the M25/M28 approved operator turns (`forward-plan.md §2.2`). The corpus-maturity gate is therefore a **curation-quality** bar, not a raw-row-count bar. **The honest caveat:** LIMA-style small data teaches *persona/format/procedure over a base whose competence already exists* — it does NOT lift a sub-floor base over the ~7B floor (§3). And **preference/DPO** data is the exception to "small is fine": it needs sustained REAL operator-transcript volume (small/narrow synthetic preference sets can *decrease* quality — §8 sources), which is why the first fine-tune is SFT-only (§2 Step 2). `token=corpus-threshold=~1k-10k-CURATED-QUALITY-OVER-QUANTITY`, `token=lima=SUPERFICIAL-ALIGNMENT-SFT-SMALL-OK/DPO-NEEDS-REAL-VOLUME`.

---

## 7. The deferrals and the operator veto points

Everything model-training is behind the **BRAIN gate** (`forward-plan.md §4.2`) — the operator's go + a corpus + spend. The named deferrals, each an explicit operator decision, not an autonomous build:

- **tinygrad — DEFERRED.** The pragmatic path is llama.cpp/GGUF for inference (plumbing built — M32) + PyTorch/Unsloth-or-axolotl for the QLoRA. tinygrad is a possible **LATER sovereign-compute stack** (a from-scratch training/inference stack with fewer C dependencies) — a real option for deepening sovereignty over the *compute*, but not now and not this doc's path. `token=tinygrad=DEFERRED-POSSIBLE-LATER-SOVEREIGN-COMPUTE`.
- **Namzu — DEFERRED.** Cogi's future ACTION/skills layer (Cogi = Namzu persona/skills + Yuva behind Namzu's MemoryStore interface). A separate composition step; the model path does not need Namzu, and the action layer is orthogonal to *which weights answer*. `token=namzu=DEFERRED-SEPARATE-ACTION-LAYER`.
- **DPO/preference tuning — DEFERRED within Phase 2.** Waits on real operator-transcript volume (§2 Step 2, §6). The first fine-tune is SFT-only. `token=dpo=DEFERRED-WITHIN-PHASE2`.
- **KAN activation — a SEPARATE gate, not this one.** Flipping `KAN_ACTIVE` is gated on the M24 Seldonian margin against a real oracle (`forward-plan.md §2.4`); it is neither the brain gate nor a substitute for the fine-tune. Named here only to keep it from being conflated with Phase 2. `token=kan=SEPARATE-M24-GATE-NOT-THIS`.
- **The B3 pure-Rust engine — orthogonal, unchanged (§4).** `token=b3=ORTHOGONAL-GATE-#95`.

**Operator veto points (where this plan STOPS and asks):** (1) authorize the spend + pick the base at the BRAIN gate; (2) approve the corpus as fine-tune-sufficient (curation-quality bar, §6); (3) approve each golden re-pin (Step 7 is a reviewed commit); (4) decide the hybrid routing policy (own-default vs escalate, §3); (5) separately, if ever, open the B3 and KAN gates. None of these is autonomously taken. `token=veto-points=SPEND+BASE / CORPUS-SUFFICIENCY / GOLDEN-REPIN / HYBRID-ROUTING / B3+KAN-SEPARATE`.

---

## 8. Honest scope — the non-overclaims (token roundup)

- **Design only; nothing trained or spent.** `token=doc=DESIGN-ONLY-BRAIN-GATED`.
- **Open-model floor, not frontier.** A ≥7B QLoRA fine-tune is sovereign + persona-grounded at the ~7B competence floor; M31 stays the escalation path. `token=ceiling=OPEN-MODEL-FLOOR-NOT-FRONTIER`.
- **Weight-sovereignty ≠ engine-sovereignty.** Phase 2 gives own-corpus weight provenance; the vendored-C-llama.cpp `debt=SOVEREIGNTY-OPEN-B3` is unchanged. `token=two-sovereignties=WEIGHTS≠ENGINE`.
- **The load path is built; the one real step is the golden-measure run** — proven cheap TODAY by §5, not a literal three-line drop-in (you cannot pin goldens you have not measured). `token=one-real-step=GOLDEN-MEASURE-RUN`.
- **Corpus is the prerequisite; small-but-curated is enough for SFT; DPO is not.** `token=corpus-threshold=~1k-10k-CURATED`, `token=dpo=NEEDS-REAL-VOLUME`.
- **A big ≥7B GGUF may not fit the in-boot TCG wall-clock** — the M32-B stage-B timeout is re-measured before pinning the guest-visible path (§2 Step 8). `token=step8=REBUDGET-TCG-TIMEOUT`.
- **Never overclaim: a mock is a mock, a toy is a toy, a stand-in is a stand-in.** The M32 witness carries every debt token unchanged after a fine-tune; nothing here claims isolation, safety, determinism, or frontier capability the substrate has not earned. `token=honesty=NEVER-OVERCLAIM`.

---

## 9. Roadmap row (handed to Track F — this doc does NOT edit ROADMAP-V2.md)

For Track F to place under BACKLOG / the Phase-2 forward-plan section (design-only, no CI marker, BRAIN-gated — a proposal pointer, not a cumulative-chain milestone):

> **Model-path Phase 2 (BRAIN-gated) — Cogi's own model.** DESIGN LANDED (`docs/proposals/model-path-phase2.md`): the corpus → QLoRA (open ≥7B, PyTorch/Unsloth-or-axolotl, SFT-first) → merge → GGUF convert/quantize → **golden-measure run** → `pins.rs` → daemon-serve pipeline, with the load path proven cheap TODAY by the §5 measure-mode runbook. EXECUTION gated on the operator's go + a fine-tune-sufficient Phase-1 corpus + spend (~$100–2000, ~2–8 GPU-h/run). Ceiling honest: sovereign persona/memory-grounded model at the ~7B competence floor, NOT frontier; M31 stays the escalation path. Weight-sovereignty only — the B3 engine debt (`#95`) is unchanged. Deferrals: tinygrad, Namzu, DPO, KAN — all separately gated.

---

## 10. References

**Code (in-repo, `origin/main` `49fd035`):**

- `tools/infer-daemon/src/pins.rs:7-40` — the `ModelPin` registry (`name`/`default_path`/`sha256`/`golden_primary`/`golden_neg`); the two in-repo pins (STORIES260K committed, STORIES15M-Q8 cache-lane) — the drop-in target for a Phase-2 model.
- `tools/infer-daemon/src/pins.rs:42-74` — the determinism pins (`ENGINE_PIN`, `SYSINFO_REQUIRE`/`SYSINFO_FORBID` two-sided ISA tripwire, `PRIMARY_PROMPT`/`NEG_PROMPT`/`NONCE_PROMPT_PREFIX`, `N_PREDICT=64`) — the frozen envelope a new model is measured inside.
- `tools/infer-daemon/src/engine.rs:210-327` (`measure_model`) — the §4 four-leg evidence + the measure-mode branch at `:290` (`!golden_primary.starts_with("@@")`) — the golden-measure path §5 exercises; `verify_artifact` at `:45-58` (SHA256 before any C parse).
- `tools/infer-daemon/src/main.rs` — the `--local-measure` standalone branch (double-gated by `XPORT_LOCAL_LLAMA=1`), `run_local_once` (the STORIES260K + optional Q8 loop, `M32_Q8_PATH` override), the `--digest-of-hex` golden helper.
- `scripts/m32-adjudicate.sh` — the workflow-level independent-stream golden compare (repo pins.rs vs daemon stdout) + the §8 house-order guards; the green step §5 ends on.
- `.github/workflows/m32-local-infer.yml` — the CPU-only, zero-network-at-runtime, zero-secret push-required lane that runs the measure + adjudication.

**Docs (in-repo):**

- `docs/proposals/forward-plan.md §2.3` (Phase 2 DoD + the load-plumbing/golden-measure honesty), `§3` row D (this track's scope + SP#5 roadmap-owner-is-F), `§4.2` (the BRAIN gate), `§6` (the non-overclaims) — the binding scope this doc implements.
- `docs/proposals/forward-plan.md §2.2` / the M39 experience-corpus track — the Phase-1 corpus this pipeline CONSUMES (Step 1); the u64-tokens-not-text constraint (`§1` fact 1).
- `docs/proposals/M32-local-infer.md §3` (stage A host-adjudicated / stage B kernel receive seam + TCG timeout), `§4` (the determinism envelope + the four golden legs), `§7` (the debt-token grammar — `engine=`/`weights=` move independently), `§8` (the witness line + guards) — the load seam and its honesty machinery.
- `docs/research/b3-pure-rust-engine.md §5/§6` — the five closure gates + the grep-enforced `VENDORED-C-LLAMACPP → PURE-RUST` flip (`#95`); the basis for §4's weight≠engine distinction.
- `docs/research/cogi-cognitive-architecture.md §1.2b/§1.3/§3.1` — the ~7B competence floor + scaling-cliff/BrowseComp-zero, "Yuva built the SLOT and the GATE, not the occupant's competence," M32=default-organ/M31=escalation — the §3 ceiling basis.

**External evidence (Phase-2 execution basis, WebSearch July 2026):**

- LIMA: Less Is More for Alignment — 1,000 curated examples; the superficial-alignment hypothesis (SFT teaches format/behavior, capability is pretrained). [arxiv.org/abs/2305.11206](https://arxiv.org/abs/2305.11206)
- QLoRA 7B cost/time — single-GPU 16–24 GB, ~2–8 GPU-h/run, ~$3–$100/run; QLoRA vs $50K full FT. [Spheron](https://www.spheron.network/blog/how-to-fine-tune-llm-2026/), [RunPod](https://www.runpod.io/articles/guides/how-to-fine-tune-large-language-models-on-a-budget), [Chanl](https://www.channel.tel/blog/fine-tuning-lora-qlora-ai-agent-builders)
- Unsloth (single-GPU) vs axolotl (multi-GPU) tooling. [Red Hat Developer](https://developers.redhat.com/articles/2026/04/01/unsloth-and-training-hub-lightning-fast-lora-and-qlora-fine-tuning), [codersera](https://codersera.com/blog/fine-tuning-llms-complete-guide-2026/)
- GGUF pipeline — merge LoRA (mandatory; converter rejects PEFT adapters) → `convert_hf_to_gguf.py` F16/BF16 → `llama-quantize` Q4_K_M → optional imatrix. [Markaicode](https://markaicode.com/gguf-quantization-after-fine-tuning-llama-cpp/), [llama.cpp discussion #2948](https://github.com/ggml-org/llama.cpp/discussions/2948)
- DPO/preference data — quality>quantity but small/narrow synthetic preference sets can decrease quality; real human feedback / mixed data more efficient. [Anyscale](https://www.anyscale.com/blog/direct-preference-optimization-with-synthetic-data), [Limited-Data survey arXiv:2411.09539](https://arxiv.org/pdf/2411.09539)

*— END MODEL-PATH PHASE 2 —*
