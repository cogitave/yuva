---
type: Standard
title: Documentation Standard — OKF adoption for the cogitave family
description: >-
  How cogitave/yuva, cogitave/cogi and cogitave/namzu keep documentation:
  OKF YAML frontmatter, Diataxis content typing, docs-as-code process, a
  progressive-disclosure index, and the honesty rules that keep metadata
  from ever upgrading a claim. Adoption is staged; stage 1 covers the
  canonical yuva docs only.
tags: [standard, docs, okf, diataxis, docs-as-code, process]
timestamp: 2026-07-09T00:00:00Z
status: active
stage: stage-1
diataxis: reference
---

# Documentation Standard — OKF for the cogitave family

This standard governs every markdown document in `cogitave/yuva`,
`cogitave/cogi`, and `cogitave/namzu`. It adopts three established,
citable standards and adds the house's honesty discipline on top:

1. **OKF — Open Knowledge Format** (Google Cloud, vendor-neutral, v0.1 2026):
   curated knowledge as a directory of markdown files with YAML frontmatter,
   human- AND agent-readable, portable, versioned in git.
   <https://github.com/GoogleCloudPlatform/knowledge-catalog/tree/main/okf>
2. **Diátaxis** — content-type discipline: every doc is a tutorial, a how-to
   guide, reference, or explanation, and is written to exactly one of those
   disciplines. <https://diataxis.fr>
3. **Docs-as-code** — docs live in the repo beside the code they describe,
   are versioned, reviewed via PR, and CI-checked.

Keywords **MUST / MUST NOT / SHOULD / MAY** are used in the RFC 2119 sense
(the same convention `docs/spec/yuva-abi-v1.md` already uses).

---

## 0. Authority order (read this first)

This project's identity is verified honesty: the kernel machine-emits its own
claim boundary and CI rejects overclaim by name. Documentation metadata is the
LOWEST-authority layer in the system, and this standard writes that down:

> **boot transcript (the marker chain + honesty tokens) > code > normative
> spec (`docs/spec/`) > proposal/decision record > roadmap/index > frontmatter.**

Frontmatter and index entries are navigation metadata. They MUST NOT be the
only place a claim lives, and when frontmatter disagrees with the document
body — or the body disagrees with the boot — the higher authority wins and
the lower one is a bug to fix.

> **The rules in 30 seconds**
>
> 1. Pick the OKF `type` + the Diátaxis discipline FIRST; write in that one
>    mode (§1, §1.3).
> 2. Real ISO-8601 `timestamp` — the actual revision time, never invented
>    (§2.5).
> 3. The `description` may compress the body, **never strengthen it** — mock
>    stays "mock", dormant stays "dormant" (§2.1–2.2).
> 4. Supersede, never delete: `status: superseded` + `superseded_by:` (§2.4).
> 5. Docs land in the SAME PR as the change they describe; `status`/`stage`
>    flip there too (§2.6).
>
> Full workflow: §9. Honesty rules in full: §2.

---

## 1. The frontmatter profile

Every in-scope markdown doc carries a YAML frontmatter block as its first
bytes. OKF strictly requires only `type`; this project requires more by
default and adds two extensions. OKF is minimally opinionated — custom fields
are permitted; reserved fields are never removed.

### 1.1 Fields

| Field | Requirement | Values / format |
|---|---|---|
| `type` | **REQUIRED** (OKF-required) | `Design Decision` \| `Roadmap` \| `Architecture` \| `Standard` \| `Index` \| `Reference` \| `How-to` \| `Explanation` \| `Tutorial` \| `Runbook` |
| `title` | REQUIRED (house) | Human-readable name; short — the H1 may stay longer |
| `description` | REQUIRED (house) | One to three lines. MUST carry the doc's own honest qualifier when the subject is mock / dormant / design-only / gated (see §2) |
| `timestamp` | REQUIRED (house) | ISO 8601, e.g. `2026-07-09T00:00:00Z` — the last substantive revision, real, never invented |
| `status` | REQUIRED (house) | `locked` \| `active` \| `draft` \| `superseded` (see §4 for the mapping from the house status ladder) |
| `diataxis` | REQUIRED (house) | `explanation` \| `reference` \| `how-to` \| `tutorial` |
| `tags` | SHOULD | Categorical labels from §1.2 |
| `stage` | MAY (project extension) | The house's honest stage token, kebab-case, taken verbatim-in-spirit from the doc's own Status header: e.g. `proposal-v2-nothing-landed`, `stage-a-landed`, `frozen`, `normative`, `design-only-brain-gated`, `plan-not-executed`, `rationale-record`, `complete-ci-green` |
| `supersedes` | MAY (conditional) | Relative path of the doc this one replaces |
| `superseded_by` | MUST when superseded | Relative path of the replacement |
| `resource` | MAY | External URL this doc describes |
| `maintained_by` | MAY (project extension) | For generated/pipeline-maintained docs, the generator (e.g. `.claude/skills/tabos-milestone` for `BENCHMARKS.md`) — a human edit to such a file is suspect by default |

Repo-specific custom fields (e.g. namzu's `related_packages`,
`last_updated`) are RETAINED — OKF permits custom fields; never delete them
to "clean up".

### 1.2 Tag vocabulary (small, controlled)

- **Pillar:** `sovereignty`, `memory`, `learning`, `operator-comms`
- **Track:** `kernel`, `vmm`, `abi`, `boot-profiles`, `extraction`,
  `corpus`, `model-path`, `verification`, `benchmarks`
- **Kind:** `adr`, `spec`, `roadmap`, `plan`, `research`, `literature`,
  `runbook`, `process`
- Free tags MAY be added; prefer reusing one of the above.

### 1.3 `type` ↔ `diataxis` — how the two axes differ

`type` is the OKF catalog type (what shelf the doc sits on); `diataxis` is
the writing discipline (what mode the prose is in). They usually pair as:

| `type` | Default `diataxis` |
|---|---|
| Design Decision (ADR/proposal) | `explanation` (the why of a decision) |
| Roadmap | `reference` (milestone/DoD tables consulted as fact) — use `explanation` for narrative decision-ladder roadmaps |
| Architecture | `explanation` |
| Reference / Standard / Index | `reference` |
| How-to / Runbook | `how-to` |
| Tutorial | `tutorial` |
| Explanation | `explanation` |

Diátaxis rule: don't blur types — if one file genuinely mixes modes
(steps + theory), split it or clearly section it; the frontmatter records the
dominant mode.

---

## 2. Honesty rules (non-negotiable)

These preserve the ethos that makes this family unusual. They are the parts
of this standard that a generic OKF adoption would not have.

1. **Frontmatter MUST NOT upgrade a claim.** A `description` may compress
   the body but never strengthen it. If the body says
   `backend=MOCK-DETERMINISTIC`, the description says "mock"; if the body
   says `DESIGN ONLY — BRAIN-gated`, the description says design-only and
   gated; if learning is `DORMANT`, no metadata anywhere says "learning".
2. **Adjective discipline.** Descriptions are adjective-honest — never
   "production-ready", "secure", "blazing", "minimal" (the kernel's own
   boot-report tail is adjective-free by design; the docs follow it). State
   what a thing does and what it does NOT claim.
3. **The existing `> Status:` headers are NOT deleted.** Yuva's house
   convention (the blockquote Status/Basis/Related header on top docs; the
   bold `**Status:** PROPOSAL Vn …` + Pillars + Depends-on + Markers block
   on proposals) carries adversarial-review records, honesty tokens, and
   line-cited dependency evidence. Frontmatter is ADDITIVE metadata above
   them; the headers remain the in-body source of truth. Where the two
   disagree, the header wins (§0) and the frontmatter is corrected.
4. **Superseded-not-deleted.** A doc that records a decision is an ADR. On
   replacement, set `status: superseded` + `superseded_by:` — never silently
   delete or rewrite history. This formalizes what the house already
   practices: M31 was "demoted-not-deleted"; BACKLOG's gated rows are
   "RETAINED, not deleted"; `proposals/yuva-abi.md` remains as "the rationale
   + adversarial-review record" after promotion to `spec/yuva-abi-v1.md`.
5. **Timestamps are real.** ISO 8601, set at the actual revision. A doc
   regenerated by a pipeline carries the generation time and
   `maintained_by`.
6. **Docs land with the change they describe** (docs-as-code). A proposal
   gains its landing banner in the same PR that lands the code; the
   frontmatter `status`/`stage` flips in that same PR.
7. **Generated provenance is immutable.** `docs/research/raw/` (JSON
   research provenance the docs cite) is out of frontmatter scope and MUST
   NOT be edited — it is the citation substrate.

---

## 3. Where frontmatter goes — and the README exemption

- **All of `docs/**/*.md`** in each repo: real YAML frontmatter (§1).
- **Root repo docs** (`BUILD.md`, `CONTRIBUTING.md`, `SECURITY.md`): real
  YAML frontmatter.
- **`README.md` at the repo root — EXEMPT from visible frontmatter.**
  GitHub renders YAML frontmatter as a metadata table above the rendered
  markdown; on the product front page that table would sit above the hero
  and sabotage the page. (Rendering behavior: ASSUMED-FROM-EXPERIENCE —
  verify once on a scratch repo before landing; if GitHub does NOT render a
  table on the root README, this exemption MAY be dropped.) Instead the
  README carries the same keys in an invisible HTML comment at the top of
  the file, so it stays greppable/parseable:

  ```html
  <!-- okf
  type: Index
  title: Yuva
  description: From-scratch agent-native unikernel / micro-VMM where the boot is the proof.
  timestamp: 2026-07-09T00:00:00Z
  status: active
  diataxis: explanation
  -->
  ```

  This is a documented, deliberate deviation from OKF for exactly one file
  per repo; the OKF-canonical entry point with conformant frontmatter is
  `docs/index.md`.
- **`docs/index.md` vs GitHub folder UX:** GitHub auto-renders `README.md`
  in a folder view, not `index.md`. Convention: `docs/index.md` is the
  canonical OKF index; `docs/README.md` is a two-line stub pointing at it.
  Folder indexes inside `docs/` (`proposals/index.md`, `research/index.md`)
  follow the same pattern only if click-through UX matters there.

---

## 4. The house status ladder → OKF `status`

Yuva's proposals already carry a precise, honest status vocabulary. The
4-value OKF `status` is a machine-readable projection of it; the `stage`
field carries the house token so no honesty is lost:

| House status (verbatim class) | `status` | `stage` (example) |
|---|---|---|
| `PROPOSAL Vn (research-first; nothing landed)` | `draft` | `proposal-v2-nothing-landed` |
| `DESIGN ONLY — BRAIN-gated` / operator-gated design | `draft` | `design-only-brain-gated` |
| `PLAN` approved, awaiting operator execution | `active` | `plan-not-executed` |
| `STAGE A LANDED` (+ deviations banner; stage B a named successor) | `locked` | `stage-a-landed` |
| `FROZEN` / `NORMATIVE SPEC` / `All [DECISION]` | `locked` | `frozen` / `normative` / `all-decision` |
| `NORMATIVE-SHAPE SPEC, runtime GATE DEFERRED` | `locked` | `normative-shape-runtime-deferred` |
| Promoted to a spec; retained as rationale + adversarial-review record | `superseded` (+ `superseded_by:`) | `rationale-record` |
| Canonical tracked doc, maintained (roadmaps, backlog, index) | `active` | `complete-ci-green` where true |
| Point-in-time plan whose work has since landed | `superseded` or `locked` | `executed` / `historical` |

Lifecycle of a proposal: `draft` while open → landing banner added in the
landing PR → `locked` (append-only afterwards; a new decision is a NEW doc
with `supersedes:`).

---

## 5. Worked examples

### 5.1 A proposal (Design Decision / ADR) — `docs/proposals/boot-profiles.md`

```yaml
---
type: Design Decision
title: Boot profiles — substrate vs agent as a real execution gate
description: >-
  yuva.profile=substrate|agent (default agent) as an execution+admission
  gate: a substrate boot provably does not run and cannot admit the agent
  organs (negative witness census). Stage A landed 2026-07-08 with recorded
  deviations; stage B (genuine compile-out) is a named successor, not
  blocked on.
tags: [adr, sovereignty, boot-profiles]
timestamp: 2026-07-08T00:00:00Z
status: locked
stage: stage-a-landed
diataxis: explanation
---
```

### 5.2 A normative spec (Reference) — `docs/spec/yuva-abi-v1.md`

```yaml
---
type: Reference
title: Yuva↔agent ABI v1 — the normative contract
description: >-
  The versioned, agent-agnostic contract across two planes (M11 numbered
  capability dispatch 0..=32; wire magics 0x5956..0x5959), enforced in-kernel
  by caps::abi_registry_selfcheck (fail-closed on drift). RFC 2119. Stage A:
  the version token is a discovery label, NOT a gate; extraction and
  negotiation are named successors.
tags: [spec, abi, sovereignty, verification]
timestamp: 2026-07-08T00:00:00Z
status: locked
stage: normative-stage-a
diataxis: reference
supersedes: ../proposals/yuva-abi.md
---
```

…and the proposal it promotes gains, in the same PR:

```yaml
status: superseded
stage: rationale-record
superseded_by: ../spec/yuva-abi-v1.md
```

### 5.3 The roadmap — `docs/ROADMAP-V2.md`

```yaml
---
type: Roadmap
title: Yuva v2 roadmap — the agent-native milestone chain
description: >-
  The canonical tracked milestone chain (M5→M18 complete, plus the follow-on
  tail through M38/M39) with executable Definitions-of-Done as exact serial
  markers. The boot transcript, not this file, is the authoritative
  completion record.
tags: [roadmap, kernel]
timestamp: 2026-07-09T00:00:00Z
status: active
stage: m0-m39-complete-ci-green
diataxis: reference
---
```

### 5.4 A README (repo root — exempt form, HTML comment)

See §3. The comment block carries the same keys; the visible page stays a
designed hero. The `description` obeys §2 verbatim — mock stays "mock",
dormant stays "dormant".

---

## 6. Diátaxis + type assignment — the existing yuva corpus

The full mapping for the current tree (82 markdown files under `docs/` — one
of them the generated manifest inside the exempt `research/raw/` — plus the
root docs). Stage 1 applies the starred rows; the rest is the tracked tail
(§8).

### 6.1 Top-level `docs/` (20 files) — all stage 1 ★

| Doc | `type` | `diataxis` | `status` / `stage` |
|---|---|---|---|
| VISION.md | Explanation | explanation | active |
| SOVEREIGNTY.md | Design Decision | explanation | locked / all-decision |
| ARCHITECTURE.md | Architecture | explanation | active / design-plus-as-built-map |
| ROADMAP-V2.md | Roadmap | reference | active / m0-m39-complete-ci-green |
| MILESTONES.md | Roadmap | reference | active |
| SOVEREIGNTY-ROADMAP.md | Roadmap | explanation | locked / all-decision |
| SOVEREIGNTY-L2-ROADMAP.md | Roadmap | reference | active / aarch64-first-resolved |
| BACKLOG.md | Roadmap | reference | active |
| KERNEL-FOUNDATION-SPEC.md | Design Decision | reference | locked / all-decision |
| MEMORY-SPEC.md | Architecture | explanation | draft / v1-planning-spec |
| AGENTS-SPEC.md | Architecture | explanation | draft / v1-planning-spec |
| SELF-IMPROVEMENT-SPEC.md | Architecture | explanation | draft / v1-planning-spec |
| RESEARCH-REPORT.md | Explanation | explanation | locked / planning-phase-basis |
| OPEN-QUESTIONS.md | Reference | reference | active |
| PROCESS.md | Explanation | explanation | locked / retrospective-audit |
| LANGUAGE-AND-STANDARDS.md | Standard | reference | locked / all-decision |
| BENCHMARKS.md | Reference | reference | active + `maintained_by: .claude/skills/tabos-milestone` |
| assumptions.md | Reference | reference | active / residual-trusted-base |
| TRY-IT.md | How-to | how-to | active |
| RUN-THE-HELLO.md | Runbook | how-to | active / operator-gated-lane |

Note the SPEC distinction the index must teach: `docs/*-SPEC.md` are the
2026-06 planning-phase DESIGN specs (explanation-heavy, `[DECISION]/
[PROPOSAL]/[OPEN]`-marked, partially realized — ARCHITECTURE.md carries the
as-built map); `docs/spec/*` are the FROZEN normative contracts. Same word,
two shelves.

### 6.2 `docs/spec/` (3 files) — all stage 1 ★

| Doc | `type` | `diataxis` | `status` / `stage` |
|---|---|---|---|
| yuva-abi-v1.md | Reference | reference | locked / normative-stage-a |
| yuva-abi-negotiation-v1.md | Reference | reference | locked / normative-shape-runtime-deferred |
| corpus-format-v1.md | Reference | reference | locked / frozen |

### 6.3 `docs/proposals/` (24 files) — index + 6 files stage 1 ★, tail stage 2

All are `type: Design Decision`, `diataxis: explanation` — the house
research-first proposal IS this project's ADR form (proposal → adversarial
review → amendments → landing banner → retained forever). Status per §4:

- ★ `forward-plan.md` — active / plan-research-first
- ★ `extraction-plan.md` — active / plan-not-executed
- ★ `model-path-phase2.md` — draft / design-only-brain-gated
- ★ `M39-experience-corpus.md` — per its landing state at adoption time
- ★ `yuva-abi.md` — superseded / rationale-record → `spec/yuva-abi-v1.md`
- ★ `boot-profiles.md` — locked / stage-a-landed
- Tail (stage 2): M20…M33, M38, aL2.4b, industrial-boot,
  M27-hal-implementation-plan — landed ones `locked / stage-x-landed`,
  each with its landing banner already in-body.

The new `docs/proposals/index.md` is a LEDGER table
(proposal | status | stage | landed PR | marker | superseded_by) — it gives
most of the tail's navigational value before the tail is enrolled.

### 6.4 `docs/plans/` (15 files incl. INDEX.md) — stage 2

`type: Roadmap`, `diataxis: reference`, plus INDEX.md `type: Index`. These
are point-in-time execution plans (2026-06-08, pre-rename era). Honest
labeling matters more than speed here: executed plans get
`superseded`/`stage: executed`; the x86 L2 plans blocked on the nested-VMX
substrate stay `draft`/`stage: operator-gated-substrate`. The BACKLOG.md
status-update banner is the freshness source; plans/INDEX.md gets a
banner pointing at it rather than a rewrite.

### 6.5 `docs/research/` (19 files + raw/) — stage 2

`type: Explanation`, `diataxis: explanation`, tags `[research, literature]`,
`status: locked / point-in-time-literature`. The two position papers
(`cogi-cognitive-architecture.md`, `trinity-coordinator-analysis.md`) are the
same type with tags `[research, position]`. `research/raw/` is immutable
provenance — exempt (§2.7); it holds the JSON substrate plus one generated
implementation manifest (`m12-impl-manifest.md`), which stays exempt with it.

---

## 7. `docs/index.md` — the progressive-disclosure entry point

Requirements (the stage-1 index ships alongside this standard):

1. **Front section: "start here" in three reading paths** —
   - *Evaluator/skeptic (15 min):* README → TRY-IT (watch it boot) →
     assumptions.md (what is NOT proven) → spec/yuva-abi-v1.md (the
     contract). The skeptic path leads with the claim boundary — that IS
     the product.
   - *Contributor:* CONTRIBUTING → PROCESS → ROADMAP-V2 → the open
     proposals (forward-plan first).
   - *Operator:* TRY-IT → RUN-THE-HELLO → forward-plan §gates → BACKLOG.
2. **Shelves by OKF type** (Understand / Operate / Contracts / Plan of
   record / Decision records / Research library) — each shelf a table with
   one-line honest descriptions, matching §6.
3. **The knowledge graph, drawn explicitly.** The docs already form a
   citable graph; the index names the edge types once so every doc doesn't
   have to:
   `research/X-literature.md` —grounds→ `proposals/X.md` —promoted-to→
   `spec/X-v1.md` —enforced-by→ code + CI lane —witnessed-by→ the boot
   marker —tracked-in→ `ROADMAP-V2.md` row. Plus the standing edges:
   `assumptions.md` ←cited-from— silicon glue
   (`arch/aarch64/stage2.rs`), and `BACKLOG.md` —status-source-for→
   `plans/`. The doc chain deliberately terminates in an executable
   witness, not prose ("the boot is the proof").
4. **Intra-folder links only** (OKF portability): `docs/` links stay
   relative inside `docs/`; links to code are plain code spans with
   repo-relative path + line (`crates/tb-hal/src/caps.rs:189-264`), the
   citation idiom the proposals already use.
5. **Freshness honesty:** the index states its own `timestamp`, states that
   `status`/`stage` fields are maintained at landing time, and points to the
   BACKLOG banner as the live status source for plans.

---

## 8. Staged adoption — do not boil the ocean

### Stage 1 — NOW (one docs-only PR, ~33 files, zero body rewording)

1. Land this file at `docs/DOCUMENTATION-STANDARD.md`.
2. Land `docs/index.md` (+ two-line `docs/README.md` pointer stub).
3. Add frontmatter to the 20 top-level docs (§6.1), the 3 specs (§6.2), and
   the 6 starred proposals + the new `docs/proposals/index.md` ledger.
4. Root docs: `BUILD.md`, `CONTRIBUTING.md`, `SECURITY.md` get frontmatter;
   `README.md` gets the invisible OKF comment block only (§3) — the README
   rewrite itself is a separate workstream and MUST NOT be coupled to this
   PR.
5. CI lint `scripts/check-docs-frontmatter.sh`: for a PINNED enrolled list
   (exactly the stage-1 files), assert parseable YAML frontmatter, required
   keys present, enum membership for `type`/`status`/`diataxis`, ISO-8601
   `timestamp`, and `superseded_by` present when `status: superseded`.
   Fail-closed on the enrolled list, silent on the tail — the same
   pinned-census idiom as `scripts/witness-census.txt` and the pinned Kani
   harness count. The lint checks STRUCTURE only; it never rewords claims.
6. Acceptance: docs-only diff; both run scripts' marker greps untouched;
   every enrolled file passes the lint; **zero dead relative links among
   stage-1 files** — the companions `docs/index.md` links to
   (`docs/proposals/index.md` ledger, `docs/README.md` stub) exist nowhere
   in the tree today, so steps 2–3 MUST land them in this same PR, not
   defer them; `git diff --stat` shows zero non-docs changes.

### Stage 2 — tracked follow-up (the tail; a BACKLOG.md row, not a blocker)

- Frontmatter for the remaining ~18 proposals, the 15 plans files (incl.
  INDEX.md), and the 19 research docs — a scripted pass drafts each block
  FROM the doc's existing Status header, human-reviewed in small batches;
  enroll each batch into the lint census.
- `docs/research/index.md`; plans freshness banner (§6.4); consider
  `plans/INDEX.md` → `index.md` rename (git mv, history-preserving).
- Reconcile stale cross-doc facts found during the pass by pointing at the
  live source, not rewording history (e.g. plans/INDEX.md still carries its
  pre-rename title; VISION §5 covers the name history).

### Stage 3 — family rollout

- **cogi:** no `docs/` exists yet. Adopt at birth: README comment block
  now; the first real doc lands together with `docs/index.md` and this
  standard vendored or linked. Nothing to migrate — the cheapest possible
  adoption.
- **namzu:** the docs site already carries near-OKF frontmatter
  (`title`, `description`, `last_updated`, `status: current`,
  `related_packages` — fumadocs-style with `meta.json` navigation).
  Adoption is ADDITIVE: add `type`, `diataxis`, `timestamp`, `tags`; map
  `status: current` → `active`; KEEP `last_updated` and `related_packages`
  as custom fields. Do not touch the README thesis. Verify the docs-site
  build in CI before landing (unknown frontmatter keys are expected to be
  ignored by fumadocs-class toolchains — ASSUMED, verify with the build).
- Each repo vendors this standard (or links the canonical copy) so agents
  apply it locally; `cogitave/yuva` hosts the canonical copy.

---

## 9. Workflow (every doc you write or maintain)

1. Pick the OKF `type` + Diátaxis discipline FIRST; write to that
   discipline; split the file if it mixes modes.
2. Add the frontmatter block with a real timestamp; inherit the body's
   honest qualifiers into the description — never strengthen them.
3. Cross-link related docs (relative, intra-folder); update the shelf table
   in `docs/index.md`.
4. On replacement: `status: superseded` + `superseded_by:` on the old doc,
   `supersedes:` on the new — never delete.
5. Commit the doc in the same PR as the change it describes; flip
   `status`/`stage` in the landing PR, alongside the landing banner.

---

## 10. References

- OKF v0.1 — Google Cloud knowledge-catalog:
  <https://github.com/GoogleCloudPlatform/knowledge-catalog/tree/main/okf>
  (frontmatter with `type` required; minimally opinionated; custom fields
  permitted; reserved fields never removed).
- Diátaxis — <https://diataxis.fr> (tutorial / how-to / reference /
  explanation; one discipline per document).
- Docs-as-code — Write the Docs guide:
  <https://www.writethedocs.org/guide/docs-as-code/>.
- RFC 2119 — key words for requirement levels (already the convention in
  `docs/spec/yuva-abi-v1.md`).
- ADR practice (records are immutable; superseded, never deleted) —
  <https://adr.github.io/>; matches the house "demoted-not-deleted"
  discipline.
- In-house precedents this standard formalizes: the `> Status:` header
  convention (every top doc), the proposal status ladder
  (`docs/proposals/*.md`), the pinned-census fail-closed lint idiom
  (`scripts/witness-census.txt`, `EXPECTED_HARNESSES_TOTAL`), and the
  authority order of "the boot is the proof" (README §"The boot is the
  proof").
