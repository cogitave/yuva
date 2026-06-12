# Yuva Process and Methodology Document

> Status: v1.0 · Purpose: an **auditable record** of the process the planning phase actually followed, an honest mapping against two recognized frameworks (**Design Thinking**, **Microsoft Success by Design**), and the closing of gaps.
> Framework sources: [IxDF — What is Design Thinking](https://www.interaction-design.org/literature/topics/design-thinking) · [Microsoft Learn — Success by Design](https://learn.microsoft.com/en-us/dynamics365/guidance/implementation-guide/success-by-design)
> Related: [README](../README.md) · [VISION](VISION.md) · [OPEN-QUESTIONS](OPEN-QUESTIONS.md)

---

## 0. Honesty Note

Until now this project followed an **implicit** methodology (research → multi-vote verify → synthesize → adversarial review → correct). Until this document was written, the process had never been *explicitly* mapped to any standard framework. The mappings below are a retrospective honest audit: what aligned, what was missing, how the gaps are being closed.

## 1. Actual Process Record (auditable)

| # | Step (2026-06-06) | Method | Output / evidence path |
|---|---|---|---|
| 1 | Scope clarification | 3 structured questions (architecture layer, model assumption, output format) → Arda's decisions | [VISION](VISION.md), memory record |
| 2 | Wave 1: deep-research | 105 subagents: 5 search axes → 23 primary sources → 115 claims → 3-vote adversarial verification (partial due to API failure) | [`verified-wave1.json`](../research/raw/verified-wave1.json) (3 confirmations) |
| 3 | Wave 2: verify + expand | 35 subagents: source-grouped re-verification of 22 claims (9×3 votes) + 8 domain investigations | [`verified.json`](../research/raw/verified.json) (20+2), `expand-*.json` (100 findings) |
| 4 | Naming | vetting of 24+7 candidates → 7/7 + most eliminated → **TABOS code name** (Arda; the final name **Yuva** was decided 2026-06) + post-decision vetting | [`expand-naming.json`](../research/raw/expand-naming.json), [`naming-round2.json`](../research/raw/naming-round2.json), [`naming-tabos.json`](../research/raw/naming-tabos.json) |
| 5 | Document set authoring | 8 documents, marked with [DECISION]/[PROPOSAL]/[OPEN] status | `README` + `docs/*` |
| 6 | Adversarial review | 3 independent reviewers (claim fidelity / internal consistency / completeness) → 1 critical + 14 major + 9 minor → **29 corrections** applied | review output workflow `wf_f1a0e71d`; corrections in the documents |
| 7 | Code name correction | "TABOS = code name, no hardcoding, no reservation" (Arda) → 9 corrections | README naming note, OPEN-QUESTIONS §G |
| 8 | Language & industry standards research | 7 domains + 2-vote verification of selected claims (**in progress**) | workflow `wf_2c78a514` → LANGUAGE-AND-STANDARDS.md (pending) |
| 9 | Process audit | This document: framework mapping + personas + risk register + gates | `PROCESS.md` |

## 2. Design Thinking Mapping

IxDF definition: *"non-linear, iterative process... five phases: Empathize, Define, Ideate, Prototype, Test"* — for wicked problems. Designing an agent-native OS is exactly a wicked problem.

| Phase | Our counterpart | Status | Gap → action |
|---|---|---|---|
| **Empathize** | Literature + gap analysis of existing systems (E2B/Letta/AIOS); agents' "pains" (context overflow, memory loss, torn-state) from research data | ⚠️ Partial | **No empathy with a real user** — no interviews with agent developers conducted; personas/JTBD drafted in this document (§4), validation in [OPEN-QUESTIONS §H](OPEN-QUESTIONS.md) |
| **Define** | [VISION](VISION.md): one-sentence definition, gap analysis, 5 principles, success criteria | ✅ | — |
| **Ideate** | Alternatives were genuinely generated and compared: 4 kernel approaches (microkernel/unikernel/exokernel/microVM → hybrid synthesis), 38 name candidates, memory design space (5 systems) | ✅ | Alternative *architectural syntheses* (a plan B/C beyond the hybrid) were not explicitly documented — accepted deviation: research converged on a single synthesis, rationale in ARCHITECTURE §1 |
| **Prototype** | None (deliberate: planning phase is "docs only") | 🔜 Phase 1 | Gate G1 (§6) defines the prototype entry criteria |
| **Test** | For the documents: adversarial review (3 reviewers) = "test the artifact"; for the system: VISION §7 measurable criteria | ⚠️ Partial | System testing in Phase 1; **user testing** (persona validation) not done → §H |
| **(Non-linearity)** | Review findings → loop back into the documents (29 corrections); naming decision → two rounds of iteration | ✅ | — |

## 3. Success by Design Mapping

Microsoft's definition: 5 methodology-agnostic phases (**Discover, Initiate, Implement, Prepare, Operate**) + reviews (**Solution Blueprint Review** → **Implementation Reviews** → **Go-live Readiness Review**) + finding taxonomy (**Assertions / Risks / Issues**) + **success measures** (R/Y/G tracking).

### 3.1 Phase mapping

| SbD phase | Yuva counterpart | Status |
|---|---|---|
| **Discover** | Scope clarification + three research waves (requirement discovery = literature + existing-system gaps) | ✅ Completed |
| **Initiate** | Document set = "high-level solution design"; workflows = [VISION §8 phases](VISION.md) | ✅ This phase |
| **Implement** | Phases 1-3 (prototype → isolation → multi-agent) | 🔜 |
| **Prepare** | Before Phase 4: public release preparation (name finalization, branding, SBOM/signing) | 🔜 |
| **Operate** | Post-release operation + telemetry | 🔜 |

### 3.2 Review mapping

- **Solution Blueprint Review** ↔ our 3-reviewer adversarial review (`wf_f1a0e71d`). SbD treats this as "mandatory" — we applied it too; the difference: ours with automated agents, SbD's with a human architect. **One more human-eye pass is recommended at Gate G0** (Arda + a second technical eye if available).
- **Implementation Reviews** ↔ Gate G1-G2 audits (§6): a topic-specific deep dive at each phase entry (data model ↔ MEMORY-SPEC; security ↔ capability model; integration ↔ bridges; ALM/test ↔ CI+fuzzing strategy).
- **Go-live Readiness Review** ↔ Gate G3 (public release).

### 3.3 Finding taxonomy mapping

| SbD | Our counterpart |
|---|---|
| **Assertions** (things done right) | Verified [DECISION] items + the review's "high fidelity overall" findings |
| **Risks** (negative if left unmitigated) | Review **major** findings + [OPEN] markers → §5 Risk Register |
| **Issues** (currently causing negative impact) | Review **critical** findings (GA formula error — fixed) |

### 3.4 Success measures

SbD wants "7 categories, 30+ measures, R/Y/G". Our counterpart is the 6 measurable criteria in [VISION §7](VISION.md) — but **no tracking mechanism was defined**. Decision: this table is updated at every gate (for now in this document, from Phase 1 onward in a separate SUCCESS-MEASURES.md):

| Measure | Target | Status (2026-06-06) |
|---|---|---|
| Agent spawn cold start | <50 ms | ⚪ Not yet measurable (depends on risk R3) |
| Atomic checkpoint (zero torn-state) | design guarantee | 🟡 Designed, not verified |
| Memory default p95 retrieval | <200 ms | 🟡 Literature-proven (Mem0), not measured by us |
| Quota efficiency (cache-aware) | ≥3× effective work | 🟡 Arithmetically proven, not implemented |
| Sleep-time payback | ≥2× compute reduction | 🟡 Literature-proven (Letta ~5×) |
| Ambient authority | zero | 🟢 Design invariant (consistent across every spec) |

## 4. Personas and JTBD (draft — to be validated, §H)

Yuva's unique situation: **the primary "user" is not human.** Four personas:

| Persona | Who | JTBD (job-to-be-done) | Counterpart in Yuva |
|---|---|---|---|
| **P1 — The agent itself** | The OS's primary citizen | "Carry out my task without context overflow, without losing my memory, knowing exactly what my authority is; and be able to escalate when stuck" | Memory guarantee, T0 registers, impasse traps, model-readable errors |
| **P2 — Agent developer** | Engineer writing agents/skills | "Build persistent, secure, portable agents without writing framework code; and be able to debug behavior" | Default memory, .taf image, `cat /agent/<id>/trace`, WIT-typed skill ABI |
| **P3 — Operator/administrator** | Person/organization running the fleet | "Operate N agents within budget and authority limits, auditably; gate irreversible operations behind approval" | Budget capabilities, consent gate, audit/lineage, session management |
| **P4 — Security/compliance officer** | The party bearing the risk | "Be able to prove what an agent can access; know the blast radius on a breach; meet record-keeping obligations" | Enumerable authority set at spawn time, static component-graph analysis, tombstone + privileged delete |

## 5. Risk Register (SbD format)

Score = Impact (1-3) × Likelihood (1-3). Owner: for now all Arda.

| ID | Risk | I | L | Score | Mitigation | Source |
|---|---|---|---|---|---|---|
| R1 | If the LLM-text ↔ capability binding (confused-deputy) cannot be solved, the security promise stays groundless | 3 | 2 | **6** | B-P0 spec-freeze gate; model-checking in the prototype | [OPEN-Q §B](OPEN-QUESTIONS.md) |
| R2 | Scope breadth × single-person bus-factor | 3 | 3 | **9** | Phase discipline; no code beyond P0; early community/partner | VISION §8 |
| R3 | The <50 ms spawn target leans on a production-unproven unikernel path | 2 | 2 | 4 | First measurement in Phase 1; if it falls short, retreat to Firecracker+minimal-guest | A-P1 |
| R4 | No OS-lifetime memory benchmark → wrong defaults | 2 | 3 | **6** | Own eval harness (C-P1); raw-log + re-indexing always possible | MEMORY-SPEC §8 |
| R5 | Self-improvement cost (DGM ~22k USD/run precedent) | 2 | 3 | **6** | Staged eval (10→50→200); BULK quota; defaults weight-free | SELF-IMP §7 |
| R6 | Volatility of the core protocols (MCP tasks experimental; ACP consolidation uncertain) | 1 | 3 | 3 | The bridge architecture absorbs it; kernel ABI is neutral | F-P1 |
| R7 | Memory write-path LLM dependency → cost/latency bloat | 2 | 2 | 4 | Local 1B enricher measurement (C-P1); async consolidation | MEMORY-SPEC §4 |
| R8 | Goodhart: cross-generation security drift is not measured | 3 | 2 | **6** | Hidden evaluators (DECISION); longitudinal telemetry design (E-P2) | SELF-IMP §9 |
| R9 | Optimizing for the wrong user before persona validation | 2 | 2 | 4 | §H interviews; Phase-1 demos with real developers | this document §4 |
| R10 | If the code name lives too long it becomes a de facto brand (unreserved) | 1 | 2 | 2 | Make the naming decision by the end of Phase 2; monitor | §G |

## 6. Review Gates

| Gate | SbD analog | Entry criteria |
|---|---|---|
| **G0 — Spec Freeze** | Solution Blueprint Review (mandatory) | P0×8 closed · persona validation done (§H) · LANGUAGE-AND-STANDARDS incorporated · human-eye blueprint review · risk register current |
| **G1 — Prototype entry** | Implementation Review #1 | ABI draft frozen · test strategy + CI + fuzzing plan · success measures under tracking |
| **G2 — Phase-2 entry (isolation)** | Implementation Review #2 (security) | Independent security review of the capability model · R1 mitigation proven |
| **G3 — Public release** | Go-live Readiness Review (mandatory) | Final name + brand search · SBOM + signed release · documentation complete · support/issue process defined |

## 7. Process Debt (output of this audit)

1. ~~Methodology mapping not documented~~ → this document (closed).
2. **Persona validation** — interviews with real agent developers/operators → [§H P1](OPEN-QUESTIONS.md).
3. **Success-measure tracking cadence** — update at every gate; in Phase 1 a separate file + automation → [§H P2](OPEN-QUESTIONS.md).
4. Human-eye blueprint review (G0 criterion) — in addition to the automated review.
5. Incorporating the language/standards research results into ARCHITECTURE (in progress, `wf_2c78a514`).