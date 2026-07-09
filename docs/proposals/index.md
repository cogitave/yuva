---
type: Index
title: Proposals — the milestone decision record
description: "Progressive-disclosure entry point for Yuva's design proposals (ADRs), grouped by lifecycle."
tags: [proposals, adr, index, okf]
timestamp: 2026-07-09T00:00:00Z
status: active
diataxis: explanation
---

# Proposals

Each proposal is an architecture/design decision record (ADR) for one milestone or plan. Landed proposals are `locked` — the decision is final and implemented; forward plans are `active` or `draft`. A superseded proposal keeps its file and links forward, never deleted.

## Landed milestones

- [M20 — Durable Persistence](M20-durable-persistence.md) — makes per-agent memory outlive a reboot via virtio-blk
- [M21 — Verified fixed-point policy seam for the M17 forget/demote decision](M21-kan-policy.md) — frozen additive scorer inside proven envelope, shipped dormant
- [M22 — Verified Memory Provenance](M22-memory-provenance.md) — Append-only hash-chain ledger, provable deletion, tamper-evidence
- [M23 — Verified experience codec + counterfactual shadow-recording](M23-experience-codec.md) — DATA-layer log of forget decisions, evaluation deferred
- [M24 — Honest Oracle, Durable Spill, and Gated Bake-off](M24-honest-gate.md) — restores off-policy overlap, refuses activation on synthetic traces
- [M25 — Verified operator transcript (the exogenous-oracle channel)](M25-operator-transcript.md) — keyless serial TX surfacing borderline decisions to a human
- [M26 — Verified EL2 exit-telemetry producer](M26-exit-telemetry.md) — guest exits folded into experience stream, producer-only
- [M27 — HAL Implementation Plan (aarch64 EL2 Two-VMID CNTHP Sovereign Scheduler)](M27-hal-implementation-plan.md) — cooperative HVC-yield floor before real timer preemption
- [M27 — Two-VMID Sovereign Time-Partition Scheduler](M27-sovereign-scheduler.md) — two VMIDs off EL2 timer, decisions folded to ledger
- [M28 — The operator inbound channel (opframe RX + enrolled-key activation)](M28-operator-inbound.md) — Closes the learning loop with authenticated human command
- [M29 — the KEYED-CRYPTO MAC (verified khash leaf)](M29-crypto-mac.md) — one verified BLAKE2s primitive, three consumers, security assumed
- [M30 — Verified Inference Transport](M30-infer-transport.md) — host-keyed echo channel that structurally excludes loopback evidence
- [M31 — the real Anthropic adapter (inferwire byte framing + live lane)](M31-real-infer.md) — deterministic mock plus liveness-proven, injection-hardened live LLM round-trip
- [M32 — the local inference daemon](M32-local-infer.md) — vendored llama.cpp as grep-locked, retirement-scheduled sovereignty debt
- [M33 — Provenance Lineage (public-verify / private-sign prov head)](M33-prov-lineage.md) — in-house LMS verify leaf, signed persisted head, DSSE attestation
- [M38 — the Conductor (Verifier-gated organ scheduler)](M38-conductor.md) — verified hand-written policy orchestrates mock organs, attested decisions
- [M39 — Phase-1 Experience Corpus (dataset moat)](M39-experience-corpus.md) — frozen format spec, verified provenance-skeleton codec, no training
- [aL2.4b — Full M0..M28 Kernel as the EL1 Guest](aL2.4b-full-kernel-guest.md) — the missing kernel-guest object that gates M34

## Contracts & standards

- [Yuva-ABI — the versioned, agent-agnostic contract](yuva-abi.md) — proposal to version-stamp existing agent-Yuva ABI seams

## Forward plans

- [Boot Profiles — substrate vs agent execution gate](boot-profiles.md) — organs skipped and denied at runtime, still in-image
- [Extraction Plan — moving the agent's host-side core to cogitave/cogi](extraction-plan.md) — sequences the host-binary move, resident agent stays
- [Industrial Boot — human-meaningful boot presentation over machine-truth markers](industrial-boot.md) — opt-in systemd-style readout; default-raw keeps CI byte-identical
- [Model-path Phase 2 — Cogi's own model (corpus→QLoRA→GGUF, DESIGN ONLY)](model-path-phase2.md) — design-only fine-tune pipeline, operator-gated, honest ~7B ceiling
- [Yuva/Cogi Forward Plan — the phased road to a learning, model-bearing agent-OS](forward-plan.md) — Sequences eight work tracks; corpus first, model gated
