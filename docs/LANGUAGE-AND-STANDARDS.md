# Yuva Language and Industry Standards Decision

> Status: v1.0 · Question: *"What language do you write an agent-native kernel from scratch in; what are serious organizations actually doing in 2026?"*
> Method: 7-area research (32 subagents) + 2-vote adversarial verification of 12 decision-critical claims.
> Basis: [`lang-research.json`](research/raw/lang-research.json) · [`lang-verified.json`](research/raw/lang-verified.json) · Related: [ARCHITECTURE](ARCHITECTURE.md) · [PROCESS](PROCESS.md) · [OPEN-QUESTIONS](OPEN-QUESTIONS.md)

---

## 0. Decision Summary **[DECISION]**

Per-layer **language allowlist** (Fuchsia's "per-language policy" model, adapted to Yuva):

| Layer | Language | Rationale (one line) |
|---|---|---|
| **Frozen capability microkernel** (≤15 kSLOC) | **Rust** (`no_std`), framekernel pattern | All `unsafe` in a small foundation crate; `#![forbid(unsafe_code)]` in the upper layers |
| **Node image / scheme daemons** (`memory:`,`model:`,`tool:`,`agent:`...) | **Rust** (`tokio`, `cap-std`) | One toolchain, one security story, crate sharing with the VMM ecosystem |
| **WASM nanoprocess host** | **Rust** (Wasmtime) | Component Model/WIT host bindings are first-class only in Rust |
| **VMM supervision** (Firecracker/KVM) | **Rust** (rust-vmm crates) | Substrate is already Rust; HTTP-over-UDS control is language-independent but crate compatibility is in Rust |
| **Protocol bridges** (`mcp:`,`a2a:`) | **Rust** (official MCP/A2A Rust SDKs) | In 2026 both have an official Rust SDK |
| **Local inference engines** | **Isolated C/C++** (behind a llama.cpp `-sys` crate) **or** network boundary (vLLM/SGLang = Python HTTP server) | Engines do NOT enter the node image or the kernel — driver daemon or HTTP client |
| **Remote inference bridge (HTTPS/TLS)** **[DECISION]** | **Rust HOST process only** (`rustls` + `ureq` class; `reqwest` acceptable) | TLS/HTTPS/network code NEVER enters the kernel, the guest image, or the `no_std` workspace — the bridge is a host peer on the M30 channel; the guest sees only MAC'd inferwire frames (M31 proposal §11) |
| **Signature scheme (prov lineage)** **[DECISION]** | **LMS** (RFC 8554, in-house, SHA-256 leaf) — VERIFY-in-kernel / SIGN-host-side | Ed25519/curve crypto REJECTED (the `2^255-19` field arithmetic is the documented CBMC SAT-explosion case — Kani-INFEASIBLE; every published curve25519 FV uses Coq/F\*/Jasmin deductive synthesis, never bounded model checking); SPHINCS+/SLH-DSA REJECTED as the kernel-verify primitive (verify ≈ 100× khash cost); LMS is a pure hash chain, in-house from the RFC exactly as M29 implemented BLAKE2s. `conformance=RFC8554` via the D2 second SHA-256 leaf (RFC 8554 pins SHA-256; the house BLAKE2s cannot keep RFC conformance) — official RFC 8554 Appendix F Test Case 1 vector verifies (M33 proposal §1/§4) |
| **Developer SDKs / CLI / tooling** | **Rust** (core) + **TypeScript/Python** (ecosystem reach) | GC'd languages allowed in the outer SDK layer |

**In one sentence:** Yuva is **Rust** from kernel to protocol bridges; C is confined only in vendored llama.cpp behind a driver daemon; Python/TypeScript live only in the outermost SDK ring and in network-bounded inference engines; remote-API TLS lives only in a Rust host bridge process, never the kernel. This is a one-to-one application of the 2024-2026 industry consensus (Google, Microsoft, AWS, ISRG, Oxide).

---

## 1. Why Rust — Production Evidence **[verified: 2-0]**

This is not "Rust hype"; it is measured production data:

- **Android memory-safety trend** [Google Security Blog]: memory-safety vulnerabilities' share of the total **76% (2019) → 35% (2022) → 24% (2024)** — while the industry norm is ~70%. Absolute count **223 (2019) → 85 (2022)**. Cause: ~2019 shift of NEW development to a memory-safe language; in Android 13 ~21% of new native code is Rust, ~1.5M lines of Rust in AOSP, and **zero memory-safety vulnerabilities in Rust code to date**. 86% of critical vulnerabilities, 89% of remotely exploitable ones, and 78% of real-world exploits were in the memory-safety class — **the class you eliminate is the worst class.** Additional finding: vulnerabilities decay exponentially (half-life); 5-year-old code has 3.4-7.4× lower vulnerability density than new code → **new-code safety beats a wholesale rewrite.**
- **Rust in production in hyperscaler kernels:**
  - *Linux*: Rust merged in v6.1 (Dec 2022); the Android **Binder** driver was rewritten in Rust and landed in v6.18-rc1; the **Nova** GPU driver is mainline [rust-for-linux.com] *(verified: 2-0)*. Greg Kroah-Hartman: *"A lot of the bugs caused by those stupid little corner cases in C are completely gone in Rust — use-after-free, error-path cleanup, forgetting to check a return value."*
  - *Windows*: the GDI REGION type was ported to Rust (`win32kbase_rs.sys`, in production in Win11 24H2); DWriteCore is ~152k lines of Rust, glyph shaping 5-15% faster. Azure CTO Russinovich (2022): *"It's time to halt starting any new projects in C/C++ and use Rust."*
  - *AWS Firecracker + Google crosvm*: Yuva's **exact target substrate** — both are Rust VMMs; Firecracker handles "trillions of requests per month" on AWS Lambda/Fargate.

**An important engineering caveat** (from the Windows GDI finding): a bounds-check `panic` in Rust deliberately produced a BSOD; MSRC called this "correct behavior" but Check Point objected that "a failing security check should not crash the system." → **Yuva standard:** the evaluator-holding microkernel MUST NOT have panic-on-violation as its default availability story; design fallible APIs that return `Result` on attacker-reachable input + graceful capability-denial paths.

## 2. For the Frozen Kernel: the Framekernel Pattern **[verified: 2-0]**

The single most decision-critical source for Yuva's ≤15 kSLOC frozen kernel is **Asterinas** [arXiv:2506.03876, USENIX ATC'25]:

- A Linux-ABI-compatible **"framekernel"**: all `unsafe` Rust is confined to a small **OSTD foundation crate** (~15 kLOC order); the rest of the kernel is safe Rust → a sound, small memory-safety TCB.
- It was independently demonstrated that **15 kLOC is sufficient for a sound memory-safety TCB under a full-featured kernel** — the quantitative anchor for Yuva's ≤15 kSLOC target.
- **Mechanical policy [DECISION]:** `unsafe` only in the kernel-foundation crate; `#![forbid(unsafe_code)]` in all upper layers; the count of `unsafe` blocks is budgeted and reviewed like VeriSMo's "31 lines" discipline.

Supporting Rust-OS lineage: **Redox** (10-year Rust microkernel + scheme daemons — Yuva's exact shape, proof it can work), **Theseus** (compiler-enforced invariants), **Tock** (compile-time driver isolation, 10M devices), **Hermit** (pure-Rust unikernel, boots on Firecracker), **Google KataOS/Sparrow** (Rust userspace on top of seL4 — Yuva's exact split).

## 3. Alternatives and Why They Were Eliminated **[verified: 2-0 / 1-1*]**

| Language | Strongest real precedent | Why not the Yuva kernel |
|---|---|---|
| **Verified C** | seL4: ~10 kSLOC, Isabelle/HOL proof **down to the binary**, 0 functional bugs in 15 years | The only binary-level-proven production kernel. But: the proof is ~20 person-years, ~$362/SLOC (§5) — unrealistic for a small team; C itself gives zero safety |
| **C++** | Fuchsia/Zircon kernel | Fuchsia policy approves C++ in the kernel *(correction: the policy approves both C "including in the kernel" and C++ "across the whole tree"; it does not say "kernel C++ only")*; but Google is memory-unsafe even in NEW code; for greenfield, CISA "bad practice #1" |
| **Go** | gVisor (in production, userspace application kernel) | Biscuit [OSDI'18]: a GC'd HLL in-kernel costs **5-15% on the hot path, up to 13% of kernel CPU, a 2-3× RAM tax, GC pauses** *(verified: 2-0)*. → Go **is valid for userspace daemons**, not for the kernel |
| **Zig** | TigerBeetle | **No 1.0** (latest is 0.16, breaking changes every release); best C-FFI story but immature for a frozen safety-critical kernel; lacks Rust's borrow checker |
| **OCaml** | MirageOS (in production in Docker Desktop VPNKit!) | Memory-safe unikernel proof but GC + ecosystem narrowness; impedance with the agent/skill ecosystem |
| **Ada/SPARK** | NVIDIA (dropped C/C++, SPARK in firmware) | Strong "prove absence of runtime errors" story; but ecosystem/hiring narrowness, no WASM/agent tooling |

**Industry pattern** *(verified, cross-cutting):* serious greenfield-OS efforts converge on a **stable split**: the kernel CORE in a "production-track-record or proven" language (seL4=verified C, Zircon=C++, KataOS=seL4+Rust), GC/HLL allowed in userspace, LLM engines (Python/C++/CUDA) kept outside at the network boundary. **Yuva's architecture is already aligned with this best practice.**

## 4. Government/Industry Pressure — "Industry Standard" **[verified: 2-0, with corrections]**

The regulatory ground a greenfield OS will be measured against:

- **NSA "Software Memory Safety" CSI** (doc U/OO/219936-22, 10 Nov 2022, Ver1.1 Apr 2023): *"NSA recommends using a memory safe language when possible"*; *(correction: the exact quote is "little or no inherent memory **protection**" — not "safety")*. Of the 9 approved MSLs, **only Rust** is non-GC and suitable for a ≤15 kSLOC frozen microkernel (Go/Java/C#/Python/Swift/Ada-GC carry a runtime/GC).
- **CISA/FBI "Product Security Bad Practices"** (v1.0 Oct 2024, v2.0 Jan 2025) *(verified: 2-0)*: **a memory-unsafe language in a greenfield product = the number-one bad practice.** Since Yuva is greenfield, writing the kernel/core in Rust lets it claim **full compliance** with the strongest clause.
- **White House ONCD "Back to the Building Blocks"** (Feb 2024): of all MSLs, **only Rust** delivers the triple of "close-to-the-kernel + deterministic + GC-free" → disqualifies Go/Java/C#/Python for the microkernel.
- **DARPA TRACTOR**: targets specifically **Rust**, not a generic "an MSL," for converting all legacy C — the systems-programming target the government is pointing at.
- **EU Cyber Resilience Act** (Reg. (EU) 2024/2847, in force 10 Dec 2024) *(verified: 2-0)*: Yuva is Annex III; the VMM + WASM runtime are in the "hypervisor/container runtime" class. The 24h/72h/14d reporting line by **September 2026**, CE + Annex I compliance by **December 2027** — falls within Yuva's development window. → a machine-readable SBOM + memory-safe roadmap must be adopted **now**.
- **CISA "The Case for Memory Safe Roadmaps"** (6 Dec 2023): as a product artifact, Yuva should publish a **public memory-safe roadmap** (new-code-Rust-only date + C/C++ engine plan + CVE/CWE program).

## 5. Formal Verification — What Is Realistic? **[verified: 2-0]**

Yuva's claim that "the frozen kernel holds the evaluator" makes verification attractive; the realistic level:

- **seL4 full functional verification cost** [Klein et al., ACM TOCS 32(1), 2014]: kernel development **2.2 py**, proof **~20 py** (~$362/SLOC). → a full C+Isabelle proof of a ~15 kSLOC Yuva kernel is a **10-20 py, multi-million-dollar, 3-5 calendar-year** program. Unrealistic for a small team.
- **The Rust+Verus collapse** — VeriSMo [Microsoft, OSDI'24] *(verified: 2-0, with correction)*: the first verified confidential-VM security module (AMD SEV-SNP), Rust+Verus; functional correctness + secure information flow + confidentiality/integrity under an adversarial hypervisor; **only 31 lines of trusted unsafe Rust, ~2:1 proof:code ratio, ~6-minute CI verification** (32-core). *(correction: the source does not say "collapses the cost versus C+Isabelle"; it never mentions Isabelle — we present the comparison as a measured inference.)*
- **Early-assurance vs retrofit** *(verified: 2-0)*: design-for-assurance from day 1 (small frozen kernel, spec alongside code, a "no merge that breaks the spec" CI gate) is **~3-8× cheaper/SLOC** than retrofitting certification.

**[DECISION] Assurance tiers (as CI gates):**
1. **Tier 0 (~free):** safe Rust + **Miri** (in CI, the dynamic UB detector the Rust Project itself uses) + Safety-Critical Rust coding guidelines — catches the UB classes that dominate C kernel CVEs; RustBelt [POPL'18] provides the formal foundation.
2. **Tier 1 (weeks):** **Kani** (AWS, bounded model checking) harnesses on every `unsafe` block and protocol parser.
3. **Tier 2 (months, selective):** **Verus** (the VeriSMo pattern) for capability invariants, scheme-daemon state machines, and the WASM sandbox boundary.
- **[OPEN]** If certification-class kernel assurance is needed: building the node image **on top of verified seL4** (the KataOS/Sparrow route) is the only proven path — [OPEN-QUESTIONS §I](OPEN-QUESTIONS.md). Caveat: Rust std/core is **not yet verified** (an AWS effort is ongoing; ~7.5k unsafe functions) → the kernel and nanoprocess runtime should prefer `no_std` + a minimal auditable dependency base.

## 6. The Standards Stack — Beyond the Language **[PROPOSAL]**

"Industry standard" is not only the language; an auditable list to adopt from day 1:

| Axis | Standard | Yuva action |
|---|---|---|
| **Rust dialect** | **FLS** (Ferrocene Language Specification, transferred to the Rust Project in Mar 2025 *— correction: does not change the Reference's status, it is a supplementary spec*) + **Safety-Critical Rust Consortium** guidelines (founded 12 Jun 2024) | Pin to FLS; make the consortium guidelines the in-repo coding standard (MISRA-shaped: compliance level + documented deviation; CI-lintable) |
| **Qualified toolchain** | **Ferrocene** (TÜV SÜD: ISO 26262 **ASIL D** + IEC 61508, since Oct 2023) | If the functional-safety market is needed later, compiler qualification can be purchased (~€240-300/seat/year); the qualification documents are free to read |
| **Residual C** | **MISRA C:2025** (now current; 2023 superseded) + CERT C, static analysis (Coverity/Polyspace) | Only in vendored llama.cpp/VMM glue; behind a driver daemon |
| **Remote-API host deps** **[DECISION]** | `rustls`, `ureq` (runner-up `reqwest`), `serde_json` — host-bridge-only, nested-workspace-firewalled from the kernel's zero-dep/zero-unsafe lanes | Sovereignty-ledger status: **ACCEPTED-PERMANENT (host-bridge-confined)** — the communication pillar's cost, not closable debt; the kernel never inherits it; any widening (new dep, new process) is a new ledger row (M31 proposal §11; the deps themselves land with stage C — the live bridge — and this row is the pre-landed decision) |
| **Kernel coding discipline** | **TigerStyle** (TigerBeetle): static allocation after init, everything bounded, ≥2 assertions per function | Adapt to the ≤15 kSLOC frozen kernel (Hubris also chose static allocation) |
| **Supply chain** | **SLSA v1.0** Build L1→L3; **in-toto** provenance | Every artifact (kernel image, node image, WASM tool bundles, SDK crates/wheels) ships with provenance from hosted CI. **M33 (stage A)** lands the DSSE-PAE-shaped attestation codec (`tb-encode::attest`, a fixed-width in-toto-Statement subset — NOT a wire-compatible JSON producer) reaching SLSA **L1→toward L2**; L3 (`repro=BIT-IDENTICAL-2BUILD`) is M36. `measure=SELF-NO-HW-ROOT selfmeasure=UNATTESTED-LOADER` (no measured boot/RTM; the subject digest is self-reported by the attested image) |
| **Signature / prov-lineage leaf** **[DECISION]** | **LMS (RFC 8554)** in-house, SHA-256 leaf (`tb-encode::lmsig` VERIFY-only + `tb-encode::sha256`); the LMS signer is host-side (`tools/prov-signer`, cfg-gated OUT of the kernel TCB) | Sovereignty-ledger status: the LMS verify leaf + the SHA-256 leaf are **ACCEPTED-PERMANENT** (in-house zero-dep, the cost of public-verify/private-sign exclusivity over M29's symmetric MAC); the simulated signing key is **TEMPORARY** (rung-0 `key=SIMULATED-ENROLLED-CI-CUSTODIED`; real operator enrolment is #85). `sec=ASSUMED-FROM-LITERATURE` (LMS EUF-CMA + SHA-256 resistance assumed, never proven — the khash claim tier); the Kani obligation is a `w=1` toy instance + the official-vector host KAT (a full-parameter verify is ~1062 SHA-256 compressions, CBMC-infeasible) (M33 proposal §4/§9) |
| **Best practices** | **OpenSSF Best Practices badge** (passing) | At repo launch; a published security policy with 14-day response / 60-day fix SLAs |
| **Reproducible builds** | **Nix** (NixOS ~97% bit-reproducibility proven) | For the unikernel node image: the strongest SLSA provenance + CRA compliance evidence |
| **SBOM** | **SPDX** (ISO/IEC 5962; license) + **CycloneDX v1.7** (ECMA-424; per-artifact, with AI-BOM/ML-model support) | Both, by role: SPDX in the source/crate manifest, CycloneDX in the per-artifact SBOM produced by CI |
| **Security process** | **SECURITY.md** (day 1) → **CVE/CNA** (at the first production release; precedent: Linux, curl, Rust) | Supported-version table, private reporting, OpenSSF 14-day SLA |
| **Fuzzing** | **cargo-fuzz/libFuzzer** → ClusterFuzzLite (CI) → **OSS-Fuzz** | Every parser/IPC boundary (MCP/A2A message decode = primary target) |
| **Kernel sanitizer** | KASAN-analog in the debug profile (allocator red-zone/quarantine/UAF poison); MTE design on arm64 | Exercise the `unsafe`-Rust surface |
| **RFC process** | **Fuchsia Eng-Council model** (single council, in-repo RFC, ≥7-day last-call) | Cross-cutting decisions like ABI/capability model/scheme namespace in a single body; a frozen-kernel ABI change is RFC-mandatory |

## 7. Stack-Fit Notes (impedance) **[verified: 2-0 stack-fit]**

- **WASM host:** the Component Model is de facto **Wasmtime/Rust-first**; WIT host bindings (`bindgen!`) are only in Rust. WAMR (C)/WasmEdge (C++) do not offer a Component Model host → conflicts with the typed-nanoprocess-interface plan. (WAMR only for a future TEE/MCU profile.)
- **cap-std** (Bytecode Alliance, in production in Wasmtime): capability-oriented std — can reuse Yuva's capability microkernel + scheme-daemon handle/Dir/Pool model **one-to-one**; thanks to WASI alignment the same capability semantics flow into the nanoprocess layer with ~zero translation. **No equivalent outside Rust.**
- **tokio** LTS-class (a safe industrial default for scheme daemons; `tonic/prost` gRPC IPC). **io_uring crates are not yet mature** → do not hard-couple the IPC layer to io_uring, abstract it.
- **Native-Rust inference** (candle, mistral.rs): production-credible for single-node/edge/dense models → a fully-Rust node image **without a C++ engine** is possible if desired. For datacenter MoE throughput, vLLM/SGLang remain necessary (Python HTTP server, not FFI — verified).
- **llama.cpp**: plain C ABI → low impedance from Rust via a `-sys` crate (the unsafe surface is confined in -sys), or supervise `llama-server` over HTTP.
- **MCP & A2A**: in 2026 **both have an official Rust SDK** (`rmcp` tokio-based) → protocol bridges are pure Rust. The TS/Python SDKs only in the developer-SDK layer.
- **The AIOS `aios-rs` lesson:** the previous agent-OS chose Python for speed; the Rust port collapsed into placeholder traits because all the value was in Python-ecosystem integration. → **Yuva lesson:** language-lock the kernel/daemons to Rust from day 1, architecturally exile Python outside the node image.

## 8. Open Topics → [OPEN-QUESTIONS §I](OPEN-QUESTIONS.md)

- Kernel verification path: pure Rust+tiered-assurance, or seL4-under-node-image for certification?
- Audit of the `no_std` core dependency base (Rust std/core not yet verified).
- When does Native-Rust inference (candle/mistral.rs) fully replace the C++ engine?
- Is Ferrocene qualification actually needed (will the functional-safety market be entered)?

---

### Verification note
All numeric claims in this document passed 2-vote adversarial verification in [`lang-verified.json`](research/raw/lang-verified.json); 9 were clean approvals, 3 approved with correction (Fuchsia kernel C/C++ — not "C++ only"; the VeriSMo "versus Isabelle" comparison is not in the source, a measured inference; FLS does not replace the Reference; NSA says "memory protection"). The design inferences ([DECISION]/[PROPOSAL]) are derived from this data; they will be tested against prototype measurements.
