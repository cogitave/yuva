# B3 literature survey — the pure-Rust sovereign engine (std-Rust HOST daemon replacing vendored llama.cpp)

Companion to `docs/plans/sovereignty-plan.md` §B3 (#95). This note discharges the **research-first eval of candle / mistral.rs / burn** (plus ratchet, rustformers/llm and the GGUF-native long tail) for a **std-Rust host daemon** — NOT in-kernel, NOT no_std; plan principle 2 ("the kernel never hosts an engine") is untouched — and, as the plan REQUIRES before M32 lands, **§6 DEFINES the llama.cpp debt-closure test**. The M32 witness tokens this work eventually retires: `engine=VENDORED-C-LLAMACPP debt=SOVEREIGNTY-OPEN-B3 memsafety=UNSAFE-C-PROCESS-CONFINED`.

---

## 1. The decision frame — what "ZERO C in the chain" honestly means

The daemon is a **host Linux process** (M32's own sovereignty-ledger honesty). Scope of the zero-C claim, ledger-style:

- **CLAIMED at closure:** zero **compiled/vendored C or C++ anywhere in OUR cargo build graph** — no `cc`/`cmake` build-script compilation, no `-sys` crate wrapping a C library, **including the tokenizer** (the axis most evals skip, and where this survey found the one buried C dependency — §3).
- **ACCEPTED-PERMANENT (ledger, not claimed away):** the host's glibc/Linux kernel that any std-Rust binary links/syscalls — the same `host=RESIDUAL-TCB` residual M31 already names. Closure shrinks the C surface from "a C++ inference engine parsing UNTRUSTED weights" to "the host platform we already carry."
- **Out of scope:** GPU paths (B2's driver-VM problem), training, no_std.

Hard requirements from the plan: GGUF + K-quant loading (the M32 model custody format — requantizing weights through a Python/C toolchain would re-open the debt), CPU-only viability on the reference host, maintained, license-compatible.

## 2. Engine comparison

| | **mistral.rs** | **candle** (quantized direct) | **burn** | **ratchet** | **rustformers/llm** |
|---|---|---|---|---|---|
| What it is | full LLM server/engine on candle | HF's minimalist ML framework + `candle-transformers` quantized models | general DL framework (ndarray/cubecl/wgpu backends) | web-first WebGPU toolkit | GGML-era ecosystem |
| C-free chain (CPU build, incl. tokenizer) | **one known C leak**: `onig_sys` via candle-core (§3); its OWN `tokenizers` dep is already `default-features=false` → fancy-regex 0.14 (pure Rust, lockfile-verified); compute = candle pure-Rust kernels | **same single leak, same fix** (§3); compute chain pure Rust: `gemm` crate matmul + hand AVX/NEON/simd128 k-quant kernels, all `.rs` | pure Rust | pure Rust (wgpu) | **NO — Rust bindings over the GGML C reference** |
| GGUF + K-quants | native: candle `gguf_file.rs` reader, Q2K–Q6K/Q8K + legacy Q4_0..Q8_0; plus ISQ, GPTQ, AWQ, HQQ, AFQ, FP8, MXFP4; auto-detects arch/quant/chat-template | native reader + `k_quants.rs` (pure-Rust k-quant de/quant + dot kernels), quantized llama/mistral/phi/qwen examples maintained | **NONE — GGUF import is open issue #1187 (since 2024)**; quant = own PTQ 8/4/2-bit format, still in development (wgpu block-quant data-loss bug #4659 open) | own quant, no general GGUF LLM path; model zoo = Whisper/Phi/Moondream | main branch GGMLv3 only; gguf branch incomplete |
| CPU-only viability | yes — plain `cargo build` is the CPU build; SIMD via candle kernels | yes — default features `[]`, MKL/Accelerate/CUDA/Metal strictly optional | yes (ndarray) but nothing to run GGUF on | WebGPU-first; CPU secondary | yes (via C) |
| CPU perf class vs llama.cpp | same order of magnitude; ~95%-of-llama.cpp claims are **CUDA** (2024); CPU expect **~1.5–3× slower decode** (candle evidence row) | #1939: 31.8 vs 51.3 t/s (7B Q4_K, ≈1.6× gap); fused CPU attention merged (#2973, ~4×); interleaved-layout CPU kernel gap vs llama.cpp tracked in #3183 (Nov 2025) — gap real, actively closing | n/a for GGUF | n/a | n/a |
| Maturity / maintenance | 7.3k★, pushed **2026-06-11** (same-day), single-lead (EricLBuehler) + contributors — bus-factor risk noted | 20.5k★, HF-maintained, pushed 2026-06-11 | 15.4k★, very active — as a framework; LLM story (tracel-ai/models llama-burn, converted weights) is demo-grade | 763★, pushes sparse (last 2026-05-26), author absorbed into HF | **ARCHIVED 2024-06-24** |
| License | MIT | Apache-2.0 OR MIT | Apache-2.0 OR MIT | MIT | MIT/Apache-2.0 |

**Long-tail eliminations.** `lm.rs` (1k★): genuinely pure-Rust CPU inference but dead since 2024-10 and uses its OWN weight format (conversion toolchain re-opens the debt). `Lexmata/llama-gguf` (claims "pure-Rust llama.cpp, full GGUF v1–v3 + k-quants"): created 2026-02, 19★, zero external validation — **watch item only**, candidate for re-eval at closure time. kalosm/floneum: candle wrappers, inherit candle's verdict with more surface.

## 3. The load-bearing C finding — `onig` is in EVERY default candle build

The HF `tokenizers` crate defaults are `["progressbar", "onig", "esaxx_fast"]` — `onig` = bindings to **oniguruma, a C regex library** (`onig_sys`), and `esaxx_fast` = `esaxx-rs/cpp` (**C++** suffix-array). The pure-Rust alternative backend exists (`fancy-regex`, upstreamed for wasm; `compile_error!` if neither backend is enabled, so the choice is total and machine-visible).

The chain status, verified against manifests and the mistral.rs lockfile (2026-06-11):

- **candle-core** (upstream main AND the rev mistral.rs pins) declares for non-wasm targets: `tokenizers = { workspace = true, features = ["onig"] }` → **every default candle/mistral.rs Linux build compiles onig_sys C today.** This is the entire C residue; cargo cannot unrequest a dependency-requested feature, so closure needs a **one-line fork/`[patch]` of candle-core** (or an upstream PR making the regex backend a pass-through feature — the right long-term move).
- **mistral.rs's own** `tokenizers = { version = "0.21.4", default-features = false }` resolves with `fancy-regex 0.14.0` and **no onig edge**; its lockfile `esaxx-rs 0.1.10` entry has **no `cc` edge** (pure-Rust esaxx path). So the project already walks the pure-Rust tokenizer path everywhere EXCEPT the candle-core line.
- mistral.rs additionally ships `mistralrs-core/src/gguf/gguf_tokenizer.rs` — a **pure-Rust reconstruction of the tokenizer from GGUF metadata** (`tokenizer.ggml.model`: `"llama"|"replit"` → Unigram/SentencePiece, `"gpt2"` → BPE), i.e. single-artifact custody: one GGUF file carries weights AND tokenizer, no `tokenizer.json` sidecar.

## 4. Tokenizer options (per model family — the plan's explicit axis)

| Option | C-free | Families | Notes |
|---|---|---|---|
| **GGUF-embedded reconstruction** (mistral.rs `gguf_tokenizer.rs` pattern) | yes (given §3 patch) | llama/SPM-unigram, gpt2-BPE | **preferred**: one artifact, one custody boundary, one hash in the M33 attestation |
| HF `tokenizers`, `default-features=false, features=["fancy-regex"]` | yes — fancy-regex backend, pure-Rust esaxx | everything with a `tokenizer.json` | the wasm-proven configuration; onig↔fancy-regex behavior parity is the named residual (token-parity gate in §6 catches it) |
| **shimmytok** | yes (~4k LOC, no C++) | SPM, BPE, WPM, UGM, RWKV, PLaMo-2 from GGUF, llama.cpp-parity test suite | exactly on-target but young (2025-10, 18★, Apache-2.0) — audit-sized, adopt-or-vendor candidate |
| kitoken | yes | converts SentencePiece / HF / Tiktoken / Tekken | BSD-2-Clause, active (2026-05) |
| tiktoken-rs / tekken-rs | yes | GPT-family / Mistral-Tekken | family-specific fallbacks |

## 5. Recommendation and runner-up

**Recommendation: mistral.rs** (MIT), with the §3 one-line candle-core patch pinned in the daemon workspace and the lockfile deny-grep of §6 enforcing it forever. It is the only maintained engine that is simultaneously GGUF-K-quant-native, CPU-only-viable, server-shaped (the M30/M32 daemon seam), tokenizer-self-contained from the GGUF artifact, and same-day active. Named risks, carried not hidden: single-lead bus factor; 70+-crate dependency surface (audit cost — mitigated by `--locked` + the deny-grep); CPU decode ~1.5–3× slower than llama.cpp (the §6 perf floor makes the regression budget explicit).

**Runner-up: candle direct** (`candle-core` + `candle-transformers` quantized pipeline, Apache-2.0/MIT, HF-backed). Strictly smaller audit surface and the stronger institutional maintainer — the better choice if the daemon only ever serves one pinned model family and we accept writing the serving loop ourselves. Same §3 patch, same closure test. Switching between recommendation and runner-up changes no token and no test — both are candle-kernel chains; the decision can be re-taken at implementation time without re-research.

**Not now:** burn (no GGUF path — re-eval if #1187 lands), ratchet (web-first, low momentum), rustformers/llm (archived AND C-bound), lm.rs (dead, non-GGUF), llama-gguf (unproven; watch).

## 6. THE DEBT-CLOSURE TEST (defined here, before M32 lands — as the plan requires)

Closure of `debt=SOVEREIGNTY-OPEN-B3` = **all five gates green in one CI run**, then the lane flip:

1. **Zero-C chain proof (machine-checked, two independent mechanisms):**
   (a) *poisoned-toolchain build*: the daemon builds `--locked --release` with `CC=/bin/false CXX=/bin/false` — any build script invoking a C/C++ compiler fails the build, so success IS the proof;
   (b) *lockfile deny-grep* in both run scripts: `Cargo.lock` of the daemon workspace must contain none of `onig_sys|onig |cc"|cmake|bindgen|-src"|esaxx` (tuned to zero false positives at implementation time, fail-closed). Witness token: `cchain=CC-POISON-VERIFIED`.
2. **Tokenizer parity gate (exact, gateable):** token-id sequences from the pure-Rust tokenizer must EXACTLY match `llama.cpp tokenize` output over a pinned multilingual + code + edge-case corpus (≥1k lines, hash-pinned), for the GGUF artifact actually served. Token: `tokparity=LLAMACPP-EXACT`. (Exact equivalence is honest here — tokenization is discrete; this is the gate that catches the onig→fancy-regex residual of §4.)
3. **Model quality bar (statistical, NOT token-equivalence):** greedy decode across engines legitimately diverges (kernel order, float rounding) — demanding output-equivalence would be a dishonest gate that either never passes or passes vacuously. The literature-honest bar: **perplexity on a pinned eval set (hash-pinned) over the SAME GGUF file, pure-Rust engine within ≤0.5% relative of llama.cpp's**; greedy prefix-agreement length over a pinned prompt set is RECORDED on the witness, not gated. Token: `ppl-delta=<measured>`.
4. **Perf floor (anti-regression, deliberately loose):** pure-Rust CPU decode ≥ **1/3 of llama.cpp t/s** on the reference host, same GGUF, same thread count — encodes the measured 1.5–3× class so closure cannot smuggle in a lane-timeout regression. Token: `tps-ratio=<measured>`.
5. **The grep-enforced lane flip (verbatim from the plan's closure DoD):** the local-infer lane's witness flips `engine=VENDORED-C-LLAMACPP` → `engine=PURE-RUST`, AND both run scripts gain a REJECT for `VENDORED-C` on that lane — after which a llama.cpp reappearance is a CI failure, not a memory.

Until all five hold, M32's `debt=SOVEREIGNTY-OPEN-B3` stays on the witness — the debt is machine-remembered, not prose-remembered.

## 7. Honesty boundary (tokens at closure)

| Property | Claimed? | Token |
|---|---|---|
| No compiled C/C++ in the daemon's cargo build graph (incl. tokenizer) | YES — CC-poison + deny-grep | `cchain=CC-POISON-VERIFIED` |
| Tokenizer = llama.cpp-exact on pinned corpus | YES | `tokparity=LLAMACPP-EXACT` |
| Output equivalence with llama.cpp | **NO — measured, bounded** | `ppl-delta=` / prefix-agreement recorded |
| Performance parity with llama.cpp CPU | **NO — floor only (≥1/3)** | `tps-ratio=` |
| Host glibc/Linux/rustc out of the C claim | ledger ACCEPTED-PERMANENT | `host=RESIDUAL-TCB` (M31's token, unchanged) |
| Model weights trusted | **NO** (unchanged from M32) | `weights=UNTRUSTED-INPUT-NAMED` |
| Engine memory safety | upgraded claim: forbid-unsafe NOT claimed (deps carry unsafe Rust); "no C parser on untrusted weights" IS claimed | `memsafety=SAFE-RUST-DEPS-UNAUDITED` |

---

### Sources
- [mistral.rs (EricLBuehler)](https://github.com/EricLBuehler/mistral.rs) · [README — quant/format matrix](https://github.com/EricLBuehler/mistral.rs/blob/master/README.md) · [workspace Cargo.toml — `tokenizers default-features=false`, candle pin](https://github.com/EricLBuehler/mistral.rs/blob/master/Cargo.toml) · [Cargo.lock — fancy-regex/onig resolution](https://github.com/EricLBuehler/mistral.rs/blob/master/Cargo.lock) · [gguf_tokenizer.rs (pure-Rust GGUF-embedded tokenizer)](https://github.com/EricLBuehler/mistral.rs/blob/master/mistralrs-core/src/gguf/gguf_tokenizer.rs) · [issue #326 (GGUF-only running)](https://github.com/EricLBuehler/mistral.rs/issues/326)
- [candle (huggingface)](https://github.com/huggingface/candle) · [candle-core Cargo.toml — `tokenizers features=["onig"]`, default features `[]`, gemm CPU path](https://github.com/huggingface/candle/blob/main/candle-core/Cargo.toml) · [candle-core/src/quantized — gguf_file.rs, k_quants.rs, avx/neon/simd128](https://github.com/huggingface/candle/tree/main/candle-core/src/quantized) · perf: [#1939 quantized slower than llama.cpp](https://github.com/huggingface/candle/issues/1939) · [#3183 CPU kernels for interleaved GGUF layouts](https://github.com/huggingface/candle/issues/3183) · [#2973 fused CPU attention (~4×)](https://github.com/huggingface/candle/pull/2973) · [#1043 quantized perf history](https://github.com/huggingface/candle/issues/1043)
- [tokenizers (huggingface) — Cargo.toml default features `onig`+`esaxx_fast`](https://github.com/huggingface/tokenizers/blob/main/tokenizers/Cargo.toml) · [utils/mod.rs — onig/fancy-regex `compile_error!` switch](https://github.com/huggingface/tokenizers/blob/v0.21.4/tokenizers/src/utils/mod.rs) · [Mithril — porting tokenizers to WASM (fancy-regex substitution)](https://blog.mithrilsecurity.io/porting-tokenizers-to-wasm/)
- [burn (tracel-ai)](https://github.com/tracel-ai/burn) · [#1187 GGUF import (open)](https://github.com/tracel-ai/burn/issues/1187) · [#4659 wgpu block-quant reshape bug](https://github.com/tracel-ai/burn/issues/4659) · [tracel-ai/models (llama-burn)](https://github.com/tracel-ai/models)
- [ratchet (FL33TW00D)](https://github.com/FL33TW00D/ratchet) · [rustformers/llm — archived, GGML-bound](https://github.com/rustformers/llm) · [lm.rs (samuel-vitorino)](https://github.com/samuel-vitorino/lm.rs) · [Lexmata/llama-gguf (watch item)](https://github.com/Lexmata/llama-gguf)
- Tokenizers (pure-Rust): [shimmytok — GGUF-native, llama.cpp parity](https://github.com/Michael-A-Kuykendall/shimmytok) · [kitoken](https://github.com/Systemcluster/kitoken) · [tekken-rs](https://docs.rs/tekken-rs) · [tiktoken-rs](https://crates.io/crates/tiktoken-rs)
- Repo metadata (stars/pushed_at/license/archived) read via GitHub API, 2026-06-11.
