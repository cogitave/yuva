// engine_shim.cpp — the flat C ABI over vendored llama.cpp the engine worker
// links. The DELIBERATE narrow surface (4 functions, primitive args only) keeps
// the Rust `-sys` bindings small and robust against llama.cpp struct churn: the
// daemon never sees a llama_model_params/llama_batch layout, only this shim's
// `int`/`char*` contract.
//
// HONESTY: this file IS the C the `debt=SOVEREIGNTY-OPEN-B3` /
// `engine=VENDORED-C-LLAMACPP` tokens point at — it #includes "llama.h" and the
// whole vendored ggml/llama C/C++ build links behind it. The DEBT-LOCKSTEP
// grep (M32 proposal §7) matches this directory; the CC=/bin/false poison probe
// (Rule 3) proves this translation unit is genuinely in the build graph.
//
// DETERMINISM ENVELOPE (M32 proposal §4): raw completion, NO chat template
// (the GGUF-embedded-template attack class is never rendered — §5.4); single
// context, single sequence, n_batch == prompt length, greedy top_k=1 / temp 0;
// threads pinned by the caller. The build flags that make this bit-exact across
// the runner fleet (GGML_NATIVE=OFF, baseline ISA, OpenMP OFF) live in build.rs.

#include "llama.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

extern "C" {

// One-time backend init/teardown. Idempotent-safe to call once per process.
void engine_backend_init(void) {
    llama_backend_init();
}
void engine_backend_free(void) {
    llama_backend_free();
}

// Copy the pinned llama.cpp system-info feature string into `buf` (the §4
// `sysinfo-pinned` tripwire input — the daemon asserts it against the pinned
// expectation, catching an upstream bump that silently re-enables SIMD
// dispatch/AVX-512). Returns the byte length (excluding NUL), or -1.
int32_t engine_sysinfo(char * buf, int32_t cap) {
    const char * s = llama_print_system_info();
    if (s == nullptr) {
        return -1;
    }
    int32_t n = (int32_t) strlen(s);
    if (n >= cap) {
        n = cap - 1;
    }
    if (n < 0) {
        return -1;
    }
    memcpy(buf, s, (size_t) n);
    buf[n] = '\0';
    return n;
}

// Run ONE greedy raw-completion over the pinned envelope. `model_path` is the
// already-SHA256-verified GGUF (the daemon verified it before the worker fd
// handoff — the C parser never touches an unverified byte). `prompt`/`prompt_len`
// are raw bytes (no template). Writes up to `out_cap` response bytes (the
// generated continuation ONLY, never the echoed prompt) into `out`. Returns the
// number of response bytes written (>= 0) on success, or a negative error code:
//   -1 model load failed   -2 tokenize failed   -3 context init failed
//   -4 decode failed        -5 sampler init failed
//
// CPU only, n_gpu_layers = 0 (the lane is GPU-less and GPU is nondeterministic
// anyway — issue #10197). add_special = true / parse_special = false: BOS is
// added per the model's training, but GGUF-metadata special tokens in the raw
// prompt bytes are NOT parsed as control tokens (defense-in-depth for the
// untrusted-prompt path).
int32_t engine_generate(const char * model_path,
                        const char * prompt,
                        int32_t      prompt_len,
                        int32_t      n_predict,
                        int32_t      n_threads,
                        char *       out,
                        int32_t      out_cap) {
    // --- model (CPU only) ---
    llama_model_params mparams = llama_model_default_params();
    mparams.n_gpu_layers = 0;
    llama_model * model = llama_model_load_from_file(model_path, mparams);
    if (model == nullptr) {
        return -1;
    }
    const llama_vocab * vocab = llama_model_get_vocab(model);

    // --- tokenize the raw prompt (no template) ---
    int n_prompt = -llama_tokenize(vocab, prompt, prompt_len, nullptr, 0, true, false);
    if (n_prompt <= 0) {
        llama_model_free(model);
        return -2;
    }
    std::vector<llama_token> ptoks(n_prompt);
    if (llama_tokenize(vocab, prompt, prompt_len, ptoks.data(), (int32_t) ptoks.size(), true, false) < 0) {
        llama_model_free(model);
        return -2;
    }

    // --- context: single slot, single seq, batch == prompt (the §4 envelope) ---
    llama_context_params cparams = llama_context_default_params();
    cparams.n_ctx     = (uint32_t) (n_prompt + n_predict);
    cparams.n_batch   = (uint32_t) n_prompt;
    cparams.n_ubatch  = (uint32_t) n_prompt;
    cparams.n_seq_max = 1;
    cparams.n_threads = n_threads;
    cparams.n_threads_batch = n_threads;
    cparams.no_perf   = true;
    llama_context * ctx = llama_init_from_model(model, cparams);
    if (ctx == nullptr) {
        llama_model_free(model);
        return -3;
    }

    // --- greedy sampler (top_k=1 / temp 0 — the claim source is bit-identical
    //     logits inside the envelope, never the seed) ---
    llama_sampler_chain_params sparams = llama_sampler_chain_default_params();
    sparams.no_perf = true;
    llama_sampler * smpl = llama_sampler_chain_init(sparams);
    if (smpl == nullptr) {
        llama_free(ctx);
        llama_model_free(model);
        return -5;
    }
    llama_sampler_chain_add(smpl, llama_sampler_init_greedy());

    // --- generation loop (response bytes only) ---
    std::string resp;
    llama_batch batch = llama_batch_get_one(ptoks.data(), (int32_t) ptoks.size());
    int32_t rc = 0;
    for (int n_pos = 0; n_pos + batch.n_tokens < n_prompt + n_predict; ) {
        if (llama_decode(ctx, batch) != 0) {
            rc = -4;
            break;
        }
        n_pos += batch.n_tokens;

        llama_token id = llama_sampler_sample(smpl, ctx, -1);
        if (llama_vocab_is_eog(vocab, id)) {
            break;
        }
        char piece[256];
        int n = llama_token_to_piece(vocab, id, piece, (int32_t) sizeof(piece), 0, false);
        if (n < 0) {
            rc = -4;
            break;
        }
        resp.append(piece, (size_t) n);
        batch = llama_batch_get_one(&id, 1);
    }

    llama_sampler_free(smpl);
    llama_free(ctx);
    llama_model_free(model);

    if (rc < 0) {
        return rc;
    }

    int32_t n = (int32_t) resp.size();
    if (n > out_cap) {
        n = out_cap;
    }
    memcpy(out, resp.data(), (size_t) n);
    return n;
}

} // extern "C"
