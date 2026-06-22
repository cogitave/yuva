//! build.rs — fetch the pinned llama.cpp source (hash-verified), build it with
//! the M32 §4 deterministic CPU envelope, compile the flat-C engine shim
//! against its headers, and emit the link directives.
//!
//! PINS (the §4 lane contract — change ONLY by a reviewed PR that re-measures
//! the goldens): the b-tag, the commit, and the source-archive SHA256.
//!
//! NETWORK: confined to THIS build step (the toolchain-install class, §5.5).
//! If `LLAMA_ENGINE_VENDOR_DIR` points at a pre-extracted tree (the CI cache /
//! the `vendor/llama.cpp/` Probe-A path), no network is touched at all. Runtime
//! is always zero-network.
//!
//! CC=/bin/false (DEBT-LOCKSTEP Rule 3): when CC/CXX is poisoned, the cmake
//! configure/build below FAILS — proving the C is genuinely in the build graph
//! (a debt token over secretly C-free code is also a lie). The probe runs
//! against a pristine target dir so a warm cache cannot make it vacuous.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

// --- THE PINS (§4 lane contract) ---------------------------------------------
const LLAMA_BTAG: &str = "b9756";
const LLAMA_COMMIT: &str = "d0f9d2e5ac5d4f51763755958b8f353fed01aaa2";
// SHA256 of the codeload.github.com tar.gz for the pinned commit. Measured at
// landing; re-measured on every bump. (Filled in by build.rs's first verified
// fetch; see VENDOR_SHA256 below — if empty, the verify step is a HARD FAIL so
// an unpinned download can never slip through.)
const VENDOR_SHA256: &str = "492afa76b61eb216a1de0be4efa4c49823fd298c05428361e6fa1b07e7ce1879";

fn main() {
    println!("cargo:rerun-if-changed=shim/engine_shim.cpp");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=LLAMA_ENGINE_VENDOR_DIR");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));

    // 1. Locate the vendored source: an explicit dir (CI cache / in-repo vendor)
    //    or fetch-on-miss into OUT_DIR, hash-pinned.
    let src = locate_or_fetch_source(&out_dir);

    // 2. Build llama.cpp with the §4 deterministic CPU envelope.
    let dst = build_llama(&src);

    // 3. Compile the flat-C engine shim against the vendored headers.
    build_shim(&src);

    // 4. Link directives. With a custom build target the static libs are NOT
    //    installed under <dst>/lib; they sit in the build tree under
    //    <dst>/build/{src,ggml/src,ggml/src/ggml-cpu}. Walk the build tree and
    //    add every dir that contains a *.a as a link-search path.
    let build_tree = dst.join("build");
    add_lib_search_dirs(&build_tree);
    println!("cargo:rustc-link-search=native={}", dst.join("lib").display());
    println!("cargo:rustc-link-search=native={}", dst.join("lib64").display());

    // The ggml/llama static libs the shim references. Order matters for static
    // linking (dependents before dependencies).
    for lib in ["llama", "ggml", "ggml-cpu", "ggml-base"] {
        println!("cargo:rustc-link-lib=static={lib}");
    }
    // C++ runtime + libm (softmax/exp go through libm — part of the envelope).
    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rustc-link-lib=dylib=m");
    println!("cargo:rustc-link-lib=dylib=pthread");
}

/// Recursively add every directory under `root` that contains a `*.a` static
/// library as a `rustc-link-search` path.
fn add_lib_search_dirs(root: &Path) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let mut has_archive = false;
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().map(|e| e == "a").unwrap_or(false) {
                has_archive = true;
            }
        }
        if has_archive {
            println!("cargo:rustc-link-search=native={}", dir.display());
        }
    }
}

/// Find the vendored source tree, or fetch it hash-pinned into OUT_DIR.
fn locate_or_fetch_source(out_dir: &Path) -> PathBuf {
    // Explicit dir override (CI cache restore or in-repo `vendor/llama.cpp/`).
    if let Ok(dir) = env::var("LLAMA_ENGINE_VENDOR_DIR") {
        let p = PathBuf::from(&dir);
        if p.join("CMakeLists.txt").exists() {
            println!("cargo:warning=llama-engine-sys: using vendored source at {dir}");
            return p;
        }
        panic!("LLAMA_ENGINE_VENDOR_DIR={dir} has no CMakeLists.txt (bad vendor dir)");
    }

    // An in-repo vendor checkout (the §7 Probe-A signal) takes precedence.
    let in_repo = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"))
        .join("vendor")
        .join("llama.cpp");
    if in_repo.join("CMakeLists.txt").exists() {
        return in_repo;
    }

    // Fetch-on-miss into OUT_DIR, hash-pinned.
    let extracted = out_dir.join(format!("llama.cpp-{LLAMA_COMMIT}"));
    if extracted.join("CMakeLists.txt").exists() {
        return extracted;
    }

    let tarball = out_dir.join("llama-src.tar.gz");
    let url = format!("https://codeload.github.com/ggml-org/llama.cpp/tar.gz/{LLAMA_COMMIT}");
    fetch(&url, &tarball);
    verify_sha256(&tarball);
    extract(&tarball, out_dir);
    if !extracted.join("CMakeLists.txt").exists() {
        panic!(
            "llama-engine-sys: extraction did not produce {} (archive layout changed?)",
            extracted.display()
        );
    }
    extracted
}

fn fetch(url: &str, dest: &Path) {
    // curl is the toolchain-install-class fetcher already present on the runner
    // (and in WSL); no network crate enters the build graph.
    let status = Command::new("curl")
        .args(["-sSL", "--fail", "-o"])
        .arg(dest)
        .arg(url)
        .status()
        .expect("llama-engine-sys: curl not available to fetch the pinned source");
    assert!(status.success(), "llama-engine-sys: fetch of {url} failed");
}

fn verify_sha256(file: &Path) {
    // HARD FAIL on an unset pin: an unpinned download must never slip through
    // (the Probllama anti-pattern). The pin is measured at landing and frozen.
    let got = sha256_hex(file);
    if VENDOR_SHA256.is_empty() {
        panic!(
            "llama-engine-sys: VENDOR_SHA256 is unset — refusing an unpinned source archive. \
             Measured sha256 of {} = {}. Pin it in build.rs (a reviewed act).",
            file.display(),
            got
        );
    }
    assert_eq!(
        got, VENDOR_SHA256,
        "llama-engine-sys: source archive sha256 MISMATCH (pinned {VENDOR_SHA256}, got {got}) — \
         the pin moved or the artifact was swapped; hard FAIL (never a fallback fetch)"
    );
}

fn sha256_hex(file: &Path) -> String {
    // Use the system sha256sum (coreutils on Linux runners/WSL) — no crypto
    // crate in the build graph.
    let out = Command::new("sha256sum")
        .arg(file)
        .output()
        .expect("llama-engine-sys: sha256sum unavailable");
    assert!(out.status.success(), "sha256sum failed");
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .expect("sha256sum output")
        .to_string()
}

fn extract(tarball: &Path, into: &Path) {
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(tarball)
        .arg("-C")
        .arg(into)
        .status()
        .expect("llama-engine-sys: tar unavailable");
    assert!(status.success(), "llama-engine-sys: extraction failed");
}

/// Build llama.cpp with the §4 deterministic CPU envelope.
fn build_llama(src: &Path) -> PathBuf {
    let mut cfg = cmake::Config::new(src);
    cfg.profile("Release")
        // --- the determinism envelope (§4) ---
        .define("GGML_NATIVE", "OFF")
        .define("GGML_CPU_ALL_VARIANTS", "OFF")
        .define("GGML_OPENMP", "OFF")
        .define("GGML_BLAS", "OFF")
        // Baseline ISA — NO AVX dispatch at all (the maximally reproducible
        // build across the GitHub fleet's AVX-512/non-AVX-512 mix; the proposal
        // pins x86-64-v3, this stage-A landing degrades to the baseline ISA for
        // cross-runner bit-exactness, the named honesty fallback — see the
        // daemon's `isa=` token and the report).
        .define("GGML_AVX", "OFF")
        .define("GGML_AVX2", "OFF")
        .define("GGML_AVX512", "OFF")
        .define("GGML_FMA", "OFF")
        .define("GGML_F16C", "OFF")
        // --- build-surface minimization (§5.3) ---
        .define("GGML_RPC", "OFF")
        .define("LLAMA_CURL", "OFF")
        .define("LLAMA_BUILD_SERVER", "OFF")
        .define("LLAMA_BUILD_TESTS", "OFF")
        .define("LLAMA_BUILD_EXAMPLES", "OFF")
        .define("LLAMA_BUILD_TOOLS", "OFF")
        .define("BUILD_SHARED_LIBS", "OFF");
    // Build ONLY the `llama` library target (it pulls the ggml static libs);
    // the default `all`/`install` target also tries to build the `app/` tool,
    // which needs a generated build-info.h that LLAMA_BUILD_TOOLS=OFF does not
    // fully gate — so we target the libraries directly. We then point the link
    // search at the build dir (the libs are NOT installed under this target).
    cfg.build_target("llama");
    let dst = cfg.build();
    // The cmake crate returns <out>/build as the build tree when a custom
    // target is used. Expose both <dst> and <dst>/build for the link search.
    dst
}

/// Compile the flat-C engine shim against the vendored headers.
fn build_shim(src: &Path) {
    cc::Build::new()
        .cpp(true)
        .std("c++17")
        .file("shim/engine_shim.cpp")
        .include(src.join("include"))
        .include(src.join("ggml").join("include"))
        .flag_if_supported("-O2")
        .compile("engine_shim");
}
