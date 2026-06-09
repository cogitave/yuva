//! The M16 `model:`-scheme routing helpers -- the PURE, panic-free string logic
//! lifted out of `tb-hal`'s in-kernel inference bridge (`tb_hal::infer`).
//!
//! `tb-hal::infer` is the LLM-agnostic in-kernel ROUTER: an agent names a target
//! model via a `model:<provider>/<path>` URI and the kernel binds a REGISTERED
//! backend behind that prefix. Two pieces of that decision are PURE string
//! algebra over UNTRUSTED input and carry ZERO kernel state:
//!
//!   * [`parse_scheme`] -- the `model:` grammar split (`model:<provider>/<rest>`),
//!     total and panic-free over ANY `&str` (a non-`model:` scheme rejects
//!     cleanly, so a prompt-injected / malformed URI can never crash the kernel).
//!   * [`longest_prefix_index`] -- the longest-prefix-match routing decision over
//!     a slice of route-key literals (the pure core of `infer::resolve`).
//!
//! Hoisting them HERE makes them host-verifiable with NO model drift: `tb-hal`
//! calls these exact functions, while the Tier-0 Miri lane EXECUTES them over a
//! thorough adversarial vector set (proving panic-freedom + correctness + zero
//! UB on untrusted input) -- exactly the `vmx` / `paging` / `ipc_frame`
//! precedent. `#![no_std]` + `#![forbid(unsafe_code)]` (inherited from the crate
//! root): byte/slice-based, zero alloc, zero deps.

/// Split a `model:<provider>/<path>` URI into `(provider, path)`.
///
/// Returns `None` for ANY non-`model:` scheme (so `memory:x` / `block:y` / a
/// bare `":"` cleanly reject) -- a bad scheme can never crash the kernel. TOTAL:
/// it NEVER panics for any input, including the empty string, `"model:"`,
/// `"model:/"`, a trailing-junk path, or non-UTF-8-looking bytes (operates on
/// `&str`, so the caller already holds valid UTF-8).
///
/// A bare `model:auto` / `model:default` (no `/`) parses to `(provider, "")` --
/// the reserved pure-preference binding (a future router scores it by
/// Prefs/Qos; deferred). An empty provider (`"model:/path"`) or an empty path
/// (`"model:prov/"`) is rejected, since neither can name a real route.
#[must_use]
pub fn parse_scheme(uri: &str) -> Option<(&str, &str)> {
    let rest = uri.strip_prefix("model:")?;
    match rest.split_once('/') {
        Some((p, path)) if !p.is_empty() && !path.is_empty() => Some((p, path)),
        None if !rest.is_empty() => Some((rest, "")),
        _ => None,
    }
}

/// Return the index of the LONGEST `keys` entry that is a prefix of `provider`,
/// or `None` if no key is a prefix.
///
/// This is the pure core of `infer::resolve`'s routing decision: a registered
/// backend claims a `provider` prefix (its route key), and the most-specific
/// (longest) matching key wins. Ties on length resolve DETERMINISTICALLY to the
/// LOWEST index (registration order), so routing is total and reproducible.
///
/// TOTAL + panic-free over ANY `provider` and ANY `keys` slice (including an
/// empty slice -> `None`). Byte/slice-based: a key `k` matches iff
/// `provider.as_bytes()` starts with `k.as_bytes()`. The empty key `""` is a
/// prefix of every string (the lowest-priority catch-all); callers that do not
/// want a catch-all simply never register an empty key.
#[must_use]
pub fn longest_prefix_index(provider: &str, keys: &[&str]) -> Option<usize> {
    let p = provider.as_bytes();
    let mut best: Option<usize> = None;
    let mut best_len = 0usize;
    let mut i = 0;
    while i < keys.len() {
        let k = keys[i].as_bytes();
        // `keys[i]` is a prefix of `provider` iff the bytes start with it.
        if p.starts_with(k) {
            // Strictly-greater length to UPDATE, so on a tie the first
            // (lowest-index) key is retained -> deterministic tie-break.
            if best.is_none() || k.len() > best_len {
                best = Some(i);
                best_len = k.len();
            }
        }
        i += 1;
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // parse_scheme: the UNTRUSTED `model:` URI grammar parser. The Tier-0 Miri
    // lane EXECUTES every one of these paths in an instrumented interpreter, so
    // a clean run proves the parser is panic-free + correct with ZERO UB over
    // valid, malformed, and adversarial input alike.
    // -----------------------------------------------------------------------

    #[test]
    fn parse_scheme_accepts_valid_provider_path() {
        assert_eq!(parse_scheme("model:claude/messages"), Some(("claude", "messages")));
        assert_eq!(parse_scheme("model:llama/chat"), Some(("llama", "chat")));
        assert_eq!(parse_scheme("model:mock/echo"), Some(("mock", "echo")));
        assert_eq!(parse_scheme("model:local/llama3"), Some(("local", "llama3")));
    }

    #[test]
    fn parse_scheme_splits_on_the_first_slash_only() {
        // split_once('/') splits on the FIRST '/': the remainder (incl. further
        // slashes / an @version) rides intact in the path segment.
        assert_eq!(parse_scheme("model:llama/v2/chat"), Some(("llama", "v2/chat")));
        assert_eq!(
            parse_scheme("model:claude/messages@2024"),
            Some(("claude", "messages@2024"))
        );
        assert_eq!(parse_scheme("model:a/b/c/d"), Some(("a", "b/c/d")));
    }

    #[test]
    fn parse_scheme_accepts_bare_provider_as_pure_preference() {
        // No '/' + a non-empty remainder -> the reserved (provider, "") binding.
        assert_eq!(parse_scheme("model:auto"), Some(("auto", "")));
        assert_eq!(parse_scheme("model:default"), Some(("default", "")));
        assert_eq!(parse_scheme("model:x"), Some(("x", "")));
    }

    #[test]
    fn parse_scheme_rejects_non_model_schemes() {
        // A different scheme prefix must cleanly reject (the M16 self-test case).
        assert_eq!(parse_scheme("memory:x"), None);
        assert_eq!(parse_scheme("block:y"), None);
        assert_eq!(parse_scheme("channel:z"), None);
        assert_eq!(parse_scheme(":"), None);
        assert_eq!(parse_scheme("MODEL:claude/x"), None); // case-sensitive prefix
        assert_eq!(parse_scheme("xmodel:claude/x"), None); // prefix not at start
        assert_eq!(parse_scheme("model"), None); // no colon at all
        assert_eq!(parse_scheme("modelx"), None);
    }

    #[test]
    fn parse_scheme_rejects_malformed_model_uris() {
        assert_eq!(parse_scheme(""), None); // empty input
        assert_eq!(parse_scheme("model:"), None); // scheme only, empty rest
        assert_eq!(parse_scheme("model:/"), None); // empty provider AND empty path
        assert_eq!(parse_scheme("model:/path"), None); // empty provider
        assert_eq!(parse_scheme("model:prov/"), None); // empty path
        assert_eq!(parse_scheme("model://"), None); // empty provider, non-empty? path="/" but provider="" -> reject
    }

    #[test]
    fn parse_scheme_is_total_over_adversarial_bytes() {
        // A spread of weird-but-valid-UTF-8 inputs: the parser must NEVER panic
        // and must return a structurally-correct split (Miri proves no UB).
        for &s in &[
            "model:\u{00e9}/\u{1f600}", // multibyte provider + emoji path
            "model: /x",                // space provider
            "model:a/ ",                // space path
            "model:::/::",              // colons everywhere
            "model:\t/\n",              // control chars
            "model:..%2F../etc",        // a would-be path-traversal payload
        ] {
            // No assertion on the exact value beyond panic-freedom + the
            // structural contract: a Some always has a non-empty provider.
            if let Some((p, _path)) = parse_scheme(s) {
                assert!(!p.is_empty());
            }
        }
        // Spot-check one structural result: provider may contain odd chars; the
        // parser is purely structural (splits on the first '/').
        assert_eq!(parse_scheme("model:::x/y"), Some(("::x", "y")));
        assert_eq!(parse_scheme("model:..%2F../etc"), Some(("..%2F..", "etc")));
    }

    // -----------------------------------------------------------------------
    // longest_prefix_index: the routing decision. Concrete vectors covering the
    // real route keys, longest-vs-shorter prefix collisions, the deterministic
    // tie-break, the empty-key catch-all, and the no-match / empty-slice cases.
    // -----------------------------------------------------------------------

    #[test]
    fn lpi_matches_the_real_route_keys() {
        // The live ROUTES provider keys at M16.
        let keys = ["mock", "local"];
        assert_eq!(longest_prefix_index("mock", &keys), Some(0));
        assert_eq!(longest_prefix_index("local", &keys), Some(1));
        // A provider that EXTENDS a key still routes to it (longest-prefix).
        assert_eq!(longest_prefix_index("mocking", &keys), Some(0));
        assert_eq!(longest_prefix_index("localhost", &keys), Some(1));
        // No key is a prefix -> None (the M16 unknown-scheme path).
        assert_eq!(longest_prefix_index("vendor", &keys), None);
        // A key that is LONGER than the provider is not a prefix.
        assert_eq!(longest_prefix_index("mo", &keys), None);
        assert_eq!(longest_prefix_index("", &keys), None);
    }

    #[test]
    fn lpi_picks_the_longest_among_prefix_collisions() {
        // "mo" is a prefix of "mock"; both prefix "mocking". The LONGEST wins.
        let keys = ["mo", "mock", "model", "local"];
        assert_eq!(longest_prefix_index("mocking", &keys), Some(1)); // "mock" (4) beats "mo" (2)
        assert_eq!(longest_prefix_index("mock", &keys), Some(1)); // exact "mock"
        assert_eq!(longest_prefix_index("moc", &keys), Some(0)); // only "mo" fits
        assert_eq!(longest_prefix_index("model", &keys), Some(2)); // "model" (5) beats "mo" (2)
        assert_eq!(longest_prefix_index("mo", &keys), Some(0)); // only "mo"
        assert_eq!(longest_prefix_index("mod", &keys), Some(0)); // "mo"; "model" too long
        assert_eq!(longest_prefix_index("local", &keys), Some(3));
        assert_eq!(longest_prefix_index("m", &keys), None); // nothing fits
    }

    #[test]
    fn lpi_tie_breaks_to_the_lowest_index() {
        // Duplicate / equal-length keys: the FIRST (lowest index) must win.
        assert_eq!(longest_prefix_index("abc", &["ab", "ab"]), Some(0));
        assert_eq!(longest_prefix_index("abc", &["a", "a", "a"]), Some(0));
        // Two equal-length distinct keys, only one matches.
        assert_eq!(longest_prefix_index("abc", &["xy", "ab"]), Some(1));
        // Equal-length both match (same string) -> lowest index.
        assert_eq!(longest_prefix_index("foobar", &["foo", "foo", "foobar"]), Some(2));
    }

    #[test]
    fn lpi_handles_empty_key_and_empty_slice() {
        // The empty string is a prefix of EVERYTHING (lowest-priority catch-all):
        // it only wins when no longer key matches.
        assert_eq!(longest_prefix_index("anything", &["", "x"]), Some(0));
        assert_eq!(longest_prefix_index("xyz", &["", "x"]), Some(1)); // "x" longer than ""
        assert_eq!(longest_prefix_index("", &[""]), Some(0));
        // An empty key set never matches.
        assert_eq!(longest_prefix_index("anything", &[]), None);
        assert_eq!(longest_prefix_index("", &[]), None);
    }

    #[test]
    fn lpi_is_total_over_adversarial_providers() {
        // Multibyte / control / would-be-traversal providers: never a panic.
        let keys = ["mock", "local", "model"];
        for &p in &[
            "\u{1f600}", "..", "../etc", "mock/../local", "mo\tck", "MODEL", "",
        ] {
            let _ = longest_prefix_index(p, &keys); // panic-freedom is the property
        }
        // A provider that is a real key with a traversal suffix still routes by
        // its prefix (path-traversal is unrepresentable -- the key is the prefix).
        assert_eq!(longest_prefix_index("mock/../etc", &keys), Some(0));
    }

    // -----------------------------------------------------------------------
    // Combined: mirror exactly what infer::resolve does (parse the URI, then
    // route the provider segment), proving the wired decision end-to-end.
    // -----------------------------------------------------------------------

    #[test]
    fn parse_then_route_mirrors_resolve_for_the_real_routes() {
        // The provider keys the live ROUTES derive from their scheme literals.
        let keys = ["mock", "local"];
        let route = |uri: &str| -> Option<usize> {
            let (provider, _path) = parse_scheme(uri)?;
            longest_prefix_index(provider, &keys)
        };
        // The three M16 self-test URIs, byte-for-byte.
        assert_eq!(route("model:mock/echo"), Some(0)); // -> MOCK_CLAUDE
        assert_eq!(route("model:local/llama3"), Some(1)); // -> MOCK_LLAMA
        assert_eq!(route("model:vendor/ghost"), None); // -> BadCap
        // A non-model scheme rejects at the parse stage.
        assert_eq!(route("memory:x"), None);
        assert_eq!(route("block:y"), None);
    }
}
