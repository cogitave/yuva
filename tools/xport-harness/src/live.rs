//! M31 stage C -- the ANTHROPIC-LIVE host bridge (operator-gated, ONE call).
//!
//! This module is the ONLY place in the repository that speaks HTTPS: the
//! Messages API call rides `ureq` (rustls via its default `tls` feature) +
//! `serde_json` -- the LANGUAGE-AND-STANDARDS §6 "Remote-API host deps" ledger
//! row (ACCEPTED-PERMANENT, host-bridge-confined). TLS/network code NEVER
//! enters the kernel, the guest image, or the `no_std` workspace (the §0
//! [DECISION] row); this file lives in the harness's own nested workspace.
//!
//! WHAT THE LIVE LEG IS (M31 proposal §4/§5, stage C):
//!
//! * **Activation** is explicit and double-gated: the `--anthropic` flag (or
//!   the `XPORT_ANTHROPIC=1` env opt-in -- the required-lane run scripts pass
//!   neither) AND `ANTHROPIC_API_KEY` present in the env. Opt-in without the
//!   key is a LOUD refusal at startup ([`NO_KEY_REFUSAL`], exit 3) -- never a
//!   silent mock fallback wearing the live token.
//! * **Key custody** (`key-custody=HOST-ENV`): the key is read from the env
//!   ONLY -- never a flag, never an arg, never printed (not even its prefix or
//!   length: GitHub log-masking fails on transformed values). Every line this
//!   module emits passes through [`scrub`] -- a paranoid belt-and-suspenders
//!   on top of the structural guarantee that witness lines are built from hex
//!   + closed tokens only.
//! * **One pinned call** ([`LIVE_MODEL`] = the operator's SPEND PIN,
//!   [`LIVE_MAX_TOKENS`] = 64; the caller's `live_done` latch makes a second
//!   call per process impossible; no retries -- a retryable outcome is
//!   REPORTED retryable, never retried into a pass).
//! * **Liveness** (§5, host leg): the prompt envelope instructs the model to
//!   reply with the character-REVERSED hex of the kernel's per-boot wire
//!   challenge (`transform=HEX-REVERSE`; the challenge is minted in-guest from
//!   the cycle counter every boot -- a canned fixture or replayed transcript
//!   carries a stale nonce and fails). A prompt echo cannot pass: the
//!   acceptance substring is `reverse(hex(N))`, not `hex(N)`.
//! * **The closed taxonomy** (§2e/§12): provider errors map to the closed
//!   outcome set below; raw provider JSON/text is NEVER printed and NEVER
//!   crosses toward the guest -- the response text's only trace is its
//!   [`tb_encode::inferwire::body_digest`] on the witness line (the same
//!   digest discipline as the wire).
//!
//! WHAT THE LIVE LEG IS **NOT** (the stage-C landing notes -- honest scope):
//!
//! * The live response does NOT ride to the guest. The stage-B kernel pins
//!   the wire exchange to the deterministic mock shape EXACTLY
//!   (`tb-hal/src/mem/selftests.rs`: stage 0x21 sizes the receive window a
//!   priori, 0x25 requires `pending == 1` + the exact chunk count, 0x26
//!   requires bit-exact equality with the in-kernel `mock_infer` expectation)
//!   -- so the guest-bound answer stays the deterministic mock response on
//!   every lane, and the kernel-side live witness/marker (§5.5) is a NAMED
//!   kernel follow-up, not a stage-C claim. The live verdict is adjudicated
//!   HOST-SIDE by `.github/workflows/real-infer.yml` from this module's
//!   witness line.
//! * The call happens AFTER the guest is answered (answer-first): the
//!   kernel's `POLL_CAP` (100M spins -- sub-second under KVM) cannot absorb
//!   HTTP latency, and extra `INFER_PENDING` heartbeats are forbidden by the
//!   stage-B exact-shape check, so verify-before-answer would only risk a
//!   hard `xport-timeout` while protecting nothing (no live byte reaches the
//!   guest either way).
//! * The transform check is probabilistic (one sample by design --
//!   `TRANSFORM-MISS` is a distinct, reported outcome, never silently
//!   retried).
//!
//! The HTTP layer sits behind the tiny [`Transport`] seam so every branch in
//! this module is unit-tested against canned JSON fixtures -- NO network in
//! tests, ever (and no test carries a real key: fixtures use obviously fake
//! strings).

use std::time::Duration;

use tb_encode::inferwire::{body_digest, INFER_BODY_CAP};

/// The pinned model id -- THE OPERATOR'S SPEND PIN. `claude-haiku-4-5` is the
/// cheapest adequate model for a 32-character string reversal (M31 proposal
/// §5.3 "cheapest adequate model" + §10 cost containment). Changing this
/// const is a deliberate, reviewed spend decision -- it is never read from
/// env/args, so no lane can escalate the spend without a code change.
pub const LIVE_MODEL: &str = "claude-haiku-4-5";

/// The pinned per-call output ceiling (M31 proposal §5.3: `max_tokens` <= 64
/// for the liveness call). 64 tokens comfortably covers the 32-character
/// reversed hex string and bounds the worst-case response bytes far below
/// [`INFER_BODY_CAP`].
pub const LIVE_MAX_TOKENS: u32 = 64;

/// The Messages API endpoint (the only URL this process ever dials).
pub const ANTHROPIC_URL: &str = "https://api.anthropic.com/v1/messages";

/// The pinned `anthropic-version` header value.
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// The ONLY source of the API key (proposal §4 `key=CAPREF-HOST-CUSTODIED`):
/// the bridge process env. Never a flag, never logged.
pub const KEY_ENV: &str = "ANTHROPIC_API_KEY";

/// The documented startup refusal (live mode opted in, key absent). The
/// run-the-hello doc and the real-infer workflow both reference this exact
/// behavior: refuse LOUDLY (exit 3), never fall back to mock wearing the
/// live token, never invent a key.
pub const NO_KEY_REFUSAL: &str = "xport-harness: --anthropic (or XPORT_ANTHROPIC=1) requested but \
     ANTHROPIC_API_KEY is absent from the environment -- refusing to serve \
     (the live bridge reads the key from the env ONLY: never a flag, never \
     logged; provision it and re-run)";

/// One HTTP reply as the bridge sees it (status + the provider-asserted
/// request-id header + the raw body TEXT, which never leaves this module
/// un-digested).
pub struct HttpReply {
    pub status: u16,
    pub request_id: Option<String>,
    pub body: String,
}

/// A transport-level fault (the call never produced an HTTP status).
pub enum HttpFault {
    /// The connect/read deadline elapsed.
    Timeout,
    /// Any other transport fault (DNS, refused, TLS, ...). The message is
    /// host-derived (never model text) and is scrubbed before any print.
    Transport(String),
}

/// The tiny HTTP seam: ONE method, so canned fixtures inject in tests and
/// `ureq` injects in production. NO test implements this with a socket.
pub trait Transport {
    fn post_json(&self, url: &str, api_key: &str, body: &str) -> Result<HttpReply, HttpFault>;
}

/// The production transport: `ureq` with rustls (the ledgered TLS stack),
/// bounded connect + overall deadlines so a wedged provider can never hang
/// the serve loop past the lane's wall-clock.
pub struct UreqTransport {
    agent: ureq::Agent,
}

impl UreqTransport {
    pub fn new() -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(10))
                .timeout(Duration::from_secs(90))
                .build(),
        }
    }
}

impl Transport for UreqTransport {
    fn post_json(&self, url: &str, api_key: &str, body: &str) -> Result<HttpReply, HttpFault> {
        let result = self
            .agent
            .post(url)
            .set("content-type", "application/json")
            .set("x-api-key", api_key)
            .set("anthropic-version", ANTHROPIC_VERSION)
            .send_string(body);
        match result {
            Ok(resp) => Ok(reply_of(resp)),
            // A non-2xx STATUS is still a reply (the error mapper owns it).
            Err(ureq::Error::Status(_code, resp)) => Ok(reply_of(resp)),
            Err(ureq::Error::Transport(t)) => {
                let msg = t.to_string();
                let lower = msg.to_ascii_lowercase();
                if lower.contains("timed out") || lower.contains("timeout") {
                    Err(HttpFault::Timeout)
                } else {
                    Err(HttpFault::Transport(msg))
                }
            }
        }
    }
}

fn reply_of(resp: ureq::Response) -> HttpReply {
    let status = resp.status();
    let request_id = resp.header("request-id").map(|s| s.to_string());
    let body = resp.into_string().unwrap_or_default();
    HttpReply {
        status,
        request_id,
        body,
    }
}

/// Lowercase hex, wire byte order -- the §6 inert-alphabet encoder (the same
/// rendering the kernel and the M30 witness path use).
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// PARANOID OUTPUT SCRUB: replace every occurrence of the key in `text`.
/// Structural guarantee already keeps the key out of every line this module
/// builds (hex + closed tokens only); the scrub is the belt-and-suspenders
/// the proposal demands ("the bridge never prints the key" -- §4), applied to
/// EVERY live-path print, stderr included.
pub fn scrub(text: &str, api_key: &str) -> String {
    if api_key.is_empty() {
        return text.to_string();
    }
    text.replace(api_key, "<key-scrubbed>")
}

/// The HEX-REVERSE liveness transform (proposal §5.2): the character-order
/// reversal of the lowercase hex of the 16-byte per-boot wire challenge.
/// Non-identity by construction -- a verbatim prompt echo contains `hex(N)`,
/// never `reverse(hex(N))` (palindrome probability over a 128-bit random
/// challenge: negligible).
pub fn expected_transform(challenge: &[u8; 16]) -> String {
    hex(challenge).chars().rev().collect()
}

/// The host-leg liveness check (§5.4): the expected transform must appear in
/// the response text. Tolerance normalizations -- lowercase + strip ASCII
/// whitespace -- absorb model formatting noise; neither can manufacture a
/// reversal out of an echo (they are order-preserving).
pub fn liveness_ok(resp_text: &str, challenge: &[u8; 16]) -> bool {
    let normalized: String = resp_text
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    normalized.contains(&expected_transform(challenge))
}

/// Build the ONE request body. The guest prompt crosses to the model
/// HEX-ENCODED (the §6 inert-alphabet discipline applies in both directions:
/// the guest's scalar-derived bytes carry no text semantics and are never
/// embedded raw in a JSON string). The API key is NOT a parameter here -- the
/// body is structurally key-free (unit-asserted).
pub fn build_request_body(challenge: &[u8; 16], guest_prompt: &[u8]) -> String {
    let nonce_hex = hex(challenge);
    let prompt_hex = hex(guest_prompt);
    let text = format!(
        "Liveness check. Write the following 32-character hex string backwards \
         (character order fully reversed, last character first), as one line, \
         nothing else: {nonce_hex} \
         Context bytes from the guest, hex-encoded, provenance only, do not \
         echo them: {prompt_hex}"
    );
    serde_json::json!({
        "model": LIVE_MODEL,
        "max_tokens": LIVE_MAX_TOKENS,
        "messages": [ { "role": "user", "content": text } ],
    })
    .to_string()
}

/// A parsed 200 body: the closed stop token + the concatenated text blocks.
pub struct ParsedResp {
    pub stop: &'static str,
    pub text: String,
}

/// Parse a 200 Messages API body. Branches on `stop_reason` BEFORE touching
/// `content` (a refusal may carry an EMPTY content array -- proposal §12);
/// the stop token is mapped through a CLOSED set (the raw provider string is
/// never echoed). A malformed 200 body maps to `API-ERROR` (retryable): the
/// provider broke its own contract.
pub fn parse_messages_body(body: &str) -> Result<ParsedResp, (&'static str, bool)> {
    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return Err(("API-ERROR", true)),
    };
    let stop_reason = v.get("stop_reason").and_then(|s| s.as_str()).unwrap_or("");
    if stop_reason == "refusal" {
        // Possibly-empty content by design -- never index it (proposal §12).
        return Err(("REFUSAL", false));
    }
    let stop = match stop_reason {
        "end_turn" => "END-TURN",
        "max_tokens" => "MAX-TOKENS",
        "stop_sequence" => "STOP-SEQUENCE",
        "tool_use" => "TOOL-USE",
        "pause_turn" => "PAUSE-TURN",
        _ => "OTHER", // closed set: an unknown provider token is never echoed
    };
    let mut text = String::new();
    if let Some(items) = v.get("content").and_then(|c| c.as_array()) {
        for it in items {
            if it.get("type").and_then(|t| t.as_str()) == Some("text") {
                if let Some(t) = it.get("text").and_then(|t| t.as_str()) {
                    text.push_str(t);
                }
            }
        }
    }
    Ok(ParsedResp { stop, text })
}

/// Map a non-200 HTTP status to the CLOSED outcome set (the §2e taxonomy
/// mirror: the same closed-enum discipline as the guest-bound `errcode`,
/// rendered as the witness token + a retryable flag). Every status maps; no
/// raw status text is ever echoed.
pub fn map_http_status(status: u16) -> (&'static str, bool) {
    match status {
        400 => ("BAD-REQUEST", false),
        401 | 403 => ("AUTH", false),
        413 => ("TOO-LARGE", false),
        429 => ("RATE-LIMITED", true),
        529 => ("OVERLOADED", true),
        500..=599 => ("API-ERROR", true),
        // Any other non-200 (404 wrong model/endpoint, 3xx, ...): a
        // request-class fault under the closed mapping.
        _ => ("BAD-REQUEST", false),
    }
}

/// The §5.4 host-leg acceptance evidence (everything on the OK witness line).
pub struct LiveEvidence {
    /// hex of the 16-byte per-boot wire challenge (the liveness nonce).
    pub nonce_hex: String,
    /// hex of the provider request-id header's ASCII bytes -- remote-derived
    /// text crosses to any log HEX-ENCODED ONLY (the §6 rule, no exceptions
    /// for "it looks safe").
    pub reqid_hex: String,
    /// `body_digest` of the response text bytes -- the fixed-width
    /// commitment; the text itself is never printed anywhere.
    pub resp_digest_hex: String,
    /// The closed stop token.
    pub stop: &'static str,
}

/// The live-call outcome: full §5.4 acceptance, or a distinct named failure.
/// The failure outcomes are DISTINCT BY DESIGN (proposal §5.7/§12):
/// `TRANSFORM-MISS` (200 + request-id, transform absent) is not
/// `LIVENESS-FAIL` (no fresh round-trip evidence) is not a retryable provider
/// fault -- and none of them is ever a pass.
pub enum LiveOutcome {
    Ok(LiveEvidence),
    Fail {
        outcome: &'static str,
        http: Option<u16>,
        retryable: bool,
    },
}

/// The ONE live call: build -> post (through the seam) -> map -> verify.
/// No retries at this layer, ever (the taxonomy REPORTS retryable, the
/// operator re-dispatches). The caller's latch enforces at-most-once per
/// process.
pub fn live_call(
    transport: &dyn Transport,
    api_key: &str,
    challenge: &[u8; 16],
    guest_prompt: &[u8],
) -> LiveOutcome {
    let body = build_request_body(challenge, guest_prompt);
    let reply = match transport.post_json(ANTHROPIC_URL, api_key, &body) {
        Ok(r) => r,
        Err(HttpFault::Timeout) => {
            return LiveOutcome::Fail {
                outcome: "TIMEOUT",
                http: None,
                retryable: true,
            }
        }
        // A non-timeout transport fault (DNS/refused/TLS) is also a
        // non-completion under the closed mapping: TIMEOUT, retryable (the
        // closed set deliberately has no NETWORK member -- proposal §2e).
        // The host-derived diagnostic goes to stderr, SCRUBBED like every
        // other live-path print.
        Err(HttpFault::Transport(msg)) => {
            eprintln!(
                "xport-harness: live transport fault: {}",
                scrub(&msg, api_key)
            );
            return LiveOutcome::Fail {
                outcome: "TIMEOUT",
                http: None,
                retryable: true,
            };
        }
    };
    if reply.status != 200 {
        let (outcome, retryable) = map_http_status(reply.status);
        return LiveOutcome::Fail {
            outcome,
            http: Some(reply.status),
            retryable,
        };
    }
    // §5.4: the request-id header is part of the acceptance (third-party-
    // correlatable evidence); 200 without it is LIVENESS-FAIL, distinct.
    let request_id = match reply.request_id {
        Some(r) if !r.is_empty() => r,
        _ => {
            return LiveOutcome::Fail {
                outcome: "LIVENESS-FAIL",
                http: Some(200),
                retryable: false,
            }
        }
    };
    let parsed = match parse_messages_body(&reply.body) {
        Ok(p) => p,
        Err((outcome, retryable)) => {
            return LiveOutcome::Fail {
                outcome,
                http: Some(200),
                retryable,
            }
        }
    };
    // Reject-never-truncate (the 413 mirror): unreachable with the pinned
    // max_tokens, asserted anyway.
    if parsed.text.len() > INFER_BODY_CAP {
        return LiveOutcome::Fail {
            outcome: "TOO-LARGE",
            http: Some(200),
            retryable: false,
        };
    }
    if !liveness_ok(&parsed.text, challenge) {
        // Compliant-but-wrong model answer: distinct, reported, NEVER
        // silently retried into a pass (proposal §5.7).
        return LiveOutcome::Fail {
            outcome: "TRANSFORM-MISS",
            http: Some(200),
            retryable: false,
        };
    }
    let digest = body_digest(parsed.text.as_bytes());
    LiveOutcome::Ok(LiveEvidence {
        nonce_hex: hex(challenge),
        reqid_hex: hex(request_id.as_bytes()),
        resp_digest_hex: hex(&digest),
        stop: parsed.stop,
    })
}

/// The OK witness line (proposal §7 bridge-witness field set on the harness's
/// M31 info prefix -- a DISTINCT prefix that matches neither the M30
/// `xport-harness: ` grep nor any guest-side filter). Built from hex + closed
/// tokens ONLY -- structurally key-free and injection-inert.
pub fn witness_line(ev: &LiveEvidence) -> String {
    format!(
        "xport-harness-infer: backend=ANTHROPIC-LIVE nonce=0x{} transform=HEX-REVERSE \
         transform-ok=1 http=200 reqid-hex={} resp-digest=0x{} model={} max-tokens={} \
         stop={} key-custody=HOST-ENV",
        ev.nonce_hex, ev.reqid_hex, ev.resp_digest_hex, LIVE_MODEL, LIVE_MAX_TOKENS, ev.stop
    )
}

/// The failure line: always `transform-ok=0` + the distinct closed outcome
/// token, so it can never satisfy the workflow's OK grep (which requires
/// `transform-ok=1 http=200`).
pub fn failure_line(
    nonce_hex: &str,
    outcome: &str,
    http: Option<u16>,
    retryable: bool,
) -> String {
    let http_s = match http {
        Some(h) => h.to_string(),
        None => "none".to_string(),
    };
    format!(
        "xport-harness-infer: backend=ANTHROPIC-LIVE nonce=0x{nonce_hex} transform=HEX-REVERSE \
         transform-ok=0 outcome={outcome} http={http_s} retryable={} key-custody=HOST-ENV",
        u8::from(retryable)
    )
}

/// Run the one live exchange and print its (scrubbed) verdict line to stdout.
/// Returns whether the §5.4 host-leg acceptance held -- informational; the
/// workflow adjudicates from the printed line, and the guest exchange is
/// independent either way.
pub fn run_live_exchange(
    transport: &dyn Transport,
    api_key: &str,
    challenge: &[u8; 16],
    guest_prompt: &[u8],
) -> bool {
    use std::io::Write;
    let (line, ok) = match live_call(transport, api_key, challenge, guest_prompt) {
        LiveOutcome::Ok(ev) => (witness_line(&ev), true),
        LiveOutcome::Fail {
            outcome,
            http,
            retryable,
        } => (failure_line(&hex(challenge), outcome, http, retryable), false),
    };
    println!("{}", scrub(&line, api_key));
    std::io::stdout().flush().ok();
    ok
}

// ---------------------------------------------------------------------------
// Fixture tests: NO network, NO real key, every branch of the bridge.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// An OBVIOUSLY fake key for the scrub/seam tests (never a real secret).
    const FAKE_KEY: &str = "sk-ant-FAKE-FIXTURE-KEY-000";

    /// A canned-reply transport: captures what the bridge sent, returns the
    /// fixture. The ONLY Transport impl tests ever use.
    struct Fixture {
        status: u16,
        request_id: Option<&'static str>,
        body: String,
        fault: Option<&'static str>, // "timeout" | "transport"
        captured: RefCell<Option<(String, String)>>, // (api_key, body)
    }

    impl Fixture {
        fn ok(body: String) -> Self {
            Self {
                status: 200,
                request_id: Some("req_011FIXTURE"),
                body,
                fault: None,
                captured: RefCell::new(None),
            }
        }
        fn status(status: u16) -> Self {
            Self {
                status,
                request_id: Some("req_011FIXTURE"),
                body: r#"{"type":"error","error":{"type":"x","message":"y"}}"#.into(),
                fault: None,
                captured: RefCell::new(None),
            }
        }
    }

    impl Transport for Fixture {
        fn post_json(
            &self,
            _url: &str,
            api_key: &str,
            body: &str,
        ) -> Result<HttpReply, HttpFault> {
            *self.captured.borrow_mut() = Some((api_key.to_string(), body.to_string()));
            match self.fault {
                Some("timeout") => Err(HttpFault::Timeout),
                Some(_) => Err(HttpFault::Transport("dns failure (fixture)".into())),
                None => Ok(HttpReply {
                    status: self.status,
                    request_id: self.request_id.map(|s| s.to_string()),
                    body: self.body.clone(),
                }),
            }
        }
    }

    const CHALLENGE: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba,
        0xdc, 0xfe,
    ];

    fn ok_body_with(text: &str) -> String {
        serde_json::json!({
            "id": "msg_fixture",
            "type": "message",
            "role": "assistant",
            "stop_reason": "end_turn",
            "content": [ { "type": "text", "text": text } ],
        })
        .to_string()
    }

    // --- the request builder ------------------------------------------------

    #[test]
    fn request_builder_pins_model_and_max_tokens() {
        let body = build_request_body(&CHALLENGE, b"guest-prompt");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["model"], "claude-haiku-4-5"); // the spend pin, literal
        assert_eq!(v["max_tokens"], 64);
        assert_eq!(v["messages"].as_array().unwrap().len(), 1); // ONE message
        let text = v["messages"][0]["content"].as_str().unwrap();
        // The challenge hex (the thing to reverse) is in the envelope...
        assert!(text.contains(&hex(&CHALLENGE)));
        // ...and the guest prompt crosses HEX-ENCODED only, never raw.
        assert!(text.contains(&hex(b"guest-prompt")));
        assert!(!text.contains("guest-prompt"));
    }

    #[test]
    fn request_body_is_structurally_key_free() {
        // The builder does not even TAKE the key; assert the seam sees the
        // key only as the header parameter and the body never contains it.
        let fx = Fixture::ok(ok_body_with("x"));
        let _ = live_call(&fx, FAKE_KEY, &CHALLENGE, b"p");
        let (sent_key, sent_body) = fx.captured.borrow().clone().unwrap();
        assert_eq!(sent_key, FAKE_KEY); // header path only
        assert!(!sent_body.contains(FAKE_KEY)); // body: key-free
    }

    // --- the liveness checker ----------------------------------------------

    #[test]
    fn transform_is_the_character_reversal() {
        let h = hex(&CHALLENGE);
        let t = expected_transform(&CHALLENGE);
        assert_eq!(t.len(), 32);
        assert_eq!(t, h.chars().rev().collect::<String>());
        assert_ne!(t, h); // non-identity on this (non-palindromic) challenge
    }

    #[test]
    fn liveness_accepts_the_reversal_and_rejects_the_echo() {
        let reversed = expected_transform(&CHALLENGE);
        assert!(liveness_ok(&format!("Sure: {reversed}"), &CHALLENGE));
        // Tolerances: case + whitespace noise (order-preserving only).
        let spaced: String = reversed
            .chars()
            .flat_map(|c| [c.to_ascii_uppercase(), ' '])
            .collect();
        assert!(liveness_ok(&spaced, &CHALLENGE));
        // A verbatim PROMPT ECHO must not pass (hex(N) != reverse(hex(N))).
        assert!(!liveness_ok(&hex(&CHALLENGE), &CHALLENGE));
        assert!(!liveness_ok("no transform here", &CHALLENGE));
    }

    // --- the response parser -------------------------------------------------

    #[test]
    fn parser_extracts_text_and_maps_the_stop_token() {
        let p = parse_messages_body(&ok_body_with("hello-bytes")).unwrap();
        assert_eq!(p.stop, "END-TURN");
        assert_eq!(p.text, "hello-bytes");
    }

    #[test]
    fn parser_branches_on_refusal_before_reading_content() {
        // A refusal may carry an EMPTY content array (proposal §12) -- the
        // parser must never index it.
        let body = r#"{"stop_reason":"refusal","content":[]}"#;
        assert!(matches!(parse_messages_body(body), Err(("REFUSAL", false))));
    }

    #[test]
    fn parser_never_echoes_an_unknown_stop_token() {
        let body = r#"{"stop_reason":"weird_new_reason","content":[{"type":"text","text":"x"}]}"#;
        let p = parse_messages_body(body).unwrap();
        assert_eq!(p.stop, "OTHER"); // the closed set absorbs the unknown
    }

    #[test]
    fn parser_maps_a_malformed_200_body_to_api_error() {
        assert!(matches!(
            parse_messages_body("this is not json"),
            Err(("API-ERROR", true))
        ));
    }

    // --- the error mapper (the closed taxonomy) -----------------------------

    #[test]
    fn error_mapper_is_the_closed_taxonomy() {
        assert_eq!(map_http_status(400), ("BAD-REQUEST", false));
        assert_eq!(map_http_status(401), ("AUTH", false));
        assert_eq!(map_http_status(403), ("AUTH", false));
        assert_eq!(map_http_status(404), ("BAD-REQUEST", false));
        assert_eq!(map_http_status(413), ("TOO-LARGE", false));
        assert_eq!(map_http_status(429), ("RATE-LIMITED", true));
        assert_eq!(map_http_status(500), ("API-ERROR", true));
        assert_eq!(map_http_status(529), ("OVERLOADED", true));
        assert_eq!(map_http_status(418), ("BAD-REQUEST", false));
    }

    #[test]
    fn fake_key_against_the_fixture_seam_walks_the_auth_path() {
        // The documented dry-run: a FAKE key -> the provider answers 401 ->
        // the mapper yields AUTH, non-retryable, and the failure line says so.
        let fx = Fixture::status(401);
        match live_call(&fx, FAKE_KEY, &CHALLENGE, b"p") {
            LiveOutcome::Fail {
                outcome,
                http,
                retryable,
            } => {
                assert_eq!(outcome, "AUTH");
                assert_eq!(http, Some(401));
                assert!(!retryable);
                let line = failure_line(&hex(&CHALLENGE), outcome, http, retryable);
                assert!(line.contains("transform-ok=0"));
                assert!(line.contains("outcome=AUTH"));
                assert!(line.contains("http=401"));
                assert!(!line.contains(FAKE_KEY));
            }
            _ => panic!("a 401 must map to AUTH"),
        }
    }

    #[test]
    fn retryable_statuses_are_reported_retryable_never_passed() {
        for (status, want) in [(429u16, "RATE-LIMITED"), (529, "OVERLOADED"), (500, "API-ERROR")]
        {
            match live_call(&Fixture::status(status), FAKE_KEY, &CHALLENGE, b"p") {
                LiveOutcome::Fail {
                    outcome, retryable, ..
                } => {
                    assert_eq!(outcome, want);
                    assert!(retryable);
                }
                _ => panic!("status {status} must be a Fail"),
            }
        }
    }

    #[test]
    fn transport_faults_map_to_timeout_retryable() {
        for fault in ["timeout", "transport"] {
            let fx = Fixture {
                fault: Some(fault),
                ..Fixture::ok(String::new())
            };
            match live_call(&fx, FAKE_KEY, &CHALLENGE, b"p") {
                LiveOutcome::Fail {
                    outcome,
                    http,
                    retryable,
                } => {
                    assert_eq!(outcome, "TIMEOUT");
                    assert_eq!(http, None);
                    assert!(retryable);
                }
                _ => panic!("a transport fault must be a Fail"),
            }
        }
    }

    // --- the §5.4 acceptance + the distinct liveness verdicts ----------------

    #[test]
    fn happy_path_yields_the_full_witness() {
        let reversed = expected_transform(&CHALLENGE);
        let text = format!("The reversed string is: {reversed}");
        let fx = Fixture::ok(ok_body_with(&text));
        match live_call(&fx, FAKE_KEY, &CHALLENGE, b"prompt-bytes") {
            LiveOutcome::Ok(ev) => {
                assert_eq!(ev.nonce_hex, hex(&CHALLENGE));
                assert_eq!(ev.reqid_hex, hex(b"req_011FIXTURE")); // hex-encoded remote text
                assert_eq!(ev.resp_digest_hex, hex(&body_digest(text.as_bytes())));
                assert_eq!(ev.stop, "END-TURN");
                let line = witness_line(&ev);
                assert!(line.starts_with("xport-harness-infer: backend=ANTHROPIC-LIVE "));
                assert!(line.contains("transform=HEX-REVERSE transform-ok=1 http=200"));
                assert!(line.contains("model=claude-haiku-4-5 max-tokens=64"));
                assert!(line.contains("key-custody=HOST-ENV"));
                assert!(!line.contains(FAKE_KEY));
            }
            _ => panic!("the compliant fixture must satisfy §5.4"),
        }
    }

    #[test]
    fn transform_miss_is_distinct_from_liveness_fail() {
        // 200 + request-id + a NON-compliant answer: TRANSFORM-MISS.
        let fx = Fixture::ok(ok_body_with("I refuse to reverse strings today."));
        match live_call(&fx, FAKE_KEY, &CHALLENGE, b"p") {
            LiveOutcome::Fail {
                outcome,
                http,
                retryable,
            } => {
                assert_eq!(outcome, "TRANSFORM-MISS");
                assert_eq!(http, Some(200));
                assert!(!retryable);
            }
            _ => panic!("a transform-less 200 must be TRANSFORM-MISS"),
        }
        // 200 WITHOUT a request-id: LIVENESS-FAIL (no fresh round-trip
        // evidence), a DIFFERENT token by design.
        let mut fx = Fixture::ok(ok_body_with(&expected_transform(&CHALLENGE)));
        fx.request_id = None;
        match live_call(&fx, FAKE_KEY, &CHALLENGE, b"p") {
            LiveOutcome::Fail { outcome, .. } => assert_eq!(outcome, "LIVENESS-FAIL"),
            _ => panic!("200 sans request-id must be LIVENESS-FAIL"),
        }
    }

    #[test]
    fn oversize_response_rejects_never_truncates() {
        // > INFER_BODY_CAP of text: TOO-LARGE (the 413 mirror), even on 200.
        let big = "a".repeat(INFER_BODY_CAP + 1);
        let fx = Fixture::ok(ok_body_with(&big));
        match live_call(&fx, FAKE_KEY, &CHALLENGE, b"p") {
            LiveOutcome::Fail { outcome, .. } => assert_eq!(outcome, "TOO-LARGE"),
            _ => panic!("an oversize body must reject"),
        }
    }

    // --- the key scrub --------------------------------------------------------

    #[test]
    fn scrub_removes_every_key_occurrence() {
        let dirty = format!("a {FAKE_KEY} b {FAKE_KEY}");
        let clean = scrub(&dirty, FAKE_KEY);
        assert!(!clean.contains(FAKE_KEY));
        assert_eq!(clean, "a <key-scrubbed> b <key-scrubbed>");
        // The empty-key edge never panics or mutates.
        assert_eq!(scrub("text", ""), "text");
    }

    #[test]
    fn even_a_key_echoing_model_cannot_leak_it() {
        // Adversarial fixture: the model "echoes" the key inside an otherwise
        // compliant answer. The text is DIGESTED, never printed -- the
        // witness carries hex + closed tokens only -- and the scrub guards
        // the line anyway. Both layers asserted.
        let reversed = expected_transform(&CHALLENGE);
        let text = format!("{reversed} {FAKE_KEY}");
        let fx = Fixture::ok(ok_body_with(&text));
        match live_call(&fx, FAKE_KEY, &CHALLENGE, b"p") {
            LiveOutcome::Ok(ev) => {
                let line = witness_line(&ev);
                assert!(!line.contains(FAKE_KEY)); // structural
                assert!(!scrub(&line, FAKE_KEY).contains(FAKE_KEY)); // belt-and-suspenders
            }
            _ => panic!("the fixture is compliant"),
        }
    }

    #[test]
    fn the_refusal_message_documents_the_env_only_rule() {
        // The documented startup refusal (the dry-run negative greps this).
        assert!(NO_KEY_REFUSAL.contains("ANTHROPIC_API_KEY"));
        assert!(NO_KEY_REFUSAL.contains("refusing to serve"));
        assert!(NO_KEY_REFUSAL.contains("env ONLY"));
    }
}
