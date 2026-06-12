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
//! * **Liveness** (§5, host leg): the prompt envelope renders the kernel's
//!   per-boot wire challenge as 4 pre-grouped hex groups and instructs the
//!   model to reply with the groups in REVERSE ORDER
//!   (`transform=HEX-GROUP-REVERSE` -- v2; v1's character-level reversal was
//!   a tokenization-unrealistic CAPABILITY test, see [`expected_transform`];
//!   the challenge is minted in-guest from the cycle counter every boot -- a
//!   canned fixture or replayed transcript carries a stale nonce and fails).
//!   A prompt echo cannot pass: the acceptance substring is the REVERSED
//!   group concatenation, never the forward one.
//! * **The closed taxonomy** (§2e/§12): provider errors map to the closed
//!   outcome set below; raw provider JSON/text is NEVER printed and NEVER
//!   crosses toward the guest -- the response text's traces are its
//!   [`tb_encode::inferwire::body_digest`] on the verdict line (the same
//!   digest discipline as the wire) and the scrubbed hex-framed
//!   [`body_line`] (emitted on OK and on the 200-class failures
//!   TRANSFORM-MISS/REFUSAL, so a failed hello is still witnessable).
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
/// reversed-groups line and bounds the worst-case response bytes far below
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

/// The 32-hex-char challenge rendered as 4 groups of 8, FORWARD order --
/// exactly how the prompt presents it (pre-grouped, so the model never has
/// to segment a 32-char blob itself).
pub fn challenge_groups(challenge: &[u8; 16]) -> [String; 4] {
    let h = hex(challenge);
    [
        h[0..8].to_string(),
        h[8..16].to_string(),
        h[16..24].to_string(),
        h[24..32].to_string(),
    ]
}

/// The HEX-GROUP-REVERSE liveness transform (v2): the 4 pre-grouped 8-char
/// hex groups in REVERSE GROUP ORDER, concatenated (the acceptance
/// normalization strips the model's separators, so spacing never matters).
///
/// WHY v2 (the `transform=HEX-REVERSE` retrospective): character-level
/// string reversal is a KNOWN LLM tokenization weakness -- the first live
/// dispatch (run 27408247558) returned a REAL 200 whose text missed the
/// char-reversal (`outcome=TRANSFORM-MISS`, fail-closed as designed): v1
/// tested model CAPABILITY, not liveness. Group-ORDER reversal is a trivial
/// sequence task for any model, and every liveness property is preserved:
/// the expected substring derives from THIS boot's kernel-minted challenge
/// (fresh per boot), and a verbatim prompt echo normalizes to the FORWARD
/// concatenation, never the reversed one. Non-identity degrades only if all
/// four groups are equal (~2^-72 over a 128-bit random challenge); the
/// challenge cannot be re-minted here (it is the kernel's), so in that
/// astronomically unlikely case the lane fails HONESTLY -- assert-and-
/// proceed, never re-mint, never widen acceptance.
pub fn expected_transform(challenge: &[u8; 16]) -> String {
    let g = challenge_groups(challenge);
    format!("{}{}{}{}", g[3], g[2], g[1], g[0])
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
///
/// The envelope asks for TWO lines: line 1 is the strict liveness transform
/// (the four pre-grouped hex groups in reverse order, nothing else ON THAT
/// LINE), line 2 is one short greeting to Yuva -- the hello this lane exists
/// for. The greeting is §5-COMPATIBLE BY CONSTRUCTION: acceptance
/// ([`liveness_ok`]) is the normalized substring search for the transform
/// and nothing else, so the greeting line can neither help a non-compliant
/// answer pass nor fail a compliant one (unit-asserted both ways). A
/// truncated or missing greeting is a model-behavior matter, never a lane
/// verdict; `max_tokens=64` covers the 35-char transform line plus a short
/// sentence.
pub fn build_request_body(challenge: &[u8; 16], guest_prompt: &[u8]) -> String {
    let g = challenge_groups(challenge);
    let grouped = format!("{} {} {} {}", g[0], g[1], g[2], g[3]);
    let prompt_hex = hex(guest_prompt);
    let text = format!(
        "Liveness check plus a first hello. Reply with exactly two lines. \
         Line 1: the following four 8-character hex groups written in \
         REVERSE ORDER (last group first, first group last), space-separated, \
         and nothing else on that line: {grouped} \
         Line 2: one short sentence greeting Yuva, the machine that sent you \
         this message. \
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

/// Parse a 200 Messages API body. The error side carries `(outcome,
/// retryable, text)`: a REFUSAL's (possibly empty -- proposal §12; the
/// content array is ITERATED, never indexed) text rides along so the body
/// line can frame what the model actually said even on the failure path; a
/// malformed 200 body maps to `API-ERROR` (retryable, no text): the provider
/// broke its own contract. The stop token is mapped through a CLOSED set
/// (the raw provider string is never echoed).
#[allow(clippy::type_complexity)]
pub fn parse_messages_body(
    body: &str,
) -> Result<ParsedResp, (&'static str, bool, Option<String>)> {
    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return Err(("API-ERROR", true, None)),
    };
    let stop_reason = v.get("stop_reason").and_then(|s| s.as_str()).unwrap_or("");
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
    if stop_reason == "refusal" {
        // The refusal verdict still carries whatever text came with it
        // (possibly none) -- visible-but-failed, never silently dropped.
        return Err(("REFUSAL", false, Some(text)));
    }
    let stop = match stop_reason {
        "end_turn" => "END-TURN",
        "max_tokens" => "MAX-TOKENS",
        "stop_sequence" => "STOP-SEQUENCE",
        "tool_use" => "TOOL-USE",
        "pause_turn" => "PAUSE-TURN",
        _ => "OTHER", // closed set: an unknown provider token is never echoed
    };
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

/// The §5.4 host-leg acceptance evidence (everything on the OK witness line,
/// plus the verified response text the body line frames).
pub struct LiveEvidence {
    /// hex of the 16-byte per-boot wire challenge (the liveness nonce).
    pub nonce_hex: String,
    /// hex of the provider request-id header's ASCII bytes -- remote-derived
    /// text crosses to any log HEX-ENCODED ONLY (the §6 rule, no exceptions
    /// for "it looks safe").
    pub reqid_hex: String,
    /// `body_digest` of the RAW response text bytes -- the fixed-width
    /// commitment (computed BEFORE any scrub, so it commits to what the
    /// model actually said).
    pub resp_digest_hex: String,
    /// The closed stop token.
    pub stop: &'static str,
    /// The RAW response text. NEVER printed raw: its only log surfaces are
    /// the digest above and the scrubbed, capped, hex-framed [`body_line`].
    pub text: String,
}

/// The model-said-something evidence a 200-class FAILURE carries: the lane
/// failed, but what the model actually said must still be witnessable
/// (the run-27408247558 lesson: a real 200 whose text we could not see).
pub struct RespBody {
    /// `body_digest` of the RAW text (the commitment exists -- print it).
    pub resp_digest_hex: String,
    /// The RAW text; same rules as [`LiveEvidence::text`] -- never printed
    /// raw, framed only through [`body_line`].
    pub text: String,
}

/// The live-call outcome: full §5.4 acceptance, or a distinct named failure.
/// The failure outcomes are DISTINCT BY DESIGN (proposal §5.7/§12):
/// `TRANSFORM-MISS` (200 + request-id, transform absent) is not
/// `LIVENESS-FAIL` (no fresh round-trip evidence) is not a retryable provider
/// fault -- and none of them is ever a pass. `resp` is `Some` for exactly
/// the outcomes that carry a 200 response text -- `TRANSFORM-MISS` and
/// `REFUSAL` -- and `None` for every other outcome (transport/auth/status
/// faults, LIVENESS-FAIL, TOO-LARGE's reject-never-truncate, malformed-200).
pub enum LiveOutcome {
    Ok(LiveEvidence),
    Fail {
        outcome: &'static str,
        http: Option<u16>,
        retryable: bool,
        resp: Option<RespBody>,
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
                resp: None,
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
                resp: None,
            };
        }
    };
    if reply.status != 200 {
        let (outcome, retryable) = map_http_status(reply.status);
        return LiveOutcome::Fail {
            outcome,
            http: Some(reply.status),
            retryable,
            resp: None,
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
                resp: None,
            }
        }
    };
    let parsed = match parse_messages_body(&reply.body) {
        Ok(p) => p,
        Err((outcome, retryable, text)) => {
            // A REFUSAL's (possibly empty) text rides along: the lane fails,
            // but what the model said stays witnessable.
            let resp = text.map(|t| RespBody {
                resp_digest_hex: hex(&body_digest(t.as_bytes())),
                text: t,
            });
            return LiveOutcome::Fail {
                outcome,
                http: Some(200),
                retryable,
                resp,
            };
        }
    };
    // Reject-never-truncate (the 413 mirror): unreachable with the pinned
    // max_tokens, asserted anyway (no body framed -- framing a capped view
    // of an oversize body would soften the reject).
    if parsed.text.len() > INFER_BODY_CAP {
        return LiveOutcome::Fail {
            outcome: "TOO-LARGE",
            http: Some(200),
            retryable: false,
            resp: None,
        };
    }
    if !liveness_ok(&parsed.text, challenge) {
        // Compliant-but-wrong model answer: distinct, reported, NEVER
        // silently retried into a pass (proposal §5.7) -- and since run
        // 27408247558, WITNESSABLE: the digest + hex-framed body ride the
        // failure verdict.
        let digest = body_digest(parsed.text.as_bytes());
        return LiveOutcome::Fail {
            outcome: "TRANSFORM-MISS",
            http: Some(200),
            retryable: false,
            resp: Some(RespBody {
                resp_digest_hex: hex(&digest),
                text: parsed.text,
            }),
        };
    }
    let digest = body_digest(parsed.text.as_bytes());
    LiveOutcome::Ok(LiveEvidence {
        nonce_hex: hex(challenge),
        reqid_hex: hex(request_id.as_bytes()),
        resp_digest_hex: hex(&digest),
        stop: parsed.stop,
        text: parsed.text,
    })
}

/// The OK witness line (proposal §7 bridge-witness field set on the harness's
/// M31 info prefix -- a DISTINCT prefix that matches neither the M30
/// `xport-harness: ` grep nor any guest-side filter). Built from hex + closed
/// tokens ONLY -- structurally key-free and injection-inert.
pub fn witness_line(ev: &LiveEvidence) -> String {
    format!(
        "xport-harness-infer: backend=ANTHROPIC-LIVE nonce=0x{} transform=HEX-GROUP-REVERSE \
         transform-ok=1 http=200 reqid-hex={} resp-digest=0x{} model={} max-tokens={} \
         stop={} key-custody=HOST-ENV",
        ev.nonce_hex, ev.reqid_hex, ev.resp_digest_hex, LIVE_MODEL, LIVE_MAX_TOKENS, ev.stop
    )
}

/// The failure line: always `transform-ok=0` + the distinct closed outcome
/// token, so it can never satisfy the workflow's OK grep (which requires
/// `transform-ok=1 http=200`). A 200-class failure that carries a response
/// (TRANSFORM-MISS/REFUSAL) also prints its `resp-digest=` -- the commitment
/// exists, so it is printed.
pub fn failure_line(
    nonce_hex: &str,
    outcome: &str,
    http: Option<u16>,
    retryable: bool,
    resp_digest_hex: Option<&str>,
) -> String {
    let http_s = match http {
        Some(h) => h.to_string(),
        None => "none".to_string(),
    };
    let digest_s = match resp_digest_hex {
        Some(d) => format!(" resp-digest=0x{d}"),
        None => String::new(),
    };
    format!(
        "xport-harness-infer: backend=ANTHROPIC-LIVE nonce=0x{nonce_hex} transform=HEX-GROUP-REVERSE \
         transform-ok=0 outcome={outcome} http={http_s} retryable={}{digest_s} key-custody=HOST-ENV",
        u8::from(retryable)
    )
}

/// The body-line cap: at most this many bytes of the (scrubbed) response
/// text are hex-framed (4096 hex chars on the wire-side of the line). With
/// the pinned `max_tokens=64` a real response sits far below this; the cap
/// bounds the log line regardless.
pub const BODY_LINE_CAP: usize = 2048;

/// The ONE hex-framed body line -- THE HELLO, made witnessable. Emitted ONLY
/// after the OK witness (never on a failure verdict). Grammar:
///
/// ```text
/// xport-harness-infer-body: len=<dec> truncated=<0|1> hex=<lowercase hex>
/// ```
///
/// `len` is the FULL scrubbed-text byte length (decimal); `hex` frames the
/// first `min(len, BODY_LINE_CAP)` bytes (EMPTY `hex=` for an empty text --
/// e.g. an empty-content refusal: the line still prints, so silence stays
/// distinguishable from emptiness); `truncated=1` iff the cap bit. The text
/// is [`scrub`]'d BEFORE framing (a key-echoing model cannot leak the key
/// even hex-encoded), so the verdict line's `resp-digest` -- computed over
/// the RAW text -- remains the commitment to what the model actually said
/// while this line is the redacted, §6 inert-alphabet VIEW of it. Raw model
/// text still appears in no log anywhere; the human-readable decode happens
/// ONLY on the workflow's run-summary page, from this line. The prefix is
/// deliberately DISJOINT from the verdict prefix `xport-harness-infer: ` (the
/// workflow's exactly-one-verdict count grep cannot match it -- asserted in
/// the tests).
pub fn body_line(text: &str, api_key: &str) -> String {
    let scrubbed = scrub(text, api_key);
    let bytes = scrubbed.as_bytes();
    let take = bytes.len().min(BODY_LINE_CAP);
    format!(
        "xport-harness-infer-body: len={} truncated={} hex={}",
        bytes.len(),
        u8::from(bytes.len() > BODY_LINE_CAP),
        hex(&bytes[..take])
    )
}

/// Render the verdict line set for one live-call outcome:
///
/// * OK -> EXACTLY `[witness, body]`;
/// * a 200-class failure carrying a response (TRANSFORM-MISS / REFUSAL,
///   `resp: Some`) -> EXACTLY `[failure-with-digest, body]` -- the lane
///   fails, but what the model said is witnessable (the run-27408247558
///   lesson);
/// * every other failure -> EXACTLY `[failure]`, no body line.
///
/// With the caller's one-call latch that is at most one body line per
/// process. Pure, so the per-outcome emission matrix is unit-asserted.
pub fn verdict_lines(
    outcome: &LiveOutcome,
    challenge: &[u8; 16],
    api_key: &str,
) -> Vec<String> {
    match outcome {
        LiveOutcome::Ok(ev) => vec![witness_line(ev), body_line(&ev.text, api_key)],
        LiveOutcome::Fail {
            outcome,
            http,
            retryable,
            resp,
        } => {
            let mut lines = vec![failure_line(
                &hex(challenge),
                outcome,
                *http,
                *retryable,
                resp.as_ref().map(|r| r.resp_digest_hex.as_str()),
            )];
            if let Some(r) = resp {
                lines.push(body_line(&r.text, api_key));
            }
            lines
        }
    }
}

/// Run the one live exchange and print its (scrubbed) verdict lines to
/// stdout. Returns whether the §5.4 host-leg acceptance held --
/// informational; the workflow adjudicates from the printed lines, and the
/// guest exchange is independent either way.
pub fn run_live_exchange(
    transport: &dyn Transport,
    api_key: &str,
    challenge: &[u8; 16],
    guest_prompt: &[u8],
) -> bool {
    use std::io::Write;
    let outcome = live_call(transport, api_key, challenge, guest_prompt);
    for line in verdict_lines(&outcome, challenge, api_key) {
        println!("{}", scrub(&line, api_key));
    }
    std::io::stdout().flush().ok();
    matches!(outcome, LiveOutcome::Ok(_))
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
        // The challenge is in the envelope PRE-GROUPED (4 space-separated
        // groups of 8, forward order -- the model never segments a blob)...
        let g = challenge_groups(&CHALLENGE);
        assert!(text.contains(&format!("{} {} {} {}", g[0], g[1], g[2], g[3])));
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
    fn transform_is_the_group_reversal() {
        // CHALLENGE hex = "0123456789abcdef1032547698badcfe"; groups forward:
        // 01234567 89abcdef 10325476 98badcfe; v2 expected = the groups in
        // reverse ORDER, concatenated (chars inside each group stay forward).
        let g = challenge_groups(&CHALLENGE);
        assert_eq!(g[0], "01234567");
        assert_eq!(g[3], "98badcfe");
        let t = expected_transform(&CHALLENGE);
        assert_eq!(t.len(), 32);
        assert_eq!(t, "98badcfe1032547689abcdef01234567");
        assert_eq!(t, format!("{}{}{}{}", g[3], g[2], g[1], g[0]));
        // Non-identity: the forward concatenation differs (the four groups
        // are not all equal on this -- and on any realistic -- challenge).
        assert_ne!(t, hex(&CHALLENGE));
        // And v2 is NOT the old v1 char-reversal (group-internal order is
        // preserved): the tokenization-unrealistic transform is retired.
        let v1: String = hex(&CHALLENGE).chars().rev().collect();
        assert_ne!(t, v1);
    }

    #[test]
    fn liveness_accepts_the_group_reversal_and_rejects_the_echo() {
        let g = challenge_groups(&CHALLENGE);
        // The natural model answer: reversed groups, space-separated, plus
        // arbitrary spacing/case noise -- the normalization absorbs it.
        let natural = format!("{} {} {} {}", g[3], g[2], g[1], g[0]);
        assert!(liveness_ok(&natural, &CHALLENGE));
        assert!(liveness_ok(&format!("Sure: {natural}"), &CHALLENGE));
        assert!(liveness_ok(&natural.to_ascii_uppercase(), &CHALLENGE));
        let noisy: String = expected_transform(&CHALLENGE)
            .chars()
            .flat_map(|c| [c.to_ascii_uppercase(), ' '])
            .collect();
        assert!(liveness_ok(&noisy, &CHALLENGE));
        // A verbatim PROMPT ECHO (forward groups, spaced or not) must not
        // pass -- it normalizes to the FORWARD concatenation.
        let echo = format!("{} {} {} {}", g[0], g[1], g[2], g[3]);
        assert!(!liveness_ok(&echo, &CHALLENGE));
        assert!(!liveness_ok(&hex(&CHALLENGE), &CHALLENGE));
        // The OLD v1 char-reversal is NOT the v2 expected -- a model still
        // answering v1 is correctly rejected under v2.
        let v1: String = hex(&CHALLENGE).chars().rev().collect();
        assert!(!liveness_ok(&v1, &CHALLENGE));
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
    fn parser_carries_refusal_text_and_never_indexes_content() {
        // A refusal may carry an EMPTY content array (proposal §12) -- the
        // parser ITERATES, never indexes; the (empty) text rides the verdict.
        let body = r#"{"stop_reason":"refusal","content":[]}"#;
        match parse_messages_body(body) {
            Err(("REFUSAL", false, Some(text))) => assert_eq!(text, ""),
            _ => panic!("an empty-content refusal must map to REFUSAL with empty text"),
        }
        // And a refusal WITH text carries it (visible-but-failed).
        let body = r#"{"stop_reason":"refusal","content":[{"type":"text","text":"no."}]}"#;
        match parse_messages_body(body) {
            Err(("REFUSAL", false, Some(text))) => assert_eq!(text, "no."),
            _ => panic!("a refusal with text must carry it"),
        }
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
            Err(("API-ERROR", true, None))
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
                resp,
            } => {
                assert_eq!(outcome, "AUTH");
                assert_eq!(http, Some(401));
                assert!(!retryable);
                assert!(resp.is_none()); // no 200 body to witness
                let line = failure_line(&hex(&CHALLENGE), outcome, http, retryable, None);
                assert!(line.contains("transform-ok=0"));
                assert!(line.contains("outcome=AUTH"));
                assert!(line.contains("http=401"));
                assert!(!line.contains("resp-digest=")); // body-less verdict
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
                    resp,
                } => {
                    assert_eq!(outcome, "TIMEOUT");
                    assert_eq!(http, None);
                    assert!(retryable);
                    assert!(resp.is_none());
                }
                _ => panic!("a transport fault must be a Fail"),
            }
        }
    }

    // --- the §5.4 acceptance + the distinct liveness verdicts ----------------

    #[test]
    fn happy_path_yields_the_full_witness() {
        let reversed = expected_transform(&CHALLENGE);
        let text = format!("The reversed groups are: {reversed}");
        let fx = Fixture::ok(ok_body_with(&text));
        match live_call(&fx, FAKE_KEY, &CHALLENGE, b"prompt-bytes") {
            LiveOutcome::Ok(ev) => {
                assert_eq!(ev.nonce_hex, hex(&CHALLENGE));
                assert_eq!(ev.reqid_hex, hex(b"req_011FIXTURE")); // hex-encoded remote text
                assert_eq!(ev.resp_digest_hex, hex(&body_digest(text.as_bytes())));
                assert_eq!(ev.stop, "END-TURN");
                let line = witness_line(&ev);
                assert!(line.starts_with("xport-harness-infer: backend=ANTHROPIC-LIVE "));
                assert!(line.contains("transform=HEX-GROUP-REVERSE transform-ok=1 http=200"));
                assert!(line.contains("model=claude-haiku-4-5 max-tokens=64"));
                assert!(line.contains("key-custody=HOST-ENV"));
                assert!(!line.contains(FAKE_KEY));
            }
            _ => panic!("the compliant fixture must satisfy §5.4"),
        }
    }

    #[test]
    fn transform_miss_is_distinct_from_liveness_fail_and_carries_the_body() {
        // 200 + request-id + a NON-compliant answer: TRANSFORM-MISS, WITH the
        // response evidence (digest + text) riding the verdict -- the
        // run-27408247558 fix: the lane fails but the words are witnessable.
        let said = "I refuse to reverse anything today.";
        let fx = Fixture::ok(ok_body_with(said));
        match live_call(&fx, FAKE_KEY, &CHALLENGE, b"p") {
            LiveOutcome::Fail {
                outcome,
                http,
                retryable,
                resp,
            } => {
                assert_eq!(outcome, "TRANSFORM-MISS");
                assert_eq!(http, Some(200));
                assert!(!retryable);
                let r = resp.expect("a TRANSFORM-MISS carries the body");
                assert_eq!(r.text, said);
                assert_eq!(r.resp_digest_hex, hex(&body_digest(said.as_bytes())));
                // The failure line prints the commitment.
                let line = failure_line(
                    &hex(&CHALLENGE),
                    outcome,
                    http,
                    retryable,
                    Some(&r.resp_digest_hex),
                );
                assert!(line.contains(&format!(" resp-digest=0x{}", r.resp_digest_hex)));
                assert!(line.contains("transform-ok=0"));
            }
            _ => panic!("a transform-less 200 must be TRANSFORM-MISS"),
        }
        // 200 WITHOUT a request-id: LIVENESS-FAIL (no fresh round-trip
        // evidence), a DIFFERENT token by design -- and body-less (the §5.4
        // evidence chain broke before the text was adjudicated).
        let mut fx = Fixture::ok(ok_body_with(&expected_transform(&CHALLENGE)));
        fx.request_id = None;
        match live_call(&fx, FAKE_KEY, &CHALLENGE, b"p") {
            LiveOutcome::Fail { outcome, resp, .. } => {
                assert_eq!(outcome, "LIVENESS-FAIL");
                assert!(resp.is_none());
            }
            _ => panic!("200 sans request-id must be LIVENESS-FAIL"),
        }
    }

    #[test]
    fn refusal_carries_its_possibly_empty_body() {
        // A refusal WITH text: the verdict carries it.
        let body = r#"{"stop_reason":"refusal","content":[{"type":"text","text":"I cannot help."}]}"#;
        let fx = Fixture::ok(body.to_string());
        match live_call(&fx, FAKE_KEY, &CHALLENGE, b"p") {
            LiveOutcome::Fail { outcome, resp, .. } => {
                assert_eq!(outcome, "REFUSAL");
                let r = resp.expect("a refusal carries its (possibly empty) body");
                assert_eq!(r.text, "I cannot help.");
            }
            _ => panic!("a refusal must map to REFUSAL"),
        }
        // An EMPTY-content refusal still carries Some("") -- the body line
        // prints len=0 (emptiness, not silence).
        let body = r#"{"stop_reason":"refusal","content":[]}"#;
        let fx = Fixture::ok(body.to_string());
        match live_call(&fx, FAKE_KEY, &CHALLENGE, b"p") {
            LiveOutcome::Fail { outcome, resp, .. } => {
                assert_eq!(outcome, "REFUSAL");
                assert_eq!(resp.expect("Some even when empty").text, "");
            }
            _ => panic!("an empty refusal must still map to REFUSAL"),
        }
    }

    #[test]
    fn oversize_response_rejects_never_truncates() {
        // > INFER_BODY_CAP of text: TOO-LARGE (the 413 mirror), even on 200
        // -- and deliberately body-less (framing a capped view would soften
        // the reject).
        let big = "a".repeat(INFER_BODY_CAP + 1);
        let fx = Fixture::ok(ok_body_with(&big));
        match live_call(&fx, FAKE_KEY, &CHALLENGE, b"p") {
            LiveOutcome::Fail { outcome, resp, .. } => {
                assert_eq!(outcome, "TOO-LARGE");
                assert!(resp.is_none());
            }
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
        // compliant answer. The witness carries hex + closed tokens only; the
        // body line frames the SCRUBBED text (so not even the hex of the key
        // appears); the scrub guards every printed line anyway. All layers
        // asserted.
        let reversed = expected_transform(&CHALLENGE);
        let text = format!("{reversed} {FAKE_KEY}");
        let fx = Fixture::ok(ok_body_with(&text));
        match live_call(&fx, FAKE_KEY, &CHALLENGE, b"p") {
            LiveOutcome::Ok(ev) => {
                let line = witness_line(&ev);
                assert!(!line.contains(FAKE_KEY)); // structural
                assert!(!scrub(&line, FAKE_KEY).contains(FAKE_KEY)); // belt-and-suspenders
                // The body line: neither the key nor its hex encoding leaks.
                let body = body_line(&ev.text, FAKE_KEY);
                assert!(!body.contains(FAKE_KEY));
                assert!(!body.contains(&hex(FAKE_KEY.as_bytes())));
                // The scrub placeholder IS framed (the redaction is visible).
                assert!(body.contains(&hex(b"<key-scrubbed>")));
            }
            _ => panic!("the fixture is compliant"),
        }
    }

    #[test]
    fn key_echo_on_the_failure_path_is_scrubbed_too() {
        // Adversarial fixture on the FAILURE path: a NON-compliant answer
        // that echoes the key. TRANSFORM-MISS now frames the body -- the
        // framed view must be the SCRUBBED one, on every layer.
        let text = format!("no reversal, but here is a secret: {FAKE_KEY}");
        let fx = Fixture::ok(ok_body_with(&text));
        let outcome = live_call(&fx, FAKE_KEY, &CHALLENGE, b"p");
        let lines = verdict_lines(&outcome, &CHALLENGE, FAKE_KEY);
        assert_eq!(lines.len(), 2); // [failure-with-digest, body]
        for line in &lines {
            assert!(!line.contains(FAKE_KEY));
            assert!(!line.contains(&hex(FAKE_KEY.as_bytes())));
        }
        assert!(lines[0].contains("outcome=TRANSFORM-MISS"));
        assert!(lines[1].contains(&hex(b"<key-scrubbed>"))); // redaction visible
    }

    // --- the greeting envelope (M31 stage C': the witnessable hello) ---------

    #[test]
    fn envelope_keeps_line1_strict_and_adds_the_greeting() {
        let body = build_request_body(&CHALLENGE, b"guest-prompt");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let text = v["messages"][0]["content"].as_str().unwrap();
        // Line 1 stays strict ON THAT LINE...
        assert!(text.contains("nothing else on that line"));
        // ...line 2 is the greeting to Yuva...
        assert!(text.contains("greeting Yuva"));
        // ...and the provenance clause survives verbatim in spirit.
        assert!(text.contains("provenance only"));
        assert!(text.contains("do not echo"));
    }

    #[test]
    fn liveness_acceptance_is_unmoved_by_the_greeting_line() {
        let reversed = expected_transform(&CHALLENGE);
        // Reversal line + a greeting second line: PASSES (the substring
        // search is line-agnostic by construction).
        let two_lines = format!("{reversed}\nHello, Yuva -- glad to meet the machine!");
        assert!(liveness_ok(&two_lines, &CHALLENGE));
        // A greeting WITHOUT the transform: FAILS (the greeting can never
        // substitute for liveness).
        assert!(!liveness_ok(
            "Hello, Yuva -- glad to meet the machine!",
            &CHALLENGE
        ));
    }

    // --- the hex-framed body line --------------------------------------------

    #[test]
    fn body_line_grammar_and_prefix_disjointness() {
        let line = body_line("Hello, Yuva!", FAKE_KEY);
        // The grammar, hand-validated (no regex dep in this crate):
        // 'xport-harness-infer-body: len=<dec> truncated=<0|1> hex=<hex>'.
        let rest = line
            .strip_prefix("xport-harness-infer-body: ")
            .expect("the body prefix");
        let fields: Vec<&str> = rest.split(' ').collect();
        assert_eq!(fields.len(), 3);
        let len_v = fields[0].strip_prefix("len=").expect("len field");
        assert!(!len_v.is_empty() && len_v.bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(len_v, "12");
        let tr_v = fields[1].strip_prefix("truncated=").expect("truncated field");
        assert!(tr_v == "0" || tr_v == "1");
        let hex_v = fields[2].strip_prefix("hex=").expect("hex field");
        assert!(!hex_v.is_empty());
        assert!(hex_v
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert_eq!(hex_v, hex(b"Hello, Yuva!"));
        // THE DISJOINTNESS ASSERTION: the body line can never be counted by
        // the workflow's exactly-one-VERDICT grep ('^xport-harness-infer: ',
        // trailing space load-bearing), and the verdict lines can never be
        // counted as body lines.
        assert!(!line.starts_with("xport-harness-infer: "));
        let ev = LiveEvidence {
            nonce_hex: hex(&CHALLENGE),
            reqid_hex: hex(b"req_011FIXTURE"),
            resp_digest_hex: hex(&body_digest(b"x")),
            stop: "END-TURN",
            text: "x".into(),
        };
        assert!(witness_line(&ev).starts_with("xport-harness-infer: "));
        assert!(!witness_line(&ev).starts_with("xport-harness-infer-body:"));
        let fl = failure_line(&hex(&CHALLENGE), "AUTH", Some(401), false, None);
        assert!(fl.starts_with("xport-harness-infer: "));
        assert!(!fl.starts_with("xport-harness-infer-body:"));
        // The digest-bearing failure line keeps the same prefix discipline.
        let dg = hex(&body_digest(b"said"));
        let fl2 = failure_line(&hex(&CHALLENGE), "TRANSFORM-MISS", Some(200), false, Some(&dg));
        assert!(fl2.starts_with("xport-harness-infer: "));
        assert!(fl2.contains(&format!("resp-digest=0x{dg} key-custody=HOST-ENV")));
        // The EMPTY-text body line (an empty-content refusal): len=0, empty
        // hex= field -- emptiness, not silence.
        let empty = body_line("", FAKE_KEY);
        assert_eq!(empty, "xport-harness-infer-body: len=0 truncated=0 hex=");
    }

    #[test]
    fn body_line_caps_at_2048_bytes_and_flags_truncation() {
        let big = "y".repeat(BODY_LINE_CAP + 500);
        let line = body_line(&big, FAKE_KEY);
        assert!(line.contains(&format!("len={} ", BODY_LINE_CAP + 500)));
        assert!(line.contains("truncated=1 "));
        let hex_v = line.split("hex=").nth(1).unwrap();
        assert_eq!(hex_v.len(), BODY_LINE_CAP * 2); // capped pre-hex
        // The un-capped case flags 0 and frames everything.
        let small = body_line("hi", FAKE_KEY);
        assert!(small.contains("len=2 truncated=0 "));
    }

    /// Count the body lines in a verdict set.
    fn body_count(lines: &[String]) -> usize {
        lines
            .iter()
            .filter(|l| l.starts_with("xport-harness-infer-body: "))
            .count()
    }

    #[test]
    fn body_line_emission_matrix_per_outcome() {
        // OK -> exactly [witness, body] (one body line per OK verdict; the
        // caller's one-call latch makes that at most one per process).
        let reversed = expected_transform(&CHALLENGE);
        let ok = live_call(
            &Fixture::ok(ok_body_with(&format!("{reversed}\nHello, Yuva!"))),
            FAKE_KEY,
            &CHALLENGE,
            b"p",
        );
        let lines = verdict_lines(&ok, &CHALLENGE, FAKE_KEY);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("xport-harness-infer: backend=ANTHROPIC-LIVE "));
        assert_eq!(body_count(&lines), 1);
        assert!(lines[1].starts_with("xport-harness-infer-body: "));

        // TRANSFORM-MISS -> exactly [failure-with-digest, body]: 1 body line.
        let miss = live_call(
            &Fixture::ok(ok_body_with("not the transform")),
            FAKE_KEY,
            &CHALLENGE,
            b"p",
        );
        let lines = verdict_lines(&miss, &CHALLENGE, FAKE_KEY);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("outcome=TRANSFORM-MISS"));
        assert!(lines[0].contains(" resp-digest=0x"));
        assert_eq!(body_count(&lines), 1);

        // REFUSAL (even empty-content) -> exactly [failure-with-digest, body].
        let refusal = live_call(
            &Fixture::ok(r#"{"stop_reason":"refusal","content":[]}"#.to_string()),
            FAKE_KEY,
            &CHALLENGE,
            b"p",
        );
        let lines = verdict_lines(&refusal, &CHALLENGE, FAKE_KEY);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("outcome=REFUSAL"));
        assert_eq!(body_count(&lines), 1);
        assert!(lines[1].ends_with("len=0 truncated=0 hex="));

        // Every body-less outcome -> exactly [failure], ZERO body lines:
        // AUTH (401 status), TIMEOUT (transport), LIVENESS-FAIL (no
        // request-id), TOO-LARGE (oversize 200), API-ERROR (malformed 200).
        let bodiless: Vec<LiveOutcome> = vec![
            live_call(&Fixture::status(401), FAKE_KEY, &CHALLENGE, b"p"),
            live_call(
                &Fixture {
                    fault: Some("timeout"),
                    ..Fixture::ok(String::new())
                },
                FAKE_KEY,
                &CHALLENGE,
                b"p",
            ),
            live_call(
                &{
                    let mut f = Fixture::ok(ok_body_with(&expected_transform(&CHALLENGE)));
                    f.request_id = None;
                    f
                },
                FAKE_KEY,
                &CHALLENGE,
                b"p",
            ),
            live_call(
                &Fixture::ok(ok_body_with(&"a".repeat(INFER_BODY_CAP + 1))),
                FAKE_KEY,
                &CHALLENGE,
                b"p",
            ),
            live_call(&Fixture::ok("not json".to_string()), FAKE_KEY, &CHALLENGE, b"p"),
        ];
        for outcome in &bodiless {
            let lines = verdict_lines(outcome, &CHALLENGE, FAKE_KEY);
            assert_eq!(lines.len(), 1);
            assert!(lines[0].contains("transform-ok=0"));
            assert_eq!(body_count(&lines), 0);
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
