#![forbid(unsafe_code)]
//! M16 -- the LLM-agnostic INFERENCE bridge core (100% SAFE Rust; the body
//! behind every [`crate::caps::ObjKind::ModelSession`] capability).
//!
//! An agent invokes a model through a capability ([`crate::caps::Rights::INVOKE_MODEL`],
//! method [`crate::caps::M_MODEL_INVOKE`]) naming the target via a `model:`
//! scheme; this module is the safe, in-kernel ROUTER that binds a REGISTERED
//! backend behind ONE uniform contract (request -> response). The backend
//! identity is HIDDEN from the agent: swap the registered impl behind a `model:`
//! prefix and the agent code is byte-for-byte identical -- that is the
//! LLM-agnostic pillar made concrete (ARCHITECTURE.md: "agnosticity = who
//! registered the scheme").
//!
//! Soundness mirrors the green M13/M14/M15 bodies: reached ONLY through a shared
//! `Rc<Object>` resolved at the M11 chokepoint, single-core, interrupts masked.
//! ZERO `unsafe`: the [`MockBackend`] is a stateless pure transform (trivially
//! `Sync`, so a `static` needs no `UnsafeCell`) and `ROUTES` is an immutable
//! `&'static` slice (no interior mutability). CUDA / real Anthropic+OpenAI
//! adapters / vsock-local providers implement the SAME [`InferBackend`] trait
//! later in userspace / the driver-VM and are DEFERRED behind it.

// ===========================================================================
// Contract types -- the minimal backend-agnostic intersection, INLINE-SCALAR at
// M16 (the M14 `Message::payload` precedent). The variable-length neutral core
// (messages[], tools[], the {cost,speed,intelligence} preference DAG, streamed
// events) rides a future M14 channel / M15 block and is DEFERRED.
// ===========================================================================

/// Resolved model identity = the routing key (index into the const route table).
/// Opaque to the agent (it holds a [`crate::caps::Handle`], not this); only the
/// kernel router mints one at session-open.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ModelId(
    /// The route-table index this id resolves to.
    pub u32,
);

/// Neutral inference REQUEST. Inline scalar at M16; the byte prompt over a
/// block/channel is the DEFERRED non-scalar path behind the same trait.
pub struct InferRequest {
    /// The resolved logical model (the routing key), echoed back -- backend hidden.
    pub model: ModelId,
    /// The inline scalar prompt the in-kernel marker rides on.
    pub prompt: u64,
}

/// CLOSED union superset of EVERY backend's finish vocabulary (Anthropic ∩
/// OpenAI), so no provider distinction is lost when a real adapter lands.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum StopReason {
    /// The model ended its turn normally.
    EndTurn,
    /// The response hit the token budget.
    MaxTokens,
    /// A registered stop sequence was emitted.
    StopSequence,
    /// The model requested a tool call.
    ToolUse,
    /// The model refused (safety).
    Refusal,
    /// A cooperative pause point.
    Pause,
}

/// Neutral inference RESPONSE. Collapses Anthropic `content[]` / OpenAI
/// `choices[0]` to ONE payload (inline scalar at M16); echoes only the LOGICAL
/// model -- the backend impl is never named.
pub struct InferResponse {
    /// The inline scalar response token (the deterministic transform at M16).
    pub token: u64,
    /// Why the backend stopped.
    pub stop_reason: StopReason,
}

/// Inference-plane error -- DISTINCT from the capability [`crate::caps::SysStatus`]
/// (the MCP lesson: model-readable). `SysStatus` governs dispatch/caps; this
/// governs inference. The facade maps `NoBackend` -> `SysStatus::BadCap` at M16.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InferError {
    /// No backend registered for the requested `model:` scheme.
    NoBackend,
    /// The bound backend is registered but temporarily unavailable.
    Unavailable,
    /// The request exceeded the backend's context window.
    ContextExceeded,
    /// The backend refused the request (safety).
    Refused,
    /// The invocation was cancelled.
    Cancelled,
}

// ===========================================================================
// The `model:` scheme grammar -- safe, panic-free parser + longest-prefix router.
// ===========================================================================

/// `model:provider/path[@version]` -> `(provider, path)`. Returns `None` for a
/// non-`model:` scheme (so `memory:x` / `block:y` cleanly reject) -- so a bad
/// scheme can never crash the kernel. NEVER panics.
///
/// A bare `model:auto` / `model:default` (no `/`) parses to `(provider, "")` --
/// the reserved pure-preference binding (router scores by Prefs/Qos; deferred).
pub fn parse_scheme(uri: &str) -> Option<(&str, &str)> {
    let rest = uri.strip_prefix("model:")?;
    match rest.split_once('/') {
        Some((p, path)) if !p.is_empty() && !path.is_empty() => Some((p, path)),
        None if !rest.is_empty() => Some((rest, "")),
        _ => None,
    }
}

/// Resolve a `model:` URI to a REGISTERED backend. `None` => unknown scheme =>
/// a clean `BadCap` at the facade (NEVER a panic). The provider segment is the
/// registry key; no global root, no `..`, so a prompt-injection path-traversal
/// is unrepresentable.
///
/// Exact-scheme match suffices for the marker; production refines this to a
/// longest-prefix match over the provider segment.
pub fn resolve(uri: &str) -> Option<(ModelId, &'static dyn InferBackend)> {
    // Reject a non-`model:` scheme cleanly first.
    parse_scheme(uri)?;
    let mut i = 0;
    while i < ROUTES.len() {
        if ROUTES[i].scheme() == uri {
            return Some((ModelId(i as u32), ROUTES[i]));
        }
        i += 1;
    }
    None
}

// ===========================================================================
// The backend trait + the in-kernel IMMUTABLE registry.
// ===========================================================================

/// A registered inference backend. The [`MockBackend`] implements this IN-KERNEL
/// with ZERO `unsafe`. Real Anthropic/OpenAI/vsock-local adapters implement the
/// SAME contract later in userspace / the driver-VM -- the agent never sees the
/// impl, only the `model:` name + the response.
///
/// Object-safe (no generic methods) so `&'static dyn InferBackend` is legal in
/// `no_std` + `alloc`; `Sync` so a `static` instance is shareable single-core.
pub trait InferBackend: Sync {
    /// This backend's longest-prefix routing key (its `model:` scheme literal).
    fn scheme(&self) -> &'static str;
    /// Run ONE synchronous, deterministic inference at M16.
    fn infer(&self, req: &InferRequest) -> InferResponse;
}

/// STATELESS, deterministic loopback -- NO clock, NO rng, NO I/O (QEMU has no
/// real net/GPU, so determinism is mandatory for a reproducible CI marker).
/// Stateless => trivially `Sync` => a `static` is sound with ZERO `unsafe`.
struct MockBackend {
    scheme: &'static str,
}

impl MockBackend {
    const fn new(scheme: &'static str) -> Self {
        Self { scheme }
    }
}

impl InferBackend for MockBackend {
    fn scheme(&self) -> &'static str {
        self.scheme
    }
    fn infer(&self, req: &InferRequest) -> InferResponse {
        // A closed transform of the inline prompt scalar -- reproducible.
        InferResponse {
            token: req.prompt ^ 0xA110_C0DE,
            stop_reason: StopReason::EndTurn,
        }
    }
}

/// TWO `model:` names binding ONE contract = the backend-agnostic proof.
static MOCK_CLAUDE: MockBackend = MockBackend::new("model:mock/echo");
static MOCK_LLAMA: MockBackend = MockBackend::new("model:local/llama3");

/// IMMUTABLE route table: a `static &[&'static dyn InferBackend]` over stateless
/// statics => NO `UnsafeCell`, NO `unsafe`. Registration = adding a `static` to
/// this slice. A RUNTIME-mutable router (real userspace/vsock providers) is the
/// DEFERRED dynamic path (the only place a future `unsafe` could appear) and is
/// kept OUT of the M16 DoD.
static ROUTES: &[&'static dyn InferBackend] = &[&MOCK_CLAUDE, &MOCK_LLAMA];

// ===========================================================================
// The bound session body carried inline on an ObjKind::ModelSession Object.
// ===========================================================================

/// Bound session body carried inline on an [`crate::caps::ObjKind::ModelSession`]
/// Object. Single-owner (the M13 `mem` ownership precedent -- no `Rc`-of-session,
/// unlike the shared-across-two-tables Channel/Block). `&'static dyn
/// InferBackend` is `Copy`, so this moves into the Object cleanly.
pub struct ModelSession {
    /// The router-bound backend (hidden from the agent).
    pub backend: &'static dyn InferBackend,
    /// The resolved logical model id this session is pinned to.
    pub model: ModelId,
}

impl ModelSession {
    /// One invocation against the bound backend. Reached ONLY through the session
    /// capability via the M11 chokepoint (`M_MODEL_INVOKE`). Deterministic; no
    /// `&mut` (stateless mock), so no `RefCell` is needed.
    pub fn invoke(&self, prompt: u64) -> InferResponse {
        self.backend.infer(&InferRequest {
            model: self.model,
            prompt,
        })
    }
}
