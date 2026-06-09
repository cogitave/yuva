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
// The `model:` scheme grammar + longest-prefix router. The PURE string logic --
// the `model:<provider>/<path>` parser and the longest-prefix-match INDEX
// decision -- lives in the host-verifiable `tb_encode::route`, where the Tier-0
// Miri lane EXECUTES it over adversarial vectors (panic-freedom + correctness +
// zero UB on untrusted input). `resolve` keeps OWNERSHIP of the `&'static dyn`
// ROUTES table and DELEGATES the string matching to those proven helpers.
// ===========================================================================

/// `model:<provider>/<path>[@version]` -> `(provider, path)`. Re-exported from
/// [`tb_encode::route`] so `tb_hal::infer::parse_scheme` keeps resolving for
/// existing callers (the M16 self-test) -- the byte-identical, panic-free pure
/// parser now lives in the host-verifiable crate. Returns `None` for a
/// non-`model:` scheme (so `memory:x` / `block:y` cleanly reject), so a bad
/// scheme can never crash the kernel. NEVER panics.
pub use tb_encode::route::parse_scheme;

/// Upper bound on the route-key scratch buffer in [`resolve`]. The in-kernel
/// [`ROUTES`] table is far smaller; this is a generous, panic-safe cap (the loop
/// is clamped to it and a `debug_assert!` flags an overflow).
const MAX_ROUTES: usize = 16;

/// Resolve a `model:` URI to a REGISTERED backend via a LONGEST-PREFIX match
/// over the provider segment. `None` => unknown scheme => a clean `BadCap` at
/// the facade (NEVER a panic). The provider segment is the registry key; no
/// global root, no `..`, so a prompt-injection path-traversal is unrepresentable
/// (the path rides opaquely in the matched-away remainder).
///
/// `resolve` owns the immutable `&'static dyn` [`ROUTES`] table; it DELEGATES the
/// pure routing decision to [`tb_encode::route::longest_prefix_index`] (proven
/// panic-free + correct under Miri), keyed on each route's OWN provider segment
/// so the keys can never drift from the table (one source of truth: the
/// backend's `scheme()` literal). This fulfils the longest-prefix-over-provider
/// routing the marker-era exact match deferred.
pub fn resolve(uri: &str) -> Option<(ModelId, &'static dyn InferBackend)> {
    // Split the untrusted URI; a non-`model:` scheme rejects cleanly here.
    let (provider, _path) = parse_scheme(uri)?;
    // Materialize each route's PROVIDER key (derived from its own scheme literal,
    // so the keys can never drift from the table) into a fixed stack slice, in
    // lockstep with ROUTES, then delegate the longest-prefix routing decision.
    let n = ROUTES.len().min(MAX_ROUTES);
    debug_assert!(ROUTES.len() <= MAX_ROUTES, "route table exceeds the key buffer");
    let mut keys: [&str; MAX_ROUTES] = [""; MAX_ROUTES];
    let mut i = 0;
    while i < n {
        // Each registered scheme is a well-formed `model:<provider>/...`, so its
        // provider IS the prefix key. A (currently unreachable) malformed entry
        // falls back to its full scheme literal -- always NON-EMPTY, so it can
        // never degrade into an empty catch-all that swallows unknown schemes.
        keys[i] = match parse_scheme(ROUTES[i].scheme()) {
            Some((p, _)) => p,
            None => ROUTES[i].scheme(),
        };
        i += 1;
    }
    let idx = tb_encode::route::longest_prefix_index(provider, &keys[..n])?;
    Some((ModelId(idx as u32), ROUTES[idx]))
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
    /// This backend's `model:` scheme literal; its provider segment is the
    /// longest-prefix routing key consumed by [`resolve`].
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
