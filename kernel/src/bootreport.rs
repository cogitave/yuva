//! Industrial Boot (#106) — the human-meaningful boot PRESENTATION over the
//! untouched machine-truth markers.
//!
//! A normal person who boots Yuva sees a wall of `Mxx: … OK` markers and
//! machine-tokened witness lines and cannot read any of it. This module adds a
//! SECOND presentation pass — a branded header, a column of `[ STATUS ] <human
//! subsystem>` lines in the systemd grammar, a `Reached target Ready.` line, and
//! an honest tally — rendered ONLY when a viewer opts in via the runtime
//! `yuva.console=pretty` cmdline token. See `docs/proposals/industrial-boot.md`.
//!
//! ## The load-bearing invariant (why CI never regresses)
//!
//! The raw marker/witness stream is a Definition-of-Done instrument: the three
//! `scripts/run-*.sh` verifiers grep 100+ exact substrings over it. This module
//! is **purely additive and DEFAULT-OFF**. With NO `yuva.console=pretty` token
//! on the boot cmdline — the state of EVERY CI lane (none passes `-append`) and
//! EVERY re-entrant aarch64 EL1 guest (no cmdline channel at all) — the mode is
//! [`Mode::Raw`], the display gate stays down, and every raw byte is emitted
//! exactly as before. The committed empty-byte-diff test proves this on both
//! arches and on the decoded guest stream.
//!
//! ## Mechanism (a deviation from the proposal's per-site reroute, noted)
//!
//! The proposal (§5.1) describes rerouting all 83+ marker sites through a
//! `report()` choke point, and concedes this is "a materially larger change"
//! that must also re-emit every pre-marker witness assembly byte-for-byte. This
//! module instead uses a **global serial display gate** ([`tb_hal::serial_set_quiet`]):
//! in pretty mode the raw stream is suppressed at the writer and this module
//! paints the clean human boot via the `_raw` bypass twins; in raw mode NOTHING
//! is touched, so byte-identity holds by not-touching rather than by
//! re-emission. This honours every load-bearing invariant of the proposal
//! (raw byte-identical by default, honest opt-in pretty, guest unconditionally
//! raw, no ESC/no color) while touching ZERO existing raw-output bytes.
//!
//! ## Honesty (the core value made load-bearing at the user surface)
//!
//! Each derived glyph is a pure function of a token the kernel still holds as a
//! boolean/const at render time (the SAME booleans that produce the on-wire
//! `backend=MOCK-DETERMINISTIC` / `gate-not-met`,`KAN_ACTIVE=0x0` / `(… skipped)`
//! tokens), fed here by the [`observe`] calls placed adjacent to those real
//! branches. A mock inference is NEVER `[ OK ] Local AI`; a dormant learning
//! cell is `[STANDBY]`, never `[ OK ] AI Learning`; a lane that took a
//! `(… skipped)` path is `[ SKIP ]`, never `[ OK ]`. Every remaining human word
//! is an AUTHORED-HONEST CONSTANT, reviewed and lint-gated (DoD-2) against an
//! overclaim vocabulary. No ANSI color is ever emitted (a kernel has no
//! `isatty`, and every lane hard-fails on a raw ESC byte).

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// The product version shown in the banner (the roadmap product version, not
/// the crate `version`). The NAME derives from the [`brand`] crate — the single
/// source of truth — pinned by the const-assert below.
const PRODUCT_VERSION: &str = "0.9";

// The banner name is the brand, title-cased for human display ("Yuva"). We
// don't spell it a second time: pin it against the brand crate so a rename that
// forgot this module is a COMPILE error, then render the display form.
const _: () = assert!(brand::BRAND.len() == 4); // "YUVA"
const _: () = assert!(brand::BRAND.as_bytes()[0] == b'Y');

/// Display banner name (title-case brand). Cosmetic; the honesty surface is the
/// status lines, not this.
const BANNER_NAME: &str = "Yuva";

// ===========================================================================
// Mode + View (runtime, cmdline-driven; DEFAULT raw / agent)
// ===========================================================================

/// The boot-console verbosity mode, selected by the `yuva.console=` cmdline
/// token. The DEFAULT (absent token) is [`Mode::Raw`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Today's exact raw marker/witness stream — the DEFAULT and the only mode
    /// any CI lane or re-entrant guest ever sees.
    Raw,
    /// The clean `[ STATUS ]` human boot only (raw stream suppressed). Opt-in.
    Pretty,
    /// Developer-only: the raw stream AND the pretty summary. Forbidden on the
    /// three run lanes (they pass no cmdline, so they never reach it).
    Both,
}

/// The render VIEW, selected by the `yuva.view=` cmdline token. At stage A this
/// is a pure RENDER FILTER — no build variant exists; the organs run
/// unconditionally (§3.2), so substrate says "HIDDEN in the substrate view",
/// never "not present".
#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    /// The full resident-agent render (the DEFAULT).
    Agent,
    /// The Firecracker-alt minimal render (micro-VMM rows only).
    Substrate,
}

const MODE_RAW: u8 = 0;
const MODE_PRETTY: u8 = 1;
const MODE_BOTH: u8 = 2;

static MODE: AtomicU8 = AtomicU8::new(MODE_RAW);
static VIEW_SUBSTRATE: AtomicBool = AtomicBool::new(false);

fn mode() -> Mode {
    match MODE.load(Ordering::Relaxed) {
        MODE_PRETTY => Mode::Pretty,
        MODE_BOTH => Mode::Both,
        _ => Mode::Raw,
    }
}

fn view() -> View {
    if VIEW_SUBSTRATE.load(Ordering::Relaxed) {
        View::Substrate
    } else {
        View::Agent
    }
}

// ===========================================================================
// The derived-glyph state, fed by `observe()` at the real skip/mock branches
// ===========================================================================

/// A subsystem status glyph. DERIVED variants (`Mock`/`Standby`/`Skip`) are a
/// pure function of an on-wire token; `Ok` is a real round-trip boolean;
/// `Info`/`Failed` are authored/real respectively.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Real subsystem, round-trip boolean passed on this lane.
    Ok,
    /// Plumbing real, backend a deterministic stub — DERIVED from
    /// `backend=MOCK-DETERMINISTIC`.
    Mock,
    /// Capability shipped, inactive by design — DERIVED from
    /// `gate-not-met`/`KAN_ACTIVE=0x0`.
    Standby,
    /// A real `(… skipped)` path was taken on this lane — DERIVED from the
    /// on-wire skip form.
    Skip,
    /// An authored honest disclaimer, not a subsystem claim.
    Info,
    /// A real failure.
    Failed,
}

/// The lane-variable subsystems whose glyph is DERIVED at their real branch.
#[derive(Clone, Copy)]
pub enum Subsys {
    /// M19 virtio devices: real vs `(no device, skipped)`.
    Virtio,
    /// M20 durable storage: real vs `(no disk, skipped)`.
    Storage,
    /// M30 inference transport: real vs `(no host peer, skipped)`.
    // BOOT-PROFILES STAGE-B: only the (gated) M30 block constructs this variant;
    // `--no-default-features` drops that caller. Inert on the default build.
    #[cfg_attr(not(feature = "agent-organs"), allow(dead_code))]
    Transport,
    /// M31 agent inference: `[ MOCK ]` (backend=MOCK-DETERMINISTIC) vs
    /// `(no host peer, skipped)`.
    // BOOT-PROFILES STAGE-B: only the (gated) M31 block constructs this variant;
    // `--no-default-features` drops that caller. Inert on the default build.
    #[cfg_attr(not(feature = "agent-organs"), allow(dead_code))]
    Inference,
}

fn state_to_u8(s: State) -> u8 {
    match s {
        State::Ok => 1,
        State::Mock => 2,
        State::Standby => 3,
        State::Skip => 4,
        State::Info => 5,
        State::Failed => 6,
    }
}

fn u8_to_state(v: u8, default: State) -> State {
    match v {
        1 => State::Ok,
        2 => State::Mock,
        3 => State::Standby,
        4 => State::Skip,
        5 => State::Info,
        6 => State::Failed,
        _ => default,
    }
}

static ST_VIRTIO: AtomicU8 = AtomicU8::new(0);
static ST_STORAGE: AtomicU8 = AtomicU8::new(0);
static ST_TRANSPORT: AtomicU8 = AtomicU8::new(0);
static ST_INFERENCE: AtomicU8 = AtomicU8::new(0);
/// Set true iff a real `M38: conductor OK … verdict=ACCEPT` fired this boot.
// BOOT-PROFILES STAGE-B: written ONLY by observe_m38_ok (the gated M38 block's
// sink) and read by no one yet (the render veto-line is deferred, §11.3), so with
// `--no-default-features` both this static and observe_m38_ok are unreferenced.
// Inert on the default build.
#[cfg_attr(not(feature = "agent-organs"), allow(dead_code))]
static M38_OK: AtomicBool = AtomicBool::new(false);

fn slot(s: Subsys) -> &'static AtomicU8 {
    match s {
        Subsys::Virtio => &ST_VIRTIO,
        Subsys::Storage => &ST_STORAGE,
        Subsys::Transport => &ST_TRANSPORT,
        Subsys::Inference => &ST_INFERENCE,
    }
}

/// Record the DERIVED status of a lane-variable subsystem, at the same branch
/// that emits its raw marker. Cheap (one relaxed store) and emits NO serial
/// bytes, so the raw stream stays byte-identical whether or not pretty is ever
/// selected. Call it in BOTH the real arm and the `(… skipped)` arm.
pub fn observe(s: Subsys, st: State) {
    slot(s).store(state_to_u8(st), Ordering::Relaxed);
}

/// Record that a real `M38: conductor OK … verdict=ACCEPT` fired this boot. The
/// Cognitive-orchestrator pretty LINE is an operator veto point (§11.3) and is
/// NOT rendered at stage A even when this is set; this observation implements
/// the proposal's gate so the operator can flip the line on later review.
// BOOT-PROFILES STAGE-B: the (gated) M38 conductor block is this fn's only caller;
// `--no-default-features` drops it. Inert on the default build.
#[cfg_attr(not(feature = "agent-organs"), allow(dead_code))]
pub fn observe_m38_ok() {
    M38_OK.store(true, Ordering::Relaxed);
}

// ===========================================================================
// Cmdline parsing (x86 PVH only at stage A; guest + aarch64-host stay raw)
// ===========================================================================

/// Parse the boot cmdline and apply the mode/view. Called ONCE, early in
/// `rust_main`, right after serial init. On x86 the cmdline comes from the PVH
/// `hvm_start_info` (`-append`); the aarch64 host cmdline (`/chosen/bootargs`)
/// is a named follow-up and the EL1 guest has no cmdline, so both stay raw.
///
/// Recognised tokens (space-separated, order-independent):
/// * `yuva.console=raw|pretty|both` — DEFAULT `raw`.
/// * `yuva.view=agent|substrate`   — DEFAULT `agent`.
/// * `yuva.profile=agent|substrate` — DEFAULT `agent` (Boot Profiles stage A).
///
/// When pretty is selected, this RAISES the serial display gate so the raw
/// stream is suppressed and [`render`] paints the clean boot in its place.
///
/// Boot Profiles (§2.1): `yuva.profile=substrate` latches the substrate profile
/// ([`crate::profile::set_substrate`] — organs skipped + the cognitive
/// chokepoint armed) AND defaults the render VIEW to substrate (the honest
/// render for that profile), UNLESS an explicit `yuva.view=` token overrides it.
/// The absent-token default is the AGENT profile, so every CI lane stays the
/// byte-identical agent stream.
//
// Called only on x86 at stage A (the sole arch with a wired cmdline channel);
// the aarch64-host `/chosen/bootargs` caller is a named follow-up, so allow the
// unused-on-aarch64 warning rather than gate the whole parser behind a cfg.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub fn apply_cmdline(cmdline: &str) {
    let console_key = concat!(brand::brand_lower!(), ".console=");
    let view_key = concat!(brand::brand_lower!(), ".view=");
    let profile_key = concat!(brand::brand_lower!(), ".profile=");

    let mut view_explicit = false;
    let mut profile_substrate = false;
    for tok in cmdline.split(|c: char| c == ' ' || c == '\t') {
        if let Some(val) = tok.strip_prefix(console_key) {
            let m = match val {
                "pretty" => MODE_PRETTY,
                "both" => MODE_BOTH,
                _ => MODE_RAW,
            };
            MODE.store(m, Ordering::Relaxed);
        } else if let Some(val) = tok.strip_prefix(view_key) {
            VIEW_SUBSTRATE.store(val == "substrate", Ordering::Relaxed);
            view_explicit = true;
        } else if let Some(val) = tok.strip_prefix(profile_key) {
            // DEFAULT agent (any value other than the exact "substrate" literal
            // leaves the agent profile — fail-safe toward the byte-identical
            // stream). The latch is applied AFTER the loop so an explicit
            // `yuva.view=` seen anywhere on the line wins the view default.
            profile_substrate = val == "substrate";
        }
    }

    if profile_substrate {
        crate::profile::set_substrate();
        // The substrate profile's honest render is the substrate view; a viewer
        // may still override with an explicit `yuva.view=`.
        if !view_explicit {
            VIEW_SUBSTRATE.store(true, Ordering::Relaxed);
        }
    }

    // Pretty suppresses the raw stream for a clean screen; both keeps raw AND
    // appends the summary; raw touches nothing.
    if mode() == Mode::Pretty {
        tb_hal::serial_set_quiet(true);
    }
}

// ===========================================================================
// The renderer (bypasses the display gate via the `_raw` twins)
// ===========================================================================

fn tag(s: State) -> &'static str {
    match s {
        State::Ok => "[  OK  ]",
        State::Mock => "[ MOCK ]",
        State::Standby => "[STANDBY]",
        State::Skip => "[ SKIP ]",
        State::Info => "[ INFO ]",
        State::Failed => "[FAILED]",
    }
}

fn line(s: State, body: &str) {
    tb_hal::serial_write_str_raw(tag(s));
    tb_hal::serial_write_str_raw(" ");
    tb_hal::serial_write_str_raw(body);
    tb_hal::serial_write_str_raw("\n");
}

/// A 62-column box rule (no ANSI, plain UTF-8 em-dash; pretty-only, never on a
/// CI stream). Kept ASCII-safe of the ESC byte by construction.
const RULE: &str = "──────────────────────────────────────────────────────────────";

/// Render the industrial boot. Self-gates on [`mode`]: a no-op in [`Mode::Raw`]
/// (every CI lane, the EL1 guest, aarch64-host at stage A), so it is safe to
/// call unconditionally at the single clean-exit site. Paints via the `_raw`
/// serial twins so it appears even while the raw stream is gated off (pretty),
/// or after it (both).
pub fn render() {
    if mode() == Mode::Raw {
        return;
    }

    // On `both`, separate the pretty summary from the raw stream above it.
    if mode() == Mode::Both {
        tb_hal::serial_write_str_raw("\n");
    }

    // The EL2-derived rows: `[ OK ]` only on a real aarch64 EL2 host, else
    // `[ SKIP ] (no EL2, skipped)`. Stage-A pretty renders on x86 only, where
    // there is no EL2, so these are SKIP — matching the §3.1 per-arch note.
    #[cfg(target_arch = "aarch64")]
    let el2 = tb_hal::booted_at_el2() != 0;
    #[cfg(not(target_arch = "aarch64"))]
    let el2 = false;

    let guest_iso = if el2 { State::Ok } else { State::Skip };
    let sched = if el2 { State::Ok } else { State::Skip };
    let virtio = u8_to_state(ST_VIRTIO.load(Ordering::Relaxed), State::Ok);
    let storage = u8_to_state(ST_STORAGE.load(Ordering::Relaxed), State::Ok);
    let transport = u8_to_state(ST_TRANSPORT.load(Ordering::Relaxed), State::Ok);
    let inference = u8_to_state(ST_INFERENCE.load(Ordering::Relaxed), State::Mock);

    let v = view();

    // --- header --------------------------------------------------------------
    tb_hal::serial_write_str_raw(BANNER_NAME);
    tb_hal::serial_write_str_raw(" ");
    tb_hal::serial_write_str_raw(PRODUCT_VERSION);
    // §1.5: "sovereign" is a sovereignty-plan LEDGER-bound term and stays on the
    // AGENT render only; the SUBSTRATE-PROFILE render takes the adjective-free
    // tail (a view-only substrate render under the agent profile keeps the
    // sovereign agent tail — the term is profile-bound, not view-bound).
    if crate::profile::is_substrate() {
        tb_hal::serial_write_str_raw(" — agent-agnostic micro-VMM core (substrate profile)  ·  ");
    } else {
        tb_hal::serial_write_str_raw(" — sovereign agent-native OS  ·  ");
    }
    tb_hal::serial_write_str_raw(match v {
        View::Agent => "agent view",
        View::Substrate => "substrate view (render filter, stage A)",
    });
    #[cfg(target_arch = "aarch64")]
    let arch_suffix = if el2 {
        " (aarch64 EL2 host)\n"
    } else {
        " (aarch64)\n"
    };
    #[cfg(not(target_arch = "aarch64"))]
    let arch_suffix = " (x86_64)\n";
    tb_hal::serial_write_str_raw(arch_suffix);
    tb_hal::serial_write_str_raw(RULE);
    tb_hal::serial_write_str_raw("\n");

    // --- the micro-VMM rows (both views) ------------------------------------
    // Authored-honest suffixes: no banned overclaim vocabulary (DoD-2). The
    // EL2/virtio/storage/scheduler rows carry their DERIVED status per lane.
    line(State::Ok, "Kernel core                traps, paging, preemptive scheduler");
    line(State::Ok, "Isolation & capabilities   per-entity address spaces, capability ABI");
    line(
        guest_iso,
        match guest_iso {
            State::Ok => "Guest isolation            full kernel as EL1 guest under EL2 (stage-2, vGIC, IOMMU)",
            _ => "Guest isolation            full kernel as EL1 guest under EL2 (no EL2, skipped)",
        },
    );
    line(
        virtio,
        match virtio {
            State::Ok => "Virtio devices             entropy (rng), block",
            _ => "Virtio devices             entropy (rng), block (no device, skipped)",
        },
    );
    line(
        storage,
        match storage {
            State::Ok => "Durable storage            virtio-blk, replayed on boot",
            _ => "Durable storage            virtio-blk (no disk, skipped)",
        },
    );
    line(
        sched,
        match sched {
            State::Ok => "Sovereign scheduler        CNTHP-preempted (timing: logical, not wall-clock)",
            _ => "Sovereign scheduler        CNTHP-preempted (no EL2, skipped)",
        },
    );
    line(State::Ok, "Message-authenticated integrity   keyed BLAKE2s-256 MAC (primitive assumed-from-literature)");

    match v {
        View::Substrate => {
            // §3.2 the M12 row split: the agent-agnostic HOSTING ABII — the M12
            // AgentProcess socket + M14/M15 IPC + the M18 admission MECHANISM —
            // STAYS in the substrate core (Linux has processes with none
            // running; Yuva has an agent socket with no agent admitted). It is a
            // real, present micro-VMM-core mechanism, so it renders green here.
            line(State::Ok, "Agent hosting ABI          socket + admission gate present, no organ admitted");
            // The cognitive-organ INFO line. The WORDING is the load-bearing
            // three-way distinction (§1.4): under the substrate PROFILE the
            // organs NOT RUN and NOT ADMITTED (an execution+admission gate);
            // under a view-only substrate render (agent profile) they DID run
            // and are merely HIDDEN. Neither ever says "not present" (stage B).
            if crate::profile::is_substrate() {
                line(State::Info, "Cognitive subsystems present in this build, NOT RUN and NOT ADMITTED (substrate profile, runtime-gated)");
            } else {
                line(State::Info, "Cognitive subsystems present in this build but HIDDEN in the substrate view");
            }
        }
        View::Agent => {
            // --- the resident-agent rows ------------------------------------
            line(State::Ok, "Agent runtime & memory     tiered store, lexical recall, consolidation");
            line(State::Ok, "Provenance ledger          tamper-evident fold (host TCB residual)");
            line(
                transport,
                match transport {
                    State::Ok => "Inference transport        host-custodied key, cross-process recompute — plumbing only",
                    _ => "Inference transport        host-custodied key, cross-process recompute (no host peer, skipped)",
                },
            );
            line(
                inference,
                match inference {
                    State::Skip => "Agent inference            deterministic stub — NO model loaded (no host peer, skipped)",
                    // DERIVED [ MOCK ] from backend=MOCK-DETERMINISTIC; the
                    // mandatory "not live AI" disclaimer.
                    _ => "Agent inference            deterministic stub — NO model loaded, not live AI",
                },
            );
            // DERIVED [STANDBY] from KAN_ACTIVE=0x0 / gate-not-met (compile
            // consts; the M21/M24 lines carry the same on-wire tokens).
            line(State::Standby, "Adaptive policy            experience logged; activation gate not met");
            line(State::Ok, "Operator channel           transcript, exit telemetry, inbound command");
        }
    }

    // --- reached-target ------------------------------------------------------
    line(State::Ok, "Reached target Ready.");

    // --- the trailing authored disclaimer (agent only) ----------------------
    // AUTHORED-HONEST CONSTANT, not derived: these are HOST-conductor artifacts,
    // NOT on the boot wire. Never a green line. No banned overclaim words.
    if v == View::Agent {
        line(State::Info, "retrieval=lexical-only · generativity=open-frontier (not claimed) · integrity-primitive=assumed-from-literature");
    }

    tb_hal::serial_write_str_raw(RULE);
    tb_hal::serial_write_str_raw("\n");

    // --- the one-line honest tally ------------------------------------------
    // Tally ONLY the lane-variable rows each view actually rendered, so the
    // skip/mock counts match the screen above (substrate hides transport +
    // inference, so they must not be counted there).
    match v {
        View::Agent => render_summary(v, &[guest_iso, virtio, storage, sched, transport, inference]),
        View::Substrate => render_summary(v, &[guest_iso, virtio, storage, sched]),
    }
}

/// The honest tally line. NAMES the non-OK cells (mock / standby / skipped /
/// failed) from the actual rendered states — never a fixed "N green" claim.
fn render_summary(v: View, variable: &[State]) {
    // Total subsystem count differs by view (substrate hides the resident rows).
    let (total, mock, standby): (u32, u32, u32) = match v {
        // 7 micro-VMM rows + 6 resident rows = 13; 1 mock (inference), 1 standby.
        View::Agent => (13, count(variable, State::Mock), 1),
        // 7 micro-VMM rows + the §3.2 hosting-ABI row = 8 (+ the INFO line, not
        // a subsystem). The hosting-ABI row is green (present mechanism), so the
        // skip/mock/standby/failed tallies are unchanged.
        View::Substrate => (8, 0, 0),
    };
    let skipped = count(variable, State::Skip);
    let failed = count(variable, State::Failed);

    match v {
        View::Agent => tb_hal::serial_write_str_raw("The agent runtime is resident. Yuva ready (logical surrogate) — "),
        View::Substrate => {
            tb_hal::serial_write_str_raw("Yuva ready (logical surrogate) — substrate view, micro-VMM subsystems only (");
            write_dec(total);
            tb_hal::serial_write_str_raw(" subsystems, ");
            write_dec(skipped);
            tb_hal::serial_write_str_raw(" skipped, ");
            write_dec(failed);
            tb_hal::serial_write_str_raw(" failed).\n");
            return;
        }
    }
    write_dec(total);
    tb_hal::serial_write_str_raw(" subsystems (");
    write_dec(mock);
    tb_hal::serial_write_str_raw(" mock, ");
    write_dec(standby);
    tb_hal::serial_write_str_raw(" standby, ");
    write_dec(skipped);
    tb_hal::serial_write_str_raw(" skipped, ");
    write_dec(failed);
    tb_hal::serial_write_str_raw(" failed).\n");
}

fn count(states: &[State], want: State) -> u32 {
    let mut n = 0;
    for &s in states {
        if s == want {
            n += 1;
        }
    }
    n
}

/// Write a small `u32` as decimal via the `_raw` bypass (pretty-only; no fmt).
fn write_dec(mut n: u32) {
    if n == 0 {
        tb_hal::serial_write_byte_raw(b'0');
        return;
    }
    let mut buf = [0u8; 10];
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    for &b in &buf[i..] {
        tb_hal::serial_write_byte_raw(b);
    }
}
