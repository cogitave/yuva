//! Boot Profiles (stage A) — the runtime SELECTOR that decides WHICH kernel
//! boots: the plain sovereign micro-VMM **substrate** or the full resident
//! **agent**. See `docs/proposals/boot-profiles.md`.
//!
//! ## The one load-bearing invariant
//!
//! The selector is `yuva.profile=substrate|agent` on the boot cmdline, **DEFAULT
//! `agent`** — the state of an ABSENT token, which is EVERY CI lane (none passes
//! `-append`) and EVERY re-entrant aarch64 EL1 guest (no cmdline channel). With
//! no token [`agent_organs_enabled`] returns `true`, so the ~18 gated cognitive
//! selftest blocks in `main.rs` run their EXISTING body byte-for-byte and the
//! chokepoint deny latch stays down — the cumulative M0..M38 marker/witness
//! stream is BYTE-IDENTICAL to before this feature. The substrate profile is an
//! ADDITIVE opt-in lane; it emits its own `profile:` witness + `PROFILE:
//! substrate OK` tail and NOTHING new lands on the default (agent) stream.
//!
//! ## Stage A is an EXECUTION + ADMISSION gate, not a render filter
//!
//! In the substrate profile the organs GENUINELY DO NOT RUN — each gated marker
//! takes the aL2.4b-grammar skip form `(substrate profile, agent organ skipped)`
//! carrying no witness tokens — AND the four cognitive M11 method families are
//! DENIED at the [`tb_hal::caps::dispatch`] chokepoint (via [`set_substrate`]),
//! so an organ is not merely un-exercised but structurally NOT ADMITTED. Only
//! stage B (a cargo-feature compile-out, deferred) removes the code BYTES; stage
//! A keeps `code=PRESENT-IN-IMAGE` and never claims "not present".

use core::sync::atomic::{AtomicBool, Ordering};

/// `true` on the AGENT profile (the DEFAULT), `false` on the SUBSTRATE profile.
/// Initialised `true` so an absent `yuva.profile=` token — every CI lane, the
/// EL1 guest, aarch64-host — is the agent profile with the byte-identical stream.
static AGENT_ORGANS: AtomicBool = AtomicBool::new(true);

/// Whether the agent organs run this boot. `true` = agent profile (default),
/// `false` = substrate profile. The ~18 gated `main.rs` blocks branch on this;
/// on `true` each runs its existing body unchanged.
#[inline]
pub fn agent_organs_enabled() -> bool {
    AGENT_ORGANS.load(Ordering::Relaxed)
}

/// Whether this boot is the substrate profile (organs skipped + denied).
#[inline]
pub fn is_substrate() -> bool {
    !agent_organs_enabled()
}

/// Latch the SUBSTRATE profile. Called ONCE, early, from the `yuva.profile=`
/// cmdline parse (`bootreport::apply_cmdline`) BEFORE any agent runs — never on
/// the agent profile, so the default latch stays `true`. Besides skipping the
/// gated selftests, this arms the [`tb_hal::caps`] chokepoint so the four
/// cognitive families fail closed (§2.4) — organs NOT ADMITTED, not merely
/// un-exercised.
pub fn set_substrate() {
    AGENT_ORGANS.store(false, Ordering::Relaxed);
    tb_hal::caps::set_cognitive_deny(true);
}

// The single skip-marker suffix (§1.4 / DoD-5) is the aL2.4b `skipped` grammar
// family — `(substrate profile, agent organ skipped)`. Each gated `main.rs`
// block emits `<landed marker literal> <that suffix>` inline in its substrate
// `else` arm (the prefix STRING-EQUAL to the literal the agent arm emits), so
// the suffix is not centralised in a const here.

/// Emit the substrate-profile witness (§2.5) at the clean-exit site — the
/// one-line `profile:` witness plus the anti-hollow, clean-exit-sited `PROFILE:
/// substrate OK` tail. A NO-OP on the agent profile, so the default stream gains
/// ZERO new bytes (the #1 invariant).
///
/// Before emitting, this EXERCISES both structural-non-admission claims in-boot
/// (DoD-3, the M38 "exercise the gate, don't merely assert it" discipline):
///   (i) a cognitive READ family ([`M_MEM_RECALL`]) at the M11 chokepoint must
///       return `Denied` → `admission=DENIED-AT-CHOKEPOINT`;
///   (ii) the ADMITTED-tier PROMOTION write ([`M_MEM_WRITE_PROC`], the M18.1
///       skill-admission verb) at the chokepoint must return `Denied` →
///       `promotion=REFUSED-AT-GATE`.
/// Both run against `agent_c`'s born-with memory home — a valid handle — so the
/// `Denied` is the chokepoint deny, not a missing agent. If EITHER does not fire
/// the boot FAILS CLOSED here (a crash-before-organs cannot impersonate a clean
/// omission), never emitting the green tail.
pub fn emit_substrate_witness(agent_c: tb_hal::Task) {
    if agent_organs_enabled() {
        return;
    }
    use tb_hal::caps::{self, SysStatus};
    let denied = SysStatus::Denied as u32;

    // (i) chokepoint denial of a cognitive READ family (ranked recall).
    let recall_denied = matches!(
        tb_hal::agent_mem_dispatch(agent_c, caps::M_MEM_RECALL, 0, 0, 1, 0),
        Some((s, _)) if s == denied
    );
    // (ii) the ADMITTED-tier promotion write (procedural-memory ADD_SKILL) — the
    // M18.1 admission verb — refused at the same chokepoint.
    let promotion_refused = matches!(
        tb_hal::agent_mem_dispatch(agent_c, caps::M_MEM_WRITE_PROC, 0, 0, 0, 0),
        Some((s, _)) if s == denied
    );
    if !recall_denied || !promotion_refused || !caps::cognitive_deny() {
        tb_hal::serial_write_str("profile: FAIL substrate structural-non-admission not exercised recall-denied=");
        tb_hal::serial_write_str(if recall_denied { "0x1" } else { "0x0" });
        tb_hal::serial_write_str(" promotion-refused=");
        tb_hal::serial_write_str(if promotion_refused { "0x1" } else { "0x0" });
        tb_hal::serial_write_byte(b'\n');
        tb_hal::fail_exit();
    }

    // The one-line profile witness (non-default selection only). Every token is
    // the honest stage-A vocabulary (§6): NO "not present"/"removed"/"minimal";
    // `code=PRESENT-IN-IMAGE` concedes stage A removes zero bytes; the tcb claim
    // ceiling is attack-surface, not bytes; guest-evidence concedes no stage-A
    // substrate boot witnesses EL2/guest-running (x86_64-only lane).
    tb_hal::serial_write_str(
        "profile: sel=SUBSTRATE source=PVH-CMDLINE organs=SKIPPED-RUNTIME-GATED \
         code=PRESENT-IN-IMAGE admission=DENIED-AT-CHOKEPOINT promotion=REFUSED-AT-GATE \
         tcb=ATTACK-SURFACE-REDUCED-NOT-BYTES-REMOVED separability=EXECUTION-ADMISSION-LEVEL \
         guest-evidence=AARCH64-AGENT-LANE-ONLY view=SUBSTRATE-DEFAULTED smp=UP-ONLY \
         rootfs=NONE realtime=NOT-CLAIMED\n",
    );
    // The substrate lane's cumulative tail — clean-exit-sited (anti-hollow). NOT
    // "substrate-vmm": no stage-A substrate boot exercises EL2/tb-vmm (§2.5).
    tb_hal::serial_write_str("PROFILE: substrate OK organs=SKIPPED-RUNTIME-GATED\n");
}
