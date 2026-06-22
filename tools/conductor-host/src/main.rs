//! conductor-host — the M38 stage-A host conductor.
//!
//! Runs the verified `tb-encode::conductor` policy over a FIXED OFFLINE transcript
//! of three M38-authored deterministic mock organs, CAPTURES the organ-call trace
//! as a SEPARATE stream, and INDEPENDENTLY recomputes the M22-folded decision
//! lineage from THAT trace — the cross-process anti-hollow leg. Prints the witness
//! (organ-sequence + role-trace + verdict + turn-count + the lineage head + the
//! ADOPT-4 honest cost record). Offline + deterministic: NO network, NO secret,
//! NO real M31/M32 call. The marker lives ONLY in the workflow summary (the run
//! script chain is untouched at stage A).
//!
//! Modes (the §8 stub-resistance is the independent recompute; the negatives prove
//! the lane goes RED on a hollow conductor):
//!   (default)            the honest run — policy + independent recompute MATCH;
//!                        organs>=2, revise-cycles>=1; prints the witness + OK.
//!   --forge-single-organ a degenerate stub that picks ONE organ and always
//!                        ACCEPTs (no measured multi-organ sequence, no REVISE) —
//!                        the witness assertions FAIL (organs<2 / revise<1).
//!   --forge-lineage      tampers ONE byte of a committed decision so the host's
//!                        independent recompute DIVERGES from the policy head —
//!                        the equality FAILS (the loopback/fixture killer).

use std::io::Read as _;
use std::process::exit;

use tb_encode::conductor::{
    assign_role, canon, conduct_chain_mix, conduct_hash, conduct_head_witness, conduct_recompute,
    conduct_verify_inclusion, select_organ, step, Action, ConductDecision, Organ, Role, Verdict,
    CONDUCT_CANON_LEN, MAX_TURNS, PROV_HASH_LEN,
};
use tb_encode::prov::kind::CONDUCT_DECISION;

/// Render a byte slice as lowercase hex in WIRE BYTE ORDER (the §6 inert-alphabet
/// encoder; the SAME rendering the kernel + every witness path use).
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// One captured organ-call step — the SEPARATE trace stream the host folds
/// INDEPENDENTLY (NOT the policy's printed summary). Each field is what the host
/// OBSERVED as the organ was invoked, so a fabricated policy summary cannot match
/// the host's independent fold over the real observed trace.
#[derive(Clone, Copy, Debug)]
struct TraceStep {
    turn: u8,
    role: Role,
    organ: Organ,
    verdict: Verdict,
    organ_calls: u16,
    t_logical: u64,
}

/// The M38-authored deterministic LocalM32 mock organ: a trivial fixed-output
/// engine M38 owns (NOT the real M32 daemon — that is host-process, not driven
/// from this offline transcript). Returns a deterministic quality score for the
/// Worker's output given the retrieved context strength and the retry round. The
/// first round yields a BELOW-margin score (forcing a Verifier REVISE); a later
/// round, having incorporated the ExternalMock organ's improvement, clears.
fn mock_worker_score(round: u8, context_strength: i64) -> i64 {
    // Deterministic, monotone in the retry round: round 0 is weak (REVISE),
    // round >=1 incorporates the external-organ refinement and clears the margin.
    // Pure integer arithmetic, no float, no network.
    let base = context_strength;
    let refinement = (round as i64) * 200;
    base + refinement
}

/// The fixed score FLOOR the Verifier gates against (the heuristic baseline the
/// Worker output must beat by the margin). A ship-const for the offline transcript.
const SCORE_FLOOR: i64 = 100;

/// The retrieved-context strength the RetrievalOverMemory mock yields (a fixed
/// lexical-recall surrogate — `retrieval=LEXICAL-NOT-SEMANTIC`, no embeddings).
const CONTEXT_STRENGTH: i64 = 200;

/// The honest run: drive the verified policy to a terminal verdict over the fixed
/// transcript, executing the M38-authored mock organs and CAPTURING the trace.
/// Returns `(policy_head, trace)` — the policy-emitted M22 head and the SEPARATE
/// captured organ-call trace. The two are folded INDEPENDENTLY by the caller.
fn run_policy(forge_single_organ: bool) -> ([u8; PROV_HASH_LEN], Vec<TraceStep>) {
    let mut trace: Vec<TraceStep> = Vec::new();
    let mut policy_head = [0u8; PROV_HASH_LEN]; // genesis (all-zero) head
    let mut scratch = [0u8; CONDUCT_CANON_LEN + 8];

    let mut turn: u8 = 0;
    let mut organ_calls: u16 = 0;
    let mut round: u8 = 0; // the Verifier retry round (REVISE -> retry)

    loop {
        let role = assign_role(turn);

        // ORGAN SELECTION (the verified policy): a degenerate stub forges a single
        // organ; the honest path advances the organ preference as the task does
        // (a measured >=2-organ sequence: retrieve THEN infer THEN refine).
        let organ = if forge_single_organ {
            // The anti-hollow degenerate: always organ 0 (no measured sequence).
            select_organ(0)
        } else {
            // The honest 2-hop+ task: Thinker proposes over RetrievalOverMemory,
            // Worker executes over LocalM32, later rounds bring in ExternalMock.
            match role {
                Role::Thinker => select_organ(0),               // RetrievalOverMemory
                Role::Worker => select_organ(1 + round as usize), // LocalM32 -> ExternalMock
                Role::Verifier => select_organ(1 + round as usize),
            }
        };

        // ORGAN EXECUTION (the host side): the M38-authored deterministic mock.
        // The Worker invokes the engine (a real organ call -> cost increments);
        // the Verifier adjudicates the Worker's last output.
        if role == Role::Worker {
            organ_calls = organ_calls.saturating_add(1);
        }
        let worker_score = if forge_single_organ {
            // The stub always clears on turn 0 (always-accept) — no REVISE cycle.
            i64::MAX
        } else {
            mock_worker_score(round, CONTEXT_STRENGTH)
        };

        // THE VERIFIED VERDICT + the bounded transition (the policy leaf).
        let (verdict, action) = step(turn, worker_score, SCORE_FLOOR, super_margin());

        // CAPTURE the step into the SEPARATE trace stream (what the host observed).
        trace.push(TraceStep {
            turn,
            role,
            organ,
            verdict,
            organ_calls,
            t_logical: turn as u64,
        });

        // FOLD the decision into the policy head via the REUSED M22 prov fold
        // (the policy-emitted lineage — folded the SAME way the host will fold the
        // independent trace, so an honest run MATCHES and a forged one DIVERGES).
        let rec = ConductDecision {
            turn,
            role: role.tag(),
            organ: organ.tag(),
            verdict: verdict.tag(),
            organ_calls,
            t_logical: turn as u64,
        };
        let n = canon(&rec, &mut scratch);
        let id = conduct_hash(&scratch[..n]);
        policy_head = conduct_chain_mix(policy_head, id);

        match action {
            Action::Terminate(_) => break,
            Action::Continue { turn: next_turn, .. } => {
                // A Verifier REVISE advances the retry round (the refine-then-retry
                // cycle that brings the ExternalMock organ into the sequence).
                if role == Role::Verifier && verdict == Verdict::Revise {
                    round = round.saturating_add(1);
                }
                turn = next_turn;
            }
        }
    }
    (policy_head, trace)
}

/// The Verifier margin the offline transcript gates against (the conductor's
/// `VERDICT_MARGIN`). A small indirection so the transcript reads against the
/// SAME const the leaf proves.
fn super_margin() -> i64 {
    tb_encode::conductor::VERDICT_MARGIN
}

/// INDEPENDENTLY recompute the M22 decision lineage from the captured trace — the
/// load-bearing stub-killer (§8.6). The host rebuilds each `ConductDecision` from
/// what it OBSERVED (the SEPARATE trace stream), folds them into a head via the
/// REUSED prov fold, and returns `(head, leaf_ids)`. A fabricated policy summary
/// fails because THIS fold over the REAL observed trace yields a different head.
/// `tamper_byte` optionally flips one byte of the FIRST committed decision's canon
/// (the `--forge-lineage` negative): the recomputed head then DIVERGES from the
/// policy head, and the run is caught.
fn recompute_lineage(
    trace: &[TraceStep],
    tamper_byte: bool,
) -> ([u8; PROV_HASH_LEN], Vec<[u8; PROV_HASH_LEN]>) {
    let mut leaves: Vec<[u8; PROV_HASH_LEN]> = Vec::with_capacity(trace.len());
    let mut scratch = [0u8; CONDUCT_CANON_LEN + 8];
    for (i, s) in trace.iter().enumerate() {
        let rec = ConductDecision {
            turn: s.turn,
            role: s.role.tag(),
            organ: s.organ.tag(),
            verdict: s.verdict.tag(),
            organ_calls: s.organ_calls,
            t_logical: s.t_logical,
        };
        let n = canon(&rec, &mut scratch);
        if tamper_byte && i == 0 {
            // The forge: a single-byte tamper of the first committed decision.
            scratch[3] ^= 0x01; // OFF_VERDICT
        }
        leaves.push(conduct_hash(&scratch[..n]));
    }
    // Fold the leaves into a head via the REUSED prov recompute (leaf, siblings).
    let head = if leaves.is_empty() {
        [0u8; PROV_HASH_LEN]
    } else {
        conduct_recompute(leaves[0], &leaves[1..])
    };
    (head, leaves)
}

/// Count the DISTINCT organs in the observed sequence (the measured multi-organ
/// requirement — a stub that picks one organ has count 1 and FAILS organs>=2).
fn distinct_organs(trace: &[TraceStep]) -> usize {
    let mut seen = [false; 3];
    for s in trace {
        let idx = s.organ.tag() as usize;
        if idx < seen.len() {
            seen[idx] = true;
        }
    }
    seen.iter().filter(|&&b| b).count()
}

/// Count the Verifier REVISE->(eventual ACCEPT) cycles in the observed trace (the
/// measured >=1 revise-cycle requirement — a stub that always-accepts has 0).
fn revise_cycles(trace: &[TraceStep]) -> usize {
    trace
        .iter()
        .filter(|s| s.role == Role::Verifier && s.verdict == Verdict::Revise)
        .count()
}

/// STAGE B (proposal §8.6): the CROSS-PROCESS independent-recompute leg, host-side.
/// Read the GUEST's OWN emitted `conduct-step:` trace lines from stdin, rebuild each
/// `ConductDecision` from THOSE fields, INDEPENDENTLY re-fold the M22 lineage via the
/// REUSED prov fold, and print `conductor-recompute: head=0x<hex16> steps=0x<n>`. The
/// run-script string-equals this host-recomputed `head` against the guest-emitted
/// `conduct: head=..` -- a forged guest summary cannot match the independent fold over
/// the guest's own real trace. This is the SAME verified `tb_encode::conductor` leaf,
/// in a SEPARATE host process, folding the guest's emitted trace -- the anti-hollow
/// leg now guest -> host. Zero network, zero secret, deterministic.
fn recompute_from_trace() -> ! {
    // Parse `conduct-step: turn=0x.. role=0x.. organ=0x.. verdict=0x.. organ-calls=0x..
    // t-logical=0x..` lines (the kernel's injection-proof hex-only trace). Any other
    // line is ignored (the trace lines are self-delimiting). Hex fields are 0x-prefixed.
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        eprintln!("conductor-recompute: FAIL -- could not read the guest trace from stdin");
        exit(1);
    }
    fn field_hex(line: &str, key: &str) -> Option<u64> {
        // Find " key=0x<hex>" (or "key=" at line start after the prefix).
        let needle = format!("{key}=0x");
        let idx = line.find(&needle)? + needle.len();
        let rest = &line[idx..];
        let end = rest.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(rest.len());
        u64::from_str_radix(&rest[..end], 16).ok()
    }

    let mut head = [0u8; PROV_HASH_LEN]; // genesis (all-zero) head
    let mut scratch = [0u8; CONDUCT_CANON_LEN + 8];
    let mut steps: u64 = 0;
    for line in input.lines() {
        let line = line.trim();
        if !line.starts_with("conduct-step:") {
            continue;
        }
        let (turn, role, organ, verdict, organ_calls, t_logical) = match (
            field_hex(line, "turn"),
            field_hex(line, "role"),
            field_hex(line, "organ"),
            field_hex(line, "verdict"),
            field_hex(line, "organ-calls"),
            field_hex(line, "t-logical"),
        ) {
            (Some(a), Some(b), Some(c), Some(d), Some(e), Some(f)) => (a, b, c, d, e, f),
            _ => {
                eprintln!("conductor-recompute: FAIL -- malformed conduct-step line: {line}");
                exit(1);
            }
        };
        // Rebuild the SAME ConductDecision the guest folded; fold it INDEPENDENTLY.
        let rec = ConductDecision {
            turn: turn as u8,
            role: role as u8,
            organ: organ as u8,
            verdict: verdict as u8,
            organ_calls: organ_calls as u16,
            t_logical,
        };
        let n = canon(&rec, &mut scratch);
        if n == 0 {
            eprintln!("conductor-recompute: FAIL -- canon failed (impossible)");
            exit(1);
        }
        let id = conduct_hash(&scratch[..n]);
        head = conduct_chain_mix(head, id);
        steps += 1;
    }
    if steps == 0 {
        eprintln!("conductor-recompute: FAIL -- no conduct-step lines on stdin (the guest emitted no trace)");
        exit(1);
    }
    // The u64 witness the guest also prints (head_witness over the 32-byte head) --
    // the run-script string-equals THIS against the guest's `conduct: head=..`.
    println!(
        "conductor-recompute: head=0x{:016x} steps=0x{:x} recompute=INDEPENDENT trace=GUEST-EMITTED",
        conduct_head_witness(head),
        steps,
    );
    exit(0);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // STAGE B: the run-script cross-process recompute leg (reads the guest trace).
    if args.iter().any(|a| a == "--recompute-from-trace") {
        recompute_from_trace();
    }
    let forge_single_organ = args.iter().any(|a| a == "--forge-single-organ");
    let forge_lineage = args.iter().any(|a| a == "--forge-lineage");

    // (1) Run the verified policy over the fixed transcript, capturing the trace.
    let (policy_head, trace) = run_policy(forge_single_organ);

    // (2) INDEPENDENTLY recompute the lineage from the SEPARATE captured trace.
    let (host_head, leaves) = recompute_lineage(&trace, forge_lineage);

    // (3) The cross-process equality (the load-bearing stub-killer): the policy
    // head and the host's independent fold over the observed trace must MATCH.
    let lineage_match = policy_head == host_head;

    // (4) An inclusion round-trip + a single-byte tamper-caught check over the
    // host's own leaves (the M22 tamper-evidence leg).
    let tamper_caught = if leaves.is_empty() {
        false
    } else {
        let genuine = conduct_verify_inclusion(leaves[0], &leaves[1..], host_head);
        let mut bad_leaf = leaves[0];
        bad_leaf[0] ^= 0x01;
        let forged_rejected = !conduct_verify_inclusion(bad_leaf, &leaves[1..], host_head);
        genuine && forged_rejected
    };

    // The measured quantities (from the OBSERVED trace, not a printed claim).
    let organs = distinct_organs(&trace);
    let revises = revise_cycles(&trace);
    let turns = trace.last().map(|s| s.turn + 1).unwrap_or(0);
    let final_verdict = trace.last().map(|s| s.verdict).unwrap_or(Verdict::HaltBudget);
    let total_organ_calls = trace.last().map(|s| s.organ_calls).unwrap_or(0);
    let head_w = conduct_head_witness(host_head);

    // The role trace (the T/W/V cadence over the observed turns).
    let role_trace: String = trace
        .iter()
        .map(|s| match s.role {
            Role::Thinker => 'T',
            Role::Worker => 'W',
            Role::Verifier => 'V',
        })
        .collect();
    // The organ sequence (the measured multi-organ pick order, hex tags).
    let organ_seq: String = trace.iter().map(|s| format!("{:x}", s.organ.tag())).collect();

    let verdict_tok = match final_verdict {
        Verdict::Accept => "ACCEPT",
        Verdict::Revise => "REVISE",
        Verdict::HaltBudget => "HALT-BUDGET",
    };
    let accept_at = trace
        .iter()
        .position(|s| s.verdict == Verdict::Accept)
        .map(|i| trace[i].turn)
        .unwrap_or(0);

    let fold_verified = if lineage_match { 1 } else { 0 };
    let tamper_flag = if tamper_caught { 1 } else { 0 };

    // THE WITNESS (one line, all corroboration on the SAME line — the proposal §8
    // shape, host-adjudicated stage A; the honest tokens verbatim from §5/§8/§10).
    println!(
        "conduct: head=0x{head_w:016x} turns=0x{turns:x} organs=0x{organs:x} roles={role_trace} \
organ-seq=0x{organ_seq} verdict={verdict_tok} accept-at=0x{accept_at:x} revise-cycles=0x{revises:x} \
fold-verified=0x{fold_verified} tamper-caught=0x{tamper_flag} organ-calls=0x{total_organ_calls:x} \
logical-ticks=0x{turns:x} attested=0x1 prov-tag=0x{tag:x} \
policy=DISCRETE-HAND-WRITTEN-NOT-LEARNED learning=DORMANT retrieval=LEXICAL-NOT-SEMANTIC \
external-organ=MOCK-IN-CI local-organ=M38-AUTHORED-MOCK verifier=CI-DISCRETE-VERDICT \
m18-gate=ADMISSION-ONLY-INERT-IN-MOCK cost=HONEST-ACCOUNTED-TOKENED \
cost-metric=LOGICAL-SURROGATE-NOT-WALLCLOCK orchestration=RAG-AGENTS-NOT-NEW-PARADIGM \
live+web=DISPATCH-ONLY novelty=VERIFIED-PROVENANCE-SOVEREIGN-WRAPPER generativity=OPEN-FRONTIER \
realtime=NOT-CLAIMED benchmark=NOT-CLAIMED stub-resistance=HOST-RECOMPUTE-FROM-INDEPENDENT-TRACE \
host=RESIDUAL-TCB sec=ASSUMED-FROM-LITERATURE",
        tag = CONDUCT_DECISION,
    );

    // The cost record (the ADOPT-4 honest accounting, §5 — folded tamper-evidently).
    println!(
        "cost: organ-calls=0x{total_organ_calls:x} turns=0x{turns:x} logical-ticks=0x{turns:x} attested=0x{tamper_flag}"
    );

    // The host's independent-recompute corroboration line (the SEPARATE stream;
    // policy-head vs host-recomputed-head string equality is the stub-killer).
    println!(
        "conductor-host: policy-head=0x{} host-head=0x{} lineage-equal=0x{} steps=0x{:x} \
trace=SEPARATE-CAPTURE recompute=INDEPENDENT",
        hex(&policy_head),
        hex(&host_head),
        fold_verified,
        trace.len(),
    );

    // ADJUDICATION (fail-closed): the honest run must MATCH + meet the measured
    // anti-hollow thresholds. The negatives MUST land RED here.
    let mut ok = true;
    if !lineage_match {
        eprintln!("conductor-host: FAIL — policy head != host independent-recompute head (forged/fixture lineage caught)");
        ok = false;
    }
    if !tamper_caught {
        eprintln!("conductor-host: FAIL — the single-byte tamper of a committed decision was NOT caught");
        ok = false;
    }
    if organs < 2 {
        eprintln!("conductor-host: FAIL — measured organ sequence has {organs} distinct organ(s) (a degenerate single-organ stub; the witness requires >=2)");
        ok = false;
    }
    if revises < 1 {
        eprintln!("conductor-host: FAIL — measured revise-cycles = {revises} (an always-accept stub; the witness requires >=1 REVISE->ACCEPT cycle)");
        ok = false;
    }
    if final_verdict != Verdict::Accept {
        eprintln!("conductor-host: FAIL — final verdict is {verdict_tok}, not ACCEPT (the loop did not reach a real Verifier-ACCEPT)");
        ok = false;
    }
    if turns > MAX_TURNS + 1 {
        eprintln!("conductor-host: FAIL — turn count {turns} exceeds the bound MAX_TURNS+1");
        ok = false;
    }

    if ok {
        // The workflow-only DoD marker (the run scripts NEVER carry it — stage A).
        println!(
            "M38: conductor OK turns={turns} organs={organs} verdict=ACCEPT"
        );
        exit(0);
    }
    eprintln!("conductor-host: lane RED");
    exit(1);
}
