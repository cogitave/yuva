//! The M30/M31 HOST peer (the QEMU chardev-harness lanes).
//!
//! M30 (LEG 2 of the proposal-§4 anti-hollow composition -- the echo):
//!
//! 1. At startup it samples `K:[u8;32]` (the per-run channel key) and
//!    `N:[u8;16]` (the per-run nonce) from the host OS RNG (`/dev/urandom`).
//!    K is BORN here and lives ONLY in this process until it is revealed on
//!    the channel -- it is never in the guest image, on the guest command
//!    line, or in guest-visible config space (`key=HOST-CUSTODIED-PER-RUN`).
//! 2. It connects to the QEMU `virtconsole` chardev unix socket and SERVES
//!    frames to EOF, re-framing the byte stream through the SAME Kani-proven
//!    [`tb_encode::inferwire::FrameAccum`] the kernel uses (one codec, never
//!    a shell/python re-implementation -- research §8).
//! 3. An `ECHO_REQ` is answered with `ECHO_RESP || K`: the response echoes
//!    the request body verbatim, carries N + `peer_id=QEMU-CHARDEV-HARNESS`,
//!    and its tag is the verified leaf's [`tb_encode::inferwire::echo_tag`].
//!    The harness prints its OWN `xport-harness:` witness line; the run
//!    script string-compares challenge/tag CROSS-PROCESS (the loopback
//!    killer).
//!
//! M31 (the inference-adapter MOCK serve loop -- stage B, ZERO network):
//!
//! 4. A MAC'd `INFER_REQ` chunk sequence (the kernel MACs its requests with K
//!    under the NEW `"YUVA-M31-INFER-V1"` domain; [`verify_infer_req`] is the
//!    symmetric check) reassembles through the SAME Kani-proven
//!    [`InferAssembler`] the kernel uses. A completed body is dispatched:
//!    * the designated [`INFER_NOKEY_PROBE`] body -> a MAC'd `ERR
//!      code=NO-KEY` (this stage-B harness holds NO API key, and says so
//!      fail-closed through the CLOSED enum -- the kernel's
//!      `wire-err-handled=0x1` evidence);
//!    * any other body -> EXACTLY ONE MAC'd `INFER_PENDING` heartbeat
//!      (liveness plumbing, never a completion) followed by the
//!      MOCK-DETERMINISTIC response: the SHARED [`mock_infer`] transform
//!      (1280 bytes -- deliberately > the 1024 payload cap, so the reply is
//!      ALWAYS a chunked sequence exercising the assembler on the guest
//!      side), each chunk MAC'd via [`infer_tag`] binding
//!      peer‖N‖challenge‖req_id‖kind‖seq‖sflags‖total_len‖body_digest‖chunk
//!      INSIDE the MAC. The harness prints an `xport-harness-infer:` info
//!      line (a DISTINCT prefix -- it never matches the M30 `xport-harness: `
//!      grep nor the guest-side M31 filters).
//!
//! HONEST: `backend=MOCK-DETERMINISTIC` -- this process applies a
//! deterministic transform; no model is loaded and, in the DEFAULT mode, no
//! network is touched and no TLS exists.
//!
//! M31 stage C (the ANTHROPIC-LIVE bridge -- operator-gated, NEVER part of
//! unattended runs): with the `--anthropic` flag (or `XPORT_ANTHROPIC=1` --
//! the env opt-in exists because the required-lane run scripts hardcode this
//! binary's argv and MUST stay byte-identical) AND `ANTHROPIC_API_KEY` in the
//! env, the serve loop ADDITIONALLY makes EXACTLY ONE Messages API call when
//! the kernel's real-prompt `INFER_REQ` completes -- see [`live`] for the full
//! design and the honest stage-C scope notes. Three invariants the live mode
//! NEVER breaks:
//!
//! * the GUEST exchange is byte-identical to mock mode (the stage-B kernel
//!   pins the wire shape exactly -- `selftests.rs` stages 0x21/0x25/0x26 --
//!   so the cumulative chain stays green and no live byte rides the channel);
//! * the live call happens AFTER the guest is answered (the kernel's
//!   `POLL_CAP` cannot absorb HTTP latency, and extra PENDINGs are forbidden
//!   by the exact-shape check);
//! * opt-in without the key is a LOUD startup refusal (exit 3,
//!   [`live::NO_KEY_REFUSAL`]) -- never a silent mock fallback wearing the
//!   live token, and the key itself is never printed (every live-path line is
//!   scrubbed).
//!
//! It also writes K's hex to `--key-out` so the run script can NEGATIVELY
//! assert the key never leaked into the guest serial output (§5.7) -- that
//! file is the script's ephemeral check input, never part of any witness.
//!
//! Exit codes: 0 = served at least one echo (then drained to EOF); 1 =
//! timeout or I/O fault (a dead lane is LOUD -- the run script fails on a
//! missing `xport-harness:` line either way).

mod live;

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::exit;
use std::time::{Duration, Instant};

use tb_encode::inferwire::{
    body_digest, canon, decode, echo_tag, errcode, err_canon, infer_tag, kind, mock_infer, peer,
    verify_infer_req, AsmPush, FrameAccum, InferAssembler, InferFrame, SubHdr, INFER_ACCUM_CAP,
    INFER_BODY_CAP, INFER_CHUNK_CAP, INFER_ERR_PAYLOAD_LEN, INFER_KEY_LEN, INFER_MOCK_RESP_LEN,
    INFER_LOCAL_PROBE, INFER_NOKEY_PROBE, INFER_NONCE_LEN, INFER_SUBHDR_LEN,
};

/// Render a byte slice as lowercase hex in WIRE BYTE ORDER (byte 0 first) --
/// the exact format the kernel's `write_hex_bytes16` uses, so the run script's
/// leg-2 equality is a plain string compare.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Sample `n` bytes from the host OS RNG (`/dev/urandom` -- no external crate,
/// the zero-dep discipline).
fn os_random(n: usize) -> Vec<u8> {
    let mut f = File::open("/dev/urandom").expect("xport-harness: /dev/urandom unavailable");
    let mut buf = vec![0u8; n];
    f.read_exact(&mut buf)
        .expect("xport-harness: short read from /dev/urandom");
    buf
}

/// Canon a frame into a fresh wire buffer (panics on an unencodable frame --
/// a harness-side construction bug, never an input condition).
fn wire_of(frame: &InferFrame) -> Vec<u8> {
    let mut wire = vec![0u8; tb_encode::inferwire::wire_len(frame)];
    let n = canon(frame, &mut wire);
    assert!(n == wire.len(), "xport-harness: frame canon failed");
    wire
}

/// Build one MAC'd M31 host->guest frame (the tag binds every field via the
/// verified leaf's [`infer_tag`] -- ONE khash call under the M31 domain).
#[allow(clippy::too_many_arguments)]
fn m31_frame(
    key: &[u8; INFER_KEY_LEN],
    nonce: &[u8; INFER_NONCE_LEN],
    challenge: &[u8; 16],
    req_id: u64,
    k: u8,
    sub: &SubHdr,
    chunk: &[u8],
    payload: Vec<u8>,
) -> Vec<u8> {
    tagged_frame(
        peer::QEMU_CHARDEV_HARNESS,
        key,
        nonce,
        challenge,
        req_id,
        k,
        sub,
        chunk,
        payload,
    )
}

/// Build one MAC'd host->guest frame stamped with an EXPLICIT `peer_id` -- the
/// M31 mock leg uses `QEMU_CHARDEV_HARNESS (0x02)`, the M32 local-organ leg uses
/// `INFER_DAEMON (0x03)`. The `peer_id` is bound INSIDE [`infer_tag`], so a
/// `0x02` mock frame can never masquerade as the `0x03` local organ (the
/// kani_inferwire_infer_peer_bound proof).
#[allow(clippy::too_many_arguments)]
fn tagged_frame(
    peer_id: u8,
    key: &[u8; INFER_KEY_LEN],
    nonce: &[u8; INFER_NONCE_LEN],
    challenge: &[u8; 16],
    req_id: u64,
    k: u8,
    sub: &SubHdr,
    chunk: &[u8],
    payload: Vec<u8>,
) -> Vec<u8> {
    let tag = infer_tag(key, peer_id, nonce, challenge, req_id, k, sub, chunk);
    let frame = InferFrame {
        kind: k,
        req_id,
        challenge: *challenge,
        nonce: *nonce,
        peer_id,
        tag,
        payload: &payload,
    };
    wire_of(&frame)
}

/// The in-flight (stop-and-wait, single outstanding req_id) request state.
struct Inflight {
    req_id: u64,
    challenge: [u8; 16],
    asm: Box<InferAssembler<INFER_BODY_CAP>>,
}

fn main() {
    // --- args: --socket <path> [--key-out <path>] [--timeout-secs <n>] -----
    // --- [--anthropic]  (M31 stage C: the operator-gated live serve mode) --
    let mut socket_path: Option<String> = None;
    let mut key_out: Option<String> = None;
    let mut timeout_secs: u64 = 300;
    let mut anthropic = false;
    let mut args = env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--socket" => socket_path = args.next(),
            "--key-out" => key_out = args.next(),
            "--timeout-secs" => {
                timeout_secs = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(timeout_secs)
            }
            "--anthropic" => anthropic = true,
            other => {
                eprintln!("xport-harness: unknown arg '{other}'");
                exit(2);
            }
        }
    }
    let socket_path = match socket_path {
        Some(p) => p,
        None => {
            eprintln!("usage: xport-harness --socket <unix-socket> [--key-out <file>] [--timeout-secs <n>] [--anthropic]");
            exit(2);
        }
    };

    // --- M31 stage C: the live-mode gate (OFF by default; double opt-in) ---
    // The flag is the canonical switch; `XPORT_ANTHROPIC=1` (strict: exactly
    // "1") is the env equivalent because the required-lane run scripts
    // hardcode this binary's argv and stay byte-identical -- the live
    // workflow exports the env var instead. NEITHER is ever set by the
    // push/PR CI lanes, and without the additional `ANTHROPIC_API_KEY`
    // secret the gate below refuses LOUDLY -- the live path is structurally
    // unreachable from unattended runs.
    let live_mode =
        anthropic || env::var("XPORT_ANTHROPIC").map(|v| v == "1").unwrap_or(false);
    let live_key: Option<String> = if live_mode {
        match env::var(live::KEY_ENV) {
            Ok(k) if !k.is_empty() => Some(k),
            _ => {
                // The documented LOUD refusal: never a silent mock fallback
                // wearing the live token, never an invented key (exit 3 --
                // distinct from the usage error 2 and the lane fault 1).
                eprintln!("{}", live::NO_KEY_REFUSAL);
                exit(3);
            }
        }
    } else {
        None
    };
    // The spend-guard latch: at most ONE live call per process, no matter how
    // many INFER_REQ bodies complete (set BEFORE the call, so even a panicky
    // unwind path can never double-spend).
    let mut live_done = false;

    // --- the per-run HOST-custodied key + nonce (OS RNG; M30 proposal §4) ---
    let kvec = os_random(INFER_KEY_LEN);
    let nvec = os_random(INFER_NONCE_LEN);
    let mut key = [0u8; INFER_KEY_LEN];
    key.copy_from_slice(&kvec);
    let mut nonce = [0u8; INFER_NONCE_LEN];
    nonce.copy_from_slice(&nvec);
    if let Some(kp) = &key_out {
        // The run script's key-LEAK check input (never a witness): K's hex
        // must appear NOWHERE in the guest serial output.
        std::fs::write(kp, hex(&key)).expect("xport-harness: cannot write --key-out");
    }

    // --- connect (retry: QEMU creates the listener at startup) -------------
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut stream = loop {
        match UnixStream::connect(&socket_path) {
            Ok(s) => break s,
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("xport-harness: cannot connect to {socket_path}: {e}");
                exit(1);
            }
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("xport-harness: set_read_timeout");

    // --- the SERVE LOOP: re-frame the byte stream, dispatch on kind --------
    let mut acc: FrameAccum<INFER_ACCUM_CAP> = FrameAccum::new();
    let mut chunkbuf = [0u8; 4096];
    let mut echoes: u32 = 0;
    let mut inflight: Option<Inflight> = None;
    'serve: loop {
        if Instant::now() >= deadline {
            eprintln!("xport-harness: serve-loop timeout");
            break 'serve;
        }
        let n = match stream.read(&mut chunkbuf) {
            Ok(0) => break 'serve, // QEMU closed (guest done) -- clean EOF
            Ok(n) => n,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => {
                eprintln!("xport-harness: read error: {e}");
                break 'serve;
            }
        };
        let mut b = 0usize;
        while b < n {
            let emitted = acc.push_byte(chunkbuf[b]);
            b += 1;
            let fl = match emitted {
                Some(fl) => fl,
                None => continue,
            };
            let frame_bytes = acc.bytes()[..fl].to_vec();
            acc.consume(fl);
            let frame = match decode(&frame_bytes) {
                Some(f) => f,
                None => {
                    eprintln!("xport-harness: emitted window failed decode (desync)");
                    continue;
                }
            };
            match frame.kind {
                // ---- M30: the host-keyed echo (verbatim semantics) --------
                kind::ECHO_REQ => {
                    let tag = echo_tag(
                        &key,
                        peer::QEMU_CHARDEV_HARNESS,
                        &nonce,
                        &frame.challenge,
                        frame.payload,
                    );
                    let resp = InferFrame {
                        kind: kind::ECHO_RESP,
                        req_id: frame.req_id,
                        challenge: frame.challenge, // echoed verbatim + MAC-bound
                        nonce,
                        peer_id: peer::QEMU_CHARDEV_HARNESS,
                        tag,
                        payload: frame.payload, // body echoed verbatim
                    };
                    let mut wire = wire_of(&resp);
                    // The channel-layer key reveal trails the frame (cleartext
                    // -- custody, not confidentiality).
                    wire.extend_from_slice(&key);
                    if let Err(e) = stream.write_all(&wire).and_then(|()| stream.flush()) {
                        eprintln!("xport-harness: write error: {e}");
                        exit(1);
                    }
                    // LEG 2: the host's OWN witness line (cross-process compare).
                    println!(
                        "xport-harness: peer=QEMU-CHARDEV-HARNESS challenge=0x{} tag=0x{} key-custody=HOST",
                        hex(&frame.challenge),
                        hex(&tag)
                    );
                    std::io::stdout().flush().ok();
                    echoes += 1;
                }
                // ---- M31: a MAC'd inference-request chunk ------------------
                kind::INFER_REQ => {
                    let (sub, chunk) = match verify_infer_req(&key, &frame) {
                        Some(x) => x,
                        None => {
                            // An unMAC'd/malformed REQ never gets a reply; the
                            // guest's bounded poll turns this LOUD red.
                            eprintln!("xport-harness: INFER_REQ failed verify_infer_req");
                            continue;
                        }
                    };
                    // Single in-flight stop-and-wait: a NEW req_id restarts.
                    let restart = match &inflight {
                        Some(f) => f.req_id != frame.req_id,
                        None => true,
                    };
                    if restart {
                        inflight = Some(Inflight {
                            req_id: frame.req_id,
                            challenge: frame.challenge,
                            asm: Box::new(InferAssembler::new()),
                        });
                    }
                    let fl_state = inflight.as_mut().expect("inflight just set");
                    match fl_state.asm.push_chunk(&sub, chunk) {
                        AsmPush::Accepted => {} // more chunks coming (lockstep)
                        AsmPush::Rejected => {
                            eprintln!("xport-harness: INFER_REQ chunk rejected by assembler");
                            inflight = None;
                        }
                        AsmPush::Complete(blen) => {
                            let req_id = fl_state.req_id;
                            let challenge = fl_state.challenge;
                            let body = fl_state.asm.body()[..blen].to_vec();
                            inflight = None;
                            // The GUEST exchange first, byte-identical to mock
                            // mode in EVERY mode: the stage-B kernel sizes its
                            // receive window a priori and requires exactly one
                            // PENDING + the bit-exact deterministic mock
                            // response (selftests.rs stages 0x21/0x25/0x26),
                            // so no live byte can ride the channel and no HTTP
                            // latency may sit between the request and this
                            // answer (POLL_CAP is sub-second under KVM).
                            serve_infer(&mut stream, &key, &nonce, &challenge, req_id, &body);
                            // M31 stage C: the ONE operator-gated live call
                            // rides ALONGSIDE, after the guest is answered.
                            // The liveness nonce is the kernel's per-boot wire
                            // challenge (minted in-guest from the cycle
                            // counter -- fresh every boot, so a canned/replay
                            // fixture fails the §5 transform check); the NOKEY
                            // probe never triggers it (that body is the
                            // designated fail-closed wire-ERR check, not a
                            // prompt). The host-leg verdict prints on THIS
                            // process's stdout; real-infer.yml adjudicates it
                            // -- the kernel-side live leg (§5.5) is a NAMED
                            // kernel follow-up, deliberately absent here.
                            // The M32 local-organ sentinel is plumbing (a
                            // deterministic stand-in probe), NOT a prompt -- it
                            // must NEVER ride the live bridge (defense in depth
                            // over the one-shot latch; the M31 real prompt
                            // arrives first and already latches live_done).
                            let is_local_probe = body.len() >= INFER_LOCAL_PROBE.len()
                                && &body[..INFER_LOCAL_PROBE.len()] == INFER_LOCAL_PROBE;
                            if live_key.is_some()
                                && !live_done
                                && body.as_slice() != INFER_NOKEY_PROBE
                                && !is_local_probe
                            {
                                live_done = true; // the latch: at most ONE call
                                let api_key =
                                    live_key.as_deref().expect("live_key checked above");
                                let transport = live::UreqTransport::new();
                                live::run_live_exchange(
                                    &transport, api_key, &challenge, &body,
                                );
                            }
                        }
                    }
                }
                other => {
                    // ECHO_RESP/ERR/INFER_RESP/INFER_PENDING are host->guest
                    // kinds; receiving one here is a reflection fault.
                    eprintln!("xport-harness: unexpected inbound kind {other}");
                }
            }
        }
    }
    exit(if echoes >= 1 { 0 } else { 1 });
}

/// Answer ONE completed inference-request body (M31 proposal §3d/§4):
/// the NOKEY probe -> a MAC'd closed-enum `ERR code=NO-KEY` (this stage-B
/// harness holds no API key -- the honest fail-closed answer); anything else
/// -> EXACTLY ONE MAC'd `INFER_PENDING` heartbeat + the MOCK-DETERMINISTIC
/// response as MAC'd chunks under the fixed discipline (full
/// [`INFER_CHUNK_CAP`] chunks, then the remainder).
fn serve_infer(
    stream: &mut UnixStream,
    key: &[u8; INFER_KEY_LEN],
    nonce: &[u8; INFER_NONCE_LEN],
    challenge: &[u8; 16],
    req_id: u64,
    body: &[u8],
) {
    if body == INFER_NOKEY_PROBE {
        // The keyless answer, MAC'd + closed-enum (never raw provider text).
        let mut ep = vec![0u8; INFER_ERR_PAYLOAD_LEN];
        assert_eq!(err_canon(errcode::NO_KEY, &mut ep), INFER_ERR_PAYLOAD_LEN);
        let wire = m31_frame(
            key,
            nonce,
            challenge,
            req_id,
            kind::ERR,
            &SubHdr::empty(),
            &ep.clone(),
            ep,
        );
        if let Err(e) = stream.write_all(&wire).and_then(|()| stream.flush()) {
            eprintln!("xport-harness: ERR write error: {e}");
            exit(1);
        }
        println!(
            "xport-harness-infer: backend=MOCK-DETERMINISTIC req-id=0x{req_id:016x} answer=ERR-NO-KEY"
        );
        std::io::stdout().flush().ok();
        return;
    }

    // M32 (stage B) LOCAL-ORGAN leg: a body opening with the reserved sentinel
    // is answered on the LOCAL peer identity (peer_id=0x03), as a DETERMINISTIC
    // STAND-IN (no vendored C engine runs here -- that is the real-engine
    // follow-up), so the kernel's M32 receive path exercises a REAL cross-
    // process receive under the distinct MAC-bound peer id. The transform is the
    // SAME shared mock_infer leaf, so the guest can still cross-check bit-exact.
    let is_local = body.len() >= INFER_LOCAL_PROBE.len()
        && &body[..INFER_LOCAL_PROBE.len()] == INFER_LOCAL_PROBE;
    let resp_peer = if is_local {
        peer::INFER_DAEMON
    } else {
        peer::QEMU_CHARDEV_HARNESS
    };

    // The deterministic mock transform -- the SAME shared tb-encode leaf the
    // in-kernel backend runs, so the guest can cross-check bit-for-bit.
    let mut resp = vec![0u8; INFER_MOCK_RESP_LEN];
    let rlen = mock_infer(body, &mut resp);
    if rlen == 0 {
        eprintln!("xport-harness: mock_infer rejected the body (len {})", body.len());
        return; // the guest's bounded poll turns this loud red
    }
    resp.truncate(rlen);
    let dig = body_digest(&resp);

    // ONE PENDING heartbeat (liveness plumbing -- never a completion).
    let mut out = tagged_frame(
        resp_peer,
        key,
        nonce,
        challenge,
        req_id,
        kind::INFER_PENDING,
        &SubHdr::empty(),
        &[],
        Vec::new(),
    );

    // The chunk sequence under the FIXED discipline (full chunks + remainder),
    // every chunk MAC'd with seq/sflags/total/digest INSIDE the MAC.
    let mut off = 0usize;
    let mut seq: u16 = 0;
    while off < resp.len() {
        let end = usize::min(off + INFER_CHUNK_CAP, resp.len());
        let sub = SubHdr {
            seq,
            more: end < resp.len(),
            total_len: resp.len() as u32,
            body_digest: dig,
        };
        let mut payload = vec![0u8; INFER_SUBHDR_LEN];
        assert_eq!(
            tb_encode::inferwire::subhdr_canon(&sub, &mut payload),
            INFER_SUBHDR_LEN
        );
        payload.extend_from_slice(&resp[off..end]);
        out.extend_from_slice(&tagged_frame(
            resp_peer,
            key,
            nonce,
            challenge,
            req_id,
            kind::INFER_RESP,
            &sub,
            &resp[off..end],
            payload,
        ));
        off = end;
        seq += 1;
    }
    if let Err(e) = stream.write_all(&out).and_then(|()| stream.flush()) {
        eprintln!("xport-harness: INFER_RESP write error: {e}");
        exit(1);
    }
    if is_local {
        // The M32 local-organ witness -- a SEPARATE capture stream from the M31
        // mock line, stamped peer_id=0x03 + the honest stand-in token. The run
        // script cross-pins this resp-digest against the guest `infer-local:`
        // line (the §8.6 cross-process leg).
        println!(
            "xport-local: peer=0x03 local-organ=DETERMINISTIC-STANDIN req-id=0x{req_id:016x} resp-len={} resp-digest=0x{} chunks={} pending=1",
            resp.len(),
            hex(&dig),
            seq
        );
    } else {
        println!(
            "xport-harness-infer: backend=MOCK-DETERMINISTIC req-id=0x{req_id:016x} resp-len={} resp-digest=0x{} chunks={} pending=1",
            resp.len(),
            hex(&dig),
            seq
        );
    }
    std::io::stdout().flush().ok();
}
