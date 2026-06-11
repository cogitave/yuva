//! The M30 HOST echo peer (stage B -- the QEMU chardev-harness lanes).
//!
//! LEG 2 of the proposal-§4 anti-hollow composition lives in the run script;
//! this binary is the HOST half it adjudicates against:
//!
//! 1. At startup it samples `K:[u8;32]` (the per-run echo key) and `N:[u8;16]`
//!    (the per-run nonce) from the host OS RNG (`/dev/urandom`). K is BORN
//!    here and lives ONLY in this process until it is revealed on the channel
//!    -- it is never in the guest image, on the guest command line, or in
//!    guest-visible config space (`key=HOST-CUSTODIED-PER-RUN`).
//! 2. It connects to the QEMU `virtconsole` chardev unix socket (the
//!    `server=on,wait=off` listener the run script passes to QEMU) and waits
//!    for the kernel's `ECHO_REQ`, re-framing the byte stream through the SAME
//!    Kani-proven [`tb_encode::inferwire::FrameAccum`] the kernel uses (one
//!    codec, never a shell/python re-implementation -- research §8).
//! 3. It answers with `ECHO_RESP || K`: the response echoes the request body
//!    verbatim, carries N + `peer_id=QEMU-CHARDEV-HARNESS`, and its tag is the
//!    verified leaf's [`tb_encode::inferwire::echo_tag`] -- ONE domain-
//!    separated khash call binding `peer_id || N || challenge || body` INSIDE
//!    the MAC. The trailing cleartext K is the channel-layer reveal the kernel
//!    recomputes with (leg 1).
//! 4. It prints its OWN witness line to stdout --
//!    `xport-harness: peer=QEMU-CHARDEV-HARNESS challenge=0x.. tag=0x..
//!    key-custody=HOST` -- from ITS copy of the values. The run script
//!    string-compares challenge/tag against the kernel's `xport:` line:
//!    cross-process equality with a host-custodied key is the loopback
//!    killer (a loopback can mint a self-consistent tag, but cannot equal
//!    khash(K, ..) without guessing the 32 OS-RNG bytes held here).
//!
//! It also writes K's hex to `--key-out` so the run script can NEGATIVELY
//! assert the key never leaked into the guest serial output (§5.7) -- that
//! file is the script's ephemeral check input, never part of any witness.
//!
//! Exit codes: 0 = answered one echo (then lingered to EOF); 1 = timeout or
//! I/O fault (a dead lane is LOUD -- the run script fails on a missing
//! `xport-harness:` line either way).

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::exit;
use std::time::{Duration, Instant};

use tb_encode::inferwire::{
    canon, decode, echo_tag, kind, peer, FrameAccum, InferFrame, INFER_ACCUM_CAP,
    INFER_KEY_LEN, INFER_NONCE_LEN,
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

fn main() {
    // --- args: --socket <path> [--key-out <path>] [--timeout-secs <n>] -----
    let mut socket_path: Option<String> = None;
    let mut key_out: Option<String> = None;
    let mut timeout_secs: u64 = 300;
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
            other => {
                eprintln!("xport-harness: unknown arg '{other}'");
                exit(2);
            }
        }
    }
    let socket_path = match socket_path {
        Some(p) => p,
        None => {
            eprintln!("usage: xport-harness --socket <unix-socket> [--key-out <file>] [--timeout-secs <n>]");
            exit(2);
        }
    };

    // --- the per-run HOST-custodied key + nonce (OS RNG; proposal §4) ------
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

    // --- wait for the kernel's ECHO_REQ (the SAME stream re-framer) --------
    let mut acc: FrameAccum<INFER_ACCUM_CAP> = FrameAccum::new();
    let mut chunk = [0u8; 4096];
    let frame_len = 'outer: loop {
        if Instant::now() >= deadline {
            eprintln!("xport-harness: timed out waiting for ECHO_REQ");
            exit(1);
        }
        let n = match stream.read(&mut chunk) {
            Ok(0) => {
                eprintln!("xport-harness: socket EOF before any request");
                exit(1);
            }
            Ok(n) => n,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => {
                eprintln!("xport-harness: read error: {e}");
                exit(1);
            }
        };
        for &b in &chunk[..n] {
            if let Some(fl) = acc.push_byte(b) {
                break 'outer fl;
            }
        }
    };
    let req_bytes: Vec<u8> = acc.bytes()[..frame_len].to_vec();
    let req = match decode(&req_bytes) {
        Some(f) if f.kind == kind::ECHO_REQ => f,
        _ => {
            eprintln!("xport-harness: first frame is not a well-formed ECHO_REQ");
            exit(1);
        }
    };

    // --- the host-keyed echo (the verified leaf's ONE khash call) ----------
    let tag = echo_tag(
        &key,
        peer::QEMU_CHARDEV_HARNESS,
        &nonce,
        &req.challenge,
        req.payload,
    );
    let resp = InferFrame {
        kind: kind::ECHO_RESP,
        req_id: req.req_id,
        challenge: req.challenge, // echoed verbatim + MAC-bound
        nonce,
        peer_id: peer::QEMU_CHARDEV_HARNESS, // MAC-covered lane label
        tag,
        payload: req.payload, // body echoed verbatim (body-bitexact)
    };
    let mut wire = vec![0u8; tb_encode::inferwire::wire_len(&resp)];
    let n = canon(&resp, &mut wire);
    if n == 0 {
        eprintln!("xport-harness: response canon failed (oversize body?)");
        exit(1);
    }
    wire.truncate(n);
    // The channel-layer key reveal trails the frame (cleartext -- custody,
    // not confidentiality; the kernel recomputes the tag with it).
    wire.extend_from_slice(&key);
    if let Err(e) = stream.write_all(&wire).and_then(|()| stream.flush()) {
        eprintln!("xport-harness: write error: {e}");
        exit(1);
    }

    // --- LEG 2: the host's OWN witness line (a different process's stdout
    // than the guest serial -- the run script string-compares challenge/tag).
    println!(
        "xport-harness: peer=QEMU-CHARDEV-HARNESS challenge=0x{} tag=0x{} key-custody=HOST",
        hex(&req.challenge),
        hex(&tag)
    );
    std::io::stdout().flush().ok();

    // --- linger to EOF so the socket stays open while the guest reads ------
    let linger_deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while Instant::now() < linger_deadline {
        match stream.read(&mut chunk) {
            Ok(0) => break, // QEMU closed (guest done) -- clean exit
            Ok(_) => {}     // late bytes: ignored (one echo per run in M30)
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
    }
    exit(0);
}
