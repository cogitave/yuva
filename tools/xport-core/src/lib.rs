//! xport-core — the dep-clean shared plumbing for the M30/M31/M32 host peers.
//!
//! This crate carries `tb-encode` ALONE (zero network deps). It provides:
//!
//!  * [`hex`] — the §6 lowercase-hex, wire-byte-order encoder (the SAME
//!    rendering the kernel and every witness path use).
//!  * [`os_random`] — host-OS-RNG byte sampling (`/dev/urandom`, zero-dep).
//!  * [`ChardevPeer`] — the FrameAccum serve loop that answers the M30
//!    `ECHO_REQ` (host-keyed echo) and the M31 mock `INFER_REQ` exchange
//!    BYTE-IDENTICALLY to the landed xport-harness, stamping
//!    `peer_id = QEMU_CHARDEV_HARNESS (0x02)` and emitting the legacy
//!    `xport-harness:` / `xport-harness-infer:` witness lines verbatim so the
//!    prefix-load-bearing chain guards stay satisfied (M32 proposal §2,
//!    peer-identity discipline §17.15).
//!
//! The M32 LOCAL-ENGINE backend lives in the daemon crate, NOT here — this
//! crate never touches llama.cpp, never opens a socket to the network, and is
//! grep-asserted dep-clean.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::exit;
use std::time::Instant;

use tb_encode::inferwire::{
    body_digest, canon, decode, echo_tag, errcode, err_canon, infer_tag, kind, mock_infer, peer,
    verify_infer_req, wire_len, AsmPush, FrameAccum, InferAssembler, InferFrame, SubHdr,
    INFER_ACCUM_CAP, INFER_BODY_CAP, INFER_CHUNK_CAP, INFER_ERR_PAYLOAD_LEN, INFER_KEY_LEN,
    INFER_MOCK_RESP_LEN, INFER_NOKEY_PROBE, INFER_NONCE_LEN, INFER_SUBHDR_LEN,
};

/// Render a byte slice as lowercase hex in WIRE BYTE ORDER (byte 0 first) —
/// the exact format the kernel's `write_hex_bytes16` uses, so cross-process
/// equality is a plain string compare (the §6 inert-alphabet encoder).
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Sample `n` bytes from the host OS RNG (`/dev/urandom` — no external crate,
/// the zero-dep discipline).
pub fn os_random(n: usize) -> Vec<u8> {
    let mut f = std::fs::File::open("/dev/urandom").expect("xport-core: /dev/urandom unavailable");
    let mut buf = vec![0u8; n];
    f.read_exact(&mut buf)
        .expect("xport-core: short read from /dev/urandom");
    buf
}

/// Canon a frame into a fresh wire buffer (panics on an unencodable frame — a
/// construction bug, never an input condition).
fn wire_of(frame: &InferFrame) -> Vec<u8> {
    let mut wire = vec![0u8; wire_len(frame)];
    let n = canon(frame, &mut wire);
    assert!(n == wire.len(), "xport-core: frame canon failed");
    wire
}

/// Build one MAC'd M31 host->guest frame stamped with `peer_id=0x02` (the tag
/// binds every field via the verified leaf's [`infer_tag`]).
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
    let tag = infer_tag(
        key,
        peer::QEMU_CHARDEV_HARNESS,
        nonce,
        challenge,
        req_id,
        k,
        sub,
        chunk,
    );
    let frame = InferFrame {
        kind: k,
        req_id,
        challenge: *challenge,
        nonce: *nonce,
        peer_id: peer::QEMU_CHARDEV_HARNESS,
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

/// The M30/M31 chardev peer: re-frames the QEMU chardev byte stream through the
/// SAME Kani-proven `FrameAccum` the kernel uses and answers the legacy legs
/// BYTE-IDENTICALLY to the landed xport-harness. The daemon embeds one of these
/// for its `peer_id=0x02` identity; the M32 LOCAL-ENGINE leg is layered by the
/// daemon AFTER each completed mock exchange (answer-first, the M31-stage-C
/// sequencing), via the [`on_infer_complete`] hook.
pub struct ChardevPeer {
    key: [u8; INFER_KEY_LEN],
    nonce: [u8; INFER_NONCE_LEN],
    echoes: u32,
}

impl ChardevPeer {
    /// Born with a fresh host-custodied per-run key + nonce (OS RNG).
    pub fn new() -> Self {
        let kvec = os_random(INFER_KEY_LEN);
        let nvec = os_random(INFER_NONCE_LEN);
        let mut key = [0u8; INFER_KEY_LEN];
        key.copy_from_slice(&kvec);
        let mut nonce = [0u8; INFER_NONCE_LEN];
        nonce.copy_from_slice(&nvec);
        Self {
            key,
            nonce,
            echoes: 0,
        }
    }

    /// Construct from a caller-provided key/nonce (used by unit tests for a
    /// deterministic seam; production always uses [`new`]).
    pub fn with_key(key: [u8; INFER_KEY_LEN], nonce: [u8; INFER_NONCE_LEN]) -> Self {
        Self {
            key,
            nonce,
            echoes: 0,
        }
    }

    /// The host-custodied per-run key (for the `--key-out` leak-check input).
    pub fn key(&self) -> &[u8; INFER_KEY_LEN] {
        &self.key
    }

    /// Serve the chardev byte stream to EOF, calling `on_infer_complete(body,
    /// challenge, req_id)` AFTER each completed mock exchange is answered (the
    /// answer-first hook the daemon hangs the LOCAL-ENGINE leg on). Returns the
    /// echo count; the caller exits 0 iff >= 1 echo was served.
    pub fn serve<F: FnMut(&[u8], &[u8; 16], u64)>(
        &mut self,
        stream: &mut UnixStream,
        deadline: Instant,
        mut on_infer_complete: F,
    ) -> u32 {
        let mut acc: FrameAccum<INFER_ACCUM_CAP> = FrameAccum::new();
        let mut chunkbuf = [0u8; 4096];
        let mut inflight: Option<Inflight> = None;
        'serve: loop {
            if Instant::now() >= deadline {
                eprintln!("xport-core: serve-loop timeout");
                break 'serve;
            }
            let n = match stream.read(&mut chunkbuf) {
                Ok(0) => break 'serve,
                Ok(n) => n,
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    continue;
                }
                Err(e) => {
                    eprintln!("xport-core: read error: {e}");
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
                        eprintln!("xport-core: emitted window failed decode (desync)");
                        continue;
                    }
                };
                match frame.kind {
                    kind::ECHO_REQ => self.serve_echo(stream, &frame),
                    kind::INFER_REQ => {
                        if let Some((body, challenge, req_id)) =
                            self.serve_infer_req(stream, &frame, &mut inflight)
                        {
                            on_infer_complete(&body, &challenge, req_id);
                        }
                    }
                    other => {
                        eprintln!("xport-core: unexpected inbound kind {other}");
                    }
                }
            }
        }
        self.echoes
    }

    /// M30: the host-keyed echo (verbatim semantics, `peer_id=0x02`).
    fn serve_echo(&mut self, stream: &mut UnixStream, frame: &InferFrame) {
        let tag = echo_tag(
            &self.key,
            peer::QEMU_CHARDEV_HARNESS,
            &self.nonce,
            &frame.challenge,
            frame.payload,
        );
        let resp = InferFrame {
            kind: kind::ECHO_RESP,
            req_id: frame.req_id,
            challenge: frame.challenge,
            nonce: self.nonce,
            peer_id: peer::QEMU_CHARDEV_HARNESS,
            tag,
            payload: frame.payload,
        };
        let mut wire = wire_of(&resp);
        wire.extend_from_slice(&self.key);
        if let Err(e) = stream.write_all(&wire).and_then(|()| stream.flush()) {
            eprintln!("xport-core: echo write error: {e}");
            exit(1);
        }
        // The legacy M30 witness line, byte-identical to xport-harness (the
        // prefix-load-bearing chain guard depends on it — §2/§17.15).
        println!(
            "xport-harness: peer=QEMU-CHARDEV-HARNESS challenge=0x{} tag=0x{} key-custody=HOST",
            hex(&frame.challenge),
            hex(&tag)
        );
        std::io::stdout().flush().ok();
        self.echoes += 1;
    }

    /// M31: accumulate a MAC'd INFER_REQ; on a completed body, answer the mock
    /// exchange (byte-identical to xport-harness) and return the body so the
    /// caller's LOCAL-ENGINE hook can run AFTER (answer-first).
    fn serve_infer_req(
        &mut self,
        stream: &mut UnixStream,
        frame: &InferFrame,
        inflight: &mut Option<Inflight>,
    ) -> Option<(Vec<u8>, [u8; 16], u64)> {
        let (sub, chunk) = match verify_infer_req(&self.key, frame) {
            Some(x) => x,
            None => {
                eprintln!("xport-core: INFER_REQ failed verify_infer_req");
                return None;
            }
        };
        let restart = match &inflight {
            Some(f) => f.req_id != frame.req_id,
            None => true,
        };
        if restart {
            *inflight = Some(Inflight {
                req_id: frame.req_id,
                challenge: frame.challenge,
                asm: Box::new(InferAssembler::new()),
            });
        }
        let fl_state = inflight.as_mut().expect("inflight just set");
        match fl_state.asm.push_chunk(&sub, chunk) {
            AsmPush::Accepted => None,
            AsmPush::Rejected => {
                eprintln!("xport-core: INFER_REQ chunk rejected by assembler");
                *inflight = None;
                None
            }
            AsmPush::Complete(blen) => {
                let req_id = fl_state.req_id;
                let challenge = fl_state.challenge;
                let body = fl_state.asm.body()[..blen].to_vec();
                *inflight = None;
                self.serve_mock(stream, &challenge, req_id, &body);
                Some((body, challenge, req_id))
            }
        }
    }

    /// Answer ONE completed inference body the mock way (byte-identical to the
    /// landed xport-harness `serve_infer`): the NOKEY probe -> a MAC'd
    /// `ERR code=NO-KEY`; anything else -> ONE PENDING heartbeat + the
    /// MOCK-DETERMINISTIC `mock_infer` response as MAC'd chunks.
    fn serve_mock(&self, stream: &mut UnixStream, challenge: &[u8; 16], req_id: u64, body: &[u8]) {
        if body == INFER_NOKEY_PROBE {
            let mut ep = vec![0u8; INFER_ERR_PAYLOAD_LEN];
            assert_eq!(err_canon(errcode::NO_KEY, &mut ep), INFER_ERR_PAYLOAD_LEN);
            let wire = m31_frame(
                &self.key,
                &self.nonce,
                challenge,
                req_id,
                kind::ERR,
                &SubHdr::empty(),
                &ep.clone(),
                ep,
            );
            if let Err(e) = stream.write_all(&wire).and_then(|()| stream.flush()) {
                eprintln!("xport-core: ERR write error: {e}");
                exit(1);
            }
            println!(
                "xport-harness-infer: backend=MOCK-DETERMINISTIC req-id=0x{req_id:016x} answer=ERR-NO-KEY"
            );
            std::io::stdout().flush().ok();
            return;
        }

        let mut resp = vec![0u8; INFER_MOCK_RESP_LEN];
        let rlen = mock_infer(body, &mut resp);
        if rlen == 0 {
            eprintln!("xport-core: mock_infer rejected the body (len {})", body.len());
            return;
        }
        resp.truncate(rlen);
        let dig = body_digest(&resp);

        let mut out = m31_frame(
            &self.key,
            &self.nonce,
            challenge,
            req_id,
            kind::INFER_PENDING,
            &SubHdr::empty(),
            &[],
            Vec::new(),
        );

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
            out.extend_from_slice(&m31_frame(
                &self.key,
                &self.nonce,
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
            eprintln!("xport-core: INFER_RESP write error: {e}");
            exit(1);
        }
        println!(
            "xport-harness-infer: backend=MOCK-DETERMINISTIC req-id=0x{req_id:016x} resp-len={} resp-digest=0x{} chunks={} pending=1",
            resp.len(),
            hex(&dig),
            seq
        );
        std::io::stdout().flush().ok();
    }
}

impl Default for ChardevPeer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_lowercase_wire_order() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn body_digest_is_16_bytes_32_hex() {
        let d = tb_encode::inferwire::body_digest(b"hello");
        assert_eq!(d.len(), 16);
        assert_eq!(hex(&d).len(), 32);
    }
}
