//! The M30/M31 HOST peer, in-process (stage C — `transport=TB-VMM-HOST`).
//!
//! This is the tb-vmm twin of `tools/xport-harness/src/main.rs` (the REFERENCE
//! host-peer the QEMU chardev lanes run): the SAME Kani-proven
//! `tb_encode::inferwire` codec, the SAME serve semantics, the SAME witness
//! shapes — wire-equivalent by construction, never a second protocol
//! implementation (the M30 research §8 rule). The only deltas are the lane
//! identity ([`peer::TB_VMM_HOST`], `key-custody=VMM`) and the byte source: the
//! harness reads a chardev unix socket; this peer is fed the transmitq bytes by
//! [`crate::virtio_mmio::VirtioMmio`] and queues its response bytes for the
//! receiveq (the "socket buffer" is [`InferHost::outbuf`], which persists
//! across guest-driven device resets exactly as a unix socket's buffered bytes
//! survive a virtio status reset).
//!
//! Anti-hollow custody (M30 proposal §4): the per-run key `K:[u8;32]` and nonce
//! `N:[u8;16]` are sampled from the host OS RNG (`/dev/urandom`) at
//! construction. K is BORN here and lives ONLY in this process until it is
//! revealed on the channel (the cleartext `INFER_KEY_REVEAL_LEN` trailer after
//! an `ECHO_RESP`) — it is never in the guest image, on either command line, or
//! in guest-visible config space (`key=HOST-CUSTODIED-PER-RUN`). The peer
//! prints its OWN `xport-harness:` witness line (proposal §5 host-peer shape,
//! `peer=TB-VMM-HOST .. key-custody=VMM`) to a stream the GUEST cannot write
//! (the `--xport-out` file; guest serial rides tb-vmm's stdout) so the run
//! script can string-compare challenge/tag CROSS-PROCESS (leg 2, the loopback
//! killer). K's hex goes to `--xport-key-out` for the run script's §5.7
//! key-leak NEGATIVE (an ephemeral check input, never a witness).
//!
//! M31 serve loop (stage B semantics, verbatim): a MAC-verified `INFER_REQ`
//! chunk sequence reassembles through the SAME proven [`InferAssembler`]; a
//! completed body is dispatched — the designated [`INFER_NOKEY_PROBE`] body
//! gets a MAC'd closed-enum `ERR code=NO-KEY` (this in-process peer holds NO
//! API key, and says so fail-closed); any other body gets EXACTLY ONE MAC'd
//! `INFER_PENDING` heartbeat + the SHARED deterministic [`mock_infer`]
//! response as MAC'd `INFER_RESP` chunks. HONEST: `backend=MOCK-DETERMINISTIC`
//! — a transform, not a model; zero network, zero TLS, zero secrets. The
//! ANTHROPIC-LIVE bridge is deliberately ABSENT here (it is the operator-gated
//! xport-harness stage C, never the unattended vmm lane).

use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use tb_encode::inferwire::{
    body_digest, canon, decode, echo_tag, err_canon, errcode, infer_tag, kind, mock_infer, peer,
    verify_infer_req, wire_len, AsmPush, FrameAccum, InferAssembler, InferFrame, SubHdr,
    INFER_ACCUM_CAP, INFER_BODY_CAP, INFER_CHUNK_CAP, INFER_ERR_PAYLOAD_LEN, INFER_KEY_LEN,
    INFER_LOCAL_PROBE, INFER_MOCK_RESP_LEN, INFER_NOKEY_PROBE, INFER_NONCE_LEN, INFER_SUBHDR_LEN,
};

use crate::error::VmmError;

/// Render bytes as lowercase hex in WIRE BYTE ORDER (byte 0 first) — the exact
/// format the kernel's `write_hex_bytes16` and the xport-harness's `hex` use,
/// so the run script's leg-2 equality stays a plain string compare.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Sample `N` bytes from the host OS RNG (`/dev/urandom` — no external crate,
/// the xport-harness discipline). Fails closed: a missing/short RNG is a
/// construction error, never a weaker key.
fn os_random<const N: usize>() -> Result<[u8; N], VmmError> {
    let mut f = File::open("/dev/urandom")
        .map_err(|e| VmmError::Config(format!("M30 host peer: /dev/urandom unavailable: {e}")))?;
    let mut buf = [0u8; N];
    f.read_exact(&mut buf)
        .map_err(|e| VmmError::Config(format!("M30 host peer: short /dev/urandom read: {e}")))?;
    Ok(buf)
}

/// The in-flight (stop-and-wait, single outstanding req_id) M31 request state —
/// the xport-harness `Inflight` verbatim.
struct Inflight {
    req_id: u64,
    challenge: [u8; 16],
    asm: Box<InferAssembler<INFER_BODY_CAP>>,
}

/// The in-process M30/M31 host peer behind tb-vmm's virtio-console backend.
pub struct InferHost {
    /// The per-run HOST-custodied echo key (born from OS RNG; revealed only on
    /// the channel as the `ECHO_RESP` cleartext trailer).
    key: [u8; INFER_KEY_LEN],
    /// The per-run host nonce (MAC-bound into every response).
    nonce: [u8; INFER_NONCE_LEN],
    /// The guest->host byte-stream re-framer (the SAME proven accumulator the
    /// harness and the kernel use). Peer state: it persists across guest-driven
    /// virtio resets, exactly as the chardev socket's stream does.
    accum: Box<FrameAccum<INFER_ACCUM_CAP>>,
    /// The host->guest "socket buffer": response bytes the transport drains
    /// into posted receiveq buffers. Persists across device resets.
    outbuf: VecDeque<u8>,
    /// The single-outstanding M31 reassembly state (stop-and-wait).
    inflight: Option<Inflight>,
    /// The leg-2 witness stream (the `--xport-out` file, or stderr). The guest
    /// can never write this stream — guest serial rides tb-vmm's stdout.
    witness: Box<dyn Write + Send>,
    /// Echoes served (diagnostic only — the run script's verdict is the
    /// witness line + the cross-process equality, never this counter).
    echoes: u64,
}

impl InferHost {
    /// Build the peer from the CLI config: sample K+N from the host OS RNG,
    /// open the witness sink, and write K's hex to the key-out file (the run
    /// script's key-leak-negative input).
    pub fn from_config(
        xport_out: Option<&Path>,
        xport_key_out: Option<&Path>,
    ) -> Result<Self, VmmError> {
        let key: [u8; INFER_KEY_LEN] = os_random()?;
        let nonce: [u8; INFER_NONCE_LEN] = os_random()?;
        let witness: Box<dyn Write + Send> = match xport_out {
            Some(p) => Box::new(File::create(p).map_err(|e| {
                VmmError::Config(format!(
                    "M30 host peer: cannot create --xport-out `{}`: {e}",
                    p.display()
                ))
            })?),
            None => Box::new(std::io::stderr()),
        };
        if let Some(p) = xport_key_out {
            std::fs::write(p, hex(&key)).map_err(|e| {
                VmmError::Config(format!(
                    "M30 host peer: cannot write --xport-key-out `{}`: {e}",
                    p.display()
                ))
            })?;
        }
        Ok(Self::with_key_nonce(key, nonce, witness))
    }

    /// Build the peer with explicit key/nonce/witness (the unit-test seam; the
    /// boot path always goes through [`InferHost::from_config`]).
    pub fn with_key_nonce(
        key: [u8; INFER_KEY_LEN],
        nonce: [u8; INFER_NONCE_LEN],
        witness: Box<dyn Write + Send>,
    ) -> Self {
        InferHost {
            key,
            nonce,
            accum: Box::new(FrameAccum::new()),
            outbuf: VecDeque::new(),
            inflight: None,
            witness,
            echoes: 0,
        }
    }

    /// Bytes currently queued toward the guest (the receiveq drain source).
    pub fn out_len(&self) -> usize {
        self.outbuf.len()
    }

    /// Pop up to `max` queued host->guest bytes (the transport writes them
    /// into a posted device-WRITE descriptor).
    pub fn take_output(&mut self, max: usize) -> Vec<u8> {
        let n = usize::min(max, self.outbuf.len());
        self.outbuf.drain(..n).collect()
    }

    /// Feed guest transmitq bytes into the peer (the harness read-loop body):
    /// re-frame through the proven accumulator, decode each emitted window
    /// with the proven fail-closed `decode` (the codec stays the arbiter at
    /// the consumption point), and dispatch on kind. Responses are queued on
    /// [`Self::outbuf`]; malformed/unverified input gets NO reply — the
    /// guest's bounded poll turns that LOUD red (never a silent skip).
    pub fn push_guest_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            let fl = match self.accum.push_byte(b) {
                Some(fl) => fl,
                None => continue,
            };
            let frame_bytes = self.accum.bytes()[..fl].to_vec();
            self.accum.consume(fl);
            let frame = match decode(&frame_bytes) {
                Some(f) => f,
                None => {
                    eprintln!("tb-vmm xport: emitted window failed decode (desync)");
                    continue;
                }
            };
            match frame.kind {
                kind::ECHO_REQ => self.serve_echo(&frame),
                kind::INFER_REQ => self.serve_infer_req(&frame),
                other => {
                    // ECHO_RESP/ERR/INFER_RESP/INFER_PENDING are host->guest
                    // kinds; receiving one here is a reflection fault.
                    eprintln!("tb-vmm xport: unexpected inbound kind {other}");
                }
            }
        }
    }

    /// M30: answer one `ECHO_REQ` with the host-keyed echo (the xport-harness
    /// semantics verbatim, lane identity aside): body echoed bit-exactly,
    /// challenge echoed + MAC-bound, host nonce + `peer_id=TB-VMM-HOST` set,
    /// tag = the verified leaf's [`echo_tag`], then the cleartext channel-layer
    /// K reveal trailing the frame. Prints the leg-2 witness line.
    fn serve_echo(&mut self, req: &InferFrame) {
        let tag = echo_tag(
            &self.key,
            peer::TB_VMM_HOST,
            &self.nonce,
            &req.challenge,
            req.payload,
        );
        let resp = InferFrame {
            kind: kind::ECHO_RESP,
            req_id: req.req_id,
            challenge: req.challenge, // echoed verbatim + MAC-bound
            nonce: self.nonce,
            peer_id: peer::TB_VMM_HOST,
            tag,
            payload: req.payload, // body echoed verbatim
        };
        let mut wire = wire_of(&resp);
        // The channel-layer key reveal trails the frame (cleartext — custody,
        // not confidentiality; M30 proposal §4/§12).
        wire.extend_from_slice(&self.key);
        self.outbuf.extend(wire);
        // LEG 2: the host peer's OWN witness line (the proposal-§5 host shape;
        // the run script cross-process-compares challenge/tag against the
        // guest's `xport:` line). key-custody=VMM names THIS custody domain.
        let line = format!(
            "xport-harness: peer=TB-VMM-HOST challenge=0x{} tag=0x{} key-custody=VMM\n",
            hex(&req.challenge),
            hex(&tag)
        );
        self.witness_write(&line);
        self.echoes += 1;
    }

    /// M31: feed one MAC-verified `INFER_REQ` chunk into the stop-and-wait
    /// assembler; serve a completed body (the xport-harness dispatch verbatim).
    fn serve_infer_req(&mut self, frame: &InferFrame) {
        let (sub, chunk) = match verify_infer_req(&self.key, frame) {
            Some(x) => x,
            None => {
                // An unMAC'd/malformed REQ never gets a reply; the guest's
                // bounded poll turns this LOUD red.
                eprintln!("tb-vmm xport: INFER_REQ failed verify_infer_req");
                return;
            }
        };
        // Single in-flight stop-and-wait: a NEW req_id restarts.
        let restart = match &self.inflight {
            Some(f) => f.req_id != frame.req_id,
            None => true,
        };
        if restart {
            self.inflight = Some(Inflight {
                req_id: frame.req_id,
                challenge: frame.challenge,
                asm: Box::new(InferAssembler::new()),
            });
        }
        let fl_state = self.inflight.as_mut().expect("inflight just set");
        match fl_state.asm.push_chunk(&sub, chunk) {
            AsmPush::Accepted => {} // more chunks coming (lockstep)
            AsmPush::Rejected => {
                eprintln!("tb-vmm xport: INFER_REQ chunk rejected by assembler");
                self.inflight = None;
            }
            AsmPush::Complete(blen) => {
                let req_id = fl_state.req_id;
                let challenge = fl_state.challenge;
                let body = fl_state.asm.body()[..blen].to_vec();
                self.inflight = None;
                self.serve_infer_body(&challenge, req_id, &body);
            }
        }
    }

    /// Answer ONE completed inference-request body (the xport-harness
    /// `serve_infer` verbatim, lane identity aside): the NOKEY probe -> a
    /// MAC'd closed-enum `ERR code=NO-KEY`; anything else -> EXACTLY ONE MAC'd
    /// `INFER_PENDING` heartbeat + the MOCK-DETERMINISTIC response as MAC'd
    /// chunks under the fixed discipline (full [`INFER_CHUNK_CAP`] chunks,
    /// then the remainder).
    fn serve_infer_body(&mut self, challenge: &[u8; 16], req_id: u64, body: &[u8]) {
        if body == INFER_NOKEY_PROBE {
            // The keyless answer, MAC'd + closed-enum (never raw provider
            // text). This in-process peer holds NO API key BY CONSTRUCTION —
            // the live bridge is the operator-gated harness, never this lane.
            let mut ep = vec![0u8; INFER_ERR_PAYLOAD_LEN];
            assert_eq!(err_canon(errcode::NO_KEY, &mut ep), INFER_ERR_PAYLOAD_LEN);
            let wire = self.m31_frame(challenge, req_id, kind::ERR, &SubHdr::empty(), &ep.clone(), ep);
            self.outbuf.extend(wire);
            let line = format!(
                "xport-harness-infer: backend=MOCK-DETERMINISTIC req-id=0x{req_id:016x} answer=ERR-NO-KEY\n"
            );
            self.witness_write(&line);
            return;
        }

        // M32 (stage B) LOCAL-ORGAN leg: a body opening with the reserved
        // sentinel is answered on the LOCAL peer identity (peer_id=0x03) as a
        // DETERMINISTIC STAND-IN (no vendored C engine on this lane either), so
        // the kernel's M32 receive path exercises a REAL cross-process receive
        // under the distinct MAC-bound peer id. The transform is the SAME shared
        // mock_infer leaf, so the guest still cross-checks bit-exact.
        let is_local = body.len() >= INFER_LOCAL_PROBE.len()
            && &body[..INFER_LOCAL_PROBE.len()] == INFER_LOCAL_PROBE;
        let resp_peer = if is_local {
            peer::INFER_DAEMON
        } else {
            peer::TB_VMM_HOST
        };

        // The deterministic mock transform — the SAME shared tb-encode leaf
        // the in-kernel backend runs, so the guest cross-checks bit-for-bit.
        let mut resp = vec![0u8; INFER_MOCK_RESP_LEN];
        let rlen = mock_infer(body, &mut resp);
        if rlen == 0 {
            eprintln!("tb-vmm xport: mock_infer rejected the body (len {})", body.len());
            return; // the guest's bounded poll turns this loud red
        }
        resp.truncate(rlen);
        let dig = body_digest(&resp);

        // ONE PENDING heartbeat (liveness plumbing — never a completion).
        let mut out = self.tagged_frame(
            resp_peer,
            challenge,
            req_id,
            kind::INFER_PENDING,
            &SubHdr::empty(),
            &[],
            Vec::new(),
        );

        // The chunk sequence under the FIXED discipline (full chunks +
        // remainder), every chunk MAC'd with seq/sflags/total/digest INSIDE
        // the MAC (the M28/Terrapin bind-inside-the-MAC rule).
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
            out.extend_from_slice(&self.tagged_frame(
                resp_peer,
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
        self.outbuf.extend(out);
        let line = if is_local {
            format!(
                "xport-local: peer=0x03 local-organ=DETERMINISTIC-STANDIN req-id=0x{req_id:016x} resp-len={} resp-digest=0x{} chunks={} pending=1\n",
                resp.len(),
                hex(&dig),
                seq
            )
        } else {
            format!(
                "xport-harness-infer: backend=MOCK-DETERMINISTIC req-id=0x{req_id:016x} resp-len={} resp-digest=0x{} chunks={} pending=1\n",
                resp.len(),
                hex(&dig),
                seq
            )
        };
        self.witness_write(&line);
    }

    /// Build one MAC'd M31 host->guest frame (the tag binds every field via
    /// the verified leaf's [`infer_tag`] — ONE khash call under the M31
    /// domain; the xport-harness `m31_frame` with this lane's peer identity).
    fn m31_frame(
        &self,
        challenge: &[u8; 16],
        req_id: u64,
        k: u8,
        sub: &SubHdr,
        chunk: &[u8],
        payload: Vec<u8>,
    ) -> Vec<u8> {
        self.tagged_frame(peer::TB_VMM_HOST, challenge, req_id, k, sub, chunk, payload)
    }

    /// Build one MAC'd host->guest frame stamped with an EXPLICIT `peer_id` —
    /// the M31 mock leg uses this lane's `TB_VMM_HOST (0x01)`, the M32 local-
    /// organ leg uses `INFER_DAEMON (0x03)`. The `peer_id` is bound INSIDE
    /// [`infer_tag`], so a `0x01` mock frame can never masquerade as the `0x03`
    /// local organ (the kani_inferwire_infer_peer_bound proof).
    #[allow(clippy::too_many_arguments)]
    fn tagged_frame(
        &self,
        peer_id: u8,
        challenge: &[u8; 16],
        req_id: u64,
        k: u8,
        sub: &SubHdr,
        chunk: &[u8],
        payload: Vec<u8>,
    ) -> Vec<u8> {
        let tag = infer_tag(&self.key, peer_id, &self.nonce, challenge, req_id, k, sub, chunk);
        let frame = InferFrame {
            kind: k,
            req_id,
            challenge: *challenge,
            nonce: self.nonce,
            peer_id,
            tag,
            payload: &payload,
        };
        wire_of(&frame)
    }

    /// Write + flush one witness line (flushed per line so a wall-clock-guard
    /// kill — the normal vmm-boot end, since the in-kernel LAPIC parks the
    /// guest's terminal `hlt` — never loses the leg-2 evidence).
    fn witness_write(&mut self, line: &str) {
        if self.witness.write_all(line.as_bytes()).is_err() || self.witness.flush().is_err() {
            eprintln!("tb-vmm xport: witness write failed");
        }
    }
}

/// Canon a frame into a fresh wire buffer (panics on an unencodable frame — a
/// peer-side construction bug, never an input condition; the xport-harness
/// `wire_of` verbatim).
fn wire_of(frame: &InferFrame) -> Vec<u8> {
    let mut wire = vec![0u8; wire_len(frame)];
    let n = canon(frame, &mut wire);
    assert!(n == wire.len(), "tb-vmm xport: frame canon failed");
    wire
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tb_encode::inferwire::{
        infer_chunk_count, infer_chunks_wire_len, verify_echo, verify_infer_resp,
        INFER_HEADER_LEN, INFER_KEY_REVEAL_LEN, INFER_TAG_LEN,
    };

    /// A witness sink the test can read back.
    #[derive(Clone, Default)]
    struct SharedSink(Arc<Mutex<Vec<u8>>>);
    impl Write for SharedSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    const KEY: [u8; 32] = [0x42u8; 32];
    const NONCE: [u8; 16] = [0x24u8; 16];

    fn host_with_sink() -> (InferHost, SharedSink) {
        let sink = SharedSink::default();
        let host = InferHost::with_key_nonce(KEY, NONCE, Box::new(sink.clone()));
        (host, sink)
    }

    fn echo_req_wire(challenge: [u8; 16], req_id: u64, body: &[u8]) -> Vec<u8> {
        let req = InferFrame {
            kind: kind::ECHO_REQ,
            req_id,
            challenge,
            nonce: [0u8; 16],
            peer_id: 0,
            tag: [0u8; 16],
            payload: body,
        };
        wire_of(&req)
    }

    /// Build the kernel-side MAC'd single-chunk INFER_REQ (the selftest shape).
    fn infer_req_wire(key: &[u8; 32], challenge: [u8; 16], req_id: u64, body: &[u8]) -> Vec<u8> {
        let sub = SubHdr {
            seq: 0,
            more: false,
            total_len: body.len() as u32,
            body_digest: body_digest(body),
        };
        let mut payload = vec![0u8; INFER_SUBHDR_LEN];
        assert_eq!(
            tb_encode::inferwire::subhdr_canon(&sub, &mut payload),
            INFER_SUBHDR_LEN
        );
        payload.extend_from_slice(body);
        let tag = infer_tag(key, 0, &[0u8; 16], &challenge, req_id, kind::INFER_REQ, &sub, body);
        let frame = InferFrame {
            kind: kind::INFER_REQ,
            req_id,
            challenge,
            nonce: [0u8; 16],
            peer_id: 0,
            tag,
            payload: &payload,
        };
        wire_of(&frame)
    }

    // ---- M30: the host-keyed echo ------------------------------------------

    #[test]
    fn echo_req_gets_keyed_echo_plus_reveal_and_witness() {
        let (mut host, sink) = host_with_sink();
        let challenge = [7u8; 16];
        let body = [0xB0u8, 0xB1, 0xB2, 0xB3];
        host.push_guest_bytes(&echo_req_wire(challenge, 0x1122, &body));

        // The response: ECHO_RESP frame + the cleartext K reveal trailer.
        let expect = INFER_HEADER_LEN + body.len() + INFER_KEY_REVEAL_LEN;
        assert_eq!(host.out_len(), expect);
        let out = host.take_output(expect);
        let frame_len = INFER_HEADER_LEN + body.len();
        let resp = decode(&out[..frame_len]).expect("ECHO_RESP must decode");
        assert_eq!(resp.kind, kind::ECHO_RESP);
        assert_eq!(resp.peer_id, peer::TB_VMM_HOST);
        assert_eq!(resp.nonce, NONCE);
        // The revealed key trails the frame and verifies the echo (leg 1).
        let mut revealed = [0u8; 32];
        revealed.copy_from_slice(&out[frame_len..]);
        assert_eq!(revealed, KEY);
        let req = InferFrame {
            kind: kind::ECHO_REQ,
            req_id: 0x1122,
            challenge,
            nonce: [0u8; 16],
            peer_id: 0,
            tag: [0u8; INFER_TAG_LEN],
            payload: &body,
        };
        assert!(verify_echo(&revealed, &resp, &req));
        // The witness line carries the SAME challenge/tag (leg 2's shape).
        let w = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        assert!(w.contains("xport-harness: peer=TB-VMM-HOST challenge=0x"));
        assert!(w.contains(&format!("challenge=0x{}", hex(&challenge))));
        assert!(w.contains(&format!("tag=0x{}", hex(&resp.tag))));
        assert!(w.contains("key-custody=VMM"));
    }

    #[test]
    fn echo_tag_binds_the_challenge() {
        // The challenge-binding negative (the run-script equality leg's unit
        // mirror): two boots' different challenges MUST move the tag.
        let (mut host, _sink) = host_with_sink();
        let body = [1u8; 8];
        host.push_guest_bytes(&echo_req_wire([1u8; 16], 1, &body));
        let out_a = host.take_output(usize::MAX);
        host.push_guest_bytes(&echo_req_wire([2u8; 16], 1, &body));
        let out_b = host.take_output(usize::MAX);
        let frame_len = INFER_HEADER_LEN + body.len();
        let tag_a = decode(&out_a[..frame_len]).unwrap().tag;
        let tag_b = decode(&out_b[..frame_len]).unwrap().tag;
        assert_ne!(tag_a, tag_b, "the echo tag must bind the challenge");
    }

    #[test]
    fn garbage_and_reflected_kinds_get_no_reply() {
        let (mut host, sink) = host_with_sink();
        // Pure garbage: no frame, no reply.
        host.push_guest_bytes(&[0u8; 256]);
        assert_eq!(host.out_len(), 0);
        // A reflected host->guest kind (ECHO_RESP) is a fault: no reply.
        let resp = InferFrame {
            kind: kind::ECHO_RESP,
            req_id: 9,
            challenge: [3u8; 16],
            nonce: NONCE,
            peer_id: peer::TB_VMM_HOST,
            tag: [0u8; 16],
            payload: &[],
        };
        host.push_guest_bytes(&wire_of(&resp));
        assert_eq!(host.out_len(), 0);
        assert!(sink.0.lock().unwrap().is_empty());
    }

    #[test]
    fn frame_split_across_pushes_still_serves() {
        // The transmitq may deliver a frame in several descriptor buffers; the
        // accumulator re-frames across push calls (the byte-stream discipline).
        let (mut host, _sink) = host_with_sink();
        let wire = echo_req_wire([5u8; 16], 77, &[0xAA; 16]);
        let (a, b) = wire.split_at(10);
        host.push_guest_bytes(a);
        assert_eq!(host.out_len(), 0); // incomplete: nothing served yet
        host.push_guest_bytes(b);
        assert_eq!(
            host.out_len(),
            INFER_HEADER_LEN + 16 + INFER_KEY_REVEAL_LEN
        );
    }

    // ---- M31: the inference serve loop --------------------------------------

    #[test]
    fn nokey_probe_gets_macd_err_no_key() {
        let (mut host, sink) = host_with_sink();
        let challenge = [9u8; 16];
        host.push_guest_bytes(&infer_req_wire(&KEY, challenge, 0xAB, INFER_NOKEY_PROBE));
        let expect = INFER_HEADER_LEN + INFER_ERR_PAYLOAD_LEN;
        assert_eq!(host.out_len(), expect);
        let out = host.take_output(expect);
        let frame = decode(&out).expect("ERR must decode");
        assert_eq!(frame.kind, kind::ERR);
        assert_eq!(frame.nonce, NONCE);
        let (_, chunk) =
            verify_infer_resp(&KEY, &frame, 0xAB, &challenge).expect("ERR must MAC-verify");
        assert_eq!(
            tb_encode::inferwire::err_decode(chunk),
            Some((errcode::NO_KEY, false))
        );
        let w = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        assert!(w.contains("answer=ERR-NO-KEY"));
    }

    #[test]
    fn prompt_gets_one_pending_plus_chunked_mock_resp() {
        let (mut host, _sink) = host_with_sink();
        let challenge = [0x11u8; 16];
        let req_id = 0xC0FFEE;
        let prompt = b"the stage-c vmm-lane prompt";
        host.push_guest_bytes(&infer_req_wire(&KEY, challenge, req_id, prompt));

        // The a-priori wire shape BOTH ends derive from the shared consts: one
        // empty PENDING frame + the fixed-discipline chunk sequence.
        let expect = INFER_HEADER_LEN + infer_chunks_wire_len(INFER_MOCK_RESP_LEN);
        assert_eq!(host.out_len(), expect);
        let out = host.take_output(expect);

        // Walk the frames: exactly ONE PENDING, then the MAC'd chunks, which
        // reassemble to the SAME shared mock_infer transform bit-for-bit.
        let mut expected = vec![0u8; INFER_MOCK_RESP_LEN];
        assert_eq!(mock_infer(prompt, &mut expected), INFER_MOCK_RESP_LEN);
        let mut asm: InferAssembler<INFER_BODY_CAP> = InferAssembler::new();
        let mut pending = 0u32;
        let mut chunks = 0u32;
        let mut off = 0usize;
        while off < out.len() {
            let frame = decode(&out[off..]).expect("each emitted frame decodes");
            let flen = INFER_HEADER_LEN + frame.payload.len();
            let (sub, chunk) = verify_infer_resp(&KEY, &frame, req_id, &challenge)
                .expect("every host frame MAC-verifies");
            match frame.kind {
                kind::INFER_PENDING => pending += 1,
                kind::INFER_RESP => {
                    chunks += 1;
                    match asm.push_chunk(&sub, chunk) {
                        AsmPush::Accepted | AsmPush::Complete(_) => {}
                        AsmPush::Rejected => panic!("assembler rejected a host chunk"),
                    }
                }
                k => panic!("unexpected kind {k}"),
            }
            off += flen;
        }
        assert_eq!(pending, 1, "EXACTLY one PENDING heartbeat");
        assert_eq!(chunks, infer_chunk_count(INFER_MOCK_RESP_LEN) as u32);
        assert!(asm.is_done());
        assert_eq!(asm.body(), &expected[..], "MOCK-DETERMINISTIC bit-exactness");
    }

    #[test]
    fn local_probe_gets_peer_0x03_standin() {
        // M32 (stage B): an INFER_REQ body opening with the reserved sentinel is
        // answered on the LOCAL peer identity (peer_id=0x03), distinct from the
        // 0x01 mock, and MAC-verifies under that peer id -- so the kernel's
        // `frame.peer_id == INFER_DAEMON` assertion holds ONLY for this leg.
        let (mut host, _sink) = host_with_sink();
        let challenge = [0x22u8; 16];
        let req_id = 0xD00D;
        let body = INFER_LOCAL_PROBE;
        host.push_guest_bytes(&infer_req_wire(&KEY, challenge, req_id, body));

        let expect = INFER_HEADER_LEN + infer_chunks_wire_len(INFER_MOCK_RESP_LEN);
        assert_eq!(host.out_len(), expect);
        let out = host.take_output(expect);

        let mut expected = vec![0u8; INFER_MOCK_RESP_LEN];
        assert_eq!(mock_infer(body, &mut expected), INFER_MOCK_RESP_LEN);
        let mut asm: InferAssembler<INFER_BODY_CAP> = InferAssembler::new();
        let mut pending = 0u32;
        let mut chunks = 0u32;
        let mut off = 0usize;
        while off < out.len() {
            let frame = decode(&out[off..]).expect("each emitted frame decodes");
            let flen = INFER_HEADER_LEN + frame.payload.len();
            // The LOCAL peer identity is stamped + MAC-bound on EVERY frame.
            assert_eq!(
                frame.peer_id,
                peer::INFER_DAEMON,
                "the M32 local leg must wear peer_id=0x03"
            );
            let (sub, chunk) = verify_infer_resp(&KEY, &frame, req_id, &challenge)
                .expect("every host frame MAC-verifies under its 0x03 peer id");
            match frame.kind {
                kind::INFER_PENDING => pending += 1,
                kind::INFER_RESP => {
                    chunks += 1;
                    match asm.push_chunk(&sub, chunk) {
                        AsmPush::Accepted | AsmPush::Complete(_) => {}
                        AsmPush::Rejected => panic!("assembler rejected a host chunk"),
                    }
                }
                k => panic!("unexpected kind {k}"),
            }
            off += flen;
        }
        assert_eq!(pending, 1, "EXACTLY one PENDING heartbeat");
        assert_eq!(chunks, infer_chunk_count(INFER_MOCK_RESP_LEN) as u32);
        assert!(asm.is_done());
        assert_eq!(asm.body(), &expected[..], "the stand-in is bit-exact");
    }

    #[test]
    fn unmacd_infer_req_gets_no_reply() {
        let (mut host, _sink) = host_with_sink();
        // A REQ MAC'd under the WRONG key must be ignored (fail-closed: the
        // guest's bounded poll turns the silence loud red).
        let wrong_key = [0x99u8; 32];
        host.push_guest_bytes(&infer_req_wire(&wrong_key, [4u8; 16], 5, b"prompt"));
        assert_eq!(host.out_len(), 0);
    }

    #[test]
    fn take_output_respects_max_and_order() {
        let (mut host, _sink) = host_with_sink();
        let body = [0xEEu8; 4];
        let wire = echo_req_wire([6u8; 16], 2, &body);
        host.push_guest_bytes(&wire);
        let total = host.out_len();
        let first = host.take_output(10);
        let rest = host.take_output(usize::MAX);
        assert_eq!(first.len(), 10);
        assert_eq!(rest.len(), total - 10);
        let mut whole = first;
        whole.extend_from_slice(&rest);
        assert!(decode(&whole[..INFER_HEADER_LEN + body.len()]).is_some());
    }
}
