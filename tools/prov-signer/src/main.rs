//! The M33 host/operator LMS signer (stage A) -- the VERIFY/SIGN split's SIGN
//! side (proposal §2). Holds a SIMULATED enrolled key (a compiled-in seed +
//! identifier `I`), signs a 32-byte prov head at the operational `W4`/`H10`
//! parameter set, self-verifies the signature with the SAME `lms_verify` the
//! kernel runs (proving sign/verify interop), builds a DSSE-PAE attestation over
//! the head, and prints the `prov-signer:` witness line.
//!
//! HONEST TOKENS (verbatim, load-bearing -- never buried): a signature proves
//! `exclusivity=OFF-PLATFORM-ONLY` and NOTHING against the host holding the key;
//! `key-custody=CI-RUNNER-SIMULATED-ENROLLED`; `reuse=SIMULATED-OK-NO-SECURITY`
//! (stage A reuses leaf index 0 every run -- acceptable ONLY because the key has
//! no security value; a real never-decrement durable counter is the M35
//! obligation). The private key NEVER enters the kernel.

use std::process::exit;

use tb_encode::attest::{
    build_type, canon, decode, ledger_status, pae, AttestStatement, LedgerEntry, ATTEST_PAYLOAD_TYPE,
    BUILDER_ID_LEN,
};
use tb_encode::lmsig::{lms_verify, signer, LMS_I_LEN};
use tb_encode::sha256::sha256;

// The SIMULATED enrolled key (CI-custodied). A fixed seed + identifier -- NOT a
// real enrolment ceremony (that is #85 / rung 2), and NOT in the kernel image
// (the kernel holds only the derived 32-byte PUBLIC root).
const SIM_SEED: [u8; 32] = [0x5A; 32];
const SIM_I: [u8; LMS_I_LEN] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
];

/// Fold the first 8 bytes of a 32-byte value into a u64 witness (LE) -- the same
/// shape the kernel renders `head=<hex16>` / `root=<hex16>` with.
fn fold8(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

fn hex16(x: u64) -> String {
    format!("0x{x:016x}")
}

fn main() {
    // The (w, p, ls, h, otstype, lmstype) operational set -- `W4`/`H10`.
    let (w, p, ls, h, ots, lms) = signer::W4_H10;

    // The 32-byte prov head to sign: argv[1] as 64 hex chars, else a fixed
    // stage-A demo head (the M22 fold head shape is a 32-byte digest).
    let head: [u8; 32] = match std::env::args().nth(1) {
        Some(h) if h.len() == 64 => {
            let mut out = [0u8; 32];
            for i in 0..32 {
                out[i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap_or_else(|_| {
                    eprintln!("prov-signer: FAIL -- argv[1] is not 64 hex chars");
                    exit(2);
                });
            }
            out
        }
        _ => sha256(b"YUVA-M33-stageA-demo-prov-head"),
    };

    // The public root (baked in the image as a 32-byte constant, in the real
    // pipeline). Stage A reuses leaf index 0 (state=SIMULATED-REUSE-OK).
    let leaf_idx: u32 = 0;
    let root = signer::public_root(&SIM_I, &SIM_SEED, w, p, h);

    // Sign the head.
    let mut sig = [0u8; 4096];
    let n = signer::sign(&SIM_I, &SIM_SEED, leaf_idx, w, p, ls, h, ots, lms, &head, &mut sig);
    if n == 0 {
        eprintln!("prov-signer: FAIL -- signing failed (bounds)");
        exit(1);
    }

    // Self-verify with the EXACT kernel verify path (sign/verify interop proof).
    if !lms_verify(&root, &SIM_I, &head, &sig[..n]) {
        eprintln!("prov-signer: FAIL -- self-verify rejected the freshly-signed head");
        exit(1);
    }

    // Build the DSSE-PAE attestation over the head (the sovereignty-ledger
    // carrier; subject digest SELF-REPORTED -- selfmeasure=UNATTESTED-LOADER).
    let subject_digest = head;
    let toolchain_hash = sha256(b"YUVA-M33-toolchain-nightly-2026-07-06");
    let materials = [sha256(b"YUVA-M33-material-kernel-image")];
    let ledger = [
        LedgerEntry { dep_tok: 0x594D_3333, status: ledger_status::ACCEPTED_PERMANENT },
        LedgerEntry { dep_tok: 0x5349_4D4B, status: ledger_status::TEMPORARY },
    ];
    let st = AttestStatement {
        subject_digest,
        builder_id: [0x59u8; BUILDER_ID_LEN],
        build_type: build_type::KERNEL_IMAGE,
        toolchain_hash,
        materials: &materials,
        ledger: &ledger,
    };
    let mut cbuf = [0u8; 512];
    let cn = canon(&st, &mut cbuf);
    if cn == 0 || decode(&cbuf[..cn]).is_none() {
        eprintln!("prov-signer: FAIL -- attestation canon/decode roundtrip failed");
        exit(1);
    }
    let mut pbuf = [0u8; 640];
    let pn = pae(ATTEST_PAYLOAD_TYPE, &cbuf[..cn], &mut pbuf);
    if pn == 0 {
        eprintln!("prov-signer: FAIL -- DSSE-PAE encoding failed");
        exit(1);
    }
    let attest_pae_digest = sha256(&pbuf[..pn]);

    // The witness line (proposal §8, host stdout -- NOT guest serial). Every
    // honesty token is machine-emitted so the line mechanically cannot overclaim.
    println!(
        "prov-signer: sig=LMS-SHA256-W4-H10 conformance=RFC8554 leaf-idx={} head={} root={} attest-pae-digest={} sig-verified=0x1 key-custody=CI-RUNNER-SIMULATED-ENROLLED exclusivity=OFF-PLATFORM-ONLY reuse=SIMULATED-OK-NO-SECURITY measure=SELF-NO-HW-ROOT selfmeasure=UNATTESTED-LOADER sec=ASSUMED-FROM-LITERATURE",
        hex16(leaf_idx as u64),
        hex16(fold8(&head)),
        hex16(fold8(&root)),
        hex16(fold8(&attest_pae_digest)),
    );
}
