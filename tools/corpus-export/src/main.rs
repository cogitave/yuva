//! `corpus-export` -- the M39 (increment-3) HOST corpus exporter (proposal §7.3).
//!
//! Reads the DURABLE experience-corpus region out of a Yuva disk IMAGE FILE, fail-
//! closed-decodes the persisted [`tb_encode::corpus::CorpusRecord`]s (REUSING the SAME
//! Kani-proven `tb_encode::{provhead,corpus}` leaves the kernel persists with), verifies
//! the M22 fold head over the read rows, and emits the PROVENANCE SKELETON as JSONL.
//!
//! HONEST (machine-tokened so the header mechanically cannot overclaim): a corpus record
//! is a PROVENANCE SKELETON, not text -- the emitted rows carry u64 INTERNED TOKEN IDS +
//! metadata; the text JOIN is the agent-side dictionary's job, NOT this tool's
//! (`corpus=PROVENANCE-SKELETON`, `export=SKELETON-NOT-TRAINING-TEXT`). It reads no
//! secret, opens no socket, and trains nothing (`training=NONE-PHASE2-GATED`).
//!
//! Usage: `corpus-export <disk-image> [--base-sector N]`. It writes the JSONL export (a
//! `_meta` header object, then one object per record) to stdout, and the one-line
//! `corpus-export:` witness to stderr. Exit non-zero (fail-closed) on a missing/short
//! image, an undecodable/torn region, a domain mismatch, or a fold head that does NOT
//! verify.

use std::process::ExitCode;

use tb_encode::corpus::{
    self, corpus_hash, corpus_recompute, CorpusRecord, OutcomeLabel, CORPUS_CANON_LEN,
    CORPUS_PERSIST_DOMAIN, CORPUS_PERSIST_MAX_RECORDS, PROV_HASH_LEN,
};
use tb_encode::provhead::{self, OFF_SIG, SECTOR, SLAB_BYTES};

/// The default first corpus slot sector -- must match the kernel's
/// `CORPUS_PERSIST_BASE` (tb-hal `mem::selftests`). Overridable via `--base-sector`.
const DEFAULT_BASE_SECTOR: u64 = 12288;

/// One decoded, fold-verified corpus record + its 32-byte fold id.
struct ExportRecord {
    rec: CorpusRecord,
    id: [u8; PROV_HASH_LEN],
}

/// The decoded + verified durable-corpus region.
struct Region {
    gen: u64,
    head: [u8; PROV_HASH_LEN],
    /// The re-folded head over the read records string-equalled the stored head.
    head_verified: bool,
    records: Vec<ExportRecord>,
}

/// Read the corpus region (both ping-pong slots) out of `image` at `base_sector`,
/// REUSING `provhead::decode` (torn-write-safe multi-sector) + `corpus::decode` (fixed-
/// width fail-closed), and re-fold the read rows to check the stored `corpus_head`.
/// TOTAL + FAIL-CLOSED: a short image / no-consistent-slab / domain-mismatch / bad
/// framing / undecodable record is an `Err` (never a partial export).
fn extract(image: &[u8], base_sector: u64) -> Result<Region, String> {
    let base = (base_sector as usize)
        .checked_mul(SECTOR)
        .ok_or_else(|| "base sector overflows".to_string())?;
    let need = base
        .checked_add(2 * SLAB_BYTES)
        .ok_or_else(|| "region end overflows".to_string())?;
    if image.len() < need {
        return Err(format!(
            "image too small: {} bytes, need >= {} for the corpus region (2 ping-pong slots at sector {})",
            image.len(),
            need,
            base_sector
        ));
    }
    let slab_a = &image[base..base + SLAB_BYTES];
    let slab_b = &image[base + SLAB_BYTES..base + 2 * SLAB_BYTES];
    let mut blob_a = vec![0u8; provhead::BLOB_CAP];
    let mut blob_b = vec![0u8; provhead::BLOB_CAP];
    let da = provhead::decode(slab_a, &mut blob_a);
    let db = provhead::decode(slab_b, &mut blob_b);

    // Pick the newer CONSISTENT ping-pong slot (a torn newer slot never wins).
    let (rec, blob) = match provhead::pick_newer(da.map(|x| x.gen), db.map(|x| x.gen)) {
        Some(false) => (da.unwrap(), &blob_a),
        Some(true) => (db.unwrap(), &blob_b),
        None => {
            return Err(
                "no consistent corpus slab in the region (fresh / torn / undecodable)".into(),
            )
        }
    };

    // Domain gate: a slab whose i_id is not the corpus tag is NOT a corpus region
    // (defense-in-depth on top of the disk-region split -- e.g. an M33 signed head).
    if rec.i_id != CORPUS_PERSIST_DOMAIN {
        return Err("decoded slab is not a corpus region (i_id domain-tag mismatch)".into());
    }
    let count = rec.q as usize;
    let siglen = rec.siglen as usize;
    if count == 0 || count > CORPUS_PERSIST_MAX_RECORDS || count * CORPUS_CANON_LEN != siglen {
        return Err(format!(
            "corpus slab framing invalid: count={count} siglen={siglen} (expected count*{CORPUS_CANON_LEN})"
        ));
    }

    // Unpack + fail-closed-decode each fixed-width record from the reused signature slot.
    let mut records: Vec<ExportRecord> = Vec::with_capacity(count);
    let mut ids: Vec<[u8; PROV_HASH_LEN]> = Vec::with_capacity(count);
    for i in 0..count {
        let off = OFF_SIG + i * CORPUS_CANON_LEN;
        let rb = &blob[off..off + CORPUS_CANON_LEN];
        let rec = corpus::decode(rb)
            .ok_or_else(|| format!("record {i} failed fail-closed decode (torn/forged skeleton)"))?;
        let id = corpus_hash(rb);
        ids.push(id);
        records.push(ExportRecord { rec, id });
    }

    // Verify the M22 fold head over the read rows (integrity -- the same fold the kernel
    // committed; a single-byte tamper of any row would fail this).
    let head_verified = corpus_recompute(ids[0], &ids[1..]) == rec.head;

    Ok(Region {
        gen: rec.gen,
        head: rec.head,
        head_verified,
        records,
    })
}

fn example_kind_name(v: u8) -> &'static str {
    match v {
        corpus::example_kind::EPISODIC_CONSOLIDATION => "EPISODIC_CONSOLIDATION",
        corpus::example_kind::OPERATOR_TURN => "OPERATOR_TURN",
        corpus::example_kind::LABELED_OUTCOME => "LABELED_OUTCOME",
        _ => "UNKNOWN",
    }
}

fn source_stream_name(v: u8) -> &'static str {
    match v {
        corpus::source_stream::M13_MEM => "M13_MEM",
        corpus::source_stream::M17_REFLECT => "M17_REFLECT",
        corpus::source_stream::M25_OPERATOR => "M25_OPERATOR",
        corpus::source_stream::M31_INFER => "M31_INFER",
        _ => "UNKNOWN",
    }
}

fn curation_verdict_name(v: u8) -> &'static str {
    match v {
        corpus::curation_verdict::REJECTED => "REJECTED",
        corpus::curation_verdict::ACCEPTED => "ACCEPTED",
        _ => "UNKNOWN",
    }
}

fn outcome_name(o: OutcomeLabel) -> &'static str {
    match o {
        OutcomeLabel::Unset => "Unset",
        OutcomeLabel::Positive(_) => "Positive",
        OutcomeLabel::Negative(_) => "Negative",
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The JSONL header object -- carries the HONEST tokens so a downstream consumer can
/// never mistake this for training TEXT (it is a provenance skeleton of token ids).
fn meta_line(region: &Region, base_sector: u64) -> String {
    format!(
        "{{\"_meta\":\"corpus-export-v1\",\"gen\":{},\"records\":{},\"base_sector\":{},\"corpus_head\":\"{}\",\"head_verified\":{},\"corpus\":\"PROVENANCE-SKELETON\",\"export\":\"SKELETON-NOT-TRAINING-TEXT\",\"text_join\":\"AGENT-SIDE-DICTIONARY\",\"training\":\"NONE-PHASE2-GATED\"}}",
        region.gen,
        region.records.len(),
        base_sector,
        hex(&region.head),
        region.head_verified,
    )
}

/// One record's JSONL object -- the PROVENANCE SKELETON (token ids + metadata), never
/// text. Token ids are emitted as JSON numbers (u64 interned dictionary handles).
fn record_line(er: &ExportRecord) -> String {
    let r = &er.rec;
    format!(
        "{{\"record_id\":\"{}\",\"schema_version\":{},\"example_kind\":{},\"example_kind_name\":\"{}\",\"source_stream\":{},\"source_stream_name\":\"{}\",\"curation_verdict\":{},\"curation_verdict_name\":\"{}\",\"content_tok\":{},\"aux_tok\":{},\"t_created\":{},\"source_head\":\"{}\",\"outcome_tag\":{},\"outcome_name\":\"{}\",\"outcome_payload\":{},\"curation_score_q\":{}}}",
        hex(&er.id),
        r.schema_version,
        r.example_kind,
        example_kind_name(r.example_kind),
        r.source_stream,
        source_stream_name(r.source_stream),
        r.curation_verdict,
        curation_verdict_name(r.curation_verdict),
        r.content_tok,
        r.aux_tok,
        r.t_created,
        hex(&r.source_head),
        r.outcome.tag(),
        outcome_name(r.outcome),
        r.outcome.payload(),
        r.curation_score_q,
    )
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut image_path: Option<String> = None;
    let mut base_sector = DEFAULT_BASE_SECTOR;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--base-sector" => {
                let v = args
                    .next()
                    .ok_or_else(|| "--base-sector requires a value".to_string())?;
                base_sector = v
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --base-sector value: {v}"))?;
            }
            "-h" | "--help" => {
                println!("usage: corpus-export <disk-image> [--base-sector N]");
                return Ok(());
            }
            other => {
                if image_path.is_some() {
                    return Err(format!("unexpected extra argument: {other}"));
                }
                image_path = Some(other.to_string());
            }
        }
    }
    let path = image_path.ok_or_else(|| {
        "usage: corpus-export <disk-image> [--base-sector N]".to_string()
    })?;
    let image = std::fs::read(&path).map_err(|e| format!("cannot read image {path}: {e}"))?;

    let region = extract(&image, base_sector)?;

    // FAIL-CLOSED: never export rows whose fold head does not verify.
    if !region.head_verified {
        return Err(format!(
            "corpus fold head did NOT verify over the {} read rows (torn/forged region) -- refusing to export",
            region.records.len()
        ));
    }

    // stdout: the JSONL export.
    println!("{}", meta_line(&region, base_sector));
    for er in &region.records {
        println!("{}", record_line(er));
    }

    // stderr: the one-line witness (honest tokens; never claims training/text).
    eprintln!(
        "corpus-export: base-sector={base_sector} gen={} records={} head={} head-verified=0x1 corpus=PROVENANCE-SKELETON export=SKELETON-NOT-TRAINING-TEXT training=NONE-PHASE2-GATED",
        region.gen,
        region.records.len(),
        hex(&region.head),
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("corpus-export: FAIL: {e}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------
// Host tests -- synthesize a disk image EXACTLY as the kernel persist seam does
// (the SAME `provhead::encode` call with the corpus domain tag + the packed
// fixed-width records), then assert extract/verify/emit round-trips + fail-closes.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(content_tok: u64, verdict: u8) -> CorpusRecord {
        CorpusRecord {
            schema_version: corpus::CORPUS_SCHEMA_V1,
            example_kind: corpus::example_kind::EPISODIC_CONSOLIDATION,
            source_stream: corpus::source_stream::M13_MEM,
            curation_verdict: verdict,
            content_tok,
            aux_tok: 0,
            t_created: 7,
            source_head: [0u8; PROV_HASH_LEN],
            outcome: OutcomeLabel::Unset,
            curation_score_q: 0,
        }
    }

    /// Build a disk image with a corpus region at `base_sector`, packing `recs` EXACTLY
    /// as the kernel does: canon each record, fold the ids into the corpus_head, pack the
    /// canonical bytes into the reused provhead `sig` slot with the corpus domain tag.
    fn synth_image(recs: &[CorpusRecord], base_sector: u64, gen: u64, image_len: usize) -> Vec<u8> {
        let mut sig = Vec::new();
        let mut ids = Vec::new();
        for r in recs {
            let mut b = [0u8; CORPUS_CANON_LEN];
            assert_eq!(corpus::canon(r, &mut b), CORPUS_CANON_LEN);
            ids.push(corpus_hash(&b));
            sig.extend_from_slice(&b);
        }
        let head = corpus_recompute(ids[0], &ids[1..]);
        let zero_root = [0u8; provhead::ROOT_LEN];
        let mut blob = vec![0u8; provhead::BLOB_CAP];
        let mut slab = vec![0u8; SLAB_BYTES];
        let n = provhead::encode(
            gen,
            recs.len() as u32,
            &head,
            &CORPUS_PERSIST_DOMAIN,
            &zero_root,
            &sig,
            &mut blob,
            &mut slab,
        );
        assert!(n > 0);
        let mut image = vec![0u8; image_len];
        let base = (base_sector as usize) * SECTOR;
        image[base..base + n].copy_from_slice(&slab[..n]);
        image
    }

    #[test]
    fn roundtrip_extract_and_verify() {
        let recs = [
            sample_record(0x00C0_0001, corpus::curation_verdict::ACCEPTED),
            sample_record(0x00C0_0002, corpus::curation_verdict::REJECTED),
            sample_record(0x00C0_0003, corpus::curation_verdict::ACCEPTED),
        ];
        let img = synth_image(&recs, DEFAULT_BASE_SECTOR, 1, 8 * 1024 * 1024);
        let region = extract(&img, DEFAULT_BASE_SECTOR).expect("extract");
        assert!(region.head_verified);
        assert_eq!(region.gen, 1);
        assert_eq!(region.records.len(), 3);
        assert_eq!(region.records[0].rec.content_tok, 0x00C0_0001);
        assert_eq!(region.records[1].rec.curation_verdict, corpus::curation_verdict::REJECTED);
        // The emitted JSONL is well-formed (meta first, then one line per record).
        let meta = meta_line(&region, DEFAULT_BASE_SECTOR);
        assert!(meta.contains("\"corpus\":\"PROVENANCE-SKELETON\""));
        assert!(meta.contains("\"export\":\"SKELETON-NOT-TRAINING-TEXT\""));
        let line0 = record_line(&region.records[0]);
        assert!(line0.contains("\"example_kind_name\":\"EPISODIC_CONSOLIDATION\""));
        assert!(line0.contains("\"content_tok\":12582913")); // 0x00C0_0001
    }

    #[test]
    fn fold_head_matches_recompute() {
        let recs = [sample_record(0xABCD, corpus::curation_verdict::ACCEPTED)];
        let img = synth_image(&recs, DEFAULT_BASE_SECTOR, 5, 8 * 1024 * 1024);
        let region = extract(&img, DEFAULT_BASE_SECTOR).expect("extract");
        // The exported head equals an independent recompute over the exported rows.
        let ids: Vec<_> = region.records.iter().map(|e| e.id).collect();
        assert_eq!(corpus_recompute(ids[0], &ids[1..]), region.head);
        assert!(region.head_verified);
    }

    #[test]
    fn fresh_region_fails_closed() {
        let img = vec![0u8; 8 * 1024 * 1024]; // all-zero disk, no corpus slab
        assert!(extract(&img, DEFAULT_BASE_SECTOR).is_err());
    }

    #[test]
    fn short_image_fails_closed() {
        let img = vec![0u8; 1024]; // far too small for the region
        assert!(extract(&img, DEFAULT_BASE_SECTOR).is_err());
    }

    #[test]
    fn torn_record_byte_fails_closed() {
        // Flip a byte inside a packed record's payload (in-sector) AND refresh that
        // sector's per-sector CRC so ONLY the record-spanning gate (or the corpus decode
        // / fold-head check) can catch it -- the export must still fail-close.
        let recs = [
            sample_record(0x00C0_0001, corpus::curation_verdict::ACCEPTED),
            sample_record(0x00C0_0002, corpus::curation_verdict::ACCEPTED),
        ];
        let mut img = synth_image(&recs, DEFAULT_BASE_SECTOR, 1, 8 * 1024 * 1024);
        let base = (DEFAULT_BASE_SECTOR as usize) * SECTOR;
        // A payload byte of the first sector (past the 8-byte sector meta + into OFF_SIG
        // packed record region). Flipping it breaks the record-spanning FNV-64.
        img[base + provhead::SEC_META + OFF_SIG + 4] ^= 0xFF;
        assert!(extract(&img, DEFAULT_BASE_SECTOR).is_err());
    }

    #[test]
    fn domain_mismatch_fails_closed() {
        // Encode a well-formed provhead slab but with a NON-corpus i_id (e.g. an M33-like
        // identifier) -> the domain gate rejects it.
        let recs = [sample_record(0x00C0_0001, corpus::curation_verdict::ACCEPTED)];
        let mut sig = Vec::new();
        let mut ids = Vec::new();
        for r in &recs {
            let mut b = [0u8; CORPUS_CANON_LEN];
            assert_eq!(corpus::canon(r, &mut b), CORPUS_CANON_LEN);
            ids.push(corpus_hash(&b));
            sig.extend_from_slice(&b);
        }
        let head = corpus_recompute(ids[0], &ids[1..]);
        let not_corpus = *b"NOT-A-CORPUS-TAG"; // 16 bytes, != CORPUS_PERSIST_DOMAIN
        let zero_root = [0u8; provhead::ROOT_LEN];
        let mut blob = vec![0u8; provhead::BLOB_CAP];
        let mut slab = vec![0u8; SLAB_BYTES];
        let n = provhead::encode(
            1, recs.len() as u32, &head, &not_corpus, &zero_root, &sig, &mut blob, &mut slab,
        );
        assert!(n > 0);
        let mut img = vec![0u8; 8 * 1024 * 1024];
        let base = (DEFAULT_BASE_SECTOR as usize) * SECTOR;
        img[base..base + n].copy_from_slice(&slab[..n]);
        assert!(extract(&img, DEFAULT_BASE_SECTOR).is_err());
    }

    #[test]
    fn ping_pong_picks_newer_gen() {
        // Slot A gen=1 (1 record), slot B gen=2 (2 records) -> extract picks B.
        let recs_a = [sample_record(0x0A, corpus::curation_verdict::ACCEPTED)];
        let recs_b = [
            sample_record(0x0B, corpus::curation_verdict::ACCEPTED),
            sample_record(0x0C, corpus::curation_verdict::ACCEPTED),
        ];
        let img_a = synth_image(&recs_a, DEFAULT_BASE_SECTOR, 1, 8 * 1024 * 1024);
        // Build B's slab and drop it into slot B (base + SLAB_BYTES).
        let img_b = synth_image(&recs_b, DEFAULT_BASE_SECTOR, 2, 8 * 1024 * 1024);
        let base = (DEFAULT_BASE_SECTOR as usize) * SECTOR;
        let mut img = img_a;
        let b_slab = &img_b[base..base + SLAB_BYTES];
        img[base + SLAB_BYTES..base + 2 * SLAB_BYTES].copy_from_slice(b_slab);
        let region = extract(&img, DEFAULT_BASE_SECTOR).expect("extract");
        assert_eq!(region.gen, 2);
        assert_eq!(region.records.len(), 2);
    }

    // Document the slab geometry the region relies on.
    #[test]
    fn region_geometry_const() {
        assert_eq!(SLAB_BYTES, provhead::MAX_SECTORS * SECTOR);
    }
}
