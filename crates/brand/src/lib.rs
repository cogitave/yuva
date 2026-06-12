//! The project IDENTITY -- the SINGLE Rust source of truth for every
//! name-bearing byte the project emits on a wire, into an ELF, or onto a disk.
//!
//! Yuva was developed under the code name TABOS; this crate is where that
//! rename became one edit. **To rename the project again:** change
//! [`brand_upper!`]/[`brand_lower!`] below + `scripts/project.env` (+ the
//! mirrored workflow `env:` blocks and the package/target names) -- every
//! domain separator, ELF-note name/type, wire magic, and disk magic DERIVES
//! from here, so nothing else re-spells the bytes.
//!
//! ## Dependency policy (read before adding a dep anywhere near this)
//!
//! This crate is `#![no_std]`, `#![forbid(unsafe_code)]`, zero-dep, and
//! consts-only, so it is trivially host-buildable and transparent to Kani
//! (pure constant propagation). `tb-encode`'s "zero deps" rule means zero
//! EXTERNAL deps: this workspace-internal identity crate is the ONE allowed
//! workspace-internal dependency (the same note lives in tb-encode's header).
//!
//! ## Freeze / versioning policy
//!
//! Every constant here is a WIRE or WITNESS constant: changing one changes
//! observable bytes (MAC'd values, ELF notes, disk superblocks). They are
//! changeable TODAY only because nothing persists them across boots and every
//! producer/consumer is in-repo (the PR-C "now-or-never window"). Once any
//! out-of-repo consumer exists, a change is a `-V2`/ordinal bump, never an
//! in-place edit. The `-V1` suffixes on the domain separators are that
//! versioning seam; the note-type/magic ordinals (`..01`, `+1`, `+2`) are the
//! same seam for the binary constants.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// The brand, UPPERCASE, as a macro -- so `concat!` and `global_asm!` callers
/// can consume it as a string LITERAL (e.g. `.asciz` note names, domain-label
/// concatenations). THE single place the name is spelled.
#[macro_export]
macro_rules! brand_upper {
    () => {
        "YUVA"
    };
}

/// The brand, lowercase, as a macro (build-identifier shaped; the script-level
/// mirror is `PROJECT_NAME` in `scripts/project.env`).
#[macro_export]
macro_rules! brand_lower {
    () => {
        "yuva"
    };
}

/// The brand as a `&str` (== `brand_upper!()`).
pub const BRAND: &str = brand_upper!();

/// The lowercase brand as a `&str` (== `brand_lower!()`).
pub const BRAND_LOWER: &str = brand_lower!();

/// Copy a `&str`'s UTF-8 bytes into a fixed `[u8; N]` at compile time
/// (panics the const evaluation if the length differs -- a wrong-width brand
/// composition is a COMPILE error, never a truncation).
pub const fn to_bytes<const N: usize>(s: &str) -> [u8; N] {
    let b = s.as_bytes();
    assert!(b.len() == N, "brand: string length != N");
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = b[i];
        i += 1;
    }
    out
}

// ===========================================================================
// khash domain separators (the M28/M29/M30 keyed-use labels)
// ===========================================================================

/// The M28/M29 operator-command DERIVE-step domain separator. CONSUMER:
/// `tb-encode::opframe_rx::KDF_DOMAIN` (`K_s = khash(key_a, DOMSEP || key_b)`;
/// witness token `kdf=DERIVE-THEN-MAC-DOMSEP`). Changing it shifts every
/// opcmd challenge/tag (per-boot in-RAM values; the guards pin FORMAT, never
/// values).
pub const DOMSEP_OPCMD_KDF: &[u8] = concat!(brand_upper!(), "-OPCMD-KDF-V1").as_bytes();

/// The M28/M29 forward key-evolution domain separator. CONSUMER:
/// `tb-encode::opframe_rx::EVOLVE_DOMAIN` (`key_{i+1} = khash(key_i, DOMSEP)`;
/// witness token `keyevolve=PRF-DOMSEP`). Disjoint from every other label by
/// the distinct suffix.
pub const DOMSEP_KEY_EVOLVE: &[u8] = concat!(brand_upper!(), "-KEY-EVOLVE-V1").as_bytes();

/// The M30 inference-transport echo-MAC domain separator. CONSUMER:
/// `tb-encode::inferwire::ECHO_DOMAIN` (the MAC'd message is
/// `DOMSEP || peer_id || nonce || challenge || body`). Changing it shifts the
/// xport tag both the kernel AND `tools/xport-harness` compute (they share
/// this leaf, so the cross-process equality guard stays in lockstep).
///
/// NOTE: the M31 inference-ADAPTER separator (`-M31-INFER-V1`) deliberately
/// does NOT exist yet -- it lands here together with M31, never earlier.
pub const DOMSEP_M30_ECHO: &[u8] = concat!(brand_upper!(), "-M30-ECHO-V1").as_bytes();

// ===========================================================================
// The boot ELF note (tb-boot v0 entry discovery)
// ===========================================================================

/// The boot ELF note's `n_name` (sans NUL). CONSUMERS: the producers in
/// `tb-hal/src/arch/{x86_64,aarch64}/boot.rs` + `bench/nano-guest/nano-guest.S`
/// (which MIRRORS it -- it cannot import Rust), the parser
/// `tb-boot::parse_entry64_note`, the `tb-vmm` loader, and the bench.yml
/// note-grep guard (via the `BRAND` env mirror).
pub const NOTE_NAME: &str = brand_upper!();

/// The boot note's `n_namesz` (the trailing NUL is counted, ELF gABI):
/// `"YUVA\0"` = 5, which the note framing pads to 8 -- the SAME padded width
/// as the TABOS-era 6 -> 8, so the 28-byte note layout is unchanged.
pub const NOTE_NAMESZ: u32 = NOTE_NAME.len() as u32 + 1;

/// The boot note's `n_type`. DERIVATION: the brand's first two bytes occupy
/// the top half (`'Y''U'` = `0x5955`, the TABOS-era `'T''B'` shape) + the note
/// ordinal `0x0001` in the bottom half -- i.e. `0x5955_0001`. CONSUMERS:
/// `tb-boot::TB_NOTE_TYPE_ENTRY64` (parser + producers), the `tb-vmm` loader,
/// the bench.yml note-type grep (via the `NOTE_TYPE_HEX` env mirror).
pub const NOTE_TYPE_ENTRY64: u32 =
    ((BRAND.as_bytes()[0] as u32) << 24) | ((BRAND.as_bytes()[1] as u32) << 16) | 0x0001;

// ===========================================================================
// The tb-boot v0 boot-info magic
// ===========================================================================

/// The `TbBootInfo::magic` bytes, in memory order: a leading NUL + the brand
/// INITIAL + the fixed `BOOTV0` mnemonic -- `"\0YBOOTV0"` (the TABOS-era
/// `"\0TBOOTV0"` shape with the initial flipped). CONSUMER:
/// `tb-boot::TB_BOOT_MAGIC` (as the LE `u64` below), stamped by the `tb-vmm`
/// producer and checked by `tb_hal::read_boot_magic` + the kernel.
pub const BOOT_MAGIC_BYTES: [u8; 8] =
    [0, BRAND.as_bytes()[0], b'B', b'O', b'O', b'T', b'V', b'0'];

/// [`BOOT_MAGIC_BYTES`] as the little-endian `u64` the v0 ABI compares
/// (`0x3056_544F_4F42_5900`).
pub const BOOT_MAGIC: u64 = u64::from_le_bytes(BOOT_MAGIC_BYTES);

// ===========================================================================
// The u16 wire-magic family (the house frame codecs)
// ===========================================================================
//
// DERIVATION: high byte = the brand initial 'Y' (0x59); low byte counts up
// from the brand's SECOND letter + 1 ('U'+1 = 'V', 0x56) -- so the family is
// 'Y''V'/'Y''W'/'Y''X' = 0x5956/0x5957/0x5958, mirroring the TABOS-era
// 'T''B'/'T''C'/'T''D' (initial + ascending-from-second-letter) shape while
// staying DISJOINT from the note type's 'Y''U' (0x5955) top half: a u16 frame
// magic can never alias the note-type's brand half.

/// The M25 operator-TRANSCRIPT frame magic (`0x5956`). CONSUMER:
/// `tb-encode::opframe::OPFRAME_MAGIC`.
pub const MAGIC_OPFRAME: u16 =
    ((BRAND.as_bytes()[0] as u16) << 8) | (BRAND.as_bytes()[1] as u16 + 1);

/// The M28 operator-INBOUND command-frame magic (`0x5957` -- family +1).
/// CONSUMER: `tb-encode::opframe_rx::CMD_MAGIC`.
pub const MAGIC_OPFRAME_RX: u16 = MAGIC_OPFRAME + 1;

/// The M30 inference-transport frame magic (`0x5958` -- family +2). CONSUMER:
/// `tb-encode::inferwire::INFER_MAGIC` (also the `FrameAccum` resync scan).
pub const MAGIC_INFERWIRE: u16 = MAGIC_OPFRAME + 2;

// ===========================================================================
// The M20 disk superblock magic
// ===========================================================================

/// The LBA-0 superblock magic: the brand + the fixed `MEM0` mnemonic
/// (`b"YUVAMEM0"`, 8 bytes exactly -- the [`to_bytes`] const helper makes a
/// wrong-width composition a compile error). CONSUMER:
/// `tb-encode::blkfmt::SB_MAGIC`. Disks are mktemp-fresh per run; nothing
/// migrates (the PR-C window).
pub const SB_MAGIC: [u8; 8] = to_bytes(concat!(brand_upper!(), "MEM0"));

// ===========================================================================
// Compile-time pins (the derived values, spelled ONCE for the auditor)
// ===========================================================================

const _: () = assert!(NOTE_NAMESZ == 5);
const _: () = assert!(NOTE_TYPE_ENTRY64 == 0x5955_0001);
const _: () = assert!(BOOT_MAGIC == 0x3056_544F_4F42_5900);
const _: () = assert!(MAGIC_OPFRAME == 0x5956);
const _: () = assert!(MAGIC_OPFRAME_RX == 0x5957);
const _: () = assert!(MAGIC_INFERWIRE == 0x5958);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brand_is_nonempty_and_consistent() {
        assert!(!BRAND.is_empty());
        assert_eq!(BRAND, "YUVA");
        assert_eq!(BRAND_LOWER, BRAND.to_ascii_lowercase());
        assert!(BRAND.bytes().all(|b| b.is_ascii_uppercase()));
    }

    #[test]
    fn domain_separators_prefixed_by_brand_and_distinct() {
        for d in [DOMSEP_OPCMD_KDF, DOMSEP_KEY_EVOLVE, DOMSEP_M30_ECHO] {
            assert!(!d.is_empty());
            assert!(d.starts_with(BRAND.as_bytes()));
            assert_eq!(d[BRAND.len()], b'-'); // BRAND is a clean token prefix
        }
        assert_ne!(DOMSEP_OPCMD_KDF, DOMSEP_KEY_EVOLVE);
        assert_ne!(DOMSEP_OPCMD_KDF, DOMSEP_M30_ECHO);
        assert_ne!(DOMSEP_KEY_EVOLVE, DOMSEP_M30_ECHO);
        // The exact bytes (the before->after table's "after" column, pinned).
        assert_eq!(DOMSEP_OPCMD_KDF, b"YUVA-OPCMD-KDF-V1");
        assert_eq!(DOMSEP_KEY_EVOLVE, b"YUVA-KEY-EVOLVE-V1");
        assert_eq!(DOMSEP_M30_ECHO, b"YUVA-M30-ECHO-V1");
    }

    #[test]
    fn note_constants_derive_from_brand() {
        assert_eq!(NOTE_NAME, BRAND);
        assert_eq!(NOTE_NAMESZ as usize, NOTE_NAME.len() + 1); // 4 + NUL = 5
        assert_eq!(NOTE_NAMESZ, 5);
        // 'Y''U' occupy the top half of the type word; ordinal 1 below.
        assert_eq!(
            (NOTE_TYPE_ENTRY64 >> 16) as u16,
            u16::from_be_bytes([BRAND.as_bytes()[0], BRAND.as_bytes()[1]])
        );
        assert_eq!(NOTE_TYPE_ENTRY64 & 0xFFFF, 1);
    }

    #[test]
    fn boot_magic_spells_the_mnemonic() {
        assert_eq!(&BOOT_MAGIC_BYTES, b"\0YBOOTV0");
        assert_eq!(BOOT_MAGIC_BYTES[1], BRAND.as_bytes()[0]);
        assert_eq!(BOOT_MAGIC, u64::from_le_bytes(*b"\0YBOOTV0"));
    }

    #[test]
    fn wire_magic_family_distinct_and_disjoint_from_note_type() {
        assert_ne!(MAGIC_OPFRAME, MAGIC_OPFRAME_RX);
        assert_ne!(MAGIC_OPFRAME, MAGIC_INFERWIRE);
        assert_ne!(MAGIC_OPFRAME_RX, MAGIC_INFERWIRE);
        // High byte = brand initial; the family never aliases the note type's
        // brand half ('Y''U' = 0x5955).
        for m in [MAGIC_OPFRAME, MAGIC_OPFRAME_RX, MAGIC_INFERWIRE] {
            assert_eq!((m >> 8) as u8, BRAND.as_bytes()[0]);
            assert_ne!(m, (NOTE_TYPE_ENTRY64 >> 16) as u16);
        }
    }

    #[test]
    fn sb_magic_starts_with_brand() {
        assert_eq!(&SB_MAGIC, b"YUVAMEM0");
        assert!(SB_MAGIC.starts_with(BRAND.as_bytes()));
    }

    #[test]
    fn to_bytes_roundtrip() {
        assert_eq!(to_bytes::<4>(BRAND), *b"YUVA");
    }
}
