//! `tb-boot` — the Yuva boot-handoff ABI (contract **v0**).
//!
//! This crate is the single, shared definition of how a Yuva VMM hands a
//! freshly-loaded kernel image its boot environment. It is depended on by BOTH
//! sides of the contract:
//!
//!  * **`tb-vmm`** (a `std` Linux/`/dev/kvm` binary, *outside* the framekernel
//!    `forbid(unsafe)` boundary) — it *produces* a [`TbBootInfo`] (+ its
//!    [`TbMemRegion`] array + cmdline) into guest RAM, then enters the guest
//!    directly in 64-bit long mode with `rdi` = the guest-physical address of
//!    that [`TbBootInfo`] (SysV arg0).
//!  * **the kernel / `tb-hal`** (`no_std`) — it *consumes* that pointer and,
//!    via the safe reader/validator here, confirms the contract before trusting
//!    any field.
//!
//! ## Why this crate is `forbid(unsafe_code)`
//!
//! The ABI types are plain `#[repr(C)]` PODs and every reader works on a
//! borrowed `&[u8]` (parsed with `u64::from_le_bytes`), so NOTHING here needs
//! `unsafe`. The one genuinely-unsafe step — turning the raw guest-physical
//! `usize` the kernel receives in `rdi` into a `&[u8]`/`&TbBootInfo` — lives in
//! `tb-hal` (the only crate allowed `unsafe`), which then calls the safe
//! validator below. That keeps the *contract definition* itself provably safe.
//!
//! ## Endianness
//!
//! v0 targets little-endian hosts/guests (x86_64 today, aarch64 LE follow-up),
//! so all multi-byte fields are little-endian. The byte readers/writers use
//! explicit `from_le_bytes`/`to_le_bytes`, so the wire format is fixed
//! regardless of the host that happens to run the unit tests.
//!
//! ## The brand (YUVA) ELF note (`PT_NOTE`) — byte layout
//!
//! So `tb-vmm` can discover the kernel's 64-bit entry point *from the ELF*
//! (exactly as PVH does via `XEN_ELFNOTE_PHYS32_ENTRY`, see
//! `tb-hal/src/arch/x86_64/boot.rs`), the kernel emits a second note carrying
//! its `tb-boot` 64-bit entry address. It is a standard ELF note: three 4-byte
//! words (`n_namesz`, `n_descsz`, `n_type`), then the name padded up to a
//! 4-byte boundary, then the descriptor. Mirrors the in-repo PVH note's
//! 4-byte (`.align 4`) framing. The name/type bytes derive from the
//! [`brand`] identity crate — this crate never re-spells them.
//!
//! ```text
//! off  size  field       value                       meaning
//! ---  ----  ----------  --------------------------  ---------------------------
//!   0    4   n_namesz    5  (= TB_NOTE_NAMESZ)        len of "YUVA\0" incl. NUL
//!   4    4   n_descsz    8  (= TB_NOTE_DESCSZ)        sizeof(u64) entry address
//!   8    4   n_type      0x59550001 (ENTRY64)        'Y''U' + 0x0001
//!  12    5   n_name      "YUVA\0"                     name bytes (incl. NUL)
//!  17    3   (pad)       0x00 0x00 0x00               pad name to 4-byte boundary
//!  20    8   n_desc      <u64 LE>                     guest-VA of `_tb_start`
//!  28        -- end (28 bytes total) --
//! ```
//!
//! Note `n_namesz` counts the trailing NUL (so `"YUVA"` -> 5), and the *name*
//! field is then padded to a 4-byte multiple (5 -> 8) before the descriptor —
//! the SAME padded width as the TABOS-era 6 -> 8, so every offset (and the
//! 28-byte total) is unchanged by the rename; the descriptor (8 bytes) is
//! already 4-aligned. See [`parse_entry64_note`] for the safe extractor
//! `tb-vmm` uses while walking `PT_NOTE` segments.
//!
//! ## References
//!  * ELF note section layout (`ElfN_Nhdr` = namesz/descsz/type, then name +
//!    desc, each padded to a 4-byte boundary): System V gABI "Note Section";
//!    Linux `elf(5)` (<https://man7.org/linux/man-pages/man5/elf.5.html>).
//!  * In-repo cross-check of the 4-byte note framing & `PT_NOTE` placement:
//!    `crates/tb-hal/src/arch/x86_64/boot.rs` (the PVH `XEN_ELFNOTE_PHYS32_ENTRY`
//!    note, type 18, name "Xen") and `xen/include/public/elfnote.h`.
//!  * SysV x86-64 psABI section 3.2.3 (arg0 in `rdi`) — how `tb-vmm` passes the
//!    [`TbBootInfo`] pointer.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Host-side **aarch64** `tb-boot v0` producer + register-file handoff (the
/// aarch64 mirror of the x86 `tb-vmm` producer; pure, `cargo test`-able on every
/// host with no `/dev/kvm`).
pub mod aarch64;

// ===========================================================================
// Contract constants
// ===========================================================================

/// Magic stamped in [`TbBootInfo::magic`] so the kernel can tell a genuine
/// `tb-boot` handoff from anything else handed to it in `rdi`/`arg0` (e.g. a
/// PVH `hvm_start_info` pointer whose magic is `0x336E_C578`).
///
/// Value `0x3056_544F_4F42_5900`: its little-endian bytes are
/// `00 'Y' 'B' 'O' 'O' 'T' 'V' '0'`, i.e. the printable mnemonic `YBOOTV0`
/// ("Yuva boot, version 0") with a leading NUL. DERIVED from
/// [`brand::BOOT_MAGIC`] (leading NUL + the brand initial + `BOOTV0`).
pub const TB_BOOT_MAGIC: u64 = brand::BOOT_MAGIC;

/// The contract version stamped in [`TbBootInfo::version`]. Bumped only on an
/// incompatible layout change; readers reject any other value.
pub const TB_BOOT_VERSION: u32 = 0;

/// [`TbMemRegion::kind`] value for usable RAM.
pub const TB_MEM_KIND_RAM: u32 = 1;

/// [`TbMemRegion::kind`] value for reserved / unusable memory.
pub const TB_MEM_KIND_RESERVED: u32 = 2;

/// Name field of the brand 64-bit-entry ELF note (`n_name`, sans NUL) --
/// `"YUVA"`, derived from [`brand::NOTE_NAME`].
pub const TB_NOTE_NAME: &str = brand::NOTE_NAME;

/// `n_type` of the brand 64-bit-entry ELF note. `0x59550001` = `'Y''U'` (the
/// brand's first two bytes in the high half) followed by note ordinal
/// `0x0001`. Mirrors PVH's `XEN_ELFNOTE_PHYS32_ENTRY` (type 18) but for our
/// 64-bit direct entry. Derived from [`brand::NOTE_TYPE_ENTRY64`].
pub const TB_NOTE_TYPE_ENTRY64: u32 = brand::NOTE_TYPE_ENTRY64;

/// `n_namesz` of the brand note: `b"YUVA\0".len()` (the NUL is counted) = 5.
pub const TB_NOTE_NAMESZ: u32 = brand::NOTE_NAMESZ;

/// `n_descsz` of the brand note: `size_of::<u64>()` (the entry address).
pub const TB_NOTE_DESCSZ: u32 = 8;

// ===========================================================================
// Memory map
// ===========================================================================

/// Strongly-typed view of a [`TbMemRegion::kind`] discriminant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum MemKind {
    /// Usable RAM (`TB_MEM_KIND_RAM`).
    Ram = TB_MEM_KIND_RAM,
    /// Reserved / unusable memory (`TB_MEM_KIND_RESERVED`).
    Reserved = TB_MEM_KIND_RESERVED,
}

impl MemKind {
    /// The raw `u32` discriminant stored in [`TbMemRegion::kind`].
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Decode a raw [`TbMemRegion::kind`] value, or `None` if unrecognised.
    pub const fn from_u32(value: u32) -> Option<MemKind> {
        match value {
            TB_MEM_KIND_RAM => Some(MemKind::Ram),
            TB_MEM_KIND_RESERVED => Some(MemKind::Reserved),
            _ => None,
        }
    }
}

/// One entry of the boot memory map: a `[base, base+len)` guest-physical span
/// with a [`MemKind`] tag. `#[repr(C)]`, 24 bytes, 8-byte aligned.
///
/// Layout (v0, little-endian):
/// `base@0(u64) len@8(u64) kind@16(u32) _pad@20(u32)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct TbMemRegion {
    /// Guest-physical base address of the region.
    pub base: u64,
    /// Length of the region in bytes.
    pub len: u64,
    /// Region kind: one of `TB_MEM_KIND_RAM` / `TB_MEM_KIND_RESERVED`
    /// (see [`MemKind`]).
    pub kind: u32,
    /// Reserved padding so the struct is a clean 24-byte `#[repr(C)]` POD with
    /// no implicit tail padding. Must be 0 in v0.
    pub _pad: u32,
}

impl TbMemRegion {
    /// Serialized size of one region in bytes (the on-the-wire stride).
    pub const SIZE: usize = 24;

    /// Required alignment of the `#[repr(C)]` struct.
    pub const ALIGN: usize = 8;

    /// Construct a region with `_pad` zeroed.
    pub const fn new(base: u64, len: u64, kind: MemKind) -> Self {
        TbMemRegion {
            base,
            len,
            kind: kind.as_u32(),
            _pad: 0,
        }
    }

    /// Strongly-typed kind, or `None` for an unrecognised discriminant.
    pub const fn kind(&self) -> Option<MemKind> {
        MemKind::from_u32(self.kind)
    }

    /// `true` iff this region is usable RAM.
    pub const fn is_ram(&self) -> bool {
        self.kind == TB_MEM_KIND_RAM
    }

    /// Serialize this region to its fixed little-endian wire form.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[0..8].copy_from_slice(&self.base.to_le_bytes());
        out[8..16].copy_from_slice(&self.len.to_le_bytes());
        out[16..20].copy_from_slice(&self.kind.to_le_bytes());
        out[20..24].copy_from_slice(&self._pad.to_le_bytes());
        out
    }

    /// Parse one region from the front of `bytes` (the rest is ignored).
    ///
    /// Returns [`TbBootError::ShortBuffer`] if fewer than [`Self::SIZE`] bytes
    /// are available. Safe: a copy via `from_le_bytes`, no alignment or
    /// pointer assumptions.
    pub fn read_from_prefix(bytes: &[u8]) -> Result<Self, TbBootError> {
        if bytes.len() < Self::SIZE {
            return Err(TbBootError::ShortBuffer {
                need: Self::SIZE,
                got: bytes.len(),
            });
        }
        Ok(TbMemRegion {
            base: read_u64_le(bytes, 0),
            len: read_u64_le(bytes, 8),
            kind: read_u32_le(bytes, 16),
            _pad: read_u32_le(bytes, 20),
        })
    }
}

/// Iterator over a packed [`TbMemRegion`] array in a borrowed byte buffer.
///
/// Produced by [`regions_from_bytes`]; stops early (yields `None`) if the
/// buffer runs short before the requested count, so a truncated map can never
/// over-read.
#[derive(Clone, Debug)]
pub struct Regions<'a> {
    bytes: &'a [u8],
    remaining: usize,
}

impl<'a> Iterator for Regions<'a> {
    type Item = TbMemRegion;

    fn next(&mut self) -> Option<TbMemRegion> {
        if self.remaining == 0 {
            return None;
        }
        let region = TbMemRegion::read_from_prefix(self.bytes).ok()?;
        // `read_from_prefix` succeeding guarantees `bytes.len() >= SIZE`.
        self.bytes = &self.bytes[TbMemRegion::SIZE..];
        self.remaining -= 1;
        Some(region)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let max = self.bytes.len() / TbMemRegion::SIZE;
        let n = if self.remaining < max { self.remaining } else { max };
        (n, Some(n))
    }
}

/// Iterate `count` packed [`TbMemRegion`]s out of `bytes`.
///
/// `bytes` is what `tb-hal` builds from `mem_regions_ptr`/`mem_regions_len`
/// (`unsafe` slice construction lives there); this borrows it and parses
/// safely, one 24-byte region at a time.
pub fn regions_from_bytes(bytes: &[u8], count: u64) -> Regions<'_> {
    Regions {
        bytes,
        remaining: count as usize,
    }
}

// ===========================================================================
// Boot info
// ===========================================================================

/// The root boot-handoff structure (`tb-boot` contract v0).
///
/// `tb-vmm` writes one of these into guest RAM and passes its guest-physical
/// address to the kernel in `rdi` (SysV arg0). `#[repr(C)]`, 56 bytes, 8-byte
/// aligned; all fields little-endian.
///
/// Layout (v0):
/// ```text
/// off  field             type
///   0  magic             u64   = TB_BOOT_MAGIC
///   8  version           u32   = TB_BOOT_VERSION
///  12  flags             u32   reserved, 0 in v0
///  16  mem_regions_ptr   u64   guest-phys addr of the TbMemRegion[] array
///  24  mem_regions_len   u64   number of regions
///  32  cmdline_ptr       u64   guest-phys addr of the cmdline bytes (or 0)
///  40  cmdline_len       u64   cmdline length in bytes (no implied NUL)
///  48  kernel_entry      u64   the 64-bit entry the VMM jumped to (info)
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct TbBootInfo {
    /// Must equal [`TB_BOOT_MAGIC`]; the kernel rejects everything else.
    pub magic: u64,
    /// Must equal [`TB_BOOT_VERSION`]; the kernel rejects other versions.
    pub version: u32,
    /// Reserved feature flags. All bits are reserved-zero in v0.
    pub flags: u32,
    /// Guest-physical address of the [`TbMemRegion`] array.
    pub mem_regions_ptr: u64,
    /// Number of [`TbMemRegion`] entries at `mem_regions_ptr`.
    pub mem_regions_len: u64,
    /// Guest-physical address of the cmdline byte buffer, or `0` if none.
    pub cmdline_ptr: u64,
    /// Length of the cmdline buffer in bytes (no implied NUL terminator).
    pub cmdline_len: u64,
    /// The kernel 64-bit entry address `tb-vmm` actually jumped to (the value
    /// read from the brand (YUVA) ELF note, or the ELF `e_entry` fallback).
    /// Informational; lets the kernel sanity-check the entry it booted through.
    pub kernel_entry: u64,
}

impl TbBootInfo {
    /// Serialized size in bytes (the wire form length).
    pub const SIZE: usize = 56;

    /// Required alignment of the `#[repr(C)]` struct.
    pub const ALIGN: usize = 8;

    /// Construct a v0 boot-info with [`magic`](Self::magic) and
    /// [`version`](Self::version) pre-filled. Used by `tb-vmm`.
    pub const fn new(
        flags: u32,
        mem_regions_ptr: u64,
        mem_regions_len: u64,
        cmdline_ptr: u64,
        cmdline_len: u64,
        kernel_entry: u64,
    ) -> Self {
        TbBootInfo {
            magic: TB_BOOT_MAGIC,
            version: TB_BOOT_VERSION,
            flags,
            mem_regions_ptr,
            mem_regions_len,
            cmdline_ptr,
            cmdline_len,
            kernel_entry,
        }
    }

    /// Validate the contract: [`magic`](Self::magic) and
    /// [`version`](Self::version) must match. This is the guard that lets the
    /// kernel safely ignore a non-`tb-boot` pointer (e.g. a PVH
    /// `hvm_start_info`, magic `0x336E_C578`) instead of misreading it.
    pub fn validate(&self) -> Result<(), TbBootError> {
        if self.magic != TB_BOOT_MAGIC {
            return Err(TbBootError::BadMagic { found: self.magic });
        }
        if self.version != TB_BOOT_VERSION {
            return Err(TbBootError::UnsupportedVersion {
                found: self.version,
            });
        }
        Ok(())
    }

    /// Convenience: `validate().is_ok()`.
    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }

    /// Serialize to the fixed little-endian wire form `tb-vmm` writes into
    /// guest RAM.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[0..8].copy_from_slice(&self.magic.to_le_bytes());
        out[8..12].copy_from_slice(&self.version.to_le_bytes());
        out[12..16].copy_from_slice(&self.flags.to_le_bytes());
        out[16..24].copy_from_slice(&self.mem_regions_ptr.to_le_bytes());
        out[24..32].copy_from_slice(&self.mem_regions_len.to_le_bytes());
        out[32..40].copy_from_slice(&self.cmdline_ptr.to_le_bytes());
        out[40..48].copy_from_slice(&self.cmdline_len.to_le_bytes());
        out[48..56].copy_from_slice(&self.kernel_entry.to_le_bytes());
        out
    }

    /// Parse a [`TbBootInfo`] from the front of `bytes` WITHOUT validating the
    /// magic/version (call [`validate`](Self::validate) after). Returns
    /// [`TbBootError::ShortBuffer`] if fewer than [`Self::SIZE`] bytes exist.
    ///
    /// Safe: a field-by-field copy via `from_le_bytes`; imposes no alignment or
    /// pointer requirement on `bytes`.
    pub fn read_from_prefix(bytes: &[u8]) -> Result<Self, TbBootError> {
        if bytes.len() < Self::SIZE {
            return Err(TbBootError::ShortBuffer {
                need: Self::SIZE,
                got: bytes.len(),
            });
        }
        Ok(TbBootInfo {
            magic: read_u64_le(bytes, 0),
            version: read_u32_le(bytes, 8),
            flags: read_u32_le(bytes, 12),
            mem_regions_ptr: read_u64_le(bytes, 16),
            mem_regions_len: read_u64_le(bytes, 24),
            cmdline_ptr: read_u64_le(bytes, 32),
            cmdline_len: read_u64_le(bytes, 40),
            kernel_entry: read_u64_le(bytes, 48),
        })
    }

    /// Parse AND validate in one step: `read_from_prefix` then `validate`.
    pub fn read_validated(bytes: &[u8]) -> Result<Self, TbBootError> {
        let info = Self::read_from_prefix(bytes)?;
        info.validate()?;
        Ok(info)
    }
}

// ===========================================================================
// The brand (YUVA) ELF note extractor
// ===========================================================================

/// Validate a candidate brand `PT_NOTE` entry and extract the 64-bit kernel
/// entry address from its descriptor.
///
/// `tb-vmm` walks the kernel ELF's notes and calls this with each note's raw
/// `(name, type, desc)`. `name` may be passed with or without its trailing
/// NUL (anything from the first NUL on is ignored). Returns the `u64` entry on
/// a match, or the relevant [`TbBootError`] otherwise. Safe: only byte
/// comparisons + a `from_le_bytes`.
pub fn parse_entry64_note(name: &[u8], note_type: u32, desc: &[u8]) -> Result<u64, TbBootError> {
    if note_type != TB_NOTE_TYPE_ENTRY64 {
        return Err(TbBootError::BadNoteType { found: note_type });
    }
    // Accept "YUVA" or "YUVA\0" (or any longer buffer NUL-terminated there).
    let trimmed: &[u8] = match name.iter().position(|&b| b == 0) {
        Some(nul) => &name[..nul],
        None => name,
    };
    if trimmed != TB_NOTE_NAME.as_bytes() {
        return Err(TbBootError::BadNoteName);
    }
    if desc.len() < 8 {
        return Err(TbBootError::ShortBuffer {
            need: 8,
            got: desc.len(),
        });
    }
    Ok(read_u64_le(desc, 0))
}

// ===========================================================================
// Errors
// ===========================================================================

/// Why a `tb-boot` read/validate failed. `Copy` so the kernel can log it
/// without allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TbBootError {
    /// [`TbBootInfo::magic`] did not equal [`TB_BOOT_MAGIC`]. Carries what was
    /// found (e.g. a PVH `hvm_start_info` magic) for diagnostics.
    BadMagic {
        /// The magic word actually present.
        found: u64,
    },
    /// [`TbBootInfo::version`] was not a version this reader understands.
    UnsupportedVersion {
        /// The version actually present.
        found: u32,
    },
    /// The byte buffer was too small to hold the structure being parsed.
    ShortBuffer {
        /// Bytes required.
        need: usize,
        /// Bytes actually available.
        got: usize,
    },
    /// A candidate ELF note did not carry [`TB_NOTE_TYPE_ENTRY64`].
    BadNoteType {
        /// The `n_type` actually present.
        found: u32,
    },
    /// A candidate ELF note's name was not [`TB_NOTE_NAME`].
    BadNoteName,
}

impl core::fmt::Display for TbBootError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TbBootError::BadMagic { found } => write!(
                f,
                "tb-boot: bad magic {found:#018x} (expected {TB_BOOT_MAGIC:#018x})"
            ),
            TbBootError::UnsupportedVersion { found } => write!(
                f,
                "tb-boot: unsupported version {found} (expected {TB_BOOT_VERSION})"
            ),
            TbBootError::ShortBuffer { need, got } => {
                write!(f, "tb-boot: short buffer (need {need} bytes, got {got})")
            }
            TbBootError::BadNoteType { found } => write!(
                f,
                "tb-boot: bad note type {found:#010x} (expected {TB_NOTE_TYPE_ENTRY64:#010x})"
            ),
            TbBootError::BadNoteName => {
                write!(f, "tb-boot: bad note name (expected \"{TB_NOTE_NAME}\")")
            }
        }
    }
}

// ===========================================================================
// Internal little-endian byte readers (panic-free given a length pre-check)
// ===========================================================================

/// Read a little-endian `u64` at `off`. Callers guarantee `off + 8 <= len`.
#[inline]
fn read_u64_le(buf: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&buf[off..off + 8]);
    u64::from_le_bytes(a)
}

/// Read a little-endian `u32` at `off`. Callers guarantee `off + 4 <= len`.
#[inline]
fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&buf[off..off + 4]);
    u32::from_le_bytes(a)
}

// ===========================================================================
// Tests (std harness; the crate itself is no_std in non-test builds)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// The PVH `hvm_start_info` magic ("xEn3"), used to prove `validate`
    /// fail-closes on a non-tb-boot pointer.
    const HVM_START_INFO_MAGIC: u64 = 0x336E_C578;

    #[test]
    fn boot_info_layout_is_v0_abi() {
        assert_eq!(core::mem::size_of::<TbBootInfo>(), 56);
        assert_eq!(core::mem::size_of::<TbBootInfo>(), TbBootInfo::SIZE);
        assert_eq!(core::mem::align_of::<TbBootInfo>(), 8);
        assert_eq!(core::mem::offset_of!(TbBootInfo, magic), 0);
        assert_eq!(core::mem::offset_of!(TbBootInfo, version), 8);
        assert_eq!(core::mem::offset_of!(TbBootInfo, flags), 12);
        assert_eq!(core::mem::offset_of!(TbBootInfo, mem_regions_ptr), 16);
        assert_eq!(core::mem::offset_of!(TbBootInfo, mem_regions_len), 24);
        assert_eq!(core::mem::offset_of!(TbBootInfo, cmdline_ptr), 32);
        assert_eq!(core::mem::offset_of!(TbBootInfo, cmdline_len), 40);
        assert_eq!(core::mem::offset_of!(TbBootInfo, kernel_entry), 48);
    }

    #[test]
    fn mem_region_layout_is_v0_abi() {
        assert_eq!(core::mem::size_of::<TbMemRegion>(), 24);
        assert_eq!(core::mem::size_of::<TbMemRegion>(), TbMemRegion::SIZE);
        assert_eq!(core::mem::align_of::<TbMemRegion>(), 8);
        assert_eq!(core::mem::offset_of!(TbMemRegion, base), 0);
        assert_eq!(core::mem::offset_of!(TbMemRegion, len), 8);
        assert_eq!(core::mem::offset_of!(TbMemRegion, kind), 16);
        assert_eq!(core::mem::offset_of!(TbMemRegion, _pad), 20);
    }

    #[test]
    fn magic_mnemonic_bytes() {
        // LE bytes spell a leading NUL + the brand initial + "BOOTV0"
        // (DERIVED -- never re-spelled: brand::BRAND's first byte).
        let initial = brand::BRAND.as_bytes()[0];
        assert_eq!(
            TB_BOOT_MAGIC,
            u64::from_le_bytes([0, initial, b'B', b'O', b'O', b'T', b'V', b'0'])
        );
    }

    #[test]
    fn note_constants() {
        assert_eq!(TB_NOTE_NAMESZ as usize, TB_NOTE_NAME.len() + 1); // incl NUL
        assert_eq!(TB_NOTE_DESCSZ as usize, core::mem::size_of::<u64>());
        assert_eq!(TB_NOTE_NAME, brand::NOTE_NAME);
        // The brand's first two bytes occupy the top half of the type word,
        // ordinal 1 below (DERIVED from the brand const, never re-spelled).
        assert_eq!(
            (TB_NOTE_TYPE_ENTRY64 >> 16) as u16,
            u16::from_be_bytes([brand::BRAND.as_bytes()[0], brand::BRAND.as_bytes()[1]])
        );
        assert_eq!(TB_NOTE_TYPE_ENTRY64 & 0xFFFF, 1);
        // The name field pads to the SAME 8-byte width as the TABOS-era name
        // (namesz 5 -> 8 == 6 -> 8), so the 28-byte note layout is unchanged.
        assert_eq!((TB_NOTE_NAMESZ as usize).next_multiple_of(4), 8);
    }

    #[test]
    fn boot_info_roundtrip() {
        let info = TbBootInfo::new(0, 0x9000, 3, 0x8000, 11, 0x10_0000);
        assert!(info.validate().is_ok());
        let bytes = info.to_bytes();
        assert_eq!(bytes.len(), TbBootInfo::SIZE);
        let back = TbBootInfo::read_from_prefix(&bytes).unwrap();
        assert_eq!(info, back);
        assert_eq!(back.magic, TB_BOOT_MAGIC);
        assert_eq!(back.version, TB_BOOT_VERSION);
        assert_eq!(TbBootInfo::read_validated(&bytes).unwrap(), info);
    }

    #[test]
    fn boot_info_roundtrip_trailing_bytes_ignored() {
        let info = TbBootInfo::new(7, 1, 1, 0, 0, 0x10_0000);
        let mut bytes = info.to_bytes().to_vec();
        bytes.extend_from_slice(&[0xAB; 16]); // junk after the struct
        assert_eq!(TbBootInfo::read_from_prefix(&bytes).unwrap(), info);
    }

    #[test]
    fn validate_rejects_hvm_start_info() {
        let mut info = TbBootInfo::new(0, 0, 0, 0, 0, 0);
        info.magic = HVM_START_INFO_MAGIC;
        assert_eq!(
            info.validate(),
            Err(TbBootError::BadMagic {
                found: HVM_START_INFO_MAGIC
            })
        );
        assert!(!info.is_valid());
    }

    #[test]
    fn validate_rejects_future_version() {
        let mut info = TbBootInfo::new(0, 0, 0, 0, 0, 0);
        info.version = 1;
        assert_eq!(
            info.validate(),
            Err(TbBootError::UnsupportedVersion { found: 1 })
        );
    }

    #[test]
    fn read_from_prefix_short_buffer() {
        let buf = [0u8; TbBootInfo::SIZE - 1];
        assert_eq!(
            TbBootInfo::read_from_prefix(&buf),
            Err(TbBootError::ShortBuffer {
                need: TbBootInfo::SIZE,
                got: TbBootInfo::SIZE - 1
            })
        );
    }

    #[test]
    fn mem_region_roundtrip_and_kind() {
        let r = TbMemRegion::new(0x10_0000, 0x800_0000, MemKind::Ram);
        assert!(r.is_ram());
        assert_eq!(r.kind(), Some(MemKind::Ram));
        assert_eq!(r._pad, 0);
        let bytes = r.to_bytes();
        assert_eq!(TbMemRegion::read_from_prefix(&bytes).unwrap(), r);

        let res = TbMemRegion::new(0, 0x1000, MemKind::Reserved);
        assert!(!res.is_ram());
        assert_eq!(res.kind(), Some(MemKind::Reserved));

        let mut weird = r;
        weird.kind = 99;
        assert_eq!(weird.kind(), None);
    }

    #[test]
    fn regions_iteration() {
        let regions = [
            TbMemRegion::new(0, 0xA_0000, MemKind::Ram),
            TbMemRegion::new(0xA_0000, 0x6_0000, MemKind::Reserved),
            TbMemRegion::new(0x10_0000, 0xF00_0000, MemKind::Ram),
        ];
        let mut buf = Vec::new();
        for r in &regions {
            buf.extend_from_slice(&r.to_bytes());
        }
        let got: Vec<_> = regions_from_bytes(&buf, regions.len() as u64).collect();
        assert_eq!(got.as_slice(), &regions[..]);

        // A short buffer stops early instead of over-reading.
        let truncated = &buf[..TbMemRegion::SIZE + 4];
        let got2: Vec<_> = regions_from_bytes(truncated, 3).collect();
        assert_eq!(got2.len(), 1);
        assert_eq!(got2[0], regions[0]);
    }

    /// The note name DERIVED from the const (never re-spelled), bare and in
    /// its NUL-terminated / pad-to-4 on-wire forms.
    fn note_name_padded(pad: usize) -> Vec<u8> {
        let mut v = TB_NOTE_NAME.as_bytes().to_vec();
        v.extend(core::iter::repeat_n(0u8, pad));
        v
    }

    #[test]
    fn parse_entry64_note_ok_with_and_without_nul() {
        let entry: u64 = 0x10_0000;
        let desc = entry.to_le_bytes();
        assert_eq!(
            parse_entry64_note(&note_name_padded(0), TB_NOTE_TYPE_ENTRY64, &desc),
            Ok(entry)
        );
        assert_eq!(
            parse_entry64_note(&note_name_padded(1), TB_NOTE_TYPE_ENTRY64, &desc),
            Ok(entry)
        );
        // Fully padded name (namesz 5 padded to 8) still parses.
        let padded = note_name_padded((TB_NOTE_NAMESZ as usize).next_multiple_of(4) - TB_NOTE_NAME.len());
        assert_eq!(
            parse_entry64_note(&padded, TB_NOTE_TYPE_ENTRY64, &desc),
            Ok(entry)
        );
    }

    #[test]
    fn parse_entry64_note_rejects() {
        let desc = 0u64.to_le_bytes();
        assert_eq!(
            parse_entry64_note(b"Xen", TB_NOTE_TYPE_ENTRY64, &desc),
            Err(TbBootError::BadNoteName)
        );
        // The retired TABOS-era name is REJECTED (the rename is total).
        assert_eq!(
            parse_entry64_note(b"TABOS\0", TB_NOTE_TYPE_ENTRY64, &desc),
            Err(TbBootError::BadNoteName)
        );
        assert_eq!(
            parse_entry64_note(&note_name_padded(0), 18, &desc),
            Err(TbBootError::BadNoteType { found: 18 })
        );
        // The retired TABOS-era type is REJECTED too.
        assert_eq!(
            parse_entry64_note(&note_name_padded(0), 0x5442_0001, &desc),
            Err(TbBootError::BadNoteType { found: 0x5442_0001 })
        );
        assert_eq!(
            parse_entry64_note(&note_name_padded(0), TB_NOTE_TYPE_ENTRY64, &[0u8; 4]),
            Err(TbBootError::ShortBuffer { need: 8, got: 4 })
        );
    }

    #[test]
    fn error_display_is_nonempty() {
        let e = TbBootError::BadMagic { found: 0x1234 };
        assert!(!format!("{e}").is_empty());
    }
}
