//! ELF64 kernel loader.
//!
//! A small, fully bounds-checked hand-rolled parser (chosen over `goblin` so the
//! parse surface is auditable + unit-testable with synthetic byte buffers, and
//! tb-vmm carries no `unsafe` here). It:
//!  1. copies every `PT_LOAD` segment to its `p_paddr` in guest RAM, zeroing the
//!     `p_memsz - p_filesz` `.bss` tail;
//!  2. locates the brand boot note (`PT_NOTE`, name [`tb_boot::TB_NOTE_NAME`]
//!     = `"YUVA"`, type [`tb_boot::TB_NOTE_TYPE_ENTRY64`]) whose 8-byte
//!     descriptor is the kernel's 64-bit `tb-boot` entry. A kernel without
//!     this note is rejected (LoaderError::MissingTbNote).
//!
//! Layout per the System V gABI / `elf.h` (`Elf64_Ehdr`/`Elf64_Phdr`/`Elf64_Nhdr`).
//! The brand note mirrors the Xen `PHYS32_ENTRY` note used by the PVH path
//! (crates/tb-hal/src/arch/x86_64/boot.rs). Every name/type byte here comes
//! from `tb_boot`'s brand-derived consts -- this file never re-spells them.

use std::fmt;

use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

// --- ELF constants (elf.h) -------------------------------------------------
const EI_NIDENT: usize = 16;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;

/// The 64-bit entry discovered for the kernel + the highest loaded address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadedKernel {
    /// The guest physical address to set `rip` to. ALWAYS the brand note entry:
    /// tb-vmm enters the guest directly in 64-bit long mode, so the kernel's
    /// `e_entry` (a 32-bit PVH trampoline) is never a valid target. A kernel
    /// with no brand note is rejected ([`LoaderError::MissingTbNote`]).
    pub entry: u64,
    /// One past the highest `p_paddr + p_memsz` of any loaded segment.
    pub image_end: u64,
}

/// Errors from parsing/loading the kernel ELF.
#[derive(Debug, PartialEq, Eq)]
pub enum LoaderError {
    /// The buffer is too small to contain an ELF header / a referenced structure.
    Truncated(&'static str),
    /// Missing the `\x7fELF` magic.
    BadMagic,
    /// Not an ELFCLASS64 little-endian image.
    NotElf64Le,
    /// `e_machine` is not `EM_X86_64`.
    BadMachine(u16),
    /// A program header references bytes outside the file.
    SegmentOutOfFile {
        /// Segment index.
        index: usize,
    },
    /// `p_filesz > p_memsz` for a `PT_LOAD` segment.
    BadSegmentSize {
        /// Segment index.
        index: usize,
    },
    /// No `PT_LOAD` segments were present.
    NoLoadSegments,
    /// The kernel ELF carries no brand (`YUVA`) `tb-boot` entry note. tb-vmm enters the
    /// guest in 64-bit long mode and refuses to fall back to `e_entry` (which,
    /// for a Yuva kernel, is the 32-bit PVH trampoline — fatal in long mode).
    MissingTbNote,
    /// Writing a segment to guest RAM failed (segment out of guest range, etc.).
    GuestWrite {
        /// Guest physical destination address.
        paddr: u64,
        /// Underlying message.
        detail: String,
    },
}

impl fmt::Display for LoaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoaderError::Truncated(what) => write!(f, "ELF truncated: {what}"),
            LoaderError::BadMagic => write!(f, "not an ELF file (bad magic)"),
            LoaderError::NotElf64Le => write!(f, "not a 64-bit little-endian ELF"),
            LoaderError::BadMachine(m) => write!(f, "unexpected e_machine {m:#x} (want x86_64=62)"),
            LoaderError::SegmentOutOfFile { index } => {
                write!(f, "program header {index} references bytes past end of file")
            }
            LoaderError::BadSegmentSize { index } => {
                write!(f, "program header {index} has p_filesz > p_memsz")
            }
            LoaderError::NoLoadSegments => write!(f, "ELF has no PT_LOAD segments"),
            LoaderError::MissingTbNote => {
                write!(
                    f,
                    "kernel has no {name} tb-boot entry note (PT_NOTE name={name}, type=ENTRY64); tb-vmm requires it and will not use e_entry",
                    name = tb_boot::TB_NOTE_NAME
                )
            }
            LoaderError::GuestWrite { paddr, detail } => {
                write!(f, "failed to write segment to guest paddr {paddr:#x}: {detail}")
            }
        }
    }
}

impl std::error::Error for LoaderError {}

// --- little-endian readers (bounds-checked) --------------------------------
fn rd_u16(b: &[u8], off: usize, what: &'static str) -> Result<u16, LoaderError> {
    let s = b.get(off..off + 2).ok_or(LoaderError::Truncated(what))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}
fn rd_u32(b: &[u8], off: usize, what: &'static str) -> Result<u32, LoaderError> {
    let s = b.get(off..off + 4).ok_or(LoaderError::Truncated(what))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn rd_u64(b: &[u8], off: usize, what: &'static str) -> Result<u64, LoaderError> {
    let s = b.get(off..off + 8).ok_or(LoaderError::Truncated(what))?;
    Ok(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

/// Round `n` up to the next multiple of 4 (ELF note field alignment).
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// A parsed program header (only the fields we need).
#[derive(Clone, Copy, Debug)]
struct Phdr {
    p_type: u32,
    p_offset: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
}

/// Parse the program-header table.
fn parse_phdrs(image: &[u8]) -> Result<Vec<Phdr>, LoaderError> {
    if image.len() < EHDR_SIZE {
        return Err(LoaderError::Truncated("ELF header"));
    }
    if &image[0..4] != b"\x7fELF" {
        return Err(LoaderError::BadMagic);
    }
    if image[4] != ELFCLASS64 || image[5] != ELFDATA2LSB {
        return Err(LoaderError::NotElf64Le);
    }
    let _ = EI_NIDENT; // e_ident occupies bytes [0,16); fields below start at 16.
    let e_machine = rd_u16(image, 18, "e_machine")?;
    if e_machine != EM_X86_64 {
        return Err(LoaderError::BadMachine(e_machine));
    }
    let e_phoff = rd_u64(image, 32, "e_phoff")? as usize;
    let e_phentsize = rd_u16(image, 54, "e_phentsize")? as usize;
    let e_phnum = rd_u16(image, 56, "e_phnum")? as usize;
    if e_phentsize < PHDR_SIZE {
        return Err(LoaderError::Truncated("e_phentsize"));
    }

    let mut phdrs = Vec::with_capacity(e_phnum);
    for i in 0..e_phnum {
        let base = e_phoff + i * e_phentsize;
        phdrs.push(Phdr {
            p_type: rd_u32(image, base, "p_type")?,
            p_offset: rd_u64(image, base + 8, "p_offset")?,
            p_paddr: rd_u64(image, base + 24, "p_paddr")?,
            p_filesz: rd_u64(image, base + 32, "p_filesz")?,
            p_memsz: rd_u64(image, base + 40, "p_memsz")?,
        });
    }
    Ok(phdrs)
}

/// Find the brand-note 64-bit entry from a `PT_NOTE` segment, if present.
fn find_tb_entry(image: &[u8], phdrs: &[Phdr]) -> Result<Option<u64>, LoaderError> {
    for ph in phdrs.iter().filter(|p| p.p_type == PT_NOTE) {
        let start = ph.p_offset as usize;
        let end = start
            .checked_add(ph.p_filesz as usize)
            .ok_or(LoaderError::Truncated("PT_NOTE"))?;
        let seg = image.get(start..end).ok_or(LoaderError::Truncated("PT_NOTE"))?;

        let mut off = 0usize;
        while off + 12 <= seg.len() {
            let namesz = u32::from_le_bytes([seg[off], seg[off + 1], seg[off + 2], seg[off + 3]])
                as usize;
            let descsz = u32::from_le_bytes([
                seg[off + 4],
                seg[off + 5],
                seg[off + 6],
                seg[off + 7],
            ]) as usize;
            let ntype = u32::from_le_bytes([
                seg[off + 8],
                seg[off + 9],
                seg[off + 10],
                seg[off + 11],
            ]);

            let name_off = off + 12;
            let desc_off = name_off + align4(namesz);
            let next = desc_off + align4(descsz);
            if next > seg.len() || next <= off {
                break; // malformed / final padding
            }

            let name = &seg[name_off..name_off + namesz];
            let name_trimmed = name.strip_suffix(b"\0").unwrap_or(name);
            if ntype == tb_boot::TB_NOTE_TYPE_ENTRY64
                && name_trimmed == tb_boot::TB_NOTE_NAME.as_bytes()
                && descsz >= 8
            {
                let d = &seg[desc_off..desc_off + 8];
                let entry = u64::from_le_bytes([
                    d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
                ]);
                return Ok(Some(entry));
            }
            off = next;
        }
    }
    Ok(None)
}

/// Parse, copy every `PT_LOAD` to its `p_paddr` in guest RAM, and resolve the
/// 64-bit entry from the mandatory brand note (`MissingTbNote` if absent).
pub fn load_kernel(image: &[u8], mem: &GuestMemoryMmap) -> Result<LoadedKernel, LoaderError> {
    let phdrs = parse_phdrs(image)?;

    let mut loaded_any = false;
    let mut image_end = 0u64;

    for (index, ph) in phdrs.iter().enumerate() {
        if ph.p_type != PT_LOAD || ph.p_memsz == 0 {
            continue;
        }
        if ph.p_filesz > ph.p_memsz {
            return Err(LoaderError::BadSegmentSize { index });
        }

        // Copy the file-backed bytes.
        let foff = ph.p_offset as usize;
        let fsz = ph.p_filesz as usize;
        let src = image
            .get(foff..foff + fsz)
            .ok_or(LoaderError::SegmentOutOfFile { index })?;
        mem.write_slice(src, GuestAddress(ph.p_paddr))
            .map_err(|e| LoaderError::GuestWrite {
                paddr: ph.p_paddr,
                detail: e.to_string(),
            })?;

        // Zero the .bss tail (p_memsz - p_filesz). Guest RAM is already zeroed,
        // but we do it explicitly so loading into reused memory is correct.
        let bss = (ph.p_memsz - ph.p_filesz) as usize;
        if bss > 0 {
            let zeros = vec![0u8; bss];
            let dst = ph.p_paddr + ph.p_filesz;
            mem.write_slice(&zeros, GuestAddress(dst))
                .map_err(|e| LoaderError::GuestWrite {
                    paddr: dst,
                    detail: e.to_string(),
                })?;
        }

        loaded_any = true;
        image_end = image_end.max(ph.p_paddr + ph.p_memsz);
    }

    if !loaded_any {
        return Err(LoaderError::NoLoadSegments);
    }

    // tb-vmm enters the guest in 64-bit long mode, so the brand note entry is
    // mandatory; e_entry (the 32-bit PVH trampoline) is never a valid target.
    let entry = find_tb_entry(image, &phdrs)?.ok_or(LoaderError::MissingTbNote)?;

    Ok(LoadedKernel { entry, image_end })
}

#[cfg(test)]
mod tests {
    use super::*;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    fn w16(b: &mut [u8], off: usize, v: u16) {
        b[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn w32(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn w64(b: &mut [u8], off: usize, v: u64) {
        b[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// Build a minimal ET_EXEC ELF64 with one PT_LOAD (payload \"ABCD\" at
    /// paddr 0x100000, +4 bytes bss) and, optionally, a PT_NOTE brand entry
    /// (every name/namesz/type byte DERIVED from tb_boot's consts -- the
    /// fixture cannot drift from the producer/parser).
    fn build_elf(note_entry: Option<u64>, e_entry: u64) -> Vec<u8> {
        let mut buf = vec![0u8; 0x400];
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = ELFCLASS64;
        buf[5] = ELFDATA2LSB;
        buf[6] = 1; // EV_CURRENT
        w16(&mut buf, 16, 2); // e_type = ET_EXEC
        w16(&mut buf, 18, EM_X86_64);
        w32(&mut buf, 20, 1); // e_version
        w64(&mut buf, 24, e_entry); // e_entry
        w64(&mut buf, 32, EHDR_SIZE as u64); // e_phoff
        w16(&mut buf, 52, EHDR_SIZE as u16); // e_ehsize
        w16(&mut buf, 54, PHDR_SIZE as u16); // e_phentsize
        let phnum = if note_entry.is_some() { 2u16 } else { 1 };
        w16(&mut buf, 56, phnum); // e_phnum

        // PT_LOAD
        let ph0 = EHDR_SIZE;
        w32(&mut buf, ph0, PT_LOAD);
        w32(&mut buf, ph0 + 4, 5); // R E
        w64(&mut buf, ph0 + 8, 0x200); // p_offset
        w64(&mut buf, ph0 + 16, 0x100000); // p_vaddr
        w64(&mut buf, ph0 + 24, 0x100000); // p_paddr
        w64(&mut buf, ph0 + 32, 4); // p_filesz
        w64(&mut buf, ph0 + 40, 8); // p_memsz (4 bss)
        w64(&mut buf, ph0 + 48, 0x1000); // p_align
        buf[0x200..0x204].copy_from_slice(b"ABCD");

        if let Some(entry) = note_entry {
            let ph1 = EHDR_SIZE + PHDR_SIZE;
            let note_off = 0x300usize;
            let mut note = Vec::new();
            note.extend_from_slice(&tb_boot::TB_NOTE_NAMESZ.to_le_bytes()); // namesz (name + NUL)
            note.extend_from_slice(&tb_boot::TB_NOTE_DESCSZ.to_le_bytes()); // descsz
            note.extend_from_slice(&tb_boot::TB_NOTE_TYPE_ENTRY64.to_le_bytes());
            note.extend_from_slice(tb_boot::TB_NOTE_NAME.as_bytes());
            note.push(0); // the counted trailing NUL
            while note.len() % 4 != 0 {
                note.push(0); // pad the name field to a 4-byte boundary
            }
            note.extend_from_slice(&entry.to_le_bytes()); // 8-byte desc
            let nlen = note.len();
            buf[note_off..note_off + nlen].copy_from_slice(&note);
            w32(&mut buf, ph1, PT_NOTE);
            w32(&mut buf, ph1 + 4, 4); // R
            w64(&mut buf, ph1 + 8, note_off as u64); // p_offset
            w64(&mut buf, ph1 + 32, nlen as u64); // p_filesz
            w64(&mut buf, ph1 + 40, nlen as u64); // p_memsz
            w64(&mut buf, ph1 + 48, 4); // p_align
        }
        buf
    }

    fn mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x200000)]).unwrap()
    }

    #[test]
    fn loads_segment_and_uses_note_entry() {
        let elf = build_elf(Some(0x0012_3456), 0x0010_0000);
        let gm = mem();
        let loaded = load_kernel(&elf, &gm).unwrap();

        assert_eq!(loaded.entry, 0x0012_3456);
        assert_eq!(loaded.image_end, 0x0010_0000 + 8);

        let mut got = [0u8; 4];
        gm.read_slice(&mut got, GuestAddress(0x0010_0000)).unwrap();
        assert_eq!(&got, b"ABCD");
        // bss tail is zeroed
        let mut bss = [0xffu8; 4];
        gm.read_slice(&mut bss, GuestAddress(0x0010_0004)).unwrap();
        assert_eq!(bss, [0, 0, 0, 0]);
    }

    #[test]
    fn rejects_missing_tb_note() {
        // No brand note -> hard error (NOT an e_entry fallback): jumping to the
        // 32-bit PVH e_entry in long mode would instantly triple-fault.
        let elf = build_elf(None, 0x0010_0000);
        let gm = mem();
        assert_eq!(
            load_kernel(&elf, &gm).unwrap_err(),
            LoaderError::MissingTbNote
        );
    }

    #[test]
    fn rejects_bad_magic() {
        let mut elf = build_elf(None, 0x100000);
        elf[1] = b'X';
        assert_eq!(load_kernel(&elf, &mem()).unwrap_err(), LoaderError::BadMagic);
    }

    #[test]
    fn rejects_non_x86_64() {
        let mut elf = build_elf(None, 0x100000);
        w16(&mut elf, 18, 0xB7); // aarch64
        assert_eq!(
            load_kernel(&elf, &mem()).unwrap_err(),
            LoaderError::BadMachine(0xB7)
        );
    }

    #[test]
    fn rejects_segment_past_eof() {
        let mut elf = build_elf(None, 0x100000);
        // Make PT_LOAD p_filesz huge so it runs past the file.
        w64(&mut elf, EHDR_SIZE + 32, 0x10_0000);
        w64(&mut elf, EHDR_SIZE + 40, 0x10_0000);
        assert_eq!(
            load_kernel(&elf, &mem()).unwrap_err(),
            LoaderError::SegmentOutOfFile { index: 0 }
        );
    }
}
