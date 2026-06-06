//! x86_64 permanent GDT + 64-bit TSS (Interrupt Stack Table) for `tb-hal`.
//!
//! Replaces the boot trampoline's transient GDT (`boot.rs`, `__boot_gdt64`) and
//! Firecracker's boot GDT with a PERMANENT flat 64-bit GDT plus a 64-bit TSS, so
//! the IDT (`idt.rs`) can route the double-fault, NMI and machine-check vectors
//! onto dedicated, known-good IST stacks. All `unsafe`/asm stays in `tb-hal`
//! (KERNEL-FOUNDATION-SPEC §1); the kernel crate is `#![forbid(unsafe_code)]`.
//!
//! Layout & descriptor bits are QUOTED from primary sources, not invented:
//!   * GDT segment descriptor — Access Byte (P,DPL,S,E,DC,RW,A) and Flags
//!     (G,DB,L): OSDev "Global Descriptor Table" == Intel SDM Vol.3A §3.4.5,
//!     Figure 3-8 "Segment Descriptor".
//!       - ring0 code : Access 0x9A (P=1,DPL=0,S=1,E=1,DC=0,RW=1,A=0); L=1.
//!       - ring0 data : Access 0x92 (P=1,DPL=0,S=1,E=0,DC=0,RW=1,A=0); DB=1.
//!   * 64-bit (Long Mode) TSS descriptor — 16 bytes, Access 0x89
//!     (P=1,DPL=0,S=0,Type=0x9 "64-bit TSS (Available)"), Base split across the
//!     low 8 bytes plus Base[63:32] in the high 8 bytes: OSDev "GDT" §"Long Mode
//!     System Segment Descriptor" == Intel SDM Vol.3A §7.2.3 / Figure 7-4
//!     "Format of TSS and LDT Descriptors in 64-Bit Mode".
//!   * 64-bit TSS body — RSP0..2, then IST1..7 (each a 64-bit stack pointer),
//!     then the 16-bit I/O-Map Base at byte 0x66; total 104 (0x68) bytes:
//!     OSDev "Task State Segment" §"Long Mode" == Intel SDM Vol.3A §7.7,
//!     Figure 7-11 "64-Bit TSS Format".

use core::arch::asm;
use core::mem::size_of;
use core::ptr::{addr_of, addr_of_mut};

/// GDT selectors: `index << 3 | TI(0) | RPL(0)`. Entry 1 = code, 2 = data,
/// 3..4 = the (16-byte) 64-bit TSS descriptor.
pub(super) const KERNEL_CODE_SEL: u16 = 0x08;
pub(super) const KERNEL_DATA_SEL: u16 = 0x10;
pub(super) const TSS_SEL: u16 = 0x18;

// Flat 64-bit descriptors (base 0, limit 0xFFFFF, page granularity). Base/limit
// are ignored by the CPU in 64-bit mode; the load-bearing bits are Access + L.
const NULL_DESC: u64 = 0x0000_0000_0000_0000;
const CODE_DESC: u64 = 0x00AF_9A00_0000_FFFF; // Access 0x9A, Flags G=1,L=1
const DATA_DESC: u64 = 0x00CF_9200_0000_FFFF; // Access 0x92, Flags G=1,DB=1

/// Access byte for an available 64-bit TSS descriptor: P=1, DPL=0, S=0,
/// Type=0x9 (Intel SDM Vol.3A §3.5, "64-bit TSS (Available)").
const TSS_ACCESS_AVAILABLE: u64 = 0x89;

/// Bytes per IST stack. 8 KiB is ample for the #DF / NMI / #MC handler chain
/// (handler + dispatch + hook + serial); multiple-of-16 keeps the top aligned.
const IST_STACK_SIZE: usize = 8 * 1024;

// 64-bit TSS as 26 dwords (104 bytes). Using u32 lanes (rather than a packed
// struct of u64s at 4-byte-aligned offsets) keeps every field naturally aligned
// so no `unaligned_references` hazard arises when we fill it through a pointer.
const TSS_DWORDS: usize = 26;
const TSS_IST1: usize = 0x24 / 4; // 9   — IST1 low dword (high is +1)
const TSS_IST2: usize = 0x2C / 4; // 11  — IST2
const TSS_IST3: usize = 0x34 / 4; // 13  — IST3
const TSS_IOPB: usize = 0x64 / 4; // 25  — I/O-Map Base lives in bits [31:16]

/// `lgdt`/`lidt` operand: 16-bit limit followed by the 64-bit linear base
/// (Intel SDM Vol.3A §2.4.1/§2.4.3; the m16&64 form). Packed = exactly 10 bytes.
#[repr(C, packed)]
pub(super) struct DescriptorPointer {
    pub(super) limit: u16,
    pub(super) base: u64,
}

#[repr(C)]
struct Tss {
    dwords: [u32; TSS_DWORDS],
}
impl Tss {
    const fn new() -> Self {
        Tss {
            dwords: [0; TSS_DWORDS],
        }
    }
}

#[repr(C, align(16))]
struct Gdt {
    entries: [u64; 5],
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct IstStack([u8; IST_STACK_SIZE]);

// Permanent tables. Zero-initialised, so they live in `.bss` (zeroed by
// `_start`); `init()` fills the live values at runtime through raw pointers.
static mut GDT: Gdt = Gdt { entries: [0; 5] };
static mut TSS: Tss = Tss::new();
static mut IST_STACKS: [IstStack; 3] = [IstStack([0; IST_STACK_SIZE]); 3];

/// Top-of-stack (highest, exclusive) address of IST stack `i` (0..3). Stacks
/// grow down; the array base is 16-aligned and each frame is a 16-multiple, so
/// the returned pointer is 16-aligned as the CPU expects.
unsafe fn ist_top(i: usize) -> u64 {
    let base = addr_of!(IST_STACKS) as u64;
    base + ((i + 1) * IST_STACK_SIZE) as u64
}

/// Build the two qwords of a 64-bit (Long Mode) TSS descriptor for `base`/
/// `limit`. Bit positions per Intel SDM Vol.3A Figure 7-4 / OSDev "GDT".
fn tss_descriptor(base: u64, limit: u32) -> (u64, u64) {
    let limit = limit as u64;
    let low = (limit & 0xFFFF)                       // Limit[15:0]
        | ((base & 0x00FF_FFFF) << 16)               // Base[23:0]
        | (TSS_ACCESS_AVAILABLE << 40)               // Access byte (0x89)
        | (((limit >> 16) & 0xF) << 48)              // Limit[19:16]
        // Flags nibble [55:52] = 0 (G=0 byte-granular, AVL=0)
        | (((base >> 24) & 0xFF) << 56); // Base[31:24]
    let high = (base >> 32) & 0xFFFF_FFFF; // Base[63:32]; high dword reserved (0)
    (low, high)
}

/// Install the permanent GDT + TSS: fill the IST tops, encode the TSS
/// descriptor at the runtime address of `TSS`, `lgdt`, reload CS + data
/// segments, and `ltr`. Called once from `super::install_traps()`.
pub(super) fn init() {
    unsafe {
        // 1. Fill the TSS: IST1..3 tops + disable the I/O permission bitmap
        //    (I/O-Map Base == sizeof(TSS) puts it past the segment limit).
        let tss = addr_of_mut!(TSS) as *mut u32;
        let s1 = ist_top(0);
        let s2 = ist_top(1);
        let s3 = ist_top(2);
        *tss.add(TSS_IST1) = s1 as u32;
        *tss.add(TSS_IST1 + 1) = (s1 >> 32) as u32;
        *tss.add(TSS_IST2) = s2 as u32;
        *tss.add(TSS_IST2 + 1) = (s2 >> 32) as u32;
        *tss.add(TSS_IST3) = s3 as u32;
        *tss.add(TSS_IST3 + 1) = (s3 >> 32) as u32;
        *tss.add(TSS_IOPB) = (size_of::<Tss>() as u32) << 16;

        // 2. Build the GDT: null, code, data, TSS descriptor (2 entries).
        let tss_base = addr_of!(TSS) as u64;
        let tss_limit = (size_of::<Tss>() - 1) as u32;
        let (tss_lo, tss_hi) = tss_descriptor(tss_base, tss_limit);
        let gdt = addr_of_mut!(GDT) as *mut u64;
        *gdt.add(0) = NULL_DESC;
        *gdt.add(1) = CODE_DESC;
        *gdt.add(2) = DATA_DESC;
        *gdt.add(3) = tss_lo;
        *gdt.add(4) = tss_hi;

        // 3. Load it and reload the segment registers / task register.
        let gdtr = DescriptorPointer {
            limit: (size_of::<Gdt>() - 1) as u16,
            base: addr_of!(GDT) as u64,
        };
        load_gdt_and_segments(addr_of!(gdtr));
    }
}

/// `lgdt` the new table, far-return to reload CS with the ring0 code selector
/// (loading an L=1 CS under EFER.LME|CR0.PG keeps us in 64-bit mode), reload
/// the data segments, then `ltr` the TSS selector.
///
/// (a) PRE: 64-bit long mode, `gdtr` points at a valid `DescriptorPointer`
///     whose GDT has compatible 0x08 code / 0x10 data and a 0x18 64-bit TSS.
///     POST: CS=0x08, DS/ES/SS/FS/GS=0x10, TR=0x18 against the new GDT.
/// (b) ABI: Intel syntax (Rust default). Uses the stack (push/`retfq`, balanced
///     so RSP nets zero); clobbers segment regs + scratch regs + flags; reads
///     the descriptor from memory. Sources: Intel SDM Vol.3A §2.4.1 (lgdt),
///     §3.4.3/§5.8.1 (CS reload / far transfer), §7.3 `ltr`; OSDev GDT Tutorial.
/// (c) Tested by: kernel M1 sequence (a #BP must dispatch + resume afterwards).
#[inline]
unsafe fn load_gdt_and_segments(gdtr: *const DescriptorPointer) {
    asm!(
        "lgdt [{gdtr}]",
        // Reload CS via a far return to label 2: push CS, push target RIP, retfq.
        "push {code}",
        "lea {tmp}, [rip + 2f]",
        "push {tmp}",
        "retfq",
        "2:",
        // Reload the data/stack segment registers with the ring0 data selector.
        "mov ds, {data:x}",
        "mov es, {data:x}",
        "mov ss, {data:x}",
        "mov fs, {data:x}",
        "mov gs, {data:x}",
        // Load the task register with the TSS selector (activates the IST).
        "ltr {tss:x}",
        gdtr = in(reg) gdtr,
        code = in(reg) KERNEL_CODE_SEL as u64,
        data = in(reg) KERNEL_DATA_SEL as u64,
        tss  = in(reg) TSS_SEL as u64,
        tmp  = lateout(reg) _,
    );
}
