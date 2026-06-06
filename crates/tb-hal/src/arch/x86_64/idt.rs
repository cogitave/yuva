//! x86_64 IDT: 256 64-bit interrupt-gate descriptors pointing at the per-vector
//! thunks in `trap.rs`. All `unsafe`/asm stays in `tb-hal`; the kernel crate is
//! `#![forbid(unsafe_code)]` (KERNEL-FOUNDATION-SPEC §1).
//!
//! Descriptor bits are QUOTED from primary sources, not invented:
//!   * 64-bit IDT gate descriptor — 16 bytes laid out offset_low(16) /
//!     selector(16) / ist(8, bits[2:0]) / type_attr(8) / offset_mid(16) /
//!     offset_high(32) / reserved(32); `type_attr = 0x8E` means P=1, DPL=0,
//!     Type=0xE "64-bit Interrupt Gate": OSDev "Interrupt Descriptor Table"
//!     §"Structure on x86-64" == Intel SDM Vol.3A §6.14.1, Figure 6-8
//!     "64-Bit IDT Gate Descriptors".
//!   * IST field selects a Task-State-Segment stack (0 = none); we route #DF
//!     (vector 8) -> IST1, NMI (2) -> IST2, #MC (18) -> IST3 onto the stacks set
//!     up in `gdt.rs`: Intel SDM Vol.3A §6.14.5 "Interrupt Stack Table".

use core::arch::asm;
use core::mem::size_of;
use core::ptr::{addr_of, addr_of_mut};

use super::gdt::{DescriptorPointer, KERNEL_CODE_SEL};
use super::trap;

/// One 64-bit IDT gate descriptor (16 bytes). Field order == on-wire layout.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)] // fields are written, never read back by Rust
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}
impl IdtEntry {
    const fn missing() -> Self {
        IdtEntry {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    /// Point this gate at `handler`, running on IST stack `ist` (0 = current
    /// stack). type_attr 0x8E == Present, DPL 0, 64-bit interrupt gate.
    fn set(&mut self, handler: u64, ist: u8) {
        self.offset_low = handler as u16;
        self.offset_mid = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
        self.selector = KERNEL_CODE_SEL;
        self.ist = ist & 0x7;
        self.type_attr = 0x8E;
        self.reserved = 0;
    }
}

#[repr(C, align(16))]
struct Idt {
    entries: [IdtEntry; 256],
}

// Zero-initialised -> `.bss` (zeroed by `_start`); `init()` fills it at runtime.
static mut IDT: Idt = Idt {
    entries: [IdtEntry::missing(); 256],
};

/// Build all 256 gates from the `trap.rs` thunk table, route the IST-backed
/// vectors, then `lidt`. Called once from `super::install_traps()` AFTER the
/// GDT/TSS are live (the IST indices reference TSS stacks `gdt.rs` installs).
pub(super) fn init() {
    unsafe {
        let entries = addr_of_mut!(IDT) as *mut IdtEntry;
        let mut v = 0usize;
        while v < 256 {
            let ist = match v {
                8 => 1,  // #DF  -> IST1
                2 => 2,  // NMI  -> IST2
                18 => 3, // #MC  -> IST3
                _ => 0,  // everything else: current stack
            };
            let mut entry = IdtEntry::missing();
            entry.set(trap::thunk(v), ist);
            core::ptr::write(entries.add(v), entry);
            v += 1;
        }

        let idtr = DescriptorPointer {
            limit: (size_of::<[IdtEntry; 256]>() - 1) as u16, // 256*16 - 1 = 4095
            base: addr_of!(IDT) as u64,
        };
        // (a) PRE: `idtr` describes a 256-entry IDT. POST: IDTR loaded.
        // (b) ABI: `lidt m16&64`; reads memory (readonly), no stack, no flags.
        //     Intel SDM Vol.3A §2.4.3 / §6.10. Intel syntax (Rust default).
        // (c) Tested by: kernel M1 sequence (a #BP must vector through this IDT).
        asm!(
            "lidt [{}]",
            in(reg) addr_of!(idtr),
            options(readonly, nostack, preserves_flags),
        );
    }
}
