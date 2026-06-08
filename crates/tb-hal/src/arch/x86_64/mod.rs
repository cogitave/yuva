//! x86_64 architecture backend for `tb-hal`.
//!
//! Exposes the safe primitives that `tb-hal`'s public API
//! (`serial_init`, `serial_write_byte`, `serial_write_str`, `halt`,
//! `install_traps`, `breakpoint`) delegates to via `arch::mod`. ALL x86_64
//! `unsafe` and assembly is confined to this `arch::x86_64` subtree
//! (KERNEL-FOUNDATION-SPEC §1); every other crate is `#![forbid(unsafe_code)]`.
//!
//! M0 boot path is PVH: `boot` emits the `XEN_ELFNOTE_PHYS32_ENTRY` note and
//! the (bootstrap-only) 32->64 trampoline; `serial` is the 16550 COM1 driver.
//! MV (the L1 sovereignty rung) adds a SECOND x86_64 entry in `boot`: a TABOS
//! ELF note (PT_NOTE name "TABOS", type 0x54420001, desc = u64 `_tb_start`
//! address) plus the 64-bit `_tb_start` that the project's own `tb-vmm` jumps
//! to directly in long mode — NO PVH note, NO A0 trampoline on that path. Both
//! notes coexist in the PT_NOTE phdr and both entries coexist in `.text`:
//! QEMU/Firecracker use the Xen note, tb-vmm uses TABOS, one runs per boot.
//! M1 adds CPU trap handling: `gdt` installs a permanent flat 64-bit GDT + TSS
//! (IST stacks), `idt` installs the 256-gate IDT, and `trap` holds the entry
//! thunks + the extern "C" handler that dispatches into safe Rust policy.
//! M2 adds the cooperative context switch: `sched` holds the naked
//! `ctx_switch` (saves/restores ONLY the psABI Fig. 3.4 callee-saved set
//! {rbx, rbp, r12-r15} + rsp, callee-saved-on-stack model) and the
//! initial-frame fabricator that tb-hal's shared `Task`/`task_create`/
//! `yield_to` layer builds on.
//! M3 adds the MMU layer: `mmu` holds the privileged paging-register
//! wrappers (read/write CR3, `invlpg`, CR4.PGE toggle, RDMSR/WRMSR for
//! IA32_EFER.NXE) plus the in-HAL `mmu_init`/`mmu_selftest` that splice a
//! new 4 KiB mapping at 0x4000_0000 into the LIVE boot page tables and
//! verify a remap with `invlpg`.
//! M4 adds the user/ring boundary: `user` holds the ring3 entry (`iretq`
//! into a ring3 stub via the DPL3 user GDT descriptors + a valid `TSS.RSP0`),
//! the DPL=3 `int 0x80` IDT gate, the ring0 syscall entry/handler, and the
//! `user_demo` round-trip that maps a `U/S=1` code+stack page through the M3
//! tables, drops to ring3, takes the stub's syscall and returns the verdict.

// `_start`, the PVH note and the 32->64 trampoline live here. The module is
// pulled into the final link because the linker script's `ENTRY(_start)`
// turns `_start` into a needed symbol, forcing extraction from the rlib.
pub mod boot;
pub mod serial;

// M1 trap stack: GDT/TSS, IDT, and the trap entry/dispatch asm + handler.
pub mod gdt;
pub mod idt;
pub mod trap;

// M2 cooperative switch: naked ctx_switch + new-task stack fabrication.
pub mod sched;

// M3 MMU: privileged paging-register wrappers (CR3, CR4.PGE, INVLPG,
// RDMSR/WRMSR for IA32_EFER.NXE) + the in-HAL 4 KiB map/remap self-test that
// splices a TEST_VA = 0x4000_0000 mapping into the live boot page tables.
pub mod mmu;

// M4 user/ring boundary: DPL3 user GDT descriptors + TSS.RSP0 (gdt.rs), the
// DPL=3 `int 0x80` gate (idt.rs), and HERE the ring3 stub, `iretq`-to-ring3
// entry, ring0 syscall entry/handler, and the `user_demo` round-trip that
// maps a U/S=1 code+stack page and drops to ring3.
pub mod user;

// M6 physical frame allocator: the x86_64 boot memory-map reader (PVH
// `hvm_start_info.memmap` + tb-boot `TbBootInfo` regions) that feeds the shared
// intrusive free-frame stack in `crate::pmm`. The only x86_64 place the
// boot-info pointer is dereferenced for M6.
pub mod pmm;

pub use serial::{serial_init, serial_write_byte};

// `breakpoint()` is re-exported as part of tb-hal's public trap surface; the
// `int3` lives in `trap.rs`. `set_trap_hook`/`TrapInfo`/`TrapKind`/`TrapAction`
// and the `dispatch_trap` glue live at the crate root (`lib.rs`).
pub use trap::breakpoint;

// M2: the arch-internal primitives consumed by the shared task layer in
// `lib.rs` (`Task`, `task_create`, `yield_to`). Per-arch contract:
//   * `unsafe extern "C" fn ctx_switch(prev_sp_save: *mut usize, next_sp: usize)`
//     — save the CURRENT task's callee-saved context on its own stack, store
//     the resulting SP to `*prev_sp_save`, adopt `next_sp` and resume the
//     next task (callee-saved-on-stack model, xv6 swtch.S shape).
//   * `fn task_stack_init(stack: &mut [usize], entry: fn()) -> usize`
//     — fabricate a brand-new task's initial frame on `stack` so the FIRST
//     switch into it `ret`s into `entry`; returns the initial saved-SP handle
//     that `task_create` records for the first `yield_to`.
// (Same names + signatures as the aarch64 arm, so `arch/mod.rs` re-exports
// one uniform contract to `lib.rs`.)
pub use sched::{ctx_switch, task_stack_init};

// M3: the safe MMU surface, re-exported through `arch/mod.rs` so `lib.rs` can
// expose `tb_hal::mmu_init` / `tb_hal::mmu_selftest`. `mmu_init` programs
// IA32_EFER.NXE once after `install_traps`; `mmu_selftest` builds, proves and
// remaps the 4 KiB test mapping entirely inside tb-hal, returning pass/fail.
// (Same names + signatures as the aarch64 arm, one uniform contract.)
pub use mmu::{heap_window, map_heap_frames, mmu_init, mmu_selftest};

// M4: the safe user/ring surface, re-exported through `arch/mod.rs` so `lib.rs`
// can expose `tb_hal::user_demo`. Drops to ring3, runs the stub's `int 0x80`,
// handles it in ring0 and returns whether the syscall was observed from user
// mode with the expected arg. (Same name + signature as the aarch64 arm.)
pub use user::user_demo;

// M6: the x86_64 boot memory-map reader, re-exported through `arch/mod.rs` so
// `crate::pmm` can call `crate::arch::pmm_collect_regions`. Same name +
// signature as the aarch64 arm, one uniform contract.
pub use pmm::pmm_collect_regions;

use core::sync::atomic::{AtomicBool, Ordering};

/// Guards `install_traps()` so the permanent GDT/TSS/IDT are only built once
/// per vCPU even if it is called more than once.
static TRAPS_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Install real CPU exception/interrupt handling: load the permanent GDT+TSS
/// (with IST stacks) FIRST, then the IDT (whose #DF/NMI/#MC gates reference
/// those IST stacks). Idempotent; called once from `rust_main` via
/// `tb_hal::install_traps()`.
pub fn install_traps() {
    if TRAPS_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    // Order matters: the IDT's IST indices select TSS stacks the GDT installs.
    gdt::init();
    idt::init();
}

/// Halt the calling (single) vCPU forever.
///
/// Masks interrupts and parks the core in a `hlt` loop. Used as the M0
/// Definition-of-Done terminator after the marker is printed, as the fatal
/// (`TrapAction::Halt`) trap terminator, and as the `#[panic_handler]`
/// fallback in the kernel crate. Never returns.
#[inline]
pub fn halt() -> ! {
    loop {
        // (a) PRE: any CPU state. POST: interrupts masked, core parked; the
        //     function never observably returns (the surrounding loop re-arms
        //     `hlt` after any spurious NMI/SMI wake).
        // (b) ABI: no operands; clobbers nothing; nomem/nostack. `hlt` clears
        //     no caller state; `cli` only affects IF.
        // (c) Tested by: scripts/run-x86_64.sh (kernel halts after emitting
        //     its markers; the runner times out and scrapes COM1).
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack, preserves_flags));
        }
    }
}
