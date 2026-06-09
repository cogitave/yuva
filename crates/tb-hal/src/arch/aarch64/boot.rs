//! aarch64 boot entry (`_start`): the EL-aware bring-up + the optional nVHE
//! EL2-monitor install, then the shared EL1 continuation (stack, `.bss`, the
//! initial `VBAR_EL1` arm, and the FDT handoff into `rust_main`).
//!
//! All assembly in TABOS is confined to `tb-hal`; this module is the aarch64
//! half of unit **A1/A2** in KERNEL-FOUNDATION-SPEC SS3, extended at **L2.0**
//! with the EL2->EL1 drop. It is compiled purely for its `global_asm!` side
//! effects -- nothing here is referenced from Rust; the linker keeps `_start`
//! via `ENTRY(_start)` + `KEEP()` in `kernel/linker/aarch64.ld`.
//!
//! The EL1 exception vector table lives in `vectors.rs` (M1); the resident EL2
//! monitor's vector table lives in `el2_vectors.rs` and its handler/facade in
//! `el2.rs` (L2.0). `_start` only *pre-arms* `VBAR_EL1` so a fault during early
//! boot is still vectored (the default policy halts); `mod.rs::install_traps()`
//! re-arms the same table from `rust_main` once the console is up (idempotent).
//!
//! EL-aware boot contract (HUGE blast radius -- obey exactly):
//!  * **QEMU `virt,virtualization=on`** enters the vCPU at **EL2h, MMU OFF,
//!    DAIF masked, x0 = FDT pointer**. `_start` installs a dormant nVHE EL2
//!    monitor (VBAR_EL2 + HCR_EL2.RW + the timer/cptr/stage-2 setup), records
//!    `BOOTED_AT_EL2 = 1`, then `eret`s down to **EL1h** so the existing
//!    M0..M18 chain runs at EL1 byte-for-byte. The monitor stays resident and
//!    is re-entered later by `el2_selftest()`'s bootstrap `HVC #0` (L2.0).
//!  * **Plain QEMU `virt`** (no virtualization) enters at **EL1h** directly;
//!    `_start` skips the whole EL2 block, leaves `BOOTED_AT_EL2 = 0`, and the
//!    L2.0 probe reports `El2Proof::Unavailable` (a green skip -- no HVC, no
//!    fault). Both entry ELs converge on the SAME EL1 continuation (label `1:`).
//!  * x0 = FDT is stashed in callee-saved **x19** at entry and restored to x0
//!    at the EL1 continuation, so the FDT/DTB handoff (M10 pmm, etc.) is
//!    byte-identical regardless of entry EL. The entry-EL flag rides in **x20**
//!    and is stored into `BOOTED_AT_EL2` only AFTER `.bss`-zero so it survives.
//!
//! EL2-setup register values (Linux `el2_setup.h`/`sysreg.h` subset for
//! cortex-a72 / GICv2 / softfloat -- re-verified, do NOT change without
//! re-reading the sources, cross-checked in `el2.rs`'s const-asserts):
//!  * `SCTLR_EL2 = 0x30C50830` -- INIT_SCTLR_EL2_MMU_OFF (RES1 bits, MMU off).
//!  * `HCR_EL2   = 1<<31`      -- RW=1 (EL1 is AArch64); VM=0 (stage-2 off),
//!                               TGE=0, HCD=0 (HVC enabled), IMO/FMO/AMO=0
//!                               (physical IRQs stay at EL1/VBAR_EL1, so M8 is
//!                               unaffected).
//!  * `CNTHCTL_EL2 = 0x3`      -- EL1PCTEN|EL1PCEN: EL1 physical timer/counter
//!                               NOT trapped to EL2 (required for M8's CNTP/
//!                               CNTPCT). `CNTVOFF_EL2 = 0`.
//!  * `CPTR_EL2  = 0x33FF`     -- nVHE RES1; no FP/copro traps to EL2.
//!  * `HSTR_EL2  = 0`, `VTTBR_EL2 = 0` -- stage-2 fully disabled.
//!  * `VPIDR_EL2 = MIDR_EL1`, `VMPIDR_EL2 = MPIDR_EL1` -- EL1 reads of those IDs
//!                               return the real values.
//!  * `VBAR_EL2  = __el2_exception_vectors` (el2_vectors.rs).
//!  * `SP_EL2    = __el2_stack_top` -- the dedicated 16 KiB monitor stack (a
//!                               single-accessor region the EL1 kernel never
//!                               references; see el2.rs's coherency note).
//!  * `SPSR_EL2  = 0x3C5`      -- EL1h + DAIF masked (INIT_PSTATE_EL1) for the
//!                               drop; `ELR_EL2` = the EL1 continuation `1:`.

use core::arch::global_asm;

// -- _start -----------------------------------------------------------------
// (a) PRE : EL2h (QEMU virt,virtualization=on) OR EL1h (plain virt); MMU OFF,
//           DAIF masked, x0 = FDT/DTB pointer. POST: a resident nVHE EL2 monitor
//           (when entered at EL2) + BOOTED_AT_EL2 recorded; SP = top of the
//           16 KiB boot stack (SP_EL1), .bss zeroed, VBAR_EL1 armed, control
//           tail-branched to rust_main(x0) with x0 (FDT) preserved as arg0.
// (b) ABI : clobbers x1, x2 (scratch); x0 stashed in x19 and restored; x20
//           carries the entry-EL flag; no SP_EL1 use before SP_EL1 is set; the
//           EL2 setup uses no stack. `b` (not `bl`) -- rust_main is `-> !`.
// (c) TEST: scripts/run-aarch64.sh asserts M0..M18 + the L2.0 `el2 OK` marker.
global_asm!(
    r#"
    .section .text._start, "ax"

    // -- _tb_start (tb-boot v0 / tb-vmm aarch64 entry) ----------------------
    // A SEPARATE entry symbol, ADDED ALONGSIDE _start (NOT replacing it): a
    // (future) tb-vmm aarch64 KVM_ARM backend resolves this address from the
    // .note.TABOS ELF note (emitted below) and lands the vCPU here via
    // KVM_SET_ONE_REG (PC=_tb_start, X0=TbBootInfo*). Under QEMU `virt` the
    // kernel still enters at _start (= e_entry) with x0=FDT and runs the #48
    // EL2->EL1 drop -- THIS path is not reached there, so the existing
    // M0..M18.2 + L2.0 `el2 OK` FDT chain is byte-for-byte unaffected.
    //
    // (a) PRE (frozen tb-boot v0 aarch64 contract; the host-side producer's
    //     KVM_SET_ONE_REG establishes it before the first KVM_RUN -- see
    //     tb_boot::aarch64): EL1h, MMU OFF, caches OFF, DAIF masked
    //     (PSTATE = 0x3c5), x0 = guest-physical TbBootInfo*, x1=x2=x3=0. A
    //     single, non-nested KVM_ARM vCPU boots directly at EL1, so -- UNLIKE
    //     _start -- this path runs NO EL2 monitor setup and never reads
    //     CurrentEL.
    // (b) POST: identical to the shared EL1 continuation's post-state, except
    //     rust_main's arg0 (x0) carries the TbBootInfo* (vs the FDT pointer);
    //     the kernel disambiguates the two paths at runtime via read_boot_magic.
    // (c) ABI: x0 is stashed in callee-saved x19 (restored as arg0 at `1:`);
    //     x20 = 0 records "no resident EL2 monitor" (-> BOOTED_AT_EL2 = 0, so
    //     el2_selftest() gracefully skips -- no bootstrap HVC, no fault). Ends
    //     in `b 1f` (a branch -- it never falls through into _start's EL2-aware
    //     bring-up below). The shared `1:` continuation sets SP, zeroes .bss,
    //     records w20, arms VBAR_EL1, restores x0 from x19, and enters rust_main.
    .globl _tb_start
_tb_start:
    mov  x19, x0                  // TbBootInfo* -> x19 (restored as arg0 at 1:)
    mov  x20, #0                  // tb-vmm path: no resident EL2 monitor
    b    1f                       // join the shared EL1 continuation (label 1:)

    .globl _start
_start:
    // Stash the FDT pointer (x0) in callee-saved x19 so it survives the
    // EL2->EL1 drop AND the .bss-zero, then is restored as rust_main's arg0.
    mov  x19, x0
    // Entry-EL flag, default 0 (entered at EL1 -- no EL2 monitor). Set to 1
    // only on the EL2 path once the monitor is armed.
    mov  x20, #0

    // Are we at EL2? CurrentEL holds the current EL in bits[3:2]. QEMU
    // `virt,virtualization=on` enters at EL2; a plain `virt` enters at EL1.
    mrs  x1, CurrentEL
    // DIAG: record raw CurrentEL[3:2] ASAP (before ANY branching) into a
    // .data static (nonzero init -- survives the later .bss zeroing; written
    // MMU-off, read under TCG where caches are not modeled). x2/x3 are dead.
    adrp x2, BOOT_ENTRY_EL
    add  x2, x2, :lo12:BOOT_ENTRY_EL
    lsr  x3, x1, #2
    strb w3, [x2]
    lsr  x1, x1, #2
    cmp  x1, #2
    b.ne 1f                       // not EL2: legacy direct-EL1 boot (x20 = 0)

    // ===== nVHE EL2 monitor setup (Linux init_el2_state subset) ============
    // SCTLR_EL2 = INIT_SCTLR_EL2_MMU_OFF (RES1 bits set; MMU off at EL2).
    movz x1, #0x0830
    movk x1, #0x30C5, lsl #16     // 0x30C50830
    msr  sctlr_el2, x1
    // HCR_EL2.RW = 1: the next lower EL (EL1) executes in AArch64 state. VM=0
    // (stage-2 off), TGE=0, HCD=0 (HVC from EL1 traps here), IMO/FMO/AMO=0
    // (physical IRQs stay at EL1, so M8's GICv2/CNTP path is unchanged).
    mov  x1, #1
    lsl  x1, x1, #31
    msr  hcr_el2, x1
    // CNTHCTL_EL2 = EL1PCTEN|EL1PCEN (0x3): do NOT trap EL1's physical timer/
    // counter to EL2 (M8 uses CNTP_*/CNTPCT_EL0). CNTVOFF_EL2 = 0.
    mov  x1, #0x3
    msr  cnthctl_el2, x1
    msr  cntvoff_el2, xzr
    // CPTR_EL2 = 0x33FF (nVHE RES1; no FP/copro traps to EL2). HSTR_EL2 = 0.
    movz x1, #0x33FF
    msr  cptr_el2, x1
    msr  hstr_el2, xzr
    // Stage-2 fully disabled: VTTBR_EL2 = 0.
    msr  vttbr_el2, xzr
    // EL1 reads of MIDR_EL1 / MPIDR_EL1 return the real (physical) IDs.
    mrs  x1, midr_el1
    msr  vpidr_el2, x1
    mrs  x1, mpidr_el1
    msr  vmpidr_el2, x1
    // VBAR_EL2 = the resident EL2 monitor vector table (el2_vectors.rs).
    adrp x1, __el2_exception_vectors
    add  x1, x1, :lo12:__el2_exception_vectors
    msr  vbar_el2, x1
    // SP_EL2 = top of the dedicated 16 KiB monitor stack. We are at EL2h, so
    // the current SP IS SP_EL2; the EL1 kernel never references this region.
    adrp x1, __el2_stack_top
    add  x1, x1, :lo12:__el2_stack_top
    mov  sp, x1
    // The monitor is armed: record it (threaded to BOOTED_AT_EL2 after bss-zero).
    mov  x20, #1
    // Drop to EL1h at the shared continuation (label 1:) via eret.
    adr  x1, 1f
    msr  elr_el2, x1
    mov  x1, #0x3c5               // SPSR_EL2 = EL1h + DAIF masked (INIT_PSTATE_EL1)
    msr  spsr_el2, x1
    isb
    eret

    // ===== EL1 continuation (shared by the EL2-drop and direct-EL1 paths) ===
1:
    // (1) Establish the boot stack (SP_EL1; linker guarantees 16-B alignment).
    adrp x1, __boot_stack_top
    add  x1, x1, :lo12:__boot_stack_top
    mov  sp, x1

    // (2) Zero .bss [__bss_start, __bss_end) eight bytes at a time. Both bounds
    //     are 16-byte aligned, so the doubleword stores never overrun.
    adrp x1, __bss_start
    add  x1, x1, :lo12:__bss_start
    adrp x2, __bss_end
    add  x2, x2, :lo12:__bss_end
0:  cmp  x1, x2
    b.hs 2f
    str  xzr, [x1], #8
    b    0b
2:

    // (3) Record the entry-EL flag (w20) into BOOTED_AT_EL2 -- AFTER .bss-zero
    //     so it is not wiped. el2_selftest() (el2.rs) reads it to gate the
    //     bootstrap HVC: 1 => probe, 0 => graceful skip (no HVC -> no fault).
    adrp x1, BOOTED_AT_EL2
    add  x1, x1, :lo12:BOOTED_AT_EL2
    strb w20, [x1]

    // (4) Pre-arm VBAR_EL1 with the M1 exception vector table (vectors.rs) and
    //     synchronize, so any early fault is vectored before we enter Rust.
    //     install_traps() re-arms this same table once the console is up.
    adrp x1, __exception_vectors
    add  x1, x1, :lo12:__exception_vectors
    msr  vbar_el1, x1
    isb

    // (5) Restore the boot pointer as AAPCS64 arg0 and enter safe Rust. On the
    //     _start path x19 = FDT/DTB; on the _tb_start path x19 = TbBootInfo*.
    //     rust_main disambiguates the two via tb_hal::read_boot_magic.
    mov  x0, x19
    b    rust_main
"#
);

// ===========================================================================
// tb-boot v0: the `.note.TABOS` ELF note carrying the `_tb_start` entry.
// ===========================================================================
// Mirrors the x86_64 TABOS note (crates/tb-hal/src/arch/x86_64/boot.rs): a
// (future) tb-vmm aarch64 KVM_ARM backend walks the kernel ELF's PT_NOTE
// segments, matches type 0x54420001 ("TABOS"), and jumps to the 8-byte LE entry
// in the descriptor (= `_tb_start`) -- it NEVER uses `e_entry` (which stays
// `_start`, the QEMU `virt` x0=FDT entry). Under QEMU the note is inert: QEMU
// `-kernel` enters at `e_entry`, ignoring notes entirely.
//
// kernel/linker/aarch64.ld places this note in a PT_NOTE phdr (and KEEP()s it,
// which also anchors `_tb_start` against --gc-sections -- the note's
// `.quad _tb_start` is the only reference to that entry from outside `.text`).
//
// AArch64 assembler idioms that DIFFER from the x86 note (do not "fix" to the
// x86 spelling):
//   * `%note` section type, not `@note`: on Arm `@` begins a comment, so the
//     ELFOSABI-safe section-type prefix is `%` (accepted by LLVM MC + GAS).
//   * `.balign 4`, not `.align 4`: on AArch64 `.align N` means 2^N bytes, so
//     `.align 4` would (wrongly) demand 16-byte alignment; `.balign 4` is the
//     literal 4-byte boundary the ELF note framing requires.
//
// Byte layout (consumer view, matches tb_boot::parse_entry64_note):
//   [ 0.. 4)  n_namesz = 6            (.long)   sizeof("TABOS\0")
//   [ 4.. 8)  n_descsz = 8            (.long)   sizeof(u64 entry)
//   [ 8..12)  n_type   = 0x54420001   (.long)   == TB_NOTE_TYPE_ENTRY64
//   [12..18)  "TABOS\0"               (.asciz)  name field
//   [18..20)  2 pad bytes             (.balign 4) name padded to 4
//   [20..28)  _tb_start as 8-byte LE  (.quad)   desc = the EL1 entry address
global_asm!(
    r#"
    .section .note.TABOS, "a", %note
    .balign 4
    .long   6                       // n_namesz = sizeof("TABOS\0")
    .long   8                       // n_descsz = sizeof(u64 entry)
    .long   0x54420001              // n_type   = TB_NOTE_TYPE_ENTRY64
    .asciz  "TABOS"                 // n_name   ("TABOS\0", 6 bytes)
    .balign 4                       // pad the name field to a 4-byte boundary
    .quad   _tb_start               // n_desc   = 64-bit EL1 entry (LE u64)
"#
);

/// Raw CurrentEL[3:2] recorded by `_start` BEFORE any EL branching. 0xFF =
/// entry did not pass through `_start` (e.g. the tb-vmm `_tb_start` path).
/// Nonzero initializer => .data placement, so the pre-.bss-zero store survives.
#[unsafe(no_mangle)]
pub(super) static BOOT_ENTRY_EL: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(0xFF);
