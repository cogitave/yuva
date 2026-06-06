//! x86_64 PVH bootstrap: the A0 32->64 trampoline + the A1 `_start` entry.
//!
//! **Bootstrap-only (M0).** Per KERNEL-FOUNDATION-SPEC §2/§3 (unit A0) the
//! 32->64 trampoline is *deleted* once `tb-vmm` / `tb-boot v0` enters directly
//! in 64-bit long mode. This is the ONLY x86_64 boot assembly in TABOS.
//!
//! Boot contract (verified facts — obey exactly):
//!  * PVH "x86/HVM direct boot ABI": QEMU `-kernel` and Firecracker select PVH
//!    via the `XEN_ELFNOTE_PHYS32_ENTRY` ELF note (type **18**, name **"Xen"**,
//!    desc = 32-bit physical entry point). The note must sit in a `PT_NOTE`
//!    phdr (see kernel/linker/x86_64.ld).
//!      - https://xenbits.xen.org/docs/unstable/misc/pvh.html
//!      - xen/include/public/elfnote.h  (`#define XEN_ELFNOTE_PHYS32_ENTRY 18`)
//!      - note byte layout cross-checked vs Google's
//!        cloud-hypervisor/rust-hypervisor-firmware `src/pvh.rs`.
//!  * On entry the vCPU is in **32-bit protected mode, paging OFF**, with
//!    `cr0 = PE|ET` (all other writable bits clear), `cr4 = 0`, flat 4 GiB
//!    cs/ds/es/ss, and **`%ebx` -> `hvm_start_info`** (pvh.html).
//!  * `hvm_start_info` lives below 4 GiB; magic `0x336ec578` ("xEn3").
//!    - xen/include/public/arch-x86/hvm/start_info.h.
//!
//! The kernel image is loaded at 1 MiB (0x0010_0000); serial is legacy 16550
//! COM1 @ I/O port 0x3F8 (see serial.rs).

use core::arch::global_asm;

global_asm!(
r#"
// ===========================================================================
// PVH ELF note: XEN_ELFNOTE_PHYS32_ENTRY (type 18, name "Xen")
// (a) PRE: linked into a PT_NOTE phdr. POST: QEMU/Firecracker read `desc` and
//     enter at `_start` in 32-bit protected mode, paging off, ebx->start_info.
// (b) ABI: pure data; namesz=4 ("Xen\0"), descsz=4 (.long entry), type=18;
//     4-byte aligned (QEMU mis-pads notes when alignment != 4).
// (c) Tested by: scripts/run-x86_64.sh (the whole PVH boot path under QEMU).
// ===========================================================================
.section .note.Xen, "a", @note
.align 4
.long   4                       // n_namesz = sizeof("Xen\0")
.long   4                       // n_descsz = sizeof(.long entry)
.long   18                      // n_type   = XEN_ELFNOTE_PHYS32_ENTRY
.asciz  "Xen"                    // n_name   (4 bytes incl NUL; already aligned)
.long   _start                  // n_desc   = 32-bit physical entry point

// ---------------------------------------------------------------------------
// Boot GDT: flat, with a 64-bit code segment, used for the far return into
// long mode. The PVH ABI states the OS sets up its own GDT.
// ---------------------------------------------------------------------------
.section .rodata
.align 8
__boot_gdt64:
    .quad 0x0000000000000000    // 0x00 null
    .quad 0x00209A0000000000    // 0x08 64-bit code (L=1,P=1,DPL=0,exec/read)
    .quad 0x0000920000000000    // 0x10 data        (P=1,DPL=0,read/write)
__boot_gdt64_end:
.align 8
__boot_gdt64_ptr:
    .short __boot_gdt64_end - __boot_gdt64 - 1
    .long  __boot_gdt64         // 32-bit base: read by the 32-bit `lgdt`

// ---------------------------------------------------------------------------
// Boot scratch (NOBITS). Placed by the linker BEFORE __bss_start so the
// .bss-clear never wipes the live page tables. CR3 needs 4 KiB alignment.
// ---------------------------------------------------------------------------
.section .boot.pagetables, "aw", @nobits
.align 4096
__boot_pml4: .skip 4096
__boot_pdpt: .skip 4096
__boot_pd:   .skip 4096

.section .boot.stack, "aw", @nobits
.align 16
__boot_stack_bottom: .skip 0x10000     // 64 KiB boot stack
__boot_stack_top:

// ===========================================================================
// A1 `_start` (32-bit PVH entry) + A0 32->64 trampoline.
// (a) PRE: 32-bit protected mode, paging OFF, cr0=PE|ET, cr4=0, flat segments,
//     ebx->hvm_start_info. POST: 64-bit long mode, identity map [0,1GiB),
//     .bss zeroed, rsp on boot stack (16-aligned), rdi=hvm_start_info, then
//     `call rust_main` (rust_main is `-> !`).
// (b) ABI: SysV/x86_64. Builds its own GDT/CR3/EFER.LME/CR0.PG; clobbers all
//     GPRs; preserves ebx until it is moved into rdi (arg0) just before the
//     call; aligns rsp to 16 before `call` (callee sees rsp%16==8).
// (c) Tested by: scripts/run-x86_64.sh (asserts "hello from rust_main\n").
// ===========================================================================
.section .text._start, "ax", @progbits
.code32
.global _start
_start:
    cli
    cld
    lea     esp, [__boot_stack_top]     // 32-bit stack for the far return

    // Zero PML4+PDPT+PD (3 * 4096 bytes) so no stale entry is ever "present".
    lea     edi, [__boot_pml4]
    xor     eax, eax
    mov     ecx, 3072                   // (4096*3)/4 dwords
    rep     stosd

    // PML4[0] = &PDPT | PRESENT|WRITE   (high dword stays 0 from the zeroing)
    lea     edi, [__boot_pml4]
    lea     eax, [__boot_pdpt]
    or      eax, 0x3
    mov     [edi], eax

    // PDPT[0] = &PD | PRESENT|WRITE
    lea     edi, [__boot_pdpt]
    lea     eax, [__boot_pd]
    or      eax, 0x3
    mov     [edi], eax

    // PD[i] = (i * 2 MiB) | PRESENT|WRITE|PS  ->  identity-map [0, 1 GiB)
    lea     edi, [__boot_pd]
    mov     eax, 0x83                   // PRESENT|WRITE|PS (2 MiB page)
    mov     ecx, 512
.Lpd_fill:
    mov     [edi], eax                  // low dword = phys | flags
    add     eax, 0x200000               // += 2 MiB
    add     edi, 8                      // next 8-byte PD entry
    dec     ecx
    jnz     .Lpd_fill

    // CR4.PAE (bit 5) - required before enabling long-mode paging.
    mov     eax, cr4
    or      eax, (1 << 5)
    mov     cr4, eax

    // CR3 = PML4 physical base.
    lea     eax, [__boot_pml4]
    mov     cr3, eax

    // EFER.LME (IA32_EFER, MSR 0xC000_0080, bit 8).
    mov     ecx, 0xC0000080
    rdmsr
    or      eax, (1 << 8)
    wrmsr

    // CR0.PG (bit 31); PE|ET are already set by PVH. Paging now on.
    mov     eax, cr0
    or      eax, (1 << 31)
    mov     cr0, eax

    // Load the 64-bit GDT and far-RET into the 64-bit code segment (sel 0x08).
    // Loading a CS with L=1 while EFER.LME=1 & CR0.PG=1 activates 64-bit mode.
    lgdt    [__boot_gdt64_ptr]
    push    0x08                        // CS selector
    lea     eax, [.Llong_mode]
    push    eax                         // 32-bit EIP target (< 4 GiB)
    retf

.code64
.Llong_mode:
    // Reload data/stack selectors against our GDT (sel 0x10).
    mov     ax, 0x10
    mov     ss, ax
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax

    lea     rsp, [rip + __boot_stack_top]

    // Clear .bss : [__bss_start, __bss_end). Excludes the page tables/stack.
    lea     rdi, [rip + __bss_start]
    lea     rcx, [rip + __bss_end]
    sub     rcx, rdi
    xor     eax, eax
    rep     stosb

    // hvm_start_info pointer: was in ebx, becomes SysV arg0 (rdi). It is a
    // sub-4 GiB physical address, so `mov edi, ebx` zero-extends correctly.
    mov     edi, ebx

    and     rsp, -16                    // SysV: 16-byte aligned before `call`
    call    rust_main                   // extern "C" fn rust_main(usize) -> !

    // rust_main is `-> !`; belt-and-suspenders halt if it ever returns.
.Lhalt:
    cli
    hlt
    jmp     .Lhalt
"#
);
