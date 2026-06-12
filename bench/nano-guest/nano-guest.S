// =============================================================================
// Axis-A nano-guest — the trivial dual-note PVH + tb-boot "signal-and-halt"
// guest, booted by BOTH Firecracker (PVH) AND tb-vmm (tb-boot v0) from ONE
// binary, so the spawn->first-guest-byte delta isolates PURE VMM-spawn overhead.
//
// This is the SINGLE SOURCE OF TRUTH for the nano-guest machine code. It is
// consumed two ways, byte-for-byte identically:
//   * CI / nightly: `bench/nano-guest/src/main.rs` includes this file via
//     `global_asm!(include_str!("../nano-guest.S"))` and is linked with
//     `nano-guest.ld` by `cargo +nightly build -Zbuild-std` against
//     `targets/x86_64-yuva-none.json` (reuses the kernel toolchain exactly).
//   * Local / stable: `bench/nano-guest/build.sh` assembles+links this same
//     file with `clang`/`ld.lld` (no nightly/rustup needed) for well-formedness
//     checks and the Strategy-B fallback.
//
// It is NOT the kernel crate, so its hand assembly is allowed (the framekernel
// invariant — kernel crate has zero real unsafe blocks — is untouched: this
// file links into a standalone bench artifact, never into kernel/tb-hal).
//
// Boot contract (mirrors crates/tb-hal/src/arch/x86_64/boot.rs +
// kernel/linker/x86_64.ld, stripped to the irreducible signal-and-halt):
//   * Firecracker selects PVH SOLELY from the `.note.Xen` PHYS32_ENTRY note
//     (type 18, name "Xen"); it enters `pvh_start` in 32-bit protected mode,
//     paging OFF, ebx -> hvm_start_info, eax ignored (xen.org PVH ABI does NOT
//     require the 0x336ec578 eax magic). https://xenbits.xen.org/docs/unstable/misc/pvh.html
//   * tb-vmm requires the `.note.kboot` brand note (type 0x59550001, name
//     "YUVA", desc = u64 64-bit entry); it enters `tb_start` in 64-bit long
//     mode with paging ALREADY on (tb-vmm's identity tables) and
//     rdi -> TbBootInfo*.
//   * Both notes live in ONE PT_NOTE phdr; exactly one entry runs per boot.
//   * Image loads at 1 MiB (== Firecracker HIMEM_START == tb-vmm load addr);
//     ET_EXEC, vaddr == paddr.
//   * Serial = legacy 16550 COM1 @ I/O port 0x3F8 (THR), wired to host stdout
//     by BOTH VMMs. The guest's `out 0x3f8, al` surfaces as the first stdout
//     byte the host times against — the SAME fair event for both VMMs.
//
// Guest work is held at ~zero and byte-identical in intent under each ABI:
// emit ONE sentinel serial byte then park. The only difference is the
// irreducible 32-bit-PVH vs 64-bit-long-mode entry glue (a 32-bit `out` vs a
// 64-bit `out` — same one I/O exit), far below the VMM-spawn signal measured.
// =============================================================================

// Use Intel syntax with no `%` register prefixes. Rust's `global_asm!` already
// defaults to Intel, so re-asserting it here is a no-op on the CI/nightly path;
// it is REQUIRED on the local clang `.S` path (clang's integrated assembler
// defaults to AT&T). One source, both assemblers.
.intel_syntax noprefix

// -----------------------------------------------------------------------------
// PT_NOTE #1 — PVH: XEN_ELFNOTE_PHYS32_ENTRY (type 18, name "Xen").
// Byte-identical to crates/tb-hal/src/arch/x86_64/boot.rs (the note Firecracker
// already boots in CI). 4-byte aligned; desc = the 32-bit PVH entry `pvh_start`.
// -----------------------------------------------------------------------------
.section .note.Xen, "a", @note
.align 4
.long   4                       // n_namesz = sizeof("Xen\0")
.long   4                       // n_descsz = sizeof(.long entry)
.long   18                      // n_type   = XEN_ELFNOTE_PHYS32_ENTRY
.asciz  "Xen"                   // n_name   (4 bytes incl NUL; already aligned)
.long   pvh_start               // n_desc   = 32-bit physical PVH entry point

// -----------------------------------------------------------------------------
// PT_NOTE #2 — tb-boot v0: the brand note (type 0x59550001, name "YUVA").
// Byte-identical to boot.rs; sits in the SAME PT_NOTE phdr right after the Xen
// note. desc = the 64-bit entry `tb_start`. tb-vmm rejects any ELF lacking it
// (loader.rs LoaderError::MissingTbNote), so it MUST be present.
//
// !!! MIRRORS crates/brand/src/lib.rs (brand_upper!() / NOTE_NAMESZ /
// !!! NOTE_TYPE_ENTRY64): this .S cannot import Rust, so the FOUR brand-
// !!! bearing lines below (.long namesz / .long type / .asciz name) are the
// !!! ONE sanctioned mirror outside crates/brand -- change them TOGETHER.
// !!! CI guards the lockstep: bench.yml greps the built ELF's notes for the
// !!! brand name + note type (env BRAND / NOTE_TYPE_HEX, mirroring
// !!! scripts/project.env).
// -----------------------------------------------------------------------------
.section .note.kboot, "a", @note
.align 4
.long   5                       // n_namesz = sizeof("YUVA\0")  == brand NOTE_NAMESZ
.long   8                       // n_descsz = sizeof(u64 entry)
.long   0x59550001              // n_type   = TB_NOTE_TYPE_ENTRY64 (brand 'Y''U' + 0x0001)
.asciz  "YUVA"                  // n_name   ("YUVA\0", 5 bytes) == brand_upper!()
.align  4                       // pad the name field to a 4-byte boundary (5 -> 8)
.quad   tb_start                // n_desc   = 64-bit entry address (LE u64)

// -----------------------------------------------------------------------------
// `pvh_start` — Firecracker / PVH 32-bit entry.
// PRE: 32-bit protected mode, paging OFF, cr0=PE|ET, cr4=0, flat 4 GiB
//      cs/ds/es/ss, ebx -> hvm_start_info, eax ignored.
// WORK: one COM1 sentinel write, then park. NO GDT/paging/stack setup — it
//       never returns or calls anything, so it needs none.
// -----------------------------------------------------------------------------
.section .text._start, "ax", @progbits
.code32
.global pvh_start
pvh_start:
    cli
    mov     dx, 0x3f8           // COM1 THR (the 16550 both VMMs wire to stdout)
    mov     al, 0x41            // sentinel byte 'A' (== the existing FC bench)
    out     dx, al              // -> host reads first stdout byte = t_signal
    mov     al, 0x0a            // newline: flush the host's line-buffered serial
    out     dx, al              // (a lone byte never flushes FC's stdout; \n does)
.Lpvh_park:
    hlt
    jmp     .Lpvh_park

// -----------------------------------------------------------------------------
// `tb_start` — tb-vmm / tb-boot v0 64-bit entry.
// PRE: 64-bit long mode, paging ON (tb-vmm's identity tables), flat 64-bit CS,
//      rdi -> TbBootInfo*, rsi = 0, rflags = 0x2 (IF=0). NO setup needed.
// WORK: the SAME one COM1 sentinel write the PVH path emits (so the host-timed
//       event is identical for both VMMs), then ALSO latch tb-vmm's native
//       0x510 BootReady clock (the higher-fidelity in-process cross-check;
//       Firecracker has no 0x510 equivalent, so it is NEVER the ratio source).
//       Then park.
// -----------------------------------------------------------------------------
.section .text._tb_start, "ax", @progbits
.code64
.global tb_start
tb_start:
    cli
    mov     dx, 0x3f8           // COM1 THR — SAME fair event as the PVH path
    mov     al, 0x41            // sentinel byte 'A', observed identically to FC
    out     dx, al              // -> host reads first stdout byte = t_signal
    mov     al, 0x0a            // newline: same flush as the PVH path (dx still 0x3f8)
    out     dx, al              // symmetric guest output across both VMMs
    mov     dx, 0x510           // tb-vmm BootReady PIO (native --report-spawn)
    xor     al, al              // value ignored by the BootReady device
    out     dx, al              // latch tb-vmm's in-process spawn->ready Instant
.Ltb_park:
    hlt
    jmp     .Ltb_park
