/* Axis-A nano-guest linker script — a minimal clone of kernel/linker/x86_64.ld,
 * stripped to the dual-note PT_NOTE phdr + a single text PT_LOAD. The nano-guest
 * has NO .data / .bss / page-tables / stack (neither entry calls anything), so
 * only two program headers exist: PT_NOTE (the two boot notes) and one PT_LOAD
 * (the notes + the two entry stubs), loaded at 1 MiB.
 *
 * Load address = 1 MiB (0x0010_0000) == Firecracker HIMEM_START == tb-vmm load
 * addr. ET_EXEC, vaddr == paddr (no AT()), so both loaders copy the PT_LOAD to
 * p_paddr and the per-ABI entry runs identity-addressed.
 *
 * `pvh_start` (32-bit, .text._start) is the PVH entry Firecracker reads from the
 * Xen note; `tb_start` (64-bit, .text._tb_start) is the entry tb-vmm reads from
 * the brand (YUVA) note. ENTRY(pvh_start) sets e_entry for completeness
 * (Firecracker PVH ignores e_entry and uses the note; tb-vmm ignores e_entry
 * entirely and uses the brand note), so e_entry never decides the boot. The
 * `.note.kboot` SECTION name is brand-NEUTRAL build plumbing (consumers read
 * the in-note name field), so this .ld never needs another rename.
 */

ENTRY(pvh_start)
OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)

PHDRS
{
    note PT_NOTE FLAGS(4);          /* R   : the Xen + brand boot notes        */
    text PT_LOAD FLAGS(5);          /* R E : .note.*, .text                    */
}

SECTIONS
{
    . = 1M;                          /* 0x0010_0000 */
    __image_start = .;

    /* Both notes are file-backed (in the text PT_LOAD) AND exposed via PT_NOTE.
     * KEEP() protects them from --gc-sections; the `.quad tb_start` desc is the
     * ONLY reference to the 64-bit entry, so KEEP also anchors it. 4-byte
     * aligned (loaders mis-pad notes at other alignments). */
    .note.Xen : ALIGN(4) {
        KEEP(*(.note.Xen))
    } :text :note

    .note.kboot : ALIGN(4) {
        KEEP(*(.note.kboot))
    } :text :note

    .text : ALIGN(16) {
        KEEP(*(.text._start))        /* pvh_start (32-bit PVH entry) first      */
        KEEP(*(.text._tb_start))     /* tb_start (64-bit tb-boot entry)         */
        *(.text .text.*)
    } :text

    . = ALIGN(4096);
    __image_end = .;

    /DISCARD/ : {
        *(.eh_frame) *(.eh_frame_hdr)
        *(.note.gnu.*) *(.comment)
        *(.dynamic) *(.dynsym) *(.dynstr) *(.hash) *(.gnu.hash)
        *(.interp) *(.rela .rela.*)
        *(.data .data.*) *(.bss .bss.*) *(COMMON)
        *(.got) *(.got.plt)
    }
}
