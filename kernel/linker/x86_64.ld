/* tb-hal x86_64 linker script - PVH ELF image, loaded at 1 MiB.
 *
 * Boot contract (verified): the image is an ELF that QEMU (-kernel) and
 * Firecracker boot via the Xen "x86/HVM direct boot ABI" (PVH). Selection is
 * driven SOLELY by the XEN_ELFNOTE_PHYS32_ENTRY note (type 18, name "Xen"),
 * which MUST live in a PT_NOTE program header.
 *   Sources: https://xenbits.xen.org/docs/unstable/misc/pvh.html
 *            xen/include/public/elfnote.h  ("notes ... live in a PT_NOTE
 *            segment and have \"Xen\" in the name field"; PHYS32_ENTRY == 18)
 *
 * Load address = 1 MiB (0x0010_0000) == Firecracker HIMEM_START. ET_EXEC,
 * vaddr == paddr (no AT()), so the PVH loader copies each PT_LOAD to p_paddr
 * and the 32-bit entry runs identity-addressed with paging off.
 */

ENTRY(_start)
OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)

PHDRS
{
    note PT_NOTE FLAGS(4);          /* R   : the Xen PHYS32_ENTRY note        */
    text PT_LOAD FLAGS(5);          /* R E : .note.Xen, .text, .rodata        */
    data PT_LOAD FLAGS(6);          /* R W : .data, .bss (page tables, stack) */
}

SECTIONS
{
    . = 1M;                          /* 0x0010_0000 */
    __image_start = .;

    /* The note is file-backed (in the text PT_LOAD) AND exposed via PT_NOTE.
     * KEEP() protects it from --gc-sections. 4-byte aligned: some loaders
     * (QEMU) mis-calculate note padding when alignment != 4. */
    .note.Xen : ALIGN(4) {
        KEEP(*(.note.Xen))
    } :text :note

    /* MV / tb-boot v0: the brand note (PT_NOTE name "YUVA", type 0x59550001 --
     * both derived from crates/brand) sits in the SAME PT_NOTE segment, right
     * after the Xen note. tb-vmm iterates PT_NOTE and matches the brand type to
     * find the kernel's 64-bit entry; QEMU/Firecracker match the Xen note (type
     * 18) and ignore this one. KEEP() also anchors `_tb_start` against
     * --gc-sections: the note's `.quad _tb_start` desc is the ONLY reference to
     * that entry. The SECTION name `.note.kboot` is brand-NEUTRAL build
     * plumbing (PT_NOTE walkers read the in-note name field, never the section
     * name), so this .ld never needs another rename.
     * Source: tb-boot v0 ABI (crates/tb-boot); mirrors XEN_ELFNOTE_PHYS32_ENTRY. */
    .note.kboot : ALIGN(4) {
        KEEP(*(.note.kboot))
    } :text :note

    .text : ALIGN(16) {
        *(.text._start)
        *(.text .text.*)
    } :text

    .rodata : ALIGN(16) {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    } :text

    . = ALIGN(4096);
    .data : ALIGN(16) {
        *(.data .data.*)
        *(.sdata .sdata.*)
        *(.got) *(.got.plt)
    } :data

    /* NOBITS. The boot page tables (CR3 root) and the boot stack are placed
     * FIRST, OUTSIDE the [__bss_start, __bss_end) window, so the _start
     * .bss-clear can never zero the page tables we are actively running on.
     * Guest RAM is zero at VM start, and _start additionally zeroes the
     * three table pages before use. */
    .bss (NOLOAD) : ALIGN(4096) {
        *(.boot.pagetables)
        *(.boot.stack)
        __bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        __bss_end = .;
    } :data

    . = ALIGN(4096);
    __image_end = .;

    /DISCARD/ : {
        *(.eh_frame) *(.eh_frame_hdr)
        *(.note.gnu.*) *(.comment)
        *(.dynamic) *(.dynsym) *(.dynstr) *(.hash) *(.gnu.hash)
        *(.interp) *(.rela .rela.*)
    }
}
