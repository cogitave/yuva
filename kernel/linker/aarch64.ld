/* kernel/linker/aarch64.ld
 *
 * Link script for the M0 "boot bring-up" image on the QEMU `virt` board.
 *
 * Load address: QEMU `virt` DRAM base is 0x4000_0000. We link the image at
 * +512 KiB (0x4008_0000) so the low DRAM window stays free for the FDT/DTB
 * that QEMU stages near RAM base -- its pointer is handed to `_start` in x0.
 * 0x4008_0000 mirrors the classic arm64 Image TEXT_OFFSET and is the
 * conventional load address for `-kernel <ELF>` on `virt`. QEMU loads each
 * PT_LOAD at its p_paddr and jumps to e_entry (= `_start`).
 *
 * (The Firecracker aarch64 microVM uses a different base: DRAM_START
 *  0x8000_0000 + 2 MiB = 0x8020_0000. That is a separate run profile / link
 *  script, landed alongside the FDT-driven UART -- see BUILD.md.)
 *
 * Symbols exported for crates/tb-hal/src/arch/aarch64/boot.rs (`_start`):
 *   __bss_start, __bss_end        -- .bss bounds, zeroed at boot
 *   __boot_stack_top              -- initial SP (16 KiB stack, grows down)
 *   __exception_vectors           -- 2 KiB-aligned VBAR_EL1 table (in .text)
 */

ENTRY(_start)

KERNEL_LMA = 0x40080000;

SECTIONS
{
    . = KERNEL_LMA;

    .text : ALIGN(0x800) {
        KEEP(*(.text._start))      /* boot entry -- must be e_entry           */
        KEEP(*(.text._vectors))    /* VBAR_EL1 table, self-aligned to 2 KiB   */
        *(.text .text.*)
    }

    .rodata : ALIGN(8) {
        *(.rodata .rodata.*)
        *(.data.rel.ro .data.rel.ro.*)
        *(.got .got.plt)           /* empty under relocation-model=static     */
    }

    .data : ALIGN(8) {
        *(.data .data.*)
    }

    . = ALIGN(16);
    __bss_start = .;
    .bss (NOLOAD) : ALIGN(16) {
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __boot_stack_bottom = .;
        . = . + 0x4000;            /* 16 KiB boot stack                       */
        __boot_stack_top = .;
    }
    . = ALIGN(16);
    __bss_end = .;

    /DISCARD/ : {
        *(.eh_frame .eh_frame_hdr)
        *(.note .note.*)
        *(.comment)
        *(.ARM.attributes)
        *(.ARM.exidx .ARM.exidx.*)
    }
}
