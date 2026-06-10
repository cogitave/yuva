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
 *   __boot_stack_top              -- initial SP (64 KiB stack, grows down)
 *   __exception_vectors           -- 2 KiB-aligned VBAR_EL1 table (in .text)
 * Symbols exported for crates/tb-hal/src/arch/aarch64/diag.rs (#65 guards):
 *   __boot_stack_guard_bottom     -- 4 KiB sacrificial guard BELOW the boot
 *                                    stack (between the .bss statics and
 *                                    __boot_stack_bottom)
 *   __el2_stack_guard_bottom      -- 4 KiB sacrificial guard BELOW the EL2
 *                                    stack (between __boot_stack_top and
 *                                    __el2_stack_bottom)
 * Symbols exported for crates/tb-hal/src/pmm.rs (M6 frame allocator):
 *   __image_start, __image_end    -- whole-image bounds; the frame allocator
 *                                    reserves [__image_start, __image_end) so it
 *                                    never hands out the image, its .bss (which
 *                                    holds M5's 2 MiB heap arena), or stacks.
 */

ENTRY(_start)

KERNEL_LMA = 0x40080000;

/* tb-boot v0: the TABOS note carrying `_tb_start` must live in a PT_NOTE phdr
 * so a (future) tb-vmm aarch64 KVM_ARM backend's PT_NOTE walk can discover the
 * kernel's EL1 entry (the consumer NEVER uses e_entry, which stays `_start`).
 * The note is file-backed in the `text` PT_LOAD AND exposed via PT_NOTE, the
 * same shape as kernel/linker/x86_64.ld. Under QEMU `virt` `-kernel` loads the
 * PT_LOADs and jumps to e_entry (= `_start`), ignoring notes -- so adding these
 * phdrs leaves the x0=FDT QEMU-virt boot byte-for-byte unchanged. */
PHDRS
{
    note PT_NOTE FLAGS(4);          /* R   : the TABOS _tb_start note          */
    text PT_LOAD FLAGS(5);          /* R E : .note.TABOS, .text, .rodata       */
    data PT_LOAD FLAGS(6);          /* R W : .data, .bss (stacks)              */
}

SECTIONS
{
    . = KERNEL_LMA;
    __image_start = .;

    /* tb-boot v0 TABOS note (name "TABOS", type 0x54420001, desc = u64
     * _tb_start). Emitted by crates/tb-hal/src/arch/aarch64/boot.rs; KEEP()
     * protects it (and, transitively, `_tb_start`) from --gc-sections. 4-byte
     * aligned per the ELF note framing. */
    .note.TABOS : ALIGN(4) {
        KEEP(*(.note.TABOS))
    } :text :note

    .text : ALIGN(0x800) {
        KEEP(*(.text._start))      /* boot entry -- must be e_entry           */
        KEEP(*(.text._vectors))    /* VBAR_EL1 table, self-aligned to 2 KiB   */
        KEEP(*(.text._el2_vectors))/* L2.0 VBAR_EL2 table, self-aligned 2 KiB */
        KEEP(*(.text._l2_guest_vectors)) /* L2.2 guest VBAR_EL1 table, 2 KiB-aligned */
        KEEP(*(.text._el2_nested_vectors)) /* aL2.4 nested-guest VBAR_EL1 table, 2 KiB-aligned */
        KEEP(*(.text._l2_vgic_vectors)) /* aL2.5 vGIC guest VBAR_EL1 table, 2 KiB-aligned */
        *(.text .text.*)
    } :text

    .rodata : ALIGN(8) {
        *(.rodata .rodata.*)
        *(.data.rel.ro .data.rel.ro.*)
        *(.got .got.plt)           /* empty under relocation-model=static     */
    } :text

    .data : ALIGN(8) {
        *(.data .data.*)
    } :data

    . = ALIGN(16);
    __bss_start = .;
    .bss (NOLOAD) : ALIGN(16) {
        *(.bss .bss.*)
        *(COMMON)
        /* #65 FIX (H1b boot-stack overflow): the -O0 boot chain (deepest in
         * the M5 heap path) was measured running SP up to ~0x280 bytes BELOW
         * the old 16 KiB stack's bottom, silently stomping whichever .bss
         * statics the build's symbol order parked there (CARGO_INCREMENTAL=0
         * layouts put LIVE statics first -> the three CI-only failure modes).
         * Three defenses, all zero runtime cost (pure NOLOAD .bss):
         *   1. the boot stack grows 16 -> 64 KiB (matching the x86_64 boot
         *      stack) and the EL2 monitor stack 16 -> 32 KiB;
         *   2. an explicit 4 KiB SACRIFICIAL GUARD sits between the .bss
         *      statics and __boot_stack_bottom, so the first KiBs of any
         *      future overflow land in dead, canary-painted memory instead
         *      of live statics;
         *   3. a second 4 KiB guard sits between __boot_stack_top and
         *      __el2_stack_bottom, so an EL2-monitor stack overflow cannot
         *      silently stomp the boot stack's top.
         * tb-hal's diag.rs paints both guards with the red-zone pattern and
         * re-checks them on every timer tick + milestone checkpoint (loud,
         * one-time-latched serial line on a breach; silent when healthy). */
        . = ALIGN(16);
        __boot_stack_guard_bottom = .;
        . = . + 0x1000;            /* 4 KiB canary guard below the boot stack */
        __boot_stack_bottom = .;
        . = . + 0x10000;           /* 64 KiB boot stack (SP_EL1)              */
        __boot_stack_top = .;
        . = ALIGN(16);
        __el2_stack_guard_bottom = .;
        . = . + 0x1000;            /* 4 KiB canary guard below the EL2 stack  */
        __el2_stack_bottom = .;
        . = . + 0x8000;            /* L2.0: 32 KiB resident EL2-monitor stack */
        __el2_stack_top = .;       /* SP_EL2; single-accessor, EL1 never used */
    } :data
    . = ALIGN(16);
    __bss_end = .;

    . = ALIGN(4096);
    __image_end = .;

    /DISCARD/ : {
        *(.eh_frame .eh_frame_hdr)
        *(.note.gnu.*)             /* drop GNU property/build-id notes, but    */
                                   /* KEEP .note.TABOS (the _tb_start entry)   */
        *(.comment)
        *(.ARM.attributes)
        *(.ARM.exidx .ARM.exidx.*)
    }
}
