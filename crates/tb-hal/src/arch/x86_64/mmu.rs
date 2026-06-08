//! x86_64 MMU layer (M3): privileged paging-register wrappers + the in-HAL
//! 4 KiB map/remap self-test spliced into the LIVE boot page tables.
//!
//! M0's PVH trampoline (boot.rs) built a three-table boot hierarchy —
//! `__boot_pml4[0] -> __boot_pdpt[0] -> __boot_pd[0..512]`, identity-mapping
//! [0, 1 GiB) with 2 MiB pages — and loaded it into CR3. M3 does NOT replace
//! that hierarchy; it EXTENDS it at runtime through the shared typed table
//! layer ([`crate::mmu::PageTable512`]) plus static 4 KiB frames in `.bss`:
//!
//!  * [`mmu_init`] — set IA32_EFER.NXE (MSR `0xC000_0080`, bit 11) so bit 63
//!    of a paging entry becomes the architectural execute-disable (XD) bit
//!    instead of a reserved bit that would #PF. IA32_PAT (MSR `0x277`) keeps
//!    its power-up default (acceptable for M3; PAT entry 0 = WB).
//!  * [`mmu_selftest`] — walk CR3 -> PML4[0] to the live boot PDPT; splice a
//!    NEW 4 KiB mapping for `TEST_VA = 0x4000_0000` (1 GiB: the first byte
//!    OUTSIDE the boot identity map, so PDPT index 1 is vacant) through two
//!    static tables (PDPT[1] -> TEST_PD, PD[0] -> TEST_PT, PT[0] -> FRAME_A);
//!    prove the mapping by writing a magic THROUGH `TEST_VA` and reading it
//!    back through FRAME_A's identity address; then RETARGET the leaf PTE to
//!    FRAME_B + `invlpg` and prove the remap by reading FRAME_B's magic
//!    through `TEST_VA`. Splicing into the live hierarchy needs no CR3
//!    reload; only the present-leaf change requires `invlpg`.
//!
//! Verified facts (primary sources; every bit value cross-checked against
//! Linux v6.6 headers, which transcribe the same SDM tables):
//!  * Paging-entry format — Intel SDM Vol 3A §4.5, Table 4-15 ff. (PML4E /
//!    PDPTE / PDE / PTE): bit 0 = P (present), bit 1 = R/W, bit 7 = PS (page
//!    size: 1 GiB at PDPTE / 2 MiB at PDE level), bit 63 = XD (execute
//!    disable; only defined when EFER.NXE = 1, reserved otherwise),
//!    physical-address field = bits 51:12. Linux
//!    `arch/x86/include/asm/pgtable_types.h`: `_PAGE_BIT_PRESENT 0`,
//!    `_PAGE_BIT_RW 1`, `_PAGE_BIT_PSE 7`, `_PAGE_BIT_NX 63` ("No execute:
//!    only valid after cpuid check").
//!  * EFER / PAT — SDM Vol 4 Table 2-2: IA32_EFER = MSR `0xC000_0080` with
//!    NXE = bit 11; IA32_PAT = MSR `0x277`. Linux
//!    `arch/x86/include/asm/msr-index.h`: `MSR_EFER 0xc0000080`,
//!    `_EFER_NX 11`, `MSR_IA32_CR_PAT 0x00000277`.
//!  * INVLPG — SDM Vol 2A "INVLPG — Invalidate TLB Entries": invalidates any
//!    TLB entry for the page containing the memory operand. SDM Vol 3A
//!    §4.10.4.2 requires invalidation after modifying a PRESENT entry that
//!    may be cached; §4.10.4.3 permits SKIPPING it for a 0 -> 1 P-flag
//!    transition (the TLB never caches not-present entries).
//!  * CR4.PGE = bit 7 — SDM Vol 3A §2.5 "Control Registers"; Linux
//!    `arch/x86/include/uapi/asm/processor-flags.h`: `X86_CR4_PGE_BIT 7`.
//!    Clearing then re-setting PGE is the architectural "flush ALL TLB
//!    entries, global included" idiom (SDM Vol 3A §4.10.4.1).
//!  * Technique — OSDev wiki "Paging" / "x86-64" (splice-into-live-tables +
//!    invalidate-on-modify; the wiki mirrors the SDM rules above).

use core::arch::asm;
use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};

use crate::mmu::{
    entry_addr, entry_is_valid, level_index, make_entry, PageTable512, ENTRIES, PAGE_SIZE,
    SHIFT_1G, SHIFT_2M, SHIFT_4K, SHIFT_512G,
};

// ---------------------------------------------------------------------------
// Architectural constants (verified — see module header).
// ---------------------------------------------------------------------------

/// IA32_EFER MSR address (SDM Vol 4 Table 2-2; Linux `MSR_EFER`).
const MSR_EFER: u32 = 0xC000_0080;

/// IA32_EFER.NXE — bit 11, "Execute Disable Bit Enable" (Linux `_EFER_NX`).
const EFER_NXE: u64 = 1 << 11;

/// CR4.PGE — bit 7, "Page Global Enable" (Linux `X86_CR4_PGE_BIT`).
const CR4_PGE: u64 = 1 << 7;

/// Paging-entry bit 0: Present (SDM Table 4-15; Linux `_PAGE_BIT_PRESENT`).
const PTE_P: u64 = 1 << 0;

/// Paging-entry bit 1: Read/Write (SDM Table 4-15; Linux `_PAGE_BIT_RW`).
const PTE_RW: u64 = 1 << 1;

/// Paging-entry bit 63: Execute-Disable / XD (architectural only because
/// `mmu_init` set IA32_EFER.NXE; SDM Table 4-15; Linux `_PAGE_BIT_NX`). The M7
/// kernel-heap leaves set it — the heap holds data, never executable code.
const PTE_NX: u64 = 1 << 63;

/// M12 paging-entry bit 2: User/Supervisor — MUST be 1 at EVERY level of the
/// walk for ring3 access (SDM Vol.3A §4.6; Linux `_PAGE_BIT_USER 2`). Set on the
/// agent's user code/stack leaves AND every intermediate table reaching them.
const PTE_US: u64 = 1 << 2;

/// Paging-entry bit 3: Page-Write-Through (PWT). With PCD it selects the PAT
/// index; M8 maps the LAPIC MMIO page with `PWT|PCD` = PAT entry 3 = strong-UC
/// (the power-up IA32_PAT default `mmu_init` kept) so device reads/writes are
/// uncacheable (SDM Vol 3A §11.12.4, Table 11-11; Linux `_PAGE_BIT_PWT 3`).
const PTE_PWT: u64 = 1 << 3;

/// Paging-entry bit 4: Page-Cache-Disable (PCD). See [`PTE_PWT`] (Linux
/// `_PAGE_BIT_PCD 4`).
const PTE_PCD: u64 = 1 << 4;

/// Physical-address field of any paging entry: bits 51:12 (SDM Table 4-15).
/// Masking with it also strips flag/ignored bits (and XD) when walking.
const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// The M3 test virtual address: 1 GiB — the first address OUTSIDE the boot
/// identity map (boot maps exactly [0, 1 GiB)), so its translation MUST come
/// from the freshly spliced tables and can never be satisfied by a stale
/// boot-table entry.
const TEST_VA: usize = 0x4000_0000;

/// `TEST_VA`'s PML4 index — VA bits 47:39 = 0 (shared with the boot map).
const PML4_IDX: usize = (TEST_VA >> 39) & 0x1FF;

/// `TEST_VA`'s PDPT index — VA bits 38:30 = 1 (the VACANT second-GiB slot).
const PDPT_IDX: usize = (TEST_VA >> 30) & 0x1FF;

/// `TEST_VA`'s PD index — VA bits 29:21 = 0.
const PD_IDX: usize = (TEST_VA >> 21) & 0x1FF;

/// `TEST_VA`'s PT index — VA bits 20:12 = 0.
const PT_IDX: usize = (TEST_VA >> 12) & 0x1FF;

/// Magic the self-test writes THROUGH `TEST_VA` into frame A (b"M3frameA").
const MAGIC_A: u64 = 0x4D33_6672_616D_6541;

/// Magic pre-seeded into frame B via its identity address and read back
/// THROUGH `TEST_VA` after the remap (b"M3frameB").
const MAGIC_B: u64 = 0x4D33_6672_616D_6542;

// ---------------------------------------------------------------------------
// Static 4 KiB cells (.bss): two new paging-structure tables + two frames.
// ---------------------------------------------------------------------------

/// A 4096-aligned, interior-mutable 4 KiB cell that can live in an immutable
/// `static` (zero-initialised, so the linker places it in `.bss`, which the
/// boot trampoline clears before `rust_main`) while tb-hal mutates it through
/// raw pointers. Reuses the shared typed layout [`PageTable512`]
/// (`#[repr(C, align(4096))]` over `[u64; 512]`) for BOTH the new
/// paging-structure tables (TEST_PD / TEST_PT) and the two data frames
/// (FRAME_A / FRAME_B) — a test frame is just 4 KiB of `.bss` that gets
/// mapped and written.
#[repr(C)]
struct Cell4K(UnsafeCell<PageTable512>);

// SAFETY: M3 is single-vCPU with interrupts masked since boot, and every
// access to the interior goes through raw pointers from `UnsafeCell::get`
// (no `&`/`&mut` to the interior is ever materialised), so handing the cell
// out via a shared `static` cannot violate aliasing. `UnsafeCell` is what
// makes in-place mutation behind an immutable `static` defined behaviour.
unsafe impl Sync for Cell4K {}

impl Cell4K {
    /// A new zeroed cell; `const`, so it can initialise a `static` in `.bss`.
    const fn new() -> Self {
        Cell4K(UnsafeCell::new(PageTable512([0; 512])))
    }

    /// Raw pointer to the 8-byte entry `idx` of this cell (`idx < 512`).
    /// Pointer projection only — never materialises a reference.
    fn entry_ptr(&self, idx: usize) -> *mut u64 {
        debug_assert!(idx < 512);
        // SAFETY: `idx < 512` keeps the offset inside this one 4096-byte
        // allocation; `PageTable512` is `repr(C, align(4096))` over
        // `[u64; 512]`, so the element cast + offset is layout-exact.
        unsafe { (self.0.get() as *mut u64).add(idx) }
    }

    /// PHYSICAL base address of this cell, as stored into paging entries.
    /// The kernel image (and its `.bss`) is loaded at 1 MiB and the boot
    /// tables identity-map [0, 1 GiB), so virtual == physical here; the
    /// 4096-alignment guarantees the low 12 bits are clear, i.e. the value
    /// drops straight into the bits-51:12 address field.
    fn phys_base(&self) -> u64 {
        self.0.get() as u64
    }
}

/// The new page directory the self-test hangs off the boot PDPT's slot 1.
static TEST_PD: Cell4K = Cell4K::new();
/// The new page table behind `TEST_PD[0]`, holding the single test PTE.
static TEST_PT: Cell4K = Cell4K::new();
/// 4 KiB frame A — first mapping target of `TEST_VA`.
static FRAME_A: Cell4K = Cell4K::new();
/// 4 KiB frame B — remap target of `TEST_VA`.
static FRAME_B: Cell4K = Cell4K::new();

// ---------------------------------------------------------------------------
// Privileged register wrappers (A6/A9): ALL of the M3 x86_64 asm lives here.
// ---------------------------------------------------------------------------

/// Read CR3 — physical base of the live PML4 plus the PWT/PCD control bits.
///
/// (a) PRE: long mode, ring 0 (TABOS never leaves it). POST: returns the
///     live CR3 value; no architectural state changes.
/// (b) ABI: `mov {out}, cr3` — one GPR written; MOV-from-CR raises no flags;
///     nomem/nostack/preserves_flags.
/// (c) Tested by: scripts/run-x86_64.sh ("M3: mmu OK" — `mmu_selftest` walks
///     CR3 -> PML4[0] to locate the live boot PDPT).
#[inline]
unsafe fn read_cr3() -> u64 {
    let val: u64;
    // SAFETY: ring-0-only instruction; see (a). Callers are inside tb-hal.
    unsafe {
        asm!("mov {}, cr3", out(reg) val, options(nomem, nostack, preserves_flags));
    }
    val
}

/// Write CR3 — re-root the live paging hierarchy. Architectural side effect:
/// flushes all non-global TLB entries (SDM Vol 3A §4.10.4.1). Provided per
/// the M3 contract; UNUSED by the self-test, which splices into the LIVE
/// hierarchy precisely so that no CR3 reload is needed.
///
/// (a) PRE: ring 0; `val` = 4 KiB-aligned physical base of a valid PML4 for
///     the current paging mode (+ optional PWT/PCD bits). POST: CR3 = `val`;
///     non-global TLB entries flushed.
/// (b) ABI: `mov cr3, {in}`; no flags; NOT nomem — re-rooting translation
///     must order against surrounding memory accesses.
/// (c) Tested by: compiled into the M3 surface; first exercised when a real
///     address-space switch lands (post-M3).
#[inline]
#[allow(dead_code)]
unsafe fn write_cr3(val: u64) {
    // SAFETY: ring-0-only instruction; caller guarantees `val` is a valid
    // PML4 base — a bad root faults on the very next fetch or walk.
    unsafe {
        asm!("mov cr3, {}", in(reg) val, options(nostack, preserves_flags));
    }
}

/// `invlpg [va]` — invalidate any TLB entry for the page containing `va`
/// (and, per the SDM, associated paging-structure-cache entries).
///
/// (a) PRE: ring 0; paging on. POST: the next access to `va`'s page re-walks
///     the live tables instead of reusing a cached translation.
/// (b) ABI: `invlpg [{in}]` — address operand only, never dereferenced as
///     data; no flags; NOT nomem (memory accesses must not be reordered
///     across a TLB invalidation); nostack/preserves_flags.
/// (c) Tested by: scripts/run-x86_64.sh ("M3: mmu OK" — the remap is only
///     observable because `invlpg` evicts the stale FRAME_A translation).
#[inline]
unsafe fn invlpg(va: usize) {
    // SAFETY: ring-0-only instruction; see (a).
    unsafe {
        asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags));
    }
}

/// Set/clear CR4.PGE (bit 7, Page Global Enable). Clearing then re-setting
/// PGE is the architectural "flush ALL TLB entries, global included" idiom
/// (SDM Vol 3A §4.10.4.1). Provided per the M3 contract; UNUSED by the
/// current self-test (the boot tables set no G bits, so `invlpg` suffices).
///
/// (a) PRE: ring 0. POST: CR4.PGE == `enable`, every other CR4 bit
///     preserved; a CR4 write that changes PGE flushes the TLB.
/// (b) ABI: `mov {out}, cr4` + `mov cr4, {in}` — read-modify-write through a
///     GPR; no flags; the WRITE is NOT nomem (TLB-flush side effect).
/// (c) Tested by: compiled into the M3 surface; exercised once global-page
///     mappings exist (none yet).
#[inline]
#[allow(dead_code)]
unsafe fn cr4_pge_toggle(enable: bool) {
    let mut cr4: u64;
    // SAFETY: ring-0-only instruction; pure read.
    unsafe {
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    if enable {
        cr4 |= CR4_PGE;
    } else {
        cr4 &= !CR4_PGE;
    }
    // SAFETY: writes back the just-read value with only PGE changed, so CR4
    // stays self-consistent (PAE etc. untouched).
    unsafe {
        asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
    }
}

/// `rdmsr` — read the 64-bit MSR selected by `msr` (EDX:EAX convention).
///
/// (a) PRE: ring 0; `msr` is implemented by the CPU (else #GP). POST:
///     returns EDX:EAX glued into one u64; no other state changes.
/// (b) ABI: ECX in, EAX/EDX out; flags unaffected; nomem/nostack/
///     preserves_flags (an MSR read has no memory side effect).
/// (c) Tested by: scripts/run-x86_64.sh ("M3: mmu OK" — `mmu_init`'s
///     read-modify-write of IA32_EFER).
#[inline]
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: ring-0-only instruction; caller passes an implemented MSR.
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// `wrmsr` — write the 64-bit MSR selected by `msr` (EDX:EAX convention).
///
/// (a) PRE: ring 0; `msr` implemented and `val` legal for it (else #GP).
///     POST: the MSR holds `val`; for IA32_EFER.NXE this immediately turns
///     paging-entry bit 63 into the XD bit.
/// (b) ABI: ECX/EAX/EDX in; flags unaffected; NOT nomem (an MSR write can
///     change memory semantics — NXE alters how mappings behave);
///     nostack/preserves_flags.
/// (c) Tested by: scripts/run-x86_64.sh ("M3: mmu OK" — `mmu_init` sets
///     EFER.NXE and the kernel keeps executing + printing afterwards).
#[inline]
unsafe fn wrmsr(msr: u32, val: u64) {
    // SAFETY: ring-0-only instruction; caller guarantees msr/val legality.
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") val as u32,
            in("edx") (val >> 32) as u32,
            options(nostack, preserves_flags),
        );
    }
}

// ---------------------------------------------------------------------------
// Safe M3 surface (re-exported through arch/mod.rs -> lib.rs).
// ---------------------------------------------------------------------------

/// x86_64 `mmu_init`: enable IA32_EFER.NXE so paging-entry bit 63 is the
/// architectural execute-disable (XD) bit (SDM Vol 3A §4.5 / Vol 4 Table 2-2
/// "IA32_EFER", bit 11 "Execute Disable Bit Enable").
///
/// Read-modify-write of one bit: idempotent, and preserves the LME/LMA/SCE
/// state the boot trampoline established. Every Firecracker-class x86_64
/// host (and QEMU TCG's default qemu64 model) implements NX
/// (CPUID.80000001H:EDX.NX = 1), so setting NXE cannot #GP on our targets.
/// IA32_PAT (MSR 0x277) is deliberately left at its power-up default — PAT
/// entry 0 is WB, which is what mappings with PWT=PCD=PAT=0 (all of ours)
/// select; per the M3 contract that is acceptable.
///
/// Call once from `rust_main`, AFTER `install_traps()` (a surprise #GP then
/// reports via the M1 trap path instead of triple-faulting).
pub fn mmu_init() {
    // SAFETY: ring 0 in long mode; IA32_EFER exists on every x86_64 CPU and
    // OR-ing NXE is legal whenever CPUID advertises NX (see above).
    unsafe {
        let efer = rdmsr(MSR_EFER);
        wrmsr(MSR_EFER, efer | EFER_NXE);
    }
}

/// x86_64 `mmu_selftest`: build, prove, REMAP and re-prove a 4 KiB mapping
/// for [`TEST_VA`] over the LIVE boot page tables. Returns `true` on pass.
/// Any structural surprise returns `false` (fail-closed — the kernel prints
/// "M3: FAIL"); a broken translation would #PF into the M1 trap path (whose
/// policy halts) and the runner's fail-closed timeout reports the missing
/// marker.
///
/// `TEST_VA = 0x4000_0000` decomposes (SDM Vol 3A §4.5, 4-level paging) as
/// PML4[0] -> PDPT[1] -> PD[0] -> PT[0]: PML4 slot 0 is the boot entry that
/// already points at `__boot_pdpt`, and PDPT slot 1 — the second gigabyte —
/// is VACANT because boot maps exactly [0, 1 GiB). Sequence:
///
///  1. Locate the boot PDPT: CR3 -> PML4[PML4_IDX] (the tables sit in
///     identity-mapped low RAM, so physical addresses deref directly).
///  2. Fail closed if PML4[0] is non-present or PDPT[1] is already present
///     (unexpected boot layout, or a second invocation).
///  3. Build BOTTOM-UP, publish LAST: TEST_PT[0] = FRAME_A|P|RW, TEST_PD[0]
///     = TEST_PT|P|RW, then PDPT[1] = TEST_PD|P|RW — the page walker can
///     never observe a half-built subtree. The `invlpg` here is
///     belt-and-suspenders only: a 0 -> 1 P transition needs no invalidation
///     (SDM Vol 3A §4.10.4.3).
///  4. MAP PROOF: write [`MAGIC_A`] through `TEST_VA`; read it back through
///     FRAME_A's identity address.
///  5. REMAP: seed FRAME_B with [`MAGIC_B`] via its identity address;
///     rewrite TEST_PT[0] = FRAME_B|P|RW; `invlpg TEST_VA` — REQUIRED now,
///     because step 4 cached the FRAME_A leaf in the TLB (SDM Vol 3A
///     §4.10.4.2). No break-before-make is needed on x86_64 (unlike
///     VMSAv8-64, the architecture has no TLB-conflict abort for a direct
///     valid -> valid rewrite on a single vCPU).
///  6. REMAP PROOF: read `TEST_VA`, expect [`MAGIC_B`].
pub fn mmu_selftest() -> bool {
    // SAFETY (whole test): ring 0, single vCPU, interrupts masked since
    // boot. Every table/frame byte is a tb-hal-owned static reached ONLY via
    // `UnsafeCell` raw pointers, so no Rust reference aliases memory the CPU
    // walker or the TEST_VA alias touches; all accesses through raw/mapped
    // addresses are volatile so the compiler can neither elide nor reorder
    // them around the table writes and `invlpg`.
    unsafe {
        // (1) CR3 -> live PML4 -> boot PDPT.
        let pml4 = (read_cr3() & PTE_ADDR_MASK) as *const u64;
        let pml4e = read_volatile(pml4.add(PML4_IDX));
        if pml4e & PTE_P == 0 {
            return false; // first GiB unmapped?! not the boot layout we built
        }
        let pdpt = (pml4e & PTE_ADDR_MASK) as *mut u64;
        let pdpte_slot = pdpt.add(PDPT_IDX);

        // (2) Target PDPT slot must be vacant (fail-closed re-run guard).
        if read_volatile(pdpte_slot) & PTE_P != 0 {
            return false;
        }

        // (3) Bottom-up build; top-level publish last; courtesy invlpg.
        write_volatile(
            TEST_PT.entry_ptr(PT_IDX),
            FRAME_A.phys_base() | PTE_P | PTE_RW,
        );
        write_volatile(
            TEST_PD.entry_ptr(PD_IDX),
            TEST_PT.phys_base() | PTE_P | PTE_RW,
        );
        write_volatile(pdpte_slot, TEST_PD.phys_base() | PTE_P | PTE_RW);
        invlpg(TEST_VA); // optional for 0->1 P (SDM 4.10.4.3); cheap insurance

        // (4) Map proof: in through the NEW VA, out through the identity VA.
        let test_va = TEST_VA as *mut u64;
        write_volatile(test_va, MAGIC_A);
        if read_volatile(FRAME_A.entry_ptr(0)) != MAGIC_A {
            return false;
        }

        // (5) Remap the leaf to FRAME_B; invlpg is REQUIRED here.
        write_volatile(FRAME_B.entry_ptr(0), MAGIC_B);
        write_volatile(
            TEST_PT.entry_ptr(PT_IDX),
            FRAME_B.phys_base() | PTE_P | PTE_RW,
        );
        invlpg(TEST_VA);

        // (6) Remap proof.
        read_volatile(test_va) == MAGIC_B
    }
}

// ===========================================================================
// M7: frame-backed growable kernel-heap window (this milestone).
//
// `map_heap_frames` grows the heap by pulling 4 KiB frames from M6 and splicing
// them into the LIVE CR3 hierarchy through the M3 typed layer — the same
// publish-bottom-up dance `mmu_selftest` / `user::map_user_pages` perform, but
// kernel-only (NO U/S), RW + NX, mapping MANY frames and REUSING intermediate
// tables across grows (a present interior entry is walked, not rebuilt). All
// the unsafe lives here; `heap.rs` (no asm) only calls this safe-ish primitive.
// ===========================================================================

/// Base VA of the kernel-heap window: `2 * 2^39` = `PML4[2]` — a vacant
/// top-level slot (boot uses `PML4[0]`, M4 `user` uses `PML4[1]`), OUTSIDE the
/// identity map `[0, 1 GiB)`. Canonical (bits 63:48 sign-extend bit 47 = 0).
const HEAP_WINDOW_BASE: u64 = 0x0000_0100_0000_0000;

/// Window VA span cap: 1 GiB — a single `PDPT[0] -> PD[0..512]` subtree (512
/// page tables, 2 MiB each), far more than any milestone heap needs, while
/// keeping the whole window inside one third-level subtree.
const HEAP_WINDOW_SIZE: u64 = 0x4000_0000;

/// The per-arch kernel-heap window VA range `(base, size)` for `heap.rs`.
pub fn heap_window() -> (u64, u64) {
    (HEAP_WINDOW_BASE, HEAP_WINDOW_SIZE)
}

/// Zero all 512 entries of a freshly-allocated table frame, through its identity
/// address (M6 frames sit below 1 GiB, so PA == VA). A new table MUST start
/// all-not-present; M6 only wrote a stale free-list link word into it.
///
/// # Safety
/// `table` is a 4 KiB-aligned, identity-mapped frame this code exclusively owns
/// (just popped from M6 and not yet linked into any live hierarchy).
unsafe fn zero_table(table: *mut u64) {
    let mut i = 0;
    while i < ENTRIES {
        write_volatile(table.add(i), 0);
        i += 1;
    }
}

/// Return the child table referenced by `parent[idx]`, creating it from a fresh,
/// zeroed M6 frame (spliced in as `P|RW`, then REUSED by later grows) when the
/// slot is empty. `None` only when M6 has no frame for a missing table.
///
/// # Safety
/// `parent` is a live, identity-mapped 512-entry table; `idx < 512`. Entry
/// reads/writes are volatile (the page walker reads them behind the compiler).
unsafe fn ensure_table(parent: *mut u64, idx: usize) -> Option<*mut u64> {
    let slot = parent.add(idx);
    let entry = read_volatile(slot);
    if entry_is_valid(entry) {
        return Some(entry_addr(entry) as *mut u64);
    }
    let frame = crate::frame_alloc()?;
    zero_table(frame as *mut u64);
    // Interior entry: Present | RW, kernel-only (no U/S). NX rides on the LEAF;
    // a P|RW interior entry does not by itself grant execute permission.
    write_volatile(slot, make_entry(frame, PTE_P | PTE_RW));
    Some(frame as *mut u64)
}

/// Map ONE page `va` -> a fresh M6 frame under the live `pml4`, building any
/// missing `PML4[2] -> PDPT -> PD -> PT` table along the way. `false` on
/// physical-frame OOM. On OOM mid-walk an interior table already spliced in by
/// `ensure_table` is RETAINED (reused by a later grow via the `entry_is_valid`
/// fast path) and the data frame is simply never pulled — so the page is left
/// fully unmapped, never half-mapped.
///
/// # Safety
/// Ring 0, single vCPU; `pml4` is the live root just read from CR3; `va` is a
/// canonical, currently-unmapped window VA in `PML4[2]`; every M6 frame is
/// identity-mapped, so each table pointer dereferences directly.
unsafe fn map_one_heap_page(pml4: *mut u64, va: u64) -> bool {
    let pdpt = match ensure_table(pml4, level_index(va, SHIFT_512G)) {
        Some(t) => t,
        None => return false,
    };
    let pd = match ensure_table(pdpt, level_index(va, SHIFT_1G)) {
        Some(t) => t,
        None => return false,
    };
    let pt = match ensure_table(pd, level_index(va, SHIFT_2M)) {
        Some(t) => t,
        None => return false,
    };
    let data = match crate::frame_alloc() {
        Some(p) => p,
        None => return false,
    };
    // Leaf: Present | RW | NX, kernel-only (no U/S). A data page, never executed.
    write_volatile(
        pt.add(level_index(va, SHIFT_4K)),
        make_entry(data, PTE_P | PTE_RW | PTE_NX),
    );
    true
}

/// Map `n` contiguous pages from `start_va` to `n` freshly-allocated M6 frames
/// (intermediate page-table frames ALSO from M6), each leaf RW + NX, kernel-only,
/// and report how many pages were actually mapped (`< n` ONLY on physical-frame
/// OOM, with no half-mapped page — a page is either fully mapped or skipped).
/// `heap.rs` then donates `[start_va, start_va + mapped*4096)` to its free list.
///
/// The live PML4 base is read from CR3 ONCE here and threaded into every
/// per-page walk (the root never changes mid-grow), so a multi-page grow issues
/// a single control-register read rather than one per page.
///
/// First-map only — each window VA is mapped exactly ONCE (a 0 -> 1 Present
/// transition), so NO `invlpg` is needed: the TLB never caches not-present
/// entries (SDM Vol 3A §4.10.4.3).
pub fn map_heap_frames(start_va: u64, n: usize) -> usize {
    // SAFETY: ring 0, single vCPU, interrupts masked; CR3 holds the live PML4
    // base, and the boot PML4 + every M6 frame are identity-mapped low RAM, so
    // the masked root value is a directly-dereferenceable table pointer.
    let pml4 = unsafe { (read_cr3() & PTE_ADDR_MASK) as *mut u64 };
    let mut mapped = 0usize;
    while mapped < n {
        let va = start_va + (mapped as u64) * (PAGE_SIZE as u64);
        // SAFETY: see above; `va` is a canonical, not-yet-mapped window VA and
        // `pml4` is the live root, so every table pointer dereferences directly.
        if !unsafe { map_one_heap_page(pml4, va) } {
            break; // physical-frame OOM: stop, return the count fully mapped
        }
        mapped += 1;
    }
    mapped
}

// ===========================================================================
// M8: uncacheable device-MMIO page mapper (LAPIC bring-up).
//
// The LAPIC register block (PA 0xFEE0_0000) sits in the FOURTH GiB — ABOVE the
// boot identity map [0, 1 GiB) (boot.rs maps exactly 512 x 2 MiB pages), so that
// PA is UNMAPPED. Map a FRESH 4 KiB kernel VA in the vacant `PML4[3]` device
// window to the device PA with `PWT|PCD` set (PAT entry 3 = strong UC) and NX
// (an MMIO register page is never executed). This fresh page is the SOLE
// mapping of the LAPIC — there is NO WB alias to resolve, so no super-page split
// is needed. Reuses the same `ensure_table` walk `map_heap_frames` uses
// (intermediate PDPT/PD/PT pulled from M6 frames); `timer.rs` accesses the
// LAPIC through the returned window VA.
// ===========================================================================

/// Map ONE 4 KiB page `va` -> device physical `pa` as strong-uncacheable,
/// kernel-only, no-execute (`P|RW|PWT|PCD|NX` = PAT entry 3) under the live
/// `pml4`, building any missing `PDPT/PD/PT` from M6 frames. `false` on
/// physical-frame OOM.
///
/// # Safety
/// Ring 0, single vCPU; `pml4` is the live root from CR3; `va` is a canonical,
/// currently-unmapped device-window VA; `pa` is a 4 KiB-aligned device PA. Every
/// M6 table frame is identity-mapped, so each table pointer dereferences directly.
unsafe fn map_one_device_page(pml4: *mut u64, va: u64, pa: u64) -> bool {
    let pdpt = match ensure_table(pml4, level_index(va, SHIFT_512G)) {
        Some(t) => t,
        None => return false,
    };
    let pd = match ensure_table(pdpt, level_index(va, SHIFT_1G)) {
        Some(t) => t,
        None => return false,
    };
    let pt = match ensure_table(pd, level_index(va, SHIFT_2M)) {
        Some(t) => t,
        None => return false,
    };
    write_volatile(
        pt.add(level_index(va, SHIFT_4K)),
        make_entry(pa, PTE_P | PTE_RW | PTE_PWT | PTE_PCD | PTE_NX),
    );
    invlpg(va as usize); // 0->1 transition; belt-and-suspenders (SDM §4.10.4.3)
    true
}

/// Map the single 4 KiB device page `va` -> `pa` (strong-UC, kernel-only, NX)
/// into the LIVE CR3 hierarchy. `false` on physical-frame OOM. Used by `timer.rs`
/// to bring the LAPIC register page into a UC kernel device window (`PML4[3]`).
pub(super) fn map_device_page(va: u64, pa: u64) -> bool {
    // SAFETY: ring 0, single vCPU, interrupts masked; CR3 holds the live PML4
    // base (identity-mapped low RAM), so the masked value is a directly
    // dereferenceable table pointer, and `map_one_device_page` only splices a
    // fresh, vacant device-window VA.
    let pml4 = unsafe { (read_cr3() & PTE_ADDR_MASK) as *mut u64 };
    unsafe { map_one_device_page(pml4, va, pa) }
}

// ===========================================================================
// M10: per-entity address spaces (memory isolation).
//
// A symmetric, low-risk design (NO TTBR1/TTBR0 split, mirrored on aarch64):
// `address_space_new` frame-allocs a fresh PML4 and COPIES all 512 entries of
// the live CR3 PML4 into it, so every kernel mapping (identity RAM, the M4 user
// window, the M7 heap window, the M8 LAPIC window, the M3 test mapping) is
// shared BY REFERENCE and the kernel half is identical in every entity root.
// `map_in_root` splices a private leaf into an EXPLICIT (not-live) root using
// the same `ensure_table` walk the heap/device mappers use; the test VA lives in
// a vacant top-level slot (`PML4[4]`), so a private entry there never touches
// the kernel half or another entity. `switch_root` is a single `mov CR3` (it
// flushes non-global TLB entries; the kernel-half pages keep this code/stack/
// serial valid). All the unsafe lives here; `lib.rs` exposes the safe facade.
// ===========================================================================

/// M10: create a fresh address space. Frame-allocate a new top-level table (one
/// M6 frame) and COPY all 512 entries of the LIVE PML4 (read from CR3) into it,
/// so the whole kernel half is shared by reference. Returns the new PML4 PA, or
/// `None` on physical-frame OOM.
pub fn address_space_new() -> Option<u64> {
    let root = crate::frame_alloc()?;
    // SAFETY: `root` is a 4 KiB-aligned M6 frame in identity-mapped low RAM
    // (PA == VA), exclusively owned here; CR3 holds the live PML4 base, also
    // identity-mapped. Copy all 512 8-byte entries from the live PML4 into the
    // new table; the kernel half is then shared by reference. Volatile so the
    // walker-visible writes are neither elided nor reordered.
    unsafe {
        let src = (read_cr3() & PTE_ADDR_MASK) as *const u64;
        let dst = root as *mut u64;
        let mut i = 0;
        while i < ENTRIES {
            write_volatile(dst.add(i), read_volatile(src.add(i)));
            i += 1;
        }
    }
    Some(root)
}

/// M10: map one private 4 KiB page `va` -> `pa` into the EXPLICIT top-level
/// table at `root_pa` (NOT the live CR3), building any missing PDPT/PD/PT from
/// M6 frames. `va` must sit in a top-level slot the kernel root leaves vacant
/// (`PML4[4]`), so the new top-level entry lands only in THIS root. Leaf =
/// Present | (RW if `writable`) | NX (a data page, never executed). `false` on
/// physical-frame OOM (no half-mapped page).
pub fn map_in_root(root_pa: u64, va: u64, pa: u64, writable: bool) -> bool {
    // SAFETY: `root_pa` is a 4 KiB-aligned PML4 frame from `address_space_new`
    // in identity-mapped low RAM (PA == VA); every intermediate table
    // `ensure_table` pulls is likewise an identity-mapped M6 frame. The root is
    // NOT live, so no live translation is disturbed and no `invlpg` is needed.
    unsafe {
        let pml4 = root_pa as *mut u64;
        let pdpt = match ensure_table(pml4, level_index(va, SHIFT_512G)) {
            Some(t) => t,
            None => return false,
        };
        let pd = match ensure_table(pdpt, level_index(va, SHIFT_1G)) {
            Some(t) => t,
            None => return false,
        };
        let pt = match ensure_table(pd, level_index(va, SHIFT_2M)) {
            Some(t) => t,
            None => return false,
        };
        let mut attrs = PTE_P | PTE_NX;
        if writable {
            attrs |= PTE_RW;
        }
        write_volatile(pt.add(level_index(va, SHIFT_4K)), make_entry(pa, attrs));
    }
    true
}

/// M12: like [`ensure_table`] but builds the intermediate table as a USER entry
/// (`P|RW|U/S`), because ring3 access requires `U/S = 1` at EVERY level of the
/// walk (SDM Vol.3A §4.6). `None` on physical-frame OOM.
///
/// # Safety
/// As [`ensure_table`]: `parent` is a live/owned identity-mapped 512-entry table
/// and `idx < 512`.
unsafe fn ensure_table_user(parent: *mut u64, idx: usize) -> Option<*mut u64> {
    let slot = parent.add(idx);
    let entry = read_volatile(slot);
    if entry_is_valid(entry) {
        // An existing interior table: ensure it is USER-reachable (the agent
        // window owns its slot, so OR-ing U/S here only ever opens our own path).
        if entry & PTE_US == 0 {
            write_volatile(slot, entry | PTE_US);
        }
        return Some(entry_addr(entry) as *mut u64);
    }
    let frame = crate::frame_alloc()?;
    zero_table(frame as *mut u64);
    write_volatile(slot, make_entry(frame, PTE_P | PTE_RW | PTE_US));
    Some(frame as *mut u64)
}

/// M12: map one private 4 KiB USER page `va` -> `pa` into the EXPLICIT root at
/// `root_pa` (NOT the live CR3), with `U/S = 1` at every level so ring3 may
/// reach it. Leaf = `P | U/S | (RW if writable) | (NX if !exec)`. `va` must sit
/// in a top-level slot the kernel root leaves vacant (`PML4[4]`). `false` on
/// physical-frame OOM. The root is not live, so no `invlpg` is needed.
pub(super) fn map_user_in_root(
    root_pa: u64,
    va: u64,
    pa: u64,
    writable: bool,
    exec: bool,
) -> bool {
    // SAFETY: `root_pa` is a 4 KiB-aligned PML4 from `address_space_new` in
    // identity-mapped low RAM (PA == VA); every table `ensure_table_user` pulls
    // is likewise an identity-mapped M6 frame; the root is not live.
    unsafe {
        let pml4 = root_pa as *mut u64;
        let pdpt = match ensure_table_user(pml4, level_index(va, SHIFT_512G)) {
            Some(t) => t,
            None => return false,
        };
        let pd = match ensure_table_user(pdpt, level_index(va, SHIFT_1G)) {
            Some(t) => t,
            None => return false,
        };
        let pt = match ensure_table_user(pd, level_index(va, SHIFT_2M)) {
            Some(t) => t,
            None => return false,
        };
        let mut attrs = PTE_P | PTE_US;
        if writable {
            attrs |= PTE_RW;
        }
        if !exec {
            attrs |= PTE_NX;
        }
        write_volatile(pt.add(level_index(va, SHIFT_4K)), make_entry(pa, attrs));
    }
    true
}

/// M10: make the address space whose PML4 PA is `root_pa` live (`mov CR3`).
/// Writing CR3 flushes all non-global TLB entries; because every entity root
/// shares an identical kernel half, this code, the current stack and serial stay
/// valid across the load.
pub fn switch_root(root_pa: u64) {
    // SAFETY: `root_pa` is a 4 KiB-aligned PML4 from `address_space_new` (a copy
    // of the live kernel root + optional private leaves), a valid paging root
    // for the current mode; every kernel mapping the executing code and stack
    // depend on is present in it.
    unsafe { write_cr3(root_pa & PTE_ADDR_MASK) }
}

/// M10: the PA of the LIVE top-level page table (CR3's PML4 base, control bits
/// masked off). Used to capture the default boot root at first space creation.
pub fn current_root() -> u64 {
    // SAFETY: reading CR3 is a side-effect-free ring-0 control-register read.
    unsafe { read_cr3() & PTE_ADDR_MASK }
}

/// M10: re-assert M3. `true` iff the M3 self-test VA (`TEST_VA`) still reads its
/// post-remap magic (`MAGIC_B`) under the LIVE root. The M3 mapping hangs off
/// `PML4[0]`, copied by reference into every space, so this reads true under the
/// boot root AND any entity root -- proving the M3 kernel-half mapping survives
/// every address-space switch.
pub fn m3_test_va_intact() -> bool {
    // SAFETY: `TEST_VA` is mapped (by `mmu_selftest`) to FRAME_B in the shared
    // kernel half present in every root; an aligned volatile u64 load.
    unsafe { read_volatile(TEST_VA as *const u64) == MAGIC_B }
}
