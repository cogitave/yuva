//! aarch64 **M4 "user/ring boundary"**: drop to EL0, issue an `svc`, trap back
//! into EL1, prove the full round-trip (unit A-user).
//!
//! This is the aarch64 half of milestone **M4**. M0-M3 brought up serial, the
//! EL1 trap path, the cooperative context switch and the MMU (identity 1 GiB
//! blocks + a 4 KiB map/remap self-test under L1[2]). M4 demonstrates the
//! privileged/unprivileged split end-to-end:
//!
//!   1. Map a fresh **user code page** (`USER_CODE_VA`) and **user stack page**
//!      (`USER_STACK_VA`) with EL0 permissions, via a private L2->L3 chain hung
//!      under a previously-unused root slot **L1[3]** (VA 0xC000_0000, the 3 GiB
//!      line). We read the LIVE root out of `TTBR0_EL1` rather than touching
//!      `mmu.rs`'s private `ID_L1`, so this file stays self-contained.
//!   2. [`enter_el0`] saves the kernel's resume context, programs `SP_EL0` /
//!      `ELR_EL1` / `SPSR_EL1` and `eret`s down to **EL0t** at the user stub.
//!   3. The [`user_stub`] (a position-independent naked fn running at the
//!      aliased `USER_CODE_VA`) loads the magic arg `0xCAFE` into `x0` and
//!      executes `svc #0`.
//!   4. `svc` is taken back to **EL1h** through the **"Lower EL using AArch64,
//!      Synchronous"** vector slot, which `vectors.rs` now routes to the real
//!      trampoline `__vec_el0_sync` -> [`aarch64_el0_sync_handler`] (here).
//!      The handler confirms `ESR_EL1.EC == 0x15` (SVC from AArch64), records
//!      the arg, then **longjmps** straight back into [`enter_el0`]'s caller --
//!      it deliberately does NOT `eret` to EL0, so the kernel keeps control.
//!   5. [`user_demo`] reads the recorded flag/arg and returns `true` iff the
//!      syscall was observed from EL0 with the expected argument.
//!
//! Return strategy (the "simplest correct design" the M4 spec calls out): a
//! kernel-internal **setjmp/longjmp**. [`enter_el0`] stashes the AAPCS64
//! callee-saved registers + LR + SP of its caller into the static
//! [`KERNEL_RESUME`] buffer before the `eret`. The SVC handler, instead of
//! returning to EL0, reloads that buffer and `ret`s -- so from the caller's
//! point of view [`enter_el0`] simply "returned" once the syscall fired. The
//! kernel SP needs no explicit save/restore beyond this: taking the exception
//! to EL1h resumes on `SP_EL1`, which was never changed by the EL0 excursion
//! (EL0t runs on `SP_EL0`), so the 0x110 exception frame is pushed onto the
//! kernel stack and is harmlessly abandoned when SP is reset on the longjmp.
//!
//! ALL `unsafe` + asm lives here in tb-hal (framekernel rule); the kernel crate
//! stays `#![forbid(unsafe_code)]` and only branches on the returned `bool`.
//!
//! VERIFIED facts this module is built on (sources re-fetched 2026-06-07; do
//! NOT change the constants without re-reading them):
//!
//!  * **EL0 entry via `eret`.** `eret` returns to the EL and stack-pointer
//!    selected by `SPSR_EL1.M[4:0]`. `M = 0b00000` = **EL0t** (EL0, which always
//!    uses `SP_EL0`); `M[4]=0` selects AArch64. Source: Linux v6.6
//!    `arch/arm64/include/uapi/asm/ptrace.h` -- `PSR_MODE_EL0t 0x00000000`,
//!    `PSR_MODE_EL1h 0x00000005`, `PSR_F_BIT 0x40`, `PSR_I_BIT 0x80`,
//!    `PSR_A_BIT 0x100`, `PSR_D_BIT 0x200`; Arm ARM (DDI 0487) D1 "AArch64
//!    exception model" (`ERET` + `SPSR_ELx` PSTATE restore); osdev.org
//!    "AArch64 Exception Levels" (eret-to-EL0 recipe: set `SP_EL0`, `ELR_EL1`,
//!    `SPSR_EL1`, then `eret`). We use `SPSR_EL1 = 0x3C0` = EL0t with `DAIF`
//!    masked: there is no GIC/timer configured yet, so masking async exceptions
//!    at EL0 keeps parity with the kernel's masked state and avoids a stray
//!    IRQ/FIQ vectoring through an as-yet-stub Lower-EL slot. `svc` is a
//!    SYNCHRONOUS exception and is unaffected by `DAIF`.
//!  * **SVC syndrome.** A `svc` from AArch64 state sets `ESR_EL1.EC = 0x15`
//!    (bits[31:26]); the 16-bit immediate lands in `ESR_EL1.ISS[15:0]`. Source:
//!    Linux v6.6 `arch/arm64/include/asm/esr.h` -- `ESR_ELx_EC_SVC64 (0x15)`,
//!    `ESR_ELx_EC_SHIFT (26)`, `ESR_ELx_EC_MASK`; Arm ARM D17.2.37 "ESR_EL1".
//!  * **EL0-accessible descriptor bits** (VMSAv8-64 stage-1 L3 page). Source:
//!    Linux v6.6 `arch/arm64/include/asm/pgtable-hwdef.h` --
//!      - `PTE_TYPE_PAGE (3 << 0)`  : L3 leaf type.
//!      - `PTE_USER   (1 << 6)`  /* AP[1] */ : set => EL0 may access.
//!      - `PTE_RDONLY (1 << 7)`  /* AP[2] */ : clear => read/write.
//!        AP[2:1] = 0b01 (PTE_USER set, PTE_RDONLY clear) = EL1 RW + EL0 RW
//!        (Arm ARM D8 stage-1 AP[2:1] table; cross-checked vs Linux
//!        `_PAGE_SHARED`, which sets `PTE_USER` for user RW pages).
//!      - `PTE_SHARED (3 << 8)`  : SH[1:0] inner shareable.
//!      - `PTE_AF     (1 << 10)` : Access Flag -- MANDATORY on every leaf (no
//!        AF-fault handler installed; a cleared AF => abort on first access).
//!      - `PTE_PXN    (1 << 53)` : Privileged execute-never (set on user pages
//!        so EL1 cannot execute EL0 code -- defensive).
//!      - `PTE_UXN    (1 << 54)` : User (EL0) execute-never. CLEAR on the code
//!        page (EL0 must execute it); SET on the stack page (data only).
//!      - `PTE_ATTRINDX(t) ((t) << 2)` : AttrIndx. We use index 1 = Normal WB,
//!        matching the `MAIR_EL1` programmed by `mmu.rs::mmu_init` (attr0 =
//!        Device-nGnRnE, attr1 = Normal WB RA/WA).
//!    The identity RAM block (L1[1]) is `AP=0b00` (EL0 no access), which is why
//!    a FRESH EL0 mapping is required -- we cannot `eret` into kernel-image VAs.
//!  * **TTBR0_EL1 BADDR.** The live L1 table's physical base is `TTBR0_EL1`
//!    bits[47:1] (bit0 = CnP); for our 4 KiB-granule config the table is
//!    4 KiB-aligned, so `TTBR0_EL1 & 0x0000_FFFF_FFFF_F000` recovers it. The
//!    root sits in the identity-mapped RAM gigabyte, so its PA == its VA and it
//!    is directly writable. Source: Arm ARM D19.2 "TTBR0_EL1"; Linux v6.6
//!    `pgtable-hwdef.h` `TTBR_CNP_BIT (UL(1) << 0)`.
//!  * **First map needs no TLBI.** L1[3] was invalid (`.bss`-zeroed; `mmu_init`
//!    only set L1[0]/L1[1], the self-test set L1[2]); entries that fault are
//!    architecturally never cached, so publishing the new chain with
//!    `dsb ishst` + `isb` suffices (same rule the M3 first-map relied on).
//!    Arm ARM D8.14 / Linux `__flush_tlb_kernel_pgtable` discussion.
//!  * **AAPCS64 callee-saved set** (the longjmp save area): r19-r29 + SP, with
//!    r29 = FP and r30 = LR. Source: ARM-software/abi-aa `aapcs64.rst` §6.1.1.

use core::arch::{asm, naked_asm};
use core::cell::UnsafeCell;
use core::ptr::write_volatile;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

// ===========================================================================
// Virtual layout (a fresh, EL0-accessible window in the unused L1[3] gigabyte)
// ===========================================================================

/// User code page VA: 3 GiB (L1[3], L2[0], L3[0]). Page-aligned. Outside both
/// the identity map (L1[0]/L1[1]) and the M3 self-test region (L1[2]).
const USER_CODE_VA: u64 = 0xC000_0000;
/// User stack page VA: `USER_CODE_VA + 4 KiB` (L1[3], L2[0], L3[1]).
const USER_STACK_VA: u64 = 0xC000_1000;
/// Top of the (downward-growing) user stack: one page above its base.
const USER_STACK_TOP_VA: u64 = USER_STACK_VA + 0x1000;

/// Root (L1) index of the user window: VA[38:30].
const USER_L1_IDX: usize = ((USER_CODE_VA >> 30) & 0x1FF) as usize; // = 3
/// L3 index of the code page: VA[20:12].
const USER_CODE_L3_IDX: usize = ((USER_CODE_VA >> 12) & 0x1FF) as usize; // = 0
/// L3 index of the stack page: VA[20:12].
const USER_STACK_L3_IDX: usize = ((USER_STACK_VA >> 12) & 0x1FF) as usize; // = 1

// Layout locks: both pages must share L1[3] and L2[0], be page-aligned, and
// land on distinct L3 slots, or the single USER_L2/USER_L3 chain is wrong.
const _: () = assert!(USER_CODE_VA & 0xFFF == 0 && USER_STACK_VA & 0xFFF == 0);
const _: () = assert!(USER_L1_IDX == 3);
const _: () = assert!((USER_CODE_VA >> 30) & 0x1FF == (USER_STACK_VA >> 30) & 0x1FF);
const _: () = assert!((USER_CODE_VA >> 21) & 0x1FF == 0 && (USER_STACK_VA >> 21) & 0x1FF == 0);
const _: () = assert!(USER_CODE_L3_IDX == 0 && USER_STACK_L3_IDX == 1);

/// Magic syscall argument the user stub passes in `x0` (proves we ran at EL0).
const USER_SYSCALL_ARG: u64 = 0xCAFE;

// ===========================================================================
// VMSAv8-64 descriptor bits + EL0 leaf templates (verified -- module doc)
// ===========================================================================

const DESC_PAGE: u64 = 0b11; // L3 leaf type
const DESC_TABLE: u64 = 0b11; // table descriptor (L1/L2 -> next level)
const DESC_AF: u64 = 1 << 10; // Access Flag (mandatory)
const DESC_SH_INNER: u64 = 0b11 << 8; // SH[1:0] inner shareable
const DESC_ATTRINDX_NORMAL: u64 = 1 << 2; // AttrIndx = 1 -> MAIR attr1 (Normal WB)
const AP_EL0_RW: u64 = 1 << 6; // AP[1] (PTE_USER): EL1 RW + EL0 RW
const DESC_PXN: u64 = 1 << 53; // Privileged execute-never
const DESC_UXN: u64 = 1 << 54; // User (EL0) execute-never

/// User code leaf: Normal WB, EL0 RW, **EL0-executable** (UXN=0), EL1 no-exec.
const PAGE_USER_CODE: u64 =
    DESC_PAGE | DESC_AF | DESC_SH_INNER | DESC_ATTRINDX_NORMAL | AP_EL0_RW | DESC_PXN;
/// User stack leaf: Normal WB, EL0 RW, no-execute at either EL (UXN=1, PXN=1).
const PAGE_USER_STACK: u64 =
    DESC_PAGE | DESC_AF | DESC_SH_INNER | DESC_ATTRINDX_NORMAL | AP_EL0_RW | DESC_PXN | DESC_UXN;

/// `TTBR0_EL1` -> L1 base mask (bits[47:12]; drops CnP bit0 + RES0 low bits).
const TTBR_BADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

// ===========================================================================
// ESR_EL1 classification + EL0 entry PSTATE (verified -- module doc)
// ===========================================================================

const ESR_EC_SHIFT: u64 = 26;
const ESR_EC_MASK: u64 = 0x3F;
const EC_SVC64: u64 = 0x15; // SVC instruction execution in AArch64 state

/// `SPSR_EL1` for the `eret` to EL0: M[4:0] = 0 (EL0t, AArch64) + D|A|I|F
/// masked (0x3C0). See module doc for the DAIF rationale.
#[allow(dead_code)]
const SPSR_EL0T_DAIF: u64 = 0x3C0;

// ===========================================================================
// Static tables, the user stack frame, and the kernel longjmp save area
// (all `.bss`, zeroed by `_start`; identity-mapped, so PA == VA)
// ===========================================================================

/// A 4096-aligned, page-sized cell used for the user L2/L3 tables and the user
/// stack frame. Mirrors `mmu.rs`'s `TableCell`/`Frame4K` but is local to this
/// module (those types are private to `mmu.rs`).
#[repr(C, align(4096))]
struct Page(UnsafeCell<[u64; 512]>);

// SAFETY: single-vCPU, cooperative kernel -- no concurrent mutator. All access
// goes through volatile raw-pointer helpers; no Rust reference to the interior
// is ever minted, so the `Sync` impl cannot be used to alias `&mut`.
unsafe impl Sync for Page {}

impl Page {
    /// A new all-zero (all-invalid) page; `const`, so it can sit in `.bss`.
    const fn new() -> Self {
        Page(UnsafeCell::new([0; 512]))
    }
    /// Physical address of this page (identity space: the pointer IS the PA).
    fn pa(&self) -> u64 {
        self.0.get() as u64
    }
}

/// Write one descriptor slot, volatile (the table walker reads behind the
/// compiler's back; ordinary stores could be reordered or elided).
fn page_set(p: &Page, idx: usize, desc: u64) {
    debug_assert!(idx < 512);
    // SAFETY: `p` is one of this module's static 4096-aligned `Page`s; the cell
    // is `#[repr(C, align(4096))]` over `[u64; 512]`, so casting to `*mut u64`
    // and offsetting by `idx < 512` stays in bounds and aligned. Single vCPU:
    // no concurrent CPU-side access; the walker is sequenced by the explicit
    // `dsb`s at the call sites in `user_demo`.
    unsafe { write_volatile((p.0.get() as *mut u64).add(idx), desc) }
}

/// L2 table for the user window (hung under root L1[3]; entry covers 2 MiB).
static USER_L2: Page = Page::new();
/// L3 table for the user window (hung under USER_L2[0]; entry covers 4 KiB).
static USER_L3: Page = Page::new();
/// The physical backing frame for the user stack page.
static USER_STACK_FRAME: Page = Page::new();

/// Kernel longjmp save area: x19..x28, x29(FP), x30(LR) at byte offsets
/// 0x00..0x58, then the kernel SP at 0x60 (13 words; padded to 16 for
/// alignment headroom). Written by [`enter_el0`], reloaded by the SVC handler.
#[repr(C, align(16))]
struct ResumeBuf(UnsafeCell<[u64; 16]>);

// SAFETY: as `Page` -- single vCPU, raw-pointer (asm) access only, no interior
// reference ever minted. Written exactly once per `enter_el0` call and read
// exactly once on the matching SVC longjmp, with no interleaving.
unsafe impl Sync for ResumeBuf {}

static KERNEL_RESUME: ResumeBuf = ResumeBuf(UnsafeCell::new([0; 16]));

/// Set true by the SVC handler when it observes the `svc` from EL0.
static SYSCALL_SEEN: AtomicBool = AtomicBool::new(false);
/// The `x0` argument captured from the EL0 `svc` (expected `0xCAFE`).
static SYSCALL_ARG: AtomicU64 = AtomicU64::new(0);

// ===========================================================================
// Privileged system-register / barrier wrappers (asm confined here)
// ===========================================================================

// -- read_ttbr0_el1() --------------------------------------------------------
// (a) PRE : EL1, MMU live (post `mmu_init`). POST: returns the raw TTBR0_EL1.
// (b) ABI : one `mrs`; no memory, no stack, NZCV preserved.
// (c) TEST: `user_demo` masks the result to find the live L1 root.
fn read_ttbr0_el1() -> u64 {
    let v: u64;
    // SAFETY: TTBR0_EL1 is an EL1-readable system register; `mrs` has no memory
    // or stack effect and leaves NZCV unchanged. We run at EL1.
    unsafe {
        asm!("mrs {0}, ttbr0_el1", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

// -- read_esr_el1() ----------------------------------------------------------
// (a) PRE : in the SVC handler, before any nested exception. POST: returns the
//           syndrome of the `svc` (EC == 0x15).
// (b) ABI : one `mrs`; no memory, no stack, NZCV preserved.
// (c) TEST: the handler asserts `EC == EC_SVC64` before recording the arg.
fn read_esr_el1() -> u64 {
    let v: u64;
    // SAFETY: ESR_EL1 is an EL1-readable system register; side-effect-free load.
    unsafe {
        asm!("mrs {0}, esr_el1", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

// -- dsb_ishst() / isb() -----------------------------------------------------
// Publish-store barrier and pipeline resync used when splicing the new user
// chain into the live root (same sequencing rule as `mmu.rs`).
fn dsb_ishst() {
    // SAFETY: a barrier is side-effect-free synchronization, always legal at EL1.
    unsafe { asm!("dsb ishst", options(nostack, preserves_flags)) }
}
fn isb() {
    // SAFETY: as `dsb_ishst`.
    unsafe { asm!("isb", options(nostack, preserves_flags)) }
}

/// Write a `u64` as a fixed-width `0x…` 16-hex-digit string over serial. Pure
/// safe Rust over the tb-hal byte writer (no `core::fmt`, no allocation).
fn write_hex_u64(value: u64) {
    crate::serial_write_str("0x");
    let mut shift: i32 = 60;
    while shift >= 0 {
        let nibble = ((value >> shift) & 0xf) as u8;
        let c = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
        crate::serial_write_byte(c);
        shift -= 4;
    }
}

// ===========================================================================
// Exception frame mirror (must match `vectors.rs` SAVE_CONTEXT, exactly as in
// `trap.rs`): x0..x30 @ 0x00..0xF0, ELR_EL1 @ 0xF8, SPSR_EL1 @ 0x100, 0x110 B.
// We only read x0 (the syscall arg), but the full struct documents + locks the
// layout the trampoline hands us.
// ===========================================================================
#[repr(C)]
#[allow(dead_code)] // elr/spsr/_pad are part of the ABI but unread here
pub(super) struct Frame {
    /// x0..x30 (x30 = LR), offsets 0x00..0xF0. `gpr[0]` carries the `svc` arg.
    gpr: [u64; 31],
    /// ELR_EL1 (the EL0 return address) at exception entry, offset 0xF8.
    elr: u64,
    /// SPSR_EL1 (the EL0 PSTATE) at exception entry, offset 0x100.
    spsr: u64,
    /// Alignment pad; frame size is 0x110 (16-aligned).
    _pad: u64,
}
const _: () = assert!(core::mem::size_of::<Frame>() == 0x110);
const _: () = assert!(core::mem::offset_of!(Frame, gpr) == 0x00);
const _: () = assert!(core::mem::offset_of!(Frame, elr) == 0xF8);
const _: () = assert!(core::mem::offset_of!(Frame, spsr) == 0x100);

// ===========================================================================
// The user stub: a position-independent EL0 payload (runs at USER_CODE_VA)
// ===========================================================================
// (a) PRE : reached only by the `eret` in `enter_el0`, executing at EL0t with
//           SP_EL0 = USER_STACK_TOP_VA and the page mapped EL0-RW + executable
//           (UXN=0). POST: traps to EL1 via `svc #0` with x0 = 0xCAFE; never
//           runs past the `svc` (the kernel keeps control and does not return).
// (b) ABI : `#[unsafe(naked)]` -- the body is EXACTLY these three instructions,
//           all PC-relative / immediate (no absolute relocation), so it is
//           valid at the aliased USER_CODE_VA. `mov x0,#0xcafe` is a single
//           MOVZ (0xCAFE fits in 16 bits). The target has no BTI, so no `bti`
//           landing pad is inserted.
// (c) TEST: scripts/run-aarch64.sh -- the handler prints
//           "syscall from user: arg=0x...cafe" and the kernel prints
//           "M4: user/ring OK".
/// The unprivileged (EL0) test payload: pass `0xCAFE` and `svc #0`, then spin.
#[unsafe(naked)]
extern "C" fn user_stub() -> ! {
    naked_asm!(
        "mov x0, #0xcafe", // magic arg in x0 (preserved across svc)
        "svc #0",          // synchronous trap to EL1 (ESR_EL1.EC = 0x15)
        "1: b 1b",         // unreachable: the kernel never returns to EL0
    )
}

// ===========================================================================
// enter_el0: kernel setjmp + drop to EL0 via eret
// ===========================================================================
// (a) PRE : EL1h, MMU live, the user code/stack pages mapped (USER_CODE_VA /
//           USER_STACK_VA). x0 = entry VA (USER_CODE_VA | code-offset), x1 =
//           user stack top. POST: the caller's AAPCS64 callee-saved regs + LR
//           + SP are saved in KERNEL_RESUME, then `eret` enters EL0t at x0 with
//           SP_EL0 = x1 and DAIF masked. Control "returns" to the caller ONLY
//           later, via the SVC handler's longjmp (which reloads KERNEL_RESUME).
// (b) ABI : `#[unsafe(naked)]`. Inputs x0/x1 (AAPCS64 arg0/arg1). Uses only x9
//           /x10 as scratch before the eret; x19..x30 are stored unmodified.
//           SP_EL1 is unchanged by the eret (EL0t runs on SP_EL0), so the
//           kernel stack is intact when the `svc` re-enters EL1h.
// (c) TEST: scripts/run-aarch64.sh -- the round-trip completes and
//           `user_demo` returns true.
/// Save the kernel resume context and `eret` down to EL0 at `entry_va` with
/// `SP_EL0 = stack_top`. Appears to "return" to its caller once the EL0 `svc`
/// is handled (the SVC handler longjmps back through [`KERNEL_RESUME`]).
#[unsafe(naked)]
extern "C" fn enter_el0(entry_va: u64, stack_top: u64) {
    naked_asm!(
        // -- setjmp: stash callee-saved + LR + SP into KERNEL_RESUME ---------
        "adrp x9, {save}",
        "add  x9, x9, :lo12:{save}",
        "mov  x10, sp",
        "stp  x19, x20, [x9, #0x00]",
        "stp  x21, x22, [x9, #0x10]",
        "stp  x23, x24, [x9, #0x20]",
        "stp  x25, x26, [x9, #0x30]",
        "stp  x27, x28, [x9, #0x40]",
        "stp  x29, x30, [x9, #0x50]", // FP + LR (caller's resume address)
        "str  x10,      [x9, #0x60]", // kernel SP
        // -- program the EL0 entry and drop privilege -----------------------
        "msr  sp_el0, x1",            // user stack top
        "msr  elr_el1, x0",           // user code entry VA
        "mov  x10, #0x3c0",           // SPSR_EL1 = EL0t (M=0) + DAIF masked
        "msr  spsr_el1, x10",
        "isb",                        // ensure ELR/SPSR/SP_EL0 are visible
        "eret",                       // -> EL0t at USER_CODE_VA
        save = sym KERNEL_RESUME,
    )
}

// ===========================================================================
// aarch64_el0_sync_handler: the real "Lower EL using AArch64, Synchronous"
// handler (called by vectors.rs `__vec_el0_sync` after SAVE_CONTEXT)
// ===========================================================================
// (a) PRE : entered at EL1h from the EL0 synchronous vector; x0 = &Frame (the
//           0x110 SAVE_CONTEXT frame on the kernel stack); ESR_EL1 still holds
//           the `svc` syndrome. POST: never returns normally -- records the
//           syscall (if EC == 0x15) and longjmps back into `enter_el0`'s caller
//           via KERNEL_RESUME. The EL0 context (ELR/SPSR/SP_EL0) is abandoned.
// (b) ABI : `extern "C"`, `#[no_mangle]` so the vector trampoline can `bl` it.
//           `-> !`: the trailing `asm!(options(noreturn))` restores x19..x30 +
//           SP and `ret`s to the saved LR. x9 is scratch (caller-saved).
// (c) TEST: scripts/run-aarch64.sh -- prints "syscall from user: arg=0x...cafe"
//           and the kernel reports "M4: user/ring OK".
/// EL0 synchronous handler: record the `svc` argument, then longjmp back into
/// the kernel (the milestone deliberately does NOT resume EL0).
#[no_mangle]
pub(super) extern "C" fn aarch64_el0_sync_handler(frame: *const Frame) -> ! {
    // SAFETY: `frame` is `sp` immediately after the trampoline's 0x110-byte
    // SAVE_CONTEXT push -- a fully-initialised, 16-aligned `Frame` on the
    // kernel (SP_EL1) stack, live for this whole call. Single core, with
    // interrupts masked while we run, so we are the only accessor.
    let frame = unsafe { &*frame };

    let esr = read_esr_el1();
    let ec = (esr >> ESR_EC_SHIFT) & ESR_EC_MASK;

    if ec == EC_SVC64 {
        // x0 of the trapping EL0 context = the syscall argument.
        let arg = frame.gpr[0];
        SYSCALL_ARG.store(arg, Ordering::Release);
        SYSCALL_SEEN.store(true, Ordering::Release);
        crate::serial_write_str("syscall from user: arg=");
        write_hex_u64(arg);
        crate::serial_write_byte(b'\n');
    } else {
        // Any other synchronous exception from EL0 (e.g. an instruction/data
        // abort if the user mapping were wrong) is unexpected. Report it and
        // still longjmp back -- `user_demo` then sees SYSCALL_SEEN == false and
        // returns false, rather than wedging the core.
        crate::serial_write_str("user-test: unexpected EL0 sync, esr=");
        write_hex_u64(esr);
        crate::serial_write_byte(b'\n');
    }

    // -- longjmp: abandon the EL0 context, reload KERNEL_RESUME, `ret` into
    //    enter_el0's caller (as if enter_el0 had returned). After the SP
    //    reset, the exception frame + this handler's frame are discarded.
    // SAFETY: KERNEL_RESUME was just written by `enter_el0` (this call is the
    // matching pop). We restore exactly the AAPCS64 callee-saved set + SP it
    // saved and branch to the saved LR. `noreturn`: control never falls
    // through, so the abandoned frames below the restored SP are inert.
    unsafe {
        asm!(
            "adrp x9, {save}",
            "add  x9, x9, :lo12:{save}",
            "ldp  x19, x20, [x9, #0x00]",
            "ldp  x21, x22, [x9, #0x10]",
            "ldp  x23, x24, [x9, #0x20]",
            "ldp  x25, x26, [x9, #0x30]",
            "ldp  x27, x28, [x9, #0x40]",
            "ldp  x29, x30, [x9, #0x50]", // FP + LR (the kernel resume address)
            "ldr  x9,  [x9, #0x60]",      // kernel SP
            "mov  sp, x9",
            "ret",                        // -> enter_el0's caller (user_demo)
            save = sym KERNEL_RESUME,
            options(noreturn),
        )
    }
}

// ===========================================================================
// user_demo: the whole aarch64 M4 round-trip (the safe public surface)
// ===========================================================================
// (a) PRE : called once from `rust_main` AFTER mmu_init()/mmu_selftest() and
//           install_traps() (the MMU is live and the EL0 vector slot is armed).
//           POST: USER_CODE_VA/USER_STACK_VA are mapped EL0-accessible; the CPU
//           dropped to EL0, ran the stub, trapped back via `svc`, and the
//           kernel resumed here. Returns true iff the syscall was observed from
//           EL0 with arg == 0xCAFE.
// (b) ABI : plain safe function; all asm confined to the helpers/naked fns
//           above, so the `#![forbid(unsafe_code)]` kernel only sees a `bool`.
// (c) TEST: scripts/run-aarch64.sh -- "M4: user/ring OK" iff this returns true.
/// Map an EL0 code+stack page, drop to EL0 at a tiny stub that issues one
/// `svc`, handle it in the kernel, and prove the round-trip. `true` = pass.
pub fn user_demo() -> bool {
    // (1) Resolve the stub's physical (identity) address and split it into a
    //     page base + in-page offset. The stub is in `.text` (identity-mapped
    //     Normal WB under L1[1]), so its VA == PA.
    let stub_pa = user_stub as *const () as u64;
    let code_page_pa = stub_pa & !0xFFF;
    let code_offset = stub_pa & 0xFFF;
    let entry_va = USER_CODE_VA | code_offset;

    // (2) Build the L3 leaves: code (EL0 RW + executable) and stack (EL0 RW,
    //     no-execute), then hang L3 under our L2[0]. Publish before linking the
    //     chain into the live root so the walker never sees it half-built.
    page_set(&USER_L3, USER_CODE_L3_IDX, code_page_pa | PAGE_USER_CODE);
    page_set(&USER_L3, USER_STACK_L3_IDX, USER_STACK_FRAME.pa() | PAGE_USER_STACK);
    page_set(&USER_L2, 0, USER_L3.pa() | DESC_TABLE);
    dsb_ishst();

    // (3) Plug our L2 into the LIVE root at L1[3] (read out of TTBR0_EL1 -- no
    //     dependency on mmu.rs's private ID_L1). L1[3] was invalid, so a first
    //     map needs no TLBI; publish + resync the pipeline.
    let l1 = (read_ttbr0_el1() & TTBR_BADDR_MASK) as *mut u64;
    // SAFETY: `l1` is the physical base of the live L1 table, which lives in the
    // identity-mapped RAM gigabyte (so PA == VA, directly writable) and has 512
    // 8-byte entries; USER_L1_IDX = 3 is in bounds. Single vCPU; the walker is
    // sequenced by the surrounding `dsb ishst`/`isb`.
    unsafe { write_volatile(l1.add(USER_L1_IDX), USER_L2.pa() | DESC_TABLE) };
    dsb_ishst();
    isb();

    // (4) Arm the result cells, then drop to EL0 at the stub. The SVC handler
    //     records the arg and longjmps back here (enter_el0 "returns").
    SYSCALL_SEEN.store(false, Ordering::Release);
    SYSCALL_ARG.store(0, Ordering::Release);
    enter_el0(entry_va, USER_STACK_TOP_VA);

    // (5) Verdict: the `svc` must have been observed from EL0 with arg 0xCAFE.
    SYSCALL_SEEN.load(Ordering::Acquire) && SYSCALL_ARG.load(Ordering::Acquire) == USER_SYSCALL_ARG
}
