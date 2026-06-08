//! x86_64 user/ring boundary (M4): drop the CPU to ring 3, run a tiny user
//! stub there, have it `int 0x80` back into the kernel, handle the syscall in
//! safe-ish tb-hal Rust, and return the round-trip verdict. ALL of M4's
//! x86_64 `unsafe`/asm lives HERE (plus the small descriptor edits in
//! `gdt.rs`/`idt.rs`); the kernel crate stays `#![forbid(unsafe_code)]`
//! (KERNEL-FOUNDATION-SPEC §1) and only calls the safe [`user_demo`].
//!
//! THE ROUND TRIP (M4-v1 uses the EXISTING trap mechanism — a DPL=3 IDT gate
//! for `int 0x80` — NOT the SYSCALL/SYSRET fast path, which is a deferred
//! optimization):
//!
//!  1. [`user_demo`] maps a fresh, ring3-accessible code page + stack page
//!     (`USER_CODE_VA` / `USER_STACK_VA`) into the LIVE CR3 hierarchy via the
//!     M3 typed table layer, with `U/S = 1` (bit 2) on EVERY level of the walk
//!     (PML4E→PDPTE→PDE→PTE) — supervisor-only entries would `#PF` the moment
//!     ring3 touches them (Intel SDM Vol.3A §4.6 "Access Rights": a user-mode
//!     access is allowed only if `U/S = 1` in *every* paging-structure entry
//!     controlling the translation). The boot map's `PML4[0]` is `U/S = 0`, so
//!     we deliberately place the user range in a SEPARATE, vacant PML4 slot
//!     (`0x0000_0080_0000_0000` → `PML4[1]`) and build our OWN
//!     PML4E/PDPTE/PDE/PTE chain with `U/S = 1` throughout.
//!  2. The code page is loaded with the bytes of [`enter_ring3`]'s companion
//!     stub `user_stub` (a position-independent naked fn: `mov rax,0xCAFE;
//!     int 0x80; jmp .`). The stub is COPIED into an isolated, page-aligned
//!     `.bss` frame (sourced via the stub's identity-mapped symbol) rather
//!     than aliasing the kernel `.text` page into ring3 — this keeps ring3
//!     from reading neighbouring kernel code and sidesteps any page-straddle.
//!  3. [`enter_ring3`] parks the kernel callee-saved registers, records the
//!     kernel resume SP, builds the `iret` frame `[SS, RSP, RFLAGS, CS, RIP]`
//!     and `iretq`s into ring3 at `USER_CODE_VA`. Verified `iretq` pop order
//!     (Intel SDM Vol.2 IRET/IRETD/IRETQ "Operation", IA-32e 64-bit path):
//!     `RIP := Pop(); CS := Pop(); tempRFLAGS := Pop();` then, because
//!     `CS.RPL (3) > CPL (0)`, RETURN-TO-OUTER-PRIVILEGE-LEVEL does
//!     `tempRSP := Pop(); tempSS := Pop();` — so the frame is BUILT by pushing
//!     SS, RSP, RFLAGS, CS, RIP in that order (RIP ends up on top).
//!  4. The stub issues `int 0x80`. The CPU sees a ring3→ring0 privilege change
//!     so it loads RSP from `TSS.RSP0` (programmed in `gdt::init`; Intel SDM
//!     Vol.3A §6.14.4 / §7.7 Fig 7-11, RSP0 at TSS byte offset 0x04), pushes
//!     the interrupt frame there, and vectors through the DPL=3 gate
//!     (`idt::set_user_gate`, type_attr 0xEE) into [`syscall_entry`].
//!  5. [`syscall_entry`] reads the syscall arg from `rax` (= `0xCAFE`), calls
//!     the Rust [`x86_syscall_handler`] (records the arg, prints
//!     `syscall from user: arg=0x...`, sets the seen flag), then performs a
//!     NON-LOCAL RETURN into the kernel: it abandons the RSP0 frame, reloads
//!     the resume SP `enter_ring3` parked, pops the kernel callee-saved set
//!     and `ret`s — so control lands back in [`user_demo`] exactly as if
//!     `enter_ring3` had returned. We never `iretq` back to ring3 (the stub's
//!     `jmp .` would just spin); the syscall IS the kernel re-entry. This is
//!     the spec's "set the flag and resume into a kernel landing point"
//!     design, realized as a direct stack switch (no iret frame rewrite, so
//!     no kernel SS/CS to fabricate).
//!  6. [`user_demo`] returns `true` iff the syscall was observed from ring3
//!     with the expected arg.
//!
//! VERIFIED FACTS quoted from primary sources (do NOT change these without
//! re-reading them):
//!   * `iretq` inter-privilege frame `[SS, RSP, RFLAGS, CS, RIP]` + pop order:
//!     Intel SDM Vol.2A "IRET/IRETD/IRETQ — Interrupt Return", Operation
//!     pseudocode (IA-32e mode, OperandSize 64 → RIP/CS/tempRFLAGS popped,
//!     then RETURN-TO-OUTER-PRIVILEGE-LEVEL pops tempRSP/tempSS); OSDev
//!     "Getting to Ring 3".
//!   * Ring3 GDT descriptors — access byte `0xFA` user code
//!     (P=1,DPL=3,S=1,E=1,RW=1) and `0xF2` user data (P=1,DPL=3,S=1,RW=1);
//!     selectors loaded with `RPL = 3`: Intel SDM Vol.3A §3.4.5 Fig 3-8
//!     "Segment Descriptor"; §5.5/§5.8.1 (RPL/DPL/CPL). See `gdt.rs`.
//!   * `int n` from ring3 needs the gate's `DPL >= CPL` — gate DPL=3
//!     (type_attr `0xEE`): Intel SDM Vol.3A §6.12.1.2 "the processor checks
//!     that the CPL is less than or equal to the DPL of the [interrupt/trap]
//!     gate"; Fig 6-8 "64-Bit IDT Gate Descriptors". See `idt.rs`.
//!   * `TSS.RSP0` is loaded on the ring3→ring0 stack switch: Intel SDM Vol.3A
//!     §6.14.4 "Stack Switching", §7.7 Fig 7-11 (RSP0 at byte 0x04). See
//!     `gdt.rs`.
//!   * Paging `U/S` (bit 2) required at EVERY level for ring3 access: Intel
//!     SDM Vol.3A §4.6 "Access Rights"; bit positions cross-checked against
//!     Linux v6.6 `arch/x86/include/asm/pgtable_types.h` (`_PAGE_BIT_USER 2`,
//!     `_PAGE_BIT_NX 63`). NX (bit 63) is honoured because M3's `mmu_init`
//!     already set `IA32_EFER.NXE`.

use core::arch::{asm, global_asm, naked_asm};
use core::cell::UnsafeCell;
use core::ptr::{addr_of, copy_nonoverlapping, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::mmu::PageTable512;

use super::gdt;
use super::idt;

// ---------------------------------------------------------------------------
// Architectural constants (verified — see module header).
// ---------------------------------------------------------------------------

/// Paging-entry bit 0: Present (Intel SDM Vol.3A Table 4-15; Linux
/// `_PAGE_BIT_PRESENT 0`).
const PTE_P: u64 = 1 << 0;
/// Paging-entry bit 1: Read/Write (Linux `_PAGE_BIT_RW 1`).
const PTE_RW: u64 = 1 << 1;
/// Paging-entry bit 2: User/Supervisor — MUST be 1 at every level for ring3
/// access (Intel SDM Vol.3A §4.6; Linux `_PAGE_BIT_USER 2`).
const PTE_US: u64 = 1 << 2;
/// Paging-entry bit 63: Execute-Disable (honoured because `mmu_init` set
/// `IA32_EFER.NXE`; Linux `_PAGE_BIT_NX 63`).
const PTE_NX: u64 = 1 << 63;

/// Physical-address field of any paging entry: bits 51:12 (Intel SDM Vol.3A
/// Table 4-15). Masking strips flag/ignored bits when walking CR3.
const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// User code virtual address: 2^39 = `PML4[1]` — a SEPARATE, vacant PML4 slot
/// from the boot map's `PML4[0]` (which is `U/S = 0` and cannot be reused for
/// ring3). Canonical (bits 63:48 = sign-extension of bit 47 = 0).
const USER_CODE_VA: usize = 0x0000_0080_0000_0000;
/// User stack virtual address: the next page after the code page.
const USER_STACK_VA: usize = USER_CODE_VA + 0x1000;
/// Initial ring3 RSP: the exclusive top of the (one-page) user stack. Stacks
/// grow down, so the first push lands at `USER_STACK_TOP - 8`, inside the
/// mapped page. 16-aligned (SysV), though the stub never touches the stack.
const USER_STACK_TOP: u64 = (USER_STACK_VA + 0x1000) as u64;

/// `USER_CODE_VA`'s PML4 index (VA bits 47:39) — `1`, the vacant slot.
const PML4_IDX: usize = (USER_CODE_VA >> 39) & 0x1FF;
/// `USER_CODE_VA`'s PDPT index (VA bits 38:30) — `0`.
const PDPT_IDX: usize = (USER_CODE_VA >> 30) & 0x1FF;
/// `USER_CODE_VA`'s PD index (VA bits 29:21) — `0`.
const PD_IDX: usize = (USER_CODE_VA >> 21) & 0x1FF;
/// `USER_CODE_VA`'s PT index (VA bits 20:12) — `0`.
const CODE_PT_IDX: usize = (USER_CODE_VA >> 12) & 0x1FF;
/// `USER_STACK_VA`'s PT index (VA bits 20:12) — `1` (same PML4/PDPT/PD chain).
const STACK_PT_IDX: usize = (USER_STACK_VA >> 12) & 0x1FF;

/// IDT vector the user stub traps through (the classic Linux `int 0x80`).
const SYSCALL_VECTOR: usize = 0x80;

/// The magic syscall argument the user stub passes in `rax`; observing it in
/// ring0 proves we genuinely trapped back FROM ring3 (b"...0xCAFE").
const EXPECTED_ARG: u64 = 0xCAFE;

/// Ring3 `RFLAGS`: ONLY reserved bit 1 (always 1); IF (bit 9) is left CLEAR so
/// ring3 runs with interrupts MASKED. M0–M4 take NO asynchronous interrupt by
/// design — M8 is the first interrupt-enable (docs/ROADMAP-V2.md §3: "M0–M4 ran
/// fully masked"). Entering ring3 with IF=1 (the old `0x202`) opened a tiny
/// window — the two stub instructions before `int 0x80` — in which a stray
/// asynchronous event could be delivered into the fatal trap path (seen as an
/// intermittent fault under QEMU TCG, whose event timing is host-load-dependent
/// and differs from KVM's in-kernel APIC); keeping IF=0 closes it. The stub's
/// `int 0x80` still traps fine with IF=0 (software interrupts ignore IF), and
/// the kernel issues no `sti` before M8 (Intel SDM Vol.1 §3.4.3 EFLAGS).
const USER_RFLAGS: u64 = 0x2;

// ---------------------------------------------------------------------------
// Round-trip observation state (single-vCPU, interrupts masked since boot).
// ---------------------------------------------------------------------------

/// Set by [`x86_syscall_handler`] when the syscall is observed from ring3.
static SYSCALL_SEEN: AtomicBool = AtomicBool::new(false);
/// The syscall arg captured from the user `rax` (expected [`EXPECTED_ARG`]).
static SYSCALL_ARG: AtomicU64 = AtomicU64::new(0);

/// Kernel stack pointer parked by [`enter_ring3`] and reloaded by
/// [`syscall_entry`] to perform the non-local return into the kernel. Touched
/// ONLY from the two naked-asm bodies (never via a Rust reference), so a plain
/// `static mut` reached by `sym` is the cleanest channel and raises no
/// `static_mut_refs` concern (we take its address, never a reference).
static mut KERNEL_RESUME_SP: u64 = 0;

// ---------------------------------------------------------------------------
// Static 4 KiB cells (.bss): the user PDPT/PD/PT chain + the code/stack pages.
// ---------------------------------------------------------------------------

/// A 4096-aligned, interior-mutable 4 KiB cell that lives in an immutable
/// `static` (zero-initialised → `.bss`, cleared by the boot trampoline) while
/// tb-hal mutates it through raw pointers. Reuses the shared typed layout
/// [`PageTable512`] (`#[repr(C, align(4096))]` over `[u64; 512]`) for both the
/// new paging tables and the data pages (a code/stack page is just 4 KiB of
/// `.bss`). Mirrors the same pattern as `mmu.rs` (kept module-local so M4's
/// edits stay confined to the files M4 owns).
#[repr(C)]
struct Cell4K(UnsafeCell<PageTable512>);

// SAFETY: M4 is single-vCPU with interrupts masked since boot; every access to
// the interior goes through raw pointers from `UnsafeCell::get` (no `&`/`&mut`
// to the interior is ever materialised), so sharing the cell via an immutable
// `static` cannot violate aliasing. `UnsafeCell` is what makes in-place
// mutation behind an immutable `static` defined behaviour.
unsafe impl Sync for Cell4K {}

impl Cell4K {
    /// A new zeroed cell; `const`, so it can initialise a `static` in `.bss`.
    const fn new() -> Self {
        Cell4K(UnsafeCell::new(PageTable512([0; 512])))
    }

    /// Raw pointer to the 8-byte entry `idx` of this cell (`idx < 512`).
    fn entry_ptr(&self, idx: usize) -> *mut u64 {
        debug_assert!(idx < 512);
        // SAFETY: `idx < 512` keeps the offset inside this one 4096-byte
        // allocation; `PageTable512` is `repr(C, align(4096))` over
        // `[u64; 512]`, so the element cast + offset is layout-exact.
        unsafe { (self.0.get() as *mut u64).add(idx) }
    }

    /// Raw byte pointer to the start of this cell (used to stage the stub).
    fn byte_ptr(&self) -> *mut u8 {
        self.0.get() as *mut u8
    }

    /// PHYSICAL base address of this cell (virtual == physical: the kernel
    /// image and its `.bss` are loaded at 1 MiB and the boot tables
    /// identity-map [0, 1 GiB)). 4096-aligned, so it drops straight into the
    /// bits-51:12 address field of a paging entry.
    fn phys_base(&self) -> u64 {
        self.0.get() as u64
    }
}

/// New PDPT hung off the live `PML4[1]`.
static USER_PDPT: Cell4K = Cell4K::new();
/// New PD behind `USER_PDPT[0]`.
static USER_PD: Cell4K = Cell4K::new();
/// New PT behind `USER_PD[0]`, holding the code + stack leaf PTEs.
static USER_PT: Cell4K = Cell4K::new();
/// The ring3 code page — the user stub is copied here, mapped P|U (exec).
static USER_CODE: Cell4K = Cell4K::new();
/// The ring3 stack page — mapped P|RW|U|NX.
static USER_STACK: Cell4K = Cell4K::new();

// ===========================================================================
// The position-independent ring3 user stub.
// (a) PRE: entered in ring3 at USER_CODE_VA with a valid user SS:RSP. POST:
//     loads the magic arg into rax, traps to the kernel via `int 0x80`; the
//     kernel does NOT return here (it longjmps back to the kernel), so the
//     trailing `jmp .` is an unreachable safety spin.
// (b) ABI: PURE position-independent code — `mov rax,imm` (B8/48C7C0),
//     `int 0x80` (CD 80), `jmp .` (EB FE) — no absolute/RIP refs, so it runs
//     correctly at the aliased USER_CODE_VA after being COPIED there. Intel
//     syntax (Rust default). `.text.user` is matched by the linker's
//     `*(.text .text.*)`, landing in the identity-mapped, ring0-readable
//     `.text` so the copy source is reachable.
// (c) Tested by: scripts/run-x86_64.sh ("M4: user/ring OK"; the kernel only
//     prints it after `user_demo` observes arg=0xCAFE FROM ring3).
// ===========================================================================
global_asm!(
    r#"
.section .text.user, "ax", @progbits
.balign 16
.global user_stub_start
.global user_stub_end
user_stub_start:
    mov rax, 0xCAFE         // syscall arg → rax (proves the trap came from us)
    int 0x80                // ring3 → ring0 via the DPL=3 vector-0x80 gate
2:
    jmp 2b                  // unreachable: the kernel longjmps, never iretq's back
user_stub_end:
"#
);

extern "C" {
    /// First byte of the ring3 stub (its identity-mapped symbol = its phys).
    static user_stub_start: u8;
    /// One-past-the-last byte of the ring3 stub.
    static user_stub_end: u8;
}

// ---------------------------------------------------------------------------
// Privileged register wrappers: the M4-local paging pokes (CR3 read + invlpg).
// (mmu.rs has equivalents, but they are private to that module; keeping these
// here confines M4's edits to the files M4 owns.)
// ---------------------------------------------------------------------------

/// Read CR3 — physical base of the live PML4 (plus PWT/PCD bits we mask off).
///
/// (a) PRE: long mode, ring 0. POST: returns live CR3; no state change.
/// (b) ABI: `mov {out}, cr3`; one GPR out; no flags; nomem/nostack.
/// (c) Tested by: scripts/run-x86_64.sh ("M4: user/ring OK" — used to splice
///     `PML4[1]` into the live hierarchy).
#[inline]
unsafe fn read_cr3() -> u64 {
    let val: u64;
    // SAFETY: ring-0-only read; caller is inside tb-hal.
    unsafe {
        asm!("mov {}, cr3", out(reg) val, options(nomem, nostack, preserves_flags));
    }
    val
}

/// `invlpg [va]` — invalidate any TLB entry for the page containing `va`.
///
/// (a) PRE: ring 0, paging on. POST: next access to `va` re-walks the tables.
/// (b) ABI: `invlpg [{in}]`; address operand only (never dereferenced as
///     data); no flags; NOT nomem (must order vs surrounding accesses).
/// (c) Tested by: scripts/run-x86_64.sh ("M4: user/ring OK"). Strictly
///     belt-and-suspenders here: building `PML4[1]` is a 0→1 Present
///     transition, which needs no invalidation (Intel SDM Vol.3A §4.10.4.3).
#[inline]
unsafe fn invlpg(va: usize) {
    // SAFETY: ring-0-only; see (a).
    unsafe {
        asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags));
    }
}

// ---------------------------------------------------------------------------
// Build the ring3 mapping: copy the stub, then splice a U/S=1 chain into CR3.
// ---------------------------------------------------------------------------

/// Stage the user code page and splice a ring3-accessible
/// `PML4[1]→PDPT[0]→PD[0]→PT[{0,1}]` chain into the LIVE CR3 hierarchy, with
/// `U/S = 1` on every level (Intel SDM Vol.3A §4.6). Built bottom-up and
/// PUBLISHED LAST (PML4 entry written after the subtree is complete) so the
/// page walker can never observe a half-built chain.
///
/// # Safety
/// Ring 0, single vCPU, interrupts masked. The five `Cell4K` statics are
/// tb-hal-owned and reached ONLY through `UnsafeCell` raw pointers, so no Rust
/// reference aliases the memory the CPU walker / ring3 alias touch. `PML4[1]`
/// is vacant in the boot map (boot uses only `PML4[0]`), so this adds a brand
/// new translation and disturbs nothing M0–M3 built.
unsafe fn map_user_pages() {
    // Copy the PIC stub into the isolated, page-aligned code frame (sourced via
    // its identity-mapped symbol; written through the frame's identity address,
    // a ring0 RW boot mapping — so SMAP, were it on, would not apply).
    let src = addr_of!(user_stub_start) as *const u8;
    let len = (addr_of!(user_stub_end) as usize) - (src as usize);
    debug_assert!(len <= 4096, "user stub must fit in one page");
    // SAFETY: `src` spans [user_stub_start, user_stub_end) in identity-mapped,
    // ring0-readable `.text`; `len <= 4096` keeps the write inside the one
    // 4 KiB `USER_CODE` frame; regions do not overlap.
    unsafe {
        copy_nonoverlapping(src, USER_CODE.byte_ptr(), len);
    }

    // SAFETY: every pointer below is a 4096-aligned tb-hal static or the live
    // PML4 read from CR3; all stores are volatile so the compiler neither
    // elides nor reorders them around the publish-last ordering.
    unsafe {
        // Leaves first. Code: P|U, NX clear (ring3 may fetch/execute), no RW
        // (the stub is never written from ring3). Stack: P|RW|U|NX.
        write_volatile(
            USER_PT.entry_ptr(CODE_PT_IDX),
            USER_CODE.phys_base() | PTE_P | PTE_US,
        );
        write_volatile(
            USER_PT.entry_ptr(STACK_PT_IDX),
            USER_STACK.phys_base() | PTE_P | PTE_RW | PTE_US | PTE_NX,
        );
        // Interior tables: P|RW|U (U/S=1 required at every level).
        write_volatile(
            USER_PD.entry_ptr(PD_IDX),
            USER_PT.phys_base() | PTE_P | PTE_RW | PTE_US,
        );
        write_volatile(
            USER_PDPT.entry_ptr(PDPT_IDX),
            USER_PD.phys_base() | PTE_P | PTE_RW | PTE_US,
        );
        // Publish last: splice into the live PML4 at the vacant slot 1.
        let pml4 = (read_cr3() & PTE_ADDR_MASK) as *mut u64;
        write_volatile(
            pml4.add(PML4_IDX),
            USER_PDPT.phys_base() | PTE_P | PTE_RW | PTE_US,
        );
        // 0→1 Present needs no flush (SDM §4.10.4.3); cheap insurance anyway.
        invlpg(USER_CODE_VA);
        invlpg(USER_STACK_VA);
    }
}

// ===========================================================================
// enter_ring3: drop CPL 0 → 3 via iretq, parking a kernel resume point.
// (a) PRE: called like a normal extern "C" fn (rdi=user RIP, rsi=user RSP,
//     rdx=user CS|3, rcx=user SS|3); GDT has the DPL3 user descriptors and
//     TSS.RSP0 is valid; USER_CODE/STACK mapped U/S=1. POST: does NOT return
//     normally — `iretq` transfers to ring3 at the stub. Control re-enters the
//     kernel only via `syscall_entry`, which restores the parked callee-saved
//     frame and `ret`s, so from the caller's view this fn returned normally.
// (b) ABI: SysV extern "C"; Intel syntax (Rust default). Saves the psABI
//     callee-saved set {rbx,rbp,r12-r15} so the syscall longjmp can hand the
//     caller back an intact register file; caller-saved regs are dead across
//     a call. iret frame order [SS,RSP,RFLAGS,CS,RIP] per Intel SDM Vol.2 IRET
//     (pops RIP,CS,RFLAGS then, for the outer-privilege return, RSP,SS).
// (c) Tested by: scripts/run-x86_64.sh ("M4: user/ring OK").
// ===========================================================================
#[unsafe(naked)]
unsafe extern "C" fn enter_ring3(user_rip: u64, user_rsp: u64, user_cs: u64, user_ss: u64) {
    naked_asm!(
        // Park the kernel's callee-saved context on the current kernel stack.
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        // Record the resume SP (top of the parked frame) for syscall_entry.
        "lea rax, [rip + {resume_sp}]",
        "mov [rax], rsp",
        // Build the inter-privilege iret frame, then drop to ring3.
        "push rcx",            // SS     = user_ss (user data | RPL3)
        "push rsi",            // RSP    = user_rsp (top of the user stack page)
        "push {rflags}",       // RFLAGS = 0x202 (IF=1, reserved bit 1)
        "push rdx",            // CS     = user_cs (user code | RPL3)
        "push rdi",            // RIP    = user_rip (USER_CODE_VA)
        "iretq",
        rflags = const USER_RFLAGS,
        resume_sp = sym KERNEL_RESUME_SP,
    )
}

// ===========================================================================
// syscall_entry: ring3 `int 0x80` lands here in ring0 on the TSS RSP0 stack.
// (a) PRE: the user stub executed `int 0x80`; the CPU switched to TSS.RSP0 and
//     pushed [SS,RSP,RFLAGS,CS,RIP] (no error code — INT n pushes none); rax
//     holds the syscall arg. POST: the arg is handed to the Rust handler, then
//     a NON-LOCAL return reloads the kernel resume SP, pops the parked
//     callee-saved set and `ret`s into enter_ring3's caller. The RSP0 frame is
//     abandoned (reused on the next syscall).
// (b) ABI: targeted by a DPL=3 64-bit INTERRUPT gate (IF cleared on entry).
//     RSP0 is 16-aligned; the CPU pushed 5 qwords (40 bytes) → rsp%16==8, so
//     `sub rsp,8` re-establishes the SysV 16-alignment before the `call`.
//     Intel syntax (Rust default).
// (c) Tested by: scripts/run-x86_64.sh ("M4: user/ring OK").
// ===========================================================================
#[unsafe(naked)]
unsafe extern "C" fn syscall_entry() {
    naked_asm!(
        // rax = syscall arg (0xCAFE) → SysV arg0 for the Rust handler.
        "mov rdi, rax",
        // Re-align to 16 for the SysV call (rsp%16==8 after the CPU's 5 pushes).
        "sub rsp, 8",
        "call {handler}",
        // Non-local return into the kernel: drop the RSP0 frame, reload the
        // parked kernel SP, restore callee-saved, and `ret` to user_demo.
        "lea rax, [rip + {resume_sp}]",
        "mov rsp, [rax]",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "ret",
        handler = sym x86_syscall_handler,
        resume_sp = sym KERNEL_RESUME_SP,
    )
}

/// The safe-ish kernel-side syscall handler (the ONLY Rust that observes the
/// trapped-back syscall). Records the arg, prints the proof line, and sets the
/// seen flag. Runs in ring0 on the TSS RSP0 stack; `serial_*` are the same
/// crate-root safe writers the rest of tb-hal uses.
extern "C" fn x86_syscall_handler(arg: u64) {
    SYSCALL_ARG.store(arg, Ordering::Release);
    SYSCALL_SEEN.store(true, Ordering::Release);
    crate::serial_write_str("syscall from user: arg=");
    write_hex_u64(arg);
    crate::serial_write_byte(b'\n');
}

// ---------------------------------------------------------------------------
// Safe M4 surface (re-exported through arch/mod.rs -> lib.rs).
// ---------------------------------------------------------------------------

/// Run the whole x86_64 ring0↔ring3 round trip and report success.
///
/// Sets up a ring3-accessible code + stack mapping, points the `int 0x80` IDT
/// gate at [`syscall_entry`] with DPL=3, drops to ring3 at the user stub, and
/// returns once the stub's syscall has trapped back and been handled. Returns
/// `true` iff the syscall was observed FROM ring3 carrying [`EXPECTED_ARG`]
/// (`0xCAFE`) — i.e. the full privileged/unprivileged split worked end-to-end.
///
/// Preconditions (met by `rust_main`'s ordering): `install_traps()` has run
/// (so the GDT carries the DPL3 user descriptors + a valid `TSS.RSP0`, and the
/// IDT is loaded) and `mmu_init()` has run (so `IA32_EFER.NXE` is set, making
/// the stack page's NX bit effective).
pub fn user_demo() -> bool {
    // 1. Map the ring3 code/stack pages (U/S=1 at every level) into live CR3.
    // SAFETY: ring 0, single vCPU, interrupts masked; see `map_user_pages`.
    unsafe {
        map_user_pages();
    }

    // 2. Open the syscall door: rewrite IDT vector 0x80 to a DPL=3 gate that
    //    targets `syscall_entry` (so `int 0x80` from ring3 is permitted).
    idt::set_user_gate(SYSCALL_VECTOR, syscall_entry as *const () as u64);

    // 3. (TSS.RSP0 is already programmed by `gdt::init`; nothing to do here.)

    // 4. Drop to ring3 at the stub. `enter_ring3` "returns" only via the
    //    syscall longjmp in `syscall_entry`.
    // SAFETY: the iret frame is fully formed — USER_CODE_VA/USER_STACK_TOP are
    // mapped U/S=1, and the selectors are the DPL3 user descriptors with RPL=3
    // (Intel SDM Vol.2 IRET inter-privilege checks: SS/CS RPL == 3 == their
    // DPL). Callee-saved state is parked + restored across the trip.
    unsafe {
        enter_ring3(
            USER_CODE_VA as u64,
            USER_STACK_TOP,
            (gdt::USER_CODE_SEL | 3) as u64,
            (gdt::USER_DATA_SEL | 3) as u64,
        );
    }

    // 5. Verdict: the syscall was observed from ring3 with the expected arg.
    SYSCALL_SEEN.load(Ordering::Acquire) && SYSCALL_ARG.load(Ordering::Acquire) == EXPECTED_ARG
}

/// Write a `u64` as a fixed-width 16-digit `0x…` hex string over serial.
/// Pure safe Rust (no `core::fmt`, no allocation), mirroring the kernel's own
/// helper so the proof line is self-contained inside tb-hal.
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
// M11: the numbered capability syscall path (the register-lift shim).
// ===========================================================================
// Generalises the M4 `int 0x80` round trip into a NUMBERED, capability-checked
// dispatcher entry. A second ring3 stub loads (method, handle, a0, a1) into
// (rax, rdi, rsi, rdx) and traps via a FRESH DPL=3 vector `int 0x81`; the new
// `caps_syscall_entry` is the ONLY new x86 unsafe -- it MARSHALS those
// registers out of the trap into SysV order and hands them to the safe Rust
// recorder. NO table walk / rights compare / generation logic in asm: the
// policy is the pure-safe `crate::caps::dispatch`, driven by the kernel from
// the lifted `SyscallArgs` this path records. The M4 path (vector 0x80 + the
// USER_CODE page) is left byte-for-byte intact.

/// The IDT vector the M11 numbered cap stub traps through (M4 owns 0x80).
const CAPS_SYSCALL_VECTOR: usize = 0x81;
/// The deterministic bootstrap capability the cap stub presents: the FIRST
/// mint into a fresh table is `(generation 1, slot 0)` == `1 << 32`.
const CAPS_PROBE_HANDLE: u64 = 0x0000_0001_0000_0000;
/// VA of the M11 cap code page: a THIRD leaf (`PT[2]`) under the same M4
/// `PML4[1]->PDPT[0]->PD[0]` chain (a first-map, so no TLB shootdown needed).
/// Does NOT touch the heap window (`PML4[2]`) or the LAPIC window (`PML4[3]`).
const CAPS_CODE_VA: usize = USER_CODE_VA + 0x2000;
/// `CAPS_CODE_VA`'s PT index (VA bits 20:12) -- `2` (M4 uses `PT[0]`/`PT[1]`).
const CAPS_PT_IDX: usize = (CAPS_CODE_VA >> 12) & 0x1FF;

/// Set by [`caps_x86_syscall_shim`] when the numbered cap syscall is observed.
static CAPS_SEEN: AtomicBool = AtomicBool::new(false);
/// The method selector lifted from the numbered cap syscall (`rax`).
static CAPS_METHOD: AtomicU64 = AtomicU64::new(0);
/// The target capability handle lifted from the numbered cap syscall (`rdi`).
static CAPS_HANDLE: AtomicU64 = AtomicU64::new(0);
/// Inline arg 0 lifted from the numbered cap syscall (`rsi`).
static CAPS_A0: AtomicU64 = AtomicU64::new(0);
/// Inline arg 1 lifted from the numbered cap syscall (`rdx`).
static CAPS_A1: AtomicU64 = AtomicU64::new(0);

/// The M11 cap code page (the numbered stub is copied here, mapped P|U exec).
static CAPS_CODE: Cell4K = Cell4K::new();

// The position-independent ring3 numbered-cap stub: load (method, handle, a0,
// a1) into (rax, rdi, rsi, rdx) and `int 0x81`. Handle = (gen 1, slot 0) is
// built with `mov edi,1; shl rdi,32` (NO imm64 relocation -> stays PIC at the
// aliased CAPS_CODE_VA). A distinct numeric label (`3:`) avoids clashing with
// the M4 stub's `2:` in the shared `.text.user` emission. The kernel longjmps
// back, so the trailing spin is unreachable.
global_asm!(
    r#"
.section .text.user, "ax", @progbits
.balign 16
.global caps_user_stub_start
.global caps_user_stub_end
caps_user_stub_start:
    xor eax, eax           // method = M_OBJECT_INSPECT (0)
    mov edi, 1             // build handle = (generation 1, slot 0) = 1 << 32 ...
    shl rdi, 32            //   ... no imm64, so the stub stays position-independent
    xor esi, esi           // a0 = 0
    xor edx, edx           // a1 = 0
    int 0x81               // ring3 -> ring0 via the DPL=3 vector-0x81 gate
3:
    jmp 3b                 // unreachable: the kernel longjmps, never iretq's back
caps_user_stub_end:
"#
);

extern "C" {
    /// First byte of the ring3 numbered-cap stub (identity-mapped == phys).
    static caps_user_stub_start: u8;
    /// One-past-the-last byte of the ring3 numbered-cap stub.
    static caps_user_stub_end: u8;
}

/// Stage the numbered-cap stub into [`CAPS_CODE`] and first-map it executable at
/// [`CAPS_CODE_VA`] (`PT[2]`) under the existing M4 chain.
///
/// # Safety
/// Ring 0, single vCPU, interrupts masked. [`map_user_pages`] must have run (it
/// is run by the caller) so the `PML4[1]->PDPT[0]->PD[0]->PT` chain + the user
/// stack page exist; this only adds a fresh leaf (`PT[2]` was zero), so no TLB
/// shootdown is required.
unsafe fn map_caps_code() {
    let src = addr_of!(caps_user_stub_start) as *const u8;
    let len = (addr_of!(caps_user_stub_end) as usize) - (src as usize);
    debug_assert!(len <= 4096, "cap stub must fit in one page");
    // SAFETY: `src` spans the PIC stub in identity-mapped, ring0-readable
    // `.text`; `len <= 4096` keeps the copy inside the one CAPS_CODE frame;
    // the regions are disjoint.
    unsafe {
        copy_nonoverlapping(src, CAPS_CODE.byte_ptr(), len);
        // First-map PT[2] -> the cap code page: P|U, NX clear (ring3 executes).
        write_volatile(
            USER_PT.entry_ptr(CAPS_PT_IDX),
            CAPS_CODE.phys_base() | PTE_P | PTE_US,
        );
        invlpg(CAPS_CODE_VA);
    }
}

// caps_syscall_entry: the ONLY new x86 unsafe -- the register-lift shim. ring3
// `int 0x81` lands here in ring0 on the TSS RSP0 stack with rax=method,
// rdi=handle, rsi=a0, rdx=a1. It shuffles them into SysV order and calls the
// safe Rust recorder, then performs the SAME non-local return as M4's
// `syscall_entry` (reload the parked kernel SP, pop callee-saved, ret).
#[unsafe(naked)]
unsafe extern "C" fn caps_syscall_entry() {
    naked_asm!(
        // Lift (method, handle, a0, a1) into SysV (rdi, rsi, rdx, rcx). The
        // moves are ordered so no source is clobbered before it is read.
        "mov rcx, rdx",   // a1     -> SysV arg4
        "mov rdx, rsi",   // a0     -> SysV arg3
        "mov rsi, rdi",   // handle -> SysV arg2
        "mov rdi, rax",   // method -> SysV arg1
        "sub rsp, 8",     // re-establish 16-alignment (CPU pushed 5 qwords)
        "call {shim}",
        // Non-local return into the kernel (identical to M4 syscall_entry).
        "lea rax, [rip + {resume_sp}]",
        "mov rsp, [rax]",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "ret",
        shim = sym caps_x86_syscall_shim,
        resume_sp = sym KERNEL_RESUME_SP,
    )
}

/// The safe Rust recorder for the lifted numbered cap syscall: stash the four
/// scalars + set the seen flag. The ENTIRE capability policy (resolve, rights
/// mask, generation check, method dispatch) is `crate::caps::dispatch`, run by
/// the kernel from the [`SyscallArgs`](crate::caps::SyscallArgs) it reads back.
extern "C" fn caps_x86_syscall_shim(method: u64, handle: u64, a0: u64, a1: u64) {
    CAPS_METHOD.store(method, Ordering::Release);
    CAPS_HANDLE.store(handle, Ordering::Release);
    CAPS_A0.store(a0, Ordering::Release);
    CAPS_A1.store(a1, Ordering::Release);
    CAPS_SEEN.store(true, Ordering::Release);
}

/// Drive ONE numbered, capability-checked syscall from ring3 through the
/// register-lift shim and return the neutral
/// [`SyscallArgs`](crate::caps::SyscallArgs) it lifted (`None` if the trap never
/// arrived or `root_handle` is not the deterministic bootstrap cap). Mirrors
/// [`user_demo`]; reuses the M4 ring3 machinery unchanged and only adds the new
/// cap stub + vector + lift shim.
pub fn caps_user_probe(root_handle: u64) -> Option<crate::caps::SyscallArgs> {
    if root_handle != CAPS_PROBE_HANDLE {
        return None;
    }
    // SAFETY: ring 0, single vCPU, interrupts masked. `map_user_pages`
    // (re)builds the M4 ring3 chain + stack page; `map_caps_code` adds the cap
    // code leaf. Both are idempotent here (M4 already ran).
    unsafe {
        map_user_pages();
        map_caps_code();
    }
    // Open the numbered syscall door at a fresh DPL=3 vector (M4 keeps 0x80).
    idt::set_user_gate(CAPS_SYSCALL_VECTOR, caps_syscall_entry as *const () as u64);
    CAPS_SEEN.store(false, Ordering::Release);
    // SAFETY: same iret-frame contract as `user_demo`; CAPS_CODE_VA is mapped
    // U/S=1 executable and the selectors are the DPL3 user descriptors (RPL=3).
    unsafe {
        enter_ring3(
            CAPS_CODE_VA as u64,
            USER_STACK_TOP,
            (gdt::USER_CODE_SEL | 3) as u64,
            (gdt::USER_DATA_SEL | 3) as u64,
        );
    }
    if !CAPS_SEEN.load(Ordering::Acquire) {
        return None;
    }
    Some(crate::caps::SyscallArgs {
        method: CAPS_METHOD.load(Ordering::Acquire) as u32,
        handle: crate::caps::Handle::from_raw(CAPS_HANDLE.load(Ordering::Acquire)),
        args: [
            CAPS_A0.load(Ordering::Acquire),
            CAPS_A1.load(Ordering::Acquire),
            0,
            0,
        ],
    })
}

// ===========================================================================
// M12: the agent runtime -- a REAL preemptible ring3 task (vs M4/M11's one-shot
// longjmp probes). The user-mode preemption path reuses the EXISTING IRQ entry
// (`int 0x20` -> `__trap_thunk_32` -> `__alltraps`) UNCHANGED: a timer IRQ taken
// while an agent runs in ring3 loads `TSS.rsp0` (programmed by `gdt::set_rsp0`
// from `yield_to`'s kernel-stack fold-in), pushes the inter-privilege frame on
// the agent's own kernel stack, and the M9 `ctx_switch` switches it out. The
// THREE new pieces here are: (a) `agent_launch` -- the first-activation
// trampoline that `iretq`s to ring3 with IF=1 (preemptible, vs M4's IF=0); (b)
// `agent_caps_entry` -- the `int 0x82` cap-syscall door that DISPATCHES against
// the current agent's table and `iretq`s BACK to ring3 (vs M4/M11's longjmp);
// (c) `agent_map_space`/`agent_traps_init` -- map the agent's user code+stack
// into its OWN root and open the cap-syscall gate. All policy stays in the safe
// `crate::agent_syscall_current` bridge.

/// The IDT vector the M12 agent cap stub traps through (M4 owns 0x80, M11 0x81).
const AGENT_SYSCALL_VECTOR: usize = 0x82;

/// Ring3 `RFLAGS` for a SCHEDULED agent: reserved bit 1 + IF (bit 9) SET, so the
/// agent is preemptible the instant it reaches ring3 (vs M4's `0x2` with IF=0).
const AGENT_USER_RFLAGS: u64 = 0x202;

/// The agent user-code VA: `PML4[4]` base (the vacant top-level slot M10 also
/// uses for its private test pages). The shared agent stub is mapped here in
/// EVERY agent's own root; the per-agent stack is the next page.
const AGENT_CODE_VA: u64 = 0x0000_0200_0000_0000;
/// The agent user-stack VA: the page after the code page (private per agent).
const AGENT_STACK_VA: u64 = AGENT_CODE_VA + 0x1000;

/// The shared agent code frame (the stub is copied here ONCE, then mapped into
/// each agent's root at [`AGENT_CODE_VA`], executable + read-only).
static AGENT_CODE: Cell4K = Cell4K::new();
/// One-shot guard so the stub is staged into [`AGENT_CODE`] exactly once.
static AGENT_CODE_STAGED: AtomicBool = AtomicBool::new(false);
/// One-shot guard so the `int 0x82` agent cap gate is installed exactly once.
static AGENT_TRAPS_DONE: AtomicBool = AtomicBool::new(false);

// The position-independent ring3 AGENT stub: it reads its born-with handles out
// of the birth registers (rdi = memory_home, rsi = bootstrap), then issues two
// numbered cap syscalls -- a PERMITTED inspect of its memory home (-> Ok) and a
// NON-MANIFEST emit-external on the same handle (-> Denied) -- and spins so ONLY
// the timer can take the CPU (proving involuntary user-mode preemption). The
// memory-home handle is parked in callee-saved r14 (preserved across `int` by
// the SysV-preserving bridge AND restored on any preemption). Distinct numeric
// label `5:` avoids clashing with the M4 `2:` / M11 `3:` stubs in `.text.user`.
global_asm!(
    r#"
.section .text.user, "ax", @progbits
.balign 16
.global agent_user_stub_start
.global agent_user_stub_end
agent_user_stub_start:
    mov r14, rdi           // save memory_home (birth reg) in callee-saved r14
    // syscall 1: M_OBJECT_INSPECT (0) on memory_home -> Ok (permitted)
    xor eax, eax
    mov rdi, r14
    xor esi, esi
    xor edx, edx
    int 0x82
    // syscall 2: M_EMIT_EXTERNAL (21) on memory_home -> Denied (non-manifest)
    mov eax, 21
    mov rdi, r14
    xor esi, esi
    xor edx, edx
    int 0x82
5:
    jmp 5b                 // spin: only the timer can preempt this ring3 task
agent_user_stub_end:
"#
);

extern "C" {
    /// First byte of the ring3 agent stub (identity-mapped == phys).
    static agent_user_stub_start: u8;
    /// One-past-the-last byte of the ring3 agent stub.
    static agent_user_stub_end: u8;
}

// agent_launch: the first-activation trampoline. The fabricated kernel-stack
// frame (sched.rs `task_stack_init_user`) makes `ctx_switch`'s `ret` land here
// with the launch arguments in callee-saved registers; it builds the
// inter-privilege iret frame and drops to ring3 with IF=1 so the agent is
// immediately preemptible.
// (a) PRE: reached by `ctx_switch`'s `ret` on an agent's FIRST activation, at
//     ring0 on the agent's kernel stack with IF=0; rbx=entry_va, rbp=user_sp,
//     r12=user_cs|3, r13=user_ss|3, r14=birth_arg0, r15=birth_arg1.
//     POST: `iretq` -> ring3 at entry_va with rdi/rsi = the birth handles.
// (b) ABI: naked. The kernel stack is abandoned by the iretq (rsp loads the
//     user RSP); rsp0 already names this same stack (set by yield_to), so the
//     next ring3 timer IRQ lands at its top.
#[unsafe(naked)]
pub(super) unsafe extern "C" fn agent_launch() {
    naked_asm!(
        "mov rdi, r14",   // birth arg0 -> rdi (memory_home handle)
        "mov rsi, r15",   // birth arg1 -> rsi (bootstrap handle)
        "push r13",       // SS     = user_ss|3
        "push rbp",       // RSP    = user_sp
        "push {rflags}",  // RFLAGS = 0x202 (IF=1, preemptible)
        "push r12",       // CS     = user_cs|3
        "push rbx",       // RIP    = entry_va
        "iretq",
        rflags = const AGENT_USER_RFLAGS,
    )
}

// agent_caps_entry: the `int 0x82` agent cap-syscall door. ring3 `int 0x82`
// lands here in ring0 on the agent's TSS.rsp0 stack with rax=method, rdi=handle,
// rsi=a0, rdx=a1. It lifts them into SysV order, calls the SAFE bridge (which
// runs `caps::dispatch` against the CURRENT agent's table), then `iretq`s BACK
// to ring3 with the status in rax (vs M4/M11's longjmp out of ring3).
#[unsafe(naked)]
unsafe extern "C" fn agent_caps_entry() {
    naked_asm!(
        // Lift (method, handle, a0, a1) into SysV (rdi, rsi, rdx, rcx).
        "mov rcx, rdx",   // a1     -> SysV arg4
        "mov rdx, rsi",   // a0     -> SysV arg3
        "mov rsi, rdi",   // handle -> SysV arg2
        "mov rdi, rax",   // method -> SysV arg1
        "sub rsp, 8",     // re-establish 16-alignment (CPU pushed 5 qwords)
        "call {bridge}",  // -> status in rax
        "add rsp, 8",     // restore rsp to the iret frame
        "iretq",          // back to ring3; rax = SysStatus, IF restored to 1
        bridge = sym agent_x86_caps_bridge,
    )
}

/// The SAFE-ish recorder shim for the agent cap syscall: forward the lifted
/// scalars to the pure-safe `crate::agent_syscall_current` (which resolves the
/// CURRENT agent, runs `caps::dispatch`, records observations) and return the
/// status to place in the agent's `rax`. `None` (not an agent) maps to `BadCap`.
extern "C" fn agent_x86_caps_bridge(method: u64, handle: u64, a0: u64, a1: u64) -> u64 {
    match crate::agent_syscall_current(method, handle, a0, a1) {
        Some((status, _value)) => status as u64,
        None => crate::caps::SysStatus::BadCap as u64,
    }
}

/// M12: map the agent user code (the shared stub) + a fresh private stack page
/// into the agent's OWN root `root_pa` (`PML4[4]`, vacant in the kernel half),
/// with `U/S = 1` at every level. Returns `(entry_va, user_stack_top)`, or
/// `None` on physical-frame OOM. The stub is staged into [`AGENT_CODE`] once.
pub fn agent_map_space(root_pa: u64) -> Option<(u64, u64)> {
    if !AGENT_CODE_STAGED.swap(true, Ordering::AcqRel) {
        let src = addr_of!(agent_user_stub_start) as *const u8;
        let len = (addr_of!(agent_user_stub_end) as usize) - (src as usize);
        debug_assert!(len <= 4096, "agent stub must fit in one page");
        // SAFETY: `src` spans the PIC stub in identity-mapped, ring0-readable
        // `.text`; `len <= 4096` keeps the copy inside the one AGENT_CODE frame;
        // the regions are disjoint.
        unsafe {
            copy_nonoverlapping(src, AGENT_CODE.byte_ptr(), len);
        }
    }
    // Code page: shared, executable, read-only to ring3. The stub is copied at
    // offset 0, so the entry VA is exactly AGENT_CODE_VA.
    if !super::mmu::map_user_in_root(root_pa, AGENT_CODE_VA, AGENT_CODE.phys_base(), false, true) {
        return None;
    }
    // Stack page: a fresh, private, writable, non-exec frame.
    let stack_pa = crate::frame_alloc()?;
    if !super::mmu::map_user_in_root(root_pa, AGENT_STACK_VA, stack_pa, true, false) {
        return None;
    }
    Some((AGENT_CODE_VA, AGENT_STACK_VA + 0x1000))
}

/// M12: open the agent cap-syscall door -- install the DPL=3 `int 0x82` IDT gate
/// targeting [`agent_caps_entry`]. Idempotent (one-shot); call once before the
/// agents run. (M4's 0x80 and M11's 0x81 gates are left untouched.)
pub fn agent_traps_init() {
    if AGENT_TRAPS_DONE.swap(true, Ordering::AcqRel) {
        return;
    }
    idt::set_user_gate(AGENT_SYSCALL_VECTOR, agent_caps_entry as *const () as u64);
}
