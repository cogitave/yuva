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

/// Ring3 `RFLAGS`: reserved bit 1 (always 1) + IF (bit 9). There is no IRQ
/// source wired in the QEMU `microvm` we target, and the stub executes only
/// two instructions before `int 0x80`, so IF=1 is safe (Intel SDM Vol.1
/// §3.4.3 EFLAGS). This matches the M4 spec's `0x202`.
const USER_RFLAGS: u64 = 0x202;

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
