//! TABOS kernel entry shim (M4: user/ring boundary).
//!
//! Framekernel rule: the kernel crate is otherwise safe Rust. THIS file is the
//! single permitted exception. It contains no `unsafe {}` blocks; the only
//! reason crate-level `forbid(unsafe_code)` is not applied here is that
//! `#[unsafe(no_mangle)]` is itself an *unsafe attribute* (it tells the linker
//! to expose `rust_main` un-mangled for tb-hal's `_start` to `call`/`b` into),
//! and the `unsafe_code` lint flags it. All real unsafe + assembly is confined
//! to tb-hal (KERNEL-FOUNDATION-SPEC.md §1).
//!
//! M2 (kept verbatim) proves the cooperative context switch: two kernel tasks
//! (A and B) on kernel-owned static stacks voluntarily `yield_to` each other
//! for `ROUND_TRIPS` strict A,B,A,B round-trips. tb-hal switches only the ABI
//! callee-saved registers + SP, so each task carries locals ACROSS every yield
//! as a REGISTER-INTEGRITY CANARY; divergence prints \"M2: FAIL <why>\". On
//! success it prints \"M2: context-switch OK\". The M0 serial hello and the M1
//! breakpoint round-trip are kept verbatim ahead of it.
//!
//! M3 (kept) appends the MMU proof: `mmu_init()`, a serial line proving the
//! UART mapping survived the enable, then `mmu_selftest()` (map -> write ->
//! verify -> remap -> re-verify). DoD marker: \"M3: mmu OK\".
//!
//! M4 (this milestone) appends the user/ring boundary proof. After M3, the
//! kernel calls `tb_hal::user_demo()`: tb-hal sets up USER-accessible code +
//! stack pages (M3 mmu layer + USER permission bits), drops the CPU to
//! unprivileged mode (x86_64 ring 3 / aarch64 EL0) at a tiny user stub, the
//! stub issues ONE syscall (`int 0x80` / `svc #0`) that traps back into the
//! kernel, the safe handler records it (+ its magic arg) and returns the CPU
//! to the kernel. `user_demo()` returns true iff the syscall was observed from
//! user mode with arg == 0xCAFE. DoD marker: \"M4: user/ring OK\". ALL the new
//! unsafe/asm lives in tb-hal; this crate calls one safe fn and branches on a
//! bool.
//!
//! MV (the L1 sovereignty rung) adds a SECOND boot path WITHOUT touching this
//! self-test: the project's own `tb-vmm` boots this SAME kernel ELF directly in
//! 64-bit long mode via tb-boot v0 (tb-hal's `_tb_start` + the TABOS ELF note),
//! with `boot_info` = the guest-physical `tb_boot::TbBootInfo` pointer instead
//! of a PVH `hvm_start_info`. `rust_main` prints "tb-boot: contract v0 OK"
//! first IFF the magic validates (a PVH pointer is silently ignored), then runs
//! M0-M4 identically. The PVH/QEMU regression path is unchanged.

#![no_std]
#![no_main]

// M5: `alloc` comes online kernel-wide. On nightly this needs NO feature gate
// (`extern crate alloc` is stable for no_std binaries, and the default
// alloc-error handler routes OOM to our `#[panic_handler]`), so the only new
// crate-level line is the `extern crate alloc;` below. The heap itself — the
// `#[global_allocator]` impl, the `.bss` arena and all raw pointer math — lives
// in tb-hal; this crate just names the allocator and uses `alloc` types.
extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::hint::black_box;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use tb_hal::{Task, TaskStack, TrapAction, TrapInfo, TrapKind};

/// The kernel-wide global allocator: a zero-sized handle whose `GlobalAlloc`
/// impl (and the `.bss` arena behind it) lives entirely in tb-hal. Declaring
/// this `static` and using `alloc` types is NOT `unsafe`; `heap_init()` lays the
/// arena down before first use (see `rust_main`).
#[global_allocator]
static HEAP: tb_hal::Heap = tb_hal::Heap::new();

/// Ping-pong round-trips (A→B→A counts as one). DoD asks for >= 1000.
const ROUND_TRIPS: usize = 1000;

/// `TURN` value meaning \"task A must run this half-round\".
const TURN_A: usize = 0;
/// `TURN` value meaning \"task B must run this half-round\".
const TURN_B: usize = 1;

/// Initial value of task A's rotating-pattern canary (arbitrary, asymmetric).
const PAT_A_INIT: usize = 0xA5A5_5A5A_DEAD_BEEF;
/// Initial value of task B's rotating-pattern canary (different from A's).
const PAT_B_INIT: usize = 0x0F0F_F0F0_CAFE_F00D;

// --- M2 scheduler bookkeeping (all in THIS forbid-class crate, all safe) ----

/// Task A's stack: 4096 usize words (32 KiB), 16-byte aligned.
static STACK_A: TaskStack<4096> = TaskStack::new();
/// Task B's stack: 4096 usize words (32 KiB), 16-byte aligned.
static STACK_B: TaskStack<4096> = TaskStack::new();

/// Task A's handle as `Task::raw()`, stashed so task B can yield back to A.
static TASK_A_RAW: AtomicUsize = AtomicUsize::new(usize::MAX);
/// Task B's handle as `Task::raw()`, stashed so task A can yield to B.
static TASK_B_RAW: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Bootstrap context's handle as `Task::raw()` (slot 0), stashed BEFORE the
/// ping-pong starts so task A can hand the CPU back to `rust_main` after the
/// M2 verdict — M3/M4 then run in the bootstrap context.
static BOOT_TASK_RAW: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Set by task A immediately after the M2 success marker and right before it
/// yields back to the bootstrap context. `rust_main` refuses to start M3
/// without it (fail-closed against any stray resume of slot 0).
static M2_PASSED: AtomicBool = AtomicBool::new(false);

/// Whose half-round it is: the strict-alternation flag (TURN_A / TURN_B).
static TURN: AtomicUsize = AtomicUsize::new(TURN_A);

/// Shared increment counter: A sees it == 2*i at round i, B sees == 2*j + 1.
static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Set by task B after it audited its own canaries on its final round.
static B_VERIFIED: AtomicBool = AtomicBool::new(false);

// --- M9 preemptive-scheduler bookkeeping (all in THIS crate, all safe) ------

/// Spin task C's stack: 4096 usize words (32 KiB), 16-byte aligned.
static STACK_C: TaskStack<4096> = TaskStack::new();
/// Spin task D's stack: 4096 usize words (32 KiB), 16-byte aligned.
static STACK_D: TaskStack<4096> = TaskStack::new();

/// Spin task C's advance counter: bumped in its infinite loop, read by the boot
/// task to prove C actually ran -- which can ONLY happen via involuntary timer
/// preemption, since the boot task never `yield_to`s it.
static SPIN_C_COUNT: AtomicU64 = AtomicU64::new(0);
/// Spin task D's advance counter (as C).
static SPIN_D_COUNT: AtomicU64 = AtomicU64::new(0);

// --- M10 per-entity-address-space bookkeeping (all in THIS crate, all safe) --

/// Task G's stack (runs in address space E): 4096 usize words, 16-aligned.
static STACK_G: TaskStack<4096> = TaskStack::new();
/// Task H's stack (runs in address space F): 4096 usize words, 16-aligned.
static STACK_H: TaskStack<4096> = TaskStack::new();

/// Task G's handle as `Task::raw()`, stashed so the boot task enters it through
/// its handle (symmetric with H/boot) and task H can target it in turn.
static TASK_G_RAW: AtomicUsize = AtomicUsize::new(usize::MAX);
/// Task H's handle as `Task::raw()`.
static TASK_H_RAW: AtomicUsize = AtomicUsize::new(usize::MAX);
/// The boot context's handle, stashed so task H hands the CPU back to it.
static BOOT10_RAW: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Set by task G iff it read back its OWN magic at the shared test VA under
/// address space E (proving the yield_to fold-in put it in its own root).
static G_SEES_OWN: AtomicBool = AtomicBool::new(false);
/// Set by task H iff it read back its OWN magic under address space F.
static H_SEES_OWN: AtomicBool = AtomicBool::new(false);

/// Armed by the boot task immediately before it provokes the cross-space fault;
/// the trap hook treats a page fault as the expected cross-space access ONLY
/// while this is set (every other fault stays fatal).
static M10_FAULT_ARMED: AtomicBool = AtomicBool::new(false);
/// The VA whose cross-space fault the trap hook expects (the M10 test VA).
static M10_FAULT_VA: AtomicU64 = AtomicU64::new(0);
/// Set by the trap hook when it observes the armed cross-space page fault.
static M10_FAULT_SEEN: AtomicBool = AtomicBool::new(false);
/// The home-space root PA the trap hook flips to (guarded resume), so the
/// faulting access re-executes where the VA is mapped instead of livelocking.
static M10_FAULT_HOME_ROOT: AtomicU64 = AtomicU64::new(0);

/// x86_64 M10 test VA: `PML4[4]` (= 4 * 2^39), a top-level slot the kernel root
/// never uses (identity `PML4[0]`, M4 user `[1]`, M7 heap `[2]`, M8 LAPIC `[3]`).
#[cfg(target_arch = "x86_64")]
const M10_TEST_VA: u64 = 0x0000_0200_0000_0000;
/// aarch64 M10 test VA: `L1[6]` (= 6 GiB), a top-level slot the kernel root
/// never uses (identity `L1[0..1]`, M3 self-test `[2]`, M4 user `[3]`, M7 heap `[4]`).
#[cfg(target_arch = "aarch64")]
const M10_TEST_VA: u64 = 0x0000_0001_8000_0000;

/// Task G's private magic, written THROUGH the shared test VA under space E.
const MAGIC_E: u64 = 0x1010_1010_1010_100E;
/// Task H's private magic, written THROUGH the shared test VA under space F.
const MAGIC_F: u64 = 0x2020_2020_2020_200F;

// --- M12 agent-runtime bookkeeping (all in THIS forbid-class crate, all safe) -

/// Agent A's KERNEL stack: 4096 usize words (32 KiB), 16-aligned -- the
/// ring0/EL1 stack a timer IRQ taken at ring3/EL0 lands on (TSS.rsp0 / SP_EL1).
static STACK_AGENT_A: TaskStack<4096> = TaskStack::new();
/// Agent B's KERNEL stack.
static STACK_AGENT_B: TaskStack<4096> = TaskStack::new();
/// M13 agent C's KERNEL stack (born-with-home substrate witness).
static STACK_AGENT_C: TaskStack<4096> = TaskStack::new();
/// M13 agent D's KERNEL stack (per-agent isolation witness).
static STACK_AGENT_D: TaskStack<4096> = TaskStack::new();

/// Agent A's manifest grants: a read/write/recall memory home + a readable
/// budget. NO `EMIT_EXTERNAL` / `INVOKE_MODEL`, so its emit-external syscall is
/// `Denied` (least privilege is the manifest's OMISSION, not a runtime check).
static MANIFEST_A_CAPS: [tb_hal::CapGrant; 2] = [
    tb_hal::CapGrant {
        kind: tb_hal::caps::ObjKind::MemoryHome,
        rights: tb_hal::caps::Rights::READ
            .union(tb_hal::caps::Rights::WRITE)
            .union(tb_hal::caps::Rights::RECALL),
    },
    tb_hal::CapGrant {
        kind: tb_hal::caps::ObjKind::Budget,
        rights: tb_hal::caps::Rights::READ,
    },
];
/// Agent A's static manifest -- the ONLY input to its spawn (capability confinement).
static MANIFEST_A: tb_hal::AgentManifest = tb_hal::AgentManifest {
    name: "agent-a",
    caps: &MANIFEST_A_CAPS,
    wants_memory_home: true,
};

/// Agent B's manifest grants: a read/recall memory home + a readable budget.
/// Also omits `EMIT_EXTERNAL` / `INVOKE_MODEL`.
static MANIFEST_B_CAPS: [tb_hal::CapGrant; 2] = [
    tb_hal::CapGrant {
        kind: tb_hal::caps::ObjKind::MemoryHome,
        rights: tb_hal::caps::Rights::READ.union(tb_hal::caps::Rights::RECALL),
    },
    tb_hal::CapGrant {
        kind: tb_hal::caps::ObjKind::Budget,
        rights: tb_hal::caps::Rights::READ,
    },
];
/// Agent B's static manifest.
static MANIFEST_B: tb_hal::AgentManifest = tb_hal::AgentManifest {
    name: "agent-b",
    caps: &MANIFEST_B_CAPS,
    wants_memory_home: true,
};

/// Set by the trap hook when the child agent's root faults on the parent-only
/// VA (cross-space isolation proof, reusing the M10 armed-fault mechanism).
static M12_CHILD_FAULTED: AtomicBool = AtomicBool::new(false);

/// x86_64 parent-only VA: `PML4[5]`, vacant in the kernel half AND in every
/// agent root (an agent only ever adds a private `PML4[4]` leaf), so an agent
/// read of it faults.
#[cfg(target_arch = "x86_64")]
const M12_PARENT_VA: u64 = 0x0000_0280_0000_0000;
/// aarch64 parent-only VA: `L1[7]` (= 7 GiB), likewise vacant in every agent root.
#[cfg(target_arch = "aarch64")]
const M12_PARENT_VA: u64 = 0x0000_0001_C000_0000;

/// The parent's private magic at `M12_PARENT_VA`, read back after the guarded
/// resume to prove the child saw the parent's frame only via the hook's flip.
const MAGIC_PARENT: u64 = 0x9090_9090_9090_9012;

/// Involuntary switches required before the M12 verdict -- proves both ring3/EL0
/// agents genuinely lost the CPU to the timer (the first user-mode preemption).
const M12_REQUIRED_SWITCHES: u64 = 60;

/// Boot entry. Reached by EITHER of tb-hal's two x86_64 entries (or the
/// aarch64 `_start`); each sets up a stack and places the boot-info pointer in
/// SysV arg0 before calling here:
///   * PVH (`_start`, QEMU/Firecracker): `rdi` = `hvm_start_info` phys addr.
///   * tb-boot v0 (`_tb_start`, the project's `tb-vmm`): `rdi` = guest-physical
///     `tb_boot::TbBootInfo` addr (identity-mapped; magic-validated below).
///   * aarch64 (`_start`): `x0` = FDT blob (MV is an x86_64-first follow-up).
#[unsafe(no_mangle)]
pub extern "C" fn rust_main(boot_info: usize) -> ! {
    // --- M8 in-guest timing: sample the cycle counter at the EARLIEST point --
    // A pure register read (x86_64 `rdtsc` / aarch64 `CNTPCT_EL0`, needs no
    // init); paired with a second read just after the M8 marker to print a
    // guest-only `boot-cycles` delta spanning the whole M0..M8 self-test — the
    // honest, VMM-independent figure (see docs/BENCHMARKS.md). Still unsafe-free.
    let boot_c0 = tb_hal::read_cycle_counter();

    // --- M0 proof (kept verbatim): serial first-light ----------------------
    tb_hal::serial_init();

    // --- MV / tb-boot v0: announce the contract IFF tb-vmm booted us -------
    // On the tb-boot path `boot_info` is the guest-physical address of an
    // identity-mapped `tb_boot::TbBootInfo` whose magic validates; on the PVH
    // path it is an `hvm_start_info` pointer whose magic does NOT match, so we
    // silently skip (fail-closed; never misread). tb-hal performs the single
    // guarded raw read of the pointer — this `#![forbid(unsafe_code)]`-class
    // crate only compares the returned magic against `tb_boot::TB_BOOT_MAGIC`.
    // Printing this is OPTIONAL and does NOT gate M0-M4: the PVH regression path
    // skips it and emits the same markers below.
    if tb_hal::read_boot_magic(boot_info) == Some(tb_boot::TB_BOOT_MAGIC) {
        tb_hal::serial_write_str("tb-boot: contract v0 OK\n");
    }

    tb_hal::serial_write_str("hello from rust_main\n");

    // --- M1 proof (kept): install traps, take a breakpoint, resume ---------
    tb_hal::install_traps();
    tb_hal::set_trap_hook(trap_hook);
    tb_hal::serial_write_str("trap-test: triggering breakpoint\n");
    tb_hal::breakpoint(); // int3 (x86_64) / brk #0 (aarch64); hook -> Resume
    tb_hal::serial_write_str("trap-test: resumed past breakpoint\n");
    tb_hal::serial_write_str("M1: traps OK\n");

    // --- M2 proof (kept): cooperative context-switch ping-pong -------------
    tb_hal::serial_write_str("ctx-test: starting ping-pong\n");
    BOOT_TASK_RAW.store(tb_hal::current_task().raw(), Ordering::Release);
    let task_a = tb_hal::task_create(STACK_A.take(), task_a_main);
    let task_b = tb_hal::task_create(STACK_B.take(), task_b_main);
    TASK_A_RAW.store(task_a.raw(), Ordering::Release);
    TASK_B_RAW.store(task_b.raw(), Ordering::Release);
    tb_hal::yield_to(task_a);

    // Fail-closed gate: the ONLY legal way back here is task A's post-verdict
    // hand-off. Anything else (a stray yield to slot 0) is an M2 failure.
    if !M2_PASSED.load(Ordering::Acquire) {
        fail("bootstrap context resumed before the M2 verdict");
    }

    // --- M3: MMU bring-up + map/remap self-test ----------------------------
    tb_hal::serial_write_str("mmu-test: init\n");
    tb_hal::mmu_init();
    tb_hal::serial_write_str("mmu-test: enabled, serial alive\n");
    if tb_hal::mmu_selftest() {
        tb_hal::serial_write_str("M3: mmu OK\n"); // <-- the M3 DoD marker
    } else {
        tb_hal::serial_write_str("M3: FAIL\n");
        tb_hal::halt();
    }

    // --- M4: user/ring boundary -- drop to ring3/EL0, syscall, trap back ----
    // tb-hal maps USER-accessible code + stack pages (M3 mmu layer + USER
    // permission bits), drops the CPU to unprivileged mode at a tiny user
    // stub, the stub issues ONE syscall (int 0x80 / svc #0) that traps back
    // into the kernel, the safe handler records it (+ its magic arg) and the
    // CPU returns here. user_demo() is true iff the syscall was seen from user
    // mode with arg == 0xCAFE. All the new unsafe/asm lives in tb-hal; this
    // forbid(unsafe_code)-class crate only branches on the bool.
    tb_hal::serial_write_str("user-test: entering unprivileged mode\n");
    if tb_hal::user_demo() {
        tb_hal::serial_write_str("M4: user/ring OK\n"); // <-- the M4 DoD marker
    } else {
        tb_hal::serial_write_str("M4: FAIL\n");
    }

    // --- M5: bring `alloc` online via a #[global_allocator] over a .bss arena --
    // tb-hal owns the from-scratch free-list allocator + the fixed static arena
    // and exposes a SAFE facade; this forbid(unsafe_code)-class crate only lays
    // the heap down with heap_init(), then exercises the GLOBAL allocator through
    // real `alloc` types (Box / Vec / BTreeMap / String), proves freed memory is
    // REUSED, and asserts nothing leaked (used-bytes returns to the post-init
    // baseline). All raw pointer math + the unsafe GlobalAlloc impl live in
    // tb-hal. DoD marker: "M5: alloc OK".
    tb_hal::serial_write_str("alloc-test: bringing heap online\n");
    tb_hal::heap_init();

    // Local fail helper: emit the M5 failure verdict over serial and park the
    // core (diverges). Matches the M2 `fail` style; uses only safe serial calls.
    let m5_fail = |why: &str| -> ! {
        tb_hal::serial_write_str("M5: FAIL ");
        tb_hal::serial_write_str(why);
        tb_hal::serial_write_byte(b'\n');
        tb_hal::halt()
    };

    // A freshly-initialised heap has handed out zero bytes.
    let base_used = tb_hal::heap_used_bytes();
    if base_used != 0 {
        m5_fail("post-init heap not empty");
    }

    // Box: a single heap allocation + deref + drop.
    {
        let boxed = Box::new(0xABCD_1234_5678_9ABCu64);
        if *boxed != 0xABCD_1234_5678_9ABC {
            m5_fail("Box value corrupted");
        }
        if tb_hal::heap_used_bytes() == base_used {
            m5_fail("Box did not allocate");
        }
    } // boxed dropped -> its block returns to the free list

    // Vec grown WELL past its first realloc: capacity starts at 0, so 1024 pushes
    // force several grow-reallocs through GlobalAlloc's (default) realloc path.
    {
        let mut v: Vec<u32> = Vec::new();
        let n: u32 = 1024;
        let mut k: u32 = 0;
        while k < n {
            v.push(k.wrapping_mul(2_654_435_761)); // Knuth multiplicative hash
            k += 1;
        }
        if v.len() != n as usize {
            m5_fail("Vec length wrong");
        }
        if (v.capacity() as u32) < n {
            m5_fail("Vec never grew past its first allocation");
        }
        let mut k2: u32 = 0;
        while k2 < n {
            if v[k2 as usize] != k2.wrapping_mul(2_654_435_761) {
                m5_fail("Vec element corrupted across reallocs");
            }
            k2 += 1;
        }
    } // v dropped

    // BTreeMap: many internal node allocations + ordered lookups.
    {
        let mut map: BTreeMap<u32, u64> = BTreeMap::new();
        let mut k: u32 = 0;
        while k < 512 {
            map.insert(k, ((k as u64).wrapping_mul(1_099_511_628_211)) ^ 0x5A5A);
            k += 1;
        }
        if map.len() != 512 {
            m5_fail("BTreeMap length wrong");
        }
        let mut k2: u32 = 0;
        while k2 < 512 {
            match map.get(&k2) {
                Some(val) if *val == ((k2 as u64).wrapping_mul(1_099_511_628_211)) ^ 0x5A5A => {}
                _ => m5_fail("BTreeMap lookup wrong"),
            }
            k2 += 1;
        }
    } // map dropped

    // String: repeated push_str forces reallocating growth of a byte buffer.
    {
        let mut s = String::new();
        let mut k = 0;
        while k < 128 {
            s.push_str("tabos-");
            k += 1;
        }
        if s.len() != 128 * 6 {
            m5_fail("String length wrong");
        }
        if !s.starts_with("tabos-") || !s.ends_with("tabos-") {
            m5_fail("String content wrong");
        }
    } // s dropped

    // No-leak: every allocation above was dropped, so used-bytes must be back at
    // the post-init baseline, while the high-water mark stayed strictly positive.
    if tb_hal::heap_used_bytes() != base_used {
        m5_fail("leak: used-bytes above baseline after drops");
    }
    if tb_hal::heap_high_water() <= base_used {
        m5_fail("high-water mark never advanced");
    }

    // Reuse proof: a freed allocation's address is handed back out for the next
    // request of the same shape (first-fit over the re-coalesced arena). No
    // `unsafe`: a shared ref cast to a raw pointer to usize is all safe Rust.
    let reuse_addr_1 = {
        let probe = Box::new(0u64);
        (&*probe) as *const u64 as usize
    }; // probe dropped -> block freed + coalesced back
    let reuse_addr_2 = {
        let probe = Box::new(0u64);
        (&*probe) as *const u64 as usize
    };
    if reuse_addr_1 != reuse_addr_2 {
        m5_fail("freed block was not reused");
    }
    if tb_hal::heap_used_bytes() != base_used {
        m5_fail("leak after reuse probe");
    }

    // tb-hal's own low-level self-test (size-0/ZST, over-arena alloc -> null,
    // aligned alloc/dealloc/realloc reuse, neighbour coalescing) — the raw-pointer
    // checks this crate cannot do without `unsafe`, all landing back at baseline.
    if !tb_hal::heap_selftest() {
        m5_fail("tb_hal::heap_selftest failed");
    }
    if tb_hal::heap_used_bytes() != base_used {
        m5_fail("heap_selftest left bytes allocated");
    }

    tb_hal::serial_write_str("M5: alloc OK\n"); // <-- the M5 DoD marker

    // --- M6: physical frame allocator from the active boot memory map -------
    // tb-hal parses the LIVE boot path's memory map (x86_64 PVH
    // `hvm_start_info.memmap` or tb-boot `TbBootInfo` regions; aarch64 the QEMU
    // `virt` map) into an INTRUSIVE FREE-FRAME STACK that hands out / reclaims
    // 4 KiB PHYSICAL frames from usable RAM only — never the kernel image (incl.
    // M5's 2 MiB .bss heap arena), the boot structures, sub-1 MiB, or device
    // MMIO. ALL the raw memmap reads, the linker-symbol image span, and the
    // next-free-PA links written THROUGH each free frame's identity address live
    // in tb-hal; this forbid(unsafe_code)-class crate only calls the safe facade
    // (frame_alloc -> Option<u64 PA>, frame_free, the pmm stats, pmm_selftest)
    // and COMPARES the returned physical addresses — it can never deref a frame.
    // DoD marker: "M6: frame alloc OK".
    tb_hal::serial_write_str("frame-test: parsing boot memory map\n");
    tb_hal::pmm_init(boot_info);

    // Local fail helper: emit the M6 failure verdict and park the core. Matches
    // the M5 `m5_fail` style; uses only safe serial calls.
    let m6_fail = |why: &str| -> ! {
        tb_hal::serial_write_str("M6: FAIL ");
        tb_hal::serial_write_str(why);
        tb_hal::serial_write_byte(b'\n');
        tb_hal::halt()
    };

    // The boot map must yield usable RAM, and a freshly seeded allocator has
    // every usable frame on the free stack: free_count == total_frames ==
    // sum(usable ranges) - reservations (the tb-hal stat).
    let total = tb_hal::pmm_total_frames();
    if total == 0 {
        m6_fail("no usable frames parsed from the boot map");
    }
    if tb_hal::pmm_free_frames() != total {
        m6_fail("post-init free count != total usable frames");
    }

    // (1) Allocate K frames; each PA must be 4 KiB-aligned, inside a usable RAM
    //     range, outside EVERY reservation, and pairwise-disjoint.
    const K: usize = 64;
    let mut frames: Vec<u64> = Vec::with_capacity(K);
    {
        let mut i = 0;
        while i < K {
            match tb_hal::frame_alloc() {
                Some(pa) => {
                    if pa % 4096 != 0 {
                        m6_fail("allocated frame is not 4 KiB-aligned");
                    }
                    if !tb_hal::pmm_addr_in_usable_ram(pa) {
                        m6_fail("allocated frame is outside usable RAM");
                    }
                    if tb_hal::pmm_addr_reserved(pa) {
                        m6_fail("allocated frame overlaps a reservation");
                    }
                    frames.push(pa);
                }
                None => m6_fail("ran out of frames before K allocations"),
            }
            i += 1;
        }
        // Pairwise-disjoint: distinct 4 KiB-aligned PAs cannot overlap.
        let mut a = 0;
        while a < K {
            let mut b = a + 1;
            while b < K {
                if frames[a] == frames[b] {
                    m6_fail("two allocations returned the same frame");
                }
                b += 1;
            }
            a += 1;
        }
    }
    if tb_hal::pmm_free_frames() != total - K {
        m6_fail("free count wrong after K allocations");
    }

    // (2) LIFO reuse: free the most-recently-allocated frame; the next alloc
    //     must hand the SAME physical frame straight back (free-stack pop).
    let last = frames[K - 1];
    if !tb_hal::frame_free(last) {
        m6_fail("free of a valid frame was rejected");
    }
    match tb_hal::frame_alloc() {
        Some(pa) if pa == last => {} // LIFO reuse proven
        Some(_) => m6_fail("free stack did not reuse the just-freed frame (LIFO)"),
        None => m6_fail("alloc after a free returned None"),
    }

    // (3) Fail-closed: reject a double-free, a misaligned free, and a null free.
    if !tb_hal::frame_free(last) {
        m6_fail("free of the re-allocated frame was rejected");
    }
    if tb_hal::frame_free(last) {
        m6_fail("double-free was accepted");
    }
    if tb_hal::frame_free(last + 1) {
        m6_fail("misaligned free was accepted");
    }
    if tb_hal::frame_free(0) {
        m6_fail("null free was accepted");
    }

    // Return the remaining K-1 held frames; the free count must climb back to
    // `total`, proving full reclaim (the seed-count invariant round-trips).
    {
        let mut i = 0;
        while i < K - 1 {
            if !tb_hal::frame_free(frames[i]) {
                m6_fail("reclaim of a held frame was rejected");
            }
            i += 1;
        }
    }
    if tb_hal::pmm_free_frames() != total {
        m6_fail("free count did not return to total after reclaim");
    }

    // (4) tb-hal's own through-the-frame self-test (alloc -> write a magic via
    //     the frame's identity address -> read it back -> free): the raw-memory
    //     check this forbid(unsafe_code)-class crate cannot perform itself.
    if !tb_hal::pmm_selftest() {
        m6_fail("tb_hal::pmm_selftest failed");
    }
    if tb_hal::pmm_free_frames() != total {
        m6_fail("pmm_selftest leaked a frame");
    }

    // (5) Drive the allocator to exhaustion: exactly `total` frames come out,
    //     then frame_alloc fail-closes to None. M7 now FOLLOWS M6 and grows the
    //     kernel heap from real frames, so the drained pool is RECLAIMED here
    //     (collected into a `with_capacity` Vec so the drain itself never
    //     reallocs) and the free count is asserted back to `total` afterwards.
    //     This drain Vec is served from the still-fixed 2 MiB .bss arena (the
    //     window is not enabled until the M7 block below), so it costs
    //     `total * 8` bytes; the M3 identity clamp keeps usable RAM <= ~1 GiB
    //     and the run scripts pin -m 256M / -m 128M, so it sits well inside the
    //     arena (~0.5 MiB / ~0.25 MiB respectively).
    drop(frames);
    let free_before = tb_hal::pmm_free_frames();
    let mut drained: Vec<u64> = Vec::with_capacity(free_before);
    loop {
        match tb_hal::frame_alloc() {
            Some(pa) => {
                if pa % 4096 != 0 {
                    m6_fail("frame from the exhaustion drain is misaligned");
                }
                drained.push(pa);
            }
            None => break,
        }
    }
    if drained.len() != free_before {
        m6_fail("exhaustion drained a different count than the free total");
    }
    if tb_hal::frame_alloc().is_some() {
        m6_fail("frame_alloc handed out a frame past exhaustion");
    }
    if tb_hal::pmm_free_frames() != 0 {
        m6_fail("free count nonzero at full exhaustion");
    }
    // Reclaim the whole pool so M7's growable heap has frames to map.
    {
        let mut i = 0;
        while i < drained.len() {
            if !tb_hal::frame_free(drained[i]) {
                m6_fail("reclaim after the exhaustion drain was rejected");
            }
            i += 1;
        }
    }
    if tb_hal::pmm_free_frames() != total {
        m6_fail("free count did not return to total after the exhaustion reclaim");
    }
    drop(drained);

    tb_hal::serial_write_str("M6: frame alloc OK\n"); // <-- the M6 DoD marker

    // --- M7: frame-backed GROWABLE kernel heap -----------------------------
    // Re-back the M5 free-list with a kernel-only VA window (RW + NX, OUTSIDE
    // the identity map) that GROWS ON DEMAND by pulling 4 KiB frames from the M6
    // allocator and mapping them through the M3 typed page-table layer — lifting
    // the heap off M5's fixed 2 MiB .bss arena. The allocator ALGEBRA (free-list
    // + coalescing + alignment) is byte-for-byte the M5 code; only the backing
    // store + the grow hook changed. ALL the page-table splicing, the frame
    // pulls and the writes THROUGH the mapped window VAs live in tb-hal; this
    // forbid(unsafe_code)-class crate only calls the safe facade, uses `alloc`
    // types, and compares numbers. DoD marker: "M7: heap OK".
    tb_hal::serial_write_str("heap-test: enabling frame-backed growable window\n");

    // Local fail helper (matches the m5_fail / m6_fail style; safe serial only).
    let m7_fail = |why: &str| -> ! {
        tb_hal::serial_write_str("M7: FAIL ");
        tb_hal::serial_write_str(why);
        tb_hal::serial_write_byte(b'\n');
        tb_hal::halt()
    };

    // Baselines: the heap is empty (M5/M6 left used-bytes at 0) and the PMM pool
    // is full again (the M6 exhaustion drain was reclaimed just above).
    let heap_baseline = tb_hal::heap_used_bytes();
    let pmm_baseline = tb_hal::pmm_free_frames();
    if pmm_baseline == 0 {
        m7_fail("no free frames to grow the heap from");
    }

    tb_hal::heap_window_init();

    // A single CONTIGUOUS buffer well past the old 2 MiB arena: 4 MiB of u64
    // (524288 elements) via `with_capacity` forces ONE 4 MiB allocation that the
    // 2 MiB arena physically cannot satisfy — it can only come from the
    // contiguous-VA, frame-backed window (scattered RAM, contiguous VA).
    const BIG: usize = 512 * 1024; // 524288 u64 = 4 MiB, > the old 2 MiB arena
    const STRIDE: u64 = 0x9E37_79B9_7F4A_7C15; // odd => bijective over u64
    {
        let mut v: Vec<u64> = Vec::with_capacity(BIG);
        if v.capacity() < BIG {
            m7_fail("contiguous 4 MiB reservation failed");
        }
        // Write a pattern THROUGH every mapped page, then read it back: any
        // mis-mapped page would #PF / data-abort here (the trap hook halts and
        // the marker never prints) — so a clean readback proves the mapping.
        let mut k: u64 = 0;
        while (k as usize) < BIG {
            v.push(k.wrapping_mul(STRIDE));
            k += 1;
        }
        let mut k2: u64 = 0;
        while (k2 as usize) < BIG {
            if v[k2 as usize] != k2.wrapping_mul(STRIDE) {
                m7_fail("frame-backed buffer corrupted (mis-mapping)");
            }
            k2 += 1;
        }
        if v.len() != BIG {
            m7_fail("contiguous buffer length wrong");
        }
        // The heap grew PAST the old 2 MiB arena...
        if tb_hal::heap_high_water() <= 2 * 1024 * 1024 {
            m7_fail("heap never grew past the 2 MiB arena");
        }
        // ...the growth mapped real frames into the window...
        if tb_hal::heap_window_mapped_bytes() == 0 {
            m7_fail("window mapped no frames for the growth");
        }
        // ...and consumed REAL physical frames from M6 (free count dropped).
        if tb_hal::pmm_free_frames() >= pmm_baseline {
            m7_fail("growth consumed no physical frames");
        }
    } // v dropped -> its 4 MiB returns to the free list (still frame-backed)

    // No HEAP leak: every byte handed out above is back on the free list.
    if tb_hal::heap_used_bytes() != heap_baseline {
        m7_fail("heap leak: used-bytes above baseline after drop");
    }

    // REUSE without consuming fresh frames: the window keeps its frames mapped,
    // so a second 4 MiB allocation must be served from the already-mapped,
    // now-free window region — `pmm_free_frames` must NOT drop any further. This
    // is the strict no-FRAME-leak evidence: the retained frames are REUSABLE,
    // not lost (retention == reuse).
    let pmm_after_first = tb_hal::pmm_free_frames();
    {
        let mut v2: Vec<u64> = Vec::with_capacity(BIG);
        let mut k: u64 = 0;
        while (k as usize) < BIG {
            v2.push(!k.wrapping_mul(STRIDE));
            k += 1;
        }
        let mut k2: u64 = 0;
        while (k2 as usize) < BIG {
            if v2[k2 as usize] != !k2.wrapping_mul(STRIDE) {
                m7_fail("reused frame-backed buffer corrupted");
            }
            k2 += 1;
        }
    } // v2 dropped
    if tb_hal::pmm_free_frames() != pmm_after_first {
        m7_fail("second growth consumed fresh frames instead of reusing the window");
    }
    if tb_hal::heap_used_bytes() != heap_baseline {
        m7_fail("heap leak after the reuse pass");
    }

    // Also exercise the REALLOC path (a Vec doubling its capacity) past the
    // arena, proving the grow hook services the UNCHANGED M5 first-fit/coalesce
    // algebra through repeated alloc/free churn — not just one big up-front map.
    {
        let mut v3: Vec<u64> = Vec::new();
        let mut k: u64 = 0;
        while (k as usize) < BIG {
            v3.push(k ^ STRIDE);
            k += 1;
        }
        if v3.len() != BIG {
            m7_fail("realloc-grown vector length wrong");
        }
        if (v3.capacity() as u64) < BIG as u64 {
            m7_fail("realloc-grown vector never grew past one page");
        }
        let mut k2: u64 = 0;
        while (k2 as usize) < BIG {
            if v3[k2 as usize] != (k2 ^ STRIDE) {
                m7_fail("realloc-grown vector corrupted across reallocs");
            }
            k2 += 1;
        }
    } // v3 dropped
    if tb_hal::heap_used_bytes() != heap_baseline {
        m7_fail("heap leak after the realloc pass");
    }

    // FRAME accounting (growable design that RETAINS its window frames): grow()
    // pulled real frames from M6 — `pmm_free_frames` dropped below the M6
    // baseline — and the heap KEEPS them mapped for reuse, so the count does NOT
    // climb back to `pmm_baseline`. That is NOT a leak: every pulled frame is
    // either a live page-table frame or a data frame owned by the window's free
    // list, and the reuse pass above proved those frames are handed back out.
    // M5's own no-leak metric (heap used-bytes == baseline, asserted above) is
    // what proves nothing was lost at the allocator level; the M5 algebra has
    // no give-back hook by design (the spec-sanctioned "keeps its frames" case).
    if tb_hal::pmm_free_frames() >= pmm_baseline {
        m7_fail("window unexpectedly returned all frames (frame accounting)");
    }

    tb_hal::serial_write_str("M7: heap OK\n"); // <-- the M7 DoD marker

    // --- M8: async interrupt + monotonic timer tick (NO scheduler) ---------
    // Bring up the interrupt controller (x86_64 LAPIC / aarch64 GICv2) + a
    // periodic timer and take the kernel's FIRST asynchronous interrupt (M0..M7
    // ran fully masked behind cli / DAIF.I), resuming the EXACT interrupted
    // instruction with every register intact — proven by a register-integrity
    // canary that runs across many ticks while an AtomicU64 tick counter
    // advances; the timer is then masked again. NO scheduler is touched (that is
    // M9). ALL the controller pokes, the first `sti` / `daifclr`, the IRQ entry
    // asm and the cycle counter live in tb-hal; this forbid(unsafe_code)-class
    // crate only calls the safe facade and branches on the bool. DoD: "M8: timer OK".
    tb_hal::serial_write_str("timer-test: taking the first async interrupt\n");

    // Local fail helper (matches the m5_fail / m6_fail / m7_fail style; safe only).
    let m8_fail = |why: &str| -> ! {
        tb_hal::serial_write_str("M8: FAIL ");
        tb_hal::serial_write_str(why);
        tb_hal::serial_write_byte(b'\n');
        tb_hal::halt()
    };

    if !tb_hal::timer_demo() {
        m8_fail("no ticks observed or register/state corruption across an IRQ");
    }
    // The monotonic tick counter advanced under the async timer.
    if tb_hal::tick_count() == 0 {
        m8_fail("tick counter did not advance");
    }

    tb_hal::serial_write_str("M8: timer OK\n"); // <-- the M8 DoD marker

    // In-guest timing: ENTRY -> here is a pure guest-only span (rdtsc / CNTPCT),
    // the defensible benchmark figure (docs/BENCHMARKS.md §5). Printed AFTER the
    // marker so the marker stays the exact cumulative DoD string.
    let boot_c1 = tb_hal::read_cycle_counter();
    tb_hal::serial_write_str("boot-cycles=");
    write_hex_u64(boot_c1.wrapping_sub(boot_c0));
    tb_hal::serial_write_byte(b'\n');

    // --- M9: preemptive scheduler (involuntary full-context switch) ---------
    // On a timer tick the kernel INVOLUNTARILY switches kernel tasks: a task
    // that never voluntarily `yield_to`s still loses the CPU. The M8 tick path
    // now calls a SAFE round-robin `schedule()` and tb-hal performs the switch
    // FROM INTERRUPT CONTEXT by REUSING M2's `ctx_switch` UNCHANGED -- the IRQ
    // entry (`__alltraps` / `__vec_irq`) already saved the FULL interrupted
    // frame on each task's own kernel stack, so the cooperative switch only has
    // to swap the callee-saved continuation that returns INTO the IRQ epilogue,
    // whose `iretq`/`eret` restores the full frame at the interrupted
    // instruction. M2's cooperative ping-pong re-ran UNCHANGED above and printed
    // "M2: context-switch OK", proving no regression. ALL the unsafe/asm lives
    // in tb-hal; this crate only drives the safe scheduler facade + reads
    // counters. DoD marker: "M9: preempt OK".
    tb_hal::serial_write_str("preempt-test: arming round-robin preemption\n");

    // Local fail helper (matches the m5_fail..m8_fail style; safe serial only).
    let m9_fail = |why: &str| -> ! {
        tb_hal::serial_write_str("M9: FAIL ");
        tb_hal::serial_write_str(why);
        tb_hal::serial_write_byte(b'\n');
        tb_hal::halt()
    };

    // Register the boot task (the current context) as the first runnable entry,
    // point the M8 tick hook at schedule() BEFORE arming the timer (decision 5),
    // and spawn two no-yield spin tasks. Round-robin order becomes
    // boot -> C -> D -> boot, so the boot task periodically REGAINS the CPU to
    // observe the switch count and render the verdict (decision 3); the spin
    // tasks never disable interrupts, so the timer keeps firing and the rotation
    // never deadlocks.
    tb_hal::scheduler_init();
    tb_hal::set_irq_hook(tb_hal::schedule);
    let _ = tb_hal::scheduler_spawn(STACK_C.take(), spin_c);
    let _ = tb_hal::scheduler_spawn(STACK_D.take(), spin_d);

    // The number of INVOLUNTARY switches that proves preemption. At the M8 ~1 ms
    // tick this lands in ~100 ms -- far inside the 15 s QEMU / 30 s tb-vmm cap.
    const REQUIRED_SWITCHES: u64 = 100;
    // Fail-closed bound on a DEAD timer. Rather than a raw spin cap (which under
    // TCG can out-run the 15 s runner cap before it trips), the wait below
    // watches the M8 tick counter for STAGNATION: a live timer keeps
    // `tick_count()` climbing, so the stall counter resets every slice; only a
    // timer that never fires lets it reach STALL_LIMIT, yielding a clean
    // "M9: FAIL" well inside the runner window. STALL_LIMIT sits far above the
    // spins one ~1 ms tick slice can do, so it never trips on a healthy boot.
    const STALL_LIMIT: u64 = 100_000_000;

    // GO: re-arm the periodic timer (M8 left it masked after its canary) and
    // unmask interrupts. From here a tick drives schedule() from IRQ context.
    tb_hal::timer_rearm();

    // The boot task spins until enough INVOLUNTARY switches have happened. Each
    // tick preempts whoever runs; the boot task loses the CPU to C/D and later
    // resumes HERE through the IRQ epilogue, so this loop is its own re-entry
    // point and observes the count climb across its time slices. Fail-closed on
    // tick STAGNATION: `last_ticks`/`stalled` reset whenever `tick_count()`
    // advances, so only a dead timer lets `stalled` reach STALL_LIMIT and break
    // early into the "M9: FAIL" path below.
    let mut last_ticks = tb_hal::tick_count();
    let mut stalled: u64 = 0;
    while tb_hal::involuntary_switch_count() < REQUIRED_SWITCHES {
        core::hint::spin_loop();
        let now = tb_hal::tick_count();
        if now != last_ticks {
            last_ticks = now;
            stalled = 0;
        } else {
            stalled = stalled.wrapping_add(1);
            if stalled >= STALL_LIMIT {
                break;
            }
        }
    }

    // STOP: mask interrupts + disarm the timer so the verdict + marker render in
    // the boot context with no further preemption (decision 7: timer masked
    // BEFORE the marker).
    tb_hal::timer_disarm();

    let switches = tb_hal::involuntary_switch_count();
    let c_ran = SPIN_C_COUNT.load(Ordering::Relaxed);
    let d_ran = SPIN_D_COUNT.load(Ordering::Relaxed);

    // Optional diagnostic (does NOT gate the grep): how many involuntary
    // switches landed. Printed BEFORE the marker, like M8's boot-cycles line.
    tb_hal::serial_write_str("preempt: involuntary switches=");
    write_hex_u64(switches);
    tb_hal::serial_write_byte(b'\n');

    if switches < REQUIRED_SWITCHES {
        m9_fail("too few involuntary switches (timer never preempted)");
    }
    if c_ran == 0 {
        m9_fail("spin task C never advanced");
    }
    if d_ran == 0 {
        m9_fail("spin task D never advanced");
    }

    tb_hal::serial_write_str("M9: preempt OK\n"); // <-- the M9 DoD marker

    // --- M10: per-entity address spaces (memory isolation) -----------------
    // Each schedulable entity runs in its OWN top-level page table, so one
    // entity cannot read/write another's private memory, while the KERNEL half
    // (code, these stacks, the heap, serial) stays mapped across every switch:
    // tb-hal's `address_space_new` COPIES the whole live kernel root into each
    // space, so the kernel half is shared by reference and survives any flip.
    // The address-space switch FOLDS INTO `yield_to` via each task's assigned
    // space (TASK_AS). tb-hal owns ALL the unsafe -- the table copy/walk, the
    // CR3/TTBR0 writes, the raw VA derefs, the cross-space fault recovery; this
    // forbid(unsafe_code)-class crate only drives the safe facade + branches.
    // The design is SYMMETRIC across arches (no TTBR1/TTBR0 split) and does NOT
    // touch `mmu_init`, so "M3: mmu OK" above is unchanged. DoD: "M10: addrspace OK".
    //
    // PRECONDITION (load-bearing): the timer is DISARMED here -- M9's
    // `timer_disarm()` ran before the "M9: preempt OK" marker above -- so this
    // whole block runs single-threaded with interrupts masked. The manual
    // `address_space_switch` calls below, and the boot task's deliberately
    // unmaintained `TASK_AS[0]` (it stays the sentinel 0 while it switches roots
    // by hand), are only safe single-threaded: a stray tick-driven `schedule()`
    // would flip the root under the boot task mid-probe. Do NOT re-arm the timer
    // before this block.
    tb_hal::serial_write_str("addrspace-test: building two private address spaces\n");

    let m10_fail = |why: &str| -> ! {
        tb_hal::serial_write_str("M10: FAIL ");
        tb_hal::serial_write_str(why);
        tb_hal::serial_write_byte(b'\n');
        tb_hal::halt()
    };

    // (1) Two fresh address spaces, each a COPY of the live kernel root.
    let space_e = match tb_hal::address_space_new() {
        Some(s) => s,
        None => m10_fail("address_space_new (E) out of frames"),
    };
    let space_f = match tb_hal::address_space_new() {
        Some(s) => s,
        None => m10_fail("address_space_new (F) out of frames"),
    };
    if space_e.root_pa() == space_f.root_pa() {
        m10_fail("the two spaces share a root table");
    }

    // (2) Two DISTINCT private frames, mapped at the SAME test VA in each space.
    //     The VA lives in a top-level slot the kernel root never uses, so the
    //     private leaf lands ONLY in that space (the copied kernel half and the
    //     other space are untouched).
    let frame_e = match tb_hal::frame_alloc() {
        Some(p) => p,
        None => m10_fail("no frame for space E's private page"),
    };
    let frame_f = match tb_hal::frame_alloc() {
        Some(p) => p,
        None => m10_fail("no frame for space F's private page"),
    };
    if frame_e == frame_f {
        m10_fail("private frames are not distinct");
    }
    if !tb_hal::map_in_space(space_e, M10_TEST_VA, frame_e, true) {
        m10_fail("map_in_space (E) failed");
    }
    if !tb_hal::map_in_space(space_f, M10_TEST_VA, frame_f, true) {
        m10_fail("map_in_space (F) failed");
    }

    // (3) Two tasks, one per space, exercise the yield_to address-space fold-in:
    //     boot -> G(space E) -> H(space F) -> boot. Each task runs under ITS OWN
    //     root (the fold-in flips it before ctx_switch), writes its private
    //     magic THROUGH the shared test VA and reads back ONLY its own. Serial
    //     working in each task proves the kernel half survived the flip.
    //     Slot budget: boot=0, M2 A=1/B=2, M9 C=3/D=4, M10 G=5/H=6 -> only slot 7
    //     is free under tb-hal's MAX_TASKS=8. Fine for M10 (the terminal
    //     milestone before halt); raise MAX_TASKS before any later milestone
    //     spawns more cumulative kernel tasks, else `task_create` fatals.
    BOOT10_RAW.store(tb_hal::current_task().raw(), Ordering::Release);
    let task_g = tb_hal::task_create(STACK_G.take(), task_g_main);
    let task_h = tb_hal::task_create(STACK_H.take(), task_h_main);
    TASK_G_RAW.store(task_g.raw(), Ordering::Release);
    TASK_H_RAW.store(task_h.raw(), Ordering::Release);
    tb_hal::task_set_address_space(task_g, space_e);
    tb_hal::task_set_address_space(task_h, space_f);
    // Enter G through its stashed handle (symmetric with the H/boot hand-off);
    // the fold-in flips the root boot -> E before ctx_switch, and the
    // G -> H -> boot chain returns control here.
    tb_hal::yield_to(Task::from_raw(TASK_G_RAW.load(Ordering::Acquire)));

    if !G_SEES_OWN.load(Ordering::Acquire) {
        m10_fail("task G did not read its own magic under space E");
    }
    if !H_SEES_OWN.load(Ordering::Acquire) {
        m10_fail("task H did not read its own magic under space F");
    }
    tb_hal::serial_write_str("addrspace: both tasks saw only their own magic\n");

    // (4) Isolation cross-check from the boot task: the SAME VA reads a
    //     DIFFERENT private magic under each root, so neither write leaked into
    //     the other frame. Serial keeps working across each manual switch.
    tb_hal::address_space_switch(space_e);
    if tb_hal::addr_load(M10_TEST_VA) != MAGIC_E {
        m10_fail("space E lost its private magic across switches");
    }
    tb_hal::address_space_switch(space_f);
    if tb_hal::addr_load(M10_TEST_VA) != MAGIC_F {
        m10_fail("space F sees the wrong magic (isolation breach)");
    }
    tb_hal::address_space_switch_default();
    tb_hal::serial_write_str("addrspace: same VA -> different private frame per root\n");

    // (5) Re-assert M3: the M3 self-test VA still reads its post-remap magic
    //     under the default root AND under an entity root, proving the M3
    //     mapping (part of the shared kernel half) survives every switch.
    if !tb_hal::m3_test_va_intact() {
        m10_fail("M3 mapping lost under the default root");
    }
    tb_hal::address_space_switch(space_e);
    let m3_ok_under_e = tb_hal::m3_test_va_intact();
    tb_hal::address_space_switch_default();
    if !m3_ok_under_e {
        m10_fail("M3 mapping not shared into an entity root");
    }

    // (6) Cross-space fault: under the DEFAULT root the test VA is VACANT (its
    //     top-level slot is only ever filled in the entity roots), so reading it
    //     MUST page-fault. The trap hook records the fault and, as a GUARDED
    //     resume, flips the live root to space E (where the VA IS mapped) so the
    //     re-executed read completes and returns space E's magic -- no
    //     livelock, no halt. (Interrupts are masked here: M9 disarmed the timer,
    //     so this whole block is single-threaded.)
    M10_FAULT_HOME_ROOT.store(space_e.root_pa(), Ordering::Release);
    M10_FAULT_VA.store(M10_TEST_VA, Ordering::Release);
    M10_FAULT_SEEN.store(false, Ordering::Release);
    M10_FAULT_ARMED.store(true, Ordering::Release);
    let recovered = tb_hal::addr_load(M10_TEST_VA); // faults -> hook -> resume
    M10_FAULT_ARMED.store(false, Ordering::Release);
    tb_hal::address_space_switch_default(); // undo the hook's recovery switch
    if !M10_FAULT_SEEN.load(Ordering::Acquire) {
        m10_fail("cross-space access did not fault");
    }
    if recovered != MAGIC_E {
        m10_fail("guarded resume read the wrong frame");
    }
    tb_hal::serial_write_str("addrspace: cross-space access faulted and recovered\n");

    tb_hal::serial_write_str("M10: addrspace OK\n"); // <-- the M10 DoD marker

    // --- M11: capability handle table + object registry + agent-native ABI --
    // Every kernel object is reached ONLY through an unforgeable, generation-
    // checked, rights-masked Handle in a per-principal table; unprivileged code
    // reaches the kernel through ONE numbered, capability-checked dispatcher
    // returning a CLOSED SysStatus -- zero ambient authority (no fd/errno/
    // ioctl/path). ALL cap machinery is SAFE Rust (tb_hal::caps, which is
    // forbid(unsafe_code)); the only new unsafe is the per-arch register-lift
    // shim. The timer was disarmed before M9's marker, so the table is touched
    // single-threaded with interrupts masked. DoD marker: "M11: caps OK".
    {
        use tb_hal::caps::{self, Handle, ObjKind, Rights, SyscallArgs, SysStatus};

        // Fail-closed: report which invariant broke and park the core (no M11
        // marker is printed, so the runner's grep fails loudly).
        fn m11_fail(why: &str) -> ! {
            tb_hal::serial_write_str("M11: FAIL ");
            tb_hal::serial_write_str(why);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::halt()
        }

        // (1) A heap-backed per-principal table; mint the ROOT object as the
        //     FIRST capability so its handle is the deterministic (generation 1,
        //     slot 0) = 0x0000_0001_0000_0000 the ring3/EL0 stub names by const.
        let mut root = caps::HandleTable::with_capacity(8);
        let broad = Rights::READ
            .union(Rights::WRITE)
            .union(Rights::DUP)
            .union(Rights::TRANSFER)
            .union(Rights::REVOKE)
            .union(Rights::SPAWN_AGENT);
        let h_root = match root.mint(ObjKind::Agent, broad) {
            Some(h) => h,
            None => m11_fail("could not mint the root capability"),
        };

        // (2) ABI proof: drive ONE numbered, capability-checked syscall FROM
        //     ring3/EL0 through the new register-lift shim, then feed the lifted
        //     call to the SAFE dispatcher and require Ok -- no fd/errno crossed
        //     the boundary, only a (method, handle) the kernel re-validates.
        //     `caps_user_probe` also fails closed unless the stub presented the
        //     deterministic root handle, a second check beside the assert below.
        let lifted = match tb_hal::caps_user_probe(h_root.raw()) {
            Some(a) => a,
            None => m11_fail("ring3 numbered syscall did not reach the dispatcher"),
        };
        if lifted.method != caps::M_OBJECT_INSPECT || lifted.handle != h_root {
            m11_fail("register-lift shim mis-marshalled the numbered syscall");
        }
        if caps::dispatch(&mut root, &lifted).status != SysStatus::Ok {
            m11_fail("dispatcher rejected a valid ring3 capability invocation");
        }
        tb_hal::serial_write_str("caps: ring3 numbered dispatcher returned Ok\n");

        // (3) The capability algebra matrix -- kernel-side safe Rust (the proof).
        //     (a) unknown method -> BadMethod (closed method set).
        if caps::dispatch(&mut root, &SyscallArgs::call(0xDEAD, h_root)).status
            != SysStatus::BadMethod
        {
            m11_fail("unknown method was not BadMethod");
        }
        //     (b) a handle that names no slot -> BadCap (out of range).
        if caps::dispatch(
            &mut root,
            &SyscallArgs::call(caps::M_OBJECT_INSPECT, Handle::from_raw(0x0000_0001_0000_0007)),
        )
        .status
            != SysStatus::BadCap
        {
            m11_fail("dangling handle was not BadCap");
        }
        //     (c) confused-deputy stop: a method whose right the cap lacks ->
        //         Denied (rights live in the slot, not the handle).
        let h_ro = match root.mint(ObjKind::MemoryHome, Rights::READ) {
            Some(h) => h,
            None => m11_fail("could not mint the read-only capability"),
        };
        if caps::dispatch(&mut root, &SyscallArgs::call(caps::M_MEM_WRITE_PROC, h_ro)).status
            != SysStatus::Denied
        {
            m11_fail("missing right was not Denied");
        }
        //     (d) monotonic attenuation: narrow-only, result ALWAYS a subset.
        let narrowed = match root.narrow(h_root, Rights::READ) {
            Some(h) => h,
            None => m11_fail("could not attenuate the root capability"),
        };
        let r_narrow = match root.rights_of(narrowed) {
            Some(r) => r,
            None => m11_fail("attenuated handle did not resolve"),
        };
        let r_root = match root.rights_of(h_root) {
            Some(r) => r,
            None => m11_fail("root handle did not resolve"),
        };
        if !r_narrow.is_subset_of(r_root) {
            m11_fail("attenuation widened rights");
        }
        //     (e) revoke = generation bump -> the SAME handle is now Stale
        //         (O(1) use-after-revoke).
        let h_victim = match root.mint(ObjKind::Generic, Rights::READ) {
            Some(h) => h,
            None => m11_fail("could not mint the revoke-victim capability"),
        };
        if root.revoke(h_victim) != SysStatus::Ok {
            m11_fail("revoke of a held capability failed");
        }
        if caps::dispatch(&mut root, &SyscallArgs::call(caps::M_OBJECT_INSPECT, h_victim)).status
            != SysStatus::Stale
        {
            m11_fail("revoked handle was not Stale");
        }
        //     (f) transfer = MOVE across principals: source goes Stale, the
        //         destination gets a fresh handle to the same object.
        let mut child = caps::HandleTable::with_capacity(4);
        let moved = match root.transfer_to(narrowed, &mut child) {
            Some(h) => h,
            None => m11_fail("transfer to the child principal failed"),
        };
        if caps::dispatch(&mut root, &SyscallArgs::call(caps::M_OBJECT_INSPECT, narrowed)).status
            != SysStatus::Stale
        {
            m11_fail("transferred-from handle was still valid");
        }
        if caps::dispatch(&mut child, &SyscallArgs::call(caps::M_OBJECT_INSPECT, moved)).status
            != SysStatus::Ok
        {
            m11_fail("transferred handle was not usable in the destination");
        }
        //     (g) object-table exhaustion is a closed status, never a panic.
        let mut tiny = caps::HandleTable::with_capacity(1);
        if tiny.mint(ObjKind::Generic, Rights::READ).is_none() {
            m11_fail("first mint into a capacity-1 table failed");
        }
        if tiny.mint(ObjKind::Generic, Rights::READ).is_some() {
            m11_fail("over-capacity mint was not refused");
        }
        tb_hal::serial_write_str("caps: attenuate/transfer/revoke/ObjFull algebra holds\n");
    }

    tb_hal::serial_write_str("M11: caps OK\n"); // <-- the M11 DoD marker

    // --- M12: the agent runtime -- AgentProcess as a first-class OS entity ----
    // Root spawns TWO agents, each in its OWN address space (M10) holding ONLY
    // its manifest-declared handles (M11), scheduled PREEMPTIVELY in ring3/EL0
    // (M9 + the user-mode preemption plumbing) and born with a memory-home handle
    // (M13 substrate later). The self-test proves, end to end: born-with memory
    // (witness #1 kernel-side + witness #2 user-side), involuntary USER-mode
    // preemption (the timer round-robins both ring3/EL0 agents), a permitted
    // capability-checked syscall (Ok) and a non-manifest one (Denied), and a
    // child fault on a parent-only VA recovered in the trap hook. The kernel
    // stays unsafe-free: every privileged step is a safe tb-hal facade call.
    // DoD marker: "M12: agent OK".
    {
        fn m12_fail(why: &str) -> ! {
            tb_hal::serial_write_str("M12: FAIL ");
            tb_hal::serial_write_str(why);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::halt()
        }

        // PHASE 0 -- spawn (timer still disarmed). Reset the run queue to {boot};
        // each `agent_spawn` mints its address space + handle table (born-with
        // memory_home/bootstrap/budget + the manifest grants), fabricates the
        // user-launch frame, maps its user code/stack and ENQUEUES it.
        tb_hal::scheduler_init();
        tb_hal::set_irq_hook(tb_hal::schedule);
        tb_hal::agent_traps_init();
        let agent_a = tb_hal::agent_spawn(&MANIFEST_A, STACK_AGENT_A.take());
        let agent_b = tb_hal::agent_spawn(&MANIFEST_B, STACK_AGENT_B.take());

        // Witness #1 (kernel-side, BEFORE either agent has run a single
        // instruction): each agent's table already resolves its memory-home and
        // bootstrap handles -> born-with memory with ZERO setup syscalls.
        if !tb_hal::agent_born_ok(agent_a) || !tb_hal::agent_born_ok(agent_b) {
            m12_fail("an agent was not born holding its memory-home/bootstrap handles");
        }
        tb_hal::serial_write_str("agent: both agents born with memory-home + bootstrap (zero setup)\n");

        // PHASE 1 -- preemptive round-robin in ring3/EL0 (the user-preemption
        // proof). Re-arm the timer: for the FIRST time, USER tasks are
        // involuntarily preempted. Each agent's stub makes a PERMITTED
        // capability-checked syscall (inspect its memory home -> Ok) and a
        // NON-MANIFEST one (emit-external -> Denied), then spins so ONLY the
        // timer can take the CPU.
        let switches_before = tb_hal::involuntary_switch_count();
        tb_hal::timer_rearm();
        let mut stall: u64 = 0;
        const STALL_LIMIT: u64 = 800_000_000;
        loop {
            let sw = tb_hal::involuntary_switch_count().wrapping_sub(switches_before);
            let done = sw >= M12_REQUIRED_SWITCHES
                && tb_hal::agent_permitted_ok(agent_a)
                && tb_hal::agent_permitted_ok(agent_b)
                && tb_hal::agent_denied_ok(agent_a)
                && tb_hal::agent_denied_ok(agent_b);
            if done {
                break;
            }
            stall += 1;
            if stall > STALL_LIMIT {
                tb_hal::timer_disarm();
                m12_fail("agents did not reach the preemption + cap-check goal in time");
            }
            core::hint::spin_loop();
        }
        tb_hal::timer_disarm(); // STOP before the verdict (like M9)
        let switches = tb_hal::involuntary_switch_count().wrapping_sub(switches_before);

        if !tb_hal::agent_permitted_ok(agent_a) || !tb_hal::agent_permitted_ok(agent_b) {
            m12_fail("an agent's permitted capability syscall was not observed Ok");
        }
        if !tb_hal::agent_denied_ok(agent_a) || !tb_hal::agent_denied_ok(agent_b) {
            m12_fail("a non-manifest capability syscall was not Denied (TB_ENOTCAPABLE)");
        }
        if switches < M12_REQUIRED_SWITCHES {
            m12_fail("too few involuntary switches (user-mode preemption did not occur)");
        }
        tb_hal::serial_write_str("agent: permitted syscall Ok + non-manifest syscall Denied (both agents)\n");
        tb_hal::serial_write_str("agent: involuntary user-mode switches=");
        write_hex_u64(switches);
        tb_hal::serial_write_byte(b'\n');

        // PHASE 2 -- parent-only-VA fault (timer disarmed, single-threaded; reuse
        // the M10 armed-fault + guarded-resume mechanism). Map M12_PARENT_VA only
        // in a parent space and seed its magic; an agent's root leaves that
        // top-level slot vacant, so a read of it under the child's root faults ->
        // the trap hook records it and flips to the parent space (the access
        // re-executes where the VA IS mapped).
        let parent_space = match tb_hal::address_space_new() {
            Some(s) => s,
            None => m12_fail("no frame for the parent-only address space"),
        };
        let pframe = match tb_hal::frame_alloc() {
            Some(p) => p,
            None => m12_fail("no frame for the parent-only page"),
        };
        if !tb_hal::map_in_space(parent_space, M12_PARENT_VA, pframe, true) {
            m12_fail("could not map the parent-only page");
        }
        tb_hal::address_space_switch(parent_space);
        let seeded = tb_hal::addr_store_load(M12_PARENT_VA, MAGIC_PARENT);
        tb_hal::address_space_switch_default();
        if seeded != MAGIC_PARENT {
            m12_fail("seeding the parent-only page failed");
        }

        let child_root = tb_hal::agent_root_pa(agent_a);
        if child_root == 0 {
            m12_fail("agent A has no address-space root");
        }
        M10_FAULT_HOME_ROOT.store(parent_space.root_pa(), Ordering::Release);
        M10_FAULT_VA.store(M12_PARENT_VA, Ordering::Release);
        M10_FAULT_SEEN.store(false, Ordering::Release);
        M10_FAULT_ARMED.store(true, Ordering::Release);
        tb_hal::address_space_switch_root(child_root); // run under the agent's own root
        let recovered = tb_hal::addr_load(M12_PARENT_VA); // faults -> hook -> resume
        M10_FAULT_ARMED.store(false, Ordering::Release);
        tb_hal::address_space_switch_default(); // undo the hook's recovery switch
        if !M10_FAULT_SEEN.load(Ordering::Acquire) {
            m12_fail("child access to a parent-only VA did not fault (isolation breach)");
        }
        if recovered != MAGIC_PARENT {
            m12_fail("guarded resume read the wrong frame");
        }
        M12_CHILD_FAULTED.store(true, Ordering::Release);
        tb_hal::serial_write_str("agent: child fault on a parent-only VA, recovered in the hook\n");

        // VERDICT -- every M12 invariant must hold together.
        if !(tb_hal::agent_born_ok(agent_a)
            && tb_hal::agent_born_ok(agent_b)
            && tb_hal::agent_permitted_ok(agent_a)
            && tb_hal::agent_permitted_ok(agent_b)
            && tb_hal::agent_denied_ok(agent_a)
            && tb_hal::agent_denied_ok(agent_b)
            && switches >= M12_REQUIRED_SWITCHES
            && M12_CHILD_FAULTED.load(Ordering::Acquire))
        {
            m12_fail("a final M12 invariant did not hold");
        }
    }

    tb_hal::serial_write_str("M12: agent OK\n"); // <-- the M12 DoD marker

    // --- M13: the default tiered, persistent, recallable memory substrate -----
    // Every agent's born-with ObjKind::MemoryHome now carries a REAL per-agent
    // tiered substrate (T0 registers + T1 working graph + T2 episodic journal +
    // T3 lexical semantic store), reached ONLY through the M11 dispatch
    // chokepoint, rights-gated, namespaced memory:private/<agent>. The timer is
    // already disarmed (single-threaded, interrupts masked -- exactly the
    // discipline the substrate's RefCell relies on). Two witnesses: (A) kernel-
    // side, driving caps::dispatch directly with the full [u64;4] encoding, and
    // (B) through the ACTUAL born-with home of freshly spawned agents (proving it
    // is a real per-agent guarantee, not a local toy). DoD marker: "M13: memory OK".
    //
    // M14 NOTE: agent_c / agent_d are spawned HERE, at function scope BEFORE the
    // M13 block, so the M14 IPC self-test (after the M13 marker) can reuse them
    // as the two channel peers WITHOUT consuming extra MAX_TASKS slots. Their
    // slot assignment is unchanged from the green build (WITNESS A spawns nothing).
    let agent_c = tb_hal::agent_spawn(&MANIFEST_A, STACK_AGENT_C.take());
    let agent_d = tb_hal::agent_spawn(&MANIFEST_B, STACK_AGENT_D.take());
    {
        use tb_hal::caps::{self, Handle, ObjKind, Rights, SysStatus};

        fn m13_fail(why: &str) -> ! {
            tb_hal::serial_write_str("M13: FAIL ");
            tb_hal::serial_write_str(why);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::halt()
        }

        // A capability-checked dispatch against `h` in `tbl` with the full
        // pointer-free [u64;4] inline-arg encoding.
        fn disp(
            tbl: &mut tb_hal::caps::HandleTable,
            h: tb_hal::caps::Handle,
            method: u32,
            a: [u64; 4],
        ) -> tb_hal::caps::SysReturn {
            tb_hal::caps::dispatch(
                tbl,
                &tb_hal::caps::SyscallArgs {
                    method,
                    handle: h,
                    args: a,
                },
            )
        }

        const TOK_K: u64 = 0x1001; // a synthetic query/lexical token id (no embeddings)
        const TOK_J: u64 = 0x1002; // a different token (must NOT match a TOK_K recall)
        const V0: u64 = 0x0000_BEEF; // value scalar; read-back proves instant RYW
        let ok = SysStatus::Ok as u32;

        // ============ WITNESS A -- kernel-side over caps::dispatch ============
        let mut tbl = caps::HandleTable::with_capacity(16);
        let all = Rights::READ
            .union(Rights::WRITE)
            .union(Rights::RECALL)
            .union(Rights::CONSOLIDATE);
        let home = match tbl.mint_memory_home(all) {
            Some(h) => h,
            None => m13_fail("could not mint a memory home with all rights"),
        };

        // 1. WRITE three records (op=ADD). The high-importance + most-recent
        //    TOK_K record (id_win) must win recall; id_old (TOK_K, low imp) is the
        //    runner-up; id_other (TOK_J) must never match a TOK_K query.
        let r_old = disp(&mut tbl, home, caps::M_MEM_WRITE, [0, TOK_K, 0x1111, 3]);
        if r_old.status != SysStatus::Ok {
            m13_fail("write of id_old was not Ok");
        }
        let id_old = r_old.value;
        let r_other = disp(&mut tbl, home, caps::M_MEM_WRITE, [0, TOK_J, 0x2222, 7]);
        if r_other.status != SysStatus::Ok {
            m13_fail("write of id_other was not Ok");
        }
        let r_win = disp(&mut tbl, home, caps::M_MEM_WRITE, [0, TOK_K, V0, 9]);
        if r_win.status != SysStatus::Ok {
            m13_fail("write of id_win was not Ok");
        }
        let id_win = r_win.value;

        // 2. READ-YOUR-WRITES (instant, append-only T2): read id_win -> V0.
        let ryw = disp(&mut tbl, home, caps::M_MEM_READ, [id_win, 0, 0, 0]);
        if ryw.status != SysStatus::Ok || ryw.value != V0 {
            m13_fail("read-your-writes did not return the written value");
        }
        tb_hal::serial_write_str("mem: read-your-writes OK (instant, append-only T2)\n");

        // 3. RECALL (activation-ranked) -> copy-on-retrieve MemoryRecord.
        let rec = disp(&mut tbl, home, caps::M_MEM_RECALL, [TOK_K, 0, 1, 0]);
        if rec.status != SysStatus::Ok {
            m13_fail("activation recall did not return Ok");
        }
        let h_rec = Handle::from_raw(rec.value);
        let insp = disp(&mut tbl, h_rec, caps::M_OBJECT_INSPECT, [0, 0, 0, 0]);
        if insp.status != SysStatus::Ok || insp.value != ObjKind::MemoryRecord as u64 {
            m13_fail("recall handle did not resolve to a MemoryRecord (copy-on-retrieve)");
        }
        let rid = disp(&mut tbl, h_rec, caps::M_MEM_READ, [0, 0, 0, 0]);
        if rid.status != SysStatus::Ok || rid.value != id_win {
            m13_fail("recall did not rank the high-importance recent record first");
        }
        // retrieve_next: the Finsts ring excludes id_win -> advances to id_old.
        let rec2 = disp(&mut tbl, home, caps::M_MEM_RECALL, [TOK_K, 1, 1, 0]);
        if rec2.status != SysStatus::Ok {
            m13_fail("retrieve_next recall did not return Ok");
        }
        let rid2 = disp(&mut tbl, Handle::from_raw(rec2.value), caps::M_MEM_READ, [0, 0, 0, 0]);
        if rid2.status != SysStatus::Ok || rid2.value != id_old || rid2.value == id_win {
            m13_fail("Finsts did not advance to the next candidate (loop not broken)");
        }
        tb_hal::serial_write_str("mem: activation recall ranked + Finsts advanced (id_win -> id_old)\n");

        // 4. CONSOLIDATE (gated SUCCESS -- this home HOLDS CONSOLIDATE).
        let cons = disp(&mut tbl, home, caps::M_MEM_CONSOLIDATE, [0, id_old, 0, 0]);
        if cons.status != SysStatus::Ok || cons.value < 1 {
            m13_fail("gated consolidate (tombstone) did not run");
        }
        tb_hal::serial_write_str("mem: gated consolidate tombstoned a record (CONSOLIDATE right)\n");

        // 5. RIGHTS-DENIED paths (fall straight out of the required_right gate).
        let home_ro = match tbl.mint_memory_home(Rights::READ.union(Rights::RECALL)) {
            Some(h) => h,
            None => m13_fail("could not mint the read-only memory home"),
        };
        if disp(&mut tbl, home_ro, caps::M_MEM_WRITE, [0, TOK_K, 1, 1]).status != SysStatus::Denied {
            m13_fail("WRITE on a home lacking WRITE was not Denied");
        }
        if disp(&mut tbl, home_ro, caps::M_MEM_CONSOLIDATE, [0, 0, 0, 0]).status != SysStatus::Denied {
            m13_fail("CONSOLIDATE on a home lacking CONSOLIDATE was not Denied");
        }
        if disp(&mut tbl, home_ro, 99, [0, 0, 0, 0]).status != SysStatus::BadMethod {
            m13_fail("an unknown method was not BadMethod (closed method set changed)");
        }
        tb_hal::serial_write_str("mem: rights-denied paths Denied + closed method set intact\n");

        // ============ WITNESS B -- through the ACTUAL born-with home ============
        // Spawn two fresh agents; each is BORN with a real substrate behind its
        // memory_home (agent_spawn -> mint_memory_home). The timer stays disarmed,
        // so they never run a user instruction -- we drive their substrate from the
        // kernel through agent_mem_dispatch (the M11 chokepoint). (agent_c /
        // agent_d were spawned at function scope just above this block so the M14
        // IPC self-test can reuse them.)

        let (s, id_c) = match tb_hal::agent_mem_dispatch(agent_c, caps::M_MEM_WRITE, 0, TOK_K, V0, 5)
        {
            Some(x) => x,
            None => m13_fail("agent C is not a live agent"),
        };
        if s != ok {
            m13_fail("agent C WRITE to its born-with home was not Ok");
        }
        let (s, v) = tb_hal::agent_mem_dispatch(agent_c, caps::M_MEM_READ, id_c, 0, 0, 0)
            .unwrap_or((SysStatus::BadCap as u32, 0));
        if s != ok || v != V0 {
            m13_fail("agent C read-your-writes failed on its born-with home");
        }
        let (s, _h) = tb_hal::agent_mem_dispatch(agent_c, caps::M_MEM_RECALL, TOK_K, 0, 1, 0)
            .unwrap_or((SysStatus::BadCap as u32, 0));
        if s != ok {
            m13_fail("agent C recall failed on its born-with home");
        }
        let (s, _) = tb_hal::agent_mem_dispatch(agent_c, caps::M_MEM_CONSOLIDATE, 0, id_c, 0, 0)
            .unwrap_or((ok, 0));
        if s != SysStatus::Denied as u32 {
            m13_fail("agent C consolidate was not Denied (born-with home lacks CONSOLIDATE)");
        }
        // per-agent isolation: agent D's substrate cannot see agent C's record.
        let (s, v) = tb_hal::agent_mem_dispatch(agent_d, caps::M_MEM_READ, id_c, 0, 0, 0)
            .unwrap_or((SysStatus::BadCap as u32, 0));
        if s == ok && v == V0 {
            m13_fail("agent D read agent C's private memory (per-agent isolation breach)");
        }
        tb_hal::serial_write_str(
            "agent: born-with home is a real per-agent substrate (write/recall Ok, consolidate Denied, isolated)\n",
        );
    }

    tb_hal::serial_write_str("M13: memory OK\n"); // <-- the M13 DoD marker

    // --- M14: inter-agent IPC -- capability-passing channels + ordered streams --
    // Two agents communicate over an ORDERED, BOUNDED, BIDIRECTIONAL message
    // stream; a message can CARRY a capability MOVED from the sender's HandleTable
    // into the receiver's (the M11 transfer_to move split across the ring --
    // rights ride intact, attenuated cross-agent first via M_HANDLE_NARROW), all
    // through the single M11 dispatch chokepoint. The timer is disarmed (single-
    // core, interrupts masked -- exactly the discipline the channel's RefCell
    // rings rely on). We reuse the already-born agent_c (side 0, sender) +
    // agent_d (side 1, receiver) as the two peers (no extra task slots).
    //
    // The disarmed-timer self-test observes the CLOSED-STATUS form
    // (WouldBlock / PeerClosed) DIRECTLY; the recv-blocks-off-the-runqueue /
    // send-wakes-peer scheduler round-trip is the additive Step-2 layer the same
    // milestone wires but a disarmed-timer self-test cannot exercise. The real
    // variable-length BYTE payload (copy_to_user) is the ONLY M14 unsafe and is
    // deliberately DEFERRED -- this marker rides the inline-scalar payload with
    // the cap moved by handle, at ZERO new unsafe. DoD marker: "M14: ipc OK".
    {
        use tb_hal::caps::{self, Handle, ObjKind, Rights, SysStatus};

        fn m14_fail(why: &str) -> ! {
            tb_hal::serial_write_str("M14: FAIL ");
            tb_hal::serial_write_str(why);
            tb_hal::serial_write_byte(b'\n');
            tb_hal::halt()
        }

        let ok = SysStatus::Ok as u32;
        let wb = SysStatus::WouldBlock as u32;
        let den = SysStatus::Denied as u32;
        let badcap = SysStatus::BadCap as u32;
        let badmethod = SysStatus::BadMethod as u32;
        let stale = SysStatus::Stale as u32;
        let peerclosed = SysStatus::PeerClosed as u32;
        let rd = Rights::READ.bits();
        let wr = Rights::WRITE.bits();

        // 1. CONNECT one bounded (cap=2) channel: ep_a (side 0) in C, ep_b
        //    (side 1) in D, sharing ONE Rc<Channel>.
        let (ep_a, ep_b) = match tb_hal::agent_channel_connect(agent_c, agent_d, 2) {
            Some(x) => x,
            None => m14_fail("channel connect failed"),
        };

        // 2. MINT a carried cap in C with READ|WRITE|TRANSFER, then NARROW it
        //    (mask READ|TRANSFER) -> drops WRITE: the derived-narrowed capability.
        let cap0 = match tb_hal::agent_mint_generic(
            agent_c,
            Rights::READ.union(Rights::WRITE).union(Rights::TRANSFER),
        ) {
            Some(h) => h,
            None => m14_fail("mint carried cap failed"),
        };
        let narrow_mask = Rights::READ.union(Rights::TRANSFER).bits() as u64;
        let (s, cap_h_raw) =
            tb_hal::agent_cap_dispatch(agent_c, caps::M_HANDLE_NARROW, cap0, narrow_mask, 0)
                .unwrap_or((badcap, 0));
        if s != ok || cap_h_raw == 0 {
            m14_fail("narrow of the carried cap was not Ok");
        }
        let cap_h = Handle::from_raw(cap_h_raw);

        // 3. SEND #1 (cap-carrying, payload 0xCAFE) C -> D.
        let (s, _) =
            tb_hal::agent_chan_send(agent_c, ep_a, 0xCAFE, cap_h_raw).unwrap_or((badcap, 0));
        if s != ok {
            m14_fail("cap-carrying send #1 was not Ok");
        }
        // The carried cap is now STALE in C ("A no longer can"): consumed on write.
        let (s, _) = tb_hal::agent_cap_dispatch(agent_c, caps::M_OBJECT_INSPECT, cap_h, 0, 0)
            .unwrap_or((ok, 0));
        if s != stale {
            m14_fail("carried cap was not STALE in the sender after send (move did not consume)");
        }

        // 4. SEND #2 (bytes-only, payload 0xF00D) -- fills the bound-2 outbox.
        let (s, _) = tb_hal::agent_chan_send(agent_c, ep_a, 0xF00D, 0).unwrap_or((badcap, 0));
        if s != ok {
            m14_fail("bytes-only send #2 was not Ok");
        }

        // 5. RECV #1 in D: FIFO head 0xCAFE, carrying the moved cap.
        let (s, payload, moved_raw) =
            tb_hal::agent_chan_recv_full(agent_d, ep_b).unwrap_or((badcap, 0, 0));
        if s != ok || payload != 0xCAFE || moved_raw == 0 {
            m14_fail("recv #1 did not deliver payload 0xCAFE with a moved cap");
        }
        let moved = Handle::from_raw(moved_raw);
        // D USES the moved cap: a READ-gated inspect -> Ok, right ObjKind.
        let (s, kind) = tb_hal::agent_cap_dispatch(agent_d, caps::M_OBJECT_INSPECT, moved, 0, 0)
            .unwrap_or((badcap, 0));
        if s != ok || kind != ObjKind::Generic as u64 {
            m14_fail("receiver could not USE the moved cap (inspect failed / wrong kind)");
        }
        // ATTENUATION held CROSS-AGENT: the pre-send narrow dropped WRITE.
        let mr = tb_hal::agent_rights_of(agent_d, moved).unwrap_or(0);
        if (mr & rd) == 0 || (mr & wr) != 0 {
            m14_fail("moved cap rights not attenuated cross-agent (want READ kept, WRITE dropped)");
        }

        // 6. FIFO: RECV #2 -> 0xF00D, no cap (proves 0xCAFE was delivered FIRST).
        let (s, payload, moved2) =
            tb_hal::agent_chan_recv_full(agent_d, ep_b).unwrap_or((badcap, 0, 0));
        if s != ok || payload != 0xF00D || moved2 != 0 {
            m14_fail("recv #2 broke per-direction FIFO (expected 0xF00D, no cap)");
        }
        tb_hal::serial_write_str("ipc: FIFO + capability moved + attenuated cross-agent\n");

        // 7. EMPTY inbox, peer still open -> WouldBlock.
        let (s, _, _) = tb_hal::agent_chan_recv_full(agent_d, ep_b).unwrap_or((badcap, 0, 0));
        if s != wb {
            m14_fail("recv on an empty-but-open inbox was not WouldBlock");
        }

        // 8. DENIED / non-channel paths (outbox has space; NONE of these enqueue).
        //    (a) M_CHAN_SEND on a NON-channel object (Generic w/ WRITE): passes
        //        the WRITE gate, the body sees chan==None -> BadCap.
        let gen_w = match tb_hal::agent_mint_generic(agent_c, Rights::READ.union(Rights::WRITE)) {
            Some(h) => h,
            None => m14_fail("mint non-channel WRITE cap failed"),
        };
        let (s, _) = tb_hal::agent_chan_send(agent_c, gen_w, 0, 0).unwrap_or((ok, 0));
        if s != badcap {
            m14_fail("M_CHAN_SEND on a non-channel object was not BadCap");
        }
        //    (b) endpoint NARROWed to drop WRITE -> Denied at the required_right gate.
        let (s, epa_no_w_raw) =
            tb_hal::agent_cap_dispatch(agent_c, caps::M_HANDLE_NARROW, ep_a, rd as u64, 0)
                .unwrap_or((badcap, 0));
        if s != ok || epa_no_w_raw == 0 {
            m14_fail("narrow of ep_a (drop WRITE) failed");
        }
        let (s, _) = tb_hal::agent_chan_send(agent_c, Handle::from_raw(epa_no_w_raw), 0xAA, 0)
            .unwrap_or((ok, 0));
        if s != den {
            m14_fail("send on a WRITE-less endpoint was not Denied");
        }
        //    (c) carried cap lacking TRANSFER -> Denied (checked before any detach).
        let cap_no_t = match tb_hal::agent_mint_generic(agent_c, Rights::READ) {
            Some(h) => h,
            None => m14_fail("mint no-TRANSFER cap failed"),
        };
        let (s, _) =
            tb_hal::agent_chan_send(agent_c, ep_a, 0xBB, cap_no_t.raw()).unwrap_or((ok, 0));
        if s != den {
            m14_fail("sending a cap lacking TRANSFER was not Denied");
        }
        //    (d) sending an endpoint into its OWN channel -> Denied (Zircon NOT_SUPPORTED).
        let (s, _) = tb_hal::agent_chan_send(agent_c, ep_a, 0xCC, ep_a.raw()).unwrap_or((ok, 0));
        if s != den {
            m14_fail("sending an endpoint into its own channel was not Denied");
        }
        //    (e) unknown method 28 -> BadMethod (the closed method set is intact).
        let (s, _) = tb_hal::agent_cap_dispatch(agent_c, 28, ep_a, 0, 0).unwrap_or((ok, 0));
        if s != badmethod {
            m14_fail("an unknown channel method was not BadMethod");
        }

        // 9. BACKPRESSURE + ATOMICITY: fill C's outbox to the bound (2), then a
        //    cap-carrying send -> WouldBlock with the carried cap NOT stranded.
        let (s, _) = tb_hal::agent_chan_send(agent_c, ep_a, 0x1, 0).unwrap_or((badcap, 0));
        if s != ok {
            m14_fail("backpressure fill #1 was not Ok");
        }
        let (s, _) = tb_hal::agent_chan_send(agent_c, ep_a, 0x2, 0).unwrap_or((badcap, 0));
        if s != ok {
            m14_fail("backpressure fill #2 was not Ok");
        }
        let cap2 = match tb_hal::agent_mint_generic(agent_c, Rights::READ.union(Rights::TRANSFER)) {
            Some(h) => h,
            None => m14_fail("mint atomicity cap failed"),
        };
        let (s, _) = tb_hal::agent_chan_send(agent_c, ep_a, 0x3, cap2.raw()).unwrap_or((ok, 0));
        if s != wb {
            m14_fail("cap-carrying send into a full outbox was not WouldBlock");
        }
        // ATOMICITY: the carried cap is STILL live in C (never detached).
        let (s, _) = tb_hal::agent_cap_dispatch(agent_c, caps::M_OBJECT_INSPECT, cap2, 0, 0)
            .unwrap_or((stale, 0));
        if s != ok {
            m14_fail("WouldBlock send STRANDED the carried cap (atomicity broken)");
        }
        tb_hal::serial_write_str(
            "ipc: full channel WouldBlock + non-channel BadCap + denied paths\n",
        );

        // 10. PEER-CLOSED (fire-and-forget): D closes its endpoint; a send from C
        //     now sees the peer gone -> PeerClosed.
        let (s, _) = tb_hal::agent_cap_dispatch(agent_d, caps::M_CHAN_CLOSE, ep_b, 0, 0)
            .unwrap_or((badcap, 0));
        if s != ok {
            m14_fail("closing the receiver endpoint was not Ok");
        }
        let (s, _) = tb_hal::agent_chan_send(agent_c, ep_a, 0x9, 0).unwrap_or((ok, 0));
        if s != peerclosed {
            m14_fail("send to a closed peer was not PeerClosed");
        }
        tb_hal::serial_write_str("ipc: peer-closed surfaces PeerClosed (fire-and-forget close)\n");
    }

    tb_hal::serial_write_str("M14: ipc OK\n"); // <-- the M14 DoD marker

    tb_hal::halt()
}

/// Task A (\"ping\"): drives `ROUND_TRIPS` strict A,B,A,B round-trips against
/// task B, renders the M2 verdict, then hands the CPU back to the bootstrap
/// context so `rust_main` can run the M3/M4 sequence.
fn task_a_main() {
    let task_b = Task::from_raw(TASK_B_RAW.load(Ordering::Acquire));

    let mut a_loops: usize = 0; // canary 1: monotonic loop count
    let mut a_sum: usize = 0; // canary 2: accumulator over the index
    let mut a_pat: usize = PAT_A_INIT; // canary 3: rotating bit pattern

    let mut i: usize = 0;
    while i < ROUND_TRIPS {
        if TURN.load(Ordering::Acquire) != TURN_A {
            fail("A: turn flag not A at round start");
        }
        let c = COUNTER.load(Ordering::Acquire);
        if c != 2 * i {
            fail("A: shared counter out of sequence");
        }
        if black_box(a_loops) != i {
            fail("A: local loop canary corrupted");
        }
        COUNTER.store(c + 1, Ordering::Release);
        a_loops = black_box(a_loops) + 1;
        a_sum = black_box(a_sum).wrapping_add(i);
        a_pat = black_box(a_pat).rotate_left(1);
        TURN.store(TURN_B, Ordering::Release);

        tb_hal::yield_to(task_b); // <-- the cooperative switch under test

        if TURN.load(Ordering::Acquire) != TURN_A {
            fail("A: alternation broken after resume");
        }
        i += 1;
    }

    let mut want_sum: usize = 0;
    let mut want_pat: usize = PAT_A_INIT;
    let mut k: usize = 0;
    while k < ROUND_TRIPS {
        want_sum = black_box(want_sum).wrapping_add(k);
        want_pat = black_box(want_pat).rotate_left(1);
        k += 1;
    }
    if black_box(a_loops) != ROUND_TRIPS {
        fail("A: final loop count wrong");
    }
    if black_box(a_sum) != want_sum {
        fail("A: final sum canary wrong");
    }
    if black_box(a_pat) != want_pat {
        fail("A: final pattern canary wrong");
    }
    if COUNTER.load(Ordering::Acquire) != 2 * ROUND_TRIPS {
        fail("A: final shared counter wrong");
    }
    if !B_VERIFIED.load(Ordering::Acquire) {
        fail("A: task B never reported success");
    }

    tb_hal::serial_write_str("M2: context-switch OK\n"); // <-- the M2 DoD marker

    M2_PASSED.store(true, Ordering::Release);
    tb_hal::yield_to(Task::from_raw(BOOT_TASK_RAW.load(Ordering::Acquire)));

    fail("A: resumed after handing control back to bootstrap")
}

/// Task B (\"pong\"): mirror half of the ping-pong, with its own canary locals
/// live across every yield. Audits its canaries on the FINAL round before the
/// last yield and publishes the verdict via `B_VERIFIED`.
fn task_b_main() {
    let task_a = Task::from_raw(TASK_A_RAW.load(Ordering::Acquire));

    let mut b_loops: usize = 0; // canary 1: monotonic loop count
    let mut b_sum: usize = 0; // canary 2: accumulator over the index
    let mut b_pat: usize = PAT_B_INIT; // canary 3: rotating bit pattern

    let mut j: usize = 0;
    while j < ROUND_TRIPS {
        if TURN.load(Ordering::Acquire) != TURN_B {
            fail("B: turn flag not B at round start");
        }
        let c = COUNTER.load(Ordering::Acquire);
        if c != 2 * j + 1 {
            fail("B: shared counter out of sequence");
        }
        if black_box(b_loops) != j {
            fail("B: local loop canary corrupted");
        }
        COUNTER.store(c + 1, Ordering::Release);
        b_loops = black_box(b_loops) + 1;
        b_sum = black_box(b_sum).wrapping_add(j);
        b_pat = black_box(b_pat).rotate_left(1);
        j += 1;

        if j == ROUND_TRIPS {
            let mut want_sum: usize = 0;
            let mut want_pat: usize = PAT_B_INIT;
            let mut k: usize = 0;
            while k < ROUND_TRIPS {
                want_sum = black_box(want_sum).wrapping_add(k);
                want_pat = black_box(want_pat).rotate_left(1);
                k += 1;
            }
            if black_box(b_loops) != ROUND_TRIPS {
                fail("B: final loop count wrong");
            }
            if black_box(b_sum) != want_sum {
                fail("B: final sum canary wrong");
            }
            if black_box(b_pat) != want_pat {
                fail("B: final pattern canary wrong");
            }
            B_VERIFIED.store(true, Ordering::Release);
        }

        TURN.store(TURN_A, Ordering::Release);
        tb_hal::yield_to(task_a); // <-- the cooperative switch under test
    }

    fail("B: resumed after completing all rounds")
}

/// Emit the M2 failure verdict (\"M2: FAIL <why>\") over serial and park the
/// core. Never returns; the run scripts then miss the later markers.
fn fail(why: &str) -> ! {
    tb_hal::serial_write_str("M2: FAIL ");
    tb_hal::serial_write_str(why);
    tb_hal::serial_write_byte(b'\n');
    tb_hal::halt()
}

/// M9 spin task C: the involuntary-preemption proof. It NEVER `yield_to`s. It
/// unmasks interrupts ONCE at the top -- a task first-activated through
/// `ctx_switch` is entered with interrupts still masked from the IRQ that
/// switched into it (it never passed through an `iretq`/`eret` that would
/// restore them), so it must go preemptible itself -- then loops forever bumping
/// its own counter. The loop has no `yield_to` / `wfi` / `hlt` / `cli`; only the
/// periodic timer can take the CPU from it, which is exactly the property M9
/// proves. It must never return (M2's `task_exit_guard` would catch it loudly).
fn spin_c() {
    tb_hal::irq_unmask(); // become preemptible exactly once, then never yield
    loop {
        SPIN_C_COUNT.fetch_add(1, Ordering::Relaxed);
        core::hint::spin_loop();
    }
}

/// M9 spin task D: identical to `spin_c` but bumps its own counter, so the
/// self-test can prove BOTH no-yield tasks advanced under round-robin preemption.
fn spin_d() {
    tb_hal::irq_unmask(); // become preemptible exactly once, then never yield
    loop {
        SPIN_D_COUNT.fetch_add(1, Ordering::Relaxed);
        core::hint::spin_loop();
    }
}

/// M10 task G: runs in address space E (the `yield_to` fold-in flips the live
/// root to E before this task is entered). Writes its private magic THROUGH the
/// shared test VA and reads back ONLY its own, publishes the verdict, then hands
/// the CPU to task H (which yields on to the boot task). Never returns.
fn task_g_main() {
    let seen = tb_hal::addr_store_load(M10_TEST_VA, MAGIC_E);
    if seen == MAGIC_E {
        G_SEES_OWN.store(true, Ordering::Release);
    }
    tb_hal::serial_write_str("addrspace: task G wrote+read its magic under space E\n");
    tb_hal::yield_to(Task::from_raw(TASK_H_RAW.load(Ordering::Acquire)));
    // Normal flow never resumes G; if it somehow does, fail loudly.
    tb_hal::serial_write_str("M10: FAIL task G resumed after hand-off\n");
    tb_hal::halt()
}

/// M10 task H: as task G but in address space F; after writing+verifying its own
/// magic it yields back to the boot task, which renders the isolation checks and
/// the M10 verdict. Never returns.
fn task_h_main() {
    let seen = tb_hal::addr_store_load(M10_TEST_VA, MAGIC_F);
    if seen == MAGIC_F {
        H_SEES_OWN.store(true, Ordering::Release);
    }
    tb_hal::serial_write_str("addrspace: task H wrote+read its magic under space F\n");
    tb_hal::yield_to(Task::from_raw(BOOT10_RAW.load(Ordering::Acquire)));
    // Normal flow never resumes H; if it somehow does, fail loudly.
    tb_hal::serial_write_str("M10: FAIL task H resumed after hand-off\n");
    tb_hal::halt()
}

/// Safe trap-dispatch policy hook (kept from M1: policy lives in this
/// `forbid(unsafe_code)`-class crate, not in tb-hal's raw entry asm).
fn trap_hook(info: &TrapInfo) -> TrapAction {
    match info.kind {
        TrapKind::Breakpoint => {
            tb_hal::serial_write_str("trap: breakpoint, resuming\n");
            TrapAction::Resume
        }
        // M10: the armed cross-space page fault. Under the default root the test
        // VA is vacant; reading it faults here. Record it and, as a GUARDED
        // resume, flip the live root to the home space (where the VA IS mapped)
        // so the re-executed access completes instead of livelocking. Disarm
        // first so any later stray fault still takes the fatal path below. Every
        // root shares the kernel half, so this handler's stack/code/serial
        // survive the flip. The compare is page-aligned (low 12 bits masked) so
        // any sub-page-offset probe access still matches the armed page.
        TrapKind::PageFault
            if M10_FAULT_ARMED.load(Ordering::Acquire)
                && (info.fault_addr & !0xFFF)
                    == (M10_FAULT_VA.load(Ordering::Acquire) & !0xFFF) =>
        {
            M10_FAULT_ARMED.store(false, Ordering::Release);
            M10_FAULT_SEEN.store(true, Ordering::Release);
            tb_hal::address_space_switch_root(M10_FAULT_HOME_ROOT.load(Ordering::Acquire));
            TrapAction::Resume
        }
        _ => {
            tb_hal::serial_write_str("trap: fatal fault, halting\n");
            tb_hal::serial_write_str("  cause=");
            write_hex_u64(info.cause);
            tb_hal::serial_write_str(" fault_addr=");
            write_hex_u64(info.fault_addr);
            tb_hal::serial_write_str(" pc=");
            write_hex_u64(info.pc);
            tb_hal::serial_write_byte(b'\n');
            TrapAction::Halt
        }
    }
}

/// Write a `u64` as a fixed-width 16-digit `0x…` hex string over serial.
/// Pure safe Rust (no `core::fmt`, no allocation).
fn write_hex_u64(value: u64) {
    tb_hal::serial_write_str("0x");
    let mut shift: i32 = 60;
    while shift >= 0 {
        let nibble = ((value >> shift) & 0xf) as u8;
        let c = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
        tb_hal::serial_write_byte(c);
        shift -= 4;
    }
}

/// Panic handler: best-effort marker over serial, then halt forever.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    tb_hal::serial_write_str("panic\n");
    tb_hal::halt()
}
