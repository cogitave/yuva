//! aarch64 **aL2.6 "smmu OK"**: the Arm SMMUv3 stage-2 DMA-isolation
//! table-programming primitive -- the IOMMU twin of the L2.1 CPU stage-2
//! demand-translation. The silicon-unsafe SMMUv3 builder + probe/arm/teardown
//! glue behind the SAFE [`smmu_selftest`] facade; ALL `read_volatile`/
//! `write_volatile` to the SMMU MMIO window (`0x0905_0000`, already inside the
//! GiB0 Device-nGnRnE identity gigabyte `mmu_init` mapped), the stream-table /
//! STE / command-queue / event-queue frame builds, the CMD_CFGI_STE + CMD_SYNC
//! push, and the GERROR / event-queue poll live HERE, so the kernel crate stays
//! `#![forbid(unsafe_code)]` and only branches on a [`crate::SmmuProof`] enum.
//!
//! ## What this programs (all at EL1 — NO EL2, NO HVC, NO world-switch)
//!
//! The SMMUv3 is a memory-mapped PLATFORM device, not an EL2 trap surface, so the
//! EL1 kernel programs it directly — structurally the SIMPLEST L2 rung (no guest
//! stub, no monitor entry). It builds a LINEAR 1-entry stream table (one frame;
//! LOG2SIZE=0), ONE stage-2-only Stream Table Entry (`Config==0b110`) whose
//! `S2TTB` == the SAME stage-2 L1 root [`super::stage2::build_identity_stage2`]
//! produced, `S2VMID` == the CPU's VMID ([`super::stage2::s2_vmid`]), and
//! `STE.VTCR` == the projection of the CPU's [`super::stage2::compute_vtcr`] (via
//! the Kani-proven `tb_encode::smmuv3::ste_vtcr_from_vtcr_el2` LEMMA — so the SMMU
//! stage-2 tables ARE the CPU stage-2 tables), and a command queue + an event
//! queue (one frame each).
//!
//! It then programs `STRTAB_BASE`/`_CFG` + `CMDQ_BASE` + `EVENTQ_BASE` + `CR0`
//! (`SMMUEN|CMDQEN|EVTQEN`, `CR0ACK`-confirmed), pushes `CMD_CFGI_STE` +
//! `CMD_TLBI_S12_VMALL` + `CMD_SYNC`, advances `CMDQ_PROD`, and observes
//! `CMDQ_CONS` reach `PROD` (the SYNC drained) under a bounded poll cap with
//! `GERROR`/`GERRORN` clean AND the event queue empty of a `C_BAD_STE` record —
//! i.e. the SMMU ACCEPTED the STE.
//!
//! ## The honest claim (the silicon-gated residual)
//!
//! The marker asserts ONLY "tables programmed + SMMU accepted them". The ACTUAL
//! DMA-isolation GUARANTEE — a rogue physical device BLOCKED from memory outside
//! its grant — needs REAL SILICON (declared in `assumptions.md`, the L2.8/VT-d
//! twin). Under TCG there is no real DMA engine to confine, no bus-mastering
//! races, no IMPLEMENTATION-DEFINED SMMU behavior — so emulation proves the
//! PROGRAMMING is well-formed and ACCEPTED, never that silicon enforces it.
//!
//! ## Teardown-clean (the M19-prints-after-L2.6 discipline)
//!
//! Before returning, `CR0.SMMUEN` is cleared (translation OFF) and the STE's `V`
//! bit is zeroed, so the SMMU is inert for the rest of boot — M19's virtio-mmio
//! path (NOT behind the SMMU) is untouched. The M19 marker printing AFTER L2.6 is
//! the teardown-miss tripwire.
//!
//! ## Stack budget (#65)
//!
//! aL2.6 runs ENTIRELY at EL1 — NO EL2 entry, so the 32 KiB EL2 monitor stack
//! (`e2free`) is NEVER touched. The call chain is `smmu_selftest()` -> a handful
//! of leaf helpers (the volatile MMIO pokes, the pure tb-encode packers); call
//! depth ~2-3, all small frames. The stream-table / command-queue / event-queue
//! are `frame_alloc`'d 4 KiB frames (NOT on-stack arrays); the only on-stack value
//! is the `[u64; 8]` STE (64 B). `bsfree` stays healthy.

use core::arch::asm;
use core::ptr::{read_volatile, write_volatile};

use tb_encode::smmuv3::{
    cmd_cfgi_ste, cmd_sync, cmd_tlbi_s12_vmall, cmdq_base, eventq_base, ste_s2,
    ste_vtcr_from_vtcr_el2, strtab_base, strtab_base_cfg, STRTAB_BASE_CFG_FMT_LINEAR,
};

// ===========================================================================
// QEMU `virt` SMMUv3 MMIO map + register offsets (Arm IHI 0070 §6.3; QEMU
// hw/arm/virt.c base_memmap[VIRT_SMMU]={0x0905_0000, 0x20000}; Linux
// drivers/iommu/arm/arm-smmu-v3/arm-smmu-v3.h offsets).
// ===========================================================================

/// SMMUv3 MMIO base on QEMU `virt` (`base_memmap[VIRT_SMMU]`). Sits INSIDE the
/// GiB0 (`0x0..0x4000_0000`) Device-nGnRnE identity gigabyte `mmu_init` already
/// mapped — NO new EL1 mapping needed (the same reach as the GICH/GICV windows).
const SMMU_BASE: u64 = 0x0905_0000;

// -- page-0 registers (Arm IHI 0070 §6.3) --
const R_IDR0: u64 = 0x000; // S2P=bit0, S1P=bit1, TTF=[3:2], ST_LVL=[28:27]
const R_CR0: u64 = 0x020; // SMMUEN=bit0, EVTQEN=bit2, CMDQEN=bit3
const R_CR0ACK: u64 = 0x024; // CR0 enable acknowledge (mirrors CR0 once latched)
const R_CR1: u64 = 0x028; // queue/table cacheability + shareability
const R_GERROR: u64 = 0x060; // active global errors (CMDQ_ERR etc.)
const R_GERRORN: u64 = 0x064; // GERROR acknowledge (== GERROR == no pending error)
const R_STRTAB_BASE: u64 = 0x080; // ADDR[51:6] | RA(bit62)
const R_STRTAB_BASE_CFG: u64 = 0x088; // FMT[17:16] | LOG2SIZE[5:0]
const R_CMDQ_BASE: u64 = 0x090; // ADDR[51:5] | RA | LOG2SIZE[4:0]
const R_CMDQ_PROD: u64 = 0x098; // producer index (we advance)
const R_CMDQ_CONS: u64 = 0x09C; // consumer index (the SMMU advances; we poll)
const R_EVENTQ_BASE: u64 = 0x0A0; // ADDR[51:5] | WA | LOG2SIZE[4:0]

// -- page-1 (interrupt page, +0x10000) registers --
const R_EVENTQ_PROD: u64 = 0x1_00A8; // event-queue producer (SMMU advances on a fault)
const R_EVENTQ_CONS: u64 = 0x1_00AC; // event-queue consumer (we own; init == PROD)

// -- IDR0 fields --
const IDR0_S2P: u32 = 1 << 0; // stage-2 translation supported

// -- CR0 enable bits --
const CR0_SMMUEN: u32 = 1 << 0; // enable SMMU translation
const CR0_EVTQEN: u32 = 1 << 2; // enable the event queue
const CR0_CMDQEN: u32 = 1 << 3; // enable the command queue

// -- GERROR error bits we surface (any pending => fail) --
/// `GERROR.CMDQ_ERR` (bit0): a command-queue error (e.g. an illegal command or a
/// command targeting an out-of-range StreamID). The no-error proof checks
/// `GERROR == GERRORN` (no UN-acked global error), so any bit suffices.
const GERROR_ANY_MASK: u32 = 0xFF; // the defined GERROR error bits (CMDQ_ERR..MSI*)

// -- event-queue record decode (16 bytes/record; the event TYPE is [7:0] of
//    dword0; Arm IHI 0070 §7.3). C_BAD_STE == 0x04. --
const EVT_TYPE_MASK: u64 = 0xFF;
const EVT_C_BAD_STE: u64 = 0x04;
const EVT_RECORD_BYTES: u64 = 32; // an event record is 32 bytes (4 x u64) in v3

// ===========================================================================
// Queue + table geometry (the aL2.6 self-test sizes; all SMALL, all in
// frame_alloc'd 4 KiB frames).
// ===========================================================================

/// The single StreamID the linear 1-entry stream table programs (BDF 0 — the
/// table has exactly one slot, index 0).
const STREAM_ID: u32 = 0;
/// Command-queue depth: log2 = 4 => 16 entries (16 B each = 256 B, well within a
/// 4 KiB frame). Three commands (CFGI_STE, TLBI, SYNC) fit trivially.
const CMDQ_LOG2: u64 = 4;
/// Event-queue depth: log2 = 4 => 16 records (32 B each = 512 B, within a frame).
const EVTQ_LOG2: u64 = 4;
/// 16-byte command-queue entry stride.
const CMD_ENTRY_BYTES: u64 = 16;
/// The CMDQ_PROD/CONS wrap mask for a 2^CMDQ_LOG2-entry queue (the index field is
/// the low LOG2SIZE bits; bit LOG2SIZE is the wrap toggle).
const CMDQ_INDEX_MASK: u32 = (1u32 << CMDQ_LOG2) - 1;

/// Bounded poll cap for CR0ACK + the CMD_SYNC drain (a dead/absent SMMU bails
/// here instead of hanging — mirrors the M19 `POLL_CAP` / M8 `CANARY_CAP`).
const POLL_CAP: u64 = 2_000_000;

// ===========================================================================
// FAIL codes (distinct nonzero; any -> `SmmuProof::Faulted` -> red marker with
// NO "smmu OK" substring). Surfaced as `L2.6: smmu FAIL code=<hex>` by the kernel.
// ===========================================================================

/// A physical-frame allocation failed (stream table / command / event queue OOM).
const FAIL_SMMU_ALLOC: u64 = 0x01;
/// The CPU stage-2 root build (`build_identity_stage2`) returned OOM.
const FAIL_SMMU_S2ROOT: u64 = 0x02;
/// `CR0ACK` never reflected the requested enable bits before the poll cap.
const FAIL_SMMU_ENABLE: u64 = 0x03;
/// The `CMD_SYNC` never drained (`CMDQ_CONS` never reached `PROD`) before the cap.
const FAIL_SMMU_SYNC: u64 = 0x04;
/// A global error was pending after the SYNC (`GERROR != GERRORN`).
const FAIL_SMMU_GERROR: u64 = 0x05;
/// A `C_BAD_STE` event was recorded in the event queue (the STE was malformed).
const FAIL_SMMU_BAD_STE: u64 = 0x06;

// ===========================================================================
// MMIO + DMA-RAM accessors (all the aL2.6 unsafe).
// ===========================================================================

/// Read a 32-bit SMMU register at `SMMU_BASE + off`.
#[inline]
fn reg_read32(off: u64) -> u32 {
    // SAFETY: `SMMU_BASE + off` is inside the GiB0 Device-nGnRnE identity
    // gigabyte `mmu_init` mapped, and `off` is a verified 4-byte-aligned register
    // offset within the 0x20000 SMMU window, so the pointer is valid + aligned.
    // Volatile: an MMIO load.
    unsafe { read_volatile((SMMU_BASE + off) as *const u32) }
}

/// Write a 32-bit SMMU register at `SMMU_BASE + off`.
#[inline]
fn reg_write32(off: u64, v: u32) {
    // SAFETY: as `reg_read32`; a Device-nGnRnE MMIO store to a verified offset.
    unsafe { write_volatile((SMMU_BASE + off) as *mut u32, v) }
}

/// Write a 64-bit SMMU register (the *_BASE registers are 64-bit) at `SMMU_BASE +
/// off`.
#[inline]
fn reg_write64(off: u64, v: u64) {
    // SAFETY: as `reg_read32`; the *_BASE registers are 8-byte-aligned 64-bit
    // registers in the SMMU window. A Device-nGnRnE MMIO store.
    unsafe { write_volatile((SMMU_BASE + off) as *mut u64, v) }
}

/// Store one 64-bit dword at an identity-mapped RAM PA (a frame we own). Used to
/// write the STE dwords + the command-queue entries through their identity alias
/// (the frames sit in the identity-mapped RAM gigabyte, PA == VA).
#[inline]
fn ram_w64(pa: u64, v: u64) {
    // SAFETY: `pa` is an 8-byte-aligned offset within one of our just-allocated,
    // identity-mapped 4 KiB frames; a single aligned volatile store stays in the
    // frame. The SMMU DMA-reads these frames, so volatile (publish ordering is
    // supplied by the explicit `dsb` at the call sites).
    unsafe { write_volatile(pa as *mut u64, v) }
}

/// Load one 64-bit dword from an identity-mapped RAM PA (an event-queue record).
#[inline]
fn ram_r64(pa: u64) -> u64 {
    // SAFETY: as `ram_w64`; the SMMU writes event records here, so volatile.
    unsafe { read_volatile(pa as *const u64) }
}

// ===========================================================================
// Barriers. The SMMU is an inner-shareable DMA agent; the table/queue stores
// must be visible to it before the enable / PROD-advance. `dsb ish` is the
// completion barrier (mirrors stage2.rs's publish dance).
// ===========================================================================

/// `dsb ishst` — order prior table/queue STORES before the publish (the CR0
/// enable / the CMDQ_PROD advance the SMMU then reads).
#[inline]
fn dsb_ishst() {
    // SAFETY: an inner-shareable store-store completion barrier; no memory/stack
    // effect, NZCV preserved. Orders our STE/command stores before the publish.
    unsafe { asm!("dsb ishst", options(nostack, preserves_flags)) }
}

/// `dsb ish` — full inner-shareable completion barrier (every prior access
/// complete to the point of coherency the SMMU DMAs from).
#[inline]
fn dsb_ish() {
    // SAFETY: as `dsb_ishst`; a full completion barrier before/after the kick.
    unsafe { asm!("dsb ish", options(nostack, preserves_flags)) }
}

// ===========================================================================
// The public self-test: tb_hal::smmu_selftest() -> SmmuProof (arch arm).
// ===========================================================================

/// Run the aL2.6 SMMUv3 stage-2 table-programming round-trip and report the
/// outcome.
///
/// `Unavailable` (no SMMU / `IDR0.S2P==0`) is a GRACEFUL green skip;
/// `Proven{stream_id}` is "the SMMU ACCEPTED a well-formed stage-2-only STE
/// pointing at the SAME stage-2 root the CPU uses (CMD_SYNC drained, GERROR clean,
/// no C_BAD_STE)"; `Faulted{code}` is fail-closed red. The SMMU is left DISABLED
/// (teardown-clean) before returning so M19 (not behind the SMMU) is untouched.
pub fn smmu_selftest() -> crate::SmmuProof {
    use crate::SmmuProof;

    // 1. PROBE / SKIP (the IDR0.S2P gate — the IOMMU analog of BOOTED_AT_EL2).
    //    A read of the SMMU IDR0 returns open-bus 0xFFFF_FFFF when no SMMU device
    //    is present (booted WITHOUT iommu=smmuv3) — the window is reserved in the
    //    virt memmap, so the read returns open-bus, not an abort. Treat BOTH
    //    open-bus AND S2P==0 (e.g. a pre-8.1 QEMU with no stage-2 SMMUv3) as a
    //    GREEN skip, never a fault, so non-SMMU lanes stay green.
    let idr0 = reg_read32(R_IDR0);
    if idr0 == 0xFFFF_FFFF || (idr0 & IDR0_S2P) == 0 {
        // Open-bus (no SMMU device — booted without iommu=smmuv3) OR an SMMU that
        // does NOT advertise stage-2 (IDR0.S2P==0). The latter is the case for
        // QEMU < 9.0 (stage-2 SMMUv3 support — the Mostafa series — landed in QEMU
        // 9.0, NOT 8.1: QEMU 8.2.2 advertises S1P=1 but S2P=0). Either way it is a
        // GREEN skip, never a fault — we must not write a stage-2 STE an S1-only
        // SMMU would reject. The IDR0.S2P gate, the IOMMU analog of BOOTED_AT_EL2.
        return SmmuProof::Unavailable;
    }

    // 2. ALLOCATE (all via the shared zeroed-frame allocator — 4 KiB frames in the
    //    identity-mapped RAM gigabyte, PA == VA). One frame each for the 1-entry
    //    stream table (64 B used), the command queue (256 B used), the event queue
    //    (512 B used).
    let strtab_pa = match super::stage2::prep_zeroed_frame() {
        Some(f) => f,
        None => return SmmuProof::Faulted { code: FAIL_SMMU_ALLOC },
    };
    let cmdq_pa = match super::stage2::prep_zeroed_frame() {
        Some(f) => f,
        None => return SmmuProof::Faulted { code: FAIL_SMMU_ALLOC },
    };
    let evtq_pa = match super::stage2::prep_zeroed_frame() {
        Some(f) => f,
        None => return SmmuProof::Faulted { code: FAIL_SMMU_ALLOC },
    };

    // 3. BUILD THE STAGE-2 ROOT (the SAME L1 root the CPU stage-2 uses). Compute
    //    the STE.VTCR via the Kani-proven projection of the CPU's compute_vtcr(),
    //    the S2TTB from that root, and the S2VMID == the CPU VMID — so the SMMU
    //    stage-2 config IS the CPU stage-2 config.
    let s2_root = match super::stage2::build_identity_stage2() {
        Some(r) => r,
        None => return SmmuProof::Faulted { code: FAIL_SMMU_S2ROOT },
    };
    let ste_vtcr = ste_vtcr_from_vtcr_el2(super::stage2::compute_vtcr());
    let vmid = super::stage2::s2_vmid();

    // 4. WRITE THE STE: pack the 8 stage-2-only STE dwords (Config==0b110) and
    //    volatile-store them into the linear stream table's entry 0. `dsb ishst`
    //    publishes them to the SMMU's STE walker.
    let ste = ste_s2(s2_root, vmid, ste_vtcr);
    let mut i = 0usize;
    while i < 8 {
        ram_w64(strtab_pa + (i as u64) * 8, ste[i]);
        i += 1;
    }
    dsb_ishst();

    // 5. PROGRAM REGISTERS: STRTAB_BASE/_CFG (linear, LOG2SIZE=0 => 1 entry),
    //    CMDQ_BASE, EVENTQ_BASE, CR1 (default cacheability), then clear any stale
    //    GERROR by acking it (GERRORN := GERROR), then enable CR0
    //    (SMMUEN|CMDQEN|EVTQEN) and poll CR0ACK.
    reg_write64(R_STRTAB_BASE, strtab_base(strtab_pa));
    reg_write32(
        R_STRTAB_BASE_CFG,
        strtab_base_cfg(0, STRTAB_BASE_CFG_FMT_LINEAR) as u32,
    );
    reg_write64(R_CMDQ_BASE, cmdq_base(cmdq_pa, CMDQ_LOG2));
    reg_write64(R_EVENTQ_BASE, eventq_base(evtq_pa, EVTQ_LOG2));
    // Init the producer/consumer indices to empty (PROD == CONS).
    reg_write32(R_CMDQ_PROD, 0);
    reg_write32(R_CMDQ_CONS, 0);
    reg_write32(R_EVENTQ_PROD, 0);
    reg_write32(R_EVENTQ_CONS, 0);
    // CR1: leave at the reset/default (inner-shareable, WB cacheable queues is the
    // QEMU-accepted default; a non-zero programming is silicon-tuning we skip).
    reg_write32(R_CR1, 0);
    // Ack any stale global error so the post-SYNC GERROR==GERRORN check is clean.
    reg_write32(R_GERRORN, reg_read32(R_GERROR));
    dsb_ish();

    // Enable the queues FIRST (CMDQEN|EVTQEN), then SMMUEN. Some implementations
    // want the queues enabled before SMMUEN; QEMU accepts a single combined write,
    // so write them together and poll CR0ACK.
    let cr0 = CR0_SMMUEN | CR0_CMDQEN | CR0_EVTQEN;
    reg_write32(R_CR0, cr0);
    let mut spins = 0u64;
    while (reg_read32(R_CR0ACK) & cr0) != cr0 {
        spins += 1;
        if spins >= POLL_CAP {
            smmu_disable();
            return SmmuProof::Faulted { code: FAIL_SMMU_ENABLE };
        }
        core::hint::spin_loop();
    }

    // 6. INVALIDATE + SYNC: push CMD_CFGI_STE(sid) (force a re-fetch of the STE we
    //    just wrote), CMD_TLBI_S12_VMALL(vmid) (parity flush), CMD_SYNC (drain).
    //    Advance CMDQ_PROD, `dsb ish`, then poll CMDQ_CONS until it == PROD.
    let cmds: [[u64; 2]; 3] = [
        cmd_cfgi_ste(STREAM_ID),
        cmd_tlbi_s12_vmall(vmid as u16),
        cmd_sync(),
    ];
    let mut slot = 0usize;
    while slot < cmds.len() {
        let entry_pa = cmdq_pa + (slot as u64) * CMD_ENTRY_BYTES;
        ram_w64(entry_pa, cmds[slot][0]);
        ram_w64(entry_pa + 8, cmds[slot][1]);
        slot += 1;
    }
    dsb_ishst();
    // Advance the producer to 3 (we wrote slots 0..3); the index field is the low
    // LOG2SIZE bits, the wrap bit is bit LOG2SIZE. 3 < 16, so no wrap.
    let prod = (cmds.len() as u32) & CMDQ_INDEX_MASK;
    reg_write32(R_CMDQ_PROD, prod);
    dsb_ish();

    // Poll CMDQ_CONS until the consumer catches the producer (the SYNC drained).
    let mut spins = 0u64;
    loop {
        let cons = reg_read32(R_CMDQ_CONS) & CMDQ_INDEX_MASK;
        if cons == prod {
            break;
        }
        spins += 1;
        if spins >= POLL_CAP {
            smmu_disable();
            return SmmuProof::Faulted { code: FAIL_SMMU_SYNC };
        }
        core::hint::spin_loop();
    }
    dsb_ish();

    // 7. CHECK CLEAN: GERROR must equal GERRORN (no pending UN-acked global error),
    //    and the event queue must hold NO C_BAD_STE record (PROD == CONS => empty,
    //    else scan for the bad-STE type). Any error => fail-closed.
    let gerror = reg_read32(R_GERROR);
    let gerrorn = reg_read32(R_GERRORN);
    if (gerror & GERROR_ANY_MASK) != (gerrorn & GERROR_ANY_MASK) {
        smmu_disable();
        return SmmuProof::Faulted { code: FAIL_SMMU_GERROR };
    }
    if event_queue_has_bad_ste(evtq_pa) {
        smmu_disable();
        return SmmuProof::Faulted { code: FAIL_SMMU_BAD_STE };
    }

    // 8. TEARDOWN-CLEAN (before M19): disable translation + invalidate the STE V
    //    bit so the SMMU is inert for the rest of boot (M19's virtio-mmio path is
    //    NOT behind the SMMU, but leave nothing armed).
    // Zero the STE V bit (dword0 -> 0) and publish, then disable CR0.
    ram_w64(strtab_pa, 0);
    dsb_ishst();
    smmu_disable();

    SmmuProof::Proven {
        stream_id: STREAM_ID,
    }
}

/// Scan the event queue for a `C_BAD_STE` record. `PROD == CONS` => empty (no
/// fault); otherwise walk the produced records and check each record's event TYPE
/// (`dword0[7:0]`). Returns `true` iff a `C_BAD_STE` (the malformed-STE event) is
/// found — the no-silent-pass guard (a CMD_SYNC alone could drain while the STE
/// was rejected with an event).
fn event_queue_has_bad_ste(evtq_pa: u64) -> bool {
    let prod = reg_read32(R_EVENTQ_PROD) & ((1u32 << EVTQ_LOG2) - 1);
    let cons = reg_read32(R_EVENTQ_CONS) & ((1u32 << EVTQ_LOG2) - 1);
    if prod == cons {
        return false; // empty event queue — no fault recorded
    }
    // Walk the produced records (bounded by the queue depth) and check the type.
    let mut idx = cons;
    let depth = 1u32 << EVTQ_LOG2;
    let mut scanned = 0u32;
    while idx != prod && scanned < depth {
        let rec_pa = evtq_pa + (idx as u64) * EVT_RECORD_BYTES;
        let dword0 = ram_r64(rec_pa);
        if (dword0 & EVT_TYPE_MASK) == EVT_C_BAD_STE {
            return true;
        }
        idx = (idx + 1) & ((1u32 << EVTQ_LOG2) - 1);
        scanned += 1;
    }
    false
}

/// Teardown: clear `CR0` (SMMUEN|CMDQEN|EVTQEN all off) so the SMMU stops
/// translating, publish. Idempotent; called on every exit path (success + each
/// fault) so the SMMU is never left armed when control returns to the boot chain.
fn smmu_disable() {
    reg_write32(R_CR0, 0);
    dsb_ish();
}
