//! aL2.4b "el1-kernel-guest" rung — the LITERAL full M0..M31 kernel booted as
//! a stage-2-CONFINED EL1 guest under the resident nVHE EL2 monitor (the M34
//! champion/challenger prerequisite). A CHILD of `el2` (the `l24_nested.rs`
//! pattern), so it sees the monitor privates (`Frame`, `el2_abort_retry`,
//! `el2_return_to_kernel`, `BOOTED_AT_EL2`, `SPSR_EL1H_DAIF`) via `super::*`.
//!
//! ## The shape (proposal aL2.4b §2; survey §3-§5)
//!
//!  * **Launch (`HVC #16`)**: the EL1 facade builds the FIRST non-identity
//!    stage-2 (guest IPA `0x4000_0000+off` → carve PA — `stage2.rs::
//!    build_guest_stage2`, the Kani-proven carve leaf per block), writes the
//!    frozen `tb_boot::aarch64::build_handoff` block over the carve with the
//!    IN-GUEST flag + the `tb.nonce=`/`tb.probe=` cmdline, and HVCs. The
//!    monitor stashes the launch context (nonce, probe IPA, saved SP_EL1),
//!    arms `VTCR/VTTBR(VMID 2)` + `HCR_EL2 = RW|VM|TWI`, and `eret`s into
//!    `_tb_start` with `X0 = TbBootInfo*`, `X1..X3 = 0`, `SPSR = 0x3C5` — the
//!    splice contract frozen by the host test
//!    `handoff_is_the_block_the_el2_monitor_splices_for_al2_4`.
//!  * **While the guest runs** the host kernel is parked inside the HVC (its
//!    B0 frame resident). Guest stage-2 aborts route here:
//!      - PL011 page → trap-and-emulate (`DR` write → the `guestlog:`
//!        hex-frame emitter; `FR` read → TXFE|RXFE; rest RAZ/WI),
//!      - the rest of the PL011 2 MiB block (incl. the SMMU regs) + the
//!        virtio-mmio block → open-bus RAZ/WI (`IDR0`/`MagicValue` read 0 →
//!        the guest's L2.6/M19/M20/M30/M31 green skips),
//!      - the doorbell IPA → the monitor-counted progress cell (count + last
//!        stored value = the nonce echo),
//!      - the host-RAM probe IPA → counted, the store DROPPED (adversarial
//!        DoD case (a): witnessed fault, never lands),
//!      - anything else → fail-closed teardown + a named red. ISV=0 on an
//!        emulated IPA renders the named `el2: nisv-abort ipa=` red (Yuva has
//!        no instruction decoder — survey §6). A hard trap-count cap turns a
//!        runaway guest into the fast named `storm` red, never a silent
//!        wall-clock timeout.
//!  * **Completion (`HVC #17` + the final WFI)**: status 0 marks done (only
//!    reachable from the guest's single armed clean-exit site); the guest
//!    then parks in `wfi`, which traps under TWI — the monitor verifies the
//!    doorbell count/nonce-echo gates, tears the stage-2 down
//!    (teardown-FIRST), restores the host's SP_EL1, and unwinds to the host
//!    with the packed witness. A WFI trap BEFORE done = the guest died →
//!    the fast `early-park` red. A nonzero `HVC #17` status = the guest's
//!    own fail path → the fast `guest-reported` red.
//!
//! Marker custody (§2.7): the host emits `L2.4b: el1-kernel-guest OK` from
//! THIS monitor-witnessed evidence only; the guest's framed text is checked
//! by the run-script GUEST profile as corroboration (pre-M34 it is our
//! trusted image; at the M34 boundary the same bytes drop to zero weight —
//! same plumbing).

#![allow(unused_imports)]
use super::*;

use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::AtomicU64;

use tb_encode::el2_trap::{esr_ec, EC_IABT_LOW};
use tb_encode::guestlog::{guestlog_encode, GUESTLOG_MAX_FRAME, GUESTLOG_MAX_PAYLOAD};
use tb_encode::stage2::{
    GUEST_CARVE_PA, GUEST_CARVE_SIZE, GUEST_DOORBELL_IPA, GUEST_IMAGE_OFF, GUEST_IPA_BASE,
};

// ===========================================================================
// HCR bits + the trapped device windows (locked).
// ===========================================================================

/// `HCR_EL2.RW` (bit31): EL1 is AArch64 — the boot baseline (disarm restores it).
const KG_HCR_RW: u64 = 1 << 31;
/// `HCR_EL2.VM` (bit0): stage-2 ON — the spatial confinement.
const KG_HCR_VM: u64 = 1 << 0;
/// `HCR_EL2.TWI` (bit13): trap guest WFI to EL2 — the final-park witness
/// (armed for the WHOLE guest run: the healthy chain executes NO wfi before
/// its final park, so an early WFI trap is the fast `early-park` red).
const KG_HCR_TWI: u64 = 1 << 13;

const _: () = assert!(KG_HCR_TWI == 0x2000); // Arm ARM HCR_EL2.TWI bit[13]

/// The PL011 2 MiB device block (UART @ 0x0900_0000 + RTC/fw-cfg/GPIO/SMMU
/// regs — ALL trapped: emulated or RAZ/WI).
const PL011_BLOCK_BASE: u64 = 0x0900_0000;
/// The PL011 register page itself (the only emulated-with-behaviour page).
const PL011_PAGE: u64 = 0x0900_0000;
/// PL011 `UARTDR` offset (write = the guest's serial byte).
const PL011_DR: u64 = 0x000;
/// PL011 `UARTFR` offset (read = TX/RX status).
const PL011_FR: u64 = 0x018;
/// Emulated `UARTFR` idle value: `TXFE (1<<7) | RXFE (1<<4)` — TX empty, RX
/// empty, BUSY clear, TXFF clear: the guest's polls always proceed.
const PL011_FR_IDLE: u64 = 0x90;
/// The virtio-mmio 2 MiB block (0x0A00_0000): open-bus RAZ/WI (never
/// identity-map a live host DMA device into a confined guest — survey §4).
const VIRTIO_BLOCK_BASE: u64 = 0x0A00_0000;
/// 2 MiB block size/mask.
const BLOCK_2M: u64 = 0x20_0000;

/// Hard trap-count cap: a runaway guest (a UART/doorbell storm, an abort
/// loop) becomes the fast named `storm` red instead of a silent wall-clock
/// timeout. The healthy full chain measures ~10^5 traps (2 per serial byte);
/// 2M gives ~20x headroom while still ending a storm in seconds under TCG.
const KG_TRAP_CAP: u64 = 2_000_000;

/// Doorbell threshold: the guest stores the nonce 4 times; require >= 3.
const KG_DOORBELL_MIN: u64 = 3;

// aL2.4b FAIL codes (distinct nonzero; family 0x0B24 — "B24" for aL2.4b).
/// Stage-2 build OOM / handoff write failure (facade-side).
pub(crate) const FAIL_KG_BUILD: u64 = 0x0000_0B24_0000_0001;
/// The guest reported a chain failure through `HVC #17` (status != 0).
pub const FAIL_KG_GUEST_REPORTED: u64 = 0x0000_0B24_0000_0002;
/// The guest parked in WFI BEFORE signalling done (it died mid-chain).
pub const FAIL_KG_EARLY_PARK: u64 = 0x0000_0B24_0000_0003;
/// The trap-count hard cap tripped (the `HANG class=storm` red).
pub const FAIL_KG_STORM: u64 = 0x0000_0B24_0000_0004;
/// A stage-2 abort at an IPA outside EVERY emulated window (a host-RAM or
/// unknown-device touch — the confinement fail-closed default).
pub const FAIL_KG_UNEXPECTED_IPA: u64 = 0x0000_0B24_0000_0005;
/// An ISV=0 (undecodable) abort on an emulated IPA (`el2: nisv-abort`).
pub const FAIL_KG_NISV: u64 = 0x0000_0B24_0000_0006;
/// An instruction abort from the guest (fetch from an unmapped IPA).
pub(crate) const FAIL_KG_IABT: u64 = 0x0000_0B24_0000_0007;
/// Completion gates failed: doorbell below threshold or nonce-echo mismatch.
pub(crate) const FAIL_KG_DOORBELL: u64 = 0x0000_0B24_0000_0008;
/// `build_handoff_flagged` refused (facade-side; structurally unreachable).
pub(crate) const FAIL_KG_HANDOFF: u64 = 0x0000_0B24_0000_0009;
/// The confinement probe did not fire exactly once (facade post-flight).
pub(crate) const FAIL_KG_PROBE_MISS: u64 = 0x0000_0B24_0000_000A;
/// The probe SENTINEL changed — a guest store LANDED in host RAM (the
/// confinement breach; facade post-flight).
pub(crate) const FAIL_KG_SENTINEL: u64 = 0x0000_0B24_0000_000B;
/// The in-guest discriminator readback was wrong (`BOOT_ENTRY_EL != 0xFF` or
/// `BOOTED_AT_EL2 != 0` in guest memory; facade post-flight).
pub(crate) const FAIL_KG_DISCRIMINATOR: u64 = 0x0000_0B24_0000_000C;
/// A stage-2 fault on the guest's OWN stage-1 walk (S1PTW) — its table
/// frames left the carve (structurally impossible; fail-closed).
pub(crate) const FAIL_KG_S1PTW: u64 = 0x0000_0B24_0000_000D;

// ===========================================================================
// The EL2 launch-context cell (single-accessor; EL1 NEVER references it).
// `align(64)`: no EL1-written .bss shares the line (the S2_CTX pattern).
// [0]=armed [1]=done [2]=nonce [3]=probe_ipa [4]=doorbell_count
// [5]=doorbell_last [6]=echo_nonce(HVC#17 x1) [7]=probe_count [8]=trap_count
// [9]=saved SP_EL1 [10]=last fault IPA [11]=last ESR
// ===========================================================================

#[repr(C, align(64))]
struct KgCtx(UnsafeCell<[u64; 12]>);

// SAFETY: single vCPU; the cells are touched ONLY from EL2 (the launch /
// abort / done / wfx handlers), never concurrently and never by EL1. No Rust
// reference to the interior is ever minted; access is volatile raw-pointer
// only — the `S2_CTX` discipline.
unsafe impl Sync for KgCtx {}

static KG_CTX: KgCtx = KgCtx(UnsafeCell::new([0; 12]));

fn kg_ptr() -> *mut u64 {
    KG_CTX.0.get() as *mut u64
}

fn kg_get(i: usize) -> u64 {
    debug_assert!(i < 12);
    // SAFETY: single-accessor EL2 cell block; aligned volatile load, i < 12.
    unsafe { read_volatile(kg_ptr().add(i)) }
}

fn kg_set(i: usize, v: u64) {
    debug_assert!(i < 12);
    // SAFETY: as `kg_get`; aligned volatile store.
    unsafe { write_volatile(kg_ptr().add(i), v) }
}

/// EL2 + the dispatch: is the kernel-guest window armed?
pub(super) fn armed() -> bool {
    kg_get(0) != 0
}

// ===========================================================================
// The guestlog emitter: a 64-byte single-accessor EL2 line buffer, flushed
// through the Kani-proven `tb_encode::guestlog` codec onto the REAL PL011.
// ===========================================================================

#[repr(C, align(64))]
struct KgLogBuf(UnsafeCell<([u8; GUESTLOG_MAX_PAYLOAD], usize)>);

// SAFETY: single vCPU, EL2-only accessor (the PL011 emulate path + the
// completion flush); no interior reference escapes — volatile-style access
// through the raw pointer only.
unsafe impl Sync for KgLogBuf {}

static KG_LOG: KgLogBuf = KgLogBuf(UnsafeCell::new(([0; GUESTLOG_MAX_PAYLOAD], 0)));

/// EL2: reset the guestlog buffer (launch time).
fn kg_log_reset() {
    // SAFETY: single-accessor EL2 cell; we only zero the length field.
    unsafe { (*KG_LOG.0.get()).1 = 0 }
}

/// EL2: flush the buffered guest bytes as ONE `guestlog:` hex frame onto the
/// real PL011 (the host console). No-op when empty.
fn kg_log_flush() {
    // SAFETY: single-accessor EL2 cell.
    let (buf, len) = unsafe {
        let cell = &mut *KG_LOG.0.get();
        let l = cell.1;
        (cell.0, l)
    };
    if len == 0 {
        return;
    }
    let mut out = [0u8; GUESTLOG_MAX_FRAME];
    let n = guestlog_encode(&buf[..len], &mut out);
    let mut i = 0usize;
    while i < n {
        crate::serial_write_byte(out[i]);
        i += 1;
    }
    // SAFETY: as above; reset the length.
    unsafe { (*KG_LOG.0.get()).1 = 0 }
}

/// EL2: append one guest serial byte; flush on `\n` (line-framed) or when the
/// payload cap is reached (long lines split across frames — the decoder
/// concatenates payloads, so the byte stream is preserved exactly).
fn kg_log_push(b: u8) {
    // Defensive: never index at/past the cap (an EL2 panic would be fatal);
    // the flush resets the length, so this is belt-and-suspenders only.
    // SAFETY: single-accessor EL2 cell; read of the current length.
    if unsafe { (*KG_LOG.0.get()).1 } >= GUESTLOG_MAX_PAYLOAD {
        kg_log_flush();
    }
    // SAFETY: single-accessor EL2 cell; the index is < GUESTLOG_MAX_PAYLOAD.
    unsafe {
        let cell = &mut *KG_LOG.0.get();
        cell.0[cell.1] = b;
        cell.1 += 1;
    }
    // SAFETY: read of the just-written length (same single accessor).
    let len = unsafe { (*KG_LOG.0.get()).1 };
    if b == b'\n' || len >= GUESTLOG_MAX_PAYLOAD {
        kg_log_flush();
    }
}

// ===========================================================================
// EL2 sysreg helpers for the launch/teardown (SP_EL1 custody + arming).
// ===========================================================================

/// EL2: read the (host's) `SP_EL1` — saved at launch, restored at teardown
/// (the guest re-points SP_EL1 at its OWN boot stack; the host's stack
/// pointer would otherwise be lost across the unwind).
fn read_sp_el1() -> u64 {
    let v: u64;
    // SAFETY: SP_EL1 is EL2-accessible via MRS; side-effect-free.
    unsafe {
        asm!("mrs {v}, sp_el1", v = out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// EL2: restore the host's `SP_EL1` before unwinding (MANDATORY: the eret
/// lands in host EL1h code that immediately uses the stack).
fn write_sp_el1(v: u64) {
    // SAFETY: SP_EL1 is EL2-writable via MSR; the value is the host's own
    // saved stack pointer; `isb` synchronizes before the eret.
    unsafe {
        asm!("msr sp_el1, {v}", "isb", v = in(reg) v, options(nomem, nostack, preserves_flags));
    }
}

/// EL2: arm the kernel-guest window — program the stage-2 geometry + root,
/// then `HCR_EL2 = RW | VM | TWI`, then flush stale translations for the
/// guest VMID. The `arm_trap_el2` shape with TWI instead of TVM.
fn kg_arm_el2(vtcr_val: u64, vttbr_val: u64) {
    // SAFETY: EL2. Program the stage-2 geometry + root, `isb`, then HCR
    // (RW|VM|TWI), `isb` — the regime + the WFI trap are in place before the
    // eret. Not `nomem` (it reconfigures translation + trapping).
    unsafe {
        asm!(
            "msr vtcr_el2,  {vtcr}",
            "msr vttbr_el2, {vttbr}",
            "isb",
            "msr hcr_el2,   {hcr}",
            "isb",
            vtcr  = in(reg) vtcr_val,
            vttbr = in(reg) vttbr_val,
            hcr   = in(reg) KG_HCR_RW | KG_HCR_VM | KG_HCR_TWI,
            options(nostack, preserves_flags),
        );
    }
    super::stage2::tlbi_vmalls12e1is();
    super::stage2::dsb_ish_pub();
    super::stage2::isb_pub();
}

/// EL2: tear the window DOWN (teardown-FIRST, the L2.1 discipline): restore
/// `HCR_EL2 = RW` (VM + TWI off), drop the root, flush, restore the host's
/// SP_EL1, flush any buffered guestlog remainder, and disarm.
fn kg_teardown_el2() {
    // SAFETY: EL2. Restore the boot baseline (RW only), drop the stage-2
    // root, `isb` so the next EL1 access (the host kernel) is stage-1-only +
    // untrapped. Not `nomem`.
    unsafe {
        asm!(
            "msr hcr_el2,   {hcr}",
            "msr vttbr_el2, xzr",
            "isb",
            hcr = in(reg) KG_HCR_RW,
            options(nostack, preserves_flags),
        );
    }
    super::stage2::tlbi_vmalls12e1is();
    super::stage2::dsb_ish_pub();
    super::stage2::isb_pub();
    kg_log_flush();
    write_sp_el1(kg_get(9));
    kg_set(0, 0); // disarm
}

// ===========================================================================
// The HVC #16 launch handler — stash context, arm, eret into _tb_start.
// ===========================================================================

/// EL2 (`HVC #16`): launch the full-kernel guest. Context rides the frame:
/// x0 = VTCR, x1 = VTTBR (carve root + VMID 2), x2 = the guest entry IPA
/// (= `_tb_start`'s link address), x3 = the `TbBootInfo` IPA, x4 = the
/// per-boot nonce, x5 = the host-RAM probe IPA. Never returns: control
/// leaves EL2 for the guest and re-enters only via its stage-2 aborts, its
/// `HVC #17`, or its trapped WFI.
pub(super) fn kguest_launch(frame: *mut Frame) -> ! {
    // SAFETY: `frame` == &B0 on the single-accessor monitor stack; gpr[0..6]
    // were framed by SAVE_CONTEXT_EL2 and carry the HVC #16 args.
    let (vtcr_v, vttbr_v, entry, boot_info, nonce, probe) = unsafe {
        (
            (*frame).gpr[0],
            (*frame).gpr[1],
            (*frame).gpr[2],
            (*frame).gpr[3],
            (*frame).gpr[4],
            (*frame).gpr[5],
        )
    };
    // Stash the launch context + zero every counter (a clean slate).
    kg_set(1, 0); // done
    kg_set(2, nonce);
    kg_set(3, probe);
    kg_set(4, 0); // doorbell count
    kg_set(5, 0); // doorbell last
    kg_set(6, 0); // echo nonce
    kg_set(7, 0); // probe count
    kg_set(8, 0); // trap count
    kg_set(9, read_sp_el1()); // the host's SP_EL1 (restored at teardown)
    kg_set(10, 0);
    kg_set(11, 0);
    kg_log_reset();
    kg_set(0, 1); // armed (LAST: the abort path keys on it)

    kg_arm_el2(vtcr_v, vttbr_v);

    // SAFETY: reset SP_EL2 = &B0 (the resident host frame — every guest trap
    // stacks below it), program ELR_EL2 = `_tb_start`'s IPA + SPSR_EL2 =
    // 0x3C5 (EL1h, DAIF masked — the frozen splice contract), place the
    // TbBootInfo IPA in the guest's x0 with x1..x3 = 0, `eret`. `noreturn`.
    unsafe {
        asm!(
            "mov sp, {b0}",
            "msr elr_el2,  {entry}",
            "msr spsr_el2, {spsr}",
            "isb",
            "eret",
            b0    = in(reg) frame,
            entry = in(reg) entry,
            spsr  = in(reg) SPSR_EL1H_DAIF,
            in("x0") boot_info,
            in("x1") 0u64,
            in("x2") 0u64,
            in("x3") 0u64,
            options(noreturn),
        );
    }
}

// ===========================================================================
// The HVC #17 done handler — the guest's completion/fail-fast hypercall.
// ===========================================================================

/// EL2 (`HVC #17`): the guest's done hypercall. x0 = status (0 = the single
/// armed clean-exit site was reached — the chain completed; nonzero = the
/// guest's fail path), x1 = the nonce echo. On 0: record + resume (the
/// guest's next `wfi` is the completion witness). On nonzero: teardown +
/// the fast `guest-reported` red. Never returns.
pub(super) fn kguest_done(frame: *mut Frame) -> ! {
    // SAFETY: `frame` is the HVC #17 frame on the monitor stack; gpr[0]/[1]
    // were framed by SAVE_CONTEXT_EL2.
    let (status, echo) = unsafe { ((*frame).gpr[0], (*frame).gpr[1]) };
    if status != 0 {
        kg_teardown_el2();
        el2_return_to_kernel(FAIL_KG_GUEST_REPORTED, status);
    }
    kg_set(6, echo);
    kg_set(1, 1); // done — the next trapped WFI completes
    el2_abort_retry(frame); // resume the guest past the hvc
}

// ===========================================================================
// The trapped-WFI handler — the final-park completion witness.
// ===========================================================================

/// EL2 (Wfx, kernel-guest window armed): the guest executed `wfi`. After
/// done: verify the doorbell gates, tear down, unwind to the host with the
/// packed witness (x1 = doorbell[15:0] | probe[23:16] | traps[63:32]).
/// Before done: the guest died mid-chain (its halt()/fatal-trap park) — the
/// fast `early-park` red. Never returns.
pub(super) fn kguest_wfx(frame: *mut Frame, esr: u64) -> ! {
    let _ = frame;
    if kg_get(1) == 0 {
        kg_teardown_el2();
        el2_return_to_kernel(FAIL_KG_EARLY_PARK, esr);
    }
    // The monitor-witnessed completion gates (non-text evidence): the
    // doorbell store-count above threshold AND both echo channels carrying
    // the per-boot nonce.
    let nonce = kg_get(2);
    let (db_count, db_last, echo) = (kg_get(4), kg_get(5), kg_get(6));
    if db_count < KG_DOORBELL_MIN || db_last != nonce || echo != nonce {
        kg_teardown_el2();
        el2_return_to_kernel(FAIL_KG_DOORBELL, db_count);
    }
    let probe = kg_get(7);
    let traps = kg_get(8);
    kg_teardown_el2();
    let packed = (db_count & 0xFFFF) | ((probe & 0xFF) << 16) | ((traps & 0xFFFF_FFFF) << 32);
    el2_return_to_kernel(0, packed);
}

// ===========================================================================
// The stage-2 abort handler — the guest's trapped device/doorbell/probe I/O.
// ===========================================================================

/// EL2 (StageTwoAbort, kernel-guest window armed): decode + emulate one
/// guest stage-2 abort. Never returns: resumes the guest past the access
/// (ELR+4) or tears down + unwinds on a fail. See the module doc for the
/// per-window verdicts.
pub(super) fn kguest_abort(frame: *mut Frame, esr: u64) -> ! {
    // The hard trap cap: a runaway guest becomes the fast named storm red.
    let traps = kg_get(8) + 1;
    kg_set(8, traps);
    if traps > KG_TRAP_CAP {
        let ipa = hpfar_fault_ipa(super::stage2::read_hpfar_el2());
        kg_teardown_el2();
        el2_return_to_kernel(FAIL_KG_STORM, ipa);
    }

    let ipa = hpfar_fault_ipa(super::stage2::read_hpfar_el2());
    kg_set(10, ipa);
    kg_set(11, esr);

    // An instruction abort = the guest fetched from an unmapped IPA (its
    // image/RAM never leaves the carve — fail-closed).
    if esr_ec(esr) == EC_IABT_LOW {
        kg_teardown_el2();
        el2_return_to_kernel(FAIL_KG_IABT, ipa);
    }
    // A fault on the guest's OWN stage-1 walk: its table frames left the
    // carve (structurally impossible) — fail-closed.
    if esr_s1ptw(esr) != 0 {
        kg_teardown_el2();
        el2_return_to_kernel(FAIL_KG_S1PTW, ipa);
    }

    let probe_page = kg_get(3) & !0xFFF;
    let in_pl011_block = ipa >= PL011_BLOCK_BASE && ipa < PL011_BLOCK_BASE + BLOCK_2M;
    let in_virtio_block = ipa >= VIRTIO_BLOCK_BASE && ipa < VIRTIO_BLOCK_BASE + BLOCK_2M;
    let in_doorbell = (ipa & !0xFFF) == GUEST_DOORBELL_IPA;
    let in_probe = probe_page != 0 && (ipa & !0xFFF) == probe_page;

    if !(in_pl011_block || in_virtio_block || in_doorbell || in_probe) {
        // Outside EVERY emulated window: a host-RAM / unknown-device touch.
        kg_teardown_el2();
        el2_return_to_kernel(FAIL_KG_UNEXPECTED_IPA, ipa);
    }

    // Every emulated access must be ISV=1-decodable (single-GPR LDR/STR —
    // serial.rs/inguest.rs are single-GPR by construction). Yuva has no
    // instruction decoder: fail closed with the NAMED nisv red (survey §6).
    if !dabt_is_emulatable(esr) {
        kg_teardown_el2();
        crate::serial_write_str("el2: nisv-abort ipa=");
        crate::diag_write_hex(ipa);
        crate::serial_write_byte(b'\n');
        el2_return_to_kernel(FAIL_KG_NISV, ipa);
    }

    let is_write = esr_wnr(esr) == 1;
    let srt = dabt_iss_srt(esr) as usize;
    // The in-page register offset: under the guest's identity device/RAM
    // stage-1 the faulting VA == IPA, so FAR_EL2's low 12 bits are the
    // page offset (HPFAR only carries bits [51:12]).
    let off = super::stage2::read_far_el2() & 0xFFF;

    if is_write {
        // SAFETY: `frame.gpr` holds x0..x30; `srt < 32` (5-bit ISS field,
        // proven by `kani_dabt_iss_decode_total`); srt==31 == XZR -> 0.
        let value = if srt < 31 { unsafe { (*frame).gpr[srt] } } else { 0 };
        if in_doorbell {
            // The monitor-counted progress cell: count + last value (nonce).
            kg_set(4, kg_get(4) + 1);
            kg_set(5, value);
        } else if in_probe {
            // Adversarial case (a): the store FAULTED (witnessed here) and is
            // DROPPED — it never lands in host RAM (the host re-checks its
            // sentinel post-flight).
            kg_set(7, kg_get(7) + 1);
        } else if in_pl011_block && (ipa & !0xFFF) == PL011_PAGE && off == PL011_DR {
            // The guest's serial byte -> the injection-proof guestlog frame.
            kg_log_push((value & 0xFF) as u8);
        }
        // Every other write in a trapped block: accept-and-ignore (WI).
    } else {
        // READ: PL011 FR -> idle flags; the doorbell -> its count; everything
        // else in a trapped block reads as zero (RAZ open-bus: the virtio
        // MagicValue probe + the SMMU IDR0 probe both see 0 -> green skips).
        let mut value: u64 = 0;
        if in_pl011_block && (ipa & !0xFFF) == PL011_PAGE && off == PL011_FR {
            value = PL011_FR_IDLE;
        } else if in_doorbell {
            value = kg_get(4);
        }
        if dabt_iss_sf(esr) == 0 {
            value &= 0xFFFF_FFFF;
        }
        if srt < 31 {
            // SAFETY: as the write path; a single in-frame store of gpr[SRT].
            unsafe { (*frame).gpr[srt] = value };
        }
    }

    // ADVANCE ELR past the 32-bit LDR/STR and resume the guest (it never
    // re-executes the access — the L2.3 emulate discipline).
    // SAFETY: `frame.elr` (0xF8) is the faulting PC; +4 resumes PAST it.
    unsafe { (*frame).elr += 4 };
    el2_abort_retry(frame);
}

// ===========================================================================
// The EL1 facade — build, stage, launch, post-flight. The kernel branches on
// the returned closed enum only.
// ===========================================================================

/// The host-RAM confinement-probe cell: a LIVE host `.bss`/`.data` word whose
/// address is handed to the guest (`tb.probe=`). The guest's store to it must
/// stage-2-fault and NEVER land — the facade writes a sentinel before launch
/// and asserts it intact after (adversarial DoD case (a)). Host-EL1-only
/// accessor (the monitor only compares the fault IPA).
static KG_PROBE_CELL: AtomicU64 = AtomicU64::new(0);

/// The probe sentinel value (must survive the guest run byte-identically).
const KG_PROBE_SENTINEL: u64 = 0x484F_5354_5241_4D21; // "HOSTRAM!"

unsafe extern "C" {
    /// The kernel's tb-boot EL1 entry (boot.rs `_tb_start`): its link address
    /// IS the guest entry IPA (link-addr == IPA, no relocation).
    fn _tb_start() -> !;
}

/// EL1: read `SP_EL0` (saved/restored around the launch — the guest's M4
/// user-mode drop reprograms it).
fn read_sp_el0() -> u64 {
    let v: u64;
    // SAFETY: SP_EL0 is EL1-accessible via MRS; side-effect-free.
    unsafe {
        asm!("mrs {v}, sp_el0", v = out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// EL1: restore `SP_EL0` after the launch.
fn write_sp_el0(v: u64) {
    // SAFETY: SP_EL0 is EL1-writable via MSR; the value is the host's own.
    unsafe {
        asm!("msr sp_el0, {v}", v = in(reg) v, options(nomem, nostack, preserves_flags));
    }
}

/// EL1: clean the written boot-block range to PoC (`dc cvac` per 64-byte
/// line + `dsb ish`) so the MMU-off guest reads the bytes, not stale cache
/// (survey §7b-1; TCG is cache-coherent so CI cannot see a miss here — the
/// silicon obligation is declared in assumptions.md).
fn clean_to_poc(base: u64, len: u64) {
    let mut a = base & !63;
    while a < base + len {
        // SAFETY: `dc cvac` on an address inside identity-mapped RAM we just
        // wrote; cache maintenance has no functional memory effect.
        unsafe { asm!("dc cvac, {a}", a = in(reg) a, options(nostack, preserves_flags)) };
        a += 64;
    }
    super::stage2::dsb_ish_pub();
}

/// EL1: is the guest image staged at the carve? Compares the first 4 KiB of
/// the host's own image (PA `0x4008_0000`, immutable .note/.text bytes)
/// against the carve copy the run-script `-device loader` staged. A mismatch
/// = no loader on this lane -> the graceful `(no guest image, skipped)`.
fn image_staged() -> bool {
    let host = tb_boot::aarch64::AARCH64_IMAGE_LMA;
    let guest = GUEST_CARVE_PA + GUEST_IMAGE_OFF;
    let mut i = 0u64;
    while i < 4096 {
        // SAFETY: both ranges are identity-mapped RAM (the host image; the
        // pmm-reserved carve); aligned volatile u64 loads.
        let a = unsafe { read_volatile((host + i) as *const u64) };
        let b = unsafe { read_volatile((guest + i) as *const u64) };
        if a != b {
            return false;
        }
        i += 8;
    }
    true
}

/// EL1: derive the per-boot nonce (monitor/host-chosen, never guest-chosen):
/// the physical counter mixed through a fixed odd multiplier. Never zero.
fn pick_nonce() -> u64 {
    let c: u64;
    // SAFETY: CNTPCT_EL0 read is granted to EL1 (CNTHCTL_EL2=0x3, the boot
    // baseline); side-effect-free.
    unsafe {
        asm!("isb", "mrs {c}, cntpct_el0", c = out(reg) c, options(nomem, nostack, preserves_flags));
    }
    let n = c.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (c << 32);
    if n == 0 { 0x0B24_0B24_0B24_0B24 } else { n }
}

/// Render `v` as 16 lowercase-hex digits into `out`.
fn hex16_into(v: u64, out: &mut [u8]) {
    let mut shift: i32 = 60;
    let mut i = 0usize;
    while shift >= 0 {
        let nib = ((v >> shift) & 0xF) as u8;
        out[i] = if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) };
        i += 1;
        shift -= 4;
    }
}

/// aL2.4b: launch the FULL-KERNEL EL1 guest under the monitor's stage-2 and
/// judge it from monitor-witnessed evidence. See [`crate::KernelGuestProof`]
/// and the module doc. Graceful skips: not booted at EL2 (which includes
/// being the confined guest ourselves — one level of nesting), or no guest
/// image staged at the carve (no `-device loader` on this lane).
pub fn el2_kernel_guest_selftest() -> crate::KernelGuestProof {
    use crate::KernelGuestProof as P;

    // Graceful skip: no resident monitor (incl. in-guest: BOOTED_AT_EL2==0).
    if BOOTED_AT_EL2.load(Ordering::Acquire) != 1 {
        return P::Unavailable;
    }
    // Graceful skip: no staged guest image (demo/bench lanes; the boot lane
    // attaches the loader and REJECTS this variant by name).
    if !image_staged() {
        return P::NoImage;
    }

    // The launch parameters: nonce, probe cell, cmdline, boot block, stage-2.
    let nonce = pick_nonce();
    KG_PROBE_CELL.store(KG_PROBE_SENTINEL, Ordering::Release);
    let probe_va = &KG_PROBE_CELL as *const _ as u64;

    // cmdline: "tb.nonce=<16hex> tb.probe=<16hex>"
    let mut cmdline = [0u8; 51];
    cmdline[0..9].copy_from_slice(b"tb.nonce=");
    hex16_into(nonce, &mut cmdline[9..25]);
    cmdline[25] = b' ';
    cmdline[26..35].copy_from_slice(b"tb.probe=");
    hex16_into(probe_va, &mut cmdline[35..51]);

    // The guest's memory map: the carve as ONE Ram region at its IPA window.
    let regions = [tb_boot::TbMemRegion::new(
        GUEST_IPA_BASE,
        GUEST_CARVE_SIZE,
        tb_boot::MemKind::Ram,
    )];
    let entry = _tb_start as *const () as u64;

    // Write the frozen boot block over the carve (the host-tested splice
    // contract), flagged IN-GUEST. `ram[0]` corresponds to GUEST_RAM_BASE;
    // the slice spans the 512 KiB sub-image staging window only.
    // SAFETY: the carve `[GUEST_CARVE_PA, +GUEST_IMAGE_OFF)` is pmm-RESERVED
    // host RAM (never aliased by any allocation), identity-mapped Normal-WB;
    // we mint the ONLY reference to it for the duration of this call.
    let ram = unsafe {
        core::slice::from_raw_parts_mut(GUEST_CARVE_PA as *mut u8, GUEST_IMAGE_OFF as usize)
    };
    if tb_boot::aarch64::build_handoff_flagged(
        ram,
        &regions,
        &cmdline,
        entry,
        tb_boot::TB_BOOT_FLAG_IN_GUEST,
    )
    .is_err()
    {
        return P::Faulted { code: FAIL_KG_HANDOFF, info: 0 };
    }
    // Clean the written boot window to PoC (the MMU-off guest reads it raw):
    // info @ +0x1000, regions @ +0x1040, cmdline @ +0x1800..+0x1900.
    clean_to_poc(GUEST_CARVE_PA + 0x1000, 0x900);

    // The FIRST non-identity stage-2 (the Kani-proven carve map per block).
    let root = match super::stage2::build_guest_stage2() {
        Some(r) => r,
        None => return P::Faulted { code: FAIL_KG_BUILD, info: 0 },
    };
    let vtcr_v = super::stage2::compute_vtcr();
    let vttbr_v = super::stage2::compute_vttbr_vmid(root, super::stage2::KGUEST_VMID);

    // Save the host EL1 state the guest will clobber (the l24_nested
    // discipline, plus SP_EL0 — the guest's M4 reprograms it; SP_EL1 is
    // saved/restored AT EL2 by the launch/teardown handlers).
    let saved_ttbr0 = super::l24_nested::read_ttbr0_el1();
    let saved_tcr = super::l24_nested::read_tcr_el1();
    let saved_mair = super::l24_nested::read_mair_el1();
    let saved_sctlr = super::l24_nested::read_sctlr_el1();
    let saved_vbar = read_vbar_el1();
    let saved_sp_el0 = read_sp_el0();

    // The pre-launch witness line (host serial, BEFORE the world switch): on
    // a hang the run-script renders the named stall red from its presence.
    crate::serial_write_str("guestlaunch: arming carve=0x46000000+32M entry=");
    crate::diag_write_hex(entry);
    crate::serial_write_str(" nonce=");
    crate::diag_write_hex(nonce);
    crate::serial_write_byte(b'\n');

    // Mask EL1 IRQs + quiesce the host timer across the whole guest run (the
    // guest re-owns CNTP + the GIC under the pass-through grant; the host's
    // own timer was disarmed after M9 but a stale compare must not pend).
    crate::timer_disarm();
    let daif = super::timer::local_irq_save();

    let outcome: u64;
    let packed: u64;
    // SAFETY: the resident EL2 monitor catches `hvc #16`, stashes the launch
    // context, arms the carve stage-2 (VMID 2) + HCR = RW|VM|TWI, and erets
    // into `_tb_start` at the carve with X0 = the TbBootInfo IPA. The guest
    // runs its FULL chain confined; the monitor services its trapped I/O and
    // unwinds here with x0 = outcome, x1 = the packed witness, every other
    // host register restored from B0 (SP_EL1 restored at EL2). x0..x5 carry
    // the in-args; clobber_abi("C") covers the rest.
    unsafe {
        asm!(
            "hvc #16",
            inout("x0") vtcr_v => outcome,
            inout("x1") vttbr_v => packed,
            in("x2") entry,
            in("x3") tb_boot::aarch64::AARCH64_BOOT_INFO_ADDR,
            in("x4") nonce,
            in("x5") probe_va,
            clobber_abi("C"),
        );
    }

    // EL1-side teardown: restore the host's stage-1 regime + vectors + user
    // stack pointer (the guest re-programmed all of them).
    super::l24_nested::restore_kernel_stage1(
        saved_mair,
        saved_tcr,
        saved_ttbr0,
        saved_sctlr,
        saved_vbar,
    );
    write_sp_el0(saved_sp_el0);
    super::timer::local_irq_restore(daif);

    if outcome != 0 {
        return P::Faulted { code: outcome, info: packed };
    }

    let doorbell = packed & 0xFFFF;
    let probe = (packed >> 16) & 0xFF;
    let traps = packed >> 32;

    // Post-flight (a): the confinement probe fired EXACTLY once...
    if probe != 1 {
        return P::Faulted { code: FAIL_KG_PROBE_MISS, info: probe };
    }
    // ... and the store NEVER landed (the sentinel is byte-identical).
    if KG_PROBE_CELL.load(Ordering::Acquire) != KG_PROBE_SENTINEL {
        return P::Faulted { code: FAIL_KG_SENTINEL, info: 0 };
    }
    // Post-flight (b): the in-guest discriminator, read back from GUEST
    // memory (the carve copy of BOOT_ENTRY_EL / BOOTED_AT_EL2): the guest
    // provably entered via _tb_start (0xFF) with NO monitor of its own (0).
    let carve_off = GUEST_CARVE_PA - GUEST_IPA_BASE;
    let g_entry_el = (&super::super::boot::BOOT_ENTRY_EL as *const _ as u64) + carve_off;
    let g_el2 = (&BOOTED_AT_EL2 as *const _ as u64) + carve_off;
    // SAFETY: both addresses land inside the pmm-reserved, identity-mapped
    // carve (the guest's .data/.bss copies); aligned volatile u8 loads.
    let (entry_el, guest_el2) = unsafe {
        (
            read_volatile(g_entry_el as *const u8),
            read_volatile(g_el2 as *const u8),
        )
    };
    if entry_el != 0xFF || guest_el2 != 0 {
        return P::Faulted {
            code: FAIL_KG_DISCRIMINATOR,
            info: ((entry_el as u64) << 8) | guest_el2 as u64,
        };
    }

    P::Proven { nonce, doorbell, probe, traps }
}
