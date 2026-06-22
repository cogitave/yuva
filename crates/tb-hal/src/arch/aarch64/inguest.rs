//! aL2.4b **IN-GUEST mode** (the EL1 guest side of the full-kernel-as-guest
//! rung): consume the `TbBootInfo` IN-GUEST flag + the launch cmdline, and
//! replace the end-of-chain semihosting QEMU-exit with the doorbell/done/WFI
//! park protocol.
//!
//! ## Why this exists (survey MISSING #4 — the semihosting kill)
//!
//! The kernel ends its chain in a semihosting QEMU-exit (`hlt #0xF000`).
//! Issued from a TCG EL1 guest, QEMU intercepts it at translation time and
//! **kills the WHOLE VM, host included**. So when the `TbBootInfo` flags
//! carry [`tb_boot::TB_BOOT_FLAG_IN_GUEST`], the `qemu_exit_*` facades route
//! here instead: the guest
//!  1. prints the suppression line + the adversarial forge-test lines (all of
//!     which leave ONLY through the trapped PL011 → injection-proof
//!     `guestlog:` frames),
//!  2. performs EXACTLY ONE confinement-probe store to the host-RAM IPA the
//!     host passed in `tb.probe=` (the store MUST stage-2-fault and never
//!     land — adversarial DoD case (a)),
//!  3. echoes the monitor-chosen per-boot nonce (`tb.nonce=`) through the
//!     doorbell MMIO window (4 stores to the watched unmapped IPA — the M27
//!     progress-cell pattern; non-text completion evidence),
//!  4. issues the `HVC #17` done hypercall (status 0 = the single armed
//!     clean-exit site was reached, i.e. the full chain printed; nonzero =
//!     fail-fast so the host lane goes red in seconds, not at the ceiling),
//!  5. parks in `wfi` — which the monitor traps under `HCR_EL2.TWI` (armed at
//!     the done hypercall) as the final-WFI completion witness.
//!
//! The doorbell/probe stores are EXPLICIT single-GPR `str` instructions (the
//! ISV=1 envelope the monitor's DABT decoder requires — survey §6's ISV=0
//! fail-closed rule), never compiler-chosen access forms.

use core::arch::asm;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use tb_boot::{TbBootInfo, TB_BOOT_FLAG_IN_GUEST};
use tb_encode::stage2::GUEST_DOORBELL_IPA;

/// `1` iff the boot block carried the IN-GUEST flag (we are the aL2.4b
/// stage-2-confined guest). Written once by [`tb_boot_consume`].
static IN_GUEST: AtomicU8 = AtomicU8::new(0);
/// The monitor-chosen per-boot nonce parsed from the `tb.nonce=` cmdline key
/// (echoed through the doorbell + `HVC #17`). 0 if absent (fail-closed: the
/// monitor's nonce-echo gate then rejects the completion).
static GUEST_NONCE: AtomicU64 = AtomicU64::new(0);
/// The host-RAM confinement-probe VA parsed from `tb.probe=`. 0 = no probe.
static PROBE_VA: AtomicU64 = AtomicU64::new(0);

/// `true` iff the kernel is running as the aL2.4b confined EL1 guest.
pub fn in_guest() -> bool {
    IN_GUEST.load(Ordering::Acquire) != 0
}

/// Guarded byte read inside the identity RAM gigabyte (the pmm reader's
/// window): `None` for anything outside `[0x4000_0000, 0x8000_0000)`.
fn read_u8(pa: u64) -> Option<u8> {
    if !(0x4000_0000..0x8000_0000).contains(&pa) {
        return None;
    }
    // SAFETY: `pa` is inside the identity-mapped (or pre-MMU flat) Normal-WB
    // RAM gigabyte; a `u8` load imposes no alignment, and `read_volatile`
    // keeps the optimiser from eliding the foreign boot-blob read.
    Some(unsafe { (pa as *const u8).read_volatile() })
}

/// Parse exactly 16 lowercase-hex digits at `pa`, or `None`.
fn parse_hex16(pa: u64) -> Option<u64> {
    let mut v: u64 = 0;
    let mut i = 0u64;
    while i < 16 {
        let c = read_u8(pa + i)?;
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => return None,
        };
        v = (v << 4) | d as u64;
        i += 1;
    }
    Some(v)
}

/// Consume the validated `TbBootInfo` at `boot_info` (the kernel calls this
/// ONLY inside its `read_boot_magic == TB_BOOT_MAGIC` branch): record the
/// IN-GUEST flag, and parse the launch cmdline's `tb.nonce=`/`tb.probe=`
/// 16-hex values. Fail-closed: any malformed field simply leaves the
/// corresponding static at 0 (the monitor's completion gates then reject).
pub fn tb_boot_consume(boot_info: usize) {
    let bi = boot_info as u64;
    // Read the TbBootInfo bytes through the same guarded window.
    let mut head = [0u8; TbBootInfo::SIZE];
    let mut i = 0u64;
    while i < TbBootInfo::SIZE as u64 {
        match read_u8(bi + i) {
            Some(b) => head[i as usize] = b,
            None => return,
        }
        i += 1;
    }
    let info = match TbBootInfo::read_validated(&head) {
        Ok(info) => info,
        Err(_) => return,
    };
    if info.flags & TB_BOOT_FLAG_IN_GUEST == 0 {
        return;
    }
    IN_GUEST.store(1, Ordering::Release);

    // Scan the cmdline for "tb.nonce=<16hex>" and "tb.probe=<16hex>".
    let (cp, cl) = (info.cmdline_ptr, info.cmdline_len);
    let mut off = 0u64;
    while off < cl {
        let here = cp + off;
        if matches_key(here, b"tb.nonce=") {
            if let Some(v) = parse_hex16(here + 9) {
                GUEST_NONCE.store(v, Ordering::Release);
            }
        }
        if matches_key(here, b"tb.probe=") {
            if let Some(v) = parse_hex16(here + 9) {
                PROBE_VA.store(v, Ordering::Release);
            }
        }
        off += 1;
    }
}

/// `true` iff the bytes at `pa` equal `key` (guarded reads; `false` on any
/// out-of-window byte).
fn matches_key(pa: u64, key: &[u8]) -> bool {
    let mut i = 0u64;
    while i < key.len() as u64 {
        match read_u8(pa + i) {
            Some(b) if b == key[i as usize] => {}
            _ => return false,
        }
        i += 1;
    }
    true
}

/// One explicit single-GPR 64-bit `str` to `va` — the ISV=1-decodable access
/// form the monitor's DABT emulate path requires (never a compiler-chosen
/// pair/writeback form).
fn str64(va: u64, val: u64) {
    // SAFETY: in-guest, `va` is either the doorbell IPA (unmapped at stage-2
    // -> the store TRAPS to the monitor and never lands) or the host-RAM
    // probe IPA (same: traps, dropped). The guest's stage-1 maps the RAM
    // gigabyte identity, so the VA translates; the stage-2 fault is the
    // DESIGNED behaviour, serviced by the monitor's emulate path which
    // advances ELR past this very instruction.
    unsafe {
        asm!(
            "str {v}, [{a}]",
            v = in(reg) val,
            a = in(reg) va,
            options(nostack, preserves_flags),
        );
    }
}

/// The IN-GUEST end-of-chain park (replaces the semihosting QEMU-exit; never
/// returns). `success` = the single armed clean-exit site was reached (the
/// full chain printed); `false` = a fail/panic path. See the module doc for
/// the protocol.
pub fn guest_exit_park(success: bool) -> ! {
    let nonce = GUEST_NONCE.load(Ordering::Acquire);
    let status: u64 = if success {
        crate::serial_write_str("qemu-exit: suppressed (in-guest) -- semihosting not issued\n");
        // Adversarial DoD case (b): DELIBERATE forged host-marker bytes. These
        // leave only via the trapped PL011 -> hex-framed `guestlog:` lines, so
        // they can NEVER satisfy a host guard; the run-script asserts they
        // appear in the decoded GUEST stream and ONLY hex-framed in HOST.
        crate::serial_write_str("forge-test: M31: infer-e2e OK backend=MOCK-DETERMINISTIC\n");
        crate::serial_write_str("forge-test: L2.4b: el1-kernel-guest OK\n");
        // M38 (stage B): a DELIBERATELY forged conductor marker. A deprivileged
        // guest cannot forge a host-trusted M38 marker -- these bytes leave ONLY
        // hex-framed via the trapped PL011 `guestlog:` lines, so a forged `M38:`
        // can NEVER satisfy a host grep nor enter the cumulative chain (the
        // run-script asserts it appears in the decoded GUEST stream and ONLY
        // hex-framed in HOST -- the guest-side anti-hollow negative, mirroring
        // the M31 forge-test case above).
        crate::serial_write_str("forge-test: M38: conductor OK turns=6 organs=3 verdict=ACCEPT\n");
        // Adversarial DoD case (a): EXACTLY ONE confinement-probe store to a
        // host-RAM IPA outside the carve. It must stage-2-fault (witnessed by
        // the monitor) and never land (the host re-checks its sentinel).
        let probe = PROBE_VA.load(Ordering::Acquire);
        if probe != 0 {
            str64(probe, 0x0B24_0B24_0B24_0B24);
        }
        // The doorbell: echo the nonce through the watched unmapped IPA (4
        // stores -- above the monitor's >=3 threshold).
        let mut i = 0;
        while i < 4 {
            str64(GUEST_DOORBELL_IPA, nonce);
            i += 1;
        }
        0
    } else {
        crate::serial_write_str("guest-fail: chain did not complete (in-guest)\n");
        1
    };
    // HVC #17: done/doorbell. x0 = status, x1 = the nonce echo (the second
    // echo channel). On status 0 the monitor records done + arms TWI and
    // resumes us; the wfi below then traps as the final-WFI witness. On
    // nonzero status the monitor tears down and fails the host lane fast.
    // SAFETY: the resident EL2 monitor owns the EL1 HVC surface in-guest
    // (HCR_EL2.HCD=0); the handler either resumes past this hvc or never
    // returns. clobber_abi covers the caller-saved registers.
    unsafe {
        asm!(
            "hvc #17",
            in("x0") status,
            in("x1") nonce,
            clobber_abi("C"),
        );
    }
    loop {
        // SAFETY: `wfi` is a hint with no memory/stack effects. With TWI
        // armed (post-done) it traps to the monitor (the completion witness);
        // otherwise it just parks this dead-end path.
        unsafe { asm!("wfi", options(nomem, nostack, preserves_flags)) };
    }
}
