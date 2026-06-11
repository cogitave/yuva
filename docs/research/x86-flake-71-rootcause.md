# #71 root cause — the x86_64 CI "ghost interrupt" flake (QEMU TCG upstream bug; kernel blameless)

**Status:** root-caused (2026-06-11, ultracode 3-modality investigation: CI-history mining over all retained runs + kernel code audit + upstream source verification; same-day disassembly confirmation) · **Verdict: NO TABOS kernel bug** — the fail-closed halt is the correct response to an emulator-injected, non-architectural `#GP`. This doc records the evidence chain, the landed diagnosis pair, and the upstream issue draft.

## The signature (10/10 retained CI instances, 2026-06-08 → 2026-06-10)

- Always immediately after `M7: heap OK` — i.e. inside the M8 LAPIC-timer bring-up, the first window with `IF=1`.
- Always `trap: fatal fault, halting | cause=0x0000000dfffffffa` — vector `0x0d` (`#GP`) with 32-bit error code **`0xfffffffa`**, `fault_addr=0x0`.
- **TCG lanes only**: 10/10 on `-accel tcg` (qemu-system-x86 1:8.2.2, ubuntu-24.04 runners, across two runner images); **0/85** on the microvm+KVM lane (in-kernel APIC bypasses the buggy path).
- 6/6 reruns green; **0/80 local repro** (idle + saturated); burst-clustered in a ~44 h heavy-runner-load window, clean since.
- `pc` constant per kernel binary, shifting with link layout across builds; two runs sharing one binary faulted at the **same** pc; **all 8 distinct pcs end in nibble `0xf`**.

## The mechanism (verified in QEMU v8.2.2 AND current master source)

QEMU TCG's **userspace APIC** can leave `CPU_INTERRUPT_HARD` pending while no IRR vector is actually deliverable (a race between the iothread timer callback and the vCPU thread, widened by host steal-time on oversubscribed CI runners). `x86_cpu_exec_interrupt` then services it:

```c
intno = cpu_get_pic_interrupt(env);   /* returns -1: nothing deliverable */
...
do_interrupt_x86_hardirq(env, intno, 1);   /* NO intno >= 0 guard */
```

`do_interrupt64`'s IDT-limit check (`intno * 16 + 15 > dt->limit`) fires for `-1` via signed→unsigned promotion and raises a **guest-visible** `#GP` with error code `intno * 8 + 2` = `(-1)*8 + 2` = **`0xfffffffa`** — bit-for-bit the observed value, and a **non-architectural** code (reserved bits set) that no real CPU can push for this fault class and that the TABOS kernel cannot forge (the thunk dummy is 0; vector 13 takes the CPU-pushed code verbatim — `trap.rs`).

**Disassembly confirmation (same day, no flake needed):** in the current binary the `run_canary` loop-head TB boundary (`callq tick_count` at `run_canary+0x1f`, address ending **`0xf`**) is the sole interrupt-recognition point in the M8 spin window — matching all 8 observed pc low-nibbles — while the four `iretq` sites end in `0a/1d/5d/72`. This kills the alternate "iretq #GP from a corrupted frame" hypothesis outright; the frame-skew and IDT-stomp hypotheses were already falsified by static audit (the thunk errcode-vector set matches SDM Table 6-1 exactly) and by the signature itself (the IDT demonstrably delivered the bogus `#GP` cleanly through gate 13).

## What landed (the diagnosis pair — diagnosis-only, zero green-path change)

1. **`scripts/run-x86_64.sh`** — `-d int -D <tempfile>` (side file; never bare `-d`, the script merges QEMU's `2>&1` into the marker-grepped output) with the trace tail printed **only on failure** + an automatic fingerprint check: a literal `Servicing hardware INT=0xffffffff` line (QEMU renders `intno=-1` via `%02x`) immediately before the `v=0d e=fffffffa` trace is the decisive witness. Plus `-accel tcg,thread=single` parity with `run-aarch64.sh` (single TCG vCPU thread narrows the injection race structurally).
2. **`trap.rs::dump_fatal_frame`** — appended `frameptr=` (handler-side `&TrapFrame`: places the frame inside `__boot_stack`, ruling out wild-RSP) and `ticks=` (`tick_count()` at fault: the ghost mechanism predicts ≥ 1 clean tick before the bogus injection). Comment updated from the old two-hypothesis text to the confirmed root cause.

**Deliberately NOT done:** teaching the kernel to tolerate reserved-bit error codes (would hide real bugs forever — the kernel halting fail-closed is correct), and any silent retry. If a retry is ever added it must trigger ONLY on the exact fingerprint and print a witness line.

## Possible follow-ups (in `#71`, after the first catch or a soak)

- Adopt `-icount shift=auto,sleep=off -rtc clock=vm` on the TCG lane (structural fix: instruction-counted virtual time decouples guest time from host steal entirely — the Zephyr #14173-family remedy). Validate first that `CANARY_CAP` still spans ≥ 16 ticks at the chosen shift and the 40 s timeout fits.
- Close #71 on the first `Servicing hardware INT=0xffffffff` catch, or after a ~100-run clean soak with the upstream issue filed as the paper trail.

---

## Upstream issue draft (for QEMU GitLab — **to be filed by the operator**, not auto-published)

> **Title:** x86 TCG: unguarded `cpu_get_pic_interrupt() == -1` in `x86_cpu_exec_interrupt` surfaces as guest-visible `#GP` with impossible error code `0xfffffffa`
>
> **Affects:** v8.2.2 through current master (code inspected 2026-06-11: `target/i386/tcg/system/seg_helper.c` / `x86_cpu_exec_interrupt` — no `intno >= 0` check before `do_interrupt_x86_hardirq`).
>
> **Symptom:** under `-machine microvm -accel tcg -cpu qemu64`, a guest using the LAPIC timer (periodic mode, ~1 ms) intermittently receives a `#GP` whose pushed error code is `0xfffffffa` — a value with reserved bits set that real hardware cannot generate for this fault class. The arithmetic matches `do_interrupt64`'s `intno * 8 + 2` with `intno = -1`: `CPU_INTERRUPT_HARD` was pending but `cpu_get_pic_interrupt()` found no deliverable vector (userspace-APIC iothread/vCPU race; reproduces only under heavy host load, e.g. oversubscribed CI runners; never under KVM's in-kernel APIC; multi-threaded TCG).
>
> **Guest-side reproducer shape:** PVH-booted kernel, LAPIC periodic timer at ~1 ms, handler EOIs while `IF=0`, then a tight `hlt`-free spin loop polling a tick counter (the interrupt is recognized at the loop's TB boundary). Observed rate ≈ 8–14% per boot on busy GitHub-hosted runners; 0% locally.
>
> **Expected:** a pending-but-undeliverable hard interrupt should be ignored (re-checked on the next recognition point), not delivered as `intno = -1`.
>
> **Suggested fix:** a one-line guard in `x86_cpu_exec_interrupt` (`if (intno >= 0)` before `do_interrupt_x86_hardirq`, or fall back to the spurious vector), mirroring the KVM path's behavior.
>
> **Evidence available:** 10 serial logs with identical `v=0d e=fffffffa` traces; guest binary disassembly showing the faulting RIP at the spin-loop TB boundary; the error-code arithmetic fingerprint.

See also: task #71 (tracker), `scripts/run-x86_64.sh` (the `-d int` witness), `crates/tb-hal/src/arch/x86_64/trap.rs::dump_fatal_frame`.
