# Try it — booting Yuva yourself (and why there is no .iso)

> TL;DR: **two commands in WSL and you are watching it boot.** Yuva is a
> Firecracker-class, direct-kernel-boot guest by design — the hypervisor loads
> the kernel image straight into guest RAM and jumps to it. There is no BIOS/
> UEFI/bootloader path, therefore no .iso and no "installer" — and that is the
> design (the same way Firecracker guests have no .iso), not a missing piece.
> A self-booting medium (USB/ISO/UEFI) only becomes meaningful on the
> bare-metal/host track — tracked as a packaging follow-up, see §4.

## 1. The 2-minute path (WSL2, the same flow CI uses)

From Windows, in the repo root:

```powershell
wsl -d Ubuntu-22.04 -- bash scripts/demo.sh            # aarch64 (the full chain)
wsl -d Ubuntu-22.04 -- bash scripts/demo.sh x86_64     # the x86 microvm flavor
```

`scripts/demo.sh` builds the kernel if needed, attaches the full device set
(virtio-rng, the M20 virtio-blk disk, the M30 inference channel with a live
host-side peer holding a per-run key), and puts the serial console on your
terminal.

### The clean industrial boot (default)

By default the demo shows a human-meaningful, systemd-style boot readout — a
branded header, one `[ STATUS ] <subsystem>` line per subsystem, and a
`Reached target Ready.` line. Run the x86 flavor to see it (the pretty knob is
wired on x86 at stage A; see the honesty note below):

```
wsl -d Ubuntu-22.04 -- bash scripts/demo.sh x86_64
```

```
Yuva 0.9 — sovereign agent-native OS  ·  agent view (x86_64)
──────────────────────────────────────────────────────────────
[  OK  ] Kernel core                traps, paging, preemptive scheduler
[  OK  ] Isolation & capabilities   per-entity address spaces, capability ABI
[ SKIP ] Guest isolation            full kernel as EL1 guest under EL2 (no EL2, skipped)
[  OK  ] Virtio devices             entropy (rng), block
[  OK  ] Durable storage            virtio-blk, replayed on boot
[ SKIP ] Sovereign scheduler        CNTHP-preempted (no EL2, skipped)
[  OK  ] Message-authenticated integrity   keyed BLAKE2s-256 MAC (primitive assumed-from-literature)
[  OK  ] Agent runtime & memory     tiered store, lexical recall, consolidation
[  OK  ] Provenance ledger          tamper-evident fold (host TCB residual)
[  OK  ] Inference transport        host-custodied key, cross-process recompute — plumbing only
[ MOCK ] Agent inference            deterministic stub — NO model loaded, not live AI
[STANDBY] Adaptive policy            experience logged; activation gate not met
[  OK  ] Operator channel           transcript, exit telemetry, inbound command
[  OK  ] Reached target Ready.
[ INFO ] retrieval=lexical-only · generativity=open-frontier (not claimed) · integrity-primitive=assumed-from-literature
──────────────────────────────────────────────────────────────
The agent runtime is resident. Yuva ready (logical surrogate) — 13 subsystems (1 mock, 1 standby, 2 skipped, 0 failed).
```

This is **honest, not marketing**: a mock inference reads `[ MOCK ] … not live
AI` (never `[ OK ] Local AI`); the dormant learning cell reads `[STANDBY]`; a
subsystem that took a `(… skipped)` path reads `[ SKIP ]` (the EL2-only rows are
skipped on x86); no ANSI color is emitted. `scripts/demo.sh x86_64 --substrate`
renders the Firecracker-alt minimal (micro-VMM only) view.

### The raw developer markers (`--verbose`)

For the machine-truth marker stream — today's exact `Mxx: … OK` chain that CI
greps — pass `--verbose` (or `--raw`):

```
wsl -d Ubuntu-22.04 -- bash scripts/demo.sh x86_64 --verbose
```

```
hello from rust_main
M1: traps OK … M10: addrspace OK … M18: evolve OK
L2.0: el2 OK … L2.6: smmu OK
sched: … timing=TCG-NON-CYCLE-ACCURATE …   ← the CNTHP-preempted scheduler
M27: sched OK … M20: persist OK … M24: bakeoff OK (gate-not-met)
khash: prim=BLAKE2S-256 … kat=RFC7693-PASS
opcmd: … mac=KEYED-CRYPTO …
xport: … echo=HOST-KEYED-VERIFIED …        ← real bytes crossed to the host and back
M30: infer-transport OK … M38: conductor OK … ← the cumulative tail
```

This raw stream is the **default and only** thing CI, the re-entrant aarch64
EL1 guest, and every verifier ever see — the pretty presentation is opt-in via
the `yuva.console=pretty` cmdline token and is byte-for-byte absent without it.
The aarch64 demo (`scripts/demo.sh`, the default arch) shows the raw stream: its
re-entrant guest is unconditionally raw and the aarch64-host pretty knob is a
named follow-up.

The aarch64 run exits by itself when the chain completes; on x86_64 press
**Ctrl-A then X** to leave QEMU. First build takes a few minutes (build-std);
afterwards it is seconds. Prerequisites are exactly BUILD.md §1 (rustup +
`qemu-system-x86 qemu-system-arm` inside WSL).

The demo is a **viewer, not a verifier**: the fail-closed verdicts (marker
greps, anti-hollow witness guards, overclaim rejects) live in
`scripts/run-aarch64.sh` / `run-x86_64.sh` — run those when you want a
PASS/FAIL instead of a show.

## 2. What "running Yuva" means today

Yuva boots the way Firecracker/cloud-hypervisor guests boot:

| Lane | Hypervisor | How the kernel gets in |
|---|---|---|
| `run-aarch64.sh` / `demo.sh` | QEMU `virt` (EL2 exposed) | `-kernel` (PE/Image direct load) |
| `run-x86_64.sh` / `demo.sh x86_64` | QEMU `microvm` | `-kernel` (PVH ELF note) |
| `run-vmm-x86_64.sh` | **our own `tb-vmm`** on /dev/kvm | tb-vmm's loader maps the ELF itself |
| CI (every push) | all three above | identical scripts |

So "does it work in a VM?" is answered hundreds of times a day — every CI push
boots both architectures end-to-end, and `tb-vmm` is our own VMM doing the
same on raw KVM. There is no guest-side installation step because the kernel
IS the workload: no shell, no userland distro — the boot **is** the executable
proof-of-life (the cumulative self-test chain with its witness lines).

## 3. Why no .iso (honestly)

An .iso implies the El Torito BIOS/UEFI path: firmware → bootloader → kernel.
Yuva deliberately has no such path — PVH/direct-kernel boot is the
sovereignty design (the kernel trusts a hypervisor handoff, not firmware), and
everything from the A/B-slot rollback plan (M35) to the champion/challenger
gate (M34) assumes hypervisor-loaded images. Burning an .iso today would mean
adopting a bootloader (GRUB/Limine) purely for ceremony, with zero CI value.

Where a bootable medium WILL matter: **VirtualBox/VMware/Hyper-V demos** (they
cannot direct-kernel-boot a PVH image) and the eventual **bare-metal host
track** (Yuva as the hypervisor under its own guests — the hardware shopping
list's nested-VMX/IOMMU machines). That work is a real, separate packaging
milestone: most likely a tiny UEFI stub (or Limine protocol support) that
loads the ELF and reproduces the PVH/Image handoff — at which point a USB/ISO
artifact falls out naturally. Tracked in the backlog (see the tracker's
"bootable media / demo packaging" task); it is gated behind nothing technical,
only prioritized below the sovereignty chain (M31+, aL2.4b, M33+).

## 4. Quick FAQ

- **"Can I poke around inside?"** Not interactively — there is no shell by
  design (yet). The M25 operator transcript and the M28/M30 inbound channels
  are the interaction surfaces; an operator console is part of the
  communication pillar's future work.
- **"Can it run on my Windows QEMU directly?"** Yes in principle (same
  `-kernel` flags), but the scripts assume a POSIX shell — WSL is the
  supported path.
- **"How do I know a boot is REAL and not theater?"** That is the whole
  honesty discipline: run the verifier scripts — every milestone's witness
  line is positively required, skip variants are rejected by name, overclaim
  words are rejected, and the M30 line is cross-checked against a separate
  host process holding a key the guest never sees.
