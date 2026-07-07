# Yuva M0 — Boot Bring-Up: Build & Run (WSL2)

> **Definition of Done (executable):** a `no_std` image boots under QEMU
> (x86_64 `microvm` via PVH, aarch64 `virt` first-light), prints the **exact**
> line `hello from rust_main` over serial, then halts. The DoD assertion at the
> bottom of this file greps that marker out of the captured serial log.

This document covers only the M0 build. The files in this milestone are split
across sibling work-units; see **§6 Internal HAL contract** for the boundary
between the files emitted here (`Cargo.toml`, `rust-toolchain.toml`,
`.cargo/config.toml`, `tb-hal/src/lib.rs`, `tb-hal/src/arch/mod.rs`,
`kernel/src/main.rs`, this file) and the sibling-owned files (`/targets/*.json`,
`tb-hal/src/arch/<arch>/{mod,boot,serial}.rs`, `kernel/linker/*.ld`,
`scripts/run-*.sh`).

---

## 1. Host: WSL2 Ubuntu 22.04 toolchain bootstrap

Run everything below inside a **WSL2 Ubuntu 22.04** shell (not Windows
PowerShell). All `cargo` commands must be run from the **repo root** so the
relative target-spec and linker-script paths in `.cargo/config.toml` resolve.

```bash
# 1. Build prerequisites + both QEMU system emulators.
sudo apt-get update
sudo apt-get install -y build-essential curl git \
    qemu-system-x86 qemu-system-arm

# 2. rustup (if not already installed).
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# 3. The pinned nightly + components install automatically on first `cargo`
#    invocation because of rust-toolchain.toml, but you can pre-fetch them:
rustup toolchain install nightly-2025-12-15 \
    --component rust-src --component llvm-tools --profile minimal
```

Why these components:

* **`rust-src`** — required by Cargo's `-Zbuild-std`, which recompiles `core` +
  `compiler_builtins` for our none-class targets (there is no precompiled `std`
  for `x86_64-yuva-none` / `aarch64-yuva-none`).
  Source: <https://os.phil-opp.com/minimal-rust-kernel/> (“The build-std Option”);
  <https://docs.rust-embedded.org/embedonomicon/custom-target.html>.
* **`llvm-tools`** — gives `llvm-objdump` / `llvm-readobj` to verify the ELF (see
  §5).
* **nightly** — `-Zbuild-std`, custom JSON target specs, and the asm features used
  by `tb-hal` are nightly-only.
  Sources: <https://doc.rust-lang.org/cargo/reference/unstable.html#build-std>,
  embedonomicon (above).

QEMU on Ubuntu 22.04 ships ≥ 6.2, which supports both the x86 `microvm` machine
and PVH ELF boot via `-kernel`.
Source: <https://www.qemu.org/docs/master/system/i386/microvm.html>.

---

## 2. Build both targets

The three nightly flags the kernel needs (`-Zbuild-std`, `compiler-builtins-mem`,
`-Zjson-target-spec`) are bundled into the `cargo kbuild` alias in
`.cargo/config.toml` (the single source of truth for how the kernel is built).
They are deliberately NOT global, so the host VMM crate `tb-vmm` still builds
with a plain `cargo build`.

```bash
# From the repo root:

# x86_64 PVH image (loads at 1 MiB):
cargo kbuild --release --target targets/x86_64-yuva-none.json
#   -> target/x86_64-yuva-none/release/yuva-kernel  (ELF, PVH + YUVA brand notes)

# aarch64 QEMU-virt image:
cargo kbuild --release --target targets/aarch64-yuva-none.json
#   -> target/aarch64-yuva-none/release/yuva-kernel  (ELF)
```

`--release` is recommended for the DoD (smaller, deterministic); `cargo kbuild`
without it (debug) also works.

`cargo run --target <spec>` invokes the matching `scripts/run-<arch>.sh` runner
(configured under `[target.<stem>].runner` in `.cargo/config.toml`), passing the
built ELF as `$1`.

---

## 3. Boot contract (verified facts the sibling boot/serial files implement)

Reproduced here for traceability; cite the source in each asm file's header note.

### x86_64 — PVH (bootstrap path for M0; deleted at `tb-vmm`)

* The image is an **ELF carrying the `XEN_ELFNOTE_PHYS32_ENTRY` note** (ELF note
  name `"Xen"`, type **18**, a `.long` 32-bit entry address). Both QEMU
  (`-kernel`) and Firecracker (`linux-loader`) select the PVH boot path **by the
  presence of this note**.
  Source: <https://xenbits.xen.org/docs/unstable/misc/pvh.html>
  (“x86/HVM direct boot ABI”).
* PVH hands off in **32-bit protected mode, paging OFF**, `cr0 = PE|ET` (only PE
  is required set; all other writable bits clear), `cr4 = 0`, and **`%ebx` →
  `hvm_start_info`** physical address. Source: same PVH page.
* `struct hvm_start_info` begins with `magic = 0x336ec578` (“xEn3”).
  Source: <https://xenbits.xen.org/gitweb/?p=xen.git;a=blob_plain;f=xen/include/public/arch-x86/hvm/start_info.h;hb=HEAD>.
* `_start` therefore must (A0 trampoline, **bootstrap-only**): build a minimal
  identity page table for the low region, set `EFER.LME`, set `CR4.PAE` +
  `CR0.PG`, far-jump to a 64-bit code segment, set up a 64-bit stack, clear
  `.bss`, move the `hvm_start_info` pointer from `ebx` into **`rdi`** (SysV
  arg0), then `call rust_main`. Kernel loads at **1 MiB (`0x0010_0000`)**.
* Serial = legacy **16550 UART, COM1 @ I/O port `0x3F8`**: write the byte to
  **THR (offset 0)** once **LSR (offset 5)** bit 5 (`0x20`, THR-empty) is set.
  Works on QEMU `microvm` (ISA serial, on by default) and Firecracker.
  Sources: QEMU microvm doc (above, “One ISA serial port”); 16550 register map,
  e.g. TI PC16550D datasheet.
* SysV ABI: callee-saved `rbx, rbp, r12–r15`; arg0 = `rdi`; **RSP 16-byte
  aligned before `call`**. Source: System V AMD64 psABI.

### aarch64 — QEMU `virt` first-light

* Entry at **EL1h, MMU OFF, DAIF masked** (`PSTATE = 0x3c5`), with **`x0` = FDT
  (devicetree) blob pointer** = AAPCS64 arg0 already. `_start` must set `sp` to a
  reserved stack, clear `.bss` **without clobbering `x0`**, install a minimal
  EL1 vector table via `VBAR_EL1` + `isb`, then `b rust_main` (x0 preserved).
  Source: KERNEL-FOUNDATION-SPEC.md §2 (PSTATE/`0x3c5` verified against
  Firecracker `setup_boot_regs`).
* Serial for QEMU `virt` = **PL011 UART0 @ MMIO `0x0900_0000`**: write the byte
  to **DR (offset `0x00`)** once **FR (offset `0x18`)** bit 5 (TXFF, transmit
  FIFO full) is clear. Source: Arm PrimeCell PL011 TRM (DDI0183), register
  summary (`UARTDR` @ 0x000, `UARTFR` @ 0x018, FR.TXFF = bit 5).
* **Firecracker caveat (verified):** Firecracker's FDT declares the serial as
  `compatible = "ns16550a"` (an **NS16550A**, *not* PL011). For M0 first-light we
  **hardcode the QEMU-virt PL011**; the sibling `arch/aarch64/serial.rs` must
  carry a clearly-marked `TODO`/`cfg` for the FDT-driven NS16550A path used on
  Firecracker. Source: `docs/research/raw/kernel-asm-verified.json` (FDT
  `compatible="ns16550a"`); KERNEL-FOUNDATION-SPEC.md §2 correction note.
* AAPCS64: callee-saved `x19–x28, x29, x30, SP`; arg0 = `x0`; `SP % 16 == 0`.

---

## 4. Why these build flags (the `kbuild` alias + `.cargo/config.toml`)

| Flag | Purpose | Source |
|---|---|---|
| `kbuild` alias `-Zjson-target-spec` | Recent nightlies error `.json target specs require -Zjson-target-spec` without it | phil-opp Minimal Rust Kernel |
| `kbuild` alias `-Zbuild-std=core,compiler_builtins,alloc` | No precompiled std for none-class targets; rebuild core+alloc from `rust-src` (`alloc` added at M5) | phil-opp; embedonomicon; cargo unstable docs |
| `kbuild` alias `-Zbuild-std-features=compiler-builtins-mem` | Provides `memcpy/memset/memcmp/memmove` (needed the moment we copy/zero memory) | phil-opp Minimal Rust Kernel |
| `link-arg=-Tkernel/linker/<arch>.ld` | rust-lld (`ld.lld`) uses our script: keep the PVH note, place `.text` at 1 MiB (x86) | embedonomicon custom-target |
| `runner = ["bash", "scripts/run-<arch>.sh"]` | `cargo run` boots the built ELF in QEMU | cargo config `target.*.runner` |

---

## 5. Verify the x86_64 ELF actually carries the PVH note

```bash
llvm-readobj --notes target/x86_64-yuva-none/release/yuva-kernel
# Expect TWO notes: Owner "Xen" Type 0x12 (XEN_ELFNOTE_PHYS32_ENTRY -- the
#   PVH/QEMU entry) and Owner "YUVA" Type 0x59550001 (the tb-boot 64-bit entry
#   that tb-vmm jumps to; both bytes derive from crates/brand -- see
#   docs/SOVEREIGNTY-ROADMAP.md).

llvm-objdump -t target/x86_64-yuva-none/release/yuva-kernel | grep -E '_start|rust_main'
# Expect _start near 0x100000 and rust_main present (un-mangled).
```

If the note is missing, QEMU/Firecracker will refuse the PVH path (or fall back
to LinuxBoot). That note + its `KEEP(...)` in `kernel/linker/x86_64.ld` is owned
by the linker-script / boot sibling files.

---

## 6. Internal HAL contract (boundary with sibling-owned files)

`tb-hal/src/lib.rs` (emitted here) exposes the four public safe functions and
implements `serial_write_str` in safe Rust. It delegates `serial_init`,
`serial_write_byte`, and `halt` to `arch::*`, re-exported by
`tb-hal/src/arch/mod.rs` (also emitted here) from the per-arch module.

**Each sibling-owned `tb-hal/src/arch/<arch>/mod.rs` MUST provide exactly:**

```rust
pub fn serial_init();
pub fn serial_write_byte(b: u8);
pub fn halt() -> !;
```

(typically re-exported from its own `serial.rs` / `boot.rs`), **plus** the
`global_asm!` boot entry `_start` and — on x86_64 only — the
`XEN_ELFNOTE_PHYS32_ENTRY` note. `_start` is kept alive by `ENTRY(_start)` in the
linker script; `rust_main` (in `kernel/src/main.rs`) is kept because `_start`
`call`/`b`-references it.

**Note on `kernel/src/main.rs` and `forbid(unsafe_code)`:** the kernel crate is
safe Rust, but `main.rs` does **not** carry crate-level `#![forbid(unsafe_code)]`
because `#[unsafe(no_mangle)]` (needed so `_start` can find `rust_main`) is an
unsafe *attribute* that the `unsafe_code` lint rejects. `main.rs` contains no
`unsafe {}` blocks; every later (non-shim) kernel module will carry
`#![forbid(unsafe_code)]`.

---

## 7. Run + assert the DoD marker

The kernel `halt()`s (it does not power off the VM), so we capture serial to a
file under a wall-clock `timeout`, let `timeout` kill QEMU, then grep the log.

### x86_64 (QEMU `microvm`, PVH via `-kernel`)

```bash
KIMG=target/x86_64-yuva-none/release/yuva-kernel
timeout --foreground 30 qemu-system-x86_64 \
    -M microvm -cpu max -m 128M \
    -kernel "$KIMG" \
    -nodefaults -no-user-config -nographic \
    -serial file:serial-x86.log \
    -no-reboot || true
grep -q 'hello from rust_main' serial-x86.log \
    && echo 'M0 x86_64: PASS' || { echo 'M0 x86_64: FAIL'; exit 1; }
```

* `microvm` keeps its ISA serial (COM1 @ `0x3F8`) on by default; `-serial file:`
  routes it to the log. Source: QEMU microvm doc.
* `-no-reboot` makes a guest triple-fault terminate QEMU instead of looping
  (harmless here since we just `hlt`).

Interactive variant (watch the marker live): replace `-serial file:serial-x86.log`
with `-serial stdio`.

### aarch64 (QEMU `virt`, PL011 UART0 @ `0x0900_0000`)

```bash
KIMG=target/aarch64-yuva-none/release/yuva-kernel
timeout --foreground 30 qemu-system-aarch64 \
    -M virt -cpu max -m 128M \
    -kernel "$KIMG" \
    -nographic \
    -serial file:serial-arm.log \
    -no-reboot || true
grep -q 'hello from rust_main' serial-arm.log \
    && echo 'M0 aarch64: PASS' || { echo 'M0 aarch64: FAIL'; exit 1; }
```

* `qemu-system-aarch64 -M virt -kernel <ELF>` enters at **EL1** (default: no
  `virtualization=on`, no `secure=on`) with `x0` = DTB, MMU off — exactly the
  boot contract. UART0 is the board PL011 @ `0x0900_0000`; `-serial file:`
  attaches to it.

### Both at once

```bash
cargo kbuild --release --target targets/x86_64-yuva-none.json
cargo kbuild --release --target targets/aarch64-yuva-none.json
# then run the two assert blocks above. CI requires BOTH to print PASS.
```

DoD is met when **both** arches print `hello from rust_main` (KERNEL-FOUNDATION-
SPEC.md §8–9, milestone M0). Firecracker is the secondary M0 channel: it boots
the same x86_64 PVH ELF (selected by the PHYS32_ENTRY note) — wired up in a later
step once the QEMU path is green.

---

## 8. Sources

* Xen “x86/HVM direct boot ABI” (PVH, PHYS32_ENTRY note, `%ebx`→start_info,
  cr0=PE): <https://xenbits.xen.org/docs/unstable/misc/pvh.html>
* `hvm_start_info` layout + `magic 0x336ec578`:
  <https://xenbits.xen.org/gitweb/?p=xen.git;a=blob_plain;f=xen/include/public/arch-x86/hvm/start_info.h;hb=HEAD>
* Minimal Rust Kernel (custom target spec, build-std, compiler-builtins-mem,
  json-target-spec, runner): <https://os.phil-opp.com/minimal-rust-kernel/>
* Embedonomicon, custom target + build-std:
  <https://docs.rust-embedded.org/embedonomicon/custom-target.html>
* Cargo unstable `build-std`:
  <https://doc.rust-lang.org/cargo/reference/unstable.html#build-std>
* QEMU `microvm` machine (ISA serial, `-kernel`, `-no-reboot`):
  <https://www.qemu.org/docs/master/system/i386/microvm.html>
* Arm PrimeCell PL011 TRM DDI0183 (`UARTDR`@0x00, `UARTFR`@0x18, FR.TXFF=bit5).
* 16550 UART register map (THR@0, LSR@5, LSR.THRE=bit5); e.g. TI PC16550D.
* Repo-internal verification: `docs/research/raw/kernel-asm-verified.json`,
  `docs/KERNEL-FOUNDATION-SPEC.md`.
