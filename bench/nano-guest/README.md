# Axis-A nano-guest — pure VMM-spawn benchmark payload

The **nano-guest** is a trivial dual-note PVH + tb-boot "signal-and-halt" ELF,
booted by **both** Firecracker (via PVH) **and** tb-vmm (via tb-boot v0) from
**one binary**, so the host-observed `spawn -> first-guest-byte` delta isolates
**pure VMM-spawn overhead** (KVM open + VM create + irqchip + guest-RAM
mmap/memslots + vCPU create + boot-state/sregs/regs setup + first-exit
dispatch). The guest does ~zero, byte-identical work under each ABI — it emits
one serial byte and parks — so the delta *is* the VMM-spawn difference.

This replaces the OLD bench.yml "Axis A" row, which compared
tb-vmm-boots-Yuva against FC-boots-a-real-Linux-kernel (two *different*
guests) — the forbidden apples-to-oranges. Axis-A here removes that confound
with one common nano-guest. See `docs/BENCHMARKS.md` §1-§7.

## Strategy A (chosen): one common dual-note binary

Proven feasible because the existing `tabos-kernel` ELF already boots under
both VMMs from a single image. The nano-guest is that same skeleton stripped to
nothing:

- `nano-guest.S` — the single source of truth. Two ELF notes in one `PT_NOTE`
  phdr + two entry stubs:
  - `.note.Xen` — `XEN_ELFNOTE_PHYS32_ENTRY` (type **18**, name `"Xen"`,
    desc = the 32-bit PVH entry `pvh_start`). Firecracker's `linux-loader`
    auto-selects PVH **solely** from this note — no config flag needed.
  - `.note.TABOS` — type **0x54420001**, name `"TABOS"`, desc = the 64-bit
    entry `tb_start`. tb-vmm's loader **requires** this note (it rejects any ELF
    lacking it: `LoaderError::MissingTbNote`) and never uses `e_entry`.
  - `pvh_start` (`.code32`): Firecracker enters here in 32-bit protected mode,
    paging off, `ebx -> hvm_start_info`, eax ignored. It does `cli; out 0x3f8,al
    ('A'); hlt` — one COM1 sentinel byte, then park. No GDT/paging/stack.
  - `tb_start` (`.code64`): tb-vmm enters here in 64-bit long mode, paging
    already on, `rdi -> TbBootInfo*`. It does the **same** `out 0x3f8,al ('A')`
    (the fair, host-timed event) **and** latches tb-vmm's native `out 0x510,al`
    BootReady clock (the in-process cross-check; FC has no 0x510 equivalent, so
    it is never the ratio source), then `hlt`.
- `nano-guest.ld` — a minimal clone of `kernel/linker/x86_64.ld`: the two notes
  in one `PT_NOTE` phdr + one text `PT_LOAD`, `ET_EXEC`, vaddr == paddr, loaded
  at **1 MiB** (== Firecracker `HIMEM_START` == tb-vmm load addr). No
  `.data`/`.bss`/page-tables/stack (neither stub calls anything).

Why not a single shared entry: the two ABIs are incompatible at the instruction
level (FC enters in 32-bit protected mode paging-off; tb-vmm in 64-bit long
mode). Apples-to-apples needs the **same binary + an identical workload**, not
one instruction stream. Both stubs do the identical minimal thing (one I/O
write + hlt); the 2-vs-~20-byte mode-specific glue is the irreducible ABI floor,
far below the VMM-spawn signal.

## Build

**Canonical (CI + any host) — clang + ld.lld, no nightly:**

```sh
bench/nano-guest/build.sh [OUT_ELF]   # default OUT_ELF = bench/nano-guest/nano-guest.elf
```

Assembles `nano-guest.S` with `clang --target=x86_64-unknown-none` and links it
with `ld.lld -T nano-guest.ld`. Deterministic; the bench lane uses this.

**Equivalent nightly path — reuses the kernel `-Zbuild-std` toolchain:**

```sh
cd bench/nano-guest && cargo nbuild --release   # see .cargo/config.toml
```

`src/main.rs` embeds `nano-guest.S` byte-for-byte via
`global_asm!(include_str!())`. Note: run from a context where the repo-root
`.cargo/config.toml` does not also inject `-Tkernel/linker/x86_64.ld` (the CI
lane sidesteps this by using `build.sh`). This crate is its **own nested
workspace** (excluded from the root), so it never cross-contaminates the kernel
build-std settings, and — being **not** the `kernel`/`tb-hal` crate — its hand
assembly is allowed without touching the framekernel "zero real unsafe in the
kernel crate" invariant.

## Well-formedness (verified)

`llvm-readelf` on the built ELF:

```
Type: EXEC (ET_EXEC)   Machine: EM_X86_64   Entry: 0x100030 (= pvh_start)
Program Headers:
  NOTE  ... 0x100000  R    align 4   -> .note.Xen .note.TABOS
  LOAD  ... 0x100000  R E            -> .note.Xen .note.TABOS .text
Notes:
  .note.Xen   : type 0x12 (=18)        desc = 30 00 10 00          -> pvh_start = 0x100030
  .note.TABOS : type 0x54420001        desc = 3b 00 10 00 00 00 00 00 -> tb_start = 0x10003b
```

So Firecracker reads `.note.Xen`/0x100030 and tb-vmm reads `.note.TABOS`/
0x10003b — each from the SAME 4848-byte binary. tb-vmm accepts the path/ELF and
proceeds to KVM (local boot needs `/dev/kvm`; the numbers come from CI).

## FC config

`fc-axisA-config.json` is a template with **only** a boot-source (no drives, no
net, no vsock) pointing at the nano-guest ELF; FC auto-selects PVH from the Xen
note. The bench lane substitutes the absolute ELF path into
`NANO_GUEST_ELF_PATH` before launch.

## Measurement (CI bench lane)

`N=30` boots per VMM on the same KVM runner. For each boot: `t0 = date +%s%N`
just before spawning the VMM; poll the VMM's stdout log until non-empty (the
first COM1 sentinel byte); `t1 = date +%s%N`; `delta = t1 - t0`. Identical poll
for both VMMs. Per VMM: median / p99 / min. **Headline = the same-runner ratio**
`FC_median / tbvmm_median` (the only fair cross-system number). tb-vmm's native
`--report-spawn spawn-ready-ns=` (the 0x510 clock) is reported as an
informational cross-check, never as the ratio numerator/denominator.

## Honest framing (carried into the step summary)

- Absolute ms are **runner-relative** (nested-virt shared GitHub runner); only
  the tb-vmm/FC **ratio on the same runner** is the fair claim.
- This is the TRUE apples-to-apples Axis-A: one common nano-guest, ~zero
  identical work, modulo the irreducible 32-bit-PVH vs 64-bit-long-mode entry
  floor. **Never** reintroduce a "0.5 ms vs 103/125 ms" headline — that is FC
  booting a real Linux kernel (Axis-C, a different guest OS), not VMM spawn.
- We do **not** claim to beat the shared KVM floor (world-switch, EPT, vCPU
  bring-up are host-KVM-bound and inherited by any guest); Axis-A measures the
  userspace-VMM spawn path on top of that shared floor.

## Strategy B (documented fallback)

If a single ELF ever fails to satisfy both loaders simultaneously, build two
equivalent-minimal binaries from the SAME `nano-guest.S` by selecting one note +
one stub each (the other loader's note/stub gc'd), then soften the claim to
"equivalent-minimal guests (each the smallest signal-and-halt payload for its
VMM's ABI)" and state plainly it is two binaries. The existing dual-booting
`tabos-kernel` makes this unnecessary, and the verified single ELF above
confirms Strategy A holds.
