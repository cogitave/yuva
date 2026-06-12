# tb-vmm — Yuva sovereign userspace VMM (the L1 rung)

> **What this is.** `tb-vmm` is Yuva's own thin **userspace** virtual-machine
> monitor. It boots the **same** `tabos-kernel` ELF that QEMU boots — but over
> the host's `/dev/kvm`, through Yuva's **own** boot contract (`tb-boot v0`),
> entering the guest **directly in 64-bit long mode**. On this path there is
> **no PVH ELF note** and **no `A0` 32→64 trampoline**: the bootstrap-OS boot
> protocol is deleted and replaced by a contract Yuva owns end-to-end.
>
> This is the **L1** step of the sovereignty ladder
> ([SOVEREIGNTY-ROADMAP §1, §7](../docs/SOVEREIGNTY-ROADMAP.md)). `tb-vmm` is a
> `std` Linux x86_64 binary and is **explicitly OUTSIDE** the framekernel's
> `#![forbid(unsafe_code)]` boundary — it is its own audited-unsafe domain, not
> part of the sovereign kernel.

---

## 1. Why this exists — L1 sovereignty (and its honest limits)

The sovereignty ladder (full detail in
[SOVEREIGNTY-ROADMAP](../docs/SOVEREIGNTY-ROADMAP.md)):

| Rung | What Yuva owns | Still trusts |
|---|---|---|
| **L0** (was) | nothing below the guest boundary | host Linux + KVM + a stock VMM (QEMU/Firecracker) |
| **L1** (this) | the **boot contract** + the **machine/device model** (`tb-vmm` + `tb-boot v0`) | host Linux **+ KVM** (world switch, EPT, vCPU scheduling, IRQ routing) |
| **L2** (`tb-core`) | the virtualization layer itself (VMX/SVM/EL2 + stage-2 + IOMMU + scheduling), **no host kernel** | firmware floor only |

**L1 honesty.** Owning `tb-vmm` wins a sovereign **boot contract and device
model** — *not* independence from Linux. The CPU world switch (VMX/SVM),
second-stage paging, vCPU scheduling and physical-interrupt routing still belong
to host **KVM**. Removing that host kernel from the trusted computing base is the
**L2** jump (`tb-core`). We state this plainly and do not promise more.

What L1 concretely buys us:

* **A boot ABI we own** (`tb-boot v0`) instead of inheriting Xen's PVH.
* **A device model we own** (an extensible PIO/MMIO bus; today a 16550A UART),
  the seam where virtio lands later.
* The natural **"no guest kernel" micro-VM shape** for the agent model: the
  framekernel *is* the guest, entered cold in long mode.

---

## 2. `tb-boot v0` ABI

`tb-boot` is a shared crate (`crates/tb-boot`), `#![no_std]` +
`#![forbid(unsafe_code)]`, depended on by **both** `tb-vmm` (the producer) and
the kernel (the consumer). It defines the hand-off structures and the ELF note
that lets `tb-vmm` discover the kernel's 64-bit entry.

### 2.1 Hand-off structures (`#[repr(C)]`)

```rust
pub const TB_BOOT_MAGIC: u64 = 0x3056_544F_4F42_5400;
pub const TB_BOOT_VERSION: u32 = 0;

#[repr(C)]
pub struct TbBootInfo {
    pub magic: u64,            // == TB_BOOT_MAGIC
    pub version: u32,          // == TB_BOOT_VERSION
    pub flags: u32,
    pub mem_regions_ptr: u64,  // guest-physical ptr to TbMemRegion[]
    pub mem_regions_len: u64,  // element count
    pub cmdline_ptr: u64,      // guest-physical ptr to NUL-free cmdline bytes
    pub cmdline_len: u64,
    pub kernel_entry: u64,     // 64-bit entry (mirrors the TABOS note desc)
}

#[repr(C)]
pub struct TbMemRegion {
    pub base: u64,
    pub len:  u64,
    pub kind: u32,             // Ram = 1, Reserved = 2
    pub _pad: u32,
}
```

`tb-vmm` writes one `TbBootInfo`, the `TbMemRegion[]` array and the cmdline bytes
into guest RAM, then passes the **guest-physical** address of the `TbBootInfo` to
the kernel in `rdi` (SysV arg0). The kernel uses `tb-boot`'s **safe**
reader/validator to confirm `magic`/`version` before trusting any field — and,
crucially, if the magic does **not** validate (e.g. a PVH `hvm_start_info`
pointer arrived via the QEMU path), the kernel simply **ignores** it. A PVH
pointer is therefore never misread as a `TbBootInfo`.

### 2.2 The `TABOS` ELF note (entry discovery)

So `tb-vmm` can find the kernel's 64-bit entry from the ELF — exactly mirroring
how PVH advertises its 32-bit entry via `XEN_ELFNOTE_PHYS32_ENTRY` — the kernel
emits a second `PT_NOTE`:

```rust
pub const TB_NOTE_NAME: &str = "TABOS";
pub const TB_NOTE_TYPE_ENTRY64: u32 = 0x5442_0001; // desc = u64 = _tb_start addr
```

**Byte layout** (standard ELF `Nhdr` + padded name + padded desc, little-endian):

```
offset  size  field      value
  0      4    n_namesz   6            (len("TABOS") + 1 NUL)
  4      4    n_descsz   8            (one u64)
  8      4    n_type     0x54420001   (TB_NOTE_TYPE_ENTRY64)
 12      6    name       'T''A''B''O''S' 0x00
 18      2    (pad)      0x00 0x00     (name padded to 4-byte multiple)
 20      8    desc       u64 LE = guest-physical address of _tb_start
```

Total note body = 28 bytes. This is the byte-for-byte analogue of the Xen PVH
note (name `"Xen\0"`, `n_namesz=4`, `n_type=18`, 4-byte `desc`), so the kernel
ELF can carry **both** notes and the right loader picks the right one:

* **QEMU** (`-kernel`) selects **PVH** by the `XEN_ELFNOTE_PHYS32_ENTRY` note →
  32-bit entry → `A0` trampoline. *(unchanged; M0–M4 stay green)*
* **`tb-vmm`** reads the **`TABOS`** note → 64-bit entry (`_tb_start`) →
  long-mode entry. If the note is missing, `tb-vmm` falls back to the ELF
  `e_entry`.

---

## 3. x86_64 long-mode boot setup (verified Firecracker constants)

Before the first `KVM_RUN`, `tb-vmm` builds the minimal long-mode environment in
guest RAM and programs the vCPU. Every constant below is taken from the
Firecracker **direct-to-64-bit (`LinuxBoot`)** path, cited per line. Firecracker
files: `src/vmm/src/arch/x86_64/regs.rs` and `…/gdt.rs`.

### 3.1 Guest memory

`vm-memory` `GuestMemoryMmap` backs the guest; each region is registered with
`KVM_SET_USER_MEMORY_REGION` (`VmFd::set_user_memory_region`). RAM size is
`--mem-mb` (default 256 MiB), described back to the guest as a `TbMemRegion`
(`kind = Ram`).

### 3.2 Flat long-mode GDT (`gdt.rs`)

Firecracker builds 4 entries via `gdt_entry(flags, base, limit)` and converts
them with `kvm_segment_from_gdt`. The **`LinuxBoot`** table
(`configure_segments_and_sregs`):

| Selector | `gdt_entry(...)` | Meaning | In-RAM qword |
|---|---|---|---|
| `0x00` NULL | `gdt_entry(0, 0, 0)` | null | `0x0` |
| `0x08` CODE | `gdt_entry(0xa09b, 0, 0xfffff)` | 64-bit code, **L=1**, present, DPL0, access `0x9b` | `0x00af_9b00_0000_ffff` |
| `0x10` DATA | `gdt_entry(0xc093, 0, 0xfffff)` | flat data RW, access `0x93` | `0x00cf_9300_0000_ffff` |
| `0x18` TSS  | `gdt_entry(0x808b, 0, 0xfffff)` | 64-bit TSS, access `0x8b` | `0x008f_8b00_0000_ffff` |

Written at `BOOT_GDT_OFFSET = 0x500`; `sregs.gdt.base/limit` point at it (IDT a
bare zero-limit table at `0x520`). *(The access bytes are Firecracker's exact
`0x9b`/`0x93`/`0x8b`; the only bit that differs from a textbook `0x9a`/`0x92` is
the **Accessed** bit, which Firecracker pre-sets — we obey the source.)*

### 3.3 Identity page tables (`regs.rs::setup_page_tables`)

PML4 → PDPTE → PDE, **2 MiB pages**, identity-mapping VA `[0, 1 GiB)` — enough to
cover the kernel (linked at **1 MiB**), the `tb-boot` structures and the early
stack:

```
PML4 @ 0x9000:  [0] = 0xa000 | 0x03            (present|rw -> PDPTE)
PDPTE @ 0xa000: [0] = 0xb000 | 0x03            (present|rw -> PDE)
PDE  @ 0xb000:  [i] = (i << 21) + 0x83  for i in 0..512   (present|rw|PS, 2 MiB)
```

### 3.4 `KVM_SET_SREGS` (`regs.rs::configure_segments_and_sregs` + `setup_page_tables`)

```
cr0  |= PE (0x1) | PG (0x8000_0000)
cr4  |= PAE (0x20)
efer |= LME (0x100) | LMA (0x400)
cr3   = 0x9000                 (PML4 guest-physical)
cs    = 64-bit code segment    (base 0, limit 0xfffff, L=1, present, DPL0)
ds/es/fs/gs/ss = flat data segment
gdt.base/limit set as in §3.2
```

### 3.5 `KVM_SET_REGS` (`regs.rs::setup_regs`) — our one deviation

```
rflags = 0x2                   (Firecracker LinuxBoot value)
rip    = the kernel's 64-bit tb-boot entry (TABOS note desc; else e_entry)
rdi    = guest-physical TbBootInfo address   (SysV arg0)
rsi    = 0
rsp    = top of a reserved boot stack         (courtesy; see note)
```

**Deviation from Firecracker `LinuxBoot`:** Firecracker targets the Linux 64-bit
boot protocol, so it sets `rsi = ZERO_PAGE_START` (boot_params) and
`rsp/rbp = BOOT_STACK_POINTER`. Yuva does **not** use the Linux boot protocol:
the kernel entry is a Rust `extern "C" fn rust_main(boot_info: usize)`, so we use
the **SysV C ABI** — `rdi = TbBootInfo*`, `rsi = 0`. The kernel's `_tb_start`
establishes its own `RSP` (a reserved 64-bit boot stack) before calling
`rust_main` with `rdi` unchanged, so stack ownership is the kernel's; `tb-vmm`
only seeds a sane value.

> Sources (fetched 2026-06-07):
> Firecracker `src/vmm/src/arch/x86_64/regs.rs` — `configure_segments_and_sregs`
> (`X86_CR0_PE=0x1`, `X86_CR0_PG=0x8000_0000`, `X86_CR4_PAE=0x20`,
> `EFER_LME=0x100`, `EFER_LMA=0x400`, `BOOT_GDT_OFFSET=0x500`), `setup_page_tables`
> (`PML4_START=0x9000`, `PDPTE_START=0xa000`, `PDE_START=0xb000`, PDE entry
> `(i<<21)+0x83`), `setup_regs` (`rflags=0x2`); and `…/gdt.rs`
> (`gdt_entry`, `kvm_segment_from_gdt`). KVM struct layout: KVM API doc,
> `KVM_SET_SREGS`/`KVM_SET_REGS`/`KVM_SET_USER_MEMORY_REGION`
> (docs.kernel.org/virt/kvm/api.html).

---

## 4. Architecture (clean arch seam)

```
tb-vmm/
  src/
    main.rs        CLI parse -> Config -> Vmm::run(); maps exit codes
    config.rs      validated VmmConfig (kernel path, mem-mb, flags) -- pure, unit-tested
    vmm.rs         Vmm: owns Kvm/VmFd/VcpuFd + GuestMemoryMmap + DeviceBus; the KVM_RUN loop
    arch/
      mod.rs       trait BootArch (boot-time vCPU/memory setup) -- the arch seam
      x86_64/
        boot.rs    GDT + identity PTs + SREGS/REGS (the §3 constants)
        layout.rs  guest-RAM layout constants (GDT/PT/bootinfo/stack offsets)
    loader.rs      ELF64 PT_LOAD copy to p_paddr + TABOS-note entry discovery (pure, unit-tested)
    boot_params.rs serialize TbBootInfo + TbMemRegion[] + cmdline into guest RAM (pure, unit-tested)
    devices/
      bus.rs       trait Device + PIO/MMIO registry (extensible -> virtio later)
      serial.rs    16550A UART @ 0x3F8 -> VMM stdout (+ stdin)
    exit.rs        VcpuExit handling + VM-exit diagnostics
```

* **Error handling:** the boot path returns `Result` with a typed error enum
  (`thiserror`-style); **no `unwrap`/`expect` on the boot path**. VM-exit
  failures (`FailEntry`, `InternalError`) dump exit reason + `rip` + `sregs`.
* **`unsafe`:** confined to the few real FFI spots (raw guest-memory slice for
  KVM dirty-log / mmap edges), each isolated and commented. `tb-vmm` is allowed
  unsafe — it is **not** the framekernel.
* **Arch seam:** all x86_64-specific setup lives behind `trait BootArch`;
  aarch64 is a documented follow-up (§8), not an `#[cfg]` afterthought.

---

## 5. The `KVM_RUN` loop & exit handling

`VcpuFd::run()` returns a `VcpuExit`; `tb-vmm` handles the relevant reasons
(kvm-ioctls `VcpuExit` variants):

| Exit | Handling |
|---|---|
| `IoIn` / `IoOut` (`KVM_EXIT_IO`) | dispatch to the **PIO** device bus (serial `0x3F8` → stdout / stdin) |
| `MmioRead` / `MmioWrite` (`KVM_EXIT_MMIO`) | dispatch to the **MMIO** device bus |
| `Hlt` (`KVM_EXIT_HLT`) | the kernel halts after M4 → **clean stop**, exit 0 |
| `Shutdown` (`KVM_EXIT_SHUTDOWN`) | guest triple-fault / reset → stop with diagnostics |
| `FailEntry` / `InternalError` | **dump** hardware exit reason + `rip` + full `sregs`, then fail |
| others | logged; loop continues or stops per policy |

A **wall-clock guard** bounds the run so a hung guest cannot loop forever (CI
adds an outer `timeout` as well). PASS is judged by the serial marker
`M4: user/ring OK`, exactly like `scripts/run-x86_64.sh`.

---

## 6. Devices

A `DeviceBus` exposes a `trait Device { fn read(..); fn write(..) }` registered
over **PIO** and **MMIO** address ranges — the extension point for virtio later
(per the roadmap we deliberately do **not** pull in rust-vmm's virtio stack for
L1; one console is enough for M0–M4 parity).

The one device today is a **16550A UART at I/O port `0x3F8`** (COM1): guest
writes to THR are streamed to `tb-vmm`'s **stdout** (so CI can `grep` the marker),
and host stdin is fed to the UART RX. It can be the minimal hand-rolled 16550 or
`vm-superio`'s `Serial`.

---

## 7. Build & run

**Crates:** `kvm-ioctls 0.24.x`, `kvm-bindings 0.14.x` (the versions Firecracker
pins), `vm-memory`, `vmm-sys-util`, optionally `goblin` for ELF parsing.
`tb-vmm` is `std`; it prefers the safe `vm-memory` APIs and isolates any real
unsafe.

Requires a Linux host with a usable **`/dev/kvm`**.

```sh
# 1) Build the kernel ELF (custom target; carries BOTH the PVH and TABOS notes).
#    From the repo root (the .cargo/config.toml wires -Zbuild-std; see BUILD.md):
cargo build -p tabos-kernel --target targets/x86_64-tabos-none.json
#    -> target/x86_64-tabos-none/debug/tabos-kernel

# 2) Build tb-vmm for the HOST. It is a std binary and must be insulated from the
#    kernel's tree-wide -Zbuild-std; an empty CARGO_UNSTABLE_BUILD_STD overrides it:
CARGO_UNSTABLE_BUILD_STD= cargo build -p tb-vmm --target x86_64-unknown-linux-gnu
#    -> target/x86_64-unknown-linux-gnu/debug/tb-vmm

# 3) Make /dev/kvm usable for your user if needed (group perms):
#      sudo chmod 0666 /dev/kvm        # quick
#    or the persistent udev rule (see CI).

# 4) Boot the kernel through tb-vmm via tb-boot v0 (NO PVH, NO A0 trampoline):
./target/x86_64-unknown-linux-gnu/debug/tb-vmm \
    --kernel target/x86_64-tabos-none/debug/tabos-kernel \
    --mem-mb 256 --print-exit
# Expect the full M0..M4 serial output, ending in:  M4: user/ring OK
```

### CLI

| Flag | Default | Meaning |
|---|---|---|
| `--kernel <path>` | `target/x86_64-tabos-none/debug/tabos-kernel` | kernel ELF to boot (required in practice) |
| `--mem-mb <N>` | `256` | guest RAM in MiB |
| `--print-exit` | off | print the final VM-exit reason (`rip`/`sregs` on failure) |

### CI

The **`vmm-boot`** GitHub Actions job ([`ci-vmm-boot.snippet.yml`](ci-vmm-boot.snippet.yml))
builds the kernel + `tb-vmm`, makes `/dev/kvm` usable, boots via `tb-boot v0`,
and asserts `M4: user/ring OK`. It **skips with a message** when `/dev/kvm` is
absent (GitHub documents runner nested-virtualisation as experimental / not
officially supported).

---

## 8. aarch64 — documented follow-up

x86_64 is the proven first rung. aarch64 `tb-vmm` is a **documented follow-up**
(the arch seam in `arch/mod.rs` is already there for it). The verified path
([SOVEREIGNTY-ROADMAP §7](../docs/SOVEREIGNTY-ROADMAP.md)):
`VmFd::get_preferred_target()` → `VcpuFd::vcpu_init(&kvi)` (`KVM_ARM_VCPU_INIT`,
`PSCI_0_2`), then `KVM_SET_ONE_REG` with `PSTATE = PSTATE_FAULT_BITS_64` (EL1h,
DAIF masked), `PC = entry`, `X0 = TbBootInfo*` (KVM `core_reg_base =
0x6030_0000_0010_0000`; `PC` at `base + 2*32`). It is heavier than x86 (no
guest-built page tables / GDT; the vCPU-init dance replaces the SREGS setup) and
is sequenced after x86_64 lands — not built to parity up front.

---

## 9. Sources

* Firecracker `src/vmm/src/arch/x86_64/regs.rs` — `configure_segments_and_sregs`,
  `setup_page_tables`, `setup_regs` (long-mode `cr0/cr4/efer/cr3`, page-table
  layout, `rflags`). Fetched 2026-06-07.
* Firecracker `src/vmm/src/arch/x86_64/gdt.rs` — `gdt_entry`,
  `kvm_segment_from_gdt`, the `LinuxBoot` GDT entries. Fetched 2026-06-07.
* KVM API: `KVM_SET_USER_MEMORY_REGION`, `KVM_SET_SREGS`, `KVM_SET_REGS`,
  `KVM_RUN`, `kvm_sregs`/`kvm_regs` layout — docs.kernel.org/virt/kvm/api.html.
* kvm-ioctls: `Kvm::new`, `create_vm`, `set_user_memory_region`,
  `VcpuFd::{set_sregs,set_regs,run}`, `VcpuExit` — docs.rs/kvm-ioctls + the
  rust-vmm/kvm-ioctls README.
* Xen PVH (the contract we replace on this path): `XEN_ELFNOTE_PHYS32_ENTRY`,
  `hvm_start_info` — xenbits.xen.org/docs/unstable/misc/pvh.html.
* Yuva internal: [SOVEREIGNTY-ROADMAP](../docs/SOVEREIGNTY-ROADMAP.md) §1/§3/§7,
  [MILESTONES](../docs/MILESTONES.md), [BUILD](../BUILD.md).
