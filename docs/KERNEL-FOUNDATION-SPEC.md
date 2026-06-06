# TABOS Kernel Foundation & Assembly Spesifikasyonu

> Durum: v1.0 · **Tüm maddeler [KARAR]** — bu döküman bilinçli olarak açık karar içermez (senaryoya kilitli).
> Kapsam: `tb-hal` foundation crate'i — kernel'ın TÜM `unsafe` + TÜM assembly'sinin hapsedildiği katman. Üstündeki her crate `#![forbid(unsafe_code)]`.
> Hedef arch: **x86_64 + aarch64** (Firecracker'ın desteklediği iki arch); riscv64 = gelecek, planlanmadı.
> Dayanak: [SOVEREIGNTY](SOVEREIGNTY.md) (boot/VMM egemenlik kararı) · [LANGUAGE-AND-STANDARDS](LANGUAGE-AND-STANDARDS.md) · [ARCHITECTURE](ARCHITECTURE.md) · Ham veri: [`kernel-asm-research.json`](../research/raw/kernel-asm-research.json) · Doğrulama: [`kernel-asm-verified.json`](../research/raw/kernel-asm-verified.json)
> İlgili: [PROCESS](PROCESS.md) (gate'ler) · [OPEN-QUESTIONS](OPEN-QUESTIONS.md)

---

## 0. Karar Özeti ve Çözülen Çelişki

TABOS kernel'ı **Firecracker/KVM-sınıfı bir VMM üstünde guest olarak** boot eder; bare-metal değil. Bu, agent'a hiçbir şey kaybettirmeden büyük miktarda assembly'yi **siler**. Tüm kalan assembly tek bir `tb-hal` foundation crate'inde, Rust 1.88+ `#[unsafe(naked)]` + `naked_asm!` / `global_asm!` ile yazılır.

**Boot yolu — egemenlik revizyonu** (detay: [SOVEREIGNTY §2](SOVEREIGNTY.md)): Bu döküman önce **LinuxBoot** seçmişti (yalnız trampoline-silme gerekçesiyle). Arda'nın "tamamen kendi yapımız, Linux olmasın" direktifi (2026-06-07) önceliği değiştirdi. **Yeni karar:**
- **Canonical = `tb-boot v0`** — kendi sahiplendiğimiz handoff kontratı, kendi ince VMM'imiz **`tb-vmm`** (rust-vmm tabanlı, tek-vCPU Mirage) üretir; 64-bit long mode'da doğrudan girer → **trampoline yok, Linux yok, Xen yok**.
- **Bootstrap (yalnız M0, geçici) = stock Firecracker + PVH** — Xen-kökenli **nötr** protokol (Linux zero-page değil); `linux-loader` bedava verir. PVH 32-bit girer → küçük **geçici** trampoline `A0` (`tb-vmm` gelince silinir).
- Net: gerçek sistemde hiçbir yer Linux'tan adlandırılmış/şekillendirilmiş değil. (Fallback: trampoline sorun çıkarırsa bootstrap'ta Linux/x86 64-bit protokol — yine ~30 struct alanı, kernel kodu değil.)

---

## 1. `tb-hal` Foundation Crate Sınırı [KARAR]

```
tb-hal/                         # TEK unsafe/asm crate'i; kernel'ın geri kalanı bunun üstünde safe
├── src/lib.rs                  # safe trait Hal + safe wrapper tipleri (TaskContext, TrapFrame, PageTableEntry, Mmio<T>, Port<T>)
├── src/arch/mod.rs             # #[cfg(target_arch)] dispatch
├── src/arch/x86_64/{boot,gdt,idt,trap,switch,mmu}.rs
└── src/arch/aarch64/{boot,vectors,trap,switch,mmu}.rs
```

- **Tek API yüzeyi:** `trait Hal { boot_init, install_traps, context_switch, flush_tlb_page, flush_tlb_all, switch_address_space, serial_putb, ... }` — üst katmanlar yalnız bu safe trait'i görür.
- **CI kapısı (zorunlu):** `tb-hal` dışındaki her crate'te `#![forbid(unsafe_code)]`; `cargo-geiger`/grep ile `unsafe`/`asm!`/`naked_asm!`/`global_asm!`'in foundation dışında **sıfır** olduğu doğrulanır.
- **Toolchain pin:** `rust-toolchain.toml` channel ≥ **1.88.0** (naked function stabilizasyonu — doğrulandı: 2025-06-26 sürümü, `#[unsafe(naked)]` + `naked_asm!`).

## 2. Boot Yolu [KARAR]

| | **x86_64** | **aarch64** |
|---|---|---|
| Imaj formatı | ELF + **PHYS32_ENTRY note VAR** → PVH (bootstrap); canonical `tb-vmm` → `tb-boot` 64-bit direkt | arm64 PE Image (bootstrap compat shim); canonical `tb-boot` |
| Yükleme adresi | 1 MiB (`0x0010_0000`, FC `HIMEM_START`) | DRAM+2 MiB (`0x8020_0000`) |
| vCPU giriş durumu (bootstrap/PVH) | **32-bit protected, paging OFF**, `cr0=PE\|ET`, `%ebx→hvm_start_info` → `A0` trampoline → 64-bit. Canonical `tb-boot`: 64-bit direkt, trampoline yok | **EL1h, MMU OFF**, `PSTATE=0x3c5`; canonical `tb-boot` kendi giriş koşulu |
| Tek boot girdisi | zero page @ RSI; cmdline @ `0x20000` (≤2048B) | FDT (DTB) @ x0 |
| Device discovery | cmdline token: `virtio_mmio.device=<sz>@<base>:<irq>` | FDT walk (memory, GIC, timer, virtio-MMIO, **NS16550A** serial, **PL031** RTC, psci) |

> **Düzeltme (doğrulama):** aarch64 serial = **NS16550A** (FDT `compatible="ns16550a"`), PL011 *değil*; yalnız RTC PrimeCell'dir (PL031). Spec'te buna göre.

**Silinen assembly (bare-metal'e göre):** x86 real→protected→long-mode trampoline, A20 gate, sıfırdan GDT-in-real-mode, CR0.PE flip; BIOS/UEFI firmware + servisleri; ACPI/MPTable enumerasyonu (boot için); PCI bus scan; AP/SMP trampoline (tek-vCPU). Bunların hiçbiri `rust_main`'e ulaşmak için gerekmez.

## 3. Assembly Ünite Envanteri — İzlenebilir WBS Çekirdeği [KARAR]

Her satır bir **izlenebilir iş kalemi**; "asm mı Rust mı" sütunu foundation sınırını çizer. (× = yok/silinmiş)

| # | Ünite | x86_64 | aarch64 | Katman |
|---|---|---|---|---|
| A0 | **(bootstrap-only, MV'de silinir)** PVH 32→64 trampoline | `global_asm!`: 4-entry boot page table, EFER.LME set, CR0.PG, far-jump 64-bit CS (~40 satır) | × (aarch64 PVH yok) | **asm (geçici)** |
| A1 | `_start` boot entry | `global_asm!`: kendi GDT'mizi `lgdt`, CS/segment reload, `rsp←boot stack`, BSS sıfırla, `%ebx/rsi→rdi` shuffle, `call rust_main` | `global_asm!`: `sp←boot stack`, BSS sıfırla, `msr VBAR_EL1`, `isb`, `b rust_main` (x0=FDT korunur) | **asm** |
| A2 | Boot stack + linker sembolleri | `.bss` içinde guard'lı `BOOT_STACK`; `__bss_start/__bss_end`, entry=`_start`, .text@0x100000 | aynı + Image header emit | **asm/linker** |
| A3 | Cooperative context switch | `#[unsafe(naked)] extern "C"`: 6 GPR `{rbx,rbp,r12-r15}` + rsp save/restore; resume stack'ten | `#[unsafe(naked)] extern "C"`: 12 GPR `{x19-x28,x29,x30}` + SP; resume `ret`→x30 | **asm** |
| A4 | Trap/IRQ/exception entry | `global_asm!` `__alltraps`: 15 GPR push → TrapFrame, `mov rdi,rsp`, `call trap_handler`, `iretq`; 256 per-vector thunk (no-errcode'lar dummy 0 push) | `global_asm!` `__alltraps`: x0-x30 + ELR_EL1 + SPSR_EL1 save, `mov x0,sp`, `bl trap_handler`, `eret`; 16×128B VBAR tablosu | **asm** |
| A5 | GDT/IDT vs vector table | `global_asm!`: kalıcı flat 64-bit GDT (null+code 0x9A+data 0x92+TSS) + 256-entry IDT; #DF/NMI/#MC → IST stack | `global_asm!`: 2KB-aligned VBAR_EL1, 16 entry; IST analoğu yok | **asm** |
| A6 | Privileged MMU wrapper'ları | `asm!` `unsafe fn`: `read_cr3/write_cr3/invlpg/cr4_pge_toggle/wrmsr_efer(NXE)/wrmsr_pat` (~6 ünite) | `asm!` `unsafe fn`: `msr_ttbr0/ttbr1/tcr/mair_el1, rmw_sctlr, tlbi(vae1/vale1/vmalle1 ±is), dsb, isb` (~9 ünite) | **asm** |
| A7 | MMU bring-up | × (FC paging'i açık verir; CR3 inherit edilir) | **zorunlu**: MAIR/TCR/TTBR programla → `isb` → SCTLR.M=1 → `isb` (VA==PA penceresi) | **asm** |
| A8 | Page-table ENTRY manipülasyonu | typed `PageTableEntry` üstünde **safe Rust** (PML4/PDPT/PD/PT walk, split/coalesce) | aynı (VALID/AP/AF/SH/UXN/PXN bitleri) | **safe Rust** |
| A9 | TLB invalidation | `invlpg [addr]` (self-ordering) | `dsb ishst; tlbi vale1is,Xt; dsb ish; isb` (4-instr template) | **asm** |
| A10 | Serial debug (erken) | `Port<u8>` 0x3F8 (`out`/`in`) | `Mmio<u8>` NS16550A @ FDT base | **asm wrapper** |
| A11 | Privileged tek-satırlar | `cli/sti/hlt/lidt/lgdt/ltr/rdmsr/wrmsr` | `wfi/wfe/dsb/isb/msr/mrs` | **asm wrapper** |
| A12 | **(v2-reserved)** user/ring boundary | `swapgs`+`STAR/LSTAR/SFMASK`+`syscall/sysretq`+TSS.rsp0 | EL0 entry (Lower-EL slot)+`SP_EL0` banking+`svc/eret` | **asm (v1'de YOK)** |
| A13 | **(silinmiş)** AP/SMP bringup | INIT-SIPI-SIPI + real-mode trampoline | PSCI CPU_ON HVC | **× (tek-vCPU)** |

## 4. ABI / Register Setleri (context-switch + trap'in uyacağı) [doğrulandı: 2-0]

- **x86_64 System V:** callee-saved `{rbx, rbp, rsp, r12, r13, r14, r15}`; caller-saved `{rax, rcx, rdx, rsi, rdi, r8-r11}`; arg sırası `rdi, rsi, rdx, rcx, r8, r9`; dönüş `rax(/rdx)`. **DF (direction flag) çağrı giriş/çıkışında temiz**; `call`'dan hemen önce **RSP 16-byte aligned** (handler girişinde RSP%16==8); 128-byte **red zone** kaldırılır (`x86_64-unknown-none` hedefi).
- **aarch64 AAPCS64:** callee-saved `x19-x28, x29(FP), SP`; caller-saved `x0-x18`; arg `x0-x7`; dönüş `x0(/x1)`. SIMD: `v8-v15`'in **yalnız alt 64-bit'i** callee-saved (v1'de FP kapalı). **SP mod 16 == 0** tüm public arayüzlerde.
- **Cooperative switch register farkı:** x86 6 GPR vs aarch64 12 GPR (AAPCS64 daha çok callee-saved tutar); aarch64'te resume adresi **register'da** (x30/LR), x86'da **stack'te** → LR explicit banklanır.
- **FP/SIMD politikası [KARAR]:** v1'de **sıfır FP/SIMD**. Hedefler: `x86_64-unknown-none` (SSE/AVX kapalı, red zone yok) + `aarch64-unknown-none-softfloat` (NEON kapalı). TrapFrame'de xmm/v-register alanı yok. (Lazy-FP trap, user FP thread'leri kabul edilince v2'de capability-kapılı.)

## 5. Trap / Privilege Modeli [KARAR]

- **v1 tek ayrıcalık seviyesi:** TÜM scheme daemon'ları imaj-içi, tek adres uzayında, **ring0/EL1 safe Rust** çalışır. Ring3/EL0 donanım-userspace sınırı **v2'ye ertelenmiş, isimlendirilmiş work-unit** (A12) — v1 fault yolu hiç dokunmadan v2 bunu açar. x86'da EFER.SCE/STAR/LSTAR/SFMASK/swapgs **yok**; aarch64'te yalnız "Current EL with SPx" vektör çeyreği canlı.
- **Cause decode asm'de DEĞİL:** entry stub yalnız marshal/call/restore yapar. x86: handler asm-push'lanan vector index + CPU error code okur. aarch64: handler **ESR_EL1.EC+ISS** okur (stub yalnız slot'u `mov x0,#src; movk` ile kodlar). İki arch tek Rust dispatch fonksiyonunda buluşur.
- **Capability check tamamen safe-Rust handler'da** — asm'de hiç karşılaştırma/tablo-walk/privilege mantığı yok. v1'de capability invocation, unforgeable bir capability-token tipiyle korunan sıradan safe-Rust çağrısıdır.

## 6. MMU asm-vs-Rust Sınırı [KARAR]

- **Privileged register yazma + TLB maintenance + barrier'lar = asm** (A6/A7/A9). **Page-table kurma/walk = safe Rust** (A8) — `asm!` burada görünürse CI lint'i kırılır.
- **x86_64:** FC boot page-table'ını CR3'ten **inherit** et (Asterinas `BootPageTable::from_current_pt`); higher-half + 4KiB map'leri Rust'ta kur. Boot'ta **WRMSR EFER.NXE + IA32_PAT** programla (FC yapmaz) — NX biti / cache policy için.
- **aarch64:** MMU **soğuk** gelir → A7 bring-up zorunlu (MAIR/TCR/TTBR → `isb` → SCTLR.M=1 → `isb`). Canlı bir valid descriptor'ın OA/attr'ı değişiyorsa **Break-Before-Make** zorunlu (invalid store → TLBI+barrier → yeni descriptor → barrier).
- **Barrier'lar:** sıradan ordering `core::sync::atomic` (Release/Acquire PTE publish, `fence`); ham `dsb/isb/mfence` yalnız arch-zorunlu yerlerde (TTBR/MAIR sonrası). Tek-vCPU olduğumuz için TLBI'da inner-shareable yerine **local (non-IS)** varyant yeterli olabilir — ölçümle (M3 DoD).

## 7. Assembly'ye Uygulanan Standartlar [KARAR]

- **Ferrocene kapsamı [doğrulandı çıkarım]:** inline asm + naked function'lar Ferrocene **normatif qualified subset'in DIŞINDA** → bu **izlenen bir kısıt**: her asm ünitesi Ferrocene Safety Manual §9 unsafe-disiplinine tabi (ekstra manuel review + test). Safe Rust katmanı qualified subset içinde kalır.
- **Her asm ünitesinde zorunlu 3-parçalı header:** (a) pre/postcondition contract yorumu, (b) clobber+ABI annotasyonu (`clobber_abi`, explicit clobber'lar, FLS hard kuralları), (c) eşli test referansı (M-gate).
- **İki-fazlı erken boot:** **Faz 0** (`_start`'tan SP+BSS hazır olana dek) yalnız spin (`hlt`/`wfe`) + tek ham UART byte; **TigerStyle `assert!()` Faz 1'e kadar YASAK** (stack/serial yok). Faz 1'den sonra fonksiyon başına ≥2 assertion (TigerStyle).
- **Unsafe/asm CI bütçesi:** foundation'daki `unsafe` blok + asm statement-line sayısı commit'li bir bütçe dosyasına karşı sayılır (Asterinas/VeriSMo "31 satır" disiplini); aşım merge'i bloklar.
- **Reproducible build:** tek rustc + Nix flake; TÜM asm in-language (`naked_asm!`/`global_asm!`, harici `.S` yok → ayrı assembler pin'lemeye gerek yok); bit-reproducibility doğrulanır.
- **Layout/ABI const-assert:** struct offset'leri, GDT/IDT descriptor değerleri, page-table bit pozisyonları, UART register offset'leri **compile-time const assertion** — drift **derlemeyi** kırar, boot'u değil.

## 8. Test Gate'leri — Her Asm Ünitesinin "Done" Tanımı [KARAR]

- **İki tier:** (a) host `cargo test` ile safe-Rust katmanı (capability algebra, page-table index/permission matematiği, scheduler); (b) on-target custom runner (phil-opp deseni: `Testable` trait, per-test serial `name ... [ok]`, platform exit device'a pass/fail yaz + halt) — **linker-section ile dağıtık test kaydı**.
- **Boot bring-up = `_start`'ın executable DoD'si:** no_std imaj QEMU `microvm`(x86)/`virt`(aarch64) altında boot eder, `hello from rust_main` serial satırı assert edilir.
- **Context-switch canary testi (A3 DoD):** iki kernel task ≥1000 kez yield eder; (a) deterministik A,B,A,B alternasyonu + (b) her callee-saved register'a önceden yüklenen unique sentinel switch'ten **sağ çıkar**.
- **Trap testi (A4/A5 DoD):** (a) `int3`/`brk #0` → handler çalıştı + devam etti; (b) kasıtlı fault (unmapped write / `udf`) → doğru fault info ile handler.
- **Fail-closed exit channel + 60s wall-clock timeout:** serial scraping'e ek deterministik VM-exit STATUS (x86: `isa-debug-exit`/port; aarch64: PSCI `SYSTEM_OFF`/semihosting).
- **CI matrisi:** {x86_64, aarch64} × {QEMU primary, Firecracker secondary}; merge **her iki arch'ta** yeşil olmadan geçmez. Her `#[cfg(target_arch)]` split iki arch'ta da test'li olmalı.
- **Formal kapsam:** Kani/Verus yalnız **safe Rust'a** (page-table aritmetiği, address-translation round-trip, capability-derivation monotonisitesi, bitflag well-formedness); ham asm **test-covered** kalır (formal değil).

## 9. Milestone WBS — Takip Omurgası [KARAR]

Faz-1 kernel foundation'ı 5 milestone; her biri yukarıdaki asm ünitelerine ve executable DoD'lere bağlı. **Ultracode bu omurgayı izler.**

| Milestone | Kapsam (asm üniteleri) | Executable DoD |
|---|---|---|
| **M0 — Boot bring-up** | A0(x86 bootstrap), A1, A2, A10, A11 (her iki arch) | `hello from rust_main` serial; stock Firecracker **+ PVH** & QEMU, iki arch yeşil |
| **M1 — Trap'ler** | A4, A5 + Rust dispatch | `int3`/`brk` + fault testleri geçer; ESR/error-code doğru |
| **M2 — Context switch** | A3 + scheduler iskeleti | 1000-yield canary + register-sentinel testi |
| **M3 — MMU** | A6, A7, A8, A9 + typed page-table | higher-half map + TLB-flush testi; aarch64 BBM; tek-vCPU TLBI varyant ölçümü |
| **M4 — (v2 kapısı) user/ring** | A12 (ring3/EL0) | EL0/ring3'e geçiş + geri; syscall fast-path; capability dispatch ucu |

| **MV — `tb-vmm` (owned VMM)** | rust-vmm crate'leri + `tb-boot v0` kontratı; tek-vCPU | TABOS kendi VMM'inde boot eder; `tb-boot` 64-bit direkt; A0 trampoline + PVH bağımlılığı **silinir** |

**Bağımlılık:** M0 → M1 → M2 → M3 (sıralı); **MV** M0'dan sonra paralel (canonical hedef; landing'de A0 silinir); M4 ayrı faz (v2), v1 dondurulduktan sonra. Tek-vCPU kararı sayesinde **A13 (AP/SMP) hiçbir milestone'da yok** — sonraki büyük faz.

---

### Doğrulama notu
Boot register değerleri, ABI register setleri, `naked_asm!` stabilizasyonu (1.88.0 / 2025-06-26), PSTATE=0x3c5, Image header dahil 16 sert olgunun 14'ü 2-0 onaylandı; 2'si düzeltmeyle (zero-page alanlarının kaynak atfı; aarch64 serial = NS16550A, PL011 değil) — düzeltmeler bu spec'e işlendi. PVH-vs-LinuxBoot çelişkisi doğrulanmış olgulara dayanarak LinuxBoot lehine çözüldü (§0). [KARAR] üniteleri prototip M-gate'lerinde executable DoD ile test edilecektir.
