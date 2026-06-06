# TABOS Egemenlik ve Temiz-Sayfa (Clean-Slate) Kararı

> Durum: v1.0 · **Tümü [KARAR]** — açık karar yok.
> Soru (Arda, 2026-06-07): *"Kerneli sıfırdan mı yazıyoruz? Linux sistemi olmayacak, tamamen kendi yapımız olacak; yeni akademik kaynakları miras alacağız ve eski bug'ları taşımak zorunda değiliz."*
> Bu döküman o soruyu **kaynaklı ve dürüst** yanıtlar: neyin silikon-zorunlu, neyin nötr açık standart, neyin reddedilen Linux mirası, neyin TABOS'un olduğunu çizer.
> Dayanak: [`cleanslate-research.json`](../research/raw/cleanslate-research.json) · [`cleanslate-verified.json`](../research/raw/cleanslate-verified.json) · İlgili: [KERNEL-FOUNDATION-SPEC](KERNEL-FOUNDATION-SPEC.md) · [ARCHITECTURE](ARCHITECTURE.md) · [VISION](VISION.md)

---

## 0. Net Cevap

**Evet — kernel %100 sıfırdan, tamamen TABOS'un kendi yapısı. Sıfır satır Linux kodu, sıfır Linux *tasarımı* miras alınmıyor.** TABOS bir Linux sistemi değildir; Asterinas/Redox gibi "Linux uyumlu" da değildir — bilinçli olarak tersi: agent'lar native vatandaştır, hiçbir Linux/POSIX uyumluluğu hedeflenmez.

Dürüstlük şartı: hiçbir OS silikondan kaçamaz. Aşağıdaki tablo, neyin **gerçekten kaçınılmaz** (CPU'nun kendisi), neyin **OS'tan bağımsız açık standart**, neyin **reddedilen Linux mirası**, neyin **TABOS'un sahiplendiği/icat ettiği** olduğunu kesin çizer. Sonuç: TABOS'un Linux'a borcu **yok**; CPU'ya (Intel/ARM) ve birkaç nötr standarda (virtio=OASIS, devicetree=devicetree.org) borcu var — ki bunları her OS paylaşır.

## 1. Egemenlik Sınırı — Kesin Sınıflandırma [doğrulandı]

| Katman | Kategori | Otorite | TABOS ne yapar |
|---|---|---|---|
| x86_64/aarch64 **instruction set**, register file, **privilege ring/EL** | 🔴 **silikon-zorunlu** | Intel SDM / ARM ARM | Uyar; `tb-hal`'da izole eder. Ring0/EL1'de ne *koşacağı* bizim; ring'in *varlığı* silikon |
| **MMU page-table FORMATI** (x86 PML4E bitleri; aarch64 VMSAv8 descriptor) | 🔴 **silikon-zorunlu** | Intel SDM §4.5 / ARM ARM D8 | Format'ı emit eder (MMU donanımda yürür); ama frame allocator + mapping policy %100 TABOS |
| **virtio** ring + wire format | 🟢 **açık standart (nötr)** | **OASIS** VIRTIO TC (v1.1/1.2 ratified; v1.3 draft) | virtio-mmio sürücülerini *kendi koduyla* yazar; kernel-içi device modeli TABOS-native, virtio değiştirilebilir sürücü katmanı |
| **devicetree (DTB)** / PVH start_info | 🟢 **açık standart (nötr)** | devicetree.org / Xen | Parser'ı kendi yazar; format OS-nötr |
| **boot handoff** (hangi register'da ne) | 🔵 **TABOS sahiplenir** | VMM'in seçimi (silikon değil!) | **tb-boot v0** kendi kontratımız; PVH yalnız bootstrap'ta |
| **C psABI** (SysV/AAPCS64) asm sınırında | 🟢 **açık standart (nötr)** | System V psABI / ARM | LLVM+CPU beklediği için uyar; Linux değil, çapraz-OS platform ABI'si |
| **ELF** boot imaj container'ı | 🟢 **açık standart (nötr)** | System V gABI / TIS | Sadece VMM loader'ın parse ettiği kabuk; agent formatı `.taf` zaten TABOS-native |
| syscall ABI, **fork/exec/process/PID**, VFS, POSIX, signals, ioctl, errno, fd-int, /proc-text | ⛔ **Linux/Unix mirası — REDDEDİLDİ** | Linux/Unix geleneği | Hiçbiri alınmıyor (§4) |
| capability/object-cap güvenlik, agent-as-principal, memory-first, DAG-inference | 🟣 **TABOS-novel / nötr-model** | KeyKOS/EROS/seL4 soyu (OS-nötr) | TABOS'un çekirdek kimliği |

**Doğrulanmış sert olgular** (14 olgu, 11 temiz 2-0 + 3 düzeltmeyle):
- "Aynı silikon, üç **uyumsuz** register kontratı" — Linux/x86 64-bit `%rsi→boot_params` (64-bit, paging ON), PVH `%ebx→hvm_start_info` (32-bit, paging OFF), Multiboot2 `EAX=0x36d76289,EBX→info` (paging off). → **boot handoff serbest seçimdir, silikon değil** (2-0).
- `rust-vmm linux-loader`: *"register handoff is the VMM's job, not a fixed library"* (2-0).
- virtio = **OASIS** TC standardı, OS'a ait değil (2-0; düzeltme: v1.3 henüz Committee Draft, ratified olan 1.1/1.2 — TABOS ratified sürüme yazar).
- devicetree = OS-nötr "hardware tarifleme veri yapısı", devicetree.org TSC'si (2-0).
- **Düzeltme/güçlendirme:** aarch64 "MMU off + DAIF maskeli giriş" `kernel.org/arm64/booting.html`'den gelir — bu **Linux'un boot kontratıdır, saf silikon değil**. Yani kendi VMM'imizle (tb-vmm) **kendi giriş koşulumuzu** tanımlarız; bu bile Linux'a borç değil, bir seçim.

## 2. Boot Handoff Kararı — Egemenlik Maksimum [KARAR, önceki kararı revize eder]

**Canonical = `tb-boot v0`:** TABOS'un sahiplendiği, dondurulmuş, capability-yönelimli handoff kontratı. Kendi ince VMM'imiz (`tb-vmm`) üretir, `tb-hal` tüketir. 64-bit long mode'da doğrudan girer (VMM ilk register file'ı biz yazarız) → **trampoline yok, Linux yok, Xen yok**. boot_params/PVH/Image header **compat shim'lere** indirgenir.

**`tb-vmm` (owned VMM) [KARAR]:** rust-vmm crate setiyle (`kvm-ioctls`, `vm-memory`, `linux-loader`, `vm-superio`, `virtio-queue`, `vm-allocator`, `event-manager`) kendi ince Mirage-tek-vCPU VMM'imizi kurarız. rust-vmm **nötr topluluk** projesidir (Firecracker, crosvm, Cloud Hypervisor aynı crate'leri kullanır — Linux değil). Bu, boot kontratını + makine modelini + device arayüzünü **uçtan uca** bize verir.

**Bootstrap istisnası (yalnız M0, geçici iskele):** `tb-vmm` hazır olana dek stock Firecracker üstünde boot ederiz. Bunun için **PVH** seçeriz (Xen-kökenli, **Linux-adı taşımayan** nötr protokol; `linux-loader` bedava verir) — Linux/x86 zero-page yerine. PVH 32-bit girdiği için küçük, **açıkça-geçici bir 32→64 trampoline** (`A0`, ~40 satır) `tb-hal`'da yaşar ve `tb-vmm`/`tb-boot` gelince **silinir**.

> **Revizyon dürüstlüğü:** [KERNEL-FOUNDATION-SPEC §0](KERNEL-FOUNDATION-SPEC.md) önce **LinuxBoot** seçmişti — gerekçe yalnız "trampoline'i sil"di. Senin egemenlik direktifin önceliği değiştirdi: canonical yol (`tb-boot`/`tb-vmm`) zaten trampoline'siz; bootstrap iskelesinde Linux-adlı kontrat yerine nötr PVH + silinecek küçük trampoline'i kabul ediyoruz. Net sonuç: **gerçek sistemde hiçbir yer Linux tarafından adlandırılmış/şekillendirilmiş değil.** (Trampoline sorun çıkarırsa fallback: bootstrap'ta Linux/x86 64-bit protokol — yine ~30 struct alanı, kernel kodu değil.)

## 3. virtio ve Device Modeli [KARAR]

- virtio **OASIS açık standardıdır** (Linux değil) → benimsemek = açık standart benimsemek. virtio-mmio transport + virtio-net/vsock sürücülerini **kendi koduyla** yazarız (block opsiyonel — agent OS disksiz/memory-backed olabilir).
- **Kernel-içi device modeli TABOS-native;** virtio yalnız bir **sürücü katmanı**, yapısal bağ değil → değiştirilebilir. Uzun vade `tb-vmm` Solo5-tarzı minimal kendi arayüzünü sunabilir.
- PC-legacy emülasyon (i8042/PIT/PS2/PIC) **yok sayılır** (Firecracker'ın reset için kullandığı tek register hariç).

## 4. "Eski Bug'ları Taşımıyoruz" — Somut Defter [KARAR]

Senin "eski bug taşımak zorunda değiliz" sözünün kaynaklı karşılığı. Linux/Unix'in bugün geniş çevrelerce **hata** sayılan tasarım kararları ve TABOS'un yapısal alternatifi:

| Linux/Unix mirası (reddedilen) | Kaynak/eleştiri | TABOS yapısal alternatifi |
|---|---|---|
| **Ambient authority** (program kullanıcının tüm yetkisiyle çalışır) | Shapiro EROS, Capsicum | Her işlem dar, explicit capability ister; sıfır ambient authority (POLA) |
| **fork()** | *"A fork() in the road"*, HotOS'19 (Baumann, Appavoo et al.) | fork/clone yok; task'lar manifest'ten **spawn-from-manifest** (Hubris app.toml modeli) + capability-kapılı |
| **ioctl** untyped kaçış | tipsiz, denetlenemez | Her op tipli capability invocation (declared method + typed args) |
| **POSIX signals** (bozuk async primitif) | async-signal-safety kâbusu | Sinyal yok; tipli, kuyruklu notification → explicit endpoint, task drenajıyla |
| **Path-based ambient access** (TOCTOU) | designation≠authority | Yalnız handle; designation+authority **kuple** (capability) → TOCTOU yapısal olarak yok |
| **Global integer fd tablosu** (forgeable/tahmin edilebilir) | — | Unforgeable capability handle'ları, per-task CSpace, dar haklar |
| **C-string / errno** | thread-local errno, sessiz hata | Rust-native ABI: tipli `Result`, enumerable, **model-okunur** hata varyantları |
| **Senkron-bloklayan syscall** tek model | — | Default async capability-invocation; uzun LLM işi tipli **DAG** olarak submit |
| **/proc text parsing** kırılganlığı | format drift | Sentetik agent ağacı **biz tanımlarız**, yapısal introspection |

Bu, yeni akademik kaynakların (capability OS soyu, framekernel, agent-memory literatürü) "ilerlemeyi çözmüş" olmasından yararlanma tezinin somut tarafıdır.

## 5. Egemen-Kernel Emsalleri — Nereye Düşüyoruz [KARAR]

| Kernel | Ne yaptı | TABOS'a göre |
|---|---|---|
| **seL4** | Kendi API'si, kendi boot'u, Unix-şeklinde değil | Egemenlik emsali (capability soyu) |
| **Theseus** (OSDI'20) | Geleneksel process/address-space modelini reddetti, intralingual | Novel-yapı emsali |
| **Hubris** (Oxide) | fork/exec yok, tüm task'lar statik | spawn-from-manifest'i ondan aldık (ama TABOS dinamik+capability-kapılı — kendi-geliştiren OS için statik yetmez) |
| **managarm** | Sıfırdan, async-first; Linux-ABI *opsiyonel seçim* | async yapısını aldık, Linux compat'ını **almadık** |
| **Asterinas** | **Karşı-örnek**: bilinçli Linux-ABI uyumlu | framekernel desenini aldık, Linux-ABI'sini **reddettik** |
| **Redox** | **Karşı-örnek**: bilinçli Unix-like | TABOS'un tersi |

**Sonuç:** Karar kriteri "neyle uygulama-uyumluluğu istiyorsun"dur. TABOS'un vatandaşı **native agent**; legacy uygulama uyumu gerekmez → TABOS Unix/Linux şekline **hiçbir şey borçlu değil.** Native execution principal = **LLM agent** (Unix process / seL4 thread / Hubris task / Theseus cell değil) — bu TABOS-novel.

## 6. Takip Etkisi (WBS)

- **Yeni milestone `MV — tb-vmm` (owned VMM):** rust-vmm tabanlı ince tek-vCPU VMM + `tb-boot v0` kontratı. M0'dan sonra paralel geliştirilebilir; canonical hedef. Landing → bootstrap PVH yolu + `A0` trampoline silinir.
- **`A0` (yeni asm ünitesi, bootstrap-only):** PVH 32→64 trampoline; `tb-hal`'da "geçici, MV'de silinir" etiketli.
- M0 DoD güncellendi: stock Firecracker + **PVH** (Linux zero-page değil).

---

### Doğrulama notu
14 "bu-Linux-mi" olgusunun 11'i 2-0 onaylı; 3 düzeltme egemenlik tezini güçlendirdi (aarch64 giriş koşulları Linux boot-kontratı; virtio v1.3 draft→ratified 1.1/1.2'ye yaz; SDM bölüm no edisyon-bağımlı). Boot çelişkisi (PVH-nötr vs LinuxBoot-trampolinesiz) egemenlik direktifi gereği **tb-boot canonical + PVH bootstrap** lehine çözüldü (§2). [KARAR]'lar prototip M/MV-gate'lerinde executable DoD ile test edilecek.
