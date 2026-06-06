# TABOS Dil ve Endüstriyel Standartlar Kararı

> Durum: v1.0 · Soru: *"Sıfırdan agent-native bir kernel hangi dille yazılır; 2026'da ciddi kurumlar fiilen ne yapıyor?"*
> Yöntem: 7 alanlık araştırma (32 subagent) + 12 karar-kritik iddianın 2-oylu adversarial doğrulaması.
> Dayanak: [`lang-research.json`](../research/raw/lang-research.json) · [`lang-verified.json`](../research/raw/lang-verified.json) · İlgili: [ARCHITECTURE](ARCHITECTURE.md) · [PROCESS](PROCESS.md) · [OPEN-QUESTIONS](OPEN-QUESTIONS.md)

---

## 0. Karar Özeti **[KARAR]**

Katman bazlı **dil allowlist'i** (Fuchsia'nın "per-language policy" modeli, TABOS'a uyarlanmış):

| Katman | Dil | Gerekçe (tek satır) |
|---|---|---|
| **Frozen capability microkernel** (≤15 kSLOC) | **Rust** (`no_std`), framekernel deseni | Tüm `unsafe` küçük bir foundation crate'inde; üst katmanlarda `#![forbid(unsafe_code)]` |
| **Node image / scheme daemon'ları** (`memory:`,`model:`,`tool:`,`agent:`...) | **Rust** (`tokio`, `cap-std`) | Tek toolchain, tek güvenlik hikâyesi, VMM ekosistemiyle crate paylaşımı |
| **WASM nanoprocess host** | **Rust** (Wasmtime) | Component Model/WIT host-binding'leri yalnız Rust'ta birinci sınıf |
| **VMM süpervizyonu** (Firecracker/KVM) | **Rust** (rust-vmm crate'leri) | Substrat zaten Rust; HTTP-over-UDS kontrol dilden bağımsız ama crate uyumu Rust'ta |
| **Protocol bridge'leri** (`mcp:`,`a2a:`) | **Rust** (resmi MCP/A2A Rust SDK'leri) | 2026'da her ikisinin de resmi Rust SDK'si var |
| **Local inference engine'leri** | **C/C++ izole** (llama.cpp `-sys` crate arkasında) **veya** ağ sınırı (vLLM/SGLang = Python HTTP server) | Engine'ler node image'a ve kernel'a GİRMEZ — driver daemon'ı veya HTTP client |
| **Geliştirici SDK'leri / CLI / tooling** | **Rust** (çekirdek) + **TypeScript/Python** (ekosistem erişimi) | Dış SDK katmanında GC'li diller serbest |

**Tek cümle:** TABOS, kernel'dan protocol bridge'lerine kadar **Rust**'tır; C yalnızca vendor'lanan llama.cpp'de bir driver daemon'ı arkasında hapsedilir; Python/TypeScript yalnızca en dış SDK halkasında ve ağ-sınırlı inference engine'lerinde yaşar. Bu, 2024-2026 endüstri konsensüsünün (Google, Microsoft, AWS, ISRG, Oxide) birebir uygulanışıdır.

---

## 1. Neden Rust — Üretim Kanıtı **[doğrulandı: 2-0]**

Bu bir "Rust hype"ı değil; ölçülmüş üretim verisi:

- **Android memory-safety eğilimi** [Google Security Blog]: memory-safety açıklarının toplam içindeki payı **%76 (2019) → %35 (2022) → %24 (2024)** — endüstri normu ~%70 iken. Mutlak sayı **223 (2019) → 85 (2022)**. Sebep: ~2019'da YENİ geliştirmenin memory-safe dile kaydırılması; Android 13'te yeni native kodun ~%21'i Rust, AOSP'de ~1.5M satır Rust, ve **bugüne kadar Rust kodunda sıfır memory-safety açığı**. Kritik açıkların %86'sı, uzaktan sömürülebilirlerin %89'u, gerçek-dünya exploit'lerinin %78'i memory-safety sınıfındaydı — **yok ettiğin sınıf en kötü sınıf.** Ek bulgu: açıklar üstel sönümleniyor (yarı-ömür); 5 yıllık kod yeni koddan 3.4-7.4× daha düşük açık yoğunluğuna sahip → **yeni-kod güvenliği toplu rewrite'ı yener.**
- **Hyperscaler kernel'larında Rust üretimde:**
  - *Linux*: Rust v6.1'de (Ara 2022) merge oldu; Android **Binder** sürücüsü Rust'a yazılıp v6.18-rc1'e girdi; **Nova** GPU sürücüsü mainline'da [rust-for-linux.com] *(doğrulandı: 2-0)*. Greg Kroah-Hartman: *"C'deki o aptal küçük köşe-durumlardan kaynaklanan hataların çoğu Rust'ta tamamen yok oluyor — use-after-free, error-path temizliği, dönüş değeri kontrolü unutmak."*
  - *Windows*: GDI REGION tipi Rust'a taşındı (`win32kbase_rs.sys`, Win11 24H2 üretiminde); DWriteCore ~152k satır Rust, glyph shaping %5-15 daha hızlı. Azure CTO Russinovich (2022): *"C/C++'ta yeni proje başlatmayı durdurma ve Rust kullanma zamanı."*
  - *AWS Firecracker + Google crosvm*: TABOS'un **tam hedef substratı** — ikisi de Rust VMM; Firecracker AWS Lambda/Fargate'te "ayda trilyonlarca istek."

**Önemli mühendislik uyarısı** (Windows GDI bulgusundan): Rust'ta bounds-check `panic`'i kasıtlı BSOD üretti; MSRC "doğru davranış" dedi ama Check Point "başarısız güvenlik kontrolü sistemi çökertmemeli" diye itiraz etti. → **TABOS standardı:** evaluator tutan microkernel'da panic-on-violation default availability hikâyesi OLMAMALI; saldırgan-erişimli girdide `Result` döndüren fallible API'ler + graceful capability-denial yolları tasarla.

## 2. Frozen Kernel İçin: Framekernel Deseni **[doğrulandı: 2-0]**

TABOS'un ≤15 kSLOC frozen kernel'ı için en karar-kritik tek kaynak **Asterinas** [arXiv:2506.03876, USENIX ATC'25]:

- Linux-ABI uyumlu **"framekernel"**: tüm `unsafe` Rust, küçük bir **OSTD foundation crate'inde** (~15 kLOC sırası) hapsedilir; kernel'ın geri kalanı safe Rust'tır → sound, küçük bir memory-safety TCB.
- **15 kLOC, tam-özellikli bir kernel altında sağlam memory-safety TCB için yeterli** olduğu bağımsız gösterildi — TABOS'un ≤15 kSLOC hedefinin nicel çapası.
- **Mekanik politika [KARAR]:** `unsafe` yalnız kernel-foundation crate'inde; tüm üst katmanlarda `#![forbid(unsafe_code)]`; `unsafe` blok sayısı VeriSMo'nun "31 satır" disiplini gibi bütçelenir ve gözden geçirilir.

Destekleyen Rust-OS soyağacı: **Redox** (10 yıllık Rust mikrokernel + scheme daemon'ları — TABOS'un tam şekli, çalışabilir olduğunun kanıtı), **Theseus** (derleyici-zorlamalı invariant'lar), **Tock** (compile-time sürücü izolasyonu, 10M cihaz), **Hermit** (saf-Rust unikernel, Firecracker'da boot), **Google KataOS/Sparrow** (seL4 üstünde Rust userspace — TABOS'un birebir bölünmesi).

## 3. Alternatifler ve Neden Elendiler **[doğrulandı: 2-0 / 1-1*]**

| Dil | En güçlü gerçek emsali | Neden TABOS kernel'ı değil |
|---|---|---|
| **Verified C** | seL4: ~10 kSLOC, **binary'ye kadar** Isabelle/HOL ispatı, 15 yılda 0 fonksiyonel hata | Tek binary-seviye ispatlı üretim kernel'ı. Ama: ispat ~20 person-year, ~$362/SLOC (§5) — küçük takım için gerçekçi değil; C'nin kendisi sıfır güvenlik verir |
| **C++** | Fuchsia/Zircon kernel | Fuchsia policy'si C++'ı kernel'da onaylıyor *(düzeltme: politika hem C "kernel içinde dahil" hem C++ "tüm ağaçta" onaylar; "kernel salt C++" demez)*; ama Google YENİ kodda bile memory-unsafe; greenfield'da CISA "bad practice #1" |
| **Go** | gVisor (üretimde, userspace application kernel) | Biscuit [OSDI'18]: GC'li HLL in-kernel **hot-path'te %5-15, kernel CPU'sunun %13'üne kadar maliyet, 2-3× RAM vergisi, GC duraklamaları** *(doğrulandı: 2-0)*. → Go **userspace daemon'ları için geçerli**, kernel için değil |
| **Zig** | TigerBeetle | **1.0 yok** (en güncel 0.16, her sürümde breaking change); en iyi C-FFI hikâyesi ama frozen safety-critical kernel için olgunlaşmamış; Rust'ın borrow-checker'ı yok |
| **OCaml** | MirageOS (Docker Desktop VPNKit'te üretimde!) | Memory-safe unikernel kanıtı ama GC + ekosistem darlığı; agent/skill ekosistemiyle impedans |
| **Ada/SPARK** | NVIDIA (C/C++'ı bıraktı, firmware'de SPARK) | "Runtime error yokluğunu ispatlama" hikâyesi güçlü; ama ekosistem/işe-alım darlığı, WASM/agent tooling yok |

**Sektör deseni** *(doğrulandı, cross-cutting):* ciddi greenfield-OS çabaları **istikrarlı bir bölünmede** yakınsıyor: kernel CORE'u "üretim track-record'lı veya ispatlı" dilde (seL4=verified C, Zircon=C++, KataOS=seL4+Rust), userspace'te GC/HLL serbest, LLM engine'leri (Python/C++/CUDA) ağ-sınırında dışarıda. **TABOS'un mimarisi zaten bu best-practice'le hizalı.**

## 4. Devlet/Endüstri Baskısı — "Endüstriyel Standart" **[doğrulandı: 2-0, düzeltmelerle]**

Greenfield bir OS'un ölçüleceği regülasyon zemini:

- **NSA "Software Memory Safety" CSI** (doc U/OO/219936-22, 10 Kas 2022, Ver1.1 Nis 2023): *"NSA recommends using a memory safe language when possible"*; *(düzeltme: tam alıntı "little or no inherent memory **protection**" — "safety" değil)*. 9 onaylı MSL'den **yalnız Rust** non-GC ve ≤15 kSLOC frozen mikrokernel için uygun (Go/Java/C#/Python/Swift/Ada-GC runtime/GC taşır).
- **CISA/FBI "Product Security Bad Practices"** (v1.0 Eki 2024, v2.0 Oca 2025) *(doğrulandı: 2-0)*: **greenfield bir üründe memory-unsafe dil = bir numaralı kötü pratik.** TABOS greenfield olduğundan, kernel/core'u Rust yazmak en güçlü maddeyle **tam uyum** iddia etmeyi sağlar.
- **White House ONCD "Back to the Building Blocks"** (Şub 2024): tüm MSL'ler içinde **yalnız Rust** "kernel'a yakın + deterministik + GC'siz" üçlüsünü sağlar → mikrokernel için Go/Java/C#/Python'u diskalifiye eder.
- **DARPA TRACTOR**: tüm legacy C'yi çevirmek için jenerik "bir MSL" değil, spesifik olarak **Rust** hedefleniyor — devletin işaret ettiği systems-programming hedefi.
- **EU Cyber Resilience Act** (Reg. (EU) 2024/2847, yürürlük 10 Ara 2024) *(doğrulandı: 2-0)*: TABOS Annex III; VMM + WASM runtime "hypervisor/container runtime" sınıfı. **Eylül 2026**'ya kadar 24s/72s/14g raporlama hattı, **Aralık 2027**'ye kadar CE + Annex I uyumu — TABOS'un geliştirme penceresine düşüyor. → makine-okunur SBOM + memory-safe roadmap **şimdi** benimsenmeli.
- **CISA "The Case for Memory Safe Roadmaps"** (6 Ara 2023): TABOS bir ürün artefaktı olarak **kamuya açık memory-safe roadmap** yayınlamalı (yeni kod yalnız Rust tarihi + C/C++ engine planı + CVE/CWE programı).

## 5. Formal Verification — Ne Gerçekçi? **[doğrulandı: 2-0]**

TABOS'un "frozen kernel evaluator tutar" iddiası verification'ı cazip kılar; gerçekçi seviye:

- **seL4 tam fonksiyonel verification maliyeti** [Klein et al., ACM TOCS 32(1), 2014]: kernel geliştirme **2.2 py**, ispat **~20 py** (~$362/SLOC). → ~15 kSLOC TABOS kernel'ının C+Isabelle tam ispatı **10-20 py'lik, çok-milyon-dolarlık, 3-5 takvim yıllık** program. Küçük takım için gerçekçi değil.
- **Rust+Verus collapse'i** — VeriSMo [Microsoft, OSDI'24] *(doğrulandı: 2-0, düzeltmeyle)*: ilk verified confidential-VM security module (AMD SEV-SNP), Rust+Verus; fonksiyonel doğruluk + secure information flow + adversarial hypervisor altında gizlilik/bütünlük; **yalnız 31 satır trusted unsafe Rust, ~2:1 ispat:kod oranı, ~6 dakika CI verification** (32-core). *(düzeltme: kaynak "C+Isabelle'e karşı maliyeti çökertir" demez; Isabelle'den hiç söz etmez — kıyasyı biz ölçülü çıkarım olarak sunuyoruz.)*
- **Erken-assurance vs retrofit** *(doğrulandı: 2-0)*: gün-1'den assurance-için-tasarım (küçük frozen kernel, spec kodla beraber, "spec'i kıran merge yok" CI kapısı) sertifikasyonu retrofit etmekten **~3-8× ucuz/SLOC**.

**[KARAR] Assurance tier'ları (CI kapısı olarak):**
1. **Tier 0 (~bedava):** safe Rust + **Miri** (CI'da, Rust Project'in kendi kullandığı dinamik UB dedektörü) + Safety-Critical Rust coding guidelines — C kernel CVE'lerine hâkim UB sınıflarını yakalar; RustBelt [POPL'18] formal temeli verir.
2. **Tier 1 (haftalar):** her `unsafe` blok ve protokol parser'ında **Kani** (AWS, bounded model checking) harness'leri.
3. **Tier 2 (aylar, seçici):** capability invariant'ları, scheme-daemon state machine'leri, WASM sandbox sınırı için **Verus** (VeriSMo deseni).
- **[AÇIK]** Sertifikasyon-sınıfı kernel assurance gerekirse: node image'ı doğrulanmış **seL4 üstüne** kurmak (KataOS/Sparrow yolu) tek kanıtlı yol — [OPEN-QUESTIONS §I](OPEN-QUESTIONS.md). Uyarı: Rust std/core **henüz doğrulanmamış** (AWS girişimi sürüyor; ~7.5k unsafe fonksiyon) → kernel ve nanoprocess runtime `no_std` + minimal denetlenebilir bağımlılık tabanı tercih etmeli.

## 6. Standartlar Yığını — Dilin Ötesi **[ÖNERİ]**

"Endüstriyel standart" yalnızca dil değil; gün-1'den benimsenecek denetlenebilir liste:

| Eksen | Standart | TABOS aksiyonu |
|---|---|---|
| **Rust dialect** | **FLS** (Ferrocene Language Specification, Mar 2025'te Rust Project'e devredildi *— düzeltme: Reference'ın statüsünü değiştirmez, ek spec'tir*) + **Safety-Critical Rust Consortium** guidelines (kuruluş 12 Haz 2024) | FLS'e pinle; consortium guidelines'ı in-repo coding standard yap (MISRA-şekilli: compliance level + documented deviation; CI-lint edilebilir) |
| **Qualified toolchain** | **Ferrocene** (TÜV SÜD: ISO 26262 **ASIL D** + IEC 61508, Eki 2023'ten) | İleride functional-safety pazarı gerekirse compiler qualification satın alınabilir (~€240-300/seat/yıl); qualification dokümanları bedava okunur |
| **Residual C** | **MISRA C:2025** (artık güncel; 2023 superseded) + CERT C, static analiz (Coverity/Polyspace) | Yalnız vendor'lanan llama.cpp/VMM glue'da; driver daemon arkasında |
| **Kernel kodlama disiplini** | **TigerStyle** (TigerBeetle): init-sonrası static allocation, her şey bounded, fonksiyon başına ≥2 assertion | ≤15 kSLOC frozen kernel'a uyarla (Hubris de static-allocation seçti) |
| **Supply chain** | **SLSA v1.0** Build L1→L3; **in-toto** provenance | Her artefakt (kernel image, node image, WASM tool bundle'ları, SDK crate/wheel'leri) hosted CI'dan provenance ile çıkar |
| **Best practices** | **OpenSSF Best Practices badge** (passing) | Repo açılışında; 14-gün yanıt / 60-gün fix SLA'leri yayınlanan güvenlik politikası olur |
| **Reproducible builds** | **Nix** (NixOS ~%97 bit-reproducibility kanıtlı) | Unikernel node image için: en güçlü SLSA provenance + CRA uyum kanıtı |
| **SBOM** | **SPDX** (ISO/IEC 5962; lisans) + **CycloneDX v1.7** (ECMA-424; per-artefakt, AI-BOM/ML-model desteğiyle) | İkisi de, role göre: SPDX kaynak/crate manifest'inde, CycloneDX CI'ın ürettiği per-artefakt SBOM'da |
| **Güvenlik süreci** | **SECURITY.md** (gün-1) → **CVE/CNA** (ilk üretim sürümünde; emsal: Linux, curl, Rust) | Supported-version tablosu, private reporting, OpenSSF 14-gün SLA |
| **Fuzzing** | **cargo-fuzz/libFuzzer** → ClusterFuzzLite (CI) → **OSS-Fuzz** | Her parser/IPC sınırı (MCP/A2A mesaj decode = birincil hedef) |
| **Kernel sanitizer** | Debug profilinde KASAN-analog (allocator red-zone/quarantine/UAF poison); arm64'te MTE tasarımı | `unsafe`-Rust yüzeyini egzersiz et |
| **RFC süreci** | **Fuchsia Eng-Council modeli** (tek konsey, in-repo RFC, ≥7-gün last-call) | ABI/capability model/scheme namespace gibi cross-cutting kararlar tek gövdede; frozen-kernel ABI değişikliği RFC-zorunlu |

## 7. Stack Uyum Notları (impedans) **[doğrulandı: 2-0 stack-fit]**

- **WASM host:** Component Model fiilen **Wasmtime/Rust-first**; WIT host-binding'leri (`bindgen!`) yalnız Rust'ta. WAMR (C)/WasmEdge (C++) Component Model host'u sunmaz → tipli nanoprocess arayüzü planıyla çelişir. (WAMR yalnız gelecekteki TEE/MCU profili için.)
- **cap-std** (Bytecode Alliance, Wasmtime'da üretimde): capability-yönelimli std — TABOS'un capability mikrokernel + scheme daemon'ları handle/Dir/Pool modelini **birebir** yeniden kullanabilir; WASI hizası sayesinde aynı capability semantiği nanoprocess katmanına ~sıfır çeviriyle akar. **Rust dışında muadili yok.**
- **tokio** LTS-sınıfı (scheme daemon'ları için güvenli endüstriyel default; `tonic/prost` gRPC IPC). **io_uring crate'leri henüz olgunlaşmamış** → IPC katmanını io_uring'e hard-couple etme, soyutla.
- **Native-Rust inference** (candle, mistral.rs): tek-node/edge/dense model için üretim-credible → istenirse **C++ engine'siz tamamen-Rust node image** mümkün. Datacenter MoE throughput'u için vLLM/SGLang gerekli kalır (Python HTTP server, FFI değil — doğrulandı).
- **llama.cpp**: düz C ABI → Rust'tan `-sys` crate ile düşük impedans (unsafe yüzey -sys'te hapsedilir) veya `llama-server`'ı HTTP'den süpervize et.
- **MCP & A2A**: 2026'da **ikisinin de resmi Rust SDK'si var** (`rmcp` tokio-tabanlı) → protocol bridge'leri saf Rust. TS/Python SDK'leri yalnız geliştirici-SDK katmanında.
- **AIOS `aios-rs` dersi:** önceki agent-OS Python'ı hız için seçti; Rust port'u placeholder trait'lere indirgendi çünkü tüm değer Python-ekosistem entegrasyonundaydı. → **TABOS dersi:** kernel/daemon'ları gün-1'den Rust'a dil-kilitle, Python'ı mimari olarak node image dışına sürgün et.

## 8. Açık Konular → [OPEN-QUESTIONS §I](OPEN-QUESTIONS.md)

- Kernel verification yolu: saf Rust+tiered-assurance mı, yoksa sertifikasyon için seL4-üstü-node-image mi?
- `no_std` çekirdek bağımlılık tabanının denetimi (Rust std/core henüz doğrulanmamış).
- Native-Rust inference (candle/mistral.rs) ne zaman C++ engine'i tamamen ikame eder?
- Ferrocene qualification'ı gerçekten gerekli mi (functional-safety pazarına girilecek mi)?

---

### Doğrulama notu
Bu dökümandaki sayısal iddiaların tamamı [`lang-verified.json`](../research/raw/lang-verified.json)'da 2-oylu adversarial doğrulamadan geçti; 9'u temiz onay, 3'ü düzeltmeyle onay (Fuchsia kernel C/C++ — "salt C++" değil; VeriSMo "Isabelle'e karşı" kıyası kaynakta yok, ölçülü çıkarım; FLS Reference'ı ikame etmez; NSA "memory protection" der). Tasarım çıkarımları ([KARAR]/[ÖNERİ]) bu verilerden türetilmiştir; prototip ölçümleriyle test edilecektir.
