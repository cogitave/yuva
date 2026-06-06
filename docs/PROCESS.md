# TABOS Süreç ve Metodoloji Dökümanı

> Durum: v1.0 · Amaç: planlama fazının fiilen izlediği sürecin **denetlenebilir kaydı**, tanınmış iki çerçeveye (**Design Thinking**, **Microsoft Success by Design**) karşı dürüst eşlemesi ve boşlukların kapatılması.
> Çerçeve kaynakları: [IxDF — What is Design Thinking](https://www.interaction-design.org/literature/topics/design-thinking) · [Microsoft Learn — Success by Design](https://learn.microsoft.com/en-us/dynamics365/guidance/implementation-guide/success-by-design)
> İlgili: [README](../README.md) · [VISION](VISION.md) · [OPEN-QUESTIONS](OPEN-QUESTIONS.md)

---

## 0. Dürüstlük Notu

Bu proje bugüne kadar **örtük** bir metodoloji izledi (araştır → çok-oylu doğrula → sentezle → adversarial review → düzelt). Bu döküman yazılana kadar süreç hiçbir standart çerçeveye *açıkça* haritalanmamıştı. Aşağıdaki eşlemeler geriye dönük dürüst bir denetimdir: ne örtüştü, ne eksikti, eksik nasıl kapatılıyor.

## 1. Fiili Süreç Kaydı (denetlenebilir)

| # | Adım (2026-06-06) | Yöntem | Çıktı / kanıt yolu |
|---|---|---|---|
| 1 | Kapsam netleştirme | 3 yapılandırılmış soru (mimari katman, model varsayımı, çıktı formatı) → Arda kararları | [VISION](VISION.md), hafıza kaydı |
| 2 | Dalga 1: deep-research | 105 subagent: 5 arama ekseni → 23 birincil kaynak → 115 iddia → 3-oylu adversarial doğrulama (API arızasıyla kısmi) | [`verified-wave1.json`](../research/raw/verified-wave1.json) (3 onay) |
| 3 | Dalga 2: verify + expand | 35 subagent: 22 iddianın kaynak-gruplu yeniden doğrulaması (9×3 oy) + 8 alan araştırması | [`verified.json`](../research/raw/verified.json) (20+2), `expand-*.json` (100 bulgu) |
| 4 | İsimlendirme | 24+7 aday vetleme → 7/7 + çoğu elendi → **TABOS kod adı** (Arda) + karar-sonrası vetleme | [`expand-naming.json`](../research/raw/expand-naming.json), [`naming-round2.json`](../research/raw/naming-round2.json), [`naming-tabos.json`](../research/raw/naming-tabos.json) |
| 5 | Döküman seti yazımı | 8 döküman, [KARAR]/[ÖNERİ]/[AÇIK] statü işaretli | `README` + `docs/*` |
| 6 | Adversarial review | 3 bağımsız denetçi (iddia sadakati / iç tutarlılık / eksiksizlik) → 1 critical + 14 major + 9 minor → **29 düzeltme** uygulandı | review çıktısı workflow `wf_f1a0e71d`; düzeltmeler dökümanlarda |
| 7 | Kod adı düzeltmesi | "TABOS = kod adı, hardcode yok, rezervasyon yok" (Arda) → 9 düzeltme | README isim notu, OPEN-QUESTIONS §G |
| 8 | Dil & endüstriyel standartlar araştırması | 7 alan + seçilmiş iddiaların 2-oylu doğrulaması (**sürüyor**) | workflow `wf_2c78a514` → LANGUAGE-AND-STANDARDS.md (beklemede) |
| 9 | Süreç denetimi | Bu döküman: çerçeve eşlemesi + persona + risk register + gate'ler | `PROCESS.md` |

## 2. Design Thinking Eşlemesi

IxDF tanımı: *"non-linear, iterative process... five phases: Empathize, Define, Ideate, Prototype, Test"* — wicked problem'lar için. Agent-native OS tasarımı tam bir wicked problem.

| Faz | Bizde karşılığı | Durum | Boşluk → aksiyon |
|---|---|---|---|
| **Empathize** | Literatür + mevcut sistemlerin (E2B/Letta/AIOS) boşluk analizi; agent'ların "acıları" (context taşması, hafıza kaybı, torn-state) araştırma verisinden | ⚠️ Kısmi | **Gerçek kullanıcıyla empati yok** — agent geliştiricileriyle görüşme yapılmadı; persona/JTBD bu dökümanda taslaklandı (§4), doğrulanması [OPEN-QUESTIONS §H](OPEN-QUESTIONS.md) |
| **Define** | [VISION](VISION.md): tek cümlelik tanım, boşluk analizi, 5 ilke, başarı kriterleri | ✅ | — |
| **Ideate** | Alternatifler gerçekten üretildi ve karşılaştırıldı: 4 kernel yaklaşımı (mikrokernel/unikernel/exokernel/microVM → hibrit sentez), 38 isim adayı, memory tasarım uzayı (5 sistem) | ✅ | Alternatif *mimari sentezler* (hibrit dışında B/C planı) açıkça belgelenmedi — kabul edilen sapma: araştırma tek sentezde yakınsadı, gerekçeler ARCHITECTURE §1'de |
| **Prototype** | Yok (bilinçli: planlama fazı "docs only") | 🔜 Faz 1 | Gate G1 (§6) prototip giriş kriterlerini tanımlar |
| **Test** | Dökümanlar için: adversarial review (3 denetçi) = "test the artifact"; sistem için: VISION §7 ölçülebilir kriterler | ⚠️ Kısmi | Sistem testi Faz 1'de; **kullanıcı testi** (persona doğrulaması) yapılmadı → §H |
| **(Non-lineerlik)** | Review bulguları → dökümanlara geri döngü (29 düzeltme); isim kararı → iki tur iterasyon | ✅ | — |

## 3. Success by Design Eşlemesi

Microsoft tanımı: 5 metodoloji-agnostik faz (**Discover, Initiate, Implement, Prepare, Operate**) + review'lar (**Solution Blueprint Review** → **Implementation Reviews** → **Go-live Readiness Review**) + bulgu taksonomisi (**Assertions / Risks / Issues**) + **success measures** (R/Y/G izleme).

### 3.1 Faz eşlemesi

| SbD fazı | TABOS karşılığı | Durum |
|---|---|---|
| **Discover** | Kapsam netleştirme + üç araştırma dalgası (gereksinim keşfi = literatür + mevcut sistem boşlukları) | ✅ Tamamlandı |
| **Initiate** | Döküman seti = "high-level solution design"; iş akışları = [VISION §8 fazları](VISION.md) | ✅ Bu faz |
| **Implement** | Faz 1-3 (prototip → izolasyon → çoklu-agent) | 🔜 |
| **Prepare** | Faz 4 öncesi: public release hazırlığı (isim finalizasyonu, marka, SBOM/imza) | 🔜 |
| **Operate** | Yayın sonrası işletim + telemetri | 🔜 |

### 3.2 Review eşlemesi

- **Solution Blueprint Review** ↔ bizim 3-denetçili adversarial review (`wf_f1a0e71d`). SbD bunu "mandatory" sayar — biz de uyguladık; fark: bizimki otomatik agent'larla, SbD'ninki insan mimarla. **Gate G0'da insan gözüyle bir tur daha önerilir** (Arda + varsa ikinci teknik göz).
- **Implementation Reviews** ↔ Gate G1-G2 denetimleri (§6): her faz girişinde konu-spesifik derin dalış (data model ↔ MEMORY-SPEC; security ↔ capability modeli; integration ↔ bridge'ler; ALM/test ↔ CI+fuzzing stratejisi).
- **Go-live Readiness Review** ↔ Gate G3 (public release).

### 3.3 Bulgu taksonomisi eşlemesi

| SbD | Bizim karşılık |
|---|---|
| **Assertions** (doğru yapılanlar) | Doğrulanmış [KARAR] maddeleri + review'un "high fidelity overall" tespitleri |
| **Risks** (mitigasyonsuz kalırsa olumsuz) | Review **major** bulguları + [AÇIK] işaretleri → §5 Risk Register |
| **Issues** (şu an olumsuz etkileyen) | Review **critical** bulguları (GA formül hatası — düzeltildi) |

### 3.4 Success measures

SbD "7 kategori, 30+ ölçü, R/Y/G" ister. Bizim karşılığımız [VISION §7](VISION.md)'deki 6 ölçülebilir kriter — ancak **izleme mekanizması tanımlı değildi**. Karar: her gate'te bu tablo güncellenir (şimdilik bu dökümanda, Faz 1'den itibaren ayrı SUCCESS-MEASURES.md):

| Ölçü | Hedef | Durum (2026-06-06) |
|---|---|---|
| Agent spawn soğuk başlangıç | <50 ms | ⚪ Henüz ölçülemez (R3 riskine bağlı) |
| Atomik checkpoint (torn-state sıfır) | tasarım garantisi | 🟡 Tasarlandı, doğrulanmadı |
| Memory default p95 retrieval | <200 ms | 🟡 Literatür kanıtlı (Mem0), bizde ölçülmedi |
| Kota verimliliği (cache-aware) | ≥3× efektif iş | 🟡 Aritmetik kanıtlı, uygulanmadı |
| Sleep-time geri ödemesi | ≥2× compute düşüşü | 🟡 Literatür kanıtlı (Letta ~5×) |
| Ambient authority | sıfır | 🟢 Tasarım invaryantı (her spec'te tutarlı) |

## 4. Personalar ve JTBD (taslak — doğrulanacak, §H)

TABOS'un özgün durumu: **birincil "kullanıcı" insan değil.** Dört persona:

| Persona | Kim | JTBD (job-to-be-done) | TABOS'ta karşılığı |
|---|---|---|---|
| **P1 — Agent'ın kendisi** | OS'un birincil vatandaşı | "Görevimi context taşmadan, hafızamı kaybetmeden, yetkim neyse onu bilerek sürdürmek; takıldığımda eskale edebilmek" | Memory garantisi, T0 register'ları, impasse trap'leri, model-okunur hatalar |
| **P2 — Agent geliştiricisi** | Agent/skill yazan mühendis | "Framework kodu yazmadan kalıcı, güvenli, taşınabilir agent kurmak; davranışı debug edebilmek" | Default memory, .taf imajı, `cat /agent/<id>/trace`, WIT tipli skill ABI'si |
| **P3 — Operatör/işletmeci** | Filoyu çalıştıran kişi/kurum | "N agent'ı bütçe ve yetki sınırları içinde, denetlenebilir şekilde işletmek; geri alınamaz işlemleri onaya bağlamak" | Budget capability'leri, consent kapısı, audit/lineage, session yönetimi |
| **P4 — Güvenlik/uyum sorumlusu** | Riski taşıyan taraf | "Agent'ın neye erişebildiğini kanıtlayabilmek; ihlalde blast radius'u bilmek; kayıt zorunluluklarını karşılamak" | Spawn anında numaralandırılabilir yetki seti, statik component-graf analizi, tombstone + privileged delete |

## 5. Risk Register (SbD formatı)

Skor = Etki (1-3) × Olasılık (1-3). Sahip: şimdilik tümü Arda.

| ID | Risk | E | O | Skor | Mitigasyon | Kaynak |
|---|---|---|---|---|---|---|
| R1 | LLM-metin ↔ capability bağı (confused-deputy) çözülemezse güvenlik vaadi temelsiz kalır | 3 | 2 | **6** | B-P0 spec-freeze kapısı; prototipte model-checking | [OPEN-Q §B](OPEN-QUESTIONS.md) |
| R2 | Kapsam genişliği × tek-kişi bus-factor | 3 | 3 | **9** | Faz disiplini; P0 dışına kod yok; erken topluluk/ortak | VISION §8 |
| R3 | <50 ms spawn hedefi üretim-kanıtsız unikernel hattına yaslı | 2 | 2 | 4 | Faz-1'de ilk ölçüm; düşerse Firecracker+minimal-guest'e geri çekil | A-P1 |
| R4 | OS-ömrü memory benchmark'ı yok → yanlış default'lar | 2 | 3 | **6** | Kendi eval harness'i (C-P1); raw-log + yeniden indeksleme her zaman mümkün | MEMORY-SPEC §8 |
| R5 | Self-improvement maliyeti (DGM ~22k USD/koşu emsali) | 2 | 3 | **6** | Staged eval (10→50→200); BULK kota; default'lar weight-free | SELF-IMP §7 |
| R6 | Çekirdek protokollerin oynaklığı (MCP tasks deneysel; ACP konsolidasyonu belirsiz) | 1 | 3 | 3 | Bridge mimarisi absorbe eder; kernel ABI nötr | F-P1 |
| R7 | Memory write-path LLM bağımlılığı → maliyet/latency şişmesi | 2 | 2 | 4 | Lokal 1B enricher ölçümü (C-P1); async consolidation | MEMORY-SPEC §4 |
| R8 | Goodhart: nesiller-arası güvenlik kayması ölçülmüyor | 3 | 2 | **6** | Hidden evaluators (KARAR); longitudinal telemetri tasarımı (E-P2) | SELF-IMP §9 |
| R9 | Persona doğrulaması yapılmadan yanlış kullanıcıya optimize etme | 2 | 2 | 4 | §H görüşmeleri; Faz-1 demo'ları gerçek geliştiricilerle | bu döküman §4 |
| R10 | Kod adı uzun yaşarsa fiili marka olur (rezervasyonsuz) | 1 | 2 | 2 | İsim kararını Faz-2 sonuna kadar ver; izleme | §G |

## 6. Review Gate'leri

| Gate | SbD analoğu | Giriş kriterleri |
|---|---|---|
| **G0 — Spec Freeze** | Solution Blueprint Review (mandatory) | P0×8 kapalı · persona doğrulaması yapıldı (§H) · LANGUAGE-AND-STANDARDS işlendi · insan-gözlü blueprint review · risk register güncel |
| **G1 — Prototip girişi** | Implementation Review #1 | ABI taslağı donduruldu · test stratejisi + CI + fuzzing planı · başarı ölçüleri izlemede |
| **G2 — Faz-2 girişi (izolasyon)** | Implementation Review #2 (security) | Capability modeli bağımsız güvenlik incelemesi · R1 mitigasyonu kanıtlı |
| **G3 — Public release** | Go-live Readiness Review (mandatory) | Nihai isim + marka taraması · SBOM + imzalı yayın · dökümantasyon tam · destek/issue süreci tanımlı |

## 7. Süreç Borcu (bu denetimin çıktısı)

1. ~~Metodoloji eşlemesi belgelenmemiş~~ → bu döküman (kapandı).
2. **Persona doğrulaması** — gerçek agent geliştiricileri/operatörleriyle görüşme → [§H P1](OPEN-QUESTIONS.md).
3. **Success-measure izleme ritmi** — her gate'te güncelleme; Faz 1'de ayrı dosya + otomasyon → [§H P2](OPEN-QUESTIONS.md).
4. İnsan-gözlü blueprint review (G0 kriteri) — otomatik review'a ek.
5. Dil/standart araştırması sonuçlarının ARCHITECTURE'a işlenmesi (sürüyor, `wf_2c78a514`).
