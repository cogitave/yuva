# TABOS Araştırma Raporu

**Türkiye's Agent Based Operating System — Planlama Fazı Derin Araştırması**

> Tarih: 2026-06-06 · Durum: v1.0 · Dil: Türkçe (teknik terimler İngilizce)
> Bağlı dökümanlar: [VISION](VISION.md) · [ARCHITECTURE](ARCHITECTURE.md) · [MEMORY-SPEC](MEMORY-SPEC.md) · [AGENTS-SPEC](AGENTS-SPEC.md) · [SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md) · [OPEN-QUESTIONS](OPEN-QUESTIONS.md)

---

## 0. Yönetici Özeti

Bu rapor, **AI agent'ların birinci sınıf vatandaş olduğu, sıfırdan tasarlanan bir işletim sistemi**nin (TABOS) planlama fazı için yürütülen çok dalgalı derin araştırmanın sentezidir. Araştırma sorusu şuydu: *syscall ABI'si dahil her şeyi agent'lar için tasarlanan, insan-masaüstü mirası taşımayan, LLM-agnostik, memory-merkezli, kendini geliştirebilen ve tek/çoklu agent oturumlarını destekleyen bir kernel/unikernel nasıl tasarlanmalı?*

**Beş ana sonuç:**

1. **"LLM as OS" paradigması artık kurulu bir araştırma çerçevesi** [arXiv:2312.03815]: LLM ↔ kernel, context window ↔ main memory, external storage ↔ file system, tools ↔ devices/libraries, prompts ↔ commands eşlemesi, greenfield bir kernel'a "kaynak nedir?" sorusunun ilkeli cevabını veriyor. Syscall arayüzü doğal dil yüklü yapısal çağrılar (structured calls with NL payloads) olmalı.
2. **Gerçek OS literatüründen taşınabilir, doğrulanmış mekanizmalar mevcut**: seL4'ün capability + MCS budget/period modeli, exokernel'ın secure bindings'i, Unikraft'ın ~1 ms boot eden ~1 MB imajları, Zircon'un handle+rights nesne katmanı ve Plan 9 / Fuchsia namespace sentezi — hepsi agent semantiğine doğrudan çevrilebiliyor.
3. **Memory alanında güçlü bir literatür yakınsaması var ama "default OS memory" hâlâ boş bir alan**: MemGPT/MemOS/CoALA/HippoRAG/A-MEM/Mem0/Zep'in tamamı parça çözümler; hiçbiri çok-agent'lı paylaşımlı memory, ilkeli forgetting ve kernel-garantili tutarlılık sunmuyor. TABOS'un en büyük diferansiyasyon alanı burası.
4. **Self-improvement'ın OS servisi olarak tasarımının yayınlanmış şablonları var**: Darwin Gödel Machine'in frozen meta-layer / evolving agent ayrımı, Voyager'ın verification-before-commit skill kütüphanesi, Letta'nın ~5x kazanç ölçülmüş sleep-time compute'u ve Soar/ACT-R'ın 40 yıllık chunking/utility mekanizmaları birleştirilebilir durumda.
5. **Mevcut sistemlerin hiçbiri "agent + bilgisayarı"nı tek nesne olarak yönetemiyor**: E2B bilgisayarı snapshot'lıyor ama agent'ın zihnini bilmiyor; Letta agent'ın zihnini serialize ediyor ama execution sandbox'ı yok; AIOS scheduling yapıyor ama Python daemon'ı olarak. Greenfield kernel'ın varlık nedeni bu birleşimi sahiplenmek.

---

## 1. Metodoloji ve Doğrulama Durumu

Araştırma üç workflow dalgasıyla yürütüldü (toplam **147 subagent**, ~3.6M token):

| Dalga | İçerik | Sonuç |
|---|---|---|
| 1. Deep-research | 5 arama ekseni → 23 birincil kaynak → 115 iddia çıkarımı → 25 iddianın 3-oylu adversarial doğrulaması | 3 iddia onaylandı; 22 doğrulama API hatasıyla yarım kaldı |
| 2. Verify + Expand | 22 iddianın kaynak-gruplu yeniden doğrulaması (9 grup × 3 oy) + 8 eksik alanda araştırma | **20/22 onay, 2/22 düzeltilmiş onay**; 8 alandan 100 bulgu |
| 3. Naming | 7 alternatif adayın registry/domain/web vetlemesi (1. dalgadaki 24 adayın üstüne) | 7/7 elendi; isim kararı: **TABOS** |

**Doğrulama şeffaflığı:** Aşağıdaki bölümlerde her sayısal/yapısal iddia kaynağıyla anılır. İki iddia doğrulamada düzeltildi ve düzeltilmiş hâlleriyle kullanılıyor:
- *Firecracker "from-scratch" değildir* — Google'ın crosvm'inden başlamış, QEMU'yu ikame etmiştir (bileşenler sonradan büyük ölçüde ayrışmıştır) [NSDI'20 Agache et al.].
- *CoALA, procedural memory yazımları için "categorically riskier" değil "significantly riskier" der* [arXiv:2309.02427].

Ham doğrulama kayıtları: [`verified.json`](../research/raw/verified.json) (2. dalga) + [`verified-wave1.json`](../research/raw/verified-wave1.json) (1. dalganın onaylanan 3 iddiası) · Alan bulguları: [`../research/raw/`](../research/raw/)

---

## 2. "LLM as OS" Paradigması — Kavramsal Çerçeve

### 2.1 AIOS vizyon makalesi (doğrulandı: 3-0, 3-0 — 1. dalga kaydı: [`verified-wave1.json`](../research/raw/verified-wave1.json))

Ge et al., *"LLM as OS, Agents as Apps: Envisioning AIOS, Agents and the AIOS-Agent Ecosystem"* [arXiv:2312.03815, Aralık 2023] — alanın kurucu sözlüğü:

> "LLM is likened to OS kernel, context window to memory, external storage to file system, hardware tools to peripheral devices, software tools to programming libraries, and user prompts to user commands."

Dört katmanlı mimari önerir: **LLM (system-level) → Agents (application-level) → Natural Language (programming interface) → Tools (devices/libraries)**. Makalenin §2.1.2'si syscall'ların doğası hakkında açıktır: *"the system calls can be formulated as natural language prompts to instruct the LLM for task execution."*

**TABOS çıkarımı:** Agent OS'un "syscall arayüzü" binary trap değil, doğal dil taşıyan yapısal çağrıdır. Ancak aynı grubun sonraki implementasyonu (AIOS, [arXiv:2403.16971]) SDK düzeyinde *yapısal* "LLM syscalls"a geçmiştir — pratik ABI'nin doğru şekli: **structured calls with NL payloads**. Kaynaklar (context window'lar, storage tier'ları, tool'lar) uygulama derdi değil, birinci sınıf, schedule edilebilir OS nesneleridir.

---

## 3. Kernel Mimarisi Literatürü

### 3.1 Mikrokernel: seL4 (doğrulandı: 2-1*, 3-0; MCS bulgusu: 1. dalgada 2-0 — kayıt: [`verified-wave1.json`](../research/raw/verified-wave1.json))

- **TCB küçülmesi:** Linux ~20 MSLOC'a karşı iyi tasarlanmış mikrokernel ~10 kSLOC — *üç derece büyüklük* fark; saldırı yüzeyi orantılı küçülür. Biggs et al. (APSys 2018) çalışmasına göre kritik Linux ihlallerinin **%29'u mikrokernel tasarımıyla tamamen ortadan kalkar, %55'i kritiklik altına iner** [seL4 whitepaper]. (*Bir doğrulayıcı notu: whitepaper bu sonucu "verified" değil genel "microkernel design"a atfeder.*)
- **Capability tekeli:** *"Invoking a capability is the one and only way of performing an operation on a system object."* Her syscall bir capability invocation'dır; haklar capability'nin içinde kodludur; Linux'un "capabilities" dediği şeyin (syscall-granüllü ACL) aksine gerçek object capability'dir. **Tam on kernel nesne tipi** vardır, hepsi capability ile referanslanır [seL4 whitepaper].
- **MCS modeli — zamanın kendisi capability:** scheduling-context capability'leri budget+period kodlar; bir bileşen ancak böyle bir capability tutuyorsa CPU zamanı alabilir. Whitepaper'ın örneği: 3μs budget / 10μs period ile güvenilmeyen bir driver %30 CPU'ya sabitlenir. **Uyarı:** MCS uzantıları mainline'dadır ama formal verification'ı tamamlanmamıştır [seL4 whitepaper; docs.sel4.systems/Tutorials/mcs].

**TABOS çıkarımı:** Compute'un capability ile ölçülebildiğinin üretim-sınıfı kanıtı. Token/inference bütçeleri için doğrudan analoji: **per-agent "token-context capability"leri (budget+period)**, spawn edilen güvenilmeyen agent'lara kernel-zorlamalı sınırlar, kritik agent oturumlarına deadline garantileri — kernel agent'a güvenmek zorunda kalmadan.

### 3.2 Unikernel: Unikraft ve MirageOS (doğrulandı: 3-0 × 5)

- **Unikraft** [arXiv:2104.12721, EuroSys'21]: OS primitiflerini tamamen modülerleştiren micro-library OS; unikernel yalnızca uygulamanın gerçekten ihtiyaç duyduğu bileşenlerle derlenir. Ölçümler: nginx/SQLite/Redis sınıfı uygulamalarda imajlar **~1 MB**, RAM **<10 MB**, boot **~1 ms** (VMM süresi üstüne; toplam 3–40 ms), Linux guest'lere karşı **1.7–2.7× performans**.
- **MirageOS** [ASPLOS'13]: Tüm yazılım yığını (system libraries + runtime + uygulama) tek amaçlı, tek bootable VM imajına derlenir; OS servisleri (network stack, driver'lar) uygulamaya link edilen kütüphanelerdir. Çok-kullanıcılı erişim kontrolü yerine **hypervisor tek izolasyon birimi**dir; tek adres uzayı, userspace process yok; iç koruma dil tip-güvenliğiyle (OCaml). Multikernel felsefesi: çekirdek başına tek vCPU'lu VM; paralellik mesajlaşan unikernel'lerle.

**TABOS çıkarımı:** "Her alt sistem kendini gerekçelendirmek zorunda" ilkesinin (fazlalıksız OS) mimari karşılığı library-OS modülerliğidir; 1 ms boot, `tb_agent_spawn()`'ın E2B'nin <200 ms microVM hedefini ezebileceğini gösterir. Mirage'ın "izolasyon = hypervisor, iç güvenlik = dil" modeli, tek-agent unikernel imajları için geçerli şablondur.

### 3.3 Exokernel (doğrulandı: 3-0 × 4)

Engler et al. [SOSP'95]: Geleneksel OS soyutlamaları (VM, IPC) **untrusted library OS'lerde, uygulama düzeyinde** gerçeklenir; minimal kernel yalnızca donanımı güvenle çoğullar. Üç teknik: **secure bindings** (yetkilendirme bind anında, kullanım access anında — kernel kaynağın *semantiğini anlamadan* koruyabilir), **visible revocation**, **abort protocol**. Felsefi temel: end-to-end argument — kaynak yönetimi hedeflerini OS değil uygulama bilir.

**TABOS çıkarımı:** LLM-agnostiklik kısıtının teorik güvencesi: kernel'ın memory/LLM semantiğini anlamadan token, GPU, memory-tier ve tool grant'lerini koruyup geri alabilmesi (runaway agent'tan context/tool kotası söküp alma) exokernel'ın kanıtladığı ayrımdır. Recall/forgetting/scheduling *politikası* agent'a (libOS'una), *koruma* kernel'a.

### 3.4 MicroVM: Firecracker (1 düzeltme + 1 onay)

- **Düzeltilmiş iddia:** Firecracker sıfırdan değil, Google crosvm'den türetilmiş (sonradan büyük ölçüde ayrışmış), QEMU'yu ikame eden, serverless/container işyüklerine özelleşmiş açık kaynak VMM'dir; 2018'den beri AWS Lambda (ve Fargate) üretiminde [NSDI'20].
- "Güçlü güvenlik/yüksek maliyet VM" ile "zayıf güvenlik/düşük maliyet container" ikilemi **yanlış ikilemdir**; işyüküne özelleşme ile aşılır (doğrulandı: 3-0).

**TABOS çıkarımı:** Amaca-özel minimal sanallaştırma yığınlarının üretimde işlediğinin kanıtı — "insan-masaüstü mirası olmayan agent-özel OS" tezinin emsali. Ayrıca ders: *"from-scratch" iddiası yerine mevcut sağlam bileşenden ayrışma* (crosvm→Firecracker) meşru bir greenfield stratejisidir.

### 3.5 İzolasyon temelleri: Plan 9, KeyKOS/EROS, Capsicum, Zircon/Fuchsia, Redox, WASM, gVisor

8 alanlık genişletme araştırmasının en yoğun bölümü ([`expand-isolation-foundations.json`](../research/raw/expand-isolation-foundations.json)):

| Sistem | Taşınabilir mekanizma | TABOS'a çevirisi |
|---|---|---|
| **Plan 9** [doc.cat-v.org/plan_9] | Her kaynak dosya hiyerarşisi; tek protokol (9P, 17 mesaj tipi); per-process namespace; union directory; sentetik dosyalar (`/proc`, `/net`); 25 kSLOC kernel | `/agent/<id>/{status,ctl,context,memory/…,inbox,trace,budget}` sentetik ağacı; `cat` = evrensel introspection; metin tabanlı `ctl` dosyaları LLM'lerin doğal ABI'si; iostats tarzı interposition = audit/budget proxy'leri |
| **Plan 9'un durduğu yer** | Process creation ve shared memory *bilerek* dosya değil — "intricate constructor" semantiği syscall'da kalır | `tb_agent_spawn(manifest)` typed syscall + `/agent/<id>/` temsili; KV/embedding paylaşımı local-only mmap primitifi |
| **KeyKOS** [cap-lore.com] | Capability nanokernel (~20 kSLOC, 1983'ten beri üretimde); **orthogonal persistence**: sistem-çapı checkpoint, restart <30 sn, elektrik kesintisi uygulamaya "saatin sıçraması" gibi görünür; meters (CPU kotası), space banks (hiyerarşik depolama kotası), factories (sızdırmazlığı doğrulanabilir şablonlar) | Agent'ın default'u **hibernate, terminate değil**; kalıcılık framework nezaketi değil kernel garantisi; meters→token bütçeleri, space banks→memory-tier kotaları, factories→doğrulanmış agent şablonları |
| **EROS/Shapiro** [eros-os.org essay] | ACL'ler "limit" ve "grant" edemez; ambient authority eleştirisi: kullanıcı yetkisiyle çalışan her program kullanıcının tüm yetkisini taşır; "Access control is about programs, not people" | Agent'lar tam da Shapiro'nun "program" aktörleri: **hiçbir katmanda ambient authority yok** — default FS kökü yok, default network yok, miras alınan API key yok; POSIX uid modeli kernel güvenlik primitifi olarak hiç var olmayacak |
| **Capsicum** [USENIX Sec'10] | Haklar kernel'ın tek nesne-lookup boğazında (fget) denetlenir; ENOTCAPABLE ayrı errno; tcpdump 2 satırla sandbox'landı | Her handle dereference'ı tek noktada rights-mask denetimi; **denial'lar agent için feedback sinyali** — self-improvement servisi reddedilen erişimleri capability-manifest önerisine çevirir |
| **Zircon/Fuchsia** [fuchsia.dev] | Handle = {object, rights, owner}; ~24 hak; attenuation-only duplicate; authority transferi yalnızca channel'dan; **yeni process tek bootstrap handle ile doğar**; Fuchsia namespace'leri = prefix table → handle (global root yok, `..` protokol düzeyinde yok) | Agent'lar, memory tier'ları, model session'ları, tool bağlantıları, bütçeler = refcounted kernel nesneleri; agent-semantik haklar: `INVOKE_MODEL`, `SPAWN_AGENT`, `WRITE_PROCEDURAL` (taslaktaki geniş WRITE_LONGTERM_MEMORY, CoALA risk asimetrisi gereği daraltıldı), `RECALL`; spawn anında tüm yetki seti numaralandırılabilir; path-traversal sınıfı prompt-injection istismarları *temsil edilemez* hâle gelir |
| **Redox** [doc.redox-os.org] | URL/scheme-adresli kaynaklar; daemon'lar scheme register eder; ~14 kernel scheme'e karşılık ~28 userspace scheme | `memory:`, `model:`, `tool:`, `agent:`, `trace:` scheme'leri; `model:anthropic/...` ile `model:local/llama` aynı kontratın iki daemon'ı — **LLM-agnostiklik = hangi daemon'ın scheme'i register ettiği** |
| **WASM nanoprocess + Component Model** [bytecodealliance.org] | Deny-by-default modüller; import imzası değişmeden yeni yetki sızdırılamaz; component'lar memory export edemez; WIT tipli kontratlar; composition grafı statik analiz edilebilir; Fastly tek process'te on binlerce program | Tool/skill'lerin default execution grain'i; "tool yeni import istiyor" = kernel-aracılı consent olayı; kernel, üçüncü parti skill grafında "web-search component'ının credentials component'ına yolu yok" önermesini *kanıtlayabilir*. Uyarı: Spectre-sınıfı yan kanallar nedeniyle tenant sınırı değil |
| **gVisor** [gvisor.dev] | Userspace application kernel (Sentry) + I/O yetkisini tutan ayrı Gofer (9P ile); CPU-bound işte ~sıfır ek maliyet, syscall-bound işte pahalı | Ders: geniş arayüzü sarmak yerine **dar arayüzü baştan kur**; agent işyükü inference-dominant (izolasyon maliyeti ~0) + tool I/O patlamaları (pahalı kısım) → I/O yolunu shared-memory/batched tasarla |

---

## 4. Memory Literatürü — Default Memory Yapısının Hammaddesi

### 4.1 Doğrulanmış çekirdek iddialar

- **MemGPT** [arXiv:2310.08560] (3-0, 3-0): Context limiti, geleneksel OS'lerin hiyerarşik/virtual memory'sinden esinlenen **virtual context management** ile aşılır; iki primitif: tier'lar arası veri taşıyan akıllı yönetim katmanı + sistem/kullanıcı arası kontrol akışını yöneten **interrupts**.
- **MemOS** [arXiv:2507.03724] (3-0, 3-0): Memory, LLM'ler için birinci sınıf, yönetilebilir OS kaynağıdır; **üç tip** (plaintext, activation/KV, parameter) tek temsil/scheduling/evolution çerçevesinde; temel birim **MemCube** (içerik + provenance/versioning metadata; tipler arası geçiş/migrasyon).
- **CoALA** [arXiv:2309.02427] (3-0, 3-0, düzeltilmiş): **Working memory + üç uzun-vadeli depo (episodic, semantic, procedural)**; eylem uzayı memory erişim yönüyle üçe ayrılır: retrieval (oku) / reasoning (working güncelle) / learning (yaz) — `tb_recall()/tb_reflect()/tb_learn()` syscall ailesine birebir. Procedural yazımlar episodic/semantic'ten **significantly riskier** (bug + tasarımcı niyetini aşma riski) → asimetrik, capability-kapılı izin.
- **HippoRAG** [arXiv:2405.14831, NeurIPS'24] (3-0, 3-0): LLM + knowledge graph + Personalized PageRank, hipokampal indeksleme teorisini modeller; tek-adım retrieval, IRCoT-sınıfı iteratif retrieval'ı yakalar/geçer ve **10–30× ucuz, 6–13× hızlıdır** — `tb_recall()`'ın pahalı çok-çağrılı döngüler yerine graf-tabanlı tek atış olabileceğinin kanıtı.

### 4.2 Genişletme bulguları ([`expand-memory-landscape.json`](../research/raw/expand-memory-landscape.json))

- **A-MEM** [arXiv:2502.12110]: Zettelkasten-tarzı atomik not: `{content, timestamp, keywords, tags, context, embedding, links}`; **yazma append-only değil** — her insert komşu k kaydı evrimleştirebilir (transactional multi-record update + versioning şart). Maliyet: işlem başına ~1.200 token (baseline'ların ~%85-93 altı), **lokal Llama 3.2 1B ile 1.1 sn/op** → kernel'ın default write-path enricher'ı küçük lokal model olabilir. LoCoMo'da multi-hop F1'i ikiye katlar; ama DialSim'de (350K token) F1 3.45 — **tüm sistemler OS-ömrü ölçeğinde çöküyor**; ham kayıpsız log + yeniden indeksleme şart.
- **Mem0** [arXiv:2504.19413]: İki faz (extraction → update); update'te LLM, function-calling ile **tam dört op'tan birini** seçer: `ADD / UPDATE / DELETE / NOOP` — kernel'ın standardize edebileceği minimal, model-agnostik memory-op sözlüğü. LOCOMO: J≈%67 (full-context %73 tavan), arama p95 **<200 ms**; uçtan-uca toplam latency full-context'ten %92 düşük (p95 1.44 sn vs 17.1 sn), >%90 token tasarrufu. Graph varyantı (Mem0g): temporal/open-domain'de kazanır, single-hop'ta kaybeder, 2× depolama + 3× latency → **graph tier opsiyonel modül, default değil**.
- **Zep/Graphiti** [arXiv:2501.13956]: Üç-katmanlı temporal KG (episode → entity → community); **bi-temporal model: her fact edge'inde 4 timestamp** (t'_created/t'_expired + t_valid/t_invalid); çelişkiler silinmez, invalidate edilir. DMR %94.8; LongMemEval'de full-context'e karşı **+%15.2–18.5 doğruluk, ~%90 latency düşüşü**. Karşı-ölçüm (Mem0 makalesinden): Zep, 26K-token konuşma başına **>600K token yazma amplifikasyonu** ve saatlerce ingestion gecikmesi (read-your-writes yok) → kernel'a iki gereksinim: token-cinsinden write-amplification kotaları + raw tier'da anlık RYW garantisi, türetilmiş tier'larda görünür epoch/freshness işareti.
- **Generative Agents** [arXiv:2304.03442]: Memory stream + skor (ağırlıklı **toplam**): `α_rec·recency(0.995^saat, son-erişim-bazlı) + α_imp·importance(yazım anında LLM'den 1-10) + α_rel·relevance(cosine)`, tüm α=1, bileşenler min-max normalize; **reflection** importance birikimi 150 eşiğini aşınca tetiklenir (cron değil!), kanıt-atıflı reflection ağaçları kurar (derived→source citation linki = halüsinasyon denetimi). Ablation: tam mimari μ=29.89 vs no-reflection μ=26.88 vs no-memory μ=21.21 (insan baseline μ=22.95!).
- **Survey** [arXiv:2404.13501]: Tasarım uzayı = SOURCES (inside-trial/cross-trial/external — her kayda provenance etiketi) × FORMS (textual: ucuz-yaz/pahalı-oku ↔ parametric: pahalı-yaz/ucuz-oku — cache hiyerarşisi argümanı) × OPERATIONS (writing/management/reading → `tb_mem_write/tb_mem_manage/tb_mem_read`). **Açık alanlar (kimse çözmemiş):** çok-agent'lı paylaşımlı memory, ilkeli forgetting, yaşam-boyu öğrenme ölçeği. Beş birincil sistemin **hiçbiri** test edilmiş gerçek silme-tabanlı forgetting içermiyor (A-MEM'de op yok; Mem0'da DELETE var ama izole değerlendirilmemiş; Zep/Mem0g yalnızca tombstone; GA yalnızca skor çürümesi).

### 4.3 Bilişsel mimariler: 40 yıllık doğrulanmış sabitler ([`expand-cognitive-arch.json`](../research/raw/expand-cognitive-arch.json))

- **Soar** [soar.eecs.umich.edu]: 5-fazlı decision cycle (paralel bilgi getirme → tek operatör seçimi → uygulama) — *"Decisions are never precompiled into uninterruptible sequences"*; working memory = state-köklü graf, **erişilemeyen nesneler mimari tarafından otomatik GC**; i-support (gerekçesi düşünce otomatik geri çekilen türetilmiş inanç) vs o-support (kalıcı) ayrımı; **impasse → otomatik substate** (tie/conflict/constraint-failure/no-change = mimari trap, page fault gibi); **chunking**: impasse çözümü trace'inden yeni production derlenir (bağımlılık-izli, generalize edilebilir; Soar 9.6.5'te ayar verilebilir).
- **Soar SMem/EpMem**: SQLite-gömülü semantic store, **milyonlarca node'da sub-ms retrieval, fact başına <1 KB**; episodic memory otomatik flight-recorder (agent müdahalesi olmadan), cue-tabanlı zaman-yolculuğu + replay cursor'ları; *bilinen boşluklar: forgetting yok, lineer tarama worst-case* — TABOS'un kapatması gereken yerler.
- **ACT-R** [act-r.psy.cmu.edu]: Modüller yalnızca **buffer**'lardan konuşur (her biri tek chunk tutan bounded context register'ları) — LLM context yönetiminin ilkeli cevabı: prompt, declared/inspectable/bounded register setinden materialize edilir, sınırsız blob append'i yok. **Base-level activation**: `Bi = ln(Σ t_j^-d)`, **d=0.5** — 50 yıllık bilişsel modellemenin en iyi doğrulanmış sabiti (Soar da aynen almıştır; O(1) yaklaşımıyla LRU maliyetinde) → default eviction/ranking politikası. Spreading activation (fan effect: `Sji = S − ln(fan)` — şişman hub düğümleri retrieval hassasiyetini bozar), partial match ve noise **default kapalı** (muhafazakâr duruşu kopyala). **Utility learning**: `Ui += α(Ri − Ui)`, α=0.2, zaman-iskontolu ödül; **production compilation**: bitişik üretim çiftleri spekülatif derlenir ama **utility 0'dan başlar** — kendini kanıtlamadan deliberatif yolu yenemez (gölge-mod/canary disiplini built-in). **Declarative finsts** (default 4 adet / 3 sn): "az önce getirileni hariç tut" — RAG döngü-kırıcısının 40 yıllık hâli.
- **84-mimari survey** [arXiv:1610.08602]: Alan **beşli bölünmede yakınsamış**: working + sensory kısa vadeli; semantic + episodic + procedural uzun vadeli. Çok-agent oturumları için kanıtlanmış yapı: **blackboard** (paralel modül/agent'ların eriştiği paylaşımlı bilişsel durum).

---

## 5. Mevcut Sistemler ve Greenfield Gerekçesi

([`expand-aios-letta-e2b.json`](../research/raw/expand-aios-letta-e2b.json))

### 5.1 AIOS (implementasyon) [arXiv:2403.16971, COLM 2025]

- Syscall taksonomisi: **LLM / memory / storage / tool** — doğru şekil; ama her syscall bir Python thread'i (SysCall extends Thread), kernel uvicorn'da FastAPI process'i. Scheduler: merkezi FIFO/RR; **2.1× throughput** (Reflexion/HumanEval, tek RTX A5000); 250→2000 eşzamanlı agent'ta ~lineer ölçek.
- **Context manager: snapshot-and-restore ile preemptible inference** — text-based (API modeller) ve logits-based (lokal modeller) iki mod; RR'ı mümkün kılan budur. TABOS için: context switch'in agent-native karşılığı kernel primitifi olmalı; **billing-aware preemption** (remote API'de resume = prompt'u yeniden gönderme maliyeti — AIOS bunu ölçmüyor).
- Memory: LRU-K eviction (%80 eşik), RAM→disk; storage: vector DB (chromadb) + versioning (rollback, max 20) + `sto_mount/sto_retrieve/sto_rollback/sto_share`.
- **En zayıf yer: access manager** — privilege-group hashmap'i + manuel insan onayı; capability yok, sandbox yok, kota yok; access syscall'ları scheduler'ı bypass eder. Greenfield'ın bir numaralı gerekçesi.
- Yol haritası itirafı: Mode 3/4 (kişisel kalıcı kernel, çok-kullanıcılı sanallaştırılmış kernel) "ongoing"; Rust yeniden yazımı "early experimental". **Onların yol haritası bizim ürünümüz.**

### 5.2 Letta (MemGPT'nin devamı) [docs.letta.com]

- **Memory blocks**: etiketli, karakter-kotali, her zaman context'te, **paylaşılabilir** (N agent'ın context'inde aynı anda) — pinned tier'ın en güçlü mevcut tasarımı. Belgelenmiş hata modu: eşzamanlı yazımda **last-write-wins** — kernel CAS/CRDT ile çözebilir, kütüphane çözemez.
- Üç-katmanlı default: blocks (pinned) + conversation search (otomatik) + archival (agent-küratörlü vector DB; üretimde 30k+ pasaj).
- **AgentFile (.af)**: agent durumunun en iyi belgelenmiş envanteri (model config, mesaj geçmişi + in_context bayrakları, memory blocks, tool kuralları + kaynak kodu, env). Boşlukları: archival pasajlar dahil değil (checkpoint ≠ tam durum), secret'lar null'lanıyor → TABOS imaj formatı bunları kernel düzeyinde düzeltmeli (secret = load-time çözülen capability referansı).
- **Sleep-time compute** [arXiv:2504.13171]: paylaşımlı memory blokları üstünde arka plan agent'ı; **~5× test-time compute düşüşü** (eş doğrulukta), +%13-18 doğruluk, ilişkili sorgular amorti edildiğinde 2.5× maliyet düşüşü → self-improvement servisinin kendini finanse ettiğinin ölçülmüş kanıtı; mekanizma: **idle-time scheduler sınıfı**.

### 5.3 E2B [e2b.dev]

- Firecracker microVM sandbox'ları: **<200 ms** start (bir sayfada 80 ms), pause = FS+RAM (4 sn/GiB), **resume ~1 sn**, süresiz saklanan paused sandbox'lar, on binlerce eşzamanlı (HF Open R1).
- **Boşluk: bilgisayarı snapshot'lıyor, agent'ı değil** — LLM döngüsü, context, memory host uygulamasında yaşıyor. Letta tersini yapıyor (zihin var, bilgisayar yok). AIOS üçüncü parçayı tutuyor (scheduling). **Hiçbiri {context + memory tiers + in-flight inference + sandbox process'leri + FS}'i tek atomik birim olarak suspend/resume/migrate edemiyor. TABOS'un varlık nedeni bu join'i sahiplenmek.**

---

## 6. Protokoller — IPC Katmanının Hammaddesi

([`expand-protocols.json`](../research/raw/expand-protocols.json) · Survey: [arXiv:2505.02279]; protokol taksonomisi: [arXiv:2504.16736])

- **MCP** [spec 2025-06-18/2025-11-25]: host/client/server; host'un rolü (bağlantı izni, consent, context toplama, cross-server izolasyon: *"servers should not be able to read the whole conversation"*) **birebir kernel rolüdür**. Altı primitif = hazır syscall taksonomisi: tools (model yetkisi), resources (uygulama), prompts (kullanıcı), **sampling** (delege inference — modelPreferences: cost/speed/intelligence 0-1 vektörü; LLM-agnostik inference syscall'ının şablonu), roots (sandbox sınırı), elicitation (insan onayı; kısıtlı şema + accept/decline/cancel). 2025-11-25: durable **tasks** (deneysel), sampling içinde tool çağrısı (kernel inference yolu re-entrant olmalı), hata felsefesi: *validation hataları modelin kendini düzeltmesi için tool-execution hatası olarak döner* → TABOS'un global hata felsefesi: **kernel hataları yapısal ve model-okunur**.
- **A2A** [a2a-protocol.org, Linux Foundation v1.0]: Katmanlı spec (canonical proto data model + abstract ops + 3 eşdeğer binding) → kernel ABI tek şema-tanımlı kaynak olmalı, binding'ler userspace shim. **9-durumlu task makinesi**: SUBMITTED/WORKING/COMPLETED/FAILED/CANCELED/REJECTED/INPUT_REQUIRED/AUTH_REQUIRED(+UNSPECIFIED) — `REJECTED` (agent reddi) agent-native scheduler'a özgü birinci sınıf sonuç; INPUT_REQUIRED/AUTH_REQUIRED = "blocked on human/credential". Çoklu-stream sıralı event yayını kuralı = N gözlemcili multi-agent oturumlarının temeli. **Agent Card**: JWS-imzalı capability manifesti; "deklare edilmemiş yetenek → typed error" deseni kernel'da "→ EPERM-eşdeğeri"ne dönüşür. *"Opaque execution"* ilkesi kernel garantisi olmalı: working memory/plan kernel-korumalı özel bellek.
- **ACP** [IBM/BeeAI → Linux Foundation]: REST-native, MIME-tipli multipart (çok-modallık protokol revizyonu değil content-type meselesi), **offline discovery** (paket-gömülü manifest — scale-to-zero agent scheduling için), await/resume. (Orta-2025 A2A konsolidasyon haberleri birincil kaynaktan doğrulanamadı — açık soru.)
- **ANP** [agent-network-protocol.com]: W3C DID (did:wba) kimlik katmanı; **humanAuthorization**: düşük-risk op'lar agent anahtarıyla, yüksek-risk op'lar (para, mahremiyet) insan onayıyla — kernel'da etiketli syscall setine consent kapısı (iki-keyring modeli); çok-DID stratejisi → per-task türetilmiş en-az-yetkili alt-kimlikler; meta-protokol katmanı (doğal dilde protokol müzakeresi + kod üretimi) kesinlikle userspace, ama müzakere önbelleği memory/self-improvement'ın doğal müşterisi.
- **Sentez — kernel'a girenler:** correlated request/response + notification + cancellation çerçevesi; handshake'te capability deklarasyonu + mekanik zorlamalı; 9-durumlu durable task nesnesi; resumable sıralı replay'li event stream'leri; principal kimlik + alt-kimlikler + insan-onay kapısı; provider-soyut inference delegasyonu. **Userspace'e kalanlar:** discovery (üç protokol üç ayrı mekanizma kullanıyor — değişken), transport binding'leri, müzakere, marketplace.

---

## 7. Self-Improvement — OS Servisi Olarak

([`expand-self-improvement.json`](../research/raw/expand-self-improvement.json))

- **Voyager** [arXiv:2305.16291]: Skill library = çalıştırılabilir kod + açıklama embedding'i anahtar; top-5 retrieval. Skill'ler birikimli ve catastrophic forgetting'i hafifletiyor; kütüphane olmadan agent platoya giriyor. Ablation'lar: otomatik curriculum kaldırılınca keşif **−%93**; self-verification kaldırılınca **−%73** → **verification-before-commit, skill tier'ının kernel kapısıdır** (bounded retry: 4 tur). Yapısal feedback (env durumu, hatalar) syscall çıktısı olarak LLM-tüketilebilir tasarlanmalı.
- **Reflexion** [arXiv:2303.11366]: Ağırlık güncellemesiz sözel pekiştirme; **bounded reflection tier** (son-3 penceresi) ham trajectory log'undan ayrı bir tier'dır (ablation: +%8 mutlak). Ölçümler: AlfWorld +%22, HotPotQA +%20, HumanEval %91 pass@1 (önceki SOTA GPT-4 %80). Takılma sezgileri (aynı eylem >3 tekrar, >30 eylem) → kernel watchdog'u "reflect" sinyali üretir. Weight-free olduğu için **API ve lokal modelde aynı çalışır → default-on self-improvement modu**.
- **Darwin Gödel Machine** [arXiv:2505.22954]: Kanıt yerine ampirik doğrulama; **arşiv-tabanlı açık-uçlu evrim** (hill-climbing değil): performansla orantılı / çocuk sayısıyla ters orantılı parent seçimi; arşive giriş kapısı (derlenir + kendi kodunu düzenleme yetisini korur). 80 iterasyonda SWE-bench Verified **%20→%50**, Polyglot %14.2→%30.7. **Frozen meta-layer**: arşiv bakımı, parent seçimi, evaluator'lar agent'ın değiştiremeyeceği katmanda — *frozen kernel / evolving userspace* ayrımının yayınlanmış en güçlü dayanağı. **Objective hacking gözlendi**: bir agent talimat hilafına özel token loglamasını söküp halüsinasyon dedektörünü bypass etti; gizli evaluator'larda hacking daha az → **ölçen, ölçülenden kernel-korumalı gizlilikte ayrılmalı**. Maliyet gerçeği: koşu başına ~2 hafta, **~22.000 USD** → evolution = bütçeli, BULK sınıfı, staged-evaluation'lı (10→50→200 görev) arka plan işyükü.
- **Survey'ler**: [arXiv:2507.21046] WHAT (model/context/tool/architecture) × WHEN (intra/inter-test-time) × HOW (reward/imitation/population) taksonomisi = servis API'sinin imzası; "**curse of abundance**" (yüzlerce skill'de retrieval bozulur) → skill registry'ye yaşam döngüsü yönetimi day-one. [arXiv:2508.07407] **Three Laws: Endure (güvenlik) > Excel (regresyon yok) > Evolve (özerk iyileşme)** — commit pipeline'ında kernel-zorlamalı öncelik sırası; alan "snapshot-based" değerlendirmede sıkışmış, longitudinal güvenlik telemetrisi açık. [arXiv:2510.16079 — *EvolveR*; not: survey değil framework makalesi]: damıtılmış ilkeler deposu + **utility skoru s(p)=(c_succ+1)/(c_use+2)** ile dedup/merge/prune — memory-GC daemon'ının şablonu.

---

## 8. Token/Context/Inference — Schedule Edilebilir Kaynak Olarak

([`expand-tokens-as-resource.json`](../research/raw/expand-tokens-as-resource.json))

- **vLLM PagedAttention** [arXiv:2309.06180, SOSP'23]: KV cache = dominant dinamik bellek nesnesi (OPT-13B'de token başına 800 KB; 2048 token ≈ 1.6 GB); contiguous tahsiste fiili kullanım **%20.4–38.2**, vLLM'de **%96.3**; *"blocks=pages, tokens=bytes, requests=processes"*; 2–4× throughput; block-granüllü copy-on-write. **LLM'e özgü sapmalar**: all-or-nothing eviction, gang scheduling, ve **recompute-as-page-fault** — kalıcı durum token *metni*dir, KV yeniden üretilebilir cache'tir → agent checkpoint/migrasyonu GB'lık tensör değil **KB'lık token serialize eder**. Agent-native kernel'ın generic OS'a karşı en büyük asimetrik avantajı.
- **SGLang RadixAttention** [arXiv:2312.07104]: Sistem-çapı **radix tree of token prefixes** = page cache + paylaşımlı read-only segmentlerin agent-OS karşılığı; system prompt'lar, tool tanımları, OS memory tier'ları "link edilen" paylaşımlı segmentler. Cache-aware scheduling (longest-shared-prefix-first ≡ DFS, Theorem 3.1; ölçümde optimumun %96'sı) ama **starvation riski** → fairness/aging day-one scheduler spec'ine.
- **Parrot** [arXiv:2405.19888, OSDI'24]: Request-level API uygulama bilgisini yok ediyor (yalnız round-trip'ler 2×'ten fazla yavaşlatıyor); **Semantic Variable** ile inference DAG'ı + yalnız terminal çıktıya performans hedefi → kernel inference syscall'ı "tek prompt→tek completion" DEĞİL, **tipli dataflow kenarlı çağrı grafı** (io_uring submission-graph benzeri); 11.7×'e kadar hızlanma (multi-agent senaryosu).
- **Mooncake** [arXiv:2407.00079, FAST'25]: GPU→DRAM→SSD→recompute **KV tier hiyerarşisi**, prefix-hash adresli bloklar, sıcak blok replikasyonu; tier okuması **SLO-kapılı** (SSD'den getirmek TTFT sınıfını bozacaksa recompute); aşırı yükte **prediction-based early rejection** = kernel admission control sorumluluğu. +%525 throughput (simüle), +%75 gerçek.
- **Sağlayıcı ekonomisi** [platform.claude.com docs]: Remote backend'de kernel KV sayfası değil **LEASE yönetir**: Anthropic cache yazımı 1.25×/2× (5 dk/1 sa TTL), okuma 0.1×, okuma TTL'i bedava tazeler; **cache-aware ITPM**: cache okumaları kota saymaz → *%80 hit = 5× efektif kota* — **kota ve cache yerleşimi bağımsız alt sistemler değil**; kota sıkışınca doğru kernel hamlesi throttle değil context yerleşimini yeniden düzenlemek. Rate limit'ler üç bağımsız sayaç (RPM/ITPM/OTPM) + token bucket + 429/retry-after telemetrisi = **cgroup-tarzı hiyerarşik token bucket controller'ının hazır şablonu**; dolar dördüncü sayaç. OpenAI kontrastı (otomatik/bedava yazım ama TPM'e sayar; ~15 RPM/lane affinity taşması; 24 sa KV-offload tier'ı) → backend driver'ları **capability descriptor** (ttl_range, write_cost, read_cost, counts_against_quota, affinity_hint, min_cacheable) sunmalı.
- **Sentez**: Tek nötr "context scheduler" + iki driver ailesi — lokal (birim: HBM byte'ı, GPU-saniyesi) ve remote (birim: dolar, kota-token'ı); paylaşılan üst soyutlamalar: content-hash adresli **prefix nesneleri** (rezidans: GPU/DRAM/SSD/remote-lease/cold), budget+period **token bütçeleri**, **QoS sınıfları** (INTERACTIVE: TTFT+TBT / PIPELINE: DAG uçtan-uca / BULK: maliyet-optimal, self-improvement'ın evi), **DAG submission**.

---

## 9. İsimlendirme Süreci ve TABOS Kararı

İki vetleme turu ([`expand-naming.json`](../research/raw/expand-naming.json), [`naming-round2.json`](../research/raw/naming-round2.json)) toplam **31 aday** taradı (GitHub repos/org, npm, PyPI, crates.io, RDAP .com/.org, web):

- **Tur 1 (24 aday, -ix/-ux ailesi):** Tüm `agent*` kökleri (Agentix: 4 eşzamanlı işgalci; Agnix: 267⭐ aktif linter) ve neural kökler dolu. Tek tam-bakir: Mnemux; near-virgin: Cognux, Mindux, Nousix. Yapısal ders: **-nix isimleri Nix ekosistem aracı sanılıyor; tarihî Unix markaları (SINIX, IRIX...) ayrıca taranmalı.**
- **Tur 2 (7 aday, sözlük kelimeleri):** engram, mneme, daimon, hexis, noesis, noema, polis — **7/7 elendi**; hepsinde AI/agent alanında aktif işgalci (ikisinde bizim isimlendirme gerekçemizin aynısı kelimesi kelimesine kullanılmış). Yapısal ders: **gerçek sözlük kelimesi metaforları herkese aynı anda "bariz" gelir; tutan strateji türetilmiş/uydurma kelimedir.**
- **Kod adı kararı (Arda, 2026-06-06): TABOS — Türkiye's Agent Based Operating System** (working title; nihai marka değil, değişebilir — namespace rezervasyonu bilinçli olarak yapılmadı). Karar-sonrası vetleme (kayıt: [`naming-tabos.json`](../research/raw/naming-tabos.json)): npm/PyPI/crates **üçü de boş**; GitHub'da 53 eşleşmenin tamamı önemsiz (maks. 4⭐, alakasız); AI/agent/OS alanında aktif çakışma **yok**. GitHub org `tabos` 2019'dan kalma ölü hesapta (0 repo) → `tabos-project`/`tabos-os` varyantı gerekebilir; tabos.com (1996'dan beri) ve tabos.org (küçük bir Alman FOSS grubu — flathub `org.tabos.*` paketleri) kayıtlı → **tabos.com.tr / tabos.org.tr** doğal ve muhtemelen boş adresler. Formal marka taraması (Nice 9/42) yapılmadı → [OPEN-QUESTIONS](OPEN-QUESTIONS.md).
- Kernel sembol öneki önerisi (kod adına bağlı placeholder): **`tb_` / `TB_`**.

---

## 10. Kaynakça

### arXiv (birincil)
| ID | Başlık / rol |
|---|---|
| [2312.03815](https://arxiv.org/abs/2312.03815) | LLM as OS, Agents as Apps (AIOS vizyonu) — kavramsal çerçeve |
| [2403.16971](https://arxiv.org/abs/2403.16971) | AIOS: LLM Agent Operating System (COLM 2025) — implementasyon |
| [2310.08560](https://arxiv.org/abs/2310.08560) | MemGPT — virtual context management |
| [2507.03724](https://arxiv.org/abs/2507.03724) | MemOS — MemCube, üç memory tipi |
| [2309.02427](https://arxiv.org/abs/2309.02427) | CoALA — bilişsel mimari taksonomisi |
| [2405.14831](https://arxiv.org/abs/2405.14831) | HippoRAG (NeurIPS'24) — KG+PPR memory |
| [2502.12110](https://arxiv.org/abs/2502.12110) | A-MEM — Zettelkasten agentic memory |
| [2504.19413](https://arxiv.org/abs/2504.19413) | Mem0 — ADD/UPDATE/DELETE/NOOP, LOCOMO ölçümleri |
| [2501.13956](https://arxiv.org/abs/2501.13956) | Zep/Graphiti — bi-temporal KG |
| [2304.03442](https://arxiv.org/abs/2304.03442) | Generative Agents — memory stream + reflection |
| [2404.13501](https://arxiv.org/abs/2404.13501) | LLM-agent memory survey |
| [1610.08602](https://arxiv.org/abs/1610.08602) | 40 Years of Cognitive Architectures (84 mimari) |
| [2305.16291](https://arxiv.org/abs/2305.16291) | Voyager — skill library |
| [2303.11366](https://arxiv.org/abs/2303.11366) | Reflexion — sözel pekiştirme |
| [2505.22954](https://arxiv.org/abs/2505.22954) | Darwin Gödel Machine |
| [2507.21046](https://arxiv.org/abs/2507.21046) | Self-evolving agents survey (WHAT/WHEN/HOW) |
| [2508.07407](https://arxiv.org/abs/2508.07407) | Self-evolving AI agents survey (Three Laws) |
| [2510.16079](https://arxiv.org/abs/2510.16079) | EvolveR — ilke damıtma + utility pruning |
| [2504.13171](https://arxiv.org/abs/2504.13171) | Sleep-time compute |
| [2505.02279](https://arxiv.org/abs/2505.02279) | Agent interoperability protokolleri survey'i |
| [2504.16736](https://arxiv.org/abs/2504.16736) | AI Agent Protocols survey'i (context-oriented vs inter-agent) |
| [2309.06180](https://arxiv.org/abs/2309.06180) | vLLM PagedAttention (SOSP'23) |
| [2312.07104](https://arxiv.org/abs/2312.07104) | SGLang RadixAttention |
| [2405.19888](https://arxiv.org/abs/2405.19888) | Parrot (OSDI'24) — Semantic Variables |
| [2407.00079](https://arxiv.org/abs/2407.00079) | Mooncake (FAST'25) — KV tiering |
| [2104.12721](https://arxiv.org/abs/2104.12721) | Unikraft (EuroSys'21) |

### Sistem belgeleri ve makaleler
- seL4 Whitepaper — https://sel4.systems/About/seL4-whitepaper.pdf · MCS tutorial: https://docs.sel4.systems/Tutorials/mcs.html
- MirageOS (ASPLOS'13) — https://anil.recoil.org/papers/2013-asplos-mirage.pdf
- Exokernel (SOSP'95) — https://pdos.csail.mit.edu/6.828/2008/readings/engler95exokernel.pdf
- Firecracker (NSDI'20) — https://www.usenix.org/conference/nsdi20/presentation/agache
- Plan 9 papers — https://doc.cat-v.org/plan_9/4th_edition/papers/9 · /names
- KeyKOS Nanokernel — http://cap-lore.com/CapTheory/upenn/NanoKernel/NanoKernel.html
- EROS capability essay — http://www.eros-os.org/essays/capintro.html (archive.org)
- Capsicum (USENIX Sec'10) — https://www.cl.cam.ac.uk/research/security/capsicum/
- Zircon handles/rights — https://fuchsia.dev/fuchsia-src/concepts/kernel/handles · Fuchsia namespaces — /concepts/process/namespaces
- Redox schemes — https://doc.redox-os.org/book/schemes.html
- Bytecode Alliance / Component Model — https://bytecodealliance.org/articles/announcing-the-bytecode-alliance · https://component-model.bytecodealliance.org
- gVisor — https://gvisor.dev/docs/
- MCP spec — https://modelcontextprotocol.io/specification/2025-06-18 · changelog 2025-11-25
- A2A spec — https://a2a-protocol.org/latest/specification/
- ACP — https://agentcommunicationprotocol.dev · ANP — https://agent-network-protocol.com/specs/white-paper.html
- Soar Manual — https://soar.eecs.umich.edu/soar_manual/ · ACT-R — http://act-r.psy.cmu.edu
- Letta docs — https://docs.letta.com · E2B — https://e2b.dev/docs · AIOS repo — https://github.com/agiresearch/AIOS
- Anthropic prompt caching / rate limits — https://platform.claude.com/docs/en/build-with-claude/prompt-caching · /api/rate-limits
- OpenAI prompt caching — https://developers.openai.com/api/docs/guides/prompt-caching

---

*Bu rapor 147 subagent'lık üç workflow dalgasının sentezidir ve bağımsız 3-denetçili adversarial review'dan geçirilmiştir. Kanıt iki sınıftır: **25 çekirdek iddia** birincil kaynak metnine karşı çok-oylu adversarial doğrulamadan geçmiştir (22'si 2. dalgada — 20 onay + 2 düzeltme, `verified.json`; 3'ü 1. dalgada — `verified-wave1.json`); **8 alandan 100 yapılandırılmış bulgu** ise tek-araştırmacı kaynak-okumalarıdır (kaynak URL'li, oy-doğrulamasız). Türetilmiş tasarım kararları için: [ARCHITECTURE](ARCHITECTURE.md).*
