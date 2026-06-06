# TABOS Mimari Taslağı

> Durum: v1.0 taslak — karar maddeleri **[KARAR]**, güçlü öneriler **[ÖNERİ]**, açık konular **[AÇIK]** olarak işaretlidir.
> Dayanak: [RESEARCH-REPORT](RESEARCH-REPORT.md) · İlgili: [VISION](VISION.md) · [MEMORY-SPEC](MEMORY-SPEC.md) · [AGENTS-SPEC](AGENTS-SPEC.md) · [SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md) · [LANGUAGE-AND-STANDARDS](LANGUAGE-AND-STANDARDS.md) · [OPEN-QUESTIONS](OPEN-QUESTIONS.md)

---

## 1. Kernel Yaklaşımı Karşılaştırması ve Karar

### 1.1 Adaylar (doğrulanmış verilerle)

| Yaklaşım | Güçlü yanı | Zayıf yanı | Kaynak |
|---|---|---|---|
| **Capability mikrokernel** (seL4/Zircon sınıfı) | TCB ~10 kSLOC (Linux'un 1/1000'i); kritik ihlallerin %29'u yok olur, %55'i kritik-altına iner; zaman/compute dahil her şey capability; tek nesne-lookup noktasında denetim | Servisler arası IPC maliyeti; sürücü/servis ekosistemini kendin kurarsın | seL4 whitepaper; Biggs'18; Capsicum |
| **Unikernel / library OS** (Unikraft/Mirage sınıfı) | ~1 MB imaj, <10 MB RAM, ~1 ms boot, 1.7–2.7× perf; yalnızca gereken bileşen derlenir ("fazlalıksız OS" ilkesinin doğrudan karşılığı); hypervisor = izolasyon | Tek adres uzayı — iç koruma dil/derleyiciye kalır; çok-kiracılı tek imaj olmaz | arXiv:2104.12721; ASPLOS'13 |
| **Exokernel** | Koruma ↔ yönetim ayrımı kanıtlı (secure bindings, visible revocation, abort protocol); kernel kaynak semantiğini anlamadan korur → LLM-agnostiklik teoremi | Saf hâliyle üretim ekosistemi yok; libOS kalitesine bağımlı | SOSP'95 |
| **MicroVM substrat** (Firecracker sınıfı) | Üretim-kanıtlı (AWS Lambda); E2B'de on binlerce eşzamanlı agent sandbox'ı; VM-vs-container ikilemi yanlış ikilem | Kernel değil substrat — üstünde yine bir guest OS gerekir | NSDI'20; e2b.dev |

### 1.2 **[KARAR] Hibrit: "Capability çekirdek + unikernel beden + exokernel ruhu"**

TABOS üç yaklaşımı katmanlaştırır — bunlar rakip değil, farklı katmanların cevaplarıdır:

```
┌─────────────────────────────────────────────────────────────────┐
│  HOST: hypervisor (KVM / Firecracker-sınıfı VMM)                 │ ← üretim-kanıtlı substrat
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ TABOS NODE IMAGE (unikernel olarak boot eden tek imaj)     │  │ ← Unikraft-tarzı modüler derleme
│  │  ┌──────────────────────────────────────────────────────┐ │  │
│  │  │ TB-CORE (frozen capability çekirdeği, hedef ≤15kSLOC) │ │  │ ← seL4/Zircon dersleri
│  │  │  handle+rights · scheme dispatch · task makinesi ·    │ │  │
│  │  │  token-budget controller · event stream'leri ·        │ │  │
│  │  │  checkpoint/persistence · held-out evaluator alanı    │ │  │
│  │  └──────────────────────────────────────────────────────┘ │  │
│  │  TB-SERVICES (userspace daemon'ları, scheme provider'lar): │  │ ← Redox dersi: mümkünse userspace
│  │   memory: · model: · tool: · agent: · trace: · discovery   │  │
│  │  AGENT'LAR: WASM nanoprocess (tool/skill) +                │  │ ← Bytecode Alliance
│  │   gerektiğinde per-agent/per-tenant alt-microVM/unikernel  │  │ ← Mirage modeli
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

- **Çekirdek mikrokernel'dir** çünkü güvenlik iddialarımız (ambient authority yok, ölçen-ölçülen ayrımı, karşılıklı-şüpheli agent'lar) küçük, denetlenebilir TCB ister — sayılar bunu destekliyor (üç derece büyüklük, %29/%55).
- **Beden unikernel'dir** çünkü "fazlalıksız OS" ilkesi derleme-zamanı modülerlik ister ve agent spawn hedefimiz (<50 ms) ~1 ms boot eden imajlarla ulaşılabilir.
- **Ruh exokernel'dir** çünkü kernel agent'ın memory/model semantiğini *anlamaz*; yalnızca secure binding kurar, görünür şekilde geri alır (runaway agent'tan context/tool kotası sökmek dahil) ve politikayı agent'ın libOS'una bırakır (end-to-end argument).
- **Substrat microVM'dir** çünkü tenant sınırında donanım-destekli izolasyon güncel tek güvenilir cevap (WASM yan-kanal itirafı; gVisor maliyet profili).

**[AÇIK]** Faz-1 prototipinin Linux üstü user-mode mı yoksa doğrudan Unikraft port'u mu olacağı ([OPEN-QUESTIONS](OPEN-QUESTIONS.md) §Mimari).

### 1.3 Uygulama Dili **[KARAR — detay: [LANGUAGE-AND-STANDARDS](LANGUAGE-AND-STANDARDS.md)]**

Kernel'dan protocol bridge'lerine kadar **Rust** (frozen kernel `no_std` + framekernel deseni: tüm `unsafe` küçük bir foundation crate'inde, üstte `#![forbid(unsafe_code)]`). Gerekçe üretim-kanıtlı: Android memory-safety açıkları %76→%24 (2019-2024), Linux/Windows/AWS kernel'larında Rust üretimde, Asterinas 15 kLOC framekernel TCB'si. C yalnız vendor'lanan llama.cpp'de driver daemon arkasında; Python/TS yalnız dış SDK + ağ-sınırlı inference engine'leri (vLLM/SGLang). Substrat (Firecracker/crosvm) zaten Rust. Sertifikasyon-sınıfı kernel verification gerekirse node image'ı seL4 üstüne kurma yolu açık ([OPEN-QUESTIONS §I](OPEN-QUESTIONS.md)).

### 1.4 Kernel Foundation ve Assembly **[KARAR — detay: [KERNEL-FOUNDATION-SPEC](KERNEL-FOUNDATION-SPEC.md)]**

Kernel Firecracker/KVM guest olarak boot eder (bare-metal değil) → büyük miktarda boot asm silinir. TÜM `unsafe`+asm tek `tb-hal` foundation crate'inde (`#[unsafe(naked)]`+`naked_asm!`/`global_asm!`, Rust ≥1.88); üstte `#![forbid(unsafe_code)]`. x86_64 **LinuxBoot** (64-bit girer, trampoline yok), aarch64 **PE-Image** (MMU soğuk, bring-up gerekir). Tek-vCPU (Mirage) → AP/SMP asm v1'de yok. Assembly iş kalemleri 13 üniteye (A1-A13), build ise 5 milestone'a (M0 boot → M1 trap → M2 context-switch → M3 MMU → M4 v2-user) bölündü; her ünite executable DoD'li (Firecracker+QEMU CI, iki arch). Kernel-verification kararı: saf-Rust + tiered-assurance (Miri+Kani zorunlu, Verus seçici). **Egemenlik:** TABOS sıfır Linux kodu/tasarımı miras almaz; canonical boot = kendi `tb-boot`/`tb-vmm`'imiz, Firecracker yalnız bootstrap loader (detay + 'eski bug taşımıyoruz' defteri: [SOVEREIGNTY](SOVEREIGNTY.md)).

## 2. Kernel Nesne Modeli **[ÖNERİ]**

Zircon şablonu, agent semantiğiyle:

- **Nesneler** (refcounted, yalnız handle'la erişilir): `Agent`, `Session`, `Task`, `MemTier`, `MemRecord`, `Block`, `Skill`, `ModelSession`, `ToolConn`, `Budget`, `Stream`, `Namespace`, `Evaluator`(held-out).
- **Handle = {object, rights, owner}**; çoğaltma yalnızca hak düşürerek (`tb_handle_dup` ⊆ haklar); transfer yalnızca channel'dan (denetlenebilir yetki-akış grafı — self-improvement servisi en-az-yetki manifestlerini bu graftan öğrenir).
- **Agent-semantik haklar** (READ/WRITE/TRANSFER/DUP'a paralel): `INVOKE_MODEL`, `SPAWN_AGENT`, `WRITE_PROCEDURAL` (CoALA risk asimetrisi gereği ayrı hak), `RECALL`, `CONSOLIDATE`, `EMIT_EXTERNAL` (dış dünyaya yazma), `DELEGATE_BUDGET`.
- **Doğum protokolü [KARAR]**: yeni agent **tek bootstrap channel handle** ile başlar (Zircon modeli); manifest'inin prefix tablosu kernel'ca handle setine çevrilir — *tabloda olmayan, erişilemezdir*; yetki seti spawn anında tamamen numaralandırılabilir.

## 3. İsim Uzayı ve Kaynak Adresleme **[ÖNERİ]**

Plan 9 + Fuchsia + Redox sentezi:

- **Global root yok** (Fuchsia): her agent'ın namespace'i, manifest'indeki prefix→handle tablosudur. `..` traversal protokol düzeyinde yoktur → path-traversal sınıfı prompt-injection istismarları temsil edilemez.
- **Tipli scheme'ler** (Redox): `memory:`, `model:`, `tool:`, `agent:`, `task:`, `fs:`, `trace:`, `budget:`. `model:anthropic/opus` ile `model:local/llama` aynı kontratın iki provider daemon'ı — **LLM-agnostiklik = scheme'i kimin register ettiği.**
- **Sentetik introspection ağacı** (Plan 9): her agent için kernel-served `/agent/<id>/{status,ctl,context,goals,memory/{working,episodic,semantic,procedural},inbox,trace,budget}`; `status` tek satır sabit-format metin, `ctl` metin fiilleri kabul eder (`pause`, `checkpoint`, `compact-context`, `reflect`). Metin = LLM'in doğal ABI'si; `cat` evrensel introspection fiili; supervisor'ın `ps`'i union üstünde `cat`tir. Interposition (iostats deseni) = audit/budget/guardrail proxy'leri agent'a dokunmadan araya girer.
- **Dosya metaforunun bilinçli sınırı** (Plan 9'un kendi dersi): spawn ve KV/embedding paylaşımı dosya değildir — `tb_agent_spawn(manifest)` typed syscall + local-only mmap primitifi; `/agent/<id>/` yalnız *temsil ve kontrol*.
- **Union directory'ler**: session-scratch memory tier'ı kalıcı tier'ın üstüne bind edilir; okuma sırayla düşer — katmanlı memory'nin ergonomisi bedavaya gelir.
- **Depolama (`fs:`) [ÖNERİ]**: dosya sistemi natively *semantic + versioned* bir VFS'tir — vector indeks ve rollback bolt-on değil VFS katmanındadır (AIOS bunu userspace'te chromadb+Redis'le kuruyor; `sto_mount(collection)` mount metaforu ve LSFS [ICLR'25] emsal). T5 archival memory tier'ı ile dosya deposu **tek storage manager'da birleşir** (Letta bulgusu: tek manager hem dosya hem memory-pasaj retrieval'ı servis edebilir) — [AÇIK: OPEN-QUESTIONS §C].

## 4. Syscall Yüzeyi (taslak) **[ÖNERİ]**

AIOS dersi: yapısal çağrı + NL yük. MCP dersi: hatalar model-okunur, self-correction'a uygun döner. Capsicum dersi: tüm denetim tek lookup noktasında; red `TB_ENOTCAPABLE` + iz bırakır (self-improvement bu izleri yer).

```
AİLE        ÇAĞRILAR (özet)
──────────  ────────────────────────────────────────────────────────────
infer       tb_infer_submit(dag, qos, prefs) → future[]   # Parrot: DAG + yalnız terminal çıktıya hedef
            tb_infer_cancel(future)                        # MCP cancellation
mem         tb_mem_write(tier, record, policy) / tb_mem_read(query, pipeline)
            tb_mem_manage(op)                              # consolidate/demote/tombstone (bkz. MEMORY-SPEC)
            tb_recall(cue, opts) · tb_reflect() · tb_learn(artifact)   # CoALA üçlüsü
tool        tb_tool_call(conn, wit_typed_args) → typed_result|model_readable_error
agent       tb_agent_spawn(manifest) → handle · tb_agent_fork(h, hints) → handle   # paylaşımlı-prefix ipucu (SGLang)
            tb_agent_send(h, msg) · tb_agent_watch(h) → stream
task        tb_task_create/get/cancel/subscribe            # A2A 9-durum makinesi
session     tb_session_create() → h · tb_session_join/leave(h, agent) · tb_session_watch(h) → stream
cap         tb_handle_dup(h, rights_subset) · tb_handle_transfer(chan, h) · tb_handle_replace
budget      tb_budget_split(h, slice) · tb_budget_query    # devredilebilir, hiyerarşik
consent     tb_consent_request(schema_restricted)          # MCP elicitation: accept/decline/cancel
stream      tb_stream_read(h, from_seq)                    # sıralı, replay'li (Last-Event-ID deseni)
```

- **`tb_infer_submit` bir DAG alır** (tek prompt→tek completion değil): tipli dataflow kenarları, ara değerler kernel kanallarında akar (Parrot: yalnız client round-trip'leri 2×+ kayıp; 11.7×'e kadar kazanç).
- Inference tercih vektörü MCP sampling modeli: `{costPriority, speedPriority, intelligencePriority}` + advisory hint; somut backend'i çağıran değil **kernel router** bağlar.
- Re-entrancy: inference yolu tool dispatch'ine geri girebilir (MCP SEP-1577 yönelimi).

## 5. Scheduling **[ÖNERİ]**

- **Quantum = decision cycle** (Soar): paralel hazırlık fazı (retrieval, tool sonuçları, rule match) → tek serileştirilmiş commit; preemption ve interrupt teslimi yalnız cycle sınırında — "asla kesilemez dizi yok" garantisi.
- **Impasse trap'leri**: arbitrasyon tie/conflict/constraint-failure/no-change üretirse kernel otomatik child reasoning context açar (page fault analojisi); handler politikası userspace (büyük modele eskale et / başka agent'a sor / memory'ye dön), tespit + substate yığını + otomatik teardown (GDS) kernel'da.
- **Arbitrasyon cebiri**: yarışan önerilen eylemler arasında default karar mekanizması Soar preference semantics'idir (acceptable/reject/better/worse/require/prohibit); öneri üreteçleri (LLM, kurallar) userspace, cebir kernel'da.
- **Retrieval fiyatlama**: ACT-R latency denklemi `RT = F·e^(−f·A)` kernel'ın maliyet modelidir — scheduler bir memory retrieval'ı göndermeden *önce* fiyatlar ve bekle/yeniden-türet/eskale kararını verebilir (F, f backend başına kalibrasyon sabitleri).
- **QoS sınıfları (ABI'de sabit)**: `INTERACTIVE` (TTFT+TBT SLO; aşırı yükte erken red — Mooncake), `PIPELINE` (DAG uçtan-uca hedef; iç düğümler türetilir — Parrot), `BULK` (maliyet-optimal; self-improvement'ın evi; sonsuz ertelenebilir).
- **Cache-topology-aware dispatch**: runnable adımlar global prefix ağacında düğümdür; sınıf içinde DFS/longest-shared-prefix tercih (SGLang Theorem 3.1, optimumun %96'sı) + **aging/fairness day-one** (starvation itirafı).
- **Billing-aware preemption**: lokal motor üzerinde preempt serbest (swap/recompute); metered remote API üzerinde run-to-completion eğilimli — text-resume'un token maliyeti fiyatlanır (AIOS'un ölçmediği boşluk).
- **Admission control**: token-pressure altında prediction-based erken red/erteleme; thrash etmek yerine geri çevir (Mooncake).

## 6. Context Scheduler — Token Kaynak Yönetimi **[ÖNERİ]**

Tek nötr katman, iki driver ailesi (blok katmanı/driver ayrımının analojisi):

| | Lokal driver (vLLM/SGLang/llama.cpp sınıfı) | Remote driver (Anthropic/OpenAI sınıfı) |
|---|---|---|
| Birim maliyet | HBM byte'ı, GPU-saniyesi | dolar, kota-token'ı |
| Mekanizma | KV block table'ları (PagedAttention: %96.3 kullanım), radix prefix ağacı, all-or-nothing eviction, gang scheduling, swap-vs-**recompute** | **Lease nesneleri** {prefix-hash, TTL, read=0.1×, write=1.25×/2×}; lease-renewal scheduler; breakpoint yerleşimi; affinity key yönetimi (~15 RPM/lane) |
| Kota | yerel havuz arbitrajı (cache-vs-batch) | cgroup-tarzı hiyerarşik token bucket (RPM/ITPM/OTPM/dolar 4 sayaç); 429 yerine header-telemetrili önleyici scheduling |
| Ortak soyutlama | **Prefix nesnesi** (content-hash; rezidans: GPU/DRAM/SSD/lease/cold) · **Budget** (budget+period) · QoS · DAG | aynı |

- **Kota×cache birleşik optimizasyon**: Anthropic'te cache okumaları ITPM saymaz → %80 hit = 5× efektif kota; kota sıkışınca kernel'ın ilk hamlesi throttle değil **context yerleşimini yeniden düzenlemek**.
- **Checkpoint asimetrisi**: kalıcı durum token metni; KV recompute edilebilir → migrasyon KB taşır, GB değil.
- Backend driver'ları **capability descriptor** yayınlar: `{ttl_range, write_cost, read_cost, counts_against_quota, affinity_hint, min_cacheable_tokens}`.

## 7. Güvenlik Modeli **[KARAR — ilkeler] / [ÖNERİ — mekanizmalar]**

1. **Ambient authority sıfır** [KARAR]: default FS kökü yok, default network yok, miras API key yok; secret'lar load-time'da çözülen capability referansları (Letta .af dersinin düzeltilmesi).
2. **Tek denetim boğazı**: her handle dereference'ında rights-mask (Capsicum fget deseni); red = `TB_ENOTCAPABLE` + denial trace.
3. **İmzalı agent manifesti** [KARAR]: A2A Agent Card JWS modeli — yükleme anında doğrulama; deklare edilmeyen yetenek mekanik EPERM. Tool manifestleri de imzalı (survey'in tool-poisoning tehdidi); capability grant'leri **task-scoped ve süreli** (privilege persistence tehdidi); tool argümanları kernel-tarafı şema doğrulamalı (command injection).
4. **İzolasyon merdiveni** [ÖNERİ]: intra-agent tool/skill = WASM nanoprocess (import-imza diff'i = consent olayı; component grafında "X'in Y'ye yolu yok" statik kanıtı); farklı principal/tenant = ayrı microVM/unikernel (Spectre itirafı gereği donanım sınırı).
5. **İnsan-onay kapısı**: ANP humanAuthorization + MCP elicitation — `EMIT_EXTERNAL`-sınıfı etiketli op'lar (ödeme, mahremiyet, geri-alınamaz silme) iki-keyring modeliyle insan onayına düşer; kernel-zorlamalı, uygulama nezaketi değil.
6. **Ölçen-ölçülen ayrımı**: evaluator/detector nesneleri agent'ın hak maskesinde hiç görünmez ([SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md)).
7. **Opaque execution** (A2A): agent'ın working memory/plan'ı kernel-korumalı özel bellek; paylaşım yalnız explicit grant'le.

## 8. Kalıcılık **[ÖNERİ]**

KeyKOS orthogonal persistence şablonu: sistem-çapı, ayarlanabilir aralıklı checkpoint; restart'ta tüm agent'lar register/VM düzeyinde aynen döner; elektrik kesintisi = "saat sıçraması". E2B maliyet asimetrisi (4 sn/GiB kaydet, ~1 sn dön) hibernate-default'u doğrular. Agent imajı = `{manifest, context (token metni), memory tier referansları, handle tablosu, task durumları, FS delta}` — .af envanterinin kernel-tamamlanmış hâli ([AGENTS-SPEC §3](AGENTS-SPEC.md)). Revocation × restore etkileşimi ve dış (transactional olmayan) kaynak handle'ları [AÇIK].

## 9. IPC ve Protokol Katmanlaması **[KARAR]**

Kernel **tek kanonik, şema-tanımlı ABI** konuşur (a2a.proto deseni); MCP/A2A/ACP/ANP **userspace bridge daemon'larıdır** — dışarıdan gelen her protokol bridge'de sonlanır, içeride tek kernel IPC lehçesi akar. Kernel primitifleri: correlated request/response, notification, cancellation, capability-passing channel, sıralı-replay'li stream (N gözlemciye aynı sırada — A2A kuralı), durable Task. Discovery, müzakere (ANP meta-protokol), transport binding'leri ve marketplace userspace'tedir; ANP müzakere önbelleği memory tier'larına, üretilen adapter kodu skill registry + sandbox hattına bağlanır.

## 10. Frozen Kernel Sınırı

Kernel + evaluator'lar + evrim makinesi (arşiv bakımı, parent seçimi) **agent'ların self-modification kapsamı dışındadır** (DGM emsali). Agent'ın default yazma yetkisi yalnız kendi config alt-ağacıdır; genişletme explicit capability grant'tir. Ayrıntı: [SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md).

---

### Bu dökümandaki kararların doğrulama zinciri
Tüm sayısal dayanaklar [RESEARCH-REPORT](RESEARCH-REPORT.md)'ta kaynaklı ve oy-doğrulamalıdır; bu dökümandaki **[ÖNERİ]** maddeleri o verilerden türetilmiş tasarım çıkarımlarıdır (kendileri ayrıca doğrulanmış "fact" değildir) ve prototip ölçümleriyle test edilmelidir.
